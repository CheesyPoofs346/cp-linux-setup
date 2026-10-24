"""Bounded privilege and disguised-file investigation. No automatic deletion.

Run after forensics: reading file headers can change access times. Findings are
review items, never evidence that arbitrary capabilities/ACLs are malicious.
"""
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

PRIVILEGED_CAPS = {'cap_setuid', 'cap_setgid', 'cap_dac_override', 'cap_dac_read_search',
                   'cap_sys_admin', 'cap_sys_ptrace', 'cap_sys_module', 'cap_setfcap',
                   'cap_chown', 'cap_fowner'}
DOCUMENT_SUFFIXES = {'.pdf', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4', '.docx', '.xlsx'}


def server_config_findings(path, text):
    findings = []
    def add(rule, number, assessment):
        findings.append({'rule': rule, 'severity': 'high', 'path': str(path),
                         'line': number, 'assessment': assessment})
    for number, line in enumerate(text.splitlines(), 1):
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not words:
            continue
        if str(path).startswith('/etc/exports'):
            for match in re.finditer(r'(\S+)\(([^()]*)\)', ' '.join(words)):
                options = set(match[2].split(','))
                if 'no_root_squash' in options:
                    add('nfs-root-identity', number, 'NFS export trusts remote root identities; verify required clients and root_squash policy')
                if match[1] in ('*', '0.0.0.0/0', '::/0') and 'rw' in options:
                    add('nfs-world-write', number, 'NFS share grants write access to all clients; derive client networks from the README before restricting')
        if 'snmpd' in str(path):
            directive = words[0].lower()
            if directive in ('rocommunity', 'rwcommunity', 'rocommunity6', 'rwcommunity6') and len(words) > 1:
                if words[1].lower() in ('public', 'private'):
                    add('snmp-default-community', number, 'SNMP uses a default community; provision authorized credentials and source restrictions without publishing secrets')
                if directive.startswith('rw'):
                    add('snmp-write-community', number, 'Community-based SNMP SET access is enabled; verify intended managers and prefer authenticated encrypted SNMPv3')
            if directive == 'com2sec' and len(words) >= 4 and words[-1].lower() in ('public', 'private'):
                add('snmp-default-community', number, 'SNMP community mapping uses a default credential; review manager and VACM requirements')
    return findings


def capability_findings(output):
    findings = []
    for line in output.splitlines():
        match = re.match(r'^(.*?)\s+(?:=\s*)?(cap_\S+.*)$', line)
        if not match:
            continue
        caps = set(re.findall(r'cap_[a-z0-9_]+', match[2]))
        dangerous = sorted(caps & PRIVILEGED_CAPS)
        if dangerous:
            findings.append({'rule': 'privileged-file-capability', 'severity': 'high',
                             'path': match[1], 'capabilities': dangerous,
                             'assessment': 'Executable can bypass ordinary privilege boundaries; verify package ownership and required service role before removing capabilities'})
    return findings


def acl_findings(path, output):
    """Honor the ACL mask: a masked write entry is not an effective write grant."""
    masks = {}
    entries = []
    for line in output.splitlines():
        clean = line.split('#', 1)[0].strip()
        match = re.fullmatch(r'(default:)?(user|group|mask):([^:]*):([rwx-]{3})', clean)
        if match:
            default, kind, name, perms = match.groups()
            scope = bool(default)
            if kind == 'mask':
                masks[scope] = set(perms) - {'-'}
            entries.append((scope, kind, name, set(perms) - {'-'}))
    findings = []
    for scope, kind, name, perms in entries:
        if not name or name in ('root', '0'):
            continue
        effective = perms & masks.get(scope, set('rwx'))
        sensitive = str(path) in ('/etc/shadow', '/etc/gshadow') and 'r' in effective
        if 'w' in effective or sensitive:
            findings.append({'rule': 'privileged-path-acl', 'severity': 'high', 'path': str(path),
                             'principal': f'{kind}:{name}', 'default_acl': scope,
                             'effective_permissions': ''.join(sorted(effective)),
                             'assessment': 'Named ACL grants effective access to a sensitive path; verify legitimate access before changing it'})
    return findings


def probe(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise OSError(f'{argv[0]} returned {result.returncode}: {result.stderr[:200]}')
    if len(result.stdout) > 128000:
        raise OSError(f'{argv[0]} exceeded the 128KB evidence limit; inspect manually')
    return result.stdout


def collect(root=Path('/'), command=probe, budget=10, max_entries=10000):
    root = Path(root)
    findings, errors = [], []
    config_paths = [root / 'etc/exports', root / 'etc/snmp/snmpd.conf', root / 'etc/snmp/snmpd.local.conf']
    config_paths += list((root / 'etc/exports.d').glob('*.exports'))[:100]
    for path in config_paths:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open('rb') as stream:
                content = stream.read(250001)
            if len(content) > 250000:
                errors.append(str(path) + ': config exceeds evidence budget')
                continue
            findings.extend(server_config_findings('/' + path.relative_to(root).as_posix(), content.decode(errors='replace')))
        except OSError as error:
            errors.append(str(error))
    cap_roots = [root / p for p in ('usr/bin', 'usr/sbin', 'usr/local', 'opt', 'home', 'tmp', 'var/tmp') if (root / p).is_dir()]
    if cap_roots:
        try:
            findings.extend(capability_findings(command(['getcap', '-r', *map(str, cap_roots)])))
        except (OSError, subprocess.SubprocessError) as error:
            errors.append('Capabilities unavailable/partial: ' + str(error))
    for relative in ('etc', 'etc/sudoers', 'etc/sudoers.d', 'etc/ssh', 'etc/cron.d',
                     'etc/passwd', 'etc/group', 'etc/shadow', 'etc/gshadow', 'usr/local/bin'):
        path = root / relative
        if not path.exists() or path.is_symlink():
            continue
        try:
            output = command(['getfacl', '-cp', '--absolute-names', '--', str(path)])
            findings.extend(acl_findings('/' + relative, output))
        except (OSError, subprocess.SubprocessError) as error:
            errors.append('ACL inspection unavailable/partial: ' + str(error))
            break  # Missing getfacl should produce one actionable error, not eleven.
    started, inspected, truncated = time.monotonic(), 0, False
    for relative in ('home', 'tmp', 'var/tmp', 'dev/shm'):
        for directory, dirs, names in os.walk(root / relative, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'cp-linux-setup', 'snap') and not (Path(directory) / d).is_symlink())
            if time.monotonic() - started >= budget or inspected >= max_entries:
                truncated = True
                break
            for name in sorted(names):
                if time.monotonic() - started >= budget or inspected >= max_entries:
                    truncated = True
                    break
                inspected += 1
                path = Path(directory) / name
                if path.suffix.lower() not in DOCUMENT_SUFFIXES or path.is_symlink():
                    continue
                try:
                    if not stat.S_ISREG(path.stat().st_mode):
                        continue
                    with path.open('rb') as stream:
                        magic = stream.read(4)
                    if magic == b'\x7fELF':
                        findings.append({'rule': 'disguised-elf', 'severity': 'high',
                                         'path': '/' + path.relative_to(root).as_posix(),
                                         'assessment': 'ELF executable uses a document/media extension; preserve forensic evidence and investigate, never execute it'})
                except OSError as error:
                    errors.append(str(error))
        if truncated:
            break
    return {'findings': findings, 'errors': errors, 'inspected_entries': inspected,
            'truncated': truncated, 'remediation': 'Review only; no capabilities, ACLs or files were changed'}
