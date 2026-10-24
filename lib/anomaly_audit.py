"""Bounded read-only Linux anomaly audit; indicators are not malware verdicts."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from forensics_agent import read_bytes

PATTERNS = [
    ('shell-network', r'/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s'),
    ('download-execute', r'\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b'),
    ('encoded-execute', r'base64\s+(?:--decode|-d)[^\n]*\|\s*(?:ba)?sh\b'),
    ('socket-script', r'\b(?:python|perl|ruby)\b[^\n]*(?:socket|connect\()'),
    ('temporary-persistence', r'(?:ExecStart|@reboot|\*\s+\*)[^\n]*/(?:tmp|var/tmp|dev/shm)/'),
]


def scan_text(path, content):
    findings = []
    for number, line in enumerate(content.splitlines(), 1):
        if line.lstrip().startswith('#'):
            continue
        for rule, pattern in PATTERNS:
            if re.search(pattern, line, re.I):
                findings.append({'severity': 'high', 'rule': rule, 'path': str(path), 'line': number, 'evidence': line[:500], 'assessment': 'Possible persistence/backdoor indicator; verify legitimate purpose before any action'})
    return findings


def account_findings(passwd, authorized=None):
    findings = []
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) != 7 or not fields[2].isdigit():
            continue
        name, _, uid, gid, _, home, shell = fields
        if int(uid) == 0 and name != 'root':
            findings.append({'severity': 'high', 'rule': 'extra-uid-zero', 'account': name, 'assessment': 'Additional root-equivalent UID; investigate'})
        if authorized is not None and 1000 <= int(uid) < 65534 and name not in authorized:
            findings.append({'severity': 'medium', 'rule': 'unlisted-account', 'account': name, 'assessment': 'Not in the validated README account list; do not delete without review'})
        if name != 'root' and int(uid) < 1000 and not shell.endswith(('nologin', '/false')):
            findings.append({'severity': 'medium', 'rule': 'system-account-login-shell', 'account': name, 'assessment': 'System account has a login shell; may be intentional'})
    return findings


def command_snapshot(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=20)
        return {'argv': args, 'exit_code': result.returncode, 'output': result.stdout[:32000].decode(errors='replace'), 'stderr': result.stderr[:2000].decode(errors='replace'), 'truncated': len(result.stdout) > 32000}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'argv': args, 'error': str(error)}


def collect(engine):
    findings, errors, inspected = [], [], []
    coverage = ['Read-only heuristic audit; not exhaustive and not proof that an image is clean.', 'No automatic deletion, quarantine, account changes, or AI shell execution.', 'Only explicitly selected persistence/config files are read; private SSH keys and password databases are not collected.']
    authorized = None
    try:
        data = json.loads((engine / 'data/readme_parsed.json').read_text())
        authorized = {u['name'] for u in data['all_users'] + data.get('recent_hires', []) if isinstance(u, dict)}
    except (OSError, ValueError, KeyError, TypeError):
        coverage.append('No validated README data available; unauthorized-account comparison omitted.')
    try:
        findings.extend(account_findings(Path('/etc/passwd').read_text(), authorized))
    except OSError as error:
        errors.append(str(error))

    paths = [Path('/etc/crontab'), Path('/etc/rc.local'), Path('/etc/ld.so.preload'), Path('/etc/ssh/sshd_config'), Path('/etc/sudoers'), Path('/etc/environment')]
    for pattern in ('/etc/cron.d/*', '/var/spool/cron/crontabs/*', '/etc/systemd/system/*.service', '/etc/systemd/system/*/*.conf', '/etc/systemd/system/*.timer', '/etc/ssh/sshd_config.d/*.conf', '/etc/sudoers.d/*', '/etc/profile.d/*', '/home/*/.config/systemd/user/*.service', '/home/*/.config/autostart/*.desktop', '/root/.config/systemd/user/*.service', '/root/.config/autostart/*.desktop', '/home/*/.bashrc', '/home/*/.profile', '/root/.bashrc', '/root/.profile', '/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys'):
        import glob
        paths.extend(Path(p) for p in glob.glob(pattern))
    if len(set(paths)) > 1500:
        coverage.append('Config inspection capped at 1,500 selected paths; remaining paths were not inspected.')
    for path in sorted(set(paths))[:1500]:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            content = read_bytes(path, 250000).decode(errors='replace')
            info = path.stat()
            inspected.append(str(path))
            findings.extend(scan_text(path, content))
            if info.st_mode & stat.S_IWOTH:
                findings.append({'severity': 'high', 'rule': 'world-writable-config', 'path': str(path), 'assessment': 'Startup/access configuration is writable by everyone'})
            if path.name == 'ld.so.preload' and any(line.strip() and not line.lstrip().startswith('#') for line in content.splitlines()):
                findings.append({'severity': 'high', 'rule': 'global-library-preload', 'path': str(path), 'assessment': 'Global library injection configured; can be legitimate or a rootkit mechanism'})
            if 'NOPASSWD' in content and ('sudoers' in str(path)):
                findings.append({'severity': 'medium', 'rule': 'passwordless-sudo', 'path': str(path), 'assessment': 'Passwordless sudo present; check required policy and exact users/commands'})
            if path.name == 'authorized_keys':
                keys = [line for line in content.splitlines() if line.strip() and not line.lstrip().startswith('#')]
                findings.append({'severity': 'review', 'rule': 'ssh-authorized-keys', 'path': str(path), 'key_count': len(keys), 'assessment': 'Verify every authorized key against the README; no key contents included in inventory'})
        except (OSError, ValueError) as error:
            errors.append(str(path) + ': ' + str(error))

    started, count = time.monotonic(), 0
    for root in ('/tmp', '/var/tmp', '/dev/shm', '/usr/local/bin', '/usr/local/sbin', '/home'):
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '.cache', '.codex') and not (Path(directory) / d).is_symlink()]
            if time.monotonic() - started > 20 or count >= 20000:
                coverage.append('Executable walk reached its 20-second/20,000-entry budget; results are partial.')
                break
            for name in files:
                count += 1
                if count > 20000 or time.monotonic() - started > 20:
                    break
                path = Path(directory) / name
                if path.is_symlink():
                    continue
                try:
                    info = path.stat()
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        findings.append({'severity': 'high', 'rule': 'unusual-setid-location', 'path': str(path), 'mode': oct(stat.S_IMODE(info.st_mode)), 'assessment': 'Privileged executable outside standard package directories; investigate ownership and origin'})
                    elif root in ('/tmp', '/var/tmp', '/dev/shm') and info.st_mode & 0o111:
                        findings.append({'severity': 'medium', 'rule': 'temporary-executable', 'path': str(path), 'assessment': 'Executable in writable temporary storage; may be a legitimate installer'})
                except OSError as error:
                    errors.append(str(path) + ': ' + str(error))
    deleted = []
    for entry in list(Path('/proc').glob('[0-9]*'))[:10000]:
        try:
            target = os.readlink(entry / 'exe')
            if target.endswith(' (deleted)'):
                deleted.append({'pid': entry.name, 'executable': target})
        except OSError:
            pass
    if deleted:
        findings.append({'severity': 'medium', 'rule': 'deleted-running-executable', 'evidence': deleted, 'assessment': 'Can indicate a replaced/unlinked payload, or an ordinary package update'})
    commands = {
        'listeners': ['ss', '-lntu'], 'process_names': ['ps', '-eo', 'pid,ppid,user,comm'],
        'services': ['systemctl', 'list-unit-files', '--type=service', '--no-pager', '--no-legend'],
        'timers': ['systemctl', 'list-timers', '--all', '--no-pager'],
    }
    if os.environ.get('AUDIT_PACKAGE_CHECK') == '1':
        commands['package_integrity'] = ['dpkg', '-V']
        from privilege_audit import collect as collect_privileges
        privilege_report = collect_privileges()
        findings.extend(privilege_report['findings'])
        errors.extend(privilege_report['errors'])
        if privilege_report['truncated']:
            coverage.append('Privilege/disguised-file walk reached its entry/time budget; inspect remaining paths manually.')
    else:
        coverage.append('Package integrity is deferred until forensics finish; a broad package scan may affect file access times.')
    snapshots = {name: command_snapshot(args) for name, args in commands.items()}
    for name, result in snapshots.items():
        if 'error' in result or result.get('exit_code') not in (0, None):
            errors.append(name + ': failed/partial command snapshot; see snapshots for details')
        if result.get('truncated'):
            coverage.append(name + ': output exceeded 32,000 bytes and was truncated.')
    coverage.append('Network listeners and package integrity are inventory signals, not automatic backdoor classifications. Package checks can time out and legitimate config changes can appear.')
    return {'findings': findings, 'inspected_configs': inspected, 'snapshots': snapshots, 'coverage': coverage, 'errors': errors}


def main():
    os.umask(0o077)
    engine = Path(__file__).resolve().parents[1]
    report = collect(engine)
    directory = engine / 'data/audit' / str(time.time_ns())
    directory.mkdir(parents=True, mode=0o700)
    serialized = json.dumps(report, indent=2)
    (directory / 'report.json').write_text(serialized)
    text = ['Linux anomaly audit — findings need investigation', *report['coverage'], '']
    for finding in report['findings']:
        text.append(f'[{finding["severity"]}] {finding["rule"]}: {finding.get("path", finding.get("account", "system"))}\n  {finding["assessment"]}')
    text.append(f'\nCollection errors: {len(report["errors"])}. See report.json for details and command snapshots.')
    (directory / 'report.txt').write_text('\n'.join(text))
    latest = engine / 'data/audit/latest.json'
    temporary = latest.with_suffix('.tmp')
    temporary.write_text(serialized)
    temporary.replace(latest)
    print(f'Anomaly audit: {len(report["findings"])} indicators, {len(report["errors"])} collection errors. Report: {directory}/report.txt')


if __name__ == '__main__':
    main()
