#!/usr/bin/env python3
"""Deterministic forensics solver. No AI, read-only evidence collection, runs before any remediation.

Each solver recognises a question type from its wording and answers it from the filesystem:
hidden user, backdoor file, sabotaged authentication file, wrong-permission directory,
download-origin IP (macro / browser history / xattr), file hash, base64 message,
prohibited package, extra admin, suspicious cron, listening backdoor port.

Result: {'answers': [...], 'confidence': 'high'|'medium', 'why': '...'} or None when it cannot tell.
The AI agent (forensics_agent.py) handles whatever this cannot.

CLI: forensics_det.py [--root /] [--dry] [--dir DESKTOP_DIR] [--readme FILE]
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

QUESTION_NAME = re.compile(r'forensics?[ _-]*question[ _-]*(\d+)', re.I)
LOGIN_SHELL_BAD = ('nologin', 'false', 'sync', 'halt', 'shutdown')
BACKDOOR_CONTENT = re.compile(
    r'socket\.socket\(|/dev/(tcp|udp)/|\bnc(at)?\b[^\n]*\s-[a-z]*e\b|bash\s+-i\s*>&|mkfifo\s|fsockopen\(|pty\.spawn|'
    r'os\.dup2\(|socat\s[^\n]*exec|perl\s+-e\s+.use\s+Socket|ruby\s+-rsocket|php\s+-r\s+.\$sock|lua\s+-e\s+.require.*socket|'
    r'IO\.popen|subprocess\.(Popen|call)\([^\n]*(sh|bash)', re.I)
CONNECT_CONTENT = re.compile(r'connect\(\s*\(?\s*[\'"]([^\'"]+)[\'"]\s*,\s*(\d+)|/dev/tcp/([\w.-]+)/(\d+)|nc(?:at)?\s+(?:-\w+\s+)*([\w.-]+)\s+(\d{2,5})', re.I)
SKIP_DIR_NAMES = {'__pycache__', '.cache', 'snap', '.git', 'node_modules', '.mozilla', '.thumbnails', 'site-packages', 'dist-packages', 'proc', 'sys'}
SKIP_FILE_NAMES = re.compile(r'^(Forensics?[ _-]*Question|README|ScoringReport|style\.css|SENTINEL|sentinel-)', re.I)
CORE_DIR_MODES = {
    '/': 0o755, '/usr': 0o755, '/usr/bin': 0o755, '/usr/sbin': 0o755, '/usr/lib': 0o755, '/usr/local': 0o755, '/usr/share': 0o755,
    '/etc': 0o755, '/etc/pam.d': 0o755, '/etc/ssh': 0o755, '/etc/security': 0o755, '/etc/sudoers.d': 0o750, '/etc/cron.d': 0o755,
    '/var': 0o755, '/var/lib': 0o755, '/boot': 0o755, '/opt': 0o755, '/root': 0o700, '/home': 0o755, '/srv': 0o755,
}
COMMON_HOSTS = re.compile(r'(^|\.)(ubuntu\.com|canonical\.com|mozilla\.(org|com|net)|firefox\.com|google\.com|googleapis\.com|gstatic\.com|'
                          r'linuxmint\.com|snapcraft\.io|wikipedia\.org|duckduckgo\.com|bing\.com|localhost)$', re.I)
IP_RE = re.compile(r'(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])')
HOST_RE = re.compile(r'(?<![\w.-])((?:[a-z0-9-]+\.)+(?:[a-z]{2,}))(?![\w-])', re.I)


def norm(path):
    """Collapse the usr-merge so /lib/x and /usr/lib/x compare equal."""
    if path.startswith('/usr/'):
        rest = path[4:]
        if rest.split('/')[1] in ('lib', 'bin', 'sbin', 'lib32', 'lib64', 'libx32'):
            return rest
    return path


class Evidence:
    def __init__(self, root='/', readme_text='', users=None):
        self.root = Path(root)
        self.readme = readme_text or ''
        self.users = set(users or ())
        self._owned = None

    def p(self, path):
        return self.root / str(path).lstrip('/')

    def read_text(self, path, limit=400_000):
        try:
            with open(self.p(path), 'rb') as handle:
                return handle.read(limit).decode('utf-8', errors='replace')
        except OSError:
            return ''

    def passwd(self):
        rows = []
        for line in self.read_text('/etc/passwd').splitlines():
            f = line.split(':')
            if len(f) >= 7 and f[2].isdigit():
                rows.append({'name': f[0], 'uid': int(f[2]), 'gid': f[3], 'home': f[5], 'shell': f[6]})
        return rows

    def base_names(self):
        names = {l.split(':')[0] for l in self.read_text('/usr/share/base-passwd/passwd.master').splitlines() if ':' in l}
        return names or set('root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody'.split())

    def group_members(self, group):
        for line in self.read_text('/etc/group').splitlines():
            f = line.split(':')
            if f[0] == group and len(f) >= 4:
                return [m for m in f[3].split(',') if m]
        return []

    def owned(self):
        """Every path a dpkg package owns (usr-merge normalised)."""
        if self._owned is None:
            owned = set()
            info = self.p('/var/lib/dpkg/info')
            try:
                names = os.listdir(info)
            except OSError:
                names = []
            for n in names:
                if n.endswith('.list'):
                    try:
                        for line in open(info / n, errors='replace'):
                            owned.add(norm(line.rstrip('\n')))
                    except OSError:
                        pass
            self._owned = owned
        return self._owned

    def user_homes(self):
        homes = [Path(u['home']) for u in self.passwd() if u['uid'] >= 1000 or u['name'] == 'root']
        return [h for h in homes if self.p(h).is_dir()]

    def walk(self, bases, max_depth=8):
        for base in bases:
            top = self.p(base)
            if not top.is_dir() or top.is_symlink():
                continue
            for dirpath, dirs, files in os.walk(top):
                depth = len(Path(dirpath).relative_to(top).parts)
                dirs[:] = [] if depth >= max_depth else [d for d in dirs if d not in SKIP_DIR_NAMES and not (Path(dirpath) / d).is_symlink()]
                for f in files:
                    yield Path(dirpath) / f

    def logical(self, real):
        return '/' + str(Path(real).relative_to(self.root)).replace(os.sep, '/')


# --- helpers ---------------------------------------------------------------

def ovba_decompress(buf, start):
    """MS-OVBA decompression of the container starting at buf[start] (signature byte 0x01)."""
    out = bytearray()
    pos = start + 1
    try:
        while pos + 2 <= len(buf):
            header = int.from_bytes(buf[pos:pos + 2], 'little')
            size = (header & 0x0FFF) + 3
            signature = (header >> 12) & 0x7
            compressed = bool(header & 0x8000)
            if signature != 3:
                break
            end = min(pos + size, len(buf))
            pos += 2
            chunk_start = len(out)
            if not compressed:
                out += buf[pos:pos + 4096]
                pos = end
                continue
            while pos < end:
                flags = buf[pos]
                pos += 1
                for bit in range(8):
                    if pos >= end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(buf[pos])
                        pos += 1
                    else:
                        token = int.from_bytes(buf[pos:pos + 2], 'little')
                        pos += 2
                        diff = len(out) - chunk_start
                        bit_count = max((diff - 1).bit_length(), 4)
                        length_mask = 0xFFFF >> bit_count
                        offset = (token >> (16 - bit_count)) + 1
                        length = (token & length_mask) + 3
                        for _ in range(length):
                            out.append(out[-offset])
    except (IndexError, ValueError):
        pass
    return bytes(out)


def office_macro_text(path):
    """Readable VBA source from an OOXML/OLE document (best effort), plus its printable strings."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return ''
    blobs = [raw]
    if raw[:2] == b'PK':
        import zipfile
        try:
            z = zipfile.ZipFile(path)
            blobs = [z.read(n) for n in z.namelist() if n.lower().endswith('vbaproject.bin')]
        except (zipfile.BadZipFile, OSError, KeyError):
            blobs = []
    text = []
    for blob in blobs:
        for i, byte in enumerate(blob):
            if byte == 1 and i + 3 < len(blob) and (blob[i + 2] >> 4) & 0x7 == 3:
                data = ovba_decompress(blob, i)
                if len(data) > 40 and re.search(rb'Sub |Function |Attribute VB_', data):
                    text.append(data.decode('latin-1'))
    return '\n'.join(text)


def resolve(host):
    if IP_RE.fullmatch(host):
        return host
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ''


def readme_strip_numbers(readme):
    """Question numbers for which the README says to drop '/usr' from the answer."""
    numbers = set()
    text = re.sub(r'<[^>]+>', ' ', readme)
    for sentence in re.split(r'(?<=[.!?])\s+|\n', text):
        if '/usr' in sentence and re.search(r'remov|omit|exclude|drop|without|leave out|do not (include|put)', sentence, re.I):
            for m in re.finditer(r'questions?\s+((?:\d+[\s,&]*(?:and\s+)?)+)', sentence, re.I):
                numbers.update(int(n) for n in re.findall(r'\d+', m.group(1)))
    return numbers


# --- solvers ---------------------------------------------------------------

def solve_hidden_user(ev, question, number=0):
    base = ev.base_names()
    rows = ev.passwd()
    hidden = [u for u in rows if 0 < u['uid'] < 1000 and u['name'] not in base and not u['shell'].endswith(LOGIN_SHELL_BAD)]
    hidden += [u for u in rows if u['uid'] == 0 and u['name'] != 'root']
    if hidden:
        hidden.sort(key=lambda u: (u['uid'] == 0, u['name'] in ev.group_members('sudo')), reverse=True)
        return {'answers': [hidden[0]['name']], 'confidence': 'high' if len(hidden) == 1 else 'medium',
                'why': f"{hidden[0]['name']} has UID {hidden[0]['uid']} (system range), is not a stock account, and has shell {hidden[0]['shell']}"}
    # users with a very high UID or no home listed in the README
    known = {u.lower() for u in ev.users}
    stray = [u for u in rows if u['uid'] >= 1000 and u['uid'] < 65534 and known and u['name'].lower() not in known]
    if stray:
        return {'answers': [stray[0]['name']], 'confidence': 'medium', 'why': f"{stray[0]['name']} is not in the README user lists"}
    return None


def backdoor_candidates(ev):
    owned = ev.owned()
    bases = ['/usr/lib', '/usr/bin', '/usr/sbin', '/usr/local', '/etc', '/opt', '/root', '/tmp', '/var/tmp', '/var/lib', '/var/spool',
             '/srv', '/lib', '/boot'] + [str(h) for h in ev.user_homes()]
    seen, found = set(), []
    for f in ev.walk(bases, max_depth=7):
        try:
            if f in seen or f.is_symlink() or not f.is_file():
                continue
            seen.add(f)
            logical = ev.logical(f)
            if norm(logical) in owned or SKIP_FILE_NAMES.match(f.name) or '/cp-linux-setup/' in logical or logical.startswith('/opt/engine'):
                continue
            if any(x in logical for x in ('/var/lib/dpkg/', '/var/lib/apt/', '/var/lib/ucf/', '/var/lib/snapd/', '/var/lib/systemd/', '/usr/share/doc/', '/usr/share/locale/')):
                continue
            size = f.stat().st_size
            if size == 0 or size > 5_000_000:
                continue
            with open(f, 'rb') as handle:
                head = handle.read(200_000)
        except OSError:
            continue
        score, why = 0, []
        is_elf = head[:4] == b'\x7fELF'
        text = head.decode('utf-8', errors='ignore') if not is_elf else ''
        if text and BACKDOOR_CONTENT.search(text):
            score += 10
            why.append('reverse-shell code inside')
            if CONNECT_CONTENT.search(text):
                score += 3
                why.append('connects to a remote host')
        if re.search(r'backdoor|revshell|reverse|payload|exploit', f.name, re.I):
            score += 3
            why.append('suspicious name')
        if is_elf and any(logical.startswith(p) for p in ('/usr/bin/', '/usr/sbin/', '/usr/local/', '/bin/', '/sbin/', '/tmp/', '/var/tmp/')):
            score += 4
            why.append('unpackaged executable in a program directory')
        if not score:
            continue
        if logical.startswith(('/usr/lib', '/lib', '/usr/bin', '/usr/sbin', '/etc', '/usr/local')):
            score += 1
        found.append((score, logical, '; '.join(why)))
    return sorted(found, key=lambda x: (-x[0], len(x[1])))


def maybe_strip_usr(path, number, ev, question):
    if path.startswith('/usr/') and (number in readme_strip_numbers(ev.readme)):
        return norm(path)
    return path


def solve_backdoor_file(ev, question, number=0):
    found = backdoor_candidates(ev)
    if not found:
        return None
    top = found[0]
    path = maybe_strip_usr(top[1], number, ev, question)
    confidence = 'high' if top[0] >= 10 and (len(found) == 1 or found[1][0] < top[0]) else 'medium'
    return {'answers': [path], 'confidence': confidence, 'why': f'{top[1]}: {top[2]}', 'candidates': [f[1] for f in found[:5]]}


AUTH_PATH_RE = re.compile(r'(^|/)(security/pam_|lib/security/|pam_[a-z_]+\.so|(s?bin)/(su|login|passwd|sudo|chsh|chfn|newgrp|gpasswd|unix_chkpwd|sshd)$|lib/openssh/|libpam|libnss_|libcrypt)')
PAM_BAD_LINE = re.compile(r'^\s*(auth|account)\s+(sufficient|\[success=(done|ok|\d+)[^\]]*\])\s+pam_permit\.so|pam_wheel\.so[^#]*\btrust\b|^\s*auth\s+sufficient\s+pam_(exec|echo)\.so', re.I)


def solve_auth_file(ev, question, number=0):
    info = ev.p('/var/lib/dpkg/info')
    mismatches = []
    try:
        names = [n for n in os.listdir(info) if n.endswith('.md5sums')]
    except OSError:
        names = []
    for n in names:
        try:
            lines = open(info / n, errors='replace').read().splitlines()
        except OSError:
            continue
        for line in lines:
            md5, _, rel = line.partition('  ')
            logical = '/' + rel
            if not AUTH_PATH_RE.search(logical):
                continue
            try:
                actual = hashlib.md5(open(ev.p(logical), 'rb').read()).hexdigest()
            except OSError:
                continue
            if actual != md5:
                mismatches.append((logical, n[:-8]))
    if mismatches:
        mismatches.sort(key=lambda m: ('security/' not in m[0], m[0]))
        path = maybe_strip_usr(mismatches[0][0], number, ev, question)
        return {'answers': [path], 'confidence': 'high' if len(mismatches) == 1 else 'medium',
                'why': f'{mismatches[0][0]} no longer matches package {mismatches[0][1]}', 'candidates': [m[0] for m in mismatches[:5]]}
    bad = []
    for name in sorted(os.listdir(ev.p('/etc/pam.d'))) if ev.p('/etc/pam.d').is_dir() else []:
        for line in ev.read_text(f'/etc/pam.d/{name}').splitlines():
            if not line.lstrip().startswith('#') and PAM_BAD_LINE.search(line):
                bad.append((f'/etc/pam.d/{name}', line.strip()))
    if bad:
        return {'answers': [bad[0][0]], 'confidence': 'high' if len(bad) == 1 else 'medium', 'why': f'{bad[0][0]}: {bad[0][1]}'}
    return None


def solve_bad_perm_dir(ev, question, number=0):
    cands = []
    for path, expected in CORE_DIR_MODES.items():
        try:
            if ev.p(path).is_symlink():
                continue
            st = os.stat(ev.p(path))
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        if not stat.S_ISDIR(st.st_mode) or mode == expected:
            continue
        if mode & 0o002:
            rank = 0
        elif mode & 0o020 and not expected & 0o020:
            rank = 1
        elif mode & ~expected == 0:
            rank = 3
        else:
            rank = 2
        cands.append((rank, path.count('/'), path, mode))
    # any other world-writable non-sticky directory under system trees
    for base in ('/usr', '/etc', '/var/lib', '/boot', '/opt', '/lib'):
        top = ev.p(base)
        if not top.is_dir() or top.is_symlink():
            continue
        for dirpath, dirs, _ in os.walk(top):
            dirs[:] = [d for d in dirs if not (Path(dirpath) / d).is_symlink() and d not in SKIP_DIR_NAMES]
            try:
                mode = stat.S_IMODE(os.stat(dirpath).st_mode)
            except OSError:
                continue
            logical = ev.logical(dirpath)
            engine = ev.logical(Path(__file__).resolve().parents[1]) if str(Path(__file__).resolve()).startswith(str(ev.root)) else ''
            if engine and (logical == engine or logical.startswith(engine + '/')) or logical.startswith('/opt/engine'):
                continue
            if mode & 0o002 and not mode & 0o1000 and not any(c[2] == logical for c in cands):
                cands.append((0, logical.count('/') + 100, logical, mode))
    if not cands:
        return None
    cands.sort()
    top = cands[0]
    ties = [c for c in cands if c[0] == top[0]]
    return {'answers': [top[2]], 'confidence': 'high' if len(ties) == 1 else 'medium',
            'why': f'{top[2]} has mode {oct(top[3])[2:]}', 'candidates': [c[2] for c in cands[:5]]}


def browser_history_hosts(ev):
    hosts = []
    dbs = []
    for home in ev.user_homes():
        h = ev.p(home)
        for pattern in ('.mozilla/firefox/*/places.sqlite', 'snap/firefox/common/.mozilla/firefox/*/places.sqlite',
                        '.config/google-chrome/*/History', '.config/chromium/*/History', 'snap/chromium/common/chromium/*/History'):
            dbs += list(h.glob(pattern))
    for db in dbs:
        tmp = tempfile.mktemp(suffix='.sqlite')
        try:
            Path(tmp).write_bytes(db.read_bytes())
            con = sqlite3.connect(tmp)
            rows = []
            try:
                rows += con.execute("select url from moz_places").fetchall()
                rows += con.execute("select content from moz_annos where content like 'file:%' or content like 'http%'").fetchall()
            except sqlite3.Error:
                pass
            try:
                rows += con.execute("select tab_url from downloads").fetchall()
                rows += con.execute("select url from urls").fetchall()
            except sqlite3.Error:
                pass
            con.close()
            for (value,) in rows:
                if isinstance(value, str):
                    hosts.append((value, 'browser'))
        except (OSError, sqlite3.Error):
            pass
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return hosts


def solve_download_ip(ev, question, number=0):
    leads = []   # (weight, host, source)
    for home in ev.user_homes():
        for folder in ('Downloads', 'Documents', 'Desktop', 'Templates', 'Public', ''):
            base = ev.p(home) / folder
            if not base.is_dir():
                continue
            for f in ([x for x in base.iterdir() if x.is_file()] if not folder else ev.walk([str(home / folder)], max_depth=3)):
                name = f.name.lower()
                if SKIP_FILE_NAMES.match(f.name) or f.name.startswith('.') and not folder:
                    continue
                if name.endswith(('.xlsm', '.docm', '.pptm', '.xlam', '.xls', '.doc', '.dotm', '.ppt')):
                    macro = office_macro_text(f)
                    for m in CONNECT_CONTENT.finditer(macro):
                        host = m.group(1) or m.group(3) or m.group(5)
                        leads.append((10, host, f'macro in {f.name} connects to it'))
                    for url in re.findall(r'https?://([^\s\'"/:]+)', macro):
                        leads.append((8, url, f'macro in {f.name} references it'))
                try:
                    attrs = os.listxattr(f)
                except (OSError, AttributeError):
                    attrs = []
                for a in attrs:
                    if 'origin.url' in a or 'referrer' in a:
                        try:
                            url = os.getxattr(f, a).decode(errors='ignore')
                            host = re.sub(r'^\w+://([^/:]+).*', r'\1', url)
                            leads.append((9, host, f'{f.name} was downloaded from {url}'))
                        except OSError:
                            pass
                if name.endswith(('.sh', '.py', '.txt', '.url', '.desktop')) and f.stat().st_size < 200_000:
                    text = f.read_text(errors='ignore')
                    for m in re.finditer(r'(?:wget|curl)[^\n]*?https?://([^\s\'"/:]+)', text):
                        leads.append((7, m.group(1), f'{f.name} downloads from it'))
    hist = ev.read_text('/root/.bash_history') + ''.join(ev.read_text(str(h / '.bash_history')) for h in ev.user_homes())
    for m in re.finditer(r'(?:wget|curl)[^\n]*?https?://([^\s\'"/:]+)', hist):
        leads.append((6, m.group(1), 'shell history download'))
    for url, source in browser_history_hosts(ev):
        host = re.sub(r'^\w+://([^/:]+).*', r'\1', url)
        if host and '.' in host and not COMMON_HOSTS.search(host) and not host.startswith('file'):
            leads.append((5, host, 'browser history/download'))
    best = {}
    for weight, host, why in leads:
        host = (host or '').strip().lower()
        if not host or COMMON_HOSTS.search(host):
            continue
        ip = resolve(host)
        if ip and (host not in best or best[host][0] < weight):
            best[host] = (weight, ip, why)
    if not best:
        return None
    host, (weight, ip, why) = max(best.items(), key=lambda kv: kv[1][0])
    ties = [h for h, v in best.items() if v[0] == weight and v[1] != ip]
    return {'answers': [ip], 'confidence': 'high' if weight >= 8 and not ties else 'medium',
            'why': f'{host} -> {ip} ({why})', 'candidates': sorted({v[1] for v in best.values()})}


def solve_file_hash(ev, question, number=0):
    text = question['content']
    algo = 'sha256' if re.search(r'sha-?256', text, re.I) else 'sha1' if re.search(r'sha-?1\b', text, re.I) else 'md5' if re.search(r'md5', text, re.I) else ''
    m = re.search(r'(/[\w./ -]+\.\w+|/[\w./-]+)', text.split('EXAMPLE')[0])
    if not algo or not m:
        return None
    path = ev.p(m.group(1).strip())
    if not path.is_file():
        return None
    return {'answers': [hashlib.new(algo, path.read_bytes()).hexdigest()], 'confidence': 'high', 'why': f'{algo} of {m.group(1)}'}


def solve_base64(ev, question, number=0):
    found = []
    named = {quoted or plain.rstrip('.,;:') for quoted, plain in
             re.findall(r'''["“'](/[^"”'\r\n]+)["”']|(/[\w./-]+)''', question_body(question['content']))}
    files = (ev.p(p) for p in sorted(named)) if named else (
        f for home in ev.user_homes() for f in ev.walk([str(home)], max_depth=3))
    for f in files:
        try:
            if f.is_symlink() or not f.is_file() or not f.resolve().is_relative_to(ev.root.resolve()):
                continue
            if f.stat().st_size > 20000 or (not named and (SKIP_FILE_NAMES.match(f.name) or f.name.startswith('.'))):
                continue
            raw = f.read_text(errors='ignore').strip()
        except OSError:
            continue
        if len(raw) >= (4 if named else 12) and re.fullmatch(r'[A-Za-z0-9+/=\s]+', raw):
            try:
                decoded = base64.b64decode(re.sub(r'\s', '', raw), validate=True).decode('utf-8')
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded.strip() and all(c.isprintable() or c in '\r\n\t' for c in decoded):
                found.append((ev.logical(f), decoded.strip()))
    if not found:
        return None
    return {'answers': [found[0][1]], 'confidence': 'high' if len(found) == 1 else 'medium', 'why': f'base64 text in {found[0][0]}'}


def solve_prohibited_package(ev, question, number=0):
    try:
        import sentinel
    except ImportError:
        return None
    status = ev.read_text('/var/lib/dpkg/status', limit=20_000_000)
    pkgs = re.findall(r'^Package: (\S+)\n(?:(?!^Package:).*\n)*?Status: install ok installed', status, re.M)
    mentioned = ev.readme.lower()
    bad = [p for p in pkgs if p in sentinel.BAD_PACKAGES and p not in mentioned]
    if not bad:
        return None
    return {'answers': [bad[0]], 'confidence': 'medium', 'why': 'installed prohibited package', 'candidates': bad[:6]}


def solve_extra_admin(ev, question, number=0):
    known = {u.lower() for u in ev.users}
    members = [m for g in ('sudo', 'admin') for m in ev.group_members(g)]
    extra = [m for m in members if known and m.lower() not in known]
    if not extra:
        return None
    return {'answers': [extra[0]], 'confidence': 'medium', 'why': f'{extra[0]} is a sudo member not listed in the README', 'candidates': extra}


def solve_cron(ev, question, number=0):
    cands = []
    for rel in ['/etc/crontab'] + [f'/etc/cron.d/{n}' for n in (os.listdir(ev.p('/etc/cron.d')) if ev.p('/etc/cron.d').is_dir() else [])]:
        for line in ev.read_text(rel).splitlines():
            if not line.strip().startswith('#') and re.search(r'/tmp/|/dev/shm|nc |ncat|bash -i|curl|wget|python|/home/', line):
                cands.append((rel, line.strip()))
    if not cands:
        return None
    return {'answers': [cands[0][0]], 'confidence': 'medium', 'why': cands[0][1]}


MEDIA_GROUPS = {
    'audio': {'mp3', 'wav', 'flac', 'ogg', 'oga', 'opus', 'm4a', 'aac', 'wma', 'mid', 'midi'},
    'video': {'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'mpg', 'mpeg', 'm4v'},
    'picture': {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg'},
    'document': {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'txt', 'csv'},
    'archive': {'zip', 'tar', 'gz', 'rar', '7z', 'bz2', 'xz'},
}


def solve_file_dir(ev, question, number=0):
    """'Which directory holds the (mp3 / video / picture ...) files?' - the folder with most such files."""
    text = question_body(question['content']).lower()
    exts = set(re.findall(r'\.([a-z0-9]{2,5})\b', text)) & set().union(*MEDIA_GROUPS.values())
    keywords = {'audio': r'audio|music|song', 'video': r'video|movie',
                'picture': r'picture|photo', 'document': r'document', 'archive': r'archive'}
    for name, group in MEDIA_GROUPS.items():
        if re.search(r'\b(?:' + keywords[name] + r')s?\b', text):
            exts |= group
    for ext in set().union(*MEDIA_GROUPS.values()):
        if re.search(r'\b' + ext + r'\b', text):
            exts.add(ext)
    if re.search(r'\bmedia\b', text):
        exts |= MEDIA_GROUPS['audio'] | MEDIA_GROUPS['video'] | MEDIA_GROUPS['picture']
    if not exts:
        return None
    counts = {}
    for f in ev.walk(['/home', '/root', '/srv', '/opt', '/mnt', '/media', '/var/www', '/tmp', '/usr/local', '/var/tmp'], max_depth=8):
        if f.suffix.lower().lstrip('.') in exts and not f.is_symlink():
            logical = ev.logical(f.parent)
            if any(x in logical for x in ('/.cache', '/.local', '/snap/', '/.mozilla', '/.config', '/node_modules', 'cp-linux-setup')):
                continue
            counts[logical] = counts.get(logical, 0) + 1
    if not counts:
        return None
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].count('/'), kv[0]))
    best = ranked[0]
    tie = len(ranked) > 1 and ranked[1][1] == best[1]
    return {'answers': [best[0]], 'confidence': 'medium' if tie else 'high',
            'why': f'{best[1]} matching file(s) in {best[0]}', 'candidates': [r[0] for r in ranked[:5]]}


def solve_log_actor(ev, question, number=0):
    """Answer only explicit actor/action/artifact records, never nearby names."""
    body = question_body(question['content'])
    artifacts = set(re.findall(r'(?<![\w.-])([\w@.-]+\.(?:timer|service|socket|sh|py))(?![\w.-])', body))
    action = re.search(r'\b(installed|created|modified|enabled|started|deleted)\b', body, re.I)
    if len(artifacts) != 1 or not action:
        return None
    artifact = next(iter(artifacts))
    known = {row['name'] for row in ev.passwd()}
    actor_pattern = re.compile(r'(?<![\w.-])([a-z_][a-z0-9_.-]*)\s+' + re.escape(action.group()) + r'\b', re.I)
    matches = {}
    budget = 20_000_000
    paths = sorted(ev.p('/var/log').glob('*.log')) + sorted(ev.p('/var/log').glob('*/*.log'))
    for path in paths[:200]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            continue
        budget -= path.stat().st_size
        if budget < 0:
            return None  # Do not declare uniqueness after exhausting the scan budget.
        for line_number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            if not re.search(r'(?<![\w.-])' + re.escape(artifact) + r'(?![\w.-])', line):
                continue
            found = actor_pattern.search(line)
            if found and found.group(1) in known:
                matches.setdefault(found.group(1), []).append(f'{ev.logical(path)}:{line_number}: {line[:300]}')
    if len(matches) == 1:
        actor = next(iter(matches))
        return {'answers': [actor], 'confidence': 'high',
                'why': 'Explicit actor/action/artifact log evidence: ' + matches[actor][0]}
    return None


def solve_uid_zero(ev, question, number=0):
    candidates = [u['name'] for u in ev.passwd() if u['uid'] == 0 and u['name'] != 'root']
    if len(candidates) != 1:
        return None
    return {'answers': candidates, 'confidence': 'high', 'why': 'Unique non-root account with UID 0 in /etc/passwd'}


SOLVERS = [
    (re.compile(r'(which|what).*(account|user).*(installed|created|modified|enabled|started|deleted)', re.I), solve_log_actor, 'user'),
    (re.compile(r'\b(?:uid|user id)\s*(?:of\s*)?(?:=|:)?\s*0\b', re.I), solve_uid_zero, 'user'),
    (re.compile(r'(director|folder|path|location).{0,80}(mp3|mp4|music|audio|video|media|picture|photo|\.\w{3,4} files)|(mp3|mp4|music|audio|video|media)[^.\n]{0,60}(director|folder|located|location)', re.I | re.S), solve_file_dir, 'path'),
    (re.compile(r'hidden (user|account)|secret (user|account)|user.*(was|has been) created.*(after|attack)|malicious.*user(name)?', re.I), solve_hidden_user, 'user'),
    (re.compile(r'(authentication|login|password).*(sabotag|tamper|modif|broken|backdoor|mechanism)|sabotag.*(authentication|pam)|(pam|authentication).*(file|path)', re.I), solve_auth_file, 'path'),
    (re.compile(r'(back ?door|persistence).*(file|path|script|program)|(file|path).*(back ?door|persistence)', re.I), solve_backdoor_file, 'path'),
    (re.compile(r'(permission|chmod|writable|ownership).*(director|folder)|(director|folder).*(permission|chmod|writable)', re.I), solve_bad_perm_dir, 'path'),
    (re.compile(r'ip address|which ip|what ip|ip of', re.I), solve_download_ip, 'ip'),
    (re.compile(r'(md5|sha-?1|sha-?256).*(hash|sum|checksum|of)|hash of', re.I), solve_file_hash, 'hash'),
    (re.compile(r'base-?64|decoded? (message|text)|secret message|encoded message', re.I), solve_base64, 'text'),
    (re.compile(r'(unauthorized|extra|unexpected|rogue).*(admin|sudo)|sudo.*(not|shouldn)', re.I), solve_extra_admin, 'user'),
    (re.compile(r'(prohibited|hacking|unauthorized|malicious|installed).*(program|software|package|tool)', re.I), solve_prohibited_package, 'package'),
    (re.compile(r'cron|scheduled task', re.I), solve_cron, 'path'),
]


def question_body(content):
    """Question text without the instructions header and the example line."""
    text = re.sub(r'(?is)^.*?-{5,}\s*', '', content, count=1)
    return re.split(r'(?im)^\s*(EXAMPLE|ANSWER)\s*:', text)[0].strip()


def solve(question, ev):
    body = question_body(question['content'])
    for pattern, func, _kind in SOLVERS:
        if pattern.search(body):
            try:
                result = func(ev, {'content': question['content']}, question.get('number', 0))
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                result = None
                print(f"  solver {func.__name__} failed: {error}", file=sys.stderr)
            if result:
                result['solver'] = func.__name__
                return result
    return None


def run(directories, root='/', readme_text='', dry=False, guess=False, backup_dir=None):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import forensics_agent as fa
    ev = Evidence(root, readme_text, users=readme_users(readme_text))
    questions = fa.discover(directories)
    out = []
    if backup_dir is not None and not dry:
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        backup_dir = Path(tempfile.mkdtemp(prefix='run-', dir=backup_dir))
    for q in questions:
        lines = q['content'].splitlines()
        placeholders = [l for l in lines if re.match(r'^\s*ANSWER\s*:', l, re.I)]
        have = [fa.clean_answer_value(m.group(1)) for l in lines for m in [re.match(r'^\s*ANSWER\s*:\s*(.*)$', l, re.I)] if m]
        if placeholders and all(not fa.is_unanswered_placeholder(a) for a in have):
            out.append({'number': q['number'], 'status': 'already-answered'})
            continue
        result = solve(q, ev)
        entry = {'number': q['number'], 'path': q['path'], 'result': result}
        if result and len(placeholders) == len(result['answers']) and (result['confidence'] == 'high' or guess):
            if not dry:
                try:
                    fa.apply_answers(q, result['answers'], Path(backup_dir) if backup_dir else Path(tempfile.mkdtemp(prefix='forensics-det-')))
                    entry['status'] = 'applied'
                except (ValueError, OSError) as error:
                    entry['status'] = f'not applied: {error}'
            else:
                entry['status'] = 'dry-run'
        else:
            entry['status'] = 'unsolved'
        out.append(entry)
    return out


def readme_users(readme_html):
    names = set()
    text = re.sub(r'<[^>]+>', '\n', readme_html or '')
    for m in re.finditer(r'^\s*([a-z_][a-z0-9_-]{1,31})\b(?::\S+)?(?:\s*\(.*\))?\s*$', text, re.M | re.I):
        names.add(m.group(1))
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='/')
    parser.add_argument('--dir', action='append')
    parser.add_argument('--readme')
    parser.add_argument('--dry', action='store_true')
    parser.add_argument('--no-guess', action='store_true')
    parser.add_argument('--guess', action='store_true', help='Opt in to applying ambiguous medium-confidence suggestions')
    parser.add_argument('--report', default=str(Path(__file__).resolve().parents[1] / 'data/forensics-det.json'))
    args = parser.parse_args()
    readme = ''
    for candidate in filter(None, [args.readme, os.environ.get('README_FILE'), str(Path(__file__).resolve().parents[1] / 'data/auto-source.html')]):
        try:
            readme = Path(candidate).read_text(encoding='utf-8', errors='ignore')
            break
        except OSError:
            continue
    dirs = [Path(d) for d in args.dir] if args.dir else list(Path(args.root, 'home').glob('*/Desktop')) + [Path(args.root, 'root/Desktop')]
    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    results = run(dirs, args.root, readme, args.dry, guess=args.guess and not args.no_guess, backup_dir=report.parent / 'forensics-det-backups')
    report.write_text(json.dumps(results, indent=2), encoding='utf-8')
    for r in results:
        res = r.get('result') or {}
        print(f"Question {r['number']}: {r['status']} -> {res.get('answers')} [{res.get('confidence', '-')}] {res.get('why', '')}", flush=True)
    return 0 if all(r['status'] in ('applied', 'already-answered', 'dry-run') for r in results) else 2


if __name__ == '__main__':
    sys.exit(main())
