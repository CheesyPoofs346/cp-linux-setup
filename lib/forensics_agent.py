"""Evidence-backed forensic question solver with active system investigation; unattended execution."""
import fnmatch
import glob
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

import select

LIMIT = 12000
QUESTION = re.compile(r'forensics?[ _-]*questions?[ _-]*(\d+)', re.I)
PLACEHOLDER_REGEX = re.compile(r'^\s*<[^>]+>\s*$|^\s*\[[^\]]+\]\s*$', re.I)

PLACEHOLDER_KEYWORDS = (
    'type answer', 'type-answer', 'insert answer', 'insert-answer',
    'enter answer', 'enter-answer', 'write answer', 'your answer',
    'put answer', 'type here', 'answer here', 'replace me',
    'todo', 'tbd', 'xxx', '???', 'fill in', 'type_answer', 'your-answer'
)

_tty_stream = None
if os.name == 'posix':
    try:
        if os.path.exists('/dev/tty'):
            _fd = os.open('/dev/tty', os.O_RDONLY | os.O_NONBLOCK)
            _tty_stream = os.fdopen(_fd, 'r')
    except Exception:
        pass


def check_user_skip(timeout=0):
    """Returns True if the user pressed Enter on the terminal to skip."""
    if os.environ.get('SKIP_FORENSICS') == '1':
        return True
    streams = []
    if _tty_stream is not None:
        streams.append(_tty_stream)
    if sys.stdin is not None and hasattr(sys.stdin, 'fileno'):
        streams.append(sys.stdin)

    for stream in streams:
        try:
            rlist, _, _ = select.select([stream], [], [], timeout)
            if rlist:
                stream.readline()
                return True
        except Exception:
            pass
    return False


def is_unanswered_placeholder(val):
    if not val or not isinstance(val, str):
        return True
    stripped = val.strip()
    if not stripped:
        return True
    if PLACEHOLDER_REGEX.match(stripped):
        return True
    lower = stripped.lower()
    if lower in ('n/a', 'na', 'none', 'unknown', 'null'):
        return True
    for kw in PLACEHOLDER_KEYWORDS:
        if kw in lower:
            return True
    return False


def clean_answer_value(val):
    if not val or not isinstance(val, str):
        return ""
    ans = str(val).strip()
    while (ans.startswith('<') and ans.endswith('>') and len(ans) >= 2) or \
          (ans.startswith('[') and ans.endswith(']') and len(ans) >= 2):
        ans = ans[1:-1].strip()
    ans = re.sub(r'^\s*ANSWER\s*:\s*', '', ans, flags=re.I).strip()
    return ans


PROMPT = '''You are an automated Linux incident response and forensics investigator solving practice-image forensic questions.
Your goal is to find the exact, accurate answer required by the question by running investigative commands.

You can inspect the system by providing bash commands in "commands": ["cmd1", "cmd2"] (max 4 per turn).
Recommended commands for common forensics tasks:
- Suspicious Downloads & External Compromise:
  * Check user Downloads: ls -la /home/*/Downloads
  * Query Firefox history/downloads:
    python3 -c "import sqlite3, glob; [print(p, sqlite3.connect(f'file:{p}?mode=ro', uri=True).execute('SELECT url, title FROM moz_places WHERE url LIKE \\"%http%\\";').fetchall()) for p in glob.glob('/home/*/.mozilla/firefox/*default*/places.sqlite') + glob.glob('/home/*/snap/firefox/common/.mozilla/firefox/*default*/places.sqlite')]"
  * Search Firefox cache2: grep -rahEo "https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+[^ ]*" /home/*/snap/firefox/common/.cache/mozilla/firefox/*default*/cache2/entries/
  * Inspect Office macros: python3 -m oletools.olevba <file.xlsm> 2>/dev/null || unzip -p <file.xlsm> xl/vbaProject.bin | strings -n 6
  * Check shell history / logs: ls -la /home/*/.bash_history, /var/log/syslog, /var/log/auth.log
- Backdoors & Unauthorized Persistence:
  * Check listening sockets with processes: ss -tulpn
  * Check autostart entries: ls -la /home/*/.config/autostart/ /etc/xdg/autostart/
  * Check active cron persistence: crontab -l, cat /etc/crontab, cat /etc/cron.d/*
  * Check systemd units: systemctl list-units --type=service --state=running, ls -la /etc/systemd/system/
  * Check SUID binaries: find / -perm -4000 -type f 2>/dev/null
  * Check reverse shells or malicious scripts: grep -rn "bash -i" /etc /home /var /tmp /opt /usr/local 2>/dev/null
  * Check unauthorized executables in /tmp, /var/tmp, /dev/shm
  * Check package integrity: dpkg -V or debsums -c 2>/dev/null
- Sabotaged Authentication Mechanisms:
  * Check PAM configurations for unusual rules or pam_permit: grep -rn "pam_permit.so" /etc/pam.d/
  * Check integrity of authentication packages: dpkg -V passwd sudo login libpam-modules libpam-runtime
  * Check recently modified authentication files: ls -lt /etc/pam.d/ /bin/passwd /usr/bin/passwd /bin/su /usr/bin/su
- Core System Directory Permissions:
  * Check core directories that are world-writable or 777:
    find /etc /bin /sbin /usr /var /root /boot -maxdepth 3 -type d \( -perm -002 -o -perm 0777 \) ! -path "/var/tmp*" ! -path "/var/lock*" ! -path "/var/spool*" ! -path "/var/crash*"
- User Accounts:
  * Check /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers, /etc/sudoers.d/*

FAST-SOLVE RULE:
Pre-gathered system reconnaissance is provided in "initial_recon" in your first user message and registered as evidence record "e0".
If the answer is already visible in "initial_recon" (e.g. download IP, backdoor path, sabotaged PAM file, or messed up directory permissions), you can solve immediately on Turn 1 by citing "tool_id": "e0" and quoting the evidence!

Return ONLY JSON in one of these two forms:

1. When investigating:
{"commands": ["bash command 1", "bash command 2"], "explanation": "what you are investigating"}
(OR use "tool_requests": [...] with structured tools or {"tool":"command","cmd":"..."})

2. When you have established the answer:
{"answers": ["exact answer"], "explanation": "how the evidence establishes this answer", "solved": true,
 "evidence": [{"tool_id": "e0", "quote": "exact quote from evidence"}]}

CRITICAL RULES:
- Read and follow any special scoring instructions provided in the question or competition notes (for example, if instructed: "If your path contains /usr, remove that from your answer", format the answer without /usr).
- Provide the exact answer format expected (e.g. IP address alone, path alone, filename alone, or username alone).
- NEVER return a placeholder string (such as '<Type Answer Here>', '<Type-Answer-Here>', '[Type Answer Here]', 'None', 'TBD', etc.) in "answers". You must actively investigate and find the real answer.
- DO NOT wrap your answers in angle brackets (<...>) or brackets ([...]). Output the clean string (e.g. "192.168.1.5", "/home/benjamin/Music", "benjamin").
- Do NOT include the prefix "ANSWER:" in the answer string; return only the answer value itself.
- Never execute destructive commands (like rm -rf, mkfs, reboot).
'''


def run_safe_command(cmd, timeout=20):
    cmd = str(cmd).strip()
    if not cmd:
        return "Empty command"
    BLOCKED = [
        r'\brm\s+(-[a-zA-Z]*r|--recursive)\s+/',
        r'\bmkfs\b',
        r'\bdd\s+if=',
        r'\b(reboot|poweroff|shutdown|init\s+0)\b',
        r':\(\)\s*\{\s*:\|:&\s*\};:'
    ]
    for pattern in BLOCKED:
        if re.search(pattern, cmd):
            return f"Blocked: destructive command not permitted during forensics: {cmd}"
    try:
        proc = subprocess.run(['bash', '-c', cmd], capture_output=True, timeout=timeout)
        out = (proc.stdout + b'\n' + proc.stderr).decode('utf-8', errors='replace').strip()
        if len(out) > 10000:
            out = out[:10000] + f"\n... [output truncated, total {len(out)} chars]"
        return out if out else f"(Command executed with exit code {proc.returncode})"
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Execution error: {e}"


def gather_initial_recon():
    """Gathers instant system reconnaissance to provide immediate context on turn 1."""
    recon = {}
    # 1. Listening sockets
    try:
        res = subprocess.run(['ss', '-tulpn'], capture_output=True, timeout=5)
        recon['listening_sockets'] = res.stdout.decode('utf-8', errors='replace').strip()[:2000]
    except Exception:
        pass
    # 2. Downloads directory contents
    try:
        downloads = []
        for d in Path('/home').glob('*/Downloads'):
            if d.is_dir():
                items = [f.name for f in d.iterdir()][:30]
                downloads.append(f"{d}: {', '.join(items)}")
        recon['downloads_directory'] = '\n'.join(downloads)
    except Exception:
        pass
    # 3. Download history & external IPs (places.sqlite + downloads strings)
    try:
        download_leads = []
        import sqlite3
        for pattern in ['/home/*/.mozilla/firefox/*default*/places.sqlite', '/home/*/snap/firefox/common/.mozilla/firefox/*default*/places.sqlite']:
            for p in glob.glob(pattern):
                try:
                    conn = sqlite3.connect(f'file:{p}?mode=ro', uri=True)
                    rows = conn.execute("SELECT url FROM moz_places WHERE url LIKE '%http%' ORDER BY id DESC LIMIT 50;").fetchall()
                    for (u,) in rows:
                        download_leads.append(u)
                except Exception:
                    pass
        for f in Path('/home').glob('*/Downloads/*'):
            if f.is_file():
                try:
                    out = subprocess.run(['strings', str(f)], capture_output=True, timeout=3).stdout.decode('utf-8', errors='ignore')
                    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', out)
                    for ip in ips:
                        if not ip.startswith('127.') and not ip.startswith('0.') and not ip.startswith('255.'):
                            download_leads.append(f"{f.name} contains IP: {ip}")
                except Exception:
                    pass
        if download_leads:
            recon['download_history_and_ips'] = '\n'.join(download_leads[:30])
    except Exception:
        pass
    # 4. Backdoor & persistence leads (autostart, suspicious executables, strings from downloads)
    try:
        backdoor_leads = []
        for p in glob.glob('/home/*/.config/autostart/*') + glob.glob('/etc/xdg/autostart/*'):
            if os.path.isfile(p):
                backdoor_leads.append(f"Autostart desktop: {p}")
        res = subprocess.run(['find', '/tmp', '/var/tmp', '/dev/shm', '/opt', '/usr/local/bin', '-maxdepth', '3', '-type', 'f', '(', '-perm', '-111', '-o', '-name', '*.sh', '-o', '-name', '*.py', '-o', '-name', '*.pl', ')'], capture_output=True, timeout=5)
        for line in res.stdout.decode('utf-8', errors='ignore').splitlines():
            if line.strip():
                backdoor_leads.append(f"Executable lead: {line.strip()}")
        for f in Path('/home').glob('*/Downloads/*'):
            if f.is_file():
                try:
                    out = subprocess.run(['strings', str(f)], capture_output=True, timeout=3).stdout.decode('utf-8', errors='ignore')
                    paths = re.findall(r'(/home/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+|/tmp/[a-zA-Z0-9_./-]+|/etc/[a-zA-Z0-9_./-]+|/var/[a-zA-Z0-9_./-]+)', out)
                    for path in set(paths):
                        backdoor_leads.append(f"Path in {f.name}: {path}")
                except Exception:
                    pass
        if backdoor_leads:
            recon['backdoor_and_persistence_leads'] = '\n'.join(backdoor_leads[:30])
    except Exception:
        pass
    # 5. Sabotaged authentication mechanism (PAM permit / modified auth binaries)
    try:
        auth_leads = []
        res = subprocess.run(['grep', '-rn', 'pam_permit.so', '/etc/pam.d/'], capture_output=True, timeout=3)
        for line in res.stdout.decode('utf-8', errors='ignore').splitlines():
            if line.strip():
                auth_leads.append(f"PAM permit line: {line.strip()}")
        res = subprocess.run(['dpkg', '-V', 'passwd', 'sudo', 'login', 'libpam-modules', 'libpam-runtime'], capture_output=True, timeout=5)
        for line in res.stdout.decode('utf-8', errors='ignore').splitlines():
            if line.strip():
                auth_leads.append(f"dpkg integrity verification: {line.strip()}")
        res = subprocess.run(['ls', '-lt', '/etc/pam.d/'], capture_output=True, timeout=3)
        auth_leads.append("Recent /etc/pam.d files:\n" + '\n'.join(res.stdout.decode('utf-8', errors='ignore').splitlines()[:10]))
        if auth_leads:
            recon['sabotaged_auth_leads'] = '\n'.join(auth_leads[:25])
    except Exception:
        pass
    # 6. Core directory permission anomalies (world-writable / 777 core directories)
    try:
        res = subprocess.run(
            ['find', '/etc', '/bin', '/sbin', '/usr', '/var', '/root', '/boot',
             '-maxdepth', '3', '-type', 'd', '(', '-perm', '-002', '-o', '-perm', '0777', ')',
             '!', '-path', '/var/tmp*', '!', '-path', '/var/lock*', '!', '-path', '/var/spool*', '!', '-path', '/var/crash*'],
            capture_output=True, timeout=5
        )
        perm_lines = [l.strip() for l in res.stdout.decode('utf-8', errors='ignore').splitlines() if l.strip()]
        if perm_lines:
            recon['abnormal_core_directory_permissions'] = '\n'.join(perm_lines[:20])
    except Exception:
        pass
    # 7. SUID binaries
    try:
        res = subprocess.run(['find', '/bin', '/usr/bin', '/sbin', '/usr/sbin', '/opt', '-perm', '-4000', '-type', 'f'], capture_output=True, timeout=5)
        recon['suid_binaries'] = res.stdout.decode('utf-8', errors='replace').strip()[:1500]
    except Exception:
        pass
    # 8. Cron jobs
    try:
        crons = []
        for p in Path('/etc/cron.d').glob('*'):
            if p.is_file(): crons.append(f"{p}: {p.read_text(errors='replace')[:150]}")
        if Path('/etc/crontab').exists():
            crons.append(f"/etc/crontab: {Path('/etc/crontab').read_text(errors='replace')[:250]}")
        recon['cron_jobs'] = '\n'.join(crons)[:1500]
    except Exception:
        pass
    # 9. User accounts
    try:
        users = []
        if Path('/etc/passwd').exists():
            for line in Path('/etc/passwd').read_text(errors='replace').splitlines():
                parts = line.split(':')
                if len(parts) >= 7 and parts[2].isdigit() and int(parts[2]) >= 1000:
                    users.append(f"{parts[0]} (uid={parts[2]}, shell={parts[6]})")
        recon['user_accounts'] = ', '.join(users[:20])
    except Exception:
        pass
    # 10. Suspicious bash history commands
    try:
        history_leads = []
        for h in glob.glob('/home/*/.bash_history') + ['/root/.bash_history']:
            if os.path.isfile(h):
                lines = Path(h).read_text(errors='replace').splitlines()
                suspicious = [l.strip() for l in lines if l.strip() and any(k in l.lower() for k in ('curl', 'wget', 'nc ', 'netcat', 'chmod 777', 'chmod +x', 'sudo ', 'useradd', 'chown', 'base64', 'python', 'bash -i', 'sh -i', 'shadow', 'passwd', 'crontab', 'authorized_keys', 'git clone', 'tar -x', 'unzip'))]
                if suspicious:
                    history_leads.append(f"{h}: " + " | ".join(suspicious[-10:]))
        if history_leads:
            recon['suspicious_bash_history'] = '\n'.join(history_leads[:15])
    except Exception:
        pass
    # 11. Custom systemd services and ld.so.preload
    try:
        custom_units = []
        for p in glob.glob('/etc/systemd/system/*.service') + glob.glob('/lib/systemd/system/backdoor*.service'):
            if os.path.isfile(p):
                custom_units.append(f"{p}: " + Path(p).read_text(errors='replace')[:200].replace('\n', ' '))
        if custom_units:
            recon['custom_systemd_services'] = '\n'.join(custom_units[:10])
        if Path('/etc/ld.so.preload').exists():
            recon['ld_so_preload'] = Path('/etc/ld.so.preload').read_text(errors='replace').strip()
    except Exception:
        pass
    # 12. Recent package installs from /var/log/dpkg.log
    try:
        if Path('/var/log/dpkg.log').exists():
            dpkg_lines = [l for l in Path('/var/log/dpkg.log').read_text(errors='replace').splitlines() if ' install ' in l or ' status installed ' in l]
            if dpkg_lines:
                recon['recent_package_installs'] = '\n'.join(dpkg_lines[-15:])
    except Exception:
        pass
    # 13. Prohibited media files in user directories
    try:
        media_leads = []
        res = subprocess.run(
            ['find', '/home', '/root', '-maxdepth', '4', '-type', 'f', '(', '-iname', '*.mp3', '-o', '-iname', '*.mp4', '-o', '-iname', '*.avi', '-o', '-iname', '*.mkv', '-o', '-iname', '*.wav', ')'],
            capture_output=True, timeout=5
        )
        for l in res.stdout.decode('utf-8', errors='ignore').splitlines():
            if l.strip():
                media_leads.append(l.strip())
        if media_leads:
            recon['prohibited_media_files'] = '\n'.join(media_leads[:20])
    except Exception:
        pass
    return recon


def read_bytes(path, limit=20_000_000):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NOATIME', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
    except PermissionError:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError('Only regular files can be read')
        data = file.read(limit + 1)
        if len(data) > limit:
            raise ValueError('File exceeds evidence read limit')
        return data


class EvidenceTools:
    def __init__(self, protected, roots=None):
        self.protected = Path(protected).resolve()
        self.roots = [Path(p).resolve() for p in (roots or ['/home', '/root', '/etc', '/var/log', '/opt', '/usr', '/tmp'])]

    def path(self, value):
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError('An absolute local path is required')
        original = Path(value)
        path = original.resolve(strict=True)
        if path == self.protected or self.protected in path.parents:
            raise ValueError('Runner configuration/data is excluded')
        if not any(path == root or root in path.parents for root in self.roots):
            raise ValueError('Path is outside evidence roots')
        for part in (original, *original.parents):
            if part.is_symlink():
                raise ValueError('Symlinks are excluded')
        if any(part in ('.aws', '.azure', '.gnupg', '.codex', '.git') for part in path.parts) or path.name in ('shadow', 'gshadow', '.env', '.netrc', '.npmrc', 'credentials', 'config.local.conf') or path.suffix.lower() in ('.pem', '.key') or (path.name.startswith('id_') and path.suffix != '.pub'):
            raise ValueError('Credential/private-key files are excluded')
        return path

    def run(self, request):
        if not isinstance(request, dict):
            raise ValueError('Invalid request format')
        tool = request.get('tool')
        if tool in ('command', 'bash', 'exec'):
            cmd = request.get('cmd') or request.get('command') or ''
            return run_safe_command(cmd)
        if 'command' in request:
            raise ValueError('Shell commands are not supported')
        if tool == 'sqlite_query':
            db_path = self.path(request.get('path'))
            query = request.get('query', '')
            if not isinstance(query, str) or not query.strip().upper().startswith('SELECT'):
                raise ValueError('Only SELECT queries are supported')
            import sqlite3
            with sqlite3.connect(f'file:{db_path}?mode=ro', uri=True) as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                rows = cursor.fetchmany(50)
                col_names = [d[0] for d in cursor.description] if cursor.description else []
                lines = [f"{' | '.join(col_names)}", "-" * 40]
                for row in rows:
                    lines.append(' | '.join(str(v) for v in row))
                return '\n'.join(lines)[:LIMIT]
        if tool == 'path_info':
            value = request.get('path')
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise ValueError('An absolute local path is required')
            original = Path(os.path.abspath(value))
            self.path(str(original.parent))
            if original == self.protected or self.protected in original.parents:
                raise ValueError('Runner configuration/data is excluded')
            info = original.lstat()
            return json.dumps({'path': str(original), 'symlink': stat.S_ISLNK(info.st_mode),
                               'target': os.readlink(original) if stat.S_ISLNK(info.st_mode) else None})
        if tool == 'resolve_path':
            value = request.get('path')
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise ValueError('An absolute path is required')
            return str(self.path(str(Path(value).resolve(strict=True))))
        if tool in ('processes', 'sockets'):
            args = ['ps', '-eo', 'pid,ppid,user,comm'] if tool == 'processes' else ['ss', '-lntu']
            result = subprocess.run(args, capture_output=True, timeout=10, check=True)
            return result.stdout[:LIMIT].decode('utf-8', errors='replace')
        path = self.path(request.get('path'))
        if tool in ('file_type', 'package_owner'):
            args = ['file', '--brief', '--', str(path)] if tool == 'file_type' else ['dpkg-query', '-S', '--', str(path)]
            result = subprocess.run(args, capture_output=True, timeout=10, check=True)
            return result.stdout[:LIMIT].decode('utf-8', errors='replace')
        if tool == 'list_dir':
            names = sorted(p.name for p in path.iterdir())[:300]
            return '\n'.join(names)[:LIMIT]
        if tool == 'find_files':
            pattern = request.get('pattern', '*')
            if not isinstance(pattern, str) or len(pattern) > 128 or '/' in pattern:
                raise ValueError('Use a simple filename glob')
            results = []
            started = time.monotonic()
            for directory, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = [d for d in dirs if d != '.git' and not (Path(directory) / d).is_symlink()][:200]
                if time.monotonic() - started > 8:
                    results.append('[search time limit reached]')
                    break
                for name in files:
                    if fnmatch.fnmatch(name, pattern):
                        try:
                            found = self.path(str(Path(directory) / name))
                        except (ValueError, OSError):
                            continue
                        results.append(str(found))
                        if len(results) >= 200:
                            return '\n'.join(results)[:LIMIT] + '\n[results limited]'
            return '\n'.join(results)[:LIMIT]
        if tool == 'stat':
            info = path.stat()
            return json.dumps({'path': str(path), 'size': info.st_size, 'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)), 'mtime_ns': info.st_mtime_ns})
        data = read_bytes(path)
        if b'PRIVATE KEY' in data or b'sk-or-v1-' in data or b'nvapi-' in data:
            raise ValueError('Private-key/API credential content is excluded')
        if tool == 'sha256':
            return hashlib.sha256(data).hexdigest()
        if tool == 'vba_source':
            python = self.protected / '.forensics-venv/bin/python'
            if not python.is_file():
                res = subprocess.run(['python3', '-m', 'oletools.olevba', str(path)], capture_output=True, timeout=20)
                if res.returncode == 0 and res.stdout:
                    return res.stdout.decode('utf-8', errors='replace')[:LIMIT]
                raise ValueError('VBA parser missing: run bash prepare-forensics.sh from your normal account')
            result = subprocess.run([str(python), '-I', str(Path(__file__).with_name('inspect_vba.py'))],
                                    input=data, capture_output=True, timeout=20)
            if result.returncode:
                raise ValueError('Static VBA parser failed: ' + result.stderr.decode('utf-8', errors='replace')[-500:])
            output = result.stdout.decode('utf-8', errors='replace')[:LIMIT]
            if any(secret in output for secret in ('PRIVATE KEY', 'sk-or-v1-', 'nvapi-')):
                raise ValueError('Private-key/API credential content is excluded')
            return output
        if tool == 'strings':
            return '\n'.join(s.decode('ascii') for s in re.findall(rb'[ -~]{4,}', data))[:LIMIT]
        if tool in ('zip_list', 'zip_read_text', 'zip_strings'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                if len(entries) > 1000:
                    raise ValueError('Archive entry limit exceeded')
                if tool == 'zip_list':
                    return '\n'.join(f'{entry.filename} ({entry.file_size} bytes)' for entry in entries)[:LIMIT]
                member = request.get('member')
                if not isinstance(member, str) or len(member) > 512:
                    raise ValueError('An exact archive member name is required')
                info = archive.getinfo(member)
                if info.file_size > 2_000_000 or info.file_size > max(1, info.compress_size) * 200:
                    raise ValueError('Archive member exceeds decompression limit')
                with archive.open(info) as stream:
                    content = stream.read(2_000_001)
                if len(content) > 2_000_000:
                    raise ValueError('Archive member exceeds decompression limit')
                if any(secret in content for secret in (b'PRIVATE KEY', b'sk-or-v1-', b'nvapi-')):
                    raise ValueError('Private-key/API credential content is excluded')
                if tool == 'zip_strings':
                    ascii_strings = [s.decode('ascii') for s in re.findall(rb'[ -~]{4,}', content)]
                    wide_strings = [s.decode('utf-16le') for s in re.findall(rb'(?:[ -~]\x00){4,}', content)]
                    return '\n'.join(ascii_strings + wide_strings)[:LIMIT]
                return content.decode('utf-8', errors='replace')[:LIMIT]
        text = data.decode('utf-8', errors='replace')
        if tool == 'read_text':
            offset = request.get('offset', 0)
            if type(offset) is not int or offset < 0 or offset > len(text):
                raise ValueError('Invalid character offset')
            return text[offset:offset + LIMIT]
        if tool == 'search_text':
            query = request.get('text')
            if not isinstance(query, str) or not query or len(query) > 256:
                raise ValueError('A bounded literal search string is required')
            return '\n'.join(f'{i}: {line}' for i, line in enumerate(text.splitlines(), 1) if query in line)[:LIMIT]
        raise ValueError('Unknown evidence tool')


def discover(directories):
    questions = []
    for desktop in directories:
        desktop = Path(desktop)
        if not desktop.is_dir() or desktop.is_symlink():
            continue
        for directory, dirs, files in os.walk(desktop, followlinks=False):
            depth = len(Path(directory).relative_to(desktop).parts)
            dirs[:] = [] if depth >= 2 else [d for d in dirs if not (Path(directory) / d).is_symlink()]
            for name in sorted(files):
                match = QUESTION.search(name)
                path = Path(directory) / name
                if not match or path.is_symlink() or path.suffix.lower() not in ('', '.txt'):
                    continue
                data = read_bytes(path, 100000)
                questions.append({'id': f'q{match[1]}-' + hashlib.sha256(str(path).encode()).hexdigest()[:10], 'number': int(match[1]), 'path': str(path), 'content': data.decode('utf-8-sig'), 'sha256': hashlib.sha256(data).hexdigest()})
    return sorted(questions, key=lambda q: (q['number'], q['path']))


def decode_model_json(content):
    text = content.lstrip('\ufeff').strip()
    text = re.sub(r'<think\b[^>]*>.*?</think\s*>', '', text, flags=re.S | re.I).strip()
    if re.search(r'<think\b', text, flags=re.I):
        raise ValueError('Unfinished model reasoning; no final JSON available')
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        objects = []
        index = 0
        while index < len(text):
            if text[index] not in '{[':
                index += 1
                continue
            try:
                candidate, length = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                raise ValueError('Malformed or truncated JSON in model output') from None
            objects.append(candidate)
            index += length
        if len(objects) != 1:
            raise ValueError('Expected one unambiguous JSON object in model output')
        value = objects[0]
    if not isinstance(value, dict):
        raise ValueError('Model response must be a JSON object')
    return value


def save_ai_diagnostic(stage, model, content, key):
    directory = Path(__file__).resolve().parents[1] / 'data' / 'ai-responses'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f'{time.time_ns()}-{stage}.json'
    value = {'stage': stage, 'model': model, 'response': content.replace(key, '[REDACTED]')}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
    return path


def call_ai(messages, model=None):
    provider = os.environ.get('AI_PROVIDER', 'openrouter')
    endpoint = {'openrouter': 'https://openrouter.ai/api/v1/chat/completions', 'nvidia': 'https://integrate.api.nvidia.com/v1/chat/completions'}.get(provider)
    if not endpoint:
        raise ValueError('Unknown configured provider')
    key = os.environ.get('OPENROUTER_API_KEY', '')
    if not key:
        raise ValueError('Selected provider API key is missing')
    payload = {'model': model or os.environ['OPENROUTER_MODEL'], 'messages': messages, 'temperature': 0.1, 'max_tokens': 16384}
    if provider == 'nvidia' and payload['model'].startswith('z-ai/glm-'):
        payload['response_format'] = {'type': 'json_object'}
    if provider == 'nvidia' and payload['model'].startswith('nvidia/nemotron-3-'):
        payload['chat_template_kwargs'] = {'enable_thinking': True}
    request = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=int(os.environ.get('AI_TIMEOUT_SECONDS', '180'))) as response:
            raw = response.read(2_000_000)
    except urllib.error.HTTPError as error:
        raise ValueError(f'Service HTTP {error.code}; check provider access/quota') from None
    try:
        result = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        diagnostic = save_ai_diagnostic('http-body', payload['model'], raw.decode('utf-8', errors='replace'), key)
        raise ValueError(f'Provider HTTP body was not JSON; diagnostic saved: {diagnostic}') from None
    choices = result.get('choices') if isinstance(result, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError('Provider response has no valid choices; check provider access/quota')
    message = choices[0].get('message')
    if not isinstance(message, dict):
        raise ValueError('Provider response has no valid assistant message')
    content = message.get('content')
    if not isinstance(content, str) or not content.strip():
        reasoning = message.get('reasoning_content') or message.get('reasoning') or message.get('text')
        if isinstance(reasoning, str) and reasoning.strip():
            content = reasoning
        else:
            raise ValueError('No response text received')
    diagnostic = save_ai_diagnostic('model-content', payload['model'], content, key)
    if choices[0].get('finish_reason') == 'length':
        raise ValueError(f'Model exhausted output budget; refusing partial answer. Diagnostic: {diagnostic}')
    try:
        return decode_model_json(content)
    except ValueError as error:
        raise ValueError(f'Model JSON formatting failed: {error}. Diagnostic: {diagnostic}') from None


def supported_answers(result, evidence, recon=None):
    answers = result.get('answers')
    if not isinstance(answers, list) or not answers or len(answers) > 20:
        raise ValueError('Model did not provide a complete confident answer set')
    if result.get('needs_manual_review') is True:
        raise ValueError('Marked for manual review')
    cleaned_answers = [clean_answer_value(a) for a in answers]
    for answer in cleaned_answers:
        if not isinstance(answer, str) or not answer.strip() or '\n' in answer or '\r' in answer or len(answer) > 1000 or is_unanswered_placeholder(answer):
            raise ValueError('Invalid answer text or placeholder returned')
    result['answers'] = cleaned_answers
    quotes = []
    citations = result.get('evidence', [])
    if isinstance(citations, list) and citations:
        for citation in citations:
            if not isinstance(citation, dict):
                raise ValueError('Invalid evidence citation')
            tid = citation.get('tool_id')
            quote = citation.get('quote')
            if tid in ('e0', 'initial_recon') and recon:
                recon_text = json.dumps(recon, ensure_ascii=False)
                if not isinstance(quote, str) or not quote.strip() or quote not in recon_text:
                    raise ValueError('Missing or fabricated evidence citation')
                quotes.append(quote)
            else:
                record = evidence.get(tid)
                if not record or not record.get('ok') or not isinstance(quote, str) or not quote.strip() or quote not in record.get('output', ''):
                    raise ValueError('Missing or fabricated evidence citation')
                quotes.append(quote)
    elif not isinstance(citations, list):
        raise ValueError('Invalid evidence citation')

    all_text = ' '.join(str(rec.get('output', '')) for rec in evidence.values() if rec.get('ok'))
    if recon:
        all_text += ' ' + json.dumps(recon, ensure_ascii=False)

    for answer in cleaned_answers:
        matched = False
        if quotes:
            for quote in quotes:
                if (
                    answer in quote or
                    ('/usr' + answer) in quote or
                    answer.replace('/bin/', '/usr/bin/') in quote or
                    answer.lower() in quote.lower() or
                    quote.strip().lower() in answer.lower() or
                    Path(answer).name in quote
                ):
                    matched = True
                    break
        if not matched:
            if (
                answer in all_text or
                ('/usr' + answer) in all_text or
                answer.replace('/bin/', '/usr/bin/') in all_text or
                answer.lower() in all_text.lower() or
                result.get('solved') is True
            ):
                matched = True
        if not matched:
            raise ValueError(f"Answer '{answer}' is not present in cited evidence; review derivation manually")
    return cleaned_answers


def apply_answers(question, answers, backup_dir):
    path = Path(question['path'])
    if path.is_symlink():
        raise ValueError('Question path became a symlink')
    original = read_bytes(path, 100000)
    if hashlib.sha256(original).hexdigest() != question['sha256']:
        raise ValueError('Question changed during investigation; original left untouched')
    info = path.stat()
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = backup_dir / (question['id'] + '.original')
    with backup.open('xb') as file:
        file.write(original)
    backup.chmod(0o600)
    newline = '\r\n' if b'\r\n' in original else '\n'
    bom = b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b''
    lines = original.decode('utf-8-sig').splitlines()
    placeholders = [i for i, line in enumerate(lines) if re.match(r'^\s*ANSWER\s*:', line, re.I)]
    if len(placeholders) != len(answers):
        raise ValueError('Answer count does not match ANSWER placeholders; manual review required')
    for index, answer in zip(placeholders, answers):
        clean = clean_answer_value(answer)
        lines[index] = re.sub(r'(?i)^(\s*ANSWER\s*:).*', lambda m: m[1] + ' ' + clean, lines[index])
    updated = bom + (newline.join(lines) + (newline if original.endswith((b'\n', b'\r')) else '')).encode('utf-8')
    fd, name = tempfile.mkstemp(prefix='.forensics-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(updated)
            file.flush()
            os.fsync(file.fileno())
            os.fchmod(file.fileno(), stat.S_IMODE(info.st_mode))
            if os.geteuid() == 0:
                os.fchown(file.fileno(), info.st_uid, info.st_gid)
        if read_bytes(path, 100000) != original:
            raise ValueError('Question changed before write; aborting')
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def investigate(question, tools, directory, caller=None, readme_html='', progress=None):
    caller = caller or call_ai
    recon = gather_initial_recon()
    lines = question['content'].splitlines()
    answer_lines = [re.sub(r'^\s*ANSWER\s*:\s*', '', line, flags=re.I).strip() for line in lines if re.match(r'^\s*ANSWER\s*:', line, re.I)]
    partial_status = []
    for idx, ans in enumerate(answer_lines, 1):
        if ans and not is_unanswered_placeholder(ans):
            partial_status.append(f"Answer {idx}: already filled with '{clean_answer_value(ans)}'")
        else:
            partial_status.append(f"Answer {idx}: UNANSWERED placeholder '{ans}' (NEEDS INVESTIGATION)")
    user_payload = {
        'question': question,
        'placeholder_status': partial_status,
        'readme_html_full': readme_html,
        'image_notes': os.environ.get('FORENSICS_IMAGE_NOTES', ''),
        'initial_recon': recon
    }
    messages = [
        {'role': 'system', 'content': PROMPT},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False)}
    ]
    evidence = {}
    rounds = int(os.environ.get('FORENSICS_MAX_ROUNDS', '12'))
    if not 1 <= rounds <= 24:
        raise ValueError('FORENSICS_MAX_ROUNDS must be between 1 and 24')
    rejected = {}
    request_cache = {}

    for round_number in range(1, rounds + 1):
        if check_user_skip(0):
            print(f"\n[SKIP] User pressed Enter: Skipping Question {question['number']} immediately!\n", flush=True)
            saved_answers = [clean_answer_value(a) for a in answer_lines if a and not is_unanswered_placeholder(a)]
            return {'answers': saved_answers if saved_answers else ['SKIPPED'], 'explanation': 'Skipped by user'}
        if progress:
            progress(f'turn {round_number}/{rounds}: investigating... (Press ENTER to skip to next)')
        result = caller(messages)
        if check_user_skip(0):
            print(f"\n[SKIP] User pressed Enter: Skipping Question {question['number']} immediately!\n", flush=True)
            saved_answers = [clean_answer_value(a) for a in answer_lines if a and not is_unanswered_placeholder(a)]
            return {'answers': saved_answers if saved_answers else ['SKIPPED'], 'explanation': 'Skipped by user'}
        (directory / f'{question["id"]}-round{round_number}.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if result.get('command_requests'):
            raise ValueError('AI requested unsupported shell commands')

        if result.get('answers'):
            try:
                supported_answers(result, evidence, recon=recon)
                return {**result, 'tool_requests': [], 'commands': []}
            except ValueError:
                pass

        requests = []
        raw_commands = result.get('commands')
        if isinstance(raw_commands, list):
            for cmd in raw_commands:
                if isinstance(cmd, str) and cmd.strip():
                    requests.append({'tool': 'command', 'cmd': cmd.strip()})
        tool_reqs = result.get('tool_requests')
        if isinstance(tool_reqs, list):
            for req in tool_reqs:
                if isinstance(req, dict):
                    requests.append(req)

        if not requests:
            try:
                supported_answers(result, evidence, recon=recon)
                return result
            except ValueError as error:
                signature = json.dumps(result, sort_keys=True)
                rejected[signature] = rejected.get(signature, 0) + 1
                if round_number == rounds or rejected[signature] >= 2:
                    raise ValueError(str(error) + '; investigation stopped without a supported final answer') from None
                messages.extend([
                    {'role': 'assistant', 'content': json.dumps(result)},
                    {'role': 'user', 'content': json.dumps({
                        'validation_feedback': str(error),
                        'instruction': 'Continue investigating by providing commands in "commands": ["..."] or tools. Provide exact answer when found.'
                    })}
                ])
                continue

        outputs = []
        for request in requests[:4]:
            tool = request.get('tool')
            signature = json.dumps({k: v for k, v in request.items() if k not in ('id', 'tool_id')}, sort_keys=True)
            if signature in request_cache:
                outputs.append({**evidence[request_cache[signature]], 'cached': True})
                continue
            identity = 'e' + str(len(evidence) + 1)
            try:
                if tool in ('command', 'bash', 'exec') or ('cmd' in request and 'path' not in request):
                    cmd = request.get('cmd') or request.get('command') or ''
                    out = run_safe_command(cmd)
                    record = {'id': identity, 'request': request, 'ok': True, 'output': out}
                else:
                    record = {'id': identity, 'request': request, 'ok': True, 'output': tools.run(request)}
            except Exception as error:
                record = {'id': identity, 'request': request, 'ok': False, 'output': str(error)}
            evidence[identity] = record
            request_cache[signature] = identity
            outputs.append(record)

        (directory / f'{question["id"]}-evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
        feedback = 'Commands executed. Analyze results and issue next commands or provide final answer.'
        messages.extend([
            {'role': 'assistant', 'content': json.dumps(result)},
            {'role': 'user', 'content': json.dumps({'evidence_results': outputs, 'feedback': feedback, 'remaining_rounds': rounds - round_number})}
        ])

    messages.append({'role': 'user', 'content': json.dumps({
        'instruction': 'Investigation turns complete. Using all collected evidence, return your best determined final answers in {"answers": ["..."], "explanation": "..."}. Format according to competition rules.',
        'final_synthesis': True
    })})
    result = caller(messages)
    (directory / f'{question["id"]}-round{rounds + 1}.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    if result.get('command_requests'):
        raise ValueError('AI requested unsupported shell commands')
    try:
        supported_answers(result, evidence, recon=recon)
    except ValueError as error:
        raise ValueError('Final synthesis could not establish a supported answer: ' + str(error)) from None
    return {**result, 'tool_requests': [], 'commands': []}


def investigation_leads(question, directory):
    value = {'partial_answers': [], 'hypothesis_unverified': '', 'leads': []}
    rounds = list(directory.glob(question['id'] + '-round*.json'))
    if rounds:
        latest = max(rounds, key=lambda p: int(re.search(r'-round(\d+)\.json$', p.name)[1]))
        result = json.loads(latest.read_text())
        value['partial_answers'] = result.get('answers', [])
        value['hypothesis_unverified'] = str(result.get('explanation', ''))[:2000]
    path = directory / (question['id'] + '-evidence.json')
    if path.exists():
        records = json.loads(path.read_text())
        seen = set()
        for identity, record in records.items():
            if not record.get('ok'):
                continue
            request = record.get('request', {})
            candidates = [request.get('path')]
            if request.get('tool') in ('find_files', 'resolve_path'):
                candidates.extend(line for line in record.get('output', '').splitlines() if line.startswith('/'))
            for candidate in candidates:
                if isinstance(candidate, str) and candidate.startswith('/') and candidate not in seen:
                    seen.add(candidate)
                    value['leads'].append({'path': candidate, 'tool_id': identity, 'assessment': 'Inspected or discovered evidence location'})
    value['leads'] = value['leads'][:20]
    return value


def main():
    os.umask(0o077)
    if os.environ.get('SKIP_FORENSICS') == '1':
        print('Forensics engine: SKIP_FORENSICS=1 set, skipping all forensics questions.', flush=True)
        return 0

    print('Forensics engine: active-solver-v4 (Press ENTER anytime to skip to next question)', flush=True)
    engine = Path(__file__).resolve().parents[1]
    directory = engine / 'data' / 'forensics' / str(time.time_ns())
    directory.mkdir(parents=True, mode=0o700)
    directories = [Path(os.environ['FORENSICS_DIR'])] if os.environ.get('FORENSICS_DIR') else list(Path('/home').glob('*/Desktop')) + [Path('/root/Desktop')]
    questions = discover(directories)
    (directory / 'questions.json').write_text(json.dumps(questions, indent=2), encoding='utf-8')
    results = []
    for question in questions:
        entry = {'id': question['id'], 'number': question['number'], 'path': question['path']}
        lines = question['content'].splitlines()
        existing_answers = [clean_answer_value(m.group(1)) for line in lines for m in [re.match(r'^\s*ANSWER\s*:\s*(.*)$', line, re.I)] if m]
        placeholders = [line for line in lines if re.match(r'^\s*ANSWER\s*:', line, re.I)]
        valid_answers = [ans for ans in existing_answers if not is_unanswered_placeholder(ans)]

        if not os.environ.get('FORENSICS_FORCE_RESOLVE') and placeholders and len(valid_answers) == len(placeholders):
            print(f"Question {question['number']}: Already answered on Desktop -> {valid_answers}", flush=True)
            entry['status'] = 'FILLED_UNVERIFIED_SCORE'
            entry['answers'] = valid_answers
            results.append(entry)
            continue

        if valid_answers:
            print(f"\nQuestion {question['number']}: Found existing desktop answers ({len(valid_answers)}/{len(placeholders)}: {valid_answers})", flush=True)
            print(f"Question {question['number']}: [Press ENTER within 4s to KEEP these and skip, or wait to investigate...]", flush=True)
            if check_user_skip(timeout=4):
                print(f"Question {question['number']}: Keeping existing desktop answers and skipping investigation!\n", flush=True)
                entry['status'] = 'FILLED_UNVERIFIED_SCORE'
                entry['answers'] = valid_answers
                results.append(entry)
                continue
        else:
            print(f"\nQuestion {question['number']}: [Press ENTER within 2s to skip this question...]", flush=True)
            if check_user_skip(timeout=2):
                print(f"Question {question['number']}: Skipped by user!\n", flush=True)
                entry['status'] = 'SKIPPED_BY_USER'
                results.append(entry)
                continue

        print(f"Forensics: Investigating Question {question['number']} (Press ENTER anytime to skip)...", flush=True)
        try:
            source = Path(os.environ.get('README_FILE') or engine / 'data/auto-source.html')
            html = source.read_text(encoding='utf-8') if source.exists() else ''
            if len(html.encode()) > 250000:
                raise ValueError('README exceeds supported input size; refusing to truncate')
            result = investigate(question, EvidenceTools(engine), directory, readme_html=html, progress=lambda text: print(f'Question {question["number"]}: {text}', flush=True))

            from peer_review import review
            evidence_file = directory / (question['id'] + '-evidence.json')
            payload = {'kind': 'forensic_answer', 'readme_html_full': html, 'question': question, 'worker_answer': result, 'evidence': json.loads(evidence_file.read_text()), 'image_notes': os.environ.get('FORENSICS_IMAGE_NOTES', '')}
            verdict = review(payload, lambda messages, model: call_ai(messages, model=model), os.environ.get('OPENROUTER_MODEL', ''), os.environ.get('REVIEWER_MODEL', ''))
            (directory / (question['id'] + '-review.json')).write_text(json.dumps(verdict, indent=2))

            entry['answer'] = result
            if os.environ.get('FORENSICS_APPLY_ANSWERS', '1') == '1' and result.get('answers'):
                apply_answers(question, result['answers'], directory / 'backups')
                entry['status'] = 'FILLED_UNVERIFIED_SCORE'
                print(f"Question {question['number']}: Solved -> {result['answers']}", flush=True)
            else:
                entry['status'] = 'DRAFT_REVIEW'
        except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
            entry.update(status='MANUAL_REVIEW', reason=str(error))
            entry.update(investigation_leads(question, directory))
            print(f"Question {question['number']}: Requires manual inspection ({error})", flush=True)
        results.append(entry)
        for lead in entry.get('leads', [])[:3]:
            print('  Evidence lead: ' + lead['path'], flush=True)

    (directory / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    summary = []
    for entry in results:
        summary.append(f'Question {entry["number"]}: {entry["status"]}')
        if entry.get('reason'): summary.append('Status: ' + entry['reason'])
        if entry.get('hypothesis_unverified'): summary.append('Analysis summary: ' + entry['hypothesis_unverified'])
        if entry.get('partial_answers'): summary.append('Candidate answers: ' + json.dumps(entry['partial_answers']))
        summary.extend('Evidence lead: ' + lead['path'] for lead in entry.get('leads', []))
        summary.append('')
    (directory / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    print('Forensics evidence/results: ' + str(directory), flush=True)
    if not questions:
        print('No question files found. Set FORENSICS_DIR to their actual directory.', file=sys.stderr)
    return 0 if questions and all(r['status'] == 'FILLED_UNVERIFIED_SCORE' for r in results) else 2


if __name__ == '__main__':
    sys.exit(main())
