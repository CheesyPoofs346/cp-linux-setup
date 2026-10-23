"""Conservative, owned sysctl baseline; preserve unrelated machine configuration."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

SETTINGS = {
    'kernel.randomize_va_space': 2, 'kernel.sysrq': 0,
    'kernel.kptr_restrict': 2, 'kernel.dmesg_restrict': 1,
    'fs.suid_dumpable': 0, 'fs.protected_hardlinks': 1,
    'fs.protected_symlinks': 1, 'net.ipv4.tcp_syncookies': 1,
    'net.ipv4.icmp_echo_ignore_broadcasts': 1,
    'net.ipv4.icmp_ignore_bogus_error_responses': 1,
}


def apply(root=Path('/'), runner=subprocess.run, check=False):
    root = Path(root).resolve()
    supported = {k: v for k, v in SETTINGS.items() if (root / 'proc/sys' / k.replace('.', '/')).is_file()}
    if not supported:
        raise ValueError('No supported baseline sysctls found')
    if not check:
        directory = root / 'etc/sysctl.d'
        directory.mkdir(parents=True, exist_ok=True)
        if not directory.resolve().is_relative_to(root / 'etc'):
            raise ValueError('Sysctl directory escapes the configuration root')
        owned = directory / '99-cp-hardening.conf'
        if owned.is_symlink():
            raise ValueError('Refusing a symlink at the managed sysctl path')
        backup = Path(tempfile.mkdtemp(prefix='run-', dir=_backup_directory(root)))
        paths = [root / 'etc/sysctl.conf', *directory.glob('*.conf')]
        seen = set()
        key_pattern = rb'^\s*(?:' + b'|'.join(re.escape(k.encode()) for k in supported) + rb')\s*='
        for p in paths:
            if p == owned or not p.is_file():
                continue
            target = p.resolve()
            if not target.is_relative_to(root / 'etc') or target in seen:
                continue
            seen.add(target)
            old = target.read_bytes()
            new = b''.join(b'# CP baseline owns this key: ' + line if re.match(key_pattern, line) else line
                           for line in old.splitlines(keepends=True))
            if new != old:
                _backup(target, root, backup)
                target.write_bytes(new)
        content = '# Managed CP baseline; networking roles and application compatibility are preserved.\n'
        content += ''.join(f'{k} = {v}\n' for k, v in supported.items())
        if owned.exists() and owned.read_text() != content:
            _backup(owned, root, backup)
        owned.write_text(content)
        owned.chmod(0o644)
        if os.geteuid() == 0:
            os.chown(owned, 0, 0)
        (backup / 'settings.json').write_text(json.dumps(supported, indent=2))
    for key, expected in supported.items():
        if not check:
            result = runner(['sysctl', '-w', f'{key}={expected}'], capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise ValueError(f'Could not apply sysctl {key}')
        result = runner(['sysctl', '-n', key], capture_output=True, text=True, timeout=10)
        if result.returncode or result.stdout.strip() != str(expected):
            raise ValueError(f'Sysctl verification failed: {key}')
    return len(supported)


def _backup_directory(root):
    path = root / 'var/backups/cyberpatriot/kernel-policy'
    path.mkdir(parents=True, exist_ok=True)
    return path


def _backup(path, root, destination):
    target = destination / path.relative_to(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise ValueError('Kernel policy requires root')
        print(f'Kernel baseline: {apply(check="--check" in sys.argv)} supported values verified')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Kernel baseline failed: {error}', file=sys.stderr)
        sys.exit(1)
