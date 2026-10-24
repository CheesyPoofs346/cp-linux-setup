"""Install and validate a global SSH baseline without rewriting Match blocks.

Password login stays available unless key-only mode was explicitly requested.
The daemon's syntax test must pass before the new configuration is retained.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def render(main, port=22, key_only=False, allow_users='', banner='/etc/issue.net'):
    if not 1 <= int(port) <= 65535:
        raise ValueError('Invalid SSH port')
    if allow_users and not all(re.fullmatch(r'[a-z_][a-z0-9_.-]*\$?', u) for u in allow_users.split()):
        raise ValueError('AllowUsers requires explicit local account names')
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', banner):
        raise ValueError('Invalid banner path')
    # First global values precede existing Include directives. Match sections are
    # preserved verbatim and independently checked by the postflight verifier.
    marker = '# BEGIN CP SSH BASELINE'
    end = '# END CP SSH BASELINE'
    clean = re.sub(r'(?ms)^' + re.escape(marker) + r'\n.*?^' + re.escape(end) + r'\n?', '', main)
    settings = {
        'Port': str(port), 'PermitRootLogin': 'no', 'PermitEmptyPasswords': 'no',
        'UsePAM': 'yes', 'StrictModes': 'yes', 'PermitUserEnvironment': 'no',
        'HostbasedAuthentication': 'no', 'IgnoreRhosts': 'yes', 'X11Forwarding': 'no',
        'MaxAuthTries': '3', 'LoginGraceTime': '60', 'LogLevel': 'VERBOSE',
        'PubkeyAuthentication': 'yes', 'PasswordAuthentication': 'no' if key_only else 'yes',
        'KbdInteractiveAuthentication': 'no' if key_only else 'yes',
        'AuthenticationMethods': 'publickey' if key_only else 'any', 'Banner': banner,
    }
    if allow_users:
        settings['AllowUsers'] = allow_users
    block = marker + '\n' + ''.join(f'{k} {v}\n' for k, v in settings.items()) + end + '\n'
    return block + clean


def install(main, snippet, validator, **options):
    if main.is_symlink() or snippet.is_symlink():
        raise ValueError('Refusing symlinked SSH configuration')
    original = main.read_bytes()
    new = render(original.decode(), **options)
    # Retire our older snippet, which could force public-key-only authentication.
    files = [(main, original, main.stat().st_mode & 0o777)]
    if snippet.exists():
        files.append((snippet, snippet.read_bytes(), snippet.stat().st_mode & 0o777))
    with tempfile.TemporaryDirectory(prefix='cp-ssh-') as temp:
        for index, (path, _, _) in enumerate(files):
            shutil.copy2(path, Path(temp) / str(index))
        try:
            main.write_text(new)
            if snippet.exists():
                snippet.write_text('# Baseline moved to the global prefix in sshd_config.\n')
            result = validator()
            if result.returncode:
                raise ValueError('sshd rejected baseline: ' + result.stderr[:1000])
        except BaseException:
            for index, (path, _, _) in enumerate(files):
                shutil.copy2(Path(temp) / str(index), path)
            raise
    return new


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--allow-users', default='')
    parser.add_argument('--banner', default='/etc/issue.net')
    parser.add_argument('--key-only', action='store_true')
    parser.add_argument('--snippet', type=Path, default=Path('/etc/ssh/sshd_config.d/99-cyberpatriot.conf'))
    args = parser.parse_args()
    binary = shutil.which('sshd') or '/usr/sbin/sshd'
    install(Path('/etc/ssh/sshd_config'), args.snippet,
            lambda: subprocess.run([binary, '-t'], capture_output=True, text=True, timeout=30),
            port=args.port, key_only=args.key_only, allow_users=args.allow_users, banner=args.banner)
