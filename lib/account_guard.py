"""Capture/check the invoking account without storing password hashes."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys


def snapshot(user):
    account = pwd.getpwnam(user)
    if account.pw_uid == 0 or account.pw_shell.endswith(('nologin', '/false')):
        raise ValueError('Protected user must be a non-root login account')
    home = Path(account.pw_dir)
    if not home.is_dir() or home.is_symlink() or home.resolve() in (Path('/'), Path('/root')):
        raise ValueError('Invalid protected home directory')
    info = home.stat()
    groups = sorted(g.gr_name for g in grp.getgrall() if user in g.gr_mem or g.gr_gid == account.pw_gid)
    # Hash sensitive policy state locally, but never send its contents to reviewers.
    policy = {}
    for name in ('passwd', 'group', 'shadow', 'gshadow', 'sudoers', 'login.defs'):
        path = Path('/etc') / name
        if path.exists():
            policy[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    for directory in ('/etc/pam.d', '/etc/sudoers.d', '/etc/security'):
        for path in sorted(Path(directory).rglob('*')):
            if path.is_file():
                policy[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'user': user, 'uid': account.pw_uid, 'gid': account.pw_gid, 'home': str(home), 'shell': account.pw_shell, 'groups': groups, 'home_uid': info.st_uid, 'home_gid': info.st_gid, 'home_mode': stat.S_IMODE(info.st_mode), 'policy_fingerprints': policy}


def main():
    mode, filename = sys.argv[1:3]
    path = Path(filename)
    if mode == 'snapshot':
        invoker = os.environ.get('SUDO_USER')
        explicit = os.environ.get('PROTECTED_USER')
        if invoker not in (None, '', 'root') and explicit and explicit != invoker:
            raise ValueError('PROTECTED_USER disagrees with the account that invoked sudo')
        user = invoker if invoker not in (None, '', 'root') else explicit
        if not user:
            raise ValueError('Launch with sudo from your main account, or set PROTECTED_USER explicitly')
        value = snapshot(user)
        parsed = json.loads((path.parent / 'readme_parsed.json').read_text())
        if not any(entry.get('name') == user and entry.get('account_type') == 'admin' for entry in parsed.get('all_users', [])):
            raise ValueError('Invoking account is not an authorized README administrator; review manually')
        os.umask(0o077)
        path.write_text(json.dumps(value, indent=2))
    elif mode == 'check':
        saved = json.loads(path.read_text())
        if snapshot(saved['user']) != saved:
            raise ValueError('Protected identity, groups, home metadata, or login policy changed; STOP')
    else:
        raise ValueError('Unknown account guard operation')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, IndexError) as error:
        print('Account guard: ' + str(error), file=sys.stderr)
        sys.exit(1)
