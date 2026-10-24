"""Repair Mint 21 official sources and native update preferences without a GUI.

Only the official Mint source file is restored; additional repositories are preserved.
--root supports offline regression fixtures. No package commands run here.
"""
import argparse
from pathlib import Path
import re
import shutil


def write(root, name, content):
    path = root / name.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        path.chmod(0o644)
        return
    if path.exists():
        backup = path.with_name(path.name + '.before-round1-fix')
        if not backup.exists():
            shutil.copy2(path, backup)
    path.write_text(content)
    path.chmod(0o644)


def configure(root, restore_sources=False):
    release = dict(re.findall(r'^(\w+)=["\']?([^\n"\']+)',
                              (root / 'etc/os-release').read_text(), re.M))
    if release.get('ID') != 'linuxmint' or not release.get('VERSION_ID', '').startswith('21'):
        raise ValueError('This helper supports Mint 21 only')
    codename = release.get('VERSION_CODENAME', '')
    if codename not in ('vanessa', 'vera', 'victoria', 'virginia'):
        raise ValueError('Unrecognized Mint 21 codename; refusing source changes')
    if restore_sources:
        write(root, '/etc/apt/sources.list.d/official-package-repositories.list',
              f'deb http://packages.linuxmint.com {codename} main upstream import backport\n'
              'deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\n'
              'deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\n'
              'deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse\n'
              'deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n')
    write(root, '/etc/apt/apt.conf.d/99-cp-origins',
          'Unattended-Upgrade::Allowed-Origins {\n'
          '    "Ubuntu:jammy-security";\n    "Ubuntu:jammy-updates";\n};\n')
    schema = root / 'usr/share/glib-2.0/schemas/com.linuxmint.updates.gschema.xml'
    if not schema.exists():
        raise ValueError('Mint Update Manager schema missing')
    from xml.etree import ElementTree
    supported = {k.attrib['name'] for k in ElementTree.parse(schema).iter('key')}
    settings = {'refresh-schedule-enabled': 'true', 'refresh-days': '0',
                'refresh-hours': '0', 'refresh-minutes': '10', 'autorefresh-days': '0',
                'autorefresh-hours': '2', 'autorefresh-minutes': '0',
                'auto-update-flatpaks': 'true', 'auto-update-cinnamon-spices': 'true'}
    if not set(settings).issubset(supported):
        raise ValueError('Mint schema lacks required refresh/app-update keys')
    write(root, '/etc/dconf/db/local.d/01-mintupdate', '[com/linuxmint/updates]\n' +
          ''.join(f'{key}={value}\n' for key, value in settings.items()))
    # Defaults alone lose to existing per-user values. Lock only supported update keys.
    write(root, '/etc/dconf/db/local.d/locks/01-mintupdate',
          ''.join(f'/com/linuxmint/updates/{key}\n' for key in settings))
    profile = root / 'etc/dconf/profile/user'
    text = profile.read_text() if profile.exists() else 'user-db:user\n'
    if 'system-db:local' not in text.splitlines():
        text = text.rstrip() + '\nsystem-db:local\n'
    write(root, '/etc/dconf/profile/user', text)
    # The runner uses umask 077; dconf data must remain readable by desktop users.
    for name in ('etc/dconf', 'etc/dconf/profile', 'etc/dconf/db',
                 'etc/dconf/db/local.d', 'etc/dconf/db/local.d/locks'):
        (root / name).chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'))
    parser.add_argument('--restore-sources', action='store_true')
    args = parser.parse_args()
    configure(args.root, args.restore_sources)
