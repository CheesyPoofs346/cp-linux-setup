"""Verify required-service availability and effective policy after remediation.

This report is not a score. Syntax, active/enabled units and local settings do
not prove remote application connectivity. Exit 1 = failure, 2 = manual review.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

SERVICES = {
    'ssh': ('ssh', 'sshd', 'ssh.socket'), 'sshd': ('ssh', 'sshd', 'ssh.socket'),
    'openssh-server': ('ssh', 'sshd', 'ssh.socket'), 'openssh': ('ssh', 'sshd', 'ssh.socket'),
    'apache2': ('apache2', 'httpd'), 'apache': ('apache2', 'httpd'), 'httpd': ('httpd', 'apache2'),
    'nginx': ('nginx',), 'vsftpd': ('vsftpd',), 'proftpd': ('proftpd',),
    'mysql': ('mysql', 'mariadb'), 'mariadb': ('mariadb', 'mysql'),
    'postgresql': ('postgresql',), 'postgres': ('postgresql',),
    'samba': ('smbd', 'samba-ad-dc'), 'smbd': ('smbd',),
    'bind9': ('named', 'bind9'), 'named': ('named', 'bind9'), 'dns': ('named', 'bind9'),
    'snmp': ('snmpd',), 'snmpd': ('snmpd',), 'postfix': ('postfix',),
    'dovecot': ('dovecot',), 'exim4': ('exim4',), 'cups': ('cups',),
    'nfs-server': ('nfs-server', 'nfs-kernel-server'), 'nfs-kernel-server': ('nfs-kernel-server', 'nfs-server'),
    'ntp': ('ntp', 'ntpd'), 'ntpd': ('ntpd', 'ntp'), 'chrony': ('chrony', 'chronyd'),
    'xrdp': ('xrdp',),
}
APPS = {'chromium', 'chromium-browser', 'firefox', 'libreoffice', 'thunderbird'}
VALIDATORS = {'apache2': ['apache2ctl', 'configtest'], 'apache': ['apache2ctl', 'configtest'],
              'httpd': ['httpd', '-t'], 'nginx': ['nginx', '-t'],
              'smbd': ['testparm', '-s'], 'samba': ['testparm', '-s'],
              'named': ['named-checkconf'], 'bind9': ['named-checkconf'], 'dns': ['named-checkconf'],
              'proftpd': ['proftpd', '-t']}


def probe(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout[:32000], result.stderr[:2000]
    except (OSError, subprocess.SubprocessError) as error:
        return 127, '', str(error)


def effective_values(text):
    result = {}
    for line in text.splitlines():
        key, _, value = line.partition(' ')
        if value:
            result[key.lower()] = value.strip()
    return result


def verify(data, readme='', command=probe, root=Path('/')):
    checks = []
    def add(name, status, detail):
        checks.append({'check': name, 'status': status, 'detail': detail})

    required = data.get('critical_services', [])
    if not isinstance(required, list) or not all(isinstance(s, str) for s in required):
        raise ValueError('Validated critical_services array required')
    seen_validators = set()
    for raw in required:
        name = raw.lower().removesuffix('.service')
        if name in APPS:
            # dpkg-query also succeeds for residual-config packages; require installed status.
            code, out, err = command(['dpkg-query', '-W', '-f=${Status}', name])
            add('required-app:' + name, 'PASS' if code == 0 and out.strip() == 'install ok installed' else 'FAIL', err or out.strip())
            continue
        units = SERVICES.get(name)
        if not units:
            add('required-service:' + name, 'REVIEW', 'Unknown/custom service; verify its units, ports and application manually')
            continue
        active, enabled = [], []
        for unit in units:
            if command(['systemctl', 'is-active', '--quiet', unit])[0] == 0:
                active.append(unit)
            if command(['systemctl', 'is-enabled', '--quiet', unit])[0] == 0:
                enabled.append(unit)
        add('required-service:' + name, 'PASS' if set(active) & set(enabled) else 'FAIL',
            f'active={active}, enabled={enabled}; remote connectivity still needs testing')
        if name in ('postgres', 'postgresql'):
            code, out, err = command(['pg_lsclusters', '--no-header'])
            online = re.search(r'^\S+\s+\S+\s+\d+\s+online\b', out, re.M)
            add('postgresql-cluster', 'PASS' if code == 0 and online else 'FAIL',
                err or 'At least one online cluster required; the umbrella service alone is insufficient')
        validator = VALIDATORS.get(name)
        if validator and tuple(validator) not in seen_validators:
            seen_validators.add(tuple(validator))
            code, _, err = command(validator)
            add('config-syntax:' + name, 'PASS' if code == 0 else 'FAIL', err or 'Configuration syntax accepted')
    ssh_required = bool(set(s.lower().removesuffix('.service') for s in required) & {'ssh', 'sshd', 'openssh', 'openssh-server'})
    if ssh_required:
        code, _, err = command(['/usr/sbin/sshd', '-t'])
        add('ssh-syntax', 'PASS' if code == 0 else 'FAIL', err or 'sshd -t accepted configuration')
        entries = data.get('all_users', []) + data.get('recent_hires', [])
        users = sorted({u['name'] for u in entries if isinstance(u, dict) and re.fullmatch(r'[a-z_][a-z0-9_.-]*\$?', u.get('name', ''))})
        # A different client address may select another Match block. These contexts
        # check selected defaults, not arbitrary source-address authorization.
        for user in ['root', *users]:
            if user != 'root':
                account_code, account, account_err = command(['getent', 'passwd', user])
                status_code, password_status, status_err = command(['passwd', '-S', user])
                fields = password_status.split()
                usable = account_code == 0 and account.startswith(user + ':') and status_code == 0 and len(fields) >= 2 and fields[1] == 'P'
                add('required-account:' + user, 'PASS' if usable else 'FAIL',
                    account_err or status_err or 'Account must exist with an unlocked, nonempty password; actual authentication remains untested')
            code, out, err = command(['/usr/sbin/sshd', '-T', '-C', f'user={user},host=localhost,addr=127.0.0.1'])
            values = effective_values(out)
            if code:
                add('ssh-effective:' + user, 'FAIL', err or 'Could not read effective SSH policy')
                continue
            if values.get('permitrootlogin') != 'no' and user == 'root':
                add('ssh-root-login', 'FAIL', 'Effective root login is not disabled; inspect Include/Match overrides')
            if values.get('permitemptypasswords') != 'no':
                add('ssh-empty-password:' + user, 'FAIL', 'Effective empty-password login is not disabled')
            if user != 'root' and re.search(r'all authorized users.*?ssh', readme, re.I | re.S):
                password_ok = values.get('passwordauthentication') == 'yes' and values.get('authenticationmethods', 'any') == 'any'
                if not password_ok:
                    add('ssh-access:' + user, 'REVIEW', 'Account requires keys/multiple factors; verify provisioned credentials before claiming SSH access')
                if any(k in values for k in ('allowusers', 'denyusers', 'allowgroups', 'denygroups')):
                    add('ssh-access-lists:' + user, 'REVIEW', 'SSH access lists exist; validate user/group/source authorization and a remote login')
        add('ssh-context-boundary', 'REVIEW' if not users else 'PASS', 'Local contexts checked; other client addresses and real logins remain unverified')

    # Verify the resulting machine, not the success strings printed by apt.
    code, out, err = command(['dpkg', '--audit'])
    add('package-state', 'PASS' if code == 0 and not out.strip() else 'FAIL', err or out.strip() or 'No incomplete package state')
    code, out, err = command(['apt-get', '-s', 'full-upgrade'])
    pending = [line for line in out.splitlines() if line.startswith('Inst ')]
    add('pending-updates', 'FAIL' if code else ('REVIEW' if pending else 'PASS'),
        err if code else f'{len(pending)} package upgrades pending; holds/phasing may require review')
    if (root / 'var/run/reboot-required').exists():
        add('reboot', 'REVIEW', 'Installed updates require reboot; do not reboot automatically during a timed run')
    if 'ufw' in readme.lower():
        code, out, err = command(['ufw', 'status'])
        add('ufw-active', 'PASS' if code == 0 and re.search(r'^Status: active\s*$', out, re.M) else 'FAIL', err or out[:200])
    release = root / 'etc/os-release'
    if release.exists() and re.search(r'^ID=["\']?linuxmint["\']?$', release.read_text(), re.M):
        for key, expected in (('refresh-schedule-enabled', 'true'), ('refresh-minutes', '10'),
                              ('autorefresh-hours', '2'), ('auto-update-flatpaks', 'true'),
                              ('auto-update-cinnamon-spices', 'true')):
            code, out, err = command(['gsettings', 'get', 'com.linuxmint.updates', key])
            add('mint-preference:' + key, 'PASS' if code == 0 and out.strip() == expected else 'FAIL',
                err or f'expected {expected}, effective={out.strip()}')
        code, _, err = command(['systemctl', 'is-enabled', '--quiet', 'mintupdate-automation-upgrade.timer'])
        add('mint-native-upgrade-timer', 'PASS' if code == 0 else 'FAIL', err or 'Native automation timer enablement checked')
        for relative, required_bit in (('etc/dconf/profile', 0o001), ('etc/dconf/db', 0o001),
                                       ('etc/dconf/profile/user', 0o004), ('etc/dconf/db/local', 0o004)):
            path = root / relative
            readable = path.exists() and bool(path.stat().st_mode & required_bit)
            add('desktop-access:/' + relative, 'PASS' if readable else 'FAIL', 'Desktop users need traversal/read access to the system dconf profile/database')
    return {'checks': checks, 'status': 'FAIL' if any(c['status'] == 'FAIL' for c in checks) else
            'REVIEW' if any(c['status'] == 'REVIEW' for c in checks) else 'PASS',
            'boundary': 'Local postflight checks are not an image score or end-to-end application test'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    data = json.loads((args.engine / 'data/readme_parsed.json').read_text())
    report = verify(data, (args.engine / 'data/auto-source.html').read_text())
    from privilege_audit import collect
    privilege_report = collect()
    report['privilege_audit'] = privilege_report
    for finding in privilege_report['findings']:
        report['checks'].append({'check': finding['rule'] + ':' + finding['path'],
                                 'status': 'REVIEW', 'detail': finding['assessment']})
    for error in privilege_report['errors']:
        report['checks'].append({'check': 'audit-coverage', 'status': 'REVIEW', 'detail': error})
    if privilege_report['truncated']:
        report['checks'].append({'check': 'audit-budget', 'status': 'REVIEW', 'detail': 'Privilege walk reached its budget; remaining files are unverified'})
    if report['status'] != 'FAIL' and any(c['status'] == 'REVIEW' for c in report['checks']):
        report['status'] = 'REVIEW'
    directory = args.engine / 'data'
    (directory / 'postflight.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = [report['boundary'], f'Postflight: {report["status"]}']
    lines.extend(f'[{c["status"]}] {c["check"]}: {c["detail"]}' for c in report['checks'])
    (directory / 'postflight.txt').write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines))
    return {'PASS': 0, 'FAIL': 1, 'REVIEW': 2}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
