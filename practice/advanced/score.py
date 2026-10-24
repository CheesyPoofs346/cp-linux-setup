#!/usr/bin/env python3
"""Independent, read-only advanced lab checks. Run as root inside the lab guest.

No remediation module imports. An error is never credit. Business availability
has explicit penalties, independently of security configuration credit.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time


def scenario(seed):
    if not re.fullmatch(r'[1-9][0-9]{0,3}', str(seed)):
        raise ValueError('seed must be 1..9999')
    n = int(seed)
    return {'admin': f'lead{n}', 'staff': f'analyst{n}', 'rogue': f'contractor{n}',
            'group': f'research{n}', 'token': f'RESEARCH-DATA-{n}-KEEP',
            'share': f'projects{n}', 'db': f'projects{n}'}


def checks(seed):
    s = scenario(seed)
    a, u, r, g = (s[k] for k in ('admin', 'staff', 'rogue', 'group'))
    rows = []

    def add(name, command, points=1, penalty=0):
        # Consume full producer output under pipefail. grep -q can make sshd -T
        # die on SIGPIPE and turn a correct policy into a false failure.
        command=re.sub(r'\bgrep\s+-([A-Za-z]+)',lambda m:'grep'+(' -'+m[1].replace('q','') if m[1].replace('q','') else ''),command)
        rows.append(dict(id=name, command=command, points=points, penalty=penalty))

    add('accounts.unauthorized', f'getent passwd {r}; test "$?" = 2')
    add('accounts.single-root', "test \"$(awk -F: '$3==0{n++}END{print n}' /etc/passwd)\" = 1")
    add('accounts.staff-not-admin', f'groups=$(id -nG {u}) && no_match grep -w sudo <<<"$groups"')
    add('accounts.authorized-admin', f'id -nG {a} | tr " " "\\n" | grep -qx sudo')
    add('accounts.root-locked', "passwd -S root | grep -Eq '^root L'")
    add('accounts.staff-password', f'passwd -S {u} | grep -Eq "^{u} P"')
    add('accounts.staff-expiry', f'test "$(getent shadow {u} | cut -d: -f5)" -le 90')
    add('accounts.minimum-age', "awk '$1==\"PASS_MIN_DAYS\"&&$2>=1{ok=1}END{exit !ok}' /etc/login.defs")
    add('accounts.maximum-age', "awk '$1==\"PASS_MAX_DAYS\"&&$2<=90{ok=1}END{exit !ok}' /etc/login.defs")
    add('sudo.syntax', 'visudo -cf /etc/sudoers')
    add('sudo.staff-no-nopasswd', f'policy=$(LC_ALL=C sudo -l -U {u} 2>&1); code=$?; {{ test "$code" = 0 || {{ test "$code" = 1 && grep -F "not allowed to run sudo" <<<"$policy"; }}; }} && no_match grep NOPASSWD <<<"$policy"')
    add('sudo.no-include-backdoor', "if test -e /etc/sudoers.d/research-maintenance; then no_match grep -R 'NOPASSWD.*ALL' /etc/sudoers.d/research-maintenance; else test ! -L /etc/sudoers.d/research-maintenance; fi")
    for file, mode in [('passwd','644'),('group','644'),('shadow','640'),('gshadow','640')]:
        add('permissions.'+file, f'test "$(stat -c %a /etc/{file})" = {mode}')
    add('pam.no-permit-bypass', "no_match grep -E '^auth[[:space:]]+sufficient[[:space:]]+pam_permit' /etc/pam.d/common-auth")
    add('pam.password-quality', "grep -Eq '^[^#]*pam_pwquality.so' /etc/pam.d/common-password")
    add('pam.password-history', "grep -Eq '^[^#]*pam_pwhistory.so' /etc/pam.d/common-password")
    add('pam.lockout', "grep -Eq '^[^#]*pam_faillock.so' /etc/pam.d/common-auth")
    for key, value in [('permitrootlogin','no'),('permitemptypasswords','no'),('x11forwarding','no'),
                       ('hostbasedauthentication','no'),('ignorerhosts','yes'),('usepam','yes')]:
        add('ssh.'+key, f'/usr/sbin/sshd -T | grep -qx "{key} {value}"')
    add('ssh.staff-match-root-denied', f'/usr/sbin/sshd -T -C user={u},host=localhost,addr=127.0.0.1 | grep -qx "permitrootlogin no"')
    add('ssh.staff-match-no-empty', f'/usr/sbin/sshd -T -C user={u},host=localhost,addr=127.0.0.1 | grep -qx "permitemptypasswords no"')
    add('ssh.syntax', '/usr/sbin/sshd -t')
    add('firewall.enabled', "ufw status | grep -q '^Status: active'")
    add('firewall.default-incoming', "ufw status verbose | grep -q 'Default: deny (incoming)'")
    add('updates.security-source', "apt-cache policy | grep -q noble-security")
    add('updates.update-source', "apt-cache policy | grep -q noble-updates")
    add('updates.daily-refresh', "apt-config dump | grep -Eq 'APT::Periodic::Update-Package-Lists \"1\"'")
    add('updates.automatic-install', "apt-config dump | grep -Eq 'APT::Periodic::Unattended-Upgrade \"1\"'")
    add('updates.refresh-timer', 'systemctl is-enabled apt-daily.timer && systemctl is-active apt-daily.timer')
    add('updates.upgrade-timer', 'systemctl is-enabled apt-daily-upgrade.timer && systemctl is-active apt-daily-upgrade.timer')
    add('updates.dpkg-consistent', 'audit=$(dpkg --audit) && test -z "$audit"')
    add('nginx.syntax', 'nginx -t')
    add('nginx.hide-version', "headers=$(curl -fsSI http://127.0.0.1/) && no_match grep -Ei 'Server: nginx/' <<<\"$headers\"")
    add('nginx.no-directory-index', 'code=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1/archive/) && test "$code" != 200')
    add('nginx.no-secret-download', 'code=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1/.env) && test "$code" != 200')
    add('nginx.webroot-not-world-writable', 'files=$(find /var/www/html -xdev -perm -0002 -print -quit) && test -z "$files"')
    pg="runuser -u postgres -- psql -Atqc "
    add('postgres.no-trust', pg+'"SELECT count(*) FROM pg_hba_file_rules WHERE auth_method=\'trust\'" | grep -qx 0')
    add('postgres.password-scram', pg+'"SHOW password_encryption" | grep -qx scram-sha-256')
    add('postgres.local-listen', pg+'"SHOW listen_addresses" | grep -Eq "^(localhost|127.0.0.1)$"')
    add('postgres.staff-not-superuser', pg+f'"SELECT rolsuper FROM pg_roles WHERE rolname=\'{u}\'" | grep -qx f')
    add('samba.syntax', 'testparm -s')
    add('samba.no-guest', f'testparm -s --section-name={s["share"]} --parameter-name="guest ok" 2>/dev/null | grep -q No')
    add('samba.no-anonymous-download', f'output=$(smbclient //127.0.0.1/{s["share"]} -N -c "get ledger.txt /dev/null" 2>&1); code=$?; test "$code" != 0 && grep -E "NT_STATUS_(ACCESS_DENIED|LOGON_FAILURE)" <<<"$output"')
    add('samba.modern-protocol', 'testparm -s --parameter-name="server min protocol" 2>/dev/null | grep -Eq "SMB[23]"')
    add('privilege.no-extra-suid', 'test ! -u /usr/local/bin/research-find')
    add('privilege.no-extra-capability', 'if test -e /usr/local/bin/research-python; then caps=$(getcap /usr/local/bin/research-python) && test -z "$caps"; else test ! -L /usr/local/bin/research-python; fi')
    add('privilege.shadow-acl', f'acl=$(getfacl -cp /etc/shadow) && no_match grep -E "^user:{u}:.*r" <<<"$acl"')
    add('persistence.cron-marker', '! test -e /etc/cron.d/research-sync')
    add('persistence.timer-marker', 'state=$(systemctl is-enabled research-sync.timer 2>&1); code=$?; test "$code" != 0 && { test "$state" = disabled || test "$state" = masked || test "$state" = not-found || grep -F "does not exist" <<<"$state"; }')
    add('persistence.shell-startup', f'if test -e /home/{u}/.bashrc; then no_match grep LAB_UNAUTHORIZED /home/{u}/.bashrc; else test -d /home/{u}; fi')
    add('files.disguised-executable', f'test ! -x /home/{u}/Desktop/quarterly_report.pdf')
    add('kernel.aslr', 'test "$(sysctl -n kernel.randomize_va_space)" = 2')
    add('kernel.redirects', 'test "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = 0')
    add('audit.running', 'systemctl is-active auditd')
    add('forensics.answer', f'grep -qx "ANSWER: {r}" /home/cpoperator/Desktop/Forensics\\ Question\\ 1.txt')
    add('persistence.user-unit', f'test ! -f /home/{u}/.config/systemd/user/research-session.service')
    add('postgres.no-public-schema-create', pg+'"SELECT coalesce(bool_or(a.privilege_type=\'CREATE\' AND a.grantee=0),false) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault(\'n\',n.nspowner))) a WHERE n.nspname=\'public\'" | grep -qx f')
    add('nginx.security-header', 'curl -fsSI http://127.0.0.1/ | grep -Eiq "^X-Content-Type-Options: nosniff"')
    add('samba.staff-write-restricted', f'testparm -s --section-name={s["share"]} --parameter-name="valid users" 2>/dev/null | grep -q "@{g}"')
    # These are mandatory business invariants, not extra hardening points.
    for service in ('ssh','nginx','postgresql','smbd'):
        add('availability.'+service, f'systemctl is-active {service} && systemctl is-enabled {service}', 0, 12)
    add('availability.web-data', f'curl -fsS http://127.0.0.1/ | grep -q {s["token"]}', 0, 15)
    add('availability.db-data', f'runuser -u postgres -- psql {s["db"]} -Atqc "SELECT value FROM ledger" | grep -qx {s["token"]}', 0, 15)
    add('availability.share-data', f'grep -qx {s["token"]} /srv/research/ledger.txt', 0, 15)
    add('availability.staff-file-access', f'runuser -u {u} -- cat /srv/research/ledger.txt | grep -qx {s["token"]}', 0, 10)
    add('availability.web-api-db-chain', f'curl -fsS http://127.0.0.1/api/ | grep -qx {s["token"]}', 0, 20)
    add('availability.authenticated-smb', f'smbclient //127.0.0.1/{s["share"]} -U "{u}%Practice-Only-{int(seed)}!Secure" -c "get ledger.txt /dev/null"', 0, 15)
    return rows


def evaluate(rows):
    results, earned, total, penalties = [], 0, 0, 0
    for row in rows:
        total += row['points']
        try:
            prefix='no_match() { "$@"; local code=$?; test "$code" = 1; }; '
            p = subprocess.run(['bash','-o','pipefail','-c',prefix+row['command']], capture_output=True, text=True, timeout=15)
            status = 'PASS' if p.returncode == 0 else ('ERROR' if p.returncode in (126,127) else 'FAIL')
            detail = (p.stdout+p.stderr)[-1500:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            status, detail = 'ERROR', str(exc)
        if status == 'PASS':
            earned += row['points']
        else:
            penalties += row['penalty']
        results.append(dict(id=row['id'], status=status, detail=detail))
    return dict(timestamp=time.time(), earned=earned, possible=total, penalties=penalties,
                score=max(0, round(100*earned/total,2)-penalties) if total else 0, checks=results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--seed', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path('/etc/cp-advanced-lab').is_file():
        raise SystemExit('Refusing: run only as root in the disposable advanced lab VM')
    report = evaluate(checks(args.seed))
    Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
    print(f"{report['score']}/100; {report['earned']}/{report['possible']} checks; penalties={report['penalties']}")
