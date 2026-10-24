#!/usr/bin/env python3
"""Create deliberately vulnerable training state ONLY in our disposable VM.

Run once per clean clone. The marker, hostname and explicit acknowledgement are
all mandatory. Payloads are inert markers; no shell listeners or actual malware.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import socket
import subprocess


def validate_target(ack):
    if (os.geteuid() != 0 or not ack or socket.gethostname() != 'advanced-cp-lab'
            or Path('/etc/cp-advanced-lab').read_text().strip() != 'disposable-advanced-lab'):
        raise SystemExit('Refusing to provision outside the explicitly marked disposable VM')
    if Path('/var/lib/cp-lab-provisioned').exists():
        raise SystemExit('Already provisioned. Restore the clean snapshot for another seed.')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--seed', type=int, required=True)
    p.add_argument('--i-understand-this-is-a-disposable-vm', action='store_true')
    args = p.parse_args()
    if not 1 <= args.seed <= 9999:
        p.error('seed must be 1..9999')
    validate_target(args.i_understand_this_is_a_disposable_vm)
    n = args.seed
    a,u,r,g=f'lead{n}',f'analyst{n}',f'contractor{n}',f'research{n}'
    token=f'RESEARCH-DATA-{n}-KEEP'

    def run(command):
        subprocess.run(['bash','-euo','pipefail','-c',command],check=True)

    def write(path, text, mode=0o644):
        target=Path(path)
        missing=[]
        parent=target.parent
        while not parent.exists():
            missing.append(parent);parent=parent.parent
        target.parent.mkdir(parents=True,exist_ok=True)
        for parent in missing: parent.chmod(0o755)
        target.write_text(text);target.chmod(mode)

    run('export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq python3-psycopg2 libpam-pwquality libpam-modules nginx postgresql samba smbclient acl libcap2-bin ufw auditd unattended-upgrades curl jq pamtester')
    for user in (a,u,r):
        run(f'useradd -m -s /bin/bash {user}')
        # Synthetic lab passwords only; never reused outside this guest.
        run(f"printf '%s\\n' '{user}:Practice-Only-{n}!Secure' | chpasswd")
    run(f'groupadd {g}; usermod -aG sudo {a}; usermod -aG sudo,{g} {u}; usermod -aG {g} {a}')
    write('/etc/sudoers.d/research-maintenance',f'{u} ALL=(ALL) NOPASSWD: ALL\n',0o440)
    run(f'chage -M 99999 -m 0 {u}')
    # A hidden extra root identity without an active password or key.
    run(f'useradd -o -u 0 -M -s /bin/bash rootshadow{n}')
    write('/etc/ssh/sshd_config.d/00-research.conf','PermitRootLogin yes\nPermitEmptyPasswords yes\nX11Forwarding yes\n')
    match = f'User {u}' if n % 2 else f'Group {g}'
    with Path('/etc/ssh/sshd_config').open('a') as f:
        f.write(f'\nMatch {match}\n    PermitEmptyPasswords yes\n    X11Forwarding yes\n')
    run('install -d -m 755 /run/sshd; systemctl enable --now ssh; sshd -t; systemctl restart ssh')
    run('chmod 644 /etc/shadow /etc/gshadow')
    run('cp /usr/bin/find /usr/local/bin/research-find; chmod 4755 /usr/local/bin/research-find')
    run('cp /usr/bin/python3 /usr/local/bin/research-python; setcap cap_setuid+ep /usr/local/bin/research-python')
    write('/etc/cron.d/research-sync','* * * * * root /usr/bin/logger -t lab-marker LAB_UNAUTHORIZED_CRON\n')
    write('/etc/systemd/system/research-sync.service','[Unit]\nDescription=Inert unauthorized training marker\n[Service]\nType=oneshot\nExecStart=/usr/bin/logger -t lab-marker LAB_UNAUTHORIZED_TIMER\n')
    write('/etc/systemd/system/research-sync.timer','[Unit]\nDescription=Inert training persistence\n[Timer]\nOnBootSec=60\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n')
    run('systemctl daemon-reload; systemctl enable --now research-sync.timer')
    with Path(f'/home/{u}/.bashrc').open('a') as f:
        f.write('\n# Unauthorized training marker\nexport LAB_UNAUTHORIZED=1\n')
    write(f'/home/{u}/.config/systemd/user/research-session.service','[Unit]\nDescription=Unauthorized inert session marker\n[Service]\nExecStart=/usr/bin/logger LAB_UNAUTHORIZED_USER_UNIT\n[Install]\nWantedBy=default.target\n')
    run(f'install -d -m 755 -o {u} -g {u} /home/{u}/Desktop; cp /usr/bin/true /home/{u}/Desktop/quarterly_report.pdf; chmod 755 /home/{u}/Desktop/quarterly_report.pdf')
    write('/var/www/html/index.html',token+'\n')
    write('/var/www/html/.env','LAB_SYNTHETIC_SECRET=not-a-real-secret\n')
    write('/var/www/html/archive/internal.txt','Do not publish research archives\n')
    write('/etc/nginx/sites-available/default','server {\n listen 80 default_server;\n root /var/www/html;\n index index.html;\n server_name _;\n autoindex on;\n location / { try_files $uri $uri/ =404; }\n location /api/ { proxy_pass http://127.0.0.1:8081/; }\n}\n')
    if not n % 2:
        site=Path('/etc/nginx/sites-available/default')
        site.write_text(site.read_text().replace(' autoindex on;', ' include /etc/nginx/snippets/research-exposure.conf;'))
        write('/etc/nginx/snippets/research-exposure.conf', 'autoindex on;\nlocation = /.env { root /var/www/html; }\n')
    run('chmod -R o+w /var/www/html')
    run(f'install -d -m 2770 -g {g} /srv/research')
    write('/srv/research/ledger.txt',token+'\n',0o664)
    run(f'chgrp {g} /srv/research/ledger.txt')
    with Path('/etc/samba/smb.conf').open('a') as f:
        f.write(f'\n[projects{n}]\n path = /srv/research\n guest ok = yes\n read only = no\n force user = {u}\n')
    run(f"printf '%s\\n%s\\n' 'Practice-Only-{n}!Secure' 'Practice-Only-{n}!Secure' | smbpasswd -s -a {u}")
    run('systemctl enable --now postgresql')
    run(f"runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c \"CREATE ROLE {u} LOGIN SUPERUSER PASSWORD 'Practice-Only-{n}!Secure';\" -c 'CREATE ROLE researchapp LOGIN;' -c 'CREATE DATABASE projects{n};'")
    run(f"runuser -u postgres -- psql projects{n} -v ON_ERROR_STOP=1 -c \"CREATE TABLE ledger(value text); INSERT INTO ledger VALUES ('{token}'); GRANT SELECT ON ledger TO researchapp;\"")
    run("runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c 'GRANT CREATE ON SCHEMA public TO PUBLIC;'")
    hba=next(Path('/etc/postgresql').glob('*/main/pg_hba.conf'))
    hba.write_text(hba.read_text()+'\nhost all all 0.0.0.0/0 trust\n')
    pg=next(Path('/etc/postgresql').glob('*/main/postgresql.conf'))
    with pg.open('a') as f:
        f.write("\nlisten_addresses = '*'\npassword_encryption = 'md5'\n")
    # ALTER SYSTEM overrides the main config: editing only postgresql.conf fails.
    override="listen_addresses = '*'" if n % 2 else "password_encryption = 'md5'"
    run(f'runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET {override};"')
    run('useradd --system -M -s /usr/sbin/nologin researchapp')
    write('/opt/research/app.py',f'''from http.server import BaseHTTPRequestHandler,HTTPServer
import psycopg2
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  try:
   with psycopg2.connect(dbname="projects{n}",user="researchapp") as conn:
    with conn.cursor() as cur:
     cur.execute("SELECT value FROM ledger")
     data=cur.fetchone()[0].encode()
   self.send_response(200); self.end_headers(); self.wfile.write(data)
  except Exception:
   self.send_response(503); self.end_headers()
HTTPServer(("127.0.0.1",8081),Handler).serve_forever()
''')
    write('/etc/systemd/system/research-api.service','[Unit]\nDescription=Required research business API\nAfter=postgresql.service\nRequires=postgresql.service\n[Service]\nUser=researchapp\nExecStart=/usr/bin/python3 /opt/research/app.py\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl daemon-reload; systemctl enable --now research-api; systemctl restart postgresql nginx smbd')
    write('/etc/apt/apt.conf.d/99-research-no-refresh','APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n')
    run('systemctl disable --now apt-daily.timer apt-daily-upgrade.timer; ufw --force disable')
    write('/etc/sysctl.d/99-research.conf','kernel.randomize_va_space=0\nnet.ipv4.conf.all.accept_redirects=1\n')
    run('sysctl --system >/dev/null')
    write('/var/log/research-access.log',f'2026-01-12T10:12:03Z accepted credential change for {r} from 192.0.2.17\n2026-01-12T10:14:22Z {r} installed unauthorized research-sync.timer\n')
    desktop=Path('/home/cpoperator/Desktop');desktop.mkdir(exist_ok=True)
    write(str(desktop/'Forensics Question 1.txt'),'Which account installed the unauthorized research-sync.timer? Inspect the research access log.\nANSWER: \n')
    readme=f'''# Research Services Ubuntu 24.04

This is an original advanced practice lab, not an official CyberPatriot image.
Keep Ubuntu 24.04. Finish forensic questions before removing evidence.

Authorized Administrators:
cpoperator
{a}

Authorized Users:
{u}

Critical Services:
OpenSSH (ssh), nginx, PostgreSQL, Samba (smbd), research-api.

SSH on port 22 and the existing cpoperator public key must continue working.
The web site at port 80 and /api/ must return the existing research ledger.
PostgreSQL must retain projects{n}.ledger and the local researchapp peer login.
The projects{n} Samba share must retain its files and authenticated {u} access.
The {g} group is required for authorized staff to read and write /srv/research.
Do not remove required service accounts, business API, data, or audit logs.
Disable anonymous shares, directory browsing and access to hidden web files.
Database users must have only necessary privileges; PostgreSQL is local-only.
Remove unauthorized root identities, access rules and persistence. No extra SUID
or interpreter capabilities are authorized. All user passwords must be nonempty.
Password max age 90 days, minimum age 1 day, complexity/history and lockout.
Enable automatic daily package list refresh and security update installation.
Enable default-deny inbound firewall while preserving required services.
Root SSH login and empty-password SSH are forbidden in all Match contexts.
Keep auditd running. Quarantine disguised executables after preserving evidence.
No additional maintenance scheduler or user-session agent is authorized.
'''
    write(str(desktop/'README.md'),readme)
    run('chown -R cpoperator:cpoperator /home/cpoperator/Desktop')
    # Account creation replaces shadow atomically, so plant its ACL last.
    run(f'setfacl -m u:{u}:r /etc/shadow')
    write('/var/lib/cp-lab-seed',str(n)+'\n',0o600)
    write('/var/lib/cp-lab-provisioned','ready\n',0o600)
    print('PROVISIONED',n,hashlib.sha256(readme.encode()).hexdigest())


if __name__ == '__main__':
    main()
