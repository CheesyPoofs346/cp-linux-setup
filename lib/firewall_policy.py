"""Default-port planning for explicitly required services, not service discovery."""
import json
import ipaddress
import os
import re
import shlex
import sys
import subprocess
from pathlib import Path

PORTS = {
    'ssh': ('22/tcp',), 'sshd': ('22/tcp',), 'openssh': ('22/tcp',), 'openssh-server': ('22/tcp',),
    'apache': ('80/tcp', '443/tcp'), 'apache2': ('80/tcp', '443/tcp'), 'httpd': ('80/tcp', '443/tcp'),
    'nginx': ('80/tcp', '443/tcp'), 'http': ('80/tcp',), 'https': ('443/tcp',),
    'ftp': ('21/tcp',), 'vsftpd': ('21/tcp',), 'proftpd': ('21/tcp',),
    'mysql': ('3306/tcp',), 'mariadb': ('3306/tcp',),
    'postgres': ('5432/tcp',), 'postgresql': ('5432/tcp',),
    'samba': ('445/tcp', '139/tcp', '137/udp', '138/udp'), 'smbd': ('445/tcp', '139/tcp', '137/udp', '138/udp'),
    'dns': ('53/tcp', '53/udp'), 'bind9': ('53/tcp', '53/udp'), 'named': ('53/tcp', '53/udp'),
    'postfix': ('25/tcp',), 'smtp': ('25/tcp',), 'exim4': ('25/tcp',),
    'dovecot': ('143/tcp', '993/tcp', '110/tcp', '995/tcp'),
    'cups': ('631/tcp',), 'snmp': ('161/udp',), 'snmpd': ('161/udp',),
    'ntp': ('123/udp',), 'ntpd': ('123/udp',), 'chrony': ('123/udp',), 'xrdp': ('3389/tcp',),
    'chromium': (), 'chromium-browser': (), 'firefox': (), 'libreoffice': (), 'thunderbird': (),
}


def loopback_only(pid, text):
    found=[]
    for line in text.splitlines():
        if not re.search(r'\bpid='+str(int(pid))+r'\b',line): continue
        parts=line.split()
        if len(parts)<6: return False
        host=parts[4].rsplit(':',1)[0].strip('[]').split('%')[0]
        try: found.append(ipaddress.ip_address(host).is_loopback)
        except ValueError: return False
    return bool(found) and all(found)


def verified_local_services(data):
    local=set()
    try:
        sockets=subprocess.run(['ss','-H','-lntup'],capture_output=True,text=True,timeout=10,check=True).stdout
        for raw in data.get('critical_services',[]):
            name=raw.lower().removesuffix('.service')
            if name in PORTS or not re.fullmatch(r'[a-z0-9_@.-]+',name): continue
            unit=name+'.service'
            result=subprocess.run(['systemctl','show','-p','MainPID','--value',unit],capture_output=True,text=True,timeout=10)
            if result.returncode or not result.stdout.strip().isdigit(): continue
            pid=int(result.stdout.strip())
            if pid<=0: continue
            groups=Path(f'/proc/{pid}/cgroup').read_text()
            if not any(line.endswith('/'+unit) for line in groups.splitlines()): continue
            if loopback_only(pid,sockets): local.add(name)
    except (OSError,subprocess.SubprocessError):
        pass  # Unverified services still fail closed in plan().
    return local


def plan(data, ssh_port=22, ssh_connection=None, local_only=()):
    services = data.get('critical_services') if isinstance(data, dict) else None
    if not isinstance(services, list) or not all(isinstance(s, str) for s in services):
        raise ValueError('Validated critical_services array required')
    ssh_port = int(ssh_port)
    if not 1 <= ssh_port <= 65535:
        raise ValueError('SSH port must be 1..65535')
    rules = set()
    ssh_names = ('ssh', 'sshd', 'openssh', 'openssh-server')
    normalized = [s.lower().removesuffix('.service') for s in services]
    if ssh_connection:
        fields = ssh_connection.split()
        if len(fields) != 4:
            raise ValueError('Cannot establish operator SSH connection port')
        ipaddress.ip_address(fields[0])
        ipaddress.ip_address(fields[2])
        port = int(fields[3])
        if not 1 <= port <= 65535 or not set(normalized).intersection(ssh_names):
            raise ValueError('Operator SSH requires review or a console launch before firewall changes')
        rules.add(f'{port}/tcp')
    for raw in services:
        service = raw.lower().removesuffix('.service')
        if service in local_only:
            continue
        if service not in PORTS:
            raise ValueError(f'Firewall review needed for required service {raw}; unknown/custom or dynamic ports')
        for port in PORTS[service]:
            rules.add(f'{ssh_port}/tcp' if service in ssh_names else port)
    return sorted(rules)


def check_existing(text, ports):
    """Do not claim required ingress works when an earlier global deny can win."""
    for line in text.splitlines():
        if not line.strip().startswith('ufw '):
            continue
        words = shlex.split(line)
        actions = [i for i, word in enumerate(words) if word in ('deny', 'reject')]
        if not actions:
            continue
        index = actions[0]
        if 'out' in words or 'route' in words:
            continue
        if 'from' in words and words[words.index('from') + 1] not in ('any', '0.0.0.0/0', '::/0'):
            continue  # Preserve source-specific ACLs; this planner does not certify their reachability.
        token = words[words.index('port') + 1] if 'port' in words else words[index + 1]
        proto = words[words.index('proto') + 1] if 'proto' in words else None
        if '/' in token:
            token, proto = token.split('/', 1)
        if not re.fullmatch(r'\d+(?::\d+)?(?:,\d+(?::\d+)?)*', token):
            if ports:
                raise ValueError('Review existing profile/global deny before changing firewall policy')
            continue
        for required in ports:
            port, protocol = required.split('/')
            if proto and proto != protocol:
                continue
            for span in token.split(','):
                bounds = [int(n) for n in span.split(':')]
                if bounds[0] <= int(port) <= bounds[-1]:
                    raise ValueError(f'Existing deny/reject conflicts with required port {required}')


if __name__ == '__main__':
    try:
        if '--check-rules' in sys.argv:
            check_existing(sys.stdin.read(), sys.argv[2].splitlines())
        else:
            data=json.load(sys.stdin)
            print('\n'.join(plan(data, os.environ.get('SSH_PORT', '22'), os.environ.get('SSH_CONNECTION'),verified_local_services(data))))
    except (ValueError, TypeError, IndexError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
