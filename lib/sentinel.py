#!/usr/bin/env python3
"""Sentinel: keeps working after the main run until the image is clean. No AI.

Each pass scans for CyberPatriot-style problems and splits them in two:
  auto    high confidence (hacking tools, SUID shells, backdoor lines, NOPASSWD, empty passwords)  -> fixed immediately
  review  "kinda sus" (odd cron/services/keys/files/users/processes)  -> ALERT (screen, popup, data/sentinel-review.txt); fix with --fix
It re-reads the scoring report each pass, prints the score, and stops at full points (or Ctrl-C / q).
Decisions are remembered in data/sentinel-state.json so nothing is asked twice.

Usage: sentinel.py [--once] [--interval SECONDS] [--auto-only] [--ask] [--fix N,N|all] [--dismiss N,N|all]
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

BACKDOOR_RE = re.compile(r'/dev/(tcp|udp)/|(^|[^a-z])nc(at)?\s[^#]*-[a-zA-Z]*e\s|bash\s+-i\s*>&|mkfifo\s+/tmp|(curl|wget)[^|]*\|\s*(ba)?sh|'
                         r'python[0-9.]*\s+-c\s+.import socket|base64\s+-d[^|]*\|\s*(ba)?sh|socat\s.*exec', re.I)
ROOT_EQUIV_GROUPS = {'docker', 'lxd', 'lxc', 'disk', 'shadow', 'root'}
PAM_BACKDOOR_RE = re.compile(r'^\s*(auth|account|password|session)\s+(sufficient|\[success=(done|ok|\d+)[^\]]*\])\s+pam_permit\.so|'
                             r'^\s*auth\s+(sufficient|\[success=done[^\]]*\])\s+pam_wheel\.so[^#]*\btrust\b|'
                             r'^\s*auth\s+sufficient\s+pam_(exec|echo)\.so', re.I)
PAM_SUSPECT_RE = re.compile(r'^\s*auth\s+(sufficient|\[success=done[^\]]*\])\s+pam_succeed_if\.so', re.I)
LISTEN_SUSPECT = set('python python3 perl ruby php lua node busybox'.split())
BACKDOOR_NAMES = set('nc ncat netcat nc.traditional nc.openbsd socat'.split())
WEBSHELL_RE = re.compile(r'(system|exec|passthru|shell_exec|popen|proc_open|eval|assert)\s*\(\s*(base64_decode\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)|'
                         r'eval\s*\(\s*(gzinflate|base64_decode|str_rot13)\s*\(|\$\{?_(GET|POST|REQUEST)\}?\s*\[[^\]]+\]\s*\(', re.I)
CRON_EVIL_RE = re.compile(r'(/tmp/|/var/tmp/|/dev/shm/|/\.[A-Za-z0-9_]+(\s|$))')
ALIAS_RE = re.compile(r'^\s*alias\s+([\w.-]+)\s*=\s*(.*)$')
ALIAS_WATCH = set('sudo su ls cd cat passwd ps netstat ss kill pkill rm mv cp ssh top systemctl visudo history apt apt-get chmod chown find grep'.split())


def _sudo_grant_to_stranger(ctx, line):
    """'eve ALL=(ALL) ALL' / '%ops ALL=...' for anyone the README does not list as an administrator."""
    m = re.match(r'^\s*(%?[\w.@-]+)\s+\S+\s*=', line)
    if not m or m.group(1) in ('Defaults', 'Cmnd_Alias', 'User_Alias', 'Host_Alias', 'Runas_Alias'):
        return False
    who = m.group(1).lstrip('%').lower()
    return not (who in ctx.admin_users or who in ctx.protected or who in ('sudo', 'admin', 'root'))


def alias_hijacked(line):
    """True for an alias that swaps a common command for something else (alias ls='ls --color' is fine)."""
    m = ALIAS_RE.match(line)
    if not m or m.group(1) not in ALIAS_WATCH:
        return False
    rhs = m.group(2).strip().strip('\'"').lstrip(chr(92)).split()
    return not rhs or rhs[0] not in (m.group(1), f'/usr/bin/{m.group(1)}', f'/bin/{m.group(1)}')

PROTECT_RE = re.compile(r'aeacus|cyberpatriot|scoring|/opt/engine|^engine$', re.I)

BAD_PACKAGES = (
    'john john-data hydra hydra-gtk nmap zenmap ophcrack ophcrack-cli aircrack-ng wireshark wireshark-qt wireshark-gtk tshark '
    'ettercap-common ettercap-graphical ettercap-text-only kismet nikto sqlmap medusa netcat-traditional ncat fcrackzip p0f dsniff '
    'burpsuite metasploit-framework armitage hashcat crunch rainbowcrack yersinia macchanger driftnet wifite hping3 cain lynis '
    'freeciv aisleriot gnome-mines gnome-sudoku gnome-mahjongg gnome-chess five-or-more four-in-a-row hitori iagno lightsoff '
    'quadrapassel swell-foo tali minetest supertux openarena frozen-bubble ace-of-penguins wesnoth 0ad '
    'telnet rsh-client rsh-redone-client talk transmission-gtk transmission-common transmission-cli deluge qbittorrent vuze frostwire '
    'zangband nethack-console bsdgames empire '
    'logkeys knocker nbtscan fierce dnsrecon recon-ng theharvester sslstrip bettercap reaver pixiewps bully weevely ncrack '
    'thc-hydra thc-ssl-dos slowhttptest wapiti w3af skipfish john-the-ripper cewl patator ike-scan onesixtyone smbmap enum4linux '
    'zmap masscan unicornscan arpwatch netdiscover dirb gobuster wpscan sslscan hunt xprobe sipcalc ftp-ssl telnetd inetutils-telnetd '
    'telnetd-ssl rsh-server rsh-redone-server talkd ntalk nis ypserv ypbind tightvncserver vnc4server '
    'gnome-games kdegames kpat ksudoku kmines kmahjongg kreversi klines gbrainy xmoto pingus extremetuxracer neverball neverputt '
    'vsftpd proftpd-basic proftpd-core pure-ftpd pure-ftpd-common tftpd-hpa tftpd snmpd xinetd openbsd-inetd inetutils-inetd rsh-server ftpd '
    'amule amule-common amule-daemon amule-utils amule-gnome-integration ktorrent gtk-gnutella nicotine ' 
    'lbreakout2 bzflag xonotic trigger-rally torcs freedroid gnome-nibbles gnome-robots gnome-taquin gnome-klotski gnome-tetravex '
    'atomix blinken bovo granatier kapman katomic kblackbox kbounce kbreakout kdiamond kfourinline kgoldrunner kigo killbots kiriki '
    'kjumpingcube klickety knetwalk kolf kollision konquest kshisen kspaceduel ksquares ksnakeduel kubrick lskat palapeli picmi '
    'tuxpuzzle ltris pingus freeorion openttd teeworlds xpilot-ng stellarium-games '
    'airgeddon alien-arena anydesk armagetronad asleap assaultcube backdoor-factory beef-xss biglybt bittornado '
    'bloodhound brutespray chntpw commix cowpatty crackmapexec cryptcat deluge-gtk deluge-web deluged dirbuster '
    'dnsenum dolphin-emu exploitdb fceux fern-wifi-cracker ffuf freeciv-client-gtk3 freeciv-client-gtk4 '
    'freeciv-server freedoom gnome-2048 gnuchess hedgewars impacket-scripts joomscan kismet-plugins kobodeluxe '
    'lazagne luanti lutris mahjongg maltego mdk3 mdk4 mimikatz mines minetest-server mitmproxy moon-buggy '
    'mupen64plus-ui-console netcat nethack-x11 netsniff-ng ninvaders nishang nomachine openra pacman4console pcsx2 '
    'pdfcrack playonlinux powersploit prboom-plus proxychains proxychains4 pychess python3-impacket qbittorrent-nox '
    'rarcrack realvnc-vnc-server redeclipse responder retroarch routersploit rtorrent rustdesk samdump2 sauerbraten '
    'scummvm sgt-puzzles shellter sipcrack snes9x-gtk social-engineer-toolkit solitaire steam steam-installer '
    'steam-launcher swell-foop teamviewer thc-ipv6 tigervnc-scraping-server tigervnc-standalone-server tixati '
    'transmission transmission-daemon transmission-qt tuxmath tuxpaint veil vino wesnoth-core wfuzz '
    'wireshark-common x11vnc xboard xrdp zaproxy '
    'chromium-bsu flightgear supertuxkart warzone2100 widelands dosbox pidgin-otr').split()
DUAL_USE_PACKAGES = 'netcat-openbsd netcat-traditional ncat tcpdump socat snort openvpn x11vnc remmina nfs-kernel-server'.split()
SUID_ABUSABLE = set('find vim vim.basic vi nano python python2 python3 perl ruby bash sh dash zsh cp mv less more awk gawk mawk env nmap tar zip '
                    'unzip nc ncat socat php node lua man tee xxd base64 dd cat head tail sed gdb strace ftp wget curl rsync tclsh'.split())
SUID_DEFAULT_DIRS = ('/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/lib', '/usr/libexec', '/usr/local/bin', '/usr/local/sbin', '/opt', '/home', '/tmp', '/var/tmp')
PROHIBITED_SERVICES = 'telnet.socket telnetd vsftpd proftpd pure-ftpd tftpd-hpa rsh.socket rlogin.socket rexec.socket snmpd nfs-server rpcbind apache2 lighttpd nginx xinetd xrdp x11vnc ypserv ypbind rpc-statd nfs-mountd tightvncserver vncserver openvpn tor privoxy isc-dhcp-server slapd'.split()
AUTO_STOP_SERVICES = set('openvpn tor privoxy isc-dhcp-server slapd apache2 nginx lighttpd smbd nmbd bind9 named dovecot postfix squid telnet telnetd vsftpd proftpd pure-ftpd tftpd-hpa rsh rlogin rexec snmpd xinetd xrdp x11vnc ypserv ypbind'.split())
SAFE_STOP_SERVICES = 'avahi-daemon cups cups-browsed bluetooth ModemManager whoopsie kerneloops speech-dispatcher colord geoclue apport'.split()
FIREFOX_PREFS = [
    'user_pref("dom.disable_open_during_load", true);',
    'user_pref("browser.safebrowsing.malware.enabled", true);',
    'user_pref("browser.safebrowsing.phishing.enabled", true);',
    'user_pref("browser.safebrowsing.downloads.enabled", true);',
    'user_pref("signon.rememberSignons", false);',
    'user_pref("app.update.auto", true);',
    'user_pref("privacy.donottrackheader.enabled", true);',
]
ROOT_FILES_OK = {'swapfile', 'swap.img', 'initrd.img', 'initrd.img.old', 'vmlinuz', 'vmlinuz.old', '.autorelabel', 'sentinel.lock'}
CRON_DEFAULT = {'e2scrub_all', 'php', 'popularity-contest', 'anacron', 'sysstat', '.placeholder', 'mdadm', 'certbot', 'ntpsec-ntpdate'}
TOOL_NAME_RE = re.compile(r'(^|/)(nmap|zenmap|john|hydra|nikto|aircrack|ophcrack|wireshark|netcat|nc|ncat|metasploit|msfconsole|sqlmap|burp|cain|wifite|ettercap|hping)[^/]*$', re.I)
SCRIPT_EXT_RE = re.compile(r'\.(sh|py|pl|rb|exe|bat|cmd|ps1|jar|apk|elf)$', re.I)


class Finding:
    def __init__(self, category, text, action, mode='review'):
        self.category, self.text, self.action, self.mode = category, text, action, mode
        self.key = hashlib.sha1(f'{category}|{text}|{action}'.encode()).hexdigest()[:12]


class Context:
    def __init__(self, engine_dir, root='/'):
        self.engine_dir, self.root = Path(engine_dir), Path(root)
        data = {}
        try:
            data = json.loads((self.engine_dir / 'data/readme_parsed.json').read_text(encoding='utf-8', errors='ignore'))
        except (OSError, ValueError):
            pass
        users = data.get('all_users', []) + [u for u in data.get('recent_hires', []) if isinstance(u, dict)]
        self.allowed_users = {u.get('name', '').lower() for u in users if isinstance(u, dict)}
        self.admin_users = {u.get('name', '').lower() for u in users if isinstance(u, dict) and u.get('account_type') == 'admin'}
        self.critical = [str(s).lower() for s in data.get('critical_services', [])]
        try:
            self.readme_text = (self.engine_dir / 'data/auto-source.html').read_text(encoding='utf-8', errors='ignore').lower()
        except OSError:
            self.readme_text = ''
        self.protected = {'root', os.environ.get('SUDO_USER', '').lower(), os.environ.get('PROTECTED_USER', '').lower()} - {''}
        for m in re.findall(r'([a-zA-Z_][a-zA-Z0-9_.-]*)\s*:\s*\S+\s*\(\s*you\s*\)', self.readme_text, re.I):
            self.protected.add(m.lower())

    def p(self, path):
        return self.root / str(path).lstrip('/')

    def readme_has(self, word):
        return any(word in c for c in self.critical) or re.search(r'\b' + re.escape(word) + r'\b', self.readme_text) is not None

    def mentioned(self, name):
        n = name.lower()
        return any(n in c or c in n for c in self.critical if len(c) > 2) or (len(n) > 3 and re.search(r'\b' + re.escape(n) + r'\b', self.readme_text) is not None)

    # --- system probes (overridable in tests)
    def installed_packages(self):
        out = subprocess.run(['dpkg-query', '-W', '-f', '${Package} ${Status}\n'], capture_output=True, text=True).stdout
        return [l.split()[0] for l in out.splitlines() if l.endswith('installed') and ' deinstall' not in l]

    def processes(self):
        procs = []
        for pid in filter(str.isdigit, os.listdir('/proc')):
            try:
                procs.append((int(pid), os.readlink(f'/proc/{pid}/exe')))
            except OSError:
                pass
        return procs

    def suid_files(self):
        out = subprocess.run(['find', '/', '-xdev', '-perm', '-4000', '-type', 'f'], capture_output=True, text=True).stdout
        return out.split()

    def unit_running(self, unit):
        """True if the systemd unit is active or enabled."""
        for verb in ('is-active', 'is-enabled'):
            if subprocess.run(['systemctl', verb, '--quiet', unit], capture_output=True).returncode == 0:
                return True
        return False

    def listeners(self):
        """(port, pid, process name) for every listening TCP/UDP socket."""
        out = subprocess.run(['ss', '-ltunpH'], capture_output=True, text=True).stdout
        found = []
        for line in out.splitlines():
            m = re.search(r':(\d+)\s+\S+\s+users:\(\("([^"]+)",pid=(\d+)', line)
            if m:
                found.append((int(m.group(1)), int(m.group(3)), m.group(2)))
        return found

    def snaps(self):
        out = subprocess.run(['snap', 'list'], capture_output=True, text=True).stdout.splitlines()[1:]
        return [l.split()[0] for l in out if l.split()]

    def password_status(self, user):
        out = subprocess.run(['passwd', '-S', user], capture_output=True, text=True).stdout.split()
        return out[1] if len(out) > 1 else ''

    def read(self, path):
        try:
            return self.p(path).read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return []

    def passwd_entries(self):
        entries = []
        for line in self.read('/etc/passwd'):
            f = line.split(':')
            if len(f) >= 7 and f[2].isdigit():
                entries.append({'name': f[0], 'uid': int(f[2]), 'home': f[5], 'shell': f[6]})
        return entries


def comment_lines(ctx, path, predicate):
    out = []
    for n, line in enumerate(ctx.read(path), 1):
        if line.strip() and not line.lstrip().startswith('#') and predicate(line):
            out.append((n, line.strip()))
    return out


def scan(ctx):
    found = []
    add = lambda *a, **k: found.append(Finding(*a, **k))

    # --- auto: known hacking tools / games (never README-mentioned or protected)
    try:
        installed = ctx.installed_packages()
    except (OSError, subprocess.SubprocessError):
        installed = []
    for pkg in installed:
        if pkg in BAD_PACKAGES and not ctx.mentioned(pkg) and not PROTECT_RE.search(pkg):
            add('hacking-package', f'{pkg} is a prohibited hacking tool/game', ('purge', pkg), 'auto')
        elif pkg in DUAL_USE_PACKAGES and not ctx.mentioned(pkg):
            # Network-sniffing/shell tools are plain "hacking tools" once the README forbids them; remote-access ones stay a judgment call.
            forbids = pkg in 'netcat-openbsd netcat-traditional ncat tcpdump socat snort'.split() and \
                re.search(r'hacking|penetration|prohibited (software|programs|tools)|unauthori[sz]ed (software|programs|tools)|no games', ctx.readme_text)
            add('dual-use-package', f'{pkg} is dual-use; remove unless the README needs it', ('purge', pkg), 'auto' if forbids else 'review')

    # --- auto: abusable SUID binaries
    try:
        suid = ctx.suid_files()
    except (OSError, subprocess.SubprocessError):
        suid = []
    for path in suid:
        if os.path.basename(path) in SUID_ABUSABLE:
            add('suid', f'{path} has the SUID bit (can give root)', ('chmod', path, 'u-s'), 'auto')
        elif path.startswith(('/home', '/tmp', '/var/tmp', '/dev/shm')):
            add('suid', f'{path} is SUID inside a user/temp folder', ('chmod', path, 'u-s'), 'auto')

    # --- auto: NOPASSWD / !authenticate sudo rules
    sudo_files = ['/etc/sudoers'] + [f'/etc/sudoers.d/{n}' for n in sorted(_listdir(ctx.p('/etc/sudoers.d'))) if not n.startswith('.') and n != 'README']
    for sf in sudo_files:
        for n, line in comment_lines(ctx, sf, lambda l: 'NOPASSWD' in l or '!authenticate' in l):
            add('sudoers', f'{sf}:{n}: {line}', ('comment-sudoers', sf, line), 'auto')

    # --- auto: sudo grants to people the README does not list as administrators
    for sf in sudo_files[1:]:
        for n, line in comment_lines(ctx, sf, lambda l: _sudo_grant_to_stranger(ctx, l)):
            add('sudoers-grant', f'{sf}:{n}: {line}', ('comment-sudoers', sf, line), 'auto')

    # --- auto: groups that are root in disguise (docker/lxd/disk/shadow) for anyone but the operator
    for line in ctx.read('/etc/group'):
        f = line.split(':')
        if len(f) >= 4 and f[0] in ROOT_EQUIV_GROUPS and not ctx.mentioned(f[0]):
            for member in filter(None, f[3].split(',')):
                if member.lower() not in ctx.protected:
                    add('privileged-group', f'{member} is in group {f[0]}, which is equivalent to root', ('gpasswd-del', member, f[0]), 'auto')

    # --- auto: hacking tools installed as snaps
    try:
        for name in ctx.snaps():
            if name in BAD_PACKAGES and not ctx.mentioned(name):
                add('hacking-snap', f'snap {name} is a prohibited hacking tool/game', ('snap-remove', name), 'auto')
    except (OSError, subprocess.SubprocessError):
        pass

    # --- review: binaries dropped into the local bin dirs (empty on a clean image)
    for d in ('/usr/local/bin', '/usr/local/sbin'):
        for n in sorted(_listdir(ctx.p(d))):
            if not PROTECT_RE.search(n):
                add('local-binary', f'{d}/{n} is a non-packaged program', ('rm', f'{d}/{n}'))

    # --- auto: backdoor one-liners in startup / cron files
    startup = ['/etc/crontab', '/etc/rc.local', '/etc/profile', '/etc/bash.bashrc', '/root/.bashrc', '/root/.profile']
    for d in ('/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly', '/etc/profile.d', '/var/spool/cron/crontabs'):
        startup += [f'{d}/{n}' for n in sorted(_listdir(ctx.p(d)))]
    for u in ctx.passwd_entries():
        if u['uid'] >= 1000 or u['name'] == 'root':
            startup += [f"{u['home']}/{n}" for n in ('.bashrc', '.profile', '.bash_profile', '.bash_aliases', '.bash_login')]
    for f in dict.fromkeys(startup):
        for n, line in comment_lines(ctx, f, lambda l: bool(BACKDOOR_RE.search(l))):
            add('backdoor-line', f'{f}:{n}: {line}', ('comment', f, line), 'auto')
        if f.startswith(('/var/spool/cron/crontabs/', '/etc/cron.d/', '/etc/crontab')):
            for n, line in comment_lines(ctx, f, lambda l: bool(CRON_EVIL_RE.search(l))):
                add('cron-line', f'{f}:{n}: {line}', ('comment', f, line), 'auto')
        for n, line in comment_lines(ctx, f, alias_hijacked):
            add('alias-hijack', f'{f}:{n}: {line}', ('comment', f, line), 'auto')

    # --- auto: autostart entries that launch a backdoor/temp program at login
    auto_dirs = ['/etc/xdg/autostart'] + [f"{u['home']}/.config/autostart" for u in ctx.passwd_entries() if u['uid'] >= 1000]
    for d in auto_dirs:
        for n in sorted(_listdir(ctx.p(d))):
            if n.endswith('.desktop'):
                af = f'{d}/{n}'
                for ln, line in comment_lines(ctx, af, lambda l: l.startswith('Exec') and bool(BACKDOOR_RE.search(l) or CRON_EVIL_RE.search(l))):
                    add('autostart', f'{af}:{ln}: {line}', ('comment', af, line), 'auto')

    # --- auto: empty-password regular accounts (lock them; never the operator)
    for u in ctx.passwd_entries():
        if u['uid'] >= 1000 and u['uid'] < 65534 and u['name'].lower() not in ctx.protected:
            try:
                if ctx.password_status(u['name']) == 'NP':
                    add('empty-password', f"{u['name']} has no password", ('lock-user', u['name']), 'auto')
            except (OSError, subprocess.SubprocessError):
                pass

    # --- auto: unsupported resolver lines that print "bad command" on every command
    for n, line in comment_lines(ctx, '/etc/host.conf', lambda l: re.match(r'\s*(nospoof|spoof|spoofalert)\b', l, re.I) is not None):
        add('host-conf', f'/etc/host.conf:{n}: {line} (glibc rejects this line)', ('del-line', '/etc/host.conf', line), 'auto')

    # --- auto: Firefox hardening in every profile (user.js is applied at each start)
    for pattern in ('home/*/.mozilla/firefox/*/prefs.js', 'home/*/snap/firefox/common/.mozilla/firefox/*/prefs.js'):
        for prefs in sorted(ctx.root.glob(pattern)):
            userjs = prefs.with_name('user.js')
            have = set()
            try:
                have = {l.strip() for l in userjs.read_text(encoding='utf-8', errors='replace').splitlines()}
            except OSError:
                pass
            missing = [l for l in FIREFOX_PREFS if l not in have]
            if missing:
                rel = '/' + str(userjs.relative_to(ctx.root)).replace(os.sep, '/')
                add('firefox', f'{rel} lacks {len(missing)} secure Firefox setting(s)', ('ensure-lines', rel, missing), 'auto')

    # --- services: harmless extras off automatically; risky ones are your call; README services untouched
    for unit in SAFE_STOP_SERVICES:
        if not ctx.mentioned(unit.split('.')[0]) and _unit_on(ctx, unit):
            add('service-off', f'{unit} is a non-essential service', ('disable-unit', unit), 'auto')
    for unit in PROHIBITED_SERVICES:
        if not ctx.mentioned(unit.split('.')[0]) and _unit_on(ctx, unit):
            add('prohibited-service', f'{unit} is running/enabled and not a README critical service', ('disable-unit', unit),
                'auto' if unit.split('.')[0] in AUTO_STOP_SERVICES else 'review')

    # --- auto: SSH when the README never mentions it (CP scores "OpenSSH service is disabled or removed")
    if ctx.readme_text and len(ctx.readme_text) > 200 and not ctx.readme_has('ssh'):
        for unit in ('ssh', 'sshd', 'ssh.socket'):
            if _unit_on(ctx, unit):
                add('ssh-not-needed', f'{unit} is running but the README never mentions SSH', ('disable-unit', unit), 'auto')

    # --- auto: PAM rules that skip authentication (backdoors); review: sufficient pam_succeed_if
    for n in sorted(_listdir(ctx.p('/etc/pam.d'))):
        pf = f'/etc/pam.d/{n}'
        for ln, line in comment_lines(ctx, pf, lambda l: bool(PAM_BACKDOOR_RE.search(l))):
            add('pam-backdoor', f'{pf}:{ln}: {line}', ('comment', pf, line), 'auto')
        for ln, line in comment_lines(ctx, pf, lambda l: bool(PAM_SUSPECT_RE.search(l)) and n != 'lightdm'):
            add('pam-suspect', f'{pf}:{ln}: {line}', ('comment', pf, line))

    # --- review: scripting interpreters listening on a port (nc is handled above)
    try:
        for port, pid, name in ctx.listeners():
            if name in LISTEN_SUSPECT and name not in BACKDOOR_NAMES:
                add('suspect-listener', f'{name} (pid {pid}) is listening on port {port}', ('kill', pid, name))
    except (OSError, subprocess.SubprocessError):
        pass

    # --- review: accounts
    for u in ctx.passwd_entries():
        name = u['name'].lower()
        if u['uid'] == 0 and name != 'root':
            add('uid0-user', f"{u['name']} has UID 0 (a second root)", ('userdel', u['name']), 'auto')
        elif u['uid'] >= 1000 and u['uid'] < 65534 and ctx.allowed_users and name not in ctx.allowed_users and name not in ctx.protected:
            add('unauthorized-user', f"{u['name']} is not in the README user lists", ('userdel', u['name']))
    for line in ctx.read('/etc/group'):
        f = line.split(':')
        if len(f) >= 4 and f[0] in ('sudo', 'admin', 'wheel'):
            for member in filter(None, f[3].split(',')):
                if ctx.admin_users and member.lower() not in ctx.admin_users and member.lower() not in ctx.protected:
                    add('extra-admin', f'{member} is in group {f[0]} but README does not list them as an administrator', ('gpasswd-del', member, f[0]))

    # --- review: files and persistence
    for name in sorted(_listdir(ctx.p('/'))):
        path = ctx.p('/') / name
        if path.is_file() and not path.is_symlink() and name not in ROOT_FILES_OK:
            add('loose-root-file', f'/{name} is a loose file at the top of /', ('rm', f'/{name}'))
    for n in sorted(_listdir(ctx.p('/etc/cron.d'))):
        if n not in CRON_DEFAULT:
            body = ' '.join(l for l in ctx.read(f'/etc/cron.d/{n}') if not l.lstrip().startswith('#'))
            evil = bool(re.search(r'(/tmp/|/var/tmp/|/dev/shm/|/home/)', body)) or bool(BACKDOOR_RE.search(body))
            add('cron', f'/etc/cron.d/{n} is not a default cron file', ('rm', f'/etc/cron.d/{n}'), 'auto' if evil else 'review')
    for n in sorted(_listdir(ctx.p('/etc/systemd/system'))):
        if n.endswith('.service'):
            exec_lines = [l for l in ctx.read(f'/etc/systemd/system/{n}') if l.startswith('ExecStart')]
            if any(re.search(r'/(home|tmp|var/tmp|dev/shm)/', l) or BACKDOOR_RE.search(l) for l in exec_lines):
                add('service', f'{n} runs {exec_lines[0]}', ('disable-unit', n))
    for line in ctx.read('/etc/hosts'):
        s = line.strip()
        if s and not s.startswith('#') and not re.search(r'localhost|127\.0\.1\.1|ip6-|^::1|^ff0[02]::', s):
            add('hosts', f'/etc/hosts entry: {s}', ('del-line', '/etc/hosts', line))
    for u in ctx.passwd_entries():
        if u['uid'] >= 1000 or u['name'] == 'root':
            keys = [l.strip() for l in ctx.read(f"{u['home']}/.ssh/authorized_keys") if l.strip() and not l.startswith('#')]
            for k in keys:
                if u['name'].lower() in ctx.protected and u['name'] != 'root' and _key_known(ctx, k):
                    continue
                add('ssh-key', f"{u['name']} authorized key: {k[:60]}...", ('del-line', f"{u['home']}/.ssh/authorized_keys", k), 'auto')
            home = ctx.p(u['home'])
            for pattern in ('Desktop', 'Documents', 'Downloads', 'Music', 'Videos', 'Pictures'):
                base = home / pattern
                for f in _walk(base, depth=3):
                    rel = '/' + str(f.relative_to(ctx.root)).replace(os.sep, '/')
                    if 'cp-linux-setup' in rel or PROTECT_RE.search(rel) or re.search(r'forensics|scoring|readme', f.name, re.I):
                        continue
                    if TOOL_NAME_RE.search(rel) or SCRIPT_EXT_RE.search(f.name):
                        add('user-file', f'{rel} (script/executable/tool in a user folder)', ('rm', rel))

    # --- auto: network backdoors (nc/socat listeners) and PHP web shells
    try:
        for port, pid, name in ctx.listeners():
            if name in BACKDOOR_NAMES:
                add('backdoor-listener', f'{name} (pid {pid}) is listening on port {port}', ('kill', pid, name), 'auto')
    except (OSError, subprocess.SubprocessError):
        pass
    for base in ('/var/www', '/srv', '/usr/share/nginx', '/opt'):
        for f in _walk(ctx.p(base), depth=8):
            if f.suffix.lower() in ('.php', '.phtml', '.php5', '.phar') and ctx.engine_dir.resolve() not in f.resolve().parents and 'sentinel-backups' not in f.parts:
                try:
                    if f.stat().st_size > 2_000_000:
                        continue
                    text = f.read_text(encoding='utf-8', errors='ignore')
                except OSError:
                    continue
                if WEBSHELL_RE.search(text):
                    rel = '/' + str(f.relative_to(ctx.root)).replace(os.sep, '/')
                    add('webshell', f'{rel} looks like a PHP web shell', ('rm', rel), 'auto')
    # --- unpackaged files holding reverse-shell code (dpkg-aware, anywhere under system/home trees)
    try:
        import forensics_det
        for score, rel, why in forensics_det.backdoor_candidates(forensics_det.Evidence(str(ctx.root), ctx.readme_text)):
            if 'cp-linux-setup' in rel or PROTECT_RE.search(rel) or ctx.engine_dir.resolve() in Path(ctx.p(rel)).resolve().parents:
                continue
            add('backdoor-file', f'{rel} is not part of any package: {why}', ('rm', rel), 'auto' if score >= 10 else 'review')
    except Exception:  # an optional scanner must never take the sentinel down
        pass
    # --- media files (README forbids them): audio/video always, pictures in the user's own folders
    media_ext = {'.mp3', '.mp4', '.m4a', '.m4v', '.aac', '.ogg', '.oga', '.opus', '.wav', '.flac', '.wma', '.wmv', '.avi', '.mkv', '.mov', '.webm', '.mpg', '.mpeg', '.flv'}
    picture_ext = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.heic'}
    forbidden = re.search(r'media (files?|content)|\bmusic\b|\bmp3|audio files?|video files?|pictures?|photos?', ctx.readme_text) is not None
    for home in [Path(ctx.p('/root'))] + sorted(Path(ctx.p('/home')).glob('*')):
        for f in _walk(home, depth=4):
            parts = f.relative_to(home).parts
            if not f.is_file() or f.is_symlink() or any(p.startswith('.') or p in ('snap', 'cp-linux-setup') for p in parts):
                continue
            ext = f.suffix.lower()
            rel = '/' + str(f.relative_to(ctx.root)).replace(os.sep, '/')
            if ext in media_ext:
                add('media-file', f'{rel} is an audio/video file', ('rm', rel), 'auto' if forbidden else 'review')
            elif ext in picture_ext and parts[0] in ('Downloads', 'Documents', 'Desktop', 'Pictures', 'Music', 'Videos', 'Public') and forbidden:
                add('media-file', f'{rel} is a picture in a user folder and the README prohibits media', ('rm', rel), 'auto')
    for base in ('/tmp', '/var/tmp', '/dev/shm'):
        for f in _walk(ctx.p(base), depth=3):
            if f.is_file() and os.access(f, os.X_OK) and not f.is_symlink() and not PROTECT_RE.search(str(f)) and 'cp-linux-setup' not in str(f):
                rel = '/' + str(f.relative_to(ctx.root)).replace(os.sep, '/')
                add('temp-executable', f'{rel} is an executable file in a temp directory', ('rm', rel))

    # --- review: running programs from user/temp locations
    try:
        for pid, exe in ctx.processes():
            if re.match(r'/(home|tmp|var/tmp|dev/shm|run/user)/', exe) and not PROTECT_RE.search(exe) and 'cp-linux-setup' not in exe:
                add('process', f'pid {pid} runs {exe}', ('kill', pid, exe))
    except OSError:
        pass
    return found


def _unit_on(ctx, unit):
    try:
        return ctx.unit_running(unit)
    except (OSError, subprocess.SubprocessError):
        return False


def _listdir(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def _walk(base, depth):
    if not base.is_dir():
        return
    for dirpath, dirs, files in os.walk(base):
        if Path(dirpath).relative_to(base).parts.__len__() >= depth:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in ('.cache', 'snap', '.git', 'node_modules')]
        for f in files:
            yield Path(dirpath) / f


def _key_known(ctx, key):
    """The README says to use the key from root's home for the main user; that key is legitimate."""
    parts = key.split()
    blob = parts[1] if len(parts) > 1 else key
    for pub in list(ctx.p('/root').glob('*.pub')) + list(ctx.p('/root/.ssh').glob('*.pub')):
        try:
            if blob in pub.read_text(errors='ignore'):
                return True
        except OSError:
            pass
    return False


# ---------------------------------------------------------------- actions
def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


VITAL_RE = re.compile(r'^(ubuntu-(desktop|minimal|standard)|mint-meta|linuxmint|cinnamon|mate-desktop|xfce4|gnome-shell|lightdm|gdm3|sddm|xorg|xserver-xorg|'
                      r'sudo|libpam|systemd|apt|dpkg|libc6|bash|coreutils|network-manager|netplan|grub|linux-image|linux-generic|firefox|chromium|'
                      r'libreoffice|openssh-server|apache2|nginx|mysql|mariadb|postgresql|samba|vsftpd|python3|ufw|cups)', re.I)


def _purge_collateral(pkg):
    """Names apt would remove besides pkg that are vital (or too many): simulate before purging."""
    try:
        out = subprocess.run(['apt-get', '-s', 'purge', pkg], capture_output=True, text=True, timeout=120,
                             env=dict(os.environ, DEBIAN_FRONTEND='noninteractive')).stdout
    except (OSError, subprocess.SubprocessError):
        return ''
    gone = [l.split()[1] for l in out.splitlines() if l.startswith('Remv ') and len(l.split()) > 1]
    others = [g for g in gone if g != pkg]
    bad = [g for g in others if VITAL_RE.match(g)]
    if bad:
        return ', '.join(bad[:4])
    return f'{len(others)} packages' if len(others) > 25 else ''


def _force_remove_user(ctx, name):
    """userdel refuses a second UID-0 account ("used by process 1"); edit the account files directly."""
    home = ''
    for line in ctx.read('/etc/passwd'):
        f = line.split(':')
        if f[0] == name and len(f) > 5:
            home = f[5]
    for path in ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow'):
        real = Path(ctx.p(path))
        if not real.exists():
            continue
        out = []
        for line in real.read_text().splitlines():
            f = line.split(':')
            if f[0] == name:
                continue
            if path.endswith(('group', 'gshadow')) and len(f) >= 4:
                idx = 3
                f[idx] = ','.join(m for m in f[idx].split(',') if m and m != name)
                line = ':'.join(f)
            out.append(line)
        real.write_text(chr(10).join(out) + chr(10))
    if home.startswith('/home/') and Path(ctx.p(home)).is_dir():
        shutil.rmtree(ctx.p(home), ignore_errors=True)
    gone = not any(l.split(':')[0] == name for l in ctx.read('/etc/passwd'))
    return gone, f'force-removed user {name}'


_APT_QUIET = []


def quiesce_apt():
    """Background apt jobs (unattended-upgrade, apt-daily) hold the dpkg lock for hours; stop them once."""
    if _APT_QUIET or os.geteuid() != 0:
        return
    _APT_QUIET.append(1)
    for unit in ('unattended-upgrades.service', 'apt-daily.service', 'apt-daily-upgrade.service', 'apt-daily.timer', 'apt-daily-upgrade.timer'):
        run(['systemctl', 'stop', unit], timeout=60)
    run(['pkill', '-f', 'unattended-upgrade'], timeout=30)
    run(['pkill', '-f', 'apt.systemd.daily'], timeout=30)


def apply(ctx, finding):
    """Perform one finding's fix. Returns (ok, message). Paths are re-validated against the root prefix."""
    act = finding.action
    kind = act[0]
    try:
        if kind == 'purge':
            quiesce_apt()
            unsafe = _purge_collateral(act[1])
            if unsafe:
                return False, f'refused to purge {act[1]}: apt would also remove {unsafe} (would break the desktop/system)'
            r = run(['apt-get', '-o', 'DPkg::Lock::Timeout=300', 'purge', '-y', act[1]],
                    env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'), stdin=subprocess.DEVNULL, timeout=600)
            blob = (r.stderr or '') + (r.stdout or '')
            if r.returncode != 0 and ('Unmet dependencies' in blob or 'fix-broken' in blob):
                run(['apt-get', '-o', 'DPkg::Lock::Timeout=300', '-f', 'install', '-y'],
                    env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'), stdin=subprocess.DEVNULL, timeout=900)
                r = run(['apt-get', '-o', 'DPkg::Lock::Timeout=300', 'purge', '-y', act[1]],
                        env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'), stdin=subprocess.DEVNULL, timeout=600)
            if r.returncode != 0 and 'dpkg --configure -a' in (r.stderr or '') + (r.stdout or ''):
                run(['dpkg', '--configure', '-a'], env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'), stdin=subprocess.DEVNULL, timeout=600)
                r = run(['apt-get', '-o', 'DPkg::Lock::Timeout=300', 'purge', '-y', act[1]],
                        env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'), stdin=subprocess.DEVNULL, timeout=600)
            if r.returncode == 0:
                return True, f'purged {act[1]}'
            tail = ((r.stderr or r.stdout).strip().splitlines() or ['no output'])[-1][:120]
            return False, f'apt could not purge {act[1]}: {tail}'
        if kind == 'chmod':
            r = run(['chmod', act[2], str(ctx.p(act[1]))])
            return r.returncode == 0, f'chmod {act[2]} {act[1]}'
        if kind == 'rm':
            path = ctx.p(act[1])
            if path.is_dir() and not path.is_symlink():
                return False, f'refusing to remove directory {act[1]}'
            _backup(ctx, path)
            path.unlink()
            return True, f'removed {act[1]}'
        if kind in ('comment', 'del-line'):
            path = ctx.p(act[1])
            lines = path.read_text(encoding='utf-8', errors='replace').splitlines(keepends=True)
            target = act[2].strip()
            out, changed = [], False
            for line in lines:
                if line.strip() == target and not line.lstrip().startswith('# [sentinel]'):
                    changed = True
                    if kind == 'comment':
                        out.append('# [sentinel] ' + line)
                    continue
                out.append(line)
            if changed:
                _backup(ctx, path)
                path.write_text(''.join(out), encoding='utf-8')
            return True, (f'{kind} in {act[1]}' if changed else f'{act[1]} already clean')
        if kind == 'comment-sudoers':
            path = ctx.p(act[1])
            original = path.read_text(encoding='utf-8', errors='replace')
            new = ''.join(('# [sentinel] ' + l if l.strip() == act[2].strip() else l) for l in original.splitlines(keepends=True))
            tmp = path.with_name(path.name + '.sentinel.tmp')
            tmp.write_text(new, encoding='utf-8')
            check = run(['visudo', '-cf', str(tmp)]) if ctx.root == Path('/') else None
            if check is not None and check.returncode != 0:
                tmp.unlink()
                return False, f'visudo rejected edit of {act[1]}; left unchanged'
            _backup(ctx, path)
            tmp.replace(path)
            return True, f'commented sudo rule in {act[1]}'
        if kind == 'ensure-lines':
            path = ctx.p(act[1])
            existing = path.read_text(encoding='utf-8', errors='replace') if path.exists() else ''
            have = {l.strip() for l in existing.splitlines()}
            add_lines = [l for l in act[2] if l not in have]
            _backup(ctx, path)
            with open(path, 'a', encoding='utf-8') as fh:
                if existing and not existing.endswith('\n'):
                    fh.write('\n')
                fh.write('\n'.join(add_lines) + '\n')
            try:
                st = path.parent.joinpath('prefs.js').stat()
                os.chown(path, st.st_uid, st.st_gid)
            except OSError:
                pass
            return True, f'ensured {len(add_lines)} setting(s) in {act[1]}'
        if kind == 'lock-user':
            return run(['passwd', '-l', act[1]]).returncode == 0, f'locked {act[1]}'
        if kind == 'userdel':
            if act[1].lower() in ctx.protected:
                return False, 'refusing to delete protected account'
            if run(['userdel', '-r', act[1]]).returncode in (0, 12):
                return True, f'deleted user {act[1]}'
            return _force_remove_user(ctx, act[1])
        if kind == 'gpasswd-del':
            return run(['gpasswd', '-d', act[1], act[2]]).returncode == 0, f'removed {act[1]} from {act[2]}'
        if kind == 'disable-unit':
            run(['systemctl', 'disable', '--now', act[1]])
            return True, f'disabled {act[1]}'
        if kind == 'snap-remove':
            return run(['snap', 'remove', '--purge', act[1]]).returncode == 0, f'removed snap {act[1]}'
        if kind == 'kill':
            run(['kill', '-9', str(act[1])])
            return True, f'killed pid {act[1]}'
    except (OSError, subprocess.SubprocessError) as error:
        return False, f'{kind} failed: {error}'
    return False, f'unknown action {kind}'


def _backup(ctx, path):
    try:
        dest = ctx.engine_dir / 'data/sentinel-backups'
        dest.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            (dest / (time.strftime('%H%M%S-') + path.name)).write_bytes(path.read_bytes())
    except OSError:
        pass


# ---------------------------------------------------------------- loop / UI
def load_state(ctx):
    try:
        return json.loads((ctx.engine_dir / 'data/sentinel-state.json').read_text())
    except (OSError, ValueError):
        return {}


def save_state(ctx, state):
    path = ctx.engine_dir / 'data/sentinel-state.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=1))


def parse_picks(text, count):
    text = text.strip().lower()
    if text in ('', 'none', 'n'):
        return []
    if text in ('all', 'a'):
        return list(range(count))
    picks = set()
    for part in re.split(r'[,\s]+', text):
        m = re.fullmatch(r'(\d+)(?:-(\d+))?', part)
        if m:
            lo, hi = int(m[1]), int(m[2] or m[1])
            picks.update(i - 1 for i in range(lo, hi + 1) if 1 <= i <= count)
    return sorted(picks)


def ask(prompt):
    try:
        with open('/dev/tty', 'r+') as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline()
    except OSError:
        return None


def score_line(engine_dir):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import score_tracker
        report = score_tracker.find_scoring_report()
        if not report:
            return None, None
        info = score_tracker.parse_scoring_report(report.read_text(encoding='utf-8', errors='ignore'))
        return info.get('score'), info.get('max_score')
    except Exception:
        return None, None


def log_path(ctx):
    return ctx.engine_dir / 'data/sentinel-log.json'


def record_fix(ctx, text):
    try:
        entries = json.loads(log_path(ctx).read_text())
    except (OSError, ValueError):
        entries = []
    entries.append(f"{time.strftime('%H:%M:%S')} {text}")
    log_path(ctx).parent.mkdir(parents=True, exist_ok=True)
    log_path(ctx).write_text(json.dumps(entries[-200:], indent=1))


def desktop_md_path(ctx):
    user = os.environ.get('SUDO_USER', '')
    candidates = [ctx.p(f'/home/{user}/Desktop')] if user else []
    candidates += sorted(ctx.root.glob('home/*/Desktop'))
    for d in candidates:
        if d.is_dir():
            return d / 'SENTINEL-ALERTS.md'
    return None


def write_desktop_md(ctx, items, text_cmds):
    path = desktop_md_path(ctx)
    if not path:
        return
    try:
        fixed = json.loads(log_path(ctx).read_text())
    except (OSError, ValueError):
        fixed = []
    out = ['# Sentinel report', '', f"_Updated {time.strftime('%H:%M:%S')}_", '']
    out += [f'## Needs your eyes ({len(items)})', '']
    out += [f"- [ ] **{i}.** `{it['category']}` {it['text']}" for i, it in enumerate(items, 1)] or ['_Nothing pending - all clear._']
    out += ['', '**Fix some:** ' + text_cmds, '', f'## Fixed automatically ({len(fixed)})', '']
    out += [f'- {line}' for line in fixed[-40:]] or ['_Nothing yet._']
    try:
        path.write_text('\n'.join(out) + '\n', encoding='utf-8')
        st = path.parent.stat()
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass


def pending_path(ctx):
    return ctx.engine_dir / 'data/sentinel-pending.json'


def load_pending(ctx):
    try:
        return json.loads(pending_path(ctx).read_text())
    except (OSError, ValueError):
        return []


def save_pending(ctx, items):
    pending_path(ctx).parent.mkdir(parents=True, exist_ok=True)
    pending_path(ctx).write_text(json.dumps(items, indent=1))
    lines = ['SENTINEL: things I could not safely decide - please check these', '']
    lines += [f"{i:>2}. [{it['category']}] {it['text']}" for i, it in enumerate(items, 1)]
    lines += ['', 'To fix some:  sudo python3 ~/cp-linux-setup/lib/sentinel.py --fix 1,3     (or --fix all)',
              'To dismiss:   sudo python3 ~/cp-linux-setup/lib/sentinel.py --dismiss all']
    text = '\n'.join(lines) + '\n'
    (ctx.engine_dir / 'data/sentinel-review.txt').write_text(text)
    write_desktop_md(ctx, items, '`sudo python3 ~/cp-linux-setup/lib/sentinel.py --fix 1,3` (or `--fix all`, `--dismiss all`)')
    return text


def notify(ctx, message):
    """Best-effort desktop popup for the logged-in user, plus a file on their Desktop."""
    user = os.environ.get('SUDO_USER', '')
    try:
        if user and ctx.root == Path('/'):
            uid = subprocess.run(['id', '-u', user], capture_output=True, text=True).stdout.strip()
            env = dict(os.environ, DISPLAY=':0', DBUS_SESSION_BUS_ADDRESS=f'unix:path=/run/user/{uid}/bus')
            # runuser, not sudo: sudo runs the invoker's PAM account check and stalls on an expired root password
            subprocess.run(['runuser', '-u', user, '--', 'env', f'DISPLAY=:0', f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus', 'notify-send', '-u', 'critical', 'Sentinel: check these', message[:200]], env=env, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def publish_alert(ctx, items, log):
    text = save_pending(ctx, items)
    log('\n' + '=' * 62 + f"\n  ALERT: {len(items)} item(s) need your eyes - I scanned and found these:\n" + '=' * 62)
    for i, it in enumerate(items, 1):
        log(f"   {i:>2}. [{it['category']}] {it['text']}")
    log('\n  Fix some:  sudo python3 lib/sentinel.py --fix 1,3   (or --fix all) from a second terminal.\n  Full list: data/sentinel-review.txt\n' + '=' * 62)
    notify(ctx, f'{len(items)} suspicious item(s) found. See data/sentinel-review.txt')


def run_fix(ctx, selection, dismiss=False, log=print):
    state, items = load_state(ctx), load_pending(ctx)
    picks = parse_picks(selection, len(items))
    keep = []
    for i, it in enumerate(items):
        if i not in picks:
            keep.append(it)
        elif dismiss:
            state[it['key']] = 'kept'
        else:
            ok, msg = apply(ctx, Finding(it['category'], it['text'], tuple(it['action'])))
            state[it['key']] = 'done' if ok else 'failed'
            log(f"  [{'fixed' if ok else 'FAILED'}] {msg}")
            if ok:
                record_fix(ctx, f"{it['category']}: {it['text']}")
            if not ok:
                keep.append(it)
    save_state(ctx, state)
    save_pending(ctx, keep)
    return len(picks)


MAX_RETRIES = 3


def _failures(state, key):
    value = str(state.get(key, ''))
    return int(value.split(':')[1]) if value.startswith('failed:') else (MAX_RETRIES if value == 'failed' else 0)


def redate_accounts(ctx):
    """Keep root and the operator from ever hitting 'password expired' (sudo/su would stall on a prompt)."""
    if ctx.root != Path('/'):
        return
    for user in sorted(ctx.protected):
        subprocess.run(['chage', '-d', time.strftime('%Y-%m-%d'), '-E', '-1', '-I', '-1', user], capture_output=True)


def one_pass(ctx, state, auto_only=False, ask_mode=False, log=print):
    redate_accounts(ctx)
    findings = scan(ctx)
    new_auto = [f for f in findings if f.mode == 'auto' and state.get(f.key) != 'done' and _failures(state, f.key) < MAX_RETRIES]
    for f in new_auto:
        ok, msg = apply(ctx, f)
        state[f.key] = 'done' if ok else f'failed:{_failures(state, f.key) + 1}'
        log(f"  [auto] {'fixed' if ok else 'FAILED'}: {f.text} -> {msg}")
        if ok:
            record_fix(ctx, f'{f.category}: {f.text}')
    review = [f for f in findings if f.mode == 'review' and state.get(f.key) not in ('kept', 'done')]
    fresh = [f for f in review if f.key not in state]
    if review and not auto_only:
        if ask_mode:
            log(f'\n  {len(review)} item(s) look suspicious - YOU decide (nothing is removed unless picked):')
            for i, f in enumerate(review, 1):
                log(f'   {i:>2}. [{f.category}] {f.text}')
            answer = ask('  Fix which? (numbers like 1,3 or 2-4, "all", Enter = none): ')
            picks = parse_picks(answer or '', len(review)) if answer is not None else []
            for i, f in enumerate(review):
                if i in picks:
                    ok, msg = apply(ctx, f)
                    state[f.key] = 'done' if ok else 'failed'
                    log(f"  [{'fixed' if ok else 'FAILED'}] {msg}")
                elif answer is not None:
                    state[f.key] = 'kept'
        else:
            for f in fresh:
                state[f.key] = 'alerted'
            items = [{'key': f.key, 'category': f.category, 'text': f.text, 'action': list(f.action)} for f in review]
            if fresh or not pending_path(ctx).exists():
                publish_alert(ctx, items, log)
            else:
                save_pending(ctx, items)
    elif not review:
        save_pending(ctx, [])
    if new_auto and not review and not auto_only:
        save_pending(ctx, [])
    return len(new_auto), len(fresh)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--once', action='store_true')
    ap.add_argument('--interval', type=int, default=60)
    ap.add_argument('--auto-only', action='store_true')
    ap.add_argument('--root', default='/')
    ap.add_argument('--ask', action='store_true', help='stop and ask about suspicious items instead of alerting')
    ap.add_argument('--fix', metavar='N,N|all', help='apply fixes for alerted items, then exit')
    ap.add_argument('--dismiss', metavar='N,N|all', help='mark alerted items as fine, then exit')
    args = ap.parse_args()
    engine_dir = Path(__file__).resolve().parents[1]
    ctx = Context(engine_dir, args.root)
    if args.fix or args.dismiss:
        count = run_fix(ctx, args.fix or args.dismiss, dismiss=bool(args.dismiss))
        print(f'  {count} item(s) handled.')
        return 0
    state = load_state(ctx)
    print('Sentinel: scanning and fixing until the image is clean (Ctrl-C to stop).', flush=True)
    last_score, quiet, rounds = None, 0, 0
    while True:
        rounds += 1
        fixed, pending = one_pass(ctx, state, args.auto_only, args.ask)
        save_state(ctx, state)
        score, max_score = score_line(engine_dir)
        if score is not None:
            delta = '' if last_score is None else f' ({score - last_score:+d})'
            print(f'  Score: {score}/{max_score}{delta}', flush=True)
            if score >= max_score > 0:
                print('  FULL POINTS - sentinel done.', flush=True)
                return 0
            last_score = score
        quiet = quiet + 1 if not fixed and not pending else 0
        if args.once:
            return 0
        if quiet >= 3:
            print('  Nothing new for 3 passes; still watching every %ds (Ctrl-C to stop).' % args.interval, flush=True)
            quiet = 0
        try:
            time.sleep(15 if rounds <= 3 else args.interval)  # quick early rounds, then settle
        except KeyboardInterrupt:
            print('\nSentinel stopped.')
            return 0


if __name__ == '__main__':
    sys.exit(main())
