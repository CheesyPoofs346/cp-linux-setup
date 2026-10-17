"""CyberPatriot autonomous score tracker and continuous remediation optimizer."""
import glob
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def restore_scoring_service():
    """Restores CyberPatriot scoring services if disabled or masked."""
    restored = False
    patterns = [
        '/etc/systemd/system/*score*.disabled',
        '/lib/systemd/system/*score*.disabled',
        '/usr/lib/systemd/system/*score*.disabled',
        '/etc/systemd/system/*cyberpatriot*.disabled',
        '/lib/systemd/system/*cyberpatriot*.disabled',
        '/etc/systemd/system/*aeacus*.disabled',
        '/lib/systemd/system/*aeacus*.disabled',
        '/etc/systemd/system/*secureboot*.disabled',
        '/lib/systemd/system/*secureboot*.disabled',
        '/etc/systemd/system/*kmod*.disabled',
        '/lib/systemd/system/*kmod*.disabled',
        '/etc/systemd/system/*ua-*.disabled',
        '/lib/systemd/system/*ua-*.disabled',
        '/etc/systemd/system/*ubuntu-*.disabled',
        '/lib/systemd/system/*ubuntu-*.disabled',
    ]
    for pattern in patterns:
        for path in glob.glob(pattern):
            target = path[:-9]  # remove .disabled
            try:
                os.replace(path, target)
                restored = True
            except Exception:
                pass

    if restored:
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)

    for svc in ['scoring', 'cyberpatriot', 'aeacus', 'ccs-client', 'secureboot-db', 'kmod-static-nodes', 'ua-timer', 'ubuntu-advantage']:
        try:
            subprocess.run(['systemctl', 'unmask', svc], capture_output=True)
            subprocess.run(['systemctl', 'enable', '--now', svc], capture_output=True)
        except Exception:
            pass


def find_scoring_report():
    """Finds the ScoringReport.html on Desktop or standard CyberPatriot directories."""
    patterns = [
        '/home/*/Desktop/*[Ss]coring*.html',
        '/home/*/Desktop/*[Ss]core*.html',
        '/root/Desktop/*[Ss]coring*.html',
        '/root/Desktop/*[Ss]core*.html',
        '/opt/CyberPatriot/*[Ss]coring*.html',
        '/opt/cyberpatriot/*[Ss]coring*.html',
        '/opt/aeacus/*[Ss]coring*.html',
        '/opt/aeacus/assets/*[Ss]coring*.html',
        '/var/log/cyberpatriot/*[Ss]core*.html',
        '/tmp/*[Ss]coring*.html',
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        for m in sorted(matches, key=os.path.getmtime, reverse=True):
            if os.path.isfile(m):
                return Path(m)
    return None


def parse_scoring_report(html_content):
    """Extracts score, max score, scored items, and penalties from report HTML."""
    info = {
        'score': None,
        'max_score': None,
        'num_vulns': 0,
        'scored_items': [],
        'penalties': []
    }
    clean_text = re.sub(r'<[^>]+>', ' ', html_content)
    clean_text = ' '.join(clean_text.split())

    # Score matching: e.g. "47 out of 100 points received" or "47 / 100 points"
    # Never match dates like 2026/10/17
    m_score = re.search(r'(\d{1,3})\s*(?:out\s+of|/)\s*(\d{1,3})\s*points(?:\s+received)?', clean_text, re.I)
    if not m_score:
        m_score = re.search(r'(?:score|total)[:\s]*(\d{1,3})\s*(?:out\s+of|/)\s*(\d{1,3})', clean_text, re.I)
    if not m_score:
        # Match "X out of Y" without slashes to avoid timestamps
        candidates = re.findall(r'(?<!\d[/-])(\b\d{1,3})\s+out\s+of\s+(\d{1,3}\b)(?![/-]\d)', clean_text, re.I)
        for s_str, m_str in candidates:
            s_val, m_val = int(s_str), int(m_str)
            if 0 <= s_val <= m_val and 40 <= m_val <= 200:
                info['score'] = s_val
                info['max_score'] = m_val
                break
    else:
        s_val, m_val = int(m_score.group(1)), int(m_score.group(2))
        if 0 <= s_val <= m_val and 40 <= m_val <= 200:
            info['score'] = s_val
            info['max_score'] = m_val

    # Number of scored vulnerabilities: e.g. "6 scored vulnerabilities found" or "(8 out of 18 scored checks)"
    m_vulns = re.search(r'(\d+)\s+scored\s+vulnerabilit', clean_text, re.I)
    if not m_vulns:
        m_vulns = re.search(r'\((\d+)\s+out\s+of\s+\d+\s+scored\s+checks\)', clean_text, re.I)
    if m_vulns:
        info['num_vulns'] = int(m_vulns.group(1))

    # Items scored
    for m in re.finditer(r'(?:<li\b[^>]*>|<tr\b[^>]*>|<div\b[^>]*>)(.*?)(?:</li>|</tr>|</div>)', html_content, re.I | re.S):
        chunk = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        if chunk and len(chunk) < 200 and not any(k in chunk.lower() for k in ['scoring report', 'vulnerabilities found', 'out of', 'style by', 'created by', 'do you want to clean', 'team id', 'penalt', 'report generated']):
            if chunk not in info['scored_items']:
                info['scored_items'].append(chunk)

    # Penalties
    for m in re.finditer(r'(?:penalty|penalties)[^<>\n]*[:\-]([^<>\n]+)', html_content, re.I):
        pen = m.group(1).strip()
        if pen and pen not in info['penalties']:
            info['penalties'].append(pen)

    return info


def run_command(cmd, timeout=10):
    try:
        res = subprocess.run(['bash', '-c', cmd], capture_output=True, timeout=timeout)
        return res.returncode, res.stdout.decode('utf-8', errors='replace').strip()
    except Exception as e:
        return 1, str(e)


def apply_targeted_hardening(engine_dir):
    """Executes high-impact CyberPatriot hardening fixes that frequently yield remaining points."""
    print("Score Optimizer: Applying targeted hardening passes...", flush=True)

    # 1. Firewall (UFW)
    run_command("ufw --force enable 2>/dev/null; ufw default deny incoming 2>/dev/null; ufw default allow outgoing 2>/dev/null")

    # Readme parsed service ports
    readme_json = engine_dir / 'data/readme_parsed.json'
    if readme_json.exists():
        try:
            rdata = json.loads(readme_json.read_text(encoding='utf-8', errors='ignore'))
            for svc in rdata.get('critical_services', []) + rdata.get('required_services', []):
                s = str(svc).lower()
                if 'ssh' in s: run_command("ufw allow 22/tcp 2>/dev/null")
                if 'http' in s or 'apache' in s or 'nginx' in s: run_command("ufw allow 80/tcp 2>/dev/null; ufw allow 443/tcp 2>/dev/null")
                if 'ftp' in s: run_command("ufw allow 21/tcp 2>/dev/null")
                if 'mysql' in s: run_command("ufw allow 3306/tcp 2>/dev/null")
                if 'samba' in s: run_command("ufw allow 445/tcp 2>/dev/null; ufw allow 139/tcp 2>/dev/null")
        except Exception:
            pass

    # 2. Critical file permissions
    perms = [
        ("chmod 644 /etc/passwd 2>/dev/null; chown root:root /etc/passwd 2>/dev/null"),
        ("chmod 640 /etc/shadow 2>/dev/null; chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow 2>/dev/null"),
        ("chmod 644 /etc/group 2>/dev/null; chown root:root /etc/group 2>/dev/null"),
        ("chmod 640 /etc/gshadow 2>/dev/null; chown root:shadow /etc/gshadow 2>/dev/null || chown root:root /etc/gshadow 2>/dev/null"),
        ("chmod 440 /etc/sudoers 2>/dev/null; chown root:root /etc/sudoers 2>/dev/null"),
        ("chmod 750 /etc/sudoers.d 2>/dev/null; chown root:root /etc/sudoers.d 2>/dev/null"),
        ("chmod 755 /usr/lib 2>/dev/null; chown root:root /usr/lib 2>/dev/null"),
        ("chmod 600 /etc/crontab 2>/dev/null; chown root:root /etc/crontab 2>/dev/null"),
    ]
    for p in perms:
        run_command(p)

    # 3. Password aging & policy in login.defs
    login_defs = Path('/etc/login.defs')
    if login_defs.exists():
        try:
            text = login_defs.read_text(encoding='utf-8', errors='ignore')
            text = re.sub(r'^\s*PASS_MAX_DAYS\s+\d+', 'PASS_MAX_DAYS 90', text, flags=re.M)
            text = re.sub(r'^\s*PASS_MIN_DAYS\s+\d+', 'PASS_MIN_DAYS 7', text, flags=re.M)
            text = re.sub(r'^\s*PASS_WARN_AGE\s+\d+', 'PASS_WARN_AGE 14', text, flags=re.M)
            login_defs.write_text(text, encoding='utf-8')
        except Exception:
            pass

    # Apply chage to all non-system accounts
    run_command("awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | while read u; do chage -M 90 -m 7 -W 14 \"$u\" 2>/dev/null || true; done")

    # 4. User Passwords (llitt weak password, edarby change at login)
    default_strong_pass = "CyberPatriot2026!#"
    run_command(f"if id llitt &>/dev/null; then echo 'llitt:{default_strong_pass}' | chpasswd 2>/dev/null; chage -M 90 -m 7 -W 14 llitt 2>/dev/null || true; fi")
    run_command("if id edarby &>/dev/null; then passwd -e edarby 2>/dev/null || chage -d 0 edarby 2>/dev/null || true; fi")

    # 5. Disable Guest Account & Automatic Login
    lightdm_conf = Path('/etc/lightdm/lightdm.conf.d/50-no-guest.conf')
    try:
        lightdm_conf.parent.mkdir(parents=True, exist_ok=True)
        lightdm_conf.write_text("[Seat:*]\nallow-guest=false\ngreeter-show-manual-login=false\ngreeter-hide-users=true\n")
    except Exception:
        pass

    gdm_conf = Path('/etc/gdm3/custom.conf')
    if gdm_conf.exists():
        try:
            gtext = gdm_conf.read_text(encoding='utf-8', errors='ignore')
            gtext = re.sub(r'AutomaticLoginEnable\s*=\s*true', 'AutomaticLoginEnable=false', gtext, flags=re.I)
            gdm_conf.write_text(gtext, encoding='utf-8')
        except Exception:
            pass

    # 6. SSH Hardening (Directly modify /etc/ssh/sshd_config AND sshd_config.d)
    sshd_config = Path('/etc/ssh/sshd_config')
    if sshd_config.exists():
        try:
            stext = sshd_config.read_text(encoding='utf-8', errors='ignore')
            if re.search(r'^\s*#?\s*PermitRootLogin', stext, flags=re.M):
                stext = re.sub(r'^\s*#?\s*PermitRootLogin\s+\S+', 'PermitRootLogin no', stext, flags=re.M)
            else:
                stext += '\nPermitRootLogin no\n'

            if re.search(r'^\s*#?\s*PermitEmptyPasswords', stext, flags=re.M):
                stext = re.sub(r'^\s*#?\s*PermitEmptyPasswords\s+\S+', 'PermitEmptyPasswords no', stext, flags=re.M)
            else:
                stext += '\nPermitEmptyPasswords no\n'

            if re.search(r'^\s*#?\s*Protocol', stext, flags=re.M):
                stext = re.sub(r'^\s*#?\s*Protocol\s+\S+', 'Protocol 2', stext, flags=re.M)

            if re.search(r'^\s*#?\s*X11Forwarding', stext, flags=re.M):
                stext = re.sub(r'^\s*#?\s*X11Forwarding\s+\S+', 'X11Forwarding no', stext, flags=re.M)

            if re.search(r'^\s*#?\s*MaxAuthTries', stext, flags=re.M):
                stext = re.sub(r'^\s*#?\s*MaxAuthTries\s+\S+', 'MaxAuthTries 4', stext, flags=re.M)

            sshd_config.write_text(stext, encoding='utf-8')
        except Exception:
            pass

    sshd_conf_d = Path('/etc/ssh/sshd_config.d/99-cyberpatriot.conf')
    try:
        sshd_conf_d.parent.mkdir(parents=True, exist_ok=True)
        sshd_conf_d.write_text("PermitRootLogin no\nPermitEmptyPasswords no\nX11Forwarding no\nMaxAuthTries 4\n")
    except Exception:
        pass
    run_command("systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true")

    # 7. Sysctl network security
    sysctl_file = Path('/etc/sysctl.d/99-cyberpatriot-hardening.conf')
    try:
        sysctl_file.write_text("""net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.ip_forward = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.randomize_va_space = 2
""")
        run_command("sysctl -p /etc/sysctl.d/99-cyberpatriot-hardening.conf 2>/dev/null || true")
    except Exception:
        pass

    # 8. Purge prohibited media in /home and /root
    run_command("find /home /root -type f \\( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.flac' -o -iname '*.mov' -o -iname '*.ogg' -o -iname '*.wma' -o -iname '*.wmv' -o -iname '*.m4a' \\) -delete 2>/dev/null || true")
    run_command("rm -rf /home/*/{Music,Videos,Downloads}/*.{mp3,mp4,wav,avi,mkv,flac,mov,ogg,wma,wmv,m4a} 2>/dev/null || true")

    # 9. Purge prohibited software: Wireshark, Zangband, Angband, hacking tools
    run_command("killall -9 wireshark tshark zangband angband 2>/dev/null || true")
    run_command("dpkg -P wireshark wireshark-common wireshark-qt tshark libwireshark-data libwireshark15 zangband zangband-data angband angband-data 2>/dev/null || true")
    run_command("DEBIAN_FRONTEND=noninteractive apt-get purge -y 'wireshark*' 'tshark*' 'zangband*' 'angband*' john hydra nmap zenmap aircrack-ng ophcrack medusa nikto sqlmap kismet dsniff tcpdump 2>/dev/null || true")
    run_command("rm -rf /usr/bin/wireshark /usr/bin/tshark /usr/bin/zangband /usr/games/zangband /usr/share/zangband /usr/games/angband /etc/wireshark 2>/dev/null || true")

    # 10. Insecure legacy services
    for dsvc in ['telnet', 'rsh-server', 'rsh-client', 'rsh-redone-server', 'rexec', 'finger', 'tftp', 'talk', 'nis', 'ypbind', 'avahi-daemon', 'cups', 'bluetooth']:
        run_command(f"systemctl stop {dsvc} 2>/dev/null; systemctl disable {dsvc} 2>/dev/null || true")

    # 11. Linux Mint Update Manager Automation & Auto-Refresh
    run_command("mintupdate-automation upgrade enable 2>/dev/null || true")
    run_command("mintupdate-automation autoremove enable 2>/dev/null || true")
    run_command("systemctl enable --now mintupdate-automation-upgrade.timer mintupdate-automation-autoremove.timer 2>/dev/null || true")
    run_command("systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true")

    apt_periodic = """APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
"""
    try:
        Path('/etc/apt/apt.conf.d/10periodic').write_text(apt_periodic, encoding='utf-8')
        Path('/etc/apt/apt.conf.d/20auto-upgrades').write_text(apt_periodic, encoding='utf-8')
    except Exception:
        pass

    dconf_dir = Path('/etc/dconf/db/local.d')
    try:
        dconf_dir.mkdir(parents=True, exist_ok=True)
        Path('/etc/dconf/profile/user').parent.mkdir(parents=True, exist_ok=True)
        Path('/etc/dconf/profile/user').write_text("user-db:user\nsystem-db:local\n", encoding='utf-8')
        (dconf_dir / '01-mintupdate').write_text("""[com/linuxmint/updates]
autorefresh-days=0
autorefresh-hours=2
autorefresh-minutes=0
auto-update=true
auto-update-enabled=true
refresh-schedule-enabled=true
automation-upgrade=true
automation-autoremove=true
remove-obsolete-kernels=true
""", encoding='utf-8')
        run_command("dconf update 2>/dev/null || true")
    except Exception:
        pass

    run_command("""for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    for k in auto-update refresh-schedule-enabled automation-upgrade auto-update-enabled; do
        sudo -u "$u" gsettings set com.linuxmint.updates "$k" true 2>/dev/null || true
    done
    sudo -u "$u" gsettings set com.linuxmint.updates autorefresh-hours 2 2>/dev/null || true
    sudo -u "$u" gsettings set com.linuxmint.updates autorefresh-minutes 0 2>/dev/null || true
done
gsettings set com.linuxmint.updates refresh-schedule-enabled true 2>/dev/null || true
gsettings set com.linuxmint.updates auto-update-enabled true 2>/dev/null || true
gsettings set com.linuxmint.updates automation-upgrade true 2>/dev/null || true
""")

    # 12. Critical Security Package Updates (systemd, chromium, openssh)
    run_command("DEBIAN_FRONTEND=noninteractive apt-get update -y 2>/dev/null || true")
    run_command("DEBIAN_FRONTEND=noninteractive apt-get --only-upgrade install -y systemd systemd-sysv libsystemd0 systemd-timesyncd chromium chromium-browser chromium-codecs-ffmpeg-extra openssh-server openssh-client openssh-sftp-server 2>/dev/null || true")


def query_ai_optimizer(report_info, engine_dir):
    """Uses configured reasoning model to inspect scoring gap and generate targeted commands."""
    try:
        from forensics_agent import call_ai
    except Exception:
        return

    readme_path = engine_dir / 'data/auto-source.html'
    readme_html = readme_path.read_text(encoding='utf-8', errors='ignore')[:5000] if readme_path.exists() else ''

    _, sockets = run_command("ss -tulpn | grep LISTEN")
    _, users = run_command("awk -F: '$3 >= 1000 {print $1}' /etc/passwd")

    prompt = f"""You are an elite CyberPatriot Linux competition solver.
Current Score: {report_info['score']} out of {report_info['max_score']} points.
Scored items so far:
{json.dumps(report_info['scored_items'], indent=2)}

README context:
{readme_html}

System listening sockets:
{sockets}

Users on system:
{users}

Analyze what vulnerabilities remain un-scored (e.g. unconfigured services, open backdoors, sudo privileges, PAM policies, file permissions, unauthorized packages).
Output ONLY valid JSON containing a list of safe shell remediation commands to fix the remaining items:
{{"remediations": [{{"cmd": "single bash command", "reason": "vulnerability fixed"}}]}}"""

    messages = [
        {"role": "system", "content": "You are a Linux security automation engineer. Output strictly valid JSON."},
        {"role": "user", "content": prompt}
    ]

    print("Score Optimizer: Consulting model for remaining unscored vulnerabilities...", flush=True)
    try:
        res = call_ai(messages)
        remediations = res.get('remediations', [])
        for item in remediations:
            cmd = item.get('cmd')
            reason = item.get('reason', '')
            if cmd and isinstance(cmd, str) and not any(k in cmd for k in ['rm -rf /', 'userdel -r rooyay', 'passwd -l rooyay']):
                print(f"  Fixing: {reason} -> `{cmd}`", flush=True)
                run_command(cmd)
    except Exception as e:
        print(f"Score Optimizer: Recommendation step skipped ({e})", flush=True)


def main():
    engine_dir = Path(__file__).resolve().parents[1]
    restore_scoring_service()

    report_path = find_scoring_report()
    if not report_path:
        print("Score Tracker: ScoringReport.html not located yet. Waiting 10s...", flush=True)
        time.sleep(10)
        report_path = find_scoring_report()

    if not report_path:
        print("Score Tracker: Could not find ScoringReport.html. Running targeted hardening...", flush=True)
        apply_targeted_hardening(engine_dir)
        return 0

    print(f"Score Tracker: Detected scoring report at {report_path}", flush=True)

    max_cycles = 5
    for cycle in range(1, max_cycles + 1):
        html = report_path.read_text(encoding='utf-8', errors='ignore')
        info = parse_scoring_report(html)

        valid_score = (
            info['score'] is not None and
            info['max_score'] is not None and
            40 <= info['max_score'] <= 200 and
            0 <= info['score'] <= info['max_score']
        )

        if valid_score:
            pct = int((info['score'] / info['max_score']) * 100) if info['max_score'] > 0 else 0
            print(f"\n==================================================", flush=True)
            print(f"  CyberPatriot Score: {info['score']} / {info['max_score']} points ({pct}%)", flush=True)
            print(f"  Scored Vulnerabilities: {info['num_vulns']}", flush=True)
            print(f"==================================================", flush=True)

            if info['score'] >= info['max_score'] and info['score'] > 0:
                print("\n[SUCCESS] 100% ACHIEVED! ALL VULNERABILITIES RESOLVED!\n", flush=True)
                return 0

            print(f"\nScore Optimizer: Cycle {cycle}/{max_cycles} to reach 100%...", flush=True)
            apply_targeted_hardening(engine_dir)

            if cycle >= 2:
                query_ai_optimizer(info, engine_dir)

            print("Score Optimizer: Waiting 15s for scoring daemon to update...", flush=True)
            time.sleep(15)
        else:
            print(f"Score Tracker: Cycle {cycle}/{max_cycles} - Report found, applying hardening pass...", flush=True)
            apply_targeted_hardening(engine_dir)
            time.sleep(12)

    # Final check
    final_html = report_path.read_text(encoding='utf-8', errors='ignore')
    final_info = parse_scoring_report(final_html)
    if final_info['score'] is not None and final_info['max_score'] is not None and 40 <= final_info['max_score'] <= 200:
        print(f"\nFinal CyberPatriot Score: {final_info['score']} / {final_info['max_score']} points.", flush=True)

    return 0


if __name__ == '__main__':
    sys.exit(main())
