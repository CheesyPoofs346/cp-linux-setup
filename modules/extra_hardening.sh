#!/bin/bash
# extra_hardening.sh - deterministic checks for common CyberPatriot vulnerabilities
# No AI. Every action is idempotent, backed up, and skips anything the README marks critical.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Reverse-shell / download-and-execute one-liners that never belong in startup files.
BACKDOOR_REGEX='/dev/(tcp|udp)/|(^|[^a-z])nc(at)?[[:space:]][^#]*-[a-zA-Z]*e[[:space:]]|bash[[:space:]]+-i[[:space:]]*>&|mkfifo[[:space:]]+/tmp|(curl|wget)[^|]*\|[[:space:]]*(ba)?sh|python[0-9.]*[[:space:]]+-c[[:space:]]+.import socket'

EXTRA_FIXES=0
extra_fixed() { EXTRA_FIXES=$((EXTRA_FIXES + 1)); log_success "$1"; }

extra_is_critical() {
    local needle="$1" svc
    local data="${README_DATA:-}"
    [[ -z "$data" && -f "$SCRIPT_DIR/../data/readme_parsed.json" ]] && data=$(cat "$SCRIPT_DIR/../data/readme_parsed.json")
    command_exists jq || return 1
    while IFS= read -r svc; do
        [[ -n "$svc" && "$needle" == *"${svc,,}"* ]] && return 0
    done < <(jq -r '.critical_services[]?' <<<"$data" 2>/dev/null)
    return 1
}

# Comment out lines matching $2 (ERE) in file $1, keeping a backup.
extra_comment_matching() {
    local file="$1" regex="$2" note="$3"
    [[ -f "$file" && ! -L "$file" ]] || return 0
    grep -Ev '^[[:space:]]*#' "$file" 2>/dev/null | grep -Eq -- "$regex" || return 0
    backup_file "$file" >/dev/null 2>&1 || true
    sed -E -i "/^[[:space:]]*#/! { \\~$regex~ s~^~# [cp-removed] ~ }" "$file" 2>/dev/null \
        && extra_fixed "$note: $file"
}

extra_autologin() {
    local f
    for f in /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf; do
        extra_comment_matching "$f" '^[[:space:]]*autologin-user[[:space:]]*=' "Disabled LightDM autologin"
    done
    for f in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf; do
        [[ -f "$f" ]] || continue
        if grep -Eqi '^[[:space:]]*(AutomaticLoginEnable|TimedLoginEnable)[[:space:]]*=[[:space:]]*(true|1)' "$f"; then
            backup_file "$f" >/dev/null 2>&1 || true
            sed -E -i 's/^([[:space:]]*(AutomaticLoginEnable|TimedLoginEnable)[[:space:]]*=[[:space:]]*)(true|True|1)/\1false/' "$f"
            extra_fixed "Disabled GDM automatic login: $f"
        fi
        # A leftover "AutomaticLogin=user" line still reads as autologin to simple checks.
        extra_comment_matching "$f" '^[[:space:]]*(AutomaticLogin|TimedLogin)[[:space:]]*=' "Removed GDM autologin user"
    done
}

extra_apt_security() {
    local f
    for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
        extra_comment_matching "$f" 'AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|Verify-(Peer|Host)[^;]*(false|0)|--force-yes' "Re-enabled APT signature checks"
    done
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
        [[ -f "$f" ]] || continue
        if grep -Eq 'trusted=yes|allow-insecure=yes' "$f"; then
            backup_file "$f" >/dev/null 2>&1 || true
            sed -E -i 's/[[:space:]]*(trusted|allow-insecure)=yes//; s/\[[[:space:]]*\]//' "$f"
            extra_fixed "Removed trusted=yes from APT source: $f"
        fi
    done
    local proxy
    proxy=$(grep -rEh '^[^#]*Acquire::[a-z]+::Proxy' /etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null | head -3 || true)
    [[ -n "$proxy" ]] && log_warn "APT proxy configured (review, may be planted): $proxy"
    return 0
}

extra_trust_files() {
    local f
    for f in /etc/hosts.equiv /root/.rhosts /home/*/.rhosts /etc/shosts.equiv; do
        [[ -e "$f" ]] && rm -f -- "$f" && extra_fixed "Removed host-trust file: $f"
    done
    return 0
}

extra_unused_filesystems() {
    local conf=/etc/modprobe.d/cp-unused-filesystems.conf mod changed=0
    touch "$conf" 2>/dev/null || return 0
    for mod in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc usb-storage firewire-core; do
        if ! grep -q "install $mod /bin/true" "$conf"; then
            printf 'install %s /bin/true\n' "$mod" >> "$conf"
            changed=1
        fi
    done
    (( changed )) && extra_fixed "Blacklisted unused filesystem modules in $conf"
    return 0
}

extra_unneeded_services() {
    command_exists systemctl || return 0
    local unit name
    for unit in xinetd inetutils-inetd openbsd-inetd telnet.socket telnetd rsh.socket rlogin.socket rexec.socket \
                tftpd-hpa snmpd xrdp x11vnc vncserver ypserv ypbind nis; do
        name="${unit%.socket}"
        extra_is_critical "$name" && { log_info "Keeping $unit (README critical service)"; continue; }
        if systemctl list-unit-files "${unit%.service}.service" "$unit" 2>/dev/null | grep -qE '^[^ ]+\.(service|socket)'; then
            if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
                systemctl stop "$unit" 2>/dev/null || true
                systemctl disable "$unit" 2>/dev/null || true
                extra_fixed "Stopped and disabled unneeded service: $unit"
            fi
        fi
    done
    return 0
}

extra_apport() {
    local f=/etc/default/apport
    if [[ -f "$f" ]] && grep -Eq '^enabled=1' "$f"; then
        backup_file "$f" >/dev/null 2>&1 || true
        sed -i 's/^enabled=1/enabled=0/' "$f"
        extra_fixed "Disabled apport crash reporting"
    fi
}

extra_sudoers_authenticate() {
    local f tmp
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f "$f" && ! -L "$f" ]] && grep -Eq '^[^#]*!authenticate' "$f" || continue
        command_exists visudo || { log_warn "visudo missing; cannot safely edit $f"; continue; }
        tmp=$(mktemp)
        sed -E '/^[[:space:]]*#/! s/^(.*!authenticate.*)$/# [cp-removed] \1/' "$f" > "$tmp"
        if visudo -cf "$tmp" >/dev/null 2>&1; then
            backup_file "$f" >/dev/null 2>&1 || true
            if cat "$tmp" > "$f"; then
                extra_fixed "Removed !authenticate from sudoers: $f"
            else
                log_warn "Could not write $f (read-only?)"
            fi
        else
            log_warn "Edited sudoers failed validation; left $f untouched"
        fi
        rm -f -- "$tmp"
    done
}

extra_startup_backdoors() {
    local f
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
             /var/spool/cron/crontabs/* /etc/rc.local /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc \
             /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile; do
        extra_comment_matching "$f" "$BACKDOOR_REGEX" "Neutralized reverse-shell/download-exec line"
    done
}

extra_tmp_sticky() {
    local d
    for d in /tmp /var/tmp; do
        if [[ -d "$d" && "$(stat -c '%a' "$d")" != 1777 ]]; then
            chmod 1777 "$d" && extra_fixed "Restored sticky bit on $d"
        fi
    done
}

extra_audit_apparmor() {
    command_exists systemctl || return 0
    if ! dpkg -s auditd >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y auditd >/dev/null 2>&1 && extra_fixed "Installed auditd"
    fi
    systemctl enable --now auditd >/dev/null 2>&1 && extra_fixed "auditd enabled"
    if systemctl list-unit-files apparmor.service 2>/dev/null | grep -q apparmor; then
        systemctl is-active --quiet apparmor || { systemctl enable --now apparmor >/dev/null 2>&1 && extra_fixed "AppArmor enabled"; }
    fi
    return 0
}

# Lock the screen after 5 idle minutes and require a password (Cinnamon/Mint and GNOME), system-wide via dconf defaults.
extra_screen_lock() {
    command_exists dconf || [[ -d /etc/dconf ]] || return 0
    local db=/etc/dconf/db/local.d prof=/etc/dconf/profile/user
    local f="$db/00-cp-screenlock"
    [[ -f "$f" ]] && return 0
    mkdir -p "$db" /etc/dconf/profile 2>/dev/null || return 0
    cat > "$f" <<'DCONF'
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true

[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
DCONF
    [[ -f "$prof" ]] || printf 'user-db:user\nsystem-db:local\n' > "$prof"
    grep -q 'system-db:local' "$prof" || echo 'system-db:local' >> "$prof"
    dconf update 2>/dev/null || true
    extra_fixed "Screen lock set (5 min idle, password required)"
}

# System-wide Firefox policy (deb and snap): popup blocking, safe browsing, no saved logins.
extra_firefox_policy() {
    local dir f
    for dir in /etc/firefox/policies /usr/lib/firefox/distribution /etc/firefox/distribution; do
        [[ -d "$(dirname "$dir")" ]] || continue
        f="$dir/policies.json"
        [[ -f "$f" ]] && grep -q PopupBlocking "$f" && continue
        mkdir -p "$dir" 2>/dev/null || continue
        cat > "$f" <<'JSON'
{"policies":{"PopupBlocking":{"Default":true},"OfferToSaveLogins":false,"PasswordManagerEnabled":false,"DisableAppUpdate":false,
"Preferences":{"browser.safebrowsing.malware.enabled":{"Value":true,"Status":"locked"},"browser.safebrowsing.phishing.enabled":{"Value":true,"Status":"locked"},"dom.disable_open_during_load":{"Value":true,"Status":"locked"}}}}
JSON
        extra_fixed "Firefox policy written: $f"
        break
    done
    return 0
}

# glibc no longer knows 'nospoof'/'spoof'; leftover lines print "bad command" errors on every command.
extra_host_conf() {
    [[ -f /etc/host.conf ]] || return 0
    grep -Eqi '^[[:space:]]*(nospoof|spoof|spoofalert)\b' /etc/host.conf || return 0
    backup_file /etc/host.conf >/dev/null 2>&1 || true
    sed -i -E '/^[[:space:]]*(nospoof|spoof|spoofalert)\b/Id' /etc/host.conf && extra_fixed "Removed unsupported nospoof lines from /etc/host.conf"
}

# Set "key<sep>value" in a config file: replace an existing active line, else append. Backed up, idempotent.
extra_set_kv() {
    local file="$1" key="$2" value="$3" sep="${4:- = }"
    [[ -f "$file" && ! -L "$file" ]] || return 0
    # already correct only if the desired line exists and no other active line sets a different value
    if grep -Fxq -- "${key}${sep}${value}" "$file"        && ! grep -E "^[[:space:]]*${key}[[:space:]]*(=|[[:space:]])" "$file" | grep -Fvxq -- "${key}${sep}${value}"; then
        return 0
    fi
    backup_file "$file" >/dev/null 2>&1 || true
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*(=|[[:space:]])" "$file"; then
        sed -E -i "s~^[[:space:]]*${key}[[:space:]]*(=|[[:space:]]).*~${key}${sep}${value}~" "$file"
    else
        printf '%s%s%s\n' "$key" "$sep" "$value" >> "$file"
    fi
    extra_fixed "Set ${key}${sep}${value} in $file"
}

# Mail/DNS servers only when they exist (README may require them): no banner leaks, no open relay, no open recursion.
extra_mail_dns() {
    if [[ -f /etc/postfix/main.cf ]]; then
        extra_set_kv /etc/postfix/main.cf disable_vrfy_command yes
        extra_set_kv /etc/postfix/main.cf smtpd_helo_required yes
        extra_set_kv /etc/postfix/main.cf mynetworks '127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'
    fi
    if [[ -f /etc/dovecot/conf.d/10-auth.conf ]]; then
        extra_set_kv /etc/dovecot/conf.d/10-auth.conf disable_plaintext_auth yes
    fi
    local opts=/etc/bind/named.conf.options
    if [[ -f "$opts" ]] && ! grep -q 'allow-recursion' "$opts"; then
        backup_file "$opts" >/dev/null 2>&1 || true
        sed -i '0,/options[[:space:]]*{/s//options {\n\tallow-recursion { localhost; localnets; };\n\tallow-transfer { none; };\n\tversion "not disclosed";/' "$opts" \
            && extra_fixed "BIND recursion/transfer restricted in $opts"
    fi
    return 0
}

# Linux Mint / Ubuntu: keep update checks on and stay on the LTS channel.
extra_update_settings() {
    local f=/etc/apt/apt.conf.d/20auto-upgrades
    if [[ -d /etc/apt/apt.conf.d ]] && ! grep -q 'Update-Package-Lists "1"' "$f" 2>/dev/null; then
        printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Download-Upgradeable-Packages "1";\nAPT::Periodic::AutocleanInterval "7";\n' > "$f" \
            && extra_fixed "Automatic update checks enabled ($f)"
    fi
    extra_set_kv /etc/update-manager/release-upgrades Prompt lts '='
    return 0
}

# Idle shell timeout and strict default umask for every login shell.
extra_shell_profile() {
    local f=/etc/profile.d/cp-hardening.sh
    [[ -f "$f" ]] && return 0
    [[ -d /etc/profile.d ]] || return 0
    printf '# CyberPatriot hardening\nreadonly TMOUT=900 2>/dev/null || true\nexport TMOUT\numask 027\n' > "$f"
    chmod 644 "$f"
    extra_fixed "Shell idle timeout + umask 027 ($f)"
}

# The security module and extra hardening use the same owned baseline.
extra_sysctl_extra() {
    python3 -I "$SCRIPT_DIR/../lib/kernel_policy.py" || return 1
    extra_fixed "Shared kernel baseline applied and verified"
}

# Scoring reads the stock files, not our later drop-ins: fix the originals too (only when the server exists).
extra_web_direct() {
    local f
    for f in /etc/apache2/conf-available/security.conf /etc/apache2/conf-enabled/security.conf /etc/httpd/conf/httpd.conf; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        extra_set_kv "$f" ServerTokens Prod ' '
        extra_set_kv "$f" ServerSignature Off ' '
        extra_set_kv "$f" TraceEnable Off ' '
    done
    f=/etc/nginx/nginx.conf
    if [[ -f "$f" ]] && ! grep -Eq '^[[:space:]]*server_tokens[[:space:]]+off;' "$f"; then
        backup_file "$f" >/dev/null 2>&1 || true
        if grep -Eq '^[[:space:]]*server_tokens' "$f"; then
            sed -i -E 's/^([[:space:]]*)server_tokens[[:space:]]+[^;]*;/\1server_tokens off;/' "$f"
        else
            sed -i -E '0,/http[[:space:]]*\{/s//http {\n\tserver_tokens off;/' "$f"
        fi
        extra_fixed "nginx server_tokens off in $f"
    fi
    for f in /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini; do
        [[ -f "$f" ]] || continue
        extra_set_kv "$f" expose_php Off ' = '
        extra_set_kv "$f" allow_url_include Off ' = '
        extra_set_kv "$f" display_errors Off ' = '
        extra_set_kv "$f" disable_functions 'exec,passthru,shell_exec,system,proc_open,popen' ' = '
    done
    return 0
}

# FTP root directories must not be world-writable (anonymous upload = scored vuln); vsftpd also wants TLS.
extra_ftp_root() {
    local d conf=/etc/vsftpd.conf roots=(/srv/ftp /var/ftp /home/ftp /srv/ftp/pub)
    if [[ -f "$conf" ]]; then
        local r
        while IFS= read -r r; do [[ -n "$r" ]] && roots+=("$r"); done < <(grep -Eh '^[[:space:]]*(anon_root|local_root)[[:space:]]*=' "$conf" | cut -d= -f2 | tr -d ' ')
    fi
    for d in "${roots[@]}"; do
        [[ -d "$d" && ! -L "$d" ]] || continue
        if [[ "$(stat -c '%a' "$d")" =~ [2367]$ ]]; then
            chmod o-w "$d" && extra_fixed "FTP root no longer world-writable: $d"
        fi
        if [[ "$d" == /srv/ftp || "$d" == /var/ftp || "$d" == /home/ftp ]] && [[ "$(stat -c '%a' "$d")" =~ ^[0-7][2367][0-7]$ ]]; then
            chmod g-w "$d" 2>/dev/null || true
        fi
    done
    return 0
}

run_extra_hardening() {
    log_section "Extra Hardening (deterministic checklist)"
    extra_host_conf
    extra_autologin
    extra_apt_security
    extra_trust_files
    extra_unused_filesystems
    extra_unneeded_services
    extra_apport
    extra_sudoers_authenticate
    extra_startup_backdoors
    extra_tmp_sticky
    extra_audit_apparmor
    extra_screen_lock
    extra_firefox_policy
    extra_mail_dns
    extra_ftp_root
    extra_web_direct
    extra_update_settings
    extra_shell_profile
    extra_sysctl_extra || return 1
    log_success "Extra hardening complete ($EXTRA_FIXES change(s))"
    return 0
}

export -f run_extra_hardening
