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
    for mod in cramfs freevxfs jffs2 hfs hfsplus udf; do
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

run_extra_hardening() {
    log_section "Extra Hardening (deterministic checklist)"
    extra_autologin
    extra_apt_security
    extra_trust_files
    extra_unused_filesystems
    extra_unneeded_services
    extra_apport
    extra_sudoers_authenticate
    extra_startup_backdoors
    extra_tmp_sticky
    log_success "Extra hardening complete ($EXTRA_FIXES change(s))"
    return 0
}

export -f run_extra_hardening
