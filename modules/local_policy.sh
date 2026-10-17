#!/bin/bash
# local_policy.sh - Local Policy Module
# Configures local security policies, permissions, sudoers, and umask

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Local Policy
# Category: Local Policy
# Description: Configures system security policies, critical permissions, umask, and sudoers

run_local_policy() {
    log_section "Local Policy & Permissions Enforcement"

    local fixed_count=0

    # 1. Critical file permissions and ownerships
    log_info "Enforcing critical system file permissions..."
    local critical_files=(
        "/etc/passwd:644:root:root"
        "/etc/shadow:640:root:shadow"
        "/etc/group:644:root:root"
        "/etc/gshadow:640:root:shadow"
        "/etc/sudoers:440:root:root"
        "/etc/crontab:600:root:root"
        "/boot/grub/grub.cfg:600:root:root"
        "/etc/ssh/sshd_config:600:root:root"
        "/usr/lib:755:root:root"
        "/root:700:root:root"
    )

    for entry in "${critical_files[@]}"; do
        IFS=':' read -r file expected_perm expected_user expected_group <<< "$entry"
        if [[ -e "$file" ]]; then
            local current_perm current_owner
            current_perm=$(stat -c '%a' "$file" 2>/dev/null || true)
            current_owner=$(stat -c '%U:%G' "$file" 2>/dev/null || true)

            if [[ "$current_perm" != "$expected_perm" ]]; then
                chmod "$expected_perm" "$file" 2>/dev/null || true
                log_success "Set permissions for $file to $expected_perm (was $current_perm)"
                fixed_count=$((fixed_count + 1))
            fi

            if [[ "$current_owner" != "${expected_user}:${expected_group}" ]]; then
                chown "${expected_user}:${expected_group}" "$file" 2>/dev/null || chown "${expected_user}:root" "$file" 2>/dev/null || true
                log_success "Set ownership for $file to ${expected_user}:${expected_group}"
                fixed_count=$((fixed_count + 1))
            fi
        fi
    done

    # Sudoers.d directory and files
    if [[ -d /etc/sudoers.d ]]; then
        chmod 750 /etc/sudoers.d 2>/dev/null || true
        chown root:root /etc/sudoers.d 2>/dev/null || true
        for sf in /etc/sudoers.d/*; do
            if [[ -f "$sf" ]]; then
                chmod 440 "$sf" 2>/dev/null || true
                chown root:root "$sf" 2>/dev/null || true
            fi
        done
    fi

    # Cron directories
    for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        if [[ -d "$crondir" ]]; then
            chmod 700 "$crondir" 2>/dev/null || true
            chown root:root "$crondir" 2>/dev/null || true
        fi
    done

    # Sticky bit on /tmp and /var/tmp
    chmod +t /tmp /var/tmp 2>/dev/null || true
    log_success "Ensured sticky bit (+t) on /tmp and /var/tmp"

    # 2. Sudoers security audit (remove NOPASSWD)
    log_info "Auditing sudoers for unauthorized NOPASSWD directives..."
    if [[ -f /etc/sudoers ]]; then
        if grep -qE '\s+NOPASSWD:' /etc/sudoers 2>/dev/null; then
            sed -i -E 's/\s+NOPASSWD:\s*/ /g' /etc/sudoers 2>/dev/null || true
            log_success "Removed NOPASSWD privilege escalation in /etc/sudoers"
            log_score 5 "Removed NOPASSWD directives from /etc/sudoers"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    if [[ -d /etc/sudoers.d ]]; then
        for sf in /etc/sudoers.d/*; do
            if [[ -f "$sf" ]] && grep -qE '\s+NOPASSWD:' "$sf" 2>/dev/null; then
                sed -i -E 's/\s+NOPASSWD:\s*/ /g' "$sf" 2>/dev/null || true
                log_success "Removed NOPASSWD privilege escalation in $sf"
                log_score 5 "Removed NOPASSWD directives from $sf"
                fixed_count=$((fixed_count + 1))
            fi
        done
    fi

    # 3. Disable core dumps
    log_info "Disabling core dumps..."
    local limits_conf="/etc/security/limits.conf"
    if [[ -f "$limits_conf" ]]; then
        if ! grep -qE '^\s*\*\s+hard\s+core\s+0' "$limits_conf" 2>/dev/null; then
            echo "* hard core 0" >> "$limits_conf"
            echo "* soft core 0" >> "$limits_conf"
            log_success "Configured core dump limits in $limits_conf"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # 4. Enforce secure default umask (027)
    log_info "Enforcing default umask (027)..."
    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        if grep -q "^UMASK" "$login_defs"; then
            sed -i -E 's/^UMASK\s+[0-9]+/UMASK 027/' "$login_defs" 2>/dev/null || true
        else
            echo "UMASK 027" >> "$login_defs"
        fi
        log_success "Configured UMASK 027 in $login_defs"
    fi

    for profile_file in /etc/profile /etc/bash.bashrc; do
        if [[ -f "$profile_file" ]] && ! grep -q "umask 027" "$profile_file" 2>/dev/null; then
            echo "umask 027" >> "$profile_file"
            log_success "Added umask 027 to $profile_file"
        fi
    done

    # 5. Mask Ctrl-Alt-Del emergency reboot
    if command_exists systemctl; then
        systemctl mask ctrl-alt-del.target 2>/dev/null || true
        log_success "Masked ctrl-alt-del.target"
    fi

    # 6. Remove world-writeable permissions on system executables
    log_info "Scanning for world-writable system binaries..."
    find /bin /sbin /usr/bin /usr/sbin /etc -xdev -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null || true

    log_success "Local policy enforcement complete ($fixed_count remediation(s) applied)"
    return 0
}

export -f run_local_policy
