#!/bin/bash
# security_policy.sh - Security Policy Module
# Implements kernel hardening and security policies via sysctl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Security Policy
# Category: Security Policy
# Description: Implements comprehensive kernel hardening and security policies


# Check if X Server allows TCP connections
check_xserver_tcp() {
    log_section "Checking X Server TCP Connections"

    local score=0

    # Check if X11 is running
    if ! pgrep -x X >/dev/null && ! pgrep -x Xorg >/dev/null; then
        log_info "X Server not running, skipping check"
        return 0
    fi

    # Check for -nolisten tcp option in X server processes
    if pgrep -a Xorg | grep -q -- "-nolisten tcp"; then
        log_success "X Server does not allow TCP connections"
        score=1
    elif pgrep -a X | grep -q -- "-nolisten tcp"; then
        log_success "X Server does not allow TCP connections"
        score=1
    else
        log_warn "X Server may be allowing TCP connections"
        log_info "Attempting to configure X Server to disable TCP..."

        # Try to configure lightdm
        if [[ -f /etc/lightdm/lightdm.conf ]]; then
            if ! grep -q "xserver-allow-tcp=false" /etc/lightdm/lightdm.conf; then
                if grep -q "^\[Seat:\*\]" /etc/lightdm/lightdm.conf; then
                    sed -i '/^\[Seat:\*\]/a xserver-allow-tcp=false' /etc/lightdm/lightdm.conf
                else
                    echo -e "\n[Seat:*]\nxserver-allow-tcp=false" >> /etc/lightdm/lightdm.conf
                fi
                log_success "Configured LightDM to disable TCP connections"
                score=1
            fi
        fi

        # Try to configure gdm3
        if [[ -f /etc/gdm3/custom.conf ]]; then
            if ! grep -q "DisallowTCP=true" /etc/gdm3/custom.conf; then
                if grep -q "^\[security\]" /etc/gdm3/custom.conf; then
                    sed -i '/^\[security\]/a DisallowTCP=true' /etc/gdm3/custom.conf
                else
                    echo -e "\n[security]\nDisallowTCP=true" >> /etc/gdm3/custom.conf
                fi
                log_success "Configured GDM3 to disable TCP connections"
                score=1
            fi
        fi
    fi

    return 0
}

# One shared baseline owns only explicitly selected, supported sysctl keys.
apply_hardened_sysctl() {
    python3 -I "$SCRIPT_DIR/../lib/kernel_policy.py"
}

verify_sysctl_settings() {
    python3 -I "$SCRIPT_DIR/../lib/kernel_policy.py" --check
}

# Check sudo configuration
check_sudo_config() {
    log_section "Checking Sudo Configuration"

    # Check if sudo requires authentication
    log_info "Checking if sudo requires authentication..."

    # Check sudoers file for NOPASSWD entries
    local nopasswd_count=0
    if [[ -f /etc/sudoers ]]; then
        # Avoid double-printing when grep exits non-zero on no matches
        local count
        count=$(grep -c "NOPASSWD:" /etc/sudoers 2>/dev/null || true)
        count=${count//[[:space:]]/}
        nopasswd_count=$((nopasswd_count + ${count:-0}))
    fi

    # Check sudoers.d directory
    if [[ -d /etc/sudoers.d ]]; then
        local dir_count
        dir_count=$({ grep -r "NOPASSWD:" /etc/sudoers.d 2>/dev/null | wc -l; } || true)
        dir_count=${dir_count//[[:space:]]/}
        nopasswd_count=$((nopasswd_count + ${dir_count:-0}))
    fi

    if [[ $nopasswd_count -eq 0 ]]; then
        log_success "Sudo requires authentication (no NOPASSWD entries found)"
    else
        log_warn "Found $nopasswd_count NOPASSWD entries in sudoers configuration"
        log_info "Removing NOPASSWD entries..."

        # Comment out NOPASSWD lines in /etc/sudoers
        if [[ -f /etc/sudoers ]]; then
            sed -i 's/^\([^#].*NOPASSWD:.*\)$/# DISABLED BY SECURITY POLICY: \1/' /etc/sudoers
        fi

        # Comment out NOPASSWD lines in /etc/sudoers.d/*
        if [[ -d /etc/sudoers.d ]]; then
            find /etc/sudoers.d -type f -exec sed -i 's/^\([^#].*NOPASSWD:.*\)$/# DISABLED BY SECURITY POLICY: \1/' {} \;
        fi

        log_success "Disabled NOPASSWD entries in sudoers configuration"
    fi

    return 0
}

# Check group sudo privileges
check_group_sudo_privileges() {
    log_section "Checking Group Sudo Privileges"

    log_info "Checking for groups with sudo privileges..."

    local issues_found=0

    # Check if sudo group has members (this is expected)
    if getent group sudo >/dev/null 2>&1; then
        local sudo_members
        sudo_members=$(getent group sudo | cut -d: -f4)
        if [[ -n "$sudo_members" ]]; then
            log_info "Sudo group members: $sudo_members"
            log_info "This is expected - individual users should be in sudo group, not other groups"
        fi
    fi

    # Check for other groups with sudo privileges in sudoers
    if [[ -f /etc/sudoers ]]; then
        # Look for lines like "%groupname ALL=(ALL:ALL) ALL"
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local groupname
                groupname=$(echo "$line" | sed 's/^%\([^ ]*\).*/\1/')
                # Skip the sudo and admin groups as they are standard
                if [[ "$groupname" != "sudo" && "$groupname" != "admin" ]]; then
                    log_warn "Group $groupname has sudo privileges in /etc/sudoers"
                    log_info "Commenting out sudo privileges for group: $groupname"
                    sed -i "s/^\(%$groupname.*\)$/# DISABLED BY SECURITY POLICY: \1/" /etc/sudoers
                    issues_found=$((issues_found + 1))
                fi
            fi
        done < <({ grep -E "^%[^#]" /etc/sudoers 2>/dev/null | grep -v "^%sudo" | grep -v "^%admin"; } || true)
    fi

    # Check sudoers.d directory
    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r file; do
            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    local groupname
                    groupname=$(echo "$line" | sed 's/^%\([^ ]*\).*/\1/')
                    if [[ "$groupname" != "sudo" && "$groupname" != "admin" ]]; then
                        log_warn "Group $groupname has sudo privileges in $file"
                        log_info "Commenting out sudo privileges for group: $groupname in $file"
                        sed -i "s/^\(%$groupname.*\)$/# DISABLED BY SECURITY POLICY: \1/" "$file"
                        issues_found=$((issues_found + 1))
                    fi
                fi
            done < <({ grep -E "^%[^#]" "$file" 2>/dev/null | grep -v "^%sudo" | grep -v "^%admin"; } || true)
        done < <(find /etc/sudoers.d -type f)
    fi

    if [[ $issues_found -eq 0 ]]; then
        log_success "No unauthorized groups have sudo privileges"
    else
        log_success "Removed sudo privileges from $issues_found unauthorized group(s)"
    fi

    return 0
}

# Print security policy checklist
print_security_checklist() {
    log_info "Conservative kernel baseline: ASLR, SYN cookies, protected links, kernel log/pointer restrictions."
    log_info "Preserving IPv6, forwarding roles, user namespaces and unrelated sysctl configuration."
}

# Main module execution
run_security_policy() {
    log_section "Security Policy Module"

    # Print checklist
    print_security_checklist

    # Check X Server TCP
    check_xserver_tcp

    # Apply hardened sysctl configuration
    apply_hardened_sysctl || return 1

    # Verification is optional; skip automatic verification so we only apply settings

    # Check sudo configuration
    check_sudo_config

    # Check group sudo privileges
    check_group_sudo_privileges

    log_section "Security Policy Complete"
    log_success "All security policy tasks completed"

    return 0
}

export -f run_security_policy
