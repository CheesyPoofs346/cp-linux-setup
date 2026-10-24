#!/bin/bash
# dependencies.sh - Dependencies Module
# Installs required system dependencies for security tools

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Dependencies
# Category: Dependencies
# Description: Installs required system dependencies and security tools

run_dependencies() {
    log_info "Starting Dependencies module..."

    log_info "Checking and installing required dependencies..."

    local packages=(curl:curl jq:jq acl:getfacl libcap2-bin:getcap)
    local missing=()

    local tool
    for pkg in "${packages[@]}"; do
        tool=${pkg#*:}
        if ! command_exists "$tool"; then
            missing+=("${pkg%%:*}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Updating package lists before installing: ${missing[*]}"
        apt-get update -qq || log_warn "apt-get update encountered issues; attempting install anyway"

        for pkg in "${missing[@]}"; do
            log_info "Installing $pkg..."
            if apt-get install -y "$pkg" >/dev/null 2>&1; then
                log_success "$pkg installed successfully"
            else
                log_error "Failed to install required dependency $pkg"
                return 1
            fi
        done
    else
        log_success "All dependency packages already installed"
    fi

    # Optional integrity tool
    if ! command_exists debsums; then
        apt-get install -y debsums >/dev/null 2>&1 || true
    fi

    return 0
}

export -f run_dependencies
