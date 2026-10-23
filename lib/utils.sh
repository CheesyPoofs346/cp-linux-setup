#!/bin/bash
# utils.sh - Utility functions for CyberPatriot Linux Engine
# Provides logging, color output, and common helper functions

# Prevent multiple sourcing
[[ -n "${UTILS_SH_LOADED:-}" ]] && return 0
readonly UTILS_SH_LOADED=1

# Color codes for output
readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_BOLD='\033[1m'

# Log levels
readonly LOG_DEBUG=0
readonly LOG_INFO=1
readonly LOG_WARN=2
readonly LOG_ERROR=3
readonly LOG_SUCCESS=4

# Global log level (can be overridden by config)
LOG_LEVEL=${LOG_LEVEL:-$LOG_INFO}

# Logging functions
log_debug() {
    if [[ $LOG_LEVEL -le $LOG_DEBUG ]]; then
        echo -e "${COLOR_CYAN}[DEBUG]${COLOR_RESET} $*" >&2
    fi
}

log_info() {
    if [[ $LOG_LEVEL -le $LOG_INFO ]]; then
        echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*" >&2
    fi
}

log_warn() {
    if [[ $LOG_LEVEL -le $LOG_WARN ]]; then
        echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*" >&2
    fi
}

log_error() {
    if [[ $LOG_LEVEL -le $LOG_ERROR ]]; then
        echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
    fi
}

log_success() {
    if [[ $LOG_LEVEL -le $LOG_SUCCESS ]]; then
        echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $*" >&2
    fi
}

# Section header for better readability
log_section() {
    echo -e "\n${COLOR_BOLD}${COLOR_MAGENTA}==== $* ====${COLOR_RESET}\n" >&2
}

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Ensure required dependencies are installed
check_dependencies() {
    local missing=()

    for cmd in "$@"; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_info "Install them with: sudo apt-get install ${missing[*]}"
        return 1
    fi

    return 0
}

# Detect OS distribution
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# Detect OS version
detect_os_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

# Check if OS is supported
is_supported_os() {
    local os=$(detect_os)
    local version=$(detect_os_version)

    if [[ "$os" == "linuxmint" && "$version" =~ ^(21|22|23) ]]; then
        return 0
    elif [[ "$os" == "ubuntu" && "$version" =~ ^(22|24|25)\. ]]; then
        return 0
    elif [[ "$os" == "debian" && "$version" =~ ^(12|13) ]]; then
        return 0
    else
        return 1
    fi
}

# Create backup of a file
backup_file() {
    local file="$1"
    local backup_dir="${2:-/var/backups/cyberpatriot}"

    if [[ ! -f "$file" ]]; then
        log_warn "File does not exist, cannot backup: $file"
        return 1
    fi

    mkdir -p "$backup_dir"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local filename=$(basename "$file")
    local backup_path="${backup_dir}/${filename}.${timestamp}.bak"

    cp -p "$file" "$backup_path"
    log_debug "Backed up $file to $backup_path"
    return 0
}

# Safe file edit with backup
safe_edit() {
    local file="$1"
    backup_file "$file"
}

# Get timestamp
get_timestamp() {
    date +%Y-%m-%d_%H:%M:%S
}

# Score tracking
SCORE_FILE="${SCORE_FILE:-/var/log/cyberpatriot/score.log}"

log_score() {
    local points="$1"
    local description="$2"
    local timestamp=$(get_timestamp)

    mkdir -p "$(dirname "$SCORE_FILE")"
    echo "[$timestamp] +$points points: $description" >> "$SCORE_FILE"
    log_success "+$points points: $description"
}

# userdel that also works for a second UID-0 account (userdel refuses: "currently used by process 1").
# usage: safe_userdel [-r] name
safe_userdel() {
    local remove_home=0 name
    [[ "${1:-}" == "-r" ]] && { remove_home=1; shift; }
    name="${1:?user required}"
    getent passwd "$name" >/dev/null || return 0
    if (( remove_home )); then userdel -r "$name" 2>/dev/null || userdel "$name" 2>/dev/null || true
    else userdel "$name" 2>/dev/null || true; fi
    getent passwd "$name" >/dev/null || return 0
    local home; home=$(getent passwd "$name" | cut -d: -f6)
    local f
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
        [[ -f "$f" ]] && sed -i "/^${name}:/d" "$f"
    done
    for f in /etc/group /etc/gshadow; do
        [[ -f "$f" ]] && sed -i -E "s/([:,])${name}(,|\$)/\1\2/; s/,,/,/g; s/,\$//; s/:,/:/" "$f"
    done
    (( remove_home )) && [[ "$home" == /home/* && -d "$home" ]] && rm -rf -- "$home"
    ! getent passwd "$name" >/dev/null
}

# Set a password even when our own pam_pwquality policy would reject it (chpasswd enforces policy for root).
# usage: set_password user password
set_password() {
    local user="$1" pw="$2" hash
    printf '%s:%s
' "$user" "$pw" | chpasswd 2>/dev/null && return 0
    if command -v openssl >/dev/null 2>&1; then
        hash=$(printf '%s' "$pw" | openssl passwd -6 -stdin 2>/dev/null)
    fi
    if [[ -z "${hash:-}" ]]; then
        hash=$(python3 -c 'import crypt,sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA512)))' "$pw" 2>/dev/null)
    fi
    [[ -n "$hash" ]] && usermod -p "$hash" "$user" 2>/dev/null
}

# Export functions for use in other scripts
export -f log_debug log_info log_warn log_error log_success log_section
export -f require_root command_exists check_dependencies
export -f detect_os detect_os_version is_supported_os
export -f safe_userdel set_password
export -f backup_file safe_edit get_timestamp log_score
