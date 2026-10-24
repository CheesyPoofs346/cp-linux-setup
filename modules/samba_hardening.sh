#!/bin/bash
# Module: Samba Hardening
# Category: Service Security
# Description: Preserve business configuration; validate and roll back failed changes.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
run_samba_hardening() {
    require_root || return 1
    python3 "$SCRIPT_DIR/../lib/service_policy.py" samba
}
export -f run_samba_hardening
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_samba_hardening
fi
