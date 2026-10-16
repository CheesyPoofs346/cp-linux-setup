#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $EUID == 0 ]] || { echo 'Run sudo bash audit.sh for complete access; the audit does not remediate findings.' >&2; exit 1; }
if [[ "${1:-}" == --package-check ]]; then
    export AUDIT_PACKAGE_CHECK=1
elif [[ $# != 0 ]]; then
    echo 'Usage: sudo bash audit.sh [--package-check]' >&2
    exit 1
fi
exec python3 "$ROOT/lib/anomaly_audit.py"
