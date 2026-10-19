#!/bin/bash
# Automated, active forensic solver. Provider credentials are not command arguments.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/../lib/openrouter.sh"

run_forensics_questions() {
    if [[ "${SKIP_FORENSICS:-0}" == 1 ]]; then
        log_info "Forensics skipped via SKIP_FORENSICS=1"
        return 0
    fi
    check_dependencies python3 || return 1
    check_openrouter_config || return 1
    export AI_PROVIDER OPENROUTER_API_KEY OPENROUTER_MODEL
    export AI_TIMEOUT_SECONDS="${AI_TIMEOUT_SECONDS:-180}"
    export FORENSICS_APPLY_ANSWERS="${FORENSICS_APPLY_ANSWERS:-1}"
    export FORENSICS_DIR="${FORENSICS_DIR:-}"
    export FORENSICS_IMAGE_NOTES="${FORENSICS_IMAGE_NOTES:-}"
    export REVIEWER_MODEL="${REVIEWER_MODEL:-nvidia/nemotron-3-super-120b-a12b}"
    export README_FILE="${README_FILE:-}"
    export FORENSICS_MAX_ROUNDS="${FORENSICS_MAX_ROUNDS:-8}"
    python3 "$SCRIPT_DIR/../lib/forensics_agent.py"
}
export -f run_forensics_questions
