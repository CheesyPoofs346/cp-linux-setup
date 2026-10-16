#!/bin/bash
# One-command orchestration. Modules run in separate processes to isolate globals.
check_guard_support() {
    unshare --mount --propagation private true || { log_error "This environment cannot provide the required private mount namespace"; return 1; }
}
snapshot_main_account() {
    python3 "$ENGINE_DIR/lib/account_guard.py" snapshot "$ENGINE_DIR/data/protected-account.json"
}
check_main_account() {
    python3 "$ENGINE_DIR/lib/account_guard.py" check "$ENGINE_DIR/data/protected-account.json"
}
run_anomaly_audit() {
    AUDIT_PACKAGE_CHECK="${1:-0}" python3 "$ENGINE_DIR/lib/anomaly_audit.py"
}
review_auto_plan() {
    printf '%s\n' "${MODULES[@]}" | jq -R . | jq -s '[.[] | select(. != "readme_parser" and . != "forensics_questions" and . != "user_auditing" and . != "account_policy" and . != "os_settings" and . != "ssh_hardening" and . != "malware" and . != "unwanted_software" and . != "prohibited_files")]' > "$ENGINE_DIR/data/review-proposal.json"
    export AI_PROVIDER OPENROUTER_API_KEY OPENROUTER_MODEL
    export REVIEWER_MODEL="${REVIEWER_MODEL:-nvidia/nemotron-3-super-120b-a12b}"
    python3 "$ENGINE_DIR/lib/peer_review.py"
}
peer_approved() {
    jq -e --arg module "$1" 'index($module) != null' "$ENGINE_DIR/data/approved-modules.json" >/dev/null
}
run_auto() {
    local source_file="$ENGINE_DIR/data/auto-source.html"
    local report="$ENGINE_DIR/data/auto-results.tsv"
    local module status reviews=0 failed=0
    [[ "${AI_PROVIDER:-openrouter}" == nvidia ]] || { log_error "Reviewed auto mode requires NVIDIA configuration; standalone modules still support OpenRouter"; return 2; }
    [[ "${REVIEWER_MODEL:-nvidia/nemotron-3-super-120b-a12b}" != "$OPENROUTER_MODEL" ]] || { log_error "Worker and reviewer must be different models"; return 2; }
    export PROTECTED_USER="${PROTECTED_USER:-}"
    check_guard_support || return 1
    umask 077
    mkdir -p "$ENGINE_DIR/data"
    exec 9>"$ENGINE_DIR/data/auto.lock"
    flock -n 9 || { log_error "Another auto run is active"; return 1; }
    if [[ -n "${README_URL:-}" ]]; then
        [[ "$README_URL" == https://* ]] || { log_error "README URL must use HTTPS"; return 1; }
        curl -fLsS --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60 "$README_URL" -o "$source_file.download" || return 1
        mv -- "$source_file.download" "$source_file"
    elif [[ -n "${README_FILE:-}" && -f "$README_FILE" ]]; then
        [[ "$(readlink -f "$README_FILE")" == "$source_file" ]] || cp -- "$README_FILE" "$source_file" || return 1
    else
        log_error "Auto mode requires --readme FILE or --readme-url HTTPS_URL"
        return 1
    fi
    [[ "${AUTO_MODULE_TIMEOUT:-1800}" =~ ^[1-9][0-9]*$ ]] || { log_error "Invalid AUTO_MODULE_TIMEOUT"; return 1; }
    [[ "${AUTO_UPDATE_MODE:-1}" == 1 || "${AUTO_UPDATE_MODE:-1}" == 2 ]] || { log_error "AUTO_UPDATE_MODE must be 1 or 2"; return 1; }
    README_FILE="$source_file"
    export README_FILE CP_AUTO=1 DEBIAN_FRONTEND=noninteractive
    printf 'module\tstatus\n' > "$report"
    # No package, account, or service mutation until parsing AND validation pass.
    if ! run_module readme_parser; then
        printf 'readme_parser\tFAILED\n' >> "$report"
        log_error "README preflight failed; no remediation modules started"
        return 1
    fi
    printf 'readme_parser\tPASS\n' >> "$report"
    snapshot_main_account || return 1
    if ! run_anomaly_audit; then
        printf 'anomaly_audit\tFAILED\n' >> "$report"
        return 1
    fi
    printf 'anomaly_audit\tREPORT_SAVED\n' >> "$report"
    # Forensic evidence may be destroyed by package, account, or file cleanup.
    status=0
    timeout --foreground --kill-after=10 "${AUTO_MODULE_TIMEOUT:-1800}" bash "$ENGINE_DIR/cp-engine.sh" --worker-module forensics_questions </dev/null || status=$?
    if [[ "$status" == 2 ]]; then
        printf 'forensics_questions\tMANUAL_REVIEW\n' >> "$report"
        log_warn "Forensics are unresolved. Remediation has not started. See data/forensics/."
        return 2
    elif [[ "$status" != 0 ]]; then
        printf 'forensics_questions\tFAILED\n' >> "$report"
        log_error "Forensics failed or timed out. Remediation has not started."
        return 1
    fi
    printf 'forensics_questions\tFILLED_UNVERIFIED_SCORE\n' >> "$report"
    check_main_account || return 1
    # Broad package file reads happen only after forensic answers are collected.
    run_anomaly_audit 1 || return 1
    if ! review_auto_plan; then
        printf 'peer_review\tMANUAL_REVIEW\n' >> "$report"
        log_warn "Independent plan review did not approve remediation. No remediation modules started."
        return 2
    fi
    printf 'peer_review\tAPPROVED\n' >> "$report"
    for module in "${MODULES[@]}"; do
        [[ "$module" == readme_parser || "$module" == forensics_questions ]] && continue
        if (( failed )); then
            printf '%s\tNOT_RUN\n' "$module" >> "$report"
            continue
        fi
        # These modules use AI-generated removal decisions/commands. Review separately.
        case "$module" in
            user_auditing|account_policy|os_settings|ssh_hardening|malware|unwanted_software|prohibited_files)
                printf '%s\tMANUAL_REVIEW\n' "$module" >> "$report"
                log_warn "$module is excluded from unattended execution to preserve accounts/access/evidence"
                reviews=$((reviews + 1))
                continue
                ;;
        esac
        if ! peer_approved "$module"; then
            printf '%s\tREVIEWER_WITHHELD\n' "$module" >> "$report"
            reviews=$((reviews + 1))
            continue
        fi
        check_main_account || return 1
        if timeout --foreground --kill-after=10 "${AUTO_MODULE_TIMEOUT:-1800}" bash "$ENGINE_DIR/lib/protect_account.sh" "$module" </dev/null; then
            status=PASS
        else
            status=FAILED
            failed=1
        fi
        printf '%s\t%s\n' "$module" "$status" >> "$report"
        if ! check_main_account; then
            printf 'protected_account\tCHANGED_STOPPED\n' >> "$report"
            log_error "Protected state changed; STOP. Restore the VM snapshot before retrying."
            return 1
        fi
        if (( failed )); then
            log_error "Stopped at $module (failed or timed out). Remaining modules were not run."
        fi
    done
    log_info "Module results: $report"
    log_warn "Module status is not an image score. Check forensics, README-specific requirements, required services, and the official scoring report."
    (( failed == 0 )) || return 1
    # A review-needed run must not look like complete success to callers.
    (( reviews == 0 )) || return 2
}

run_worker_module() {
    local module="$1"
    require_root
    [[ "${CP_AUTO:-0}" == 1 ]] || { log_error "Worker entry is internal to --auto"; return 1; }
    source "$ENGINE_DIR/modules/readme_parser.sh"
    python3 "$ENGINE_DIR/lib/validate_readme.py" "$ENGINE_DIR/data/auto-source.html" "$ENGINE_DIR/data/readme_parsed.json" || return 1
    README_DATA=$(cat "$ENGINE_DIR/data/readme_parsed.json")
    README_PARSED=1
    if [[ "$module" == ssh_hardening ]]; then
        [[ -n "${SSH_TARGET_USER:-}" && -f "${SSH_PUBLIC_KEY_FILE:-}" ]] || return 1
        echo "$README_DATA" | jq -e --arg user "$SSH_TARGET_USER" '.all_users[] | select(.name == $user)' >/dev/null || return 1
        ssh-keygen -lf "$SSH_PUBLIC_KEY_FILE" >/dev/null || return 1
        SSH_PUBLIC_KEY=$(cat "$SSH_PUBLIC_KEY_FILE")
        [[ "$SSH_PUBLIC_KEY" == ssh-* || "$SSH_PUBLIC_KEY" == ecdsa-* ]] || { log_error "Use a public SSH key file"; return 1; }
    fi
    run_module "$module"
}
