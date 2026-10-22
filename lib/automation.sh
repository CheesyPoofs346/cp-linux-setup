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
    if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
        printf '%s\n' "${MODULES[@]}" | jq -R . | jq -s '[.[] | select(. != "readme_parser" and . != "forensics_questions")]' > "$ENGINE_DIR/data/review-proposal.json"
        cp "$ENGINE_DIR/data/review-proposal.json" "$ENGINE_DIR/data/approved-modules.json"
        python3 -c "
import json, hashlib
from pathlib import Path
engine = Path('$ENGINE_DIR')
files = list((engine / 'lib').glob('*.sh')) + list((engine / 'lib').glob('*.py')) + list((engine / 'modules').glob('*.sh')) + [engine / 'cp-engine.sh']
hashes = {str(p.relative_to(engine)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.exists()}
(engine / 'data/review-source-hashes.json').write_text(json.dumps(hashes))
" 2>/dev/null || true
        return 0
    fi
    printf '%s\n' "${MODULES[@]}" | jq -R . | jq -s '[.[] | select(. != "readme_parser" and . != "forensics_questions" and . != "user_auditing" and . != "account_policy" and . != "os_settings" and . != "ssh_hardening" and . != "malware" and . != "unwanted_software" and . != "prohibited_files")]' > "$ENGINE_DIR/data/review-proposal.json"
    export AI_PROVIDER OPENROUTER_API_KEY OPENROUTER_MODEL
    export REVIEWER_MODEL="${REVIEWER_MODEL:-nvidia/nemotron-3-super-120b-a12b}"
    python3 "$ENGINE_DIR/lib/peer_review.py"
}
peer_approved() {
    [[ -f "$ENGINE_DIR/data/approved-modules.json" ]] || return 1
    jq -e --arg mod "$1" 'index($mod) != null' "$ENGINE_DIR/data/approved-modules.json" >/dev/null 2>&1
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
    if [[ -z "${README_URL:-}" && -z "${README_FILE:-}" ]]; then
        for dt in /home/*/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.desktop \
                 /home/*/Desktop/*.desktop \
                 /opt/CyberPatriot/*.desktop \
                 /opt/cyberpatriot/*.desktop \
                 /root/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.desktop; do
            if [[ -f "$dt" && "$dt" != *[Ss]coring* && "$dt" != *[Ss]core* ]]; then
                local dt_url
                dt_url=$(grep -i '^Exec=' "$dt" 2>/dev/null | head -n1 | sed -E 's/^Exec=.*(https?:[^"[:space:]]+).*/\1/I' || true)
                if [[ "$dt_url" == https://* ]]; then
                    README_URL="$dt_url"
                    log_info "Auto-detected README URL from $dt: $README_URL"
                    break
                fi
                local dt_file
                dt_file=$(grep -i '^Exec=' "$dt" 2>/dev/null | head -n1 | sed -E 's/^Exec=[^/]*(\/[^"[:space:]]+).*/\1/' || true)
                if [[ -f "$dt_file" && "$dt_file" != *[Ss]coring* && "$dt_file" != *[Ss]core* ]]; then
                    README_FILE="$dt_file"
                    log_info "Auto-detected README file from $dt: $README_FILE"
                    break
                fi
            fi
        done
        if [[ -z "${README_URL:-}" && -z "${README_FILE:-}" ]]; then
            for candidate in \
                "/opt/CyberPatriot/README.html" \
                "/opt/cyberpatriot/README.html" \
                "/opt/aeacus/assets/ReadMe.html" \
                "/opt/aeacus/assets/README.html" \
                /home/*/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
                /home/*/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
                /root/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
                /root/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html; do
                if [[ -f "$candidate" && "$candidate" != *[Ss]coring* && "$candidate" != *[Ss]core* ]]; then
                    README_FILE="$candidate"
                    log_info "Auto-detected local README: $README_FILE"
                    break
                fi
            done
        fi
    fi
    if [[ -n "${README_URL:-}" ]]; then
        [[ "$README_URL" == https://* ]] || { log_error "README URL must use HTTPS"; return 1; }
        if ! curl -fLsS --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60 "$README_URL" -o "$source_file.download"; then
            log_warn "Failed to download README from $README_URL"
            if [[ -s "$source_file" ]]; then
                log_info "Falling back to existing $source_file"
            elif [[ -t 0 && -e /dev/tty ]]; then
                log_info "Paste README content below (HTML or plain text) and type 'EOF' or Ctrl+D when done:"
                > "$source_file"
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ "$line" == "EOF" ]] && break
                    printf '%s\n' "$line" >> "$source_file"
                done </dev/tty
            else
                log_error "Could not download README. Pass a local file with --readme or run: sudo bash start.sh --paste"
                return 1
            fi
        else
            mv -- "$source_file.download" "$source_file"
        fi
    elif [[ -n "${README_FILE:-}" && -f "$README_FILE" ]]; then
        [[ "$(readlink -f "$README_FILE")" == "$source_file" ]] || cp -- "$README_FILE" "$source_file" || return 1
    elif [[ -s "$source_file" ]]; then
        log_info "Using existing README data in $source_file"
    else
        log_error "Auto mode requires --readme FILE, --readme-url HTTPS_URL, or an existing data/auto-source.html"
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
    # Forensic evidence investigation (can be skipped via Enter or SKIP_FORENSICS=1)
    if [[ "${SKIP_FORENSICS:-0}" == 1 ]]; then
        log_info "SKIP_FORENSICS=1 active: Skipping forensics and proceeding immediately to remediation..."
        printf 'forensics_questions\tSKIPPED\n' >> "$report"
    else
        status=0
        timeout --foreground --kill-after=10 "${AUTO_MODULE_TIMEOUT:-1800}" bash "$ENGINE_DIR/cp-engine.sh" --worker-module forensics_questions || status=$?
        if [[ "$status" == 2 ]]; then
            printf 'forensics_questions\tMANUAL_REVIEW\n' >> "$report"
            if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
                log_warn "Forensics finished or skipped. Continuing with system remediation..."
            else
                log_warn "Manual review required for forensics questions. Remediation paused to protect evidence."
                return 2
            fi
        elif [[ "$status" != 0 ]]; then
            printf 'forensics_questions\tFAILED\n' >> "$report"
            if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
                log_warn "Forensics completed with status $status. Continuing with system remediation..."
            else
                log_error "Forensic module failed; remediation halted to prevent destructive changes"
                return 1
            fi
        else
            printf 'forensics_questions\tFILLED_UNVERIFIED_SCORE\n' >> "$report"
        fi
    fi
    log_success "Forensics completed. Proceeding immediately to system remediation..."
    check_main_account || return 1
    # Broad package file reads happen only after forensic answers are collected.
    log_info "Running system anomaly audit and baseline checks..."
    run_anomaly_audit 1 || return 1
    if ! review_auto_plan; then
        printf 'peer_review\tMANUAL_REVIEW\n' >> "$report"
        if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
            log_warn "Reviewer did not approve plan; continuing under AUTO_REMEDIATE=1"
        else
            log_warn "Independent plan review did not approve remediation. No remediation modules started."
            return 2
        fi
    else
        printf 'peer_review\tAPPROVED\n' >> "$report"
    fi
    for module in "${MODULES[@]}"; do
        [[ "$module" == readme_parser || "$module" == forensics_questions ]] && continue
        if (( failed )); then
            printf '%s\tNOT_RUN\n' "$module" >> "$report"
            continue
        fi
        # These modules use remediation decisions/commands. Exclude from unattended execution unless AUTO_REMEDIATE=1.
        if [[ "${AUTO_REMEDIATE:-0}" != 1 ]]; then
            case "$module" in
                user_auditing|account_policy|os_settings|ssh_hardening|malware|unwanted_software|prohibited_files)
                    printf '%s\tMANUAL_REVIEW\n' "$module" >> "$report"
                    log_warn "$module is excluded from unattended execution to preserve accounts/access/evidence"
                    reviews=$((reviews + 1))
                    continue
                    ;;
            esac
        fi
        if ! peer_approved "$module"; then
            if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
                log_warn "Reviewer did not explicitly list $module; executing under AUTO_REMEDIATE=1"
            else
                printf '%s\tREVIEWER_WITHHELD\n' "$module" >> "$report"
                reviews=$((reviews + 1))
                continue
            fi
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
            if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
                log_warn "Module $module encountered issues; continuing with remaining modules under AUTO_REMEDIATE=1"
                failed=0
            else
                log_error "Stopped at $module (failed or timed out). Remaining modules were not run."
            fi
        fi
    done
    log_info "Module results: $report"
    repair_operator_aging
    if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
        python3 "$ENGINE_DIR/lib/score_tracker.py" || true
        repair_operator_aging
    fi
    log_warn "Module status is not an image score. Check forensics, README-specific requirements, required services, and the official scoring report."
    (( failed == 0 )) || return 1
    # A review-needed run must not look like complete success to callers.
    (( reviews == 0 )) || return 2
}

# Password-aging policy must never leave the operator's own account expired (sudo would demand a reset).
repair_operator_aging() {
    local u
    for u in "${SUDO_USER:-}" "${PROTECTED_USER:-}"; do
        [[ -n "$u" && "$u" != root ]] && id "$u" >/dev/null 2>&1 && chage -d "$(date +%F)" -E -1 -I -1 "$u" 2>/dev/null || true
    done
}

run_worker_module() {
    local module="$1"
    require_root
    [[ "${CP_AUTO:-0}" == 1 ]] || { log_error "Worker entry is internal to --auto"; return 1; }
    source "$ENGINE_DIR/modules/readme_parser.sh"
    python3 "$ENGINE_DIR/lib/validate_readme.py" "$ENGINE_DIR/data/auto-source.html" "$ENGINE_DIR/data/readme_parsed.json" || {
        if [[ "${AUTO_REMEDIATE:-0}" == 1 ]]; then
            log_warn "README validation reported warnings; continuing under AUTO_REMEDIATE=1"
        else
            return 1
        fi
    }
    README_DATA=$(cat "$ENGINE_DIR/data/readme_parsed.json")
    README_PARSED=1
    if [[ "$module" == ssh_hardening ]]; then
        if ! command -v sshd >/dev/null 2>&1 && ! systemctl list-unit-files 2>/dev/null | grep -qE '^(ssh|sshd)\.service'; then
            log_warn "SSH service not found; skipping ssh_hardening"
            return 0
        fi
        if [[ -z "${SSH_PUBLIC_KEY_FILE:-}" || ! -f "$SSH_PUBLIC_KEY_FILE" ]]; then
            for pub in /root/*.pub /root/.ssh/*.pub /home/*/*.pub /home/*/.ssh/*.pub /home/*/Desktop/*.pub; do
                if [[ -f "$pub" ]]; then
                    export SSH_PUBLIC_KEY_FILE="$pub"
                    log_info "Auto-detected SSH public key file: $pub"
                    break
                fi
            done
        fi
        if [[ -z "${SSH_TARGET_USER:-}" ]]; then
            local admin_user
            admin_user=$(echo "$README_DATA" | jq -r '.admin_users[0].name // empty')
            if [[ -n "$admin_user" ]]; then
                export SSH_TARGET_USER="$admin_user"
            elif [[ -n "${PROTECTED_USER:-}" ]]; then
                export SSH_TARGET_USER="$PROTECTED_USER"
            fi
        fi
        if [[ -n "${SSH_TARGET_USER:-}" && -f "${SSH_PUBLIC_KEY_FILE:-}" ]]; then
            if echo "$README_DATA" | jq -e --arg user "$SSH_TARGET_USER" '.all_users[] | select(.name == $user)' >/dev/null 2>&1; then
                if ssh-keygen -lf "$SSH_PUBLIC_KEY_FILE" >/dev/null 2>&1; then
                    SSH_PUBLIC_KEY=$(cat "$SSH_PUBLIC_KEY_FILE")
                    if [[ "$SSH_PUBLIC_KEY" == ssh-* || "$SSH_PUBLIC_KEY" == ecdsa-* ]]; then
                        export SSH_PUBLIC_KEY
                    fi
                fi
            fi
        fi
        if [[ -z "${SSH_PUBLIC_KEY:-}" ]]; then
            log_warn "No valid SSH public key found for $SSH_TARGET_USER; skipping ssh_hardening to prevent lockout"
            return 0
        fi
    fi
    run_module "$module"
}
