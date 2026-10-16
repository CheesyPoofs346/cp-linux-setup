#!/bin/bash
# One-command orchestration. Modules run in separate processes to isolate globals.
run_auto() {
    local source_file="$ENGINE_DIR/data/auto-source.html"
    local report="$ENGINE_DIR/data/auto-results.tsv"
    local module status reviews=0 failed=0
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
    for module in "${MODULES[@]}"; do
        [[ "$module" == readme_parser ]] && continue
        if (( failed )); then
            printf '%s\tNOT_RUN\n' "$module" >> "$report"
            continue
        fi
        # These modules use AI-generated removal decisions/commands. Review separately.
        case "$module" in
            malware|unwanted_software|prohibited_files)
                printf '%s\tMANUAL_REVIEW\n' "$module" >> "$report"
                log_warn "$module requires separate review; not executed unattended"
                reviews=$((reviews + 1))
                continue
                ;;
            ssh_hardening)
                if [[ -z "${SSH_TARGET_USER:-}" || ! -f "${SSH_PUBLIC_KEY_FILE:-}" ]]; then
                    printf '%s\tMANUAL_REVIEW\n' "$module" >> "$report"
                    log_warn "SSH needs SSH_TARGET_USER and SSH_PUBLIC_KEY_FILE; left unchanged"
                    reviews=$((reviews + 1))
                    continue
                fi
                ;;
        esac
        if timeout --foreground --kill-after=10 "${AUTO_MODULE_TIMEOUT:-1800}" bash "$ENGINE_DIR/cp-engine.sh" --worker-module "$module" </dev/null; then
            status=PASS
        else
            status=FAILED
            failed=1
        fi
        printf '%s\t%s\n' "$module" "$status" >> "$report"
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
