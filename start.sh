#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Deterministic operation is the default, even when API credentials are saved.
export CP_NO_AI="${CP_NO_AI:-1}"
[[ -f "$ROOT/run.local.conf" ]] && source "$ROOT/run.local.conf"
[[ $EUID == 0 ]] || { echo 'Start with sudo bash start.sh.' >&2; exit 1; }
export AUTO_REMEDIATE=1
if [[ "$CP_NO_AI" == 1 ]]; then
    export SKIP_FORENSICS=1 README_AI=never
fi
# All remediation belongs in the engine, after README validation and forensics.

paste_readme() {
    local target="$ROOT/data/auto-source.html"
    mkdir -p "$ROOT/data"
    echo ""
    echo "================================================================"
    echo "  CYBERPATRIOT README INGESTION"
    echo "================================================================"
    echo "  Paste the full README content below (HTML or plain text)."
    echo "  When finished, press Enter, then Ctrl+D (or type 'EOF' and Enter)."
    echo "  Type 'auto' and Enter instead to search for the README on this machine."
    echo "================================================================"
    
    local line first=1
    : > "$target"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if (( first )); then
            first=0
            [[ "${line,,}" == auto ]] && return 2
        fi
        if [[ "$line" == "EOF" ]]; then
            break
        fi
        printf '%s\n' "$line" >> "$target"
    done
    
    if [[ ! -s "$target" ]]; then
        echo "[ERROR] Pasted README was empty!" >&2
        return 1
    fi
    
    local bytes
    bytes=$(wc -c < "$target" | tr -d ' ')
    echo "[+] Saved $bytes bytes to $target"
    
    # Also save copies for other tools
    cp "$target" /tmp/README.html 2>/dev/null || true
    if [[ -d "/home/${SUDO_USER:-}/Desktop" ]]; then
        cp "$target" "/home/${SUDO_USER:-}/Desktop/README.html" 2>/dev/null || true
    fi
    IMAGE_README="$target"
    if [[ -f "$ROOT/run.local.conf" ]]; then
        sed -i -E "s|^IMAGE_README=.*|IMAGE_README=\"$target\"|" "$ROOT/run.local.conf" 2>/dev/null || true
    fi
    return 0
}

PASTE_MODE=0
CLI_README=""
CLI_README_URL=""
# Deterministic forensics always runs first; this switch controls only the optional AI fallback.
export SKIP_FORENSICS="${SKIP_FORENSICS:-1}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--paste|--paste-readme|paste)
            PASTE_MODE=1
            shift
            ;;
        --readme)
            [[ $# -ge 2 && -n "$2" ]] || { echo "Missing path for --readme" >&2; exit 1; }
            CLI_README="$2"
            shift 2
            ;;
        --readme-url)
            [[ $# -ge 2 && -n "$2" ]] || { echo "Missing URL for --readme-url" >&2; exit 1; }
            CLI_README_URL="$2"
            shift 2
            ;;
        --forensics)
            export SKIP_FORENSICS=0
            echo "[+] Automatic forensics enabled."
            shift
            ;;
        --auto-readme)
            export AUTO_README=1
            shift
            ;;
        -sf|--skip-forensics)
            export SKIP_FORENSICS=1 FORENSICS_DET=0
            echo "[+] SKIP_FORENSICS=1 enabled: Both forensic solvers skipped by explicit operator request; preserve completed answers and evidence."
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Default: paste this image's README by hand (a saved one from an earlier image would be stale).
# Skip with --readme FILE / --readme-url URL / --auto-readme, or type "auto" at the paste prompt.
paste_rc=0
if [[ -n "$CLI_README" ]]; then
    IMAGE_README="$(readlink -f "$CLI_README")"
elif [[ -n "$CLI_README_URL" ]]; then
    IMAGE_README="$CLI_README_URL"
elif [[ "$PASTE_MODE" == 1 || "${README_PASTE:-0}" == 1 || ( "${AUTO_README:-0}" != 1 && -t 0 ) ]]; then
    paste_readme || paste_rc=$?
    if (( paste_rc == 2 )); then
        IMAGE_README=""
    elif (( paste_rc != 0 )); then
        exit 1
    fi
fi

# Auto-detect README if unset or invalid
if [[ -z "${IMAGE_README:-}" || (! -f "$IMAGE_README" && "$IMAGE_README" != https://*) ]]; then
    # First check current directory or setup root for common names
    for cand in \
        "$PWD/README.html" "$PWD/readme.html" "$PWD/README.txt" "$PWD/readme.txt" \
        "$ROOT/README.html" "$ROOT/readme.html" "$ROOT/README.txt" "$ROOT/readme.txt"; do
        if [[ -f "$cand" && -s "$cand" ]]; then
            IMAGE_README="$cand"
            echo "Auto-detected local README from $cand"
            break
        fi
    done
fi

if [[ -z "${IMAGE_README:-}" || (! -f "$IMAGE_README" && "$IMAGE_README" != https://*) ]]; then
    for dt in /home/*/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.desktop \
             /home/*/Desktop/*.desktop \
             /opt/CyberPatriot/*.desktop \
             /opt/cyberpatriot/*.desktop \
             /root/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.desktop; do
        if [[ -f "$dt" && "$dt" != *[Ss]coring* && "$dt" != *[Ss]core* ]]; then
            url=$(grep -i '^Exec=' "$dt" 2>/dev/null | head -n1 | sed -E 's/^Exec=.*(https?:[^"[:space:]]+).*/\1/I' || true)
            if [[ "$url" == https://* ]]; then
                IMAGE_README="$url"
                echo "Auto-detected README URL from $dt: $IMAGE_README"
                break
            fi
            dt_file=$(grep -i '^Exec=' "$dt" 2>/dev/null | head -n1 | sed -E 's/^Exec=[^/]*(\/[^"[:space:]]+).*/\1/' || true)
            if [[ -f "$dt_file" && "$dt_file" != *[Ss]coring* && "$dt_file" != *[Ss]core* ]]; then
                IMAGE_README="$dt_file"
                echo "Auto-detected README from $dt: $IMAGE_README"
                break
            fi
        fi
    done
fi

if [[ -z "${IMAGE_README:-}" || (! -f "$IMAGE_README" && "$IMAGE_README" != https://*) ]]; then
    for candidate in \
        "/opt/CyberPatriot/README.html" \
        "/opt/cyberpatriot/README.html" \
        "/opt/aeacus/assets/ReadMe.html" \
        "/opt/aeacus/assets/README.html" \
        /home/*/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
        /home/*/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
        /tmp/README.html \
        /tmp/readme.html \
        /root/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
        /root/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html; do
        if [[ -f "$candidate" && "$candidate" != *[Ss]coring* && "$candidate" != *[Ss]core* ]]; then
            IMAGE_README="$candidate"
            echo "Auto-detected README: $IMAGE_README"
            break
        fi
    done
fi

if [[ -z "${IMAGE_README:-}" || (! -f "$IMAGE_README" && "$IMAGE_README" != https://*) ]]; then
    if [[ -f "$ROOT/data/auto-source.html" && -s "$ROOT/data/auto-source.html" ]]; then
        IMAGE_README="$ROOT/data/auto-source.html"
        echo "Using existing README data from $IMAGE_README"
    elif [[ -t 0 ]]; then
        echo "[!] No README found automatically."
        paste_readme || exit 1
    fi
fi

args=(--auto)
[[ "${RUN_ALLOW_UNSUPPORTED:-0}" == 1 ]] && args+=(--allow-unsupported)
if [[ "${IMAGE_README:-}" == https://* ]]; then
    args+=(--readme-url "$IMAGE_README")
elif [[ -n "${IMAGE_README:-}" && -f "$IMAGE_README" ]]; then
    args+=(--readme "$IMAGE_README")
else
    echo '[ERROR] Saved README is missing or invalid. Run: sudo bash start.sh --paste' >&2
    exit 1
fi
exec bash "$ROOT/cp-engine.sh" "${args[@]}"
