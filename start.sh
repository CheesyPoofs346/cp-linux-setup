#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# If private setup hasn't been generated yet, bootstrap from config.conf if key is set
if [[ ! -f "$ROOT/config.local.conf" || ! -f "$ROOT/run.local.conf" ]]; then
    if [[ -f "$ROOT/config.conf" ]]; then
        source "$ROOT/config.conf"
        if [[ -n "${NVIDIA_API_KEY:-}" ]]; then
            cp "$ROOT/config.conf" "$ROOT/config.local.conf"
            printf 'IMAGE_README=""\nRUN_ALLOW_UNSUPPORTED=1\nRUN_SETUP_USER="%s"\n' "${SUDO_USER:-root}" > "$ROOT/run.local.conf"
        fi
    fi
fi

[[ -f "$ROOT/config.local.conf" && -f "$ROOT/run.local.conf" ]] || { echo 'Run bash setup.sh first.' >&2; exit 1; }
source "$ROOT/run.local.conf"
[[ $EUID == 0 && (-z "${RUN_SETUP_USER:-}" || -z "${SUDO_USER:-}" || "$SUDO_USER" == "${RUN_SETUP_USER:-}" || "${RUN_SETUP_USER:-}" == root) ]] || { echo 'Start with sudo bash start.sh from the same normal account used for setup.' >&2; exit 1; }

export AUTO_REMEDIATE=1

# Auto-detect README if unset or invalid
if [[ -z "${IMAGE_README:-}" || (! -f "$IMAGE_README" && "$IMAGE_README" != https://*) ]]; then
    for candidate in \
        "/opt/CyberPatriot/README.html" \
        "/opt/cyberpatriot/README.html" \
        "/opt/aeacus/assets/ReadMe.html" \
        "/opt/aeacus/assets/README.html" \
        /home/*/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
        /home/*/Desktop/*[Rr][Ee][Aa][Dd]*.html \
        /home/*/Desktop/*.html \
        /home/*/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
        /root/Desktop/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html \
        /root/*[Rr][Ee][Aa][Dd][Mm][Ee]*.html; do
        if [[ -f "$candidate" ]]; then
            IMAGE_README="$candidate"
            echo "Auto-detected README: $IMAGE_README"
            break
        fi
    done
    if [[ -z "${IMAGE_README:-}" || ! -f "$IMAGE_README" ]]; then
        for dt in /home/*/Desktop/*.desktop /opt/CyberPatriot/*.desktop /opt/cyberpatriot/*.desktop; do
            if [[ -f "$dt" ]]; then
                url=$(grep -i '^Exec=' "$dt" 2>/dev/null | head -n1 | sed -E 's/^Exec=.*(https?:[^"[:space:]]+).*/\1/I' || true)
                if [[ "$url" == https://* ]]; then
                    IMAGE_README="$url"
                    echo "Auto-detected README URL from $dt: $IMAGE_README"
                    break
                fi
            fi
        done
    fi
fi

args=(--auto)
[[ "${RUN_ALLOW_UNSUPPORTED:-0}" == 1 ]] && args+=(--allow-unsupported)
if [[ "${IMAGE_README:-}" == https://* ]]; then
    args+=(--readme-url "$IMAGE_README")
elif [[ -n "${IMAGE_README:-}" && -f "$IMAGE_README" ]]; then
    args+=(--readme "$IMAGE_README")
else
    echo 'Saved README is missing or invalid; rerun bash setup.sh.' >&2
    exit 1
fi
exec bash "$ROOT/cp-engine.sh" "${args[@]}"
