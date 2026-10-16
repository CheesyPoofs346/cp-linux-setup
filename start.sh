#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ -f "$ROOT/config.local.conf" && -f "$ROOT/run.local.conf" ]] || { echo 'Run bash setup.sh first.' >&2; exit 1; }
source "$ROOT/run.local.conf"
[[ $EUID == 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" == "${RUN_SETUP_USER:-}" ]] || { echo 'Start with sudo bash start.sh from the same normal account used for setup.' >&2; exit 1; }
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
