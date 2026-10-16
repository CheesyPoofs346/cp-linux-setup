#!/bin/bash
set -euo pipefail
[[ $EUID != 0 ]] || { echo 'Run bash prepare-forensics.sh from your normal account, without sudo.' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if ! python3 -m venv "$ROOT/.forensics-venv"; then
    sudo apt-get install -y python3-venv
    python3 -m venv "$ROOT/.forensics-venv"
fi
"$ROOT/.forensics-venv/bin/python" -m pip install 'oletools==0.60.2'
"$ROOT/.forensics-venv/bin/python" -c 'from oletools.olevba import VBA_Parser'
echo 'Static Office macro parser installed. Next: sudo bash start.sh'
