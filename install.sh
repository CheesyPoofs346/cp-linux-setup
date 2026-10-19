#!/bin/bash
# One-shot installer. Run from your normal account on the practice VM:
#   curl -fsSL https://raw.githubusercontent.com/CheesyPoofs346/cp-linux-setup/main/install.sh | bash
# Installs git and prerequisites, downloads/updates the repo, asks only for the API key, then starts.
set -euo pipefail
REPO_URL="${CP_REPO_URL:-https://github.com/CheesyPoofs346/cp-linux-setup.git}"
DEST="${CP_DEST:-$HOME/cp-linux-setup}"

[[ $EUID != 0 ]] || { echo 'Run as your normal user (not root, no sudo). It asks for sudo itself.' >&2; exit 1; }
[[ -r /dev/tty ]] || { echo 'Needs an interactive terminal.' >&2; exit 1; }

echo '[1/4] Installing git and prerequisites (waits for any running apt upgrade)...'
sudo -v </dev/tty
sudo apt-get -o DPkg::Lock::Timeout=3600 update -y </dev/tty || true
sudo apt-get -o DPkg::Lock::Timeout=3600 install -y git curl jq python3 python3-venv perl util-linux coreutils </dev/tty

echo '[2/4] Downloading cp-linux-setup...'
if [[ -d "$DEST/.git" ]]; then
    git -C "$DEST" pull --ff-only || echo 'Could not fast-forward; using the existing copy.'
else
    git clone --depth 1 "$REPO_URL" "$DEST"
fi

echo '[3/4] Installing forensic helpers (optional)...'
bash "$DEST/prepare-forensics.sh" </dev/tty || echo 'Macro parser not installed; forensics still works without it.'

echo '[4/4] Setup: paste your API key when asked (input hidden).'
SETUP_AUTO=1 bash "$DEST/setup.sh" </dev/tty
cd "$DEST"
exec sudo bash start.sh </dev/tty
