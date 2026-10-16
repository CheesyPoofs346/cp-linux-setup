#!/bin/bash
# Interactive setup only. Remediation starts separately through start.sh.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
umask 077
[[ -t 0 ]] || { echo 'Run setup in an interactive terminal.' >&2; exit 1; }
[[ $EUID != 0 ]] || { echo 'Run bash setup.sh from your normal user account, without sudo.' >&2; exit 1; }
source "$ROOT/config.conf"
if [[ -f "$ROOT/config.local.conf" ]]; then source "$ROOT/config.local.conf"; fi

echo 'Linux practice setup — GLM Flash worker + Nemotron Super reviewer'
echo 'Use a disposable VM snapshot. This setup does not start remediation.'
missing=0
for tool in curl jq python3 perl flock timeout unshare mount setpriv; do
    command -v "$tool" >/dev/null || missing=1
done
if (( missing )); then
    read -r -p 'Install missing prerequisites using apt? [Y/n]: ' answer
    if [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]; then
        sudo apt-get update
        sudo apt-get install -y curl jq python3 perl util-linux coreutils
    else
        echo 'Install curl, jq, python3, perl, util-linux and coreutils, then rerun setup.' >&2
        exit 1
    fi
fi

key=''
if [[ -n "${NVIDIA_API_KEY:-}" ]]; then
    read -r -s -p 'NVIDIA API key (Enter keeps the saved key): ' key
else
    read -r -s -p 'Paste NVIDIA API key (input hidden): ' key
fi
echo
key="${key:-${NVIDIA_API_KEY:-}}"
[[ -n "$key" && "$key" != *$'\n'* && "$key" != *$'\r'* ]] || { echo 'A valid single-line key is required.' >&2; exit 1; }

previous=''
if [[ -f "$ROOT/run.local.conf" ]]; then
    source "$ROOT/run.local.conf"
    previous="${IMAGE_README:-}"
fi
read -r -p "Image README HTTPS URL or local HTML path${previous:+ (Enter keeps saved value)}: " readme
readme="${readme:-$previous}"
if [[ "$readme" == https://* ]]; then
    :
elif [[ -n "$readme" && -f "$readme" ]]; then
    readme=$(readlink -f "$readme")
else
    echo 'Provide an HTTPS URL or an existing local README HTML file.' >&2
    exit 1
fi
read -r -p 'Question directory (Enter searches user Desktops): ' questions
if [[ -n "$questions" ]]; then
    [[ -d "$questions" ]] || { echo 'Question directory does not exist.' >&2; exit 1; }
    questions=$(readlink -f "$questions")
fi

source /etc/os-release
unsupported=0
if ! { [[ "$ID" == ubuntu && "$VERSION_ID" == 24.* ]] || [[ "$ID" == linuxmint && "$VERSION_ID" == 21* ]]; }; then
    echo "Detected $ID $VERSION_ID. This is outside the original supported OS versions."
    read -r -p 'Allow an experimental run on this disposable VM? [y/N]: ' answer
    [[ "$answer" =~ ^[Yy]$ ]] || { echo 'Setup stopped; use a supported practice VM.' >&2; exit 1; }
    unsupported=1
fi

config_tmp=$(mktemp "$ROOT/.config.local.XXXXXX")
run_tmp=$(mktemp "$ROOT/.run.local.XXXXXX")
trap 'rm -f -- "$config_tmp" "$run_tmp"' EXIT
# %q prevents pasted values from becoming shell code when loaded later.
{
    printf 'AI_PROVIDER=nvidia\nNVIDIA_MODEL=z-ai/glm-5.3-flash\nREVIEWER_MODEL=nvidia/nemotron-3-super-120b-a12b\n'
    printf 'NVIDIA_API_KEY=%q\n' "$key"
    printf 'FORENSICS_DIR=%q\n' "$questions"
    printf 'FORENSICS_IMAGE_NOTES=%q\n' "${FORENSICS_IMAGE_NOTES:-}"
    printf 'FORENSICS_APPLY_ANSWERS=%q\n' "${FORENSICS_APPLY_ANSWERS:-1}"
    printf 'AI_TIMEOUT_SECONDS=%q\n' "${AI_TIMEOUT_SECONDS:-180}"
    printf 'AUTO_MODULE_TIMEOUT=%q\n' "${AUTO_MODULE_TIMEOUT:-1800}"
    printf 'AUTO_UPDATE_MODE=%q\n' "${AUTO_UPDATE_MODE:-1}"
} > "$config_tmp"
{
    printf 'IMAGE_README=%q\n' "$readme"
    printf 'RUN_ALLOW_UNSUPPORTED=%q\n' "$unsupported"
    printf 'RUN_SETUP_USER=%q\n' "$(id -un)"
} > "$run_tmp"
chmod 600 "$config_tmp" "$run_tmp"
if [[ -f "$ROOT/config.local.conf" ]]; then install -m 600 "$ROOT/config.local.conf" "$ROOT/config.local.conf.previous"; fi
mv -- "$config_tmp" "$ROOT/config.local.conf"
mv -- "$run_tmp" "$ROOT/run.local.conf"
unset key NVIDIA_API_KEY
echo 'Saved private setup. Your key was not displayed.'
echo 'Next command: sudo bash start.sh'
