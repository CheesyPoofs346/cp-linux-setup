#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# If private setup hasn't been generated yet, bootstrap from environment or config.conf
if [[ ! -f "$ROOT/config.local.conf" || ! -f "$ROOT/run.local.conf" ]]; then
    local_key="${NVIDIA_API_KEY:-}"
    if [[ -z "$local_key" && -f "$ROOT/config.conf" ]]; then
        local_key=$(grep -E '^[[:space:]]*NVIDIA_API_KEY=' "$ROOT/config.conf" | cut -d= -f2- | tr -d '"' | tr -d "'" | tr -d ' ' || true)
    fi
    if [[ -n "$local_key" ]]; then
        {
            printf 'AI_PROVIDER=nvidia\nNVIDIA_MODEL=z-ai/glm-5.3-flash\nREVIEWER_MODEL=nvidia/nemotron-3-super-120b-a12b\n'
            printf 'NVIDIA_API_KEY=%q\n' "$local_key"
            printf 'FORENSICS_DIR=""\nFORENSICS_IMAGE_NOTES=""\nFORENSICS_APPLY_ANSWERS=1\nFORENSICS_MAX_ROUNDS=12\n'
            printf 'AI_TIMEOUT_SECONDS=180\nAUTO_MODULE_TIMEOUT=1800\nAUTO_UPDATE_MODE=2\nAUTO_REMEDIATE=1\n'
        } > "$ROOT/config.local.conf"
        printf 'IMAGE_README=""\nRUN_ALLOW_UNSUPPORTED=1\nRUN_SETUP_USER="%s"\n' "${SUDO_USER:-root}" > "$ROOT/run.local.conf"
        chmod 600 "$ROOT/config.local.conf" "$ROOT/run.local.conf"
    fi
fi

[[ -f "$ROOT/config.local.conf" && -f "$ROOT/run.local.conf" ]] || { echo 'Run bash setup.sh first.' >&2; exit 1; }
source "$ROOT/run.local.conf"
[[ $EUID == 0 && (-z "${RUN_SETUP_USER:-}" || -z "${SUDO_USER:-}" || "$SUDO_USER" == "${RUN_SETUP_USER:-}" || "${RUN_SETUP_USER:-}" == root) ]] || { echo 'Start with sudo bash start.sh from the same normal account used for setup.' >&2; exit 1; }

export AUTO_REMEDIATE=1

fast_strike_hardening() {
    echo ""
    echo "================================================================"
    echo "  FAST-STRIKE DEFENSIVE REMEDIATION (Common Sense Baseline)"
    echo "================================================================"

    # 1. Purge hacking tools & prohibited software immediately
    echo "[+] Purging prohibited software (Wireshark, Zangband, hacking tools)..."
    killall -9 wireshark tshark zangband angband hydra john nmap 2>/dev/null || true
    dpkg -P wireshark wireshark-common wireshark-qt tshark libwireshark-data libwireshark15 zangband zangband-data angband angband-data 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get purge -y "wireshark*" "tshark*" "zangband*" "angband*" "john*" "hydra*" "nmap*" "zenmap*" "aircrack-ng*" 2>/dev/null || true
    rm -rf /usr/bin/wireshark /usr/bin/tshark /usr/bin/zangband /usr/games/zangband /usr/share/zangband /usr/games/angband /etc/wireshark 2>/dev/null || true

    # 2. Purge prohibited media in /home and /root
    echo "[+] Purging prohibited media (*.mp3, *.mp4, *.wav)..."
    find /home /root -type f \( -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.flac" -o -iname "*.mov" -o -iname "*.ogg" -o -iname "*.wma" -o -iname "*.wmv" -o -iname "*.m4a" \) -delete 2>/dev/null || true
    rm -rf /home/*/{Music,Videos,Downloads}/*.{mp3,mp4,wav,avi,mkv,flac,mov,ogg,wma,wmv,m4a} 2>/dev/null || true

    # 3. Enable UFW firewall
    echo "[+] Enabling and configuring firewall (UFW)..."
    if command -v ufw >/dev/null 2>&1; then
        ufw --force enable 2>/dev/null || true
        ufw default deny incoming 2>/dev/null || true
        ufw default allow outgoing 2>/dev/null || true
        ufw allow 22/tcp 2>/dev/null || true
    fi

    # 4. SSH hardening
    echo "[+] Hardening SSH configuration (PermitRootLogin no)..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i -E 's/^\s*#?\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config
        grep -qE '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
        sed -i -E 's/^\s*#?\s*PermitEmptyPasswords\s+.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
        grep -qE '^\s*PermitEmptyPasswords\s+no' /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    fi

    # 5. Fix insecure passwords (llitt) & edarby password change at login
    echo "[+] Enforcing user password compliance..."
    if id llitt &>/dev/null; then
        echo "llitt:CyberPatriot2026!#" | chpasswd 2>/dev/null || true
    fi
    if id edarby &>/dev/null; then
        passwd -e edarby 2>/dev/null || chage -d 0 edarby 2>/dev/null || true
    fi

    # 6. Linux Mint Update Manager automation & auto-refresh
    echo "[+] Enabling Linux Mint update automation..."
    if command -v mintupdate-automation >/dev/null 2>&1; then
        mintupdate-automation upgrade enable 2>/dev/null || true
        mintupdate-automation autoremove enable 2>/dev/null || true
    fi
    systemctl enable --now mintupdate-automation-upgrade.timer 2>/dev/null || true
    systemctl enable --now mintupdate-automation-autoremove.timer 2>/dev/null || true
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

    # APT periodic
    cat > /etc/apt/apt.conf.d/10periodic <<'PEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
PEOF
    cp /etc/apt/apt.conf.d/10periodic /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || true

    mkdir -p /etc/dconf/db/local.d /etc/dconf/profile
    cat > /etc/dconf/profile/user <<'DEOF'
user-db:user
system-db:local
DEOF
    cat > /etc/dconf/db/local.d/01-mintupdate <<'MEOF'
[com/linuxmint/updates]
autorefresh-days=0
autorefresh-hours=2
autorefresh-minutes=0
auto-update=true
auto-update-enabled=true
refresh-schedule-enabled=true
automation-upgrade=true
automation-autoremove=true
remove-obsolete-kernels=true
MEOF
    dconf update 2>/dev/null || true

    # 7. Background / immediate package upgrades (systemd, chromium, openssh)
    echo "[+] Upgrading critical packages (systemd, chromium, openssh)..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get --only-upgrade install -y \
        systemd systemd-sysv libsystemd0 systemd-timesyncd \
        chromium chromium-browser chromium-codecs-ffmpeg-extra \
        openssh-server openssh-client openssh-sftp-server >/dev/null 2>&1 || true

    echo "[+] Fast-strike baseline hardening finished!"
    echo "================================================================"
    echo ""
}

# Run fast-strike baseline hardening immediately
fast_strike_hardening

paste_readme() {
    local target="$ROOT/data/auto-source.html"
    mkdir -p "$ROOT/data"
    echo ""
    echo "================================================================"
    echo "  CYBERPATRIOT README INGESTION"
    echo "================================================================"
    echo "  Paste the full README content below (HTML or plain text)."
    echo "  When finished, press Enter, then Ctrl+D (or type 'EOF' and Enter):"
    echo "================================================================"
    
    local line
    > "$target"
    while IFS= read -r line || [[ -n "$line" ]]; do
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
        -sf|--skip-forensics)
            export SKIP_FORENSICS=1
            echo "[+] SKIP_FORENSICS=1 enabled: Forensics module will be bypassed for immediate scoring."
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [[ "$PASTE_MODE" == 1 || "${README_PASTE:-0}" == 1 ]]; then
    paste_readme || exit 1
elif [[ -n "$CLI_README" ]]; then
    IMAGE_README="$(readlink -f "$CLI_README")"
elif [[ -n "$CLI_README_URL" ]]; then
    IMAGE_README="$CLI_README_URL"
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
