#!/bin/bash
set -euo pipefail
ENGINE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ "${1:-}" != --inside ]]; then
    export CP_PARENT_MNT_NS="$(readlink /proc/self/ns/mnt)"
    exec unshare --mount --propagation private bash "$0" --inside "$@"
fi
shift
[[ "${CP_PARENT_MNT_NS:-}" == "$(readlink /proc/$PPID/ns/mnt)" && "$(readlink /proc/self/ns/mnt)" != "$CP_PARENT_MNT_NS" ]] || { echo 'Private mount namespace required' >&2; exit 1; }
module="${1:?module required}"
guard="$ENGINE_DIR/data/protected-account.json"
python3 "$ENGINE_DIR/lib/peer_review.py" --check-sources
python3 "$ENGINE_DIR/lib/account_guard.py" check "$guard"
home=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["home"])' "$guard")
# Direct legacy writes cannot change account databases, sudo/PAM policy, or home files.
for path in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/login.defs /etc/pam.d /etc/sudoers.d /etc/security "$home"; do
    [[ -e "$path" ]] || continue
    mount --bind "$path" "$path"
    mount -o remount,bind,ro "$path"
done
# Permit only runner reports/caches within an otherwise read-only home tree.
mount --bind "$ENGINE_DIR/data" "$ENGINE_DIR/data"
mount -o remount,bind,rw "$ENGINE_DIR/data"
exec setpriv --bounding-set=-sys_admin,-sys_rawio,-linux_immutable,-sys_ptrace bash "$ENGINE_DIR/cp-engine.sh" --worker-module "$module"
