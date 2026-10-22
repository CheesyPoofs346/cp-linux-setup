#!/bin/bash
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
# Load only the paste function from start.sh.
source <(sed -n '/^paste_readme()/,/^}/p' "$HERE/start.sh")
ROOT="$TMP"
printf '%s\n' '<h2>Authorized Users:</h2><p>bob</p>' 'EOF' | paste_readme >/dev/null
rc=$?
[[ $rc == 0 ]] || { echo "FAIL: paste rc=$rc"; exit 1; }
grep -q 'Authorized Users' "$TMP/data/auto-source.html" || { echo 'FAIL: pasted README not saved'; exit 1; }
printf '%s\n' 'auto' | paste_readme >/dev/null
rc=$?
[[ $rc == 2 ]] || { echo "FAIL: 'auto' should return 2, got $rc"; exit 1; }
printf '' | paste_readme >/dev/null 2>&1
rc=$?
[[ $rc == 1 ]] || { echo "FAIL: empty paste should fail, got $rc"; exit 1; }
echo 'PASS: README paste saves text, "auto" falls back to search, empty paste is rejected'
