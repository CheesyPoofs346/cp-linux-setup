#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap '[[ -n "$TEST_DIR" && -d "$TEST_DIR" ]] && rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/lib" "$TEST_DIR/modules"
cp "$ROOT"/lib/{utils.sh,openrouter.sh,validate_readme.py,readme_extract.py} "$TEST_DIR/lib/"
cp "$ROOT/modules/readme_parser.sh" "$TEST_DIR/modules/"
printf '%s\n' '<h2>Authorized Administrators:</h2><p>operator:secret (YOU)<br></p><h2>Authorized Users:</h2><p>member<br></p><h2>Critical Services:</h2><p>SSH (openssh-server)</p>' > "$TEST_DIR/README.html"
source "$TEST_DIR/modules/readme_parser.sh"
invoke_readme_extraction() { echo 'FAIL: AI called for fully structured README'; return 1; }
parse_readme "$TEST_DIR/README.html"
[[ "$README_PARSED" == 1 ]]
[[ "$(jq '.all_users | length' <<<"$README_DATA")" == 2 ]]
# Free-text mention the parser cannot structure: AI fills only that field, users stay deterministic.
printf '%s
' '<p>Mallory was terminated.</p><h2>Authorized Administrators:</h2><p>operator:secret (YOU)<br></p><h2>Authorized Users:</h2><p>member<br></p><h2>Critical Services:</h2><p>SSH (openssh-server)</p>' > "$TEST_DIR/README2.html"
export OPENROUTER_API_KEY=test
invoke_readme_extraction() { printf '%s
' '{"all_users":[{"name":"evil","account_type":"admin","groups":[]}],"recent_hires":[],"terminated_users":["mallory"],"critical_services":["telnet"],"groups_to_create":[],"system_users_to_restrict":[]}'; }
AUTO_REMEDIATE=1 parse_readme "$TEST_DIR/README2.html"
[[ "$(jq -r '.terminated_users[]' <<<"$README_DATA")" == mallory ]]
[[ "$(jq -r '[.all_users[].name] | join(",")' <<<"$README_DATA")" == operator,member ]]
[[ "$(jq -r '.critical_services | join(",")' <<<"$README_DATA")" == ssh ]]
# No recognizable sections and the AI call fails: nothing is authorized.
printf '%s
' '<p>No structure at all.</p>' > "$TEST_DIR/README3.html"
invoke_readme_extraction() { return 28; }
if parse_readme "$TEST_DIR/README3.html"; then echo 'FAIL: API failure authorized'; exit 1; fi
[[ "$README_PARSED" == 0 ]]
echo 'PASS: deterministic parse without AI, AI limited to free-text gaps, failed AI boundary rejects'
