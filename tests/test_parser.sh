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
export OPENROUTER_API_KEY=test
GOOD='{"all_users":[{"name":"operator","account_type":"admin","groups":[]},{"name":"member","account_type":"standard","groups":[]}],"recent_hires":[],"terminated_users":[],"critical_services":["ssh"],"groups_to_create":[],"system_users_to_restrict":[]}'
invoke_readme_extraction() { echo "FAIL: AI called for a cleanly structured README"; return 1; }
parse_readme "$TEST_DIR/README.html"
[[ "$README_PARSED" == 1 ]]
# AI omits a user: deterministic users win, unbacked AI-only account actions are discarded.
OMIT=$(jq '.all_users |= .[0:1] | .terminated_users = ["mallory"]' <<<"$GOOD")
invoke_readme_extraction() { printf '%s\n' "$OMIT"; }
README_AI=always AUTO_REMEDIATE=1 parse_readme "$TEST_DIR/README.html"
[[ "$(jq -r '[.all_users[].name] | join(",")' <<<"$README_DATA")" == operator,member ]]
[[ "$(jq '.terminated_users | length' <<<"$README_DATA")" == 0 ]]
# AI call fails: deterministic parse still authorizes the README's explicit lists.
invoke_readme_extraction() { return 28; }
parse_readme "$TEST_DIR/README.html"
[[ "$(jq '.all_users | length' <<<"$README_DATA")" == 2 ]]
# No recognizable sections and the AI call fails: nothing is authorized.
printf '%s\n' '<p>No structure at all.</p>' > "$TEST_DIR/README3.html"
if parse_readme "$TEST_DIR/README3.html"; then echo 'FAIL: API failure authorized'; exit 1; fi
[[ "$README_PARSED" == 0 ]]
echo 'PASS: AI parses README, deterministic cross-check corrects it and covers AI failure, no sections + AI failure rejects'
