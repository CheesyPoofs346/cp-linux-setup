#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap '[[ -n "$TEST_DIR" && -d "$TEST_DIR" ]] && rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/lib" "$TEST_DIR/modules"
cp "$ROOT"/lib/{utils.sh,openrouter.sh,validate_readme.py} "$TEST_DIR/lib/"
cp "$ROOT/modules/readme_parser.sh" "$TEST_DIR/modules/"
printf '%s\n' '<h2>Authorized Administrators:</h2><p>operator:secret (YOU)<br></p><h2>Authorized Users:</h2><p>member<br></p><h2>Critical Services:</h2><p>SSH (openssh-server)</p>' > "$TEST_DIR/README.html"
source "$TEST_DIR/modules/readme_parser.sh"
FIXTURE_RESPONSE='{"all_users":[{"name":"operator","account_type":"admin","groups":[]},{"name":"member","account_type":"standard","groups":[]}],"recent_hires":[],"terminated_users":[],"critical_services":["ssh"],"groups_to_create":[],"system_users_to_restrict":[]}'
invoke_readme_extraction() { printf '%s\n' "$FIXTURE_RESPONSE"; }
parse_readme "$TEST_DIR/README.html"
[[ "$README_PARSED" == 1 ]]
FIXTURE_RESPONSE=$(printf '%s' "$FIXTURE_RESPONSE" | jq '.all_users |= .[0:1]')
if parse_readme "$TEST_DIR/README.html"; then echo 'FAIL: omitted user authorized'; exit 1; fi
[[ "$README_PARSED" == 0 ]]
invoke_readme_extraction() { return 28; }
if parse_readme "$TEST_DIR/README.html"; then echo 'FAIL: API failure authorized'; exit 1; fi
echo 'PASS: full parser accepts valid source, rejects omitted account and failed HTTP boundary'
