#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap '[[ -n "$TEST_DIR" && -d "$TEST_DIR" ]] && rm -rf -- "$TEST_DIR"' EXIT
source "$ROOT/lib/openrouter.sh"
source "$ROOT/lib/automation.sh"
export FORENSICS_DET=0

# Mock only the HTTP boundary. jq and the response handling are real.
OPENROUTER_API_KEY=dummy
AI_PROVIDER=openrouter
configure_ai
curl() { printf '%s\n' "$MOCK_RESPONSE"; }
MOCK_RESPONSE='{"choices":[{"message":{"role":"assistant","content":null,"reasoning":"thinking"},"finish_reason":"length"}]}'
test_openrouter
MOCK_RESPONSE='{"error":{"message":"Quota exhausted"}}'
if test_openrouter; then echo 'FAIL: API error accepted'; exit 1; fi
AI_PROVIDER=nvidia
NVIDIA_API_KEY=dummy-nvidia
NVIDIA_MODEL=nvidia/test-model
configure_ai
[[ "$OPENROUTER_API_KEY" == dummy-nvidia && "$OPENROUTER_API_URL" == https://integrate.api.nvidia.com/v1/chat/completions && "$OPENROUTER_MODEL" == nvidia/test-model ]]
unset -f curl

# Auto runner: no real remediation, networking, root privileges, or package changes.
ENGINE_DIR="$TEST_DIR/engine"
mkdir -p "$ENGINE_DIR/data"
printf '<h1>Fixture</h1>' > "$TEST_DIR/readme.html"
README_FILE="$TEST_DIR/readme.html"
README_URL=''
MODULES=(readme_parser forensics_questions local_policy security_policy user_auditing account_policy malware prohibited_files unwanted_software ssh_hardening)
snapshot_main_account() { return 0; }
check_guard_support() { return 0; }
check_main_account() { return 0; }
run_anomaly_audit() { return 0; }
review_auto_plan() { return 0; }
peer_approved() { return 0; }
run_module() { return 1; }
timeout() { touch "$TEST_DIR/remediation-started"; }
if run_auto; then echo 'FAIL: parser failure ignored'; exit 1; fi
[[ ! -e "$TEST_DIR/remediation-started" ]]
run_module() { return 0; }
timeout() { printf '%s\n' "${@: -1}" >> "$TEST_DIR/executed"; }
status=0
run_auto || status=$?
[[ "$status" == 2 ]]
[[ "$(wc -l < "$TEST_DIR/executed")" == 3 ]]
[[ "$(head -1 "$TEST_DIR/executed")" == forensics_questions ]]
grep -q $'malware\tMANUAL_REVIEW' "$ENGINE_DIR/data/auto-results.tsv"
grep -q $'ssh_hardening\tMANUAL_REVIEW' "$ENGINE_DIR/data/auto-results.tsv"
timeout() { [[ "${@: -1}" == forensics_questions ]] && return 0; return 124; }
status=0
run_auto || status=$?
[[ "$status" == 1 ]]
grep -q $'local_policy\tFAILED' "$ENGINE_DIR/data/auto-results.tsv"
grep -q $'security_policy\tNOT_RUN' "$ENGINE_DIR/data/auto-results.tsv"
timeout() { return 2; }
status=0
run_auto || status=$?
[[ "$status" == 2 ]]
grep -q $'forensics_questions\tMANUAL_REVIEW' "$ENGINE_DIR/data/auto-results.tsv"
if grep -q 'user_auditing' "$ENGINE_DIR/data/auto-results.tsv"; then echo 'FAIL: cleanup started before forensics resolved'; exit 1; fi
timeout() { printf '%s\n' "${@: -1}" >> "$TEST_DIR/reviewer-block-executed"; }
review_auto_plan() { return 2; }
status=0
run_auto || status=$?
[[ "$status" == 2 && "$(wc -l < "$TEST_DIR/reviewer-block-executed")" == 1 ]]
grep -q $'peer_review\tMANUAL_REVIEW' "$ENGINE_DIR/data/auto-results.tsv"
echo 'PASS: API reasoning-only success/error, NVIDIA routing, failed preflight, review status, timeout stops remaining modules'

# Unattended runs may continue after a module failure, but must return failure.
export CP_NO_AI=1 AUTO_REMEDIATE=1 SKIP_FORENSICS=1 SENTINEL=0
MODULES=(readme_parser local_policy security_policy)
review_auto_plan() { return 0; }
quiesce_apt() { return 0; }
clear_immutable_flags() { return 0; }
repair_package_state() { return 0; }
repair_operator_aging() { return 0; }
python3() { return 0; }
timeout() { [[ "${@: -1}" != local_policy ]]; }
status=0
run_auto || status=$?
[[ "$status" == 1 ]] || { echo "FAIL: unattended module failure returned $status"; exit 1; }
grep -q $'security_policy\tPASS' "$ENGINE_DIR/data/auto-results.tsv"
echo 'PASS: unattended execution continues but preserves failure status'

export SENTINEL=1
python3() { printf '%s\n' "$*" >> "$TEST_DIR/python-calls"; return 0; }
timeout() { return 0; }
run_auto </dev/null
grep -q 'sentinel.py --once' "$TEST_DIR/python-calls" || { echo 'FAIL: noninteractive run skipped sentinel'; exit 1; }
echo 'PASS: noninteractive run executes one deterministic sentinel pass'

export FORENSICS_DET=1
python3() { [[ "$*" != *forensics_det.py* ]] || return 2; return 0; }
timeout() { touch "$TEST_DIR/cleanup-after-unsolved"; }
status=0
run_auto </dev/null || status=$?
[[ "$status" == 2 && ! -e "$TEST_DIR/cleanup-after-unsolved" ]] || { echo 'FAIL: unresolved forensics allowed cleanup'; exit 1; }
echo 'PASS: unresolved forensics pauses before evidence-changing modules'
