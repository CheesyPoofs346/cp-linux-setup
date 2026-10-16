#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
for script in cp-engine.sh lib/*.sh modules/*.sh tests/*.sh; do
    bash -n "$script"
done
bash cp-engine.sh --help | grep -q -- '--auto'
echo 'PASS: all shell syntax and CLI help'
