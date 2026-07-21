#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/audit.py
.venv/bin/pytest -v --junitxml=reports/audit-tests.xml
echo 'PASS: runtime audit and live security tests'
