#!/usr/bin/env bash
# Full git-history secret scan with redacted output. Usage: scan-git-history.sh
set -euo pipefail
umask 077
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"
work="${RUNNER_TEMP:-/tmp}/git-history-scan-$$"
mkdir -p "${work}"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT
set +e
gitleaks detect --source "${root}" --redact --log-opts="--all" \
  --report-path "${work}/gitleaks.json" --report-format json \
  --exit-code 1 \
  > "${work}/gitleaks.stdout" 2> "${work}/gitleaks.stderr"
gl_rc=$?
trufflehog git "file://${root}" --no-update --json --no-verification --results=unverified \
  > "${work}/trufflehog.jsonl" 2> "${work}/trufflehog.stderr"
th_rc=$?
set -e
python3 "${root}/.github/scripts/summarize-git-history.py" \
  "${work}/trufflehog.jsonl" "${th_rc}" \
  "${work}/gitleaks.json" "${gl_rc}"
