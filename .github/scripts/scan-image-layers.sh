#!/usr/bin/env bash
# docker save an already-loaded image, extract layers, and scan with
# trufflehog + gitleaks. Values never go to stdout; the summarizer prints
# counts and paths only. Usage: scan-image-layers.sh <image-ref>
set -euo pipefail
umask 077
image="${1:?image ref required}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="${RUNNER_TEMP:-/tmp}/image-scan-$$"
mkdir -p "${work}/raw" "${work}/layers" "${work}/reports"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT
docker save "${image}" -o "${work}/image.tar"
tar -xf "${work}/image.tar" -C "${work}/raw"
python3 "${root}/.github/scripts/extract-image-layers.py" "${work}/raw" "${work}/layers"
set +e
# Default verification is on. The summarizer fails only on verified results
# so noise in OS/language layers (URI, dpkg metadata) is reported but does
# not block the job.
trufflehog filesystem "${work}/layers" --no-update --json --results=verified,unknown,unverified \
  > "${work}/reports/trufflehog.jsonl" 2> "${work}/reports/trufflehog.stderr"
th_rc=$?
gitleaks detect --source "${work}/layers" --no-git --redact \
  --report-path "${work}/reports/gitleaks.json" --report-format json \
  --exit-code 1 \
  > "${work}/reports/gitleaks.stdout" 2> "${work}/reports/gitleaks.stderr"
gl_rc=$?
set -e
python3 "${root}/.github/scripts/summarize-scan-results.py" \
  "${work}/reports/trufflehog.jsonl" "${th_rc}" \
  "${work}/reports/gitleaks.json" "${gl_rc}"
