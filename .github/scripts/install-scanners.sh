#!/usr/bin/env bash
# Install pinned gitleaks and trufflehog. Requires GITLEAKS_VERSION,
# GITLEAKS_SHA256, TRUFFLEHOG_VERSION, and TRUFFLEHOG_SHA256.
set -euo pipefail
umask 077
: "${GITLEAKS_VERSION:?}" "${GITLEAKS_SHA256:?}"
: "${TRUFFLEHOG_VERSION:?}" "${TRUFFLEHOG_SHA256:?}"
cd "${RUNNER_TEMP:-/tmp}"
curl -fsSL -o gitleaks.tgz \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
echo "${GITLEAKS_SHA256}  gitleaks.tgz" | sha256sum -c -
tar -xzf gitleaks.tgz gitleaks
install -m 0755 gitleaks /usr/local/bin/gitleaks
curl -fsSL -o trufflehog.tgz \
  "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"
echo "${TRUFFLEHOG_SHA256}  trufflehog.tgz" | sha256sum -c -
tar -xzf trufflehog.tgz trufflehog
install -m 0755 trufflehog /usr/local/bin/trufflehog
gitleaks version
trufflehog --version
