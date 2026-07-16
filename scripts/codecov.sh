#!/bin/bash
# Upload Go unit test coverage to Codecov.
# Called by CI presubmit (coverage) and postsubmit (publish-coverage) Prow jobs.
# Credentials are mounted from the rosa-boundary-codecov Kubernetes secret.

set -euo pipefail

echo "=== Uploading Coverage to Codecov ==="

CODECOV_TOKEN=$(cat /var/run/codecov-secret/CODECOV_TOKEN)
export CODECOV_TOKEN
CODECOV_ENTERPRISE_URL=$(cat /var/run/codecov-secret/CODECOV_ENTERPRISE_URL)

trap 'rm --force codecov codecov.SHA256SUM' EXIT

if [ ! -f coverage.out ]; then
    echo "Error: coverage.out not found — run 'make test-coverage' first"
    exit 1
fi

# PULL_PULL_SHA: PR head commit (presubmit); PULL_BASE_SHA: pushed commit (postsubmit)
GIT_COMMIT="${PULL_PULL_SHA:-${PULL_BASE_SHA:-$(git rev-parse HEAD)}}"
# PULL_HEAD_REF: PR head branch (presubmit); PULL_BASE_REF: pushed branch (postsubmit)
GIT_BRANCH="${PULL_HEAD_REF:-${PULL_BASE_REF:-$(git rev-parse --abbrev-ref HEAD)}}"

echo "Upload: commit=${GIT_COMMIT}, branch=${GIT_BRANCH}, pr=${PULL_NUMBER:-none}"

CODECOV_VERSION="v11.3.1"
curl --fail --silent --show-error --output codecov --connect-timeout 10 --max-time 60 --retry 3 --retry-max-time 90 \
    "https://cli.codecov.io/${CODECOV_VERSION}/linux/codecov"
curl --fail --silent --show-error --output codecov.SHA256SUM --connect-timeout 10 --max-time 60 --retry 3 --retry-max-time 90 \
    "https://cli.codecov.io/${CODECOV_VERSION}/linux/codecov.SHA256SUM"
sha256sum --check codecov.SHA256SUM
chmod +x codecov

UPLOAD_ARGS=(
    --enterprise-url "${CODECOV_ENTERPRISE_URL}"
    upload-process
    --fail-on-error
    --slug="openshift-online/rosa-boundary"
    --flag go-unit-tests
    --file coverage.out
    --git-service github
    --commit-sha "${GIT_COMMIT}"
    --branch "${GIT_BRANCH}"
    --disable-search
)

if [ -n "${PULL_NUMBER:-}" ]; then
    UPLOAD_ARGS+=(--pr "${PULL_NUMBER}")
    UPLOAD_ARGS+=(--parent-sha "${PULL_BASE_SHA}")
fi

./codecov "${UPLOAD_ARGS[@]}"

echo "Coverage upload complete."
