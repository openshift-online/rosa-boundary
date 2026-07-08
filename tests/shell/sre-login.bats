#!/usr/bin/env bats
# Tests for skel/sre/.local/bin/sre-login — cluster login script

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"

load helpers/setup
load helpers/stubs

SRE_LOGIN="${REPO_ROOT}/skel/sre/.local/bin/sre-login"

setup() {
    TEST_TMPDIR="$(mktemp --directory)"
    export TEST_TMPDIR
    STUBS_DIR="${TEST_TMPDIR}/stubs"
    mkdir --parents "${STUBS_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"
    export HOME="${TEST_TMPDIR}/home"
    mkdir --parents "${HOME}/.session"

    # Source sre-login to get access to get_cluster_json function
    source "${SRE_LOGIN}"
}

teardown() {
    rm --recursive --force "${TEST_TMPDIR}"
}

# ── proxy mode ───────────────────────────────────────────────────────────────

@test "sre-login: exits cleanly in proxy mode" {
    export CLUSTER_AUTH_METHOD="proxy"
    run bash "${SRE_LOGIN}" test-cluster
    assert_success
    assert_output --partial "Proxy sidecar mode"
}

# ── get_cluster_json ─────────────────────────────────────────────────────────

@test "get_cluster_json: finds cluster by name" {
    create_stub ocm 0 '{"total": 1, "items": [{"id": "abc123", "name": "my-cluster"}]}'
    cat > "${STUBS_DIR}/jq" <<'STUB'
#!/bin/bash
case "$1" in
    --raw-output) echo "1" ;;
    ".items[0]") echo '{"id": "abc123", "name": "my-cluster"}' ;;
    *) echo "" ;;
esac
STUB
    chmod +x "${STUBS_DIR}/jq"

    run get_cluster_json "my-cluster"
    assert_success
}

@test "get_cluster_json: fails when cluster not found" {
    cat > "${STUBS_DIR}/jq" <<'STUB'
#!/bin/bash
case "$1" in
    --raw-output) echo "0" ;;
    *) echo "" ;;
esac
STUB
    chmod +x "${STUBS_DIR}/jq"
    create_stub ocm 0 '{"total": 0, "items": []}'

    run get_cluster_json "nonexistent"
    assert_failure
    assert_output --partial "Could not find a cluster"
}

# ── backplane mode validation ────────────────────────────────────────────────

@test "sre-login: requires backplane plugin in backplane mode" {
    export CLUSTER_AUTH_METHOD="backplane"
    create_stub ocm 1 ""
    run bash "${SRE_LOGIN}" test-cluster
    assert_failure
    assert_output --partial "OCM backplane plugin must be installed"
}

@test "sre-login: requires cluster argument" {
    export CLUSTER_AUTH_METHOD="backplane"
    create_stub ocm 0 "backplane version"
    run bash "${SRE_LOGIN}"
    assert_failure
    assert_output --partial "Usage: sre-login"
}
