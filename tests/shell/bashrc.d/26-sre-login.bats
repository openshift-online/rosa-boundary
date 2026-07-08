#!/usr/bin/env bats
# Tests for 26-sre-login.bashrc — auto cluster login on shell entry

load ../helpers/setup
load ../helpers/stubs

BASHRC_FILE="${REPO_ROOT}/skel/sre/.bashrc.d/26-sre-login.bashrc"

@test "26-sre-login: skips when CLUSTER_ID is unset" {
    unset CLUSTER_ID
    create_stub oc 1 ""
    source "${BASHRC_FILE}"
    # Should not create the sentinel file
    assert [ ! -f "${HOME}/.session/sre-login-attempted" ]
}

@test "26-sre-login: skips when SKIP_CLUSTER_LOGIN is set" {
    export CLUSTER_ID="test-cluster"
    export SKIP_CLUSTER_LOGIN="1"
    create_stub oc 1 ""
    source "${BASHRC_FILE}"
    assert [ ! -f "${HOME}/.session/sre-login-attempted" ]
}

@test "26-sre-login: skips when oc already has a context" {
    export CLUSTER_ID="test-cluster"
    unset SKIP_CLUSTER_LOGIN
    # oc config current-context succeeds = already logged in
    create_stub oc 0 "existing-context"
    source "${BASHRC_FILE}"
    assert [ ! -f "${HOME}/.session/sre-login-attempted" ]
}

@test "26-sre-login: skips with message when sentinel exists" {
    export CLUSTER_ID="test-cluster"
    unset SKIP_CLUSTER_LOGIN
    create_stub oc 1 ""
    touch "${HOME}/.session/sre-login-attempted"
    run source "${BASHRC_FILE}"
    assert_output --partial "Skipping automatic cluster login"
}

@test "26-sre-login: calls sre-login in backplane mode" {
    export CLUSTER_ID="test-cluster"
    export CLUSTER_AUTH_METHOD="backplane"
    unset SKIP_CLUSTER_LOGIN
    create_stub oc 1 ""
    create_capturing_stub sre-login 0 ""
    source "${BASHRC_FILE}"
    assert_file_exists "${HOME}/.session/sre-login-attempted"
    run stub_args sre-login
    assert_output "test-cluster"
}

@test "26-sre-login: verifies proxy in proxy mode" {
    export CLUSTER_ID="test-cluster"
    export CLUSTER_AUTH_METHOD="proxy"
    unset SKIP_CLUSTER_LOGIN
    # First oc call (config current-context) fails, second (version) and third (get --raw) succeed
    cat > "${STUBS_DIR}/oc" <<'STUB'
#!/bin/bash
case "$1" in
    config) exit 1 ;;
    version) exit 0 ;;
    get) exit 0 ;;
esac
STUB
    chmod +x "${STUBS_DIR}/oc"
    run source "${BASHRC_FILE}"
    assert_output --partial "Cluster access verified via kube-proxy sidecar"
}

@test "26-sre-login: warns when proxy connectivity fails" {
    export CLUSTER_ID="test-cluster"
    export CLUSTER_AUTH_METHOD="proxy"
    unset SKIP_CLUSTER_LOGIN
    cat > "${STUBS_DIR}/oc" <<'STUB'
#!/bin/bash
case "$1" in
    config) exit 1 ;;
    version) exit 0 ;;
    get) exit 1 ;;
esac
STUB
    chmod +x "${STUBS_DIR}/oc"
    run source "${BASHRC_FILE}"
    assert_output --partial "kube-proxy sidecar not responding"
    assert_file_exists "${HOME}/.session/sre-login-attempted"
}
