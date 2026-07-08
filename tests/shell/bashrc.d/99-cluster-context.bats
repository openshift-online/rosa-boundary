#!/usr/bin/env bats
# Tests for 99-cluster-context.bashrc — osdctl cluster context on login

load ../helpers/setup
load ../helpers/stubs

BASHRC_FILE="${REPO_ROOT}/skel/sre/.bashrc.d/99-cluster-context.bashrc"

@test "99-cluster-context: runs osdctl when CLUSTER_ID is set" {
    export CLUSTER_ID="test-cluster"
    export SHOW_CLUSTER_CONTEXT="1"
    create_capturing_stub osdctl 0 "Cluster context info"
    source "${BASHRC_FILE}"
    assert_file_exists "${HOME}/.session/osdctl-context-attempted"
    run stub_args osdctl
    assert_output "cluster context --cluster-id test-cluster"
}

@test "99-cluster-context: skips when CLUSTER_ID is unset" {
    unset CLUSTER_ID
    create_capturing_stub osdctl 0 ""
    source "${BASHRC_FILE}"
    assert [ ! -f "${STUBS_DIR}/osdctl.args" ]
}

@test "99-cluster-context: skips when SHOW_CLUSTER_CONTEXT is 0" {
    export CLUSTER_ID="test-cluster"
    export SHOW_CLUSTER_CONTEXT="0"
    create_capturing_stub osdctl 0 ""
    source "${BASHRC_FILE}"
    assert [ ! -f "${STUBS_DIR}/osdctl.args" ]
}

@test "99-cluster-context: defaults to on when SHOW_CLUSTER_CONTEXT is unset" {
    export CLUSTER_ID="test-cluster"
    unset SHOW_CLUSTER_CONTEXT
    create_capturing_stub osdctl 0 "Context info"
    source "${BASHRC_FILE}"
    assert_file_exists "${HOME}/.session/osdctl-context-attempted"
}

@test "99-cluster-context: runs only once (sentinel file)" {
    export CLUSTER_ID="test-cluster"
    export SHOW_CLUSTER_CONTEXT="1"
    touch "${HOME}/.session/osdctl-context-attempted"
    create_capturing_stub osdctl 0 ""
    source "${BASHRC_FILE}"
    # osdctl should not have been called
    assert [ ! -f "${STUBS_DIR}/osdctl.args" ]
}

@test "99-cluster-context: does not fail when osdctl fails" {
    export CLUSTER_ID="test-cluster"
    export SHOW_CLUSTER_CONTEXT="1"
    create_stub osdctl 1 "Error"
    run source "${BASHRC_FILE}"
    # Should not fail (|| true in the script)
    assert_success
}
