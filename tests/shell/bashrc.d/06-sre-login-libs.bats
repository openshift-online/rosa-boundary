#!/usr/bin/env bats
# Tests for 06-sre-login-libs.bashrc — cluster_function() for kube-ps1

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../../.." && pwd)"

load ../helpers/setup
load ../helpers/stubs

BASHRC_FILE="${REPO_ROOT}/skel/sre/.bashrc.d/06-sre-login-libs.bashrc"

setup() {
    TEST_TMPDIR="$(mktemp --directory)"
    export TEST_TMPDIR
    STUBS_DIR="${TEST_TMPDIR}/stubs"
    mkdir --parents "${STUBS_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"
    export HOME="${TEST_TMPDIR}/home"
    mkdir --parents "${HOME}"

    source "${BASHRC_FILE}"
}

teardown() {
    rm --recursive --force "${TEST_TMPDIR}"
}

@test "cluster_function: returns CLUSTER_ID in proxy mode" {
    export CLUSTER_AUTH_METHOD="proxy"
    export CLUSTER_ID="my-rosa-cluster"
    run cluster_function
    assert_output "my-rosa-cluster"
}

@test "cluster_function: returns 'unknown' in proxy mode when CLUSTER_ID is unset" {
    export CLUSTER_AUTH_METHOD="proxy"
    unset CLUSTER_ID
    run cluster_function
    assert_output "unknown"
}

@test "cluster_function: uses ocm backplane status in backplane mode" {
    export CLUSTER_AUTH_METHOD="backplane"
    # Stub ocm to return backplane status output
    create_stub ocm 0 "Cluster Name:     my-cluster
Cluster Basedomain: apps.example.com"
    run cluster_function
    assert_output "my-cluster.apps.example"
}

@test "cluster_function: defaults to backplane mode" {
    unset CLUSTER_AUTH_METHOD
    create_stub ocm 0 "Cluster Name:     prod-cluster
Cluster Basedomain: apps.rosa.example.com"
    run cluster_function
    assert_output "prod-cluster.apps.rosa"
}

@test "cluster_function: returns empty on backplane status failure" {
    export CLUSTER_AUTH_METHOD="backplane"
    create_stub ocm 1 ""
    run cluster_function
    assert_output ""
}
