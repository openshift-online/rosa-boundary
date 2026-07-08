#!/usr/bin/env bats
# Tests for entrypoint.sh functions.
# Sources entrypoint.sh via the testability guard (main() is not called).

HELPERS_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")/helpers" && pwd)"
REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"

load helpers/setup
load helpers/stubs

ENTRYPOINT="${REPO_ROOT}/entrypoint.sh"

setup() {
    TEST_TMPDIR="$(mktemp --directory)"
    export TEST_TMPDIR
    STUBS_DIR="${TEST_TMPDIR}/stubs"
    mkdir --parents "${STUBS_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"
    export HOME="${TEST_TMPDIR}/home"
    mkdir --parents "${HOME}/.session" "${HOME}/.kube" "${HOME}/.bashrc.d"

    # Override entrypoint constants to use test directories
    export SRE_HOME="${HOME}"
    export SKEL_DIR="${TEST_TMPDIR}/skel-sre"
    export OC_BASE_DIR="${TEST_TMPDIR}/openshift"
    mkdir --parents "${SKEL_DIR}"

    # Stub sudo to just run the command (no root in tests)
    cat > "${STUBS_DIR}/sudo" <<'STUB'
#!/bin/bash
"$@"
STUB
    chmod +x "${STUBS_DIR}/sudo"

    # Source entrypoint without executing main
    source "${ENTRYPOINT}"
}

teardown() {
    rm --recursive --force "${TEST_TMPDIR}"
}

# ── switch_oc_version ────────────────────────────────────────────────────────

@test "switch_oc_version: does nothing when OC_VERSION is unset" {
    unset OC_VERSION
    create_capturing_stub alternatives
    switch_oc_version
    assert [ ! -f "${STUBS_DIR}/alternatives.args" ]
}

@test "switch_oc_version: calls alternatives --set when version binary exists" {
    export OC_VERSION="4.18"
    mkdir --parents "${OC_BASE_DIR}/4.18"
    touch "${OC_BASE_DIR}/4.18/oc"
    chmod +x "${OC_BASE_DIR}/4.18/oc"

    create_capturing_stub alternatives 0
    switch_oc_version

    run stub_args alternatives
    assert_output "--set oc ${OC_BASE_DIR}/4.18/oc"
}

@test "switch_oc_version: warns when version binary does not exist" {
    export OC_VERSION="4.99"
    run switch_oc_version
    assert_output --partial "Warning: OC version 4.99 not found"
}

# ── configure_kube_proxy ─────────────────────────────────────────────────────

@test "configure_kube_proxy: does nothing when KUBE_PROXY_PORT is unset" {
    unset KUBE_PROXY_PORT
    configure_kube_proxy
    assert [ ! -f "${HOME}/.kube/config" ]
}

@test "configure_kube_proxy: generates kubeconfig when KUBE_PROXY_PORT is set" {
    export KUBE_PROXY_PORT="8001"
    configure_kube_proxy
    assert_file_exists "${HOME}/.kube/config"
    run cat "${HOME}/.kube/config"
    assert_output --partial "server: http://localhost:8001"
    assert_output --partial "name: investigation"
    assert_output --partial "current-context: investigation"
}

# ── initialize_home ──────────────────────────────────────────────────────────

@test "initialize_home: copies skel when SKEL_DIR exists" {
    mkdir --parents "${SKEL_DIR}/.bashrc.d"
    echo "test-content" > "${SKEL_DIR}/test-file"

    initialize_home

    assert_file_exists "${HOME}/test-file"
    run cat "${HOME}/test-file"
    assert_output "test-content"
}

@test "initialize_home: does nothing when SKEL_DIR does not exist" {
    SKEL_DIR="/nonexistent-skel-dir"
    initialize_home
}

# ── configure_bedrock ────────────────────────────────────────────────────────

@test "configure_bedrock: sets AWS_REGION to us-east-1 when not set" {
    unset AWS_REGION
    unset ECS_CONTAINER_METADATA_URI_V4
    export CLAUDE_CODE_USE_BEDROCK=1
    configure_bedrock
    assert_equal "${AWS_REGION}" "us-east-1"
}

@test "configure_bedrock: preserves existing AWS_REGION" {
    export AWS_REGION="eu-west-1"
    unset ECS_CONTAINER_METADATA_URI_V4
    export CLAUDE_CODE_USE_BEDROCK=1
    configure_bedrock
    assert_equal "${AWS_REGION}" "eu-west-1"
}

@test "configure_bedrock: does nothing when CLAUDE_CODE_USE_BEDROCK is 0" {
    export CLAUDE_CODE_USE_BEDROCK=0
    unset AWS_REGION
    configure_bedrock
    assert [ -z "${AWS_REGION:-}" ]
}

# ── sync_to_s3 ──────────────────────────────────────────────────────────────

@test "sync_to_s3: auto-generates S3 path from structured vars" {
    export S3_AUDIT_BUCKET="my-bucket"
    export CLUSTER_ID="cluster-01"
    export INVESTIGATION_ID="inv-001"
    unset S3_AUDIT_ESCROW
    unset ECS_CONTAINER_METADATA_URI_V4

    create_capturing_stub aws 0
    create_capturing_stub timeout 0

    sync_to_s3

    # S3_AUDIT_ESCROW should have been auto-generated
    [[ "${S3_AUDIT_ESCROW}" == s3://my-bucket/cluster-01/inv-001/* ]]
}

@test "sync_to_s3: uses --no-follow-symlinks" {
    export S3_AUDIT_ESCROW="s3://test-bucket/path/"
    create_capturing_stub timeout 0

    sync_to_s3

    run stub_args timeout
    assert_output --partial "--no-follow-symlinks"
}

@test "sync_to_s3: warns when audit not configured" {
    unset S3_AUDIT_ESCROW S3_AUDIT_BUCKET CLUSTER_ID INVESTIGATION_ID
    run sync_to_s3
    assert_output --partial "Warning: S3 audit not configured"
}

# ── warn_audit_config ────────────────────────────────────────────────────────

@test "warn_audit_config: warns when no audit config is set" {
    unset S3_AUDIT_ESCROW S3_AUDIT_BUCKET CLUSTER_ID INVESTIGATION_ID
    run warn_audit_config
    assert_output --partial "Warning: S3 audit not configured"
}

@test "warn_audit_config: silent when S3_AUDIT_ESCROW is set" {
    export S3_AUDIT_ESCROW="s3://test-bucket/path/"
    run warn_audit_config
    assert_output ""
}

@test "warn_audit_config: silent when all structured vars are set" {
    export S3_AUDIT_BUCKET="test-bucket"
    export CLUSTER_ID="test-cluster"
    export INVESTIGATION_ID="inv-001"
    unset S3_AUDIT_ESCROW
    run warn_audit_config
    assert_output ""
}

# ── display_timeout ──────────────────────────────────────────────────────────

@test "display_timeout: shows timeout when set" {
    export TASK_TIMEOUT="3600"
    run display_timeout
    assert_output --partial "3600 seconds"
}

@test "display_timeout: silent when timeout is 0" {
    export TASK_TIMEOUT="0"
    run display_timeout
    assert_output ""
}

@test "display_timeout: silent when timeout is unset" {
    unset TASK_TIMEOUT
    run display_timeout
    assert_output ""
}

# ── is_interactive_command ───────────────────────────────────────────────────

@test "is_interactive_command: returns 0 for 'sleep infinity'" {
    run is_interactive_command sleep infinity
    assert_success
}

@test "is_interactive_command: returns 0 for empty args" {
    run is_interactive_command
    assert_success
}

@test "is_interactive_command: returns 1 for 'oc get nodes'" {
    run is_interactive_command oc get nodes
    assert_failure
}

@test "is_interactive_command: returns 1 for 'bash'" {
    run is_interactive_command bash
    assert_failure
}

# ── do_cluster_login ─────────────────────────────────────────────────────────

@test "do_cluster_login: does nothing when CLUSTER_ID is unset" {
    unset CLUSTER_ID
    create_capturing_stub sre-login
    do_cluster_login
    assert [ ! -f "${STUBS_DIR}/sre-login.args" ]
}

@test "do_cluster_login: calls sre-login in backplane mode" {
    export CLUSTER_ID="test-cluster"
    export CLUSTER_AUTH_METHOD="backplane"
    create_capturing_stub sre-login 0
    run do_cluster_login
    assert_output --partial "Logging into cluster test-cluster"
}

@test "do_cluster_login: skips login in proxy mode" {
    export CLUSTER_ID="test-cluster"
    export CLUSTER_AUTH_METHOD="proxy"
    run do_cluster_login
    assert_output --partial "Proxy sidecar mode"
}

@test "do_cluster_login: defaults to backplane when CLUSTER_AUTH_METHOD is unset" {
    export CLUSTER_ID="test-cluster"
    unset CLUSTER_AUTH_METHOD
    create_capturing_stub sre-login 0
    run do_cluster_login
    assert_output --partial "Logging into cluster test-cluster"
}
