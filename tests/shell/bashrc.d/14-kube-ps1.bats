#!/usr/bin/env bats
# Tests for 14-kube-ps1.bashrc — PS1 prompt configuration

load ../helpers/setup

BASHRC_FILE="${REPO_ROOT}/skel/sre/.bashrc.d/14-kube-ps1.bashrc"

@test "14-kube-ps1: sets KUBE_PS1_BINARY to oc" {
    source "${BASHRC_FILE}"
    assert_equal "${KUBE_PS1_BINARY}" "oc"
}

@test "14-kube-ps1: sets KUBE_PS1_CLUSTER_FUNCTION to cluster_function" {
    source "${BASHRC_FILE}"
    assert_equal "${KUBE_PS1_CLUSTER_FUNCTION}" "cluster_function"
}

@test "14-kube-ps1: disables kube-ps1 symbol" {
    source "${BASHRC_FILE}"
    assert_equal "${KUBE_PS1_SYMBOL_ENABLE}" "false"
}

@test "14-kube-ps1: PS1 contains OCM_ENVIRONMENT" {
    export OCM_ENVIRONMENT="production"
    source "${BASHRC_FILE}"
    # PS1 should contain the environment name
    [[ "${PS1}" == *"production"* ]]
}

@test "14-kube-ps1: PS1 shows 'unknown' when OCM_ENVIRONMENT is unset" {
    unset OCM_ENVIRONMENT
    source "${BASHRC_FILE}"
    [[ "${PS1}" == *"unknown"* ]]
}
