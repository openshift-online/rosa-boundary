#!/usr/bin/env bats
# Tests for 00-history.bashrc — shell history configuration

load ../helpers/setup

BASHRC_FILE="${REPO_ROOT}/skel/sre/.bashrc.d/00-history.bashrc"

@test "00-history: sets HISTSIZE to 10000" {
    source "${BASHRC_FILE}"
    assert_equal "${HISTSIZE}" "10000"
}

@test "00-history: sets HISTFILESIZE to 20000" {
    source "${BASHRC_FILE}"
    assert_equal "${HISTFILESIZE}" "20000"
}

@test "00-history: sets HISTCONTROL to ignoredups:ignorespace" {
    source "${BASHRC_FILE}"
    assert_equal "${HISTCONTROL}" "ignoredups:ignorespace"
}
