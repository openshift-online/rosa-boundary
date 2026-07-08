#!/usr/bin/env bats
# Tests for 50-tmux.bashrc — tmux auto-start (ENV-gated)
# Note: we cannot test the actual exec tmux path because it replaces the
# shell process. We test the guard conditions that prevent it from firing.

load ../helpers/setup

BASHRC_FILE="${REPO_ROOT}/skel/sre/.bashrc.d/50-tmux.bashrc"

@test "50-tmux: does not start tmux when TMUX_AUTOSTART is unset" {
    unset TMUX_AUTOSTART
    unset TMUX
    # Source in a subshell so exec doesn't kill our test
    run bash -c "source '${BASHRC_FILE}'; echo 'survived'"
    assert_output "survived"
}

@test "50-tmux: does not start tmux when TMUX_AUTOSTART is 0" {
    export TMUX_AUTOSTART="0"
    unset TMUX
    run bash -c "source '${BASHRC_FILE}'; echo 'survived'"
    assert_output "survived"
}

@test "50-tmux: does not start tmux when already inside tmux" {
    export TMUX_AUTOSTART="1"
    export TMUX="/tmp/tmux-1000/default,12345,0"
    run bash -c "source '${BASHRC_FILE}'; echo 'survived'"
    assert_output "survived"
}
