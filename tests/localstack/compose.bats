#!/usr/bin/env bats
# Focused shell coverage; the full mocked discovery matrix is in test_compose.py.

setup() {
    WRAPPER="$BATS_TEST_DIRNAME/compose.sh"
}

@test "compose wrapper can be sourced without running Podman" {
    run bash -c 'source "$1"; declare -F main' _ "$WRAPPER"
    [ "$status" -eq 0 ]
    [ "$output" = main ]
}

@test "compose wrapper rejects a relative explicit socket before running Compose" {
    run env LOCALSTACK_PODMAN_SOCKET=relative.sock bash "$WRAPPER" up -d
    [ "$status" -eq 1 ]
    [[ "$output" == *"absolute socket path"* ]]
}

@test "compose wrapper passes the regression matrix without a container engine" {
    run python3 -m unittest discover -s "$BATS_TEST_DIRNAME" -p test_compose.py -v
    [ "$status" -eq 0 ]
}
