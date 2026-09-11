#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    ENTRYPOINT="${REPO_ROOT}/entrypoint.sh"
}

@test "entrypoint is safely sourceable" {
    run bash -c 'source "$1"; printf "%s\n" sourced' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "sourced" ]
}

@test "credential mounts are initialized with sre ownership and mode 0700" {
    run bash -c '
        mkdir() { printf "mkdir:%s\n" "$*"; }
        chown() { printf "chown:%s\n" "$*"; }
        chmod() { printf "chmod:%s\n" "$*"; }
        source "$1"
        initialize_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${lines[0]}" = "mkdir:--parents /home/sre/.config/ocm" ]
    [ "${lines[1]}" = "chown:sre:sre /home/sre/.config/ocm" ]
    [ "${lines[2]}" = "chmod:0700 /home/sre/.config/ocm" ]
    [ "${lines[3]}" = "mkdir:--parents /home/sre/.kube" ]
    [ "${lines[4]}" = "chown:sre:sre /home/sre/.kube" ]
    [ "${lines[5]}" = "chmod:0700 /home/sre/.kube" ]
    [ "${#lines[@]}" -eq 6 ]
}
