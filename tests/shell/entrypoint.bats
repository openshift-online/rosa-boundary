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

@test "credential mount verification requires non-NFS mount overlays" {
    run bash -c '
        mountpoint() { return 0; }
        findmnt() { printf "%s\\n" "ext4"; }
        source "$1"
        verify_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
}

@test "credential mount verification fails for a missing overlay" {
    run bash -c '
        mountpoint() { return 1; }
        source "$1"
        verify_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -ne 0 ]
    [[ "${output}" == *"not a task-scoped mount: /home/sre/.config/ocm"* ]]
}

@test "credential mount verification rejects an EFS-backed overlay" {
    run bash -c '
        mountpoint() { return 0; }
        findmnt() { printf "%s\\n" "nfs4"; }
        source "$1"
        verify_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -ne 0 ]
    [[ "${output}" == *"backed by NFS/EFS: /home/sre/.config/ocm"* ]]
}

@test "main verifies credential mounts before initialization" {
    run env \
        OC_VERSION="" \
        KUBE_PROXY_PORT="" \
        CLAUDE_CODE_USE_BEDROCK="0" \
        S3_AUDIT_ESCROW="s3://audit-bucket/investigation/" \
        TASK_TIMEOUT="0" \
        bash -c '
            source "$1"
            verify_credential_mounts() { printf "verify\\n"; }
            initialize_credential_mounts() { printf "initialize\\n"; }
            runuser() { :; }
            sync_to_s3() { :; }
            main true
        ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = $'verify\ninitialize' ]
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

@test "configured audit sync excludes both credential subtrees" {
    run env \
        S3_AUDIT_ESCROW="s3://audit-bucket/investigation/" \
        SYNC_TIMEOUT="123" \
        bash -c '
            timeout() { printf "arg:%s\n" "$@"; }
            source "$1"
            sync_to_s3
        ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"arg:123"* ]]
    [[ "${output}" == *"arg:aws"* ]]
    [[ "${output}" == *"arg:s3"* ]]
    [[ "${output}" == *"arg:sync"* ]]
    [[ "${output}" == *"arg:/home/sre"* ]]
    [[ "${output}" == *"arg:s3://audit-bucket/investigation/"* ]]
    [ "$(grep --count --fixed-strings 'arg:--exclude' <<<"${output}")" -eq 2 ]
    [[ "${output}" == *$'arg:.config/ocm/*'* ]]
    [[ "${output}" == *$'arg:.kube/*'* ]]
    [[ "${output}" == *"arg:--no-follow-symlinks"* ]]
    [[ "${output}" == *"arg:--quiet"* ]]
    [[ "${output}" != *"/home/sre/.config/ocm"* ]]
    [[ "${output}" != *"/home/sre/.kube"* ]]
}

@test "auto-generated audit sync uses the same credential exclusions" {
    run env \
        S3_AUDIT_ESCROW="" \
        S3_AUDIT_BUCKET="audit-bucket" \
        CLUSTER_ID="cluster-1" \
        INVESTIGATION_ID="investigation-1" \
        ECS_CONTAINER_METADATA_URI_V4="" \
        bash -c '
            date() { printf "20260911\n"; }
            timeout() { printf "arg:%s\n" "$@"; }
            source "$1"
            sync_to_s3
        ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"arg:s3://audit-bucket/cluster-1/investigation-1/20260911//"* ]]
    [ "$(grep --count --fixed-strings 'arg:--exclude' <<<"${output}")" -eq 2 ]
    [[ "${output}" == *$'arg:.config/ocm/*'* ]]
    [[ "${output}" == *$'arg:.kube/*'* ]]
    [[ "${output}" == *"arg:--no-follow-symlinks"* ]]
}

@test "credential exclusion patterns cover nested files without excluding audit controls" {
    run env S3_AUDIT_ESCROW="s3://audit-bucket/investigation/" bash -c '
        timeout() { printf "%s\n" "$@"; }
        source "$1"

        mapfile -t sync_output < <(sync_to_s3)
        patterns=()
        for ((index = 0; index < ${#sync_output[@]}; index++)); do
            if [[ "${sync_output[index]}" == "--exclude" ]]; then
                patterns+=("${sync_output[index + 1]}")
            fi
        done
        [[ "${#patterns[@]}" -eq 2 ]]

        excluded() {
            local relative_path="$1"
            local pattern

            for pattern in "${patterns[@]}"; do
                if [[ "${relative_path}" == ${pattern} ]]; then
                    return 0
                fi
            done
            return 1
        }

        excluded ".config/ocm/ocm.json"
        excluded ".config/ocm/.ocm.json.upload-token-canary.tmp"
        excluded ".config/ocm/cache/nested/state.json"
        excluded ".kube/config"
        excluded ".kube/cache/discovery/response.json"
        ! excluded "control.txt"
        ! excluded ".config/rosa-boundary/config.yaml"
        ! excluded ".config/ocm-control.txt"
        ! excluded ".kube-control/config"
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
}

@test "signal cleanup and normal exit use the shared protected sync" {
    run bash -c '
        source "$1"
        sync_to_s3() { printf "protected-sync\n"; }
        CHILD_PID=""
        cleanup
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "protected-sync" ]

    run env \
        OC_VERSION="" \
        KUBE_PROXY_PORT="" \
        CLAUDE_CODE_USE_BEDROCK="0" \
        S3_AUDIT_ESCROW="s3://audit-bucket/investigation/" \
        TASK_TIMEOUT="0" \
        bash -c '
            source "$1"
            verify_credential_mounts() { :; }
            initialize_credential_mounts() { :; }
            runuser() { :; }
            sync_to_s3() { printf "protected-sync\n"; }
            main true
        ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "protected-sync" ]
}
