#!/bin/bash

# Outer watchdog covers metadata lookup, upload and reporting together.
# 105s + 2s forced kill + at most 3s waiting for startup metadata leaves
# 10s inside the regional 120s stopTimeout. The writer grace (3s), metadata
# (3s), transfer (85+2s) and report (6+2s) all run under this watchdog.
SHUTDOWN_SECONDS=105
KILL_GRACE_SECONDS=2
MAX_SYNC_SECONDS=85
METADATA_SECONDS=3

sync_seconds() {
    local n=${SYNC_TIMEOUT:-}
    if [[ $n =~ ^[1-9][0-9]?$ ]] && ((n <= MAX_SYNC_SECONDS)); then
        printf '%s\n' "$n"
    else
        printf '%s\n' "$MAX_SYNC_SECONDS"
    fi
}

sync_to_s3() {
    set -o pipefail
    local attempt task='' investigation=${INVESTIGATION_ID:-} base=${S3_AUDIT_ESCROW:-} dest rc=0
    attempt=$(python3 -I -c 'import uuid; print(uuid.uuid4())') || return 1
    if [[ -n ${ECS_CONTAINER_METADATA_URI_V4:-} ]]; then
        task=$(curl --fail --silent --max-time "$METADATA_SECONDS" "${ECS_CONTAINER_METADATA_URI_V4}/task" |
            jq -er '.TaskARN | split("/") | last') || task=''
    fi
    if ! [[ $task =~ ^[a-f0-9]{32}$ && $investigation =~ ^[a-zA-Z0-9_-]+$ ]]; then
        printf 'audit_sync result=unverified reason=missing_correlation investigation=%q task=%q attempt=%s\n' "$investigation" "$task" "$attempt" >&2
        return 1
    fi
    if [[ -z $base && -n ${S3_AUDIT_BUCKET:-} && -n ${CLUSTER_ID:-} ]]; then
        base="s3://${S3_AUDIT_BUCKET}/${CLUSTER_ID}/${investigation}/$(date -u +%Y%m%d)/${task}"
    fi
    if [[ $base != s3://?* ]]; then
        printf 'audit_sync result=unverified reason=missing_destination investigation=%s task=%s attempt=%s\n' "$investigation" "$task" "$attempt" >&2
        return 1
    fi
    dest="${base%/}/attempts/${attempt}/workspace/"
    printf 'audit_sync event=start investigation=%s task=%s attempt=%s destination=%q\n' "$investigation" "$task" "$attempt" "$dest"
    timeout --foreground --kill-after=2 "$(sync_seconds)" aws s3 sync /home/sre "$dest" \
        --exclude ".config/ocm/*" --exclude ".kube/*" --no-follow-symlinks --quiet || rc=$?
    # Other tasks and ECS Exec sessions can write throughout the transfer.
    # No task-writable S3 object is authoritative evidence for close.
    printf 'audit_sync result=unverified transfer_rc=%d investigation=%s task=%s attempt=%s destination=%q\n' "$rc" "$investigation" "$task" "$attempt" "$dest"
    local report="${dest%workspace/}report.json"
    if ! jq -cn --arg inv "$investigation" --arg task "$task" --arg attempt "$attempt" \
        --arg uri "$dest" --argjson rc "$rc" \
        '{schema_version:1, investigation_id:$inv, task_id:$task, attempt_id:$attempt, workspace_uri:$uri, transfer_rc:$rc, status:"unverified"}' |
        timeout --foreground --kill-after=2 6 aws s3 cp - "$report" --content-type application/json --quiet; then
        printf 'audit_sync result=unverified reason=report_failed destination=%q\n' "$report" >&2
        return 1
    fi
    return "$rc"
}

cleanup() {
    local workload_rc=${1:-0} transfer_rc=0
    trap ':' TERM INT HUP
    trap - EXIT
    # Signal managed writers before transfer; never wait indefinitely for them.
    if [[ -n ${CHILD_PID:-} ]]; then kill -TERM "$CHILD_PID" 2>/dev/null || :; fi
    local helper=${SKILL_RECONCILER_PID:-}
    stop_skill_reconciler
    timeout --kill-after="$KILL_GRACE_SECONDS" "$SHUTDOWN_SECONDS" bash -c \
        'source "$1"; await_writers "$2" "$3"; sync_to_s3' bash "${BASH_SOURCE[0]}" "${CHILD_PID:-}" "$helper" || transfer_rc=$?
    if ((transfer_rc)); then
        printf 'audit_sync result=unverified shutdown_rc=%d\n' "$transfer_rc" >&2
    fi
    ((workload_rc)) && exit "$workload_rc"
    exit "$transfer_rc"
}

# Give managed writers up to three seconds to flush. This is not a fence
# against surviving descendants, ECS Exec sessions or other tasks on EFS.
await_writers() {
    local i
    for ((i = 0; i < 30; i++)); do
        if ! kill -0 "$1" 2>/dev/null && ! kill -0 "$2" 2>/dev/null; then return; fi
        sleep 0.1
    done
}

# Launch one unprivileged, non-blocking skill reconciler per task (default on).
start_skill_reconciler() {
    local helper="${1:-/usr/local/libexec/rosa-boundary-skill-sync.sh}"
    if [ "${BOUNDARY_SKILLS_ENABLED:-1}" = "1" ] && [ -r "${helper}" ]; then
        runuser --user sre -- env HOME=/home/sre bash "${helper}" &
        SKILL_RECONCILER_PID=$!
    fi
}

# Stop the runuser supervisor, which forwards SIGTERM to its Bash child.
# PID 1 must not block on a stuck writer; transfer remains unverified.
stop_skill_reconciler() {
    if [ -n "${SKILL_RECONCILER_PID:-}" ]; then
        kill -TERM "${SKILL_RECONCILER_PID}" 2>/dev/null || true
        SKILL_RECONCILER_PID=""
    fi
}

# Fail closed unless credential paths are task-scoped mounts, not EFS paths.
# ECS defines these as empty bind mounts; this catches a missing or EFS-backed
# overlay before credentials can be written to the persistent home directory.
verify_credential_mounts() {
    local credential_dir filesystem_type

    for credential_dir in /home/sre/.config/ocm /home/sre/.kube; do
        if ! mountpoint --quiet "${credential_dir}"; then
            echo "Error: credential path is not a task-scoped mount: ${credential_dir}" >&2
            return 1
        fi

        if ! filesystem_type=$(findmnt --noheadings --raw --output FSTYPE --target "${credential_dir}"); then
            echo "Error: could not determine credential mount type: ${credential_dir}" >&2
            return 1
        fi
        if [[ "${filesystem_type}" == nfs* ]]; then
            echo "Error: credential path is backed by NFS/EFS: ${credential_dir}" >&2
            return 1
        fi
    done
}

# Initialize verified task-scoped credential mounts for the sre workload.
# These explicit paths are required because HOME and ~ resolve to /root while
# the privileged entrypoint runs; the Fargate mounts are under /home/sre.
initialize_credential_mounts() {
    local credential_dir

    for credential_dir in /home/sre/.config/ocm /home/sre/.kube; do
        mkdir --parents "${credential_dir}"
        chown sre:sre "${credential_dir}"
        chmod 0700 "${credential_dir}"
    done
}

# Seed credential-free agent settings as sre (default on, following Claude's
# Bedrock switch); BOUNDARY_AI_USE_BEDROCK=0 opts out without changing files.
configure_agent_defaults() {
    if [ "${BOUNDARY_AI_USE_BEDROCK:-${CLAUDE_CODE_USE_BEDROCK:-1}}" = "1" ]; then
        runuser --user sre -- env HOME=/home/sre \
            python3 /usr/local/libexec/rosa-boundary-agent-defaults.py || \
            echo "Warning: optional agent defaults helper failed; continuing startup" >&2
    fi
}

# Keep PID 1 in an interruptible wait, even if a startup operation blocks on EFS.
startup_step() {
    "$@" &
    CHILD_PID=$!
    wait "$CHILD_PID"
    CHILD_PID=""
}

prepare_home() {
    # Configure kubectl/oc to use the kube-proxy sidecar
    if [ -n "${KUBE_PROXY_PORT}" ]; then
        cat >/home/sre/.kube/config <<KUBECONFIG
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://localhost:${KUBE_PROXY_PORT}
  name: investigation
contexts:
- context:
    cluster: investigation
  name: investigation
current-context: investigation
KUBECONFIG
        chown sre:sre /home/sre/.kube /home/sre/.kube/config
        echo "Configured oc/kubectl to use proxy at localhost:${KUBE_PROXY_PORT}"
    fi

    # Copy skeleton config to /home/sre, running as sre so files are created
    # with correct ownership. cp -rn (no clobber) skips existing files, making
    # this fast and idempotent on subsequent runs without needing chown -R.
    if [ -d /etc/skel-sre ]; then
        runuser -u sre -- cp -rn /etc/skel-sre/. /home/sre/
    fi
}

# Perform privileged container setup, then run the requested workload as sre.
main() {
    set -e

    # Override HOME so root operations (aws s3 sync) don't create root-owned
    # files under /home/sre (EFS). ECS Exec sessions inherit the image-level
    # HOME=/home/sre in their own process.
    export HOME=/root

    # Never upload before credential mount verification/initialization.
    trap 'echo "audit_sync result=unverified reason=interrupted_mount_setup" >&2; exit 1' TERM INT HUP

    # Empty Fargate volumes are normally root-owned. Prepare both nested mounts
    # before writing proxy configuration or starting any process as sre.
    startup_step verify_credential_mounts
    startup_step initialize_credential_mounts
    trap cleanup TERM INT HUP
    trap 'cleanup $?' EXIT

    startup_step prepare_home
    start_skill_reconciler

    # Set Bedrock defaults if CLAUDE_CODE_USE_BEDROCK is enabled
    if [ "${CLAUDE_CODE_USE_BEDROCK:-1}" = "1" ]; then
        export CLAUDE_CODE_USE_BEDROCK=1

        # Auto-detect region from ECS task metadata if AWS_REGION not set
        if [ -z "${AWS_REGION}" ] && [ -n "${ECS_CONTAINER_METADATA_URI_V4}" ]; then
            # Extract region from task ARN in metadata
            TASK_METADATA=$(curl --max-time "$METADATA_SECONDS" -s "${ECS_CONTAINER_METADATA_URI_V4}/task" 2>/dev/null || true)
            if [ -n "${TASK_METADATA}" ]; then
                # Task ARN format: arn:aws:ecs:REGION:ACCOUNT:task/CLUSTER/TASKID
                DETECTED_REGION=$(echo "${TASK_METADATA}" | grep -o '"TaskARN":"arn:aws:ecs:[^:]*' | cut -d: -f4)
                if [ -n "${DETECTED_REGION}" ]; then
                    export AWS_REGION="${DETECTED_REGION}"
                    echo "Auto-detected AWS_REGION=${AWS_REGION} from ECS task metadata"
                fi
            fi
        fi

        # Fallback to us-east-1 if still not set
        export AWS_REGION="${AWS_REGION:-us-east-1}"
    fi

    startup_step configure_agent_defaults

    # Warn if S3 audit is not configured
    if [ -z "${S3_AUDIT_ESCROW}" ] && { [ -z "${S3_AUDIT_BUCKET}" ] || [ -z "${CLUSTER_ID}" ] || [ -z "${INVESTIGATION_ID}" ]; }; then
        echo "Warning: S3 audit not configured. /home/sre will not be backed up on exit." >&2
        echo "  Set either S3_AUDIT_ESCROW or (S3_AUDIT_BUCKET + CLUSTER_ID + INVESTIGATION_ID)" >&2
    fi

    # Display task timeout if configured (informational only - enforced by periodic reaper Lambda)
    if [ -n "${TASK_TIMEOUT}" ] && [ "${TASK_TIMEOUT}" != "0" ]; then
        echo "Task will be automatically stopped after ${TASK_TIMEOUT} seconds (enforced by periodic reaper)"
    fi

    # Run the command as the sre user in the background and wait for it.
    # This allows the root shell to remain and handle signals (cleanup/S3 sync).
    # The entrypoint runs as root for privileged setup (chown,
    # runuser); the actual workload drops to sre here.
    runuser -u sre -- "${@:-sleep infinity}" &
    CHILD_PID=$!
    local rc=0
    wait "$CHILD_PID" || rc=$?
    CHILD_PID=""
    cleanup "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
