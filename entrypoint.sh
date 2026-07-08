#!/bin/bash
# entrypoint.sh — rosa-boundary container initialization and lifecycle.
#
# Runs as root at container start to perform privileged setup (alternatives,
# kubeconfig generation). ECS Exec sessions connect as the sre user via a
# separate process that inherits the Containerfile ENV HOME=/home/sre.
#
# Supports two modes:
#   Interactive (default): CMD is "sleep infinity", container waits for ECS Exec
#   Command:               CMD is a command, optionally preceded by cluster login

set -e

# ─── CONSTANTS ───────────────────────────────────────────────────────────────

# Override HOME for root entrypoint so root operations (alternatives, aws s3
# sync) don't create root-owned files under /home/sre (EFS). ECS Exec sessions
# inherit the container-level ENV HOME=/home/sre from the Containerfile, not
# this export, since they start as a separate process.
readonly ENTRYPOINT_HOME=/root
readonly SRE_HOME=/home/sre
readonly SKEL_DIR=/etc/skel-sre

# ─── S3 AUDIT SYNC ──────────────────────────────────────────────────────────

# Sync /home/sre to S3 for audit compliance. Called on both normal exit and
# signal-triggered cleanup. Auto-generates the S3 path from structured env
# vars if S3_AUDIT_ESCROW is not explicitly set.
sync_to_s3() {
    if [ -z "${S3_AUDIT_ESCROW}" ] && [ -n "${S3_AUDIT_BUCKET}" ] && [ -n "${CLUSTER_ID}" ] && [ -n "${INVESTIGATION_ID}" ]; then
        if [ -n "${ECS_CONTAINER_METADATA_URI_V4}" ]; then
            TASK_ARN=$(curl --silent "${ECS_CONTAINER_METADATA_URI_V4}/task" 2>/dev/null \
                | grep --only-matching '"TaskARN":"[^"]*"' \
                | cut --delimiter='"' --fields=4)
            TASK_ID="${TASK_ARN##*/}"
        fi

        DATE=$(date +%Y%m%d)
        S3_AUDIT_ESCROW="s3://${S3_AUDIT_BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/${DATE}/${TASK_ID}/"
        echo "Auto-generated S3 audit path: ${S3_AUDIT_ESCROW}"
    fi

    if [ -n "${S3_AUDIT_ESCROW}" ]; then
        echo "Syncing ${SRE_HOME} to ${S3_AUDIT_ESCROW}..."
        # timeout: prevents a hung sync from blocking container shutdown past the ECS stop timeout.
        # --no-follow-symlinks: uploads symlink metadata only; never uploads symlink targets,
        #   which could point outside /home/sre and exfiltrate host-level files.
        timeout "${SYNC_TIMEOUT:-300}" \
            aws s3 sync "${SRE_HOME}" "${S3_AUDIT_ESCROW}" \
            --no-follow-symlinks \
            --quiet ||
            echo "Warning: S3 sync failed or timed out" >&2
    else
        echo "Warning: S3 audit not configured, ${SRE_HOME} will not be backed up" >&2
    fi
}

# ─── SIGNAL HANDLING ─────────────────────────────────────────────────────────

# Sync audit data and terminate the background process on signal.
cleanup() {
    sync_to_s3
    if [ -n "${CHILD_PID}" ]; then
        kill -TERM "${CHILD_PID}" 2>/dev/null || true
    fi
    exit 0
}

# ─── OC VERSION SWITCHING ───────────────────────────────────────────────────

# Switch the active OC CLI version via the alternatives system.
# OC_VERSION is set per-investigation by the Lambda (e.g., "4.18").
switch_oc_version() {
    if [ -z "${OC_VERSION}" ]; then
        return
    fi

    if [ -x "/opt/openshift/${OC_VERSION}/oc" ]; then
        alternatives --set oc "/opt/openshift/${OC_VERSION}/oc"
    else
        echo "Warning: OC version ${OC_VERSION} not found, using default" >&2
    fi
}

# ─── KUBE PROXY KUBECONFIG ──────────────────────────────────────────────────

# Generate a kubeconfig pointing at the kube-proxy sidecar when
# KUBE_PROXY_PORT is set. The sidecar runs `oc proxy` with a cluster
# kubeconfig injected from Secrets Manager.
configure_kube_proxy() {
    if [ -z "${KUBE_PROXY_PORT}" ]; then
        return
    fi

    mkdir --parents "${SRE_HOME}/.kube"
    cat >"${SRE_HOME}/.kube/config" <<KUBECONFIG
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
    chown sre:sre "${SRE_HOME}/.kube" "${SRE_HOME}/.kube/config"
    echo "Configured oc/kubectl to use proxy at localhost:${KUBE_PROXY_PORT}"
}

# ─── SKELETON COPY ──────────────────────────────────────────────────────────

# Copy skeleton config from /etc/skel-sre/ to /home/sre/ on first run.
# Uses --no-clobber so existing files are preserved on subsequent runs.
# Runs as the sre user so files have correct ownership without chown -R.
initialize_home() {
    if [ -d "${SKEL_DIR}" ]; then
        runuser --user sre -- cp --recursive --no-clobber "${SKEL_DIR}/." "${SRE_HOME}/"
    fi
}

# ─── BEDROCK CONFIGURATION ──────────────────────────────────────────────────

# Configure Claude Code to use Amazon Bedrock. Auto-detects the AWS region
# from ECS task metadata if not explicitly set.
configure_bedrock() {
    if [ "${CLAUDE_CODE_USE_BEDROCK:-1}" != "1" ]; then
        return
    fi

    export CLAUDE_CODE_USE_BEDROCK=1

    if [ -z "${AWS_REGION}" ] && [ -n "${ECS_CONTAINER_METADATA_URI_V4}" ]; then
        local task_metadata detected_region
        task_metadata=$(curl --silent "${ECS_CONTAINER_METADATA_URI_V4}/task" 2>/dev/null || true)
        if [ -n "${task_metadata}" ]; then
            # Task ARN format: arn:aws:ecs:REGION:ACCOUNT:task/CLUSTER/TASKID
            detected_region=$(echo "${task_metadata}" \
                | grep --only-matching '"TaskARN":"arn:aws:ecs:[^:]*' \
                | cut --delimiter=: --fields=4)
            if [ -n "${detected_region}" ]; then
                export AWS_REGION="${detected_region}"
                echo "Auto-detected AWS_REGION=${AWS_REGION} from ECS task metadata"
            fi
        fi
    fi

    export AWS_REGION="${AWS_REGION:-us-east-1}"
}

# ─── AUDIT WARNING ──────────────────────────────────────────────────────────

# Warn if S3 audit sync is not configured. Audit sync is mandatory for
# compliance — this warning helps catch misconfigured deployments.
warn_audit_config() {
    if [ -z "${S3_AUDIT_ESCROW}" ] && \
       { [ -z "${S3_AUDIT_BUCKET}" ] || [ -z "${CLUSTER_ID}" ] || [ -z "${INVESTIGATION_ID}" ]; }; then
        echo "Warning: S3 audit not configured. ${SRE_HOME} will not be backed up on exit." >&2
        echo "  Set either S3_AUDIT_ESCROW or (S3_AUDIT_BUCKET + CLUSTER_ID + INVESTIGATION_ID)" >&2
    fi
}

# ─── TIMEOUT DISPLAY ────────────────────────────────────────────────────────

# Display the task timeout for SRE awareness. The timeout is enforced by
# the reaper Lambda, not by the container — this is informational only.
display_timeout() {
    if [ -n "${TASK_TIMEOUT}" ] && [ "${TASK_TIMEOUT}" != "0" ]; then
        echo "Task will be automatically stopped after ${TASK_TIMEOUT} seconds (enforced by periodic reaper)"
    fi
}

# ─── CLUSTER COMMAND MODE ───────────────────────────────────────────────────

# Returns 0 if the CMD is the default interactive "sleep infinity".
is_interactive_command() {
    [[ "${*}" == "sleep infinity" ]] || [[ -z "${*}" ]]
}

# Perform cluster login before running a non-interactive command.
# Respects CLUSTER_AUTH_METHOD to support both backplane and proxy paths.
do_cluster_login() {
    if [ -z "${CLUSTER_ID}" ]; then
        return
    fi

    case "${CLUSTER_AUTH_METHOD:-backplane}" in
        proxy)
            echo "Proxy sidecar mode: cluster access provided by kube-proxy sidecar"
            ;;
        backplane|*)
            if command -v sre-login &>/dev/null; then
                echo "Logging into cluster ${CLUSTER_ID} via backplane..."
                sre-login "${CLUSTER_ID}" || echo "Warning: cluster login failed" >&2
            else
                echo "Warning: sre-login not found, skipping cluster login" >&2
            fi
            ;;
    esac
}

# ─── MAIN ────────────────────────────────────────────────────────────────────

main() {
    export HOME="${ENTRYPOINT_HOME}"

    trap cleanup SIGTERM SIGINT SIGHUP

    # Privileged setup (runs as root)
    switch_oc_version
    configure_kube_proxy
    initialize_home
    configure_bedrock
    warn_audit_config
    display_timeout

    # Cluster command mode: if CMD is not interactive and CLUSTER_ID is set,
    # login to the cluster first then run the command.
    if ! is_interactive_command "$@" && [ -n "${CLUSTER_ID}" ]; then
        do_cluster_login
    fi

    # Run the command in the background and wait for it. Cannot use exec
    # because it replaces the shell process and traps would not fire.
    # Note: entrypoint runs as root for alternatives --set; ECS Exec sessions
    # connect as the sre user via the CLI's "runuser -u sre -- bash" command.
    "${@:-sleep infinity}" &
    CHILD_PID=$!
    wait ${CHILD_PID}
    EXIT_CODE=$?

    sync_to_s3
    exit ${EXIT_CODE}
}

# Guard: allow sourcing for bats tests without triggering execution.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
