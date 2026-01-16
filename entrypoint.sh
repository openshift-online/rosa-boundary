#!/bin/bash
set -e

# Function to sync home directory to S3 on exit
sync_to_s3() {
  # Build S3 path automatically if structured variables are provided
  if [ -z "${S3_AUDIT_ESCROW}" ] && [ -n "${S3_AUDIT_BUCKET}" ] && [ -n "${CLUSTER_ID}" ] && [ -n "${INVESTIGATION_ID}" ]; then
    # Auto-detect task ID from ECS metadata
    if [ -n "${ECS_CONTAINER_METADATA_URI_V4}" ]; then
      TASK_ARN=$(curl -s "${ECS_CONTAINER_METADATA_URI_V4}/task" 2>/dev/null | grep -o '"TaskARN":"[^"]*"' | cut -d'"' -f4)
      TASK_ID=$(echo "$TASK_ARN" | awk -F'/' '{print $NF}')
    fi

    # Build S3 path: s3://bucket/$cluster/$investigation/$date/$taskid/
    DATE=$(date +%Y%m%d)
    S3_AUDIT_ESCROW="s3://${S3_AUDIT_BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/${DATE}/${TASK_ID}/"
    echo "Auto-generated S3 audit path: ${S3_AUDIT_ESCROW}"
  fi

  if [ -n "${S3_AUDIT_ESCROW}" ]; then
    echo "Syncing /home/sre to ${S3_AUDIT_ESCROW}..."
    aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet || \
      echo "Warning: S3 sync failed" >&2
  else
    echo "Warning: S3 audit not configured, /home/sre will not be backed up" >&2
  fi
}

# Cleanup function - sync and terminate child process
cleanup() {
  sync_to_s3
  # Kill the background process if it exists
  if [ -n "${CHILD_PID}" ]; then
    kill -TERM "${CHILD_PID}" 2>/dev/null || true
  fi
  exit 0
}

# Trap signals for cleanup
trap cleanup SIGTERM SIGINT SIGHUP

# Switch OpenShift CLI version if OC_VERSION is set
if [ -n "${OC_VERSION}" ]; then
  if [ -x "/opt/openshift/${OC_VERSION}/oc" ]; then
    alternatives --set oc "/opt/openshift/${OC_VERSION}/oc"
  else
    echo "Warning: OC version ${OC_VERSION} not found, using default" >&2
  fi
fi

# Switch AWS CLI if AWS_CLI is set
if [ -n "${AWS_CLI}" ]; then
  case "${AWS_CLI}" in
    fedora)
      alternatives --set aws /usr/bin/aws
      ;;
    official|aws-official)
      alternatives --set aws /opt/aws-cli-official/v2/current/bin/aws
      ;;
    *)
      echo "Warning: Unknown AWS_CLI value '${AWS_CLI}', using default" >&2
      ;;
  esac
fi

# Copy skeleton Claude Code config to /home/sre if not already present
# /home/sre is EFS-mounted, so only copy if .claude doesn't exist
if [ ! -d /home/sre/.claude ] && [ -d /etc/skel-sre/.claude ]; then
  echo "Initializing Claude Code configuration in /home/sre/.claude..."
  cp -r /etc/skel-sre/.claude /home/sre/.claude
  chown -R sre:sre /home/sre/.claude
fi

# Set Bedrock defaults if CLAUDE_CODE_USE_BEDROCK is enabled
if [ "${CLAUDE_CODE_USE_BEDROCK:-1}" = "1" ]; then
  export CLAUDE_CODE_USE_BEDROCK=1

  # Auto-detect region from ECS task metadata if AWS_REGION not set
  if [ -z "${AWS_REGION}" ] && [ -n "${ECS_CONTAINER_METADATA_URI_V4}" ]; then
    # Extract region from task ARN in metadata
    TASK_METADATA=$(curl -s "${ECS_CONTAINER_METADATA_URI_V4}/task" 2>/dev/null || true)
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

# Warn if S3 audit is not configured
if [ -z "${S3_AUDIT_ESCROW}" ] && { [ -z "${S3_AUDIT_BUCKET}" ] || [ -z "${CLUSTER_ID}" ] || [ -z "${INVESTIGATION_ID}" ]; }; then
  echo "Warning: S3 audit not configured. /home/sre will not be backed up on exit." >&2
  echo "  Set either S3_AUDIT_ESCROW or (S3_AUDIT_BUCKET + CLUSTER_ID + INVESTIGATION_ID)" >&2
fi

# Run the command in the background and wait for it
# This allows the shell to remain and handle signals
# Running as sre user (set via USER directive in Containerfile)
"${@:-sleep infinity}" &
CHILD_PID=$!
wait ${CHILD_PID}
EXIT_CODE=$?

# Sync on normal exit too
sync_to_s3
exit ${EXIT_CODE}
