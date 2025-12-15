#!/bin/bash
set -e

# Function to sync home directory to S3 on exit
sync_to_s3() {
  if [ -n "${S3_AUDIT_ESCROW}" ]; then
    echo "Syncing /home/sre to ${S3_AUDIT_ESCROW}..."
    aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet || \
      echo "Warning: S3 sync failed" >&2
  else
    echo "Warning: S3_AUDIT_ESCROW not set, /home/sre will not be backed up" >&2
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

# Warn if S3_AUDIT_ESCROW is not configured
if [ -z "${S3_AUDIT_ESCROW}" ]; then
  echo "Warning: S3_AUDIT_ESCROW not set. /home/sre will not be backed up on exit." >&2
fi

# Run the command in the background and wait for it
# This allows the shell to remain and handle signals
"${@:-sleep infinity}" &
CHILD_PID=$!
wait ${CHILD_PID}
EXIT_CODE=$?

# Sync on normal exit too
sync_to_s3
exit ${EXIT_CODE}
