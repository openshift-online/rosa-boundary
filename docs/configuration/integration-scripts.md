# Integration Scripts for Boundary ECS Exec

## Overview

Integration scripts bridge HCP Boundary to AWS ECS Exec via the `-exec` flag pattern. These scripts handle the actual connection establishment after Boundary authorizes the session.

## Core Script: ecs-exec.sh

**Location**: `deploy/boundary/scripts/ecs-exec.sh`

### Basic Implementation

```bash
#!/bin/bash
# ecs-exec.sh - Boundary -exec wrapper for AWS ECS Exec
#
# Usage:
#   boundary connect -target-id ttcp_xxx \
#     -exec ./ecs-exec.sh -- \
#     <cluster-name> <task-arn> [container-name] [user]

set -euo pipefail

# Arguments from boundary connect
CLUSTER="${1:?CLUSTER required}"
TASK="${2:?TASK ARN required}"
CONTAINER="${3:-rosa-boundary}"
USER="${4:-sre}"

# AWS region (from environment or default)
AWS_REGION="${AWS_REGION:-us-east-2}"

# Execute interactive shell in container
aws ecs execute-command \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER" \
  --task "$TASK" \
  --container "$CONTAINER" \
  --command "/bin/bash" \
  --interactive
```

### Enhanced Implementation with Validation

```bash
#!/bin/bash
# ecs-exec.sh - Enhanced Boundary -exec wrapper for AWS ECS Exec

set -euo pipefail

# Enable debug mode with BOUNDARY_DEBUG=1
if [[ "${BOUNDARY_DEBUG:-0}" == "1" ]]; then
  set -x
fi

# Parse arguments
CLUSTER="${1:?CLUSTER required (e.g., rosa-boundary-dev)}"
TASK="${2:?TASK ARN required (e.g., arn:aws:ecs:region:account:task/cluster/id)}"
CONTAINER="${3:-rosa-boundary}"
USER="${4:-sre}"

# Environment defaults
AWS_REGION="${AWS_REGION:-us-east-2}"
TIMEOUT="${TIMEOUT:-28800}"  # 8 hours

# Logging
log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2
}

error() {
  log "ERROR: $*"
  exit 1
}

# Validate AWS credentials
if ! aws sts get-caller-identity &>/dev/null; then
  error "AWS credentials not configured or expired"
fi

log "Connecting to ECS task..."
log "  Cluster: $CLUSTER"
log "  Task: ${TASK##*/}"
log "  Container: $CONTAINER"
log "  User: $USER"

# Validate task exists and is running
TASK_STATUS=$(aws ecs describe-tasks \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER" \
  --tasks "$TASK" \
  --query 'tasks[0].lastStatus' \
  --output text 2>/dev/null || echo "UNKNOWN")

if [[ "$TASK_STATUS" != "RUNNING" ]]; then
  error "Task is not RUNNING (status: $TASK_STATUS)"
fi

# Check if ECS Exec is enabled
EXEC_ENABLED=$(aws ecs describe-tasks \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER" \
  --tasks "$TASK" \
  --query 'tasks[0].enableExecuteCommand' \
  --output text 2>/dev/null || echo "false")

if [[ "$EXEC_ENABLED" != "True" ]]; then
  error "ECS Exec is not enabled for this task"
fi

log "Task validation passed, starting session..."

# Start interactive session
aws ecs execute-command \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER" \
  --task "$TASK" \
  --container "$CONTAINER" \
  --command "/bin/bash" \
  --interactive

EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
  log "Session ended normally"
else
  log "Session ended with error (exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE
```

## Helper Script: Fetch Target Metadata

**`deploy/boundary/scripts/get-target-metadata.sh`:**

```bash
#!/bin/bash
# get-target-metadata.sh - Extract ECS details from Boundary target

set -euo pipefail

TARGET_ID="${1:?TARGET_ID required}"

# Get target details
TARGET_JSON=$(boundary targets read -id "$TARGET_ID" -format json)

# Extract attributes
CLUSTER=$(echo "$TARGET_JSON" | jq -r '.item.attributes.ecs_cluster')
TASK_ARN=$(echo "$TARGET_JSON" | jq -r '.item.attributes.ecs_task_arn')
CONTAINER=$(echo "$TARGET_JSON" | jq -r '.item.attributes.ecs_container // "rosa-boundary"')

echo "CLUSTER=$CLUSTER"
echo "TASK_ARN=$TASK_ARN"
echo "CONTAINER=$CONTAINER"
```

## Simplified Connection Wrapper

**`deploy/boundary/scripts/boundary-ecs-connect.sh`:**

```bash
#!/bin/bash
# boundary-ecs-connect.sh - Simplified wrapper that fetches metadata

set -euo pipefail

TARGET_ID="${1:?TARGET_ID required}"

# Get target metadata
eval "$(./get-target-metadata.sh "$TARGET_ID")"

# Connect via Boundary
boundary connect \
  -target-id "$TARGET_ID" \
  -exec ./ecs-exec.sh -- \
  "$CLUSTER" \
  "$TASK_ARN" \
  "$CONTAINER"
```

**Usage:**
```bash
./boundary-ecs-connect.sh ttcp_1234567890
```

## Extending Lifecycle Scripts

### Update create_incident.sh

Add Boundary target creation after task definition registration:

```bash
# In deploy/regional/examples/create_incident.sh
# After task definition is registered...

# Create Boundary target
BOUNDARY_TARGET_ID=$(boundary targets create tcp \
  -scope-id "$BOUNDARY_PROJECT_SCOPE" \
  -name "${CLUSTER_ID}-incident-${INCIDENT_NUMBER}" \
  -description "Incident ${INCIDENT_NUMBER} for ROSA cluster ${CLUSTER_ID}" \
  -default-port 9999 \
  -address localhost \
  -session-max-seconds 28800 \
  -attr "ecs_cluster=rosa-boundary-${STAGE}" \
  -attr "cluster_id=${CLUSTER_ID}" \
  -attr "incident_number=${INCIDENT_NUMBER}" \
  -format json | jq -r '.item.id')

echo "Boundary Target ID: $BOUNDARY_TARGET_ID"

# Store for later cleanup
echo "$BOUNDARY_TARGET_ID" > "/tmp/incident-${INCIDENT_NUMBER}-boundary-target.txt"
```

### Update launch_task.sh

Add task ARN to Boundary target after task launches:

```bash
# In deploy/regional/examples/launch_task.sh
# After task is RUNNING...

# Update Boundary target with task ARN
if [[ -f "/tmp/incident-${INCIDENT_NUMBER}-boundary-target.txt" ]]; then
  BOUNDARY_TARGET_ID=$(cat "/tmp/incident-${INCIDENT_NUMBER}-boundary-target.txt")

  boundary targets update \
    -id "$BOUNDARY_TARGET_ID" \
    -attr "ecs_task_arn=${TASK_ARN}"

  echo "Updated Boundary target with task ARN: ${TASK_ARN}"
fi
```

### Update close_incident.sh

Add Boundary target cleanup:

```bash
# In deploy/regional/examples/close_incident.sh
# Before deregistering task definitions...

# Delete Boundary target
if [[ -f "/tmp/incident-${INCIDENT_NUMBER}-boundary-target.txt" ]]; then
  BOUNDARY_TARGET_ID=$(cat "/tmp/incident-${INCIDENT_NUMBER}-boundary-target.txt")

  boundary targets delete -id "$BOUNDARY_TARGET_ID"
  echo "Deleted Boundary target: $BOUNDARY_TARGET_ID"

  rm "/tmp/incident-${INCIDENT_NUMBER}-boundary-target.txt"
fi
```

## Installation

### 1. Create scripts directory

```bash
mkdir -p deploy/boundary/scripts
chmod +x deploy/boundary/scripts/*.sh
```

### 2. Copy scripts to user environment

Users need local copies of wrapper scripts:

```bash
# Copy to user home
cp deploy/boundary/scripts/ecs-exec.sh ~/.boundary/
cp deploy/boundary/scripts/boundary-ecs-connect.sh ~/.boundary/
chmod +x ~/.boundary/*.sh

# Add to PATH (optional)
echo 'export PATH="$HOME/.boundary:$PATH"' >> ~/.bashrc
```

### 3. Set environment variables

```bash
# In ~/.bashrc or ~/.zshrc
export BOUNDARY_ADDR="https://<your-cluster>.boundary.hashicorp.cloud"
export AWS_REGION="us-east-2"
export AWS_PROFILE="your-profile"  # Or use SSO
```

## Testing the Integration

### End-to-end test

```bash
# 1. Authenticate to Boundary
boundary authenticate oidc -auth-method-id amoidc_<id>

# 2. List available targets
boundary targets list -scope-id <project-scope>

# 3. Connect to a target
boundary connect \
  -target-id ttcp_<target-id> \
  -exec ~/.boundary/ecs-exec.sh -- \
  rosa-boundary-dev \
  arn:aws:ecs:us-east-2:xxx:task/rosa-boundary-dev/abc123 \
  rosa-boundary

# Should open interactive shell in container
```

### Troubleshooting

If connection fails:

```bash
# Enable debug logging
BOUNDARY_DEBUG=1 boundary connect \
  -target-id ttcp_<target-id> \
  -exec ~/.boundary/ecs-exec.sh -- \
  rosa-boundary-dev \
  arn:aws:ecs:us-east-2:xxx:task/rosa-boundary-dev/abc123

# Test AWS credentials
aws sts get-caller-identity

# Test ECS Exec directly (bypass Boundary)
aws ecs execute-command \
  --cluster rosa-boundary-dev \
  --task arn:aws:ecs:us-east-2:xxx:task/rosa-boundary-dev/abc123 \
  --container rosa-boundary \
  --command "/bin/echo test" \
  --interactive
```

## Advanced: Credential Brokering via Vault

For dynamic AWS credentials, integrate Vault:

```bash
#!/bin/bash
# ecs-exec-vault.sh - Uses Vault-brokered AWS credentials

# Fetch AWS credentials from Vault
VAULT_TOKEN="$BOUNDARY_VAULT_TOKEN"  # Injected by Boundary
VAULT_ADDR="https://vault.example.com"

CREDS=$(curl -sk -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/aws/creds/boundary-ecs-role" | jq -r '.data')

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.access_key')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.secret_key')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.security_token')

# Now run ECS Exec with temporary credentials
aws ecs execute-command \
  --cluster "$1" \
  --task "$2" \
  --container "${3:-rosa-boundary}" \
  --command "/bin/bash" \
  --interactive

# Credentials expire after session (no cleanup needed)
```

## Next Steps

- [User Access Guide](../runbooks/user-access-guide.md) - End-user instructions
- [Incident Workflow](../runbooks/incident-workflow.md) - Full incident lifecycle with Boundary
