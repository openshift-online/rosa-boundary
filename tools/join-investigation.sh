#!/bin/bash
set -euo pipefail

# Join Investigation
# Connect to an ECS task via ECS Exec using assumed OIDC credentials

usage() {
    cat <<EOF
Usage: $0 <task-id> [cluster]

Connect to an ECS task via ECS Exec.

ARGUMENTS:
    task-id    ECS task ID (short ID or full ARN)
    cluster    ECS cluster name (default: rosa-boundary-dev)

PREREQUISITES:
    - AWS credentials must be configured (run create-investigation-lambda.sh first)
    - Task must be in RUNNING state
    - Task must have ECS Exec enabled

EXAMPLES:
    # Connect to task in default cluster
    $0 abc123def456

    # Connect to task in specific cluster
    $0 abc123def456 rosa-boundary-prod

    # Full task ARN also works
    $0 arn:aws:ecs:us-east-2:123456789012:task/rosa-boundary-dev/abc123def456

EOF
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

TASK_ID="$1"
CLUSTER="${2:-rosa-boundary-dev}"
REGION="${AWS_REGION:-us-east-2}"

# Extract task ID if full ARN provided
if [[ "$TASK_ID" =~ ^arn:aws:ecs ]]; then
    TASK_ID=$(basename "$TASK_ID")
fi

# Verify AWS credentials are configured
if ! aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1; then
    echo "Error: AWS credentials not configured" >&2
    echo "Run create-investigation-lambda.sh first to authenticate" >&2
    exit 1
fi

CALLER_IDENTITY=$(aws sts get-caller-identity --region "$REGION")
CALLER_ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn')

echo "Current AWS identity: $CALLER_ARN" >&2
echo "Cluster: $CLUSTER" >&2
echo "Task: $TASK_ID" >&2
echo "" >&2

# Check task status
echo "Checking task status..." >&2
TASK_STATUS=$(aws ecs describe-tasks \
    --cluster "$CLUSTER" \
    --tasks "$TASK_ID" \
    --region "$REGION" \
    --query 'tasks[0].lastStatus' \
    --output text 2>/dev/null || echo "UNKNOWN")

if [[ "$TASK_STATUS" == "UNKNOWN" ]] || [[ "$TASK_STATUS" == "None" ]]; then
    echo "Error: Task not found or no permission to describe task" >&2
    echo "Task ID: $TASK_ID" >&2
    echo "Cluster: $CLUSTER" >&2
    exit 1
fi

echo "Task status: $TASK_STATUS" >&2

if [[ "$TASK_STATUS" != "RUNNING" ]]; then
    echo "Warning: Task is not RUNNING (current status: $TASK_STATUS)" >&2
    echo "Waiting for task to reach RUNNING state..." >&2
    aws ecs wait tasks-running --cluster "$CLUSTER" --tasks "$TASK_ID" --region "$REGION"
fi

# Connect via ECS Exec
echo "" >&2
echo "Connecting to task..." >&2
echo "" >&2

aws ecs execute-command \
    --cluster "$CLUSTER" \
    --task "$TASK_ID" \
    --container rosa-boundary \
    --interactive \
    --command "/bin/bash" \
    --region "$REGION"
