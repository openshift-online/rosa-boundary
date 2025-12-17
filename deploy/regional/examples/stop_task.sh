#!/bin/bash
set -e

# Script to stop a Fargate task (triggers S3 sync)
# Usage: ./stop_task.sh <task-id> [reason]

TASK_ID="${1}"
REASON="${2:-Investigation complete}"

if [ -z "$TASK_ID" ]; then
  echo "Usage: $0 <task-id> [reason]"
  echo ""
  echo "Example:"
  echo "  $0 394399c601f94548bedb65d5a90f30c6"
  echo "  $0 394399c601f94548bedb65d5a90f30c6 \"Incident resolved\""
  echo ""
  echo "List running tasks:"
  echo "  aws ecs list-tasks --cluster rosa-boundary-dev --desired-status RUNNING"
  exit 1
fi

# AWS configuration
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_REGION:-us-east-2}"

# Get cluster name from AWS directly (Terraform state not available)
cd "$(dirname "$0")/.."
CLUSTER_NAME=$(aws --profile "$PROFILE" --region "$REGION" ecs list-clusters \
  --query 'clusterArns[?contains(@, `rosa-boundary`)]' --output text | awk -F'/' '{print $NF}')

BUCKET_NAME=$(aws --profile "$PROFILE" --region "$REGION" s3api list-buckets \
  --query 'Buckets[?contains(Name, `rosa-boundary-dev`)].Name' \
  --output text | head -1)

echo "Stopping task..."
echo "  Task ID: $TASK_ID"
echo "  Cluster: $CLUSTER_NAME"
echo "  Reason: $REASON"
echo "  AWS Profile: $PROFILE"
echo "  AWS Region: $REGION"
echo ""

# Get task details before stopping
TASK_INFO=$(aws ecs describe-tasks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cluster "$CLUSTER_NAME" \
  --tasks "$TASK_ID" \
  --query 'tasks[0]' \
  --output json 2>/dev/null)

if [ -z "$TASK_INFO" ] || [ "$TASK_INFO" = "null" ]; then
  echo "ERROR: Task $TASK_ID not found"
  exit 1
fi

# Extract task definition ARN to get environment variables
TASK_DEF_ARN=$(echo "$TASK_INFO" | jq -r '.taskDefinitionArn')

# Get environment variables from the task definition
TASK_DEF_INFO=$(aws ecs describe-task-definition \
  --profile "$PROFILE" \
  --region "$REGION" \
  --task-definition "$TASK_DEF_ARN" \
  --query 'taskDefinition.containerDefinitions[0].environment' \
  --output json)

CLUSTER_ID=$(echo "$TASK_DEF_INFO" | jq -r '.[] | select(.name=="CLUSTER_ID") | .value' 2>/dev/null || echo "unknown")
INCIDENT_NUMBER=$(echo "$TASK_DEF_INFO" | jq -r '.[] | select(.name=="INCIDENT_NUMBER") | .value' 2>/dev/null || echo "unknown")

# Stop the task
aws ecs stop-task \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cluster "$CLUSTER_NAME" \
  --task "$TASK_ID" \
  --reason "$REASON" \
  --query 'task.{taskArn:taskArn,desiredStatus:desiredStatus,stoppedReason:stoppedReason}' \
  --output json

echo ""
echo "✓ Task stop initiated"
echo ""
echo "The container's entrypoint will:"
echo "  1. Receive SIGTERM signal"
echo "  2. Sync /home/sre to S3"
echo "  3. Exit gracefully"
echo ""

if [ "$CLUSTER_ID" != "unknown" ] && [ "$INCIDENT_NUMBER" != "unknown" ]; then
  DATE=$(date +%Y%m%d)
  S3_PATH="s3://$BUCKET_NAME/$CLUSTER_ID/$INCIDENT_NUMBER/$DATE/$TASK_ID/"
  echo "Expected S3 sync destination:"
  echo "  $S3_PATH"
  echo ""
  echo "Verify sync completed (after ~30 seconds):"
  echo "  aws s3 ls \"$S3_PATH\" --recursive"
else
  echo "Note: Could not determine S3 path (missing CLUSTER_ID or INCIDENT_NUMBER env vars)"
fi

echo ""
echo "Monitor task stopping:"
echo "  aws ecs describe-tasks --cluster $CLUSTER_NAME --tasks $TASK_ID --query 'tasks[0].{status:lastStatus,stoppedReason:stoppedReason}'"
