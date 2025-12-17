#!/bin/bash
set -e

# Script to close an incident by deleting task definition and EFS access point
# Usage: ./close_incident.sh <task-family-name> <access-point-id>

TASK_FAMILY="${1}"
ACCESS_POINT_ID="${2}"

if [ -z "$TASK_FAMILY" ] || [ -z "$ACCESS_POINT_ID" ]; then
  echo "Usage: $0 <task-family-name> <access-point-id>"
  echo ""
  echo "Example:"
  echo "  $0 rosa-boundary-dev-rosa-prod-abc-INC-12345 fsap-0123456789abcdef"
  echo ""
  echo "Get these from create_incident.sh output"
  exit 1
fi

# AWS configuration
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_REGION:-us-east-2}"

echo "Closing incident..."
echo "  Task Family: $TASK_FAMILY"
echo "  Access Point: $ACCESS_POINT_ID"
echo "  AWS Profile: $PROFILE"
echo "  AWS Region: $REGION"
echo ""

# Get cluster name from AWS directly (Terraform state not available)
cd "$(dirname "$0")/.."
CLUSTER_NAME=$(aws --profile "$PROFILE" --region "$REGION" ecs list-clusters \
  --query 'clusterArns[?contains(@, `rosa-boundary`)]' --output text | awk -F'/' '{print $NF}')

# Extract incident details from access point tags instead of parsing task family
ACCESS_POINT_INFO=$(aws efs describe-access-points \
  --profile "$PROFILE" \
  --region "$REGION" \
  --access-point-id "$ACCESS_POINT_ID" \
  --query 'AccessPoints[0]' \
  --output json 2>/dev/null)

CLUSTER_ID=$(echo "$ACCESS_POINT_INFO" | jq -r '.Tags[]? | select(.Key=="ClusterID") | .Value' 2>/dev/null || echo "unknown")
INCIDENT_NUMBER=$(echo "$ACCESS_POINT_INFO" | jq -r '.Tags[]? | select(.Key=="IncidentNumber") | .Value' 2>/dev/null || echo "unknown")
EFS_PATH=$(echo "$ACCESS_POINT_INFO" | jq -r '.RootDirectory.Path' 2>/dev/null || echo "unknown")

echo "Incident Details:"
echo "  Cluster ID: $CLUSTER_ID"
echo "  Incident Number: $INCIDENT_NUMBER"
echo "  EFS Path: $EFS_PATH"
echo ""

# Step 1: Check for running tasks using this task definition
echo "[1/3] Checking for active tasks..."
RUNNING_TASKS=$(aws ecs list-tasks \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cluster "$CLUSTER_NAME" \
  --family "$TASK_FAMILY" \
  --desired-status RUNNING \
  --query 'taskArns[]' \
  --output text)

if [ -n "$RUNNING_TASKS" ]; then
  echo ""
  echo "ERROR: Found running tasks for this incident:"
  for task_arn in $RUNNING_TASKS; do
    TASK_ID=$(echo "$task_arn" | awk -F'/' '{print $NF}')
    echo "  - $TASK_ID"
  done
  echo ""
  echo "Stop all tasks first:"
  for task_arn in $RUNNING_TASKS; do
    TASK_ID=$(echo "$task_arn" | awk -F'/' '{print $NF}')
    echo "  ./stop_task.sh $TASK_ID"
  done
  exit 1
fi

echo "  ✓ No active tasks found"

# Step 2: Deregister all task definition revisions
echo "[2/3] Deregistering task definition revisions..."

# Get all revisions for this family
REVISIONS=$(aws ecs list-task-definitions \
  --profile "$PROFILE" \
  --region "$REGION" \
  --family-prefix "$TASK_FAMILY" \
  --status ACTIVE \
  --query 'taskDefinitionArns[]' \
  --output text)

if [ -z "$REVISIONS" ]; then
  echo "  ⚠ No task definition revisions found (may have been deleted already)"
else
  REVISION_COUNT=0
  for revision_arn in $REVISIONS; do
    echo "  Deregistering: $revision_arn"
    aws ecs deregister-task-definition \
      --profile "$PROFILE" \
      --region "$REGION" \
      --task-definition "$revision_arn" \
      --query 'taskDefinition.taskDefinitionArn' \
      --output text >/dev/null
    ((REVISION_COUNT++))
  done
  echo "  ✓ Deregistered $REVISION_COUNT revision(s)"
fi

# Step 3: Delete EFS access point
echo "[3/3] Deleting EFS access point..."

# Confirm deletion
read -p "Delete access point $ACCESS_POINT_ID and EFS data for $INCIDENT_NUMBER? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted. Task definitions have been deregistered but access point remains."
  exit 0
fi

aws efs delete-access-point \
  --profile "$PROFILE" \
  --region "$REGION" \
  --access-point-id "$ACCESS_POINT_ID"

echo "  ✓ Access point deleted"

echo ""
echo "=========================================="
echo "✓ Incident closed successfully!"
echo "=========================================="
echo ""
echo "Cleaned up:"
echo "  ✓ Task definition family: $TASK_FAMILY (all revisions)"
echo "  ✓ EFS access point: $ACCESS_POINT_ID"
echo ""
echo "Note: EFS data at /$CLUSTER_ID/$INCIDENT_NUMBER is preserved on the filesystem."
echo "The directory will remain but is no longer accessible via this access point."
echo ""
echo "To completely remove EFS data (manual action required):"
echo "  1. Mount the EFS filesystem to an EC2 instance"
echo "  2. Delete the directory: rm -rf /$CLUSTER_ID/$INCIDENT_NUMBER"
