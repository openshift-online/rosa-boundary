#!/bin/bash
set -e

# Script to create an incident workspace with EFS access point and task definition
# Usage: ./create_incident.sh <cluster-id> <incident-number> [oc-version]

CLUSTER_ID="${1}"
INCIDENT_NUMBER="${2}"
OC_VERSION="${3:-4.20}"  # Default to 4.20

if [ -z "$CLUSTER_ID" ] || [ -z "$INCIDENT_NUMBER" ]; then
  echo "Usage: $0 <cluster-id> <incident-number> [oc-version]"
  echo ""
  echo "Example:"
  echo "  $0 rosa-prod-abc INC-12345"
  echo "  $0 rosa-prod-abc INC-12345 4.18"
  echo ""
  echo "Available OC versions: 4.14, 4.15, 4.16, 4.17, 4.18, 4.19, 4.20"
  exit 1
fi

# Validate OC version
if ! echo "4.14 4.15 4.16 4.17 4.18 4.19 4.20" | grep -qw "$OC_VERSION"; then
  echo "ERROR: Invalid OC version '$OC_VERSION'"
  echo "Available versions: 4.14, 4.15, 4.16, 4.17, 4.18, 4.19, 4.20"
  exit 1
fi

# AWS configuration
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_REGION:-us-east-2}"

# Save script directory before changing directories
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Creating incident workspace..."
echo "  Cluster ID: $CLUSTER_ID"
echo "  Incident: $INCIDENT_NUMBER"
echo "  OC Version: $OC_VERSION"
echo "  AWS Profile: $PROFILE"
echo "  AWS Region: $REGION"
echo ""

# Get infrastructure details from AWS directly (Terraform state not available)
cd "$(dirname "$0")/.."

EFS_ID=$(aws --profile "$PROFILE" --region "$REGION" efs describe-file-systems \
  --query 'FileSystems[?Tags[?Key==`Name` && contains(Value, `rosa-boundary-dev-sre-home`)]].FileSystemId' \
  --output text)

BASE_TASK_DEF="rosa-boundary-dev"

TASK_ROLE_ARN=$(aws --profile "$PROFILE" --region "$REGION" iam get-role \
  --role-name rosa-boundary-dev-task-role \
  --query 'Role.Arn' --output text)

EXECUTION_ROLE_ARN=$(aws --profile "$PROFILE" --region "$REGION" iam get-role \
  --role-name rosa-boundary-dev-execution-role \
  --query 'Role.Arn' --output text)

BUCKET_NAME=$(aws --profile "$PROFILE" --region "$REGION" s3api list-buckets \
  --query 'Buckets[?contains(Name, `rosa-boundary-dev`)].Name' \
  --output text | head -1)

echo "Infrastructure:"
echo "  EFS: $EFS_ID"
echo "  Base Task Definition: $BASE_TASK_DEF"
echo "  S3 Bucket: $BUCKET_NAME"
echo ""

# Step 1: Create EFS access point for this incident
echo "[1/2] Creating EFS access point..."
ACCESS_POINT=$(aws efs create-access-point \
  --profile "$PROFILE" \
  --region "$REGION" \
  --file-system-id "$EFS_ID" \
  --posix-user "Uid=1000,Gid=1000" \
  --root-directory "Path=/$CLUSTER_ID/$INCIDENT_NUMBER,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=0755}" \
  --tags "Key=ClusterID,Value=$CLUSTER_ID" \
         "Key=IncidentNumber,Value=$INCIDENT_NUMBER" \
         "Key=OcVersion,Value=$OC_VERSION" \
         "Key=Project,Value=rosa-boundary" \
         "Key=ManagedBy,Value=Script" \
  --query 'AccessPointId' \
  --output text)

if [ -z "$ACCESS_POINT" ]; then
  echo "ERROR: Failed to create EFS access point"
  exit 1
fi

echo "  ✓ Access Point created: $ACCESS_POINT"

# Step 2: Create task definition for this incident
echo "[2/2] Creating task definition..."

# Get the base task definition and modify it
BASE_TASK_JSON=$(aws ecs describe-task-definition \
  --profile "$PROFILE" \
  --region "$REGION" \
  --task-definition "$BASE_TASK_DEF" \
  --query 'taskDefinition' \
  --output json)

# Build new task definition family name with timestamp for uniqueness
# Format: rosa-boundary-dev-CLUSTER_ID-INCIDENT_NUMBER-TIMESTAMP
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
INCIDENT_TASK_FAMILY="${BASE_TASK_DEF}-${CLUSTER_ID}-${INCIDENT_NUMBER}-${TIMESTAMP}"

# Create new task definition with incident-specific configuration
TASK_DEF_JSON=$(echo "$BASE_TASK_JSON" | jq -f "$SCRIPT_DIR/build-task-def.jq" \
  --arg family "$INCIDENT_TASK_FAMILY" \
  --arg task_role "$TASK_ROLE_ARN" \
  --arg exec_role "$EXECUTION_ROLE_ARN" \
  --arg efs_id "$EFS_ID" \
  --arg access_point "$ACCESS_POINT" \
  --arg cluster_id "$CLUSTER_ID" \
  --arg incident "$INCIDENT_NUMBER" \
  --arg oc_version "$OC_VERSION" \
  --arg bucket "$BUCKET_NAME")

# Save task definition to temp file and register
TEMP_FILE=$(mktemp)
echo "$TASK_DEF_JSON" > "$TEMP_FILE"

TASK_DEF_ARN=$(aws ecs register-task-definition \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cli-input-json "file://$TEMP_FILE" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

rm -f "$TEMP_FILE"

if [ -z "$TASK_DEF_ARN" ]; then
  echo "ERROR: Failed to create task definition"
  echo "Rolling back access point..."
  aws efs delete-access-point --profile "$PROFILE" --region "$REGION" --access-point-id "$ACCESS_POINT" 2>/dev/null || true
  exit 1
fi

echo "  ✓ Task Definition created: $TASK_DEF_ARN"

echo ""
echo "=========================================="
echo "✓ Incident workspace created successfully!"
echo "=========================================="
echo ""
echo "Incident Details:"
echo "  Cluster ID: $CLUSTER_ID"
echo "  Incident Number: $INCIDENT_NUMBER"
echo "  OC Version: $OC_VERSION"
echo ""
echo "Infrastructure:"
echo "  EFS Access Point: $ACCESS_POINT"
echo "  EFS Path: /$CLUSTER_ID/$INCIDENT_NUMBER"
echo "  Task Definition: $INCIDENT_TASK_FAMILY"
echo "  S3 Bucket: $BUCKET_NAME"
echo ""
echo "Save this information:"
echo "  export CLUSTER_ID=\"$CLUSTER_ID\""
echo "  export INCIDENT_NUMBER=\"$INCIDENT_NUMBER\""
echo "  export ACCESS_POINT_ID=\"$ACCESS_POINT\""
echo "  export TASK_FAMILY=\"$INCIDENT_TASK_FAMILY\""
echo ""
echo "Next steps:"
echo "  1. Launch a task: ./launch_task.sh $INCIDENT_TASK_FAMILY"
echo "  2. Join the task: ./join_task.sh <task-id>"
echo "  3. Stop task: ./stop_task.sh <task-id>"
echo "  4. Close incident: ./close_incident.sh $INCIDENT_TASK_FAMILY $ACCESS_POINT"
