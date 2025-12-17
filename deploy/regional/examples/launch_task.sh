#!/bin/bash
set -e

# Script to launch a Fargate task for an incident
# Usage: ./launch_task.sh <task-family-name>

TASK_FAMILY="${1}"

if [ -z "$TASK_FAMILY" ]; then
  echo "Usage: $0 <task-family-name>"
  echo ""
  echo "Example:"
  echo "  $0 rosa-boundary-dev-rosa-prod-abc-INC-12345"
  echo ""
  echo "Get the task family name from create_incident.sh output"
  exit 1
fi

# AWS configuration
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_REGION:-us-east-2}"

echo "Launching Fargate task..."
echo "  Task Family: $TASK_FAMILY"
echo "  AWS Profile: $PROFILE"
echo "  AWS Region: $REGION"
echo ""

# Get infrastructure details from AWS directly (Terraform state not available)
cd "$(dirname "$0")/.."

CLUSTER_NAME=$(aws --profile "$PROFILE" --region "$REGION" ecs list-clusters \
  --query 'clusterArns[?contains(@, `rosa-boundary`)]' --output text | awk -F'/' '{print $NF}')

SECURITY_GROUP=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-security-groups \
  --filters "Name=tag:Project,Values=rosa-boundary" "Name=tag:Stage,Values=dev" \
  --query 'SecurityGroups[?contains(GroupName, `fargate`)].GroupId' --output text)

# Get EFS filesystem ID, then query mount targets for subnet IDs
EFS_ID=$(aws --profile "$PROFILE" --region "$REGION" efs describe-file-systems \
  --query 'FileSystems[?Tags[?Key==`Name` && contains(Value, `rosa-boundary-dev-sre-home`)]].FileSystemId' \
  --output text)

SUBNET_IDS=$(aws --profile "$PROFILE" --region "$REGION" efs describe-mount-targets \
  --file-system-id "$EFS_ID" --query 'MountTargets[].SubnetId' --output text | tr '\t' ',')

echo "Infrastructure:"
echo "  ECS Cluster: $CLUSTER_NAME"
echo "  Security Group: $SECURITY_GROUP"
echo "  Subnets: $SUBNET_IDS"
echo ""

# Launch the Fargate task
TASK_ARN=$(aws ecs run-task \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cluster "$CLUSTER_NAME" \
  --task-definition "$TASK_FAMILY" \
  --launch-type FARGATE \
  --platform-version "1.4.0" \
  --enable-execute-command \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_IDS],securityGroups=[$SECURITY_GROUP],assignPublicIp=ENABLED}" \
  --query 'tasks[0].taskArn' \
  --output text)

if [ -z "$TASK_ARN" ]; then
  echo "ERROR: Failed to launch task"
  exit 1
fi

# Extract task ID from ARN
TASK_ID=$(echo "$TASK_ARN" | awk -F'/' '{print $NF}')

echo "✓ Task launched successfully!"
echo ""
echo "Task ARN: $TASK_ARN"
echo "Task ID: $TASK_ID"
echo ""
echo "Waiting for task to be running..."

# Wait for task to reach RUNNING state
aws ecs wait tasks-running \
  --profile "$PROFILE" \
  --region "$REGION" \
  --cluster "$CLUSTER_NAME" \
  --tasks "$TASK_ID"

echo ""
echo "✓ Task is now running!"
echo ""
echo "Connect to task:"
echo "  ./join_task.sh $TASK_ID"
echo ""
echo "Or manually:"
echo "  AWS_PROFILE=$PROFILE AWS_REGION=$REGION aws ecs execute-command \\"
echo "    --cluster $CLUSTER_NAME \\"
echo "    --task $TASK_ID \\"
echo "    --container rosa-boundary \\"
echo "    --interactive \\"
echo "    --command '/bin/bash'"
echo ""
echo "Stop task when done:"
echo "  ./stop_task.sh $TASK_ID"
