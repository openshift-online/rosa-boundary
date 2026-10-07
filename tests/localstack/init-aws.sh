#!/bin/bash
# Bootstrap VPC and network infrastructure for LocalStack testing
# This runs when LocalStack reaches "ready" state

set -euo pipefail

echo "Initializing AWS resources for testing..."

# Create VPC
VPC_ID=$(awslocal ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)
echo "Created VPC: $VPC_ID"

# Tag VPC
awslocal ec2 create-tags --resources "$VPC_ID" --tags Key=Name,Value=test-vpc

# Create Internet Gateway
IGW_ID=$(awslocal ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)
awslocal ec2 attach-internet-gateway --vpc-id "$VPC_ID" --internet-gateway-id "$IGW_ID"
echo "Created Internet Gateway: $IGW_ID"

# Create subnets in two AZs
SUBNET1_ID=$(awslocal ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.0.1.0/24 --availability-zone us-east-2a --query 'Subnet.SubnetId' --output text)
SUBNET2_ID=$(awslocal ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.0.2.0/24 --availability-zone us-east-2b --query 'Subnet.SubnetId' --output text)
echo "Created Subnets: $SUBNET1_ID, $SUBNET2_ID"

# Tag subnets
awslocal ec2 create-tags --resources "$SUBNET1_ID" --tags Key=Name,Value=test-subnet-1
awslocal ec2 create-tags --resources "$SUBNET2_ID" --tags Key=Name,Value=test-subnet-2

# Create route table
ROUTE_TABLE_ID=$(awslocal ec2 create-route-table --vpc-id "$VPC_ID" --query 'RouteTable.RouteTableId' --output text)
awslocal ec2 create-route --route-table-id "$ROUTE_TABLE_ID" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID"
echo "Created Route Table: $ROUTE_TABLE_ID"

# Associate route table with subnets
awslocal ec2 associate-route-table --subnet-id "$SUBNET1_ID" --route-table-id "$ROUTE_TABLE_ID"
awslocal ec2 associate-route-table --subnet-id "$SUBNET2_ID" --route-table-id "$ROUTE_TABLE_ID"

# Create security group for ECS tasks
SG_ID=$(awslocal ec2 create-security-group \
  --group-name test-ecs-sg \
  --description "Security group for ECS testing" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)
echo "Created Security Group: $SG_ID"

# Allow all outbound traffic
awslocal ec2 authorize-security-group-egress \
  --group-id "$SG_ID" \
  --ip-permissions IpProtocol=-1,FromPort=-1,ToPort=-1,IpRanges='[{CidrIp=0.0.0.0/0}]' 2>/dev/null || true

# Store resource IDs in SSM Parameter Store for test discovery
awslocal ssm put-parameter --name /test/vpc-id --value "$VPC_ID" --type String --overwrite
awslocal ssm put-parameter --name /test/subnet-1-id --value "$SUBNET1_ID" --type String --overwrite
awslocal ssm put-parameter --name /test/subnet-2-id --value "$SUBNET2_ID" --type String --overwrite
awslocal ssm put-parameter --name /test/security-group-id --value "$SG_ID" --type String --overwrite

# Deploy create-investigation Lambda for start-task testing
echo "Deploying create-investigation Lambda..."

# Create Lambda execution role
LAMBDA_ROLE_NAME="create-investigation-lambda-role"
LAMBDA_TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

LAMBDA_ROLE_ARN=$(awslocal iam create-role \
  --role-name "$LAMBDA_ROLE_NAME" \
  --assume-role-policy-document "$LAMBDA_TRUST_POLICY" \
  --query 'Role.Arn' --output text 2>/dev/null || \
  awslocal iam get-role --role-name "$LAMBDA_ROLE_NAME" --query 'Role.Arn' --output text)

echo "Lambda role ARN: $LAMBDA_ROLE_ARN"

# Attach basic Lambda execution policy
LAMBDA_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "ecs:*",
        "elasticfilesystem:*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}'

awslocal iam put-role-policy \
  --role-name "$LAMBDA_ROLE_NAME" \
  --policy-name lambda-permissions \
  --policy-document "$LAMBDA_POLICY"

# Create Lambda deployment package
# LocalStack Lambda doesn't need all dependencies - just core handler logic
LAMBDA_ZIP="/tmp/create-investigation-lambda.zip"
LAMBDA_SOURCE="/var/lib/localstack/lambda/create-investigation"

# Determine the actual Lambda source directory
# When running in container, use the mounted path; otherwise use relative path
if [ -d "$LAMBDA_SOURCE" ]; then
  LAMBDA_DIR="$LAMBDA_SOURCE"
else
  # Running outside container - use relative path from this script
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  LAMBDA_DIR="$SCRIPT_DIR/../../lambda/create-investigation"
fi

if [ ! -f "$LAMBDA_DIR/handler.py" ]; then
  echo "ERROR: handler.py not found at $LAMBDA_DIR"
  echo "Lambda deployment skipped - handler must be mounted or present"
  # Don't fail the whole init - just skip Lambda deployment
  LAMBDA_DEPLOYED=false
else
  echo "Using Lambda source from: $LAMBDA_DIR"

  # Create deployment package with handler and required dependencies
  # For LocalStack, we include only the handler - boto3/botocore are provided by Lambda runtime
  LAMBDA_TEMP_DIR="/tmp/lambda-build-$$"
  mkdir -p "$LAMBDA_TEMP_DIR"

  # Copy handler
  cp "$LAMBDA_DIR/handler.py" "$LAMBDA_TEMP_DIR/"

  # Copy minimal dependencies for OIDC bypass mode testing
  # PyJWT and cryptography are needed even in bypass mode due to imports
  if [ -d "$LAMBDA_DIR/jwt" ]; then
    cp -r "$LAMBDA_DIR/jwt" "$LAMBDA_TEMP_DIR/"
  fi
  if [ -d "$LAMBDA_DIR/cryptography" ]; then
    cp -r "$LAMBDA_DIR/cryptography" "$LAMBDA_TEMP_DIR/"
  fi
  if [ -d "$LAMBDA_DIR/requests" ]; then
    cp -r "$LAMBDA_DIR/requests" "$LAMBDA_TEMP_DIR/"
  fi

  # Create zip
  (cd "$LAMBDA_TEMP_DIR" && zip -q -r "$LAMBDA_ZIP" .)
  rm -rf "$LAMBDA_TEMP_DIR"

  echo "Lambda package created: $LAMBDA_ZIP ($(du -h "$LAMBDA_ZIP" | cut -f1))"
  LAMBDA_DEPLOYED=true
fi

# Create shared SRE role for testing
SHARED_ROLE_NAME="rosa-boundary-sre-shared-localstack"
SHARED_ROLE_ARN=$(awslocal iam create-role \
  --role-name "$SHARED_ROLE_NAME" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --query 'Role.Arn' --output text 2>/dev/null || \
  awslocal iam get-role --role-name "$SHARED_ROLE_NAME" --query 'Role.Arn' --output text)

echo "Shared SRE role ARN: $SHARED_ROLE_ARN"

# Create ECS cluster
ECS_CLUSTER_NAME="rosa-boundary-localstack"
awslocal ecs create-cluster --cluster-name "$ECS_CLUSTER_NAME" 2>/dev/null || echo "Cluster already exists"

# Register a minimal task definition for testing
TASK_DEF_FAMILY="rosa-boundary-task-localstack"
awslocal ecs register-task-definition \
  --family "$TASK_DEF_FAMILY" \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 \
  --memory 512 \
  --container-definitions '[{
    "name": "rosa-boundary",
    "image": "public.ecr.aws/docker/library/alpine:latest",
    "essential": true
  }]' > /dev/null 2>&1 || echo "Task definition already exists"

TASK_DEF_ARN=$(awslocal ecs describe-task-definition --task-definition "$TASK_DEF_FAMILY" --query 'taskDefinition.taskDefinitionArn' --output text)
echo "Task definition ARN: $TASK_DEF_ARN"

# Create EFS filesystem
EFS_ID=$(awslocal efs create-file-system --query 'FileSystemId' --output text 2>/dev/null || \
  awslocal efs describe-file-systems --query 'FileSystems[0].FileSystemId' --output text)
echo "EFS filesystem ID: $EFS_ID"

# Deploy Lambda function with bypass mode enabled (only if package was built)
if [ "$LAMBDA_DEPLOYED" = "true" ]; then
  FUNCTION_NAME="create-investigation-localstack"
  awslocal lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime python3.11 \
    --role "$LAMBDA_ROLE_ARN" \
    --handler handler.lambda_handler \
    --zip-file "fileb://$LAMBDA_ZIP" \
    --timeout 60 \
    --environment "Variables={
      BYPASS_OIDC_VALIDATION=true,
      ECS_CLUSTER=$ECS_CLUSTER_NAME,
      TASK_DEFINITION=$TASK_DEF_ARN,
      SUBNETS=$SUBNET1_ID,
      SECURITY_GROUP=$SG_ID,
      EFS_FILESYSTEM_ID=$EFS_ID,
      SHARED_ROLE_ARN=$SHARED_ROLE_ARN
    }" 2>/dev/null || echo "Lambda function already exists (updating...)"

  # If function already exists, update it
  awslocal lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file "fileb://$LAMBDA_ZIP" > /dev/null 2>&1 || true

  awslocal lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --environment "Variables={
      BYPASS_OIDC_VALIDATION=true,
      ECS_CLUSTER=$ECS_CLUSTER_NAME,
      TASK_DEFINITION=$TASK_DEF_ARN,
      SUBNETS=$SUBNET1_ID,
      SECURITY_GROUP=$SG_ID,
      EFS_FILESYSTEM_ID=$EFS_ID,
      SHARED_ROLE_ARN=$SHARED_ROLE_ARN
    }" > /dev/null 2>&1 || true

  echo "Lambda function deployed: $FUNCTION_NAME"

  # Store Lambda ARN in SSM for test discovery
  LAMBDA_ARN=$(awslocal lambda get-function --function-name "$FUNCTION_NAME" --query 'Configuration.FunctionArn' --output text)
  awslocal ssm put-parameter --name /test/lambda-function-name --value "$FUNCTION_NAME" --type String --overwrite
  awslocal ssm put-parameter --name /test/lambda-function-arn --value "$LAMBDA_ARN" --type String --overwrite
else
  echo "Skipping Lambda deployment - handler not available"
fi

# Store common test parameters
awslocal ssm put-parameter --name /test/shared-role-arn --value "$SHARED_ROLE_ARN" --type String --overwrite
awslocal ssm put-parameter --name /test/ecs-cluster-name --value "$ECS_CLUSTER_NAME" --type String --overwrite
awslocal ssm put-parameter --name /test/efs-filesystem-id --value "$EFS_ID" --type String --overwrite

echo "AWS initialization complete"
