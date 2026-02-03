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

echo "AWS initialization complete"
