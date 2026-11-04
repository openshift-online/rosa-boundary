#!/bin/bash
# Helper script to get VPC and subnet information for terraform.tfvars

PROFILE="${AWS_PROFILE:-scuppett-dev}"
REGION="${AWS_REGION:-us-east-2}"

echo "Getting VPC information for profile: $PROFILE in region: $REGION"
echo ""

# Get VPCs
echo "=== Available VPCs ==="
aws ec2 describe-vpcs \
    --profile "$PROFILE" \
    --region "$REGION" \
    --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[0],CidrBlock,IsDefault]' \
    --output table

echo ""
read -r -p "Enter VPC ID to use: " VPC_ID

# Get subnets in the selected VPC
echo ""
echo "=== Subnets in $VPC_ID ==="
aws ec2 describe-subnets \
    --profile "$PROFILE" \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,Tags[?Key==`Name`].Value|[0]]' \
    --output table

echo ""
echo "Select at least 2 subnets (preferably in different AZs)"

# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query 'Account' --output text)

echo ""
echo "=== Configuration Summary ==="
echo "AWS Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
echo "VPC ID: $VPC_ID"
echo ""
echo "Update terraform.tfvars with:"
echo "  vpc_id = \"$VPC_ID\""
echo "  subnet_ids = [\"subnet-xxx\", \"subnet-yyy\"]"
