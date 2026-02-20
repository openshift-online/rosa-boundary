#!/bin/bash
set -euo pipefail

# Create Investigation via Lambda
# Wrapper for Lambda-based investigation creation with OIDC authentication

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <cluster-id> <investigation-id> [oc-version] [task-timeout]

Create a new investigation with Lambda-based authorization.

ARGUMENTS:
    cluster-id          Cluster identifier (e.g., rosa-boundary-dev)
    investigation-id    Investigation identifier (e.g., inv-12345)
    oc-version          OpenShift CLI version (default: 4.20)
    task-timeout        Task timeout in seconds (0 = no timeout, default: 3600)

ENVIRONMENT VARIABLES:
    LAMBDA_URL          Lambda function URL (optional, will fetch from Terraform)
    SRE_ROLE_ARN        Shared SRE role ARN (optional, overrides Lambda response role_arn)

EXAMPLES:
    # Create investigation with default OC version and timeout
    $0 rosa-boundary-dev inv-12345

    # Create with specific OC version
    $0 rosa-boundary-dev inv-12345 4.18

    # Create with 2-hour timeout
    $0 rosa-boundary-dev inv-12345 4.20 7200

    # Create with no timeout
    $0 rosa-boundary-dev inv-12345 4.20 0

    # Use explicit Lambda URL
    LAMBDA_URL=https://xxx.lambda-url.us-east-2.on.aws/ $0 rosa-boundary-dev inv-12345

EOF
    exit 1
}

# Parse arguments
if [[ $# -lt 2 ]]; then
    usage
fi

CLUSTER_ID="$1"
INVESTIGATION_ID="$2"
OC_VERSION="${3:-4.20}"
TASK_TIMEOUT="${4:-3600}"

# Get Lambda URL
if [[ -z "${LAMBDA_URL:-}" ]]; then
    echo "Fetching Lambda URL from Terraform..." >&2
    TERRAFORM_DIR="$SCRIPT_DIR/../deploy/regional"

    if [[ ! -f "$TERRAFORM_DIR/terraform.tfstate" ]]; then
        echo "Error: Terraform state not found at $TERRAFORM_DIR" >&2
        echo "Run 'terraform apply' first or set LAMBDA_URL environment variable" >&2
        exit 1
    fi

    LAMBDA_URL=$(cd "$TERRAFORM_DIR" && terraform output -raw lambda_function_url 2>/dev/null || echo "")

    if [[ -z "$LAMBDA_URL" ]]; then
        echo "Error: Could not get Lambda URL from Terraform outputs" >&2
        echo "Set LAMBDA_URL environment variable manually" >&2
        exit 1
    fi
fi

echo "Lambda URL: $LAMBDA_URL" >&2
echo "" >&2

# Step 1: Get OIDC token
echo "=== Step 1: Authenticating with Keycloak ===" >&2

OIDC_TOKEN=$("$SCRIPT_DIR/sre-auth/get-oidc-token.sh" 2>&1 | tail -1)

if [[ -z "$OIDC_TOKEN" ]] || [[ ! "$OIDC_TOKEN" =~ ^eyJ ]]; then
    echo "Error: Failed to get OIDC token" >&2
    exit 1
fi

echo "✅ OIDC token obtained" >&2
echo "" >&2

# Step 2: Call Lambda
echo "=== Step 2: Creating Investigation via Lambda ===" >&2
echo "Cluster: $CLUSTER_ID" >&2
echo "Investigation: $INVESTIGATION_ID" >&2
echo "OC Version: $OC_VERSION" >&2
echo "Task Timeout: $TASK_TIMEOUT seconds" >&2
echo "" >&2

REQUEST_BODY=$(jq -n \
    --arg cluster "$CLUSTER_ID" \
    --arg investigation "$INVESTIGATION_ID" \
    --arg oc_version "$OC_VERSION" \
    --argjson task_timeout "$TASK_TIMEOUT" \
    '{cluster_id: $cluster, investigation_id: $investigation, oc_version: $oc_version, task_timeout: $task_timeout}')

RESPONSE=$(curl -s -X POST "$LAMBDA_URL" \
    -H "Authorization: Bearer $OIDC_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY")

# Check for errors
if echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
    echo "❌ Lambda Error:" >&2
    echo "$RESPONSE" | jq -r '.error' >&2
    exit 1
fi

# Extract response fields
LAMBDA_ROLE_ARN=$(echo "$RESPONSE" | jq -r '.role_arn')
TASK_ARN=$(echo "$RESPONSE" | jq -r '.task_arn')
CLUSTER=$(echo "$RESPONSE" | jq -r '.cluster_id')
ACCESS_POINT_ID=$(echo "$RESPONSE" | jq -r '.access_point_id')

if [[ -z "$TASK_ARN" ]] || [[ "$TASK_ARN" == "null" ]]; then
    echo "❌ Error: Invalid response from Lambda" >&2
    echo "$RESPONSE" | jq '.' >&2
    exit 1
fi

# Use SRE_ROLE_ARN env var if set, otherwise use role_arn from Lambda response
ROLE_ARN="${SRE_ROLE_ARN:-$LAMBDA_ROLE_ARN}"

if [[ -z "$ROLE_ARN" ]] || [[ "$ROLE_ARN" == "null" ]]; then
    echo "❌ Error: No role ARN available (set SRE_ROLE_ARN or ensure Lambda returns role_arn)" >&2
    exit 1
fi

echo "✅ Investigation created successfully!" >&2
echo "" >&2

# Step 3: Assume shared SRE role with OIDC session tags
# Session tags from the JWT https://aws.amazon.com/tags claim propagate automatically,
# enabling ABAC isolation (ecs:ResourceTag/username == ${aws:PrincipalTag/username}).
echo "=== Step 3: Assuming Shared SRE Role ===" >&2
echo "Role: $ROLE_ARN" >&2
echo "" >&2

ASSUME_OUTPUT=$("$SCRIPT_DIR/sre-auth/assume-role.sh" --role "$ROLE_ARN" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "❌ Error: Failed to assume role" >&2
    echo "$ASSUME_OUTPUT" >&2
    exit 1
fi

eval $(echo "$ASSUME_OUTPUT" | grep "^export")

echo "✅ Role assumed successfully" >&2
echo "" >&2

# Step 4: Wait for task to be running
TASK_ID=$(basename "$TASK_ARN")

echo "=== Step 4: Waiting for Task ===" >&2
echo "Task: $TASK_ID" >&2
echo "" >&2

echo "Waiting for task to be RUNNING..." >&2
aws ecs wait tasks-running --cluster "$CLUSTER" --tasks "$TASK_ID" --region us-east-2

if [[ $? -ne 0 ]]; then
    echo "⚠️  Warning: Task may not be running yet" >&2
else
    echo "✅ Task is running" >&2
fi

TIMEOUT=$(echo "$RESPONSE" | jq -r '.task_timeout // "3600"')

echo "" >&2
echo "========================================" >&2
echo "Investigation Created Successfully! 🎉" >&2
echo "========================================" >&2
echo "" >&2
echo "Investigation Details:" >&2
echo "  Cluster:        $CLUSTER" >&2
echo "  Investigation:  $INVESTIGATION_ID" >&2
echo "  Task:           $TASK_ID" >&2
echo "  OC Version:     $OC_VERSION" >&2
echo "  Task Timeout:   $TIMEOUT seconds" >&2
echo "  EFS Access Pt:  $ACCESS_POINT_ID" >&2
echo "  Your Role:      $ROLE_ARN" >&2
echo "" >&2
echo "Connect to task:" >&2
echo "  aws ecs execute-command \\" >&2
echo "    --cluster $CLUSTER \\" >&2
echo "    --task $TASK_ID \\" >&2
echo "    --container rosa-boundary \\" >&2
echo "    --interactive \\" >&2
echo "    --command /bin/bash \\" >&2
echo "    --region us-east-2" >&2
echo "" >&2
echo "Or use the join helper:" >&2
echo "  ./join-investigation.sh $TASK_ID" >&2
