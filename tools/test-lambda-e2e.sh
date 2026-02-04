#!/bin/bash
set -euo pipefail

# End-to-End Test for Lambda (Direct Invocation)
# Full workflow: authenticate, create investigation, assume role, connect to task

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <cluster-id> <investigation-id> [oc-version]

Test the Lambda function end-to-end by invoking it directly and connecting to the task.

ARGUMENTS:
    cluster-id          Cluster identifier (e.g., rosa-boundary-dev)
    investigation-id    Investigation identifier (e.g., e2e-test-123)
    oc-version          OpenShift CLI version (default: 4.20)

EXAMPLES:
    $0 rosa-boundary-dev e2e-test-123
    $0 rosa-boundary-dev e2e-test-456 4.18

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

echo "=== Lambda End-to-End Test ===" >&2
echo "" >&2

# Save current AWS credentials
SAVED_AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
SAVED_AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
SAVED_AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"

# Unset AWS credentials temporarily
echo "Clearing AWS environment variables..." >&2
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset AWS_SECURITY_TOKEN
echo "✅ AWS credentials cleared (will be restored at exit)" >&2
echo "" >&2

# Restore credentials on exit
cleanup() {
    if [[ -n "$SAVED_AWS_ACCESS_KEY_ID" ]]; then
        export AWS_ACCESS_KEY_ID="$SAVED_AWS_ACCESS_KEY_ID"
        export AWS_SECRET_ACCESS_KEY="$SAVED_AWS_SECRET_ACCESS_KEY"
        export AWS_SESSION_TOKEN="$SAVED_AWS_SESSION_TOKEN"
    fi
}
trap cleanup EXIT

# Step 1: Get OIDC token
echo "Step 1: Authenticating with Keycloak..." >&2
OIDC_TOKEN=$("$SCRIPT_DIR/sre-auth/get-oidc-token.sh" 2>&1 | tail -1)

if [[ -z "$OIDC_TOKEN" ]] || [[ ! "$OIDC_TOKEN" =~ ^eyJ ]]; then
    echo "❌ Error: Failed to get OIDC token" >&2
    exit 1
fi

echo "✅ OIDC token obtained" >&2
echo "" >&2

# Step 2: Create Lambda event payload
echo "Step 2: Creating investigation via Lambda..." >&2
cat > /tmp/lambda-test-payload.json <<EOF
{
  "headers": {
    "authorization": "Bearer $OIDC_TOKEN",
    "content-type": "application/json"
  },
  "body": "{\"cluster_id\": \"$CLUSTER_ID\", \"investigation_id\": \"$INVESTIGATION_ID\", \"oc_version\": \"$OC_VERSION\"}"
}
EOF

echo "  Cluster: $CLUSTER_ID" >&2
echo "  Investigation: $INVESTIGATION_ID" >&2
echo "  OC Version: $OC_VERSION" >&2

# Step 3: Invoke Lambda directly
aws lambda invoke \
  --function-name rosa-boundary-dev-create-investigation \
  --cli-binary-format raw-in-base64-out \
  --payload file:///tmp/lambda-test-payload.json \
  /tmp/lambda-test-response.json >/dev/null 2>&1

# Step 4: Parse response
RESPONSE=$(cat /tmp/lambda-test-response.json)
STATUS_CODE=$(echo "$RESPONSE" | jq -r '.statusCode')

if [[ "$STATUS_CODE" != "200" ]]; then
    echo "❌ FAILED: Lambda returned status $STATUS_CODE" >&2
    echo "" >&2
    echo "Response:" >&2
    echo "$RESPONSE" | jq . >&2
    exit 1
fi

echo "✅ Investigation created!" >&2
echo "" >&2

BODY=$(echo "$RESPONSE" | jq -r '.body' | jq .)
ROLE_ARN=$(echo "$BODY" | jq -r '.role_arn')
TASK_ARN=$(echo "$BODY" | jq -r '.task_arn')
ACCESS_POINT_ID=$(echo "$BODY" | jq -r '.access_point_id')
OWNER=$(echo "$BODY" | jq -r '.owner')
TASK_ID=$(echo "$TASK_ARN" | awk -F/ '{print $NF}')

echo "=== Investigation Details ===" >&2
echo "  Owner: $OWNER" >&2
echo "  Role ARN: $ROLE_ARN" >&2
echo "  Task ID: $TASK_ID" >&2
echo "  Access Point: $ACCESS_POINT_ID" >&2
echo "" >&2

# Step 5: Assume the role
echo "Step 3: Assuming IAM role..." >&2
ASSUME_OUTPUT=$("$SCRIPT_DIR/sre-auth/assume-role.sh" --role "$ROLE_ARN" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "❌ Failed to assume role" >&2
    echo "$ASSUME_OUTPUT" >&2
    exit 1
fi

# Export credentials (filter only export lines)
eval "$(echo "$ASSUME_OUTPUT" | grep '^export ')"
echo "✅ Role assumed successfully" >&2
echo "" >&2

# Verify identity
IDENTITY=$(aws sts get-caller-identity 2>&1)
echo "Current identity:" >&2
echo "$IDENTITY" | jq . >&2
echo "" >&2

# Step 6: Wait for task to be RUNNING
echo "Step 4: Waiting for task to be RUNNING..." >&2
echo "  Task: $TASK_ID" >&2

if aws ecs wait tasks-running --cluster "$CLUSTER_ID" --tasks "$TASK_ID" 2>&1; then
    echo "✅ Task is RUNNING" >&2
else
    echo "❌ Task failed to reach RUNNING state" >&2
    echo "" >&2
    echo "Task details:" >&2
    aws ecs describe-tasks --cluster "$CLUSTER_ID" --tasks "$TASK_ID" | jq . >&2
    exit 1
fi

echo "" >&2

# Step 7: Connect to task via ECS Exec
echo "Step 5: Connecting to task via ECS Exec..." >&2
echo "  Running: aws ecs execute-command --cluster $CLUSTER_ID --task $TASK_ID --container rosa-boundary --interactive --command /bin/bash" >&2
echo "" >&2

aws ecs execute-command \
    --cluster "$CLUSTER_ID" \
    --task "$TASK_ID" \
    --container rosa-boundary \
    --interactive \
    --command /bin/bash
