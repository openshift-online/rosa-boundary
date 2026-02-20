#!/bin/bash
set -euo pipefail

# Verify OIDC token claims and ABAC session tag propagation.
#
# Tests:
#   1. JWT claim check  – https://aws.amazon.com/tags has principal_tags.username
#                         (not sub) and transitive_tag_keys includes username
#   2. Role assumption  – assume-role-with-web-identity succeeds with the token,
#                         proving sts:TagSession flows through correctly
#   3. ABAC simulation  – iam:SimulatePrincipalPolicy confirms the shared role's
#                         ExecuteCommandOnOwnedTasks statement allows access to a
#                         resource tagged username=<our-username> and denies access
#                         to a resource tagged with a different username

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load .env for KEYCLOAK_* and SRE_ROLE_ARN
if [[ -f "$REPO_ROOT/.env" ]]; then
    source "$REPO_ROOT/.env"
fi

REGION="${AWS_REGION:-us-east-2}"
FORCE_REFRESH=false

usage() {
    cat <<EOF >&2
Usage: $0 [--role <role-arn>] [--force]

Verify OIDC token claims and ABAC session tag propagation.

OPTIONS:
    --role ARN   Shared SRE role ARN (or set SRE_ROLE_ARN in .env)
    --force      Force fresh OIDC authentication
    -h, --help   Show this help

ENVIRONMENT VARIABLES:
    SRE_ROLE_ARN   Shared SRE role ARN (fallback when --role is not provided)
    AWS_REGION     AWS region (default: us-east-2)
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --role) ROLE_ARN="$2"; shift 2 ;;
        --force) FORCE_REFRESH=true; shift ;;
        -h|--help) usage ;;
        *) echo "Error: Unknown option: $1" >&2; usage ;;
    esac
done

ROLE_ARN="${ROLE_ARN:-${SRE_ROLE_ARN:-}}"
if [[ -z "$ROLE_ARN" ]]; then
    echo "Error: shared SRE role ARN required via --role or SRE_ROLE_ARN in .env" >&2
    usage
fi

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Obtain OIDC token
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Step 1: Obtaining OIDC token ==="

OIDC_ARGS=""
if [[ "$FORCE_REFRESH" == "true" ]]; then
    OIDC_ARGS="--force"
fi

TOKEN=$("$SCRIPT_DIR/sre-auth/get-oidc-token.sh" $OIDC_ARGS)

if [[ -z "$TOKEN" ]] || [[ ! "$TOKEN" =~ ^eyJ ]]; then
    echo "Error: Failed to obtain OIDC token" >&2
    exit 1
fi
echo "  Token obtained (${#TOKEN} bytes)"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Decode JWT and verify claims
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Step 2: Verifying JWT claims ==="

# Decode JWT payload (base64url → base64 → JSON)
PAYLOAD_B64=$(echo "$TOKEN" | cut -d'.' -f2)
# Pad to a multiple of 4 and convert base64url to standard base64
PADDING=$(( 4 - ${#PAYLOAD_B64} % 4 ))
if [[ $PADDING -lt 4 ]]; then
    PAYLOAD_B64="${PAYLOAD_B64}$(printf '=%.0s' $(seq 1 $PADDING))"
fi
PAYLOAD=$(echo "$PAYLOAD_B64" | tr '_-' '/+' | base64 -d 2>/dev/null)

if [[ -z "$PAYLOAD" ]]; then
    echo "Error: Failed to decode JWT payload" >&2
    exit 1
fi

echo "  JWT payload:"
echo "$PAYLOAD" | jq --indent 2 '{
    sub,
    preferred_username,
    email,
    groups,
    aws_tags: ."https://aws.amazon.com/tags"
}' | sed 's/^/    /'

# Extract the AWS tags claim
AWS_TAGS=$(echo "$PAYLOAD" | jq -r '."https://aws.amazon.com/tags" // empty')

if [[ -z "$AWS_TAGS" ]]; then
    fail "https://aws.amazon.com/tags claim missing from token"
else
    pass "https://aws.amazon.com/tags claim is present"

    # Check transitive_tag_keys includes 'username' (not 'sub')
    TRANSITIVE=$(echo "$AWS_TAGS" | jq -r '.transitive_tag_keys[]? // empty')
    if echo "$TRANSITIVE" | grep -q '^username$'; then
        pass "transitive_tag_keys includes 'username'"
    else
        fail "transitive_tag_keys does not include 'username' (got: $(echo "$TRANSITIVE" | tr '\n' ' '))"
    fi

    if echo "$TRANSITIVE" | grep -q '^sub$'; then
        fail "transitive_tag_keys still contains old 'sub' key — Keycloak mapper not updated"
    else
        pass "transitive_tag_keys does not contain old 'sub' key"
    fi

    # Check principal_tags.username is present and non-empty
    USERNAME_TAG=$(echo "$AWS_TAGS" | jq -r '.principal_tags.username[0] // empty')
    if [[ -n "$USERNAME_TAG" ]]; then
        pass "principal_tags.username is present: '$USERNAME_TAG'"
    else
        fail "principal_tags.username missing or empty"
    fi

    # Check principal_tags.sub is gone
    SUB_TAG=$(echo "$AWS_TAGS" | jq -r '.principal_tags.sub[0] // empty')
    if [[ -z "$SUB_TAG" ]]; then
        pass "principal_tags.sub is absent (old mapping removed)"
    else
        fail "principal_tags.sub still present ('$SUB_TAG') — Keycloak mapper not updated"
    fi

    # Cross-check username tag matches preferred_username claim
    PREFERRED=$(echo "$PAYLOAD" | jq -r '.preferred_username // empty')
    if [[ -n "$PREFERRED" ]] && [[ "$USERNAME_TAG" == "$PREFERRED" ]]; then
        pass "principal_tags.username matches preferred_username ('$PREFERRED')"
    elif [[ -n "$PREFERRED" ]]; then
        fail "principal_tags.username ('$USERNAME_TAG') != preferred_username ('$PREFERRED')"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Assume shared SRE role with the OIDC token
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Step 3: Assuming shared SRE role ==="
echo "  Role: $ROLE_ARN"

ASSUME_OUTPUT=$(aws sts assume-role-with-web-identity \
    --role-arn "$ROLE_ARN" \
    --role-session-name "verify-abac-$(date +%s)" \
    --web-identity-token "$TOKEN" \
    --duration-seconds 900 \
    --region "$REGION" \
    --output json 2>&1) || {
    fail "assume-role-with-web-identity failed: $ASSUME_OUTPUT"
    echo ""
    echo "=== Summary: $PASS passed, $FAIL failed ==="
    exit 1
}

SESSION_IDENTITY=$(echo "$ASSUME_OUTPUT" | jq -r '.AssumedRoleUser.Arn')
pass "Role assumed successfully: $SESSION_IDENTITY"

# Verify credentials work — use the assumed session credentials just for GetCallerIdentity,
# then restore originals so Step 4 can call iam:SimulatePrincipalPolicy (which requires
# IAM read permissions that the SRE role doesn't have).
ORIG_KEY="${AWS_ACCESS_KEY_ID:-}"
ORIG_SECRET="${AWS_SECRET_ACCESS_KEY:-}"
ORIG_TOKEN="${AWS_SESSION_TOKEN:-}"

export AWS_ACCESS_KEY_ID=$(echo "$ASSUME_OUTPUT" | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$ASSUME_OUTPUT" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$ASSUME_OUTPUT" | jq -r '.Credentials.SessionToken')

CALLER=$(aws sts get-caller-identity --region "$REGION" --output json)
pass "GetCallerIdentity: $(echo "$CALLER" | jq -r '.UserId') / $(echo "$CALLER" | jq -r '.Account')"

# Restore original credentials for the simulation step
export AWS_ACCESS_KEY_ID="$ORIG_KEY"
export AWS_SECRET_ACCESS_KEY="$ORIG_SECRET"
export AWS_SESSION_TOKEN="$ORIG_TOKEN"

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Simulate ABAC policy with iam:SimulatePrincipalPolicy
# (uses caller's credentials — the SRE role itself lacks iam:Simulate*)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Step 4: Simulating ABAC policy ==="

# Use the role ARN (not the session ARN) as the policy source
ASSUMED_ROLE_ARN="$ROLE_ARN"
ACCOUNT_ID=$(echo "$ROLE_ARN" | cut -d: -f5)
OWN_USERNAME="$USERNAME_TAG"
OTHER_USERNAME="someone-else"

# Simulate resource we own (username matches our session tag)
OWN_TASK_ARN="arn:aws:ecs:${REGION}:${ACCOUNT_ID}:task/rosa-boundary-dev/simulate-own-task"
OTHER_TASK_ARN="arn:aws:ecs:${REGION}:${ACCOUNT_ID}:task/rosa-boundary-dev/simulate-other-task"

echo "  Simulating as: $ASSUMED_ROLE_ARN"
echo "  Our username tag: $OWN_USERNAME"

# Allow on own resource
SIM_OWN=$(aws iam simulate-principal-policy \
    --policy-source-arn "$ASSUMED_ROLE_ARN" \
    --action-names "ecs:ExecuteCommand" \
    --resource-arns "$OWN_TASK_ARN" \
    --context-entries \
        "ContextKeyName=aws:PrincipalTag/username,ContextKeyValues=$OWN_USERNAME,ContextKeyType=string" \
        "ContextKeyName=ecs:ResourceTag/username,ContextKeyValues=$OWN_USERNAME,ContextKeyType=string" \
    --region "$REGION" \
    --output json 2>/dev/null)

OWN_DECISION=$(echo "$SIM_OWN" | jq -r '.EvaluationResults[0].EvalDecision // "error"')
if [[ "$OWN_DECISION" == "allowed" ]]; then
    pass "ExecuteCommand ALLOWED on own task (username='$OWN_USERNAME' matches)"
else
    fail "ExecuteCommand should be ALLOWED on own task but got: $OWN_DECISION"
    echo "$SIM_OWN" | jq '.EvaluationResults[0].MatchedStatements' | sed 's/^/    /'
fi

# Deny on other user's resource
SIM_OTHER=$(aws iam simulate-principal-policy \
    --policy-source-arn "$ASSUMED_ROLE_ARN" \
    --action-names "ecs:ExecuteCommand" \
    --resource-arns "$OTHER_TASK_ARN" \
    --context-entries \
        "ContextKeyName=aws:PrincipalTag/username,ContextKeyValues=$OWN_USERNAME,ContextKeyType=string" \
        "ContextKeyName=ecs:ResourceTag/username,ContextKeyValues=$OTHER_USERNAME,ContextKeyType=string" \
    --region "$REGION" \
    --output json 2>/dev/null)

OTHER_DECISION=$(echo "$SIM_OTHER" | jq -r '.EvaluationResults[0].EvalDecision // "error"')
if [[ "$OTHER_DECISION" == "implicitDeny" ]] || [[ "$OTHER_DECISION" == "explicitDeny" ]]; then
    pass "ExecuteCommand DENIED on other user's task (username='$OTHER_USERNAME' != '$OWN_USERNAME')"
else
    fail "ExecuteCommand should be DENIED on other user's task but got: $OTHER_DECISION"
fi

# Deny on untagged resource (missing username tag — fail-closed)
SIM_UNTAGGED=$(aws iam simulate-principal-policy \
    --policy-source-arn "$ASSUMED_ROLE_ARN" \
    --action-names "ecs:ExecuteCommand" \
    --resource-arns "$OWN_TASK_ARN" \
    --context-entries \
        "ContextKeyName=aws:PrincipalTag/username,ContextKeyValues=$OWN_USERNAME,ContextKeyType=string" \
    --region "$REGION" \
    --output json 2>/dev/null)

UNTAGGED_DECISION=$(echo "$SIM_UNTAGGED" | jq -r '.EvaluationResults[0].EvalDecision // "error"')
if [[ "$UNTAGGED_DECISION" == "implicitDeny" ]] || [[ "$UNTAGGED_DECISION" == "explicitDeny" ]]; then
    pass "ExecuteCommand DENIED on task with no username tag (fail-closed)"
else
    fail "ExecuteCommand should be DENIED on untagged task but got: $UNTAGGED_DECISION"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo "All checks passed. ABAC with username session tag is working correctly."
    exit 0
else
    echo "Some checks failed. See above for details."
    exit 1
fi
