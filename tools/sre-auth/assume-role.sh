#!/bin/bash
set -euo pipefail

# Assume AWS IAM role using OIDC web identity token
# Uses get-oidc-token.sh to obtain the ID token

# Parse arguments
ROLE_ARN=""
FORCE_REFRESH=false

usage() {
    cat <<EOF >&2
Usage: $0 [--role <role-arn>] [--force]

Assume AWS IAM role using OIDC web identity federation.
Uses get-oidc-token.sh to obtain Keycloak ID token.

OPTIONS:
    --role ARN      AWS role ARN to assume (optional if SRE_ROLE_ARN is set)
    --force         Force fresh OIDC authentication (ignore token cache)
    -h, --help      Show this help message

ENVIRONMENT VARIABLES:
    SRE_ROLE_ARN    Shared SRE role ARN (fallback when --role is not provided)

EXAMPLES:
    # Assume shared role via env var
    eval \$(SRE_ROLE_ARN=arn:aws:iam::123456789012:role/rosa-boundary-dev-sre-shared $0)

    # Assume specific role
    eval \$($0 --role arn:aws:iam::123456789012:role/rosa-boundary-dev-sre-shared)

    # Force fresh authentication
    eval \$($0 --force)

OUTPUT:
    Bash export statements for AWS credentials (stdout)
    Status messages (stderr)
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --role)
            ROLE_ARN="$2"
            shift 2
            ;;
        --force)
            FORCE_REFRESH=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            usage
            ;;
    esac
done

if [[ -z "$ROLE_ARN" ]]; then
    ROLE_ARN="${SRE_ROLE_ARN:-}"
fi

if [[ -z "$ROLE_ARN" ]]; then
    echo "Error: role ARN required via --role or SRE_ROLE_ARN environment variable" >&2
    usage
fi

# Get OIDC token
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$FORCE_REFRESH" == "true" ]]; then
    ID_TOKEN=$("$SCRIPT_DIR/get-oidc-token.sh" --force)
else
    ID_TOKEN=$("$SCRIPT_DIR/get-oidc-token.sh")
fi

if [[ -z "$ID_TOKEN" ]]; then
    echo "Error: Failed to obtain OIDC token" >&2
    exit 1
fi

echo "Assuming AWS role..." >&2

# Assume role with web identity
AWS_CREDS=$(aws sts assume-role-with-web-identity \
    --role-arn "$ROLE_ARN" \
    --role-session-name "sre-oidc-$(date +%s)" \
    --web-identity-token "$ID_TOKEN" \
    --duration-seconds 3600 \
    --region us-east-2 \
    --output json 2>&1)

if [[ $? -ne 0 ]]; then
    echo "Error: Failed to assume AWS role" >&2
    echo "$AWS_CREDS" >&2
    exit 1
fi

echo "AWS credentials obtained successfully" >&2

# Extract credentials and output export statements
ACCESS_KEY=$(echo "$AWS_CREDS" | jq -r '.Credentials.AccessKeyId')
SECRET_KEY=$(echo "$AWS_CREDS" | jq -r '.Credentials.SecretAccessKey')
SESSION_TOKEN=$(echo "$AWS_CREDS" | jq -r '.Credentials.SessionToken')
EXPIRATION=$(echo "$AWS_CREDS" | jq -r '.Credentials.Expiration')

echo "Credentials expire at: $EXPIRATION" >&2

# Output export statements to stdout
echo "export AWS_ACCESS_KEY_ID='$ACCESS_KEY'"
echo "export AWS_SECRET_ACCESS_KEY='$SECRET_KEY'"
echo "export AWS_SESSION_TOKEN='$SESSION_TOKEN'"
