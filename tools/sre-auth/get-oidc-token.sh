#!/bin/bash
set -euo pipefail

# Get OIDC ID Token from Keycloak using PKCE flow
# Caches token for 4 minutes to avoid repeated browser authentication

# Load environment configuration if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ -f "$REPO_ROOT/.env" ]]; then
    source "$REPO_ROOT/.env"
fi

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-https://keycloak.example.com}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-sre-ops}"
CLIENT_ID="${OIDC_CLIENT_ID:-aws-sre-access}"
REDIRECT_URI="http://localhost:8400/callback"
TOKEN_CACHE_DIR="${HOME}/.sre-auth"
TOKEN_CACHE_FILE="${TOKEN_CACHE_DIR}/id-token.cache"
CACHE_VALIDITY_SECONDS=240  # 4 minutes (token lifetime is 5 minutes)

# OIDC endpoints
ISSUER_URL="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}"
AUTH_ENDPOINT="${ISSUER_URL}/protocol/openid-connect/auth"
TOKEN_ENDPOINT="${ISSUER_URL}/protocol/openid-connect/token"

# Parse arguments
FORCE_REFRESH=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_REFRESH=true
            shift
            ;;
        -h|--help)
            cat <<EOF >&2
Usage: $0 [--force]

Get OIDC ID token from Keycloak using PKCE flow.
Token is cached for 4 minutes to avoid repeated browser authentication.

OPTIONS:
    --force     Force fresh authentication (ignore cache)
    -h, --help  Show this help message

EXAMPLES:
    # Get token (uses cache if valid)
    TOKEN=\$($0)

    # Force fresh authentication
    TOKEN=\$($0 --force)

OUTPUT:
    OIDC ID token is written to stdout
    Status messages are written to stderr
EOF
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Create cache directory
mkdir -p "$TOKEN_CACHE_DIR"
chmod 700 "$TOKEN_CACHE_DIR"

# Check cached token
if [[ -f "$TOKEN_CACHE_FILE" ]] && [[ "$FORCE_REFRESH" == "false" ]]; then
    CACHE_AGE_SECONDS=$(($(date +%s) - $(stat -f %m "$TOKEN_CACHE_FILE" 2>/dev/null || echo 0)))

    if [[ $CACHE_AGE_SECONDS -lt $CACHE_VALIDITY_SECONDS ]]; then
        REMAINING=$((CACHE_VALIDITY_SECONDS - CACHE_AGE_SECONDS))
        echo "Using cached token ($REMAINING seconds remaining)" >&2
        cat "$TOKEN_CACHE_FILE"
        exit 0
    else
        echo "Cached token expired, authenticating..." >&2
    fi
else
    echo "No cached token, authenticating..." >&2
fi

# Generate PKCE code verifier and challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')

# Generate random state
STATE=$(openssl rand -hex 16)

# Build authorization URL
AUTH_URL="${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid%20profile%20email&state=${STATE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

# Start local callback server
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALLBACK_FILE=$(mktemp)

echo "Starting local callback server on port 8400..." >&2
"$SCRIPT_DIR/callback-server.py" "$CALLBACK_FILE" &
CALLBACK_PID=$!

# Give server time to start
sleep 1

echo "Opening browser for authentication..." >&2

# Open browser
if command -v open &>/dev/null; then
    open "$AUTH_URL"
elif command -v xdg-open &>/dev/null; then
    xdg-open "$AUTH_URL"
else
    echo "Please open the following URL in your browser:" >&2
    echo "$AUTH_URL" >&2
fi

# Wait for callback (timeout 120 seconds)
WAIT_COUNT=0
while kill -0 $CALLBACK_PID 2>/dev/null && [ $WAIT_COUNT -lt 120 ]; do
    sleep 1
    ((WAIT_COUNT++))
    if [ -s "$CALLBACK_FILE" ]; then
        break
    fi
done

# Kill callback server if still running
kill $CALLBACK_PID 2>/dev/null || true
wait $CALLBACK_PID 2>/dev/null || true

# Read callback result
if [ ! -f "$CALLBACK_FILE" ]; then
    echo "Error: Callback failed" >&2
    exit 1
fi

CALLBACK_OUTPUT=$(cat "$CALLBACK_FILE")
rm -f "$CALLBACK_FILE"

# Parse callback output
CODE=$(echo "$CALLBACK_OUTPUT" | sed -n '1p')
RETURNED_STATE=$(echo "$CALLBACK_OUTPUT" | sed -n '2p')

if [[ -z "$CODE" ]]; then
    echo "Error: No authorization code received" >&2
    exit 1
fi

# Validate state (CSRF protection)
if [[ "$RETURNED_STATE" != "$STATE" ]]; then
    echo "Error: State mismatch (CSRF protection)" >&2
    exit 1
fi

echo "Authorization code received, exchanging for token..." >&2

# Exchange authorization code for tokens
TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "code=$CODE" \
    -d "redirect_uri=$REDIRECT_URI" \
    -d "client_id=$CLIENT_ID" \
    -d "code_verifier=$CODE_VERIFIER")

ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token // empty')
if [[ -z "$ID_TOKEN" ]]; then
    echo "Error: Failed to obtain ID token" >&2
    echo "Response: $TOKEN_RESPONSE" >&2
    exit 1
fi

# Cache the token
echo "$ID_TOKEN" > "$TOKEN_CACHE_FILE"
chmod 600 "$TOKEN_CACHE_FILE"

echo "ID token obtained successfully" >&2

# Output token to stdout
echo "$ID_TOKEN"
