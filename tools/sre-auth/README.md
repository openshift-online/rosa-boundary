# SRE OIDC Authentication Tools

CLI tools for authenticating with Keycloak and obtaining temporary AWS credentials via OIDC federation.

## Prerequisites

- `jq` - JSON processing
- `curl` - HTTP requests
- `openssl` - PKCE code generation
- `python3` - Callback server (included: callback-server.py)
- `aws` CLI - STS assume-role-with-web-identity

## Scripts

### get-oidc-token.sh

Get OIDC ID token from Keycloak using PKCE authorization code flow.

**Features:**
- Browser-based authentication
- Token caching for 4 minutes (avoids repeated browser popups)
- Returns token to stdout, messages to stderr

**Usage:**

```bash
# Get token (uses cache if valid)
TOKEN=$(./get-oidc-token.sh)

# Force fresh authentication
TOKEN=$(./get-oidc-token.sh --force)
```

**Options:**
- `--force` - Force fresh authentication (ignore cache)
- `-h, --help` - Show help message

**Token Cache:**
- Location: `~/.sre-auth/id-token.cache`
- Validity: 4 minutes (token lifetime is 5 minutes)
- Automatic expiration checking

### assume-role.sh

Assume AWS IAM role using OIDC web identity federation.

**Features:**
- Uses `get-oidc-token.sh` internally for OIDC token
- Calls AWS STS assume-role-with-web-identity
- Returns bash export statements for easy credential loading
- No AWS credential caching (AWS CLI handles this automatically)

**Usage:**

```bash
# Assume role and export credentials
eval $(./assume-role.sh --role arn:aws:iam::123456789012:role/rosa-boundary-user-abc123)

# Force fresh OIDC authentication
eval $(./assume-role.sh --role arn:aws:iam::123456789012:role/rosa-boundary-user-abc123 --force)
```

**Options:**
- `--role ARN` - AWS role ARN to assume (required)
- `--force` - Force fresh OIDC authentication (ignore token cache)
- `-h, --help` - Show help message

**Environment Variables:**
- `KEYCLOAK_URL` - Keycloak server URL (default: https://keycloak.example.com)
- `KEYCLOAK_REALM` - Keycloak realm name (default: sre-ops)
- `OIDC_CLIENT_ID` - OIDC client ID (default: aws-sre-access)

### callback-server.py

Local HTTP server for OAuth callback handling (used internally by get-oidc-token.sh).

**Do not run directly** - automatically launched by get-oidc-token.sh.

## Authentication Flow

1. User runs `assume-role.sh --role <ROLE_ARN>`
2. Script calls `get-oidc-token.sh` to obtain OIDC token
3. `get-oidc-token.sh` generates PKCE code verifier and challenge
4. Browser opens to Keycloak authorization endpoint
5. User authenticates with Keycloak
6. Keycloak redirects to `http://localhost:8400/callback` with authorization code
7. Script exchanges code for ID token (with PKCE verifier)
8. Token is cached for 4 minutes
9. `assume-role.sh` calls `aws sts assume-role-with-web-identity` with ID token
10. AWS returns temporary credentials (valid for 1 hour)
11. Credentials are output as bash export statements

## Security Features

- **PKCE (Proof Key for Code Exchange)**: Prevents authorization code interception attacks
- **State parameter**: CSRF protection for OAuth flow
- **Token caching**: Reduces authentication prompts (4 minute cache)
- **Secure file permissions**: Token cache directory set to `700`, token file to `600`
- **No client secret**: Public client with PKCE is more secure than storing secrets
- **Separated concerns**: OIDC tokens and AWS credentials handled independently

## Troubleshooting

**Browser doesn't open automatically:**
- Copy the URL from the terminal and paste into your browser manually

**"Error: No authorization code received":**
- Check that port 8400 is not in use
- Ensure Keycloak redirect URI includes `http://localhost:8400/callback`

**"Error: Failed to assume AWS role":**
- Verify the role ARN is correct
- Check that you're a member of the `sre-team` group in Keycloak
- Ensure the AWS OIDC provider trusts Keycloak
- Wait 10-15 seconds after role creation for IAM propagation

**"Error: Invalid token":**
- OIDC tokens expire after 5 minutes
- Use `--force` to get a fresh token

## Examples

### Connect to ECS task with OIDC role

```bash
# Assume role (uses cached token if <4 min old)
eval $(./assume-role.sh --role arn:aws:iam::123456789012:role/rosa-boundary-user-abc123)

# Verify identity
aws sts get-caller-identity

# Connect to ECS task
aws ecs execute-command \
  --cluster rosa-boundary-dev \
  --task 1234567890abcdef \
  --container rosa-boundary \
  --interactive \
  --command "/bin/bash" \
  --region us-east-2
```

### Use with Lambda invocation

```bash
# Get just the OIDC token for Lambda
TOKEN=$(./get-oidc-token.sh)

# Invoke Lambda with token
aws lambda invoke \
  --function-name rosa-boundary-dev-create-investigation \
  --payload "{\"headers\":{\"authorization\":\"Bearer $TOKEN\"},\"body\":\"...\"}" \
  response.json
```

### Force fresh authentication

```bash
# Clear cached token and re-authenticate
eval $(./assume-role.sh --role arn:aws:iam::123456789012:role/rosa-boundary-user-abc123 --force)
```

## Architecture

### Why Two Scripts?

**get-oidc-token.sh:**
- Single responsibility: Get OIDC ID token from Keycloak
- Caches tokens to avoid repeated browser authentication
- Can be used standalone for Lambda invocation

**assume-role.sh:**
- Single responsibility: Exchange OIDC token for AWS credentials
- Uses get-oidc-token.sh internally
- No AWS credential caching (AWS CLI does this automatically)

**Benefits:**
- Simple, focused scripts (262 lines total vs 313 in old monolithic script)
- OIDC token caching reduces browser popups
- Easier to debug and maintain
- Each script does one thing well

## Integration with Investigation Creation

See `tools/create-investigation-lambda.sh` for an example of using these scripts in a workflow:

1. Get OIDC token via `get-oidc-token.sh`
2. Invoke Lambda to create investigation (returns role ARN)
3. Assume role via `assume-role.sh`
4. Connect to ECS task with assumed credentials
