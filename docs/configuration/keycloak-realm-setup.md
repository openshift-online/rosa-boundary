# Keycloak Realm Setup

## Overview

Configure a Keycloak realm for AWS Lambda OIDC authentication using the `KeycloakRealmImport` custom resource. RHBK v26 does not support declarative client/user/group CRs - all configuration must be provided as a complete realm JSON export.

## Prerequisites

- Keycloak instance deployed (see `deploy/keycloak/`)
- Keycloak admin credentials

## Realm Structure

```
rosa-boundary (realm)
├── Clients
│   └── aws-sre-access (OIDC client)
│       ├── Redirect URIs
│       ├── Protocol Mappers
│       └── Client Secret
├── Groups
│   ├── sre-admins
│   ├── sre-operators
│   └── sre-viewers
├── Roles
│   ├── boundary-admin
│   └── boundary-user
└── Users
    └── (managed via external IdP or manual)
```

## KeycloakRealmImport Custom Resource

Create `deploy/keycloak/components/keycloak/realm-import-boundary.yaml`:

```yaml
apiVersion: k8s.keycloak.org/v2alpha1
kind: KeycloakRealmImport
metadata:
  name: boundary-realm
  namespace: keycloak
spec:
  keycloakCRName: keycloak
  realm:
    id: rosa-boundary
    realm: rosa-boundary
    enabled: true
    displayName: "ROSA Boundary Access"
    loginTheme: "keycloak"

    # OIDC Client for AWS SRE Access
    clients:
      - clientId: aws-sre-access
        name: "AWS SRE Access"
        enabled: true
        protocol: openid-connect
        publicClient: true
        standardFlowEnabled: true
        directAccessGrantsEnabled: false
        serviceAccountsEnabled: false
        implicitFlowEnabled: false

        # Redirect URIs for PKCE flow
        redirectUris:
          - "http://localhost:8400/callback"
          - "http://127.0.0.1:8400/callback"

        webOrigins:
          - "+"

        # Access settings
        fullScopeAllowed: true
        consentRequired: false

        attributes:
          "access.token.lifespan": "3600"
          "client.secret.creation.time": "1704301200"

        # Protocol mappers for OIDC claims
        protocolMappers:
          # Groups claim mapper
          - name: groups
            protocol: openid-connect
            protocolMapper: oidc-group-membership-mapper
            consentRequired: false
            config:
              full.path: "false"
              id.token.claim: "true"
              access.token.claim: "true"
              claim.name: "groups"
              userinfo.token.claim: "true"

          # Email mapper
          - name: email
            protocol: openid-connect
            protocolMapper: oidc-usermodel-property-mapper
            consentRequired: false
            config:
              user.attribute: "email"
              id.token.claim: "true"
              access.token.claim: "true"
              claim.name: "email"
              userinfo.token.claim: "true"
              jsonType.label: "String"

          # Name mapper
          - name: name
            protocol: openid-connect
            protocolMapper: oidc-usermodel-property-mapper
            consentRequired: false
            config:
              user.attribute: "name"
              id.token.claim: "true"
              access.token.claim: "true"
              claim.name: "name"
              userinfo.token.claim: "true"
              jsonType.label: "String"

          # Audience mapper
          - name: audience
            protocol: openid-connect
            protocolMapper: oidc-audience-mapper
            consentRequired: false
            config:
              included.client.audience: "aws-sre-access"
              id.token.claim: "true"
              access.token.claim: "true"

    # User groups for RBAC
    groups:
      - name: sre-admins
        path: /sre-admins
        attributes:
          description: ["Full administrator access to all rosa-boundary targets"]
        realmRoles: []
        clientRoles: {}
        subGroups: []

      - name: sre-operators
        path: /sre-operators
        attributes:
          description: ["Standard operator access to assigned incidents"]
        realmRoles: []
        clientRoles: {}
        subGroups: []

      - name: sre-viewers
        path: /sre-viewers
        attributes:
          description: ["Read-only access for audit and review"]
        realmRoles: []
        clientRoles: {}
        subGroups: []

    # Realm roles (optional, can also use groups)
    roles:
      realm:
        - name: sre-admin
          description: "SRE administrator with full access"
          composite: false
          clientRole: false

        - name: sre-user
          description: "SRE standard user"
          composite: false
          clientRole: false

    # Token settings
    accessTokenLifespan: 3600
    accessTokenLifespanForImplicitFlow: 900
    ssoSessionIdleTimeout: 1800
    ssoSessionMaxLifespan: 36000

    # Security settings
    bruteForceProtected: true
    failureFactor: 5
    waitIncrementSeconds: 60
    maxFailureWaitSeconds: 900
```

## Deploying the Realm

### 1. Add to Kustomize

Edit `deploy/keycloak/components/keycloak/kustomization.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1alpha1
kind: Component
resources:
  - keycloak.yaml
  - route.yaml
  - realm-import-boundary.yaml  # Add this line
```

### 2. Apply the configuration

```bash
oc apply -k deploy/keycloak/overlays/dev
```

### 3. Verify realm import

```bash
# Check import status
oc get keycloakrealmimport boundary-realm -n keycloak

# Get realm details via API
KEYCLOAK_URL="https://$(oc get route keycloak -n keycloak -o jsonpath='{.spec.host}')"
ADMIN_USER=$(oc get secret keycloak-initial-admin -n keycloak -o jsonpath='{.data.username}' | base64 -d)
ADMIN_PASS=$(oc get secret keycloak-initial-admin -n keycloak -o jsonpath='{.data.password}' | base64 -d)

# Get admin token
TOKEN=$(curl -sk -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" | jq -r '.access_token')

# Verify realm exists
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary" | jq '.realm'

# Verify client exists
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary/clients" | jq '.[] | select(.clientId=="aws-sre-access")'
```

## Creating Users and Group Assignments

### Option A: Via Keycloak Admin Console

1. Navigate to `https://<keycloak-route>/admin/master/console/#/rosa-boundary`
2. Go to Users → Add User
3. Set username, email, and other attributes
4. Go to Credentials tab → Set password
5. Go to Groups tab → Join `sre-operators` or `sre-admins`

### Option B: Via API

```bash
# Create user
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary/users" \
  -d '{
    "username": "jane.doe",
    "email": "jane.doe@example.com",
    "emailVerified": true,
    "enabled": true,
    "credentials": [{
      "type": "password",
      "value": "temporary-password",
      "temporary": true
    }]
  }'

# Get user ID
USER_ID=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary/users?username=jane.doe" | jq -r '.[0].id')

# Get group ID
GROUP_ID=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary/groups" | jq -r '.[] | select(.name=="sre-operators") | .id')

# Add user to group
curl -sk -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary/users/$USER_ID/groups/$GROUP_ID"
```

## OIDC Discovery Endpoints

Keycloak publishes OIDC metadata at:

```
https://<keycloak-route>/realms/rosa-boundary/.well-known/openid-configuration
```

**Key endpoints:**
- `authorization_endpoint`: `/realms/rosa-boundary/protocol/openid-connect/auth`
- `token_endpoint`: `/realms/rosa-boundary/protocol/openid-connect/token`
- `userinfo_endpoint`: `/realms/rosa-boundary/protocol/openid-connect/userinfo`
- `jwks_uri`: `/realms/rosa-boundary/protocol/openid-connect/certs`

Boundary uses these endpoints automatically when configured with the `issuer` URL.

## Testing OIDC Configuration

### Test token issuance with PKCE

Use the `tools/sre-auth/get-oidc-token.sh` script to test PKCE authentication:

```bash
cd tools/sre-auth
./get-oidc-token.sh
```

This will:
1. Start local callback server on port 8400
2. Open browser for authentication
3. Exchange code for token using PKCE
4. Return ID token to stdout

### Validate ID token claims

```bash
# Decode ID token (after obtaining from above)
echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

# Expected claims:
# {
#   "iss": "https://<keycloak>/realms/rosa-boundary",
#   "sub": "<user-uuid>",
#   "aud": "aws-sre-access",
#   "email": "user@example.com",
#   "name": "Jane Doe",
#   "groups": ["sre-operators"]
# }
```

## Updating the Realm

To update realm configuration:

1. Edit `realm-import-boundary.yaml`
2. Reapply: `oc apply -k deploy/keycloak/overlays/dev`
3. KeycloakRealmImport controller will update the realm

**Note**: Some changes require deleting and recreating the `KeycloakRealmImport` resource.

## Exporting Current Realm Configuration

To export the current realm state for backup or migration:

```bash
# Get admin token (as shown above)
TOKEN="<admin-token>"

# Export full realm configuration
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/rosa-boundary" > rosa-boundary-export.json

# Pretty print
jq '.' rosa-boundary-export.json > realm-import-boundary.json
```

This export can be used as the base for your `KeycloakRealmImport` CR.

## Security Best Practices

1. **PKCE Flow**:
   - Public client with PKCE protects against authorization code interception
   - Code verifier generated client-side, code challenge sent to authorization endpoint
   - No client secret needed (eliminates secret storage concerns)

2. **Token Lifespans**:
   - Access token: 3600s (1 hour)
   - SSO session idle: 1800s (30 minutes)
   - SSO session max: 36000s (10 hours)

3. **Brute Force Protection**:
   - Enabled by default
   - 5 failures before lockout
   - Exponential backoff up to 900s (15 minutes)

4. **TLS**:
   - Keycloak Route uses edge termination
   - OpenShift Router handles TLS
   - Ensure valid certificate for production

## Next Steps

- [AWS IAM Policies](aws-iam-policies.md) - Set up AWS permissions for users
- [User Access Guide](../runbooks/user-access-guide.md) - End-user authentication workflow
