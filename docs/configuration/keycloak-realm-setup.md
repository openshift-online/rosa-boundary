# Keycloak Realm Setup for Development

Use this guide to configure an approved, already-running Keycloak instance for a
personal Boundary development environment. Boundary does not deploy Keycloak.
Staging and production use Red Hat EmployeeIDP; this guide is not a procedure
for changing those realms.

## Create a realm and client

In the Keycloak Admin Console, create a development realm (for example,
`rosa-boundary`) and an OpenID Connect client (for example, `rosa-boundary-sre`).
Use the actual realm and client IDs when configuring Boundary.

- Turn **Client authentication** off to make the client public.
- Enable **Standard flow** (authorization code) and require PKCE with `S256`.
- Set **Valid redirect URIs** to `http://localhost:8400/callback` for the CLI's
  browser flow. Do not use a wildcard redirect.
- Leave implicit flow and direct access grants disabled. Enable the OAuth 2.0
  Device Authorization Grant only if this deployment uses the CLI's device flow.

If your development instance is operator-managed, you can use the equivalent
settings in a `KeycloakRealmImport` for a new realm. Keep the import manifest
with the configuration for that instance and follow its operator's instructions;
use the Admin Console or the instance's management workflow for existing realms.

## Configure ID token claims

Configure client scopes and protocol mappers so the following values are
included in the **ID token**:

| Claim | Development configuration |
| --- | --- |
| `aud` | Include the Boundary client ID; use an audience mapper if it is not already present. |
| `groups` or `realm_access.roles` | Include the group or realm role the regional deployment expects in `required_groups`. If using a group membership mapper with short group names, disable **Full group path**. |
| `https://aws.amazon.com/tags` | Include `principal_tags` with the configured `abac_tag_key` and the caller's identity value. For example, a deployment using `username` requires `{"principal_tags":{"username":["jane.doe"]}}`. Use an identity-specific value, not a constant shared by users. |
| `https://aws.amazon.com/tags` (when IAM role enforcement is enabled) | Also include the authorized caller's role as the single value in `principal_tags.roles`, matching `required_oidc_role`. This is separate from the group or realm-role claim Lambda checks. |

Create or select a non-admin test user and assign the appropriate group or role.
Do not grant a role by emitting a constant role tag for every user of the client.

## Verify the realm and sign in

1. Check the realm's OIDC discovery document at
   `https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration`.
   The returned issuer must match the one configured in Boundary and AWS IAM.
   Use a trusted TLS certificate and independently verify the issuer thumbprint
   before configuring AWS.
2. Follow the [personal dev bootstrap](../runbooks/personal-dev-bootstrap.md)
   to align the deployment's issuer, client, group and principal-tag settings.
   The issuer is the Keycloak base URL plus `/realms/<realm>`.
3. Configure the CLI using the [user access guide](../runbooks/user-access-guide.md)
   and run `rosa-boundary login --force` with the non-admin test user. If sign-in
   or authorization fails, see [OIDC issuer diagnostics](../runbooks/troubleshooting.md#oidc-issuer-diagnostics).
   Do not paste tokens into online decoders, tickets, or logs.
