---
type: architecture
title: Identity and access control
description: Explains how CLI OIDC login, Lambda-side token validation, AWS role assumption, and session-tag ABAC combine to authorize Boundary CLI/Lambda actions and ECS Exec access.
tags: [identity, oidc, authorization, aws-iam, abac, ecs-exec]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-10T16:03:08.957Z
sources:
  - id: openwiki-source-c2905a327012a93813a2dd05
    resource: repo://deploy/account/modules/shared-iam/oidc.tf
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-d8e76337d241d645fdbde114
    resource: repo://internal/auth/device.go
  - id: openwiki-source-f3c901cd7f81495d7b85597f
    resource: repo://internal/auth/oidc.go
  - id: openwiki-source-872fbb99e33ba1498c5790f0
    resource: repo://internal/auth/token.go
  - id: openwiki-source-d2f66eb6a0ccf1ed7a35e866
    resource: repo://internal/cmd/cli.go
  - id: openwiki-source-f18b195b06299be0877c0d2e
    resource: repo://internal/cmd/create_investigation.go
  - id: openwiki-source-2452fe2ff931e1490d573519
    resource: repo://internal/cmd/start_session.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
generated: { by: "openwiki/0.7.1", at: "2026-11-10T16:03:08.957Z" }
---

# Identity and access control

Boundary uses Keycloak-issued OIDC ID tokens at separate trust boundaries. The CLI obtains a token for the operator, AWS STS exchanges it for temporary credentials, and the `create-investigation` Lambda validates the token again before creating a workspace or task. AWS IAM and ECS resource tags — not local CLI filtering — enforce task-level ECS Exec isolation.

This page covers only Boundary's own CLI/Lambda identity model. Trusted Actions uses a separate OCM-JWT/AMS authorization model for its own actions and is documented on its own page; see [Trusted Actions authorization](trusted-actions-authorization.md).

## CLI login and AWS credentials

The default CLI login is an authorization-code flow with PKCE: `GetTokenWithOptions` checks the token cache first, then `acquireBrowserToken` creates a verifier/challenge and CSRF state, starts a local callback listener, opens the browser, and exchanges the callback code at the Keycloak token endpoint. A separate device-authorization flow (`--use-device-code`, or a default forced by configuration) lives in its own module, `acquireDeviceToken`: it posts to the provider's device endpoint, displays a verification URL and user code, and polls the token endpoint on the provider-supplied interval until approval, denial, or expiry. Both flows return a raw ID token to the same caller, `getTokenWithOptionsAndDeps`, which validates its expiration before caching it.

The returned ID token is cached with mode `0600` (re-applied with `os.Chmod` on every write in case an older cache was created with broader permissions). Cache reads parse the JWT expiration and treat tokens expiring within a 30-second buffer as unusable, deleting a malformed cache file outright. A freshly obtained token is also rejected before caching if it does not have at least that same 30-second remaining lifetime, which maps to the same `expirationBuffer` constant used by the cache reader. An explicit force-login bypasses the cache entirely. The CLI's central pre-run hook, `commandPreRun` in `internal/cmd/cli.go`, authenticates AWS-dependent commands, reuses a cached token when possible, and retries once with a fresh login for recognized token-authentication failures (`isAuthError`) via `assumeRoleWithRetryOptions`.

`commandPreRun` selects the AWS role to assume before invocation based on the invoked command: `investigation create` and `session create` assume the invoker role (session name `rosa-boundary-invoker`), and both also require `invoker_role_arn` and `lambda_function_name` to be configured; every other operational command (`session list`, `session join`, `session close`, `investigation list`, `investigation close`, credential configuration) assumes the shared SRE role directly (session name `rosa-boundary-session`) and requires `sre_role_arn`.

`session create` (`runStartSession` in `internal/cmd/start_session.go`) performs a second, explicit role assumption after its Lambda call: it invokes the Lambda with SigV4 credentials from the invoker-role session, then calls `assumeRoleWithRetryOptions` again — this time against the SRE role ARN returned by the Lambda (or an operator-configured `sre_role_arn` override), using a session name derived from the Lambda-reported owner — to obtain the credentials used for ECS operations. This is a two-stage flow: the invoker credential authorizes the Lambda invocation only, while the returned/configured SRE role credential is used for ECS task waiting, credential configuration, and ECS Exec. By contrast, `investigation create` (`runCreateInvestigation` in `internal/cmd/create_investigation.go`) only ever authenticates with the invoker role: it makes a single Lambda call (`CreateInvestigationOnly`, which sets `skip_task`) to create the investigation's EFS access point without launching an ECS task, so no second role assumption is needed.

The Lambda Function URL is configured for AWS IAM authorization. The regional invoker policy grants `lambda:InvokeFunction` on the function ARN because the CLI uses direct Lambda SDK invocation; the Lambda independently checks the OIDC token supplied in `X-OIDC-Token` (with a Bearer header fallback). Thus a valid AWS invocation credential does not replace application-level token validation.

## Lambda authorization

Before resource creation, the Lambda validates required configuration and the request, then routes the token by its unverified `iss` claim to a configured issuer's JWKS endpoint (primary Keycloak realm, and optional stage/prod OIDC providers). The selected key is used to verify the RS256 signature, expiration, and expected audience. Unsupported issuers and failed validation are rejected. After validation, the handler checks that the identity belongs to at least one configured required group/role, accepting either the flat `groups` claim or `realm_access.roles` shape.

The handler extracts the configured ABAC identifier from the `https://aws.amazon.com/tags` principal-tags claim. When the configured key is the default `username`, it can fall back to `preferred_username`; for a non-default key, a missing tag is rejected rather than silently using a different identity. The Lambda applies that identifier to the ECS task resource tag and returns the shared SRE role ARN in the response for the caller's second role assumption.

## Shared-role ABAC for ECS Exec

Account Terraform defines the shared SRE role with OIDC trust and `sts:TagSession`, so AWS can map the token's principal tags into session tags. Regional Terraform owns its ECS Exec policy: the task statement compares `ecs:ResourceTag/<abac_tag_key>` with `${aws:PrincipalTag/<abac_tag_key>}`. A missing or non-matching tag therefore does not satisfy the task condition. The ABAC key is configurable, and must agree across the OIDC claim, task tag, and IAM condition.

The role also grants supporting list/describe, stop, EFS access-point cleanup, and SSM/KMS permissions used by operator workflows. These are distinct from the task-tag-conditioned `ecs:ExecuteCommand` permission; shared-role assumption is the authorization boundary for investigation cleanup. Integration tests check the audience-scoped OIDC trust, `sts:TagSession`, dynamic PrincipalTag policy expression, and task tagging rather than a per-user role model.

```mermaid
sequenceDiagram
    participant CLI as rosa-boundary CLI
    participant KC as Keycloak (OIDC)
    participant STS as AWS STS
    participant Lambda as create-investigation Lambda
    participant ECS as ECS / SSM

    CLI->>KC: Authorization-code+PKCE (or device) flow
    KC-->>CLI: ID token (cached 0600, 30s expiry buffer)
    CLI->>STS: AssumeRoleWithWebIdentity (invoker role, ID token)
    STS-->>CLI: Invoker credentials
    CLI->>Lambda: SigV4 request + X-OIDC-Token header
    Lambda->>Lambda: Verify JWKS signature, audience, group membership
    Lambda->>ECS: RunTask tagged with ABAC identifier
    Lambda-->>CLI: Task ARN + shared SRE role ARN
    CLI->>STS: AssumeRoleWithWebIdentity (SRE role, same ID token)
    STS-->>CLI: SRE session credentials (PrincipalTag = ABAC identifier)
    CLI->>ECS: ExecuteCommand (allowed only if ResourceTag == PrincipalTag)
```

*Two-stage authorization for `session create`: an invoker-role credential authorizes the Lambda call, and a second, independently assumed shared SRE role credential (tagged via ABAC) authorizes ECS task access. `investigation create` only performs the first stage, since it creates an EFS access point but no ECS task.*

## Evidence-backed claims

- The CLI uses an OIDC authorization-code flow with PKCE (with a separately implemented device-authorization alternative), caches the ID token with restrictive permissions, and rejects tokens within a 30-second expiration buffer both on cache read and immediately after acquisition. [OIDC flow](repo://internal/auth/oidc.go#L57-L184) · [device flow](repo://internal/auth/device.go#L40-L124) · [token cache](repo://internal/auth/token.go#L16-L138)
- CLI authentication selects the invoker role for `investigation create` and `session create`, and the shared SRE role directly for other operational commands; `session create` invokes the Lambda first and then assumes the SRE role via a second, explicit `assumeRoleWithRetryOptions` call, while `investigation create` makes a single invoker-only Lambda call and never assumes the SRE role. [pre-run role selection](repo://internal/cmd/cli.go#L56-L136) · [session create two-stage flow](repo://internal/cmd/start_session.go#L33-L131) · [investigation create single-stage flow](repo://internal/cmd/create_investigation.go#L22-L60)
- The Lambda validates signed OIDC tokens against configured issuer JWKS/audience, checks required group membership, and derives the task ABAC identifier from claims before creating resources. [claims extraction and group/ABAC checks](repo://lambda/create-investigation/handler.py#L181-L256) · [issuer routing and JWKS verification](repo://lambda/create-investigation/handler.py#L374-L457)
- The shared SRE role requires OIDC session tagging and regional IAM policy gates ECS Exec on equality between the task resource tag and the caller's principal tag. [role trust](repo://deploy/account/modules/shared-iam/oidc.tf#L12-L85) · [regional ABAC policy](repo://deploy/regional/iam.tf#L143-L168)
- Lambda invocation is protected with AWS IAM/SigV4 and the function separately validates the OIDC token; the regional invoker policy targets direct Lambda invocation. [invocation permission](repo://deploy/regional/iam.tf#L215-L230) · [Lambda URL authorization](repo://deploy/regional/lambda-create-investigation.tf#L162-L182)

## Related pages

- [System overview](system-overview.md)
- [Trusted Actions authorization](trusted-actions-authorization.md)
- [Keycloak deployment](../integrations/keycloak-deployment.md)
- [Credential lifecycle](../security/credential-lifecycle.md)
- [Investigation lifecycle](../workflows/investigation-lifecycle.md)
