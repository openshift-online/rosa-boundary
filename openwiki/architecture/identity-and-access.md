---
type: architecture
title: Identity and access control
description: Explains how CLI OIDC login, Lambda authorization, AWS role assumption, and session-tag ABAC combine to authorize ROSA Boundary actions and ECS Exec access, including the account/regional split in Terraform ownership of the underlying IAM roles.
tags: [identity, oidc, authorization, aws-iam, abac, ecs-exec]
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
sources:
  - id: openwiki-source-d25a030029a9183fad61b582
    resource: repo://deploy/account/modules/shared-iam/lambda-invoker.tf
  - id: openwiki-source-c2905a327012a93813a2dd05
    resource: repo://deploy/account/modules/shared-iam/oidc.tf
  - id: openwiki-source-45393b666c4d8ce854ed025b
    resource: repo://deploy/account/README.md
  - id: openwiki-source-e63bbacd264bc409c45ddf07
    resource: repo://deploy/account/tests/shared-iam.tftest.hcl
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-1599d372a558b44029d5589b
    resource: repo://deploy/regional/tests/iam-ownership.tftest.hcl
  - id: openwiki-source-f3c901cd7f81495d7b85597f
    resource: repo://internal/auth/oidc.go
  - id: openwiki-source-872fbb99e33ba1498c5790f0
    resource: repo://internal/auth/token.go
  - id: openwiki-source-7a5e071b6b6192c80a6918aa
    resource: repo://internal/cmd/root.go
  - id: openwiki-source-b123c673a5b90ca2010ffe64
    resource: repo://internal/cmd/start_task.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-739520a5cce4271eab53a612
    resource: repo://tests/localstack/integration/test_tag_isolation.py
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
---

# Identity and access control

ROSA Boundary uses Keycloak-issued OIDC ID tokens at separate trust boundaries. The CLI obtains a token for the operator, AWS STS exchanges it for temporary credentials, and the investigation Lambda validates the token again before creating a workspace or task. AWS IAM and ECS resource tags—not local CLI filtering—enforce task-level ECS Exec isolation.

This page covers the *runtime* authorization flow: how a CLI operator becomes an authenticated AWS principal, how the Lambda validates and routes that identity, and how session-tag ABAC gates ECS Exec. The Terraform mechanics that create and migrate the underlying IAM role identities — including why a separate `deploy/account` root now owns them — are described in [Account identity ownership](../infrastructure/account-identity-ownership.md); this page only summarizes the parts of that split relevant to understanding who can assume which role and what that role is allowed to do.

## Account/regional ownership split

The IAM roles and OIDC trust used in this flow are defined once, account-wide, but their permissions are assembled per region:

- **Account Terraform** (`deploy/account/modules/shared-iam/oidc.tf` and `lambda-invoker.tf`) owns role **identity and trust**: the `aws_iam_role.sre_shared` and `aws_iam_role.lambda_invoker` resources, their `assume_role_policy` (who can assume the role via `sts:AssumeRoleWithWebIdentity`/`sts:TagSession`, under which OIDC provider, audience, and optional UUID/role allowlists), and the Keycloak/stage/prod `aws_iam_openid_connect_provider` resources themselves.
- **Regional Terraform** (`deploy/regional/iam.tf`) owns **inline grants** — what the role is allowed to do once assumed — attached via `aws_iam_role_policy` resources against `data.aws_iam_role` lookups (`deploy/regional/account-iam.tf`) rather than against directly owned role resources. Regional state also looks up the OIDC providers via `data.aws_iam_openid_connect_provider`, by issuer URL, instead of creating them.

Because the roles and OIDC providers are account-global, every region that attaches grants to `sre_shared` or `lambda_invoker` contributes to the *same* role: the effective permission set a session receives is the **union of every region's inline policies** on that role, not a per-region sandbox (see `deploy/account/README.md`). Regional inline policy names are therefore disambiguated per region (a designated legacy region keeps unsuffixed names; others append `-${aws_region}`) so that two regions' grants coexist rather than overwrite each other.

This split is asserted by two Terraform test suites:

- `deploy/account/tests/shared-iam.tftest.hcl` runs `apply` against mocked `aws_iam_role`/`aws_caller_identity` data to assert that the account module's `aws_iam_role.sre_shared` and `aws_iam_role.lambda_invoker` preserve their legacy names, OIDC trust principals/audiences, session-tagging actions, and `max_session_duration` values across all configured issuers (default, stage, prod).
- `deploy/regional/tests/iam-ownership.tftest.hcl` mocks `data.aws_iam_role` and `data.aws_iam_openid_connect_provider` and runs `apply`/`plan` to assert that every regional `aws_iam_role_policy` (including `sre_shared_ecs_exec` and `lambda_invoker`) attaches to the looked-up role ID rather than an owned resource, that policy names are legacy-unsuffixed only in the designated legacy region, and that each region renders its own resource-scoped ABAC/ECS/EFS statements instead of copying another region's scopes.

## CLI login and AWS credentials

The CLI runs an authorization-code flow with PKCE: it creates a verifier/challenge and CSRF state, starts a local callback listener, opens the browser, and exchanges the callback code at the Keycloak token endpoint. The returned ID token is cached with mode `0600`; cache reads parse the JWT expiration and treat tokens expiring within 30 seconds as unusable. An explicit force-login bypasses the cache. The CLI's central pre-run hook authenticates AWS-dependent commands, reuses a cached token when possible, and retries once with a fresh login for recognized token-authentication failures.

`create-investigation` and `start-task` initially assume the lambda-invoker role. `start-task` then calls the Lambda with SigV4 credentials and assumes the shared SRE role for task access; other operational commands use that SRE role directly. This is a two-stage flow: the invoker credential authorizes Lambda invocation, while the returned/configured SRE role credential is used for ECS operations.

Both roles' trust policies — the Federated OIDC principal, `sts:AssumeRoleWithWebIdentity`/`sts:TagSession` actions, audience condition, and optional UUID/required-role allowlist conditions — are defined once in `deploy/account/modules/shared-iam/oidc.tf` (`aws_iam_role.sre_shared`) and `lambda-invoker.tf` (`aws_iam_role.lambda_invoker`), each with a near-identical trust statement repeated for the default, stage, and prod Keycloak OIDC providers. The Lambda Function URL is configured for AWS IAM authorization (`deploy/regional/lambda-create-investigation.tf`). The invoker role's regional `lambda:InvokeFunction` grant (`aws_iam_role_policy.lambda_invoker` in `deploy/regional/iam.tf`) lets the CLI use direct Lambda SDK invocation with SigV4 credentials; the Lambda independently checks the OIDC token supplied in `X-OIDC-Token` (with a Bearer header fallback). Thus a valid AWS invocation credential does not replace application-level token validation.

## Lambda authorization

Before resource creation, the Lambda validates required configuration and the request, then routes the token by its unverified issuer claim to a configured issuer's JWKS endpoint. The selected key is used to verify the RS256 signature, expiration, and expected audience. Unsupported issuers and failed validation are rejected. After validation, the handler checks that the identity belongs to at least one configured required group/role, accepting either the flat `groups` claim or `realm_access.roles` shape.

The handler extracts the configured ABAC identifier from the AWS session-tags claim. When the configured key is the default `username`, it can fall back to `preferred_username`; for a non-default key, a missing tag is rejected rather than silently using a different identity. The Lambda applies that identifier to the ECS task resource tag and returns the shared SRE role ARN for the caller's second role assumption.

## Shared-role ABAC for ECS Exec

The shared SRE role's OIDC trust (`sts:AssumeRoleWithWebIdentity` plus `sts:TagSession`, defined in `deploy/account/modules/shared-iam/oidc.tf`) lets AWS map the token's `https://aws.amazon.com/tags` claim into session tags during assumption. The role's *permissions* — including the ABAC condition — are a separate, regionally owned artifact: `aws_iam_role_policy.sre_shared_ecs_exec` in `deploy/regional/iam.tf`, attached against a `data.aws_iam_role.sre_shared` lookup rather than a directly owned role resource. That policy separates the cluster-level prerequisite permission from task-level access: an `ExecuteCommandOnCluster` statement grants `ecs:ExecuteCommand` on the cluster ARN unconditionally (cluster authorization alone grants no task access), while the `ExecuteCommandOnOwnedTasks` statement compares `ecs:ResourceTag/<abac_tag_key>` with `${aws:PrincipalTag/<abac_tag_key>}` on a wildcard task resource. A missing or non-matching tag does not satisfy the task condition — this fails closed. The ABAC key is configurable (`var.abac_tag_key`), and must agree across the OIDC claim, task tag, and IAM condition.

The same policy also grants supporting `StopOwnedTasks` (tag-conditioned, scoped to the cluster's task ARN pattern), `DescribeListAndCleanupECS` (list/describe/deregister, unscoped since those actions don't support resource-level authorization), EFS access-point read/managed-cleanup, and SSM/KMS permissions needed to open an ECS Exec session. These are distinct from the task-tag-conditioned `ecs:ExecuteCommand` permission; shared-role assumption is the authorization boundary for investigation cleanup. Integration tests in `tests/localstack/integration/test_tag_isolation.py` check the dynamic `${aws:PrincipalTag/username}` policy expression and simulate IAM policy evaluation (via `iam:SimulatePrincipalPolicy`-style context) to confirm that a missing session tag results in deny rather than an implicit match — a fail-closed property of the condition, not of any CLI-side filtering.

## Ownership summary for this flow

| Concern | Owner | Where |
| --- | --- | --- |
| Role identity, `max_session_duration`, trust policy (who can assume) | Account Terraform | `deploy/account/modules/shared-iam/oidc.tf`, `lambda-invoker.tf` |
| OIDC provider resources (Keycloak default/stage/prod) | Account Terraform | `deploy/account/modules/shared-iam/oidc.tf` |
| ABAC ECS Exec permissions, invoker's `lambda:InvokeFunction` grant | Regional Terraform | `deploy/regional/iam.tf` (`aws_iam_role_policy.sre_shared_ecs_exec`, `aws_iam_role_policy.lambda_invoker`) |
| Lambda Function URL AWS_IAM authorization + invoke permission | Regional Terraform | `deploy/regional/lambda-create-investigation.tf` |
| Role/OIDC-provider lookups consumed by regional grants | Regional Terraform | `deploy/regional/account-iam.tf` (`data.aws_iam_role`, `data.aws_iam_openid_connect_provider`) |

For the migration history, the shared-prefix naming contract, and the 10,240-character per-role inline-policy quota implications of this split, see [Account identity ownership](../infrastructure/account-identity-ownership.md).

## Evidence-backed claims

- The CLI uses an OIDC authorization-code flow with PKCE, caches the ID token, and rejects cached tokens within a 30-second expiration buffer. [OIDC flow](repo://internal/auth/oidc.go#L45-L135) · [token cache](repo://internal/auth/token.go#L16-L85)
- CLI authentication selects the invoker role for investigation creation/start and uses the shared SRE role for operational commands; `start-task` invokes Lambda first and then assumes the SRE role. [pre-run role selection](repo://internal/cmd/root.go#L154-L207) · [start-task sequence](repo://internal/cmd/start_task.go#L90-L156)
- The Lambda validates signed OIDC tokens against configured issuer JWKS/audience, checks required group membership, and derives the task ABAC identifier from claims before creating resources. [token extraction and checks](repo://lambda/create-investigation/handler.py#L107-L135) · [claims and authorization](repo://lambda/create-investigation/handler.py#L175-L260) · [issuer verification](repo://lambda/create-investigation/handler.py#L362-L405)
- The shared SRE role's OIDC trust and session-tagging requirement is defined by account Terraform, while the regionally owned `ecs-exec-abac` inline policy gates `ecs:ExecuteCommand` on tasks by matching the configured ECS resource tag to the caller's principal session tag; integration tests assert the dynamic condition and its fail-closed behavior. [account role trust](repo://deploy/account/modules/shared-iam/oidc.tf#L9-L98) · [regional ABAC policy](repo://deploy/regional/iam.tf#L133-L215) · [policy integration tests](repo://tests/localstack/integration/test_tag_isolation.py#L142-L180)
- Lambda invocation is protected with AWS IAM/SigV4 and the function separately validates the OIDC token; the invoker role's trust is account-owned while its direct `lambda:InvokeFunction` grant and the Lambda URL's `AWS_IAM` authorization/permission statement are regionally owned. [account invoker role trust](repo://deploy/account/modules/shared-iam/lambda-invoker.tf#L9-L91) · [regional invoke permission](repo://deploy/regional/iam.tf#L217-L225) · [Lambda URL authorization](repo://deploy/regional/lambda-create-investigation.tf#L161-L185)
- Account and regional Terraform test suites assert the ownership split: account tests mock IAM/caller-identity data to verify role trust/session-tag/duration fidelity, and regional tests mock `data.aws_iam_role`/`data.aws_iam_openid_connect_provider` to verify every regional grant attaches to a looked-up role and renders region-scoped resource ARNs rather than owning or copying another region's grants. [account role tests](repo://deploy/account/tests/shared-iam.tftest.hcl#L33-L94) · [regional ownership tests](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L77-L170)
