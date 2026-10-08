---
type: architecture
title: Identity and access control
description: Explains how CLI OIDC login, Lambda authorization, AWS role assumption, and session-tag ABAC combine to authorize ROSA Boundary actions and ECS Exec access.
tags: [identity, oidc, authorization, aws-iam, abac, ecs-exec]
verified:
  - by: openwiki/0.7.0
    at: 2026-10-05T19:18:44.075Z
sources:
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-324dc474304cccd7db2756ff
    resource: repo://deploy/regional/lambda-invoker.tf
  - id: openwiki-source-9b7905e9e38369b09bae85a2
    resource: repo://deploy/regional/oidc.tf
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
generated: { by: "opencode", at: "2026-10-05T17:08:59.471Z" }
---

# Identity and access control

ROSA Boundary uses Keycloak-issued OIDC ID tokens at separate trust boundaries. The CLI obtains a token for the operator, AWS STS exchanges it for temporary credentials, and the investigation Lambda validates the token again before creating a workspace or task. AWS IAM and ECS resource tags—not local CLI filtering—enforce task-level ECS Exec isolation.

## CLI login and AWS credentials

The CLI runs an authorization-code flow with PKCE: it creates a verifier/challenge and CSRF state, starts a local callback listener, opens the browser, and exchanges the callback code at the Keycloak token endpoint. The returned ID token is cached with mode `0600`; cache reads parse the JWT expiration and treat tokens expiring within 30 seconds as unusable. An explicit force-login bypasses the cache. The CLI's central pre-run hook authenticates AWS-dependent commands, reuses a cached token when possible, and retries once with a fresh login for recognized token-authentication failures.

`create-investigation` and `start-task` initially assume the Lambda invoker role. `start-task` then calls the Lambda with SigV4 credentials and assumes the shared SRE role for task access; other operational commands use that SRE role directly. This is a two-stage flow: the invoker credential authorizes Lambda invocation, while the returned/configured SRE role credential is used for ECS operations.

The Lambda Function URL is configured for AWS IAM authorization. The invoker role policy grants `lambda:InvokeFunction` on the function ARN because the CLI uses direct Lambda SDK invocation; the Lambda independently checks the OIDC token supplied in `X-OIDC-Token` (with a Bearer header fallback). Thus a valid AWS invocation credential does not replace application-level token validation.

## Lambda authorization

Before resource creation, the Lambda validates required configuration and the request, then routes the token by its unverified issuer claim to a configured issuer's JWKS endpoint. The selected key is used to verify the RS256 signature, expiration, and expected audience. Unsupported issuers and failed validation are rejected. After validation, the handler checks that the identity belongs to at least one configured required group/role, accepting either the flat `groups` claim or `realm_access.roles` shape.

The handler extracts the configured ABAC identifier from the AWS session-tags claim. When the configured key is the default `username`, it can fall back to `preferred_username`; for a non-default key, a missing tag is rejected rather than silently using a different identity. The Lambda applies that identifier to the ECS task resource tag and returns the shared SRE role ARN for the caller's second role assumption.

## Shared-role ABAC for ECS Exec

Terraform defines a shared SRE role with OIDC trust and `sts:TagSession`, so AWS can map the token's principal tags into session tags. Its ECS Exec policy separates the cluster-level prerequisite permission from task-level access: the task statement compares `ecs:ResourceTag/<abac_tag_key>` with `${aws:PrincipalTag/<abac_tag_key>}`. A missing or non-matching tag therefore does not satisfy the task condition. The ABAC key is configurable, and must agree across the OIDC claim, task tag, and IAM condition.

The role also grants supporting list/describe, stop, EFS access-point cleanup, and SSM/KMS permissions used by operator workflows. These are distinct from the task-tag-conditioned `ecs:ExecuteCommand` permission; shared-role assumption is the authorization boundary for investigation cleanup. Integration tests check the audience-scoped OIDC trust, `sts:TagSession`, dynamic PrincipalTag policy expression, and task tagging rather than a per-user role model.

## Evidence-backed claims

- The CLI uses an OIDC authorization-code flow with PKCE, caches the ID token, and rejects cached tokens within a 30-second expiration buffer. [OIDC flow](repo://internal/auth/oidc.go#L45-L135) · [token cache](repo://internal/auth/token.go#L16-L85)
- CLI authentication selects the invoker role for investigation creation/start and uses the shared SRE role for operational commands; `start-task` invokes Lambda first and then assumes the SRE role. [pre-run role selection](repo://internal/cmd/root.go#L154-L207) · [start-task sequence](repo://internal/cmd/start_task.go#L90-L156)
- The Lambda validates signed OIDC tokens against configured issuer JWKS/audience, checks required group membership, and derives the task ABAC identifier from claims before creating resources. [token extraction and checks](repo://lambda/create-investigation/handler.py#L107-L135) · [claims and authorization](repo://lambda/create-investigation/handler.py#L175-L260) · [issuer verification](repo://lambda/create-investigation/handler.py#L362-L405)
- The shared SRE role requires OIDC session tagging and gates ECS Exec on equality between the task resource tag and the caller's principal tag; tests assert the dynamic condition. [role trust and task policy](repo://deploy/regional/oidc.tf#L74-L115) · [ABAC policy](repo://deploy/regional/oidc.tf#L181-L235) · [policy integration tests](repo://tests/localstack/integration/test_tag_isolation.py#L20-L98)
- Lambda invocation is protected with AWS IAM/SigV4 and the function separately validates the OIDC token; the CLI's invoker policy targets direct Lambda invocation. [invoker role](repo://deploy/regional/lambda-invoker.tf#L1-L8) · [invocation permission](repo://deploy/regional/lambda-invoker.tf#L93-L107) · [Lambda URL authorization](repo://deploy/regional/lambda-create-investigation.tf#L245-L269)
