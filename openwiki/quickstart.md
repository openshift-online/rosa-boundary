---
type: navigation
title: OpenWiki quickstart
description: Routes readers to architecture, investigation cleanup, shared and regional infrastructure, two-region HCP staging plus the bootstrapping prod account, audit access, identity, credentials, container runtime, and verification guidance.
tags: [navigation, quickstart, rosa-boundary]
verified:
  - by: openwiki/0.7.1
    at: 2026-10-29T16:03:33.678Z
sources:
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-45ce132817cdbbe35348bf04
    resource: repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
  - id: openwiki-source-b123c673a5b90ca2010ffe64
    resource: repo://internal/cmd/start_task.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
generated: { by: "openwiki/0.7.1", at: "2026-10-29T16:03:33.678Z" }
---

# OpenWiki quickstart

Use this page to find the part of ROSA Boundary that matches your question. Verify behavior against current implementation, configuration, and tests; linked human-maintained runbooks supply operational procedures, not proof of live deployment or access.

## Find a topic

- **How the pieces fit together:** [System overview](architecture/system-overview.md) maps the Go CLI, AWS identity, investigation Lambda, Fargate runtime, persistent/task-scoped storage, and the two independent scheduled cleanup Lambdas (per-task timeout reaping and whole-investigation garbage collection).
- **Create, run, replace, connect, or close an investigation:** [Investigation lifecycle](workflows/investigation-lifecycle.md) follows CLI/Lambda/ECS/EFS state, handover, task deadlines, creation-age and legacy-timestamp GC eligibility, required final backups, and the interaction between close and reaper discovery.
- **OIDC login, Lambda authorization, and ECS Exec permissions:** [Identity and access](architecture/identity-and-access.md) explains role selection and session-tag ABAC.
- **Build or troubleshoot the container and its startup/shutdown behavior:** [Container image and task runtime](runtime/container-image.md) covers architecture-specific builds, runtime identity, entrypoint setup, and S3 sync.
- **Understand AWS resources and account/regional ownership:** [Regional runtime infrastructure](infrastructure/regional-runtime.md) covers ECS, EFS, audit storage, Lambda, shared IAM identities versus regional inline grants, policy-name collision prevention, and multi-region Bedrock logging trust.
- **Trace staging plans, authorization, and applies:** [HCP Terraform workspace integration](infrastructure/hcp-terraform-workspaces.md) maps staging's six L3 states: credentials, account, and separate network/runtime workspaces for `us-east-1` and `us-west-2`, plus a separate, still-bootstrapping `rosa-boundary-prod` AWS account that so far only has its own aws-creds and account workspaces (no network or regional workspaces yet). It explains VCS integration, dynamic-credential authorization versus variable-set bindings, the staging workspaces' default/explicit auto-apply versus the prod workspaces' manual (`auto_apply = false`) gate, sibling ordering, and image promotion.
- **Find audit records and request read access:** [Auditing and logging flows](operations/audit-and-logging.md) distinguishes CloudWatch transcripts, S3 snapshots, Bedrock payloads and CloudTrail coverage, and links the scoped S3 audit-reader procedure separately from CloudWatch read permissions.
- **Trace OCM credential handling:** [Credential lifecycle](security/credential-lifecycle.md) documents access-token acquisition, ECS Exec transfer, task-side validation, ephemeral storage, and cleanup.
- **Understand the Keycloak deployment and its OIDC consumers:** [Keycloak integration](integrations/keycloak-deployment.md) links OpenShift Kustomize resources to the CLI, Lambda, and IAM configuration.
- **Choose a test suite or understand CI behavior:** [Testing and verification](testing/verification.md) covers legacy-staleness regressions, Lambda discovery boundaries, mocked IAM ownership/trust checks, known account-test drift, and LocalStack local-executor versus Prow task-capable runs.

## Start from the main flow

The operator CLI obtains OIDC-backed AWS credentials and invokes the create-investigation Lambda; the Lambda authorizes the identity, provisions an EFS-backed workspace, and can launch an ECS Fargate task; Terraform defines the regional AWS resources that support that flow. For the request path, begin with the [system overview](architecture/system-overview.md), then follow the [investigation lifecycle](workflows/investigation-lifecycle.md). For detailed authorization or resource ownership, continue to [identity and access](architecture/identity-and-access.md) or [regional infrastructure](infrastructure/regional-runtime.md).

## Evidence-backed claims

- The CLI passes task-start requests to the create-investigation Lambda, which validates the operator, provisions or reuses an investigation EFS access point, and can launch a Fargate task using a per-investigation task definition derived from the regional task definition. [CLI request path](repo://internal/cmd/start_task.go#L90-L104) · [Lambda dispatch](repo://lambda/create-investigation/handler.py#L175-L281) · [Lambda access-point and task launch](repo://lambda/create-investigation/handler.py#L676-L999) · [regional task definition](repo://deploy/regional/ecs.tf#L62-L82)
- The staging workspace map declares one credentials workspace, one account workspace, and east/west pairs of network and regional runtime workspaces; both regional states reuse `deploy/regional`, and both network states reuse `deploy/network`. [east network](repo://hcp-terraform/rosa-boundary/main.tf#L35-L42) · [west network](repo://hcp-terraform/rosa-boundary/main.tf#L71-L81) · [credentials and account](repo://hcp-terraform/rosa-boundary/main.tf#L144-L165) · [east runtime](repo://hcp-terraform/rosa-boundary/main.tf#L321-L330) · [west runtime](repo://hcp-terraform/rosa-boundary/main.tf#L516-L525)
- `hcp-terraform/rosa-boundary/main.tf` also defines a separate, still-bootstrapping `rosa-boundary-prod` AWS account (distinct AWS account ID `514903006123`, confirmed by `hcp-terraform/aws-creds/rosa-boundary-prod/main.tf`'s `allowed_account_ids`) with only an aws-creds workspace and an account workspace so far — no network or regional workspaces exist for it yet. Both prod workspaces set `execution_mode = "remote"` and `auto_apply = false` (manual apply gating), while the staging network-us-west-2, account, and both regional workspaces now set `auto_apply = true` and `auto_apply_run_trigger = true`. [prod aws-creds and account workspaces](repo://hcp-terraform/rosa-boundary/main.tf#L694-L720) · [prod account ID](repo://hcp-terraform/rosa-boundary/main.tf#L722-L726) · [prod account ID confirmation](repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf#L16-L20) · [staging auto-apply, e.g. account workspace](repo://hcp-terraform/rosa-boundary/main.tf#L153-L160)
