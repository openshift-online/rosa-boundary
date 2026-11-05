---
type: navigation
title: OpenWiki quickstart
description: Routes readers to architecture, investigation cleanup, shared and regional infrastructure, two-region HCP staging plus the now-six-workspace rosa-boundary-prod account, audit access, identity, credentials, container runtime, and verification guidance.
tags: [navigation, quickstart, rosa-boundary]
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
generated: { by: "openwiki/0.7.1", at: "2026-11-05T16:02:21.720Z" }
verified:
  - by: openwiki/0.7.1
    at: 2026-11-05T16:02:21.720Z
---

# OpenWiki quickstart

Use this page to find the part of ROSA Boundary that matches your question. Verify behavior against current implementation, configuration, and tests; linked human-maintained runbooks supply operational procedures, not proof of live deployment or access.

## Find a topic

- **How the pieces fit together:** [System overview](architecture/system-overview.md) maps the Go CLI, AWS identity, investigation Lambda, Fargate runtime, persistent/task-scoped storage, and the two independent scheduled cleanup Lambdas (per-task timeout reaping and whole-investigation garbage collection).
- **Create, run, replace, connect, or close an investigation:** [Investigation lifecycle](workflows/investigation-lifecycle.md) follows CLI/Lambda/ECS/EFS state, handover, task deadlines, creation-age and legacy-timestamp GC eligibility, required final backups, and the interaction between close and reaper discovery.
- **OIDC login, Lambda authorization, and ECS Exec permissions:** [Identity and access](architecture/identity-and-access.md) explains role selection and session-tag ABAC.
- **Build or troubleshoot the container and its startup/shutdown behavior:** [Container image and task runtime](runtime/container-image.md) covers architecture-specific builds, runtime identity, entrypoint setup, and S3 sync.
- **Understand AWS resources and account/regional ownership:** [Regional runtime infrastructure](infrastructure/regional-runtime.md) covers ECS, EFS, audit storage, Lambda, shared IAM identities versus regional inline grants, policy-name collision prevention, and multi-region Bedrock logging trust.
- **Trace staging and production plans, authorization, and applies:** [HCP Terraform workspace integration](infrastructure/hcp-terraform-workspaces.md) maps staging's six L3 workspaces: credentials, account, and separate network/runtime workspaces for `us-east-1` and `us-west-2`, plus the separate `rosa-boundary-prod` AWS account, which has grown to six registered workspaces of its own (credentials, account, and `us-east-1`/`us-west-2` network/regional pairs). It explains VCS integration, dynamic-credential authorization versus variable-set bindings, the staging workspaces' default/explicit auto-apply, the fact that only `rosa-boundary-prod-aws-creds` still keeps a manual (`auto_apply = false`) gate while the other five prod workspaces now set `auto_apply = true` like staging, sibling ordering, and image promotion.
- **Find audit records and request read access:** [Auditing and logging flows](operations/audit-and-logging.md) distinguishes CloudWatch transcripts, S3 snapshots, Bedrock payloads and CloudTrail coverage, and links the scoped S3 audit-reader procedure separately from CloudWatch read permissions.
- **Trace OCM credential handling:** [Credential lifecycle](security/credential-lifecycle.md) documents access-token acquisition, ECS Exec transfer, task-side validation, ephemeral storage, and cleanup.
- **Understand the Keycloak deployment and its OIDC consumers:** [Keycloak integration](integrations/keycloak-deployment.md) links OpenShift Kustomize resources to the CLI, Lambda, and IAM configuration.
- **Choose a test suite or understand CI behavior:** [Testing and verification](testing/verification.md) covers legacy-staleness regressions, Lambda discovery boundaries, mocked IAM ownership/trust checks, known account-test drift, and LocalStack local-executor versus Prow task-capable runs.

## Start from the main flow

The operator CLI obtains OIDC-backed AWS credentials and invokes the create-investigation Lambda; the Lambda authorizes the identity, provisions an EFS-backed workspace, and can launch an ECS Fargate task; Terraform defines the regional AWS resources that support that flow. For the request path, begin with the [system overview](architecture/system-overview.md), then follow the [investigation lifecycle](workflows/investigation-lifecycle.md). For detailed authorization or resource ownership, continue to [identity and access](architecture/identity-and-access.md) or [regional infrastructure](infrastructure/regional-runtime.md).

## Evidence-backed claims

- The CLI invokes the create-investigation Lambda with the SigV4-signed AWS SDK client and derives the task ID and SRE role ARN from its response; the Lambda itself validates the operator, provisions or reuses an investigation EFS access point, and can launch a Fargate task using a per-investigation task definition derived from the regional task definition. [CLI Lambda invocation](repo://internal/cmd/start_task.go#L105-L117) · [Lambda dispatch](repo://lambda/create-investigation/handler.py#L175-L281) · [Lambda access-point and task launch](repo://lambda/create-investigation/handler.py#L676-L999) · [regional task definition](repo://deploy/regional/ecs.tf#L62-L82)
- The staging workspace map declares one credentials workspace, one account workspace, and east/west pairs of network and regional runtime workspaces; both regional states reuse `deploy/regional`, and both network states reuse `deploy/network`. These six staging workspaces are not the entirety of the module's HCP Terraform footprint: a separate `rosa-boundary-prod` account defines six more. [east network](repo://hcp-terraform/rosa-boundary/main.tf#L36-L69) · [west network](repo://hcp-terraform/rosa-boundary/main.tf#L71-L139) · [credentials and account](repo://hcp-terraform/rosa-boundary/main.tf#L141-L328) · [east runtime](repo://hcp-terraform/rosa-boundary/main.tf#L330-L521) · [west runtime](repo://hcp-terraform/rosa-boundary/main.tf#L523-L706)
- `hcp-terraform/rosa-boundary/main.tf` also defines a separate `rosa-boundary-prod` AWS account (distinct AWS account ID `514903006123`, confirmed by `hcp-terraform/aws-creds/rosa-boundary-prod/main.tf`'s `allowed_account_ids`), which has grown from its initial credentials/account pair to six registered workspaces: credentials, account, and `us-east-1`/`us-west-2` network/regional pairs, all reusing the same `deploy/network` and `deploy/regional` source roots as staging. All six prod workspaces set `execution_mode = "remote"`, but only `rosa-boundary-prod-aws-creds` still sets `auto_apply = false` and `auto_apply_run_trigger = false` as a manual-apply gate; the other five prod workspaces (account, network-us-east-1, regional-us-east-1, network-us-west-2, regional-us-west-2) set `auto_apply = true` and `auto_apply_run_trigger = true`, mirroring staging's auto-apply workspaces. `hcp-terraform/aws-creds/rosa-boundary-prod/main.tf`'s `workspace_names` allowlist now authorizes all six prod workspaces for AWS access. [prod aws-creds workspace](repo://hcp-terraform/rosa-boundary/main.tf#L709-L722) · [prod account workspace](repo://hcp-terraform/rosa-boundary/main.tf#L726-L890) · [prod network/regional us-east-1 workspaces](repo://hcp-terraform/rosa-boundary/main.tf#L894-L1117) · [prod network/regional us-west-2 workspaces](repo://hcp-terraform/rosa-boundary/main.tf#L1121-L1372) · [prod account ID](repo://hcp-terraform/rosa-boundary/main.tf#L737-L740) · [prod account ID confirmation](repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf#L16-L20) · [prod workspace_names allowlist](repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf#L38-L45) · [staging auto-apply, e.g. account workspace](repo://hcp-terraform/rosa-boundary/main.tf#L153-L160)
