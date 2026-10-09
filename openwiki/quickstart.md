---
type: navigation
title: OpenWiki quickstart
description: Routes readers to the source-grounded architecture, investigation workflow, identity, runtime, infrastructure, HCP Terraform deployment, account IAM ownership, credential handling, Keycloak, and testing pages.
tags: [navigation, quickstart, rosa-boundary]
sources:
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-b123c673a5b90ca2010ffe64
    resource: repo://internal/cmd/start_task.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
---

# OpenWiki quickstart

Use this page to find the part of ROSA Boundary that matches your question. This wiki was initialized from current implementation, configuration, and tests; the human-maintained `docs/` directory was not used as a source of truth.

## Find a topic

- **How the pieces fit together:** [System overview](architecture/system-overview.md) maps the Go CLI, AWS identity, investigation Lambda, Fargate runtime, persistence, and test boundaries, including the split between the account-owned IAM role identities/trust/OIDC providers and the regional inline permission grants that are looked up by data source.
- **Create, run, replace, connect, or close an investigation:** [Investigation lifecycle](workflows/investigation-lifecycle.md) follows state through the CLI, Lambda, ECS, EFS, and timeout reaper, including the reaper's fail-closed check for active ECS Exec/SSM sessions before it stops an expired task.
- **OIDC login, Lambda authorization, and ECS Exec permissions:** [Identity and access](architecture/identity-and-access.md) explains role selection and session-tag ABAC, including how IAM role identities, trust policies, and OIDC providers now live in a separate account Terraform root while regional Terraform owns only the inline permission grants it looks those roles up to attach.
- **Build or troubleshoot the container and its startup/shutdown behavior:** [Container image and task runtime](runtime/container-image.md) covers architecture-specific builds, runtime identity, entrypoint setup, and S3 sync.
- **Understand AWS resources or Terraform constraints for a single region:** [Regional runtime infrastructure](infrastructure/regional-runtime.md) describes ECS, EFS, IAM grants, audit storage, Lambda, encryption, and Bedrock resources and their data-source handoff to account-owned identities.
- **Understand account-wide IAM identity and budget ownership:** [Account-level IAM identity and budget ownership](infrastructure/account-identity-ownership.md) documents the `deploy/account` Terraform root and its shared-iam module, which own role identities, trust policies, OIDC providers, common managed-policy attachments, and the account-wide Bedrock budget/model agreements — and explains the account/regional IAM ownership split and the state-migration handoff from the former regional-owned identities.
- **Add an HCP Terraform workspace or trace staging plans and applies:** [HCP Terraform workspace integration](infrastructure/hcp-terraform-workspaces.md) follows bootstrap, meta-workspace, AWS credential, account, network, and regional workload workspaces across repositories, including run triggers and first-run prerequisites.
- **Find audit records, log groups, retrieval commands, retention, and coverage limits:** [Auditing and logging flows](operations/audit-and-logging.md) distinguishes CloudWatch streams, S3 workspace escrow, Bedrock payload logging, and account-managed CloudTrail.
- **Trace OCM credential handling:** [Credential lifecycle](security/credential-lifecycle.md) documents access-token acquisition, ECS Exec transfer, task-side validation, ephemeral storage, and cleanup.
- **Understand the Keycloak deployment and its OIDC consumers:** [Keycloak integration](integrations/keycloak-deployment.md) links OpenShift Kustomize resources to the CLI, Lambda, and IAM configuration, including the account-owned OIDC provider resources.
- **Choose a test suite or understand CI behavior:** [Testing and verification](testing/verification.md) maps tests to behaviors and distinguishes LocalStack local-executor runs from Prow's task-capable setup, including the account/regional Terraform ownership test suites.

## Start from the main flow

The operator CLI obtains OIDC-backed AWS credentials and invokes the create-investigation Lambda; the Lambda authorizes the identity, provisions an EFS-backed workspace, and can launch an ECS Fargate task; the regional Terraform root defines that ECS task definition and the other regional AWS resources that support the flow, while a separate account Terraform root owns the underlying IAM role identities, trust policies, and OIDC providers that the regional root only looks up and attaches inline grants to. For the request path, begin with the [system overview](architecture/system-overview.md), then follow the [investigation lifecycle](workflows/investigation-lifecycle.md). For detailed authorization or resource ownership, continue to [identity and access](architecture/identity-and-access.md), [regional infrastructure](infrastructure/regional-runtime.md), or [account identity ownership](infrastructure/account-identity-ownership.md).

## Evidence-backed claim

- The CLI passes task-start requests to the create-investigation Lambda, which provisions investigation state and can launch an ECS task; the regional Terraform root defines the Fargate task definition, which looks up its execution and task IAM roles by name via `data.aws_iam_role` rather than owning those roles itself — role identities and trust now belong to the separate account Terraform root. [CLI request path](repo://internal/cmd/start_task.go#L90-L104) · [Lambda dispatch](repo://lambda/create-investigation/handler.py#L243-L281) · [regional task definition](repo://deploy/regional/ecs.tf#L61-L70) · [account-owned role data-source lookups](repo://deploy/regional/account-iam.tf#L10-L13)
