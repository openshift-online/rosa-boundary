---
type: navigation
title: OpenWiki quickstart
description: Routes readers to the source-grounded architecture, investigation workflow, identity, runtime, infrastructure, HCP Terraform deployment, credential handling, Keycloak, and testing pages.
tags: [navigation, quickstart, rosa-boundary]
sources:
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-b123c673a5b90ca2010ffe64
    resource: repo://internal/cmd/start_task.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
generated: { by: "opencode", at: "2026-10-09T17:13:47.426Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-09T17:13:47.426Z
---

# OpenWiki quickstart

Use this page to find the part of ROSA Boundary that matches your question. This wiki was initialized from current implementation, configuration, and tests; the human-maintained `docs/` directory was not used as a source of truth.

## Find a topic

- **How the pieces fit together:** [System overview](architecture/system-overview.md) maps the Go CLI, AWS Lambda, Fargate runtime, persistence, and test boundaries.
- **Create, run, replace, connect, or close an investigation:** [Investigation lifecycle](workflows/investigation-lifecycle.md) follows state through the CLI, Lambda, ECS, EFS, and timeout reaper.
- **OIDC login, Lambda authorization, and ECS Exec permissions:** [Identity and access](architecture/identity-and-access.md) explains role selection and session-tag ABAC.
- **Build or troubleshoot the container and its startup/shutdown behavior:** [Container image and task runtime](runtime/container-image.md) covers architecture-specific builds, runtime identity, entrypoint setup, and S3 sync.
- **Understand AWS resources or Terraform constraints:** [Regional runtime infrastructure](infrastructure/regional-runtime.md) describes ECS, EFS, IAM, audit storage, Lambda, encryption, and Bedrock resources.
- **Reconstruct how staging was onboarded or trace HCP plans and applies:** [HCP Terraform staging onboarding and workspaces](infrastructure/hcp-terraform-workspaces.md) covers the AWS account, app-interface, infra-platform, GitHub App and bot identities, permissions, dynamic credentials, network/account/regional workspaces, Prow distinction, run triggers, and first-run prerequisites.
- **Find audit records, log groups, retrieval commands, retention, and coverage limits:** [Auditing and logging flows](operations/audit-and-logging.md) distinguishes CloudWatch streams, S3 workspace escrow, Bedrock payload logging, and account-managed CloudTrail.
- **Trace OCM credential handling:** [Credential lifecycle](security/credential-lifecycle.md) documents access-token acquisition, ECS Exec transfer, task-side validation, ephemeral storage, and cleanup.
- **Understand the Keycloak deployment and its OIDC consumers:** [Keycloak integration](integrations/keycloak-deployment.md) links OpenShift Kustomize resources to the CLI, Lambda, and IAM configuration.
- **Choose a test suite or understand CI behavior:** [Testing and verification](testing/verification.md) maps tests to behaviors and distinguishes LocalStack local-executor runs from Prow's task-capable setup.

## Start from the main flow

The operator CLI obtains OIDC-backed AWS credentials and invokes the create-investigation Lambda; the Lambda authorizes the identity, provisions an EFS-backed workspace, and can launch an ECS Fargate task; Terraform defines the regional AWS resources that support that flow. For the request path, begin with the [system overview](architecture/system-overview.md), then follow the [investigation lifecycle](workflows/investigation-lifecycle.md). For detailed authorization or resource ownership, continue to [identity and access](architecture/identity-and-access.md) or [regional infrastructure](infrastructure/regional-runtime.md).

## Evidence-backed claim

- The CLI passes task-start requests to the create-investigation Lambda, which provisions investigation state and can launch an ECS task; Terraform defines the Fargate task and its supporting resources. [CLI request path](repo://internal/cmd/start_task.go#L90-L104) · [Lambda dispatch](repo://lambda/create-investigation/handler.py#L243-L281) · [regional task definition](repo://deploy/regional/ecs.tf#L62-L82)
