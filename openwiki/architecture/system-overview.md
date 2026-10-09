---
type: architecture
title: System overview and boundaries
description: Maps the ROSA Boundary CLI, AWS identity, investigation Lambda, Fargate runtime, persistent and task-scoped storage, and verification layers by responsibility.
tags: [architecture, system-overview, aws, ecs, investigations]
sources:
  - id: openwiki-source-40c7b4fa49977c539f479848
    resource: repo://cmd/rosa-boundary/main.go
  - id: openwiki-source-45393b666c4d8ce854ed025b
    resource: repo://deploy/account/README.md
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-7a5e071b6b6192c80a6918aa
    resource: repo://internal/cmd/root.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
  - id: openwiki-source-30a9bbeef6a7c1bda59eab80
    resource: repo://tests/localstack/integration/test_full_workflow.py
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
---

# System overview and boundaries

ROSA Boundary is an operator CLI plus a two-root AWS Terraform deployment for ephemeral SRE investigations. The system separates operator authentication and orchestration from privileged resource creation and task execution: the Go CLI obtains OIDC-backed AWS credentials, the create-investigation Lambda validates the user's token and provisions the investigation, and ECS Fargate runs the SRE tool container. Terraform ownership is itself split into an account-level identity root and a regional infrastructure root (see [Account identity ownership](../infrastructure/account-identity-ownership.md)); the repository's Kustomize manifests separately define the Keycloak deployment components.

## Responsibility boundaries

- **CLI (`cmd/rosa-boundary`, `internal/`)** — exposes login/configuration and investigation/task commands. Shared command setup resolves configuration and performs OIDC-to-STS authentication. `start-task` invokes Lambda directly through the AWS SDK, assumes the shared SRE role for ECS operations, optionally waits for task readiness, and can configure credentials or connect.
- **Create-investigation Lambda (`lambda/create-investigation/`)** — is the authorization and provisioning boundary. It validates the OIDC token and group claims, establishes the ABAC identity, creates or reuses the investigation's EFS access point, and when requested registers a task definition and launches a Fargate task.
- **ECS task (`Containerfile`, `entrypoint.sh`)** — is the ephemeral operator environment. ECS Exec sessions enter as `sre`; the root entrypoint performs controlled setup, verifies task-scoped credential overlays, then launches the requested workload as `sre`. On shutdown it attempts a bounded S3 sync of the persistent home while excluding credential state.
- **Account Terraform (`deploy/account/`)** — is a distinct, separately applied Terraform root that owns Boundary's shared IAM role identities (execution, task, shared SRE, invoker, create-investigation Lambda, reaper Lambda, Bedrock logging, and optional S3 replication roles), their trust policies, the OIDC providers, the common AWS-managed policy attachments, and the account-wide Bedrock budget and model agreements. These identities are account-global, not regional.
- **Regional Terraform (`deploy/regional/`)** — looks up the account-owned roles and OIDC providers by name/issuer via data sources (no remote-state access) and owns only the regional inline permission grants on those roles plus the ECS, EFS, S3, KMS/logging, and Lambda *resources* and their connections. The regional task definition mounts a shared EFS home and empty per-task overlays at OCM and kubeconfig paths; the investigation Lambda replaces the home volume with an investigation-specific access point at launch. See [Account identity ownership](../infrastructure/account-identity-ownership.md) and [Regional runtime](../infrastructure/regional-runtime.md) for the full ownership table and migration mechanics.
- **Tests** — Go and Lambda unit tests isolate logic with fakes/mocks; bats tests exercise shell boundaries; Terraform tests validate input constraints; LocalStack integration tests exercise AWS resource/API interactions using fixture-created resources.

## Main request flow

For a new task, the CLI authenticates as the operator and assumes the Lambda invoker role. It invokes the create-investigation Lambda with cluster and investigation identifiers. The Lambda checks the caller's token and required group membership, then creates/reuses an EFS access point rooted at `/<cluster-id>/<investigation-id>`. For a task launch it builds a per-investigation task definition from the configured base definition, substituting the access point and investigation parameters, then calls ECS `RunTask` with ECS Exec enabled and tags needed for ABAC, audit, and task-timeout enforcement. The CLI next assumes the shared SRE role, waits for `RUNNING` unless `--no-wait` was selected, and emits connection details (or joins when requested).

The CLI distinguishes the ROSA cluster identifier being investigated from the ECS cluster that hosts the task. Lambda receives the former as investigation context; ECS API calls use the configured ECS cluster name.

## State and containment

Investigation work files persist in an EFS access point scoped to the ROSA cluster and investigation identifiers. OCM configuration and kubeconfig are mounted over that home from task-scoped empty volumes so they do not persist with EFS. The container's exit sync is best-effort and time-bounded; it excludes those credential-bearing paths and does not follow symlinks. A scheduled reaper Lambda separately enforces task deadlines from ECS tags—the timeout printed by the container is informational, not the enforcement mechanism. The reaper additionally checks for an active ECS Exec/SSM session before stopping an expired task and fails closed (treats the task as protected or errors out, without stopping it) whenever that session state cannot be reliably determined; see [Investigation lifecycle](../workflows/investigation-lifecycle.md) for the full deadline/reaping lifecycle.

## Verification boundaries

LocalStack integration tests create representative IAM, ECS, and EFS resources and assert cross-service relationships such as task tags, task-definition EFS access-point wiring, deadline processing, and cleanup. They are not a substitute for the Go/Lambda unit tests or shell tests, which cover logic and failure paths unavailable from an AWS API integration test alone. The LocalStack suite may not execute task containers under the local executor; this is explicit in the slow end-to-end test's skip condition.

## Evidence-backed claims

- The CLI uses a centralized OIDC/STS pre-run hook and selects the Lambda invoker role for create/start commands, with a separate SRE role for operational commands. [CLI root](repo://internal/cmd/root.go#L154-L207) · [task-start orchestration](repo://internal/cmd/start_task.go#L90-L207)
- The Lambda validates the user, creates/reuses an investigation EFS access point, creates a per-investigation task definition, and launches a Fargate task with ECS Exec and identifying/deadline tags. [authorization and dispatch](repo://lambda/create-investigation/handler.py#L175-L281) · [resource creation and launch](repo://lambda/create-investigation/handler.py#L641-L905)
- `deploy/account` is a separate Terraform root and state that owns the shared IAM role identities, their trust policies, the OIDC providers, the common AWS-managed policy attachments, and the account-wide Bedrock budget/model agreements; `deploy/regional` looks those identities up by name/issuer via data sources and owns only the regional inline grants on them. [account ownership](repo://deploy/account/README.md#L1-L21) · [regional role/OIDC lookups](repo://deploy/regional/account-iam.tf#L1-L46)
- ECS task infrastructure looks up the account-owned execution and task role ARNs via data sources and mounts a persistent EFS home plus task-scoped OCM and kubeconfig overlays; entrypoint rejects missing or EFS-backed overlays and uses a protected S3 sync on exit. [task role lookups](repo://deploy/regional/ecs.tf#L61-L70) · [EFS/overlay mounts](repo://deploy/regional/ecs.tf#L71-L159) · [mount verification and sync](repo://entrypoint.sh#L3-L67) · [runtime shutdown](repo://entrypoint.sh#L167-L183)
- The reaper lists RUNNING ECS tasks, computes each task's deadline from its tags, and before stopping an expired task calls `has_active_ssm_session` to check the task's `enableExecuteCommand` flag and query SSM `DescribeSessions` for an active ECS Exec session; it fails closed (recording a `protected` or `errors` outcome instead of stopping the task) whenever exec/session state is missing, ambiguous, or the SSM call fails. [reaper handler](repo://lambda/reap-tasks/handler.py#L48-L206) · [session-check helpers](repo://lambda/reap-tasks/handler.py#L246-L361) · [deadline lifecycle integration](repo://tests/localstack/integration/test_full_workflow.py#L221-L260)
- LocalStack integration tests verify relationships between provisioned task tags, shared-role ABAC, access points, and task-definition mounts; execution of actual task containers is conditionally skipped for the local executor. [full workflow assertions](repo://tests/localstack/integration/test_full_workflow.py#L21-L137) · [container-execution condition](repo://tests/localstack/integration/test_full_workflow.py#L214-L220)
