---
type: navigation
title: OpenWiki quickstart
description: Routes readers to the right page for both monorepo components — ROSA Boundary (CLI, investigation Lambda, ECS/EFS runtime, HCP Terraform, Keycloak/OIDC identity, audit, credentials) and Trusted Actions (API, authorization, execution, audit, deployment, testing) — and states what the files-only Trusted Actions import did and did not change.
tags: [navigation, quickstart, rosa-boundary, trusted-actions]
sources:
  - id: openwiki-source-b3cacc865e62dc31f0a55b4a
    resource: repo://.tekton/rosa-boundary-pull-request.yaml
  - id: openwiki-source-eebdf2baefd63a03b1cb3b5e
    resource: repo://.tekton/rosa-trusted-actions-pull-request.yaml
  - id: openwiki-source-12238a6f88dc834f61553058
    resource: repo://.tekton/rosa-trusted-actions-push.yaml
  - id: openwiki-source-4c833b02bf6d5fc7a2476dea
    resource: repo://components/trusted-actions/Makefile
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-45ce132817cdbbe35348bf04
    resource: repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
  - id: openwiki-source-37ce5ca787d481a0d0fc0453
    resource: repo://hcp-terraform/rosa-trusted-actions/main.tf
  - id: openwiki-source-f18b195b06299be0877c0d2e
    resource: repo://internal/cmd/create_investigation.go
  - id: openwiki-source-2452fe2ff931e1490d573519
    resource: repo://internal/cmd/start_session.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
generated: { by: "opencode", at: "2026-11-13T18:18:24.408Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-11-13T18:18:24.408Z
---

# OpenWiki quickstart

This repository now hosts **two independently owned, built, and deployed
components**: **ROSA Boundary** (the original product) and **Trusted Actions**
(imported as files only; see [Monorepo components](architecture/monorepo-and-trusted-actions.md)
for exactly what moved). Use this page to find the part of either component
that matches your question. Verify behavior against current implementation,
configuration, and tests; linked human-maintained runbooks supply operational
procedures, not proof of live deployment or access.

## Repository-wide CI/CD and verification

- **What CI/CD configuration and local gates are defined in this repository?** [Repository CI/CD configuration and quality gates](operations/ci-cd-and-quality-gates.md) covers the six `.tekton/` PipelineRuns, Git-managed HCP workspace declarations, pre-commit hooks, and local test/lint targets for Boundary and Trusted Actions. External Prow job definitions, GitHub-managed checks, Konflux release plans, and live results require independent verification; for a dated review with external evidence, see the human-maintained [`docs/ci-cd.md`](../docs/ci-cd.md).

## Find a topic — ROSA Boundary

- **How the pieces fit together:** [System overview](architecture/system-overview.md) maps the Go CLI, AWS identity, investigation Lambda, Fargate runtime, persistent/task-scoped storage, and the two independent scheduled cleanup Lambdas (per-task timeout reaping and whole-investigation garbage collection), and situates this flow relative to the co-located but independently built/deployed Trusted Actions component.
- **Create, run, replace, connect, or close an investigation:** [Investigation lifecycle](workflows/investigation-lifecycle.md) follows CLI/Lambda/ECS/EFS state, handover, task deadlines, creation-age and legacy-timestamp GC eligibility, required final backups, and the interaction between close and reaper discovery.
- **OIDC login, Lambda authorization, and ECS Exec permissions:** [Identity and access](architecture/identity-and-access.md) explains role selection and session-tag ABAC.
- **Build or troubleshoot the container and its startup/shutdown behavior:** [Container image and task runtime](runtime/container-image.md) covers architecture-specific builds, runtime identity, entrypoint setup, and S3 sync.
- **Understand AWS resources and account/regional ownership:** [Regional runtime infrastructure](infrastructure/regional-runtime.md) covers ECS, EFS, audit storage, Lambda, shared IAM identities versus regional inline grants, policy-name collision prevention, and multi-region Bedrock logging trust.
- **Trace staging and production plans, authorization, and applies:** [HCP Terraform workspace integration](infrastructure/hcp-terraform-workspaces.md) maps staging's six L3 workspaces: credentials, account, and separate network/runtime workspaces for `us-east-1` and `us-west-2`, plus the separate `rosa-boundary-prod` AWS account, which has grown to six registered workspaces of its own (credentials, account, and `us-east-1`/`us-west-2` network/regional pairs). It explains VCS integration, dynamic-credential authorization versus variable-set bindings, the staging workspaces' default/explicit auto-apply, the fact that only `rosa-boundary-prod-aws-creds` still keeps a manual (`auto_apply = false`) gate while the other five prod workspaces now set `auto_apply = true` like staging, sibling ordering, and image promotion. This map is Boundary's own HCP Terraform footprint and is distinct from Trusted Actions' separate `hcp-terraform/rosa-trusted-actions/` workspace tree.
- **Find audit records and request read access:** [Auditing and logging flows](operations/audit-and-logging.md) distinguishes CloudWatch transcripts, S3 snapshots, Bedrock payloads and CloudTrail coverage, and links the scoped S3 audit-reader procedure separately from CloudWatch read permissions — distinct from Trusted Actions' own audit pipeline below.
- **Trace OCM credential handling:** [Credential lifecycle](security/credential-lifecycle.md) documents access-token acquisition, ECS Exec transfer, task-side validation, ephemeral storage, and cleanup.
- **Understand the Keycloak deployment and its OIDC consumers:** [Keycloak integration](integrations/keycloak-deployment.md) links OpenShift Kustomize resources to the CLI, Lambda, and IAM configuration.
- **Choose a test suite or understand CI behavior:** [Testing and verification](testing/verification.md) covers legacy-staleness regressions, Lambda discovery boundaries, mocked IAM ownership/trust checks, known account-test drift, and LocalStack local-executor versus Prow task-capable runs.

## Find a topic — Trusted Actions

- **Understand what the monorepo merge did (and did not) change:** [Monorepo components: Boundary and Trusted Actions](architecture/monorepo-and-trusted-actions.md) is the required starting point — it covers the files-only import boundary, ownership, and which systems (for example the Go module path `github.com/openshift-online/rosa-trusted-actions` and its GitHub release artifacts) still reference the original `openshift-online/rosa-trusted-actions` repository even though its HCP Terraform workspaces and Tekton triggers are already committed as rebound to this monorepo.
- **How the service is layered:** [Trusted Actions architecture](architecture/trusted-actions-overview.md) explains the request path (router → middleware → handlers → store) and the execution path (worker pool → runner → executor → action → backplane → cluster/cloud), plus the action plugin model and OpenAPI-first code generation.
- **Who can call which action:** [Trusted Actions authorization model](architecture/trusted-actions-authorization.md) documents caller identity/role resolution against OCM AMS, per-action role allowlisting, and the separate resource-level (namespace/secret) authorization enforced inside the executor scope.
- **The HTTP contract and client tooling:** [Trusted Actions API surface and clients](integrations/trusted-actions-api.md) documents the OpenAPI-defined catalog/run/runs/audit endpoints, the OCM-JWT security scheme, the `rta` command, `action-cli`, `test-client`, `scripts/test-api.sh`, and the external Backplane/OCM dependencies.
- **How a run actually executes:** [Trusted Actions execution pipeline](workflows/trusted-actions-execution.md) traces store persistence, worker-pool claiming, executor scope resolution, backplane client provisioning, action execution, and result/output retrieval.
- **Audit and log records:** [Trusted Actions audit and logging](operations/trusted-actions-audit.md) documents the per-call audit record model, its middleware-level injection, and the regional CloudWatch → Firehose → S3 pipeline — kept distinct from Boundary's own audit flows.
- **Terraform and runtime deployment:** [Trusted Actions deployment and infrastructure](infrastructure/trusted-actions-deployment.md) documents the two-tier Terraform deployment (global account-wide IAM/secrets, regional VPC/ALB/ECS/EC2/S3/DNS), the ECS+ALB runtime co-located in the `rosa-boundary` AWS account, the Postgres-or-SQLite store, and the `hcp-terraform/rosa-trusted-actions` meta-workspace, whose two HCP workspaces are committed as rebound to this repository's `components/trusted-actions/terraform/{global,regional}` roots.
- **Tests and CI:** [Trusted Actions testing and CI](testing/trusted-actions-testing.md) covers the unit/integration/mock-dependency test strategy, coverage enforcement, and how build/test targets run from `components/trusted-actions` independent of the root Makefile.

**Important:** this merge is a **files-only source import** — no Trusted
Actions Git history came with it. That said, the *committed* configuration in
this repository already reflects a cutover, not a pending one: both
`hcp-terraform/rosa-trusted-actions/main.tf` workspaces (`rosa-trusted-actions-global`
and `rosa-trusted-actions-stage`) declare `github_repo_name = "rosa-boundary"`
and working directories under `components/trusted-actions/terraform/`, and
the `.tekton/rosa-trusted-actions-push.yaml` / `-pull-request.yaml`
PipelineRuns no longer carry a hard `false &&` disable on their
`pipelinesascode.tekton.dev/on-cel-expression` trigger — both expressions
evaluate normally for push/PR events touching `components/trusted-actions/***`
or the pipeline file itself. A comment above each expression ("Enable only at
the coordinated cutover after checking the shared image/release destination")
remains in the files as a record of the earlier pre-cutover state, not an
instruction still being enforced by the YAML. None of this is proof of
current live HCP run state, Prow/Tide merge behavior, or Konflux build/release
bindings for the imported copy — those live outside this repository and must
be checked directly. See
[Monorepo components](architecture/monorepo-and-trusted-actions.md) for the
full accounting of what was and was not imported.

## Start from the main flow

**Boundary:** the operator CLI obtains OIDC-backed AWS credentials and invokes the create-investigation Lambda; the Lambda authorizes the identity, provisions an EFS-backed workspace, and can launch an ECS Fargate task; Terraform defines the regional AWS resources that support that flow. For the request path, begin with the [system overview](architecture/system-overview.md), then follow the [investigation lifecycle](workflows/investigation-lifecycle.md). For detailed authorization or resource ownership, continue to [identity and access](architecture/identity-and-access.md) or [regional infrastructure](infrastructure/regional-runtime.md).

**Trusted Actions:** a caller presents an OCM token to the HTTP API, middleware authenticates and authorizes the request against the action's role allowlist, a handler persists a run and hands it to the worker pool, and an executor resolves a scoped Backplane/cluster client to run the action and record its audit entry. Begin with [Trusted Actions architecture](architecture/trusted-actions-overview.md), then follow the [execution pipeline](workflows/trusted-actions-execution.md); for the HTTP contract start at [the API surface](integrations/trusted-actions-api.md).

These two flows are independent: they do not share a runtime, a credentials path, an audit pipeline, or a deployment state. Boundary runs as a Fargate task launched per investigation with EFS-backed storage and CloudWatch/S3/CloudTrail audit coverage described under [auditing and logging](operations/audit-and-logging.md); Trusted Actions runs as a long-lived ECS+ALB service with a Postgres-or-SQLite store and its own CloudWatch→Firehose→S3 audit pipeline described under [Trusted Actions audit and logging](operations/trusted-actions-audit.md). Do not conflate the two when reasoning about credentials, blast radius, or deployment state.

## Evidence-backed claims

- The CLI's investigation-creation path is split across two commands that both call the create-investigation Lambda with a SigV4-signed AWS SDK client: `investigation create` (`internal/cmd/create_investigation.go`) invokes it with `skip_task=true` to provision or reuse only the EFS access point, while `session create` (`internal/cmd/start_session.go`) invokes it without that flag to also launch the ECS Fargate task, deriving the session/task ID from the returned task ARN and the SRE role ARN from the response (falling back to the profile's configured role only if the Lambda omits one). The Lambda itself (`lambda/create-investigation/handler.py`) validates the OIDC operator and required group membership before dispatching to a shared routine that provisions or reuses an investigation EFS access point and can launch a Fargate task using a per-investigation task definition derived from the regional task definition. [CLI EFS-only invocation](repo://internal/cmd/create_investigation.go#L40-L60) · [CLI session/task invocation](repo://internal/cmd/start_session.go#L59-L98) · [Lambda dispatch and authorization](repo://lambda/create-investigation/handler.py#L79-L300) · [Lambda access-point and task launch](repo://lambda/create-investigation/handler.py#L693-L1051) · [regional task definition](repo://deploy/regional/ecs.tf#L62-L82)
- The staging workspace map declares one credentials workspace, one account workspace, and east/west pairs of network and regional runtime workspaces; both regional states reuse `deploy/regional`, and both network states reuse `deploy/network`. These six staging workspaces are not the entirety of the module's HCP Terraform footprint: a separate `rosa-boundary-prod` account defines six more. (A further, entirely separate `hcp-terraform/rosa-trusted-actions/` tree holds Trusted Actions' own workspaces — see the dedicated Trusted Actions claim below.) [east network](repo://hcp-terraform/rosa-boundary/main.tf#L36-L69) · [west network](repo://hcp-terraform/rosa-boundary/main.tf#L71-L139) · [credentials and account](repo://hcp-terraform/rosa-boundary/main.tf#L141-L328) · [east runtime](repo://hcp-terraform/rosa-boundary/main.tf#L330-L521) · [west runtime](repo://hcp-terraform/rosa-boundary/main.tf#L523-L706)
- `hcp-terraform/rosa-boundary/main.tf` also defines a separate `rosa-boundary-prod` AWS account (distinct AWS account ID `514903006123`, confirmed by `hcp-terraform/aws-creds/rosa-boundary-prod/main.tf`'s `allowed_account_ids`), which has grown from its initial credentials/account pair to six registered workspaces: credentials, account, and `us-east-1`/`us-west-2` network/regional pairs, all reusing the same `deploy/network` and `deploy/regional` source roots as staging. All six prod workspaces set `execution_mode = "remote"`, but only `rosa-boundary-prod-aws-creds` still sets `auto_apply = false` and `auto_apply_run_trigger = false` as a manual-apply gate; the other five prod workspaces (account, network-us-east-1, regional-us-east-1, network-us-west-2, regional-us-west-2) set `auto_apply = true` and `auto_apply_run_trigger = true`, mirroring staging's auto-apply workspaces. `hcp-terraform/aws-creds/rosa-boundary-prod/main.tf`'s `workspace_names` allowlist now authorizes all six prod workspaces for AWS access. This `rosa-boundary` project's HCP footprint remains separate from Trusted Actions' own `hcp-terraform/rosa-trusted-actions/` workspace tree, which this merge did not alter. [prod aws-creds workspace](repo://hcp-terraform/rosa-boundary/main.tf#L709-L722) · [prod account workspace](repo://hcp-terraform/rosa-boundary/main.tf#L726-L905) · [prod network/regional us-east-1 workspaces](repo://hcp-terraform/rosa-boundary/main.tf#L909-L1132) · [prod network/regional us-west-2 workspaces](repo://hcp-terraform/rosa-boundary/main.tf#L1136-L1394) · [prod account ID](repo://hcp-terraform/rosa-boundary/main.tf#L751-L754) · [prod account ID confirmation](repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf#L16-L20) · [prod workspace_names allowlist](repo://hcp-terraform/aws-creds/rosa-boundary-prod/main.tf#L38-L45) · [staging auto-apply, e.g. account workspace](repo://hcp-terraform/rosa-boundary/main.tf#L153-L160)
- Trusted Actions' source, Terraform, and Tekton configuration were imported into this repository as files only (no Git history), but the *committed* Terraform and Tekton configuration already reflects a rebind to this repository rather than the original one: `hcp-terraform/rosa-trusted-actions/main.tf`'s `rosa-trusted-actions-global` and `rosa-trusted-actions-stage` workspaces both declare `github_repo_name = "rosa-boundary"` and working directories under `components/trusted-actions/terraform/{global,regional}` (not the archived `rosa-trusted-actions` repository), and the copied `.tekton/rosa-trusted-actions-push.yaml` / `rosa-trusted-actions-pull-request.yaml` pipelines no longer carry a `false &&` guard on their `on-cel-expression` trigger — both evaluate normally for push/PR events touching `components/trusted-actions/***` or the pipeline file, though a retained comment above each expression ("Enable only at the coordinated cutover after checking the shared image/release destination") records the earlier pre-cutover state rather than an active guard. Both pipelines still publish to `quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions:{{revision}}` (or `on-pr-{{revision}}`), matching the image reference consumed by the regional HCP workspace. None of this is evidence of Trusted Actions' current live HCP run state, Prow/Tide merge behavior, or Konflux build/release bindings — only the committed configuration is described here; verify live platform state directly. [global workspace rebound to rosa-boundary](repo://hcp-terraform/rosa-trusted-actions/main.tf#L39-L50) · [regional workspace rebound to rosa-boundary](repo://hcp-terraform/rosa-trusted-actions/main.tf#L114-L120) · [push trigger without false && guard](repo://.tekton/rosa-trusted-actions-push.yaml#L1-L28) · [pull-request trigger without false && guard](repo://.tekton/rosa-trusted-actions-pull-request.yaml#L1-L20)
