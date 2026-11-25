---
type: architecture
title: ROSA Boundary System Overview
description: Maps the ROSA Boundary Go CLI and control-plane code layout, the ephemeral SRE investigation container on ECS Fargate, the Lambda-based investigation lifecycle, and the Terraform stacks that wire them together, and situates this flow relative to the co-located but independently built/deployed Trusted Actions component.
tags: [architecture, system-overview, aws, ecs, fargate, go, investigations, trusted-actions, monorepo]
sources:
  - id: openwiki-source-8037e2358a2c4f9b2c722a11
    resource: repo://AGENTS.md
  - id: openwiki-source-40c7b4fa49977c539f479848
    resource: repo://cmd/rosa-boundary/main.go
  - id: openwiki-source-56c54c10348f1e72daffc214
    resource: repo://components/trusted-actions/go.mod
  - id: openwiki-source-8ea12a05c67ed54e49e49437
    resource: repo://Containerfile
  - id: openwiki-source-f4745022f20c2f39d1db313b
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf
  - id: openwiki-source-ee86c0d48b646d4bc6813442
    resource: repo://deploy/account/outputs.tf
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-81b84da9542934c33f2e42d7
    resource: repo://deploy/regional/lambda-reap-investigations.tf
  - id: openwiki-source-a055ff9a3fcbd2c0a0fc4ee2
    resource: repo://deploy/regional/variables.tf
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-7bd911fdd3026b7b031a01e3
    resource: repo://go.mod
  - id: openwiki-source-d2f66eb6a0ccf1ed7a35e866
    resource: repo://internal/cmd/cli.go
  - id: openwiki-source-7a5e071b6b6192c80a6918aa
    resource: repo://internal/cmd/root.go
  - id: openwiki-source-2452fe2ff931e1490d573519
    resource: repo://internal/cmd/start_session.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-53ded000b5419d48efde6aba
    resource: repo://lambda/reap-investigations/close_finalization.py
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
  - id: openwiki-source-30a9bbeef6a7c1bda59eab80
    resource: repo://tests/localstack/integration/test_full_workflow.py
generated: { by: "pi", at: "2026-11-25T19:00:35.491Z" }
verified:
  - by: openwiki/0.9.0
    at: 2026-11-25T19:00:35.491Z
---

# ROSA Boundary system overview

Boundary gives an operator a temporary Fargate session backed by an investigation-specific EFS workspace. Ending the shell, stopping its task, and closing the investigation are separate operations.

## From CLI to task

The CLI entrypoint delegates to cmd.Execute in the Boundary module, which declares Go 1.27.4. The command tree and authentication pre-run live in cli.go, dispatch and STS retry in root.go, and session launch and connection orchestration in start_session.go. The CLI assumes the invoker role for create and close-status lookup. Ordinary close starts with SRE credentials for preview and needs invoker credentials for submission. The creation handler checks the token, group and ABAC identity before dispatching resource creation. Replacement requires known different task ownership and confirmed shell absence. Matching identity directs the caller to join; partial identity or incomplete session evidence blocks replacement. Task creation binds an investigation access point to the task definition, preserves task-local credential overlays, and launches Fargate with ECS Exec and identifying tags.

The home persists between tasks. Startup checks that OCM and kubeconfig mounts are task-local rather than EFS-backed. Container exit sync stops the skill reconciler, waits for writers under a watchdog, and excludes credential overlays and symlink targets from the S3 transfer. This best-effort copy is not close verification.

## Timeout and verified close

The independently scheduled investigation sweep discovers whole workspaces for close; the task reaper enforces session age limits, including an eight-hour cap independent of the optional idle timeout. The investigation sweep distinguishes expiry from idle eligibility. Missing CreatedAt counts as expired; expiry closes admission without proving shell absence. INVESTIGATION_EXPIRY_HOURS defaults to 168 hours in the handler and comes from investigation_grace_period_hours in Terraform, also defaulting to 168.

Normal close verifies the workspace copy before cleanup and retains the EFS directory. Stale cleanup may reclaim it if enabled. Task-definition cleanup precedes access-point deletion; the receipt records verification and cleanup separately. Accepting a request does not establish that tasks have stopped or that a verified receipt exists.

## Build and deployment boundaries

The root container build includes a dedicated rta-builder stage; the final operator image installs its binary and runs entrypoint.sh with sleep infinity as the default command. Trusted Actions has a separate module and server deployment. The Boundary image includes its rta client, and regional task configuration can supply RTA_SERVER; this is client integration, not a shared authorization or audit service.

Boundary's Lambda handlers and Terraform roots remain at the repository root. Account Terraform owns shared identities and managed-policy attachments; regional roots add region-specific inline grants on those roles and own the runtime resources.

## Verification boundaries

LocalStack integration tests create representative IAM, ECS, and EFS resources and assert cross-service relationships such as task tags, task-definition EFS access-point wiring, deadline processing, and cleanup. They are not a substitute for the Go/Lambda unit tests or shell tests, which cover logic and failure paths unavailable from an AWS API integration test alone. The LocalStack suite may not execute task containers under the local executor; this is explicit in the slow end-to-end test's skip condition.

## Related pages

- [Investigation lifecycle](../workflows/investigation-lifecycle.md) — handover, close, timeout, and garbage-collection details.
- [Container image and task runtime](../runtime/container-image.md) — full `Containerfile` build/verification detail and entrypoint startup/shutdown behavior.
- [Regional infrastructure](../infrastructure/regional-runtime.md) and [HCP workspaces](../infrastructure/hcp-terraform-workspaces.md) — resource ownership and staging's regional states.
- [Identity and access](identity-and-access.md) and [auditing](../operations/audit-and-logging.md) — authorization and operational evidence.
- [Monorepo and Trusted Actions](monorepo-and-trusted-actions.md) — ownership, build, and deployment independence of the co-located Trusted Actions component.
