---
type: testing
title: Testing and verification strategy
description: Maps Go, Lambda, shell, Terraform IAM/model, and LocalStack tests to their contracts, including legacy-staleness regressions, test-discovery boundaries, and known account-test drift.
tags: [testing, unit-tests, integration-tests, localstack, ci]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-10T16:03:08.957Z
sources:
  - id: openwiki-source-56c54c10348f1e72daffc214
    resource: repo://components/trusted-actions/go.mod
  - id: openwiki-source-4c833b02bf6d5fc7a2476dea
    resource: repo://components/trusted-actions/Makefile
  - id: openwiki-source-7afccf6bb50a66b861c2b750
    resource: repo://deploy/account/Makefile
  - id: openwiki-source-e0e8c15f232fd81f46f03e41
    resource: repo://deploy/account/modules/shared-iam/iam.tf
  - id: openwiki-source-65e02007ebea688b767a848b
    resource: repo://deploy/account/modules/shared-iam/lambda-create-investigation.tf
  - id: openwiki-source-f4745022f20c2f39d1db313b
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf
  - id: openwiki-source-ca5deb97ae20b796aad13c09
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-tasks.tf
  - id: openwiki-source-13bc46f3694506473af729bc
    resource: repo://deploy/account/tests/baseline.tftest.hcl
  - id: openwiki-source-e63bbacd264bc409c45ddf07
    resource: repo://deploy/account/tests/shared-iam.tftest.hcl
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-1599d372a558b44029d5589b
    resource: repo://deploy/regional/tests/iam-ownership.tftest.hcl
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
  - id: openwiki-source-bb51fbbb404e02867c4bd266
    resource: repo://lambda/reap-investigations/test_handler.py
  - id: openwiki-source-9c54377d52ae59aed2d249c7
    resource: repo://lambda/reap-tasks/test_handler.py
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
  - id: openwiki-source-d482d1f96b1110689c18ec99
    resource: repo://tests/localstack/ci-run.bats
  - id: openwiki-source-38fbf433aefe6645b985c0ac
    resource: repo://tests/localstack/ci-run.sh
  - id: openwiki-source-3732999215bf4e723553d573
    resource: repo://tests/localstack/compose.yml
  - id: openwiki-source-cc51d0899e030946c3f99112
    resource: repo://tests/localstack/conftest.py
  - id: openwiki-source-f646ed6ea41f0e6b04102f78
    resource: repo://tests/localstack/integration/test_task_timeout.py
  - id: openwiki-source-c0cdf2dd91cc32b1156060f9
    resource: repo://tests/localstack/required_services.py
  - id: openwiki-source-80fcaf58926aeda8dd2be405
    resource: repo://tests/unit/test_reap_investigations_staleness.py
generated: { by: "openwiki/0.7.1", at: "2026-11-10T16:03:08.957Z" }
---

# Testing and verification strategy

The repository uses several test layers because no single environment covers the CLI, container scripts, Terraform policy shape, Lambda logic, and AWS API interactions. Go and Python unit tests isolate logic; bats tests exercise shell behavior; Terraform tests use a mocked provider for input constraints; LocalStack tests exercise service APIs and relationships between AWS resources. Prow's `tests/localstack/ci-run.sh` adds service/readiness gates, Docker-compatible ECS task execution, JUnit artifacts, and failure logs around the LocalStack suite.

## Scope: root suites do not cover `components/trusted-actions`

Everything on this page describes the root `rosa-boundary` module's test layers — the Go CLI module rooted at the repository's top-level `go.mod`, the Lambda handlers under `lambda/`, the root Makefile's targets, and `tests/localstack`/`tests/unit`. `components/trusted-actions` is a separate Go module with its own `go.mod`, its own `Makefile`, and its own test suite; root `go test ./...` (via `make test-cli`/`make test-coverage`) does not walk into it, and none of the root Makefile's `test`, `test-all`, or `check` targets invoke it either, because Go module boundaries stop package discovery at the nested `go.mod` and the root Makefile never shells into `components/trusted-actions/`. To run that component's tests, use its own Makefile from the repository root: `make -C components/trusted-actions test` (or `cd components/trusted-actions && make test`). See [Trusted Actions testing and CI](trusted-actions-testing.md) for its unit/integration layers, mock-dependency strategy, and Codecov gate instead of duplicating that detail here.

## Unit and focused tests

- **Go CLI and libraries:** `make test-cli` runs `go test ./...`. Tests cover OIDC callback/PKCE and token cache behavior, command validation and role selection, AWS wrapper logic, Lambda invocation, and OCM credential transfer.
- **Investigation Lambda:** `make test-lambda-create-investigation` runs its pytest handler tests; they exercise request validation, OIDC/group authorization, error sanitization, investigation resource creation, and handover behavior with mocked AWS clients.
- **Task reaper Lambda:** `make test-lambda-reap-tasks` runs its `unittest` handler suite, including deadline parsing, stop errors, pagination, and task processing.
- **Investigation reaper Lambda:** `make test-lambda-reap-investigations` runs its `unittest` handler suite against `lambda/reap-investigations/handler.py`, covering staleness/grace-period detection (including just before, at, and after the threshold), legacy missing-`CreatedAt` handling at zero and nonzero grace values, EFS access-point/directory cleanup, task-definition deregistration, identifier/path validation, and backup-before-delete behavior. `make test-lambda` aggregates all three Lambda suites, not the separate `tests/unit/` pytest module below.
- **Shell:** the bats suites under `tests/shell/` source the entrypoint and credential helper and stub external commands to verify mount checks, cleanup, sync exclusions, input validation, and credential error handling without launching a container.
- **Build helper:** `make test-github-dl` runs tests for GitHub release download authentication, checksum validation, and build secret resolution.
- **Terraform:** mocked-provider suites check default Claude inference-profile/agreement consistency and the account/regional IAM ownership contracts described below. A mocked `command = apply` operates on test state, not the deployed AWS environment.

## Focused investigation-staleness regression tests

`tests/unit/test_reap_investigations_staleness.py` calls `is_investigation_stale` with timezone-aware times and small task snapshots. It asserts that an idle legacy investigation missing `CreatedAt` is stale, that a matching RUNNING task protects both old and legacy investigations, that creation ages inside/outside a 168-hour grace period differ, and that tasks belonging to another investigation do not protect this one. The Lambda's `unittest` suite separately checks missing timestamps at zero and nonzero grace values and exact threshold boundaries.

The standalone pytest module is **not discovered by `make test-lambda-reap-investigations` or `make test-lambda`**: those recipes change into the Lambda directory and run `unittest test_handler`. Select the file in a separate pytest process, for example `python3 -m pytest tests/unit/test_reap_investigations_staleness.py`, using a test environment with pytest/boto3, a test AWS Region and non-production credential configuration. The imported handler constructs boto3 clients at import time, so these import prerequisites still apply even though the selected tests exercise pure staleness logic. Do not treat a successful Lambda aggregate as evidence that this standalone module ran.

## Terraform ownership, regional grants, and trust tests

The regional `iam-ownership.tftest.hcl` renders grants with mocked AWS/archive providers. Its source-level assertions reject role/OIDC identity ownership, managed-policy attachments, and exclusive policy reconciliation in regional roots. It verifies grants attach to looked-up account roles, the one legacy region retains original policy names, additional regions append their own suffixes and render local resource scopes, and the reaper's EFS mount grant remains tied to its dedicated access point. These checks guard cross-state interference; they do not establish that live IAM role adoption or cross-region permissions work.

Account tests cover shared identity names/trust/tags and common attachments, the exported prefix/legacy-region contract, optional OIDC/replication settings, budget/model inputs, and validation failures. `shared-iam.tftest.hcl` explicitly checks an approved multi-region Bedrock logging `SourceArn` list while preserving `SourceAccount`; baseline validation cases reject wildcard regions and silently dropping the legacy region. The account Makefile exposes these through `make --directory=deploy/account test`; the regional Makefile currently has no `test` target, so do not invent a regional Make invocation or mistake `make validate` for running its test files.

> **Source-level verification reconciled:** `deploy/account/imports.tf` no longer exists in the repository, and the account baseline test's source-level ownership assertion no longer references it. The assertion now asserts exactly five `aws_iam_role_policy_attachment` resources under `modules/shared-iam` — the three pre-reaper attachments (`execution_managed` in `iam.tf`, `create_investigation_lambda_basic`, `reap_tasks_lambda_basic`) plus the investigation reaper role's basic and VPC execution attachments. The baseline test now reconciles with the reaper module's attachments instead of drifting from them.

## LocalStack integration tests

The pytest integration suite obtains boto3 clients from fixtures pointed at `LOCALSTACK_ENDPOINT` and waits for every service in `required_services.py`. A session-scoped `localstack_available` fixture, plus an autouse per-test recheck, both delegate to the shared `check_ready.require_ready` helper and fail the run with `pytest.fail` (not skip it) if the health endpoint is unreachable or any required service is not yet `available`/`running`; a session-scoped `boto_config` fixture supplies shared retry/timeout settings, and per-service client fixtures (`s3_client`, `iam_client`, `ecs_client`, `efs_client`, `kms_client`, `logs_client`, `sts_client`, `ec2_client`, `ssm_client`) depend on both before constructing a boto3 client against the local endpoint. Initialization provisions test network/resources and writes IDs into SSM Parameter Store; the `test_vpc` fixture polls for those parameters. Integration tests cover S3 audit settings and sync filtering, IAM/OIDC/ABAC policy shapes, ECS task definitions and tags, EFS access points/policies, KMS, kube-proxy mounts, deadline enforcement, and investigation cleanup/workflow relationships.

The local `compose.yml` configures LocalStack with `LAMBDA_EXECUTOR=local`, `ECS_EXECUTOR=local`, and a persistence volume for macOS/local compatibility. Slow tests that need task containers explicitly skip when `ECS_EXECUTOR=local`. `make test-localstack-fast` expects LocalStack to already be running and selects tests marked not slow. `make test-localstack` starts the local stack, runs the integration directory, and shuts it down.

## Prow LocalStack runner

The Prow entrypoint starts a Podman API socket, selects `ECS_EXECUTOR=docker`, pulls a pinned LocalStack Pro image, and starts LocalStack with the required service set and `init-aws.sh`. It waits for service health and an SSM sentinel written after test network parameters are initialized before running pytest. It writes JUnit XML, rejects a run where every test was skipped, and collects both container and internal LocalStack logs on exit. `tests/localstack/ci-run.bats` provides local-only tests of the JUnit gate, service readiness, and log collection; it cannot run in the Prow job itself because that job is the script under test.

This pre-merge LocalStack job does **not** prove a nightly real-infrastructure Prow E2E or Sippy integration. Verify periodic-job configuration and results in [`openshift/release`](https://github.com/openshift/release/tree/master/ci-operator/config/openshift-online/rosa-boundary) before claiming those are available. See [staging HCP onboarding](../infrastructure/hcp-terraform-workspaces.md#prow-and-image-delivery-are-separate-from-hcp-permissions) for the distinction between deployment credentials and build/test credentials.

## Choosing a test layer

Use the narrow unit suite for code paths that can be isolated and the focused bats suite for shell contract changes. Use LocalStack for AWS API behavior and cross-resource wiring, noting that local executor mode does not run real task containers. For ECS task launch/reaper behavior that depends on an actual task reaching `RUNNING`, use the Prow runner's docker executor or another supported non-local ECS executor. Terraform input checks and mocked resource-configuration tests are independent of LocalStack and live AWS authorization. Check the exact test selection and resolve the account-baseline drift above before reporting coverage. None of these mocks proves a live HCP apply, ECS Exec transcript delivery, Bedrock payload capture, or audit-reader access; use approved deployed-environment verification and retained evidence for those assertions.

## Evidence-backed claims

- The root Makefile defines separate Go, Lambda, build-helper, and LocalStack test targets; LocalStack fast mode requires a running endpoint, while full mode starts and tears down the stack. [LocalStack targets](repo://Makefile#L86-L127) · [Lambda targets](repo://Makefile#L175-L190) · [build helper target](repo://Makefile#L191-L201) · [Go test targets](repo://Makefile#L221-L229)
- The Makefile now defines three Lambda unit suites: the investigation Lambda suite runs with pytest, and the reap-tasks and reap-investigations suites both run with `unittest`; `test-lambda` aggregates all three, with the reap-investigations suite covering staleness/grace-period detection, EFS access-point and directory cleanup, task-definition deregistration, and identifier/path-traversal validation. [root Lambda targets](repo://Makefile#L175-L190) · [reap-tasks tests](repo://lambda/reap-tasks/test_handler.py#L7-L44) · [reap-investigations staleness/EFS cleanup tests](repo://lambda/reap-investigations/test_handler.py#L56-L213) · [task-definition deregistration tests](repo://lambda/reap-investigations/test_handler.py#L636-L692) · [identifier/path-traversal validation tests](repo://lambda/reap-investigations/test_handler.py#L840-L1015)
- LocalStack pytest fixtures check the health endpoint and require configured AWS services before returning service clients against the local endpoint; health polling itself is delegated to the shared `check_ready.require_ready` helper. [service requirements](repo://tests/localstack/required_services.py#L1-L6) · [health-gate / `localstack_available` fixture chain](repo://tests/localstack/conftest.py#L27-L45) · [shared boto config fixture](repo://tests/localstack/conftest.py#L48-L57) · [per-service client fixtures](repo://tests/localstack/conftest.py#L60-L165)
- The local compose configuration uses LocalStack's local Lambda and ECS executors with a persistence volume, while slow reaper integration tests skip in local mode because tasks do not reach RUNNING; the Prow script sets a Docker-compatible ECS executor. [local compose executor block](repo://tests/localstack/compose.yml#L1-L28) · [integration skip condition](repo://tests/localstack/integration/test_task_timeout.py#L16-L78) · [Prow Docker-compatible executor setup](repo://tests/localstack/ci-run.sh#L64-L88)
- The Prow runner waits for required services and initialized SSM state, writes JUnit results, rejects an all-skipped suite, and captures LocalStack logs on exit. [service and SSM readiness](repo://tests/localstack/ci-run.sh#L131-L235) · [pytest and JUnit gate](repo://tests/localstack/ci-run.sh#L237-L274) · [log collection trap](repo://tests/localstack/ci-run.sh#L43-L62)
- Local-only bats tests validate the CI runner's JUnit, readiness, and log collection helpers without launching LocalStack or Podman. [ci-run bats scope and setup](repo://tests/localstack/ci-run.bats#L1-L22) · [JUnit and log tests](repo://tests/localstack/ci-run.bats#L24-L79) · [readiness tests](repo://tests/localstack/ci-run.bats#L81-L101)
- Terraform's model test uses a mocked AWS provider and includes success for an approved profile plus failure cases for a bare model ID and missing model agreement. [mock provider setup](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L12-L66) · [model test cases](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L78-L115)
- Staleness regression tests assert that idle missing-`CreatedAt` investigations are stale, matching running tasks protect both legacy and old investigations, ages inside/outside a 168-hour threshold differ, and unrelated tasks do not protect the target investigation; the Lambda `unittest` suite separately covers missing timestamps at zero and nonzero grace values. [zero/nonzero grace cases](repo://lambda/reap-investigations/test_handler.py#L821-L838) · [grace-period boundary cases](repo://lambda/reap-investigations/test_handler.py#L921-L955) · [standalone staleness tests](repo://tests/unit/test_reap_investigations_staleness.py#L56-L158)
- The standalone `tests/unit` staleness pytest module is not selected by the Lambda Make targets, which run `unittest test_handler` from the Lambda directory; it imports the handler directly, whose boto3 clients are constructed at import time, so selecting the pure staleness tests still requires an isolated pytest/boto3 and test-AWS import environment. [Make recipes](repo://Makefile#L175-L190) · [handler module-level boto3 clients](repo://lambda/reap-investigations/handler.py#L26-L49) · [standalone test imports and handler import](repo://tests/unit/test_reap_investigations_staleness.py#L8-L23)
- Mocked IAM tests guard regional identity/attachment ownership, non-colliding policy names, local scopes, and explicit Bedrock service trust. [regional ownership](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L98-L121) · [second-region scopes](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L193-L233) · [multi-region trust test](repo://deploy/account/tests/shared-iam.tftest.hcl#L96-L107)
- The account baseline's source-level ownership assertion now expects exactly five shared `aws_iam_role_policy_attachment` resources, reconciling the three pre-reaper attachments with the investigation reaper's added basic and VPC execution attachments; it no longer references the removed `deploy/account/imports.tf`. [baseline assertion](repo://deploy/account/tests/baseline.tftest.hcl#L69-L84) · [reaper attachments](repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf#L10-L19)
