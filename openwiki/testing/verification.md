---
type: testing
title: Testing and verification strategy
description: Maps Go, Lambda, shell, Terraform, and LocalStack tests to the behavior they verify and explains the difference between local integration and Prow execution.
tags: [testing, unit-tests, integration-tests, localstack, ci]
sources:
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-ae0e11fbe7ed89eafcab9312
    resource: repo://lambda/create-investigation/Makefile
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
generated: { by: "opencode", at: "2026-10-05T17:08:59.471Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-05T19:18:44.075Z
---

# Testing and verification strategy

The repository uses several test layers because no single environment covers the CLI, container scripts, Terraform policy shape, Lambda logic, and AWS API interactions. Go and Python unit tests isolate logic; bats tests exercise shell behavior; Terraform tests use a mocked provider for input constraints; LocalStack tests exercise service APIs and relationships between AWS resources. Prow's `tests/localstack/ci-run.sh` adds service/readiness gates, Docker-compatible ECS task execution, JUnit artifacts, and failure logs around the LocalStack suite.

## Unit and focused tests

- **Go CLI and libraries:** `make test-cli` runs `go test ./...`. Tests cover OIDC callback/PKCE and token cache behavior, command validation and role selection, AWS wrapper logic, Lambda invocation, and OCM credential transfer.
- **Investigation Lambda:** `make test-lambda-create-investigation` runs its pytest handler tests; they exercise request validation, OIDC/group authorization, error sanitization, investigation resource creation, and handover behavior with mocked AWS clients.
- **Reaper Lambda:** `make test-lambda-reap-tasks` runs its unittest handler suite, including deadline parsing, stop errors, pagination, and task processing. `make test-lambda` combines the two Lambda suites.
- **Shell:** the bats suites under `tests/shell/` source the entrypoint and credential helper and stub external commands to verify mount checks, cleanup, sync exclusions, input validation, and credential error handling without launching a container.
- **Build helper:** `make test-github-dl` runs tests for GitHub release download authentication, checksum validation, and build secret resolution.
- **Terraform:** `deploy/regional/tests/claude_default_model.tftest.hcl` uses `mock_provider "aws"`; cases check accepted and rejected Claude inference-profile/agreement combinations without calling AWS.

## LocalStack integration tests

The pytest integration suite obtains boto3 clients from fixtures pointed at `LOCALSTACK_ENDPOINT` and waits for every service in `required_services.py`. Initialization provisions test network/resources and writes IDs into SSM Parameter Store; the test fixture polls for those parameters. Integration tests cover S3 audit settings and sync filtering, IAM/OIDC/ABAC policy shapes, ECS task definitions and tags, EFS access points/policies, KMS, kube-proxy mounts, deadline enforcement, and investigation cleanup/workflow relationships.

The local `compose.yml` uses LocalStack's local ECS and Lambda executors and persistence volume. Slow tests that need task containers explicitly skip when `ECS_EXECUTOR=local`. `make test-localstack-fast` expects LocalStack to already be running and selects tests marked not slow. `make test-localstack` starts the local stack, runs the integration directory, and shuts it down.

## Prow LocalStack runner

The Prow entrypoint starts a Podman API socket, selects `ECS_EXECUTOR=docker`, pulls a pinned LocalStack Pro image, and starts LocalStack with the required service set and `init-aws.sh`. It waits for service health and an SSM sentinel written after test network parameters are initialized before running pytest. It writes JUnit XML, rejects a run where every test was skipped, and collects both container and internal LocalStack logs on exit. `tests/localstack/ci-run.bats` provides local-only tests of the JUnit gate, service readiness, and log collection; it cannot run in the Prow job itself because that job is the script under test.

## Choosing a test layer

Use the narrow unit suite for code paths that can be isolated and the focused bats suite for shell contract changes. Use LocalStack for AWS API behavior and cross-resource wiring, noting that local executor mode does not run real task containers. For ECS task launch/reaper behavior that depends on an actual task reaching `RUNNING`, use the Prow runner's docker executor or another supported non-local ECS executor. Terraform input checks and resource configuration tests are independent of LocalStack and AWS credentials.

## Evidence-backed claims

- The root Makefile defines separate Go, Lambda, build-helper, and LocalStack test targets; LocalStack fast mode requires a running endpoint, while full mode starts and tears down the stack. [root test targets](repo://Makefile#L70-L128) · [Go test targets](repo://Makefile#L150-L168) · [build helper target](repo://Makefile#L130-L139)
- The two Lambda unit suites use distinct pytest and unittest runners, and the aggregate target invokes both. [root Lambda targets](repo://Makefile#L117-L128) · [create-investigation local targets](repo://lambda/create-investigation/Makefile#L78-L88) · [reaper tests](repo://lambda/reap-tasks/test_handler.py#L19-L35)
- LocalStack pytest fixtures check the health endpoint and require configured AWS services before returning service clients against the local endpoint. [service requirements](repo://tests/localstack/required_services.py#L1-L6) · [fixture health gate](repo://tests/localstack/conftest.py#L21-L99)
- The local compose configuration uses LocalStack's local ECS executor, while slow reaper integration tests skip in local mode because tasks do not reach RUNNING; the Prow script sets a Docker-compatible ECS executor. [local compose](repo://tests/localstack/compose.yml#L1-L24) · [integration skip condition](repo://tests/localstack/integration/test_task_timeout.py#L16-L78) · [Prow executor setup](repo://tests/localstack/ci-run.sh#L64-L85)
- The Prow runner waits for required services and initialized SSM state, writes JUnit results, rejects an all-skipped suite, and captures LocalStack logs on exit. [service and SSM readiness](repo://tests/localstack/ci-run.sh#L128-L223) · [pytest and JUnit gate](repo://tests/localstack/ci-run.sh#L225-L262) · [log collection trap](repo://tests/localstack/ci-run.sh#L43-L62)
- Local-only bats tests validate the CI runner's JUnit, readiness, and log collection helpers without launching LocalStack or Podman. [ci-run bats scope and setup](repo://tests/localstack/ci-run.bats#L1-L22) · [JUnit and log tests](repo://tests/localstack/ci-run.bats#L24-L79) · [readiness tests](repo://tests/localstack/ci-run.bats#L81-L101)
- Terraform's model test uses a mocked AWS provider and includes success for an approved profile plus failure cases for a bare model ID and missing model agreement. [mock provider setup](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L12-L66) · [model test cases](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L68-L124)
