---
type: delivery-and-verification
title: Repository CI/CD configuration and quality gates
description: Documents only ROSA Boundary repository-owned image pipelines, local test and lint entrypoints, pre-commit hooks and HCP workspace declarations; explains which external CI and release behavior cannot be verified from this checkout.
tags: [ci, cd, prow, konflux, github, pre-commit, testing]
verified:
  - by: openwiki/0.7.0
    at: 2026-11-13T18:18:24.408Z
sources:
  - id: openwiki-source-4d1645cb6317345817452838
    resource: repo://.pre-commit-config.yaml
  - id: openwiki-source-fcc8bea771df4307d9c58683
    resource: repo://.tekton/create-investigation-lambda-pull-request.yaml
  - id: openwiki-source-8d854dd2f194b475c0e43107
    resource: repo://.tekton/create-investigation-lambda-push.yaml
  - id: openwiki-source-b3cacc865e62dc31f0a55b4a
    resource: repo://.tekton/rosa-boundary-pull-request.yaml
  - id: openwiki-source-37bff7e3e708c49a7ea81bc8
    resource: repo://.tekton/rosa-boundary-push.yaml
  - id: openwiki-source-eebdf2baefd63a03b1cb3b5e
    resource: repo://.tekton/rosa-trusted-actions-pull-request.yaml
  - id: openwiki-source-12238a6f88dc834f61553058
    resource: repo://.tekton/rosa-trusted-actions-push.yaml
  - id: openwiki-source-56c54c10348f1e72daffc214
    resource: repo://components/trusted-actions/go.mod
  - id: openwiki-source-4c833b02bf6d5fc7a2476dea
    resource: repo://components/trusted-actions/Makefile
  - id: openwiki-source-527b127f4d59725c0085dfbf
    resource: repo://docs/staging-deployment.md
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
  - id: openwiki-source-37ce5ca787d481a0d0fc0453
    resource: repo://hcp-terraform/rosa-trusted-actions/main.tf
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
  - id: openwiki-source-cf1ae14f674a076c967465d1
    resource: repo://scripts/test_all.py
  - id: openwiki-source-38fbf433aefe6645b985c0ac
    resource: repo://tests/localstack/ci-run.sh
generated: { by: "opencode", at: "2026-11-13T18:18:24.408Z" }
---

# Repository CI/CD configuration and quality gates

This page covers **only what is defined or directly observable in this repository**. Boundary's root Go module and `components/trusted-actions/` (TA) are separate; their tests, images and Terraform roots must be checked separately. The six [`.tekton/`](../../.tekton/) files declare image-building PipelineRuns, not the release plans or deployed results. The root and TA Makefiles describe runnable checks, not a promise that CI invokes them. Consult actual external job definitions and run artifacts before stating that a test ran or blocked a merge.

## Repository-owned automation at a glance

| Source in this repo | What it defines | What it does not establish |
| --- | --- | --- |
| [`.tekton/`](../../.tekton/) | PR and `main`-push PipelineRun definitions for Boundary container, create-investigation Lambda image and TA container; build parameters, path filters and configured scan tasks. | Whether Konflux registered or ran them, how policy treats scan results, whether an image was released to a destination registry or deployed. |
| [`.github/`](../../.github/) and [`OWNERS`](../../OWNERS) | PR/issue templates and ownership rules; **no tracked `.github/workflows/*.yml` or `*.yaml` files**. Nested OWNERS files add component-specific reviewers/labels. | GitHub-managed dynamic workflows, branch-protection requirements, actual approvals or Prow/Tide gating. |
| [Boundary HCP workspace map](../../hcp-terraform/rosa-boundary/main.tf) and [TA HCP workspace map](../../hcp-terraform/rosa-trusted-actions/main.tf) | VCS repository names, Terraform working directories, Git-managed variables and declared auto-apply settings for distinct workspaces/states. | Effective live workspace configuration, whether a speculative plan queued, whether apply succeeded or what image currently runs. |
| Root [`Makefile`](../../Makefile), [`scripts/test_all.py`](../../scripts/test_all.py), [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml), TA [`Makefile`](../../components/trusted-actions/Makefile) | Explicit local test, lint, formatting, build and mocked-infrastructure entrypoints. | That every entrypoint is called by any external presubmit or release job. |

## Image PipelineRuns in `.tekton/`

| Component | PR and push definitions | Configured build and trigger |
| --- | --- | --- |
| Boundary ECS container | [PR](../../.tekton/rosa-boundary-pull-request.yaml) / [push](../../.tekton/rosa-boundary-push.yaml) | Root `Containerfile`, root context, `REQUIRE_GITHUB_TOKEN=true`, **linux/x86_64**. The `files.all.exists` CEL expression requires *every* changed path to match its allowlist (`Containerfile`, `entrypoint.sh`, `.containerignore`, `build/`, `skel/`, `.tekton/rosa-boundary-*`). A mixed PR with a nonmatching file does not satisfy this expression. |
| Create-investigation Lambda image | [PR](../../.tekton/create-investigation-lambda-pull-request.yaml) / [push](../../.tekton/create-investigation-lambda-push.yaml) | `lambda/create-investigation/Containerfile` and component context; changes under `lambda/create-investigation/***` or the corresponding pipeline file satisfy its trigger. |
| Trusted Actions image | [PR](../../.tekton/rosa-trusted-actions-pull-request.yaml) / [push](../../.tekton/rosa-trusted-actions-push.yaml) | `components/trusted-actions/Containerfile` and component context, **linux/x86_64**; changes under `components/trusted-actions/***` or the corresponding pipeline file satisfy its trigger. |

The YAML specifies `on-pr-{{revision}}` images with `5d` expiration for PRs and `{{revision}}` images for `main` pushes in `quay.io/redhat-user-workloads/rosa-tenant/`. These are **configured output locations**, not confirmation of a successful push. All six PipelineRuns include roxctl-scan; the files also name deprecated-base-image, ecosystem-cert preflight, Snyk SAST, ClamAV, shell/unicode SAST and RPM-signature tasks. They do **not** invoke the root or TA Makefile test suites, verify ECS access, or exercise ARM64 in the two x86_64 build definitions. Named scan tasks and built image indexes alone do not prove scan effectiveness, a blocking policy decision or release approval.

The deployment variables pin images separately from these PipelineRuns: see `container_image` and `lambda_image_tag` in the [Boundary workspace map](../../hcp-terraform/rosa-boundary/main.tf) and the image variable in [TA's workspace map](../../hcp-terraform/rosa-trusted-actions/main.tf). A build does not update these pins. Actual release and registry-import configuration is **not** defined by the six PipelineRuns; do not infer Quay/ECR publication, replication, or a running image version from them.

## Local tests, lint and pre-commit

- Root `make test` runs root Go coverage, the three Lambda Python unit suites (create-investigation, reap-tasks and reap-investigations), Python build-helper tests and Bats shell regressions. Root `go test ./...` does **not** enter the independent TA Go module. `make check` runs `test`, `lint`, `staticcheck` and `pre-commit` sequentially. `make lint` uses `golangci-lint` when available, otherwise `go vet`, plus required ShellCheck; `staticcheck` fails if its tool is absent. `make codecov` uploads root Go coverage in addition to generating it: use `make test-coverage` for local coverage without uploading.
- `make test-localstack-ci` invokes [`tests/localstack/ci-run.sh`](../../tests/localstack/ci-run.sh), which requires `LOCALSTACK_AUTH_TOKEN` and `ARTIFACT_DIR`, starts a Podman-backed LocalStack Pro ECS task executor, writes a JUnit artifact and rejects missing/all-skipped test results. Its comments describe a Prow caller, but **this script does not define the external Prow job or its trigger**. LocalStack is not live AWS.
- Root `make test-all` runs [`scripts/test_all.py`](../../scripts/test_all.py): local suites, formatting/lint, a disposable Terraform snapshot with mocked-provider tests, LocalStack integration, Boundary multi-architecture and Lambda image builds, pre-commit and per-check logs. It requires an available LocalStack endpoint; `--require-complete` rejects skipped JUnit cases. It does **not** deploy, publish images, upload coverage/SARIF, run external scanners or verify live AWS. Neither `make test-all` nor `make check` is automatically a CI gate just because it exists.
- [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) configures always-run `skillsaw lint .`, whitespace/EOF/YAML/large-file/merge-conflict hooks, root `golangci-lint` **excluding TA**, `gitleaks` **limited to TA**, and TA `go build ./...` on changed TA Go/module files. `make pre-commit` runs those hooks on all files through `uv` and may rewrite files. This is not a full unit suite, root-wide secret scan or TA lint gate.
- TA [`make test`](../../components/trusted-actions/Makefile) regenerates its bundled OpenAPI/Go code, compiles integration-tagged tests without running them, then executes `go test -v ./...` in the TA module. Its race, coverage, Postgres, API, full integration and kind/ministack checks are separate targets, as is `make lint` and OpenAPI validation; no root Makefile target covers them all by default. Boundary account/regional `.tftest.hcl` suites use mocked AWS; the account Python replication-topology check is a separate Python test. See [Terraform verification](../testing/verification.md) and [TA testing](../testing/trusted-actions-testing.md) for scope and limitations.

## What this checkout cannot prove

The repository contains references to Prow and Codecov in [`tests/localstack/ci-run.sh`](../../tests/localstack/ci-run.sh), [`scripts/codecov.sh`](../../scripts/codecov.sh) and [`docs/testing.md`](../../docs/testing.md), but **the authoritative Prow job definitions are not in this checkout**. It cannot establish their current names, schedules, optional/required status, path filters, exact commands, successful results or any nightly real-infrastructure coverage. Similarly, GitHub-hosted or app-managed checks, effective Konflux release plans/admissions (including internal release-data configuration), scan policy outcomes and live HCP runs are not specified by the source files above. Human-maintained docs may describe them, but are not independent evidence of current external configuration.

For a PR, run the relevant local checks for **both** affected components, inspect the actual PR/CI and image-build results and review any speculative and applied HCP plans. Mocked Terraform, LocalStack and image scans are not proof of AWS IAM enforcement, EFS/ECS task behavior, OIDC access, audit evidence or production availability; those require approved live verification. Keep any external findings in a separately reviewed, appropriately scoped source rather than presenting them as OpenWiki Claims grounded in this repository.
