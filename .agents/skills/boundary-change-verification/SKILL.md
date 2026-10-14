---
name: boundary-change-verification
description: Plan and run scoped validation for a ROSA Boundary working-tree diff, commit, or PR. Use before a PR, after changing CLI, Lambda, shell, image, Terraform, credentials, or audit behavior, or when asked what tests prove a change. Distinguish passed, skipped, and unverified boundaries without deploying resources.
---

# Boundary Change Verification

Choose checks that exercise the behavior changed by a diff, not a generic full-repository test list. Treat [development standards](../../../docs/development-standards.md) as the quality gate and [testing guide](../../../docs/testing.md) as orientation. Confirm commands against the current root and affected-directory Makefiles and the tests themselves; documents and this skill are not a test inventory.

## Scope the change

1. Determine the requested revision: working tree, commit/range, or PR. If unspecified, use the current working-tree diff, including staged changes; report untracked files separately and inspect only those relevant to the request. Do not switch branches, pull, stash, or overwrite existing work. For a PR, use `gh` to inspect its base and changed files before selecting tests; do not assume the local checkout is the PR revision. To *run* historical PR checks, use that revision in a separate clean checkout/worktree with permission; a pass on today's main does not verify yesterday's PR.
2. Identify the affected behaviors and security boundaries, not only file extensions: identity/authorization and ABAC, ECS lifecycle and reaping, task-scoped credentials, EFS workspace, CloudWatch session I/O, S3 audit sync, image architecture, or Terraform ownership. Check changed code and its existing tests for expected failure paths as well as success paths.
3. For each proposed check, state what it proves and what it cannot prove. Prefer the narrowest focused regression first, then expand to affected unit, contract, integration, build, or runtime checks. Inspect test fixtures and markers before starting dependencies: a pytest file under `tests/localstack/integration/` may only inspect Terraform source and need no LocalStack service. When the change hardens a test assertion, look for negative cases that make the old false positive fail. A cross-layer change needs checks at each changed boundary; do not equate a mocked test or LocalStack pass with real AWS/Fargate validation.

## Choose and verify checks

Use this routing table as a starting point, not a substitute for reading current recipes and tests. Find tests by the behavior they assert; do not infer coverage from a filename alone.

| Changed behavior | Candidate checks and limits |
|---|---|
| Go CLI or configuration | Focused `go test` package/subtest, then `make test-cli`; `make test-coverage`, `make lint`, `make staticcheck` as applicable. Check CLI/Terraform contract tests if identifiers, roles, or defaults changed. `make fmt` writes files: review its diff afterward. |
| Python Lambda | Relevant co-located unit tests via the current `make test-lambda-*` target; `make test-lambda` when interactions cross handlers. For changed AWS calls, select relevant LocalStack tests too. Unit mocks cannot prove deployed IAM or resource policies. |
| Shell, entrypoint, credential helper | Relevant `bats tests/shell/` tests and direct `shellcheck` on changed scripts; use `bats tests/localstack/ci-run.bats` when changing the Prow LocalStack entrypoint. The root `make lint` tolerates shellcheck failures: it is not a substitute for direct shellcheck. |
| Terraform, ECS, IAM, EFS, audit | Use validation and any relevant `terraform test` target in the owning root *after inspecting its Makefile*. Identify policy/contract assertions and LocalStack tests that exercise the changed resource; run fast integration first and full ECS-dependent tests when feasible. A Terraform plan and real AWS behavior are separate evidence. |
| Containerfile, build helper, skel | Focused build-helper tests where present, Makefile image build for affected architectures, and an interactive runtime check for affected tools or entrypoint behavior. For architecture-sensitive changes, test both amd64 and arm64. An image build does not prove exit-time audit sync. |
| Docs, guidance, CI | Check affected links, references, formatting, and CI/test commands against current source; run shell/CI fixture tests where present. Do not require unrelated runtime suites solely for documentation changes. |

Read the root `Makefile` and any affected `deploy/*/Makefile` before invoking targets. There is no root `make test` or `make test-shell`. Check what `make test-lambda` currently includes rather than repeating an old inventory. For LocalStack, inspect prerequisites and `tests/localstack/README.md`; `make test-localstack-fast` expects LocalStack already running, while `make test-localstack` starts it. Inspect skips and executor requirements in the test output; a green run with skipped ECS tests does not validate task execution. Run `pre-commit run --all-files` before a PR as required by development standards; report if unavailable or not run.

## Execution boundaries

- Default to a **plan and safe local checks**. Explain prerequisites and side effects before running formatting/fixers, image builds, LocalStack startup, network-dependent downloads, or tests that create local resources. Preserve unrelated working-tree changes and generated artifacts; review any changed files after fixers. Run broad mutating hooks such as `pre-commit run --all-files` only in a clean checkout, or first resolve how to protect unrelated work.
- Do not run `apply`, `destroy`, the regional `lambda` target, image publication, ECS task creation, or other live AWS/HCP mutations under this skill. Obtain explicit authorization through the deployment workflow for any such action. For staging changes, inspect `hcp-terraform/rosa-boundary/main.tf` for workspace ownership and apply settings, then review the Git/PR-triggered speculative plan; never use the dev regional Makefile or edit HCP regional variables directly.
- If the diff requires real AWS/Fargate/OIDC/audit evidence, offer a **separate handoff** to [boundary-live-verification](../boundary-live-verification/SKILL.md) for an approved personal dev environment. State the exact revision and source fingerprint (include relevant untracked changes), affected boundaries, proposed live assertions and negative cases, architecture, required target/identity, evidence, cleanup, and deployment/provenance gaps. Do not invoke the live skill or treat this handoff as approval to deploy/create a task; ask for target and explicit live-action authorization first. The live skill must re-check account, region and artifact provenance itself.
- Do not print `.env`, Terraform variable values, LocalStack tokens, AWS credentials, OIDC tokens, or raw logs likely to contain them. If prerequisites are missing, record the blocked check and reason rather than manufacturing a pass or attempting a live substitute.
- If a check fails, retain enough output to diagnose it, distinguish a regression from a prerequisite failure, and report the result. Do not silently skip failed checks or broaden scope merely to claim a green build.

## Report

Summarize with:

1. **Revision and changed boundaries** — what was inspected, including relevant untracked files.
2. **Checks run** — exact commands, outcomes, and meaningful skip counts; mention whether files were modified by checks.
3. **Not run or blocked** — reason and prerequisite, including relevant LocalStack, architecture, or live-system gaps.
4. **Evidence and remaining risk** — which behavior is supported by each result and what still needs review, speculative planning, staging validation, or human approval. Never label a change end-to-end verified on the strength of mocks, plans, or LocalStack alone.

For planning-only requests, provide the same structure with proposed checks and expected evidence instead of implying they ran.
