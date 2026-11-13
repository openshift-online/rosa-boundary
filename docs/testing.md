# ROSA-Boundary Testing

This document describes the testing strategy, test suites, and how to run them.
Start with [CONTRIBUTING.md](../CONTRIBUTING.md) for mise/uv setup and access.
Package-manager examples below are alternatives when tools are not already
provided by mise, not additional installs required on top of that setup.

## Overview

| Suite | Framework | Scope |
|-------|-----------|-------|
| Go unit tests | `go test` | CLI commands, Lambda client, config derivation |
| Lambda unit tests | pytest / unittest | `create-investigation`, `reap-tasks`, and `reap-investigations` Lambdas |
| LocalStack integration | pytest | AWS service interactions end-to-end |
| Linting | shellcheck, golangci-lint, staticcheck | Code quality and static analysis |
| Pre-commit | pre-commit hooks | Formatting, YAML, merge conflicts |

## Exhaustive Local Validation

With LocalStack already running, the single entry point is:

```bash
make test-all
```

Unlike the smaller `make test` and `make check`, this attempts independent gates
sequentially **even when an earlier gate fails**. It writes complete logs and
`summary.json` into a private temporary directory whose path is printed at start
and finish. Logs can contain test diagnostics; review/redact before sharing.
It exits nonzero if any gate fails or a required dependency is missing.

Coverage includes:

- Go tests/coverage; all three Lambda suites and create-investigation coverage;
  build-helper tests; every Bats suite, including socket-discovery regressions.
- `tests/unit/` (including the test-all runner tests) and offline live-verification
  tooling tests. These tooling tests do not run live AWS verification.
- Go lint, Staticcheck, ShellCheck on all repository shell scripts and the
  credential helper, Python syntax, Go formatting, existing shell formatting,
  and Terraform formatting checks.
- Initialization/validation of every Terraform root under `deploy/` and
  `hcp-terraform/`, plus all account/regional Terraform tests. These use a
  disposable source-only copy, disabled backends, and mocked AWS test providers;
  they do not use your live Terraform state or apply infrastructure.
- Endpoint-isolation unit tests for the explicitly `localstack`-tagged CLI build.
  CLI integration fixtures build this binary in a temporary directory and use
  private synthetic identity/cache data plus LocalStack STS. The STS/ECS/EFS
  endpoint override is loopback-only and absent from normal builds; these tests
  do not verify real OIDC signatures, trust policies, or IAM enforcement.
- The complete LocalStack integration selection, including slow tests, with
  health preflight and a JUnit report. The runner accepts only a loopback HTTP
  endpoint and supplies dummy AWS credentials for these tests. Tests create
  local emulated resources; the runner does not restart or tear down LocalStack.
- Both-architecture workspace-image builds and the Lambda image build through
  their Make targets (no image push).
- Findings validation/SARIF conversion when root `adversary-findings.json` exists,
  and all pre-commit hooks. Pre-commit may rewrite files; review the diff.

**Prerequisites:** those for `make check`, plus `shfmt`, Terraform, running
Podman/LocalStack Pro, registry/network access needed by image builds, and HCP
Terraform private-module registry access (`terraform login app.terraform.io`).
Terraform initialization and dependency/build setup may download packages.

**Test failures and incomplete coverage are different outcomes.** The console
and `summary.json` use explicit `status` values:

- `PASS`: the gate passed without a reported coverage gap.
- `FAIL`: a test, command, or required prerequisite failed, or a JUnit report was
  missing, invalid, or empty. This always makes the aggregate exit nonzero.
- `INCOMPLETE`: the integration report contains skips but no test failures.
  The count and report location remain prominent in the summary. This does not
  make a normal local run nonzero and never means the skipped tests were verified.

Current tests include unsupported-service and deployed-infrastructure skips, and
`ECS_EXECUTOR=local` skips task-container execution tests. To require every selected
test to execute as well as pass:

```bash
make test-all TEST_ALL_ARGS=--require-complete
```

This also exits nonzero for `INCOMPLETE`, without mislabeling it as a test failure.
In JSON, `passed` is true only for `PASS`;
use `status`, not `passed` alone, to distinguish failures from incomplete coverage.
Changing the pytest executor variable alone does not configure the LocalStack
server's executor. A completely unskipped run may not be possible in LocalStack.

Not included: AWS deployments/investigation creation, live identity/network/audit
assertions, image publication, coverage/SARIF uploads, and external Konflux/Prow
security scanners. Those require their approved workflows; no local aggregate can
prove they passed. `tests/oidc-token-debug.py` is a manual diagnostic, not an
unattended test suite, and is not invoked.

## Local Test Suite

From the repository root:

```bash
make test
```

This runs `make test-coverage`, `make test-lambda`, `make test-github-dl`, and
`make test-shell` sequentially and stops on failure. It requires the Go toolchain,
`uv`, Python 3 with venv/pip support, and Bats (`brew install bats-core` on macOS
or `dnf install bats` on Fedora), plus `jq` and GNU coreutils/sed. On macOS,
install these with `brew install bats-core jq coreutils gnu-sed`; `make test-shell`
adds Homebrew's GNU tools to PATH only for the test process. This matches the
Linux container's GNU command behavior without changing your shell environment.
Dependency setup may download packages.

`make test-shell` runs `tests/shell/`, `tests/localstack/ci-run.bats`, and
`tests/localstack/compose.bats`, including mocked socket-discovery tests. No
LocalStack license, running containers, AWS credentials, or AWS region are needed.
Lambda unit tests mock boto3 client construction before handler imports/reloads.

For the combined local quality gate:

```bash
make check
```

This runs `make test`, `make lint`, `make staticcheck`, and `make pre-commit`
sequentially, stopping on failure. Also install `shellcheck`, `staticcheck`, and
`golangci-lint` (the pre-commit hook pins its own golangci-lint version).
`make lint` includes strict `make lint-shell`: missing ShellCheck or findings
fail rather than being silently ignored. `make pre-commit` uses the root uv
environment and may rewrite files; review your diff afterward.

LocalStack integration, image builds/runtime checks, Terraform validation, and
live AWS verification remain separate. Neither `make test` nor `make check`
starts or tears down LocalStack.

## SRE Tool Pin Migration Acceptance

ROSAENG-67158 targets six directly pinned tools: ocm, ocm-backplane, osdctl, yq,
oc, and AWS CLI v2. See the
[exact-pin contract](dependency-management-automation.md#six-tool-exact-pin-contract-rosaeng-67158)
for sources and integrity requirements. Exact values belong only in
`Containerfile`. These are acceptance criteria, **not passed results**.

### Focused local checks

```bash
make test-github-dl
```

Despite its historical name, this target collects all build-helper unit and
contract tests under `build/`. It creates a temporary venv, installs requests,
PyJWT with crypto support, and pytest, and removes the venv on exit. Python
venv/pip and dependency-download access are required. Inspect the recipe and
updated test assertions; an unchanged draft test pass cannot validate revised source.

For the implementation, check:

- Latest stable selections at implementation time, with the lookup date in the PR.
- Exactly six unique updater dependencies mapped to the six annotated ARGs,
  no installer or ocm-addons rule, and explicit `automerge: false` with normal
  human review. Validate extraction and lookups; report unsupported tracking
  rather than inventing new infrastructure.
- Exact asset/checksum selection; failure on missing, duplicate, or malformed
  integrity entries, bad hashes, missing/invalid/wrong-key signatures, and
  unavailable assets. Preserve authenticated downloads without leaking tokens.
- Verification before safe extraction, rejecting traversal and unsafe archive
  members while preserving the normal AWS distribution layout.
- Exact installed executable-version equality: both newer and older unexpected
  versions fail, as do missing executables and unparseable versions.
- Downloaded tools execute only after token/private-key mounts are gone.
- No stale removed-tool inventory, completion, or acceptance assumptions.

### Local image check

After the implementation is reduced, build through the existing Makefile for the
currently usable target with approved GitHub secret inputs and working Podman:

```bash
REQUIRE_GITHUB_TOKEN=true make build-amd64
make verify-image-tools TOOL_IMAGE=rosa-boundary:latest-amd64
```

`make build` requests both amd64 and arm64; it is not necessary to enable ARM
for this change. The earlier draft identified an amd64-only base digest and
rejected a mislabeled ARM build. Do not bypass the architecture guard or claim
ARM support; base-image and ARM enablement work are separate.

The verifier must enforce the six-tool contract. The existing Make
target resolves the supplied image reference to an immutable local image ID and
runs offline as `sre`, with a read-only filesystem, dropped capabilities, and no
credentials. It mounts the helpers and Containerfile read-only, overrides the
entrypoint, and does not test investigation or audit behavior.

Check all six executable versions against the ARG defaults in the final image.
If retaining generated `/usr/local/share/rosa-boundary/tool-versions.json`, require
six entries matching those defaults and actual binaries; it is build output, not
another editable pin source. Record the tested revision, image ID, and results.

Exercise `ocm backplane` plugin discovery, AWS invocation and its existing
alternative/distribution layout, and retained completions. Confirm no
ocm-addons binary/completion, backplane-tools installer, or newly introduced
license-vendoring artifacts remain. Do not strip normal distribution files.
Keep verification-only dependencies in builder stages and preserve runtime paths,
entrypoint, privileges, credentials, and audit behavior.

Run scoped formatting/pre-commit checks and report blocked checks. No unrelated
Go, Lambda, LocalStack, ARM CI, promotion, or operational project is a prerequisite
solely for this change. Run broad rewriting hooks only in a protected clean
checkout in a shared tree.

### Evidence limits

Earlier draft evidence is historical, not validation of the reduced implementation. Rerun affected tests and the usable
image build after source changes. A local build does not prove ARM, deployed
Mintmaker, cluster compatibility, staging, or production behavior. Report gaps
without turning deployment, publication, AWS/HCP changes, or investigation
creation into prerequisites for preparing this PR; those need separate approval.

## Go Unit Tests

Tests for the `rosa-boundary` CLI live alongside the code in `internal/`.

```bash
make test-cli       # go test ./...
make fmt            # writes Go/shell formatting; review the diff
make lint           # golangci-lint (falls back to go vet)
make staticcheck    # staticcheck ./...
```

**Patterns**:
- Standard library `testing` — no external test frameworks.
- Table-driven subtests for parameterized cases.
- Mock interfaces (e.g. `lambdaInvoker`) to isolate SDK dependencies.


## Lambda Unit Tests

Each Lambda (`create-investigation`, `reap-tasks`, `reap-investigations`) has a
`test_handler.py` co-located with its `handler.py`.

```bash
make test-lambda-create-investigation   # pytest (via uv)
make test-lambda-reap-tasks             # unittest (via uv)
make test-lambda-reap-investigations    # unittest (via uv)
make test-lambda                        # all three Lambda suites
```

**Patterns**:
- `create-investigation` uses pytest with `moto` for AWS mocking and `unittest.mock` for OIDC/JWKS stubs. Tests are grouped into classes by feature area (e.g. input validation, tagging, sidecar config).
- `reap-tasks` and `reap-investigations` use `unittest` with mocked AWS clients;
  the latter covers investigation garbage collection and audit cleanup.

## LocalStack Integration Tests

Tests in `tests/localstack/integration/` that run against [LocalStack Pro](https://localstack.cloud/) to validate AWS service interactions without a real AWS account.

### Prerequisites

- LocalStack Pro token in `tests/localstack/.env` as `LOCALSTACK_AUTH_TOKEN`
- `uv` and the root project's Python version (currently 3.13). LocalStack test
  dependencies are declared in the root `localstack` dependency group and pinned
  by the root `uv.lock`; install with `uv sync --group localstack`.
  The nested `tests/localstack/pyproject.toml` and `setup.py` retain the external
  CI image's Python 3.11 directory-install contract, sourcing the same root group
  without installing the root project. That existing CI install resolves the
  group's constraints rather than using the root lockfile; it is not the local
  setup command.
- Podman with socket enabled (Linux: `systemctl --user enable --now podman.socket`)

### Running

```bash
uv sync --group localstack   # Optional: test targets sync automatically
make localstack-up            # Start LocalStack and its AWS initialization hook
make test-localstack-fast     # Skip @slow ECS task launches
make test-localstack          # Full selection; starts and tears down LocalStack
make localstack-down          # Tear down
```

### CI entrypoint

`make test-localstack-ci` runs `tests/localstack/ci-run.sh`, the entrypoint used by
Prow. Unlike the Compose-based local targets above, it starts its own Podman API
socket and LocalStack container, enables Docker-backed ECS tests, and writes JUnit
results and diagnostic logs to `ARTIFACT_DIR`. It requires the prepared Linux
nested-Podman CI environment with test dependencies installed, an exported
`LOCALSTACK_AUTH_TOKEN`, and an existing writable `ARTIFACT_DIR`. It does not load
`tests/localstack/.env`.

The other direct test command in Prow, `uv run pytest test_handler.py -v` in
`lambda/create-investigation`, is covered by `make test-lambda-create-investigation`.
Run both Make targets from the repository root (or use `make -C /path/to/rosa-boundary`).

### Local integration readiness

The Make test targets use `uv run --group localstack`; virtualenv activation
and manual `uv pip install` are not required. To run against an already-started
LocalStack and leave it running:

```bash
uv run --group localstack pytest tests/localstack/integration/ -v --tb=short -ra
```

`make localstack-ready` asserts live HTTP health and required-service readiness.
All Make integration entry points and `test-all` run the same check before pytest;
direct pytest runs also check before session-client initialization and before
each dependent test, failing fixture setup if readiness is lost. No
tracker file is trusted, and the completion policy cannot bypass this guard.

Review skip reasons: the local ECS executor intentionally skips task-container
tests. A passing local run is not proof of live AWS/Fargate behavior.

### Test markers

- `@pytest.mark.integration` — all tests
- `@pytest.mark.slow` — ECS task launches (>30s)
- `@pytest.mark.e2e` — end-to-end investigation workflows

Tests are organized by service or feature area. Some exercise emulated AWS APIs,
others inspect source/policy/task-definition contracts, and close-investigation
cases execute the temporary, endpoint-restricted Go CLI. The investigation
workflow cases emulate resource creation; they do not invoke a deployed Lambda.
None of these replaces live OIDC/IAM, Fargate, or audit verification.

## Linting and Formatting

```bash
make fmt            # gofmt + shfmt (if installed)
make lint           # Go lint (falls back to go vet) + strict ShellCheck
make lint-shell     # strict ShellCheck only
make staticcheck    # Go static analysis
make pre-commit     # all pre-commit hooks via uv; may modify files
```

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml`:

- Trailing whitespace, end-of-file fixer, YAML check
- Large file check (>500KB), merge conflict detection
- golangci-lint
- Skillsaw
- Trusted Actions: secret scan and Go build when component files are changed.
  The copied component-local config is not run by the root Git hook (a direct
  pre-commit command from the component directory does select it); run TA's lint
  and tests separately from `components/trusted-actions/`. Lint is not yet a
  root hook: the imported baseline has existing findings, and its old pinned
  linter cannot handle the current Go toolchain.

```bash
make pre-commit
```

## CI

For the dated, source-linked Prow, Konflux, GitHub and HCP Terraform delivery map—including path-filtered jobs, release configuration and what each gate **does not** test—see [CI/CD and verification](ci-cd.md). The authoritative Prow job definitions live in `openshift/release`, not this repository; do not assume every PR runs every job. Check actual PR contexts and run artifacts before claiming CI coverage. This guide's Makefile commands describe local gates, not automatic CI execution.

## Quick Reference

```bash
# Unit/regression suites plus quality checks before a PR
make check

# Optional formatter (writes files); review the diff and rerun make check
make fmt

# If changing infrastructure (Lambda, Terraform, ECS)
make localstack-up
make test-localstack-fast
make localstack-down
```
