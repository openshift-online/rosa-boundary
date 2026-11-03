# ROSA-Boundary Testing

This document describes the testing strategy, test suites, and how to run them.

## Overview

| Suite | Framework | Scope |
|-------|-----------|-------|
| Go unit tests | `go test` | CLI commands, Lambda client, config derivation |
| Lambda unit tests | pytest / unittest | `create-investigation` and `reap-tasks` Lambdas |
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

**Skips are not silently accepted.** By default, LocalStack skips make the overall
result fail, even if pytest exits zero. Current tests include unsupported-service
and deployed-infrastructure skips, and `ECS_EXECUTOR=local` skips task-container
execution tests. For a deliberately partial local run, explicitly opt in:

```bash
make test-all TEST_ALL_ARGS=--allow-skips
```

This still reports the skips and does not turn them into exercised coverage.
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

## Go Unit Tests

Tests for the `rosa-boundary` CLI live alongside the code in `internal/`.

```bash
make test-cli       # go test ./...
make fmt            # gofmt (must produce no diff)
make lint           # golangci-lint (falls back to go vet)
make staticcheck    # staticcheck ./...
```

**Patterns**:
- Standard library `testing` — no external test frameworks.
- Table-driven subtests for parameterized cases.
- Mock interfaces (e.g. `lambdaInvoker`) to isolate SDK dependencies.


## Lambda Unit Tests

Each Lambda (`create-investigation`, `reap-tasks`) has a `test_handler.py` co-located with its `handler.py`.

```bash
make test-lambda-create-investigation   # pytest (via uv)
make test-lambda-reap-tasks             # unittest (via uv)
make test-lambda                        # all three Lambda suites
```

**Patterns**:
- `create-investigation` uses pytest with `moto` for AWS mocking and `unittest.mock` for OIDC/JWKS stubs. Tests are grouped into classes by feature area (e.g. input validation, tagging, sidecar config).
- `reap-tasks` uses `unittest` with `unittest.mock` patches for the ECS client. No moto dependency since the Lambda only calls `list_tasks`, `describe_tasks`, and `stop_task`.

## LocalStack Integration Tests

Tests in `tests/localstack/integration/` that run against [LocalStack Pro](https://localstack.cloud/) to validate AWS service interactions without a real AWS account.

### Prerequisites

- LocalStack Pro token in `tests/localstack/.env` as `LOCALSTACK_AUTH_TOKEN`
- `uv` and the root project's Python version (currently 3.13). LocalStack test
  dependencies are declared in the root `localstack` dependency group and pinned
  by the root `uv.lock`; install with `uv sync --group localstack`.
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
tracker file is trusted, and `--allow-skips` cannot bypass this guard.

Review skip reasons: the local ECS executor intentionally skips task-container
tests. A passing local run is not proof of live AWS/Fargate behavior.

### Test markers

- `@pytest.mark.integration` — all tests
- `@pytest.mark.slow` — ECS task launches (>30s)
- `@pytest.mark.e2e` — end-to-end investigation workflows

Tests are organized one file per AWS service or feature area (e.g. ECS tasks, EFS access points, IAM roles, ABAC tag isolation). Each test validates API-level behavior against LocalStack rather than testing application code directly.

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

```bash
make pre-commit
```

## CI

| System | Trigger | What it runs |
|--------|---------|--------------|
| Tekton/Konflux | PR and push to `main` | Container build + security scans (Clair, ClamAV, Snyk SAST, shellcheck, RPM signatures) |
| Prow | Every PR to `main` | Non-blocking Go [coverage](configuration/code-coverage.md) (`make codecov`), container image build, Lambda unit tests |
| Prow (postsubmit) | Merge to `main` | Publish [coverage](configuration/code-coverage.md) to Codecov |

### Prow Jobs

Presubmit jobs run on every PR (`always_run: true`). The coverage presubmit is explicitly optional, so it reports coverage without blocking merges. Config lives in [`openshift/release`](https://github.com/openshift/release) under `ci-operator/config/openshift-online/rosa-boundary/`.

| Job | Target | Description | Retrigger |
|-----|--------|-------------|-----------|
| `pull-ci-...-coverage` | `coverage` | Runs `make codecov` (non-blocking Go test coverage) | `/test coverage` |
| `pull-ci-...-images` | `[images]` | Builds container images via ci-operator | `/test images` |
| `pull-ci-...-lambda-unit-tests` | `lambda-unit-tests` | Runs `pytest test_handler.py` for `create-investigation` Lambda in a UBI Python container | `/test lambda-unit-tests` |
| `branch-ci-...-publish-coverage` | `publish-coverage` | Publishes coverage to Codecov on merge (postsubmit) | — |

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
