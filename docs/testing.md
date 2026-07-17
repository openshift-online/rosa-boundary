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
make test-lambda                        # both suites
```

**Patterns**:
- `create-investigation` uses pytest with `moto` for AWS mocking and `unittest.mock` for OIDC/JWKS stubs. Tests are grouped into classes by feature area (e.g. input validation, tagging, sidecar config).
- `reap-tasks` uses `unittest` with `unittest.mock` patches for the ECS client. No moto dependency since the Lambda only calls `list_tasks`, `describe_tasks`, and `stop_task`.

## LocalStack Integration Tests

Tests in `tests/localstack/integration/` that run against [LocalStack Pro](https://localstack.cloud/) to validate AWS service interactions without a real AWS account.

### Prerequisites

- LocalStack Pro token in `tests/localstack/.env` as `LOCALSTACK_AUTH_TOKEN`
- Python deps: `pytest`, `boto3`, `requests`
- Podman with socket enabled (Linux: `systemctl --user enable --now podman.socket`)

### Running

```bash
make localstack-up            # Start LocalStack + mock OIDC server
make test-localstack-fast     # Skip @slow ECS task launches
make test-localstack          # Full suite
make localstack-down          # Tear down
```

### Test markers

- `@pytest.mark.integration` — all tests
- `@pytest.mark.slow` — ECS task launches (>30s)
- `@pytest.mark.e2e` — end-to-end investigation workflows

Tests are organized one file per AWS service or feature area (e.g. ECS tasks, EFS access points, IAM roles, ABAC tag isolation). Each test validates API-level behavior against LocalStack rather than testing application code directly.

## Linting and Formatting

```bash
make fmt            # gofmt + shfmt (if installed)
make lint           # golangci-lint + shellcheck
make staticcheck    # Go static analysis
```

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml`:

- Trailing whitespace, end-of-file fixer, YAML check
- Large file check (>500KB), merge conflict detection
- golangci-lint

```bash
pre-commit run --all-files
```

## CI

| System | Trigger | What it runs |
|--------|---------|--------------|
| Tekton/Konflux | PR and push to `main` | Container build + security scans (Clair, ClamAV, Snyk SAST, shellcheck, RPM signatures) |
| Prow | Every PR to `main` | Go coverage (`make codecov`), container image build, Lambda unit tests |
| Prow (postsubmit) | Merge to `main` | Publish coverage to Codecov |

### Prow Jobs

All presubmit jobs run on every PR (`always_run: true`). Config lives in [`openshift/release`](https://github.com/openshift/release) under `ci-operator/config/openshift-online/rosa-boundary/`.

| Job | Target | Description | Retrigger |
|-----|--------|-------------|-----------|
| `pull-ci-...-coverage` | `coverage` | Runs `make codecov` (Go test coverage) | `/test coverage` |
| `pull-ci-...-images` | `[images]` | Builds container images via ci-operator | `/test images` |
| `pull-ci-...-lambda-unit-tests` | `lambda-unit-tests` | Runs `pytest test_handler.py` for `create-investigation` Lambda in a UBI Python container | `/test lambda-unit-tests` |
| `branch-ci-...-publish-coverage` | `publish-coverage` | Publishes coverage to Codecov on merge (postsubmit) | — |

## Quick Reference

```bash
# Run everything locally before a PR
make test-cli
make test-lambda
make fmt
make lint
make staticcheck
pre-commit run --all-files

# If changing infrastructure (Lambda, Terraform, ECS)
make localstack-up
make test-localstack-fast
make localstack-down
```
