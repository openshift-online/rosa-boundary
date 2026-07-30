# Code Coverage

This document describes the code coverage infrastructure for rosa-boundary, including how coverage is generated, uploaded, and reported via the App-SRE self-hosted Codecov instance.

## Overview

rosa-boundary uses [Codecov](https://codecov.io) (App-SRE self-hosted instance) to track Go unit test coverage. Coverage is uploaded automatically by Prow CI on every PR (presubmit) and on every merge to `main` (postsubmit). PR comments show coverage diffs and per-file impact.

### Architecture

```
┌──────────────────────┐     ┌─────────────────────────┐     ┌───────────────────────┐
│  Developer opens PR  │────▶│ Prow presubmit: coverage│────▶│  Codecov (App-SRE)    │
│                      │     │  make codecov            │     │  PR comment + status  │
└──────────────────────┘     └─────────────────────────┘     └───────────────────────┘

┌──────────────────────┐     ┌──────────────────────────────┐     ┌───────────────────┐
│  PR merged to main   │────▶│ Prow postsubmit:             │────▶│  Codecov baseline │
│                      │     │ publish-coverage             │     │  updated           │
│                      │     │  make codecov                │     │                    │
└──────────────────────┘     └──────────────────────────────┘     └───────────────────┘
```

## Components

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make test-coverage` | Runs `go test -coverprofile=coverage.out -covermode=atomic ./...` and prints the total coverage line |
| `make codecov` | Depends on `test-coverage`, then calls `scripts/codecov.sh` to upload results |

`make test-coverage` can be run locally at any time to generate a coverage report. `make codecov` is intended for CI use only — it requires credentials mounted at `/var/run/codecov-secret/`.

### Upload Script (`scripts/codecov.sh`)

The upload script handles downloading the Codecov CLI and uploading the coverage report. Key design decisions:

- **Pinned CLI version**: Downloads Codecov CLI v11.3.1 with SHA256 checksum verification — no `curl | bash` pattern.
- **Prow environment awareness**: Reads Prow-injected environment variables (`PULL_PULL_SHA`, `PULL_BASE_SHA`, `PULL_HEAD_REF`, `PULL_BASE_REF`, `PULL_NUMBER`) to determine commit, branch, and PR context.
- **Presubmit vs postsubmit behavior**:
  - **Presubmit** (PR): passes `--pr` and `--parent-sha`; lets Codecov infer the head branch from the PR number to avoid fork branch name collisions.
  - **Postsubmit** (merge to main): passes `--branch` explicitly to tag the upload as a baseline.
- **Credentials**: Reads `CODECOV_TOKEN` and `CODECOV_ENTERPRISE_URL` from files mounted at `/var/run/codecov-secret/` by the Prow job.
- **Flag**: Uploads with the `go-unit-tests` flag for per-flag tracking in the Codecov UI.

### Repository Configuration (`codecov.yml`)

The `codecov.yml` at the repository root configures how Codecov processes and reports coverage:

**Coverage targets**:
- Project and patch coverage use `auto` target (tracks against the base branch) with a 1% threshold — a PR will not fail the Codecov status check unless coverage drops by more than 1%.

**Ignored paths** — the following are excluded from coverage calculations since they contain no Go unit-testable code:

| Pattern | Reason |
|---------|--------|
| `vendor/**` | Vendored dependencies |
| `**/mock_*.go`, `**/*_mock.go` | Generated mocks |
| `**/zz_generated*.go`, `**/*_generated.go`, `**/fake_*.go` | Generated code |
| `test/**`, `tests/**` | Test infrastructure (LocalStack, bats) |
| `docs/**`, `scripts/**`, `build/**` | Non-Go support files |
| `skel/**` | Shell skeleton config (bashrc.d) |
| `deploy/**` | Terraform and Kustomize |
| `lambda/**` | Python Lambda functions (separate test suites) |

**Flags**:
- `go-unit-tests` flag with `carryforward: true` — if a PR does not change Go code (and therefore the coverage job doesn't run or doesn't produce a new upload), the previous coverage data is carried forward instead of showing "no data".

**PR comments**:
- Layout includes header, diff, flags, file breakdown, and footer.
- Requires both base and head uploads to render a diff.

## Prow CI Jobs

Two Prow jobs are defined in [`openshift/release`](https://github.com/openshift/release) under `ci-operator/config/openshift-online/rosa-boundary/openshift-online-rosa-boundary-main.yaml`:

### `coverage` (presubmit)

- **Trigger**: Every PR to `main` (`always_run: true`)
- **Retrigger**: `/test coverage`
- **Command**: `make codecov`
- **Secret**: Mounts `rosa-boundary-codecov` at `/var/run/codecov-secret`
- **Result**: Uploads PR coverage to Codecov; Codecov posts a PR comment showing the coverage diff

### `publish-coverage` (postsubmit)

- **Trigger**: Every merge to `main`
- **Command**: `make codecov`
- **Secret**: Same mount as above
- **Result**: Uploads baseline coverage for `main`; used as the comparison target for future PR diffs

Both jobs use `nested-podman` capabilities and run in a `golang-plus` container image.

## Secrets

Credentials are stored in the [OpenShift CI self-service Vault](https://selfservice.vault.ci.openshift.org).

| Vault path | Key | Purpose |
|------------|-----|---------|
| `selfservice/openshift-online-rosa-boundary/codecov-secret` | `CODECOV_TOKEN` | Repository upload token from the Codecov instance |
| | `CODECOV_ENTERPRISE_URL` | URL of the App-SRE self-hosted Codecov instance |

The vault secret includes `secretsync` annotations that automatically sync it as a Kubernetes secret named `rosa-boundary-codecov` in the `ci` namespace on the Prow build clusters. The Prow jobs mount this secret at `/var/run/codecov-secret/`.

## GitHub App

The `codecov-appsre` GitHub App is installed on the `openshift-online` organization with access to the `rosa-boundary` repository. This allows Codecov to:

- Post PR comments with coverage diffs
- Set commit status checks on PRs
- Read PR metadata for branch/commit context

## Local Development

### Generating a coverage report locally

```bash
make test-coverage
```

This produces `coverage.out` in the repository root and prints the total coverage percentage. To view a detailed HTML report:

```bash
make test-coverage
go tool cover -html=coverage.out -o coverage.html
open coverage.html   # or xdg-open on Linux
```

### Viewing per-function coverage

```bash
make test-coverage
go tool cover -func=coverage.out
```

### Note on local uploads

`make codecov` is not intended for local use — it requires Prow environment variables and the mounted secret. For manual baseline uploads (e.g., bootstrapping a new branch), see the onboarding guide's manual upload instructions.

### Key PRs

| PR | Description | Status |
|----|-------------|--------|
| [rosa-boundary#112](https://github.com/openshift-online/rosa-boundary/pull/112) | Added `make test-coverage`, `make codecov`, and `scripts/codecov.sh` | Merged |
| [rosa-boundary#170](https://github.com/openshift-online/rosa-boundary/pull/170) | Added `codecov.yml` configuration | Merged |
| [openshift/release#82021](https://github.com/openshift/release/pull/82021) | Added `coverage` presubmit and `publish-coverage` postsubmit Prow jobs | Merged |
