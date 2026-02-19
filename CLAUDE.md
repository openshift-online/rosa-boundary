# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

Multi-architecture container for AWS Fargate that provides tools for managing AWS and OpenShift (ROSA) clusters. Part of an **access control pattern** that combines:

- **Identity**: Keycloak (Red Hat build) for OIDC authentication
- **Infrastructure**: ECS Fargate with SSM for ephemeral SRE containers

Designed for ephemeral SRE use with ECS Exec access as the `sre` user. The entrypoint script supports dynamic version selection via environment variables, signal handling for graceful shutdown with S3 backup, and defaults to `sleep infinity`.

**For complete architecture and integration details**, see [`docs/`](docs/README.md).

## Development Workflow

### Tool Usage Guidelines

**IMPORTANT**: Always use Makefiles and Terraform for builds and deployments:
- **Container builds**: Use `make` commands (never `podman build` directly)
- **Lambda builds**: Use `make` commands in `lambda/*/` directories
- **Infrastructure**: Use `terraform` commands in `deploy/regional/`, or the `deploy/regional/Makefile` which wraps Terraform and sources `.env`

### Environment Configuration

**Required variables** without Terraform defaults must be supplied in `.env` at the project root:
- If a Terraform variable lacks a default value, check `.env` first
- If missing from `.env`, prompt the user to add it
- Never hardcode environment-specific values in tool commands

**Example**: `keycloak_issuer_url` has no default in `variables.tf`, so it must be in `.env` as `KEYCLOAK_ISSUER_URL`.

## Building

```bash
# Build both architectures and create manifest list
make all

# Build single architecture
make build-amd64
make build-arm64

# Create manifest list from existing builds
make manifest

# Remove all images and manifests
make clean
```

The `make manifest` target creates an OCI image index containing both architectures; Podman/Docker automatically selects the correct platform when pulling `rosa-boundary:latest`.

## Testing Containers Locally

```bash
# Run interactively with default versions
podman run -it rosa-boundary:latest /bin/bash

# Test a specific OC version
podman run --rm -e OC_VERSION=4.18 rosa-boundary:latest oc version --client

# Test with Fedora AWS CLI
podman run --rm -e AWS_CLI=fedora rosa-boundary:latest aws --version

# Test S3 sync on exit (warns without credentials)
podman run --rm -e S3_AUDIT_ESCROW=s3://test-bucket/test/ \
  rosa-boundary:latest sh -c "echo 'test' > /home/sre/test.txt && exit"

# Check alternatives configuration
podman run --rm rosa-boundary:latest alternatives --display oc
```

## Container Architecture

### Multi-Architecture Build

The Containerfile uses `uname -m` to detect architecture at build time. When podman builds with `--platform linux/arm64`, RUN commands execute in QEMU emulation where `uname -m` returns `aarch64`. For `--platform linux/amd64`, it returns `x86_64`.

Architecture values are written to temp files (`/tmp/aws_cli_arch`, `/tmp/oc_suffix`) and consumed by subsequent RUN layers — this is necessary because environment variables don't persist across RUN layers.

### Tool Installation via Alternatives

**AWS CLI**:
- Fedora RPM (`/usr/bin/aws`) — priority 10, family `fedora`
- Official AWS CLI v2 (`/opt/aws-cli-official/v2/current/bin/aws`) — priority 20, family `aws-official` (default)

**OpenShift CLI**:
- Versions 4.14–4.20 installed to `/opt/openshift/{version}/oc`
- Priorities 14–19 for versions 4.14–4.19; priority 100 for 4.20 (default)

### Entrypoint Behavior

`entrypoint.sh` runs at container start and:

1. **Traps signals** (SIGTERM, SIGINT, SIGHUP) so `cleanup()` can sync data before exit
2. **Switches OC version** via `alternatives --set` if `OC_VERSION` is set
3. **Switches AWS CLI** via `alternatives --set` if `AWS_CLI` is set (`fedora` or `official`)
4. **Copies skeleton config** from `/etc/skel-sre/.claude/` to `/home/sre/.claude/` on first run only (preserves user customizations on subsequent runs)
5. **Configures Bedrock**: enables `CLAUDE_CODE_USE_BEDROCK=1`, auto-detects `AWS_REGION` from ECS task metadata, falls back to `us-east-1`
6. **Runs the command** in background with `&` (cannot use `exec` — it replaces the shell and traps won't fire)
7. **On exit or signal**: `sync_to_s3()` runs `aws s3 sync /home/sre` to the configured S3 URI

**S3 path auto-generation** (`sync_to_s3`): if `S3_AUDIT_ESCROW` is unset but `S3_AUDIT_BUCKET` + `CLUSTER_ID` + `INVESTIGATION_ID` are all set, the path is built automatically: `s3://$bucket/$cluster/$investigation/$date/$taskid/`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OC_VERSION` | 4.20 via alternatives | Select OC CLI version: 4.14–4.20 |
| `AWS_CLI` | official via alternatives | Select AWS CLI: `fedora` or `official` |
| `S3_AUDIT_ESCROW` | — | S3 URI for /home/sre sync on exit |
| `S3_AUDIT_BUCKET` | — | Bucket for auto-generated S3 path |
| `CLUSTER_ID` | — | Cluster ID for auto-generated S3 path |
| `INVESTIGATION_ID` | — | Investigation ID for auto-generated S3 path |
| `CLAUDE_CODE_USE_BEDROCK` | `1` | Enable Claude Code Bedrock mode |
| `AWS_REGION` | auto-detected | Bedrock region (ECS metadata → fallback `us-east-1`) |
| `ANTHROPIC_MODEL` | — | Override Claude model ID |

### Claude Code Integration

- Installed via native installer with `HOME=/opt/claude-code`; binary symlinked to `/usr/local/bin/claude`
- Auto-updates disabled in `skel/sre/.claude/settings.json`
- Skeleton config (`skel/sre/.claude/`) is copied to `/etc/skel-sre/` at build time and initialized to `/home/sre/.claude/` at first runtime
- For Bedrock IAM requirements, see [`docs/configuration/aws-iam-policies.md`](docs/configuration/aws-iam-policies.md)

## Adding New OpenShift Versions

1. Add the version to the download loop in the Containerfile (the `for version in 4.14 4.15 ... 4.20` block)
2. Add an `alternatives --install` line in the alternatives registration block with priority equal to the minor version number
3. If the new version should be the default, change its priority to `100` and lower the previous default
4. Update `OC_VERSION` documentation in `README.md` and the validation logic in `entrypoint.sh`

## Repository Layout

```
rosa-boundary/
├── Containerfile              # Multi-arch container build
├── entrypoint.sh              # Runtime init: version selection, S3 sync, Bedrock setup
├── Makefile                   # Build targets: all, build-amd64, build-arm64, manifest, clean
├── skel/sre/.claude/          # Skeleton Claude Code config (CLAUDE.md, settings.json)
├── deploy/
│   ├── keycloak/              # Kustomize config for Keycloak (RHBK) on OpenShift
│   │   ├── base/              # Namespace and base kustomization
│   │   ├── components/cnpg/   # CloudNativePG PostgreSQL cluster
│   │   ├── components/keycloak/ # Keycloak CR and OpenShift Route
│   │   └── overlays/dev/      # ExternalSecrets, ClusterSecretStore, ServiceAccount
│   └── regional/              # Terraform for AWS Fargate deployment
│       ├── Makefile           # Wraps terraform commands, sources .env
│       ├── *.tf               # main, variables, outputs, s3, iam, efs, ecs, kms, oidc, lambda
│       ├── examples/          # Manual lifecycle scripts (create, launch, join, stop, close)
│       └── README.md          # Complete deployment documentation
├── lambda/
│   └── create-investigation/  # OIDC-authenticated investigation creation
│       ├── handler.py         # validate_oidc_token, get_or_create_user_role, create_investigation_task
│       ├── test_handler.py    # moto-based unit tests
│       └── Makefile           # Builds deps inside Lambda container
├── tools/
│   ├── create-investigation-lambda.sh  # End-to-end: OIDC → Lambda → assume role → wait for task
│   ├── join-investigation.sh           # Connect to running investigation via ECS Exec
│   ├── test-lambda-e2e.sh              # End-to-end Lambda test script
│   └── sre-auth/                       # OIDC token + role assumption scripts
│       ├── get-oidc-token.sh           # PKCE browser flow, caches token 4 min
│       ├── assume-role.sh              # sts:AssumeRoleWithWebIdentity
│       └── README.md                   # Detailed OIDC tool documentation
├── tests/localstack/
│   ├── compose.yml            # LocalStack Pro + mock OIDC (local/macOS, local executor)
│   ├── compose.ci.yml         # LocalStack Pro + mock OIDC (CI, Docker executor for Lambda)
│   ├── integration/           # 28 tests across 8 test files
│   ├── oidc/mock_jwks.py      # Flask mock OIDC server
│   └── README.md              # Full test documentation
└── docs/
    ├── architecture/overview.md
    ├── configuration/aws-iam-policies.md
    ├── configuration/keycloak-realm-setup.md
    └── runbooks/              # investigation-workflow, troubleshooting, user-access-guide
```

## Investigation Isolation Model

Each investigation gets:
- **Unique EFS access point**: `/$cluster_id/$investigation_id/` mounted to `/home/sre`
- **Unique task definition**: `rosa-boundary-dev-$cluster_id-$investigation_id-TIMESTAMP` with locked OC version and pre-configured env vars
- **Unique S3 paths per task**: `s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`

**EFS Access Point Limit**: 10,000 per filesystem.

Two creation workflows: **Lambda-based** (recommended, OIDC-authenticated, `sre-team` group checked, per-user IAM roles tagged to `owner_sub`) via `tools/create-investigation-lambda.sh`, and **manual lifecycle scripts** via `deploy/regional/examples/`. See [`docs/runbooks/investigation-workflow.md`](docs/runbooks/investigation-workflow.md).

## Keycloak on OpenShift

`deploy/keycloak/` is a **Kustomize** configuration (not Terraform) for deploying Keycloak (RHBK operator) on an OpenShift cluster:

- **CloudNativePG** (PostgreSQL 18.1) for Keycloak state
- **ExternalSecrets** pulls DB credentials from AWS SSM Parameter Store (`/keycloak/db/*`)
- **Edge TLS**: OpenShift Router terminates TLS; Keycloak serves HTTP
- Overlay (`overlays/dev/`) adds ClusterSecretStore, ExternalSecret-based service account, and IRSA-based secret access

```bash
oc apply -k deploy/keycloak/overlays/dev
```

For realm and OIDC client configuration, see [`docs/configuration/keycloak-realm-setup.md`](docs/configuration/keycloak-realm-setup.md).

## LocalStack Integration Testing

28 integration tests in `tests/localstack/integration/` cover S3, IAM, Lambda, KMS, EFS, ECS, SSM, and CloudWatch Logs.

### Running Tests

```bash
make localstack-up           # Start LocalStack Pro + mock OIDC
make test-localstack-fast    # Skip slow ECS task launches
make test-localstack         # Full test suite
make localstack-down
```

### Prerequisites

**macOS**: Podman machine running + `brew install podman-compose` + LocalStack Pro token in `tests/localstack/.env`
```bash
uv venv && source .venv/bin/activate && uv pip install pytest boto3 requests
```

**Linux**: `systemctl --user enable --now podman.socket` + `uv pip install --system podman-compose pytest boto3 requests`

### Key Notes

- **macOS**: `compose.yml` uses `local` executors (not `docker`/`podman`) to avoid socket issues — tests validate AWS API compliance, not container execution. CI uses `compose.ci.yml` with Docker executor for Lambda support.
- **Service names**: LocalStack uses `efs` (not `elasticfilesystem`), `ssm` (not `systems-manager`)
- **Version**: LocalStack Pro ≥ 4.4.0 required; use `latest` tag in compose files
- **Test markers**: `@pytest.mark.integration` (all), `@pytest.mark.slow` (ECS task launches), `@pytest.mark.e2e` (end-to-end)

See `tests/localstack/README.md` for full documentation including troubleshooting and adding tests.

## GitHub Actions CI

**File**: `.github/workflows/localstack-tests.yml`

**Triggers**: PRs to `main`/`feature/*` or pushes to `main`, only when `lambda/`, `deploy/regional/`, or `tests/localstack/` change.

**Required secret**: `LOCALSTACK_AUTH_TOKEN` (repo Settings → Secrets and variables → Actions)

**Jobs**:
1. **localstack-tests** — integration tests using `compose.ci.yml`; runs for upstream PRs and pushes to main
2. **localstack-tests-fork** — skips with a notice for fork PRs (no access to secrets)
3. **lambda-unit-tests** — moto-based unit tests with Codecov coverage upload; runs on all triggers
