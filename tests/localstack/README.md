# LocalStack Integration Testing

Comprehensive LocalStack Pro-based testing infrastructure for rosa-boundary AWS services.

## Overview

This testing infrastructure validates all AWS functionality locally before production deployment:

- **S3**: Audit bucket with WORM compliance and Object Lock
- **IAM**: Roles, policies, OIDC providers, tag-based authorization
- **ECS**: Fargate task lifecycle (submit/stop/tag verification)
- **EFS**: Filesystems and access points with POSIX user configuration
- **KMS**: ECS Exec session encryption keys
- **CloudWatch Logs**: Log groups for ECS/Lambda/SSM

## Prerequisites

### LocalStack Pro License

Required for full ECS Fargate and EFS support. Get your auth token from:
https://app.localstack.cloud/workspace/auth-tokens

**Version requirement**: LocalStack Pro ≥ 4.4.0 (we use `latest` tag)

### Podman Setup

**macOS**:
```bash
# Install podman-compose via Homebrew
brew install podman-compose

# Ensure podman machine is running
podman machine list  # Should show "Currently running"
```

**Linux**:
```bash
# Enable podman socket
systemctl --user enable --now podman.socket

# Install podman-compose
uv pip install --system podman-compose
# OR use distribution package: dnf install podman-compose
```

### Podman socket discovery

The root `make localstack-up`, `make localstack-down`, and `make localstack-logs`
targets use `compose.sh`, which queries `podman info` for the server-side socket
path. On macOS this is a path **inside the Podman VM**, not a socket on the Mac.
On Linux it follows the active rootless/rootful engine. No user ID or
`XDG_RUNTIME_DIR` configuration is needed.

For direct Compose operations, run `bash compose.sh ...` from this directory
instead of `podman-compose ...`. The wrapper passes all arguments through.
For an engine that cannot report its socket, explicitly set
`LOCALSTACK_PODMAN_SOCKET` to its absolute server-side socket path. This override
also takes precedence over discovery; it does not select a different Podman
connection. Start the engine before invoking the wrapper directly.

The wrapper does not grant socket permissions or fix license activation. Access
to the engine socket grants container-management privileges; use only a trusted
LocalStack image and your intended development engine.

### Python Environment (for running tests)

LocalStack test dependencies are managed by the root `pyproject.toml`'s
`localstack` dependency group and root `uv.lock`. Use the root project's Python
version (currently Python 3.13); no separate test-package installation, system-wide
pip install, or virtualenv activation is needed.

```bash
# From the repository root (macOS and Linux)
uv sync --group localstack
```

The Make test targets invoke `uv run --group localstack`, which also syncs the
required environment automatically. To test an already-running LocalStack
without restarting or tearing it down:

```bash
uv run --group localstack pytest tests/localstack/integration/ -v --tb=short -ra
```

Make targets and `test-all` assert live health before launching integration tests.
Direct pytest runs fail dependent fixture setup if LocalStack is down or required
services are unhealthy; this is always a failure, independent of completion policy.
`make test-all` reports skipped coverage as `INCOMPLETE` without a nonzero exit by
default; use `TEST_ALL_ARGS=--require-complete` to require an unskipped run.
The local ECS executor still does not exercise real task-container execution.

### Configuration

```bash
# Copy environment template
cp .env.example .env

# Add your LocalStack Pro token
echo "LOCALSTACK_AUTH_TOKEN=your-token-here" >> .env
```

## Quick Start

```bash
# From project root
uv sync --group localstack
make localstack-up

# Run all tests (runs startup, then tears down with down -v afterward)
make test-localstack

# Run fast tests only (skip slow ECS task launches)
make test-localstack-fast

# View logs
make localstack-logs

# Stop and cleanup
make localstack-down
```

## Test Organization

### Integration Tests (`integration/`)

All tests marked with `@pytest.mark.integration`:

- `test_s3_audit.py` - S3 bucket with versioning, Object Lock, lifecycle policies
- `test_iam_roles.py` - Role creation, policy attachment, OIDC providers
- `test_kms_keys.py` - KMS key creation with policies for ECS task role
- `test_efs_access_points.py` - EFS filesystem and access point lifecycle
- `test_ecs_tasks.py` - ECS cluster, task definitions, task lifecycle
- `test_tag_isolation.py` - Tag-based authorization model testing
- `test_full_workflow.py` - End-to-end investigation creation
- `test_task_timeout.py` - Reaper Lambda deadline enforcement and IAM policy simulation

### Test Markers

```bash
# From the repository root: run all integration tests
uv run --group localstack pytest tests/localstack/integration/ -m integration -ra

# Skip slow tests (>30s)
uv run --group localstack pytest tests/localstack/integration/ -m "integration and not slow" -ra

# Run only end-to-end tests
uv run --group localstack pytest tests/localstack/integration/ -m e2e -ra
```

## Architecture

### LocalStack Services

Two compose files are provided:
- **compose.yml** - Local development (macOS compatible)
- **compose.ci.yml** - Local Prow simulation (no Docker socket required)

Both start a single container:

1. **localstack** - LocalStack Pro with ECS, EFS, S3, IAM, KMS, SSM, EC2, etc.

### Network Initialization

`init-aws.sh` runs when LocalStack reaches "ready" state:
- Creates VPC with 10.0.0.0/16 CIDR
- Creates two subnets in us-east-2a and us-east-2b
- Creates Internet Gateway and route table
- Creates security group for ECS tasks
- Stores resource IDs in SSM Parameter Store for test discovery

### pytest Fixtures (`conftest.py`)

- `localstack_available` - Fails dependent fixture setup before resource creation if LocalStack or required services are not ready
- `s3_client`, `iam_client`, `ecs_client`, etc. - Boto3 clients for LocalStack
- `test_vpc` - VPC and subnets created by init-aws.sh (session-scoped)
- `test_efs` - EFS filesystem with automatic cleanup
- `localstack_cli_binary` - Temporary CLI compiled with the `localstack` build tag;
  STS/ECS/EFS endpoints are loopback-only. Normal builds retain AWS endpoints.
- `localstack_cli_env` - Isolated synthetic ID-token cache, LocalStack SRE role,
  dummy credentials, and consistent region; never reuses your real SSO state.
  This exercises close-investigation workflow behavior, not real OIDC/IAM security.

## Testing Approach

### Task Lifecycle Focus

ECS tests validate task submission and management, not container internals:

- **Tested**: Task definition registration, run-task API, tagging, stop-task
- **Not Tested**: Container execution, ECS Exec sessions, actual container logs

This approach tests infrastructure components without requiring containers to run.

### Tag-Based Authorization

Tests verify IAM policy conditions without executing tasks:

- Create roles with tag-based policies
- Run tasks with different username tags
- Verify IAM policy evaluation logic
- Test cross-user access prevention


## Terraform Testing

```bash
cd deploy/regional

# Initialize with LocalStack provider
terraform init

# Validate configuration
terraform validate

# Plan against LocalStack
terraform plan -var-file=../../tests/localstack/terraform/localstack.tfvars

# Apply (LocalStack Pro only, experimental)
terraform apply -var-file=../../tests/localstack/terraform/localstack.tfvars
```

**Note**: Full Terraform apply may not work due to LocalStack limitations with complex resources.

## Known Limitations

### S3 Object Lock Compliance Mode

LocalStack simulates WORM compliance but may differ from real AWS. Verify production behavior separately.

### Fargate Task Execution

LocalStack simulates task submission but actual container execution varies. We test task lifecycle, not container behavior.

### Container Image Pull

LocalStack may not pull from ECR. Tests use public Amazon Linux images for task definitions.

### VPC Networking

LocalStack simulates VPC/subnets but actual network connectivity not tested.

### OIDC Provider Support

LocalStack may have limited OIDC provider functionality. Some tests may skip if not supported.

## CI/CD Integration

### Prow CI

Prow presubmit job runs in `openshift/release` at
`ci-operator/config/openshift-online/rosa-boundary/openshift-online-rosa-boundary-main.yaml`.

**Job name:** `pull-ci-openshift-online-rosa-boundary-main-localstack-integration-tests` (presubmit)

**Triggers:** PRs touching `lambda/`, `deploy/regional/`, or `tests/localstack/`.

**Architecture:** CI entrypoint is `ci-run.sh`. It starts LocalStack Pro in a podman container,
mounts `init-aws.sh` as an init hook (auto-runs on ready), waits for the ECS service,
then runs `pytest integration/ -v --tb=short` against the full suite.

**Executor-dependent test skips:** Three tests in `test_task_timeout.py` and `test_full_workflow.py` are gated on `ECS_EXECUTOR != 'local'`. In Prow CI, `ci-run.sh` exports `ECS_EXECUTOR=docker` before invoking pytest, so these tests run. Locally, `make test-localstack` does not set `ECS_EXECUTOR`, so they are silently skipped — this is intentional since they require a live container runtime socket. To replicate CI behavior locally:
```bash
ECS_EXECUTOR=docker make test-localstack
```

**Executor-dependent test skips:** Three tests in `test_task_timeout.py` and `test_full_workflow.py` are gated on `ECS_EXECUTOR != 'local'`. In Prow CI, `ci-run.sh` exports `ECS_EXECUTOR=docker` before invoking pytest, so these tests run. Locally, `make test-localstack` does not set `ECS_EXECUTOR`, so they are silently skipped — this is intentional since they require a live container runtime socket. To replicate CI behavior locally:
```bash
ECS_EXECUTOR=docker make test-localstack
```

**Secret bootstrap (one-time setup):**
Vault path: `selfservice/rosa-boundary/ci` → key: `localstack-token`
CI cluster secret: `localstack-token` → key: `localstack-token`

To add the secret:
1. Store `LOCALSTACK_AUTH_TOKEN` in Vault at the path above
2. Open a PR to `openshift/release` adding a secret sync rule for `rosa-boundary-localstack-auth-token`
3. Coordinate with DPTP via `#forum-ocp-testplatform`

**Local verification (Prow-mode):**
```bash
cd tests/localstack
# Configure LOCALSTACK_AUTH_TOKEN in .env; do not put secrets in shell history.
bash compose.sh -f compose.ci.yml up -d
cd ../..
LAMBDA_EXECUTOR=local uv run --group localstack pytest tests/localstack/integration/ -v -ra
cd tests/localstack
bash compose.sh -f compose.ci.yml down -v
```

## Troubleshooting

### LocalStack not starting

```bash
# Query the active engine and its server-side socket
podman info --format '{{.Host.RemoteSocket.Path}}'

# Linux only: check the rootless socket service
systemctl --user status podman.socket

# Verify .env contains a valid LOCALSTACK_AUTH_TOKEN without printing it.

# View LocalStack logs
make localstack-logs
```

### Tests skipping

```bash
# Verify LocalStack health
curl http://localhost:4566/_localstack/health | jq
```

### Podman permission issues

```bash
# Inspect the active connection and server-side socket
podman system connection list
podman info --format '{{.Host.RemoteSocket.Path}}'

# On macOS, inspect sockets inside the VM, not with a host-side ls:
podman machine ssh 'ls -l /run/user/$(id -u)/podman/podman.sock'
```

## Development Workflow

1. Start LocalStack: `make localstack-up`
2. Run tests during development from the root: `uv run --group localstack pytest tests/localstack/integration/ -v -ra`
3. Run full suite before commit: `make test-localstack`
4. Run staticcheck before commit: `make staticcheck`
5. Stop LocalStack: `make localstack-down`

## Adding New Tests

1. Create test file in `integration/` following naming convention `test_*.py`
2. Use appropriate markers: `@pytest.mark.integration`, `@pytest.mark.slow`, `@pytest.mark.e2e`
3. Use fixtures from `conftest.py` for AWS clients
4. Include cleanup in tests (delete created resources)
5. Run locally with LocalStack before committing

## Resources

- LocalStack Pro Docs: https://docs.localstack.cloud/
- LocalStack ECS Support: https://docs.localstack.cloud/user-guide/aws/elastic-container-service/
- LocalStack EFS Support: https://docs.localstack.cloud/user-guide/aws/elastic-file-system/
- Podman Compose: https://github.com/containers/podman-compose
