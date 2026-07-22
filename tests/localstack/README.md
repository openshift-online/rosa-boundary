# LocalStack Integration Testing

Comprehensive LocalStack Pro-based testing infrastructure for rosa-boundary AWS services.

## Overview

This testing infrastructure validates all AWS functionality locally before production deployment:

- **S3**: Audit bucket with WORM compliance and Object Lock
- **IAM**: Roles, policies, OIDC providers, tag-based authorization
- **Lambda**: Investigation creation (moto unit tests; see `make test-lambda-create-investigation`)
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

### Python Environment (for running tests)

**macOS - Use virtual environment**:
```bash
# Create and activate venv
uv venv
source .venv/bin/activate

# Install test dependencies
uv pip install pytest boto3 requests
```

**Linux - System-wide or venv**:
```bash
# Option 1: System-wide (requires --system flag)
uv pip install --system pytest boto3 requests

# Option 2: Virtual environment (recommended)
uv venv && source .venv/bin/activate
uv pip install pytest boto3 requests
```

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
make localstack-up

# Run all tests
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

### Test Markers

```bash
# Run all integration tests
pytest -m integration

# Skip slow tests (>30s)
pytest -m "integration and not slow"

# Run only end-to-end tests
pytest -m e2e
```

## Architecture

### LocalStack Services

Two compose files are provided:
- **compose.yml** - Local development (macOS compatible)
- **compose.ci.yml** - Local Prow simulation (local executor, no Docker socket required; Prow itself uses `ci-run.sh`)

Both start one container:

1. **localstack** - LocalStack Pro with ECS, EFS, S3, IAM, Lambda, etc.

### Network Initialization

`init-aws.sh` runs when LocalStack reaches "ready" state:
- Creates VPC with 10.0.0.0/16 CIDR
- Creates two subnets in us-east-2a and us-east-2b
- Creates Internet Gateway and route table
- Creates security group for ECS tasks
- Stores resource IDs in SSM Parameter Store for test discovery

### pytest Fixtures (`conftest.py`)

- `localstack_available` - Skips tests if LocalStack not running
- `s3_client`, `iam_client`, `lambda_client`, etc. - Boto3 clients for LocalStack
- `test_vpc` - VPC and subnets created by init-aws.sh
- `test_efs` - EFS filesystem with automatic cleanup

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

### Lambda Testing

Lambda integration tests are not part of this LocalStack suite. Lambda functionality is
covered by moto unit tests — run them with `make test-lambda-create-investigation`
(see `lambda/create-investigation/test_handler.py`).

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
mounts `init-aws.sh` as an init hook (auto-runs on ready), waits for all required services
(see `required_services.py`) and for `init-aws.sh` to populate SSM parameters, then runs
`pytest integration/ -v --tb=short` against the full suite.

**Executor-dependent test skips:** Three tests in `test_task_timeout.py` and `test_full_workflow.py` are gated on `ECS_EXECUTOR != 'local'`. In Prow CI, `ci-run.sh` exports `ECS_EXECUTOR=docker` before invoking pytest, so these tests run. Locally, `make test-localstack` does not set `ECS_EXECUTOR`, so they are silently skipped — this is intentional since they require a live container runtime socket. To replicate CI behavior locally:
```bash
ECS_EXECUTOR=docker make test-localstack
```

**Secret bootstrap (one-time setup):**
Vault path: `secret/rosa-boundary/localstack` → key: `auth-token`
CI cluster secret: `localstack-token` → key: `localstack-token`

To add the secret:
1. Store `LOCALSTACK_AUTH_TOKEN` in Vault at the path above
2. Open a PR to `openshift/release` adding a secret sync rule for `rosa-boundary-localstack-auth-token`
3. Coordinate with DPTP via `#forum-ocp-testplatform`

**Local verification (Prow-mode):**
```bash
cd tests/localstack
LOCALSTACK_AUTH_TOKEN=<your-token> podman-compose -f compose.ci.yml up -d
pytest integration/ -v
podman-compose -f compose.ci.yml down -v
```

## Troubleshooting

### LocalStack not starting

```bash
# Check podman socket
systemctl --user status podman.socket

# Check LocalStack auth token
cat .env | grep LOCALSTACK_AUTH_TOKEN

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
# Ensure XDG_RUNTIME_DIR is set
echo $XDG_RUNTIME_DIR

# Check podman socket permissions
ls -l $XDG_RUNTIME_DIR/podman/podman.sock
```

## Development Workflow

1. Start LocalStack: `make localstack-up`
2. Run tests during development: `pytest tests/localstack/integration/test_*.py -v`
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
