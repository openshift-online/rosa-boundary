# LocalStack Integration Testing

Comprehensive LocalStack Pro-based testing infrastructure for rosa-boundary AWS services.

## Overview

This testing infrastructure validates all AWS functionality locally before production deployment:

- **S3**: Audit bucket with WORM compliance and Object Lock
- **IAM**: Roles, policies, OIDC providers, tag-based authorization
- **Lambda**: OIDC-authenticated investigation creation
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

# Run without Lambda tests (skip if LocalStack local executor fails)
pytest tests/localstack/integration/ -v -m "not slow" --ignore=tests/localstack/integration/test_lambda_handler.py

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
- `test_lambda_handler.py` - Lambda with OIDC authentication
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
- **compose.yml** - Local development (macOS compatible, Lambda tests skipped)
- **compose.ci.yml** - CI/Linux (Docker executor, Lambda tests enabled)

Both start two containers:

1. **localstack** - LocalStack Pro with ECS, EFS, S3, IAM, Lambda, etc.
2. **mock-oidc** - Flask server providing JWKS and test token generation

### Mock OIDC Server

Provides:
- JWKS endpoint at `/realms/sre-ops/protocol/openid-connect/certs`
- OpenID configuration at `/.well-known/openid-configuration`
- Test token generation via `create_test_token()` function

RSA keys generated in `oidc/test_keys/` used for signing test JWTs.

### Network Initialization

`init-aws.sh` runs when LocalStack reaches "ready" state:
- Creates VPC with 10.0.0.0/16 CIDR
- Creates two subnets in us-east-2a and us-east-2b
- Creates Internet Gateway and route table
- Creates security group for ECS tasks
- Stores resource IDs in SSM Parameter Store for test discovery

### pytest Fixtures (`conftest.py`)

- `localstack_available` - Skips tests if LocalStack not running
- `mock_oidc_available` - Skips if mock OIDC server not running
- `s3_client`, `iam_client`, `lambda_client`, etc. - Boto3 clients for LocalStack
- `test_vpc` - VPC and subnets created by init-aws.sh
- `test_efs` - EFS filesystem with automatic cleanup
- `test_token_generator` - Function to create test OIDC tokens

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

Lambda tests require LocalStack's Docker executor to run. We provide two compose files:

**`compose.yml`** (default - local development):
- Uses `LAMBDA_EXECUTOR=local` for macOS compatibility
- Lambda tests are automatically skipped
- Faster startup, no Docker socket required

**`compose.ci.yml`** (CI/Linux):
- Uses `LAMBDA_EXECUTOR=docker` with socket mount
- Lambda tests run successfully
- Requires Docker/Podman socket access

**Local development** (macOS):
```bash
# Lambda tests skipped automatically
make localstack-up
make test-localstack-fast
```

**Linux/CI** (enable Lambda tests):
```bash
cd tests/localstack
podman-compose -f compose.ci.yml up -d
LAMBDA_EXECUTOR=docker pytest integration/ -v -m "not slow"
```

Lambda tests are also available as unit tests with moto (see `lambda/create-investigation/test_handler.py`).

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

GitHub Actions workflow (`.github/workflows/localstack-tests.yml`):

1. **Unit Tests** - Run existing moto-based tests
2. **LocalStack Integration** - Full integration tests with Pro features
3. **Terraform Validate** - Terraform plan against LocalStack

**Required GitHub Secret**:
- `LOCALSTACK_AUTH_TOKEN` - LocalStack Pro license token

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

# Verify mock OIDC
curl http://localhost:8080/realms/sre-ops/protocol/openid-connect/certs
```

### Podman permission issues

```bash
# Ensure XDG_RUNTIME_DIR is set
echo $XDG_RUNTIME_DIR

# Check podman socket permissions
ls -l $XDG_RUNTIME_DIR/podman/podman.sock
```

### Container build fails

```bash
# Build mock OIDC container manually
cd oidc
podman build -t mock-oidc -f Containerfile .
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
