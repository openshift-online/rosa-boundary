# LocalStack Integration Testing

Comprehensive LocalStack Pro-based testing infrastructure for rosa-boundary AWS services.

## Overview

These tests exercise emulated AWS APIs, policy structure, and selected CLI
workflows. Optional content-sync runtime tests also execute containers locally;
none of these prove real AWS authorization or production behavior:

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

The image is pinned in `compose.yml` and `compose.ci.yml`; `ci-run.sh` selects
its default through `LOCALSTACK_VERSION`. Consult those files for the current
version rather than substituting `latest`.

### Podman Setup

Start with [contributor setup](../../CONTRIBUTING.md) for mise, Podman, GNU
utilities, and the root uv environment. `podman-compose` is already a root Python
dependency; no separate system-wide installation is needed.

On macOS, initialize a Podman machine once if needed, then start it:

```bash
podman machine init  # Only if no machine exists
podman machine start
```

On rootless Linux, enable the socket:

```bash
systemctl --user enable --now podman.socket
```

### Podman socket discovery

The root `make localstack-up`, `make localstack-down`, and `make localstack-logs`
targets use `compose.sh`, which queries `podman info` for the server-side socket
path. On macOS this is a path **inside the Podman VM**, not a socket on the Mac.
On Linux it follows the active rootless/rootful engine. No user ID or
`XDG_RUNTIME_DIR` configuration is needed.

For direct Compose operations from the repository root, use
`uv run --group localstack bash tests/localstack/compose.sh ...` instead of raw
`podman-compose`. This also supplies the uv-managed executable when the virtualenv
is not activated. The wrapper passes all arguments through.
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

The small `pyproject.toml`/`setup.py` in this directory is a compatibility adapter
for the external Prow image build, which runs
`uv pip install --python python3.11 --system .` here. It reads dependencies from
the root group without installing the Python 3.13 root project. It requires the
complete repository checkout and is not a separately published package. Keep
this directory-install contract until the external job is migrated; local
contributors should continue using the root uv commands below.

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

From the repository root:

```bash
cp tests/localstack/.env.example tests/localstack/.env
```

Edit the ignored file to set `LOCALSTACK_AUTH_TOKEN`; do not put the token in
shell history or shared logs. An exported shell value overrides the file.

## Quick Start

```bash
# From project root
uv sync --group localstack
uv run --group localstack make localstack-up

# Run fast tests while LocalStack remains running
make test-localstack-fast

# View logs before teardown (Ctrl-C stops following logs)
uv run --group localstack make localstack-logs

# All local gates, including full integration; leaves LocalStack running
make test-all

# Stop without requesting volume deletion
uv run --group localstack bash tests/localstack/compose.sh down
```

On macOS, if GNU `timeout` is not on PATH, use the startup invocation in
[local setup guide](../../docs/runbooks/contributor-local-setup.md#2-request-localstack-access).
For full integration only, `make test-localstack` starts LocalStack and tears it
down afterward using `down -v`. Treat that as an alternative workflow, not a step
before commands that need the same running service. `make localstack-down` also
requests removal of Compose-managed volumes.

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
- `test_task_timeout.py` - Reaper deadline checks and policy assertions, with explicit platform skips
- `test_close_investigation.py` - named-profile CLI close/cleanup, required cluster targeting, and invalid-config rejection using the test-built Go binary
- `test_reap_investigations_directory.py` - Investigation directory contracts
- `test_efs_filesystem_policy.py`, `test_terraform_efs_policy.py` - EFS policy API/source contracts
- `test_kube_proxy_sidecar.py` - Multi-container task-definition contracts

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
- **compose.ci.yml** - Alternative local configuration with a Podman socket mount;
  not a reproduction of the complete Prow job

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
  STS/ECS/EFS endpoints are loopback-only. LocalStack's ECS familyPrefix matches
  only complete family names, so this tagged build scans ACTIVE task definitions
  and filters the investigation prefix locally; normal builds use the AWS
  server-side prefix. Neither build trusts the family name alone for cleanup.
- `localstack_cli_env` - Isolated synthetic ID-token cache, LocalStack SRE role,
  dummy credentials, and consistent region. The close tests save a named profile
  in this isolated config directory; they never reuse your real SSO state.
  This exercises close workflow behavior, not real OIDC/IAM security.

## Testing Approach

### Task Lifecycle Focus

Most ECS tests validate task submission and management, not container internals
(the content-sync runtime test below is an explicit exception):

- **Tested**: Task definition registration, run-task API, tagging, stop-task
- **Not Tested**: Container execution, ECS Exec sessions, actual container logs

This approach tests infrastructure components without requiring containers to run.

### Tag-Based Authorization

Tests create roles and tasks with username tags and inspect trust/policy
structure. Some policy-simulation cases are explicitly skipped because LocalStack
does not evaluate the required ECS resource-tag conditions. A passing local run
is not evidence of real cross-user isolation or IAM enforcement; those assertions
require separately approved live verification.

## Content-sync runtime coverage

`integration/test_content_sync_runtime.py` has two distinct levels. Both use the
**current shipped script bytes**, passed to Bash exactly as in the task definition,
and the image's real AWS CLI. No stub AWS executable, production script changes,
GitHub Action, or real AWS account is needed. Fixtures own unique unversioned S3
buckets; tests remove only their buckets, container/volume, and ECS resources.
They never start/stop LocalStack or change its global executor configuration.

Prerequisites: an already-ready LocalStack, a prebuilt Boundary image containing
Bash/GNU timeout/AWS CLI, and Podman (or `CONTENT_SYNC_TEST_ENGINE=docker`). Build
through `make build-amd64` when needed; this test does not build or pull images.
With the existing Compose network and image, from the repository root:

```bash
CONTENT_SYNC_TEST_IMAGE=localhost/rosa-boundary:latest-amd64 ECS_EXECUTOR=local \
  uv run --group localstack pytest \
  tests/localstack/integration/test_content_sync_runtime.py -v -ra
uv run --group localstack pytest tests/unit/test_content_sync_runtime_guards.py -v
```

**Level 1** starts a standalone image container with a unique named volume at the
fixed `/opt/rosa-content` destination, with the sidecar's read-only root filesystem
and dropped capabilities. Defaults are network `rosa-boundary-test`
and endpoint `http://localstack:4566`; override with `CONTENT_SYNC_TEST_NETWORK`
and `CONTENT_SYNC_CONTAINER_ENDPOINT` for an existing local topology. The host
fixture uses `LOCALSTACK_ENDPOINT` (default `http://localhost:4566`). Runtime
endpoints must explicitly use local HTTP port 4566 (loopback/private IP or the
recognized LocalStack service names). Only dummy credentials are supplied;
personal AWS configuration is not mounted. Missing image configuration produces
an explicit skip; a configured but missing image or broken runtime fails.

Assertions: all three prefixes exhaust bounded retries against a test-owned
missing bucket without terminating; creating/populating that bucket recovers
without restarting the script; nested skills/assets, SOPs and notifications are
byte-exact across `ops-sop/`, `rosa-claude-plugins/` and
`managed-notifications/`; periodic sync propagates updates and remote deletion
while preserving unrelated content. Script logs are saved under pytest's per-test temporary path
(printed by the test, available with `-s` or on failure). Use `--basetemp` to retain
these under your validation artifact directory. This is S3/CLI/script execution,
**not ECS task execution**.

**Level 2** is marked `slow` and skips explicitly on `ECS_EXECUTOR=local`. On an
already configured Docker-backed LocalStack executor, provision the same prebuilt
image in the executor's engine and run:

```bash
ECS_EXECUTOR=docker CONTENT_SYNC_TEST_IMAGE=localhost/rosa-boundary:latest-amd64 \
  CONTENT_SYNC_ECS_ENDPOINT=http://localstack:4566 \
  uv run --group localstack pytest \
  tests/localstack/integration/test_content_sync_runtime.py -k ecs -v -ra
```

The endpoint must actually be reachable from executor containers; use its private
IP if the executor network does not resolve the service name. Changing the pytest
variable does **not** enable the server executor. Missing image/endpoint
configuration is an explicit skip, not successful execution. Configured execution
that cannot start containers or share the volume fails by bounded timeout.

This registers/runs an ECS EC2/bridge test task with an anonymous task-shared host
volume: writable sidecar, read-only consumer, no startup dependency. The consumer
writes a control S3 marker **before the content bucket exists**, proving startup
is not blocked by content availability. It then rejects a write as root on its
read-only mount, reads all three prefixes (including nested assets) produced by
the sidecar, and writes a separate success marker. ECS lifecycle status alone
cannot satisfy the test. This tests emulated ECS execution/mount semantics, not
the deployed Fargate task definition, EFS, real IAM, or production networking.
No automatic CI image provisioning has been added.

## Terraform Testing

Use `make test-all` for isolated Terraform initialization/validation and mocked
account/regional tests; see the [testing guide](../../docs/testing.md). The runner
copies source into disposable directories, disables backends, and rejects test
files without a mocked AWS provider.

There is no supported LocalStack Terraform apply recipe here.
`terraform/override.tf` is an endpoint-override reference, not automatically loaded
by the regional root. Running Terraform in `deploy/regional` uses its normal AWS
provider, not LocalStack. Do not run plan/apply there expecting emulator isolation.
Real infrastructure changes use the approved [personal dev workflow](../../docs/runbooks/personal-dev-bootstrap.md)
or [staging delivery path](../../docs/staging-deployment.md), with target review
and explicit approval.

## Known Limitations

### S3 Object Lock Compliance Mode

LocalStack simulates WORM compliance but may differ from real AWS. Verify production behavior separately.

### Fargate Task Execution

LocalStack simulates task submission but actual container execution varies.
Most tests cover lifecycle only; the opt-in content-sync runtime test requires
container execution and shared-volume evidence as described above.

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

**Triggers and secret provisioning:** the external `openshift/release` job and
secret-sync configuration are authoritative. The CI entrypoint requires
`LOCALSTACK_AUTH_TOKEN` and `ARTIFACT_DIR`; confirm the current Vault path, key,
and cluster-secret mapping with the platform/CI administrators rather than
copying an unverified mapping from this guide. Do not change existing secret
infrastructure as part of local onboarding.

**Architecture:** `ci-run.sh` starts a Podman API service, mounts its socket and
`init-aws.sh` into LocalStack, checks required-service readiness, and runs the full
`pytest integration/ --verbose --tb=short --junit-xml=...` selection. It exports
`ECS_EXECUTOR=docker` to enable executor-dependent test cases and retains its own
JUnit completion guard. The local aggregate's optional completeness policy does
not change that CI guard.

**Executor-dependent skips:** three cases in `test_task_timeout.py` and
`test_full_workflow.py` skip when the pytest environment uses `ECS_EXECUTOR=local`.
Local `compose.yml` also explicitly configures the *server* with that executor.
Setting `ECS_EXECUTOR=docker` only on the host changes test selection, not the
server configuration, and is not a supported shortcut to reproducing CI.

**Alternative local Compose configuration:** from the repository root, with the
engine running and the ignored `.env` configured:

```bash
uv run --group localstack bash tests/localstack/compose.sh -f compose.ci.yml up -d
# Retry this check until required services are ready; do not test before it passes.
make localstack-ready
uv run --group localstack pytest tests/localstack/integration/ -v -ra
uv run --group localstack bash tests/localstack/compose.sh -f compose.ci.yml down
```

This does not recreate the CI job environment or prove executor-dependent tests
ran. Inspect skips; configuring a real container executor is a separate task.

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

1. Follow [CONTRIBUTING.md](../../CONTRIBUTING.md) for tools and licensing.
2. Use `make test` or `make check` for offline iteration.
3. Start LocalStack, then run focused integration tests from the root.
4. Use `make test-all` for the broader local gates; inspect INCOMPLETE coverage.
   Add `TEST_ALL_ARGS=--require-complete` when an unskipped run is required.
5. Stop with `uv run --group localstack bash tests/localstack/compose.sh down`.
   Use `make localstack-down` only when requesting volume deletion is intended.

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
