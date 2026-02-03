# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

Multi-architecture container for AWS Fargate that provides tools for managing AWS and OpenShift (ROSA) clusters. Part of a **zero-trust access pattern** that combines:

- **Identity**: Keycloak (Red Hat build) for OIDC authentication
- **Access Control**: HCP Boundary for authorization and session management
- **Infrastructure**: ECS Fargate with SSM for ephemeral SRE containers

Designed for ephemeral SRE use with ECS Exec access as the `sre` user. The entrypoint script supports dynamic version selection via environment variables, signal handling for graceful shutdown with S3 backup, and defaults to `sleep infinity`.

**For complete architecture and integration details**, see [`docs/`](docs/README.md).

## Development Workflow

### Tool Usage Guidelines

**IMPORTANT**: Always use Makefiles and Terraform for builds and deployments:
- **Container builds**: Use `make` commands (never `podman build` directly)
- **Lambda builds**: Use `make` commands in `lambda/*/` directories
- **Infrastructure**: Use `terraform` commands in `deploy/regional/`

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

## Container Architecture

### Multi-Architecture Build System

The Containerfile uses `uname -m` to detect architecture at build time. When podman builds with `--platform linux/arm64`, RUN commands execute in QEMU emulation where `uname -m` returns `aarch64`. For `--platform linux/amd64`, it returns `x86_64`.

- **x86_64 (amd64)**: Uses `x86_64` for AWS CLI, no suffix for OpenShift downloads
- **ARM64 (aarch64)**: Uses `aarch64` for AWS CLI, `-arm64` suffix for OpenShift downloads

Architecture values from `uname -m` are stored in temp files (`/tmp/aws_cli_arch`, `/tmp/oc_suffix`) during build and consumed by subsequent RUN commands.

### Tool Installation via Alternatives System

The container uses Linux alternatives system to manage multiple versions:

**AWS CLI**:
- Fedora RPM (`/usr/bin/aws`) - priority 10, family "fedora"
- Official AWS CLI v2 (`/opt/aws-cli-official/v2/current/bin/aws`) - priority 20, family "aws-official" (default)

**OpenShift CLI**:
- 7 versions installed to `/opt/openshift/{version}/oc`
- Priorities: 14-19 for versions 4.14-4.19, priority 100 for 4.20 (default)
- All downloaded from `https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-{version}/`

### Critical URLs

- **AWS CLI**: `https://awscli.amazonaws.com/awscli-exe-linux-{arch}.zip`
- **OpenShift CLI**: `https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-{version}/openshift-client-linux{suffix}.tar.gz`

### Runtime Version Selection

The container includes an entrypoint script (`/usr/local/bin/entrypoint.sh`) that supports dynamic version selection via environment variables:

**Environment Variables**:
- `OC_VERSION`: Select OpenShift CLI version (4.14-4.20, default: 4.20)
- `AWS_CLI`: Select AWS CLI source (`fedora` or `official`, default: official)
- `S3_AUDIT_ESCROW`: S3 URI for syncing /home/sre on exit (optional, e.g., `s3://bucket/investigation-123/`)

**Entrypoint Behavior**:
1. Sets up signal traps for SIGTERM, SIGINT, SIGHUP
2. Checks `OC_VERSION` and uses `alternatives --set` to switch to that version if provided
3. Checks `AWS_CLI` and uses `alternatives --set` to switch to fedora/official if provided
4. Runs the command in background (defaults to `sleep infinity`)
5. Waits for command to complete or signal to arrive
6. On exit/signal: syncs /home/sre to S3 if `S3_AUDIT_ESCROW` is set

The entrypoint is located at `entrypoint.sh` in the repository root and copied to `/usr/local/bin/entrypoint.sh` during build.

### SRE User and Audit Escrow

**SRE User Creation**:
- Created in Containerfile:60 with `useradd -m -s /bin/bash sre`
- User ID: 1000 (standard first user ID)
- Home directory: `/home/sre`
- Intended to be mounted as EFS via Fargate task definition for persistent storage

**Signal Handling and S3 Sync**:
The entrypoint implements signal trapping for graceful shutdown with automatic S3 backup:

1. **Signals Trapped**: SIGTERM, SIGINT, SIGHUP
2. **Sync Trigger**: On receiving any trapped signal or normal exit
3. **Environment Variable**: `S3_AUDIT_ESCROW` - S3 URI for backup destination
4. **Behavior**:
   - If `S3_AUDIT_ESCROW` is set, runs `aws s3 sync /home/sre <destination>`
   - If unset, no sync occurs (silent)
   - Sync failures warn but don't block container exit

**Technical Implementation**:
- Command runs in background with `&` and PID captured
- Script uses `wait` to wait for child process (allows trap handling)
- Cannot use `exec` because it replaces the shell and traps won't fire
- `cleanup()` function handles signals: syncs to S3, kills child, exits

This allows ephemeral containers to preserve investigation artifacts (logs, configs, scripts) when terminated.

### Claude Code Integration

**Installation**:
- Installed via native installer in Containerfile:63-64 with `HOME=/opt/claude-code`
- Binary symlinked to `/usr/local/bin/claude` for system-wide access
- Auto-updates disabled via settings.json

**Configuration Structure**:
```
skel/sre/.claude/           # Skeleton files copied at build time to /etc/skel-sre/
  CLAUDE.md                 # SRE workflow guidance and tool documentation
  settings.json             # Bedrock config, auto-update disabled
```

**Runtime Initialization**:
The entrypoint script (lines 52-58) copies skeleton config to `/home/sre/.claude/` if not present:
- First run on fresh EFS: copies skeleton files from `/etc/skel-sre/.claude/`
- Subsequent runs: preserves user customizations (no overwrite)
- Sets proper ownership for `sre` user

**Bedrock Authentication**:
Environment setup in entrypoint.sh (lines 60-80):
1. Enables Bedrock via `CLAUDE_CODE_USE_BEDROCK=1` (default)
2. Auto-detects AWS region from ECS task metadata (`ECS_CONTAINER_METADATA_URI_V4/task`)
3. Extracts region from Task ARN format: `arn:aws:ecs:REGION:ACCOUNT:task/...`
4. Falls back to `us-east-1` if detection fails
5. Can be overridden via `AWS_REGION` environment variable

**Environment Variables**:
- `CLAUDE_CODE_USE_BEDROCK`: Enable Bedrock (default: 1)
- `AWS_REGION`: Bedrock region (auto-detected from ECS metadata or fallback to us-east-1)
- `ANTHROPIC_MODEL`: Override model ID (optional)
- `DISABLE_AUTOUPDATER`: Disable auto-updates (set to 1 in settings.json)

**IAM Requirements**:
Task role needs:
```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:ListInferenceProfiles"
  ],
  "Resource": [
    "arn:aws:bedrock:*:*:inference-profile/*",
    "arn:aws:bedrock:*:*:foundation-model/*"
  ]
}
```

**Key Files**:
- `Containerfile:63-64` - Claude Code installation
- `Containerfile:68` - Skeleton file copy
- `entrypoint.sh:52-80` - Runtime initialization and Bedrock setup
- `skel/sre/.claude/CLAUDE.md` - SRE context template
- `skel/sre/.claude/settings.json` - Bedrock and auto-update config

## Testing Containers Locally

```bash
# Run with default versions
podman run -it rosa-boundary:latest /bin/bash

# Test with specific OC version
podman run --rm -e OC_VERSION=4.18 rosa-boundary:latest oc version --client

# Test with Fedora AWS CLI
podman run --rm -e AWS_CLI=fedora rosa-boundary:latest aws --version

# Test both environment variables together
podman run -it -e OC_VERSION=4.17 -e AWS_CLI=fedora rosa-boundary:latest /bin/bash

# Verify default tool versions
podman run --rm rosa-boundary:latest sh -c "aws --version && oc version --client"

# Check alternatives configuration (advanced)
podman run --rm rosa-boundary:latest sh -c "alternatives --display aws && alternatives --display oc"

# Test SRE user exists
podman run --rm rosa-boundary:latest id sre

# Test S3 sync on exit (will warn without credentials)
podman run --rm -e S3_AUDIT_ESCROW=s3://test-bucket/test/ \
  rosa-boundary:latest sh -c "echo 'test' > /home/sre/test.txt && exit"

# Test Claude Code installation
podman run --rm rosa-boundary:latest claude --version

# Verify skeleton config files are available
podman run --rm rosa-boundary:latest ls -la /etc/skel-sre/.claude/

# Test Bedrock environment variables
podman run --rm rosa-boundary:latest sh -c 'echo "CLAUDE_CODE_USE_BEDROCK=$CLAUDE_CODE_USE_BEDROCK AWS_REGION=$AWS_REGION"'

# Test Claude Code with Bedrock disabled
podman run --rm -e CLAUDE_CODE_USE_BEDROCK=0 rosa-boundary:latest sh -c 'echo $CLAUDE_CODE_USE_BEDROCK'
```

## Adding New OpenShift Versions

1. Add version to loop in Containerfile:38 (e.g., `4.21`)
2. Add alternatives registration in Containerfile:47-53 with appropriate priority (e.g., priority 21 for 4.21)
3. Update highest version priority to 100 if it should be the new default
4. Update environment variable documentation in README.md and entrypoint.sh validation

## Manifest List Structure

The `make manifest` target creates an OCI image index containing both architectures. Podman/Docker automatically selects the correct platform when pulling `rosa-boundary:latest`.

## Terraform Deployment Infrastructure

### Location

`deploy/regional/` - Complete Terraform configuration for AWS Fargate deployment

### Structure

```
deploy/regional/
  main.tf              - Provider, data sources, locals
  variables.tf         - Input variables with validation
  outputs.tf           - Output values (Lambda URL, OIDC provider, etc.)
  s3.tf                - S3 bucket with WORM compliance
  iam.tf               - Task execution and task roles
  efs.tf               - EFS filesystem with mount targets
  ecs.tf               - ECS cluster, task definition, security groups
  kms.tf               - KMS key for ECS Exec encryption
  oidc.tf              - OIDC identity provider for Keycloak
  lambda-create-investigation.tf  - Lambda function for investigation creation
  examples/            - Manual lifecycle management scripts
    create_investigation.sh - Create access point + task definition
    launch_task.sh     - Launch Fargate task
    join_task.sh       - Connect via ECS Exec
    stop_task.sh       - Stop task (triggers S3 sync)
    close_investigation.sh  - Cleanup access point + task definition
    build-task-def.jq  - jq script for task definition transformation
  get-vpc-info.sh      - Helper to discover VPC/subnets
  .gitignore           - Excludes tfvars, state, .terraform/
```

### Lambda-Based Investigation Creation

**Location**: `lambda/create-investigation/`

The Lambda function provides OIDC-authenticated investigation creation with automatic IAM role management:

**Architecture**:
1. **Authentication**: Validates OIDC token from Keycloak
2. **Authorization**: Checks `sre-team` group membership
3. **Role Management**: Creates or reuses per-user IAM role with tag-based permissions
4. **Task Creation**: Launches ECS task with owner tags
5. **Response**: Returns role ARN and task ARN for client use

**Handler Functions** (`handler.py`):
- `validate_oidc_token()` - JWT signature verification and claim extraction
- `get_or_create_user_role()` - Deterministic role creation based on OIDC `sub` claim
- `create_investigation_task()` - ECS task launch with owner tags
- `lambda_handler()` - Main entry point with error handling

**IAM Policy Created** (per-user role):
```python
# ExecuteCommandOnCluster - Allow ecs:ExecuteCommand on cluster (no tag condition)
# ExecuteCommandOnOwnedTasks - Allow ecs:ExecuteCommand on tasks with matching owner_sub tag
# DescribeAndListECS - Allow task describe/list operations
# SSMSessionForECSExec - Allow ssm:StartSession with tag condition
# KMSForECSExec - Allow KMS operations for encrypted sessions
```

**Tag-Based Authorization**:
- Tasks tagged with `owner_sub` (OIDC `sub` claim)
- Roles can only exec into tasks with matching `owner_sub` tag
- Cross-user task access prevented at IAM policy level

**Building Lambda**:
```bash
cd lambda/create-investigation/
make clean build  # Builds dependencies in Lambda container
```

**Deployment**:
Lambda function is deployed via Terraform in `deploy/regional/lambda-create-investigation.tf`

### Per-Investigation Isolation Model

Each investigation gets:
- **Unique EFS access point**: `/$cluster_id/$investigation_id/` → mounted to `/home/sre`
- **Unique task definition**: `rosa-boundary-dev-$cluster_id-$investigation_id-TIMESTAMP`
  - Locks OC version at investigation creation
  - Pre-configured with CLUSTER_ID, INVESTIGATION_ID, S3_AUDIT_BUCKET env vars
- **Unique S3 paths per task**: `s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`

**EFS Access Point Limit**: 10,000 per filesystem (as of Feb 2025)

### S3 Path Auto-Generation

Entrypoint logic (lines 5-27):
- If `S3_AUDIT_ESCROW` is set → use it
- Else if `S3_AUDIT_BUCKET` + `CLUSTER_ID` + `INVESTIGATION_ID` are set:
  - Auto-detect `TASK_ID` from ECS metadata
  - Generate date: `$(date +%Y%m%d)`
  - Build path: `s3://$bucket/$cluster/$investigation/$date/$taskid/`

## OIDC Authentication Tools

**Location**: `tools/sre-auth/`

Two focused scripts handle OIDC authentication and AWS role assumption:

### get-oidc-token.sh

**Purpose**: Obtain OIDC ID token from Keycloak via browser-based PKCE flow

**Features**:
- PKCE authorization code flow (secure for public clients)
- Local callback server on port 8400
- Token caching for 4 minutes (reduces browser popup fatigue)
- Tokens returned to stdout, messages to stderr

**Usage**:
```bash
# Get token (uses cache if valid)
TOKEN=$(./get-oidc-token.sh)

# Force fresh authentication
TOKEN=$(./get-oidc-token.sh --force)
```

**Token Cache**: `~/.sre-auth/id-token.cache` (600 permissions, 4-minute validity)

### assume-role.sh

**Purpose**: Assume AWS IAM role using OIDC web identity federation

**Features**:
- Calls `get-oidc-token.sh` internally for OIDC token
- Invokes `aws sts assume-role-with-web-identity`
- Returns bash export statements for easy credential loading
- No AWS credential caching (AWS CLI handles this)

**Usage**:
```bash
# Assume role and export credentials
eval $(./assume-role.sh --role arn:aws:iam::123456789012:role/rosa-boundary-user-abc123)

# Verify identity
aws sts get-caller-identity
```

**Key Implementation**:
- Uses cached OIDC token if < 4 minutes old
- Session credentials valid for 1 hour
- Supports `--force` to bypass OIDC token cache

### create-investigation-lambda.sh

**Purpose**: End-to-end wrapper for Lambda-based investigation creation

**Workflow**:
1. Get OIDC token via `get-oidc-token.sh`
2. Invoke Lambda function to create investigation
3. Lambda validates token and creates role + task
4. Assume returned role via `assume-role.sh`
5. Wait for task to reach RUNNING state
6. Display ECS Exec connection command

**Usage**:
```bash
cd tools/
./create-investigation-lambda.sh rosa-boundary-dev inv-12345 4.20
```

**See**: `tools/sre-auth/README.md` for detailed documentation

## Keycloak Infrastructure

**Location**: `deploy/keycloak/`

Terraform configuration for Keycloak realm and OIDC clients on ROSA cluster:

**Resources**:
- Keycloak realm: `sre-ops`
- OIDC client: `aws-sre-access` (public client, PKCE required)
- User federation and group management
- Script mappers for AWS session tags

**Key Files**:
- `main.tf` - Keycloak provider configuration
- `realm.tf` - Realm and client definitions
- `aws-session-tags-mapper.js` - Custom script mapper for AWS tags
- `PREREQUISITES.md` - Setup requirements
- `QUICKSTART.md` - Deployment guide

### Investigation Creation Workflows

Two approaches are available for creating investigations:

#### Lambda-Based (Recommended)

**Workflow**: OIDC authentication → Lambda authorization → Automatic role + task creation

```bash
tools/create-investigation-lambda.sh <cluster-id> <investigation-id> [oc-version]
```

**Steps**:
1. User authenticates via Keycloak (browser popup, PKCE flow)
2. Script calls Lambda with OIDC token
3. Lambda validates token, checks `sre-team` group membership
4. Lambda creates/reuses IAM role tied to user's OIDC `sub` claim
5. Lambda creates EFS access point and launches tagged ECS task
6. Script assumes returned role (tag-based permissions)
7. User connects via ECS Exec with isolated access

**Benefits**:
- Group-based authorization (Lambda validates membership)
- Per-user IAM roles (one role per OIDC sub)
- Tag-based task isolation (users can only access own tasks)
- Token caching (4 minutes, reduces browser popups)
- Automatic role management (no manual IAM operations)

#### Manual Lifecycle Scripts

**Workflow**: Direct AWS API calls → Manual task management

Located in `deploy/regional/examples/`:

1. **create_investigation.sh** `<cluster-id> <investigation-id> [oc-version]`
   - Creates EFS access point with tags
   - Clones base task definition
   - Adds environment variables
   - Registers new task definition family
   - Returns task family name + access point ID

2. **launch_task.sh** `<task-family>`
   - Launches Fargate task with ECS Exec enabled
   - Waits for RUNNING state
   - Returns task ID

3. **join_task.sh** `<task-id>`
   - Connects via ECS Exec as sre user

4. **stop_task.sh** `<task-id> [reason]`
   - Sends SIGTERM to task
   - Entrypoint syncs to auto-generated S3 path
   - Shows expected S3 location

5. **close_investigation.sh** `<task-family> <access-point-id>`
   - Checks for running tasks
   - Deregisters all task definition revisions
   - Deletes EFS access point (prompts for confirmation)

**Use Cases**:
- Testing infrastructure without OIDC
- Debugging task definition issues
- Administrative operations
- CI/CD automation with service roles

### Key Files for Deployment

- `deploy/regional/terraform.tfvars.example` - Template configuration
- `deploy/regional/README.md` - Complete deployment documentation
- `deploy/regional/examples/*.sh` - Manual lifecycle scripts
- `lambda/create-investigation/handler.py` - Lambda authorization logic
- `tools/sre-auth/` - OIDC authentication scripts
- `tools/create-investigation-lambda.sh` - End-to-end creation wrapper

## Keycloak Identity Provider (OpenShift)

### Location

`deploy/keycloak/` - Kustomize configuration for Keycloak (RHBK) deployment on OpenShift

### Structure

```
deploy/keycloak/
  base/
    namespace.yaml         - keycloak namespace
    kustomization.yaml
  components/
    cnpg/
      cluster.yaml         - PostgreSQL cluster (CloudNativePG)
      external-secret-db.yaml - DB credentials from AWS SSM
      kustomization.yaml
    keycloak/
      keycloak.yaml        - Keycloak CR (RHBK operator)
      route.yaml           - OpenShift Route (edge TLS)
      kustomization.yaml
  overlays/
    dev/
      cluster-secret-store.yaml - ExternalSecrets config for AWS SSM
      kustomization.yaml
```

### Deployment

```bash
# Apply Keycloak deployment
oc apply -k deploy/keycloak/overlays/dev

# Get admin credentials (auto-generated by operator)
oc get secret keycloak-initial-admin -n keycloak -o jsonpath='{.data.username}' | base64 -d
oc get secret keycloak-initial-admin -n keycloak -o jsonpath='{.data.password}' | base64 -d

# Get Keycloak URL
oc get route keycloak -n keycloak -o jsonpath='{.spec.host}'
```

### Key Features

- **CloudNativePG 1.28**: PostgreSQL 18.1 for Keycloak state
- **ExternalSecrets**: DB credentials from AWS SSM Parameter Store (`/keycloak/db/*`)
- **ClusterSecretStore**: Uses external-secrets-operator IAM role (IRSA)
- **Edge TLS**: OpenShift Router terminates TLS, Keycloak serves HTTP
- **OIDC Provider**: Configured for AWS Lambda and HCP Boundary integration

## Zero-Trust Access Pattern

The complete system integrates three components:

1. **Keycloak** (OpenShift) - OIDC authentication, user/group management
2. **HCP Boundary** (SaaS) - Authorization enforcement, session management, audit logging
3. **ECS Fargate** (AWS) - Ephemeral containers with SSM access

**Key integration points:**
- Keycloak realm: `rosa-boundary` with OIDC client `hcp-boundary`
- Boundary auth method: OIDC with Keycloak issuer, managed groups for RBAC
- Boundary targets: Per-investigation TCP targets using `-exec` wrapper for ECS Exec
- AWS IAM: Policies for ECS ExecuteCommand, SSM StartSession, KMS Decrypt
- Integration script: `ecs-exec.sh` wraps `aws ecs execute-command` via Boundary `-exec` flag

**Workflow**:
1. User authenticates to Boundary via Keycloak OIDC
2. Boundary checks group membership and grants access to targets
3. User runs `boundary connect -target-id <id> -exec ecs-exec.sh`
4. Script calls `aws ecs execute-command` to start SSM session
5. Session logged in Boundary (metadata), CloudWatch (I/O), and S3 (artifacts)

## LocalStack Integration Testing

**Location**: `tests/localstack/`

Comprehensive integration testing for AWS services using LocalStack Pro. Tests infrastructure components locally before production deployment.

### Running Tests

```bash
# Start LocalStack (macOS: requires podman-compose via Homebrew)
make localstack-up

# Run fast tests (skip slow ECS task launches, ~2-3 min)
make test-localstack-fast

# Run full test suite (~5-7 min)
make test-localstack

# Stop LocalStack
make localstack-down
```

### Prerequisites

**macOS**:
- LocalStack Pro token in `tests/localstack/.env`
- Podman machine running: `podman machine list`
- Install: `brew install podman-compose`
- Python deps in venv: `uv venv && source .venv/bin/activate && uv pip install pytest boto3 requests`

**Linux**:
- Podman socket: `systemctl --user enable --now podman.socket`
- Install: `uv pip install --system podman-compose pytest boto3 requests`

### Architecture

**Services tested**: S3, IAM, Lambda, KMS, EFS, ECS, SSM, CloudWatch Logs

**Key components**:
- `compose.yml` - LocalStack Pro (latest) + mock OIDC server
- `init-aws.sh` - Bootstraps VPC/subnets/security groups on startup
- `conftest.py` - pytest fixtures for all AWS service clients
- `oidc/mock_jwks.py` - Flask server providing test JWT tokens
- 29 integration tests across 8 test files

**Test organization**:
- `test_s3_audit.py` - S3 versioning, Object Lock, lifecycle
- `test_iam_roles.py` - Role creation, tag-based policies
- `test_kms_keys.py` - KMS key management
- `test_efs_access_points.py` - EFS filesystem and access points
- `test_ecs_tasks.py` - ECS cluster, task definitions, tagging
- `test_tag_isolation.py` - Tag-based authorization model
- `test_lambda_handler.py` - Lambda with OIDC authentication
- `test_full_workflow.py` - End-to-end investigation creation

### Important Notes

**macOS compatibility**: Uses `local` executors instead of `docker`/`podman` executors to avoid socket mounting issues. Tests validate AWS API compliance, not container execution.

**Service names**: LocalStack uses `efs` not `elasticfilesystem`, `ssm` not `systems-manager`.

**Version requirement**: LocalStack Pro ≥ 4.4.0 (license requirement). Use `latest` tag in compose.yml.

**Test markers**:
- `@pytest.mark.integration` - All tests (requires LocalStack running)
- `@pytest.mark.slow` - ECS task launches (>30s)
- `@pytest.mark.e2e` - End-to-end workflows

### Adding New Tests

1. Create test file in `integration/` following `test_*.py` naming
2. Use fixtures from `conftest.py` for AWS clients
3. Include cleanup (delete created resources)
4. Mark with appropriate pytest markers
5. Run locally with LocalStack before committing

### Troubleshooting

**LocalStack won't start** (macOS):
```bash
podman machine list  # Should show "Currently running"
podman machine start  # If not running
```

**Service not available**:
```bash
curl http://localhost:4566/_localstack/health | jq '.services'
# Verify service names match those in compose.yml SERVICES env var
```

**Tests skip**:
```bash
# Check LocalStack is running
make localstack-up
# Verify health check passes
curl http://localhost:4566/_localstack/health | jq
```

See `tests/localstack/README.md` for complete documentation.

### GitHub Actions CI

**Location**: `.github/workflows/localstack-tests.yml`

Automated testing on PRs and main branch pushes. Runs integration tests and Lambda unit tests.

**Required GitHub Secret**:
- `LOCALSTACK_AUTH_TOKEN` - LocalStack Pro license token
- Add in repo Settings → Secrets and variables → Actions

**Workflow jobs**:
1. **localstack-tests** - Integration tests (~3-5 min)
   - Starts LocalStack Pro with podman-compose
   - Runs fast tests (skips slow ECS task launches)
   - Publishes test results and coverage

2. **lambda-unit-tests** - Lambda unit tests (~1-2 min)
   - Runs moto-based unit tests
   - Uploads coverage to Codecov

**Triggers**:
- Pull requests to main or feature/* branches
- Pushes to main branch
- Only when lambda/, deploy/regional/, or tests/localstack/ changes
