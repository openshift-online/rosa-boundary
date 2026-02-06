# ROSA Boundary Container

Multi-architecture container based on Fedora 43 for working with AWS and OpenShift clusters. Designed for AWS Fargate with ECS Exec support.

## Features

- **AWS CLI**: Both Fedora RPM and official AWS CLI v2 with alternatives support
- **OpenShift CLI**: Versions 4.14 through 4.20 from stable channels
- **Claude Code**: AI-powered CLI assistant with Amazon Bedrock integration
- **Dynamic Version Selection**: Switch tool versions via environment variables at runtime
- **ECS Exec Ready**: Designed for AWS Fargate with ECS Exec support
- **Multi-architecture**: Supports both x86_64 (amd64) and ARM64 (aarch64)
- **OIDC Authentication**: Keycloak integration with Lambda-based authorization
- **Tag-Based Isolation**: Per-user IAM roles with task-level access control

## Quick Start

### 1. Configure Environment

Copy the example environment file and update with your values:

```bash
cp .env.example .env
# Edit .env with your AWS account ID and Keycloak URL
```

The `.env` file is gitignored and contains:
- AWS account ID
- Keycloak server URL and realm
- OIDC client ID

Authentication scripts automatically load `.env` if present.

### 2. Deploy Infrastructure

See [Fargate Deployment](#fargate-deployment) section below for Terraform deployment steps.

## Repository Structure

```
rosa-boundary/
├── .env.example           # Environment configuration template (copy to .env)
├── Containerfile          # Multi-arch container build
├── entrypoint.sh          # Runtime initialization and signal handling
├── skel/                  # Skeleton files for container users
│   └── sre/.claude/       # Claude Code configuration templates
├── deploy/
│   ├── regional/          # Terraform: ECS, EFS, S3, Lambda, OIDC
│   │   ├── *.tf          # Infrastructure definitions
│   │   ├── examples/     # Manual lifecycle scripts
│   │   └── README.md     # Deployment guide
│   └── keycloak/         # Terraform: Keycloak realm and clients
├── lambda/
│   └── create-investigation/  # Lambda function for OIDC-authenticated creation
│       ├── handler.py    # Group auth, role creation, task tagging
│       └── Makefile      # Build Lambda package
├── tools/
│   ├── sre-auth/         # OIDC authentication scripts
│   │   ├── get-oidc-token.sh    # Keycloak PKCE flow
│   │   ├── assume-role.sh       # AWS role assumption
│   │   └── README.md            # Auth documentation
│   └── create-investigation-lambda.sh  # End-to-end creation wrapper
├── tests/
│   └── localstack/       # LocalStack integration tests
│       ├── compose.yml   # LocalStack Pro + mock OIDC
│       └── integration/  # AWS service tests
├── docs/                 # Architecture and implementation docs
└── .github/workflows/    # CI/CD automation
```

## Building

### Build all architectures and create manifest
```bash
make all
```

### Build specific architecture
```bash
make build-amd64   # Build x86_64 only
make build-arm64   # Build ARM64 only
```

### Create manifest list
```bash
make manifest      # Combines both architectures
```

### Clean up
```bash
make clean         # Remove all images and manifests
```

## Environment Variables

The easiest way to select tool versions is via environment variables at container startup:

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `OC_VERSION` | `4.14`, `4.15`, `4.16`, `4.17`, `4.18`, `4.19`, `4.20` | `4.20` | OpenShift CLI version |
| `AWS_CLI` | `fedora`, `official` | `official` | AWS CLI source |
| `S3_AUDIT_ESCROW` | S3 URI (e.g., `s3://bucket/path/`) | _(none)_ | S3 destination for /home/sre sync on exit |
| `CLAUDE_CODE_USE_BEDROCK` | `0`, `1` | `1` | Enable Claude Code via Amazon Bedrock |
| `AWS_REGION` | AWS region code | _(auto-detect)_ | AWS region for Bedrock. Auto-detected from ECS metadata; fallback to us-east-1 |
| `ANTHROPIC_MODEL` | Bedrock model ID | _(default)_ | Override Claude model (e.g., `global.anthropic.claude-sonnet-4-5-20250929-v1:0`) |

**Examples:**
```bash
# Use OpenShift CLI 4.18
podman run -e OC_VERSION=4.18 rosa-boundary:latest

# Use Fedora's AWS CLI
podman run -e AWS_CLI=fedora rosa-boundary:latest

# Use both together
podman run -e OC_VERSION=4.17 -e AWS_CLI=fedora rosa-boundary:latest

# With a custom command
podman run -e OC_VERSION=4.19 rosa-boundary:latest /bin/bash
```

## SRE User and Audit Escrow

The container includes a non-root `sre` user (uid=1000) designed for SSM/ECS Exec connections. The `/home/sre` directory is intended to be mounted as EFS via Fargate task definition.

### Automatic S3 Sync on Exit

When the container receives termination signals (SIGTERM, SIGINT, SIGHUP) or exits normally, the entrypoint automatically syncs `/home/sre` to S3 if `S3_AUDIT_ESCROW` is set:

```bash
# Container will sync /home/sre to S3 on exit
podman run -e S3_AUDIT_ESCROW=s3://my-bucket/investigation-123/ rosa-boundary:latest
```

**Features:**
- Automatic sync on container exit or termination signals
- Graceful failure - warns but doesn't block exit if sync fails
- Only syncs if `S3_AUDIT_ESCROW` is defined (no sync if unset)
- Useful for preserving investigation artifacts after ephemeral container use

## Tool Management

The container supports two methods for switching tool versions:

1. **Environment Variables** (recommended): Set `OC_VERSION` or `AWS_CLI` at container startup (see above)
2. **Alternatives Commands** (advanced): Manually switch versions inside a running container

### AWS CLI Alternatives

The container includes two AWS CLI versions managed with alternatives:

- **fedora** (priority 10): Fedora RPM package
- **aws-official** (priority 20): Official AWS CLI v2 (default)

```bash
# View current AWS CLI configuration
alternatives --display aws

# Switch to Fedora version
alternatives --set aws /usr/bin/aws

# Switch to official version
alternatives --set aws /opt/aws-cli-official/v2/current/bin/aws
```

### OpenShift CLI Versions

Seven OpenShift CLI versions are available (4.14-4.20), with 4.20 as the default:

```bash
# View available oc versions
alternatives --display oc

# Switch to a specific version
alternatives --set oc /opt/openshift/4.17/oc
alternatives --set oc /opt/openshift/4.19/oc
```

## Claude Code

The container includes Claude Code CLI with Amazon Bedrock integration for AI-assisted troubleshooting and automation.

### Configuration

**Location**: `/home/sre/.claude/`

Default configuration files are automatically initialized on first run:
- `settings.json` - Bedrock authentication and auto-update settings
- `CLAUDE.md` - SRE workflow guidance and available tools documentation

**Authentication**: Uses IAM via Amazon Bedrock (no API keys required)

### AWS Region Detection

Claude Code automatically detects the AWS region from ECS task metadata:

1. Checks if `AWS_REGION` environment variable is set (explicit override)
2. Queries ECS metadata endpoint to extract region from Task ARN
3. Falls back to `us-east-1` if detection fails

This ensures Claude Code uses Bedrock in the same region as the running container.

### IAM Permissions

The ECS task role needs Bedrock permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
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
  ]
}
```

### Usage Examples

```bash
# Start Claude Code session
claude

# Get help with a command
claude "How do I check the status of cluster operators?"

# Run interactive investigation
claude "Investigate pods in crashloop in default namespace"

# Disable Claude Code via environment variable
podman run -e CLAUDE_CODE_USE_BEDROCK=0 rosa-boundary:latest
```

### Configuration Persistence

Configuration files in `/home/sre/.claude/` are preserved across container restarts when using EFS:
- **First run**: Skeleton files copied from `/etc/skel-sre/.claude/`
- **Subsequent runs**: Existing configuration preserved (no overwrite)
- **Customize**: Edit `/home/sre/.claude/CLAUDE.md` to add cluster-specific context

## Authentication Tools

The `tools/sre-auth/` directory contains OIDC authentication scripts for AWS federation:

### get-oidc-token.sh

Obtains OIDC ID token from Keycloak via browser-based PKCE flow:

```bash
# Get token (uses cache if < 4 minutes old)
TOKEN=$(./tools/sre-auth/get-oidc-token.sh)

# Force fresh authentication
TOKEN=$(./tools/sre-auth/get-oidc-token.sh --force)
```

**Features**:
- Browser-based authentication with Keycloak
- 4-minute token caching (avoids repeated popups)
- PKCE for secure public client flow

### assume-role.sh

Assumes AWS IAM role using OIDC web identity:

```bash
# Assume role created by Lambda
eval $(./tools/sre-auth/assume-role.sh --role arn:aws:iam::123456789012:role/rosa-boundary-user-abc123)

# Verify identity
aws sts get-caller-identity
```

**Features**:
- Uses get-oidc-token.sh internally
- Returns bash export statements for credentials
- Credentials valid for 1 hour

See [`tools/sre-auth/README.md`](tools/sre-auth/README.md) for detailed documentation.

## Usage

### Running locally
```bash
# Run with default versions (OC 4.20, official AWS CLI)
podman run -it rosa-boundary:latest /bin/bash

# Run with specific versions
podman run -it -e OC_VERSION=4.18 -e AWS_CLI=fedora rosa-boundary:latest /bin/bash

# Check tool versions
podman run --rm rosa-boundary:latest sh -c "aws --version && oc version --client"
```

### Fargate Deployment

This container is designed to run as an AWS Fargate task with ECS Exec for remote access. Two deployment approaches are supported:

#### Lambda-Based Investigation Creation (Recommended)

OIDC-authenticated Lambda function that creates per-user IAM roles with tag-based authorization:

```bash
cd deploy/regional/

# Deploy infrastructure (includes Lambda function)
terraform init
terraform apply

# Create investigation with OIDC authentication
cd ../tools/
./create-investigation-lambda.sh rosa-boundary-dev inv-12345

# Script will:
# 1. Authenticate via Keycloak (browser popup)
# 2. Call Lambda to create investigation (role + task)
# 3. Assume OIDC role with tag-based permissions
# 4. Wait for task to be running
# 5. Provide ECS Exec connection command
```

**Features**:
- Group-based authorization (requires `sre-team` membership)
- Per-user IAM roles with tag-based task isolation
- Automatic role creation on first use
- Token caching (4 minutes) to avoid repeated browser authentication

See [`tools/sre-auth/README.md`](tools/sre-auth/README.md) for authentication details and [`docs/LAMBDA_AUTH_SUMMARY.md`](docs/LAMBDA_AUTH_SUMMARY.md) for architecture.

#### Manual Lifecycle Scripts

Lower-level scripts for manual investigation management:

```bash
cd deploy/regional/examples/

# Create investigation (access point + task definition)
./create_investigation.sh <cluster-id> <investigation-id> [oc-version]

# Launch task
./launch_task.sh <task-family>

# Connect to task
./join_task.sh <task-id>

# Stop task (triggers S3 sync)
./stop_task.sh <task-id>

# Cleanup investigation
./close_investigation.sh <task-family> <access-point-id>
```

See [`deploy/regional/README.md`](deploy/regional/README.md) for complete documentation.

#### Manual Deployment

For manual deployment without Terraform:

1. Push container image to ECR or container registry
2. Create ECS cluster with Container Insights
3. Create EFS filesystem with access points per investigation
4. Create IAM roles with Bedrock, S3, and ECS Exec permissions
5. Create task definition with EFS mount and environment variables
6. Launch tasks with `--enable-execute-command`

The container runs `sleep infinity` by default. On termination, it syncs `/home/sre` to S3 if configured.

## Image Details

- **Base**: Fedora 43
- **AWS CLI**: v2.32.16+ (official), v2.27.0 (Fedora RPM)
- **OpenShift CLI**: 4.14.x, 4.15.x, 4.16.x, 4.17.x, 4.18.x, 4.19.x, 4.20.x
- **Claude Code**: 2.0.69 (native installer), auto-updates disabled
- **Additional tools**: util-linux (includes su for user switching)

## Architecture Support

The manifest list automatically selects the appropriate image for your platform:
- `linux/amd64` - x86_64 architecture
- `linux/arm64` - ARM64/aarch64 architecture (Graviton)

## Testing

### LocalStack Integration Tests

Test AWS functionality locally before production deployment:

```bash
# Start LocalStack (requires LocalStack Pro token)
make localstack-up

# Run fast tests (~2-3 min)
make test-localstack-fast

# Run full test suite (~5-7 min)
make test-localstack

# Stop LocalStack
make localstack-down
```

See [`tests/localstack/README.md`](tests/localstack/README.md) for complete documentation.

### Lambda Unit Tests

```bash
cd lambda/create-investigation/
make test
```

## CI/CD

GitHub Actions workflow runs on PRs and pushes to main:

- **LocalStack Integration Tests** - AWS service validation
- **Lambda Unit Tests** - Handler function validation with moto

**Required GitHub Secret**: `LOCALSTACK_AUTH_TOKEN` (LocalStack Pro license)

See [`.github/workflows/localstack-tests.yml`](.github/workflows/localstack-tests.yml).
