# ROSA Boundary

Multi-architecture container and CLI for managing ephemeral SRE investigations on AWS Fargate with OIDC-authenticated access control.

## Features

- **Go CLI**: `rosa-boundary` — authenticate, start, join, list, and stop investigations
- **AWS CLI**: Both Fedora RPM and official AWS CLI v2 with alternatives support
- **OpenShift CLI**: Versions 4.14 through 4.20 from stable channels
- **Claude Code**: AI-powered CLI assistant with Amazon Bedrock integration
- **Dynamic Version Selection**: Switch tool versions via environment variables at runtime
- **ECS Exec Ready**: Designed for AWS Fargate with ECS Exec support
- **Multi-architecture**: Supports both x86_64 (amd64) and ARM64 (aarch64)
- **OIDC Authentication**: Keycloak integration with Lambda-based authorization
- **Tag-Based Isolation**: Shared SRE role with task-level ABAC access control

## Getting Started

### Prerequisites

- Go 1.23+ (to build the CLI from source)
- Terraform (infrastructure deployment)
- Keycloak with OIDC configured (see [OIDC Identity Requirements](#oidc-identity-requirements))
- [`session-manager-plugin`](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) — required for `join-task` and `start-task --connect`

The `session-manager-plugin` is an AWS-provided binary that handles the WebSocket session protocol used by ECS Exec. The `rosa-boundary` CLI calls the ECS `ExecuteCommand` API to obtain session credentials, then hands off to this plugin to establish the interactive session. It must be installed separately on each machine running the CLI.

**macOS:**
```bash
brew install --cask session-manager-plugin
```

**Linux (x86_64):**
```bash
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o /tmp/session-manager-plugin.rpm
sudo yum install -y /tmp/session-manager-plugin.rpm
```

**Verify:**
```bash
session-manager-plugin --version
```

See the [AWS documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) for other platforms and package managers.

### Deploy Infrastructure

1. Copy the example environment file and fill in values:

   ```bash
   cp .env.example .env
   ```

2. Required Terraform variables (no defaults):

   | Variable | Description |
   |---|---|
   | `container_image` | Container image URI |
   | `vpc_id` | VPC for Fargate tasks |
   | `subnet_ids` | 2+ subnets in the same VPC |
   | `keycloak_issuer_url` | OIDC issuer URL (e.g., `https://keycloak.example.com/realms/sre-ops`) |
   | `keycloak_thumbprint` | SHA1 thumbprint of the Keycloak TLS certificate |

3. Deploy:

   ```bash
   cd deploy/regional && terraform init && terraform apply
   ```

See [`deploy/regional/README.md`](deploy/regional/README.md) for the complete deployment guide.

### OIDC Identity Requirements

Keycloak must issue tokens with these claims:

| Claim | Purpose |
|---|---|
| `sub` | Stored as `oidc_sub` tag (audit trail) |
| `preferred_username` | Used as `username` tag (ABAC key) |
| `email` | Logged |
| `groups` | Must contain `sre-team` |
| `aud` | Must match `aws-sre-access` |
| `https://aws.amazon.com/tags` | Session tags with `principal_tags.username` for ABAC |

Required Keycloak mappers:
- Groups (flat names), email, audience (`aws-sre-access`)
- AWS session tags: map `preferred_username` → `principal_tags.username`

Client settings: public client, standard flow + PKCE, redirect URI `http://localhost:8400/callback`.

See [`docs/configuration/keycloak-realm-setup.md`](docs/configuration/keycloak-realm-setup.md) for step-by-step setup.

### Install and Use the CLI

```bash
make build-cli && make install-cli
```

Create `~/.rosa-boundary/config.yaml` with the values specific to your deployment:

```yaml
keycloak_url: https://keycloak.example.com
lambda_function_name: rosa-boundary-dev-create-investigation
invoker_role_arn: arn:aws:iam::123456789012:role/rosa-boundary-dev-lambda-invoker
```

Core workflow:

```bash
# Start an investigation (authenticates, creates task, waits for RUNNING)
rosa-boundary start-task --cluster-id my-cluster --connect

# List running tasks
rosa-boundary list-tasks

# Connect to an existing task
rosa-boundary join-task <task-id>

# Stop a task (triggers S3 sync)
rosa-boundary stop-task <task-id>
```

## Repository Structure

```
rosa-boundary/
├── .env.example           # Environment configuration template (copy to .env)
├── Containerfile          # Multi-arch container build
├── entrypoint.sh          # Runtime initialization and signal handling
├── skel/sre/.claude/      # Skeleton Claude Code config for container users
├── cmd/rosa-boundary/     # CLI entrypoint
├── internal/
│   ├── auth/              # PKCE/OIDC authentication
│   ├── aws/               # ECS and STS clients
│   ├── cmd/               # Cobra subcommands
│   ├── config/            # Viper-based configuration
│   ├── lambda/            # Lambda invocation client
│   └── output/            # Text/JSON output helpers
├── deploy/
│   ├── regional/          # Terraform: ECS, EFS, S3, Lambda, OIDC
│   │   ├── *.tf          # Infrastructure definitions
│   │   ├── examples/     # Manual lifecycle scripts
│   │   └── README.md     # Deployment guide
│   └── keycloak/         # Kustomize: Keycloak realm and clients
├── lambda/
│   ├── create-investigation/  # OIDC-authenticated investigation creation
│   │   ├── handler.py    # Group auth, role creation, task tagging
│   │   └── Makefile      # Build Lambda package
│   └── reap-tasks/            # Periodic task timeout enforcement
│       └── handler.py    # Deadline-based task termination
├── tests/
│   └── localstack/       # LocalStack integration tests
│       ├── compose.yml   # LocalStack Pro + mock OIDC
│       └── integration/  # AWS service tests
├── docs/                 # Architecture and implementation docs
└── .github/workflows/    # CI/CD automation
```

## CLI Reference

### Subcommands

| Command | Description |
|---|---|
| `login` | Authenticate with Keycloak and cache the OIDC token |
| `start-task` | Create an investigation and start an ECS task |
| `join-task <task-id>` | Connect to a running ECS task via ECS Exec |
| `list-tasks` | List ECS tasks in the cluster |
| `stop-task <task-id>` | Stop a running ECS task |
| `version` | Print the rosa-boundary version |

### Notable Flags

**`start-task`**:
- `--cluster-id` — cluster ID (defaults to `cluster_name` from config)
- `--investigation-id` — auto-generated if omitted (e.g., `swift-dance-party`)
- `--oc-version` — OpenShift CLI version (default: `4.20`)
- `--task-timeout` — seconds before reaper kills the task (default: `3600`)
- `--connect` — automatically join the task after it reaches RUNNING
- `--no-wait` — return immediately without waiting for RUNNING
- `--force-login` — force fresh OIDC authentication
- `--output text|json`

**`join-task`**: `--container` (default: `rosa-boundary`), `--command` (default: `/bin/bash`), `--no-wait`

**`list-tasks`**: `--status RUNNING|STOPPED|all` (default: `RUNNING`), `--output text|json`

**`stop-task`**: `--reason`, `--wait`

**`login`**: `--force`

### Global Flags

```
--verbose, -v           Enable verbose/debug output
--keycloak-url          Keycloak base URL
--realm                 Keycloak realm (default: sre-ops)
--client-id             OIDC client ID (default: aws-sre-access)
--region                AWS region (default: us-east-2)
--cluster               ECS cluster name (default: rosa-boundary-dev)
--lambda-function-name  Lambda function name or ARN
--invoker-role-arn      Lambda invoker role ARN
--role-arn              SRE role ARN (overrides Lambda response)
--lambda-url            Lambda function URL (HTTP mode)
```

### Configuration Precedence

Flags > environment variables (`ROSA_BOUNDARY_*`) > `~/.rosa-boundary/config.yaml` > defaults

Environment variable examples: `ROSA_BOUNDARY_KEYCLOAK_URL`, `ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME`, `ROSA_BOUNDARY_INVOKER_ROLE_ARN`.

## Building

### Container

```bash
# Build both architectures and create manifest
make all

# Build single architecture
make build-amd64
make build-arm64

# Create manifest list from existing builds
make manifest

# Remove all images and manifests
make clean
```

### CLI

```bash
# Build the rosa-boundary binary to ./bin/
make build-cli

# Install to $GOBIN
make install-cli

# Run Go unit tests
make test-cli
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
