# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

Multi-architecture container for AWS Fargate that provides tools for managing AWS and OpenShift (ROSA) clusters. Designed for ephemeral SRE use with ECS Exec access as the `sre` user. The entrypoint script supports dynamic version selection via environment variables, signal handling for graceful shutdown with S3 backup, and defaults to `sleep infinity`.

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
  outputs.tf           - Output values (13 outputs)
  s3.tf                - S3 bucket with WORM compliance
  iam.tf               - Task execution and task roles
  efs.tf               - EFS filesystem with mount targets
  ecs.tf               - ECS cluster, task definition, security groups
  examples/            - Lifecycle management scripts
    create_investigation.sh - Create access point + task definition
    launch_task.sh     - Launch Fargate task
    join_task.sh       - Connect via ECS Exec
    stop_task.sh       - Stop task (triggers S3 sync)
    close_investigation.sh  - Cleanup access point + task definition
    build-task-def.jq  - jq script for task definition transformation
  get-vpc-info.sh      - Helper to discover VPC/subnets
  .gitignore           - Excludes tfvars, state, .terraform/
```

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

### Lifecycle Script Workflow

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

### Key Files for Deployment

- `deploy/regional/terraform.tfvars.example` - Template configuration
- `deploy/regional/README.md` - Complete deployment documentation
- `deploy/regional/examples/*.sh` - Investigation lifecycle scripts
