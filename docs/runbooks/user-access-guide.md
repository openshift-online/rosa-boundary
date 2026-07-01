# User Access Guide

## Overview

This guide provides step-by-step instructions for SRE users to create investigations and access containers using OIDC authentication (via Red Hat SSO) and AWS ECS Exec.

## Prerequisites

Before you can access investigation containers, you need:

1. ✅ RHSSO account with `sre-team` group membership
2. ✅ AWS CLI installed and configured
3. ✅ `rosa-boundary` CLI installed (`make build-cli && make install-cli`)
4. ✅ `session-manager-plugin` installed and in `PATH`

## One-Time Setup

### 1. Install AWS CLI

**macOS:**
```bash
brew install awscli
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Verify installation:**
```bash
aws --version
```

### 2. Install session-manager-plugin

**macOS:**
```bash
brew install --cask session-manager-plugin
```

**Linux:**
```bash
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o "session-manager-plugin.rpm"
sudo rpm -U session-manager-plugin.rpm
```

### 3. Install rosa-boundary CLI

```bash
# Build and install
make build-cli && make install-cli

# Verify
rosa-boundary version
```

### 4. Configure rosa-boundary

```bash
rosa-boundary configure
```

You will be prompted for:

| Field | Example |
|---|---|
| OIDC issuer URL | `https://sso.example.com/auth/realms/sre-ops` |
| OIDC client ID | `aws-sre-access` |
| Lambda function name | `rosa-boundary-dev-create-investigation` |
| Invoker role ARN | `arn:aws:iam::123456789012:role/rosa-boundary-dev-lambda-invoker` |
| SRE role ARN | (leave blank to use Lambda response) |
| AWS region | `us-east-2` |
| ECS cluster name | `rosa-boundary-dev` |

Or set via environment variables:
```bash
export ROSA_BOUNDARY_OIDC_ISSUER_URL="https://sso.example.com/auth/realms/sre-ops"
export ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME="rosa-boundary-dev-create-investigation"
export ROSA_BOUNDARY_INVOKER_ROLE_ARN="arn:aws:iam::123456789012:role/rosa-boundary-dev-lambda-invoker"
export ROSA_BOUNDARY_AWS_REGION="us-east-2"
```

## Daily Usage

### Step 1: Create Investigation and Start Task

```bash
# Start an investigation (opens browser for OIDC login, creates task, waits for RUNNING)
rosa-boundary start-task --cluster-id rosa-prod-01

# With a specific investigation ID
rosa-boundary start-task --cluster-id rosa-prod-01 --investigation-id inv-123

# Start and immediately connect
rosa-boundary start-task --cluster-id rosa-prod-01 --connect
```

This will:
1. Open browser for OIDC authentication (PKCE flow) against RHSSO
2. Assume the Lambda invoker role via `AssumeRoleWithWebIdentity`
3. Invoke Lambda with the OIDC token (validates group membership)
4. Lambda creates EFS access point and launches ECS task
5. CLI assumes the shared ABAC SRE role (session-tagged with your username)
6. Wait for task to reach RUNNING state
7. Display task ID and connection command

### Step 2: Connect to Investigation Container

```bash
# Connect to a running task
rosa-boundary join-task <task-id>

# Or use the command printed by start-task
```

### Step 3: Work in the Container

Once connected, you're in an interactive shell as the `sre` user:

```bash
# Check environment
echo $CLUSTER_ID
echo $INVESTIGATION_ID
echo $OC_VERSION

# Your home directory is persistent (EFS)
pwd
# /home/sre

# List OpenShift clusters (if configured)
oc config get-contexts

# Run AWS CLI
aws sts get-caller-identity

# Use Claude Code
claude
```

### Step 4: Exit Cleanly

```bash
# Exit shell
exit

# Or press Ctrl-D
```

The container's entrypoint will automatically sync `/home/sre` to S3 on exit.

## Working with Multiple Investigations

### List your investigations

```bash
rosa-boundary list-tasks
```

### Terminal multiplexing

Use tmux or screen to manage multiple connections:

```bash
# Start tmux
tmux

# Create windows for each investigation
Ctrl-B C  # New window
rosa-boundary join-task <task1-id>

Ctrl-B C  # Another window
rosa-boundary join-task <task2-id>

# Switch between windows
Ctrl-B N  # Next window
Ctrl-B P  # Previous window
```

## Troubleshooting

### "Authentication failed" in OIDC flow

1. Check RHSSO is accessible:
   ```bash
   curl -I "${ROSA_BOUNDARY_OIDC_ISSUER_URL}/.well-known/openid-configuration"
   ```

2. Verify your credentials:
   - Log in to the RHSSO portal and confirm your account is active

3. Check group membership:
   - Contact the identity team to verify you're in the `sre-team` group

### "AccessDenied" from Lambda

1. Verify group membership — Lambda requires `sre-team` group
2. Verify your OIDC issuer URL is correct
3. Force fresh authentication: `rosa-boundary login --force`

### "Task not found" or "Task not running"

1. Check if task is still running:
   ```bash
   rosa-boundary list-tasks
   ```

2. If task stopped, create new investigation with `rosa-boundary start-task`

### "AccessDenied" when executing ECS Exec

Your IAM role can only access tasks tagged with your OIDC `sub` claim. Verify:

```bash
# Check task tags
aws ecs describe-tasks \
  --cluster rosa-boundary-dev \
  --tasks <task-arn> \
  --query 'tasks[0].tags'

# Check assumed role
aws sts get-caller-identity
```

If the `username` tag doesn't match your role's permissions, you don't own this task.

### "ECS Exec is not enabled for this task"

The task was launched without `--enable-execute-command`. This should not happen with properly created investigations via Lambda. Contact the administrator.

### Token cache issues

```bash
# Force fresh OIDC token
rosa-boundary login --force

# Clear token cache manually
rm -rf ~/.cache/rosa-boundary/
```

## Security Best Practices

1. **Lock your workstation** when stepping away (sessions remain active)
2. **Exit sessions** when done (triggers audit sync to S3)
3. **Change passwords** via RHSSO regularly
4. **Enable MFA** in RHSSO for your account
5. **Review CloudWatch Logs** periodically (`/ecs/rosa-boundary-*/ssm-sessions`)
6. **Never share credentials** or OIDC tokens
7. **Use tag-based isolation** - you can only access your own tasks

## Getting Help

- **RHSSO login issues**: Contact the identity team
- **Lambda invocation issues**: Contact AWS administrators
- **AWS permission issues**: Check IAM role policies for tag-based access
- **Container/tool issues**: Check container documentation in `/CLAUDE.md`

## Next Steps

- [Investigation Workflow](investigation-workflow.md) - Full investigation lifecycle from admin perspective
- [Troubleshooting](troubleshooting.md) - Detailed troubleshooting guide
