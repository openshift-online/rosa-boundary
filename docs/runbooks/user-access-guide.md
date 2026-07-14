# User Access Guide

## Overview

This guide provides step-by-step instructions for SRE users to create investigations and access containers using the `rosa-boundary` CLI with Keycloak OIDC authentication and AWS ECS Exec.

## Prerequisites

Before you can access investigation containers, you need:

1. ✅ Keycloak account with `sre-team` group membership
2. ✅ AWS CLI installed and configured
3. ✅ `session-manager-plugin` installed (required for `join-task`)
4. ✅ `rosa-boundary` CLI built or installed

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

**Linux (rpm):**
```bash
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o session-manager-plugin.rpm
sudo dnf install -y session-manager-plugin.rpm
```

**Verify:**
```bash
session-manager-plugin --version
```

### 3. Build the rosa-boundary CLI

```bash
# From the repo root
make build-cli

# Or install to ~/go/bin
make install-cli
```

### 4. Configure CLI

Run the interactive configurator or write `~/.config/rosa-boundary/config.yaml` directly:

```bash
./bin/rosa-boundary configure
```

Key fields (get values from your administrator):

```yaml
lambda_function_name: rosa-boundary-dev-create-investigation
invoker_role_arn: arn:aws:iam::<account-id>:role/rosa-boundary-dev-lambda-invoker
sre_role_arn: arn:aws:iam::<account-id>:role/rosa-boundary-dev-sre-shared
ecs_cluster_name: rosa-boundary-dev
aws_region: us-east-2
```

## Daily Usage

### Step 1: Authenticate

```bash
./bin/rosa-boundary login \
  --keycloak-url https://auth.redhat.com/auth \
  --realm EmployeeIDP \
  --client-id rosa-boundary-sre
```

This opens a browser for Keycloak PKCE authentication and caches the token at
`~/.cache/rosa-boundary/token.json`. The token is reused for subsequent commands.

### Step 2: Start Investigation

```bash
./bin/rosa-boundary start-task \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id>
```

This will:
1. Assume the invoker role via STS
2. Invoke the create-investigation Lambda with your cached OIDC token
3. Lambda validates group membership (`sre-team`)
4. Lambda creates an EFS access point and per-investigation task definition
5. Lambda launches the ECS task tagged with your username
6. CLI prints the task ID — save it for the next steps

### Step 3: Connect to Investigation Container

```bash
# List running tasks to find your task ID
./bin/rosa-boundary list-tasks

# Connect
./bin/rosa-boundary join-task <task-id>
```

### Step 4: Work in the Container

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

### Step 5: Exit Cleanly

```bash
# Exit shell
exit

# Or press Ctrl-D
```

The container's entrypoint automatically syncs `/home/sre` to S3 on exit.

### Step 6: Stop Task (Optional — if not already exited)

```bash
./bin/rosa-boundary stop-task <task-id>
```

Sends SIGTERM to the task, triggering the S3 sync and graceful shutdown.

## Working with Multiple Investigations

### Terminal multiplexing

Use tmux or screen to manage multiple connections:

```bash
# Start tmux
tmux

# Create windows for each investigation
Ctrl-B C  # New window
./bin/rosa-boundary join-task <task1-id>

Ctrl-B C  # Another window
./bin/rosa-boundary join-task <task2-id>

# Switch between windows
Ctrl-B N  # Next window
Ctrl-B P  # Previous window
```

### List your investigations

```bash
./bin/rosa-boundary list-tasks --ecs-cluster rosa-boundary-dev

# Or via AWS CLI for tag details
aws ecs describe-tasks \
  --cluster rosa-boundary-dev \
  --tasks <task-arn> \
  --query 'tasks[0].{taskArn:taskArn,lastStatus:lastStatus,tags:tags}'
```

## Troubleshooting

### "Authentication failed" in OIDC flow

1. Clear the token cache and re-authenticate:
   ```bash
   rm ~/.cache/rosa-boundary/token.json
   ./bin/rosa-boundary login ...
   ```

2. Verify your Keycloak credentials by logging in at the Keycloak URL

3. Check group membership — Lambda requires `sre-team`

### "AccessDenied" from Lambda

1. Verify group membership (`sre-team`) in Keycloak
2. Confirm the invoker role ARN in your config matches what the administrator provided
3. Token may be expired — clear cache and re-login (see above)

### "Task not found" or "Task not running"

1. Check task status:
   ```bash
   ./bin/rosa-boundary list-tasks
   ```

2. If the task stopped, start a new investigation:
   ```bash
   ./bin/rosa-boundary start-task --cluster-id <id> --investigation-id <id>
   ```

### "AccessDenied" when executing ECS Exec

Your session is ABAC-scoped — you can only exec into tasks tagged with your username.
Verify:

```bash
# Check task tags
aws ecs describe-tasks \
  --cluster rosa-boundary-dev \
  --tasks <task-arn> \
  --include TAGS \
  --query 'tasks[0].tags'

# Check assumed role
aws sts get-caller-identity
```

If the `username` tag doesn't match your session tag, you don't own this task.

### "ECS Exec is not enabled for this task"

The task was launched without `--enable-execute-command`. This should not happen
with properly created investigations via the Lambda. Contact the administrator.

### session-manager-plugin: connection drops immediately

The container exec agent may not have finished opening its WebSocket. The CLI
waits 8 seconds by default. If it still fails, verify the task has ECS Exec
enabled:

```bash
aws ecs describe-tasks \
  --cluster rosa-boundary-dev \
  --tasks <task-arn> \
  --query 'tasks[0].enableExecuteCommand'
```

## Security Best Practices

1. **Lock your workstation** when stepping away (sessions remain active)
2. **Exit sessions** when done (triggers audit sync to S3)
3. **Rotate passwords** in Keycloak regularly
4. **Enable MFA** in Keycloak for your account
5. **Review CloudWatch Logs** periodically (`/ecs/rosa-boundary-*/ssm-sessions`)
6. **Never share credentials** or OIDC tokens
7. **Use tag-based isolation** — you can only access your own tasks

## Getting Help

- **Keycloak login issues**: Contact identity team
- **Lambda invocation issues**: Contact AWS administrators
- **AWS permission issues**: Check IAM role policies for tag-based access
- **Container/tool issues**: Check container documentation in `/CLAUDE.md`

## Next Steps

- [Investigation Workflow](investigation-workflow.md) - Full investigation lifecycle
- [Troubleshooting](troubleshooting.md) - Detailed troubleshooting guide
