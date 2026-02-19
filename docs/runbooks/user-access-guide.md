# User Access Guide

## Overview

This guide provides step-by-step instructions for SRE users to create investigations and access containers using Keycloak OIDC authentication and AWS ECS Exec.

## Prerequisites

Before you can access investigation containers, you need:

1. ✅ Keycloak account with `sre-team` group membership
2. ✅ AWS CLI installed and configured
3. ✅ Authentication scripts from `tools/sre-auth/`
4. ✅ Lambda function URL from your administrator

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

### 2. Install Authentication Scripts

```bash
# Clone the repository or download scripts
git clone https://github.com/cuppett/rosa-boundary.git
cd rosa-boundary/tools/sre-auth

# Or download individually
mkdir -p ~/rosa-boundary-tools
cd ~/rosa-boundary-tools
curl -O <repo-url>/tools/sre-auth/get-oidc-token.sh
curl -O <repo-url>/tools/sre-auth/assume-role.sh

# Make executable
chmod +x *.sh
```

### 3. Configure Environment

Create `~/.sre-auth/config` or set environment variables:

```bash
export KEYCLOAK_ISSUER_URL="https://keycloak-keycloak.apps.rosa.dev.dyee.p3.openshiftapps.com/realms/rosa-boundary"
export OIDC_CLIENT_ID="aws-sre-access"
export AWS_REGION="us-east-2"
```

## Daily Usage

### Step 1: Create Investigation

Use the Lambda-based creation script:

```bash
cd tools/sre-auth

# Create investigation for cluster rosa-prod-01, investigation inv-123, OC version 4.20
./create-investigation-lambda.sh rosa-prod-01 inv-123 4.20
```

This will:
1. Get OIDC token from Keycloak (opens browser)
2. Invoke Lambda function with token
3. Lambda validates group membership
4. Lambda creates IAM role and ECS task
5. Script assumes the returned role
6. Script waits for task to reach RUNNING state
7. Displays ECS Exec connection command

### Step 2: Connect to Investigation Container

After the investigation is created, use the provided command:

```bash
# Example output from create-investigation-lambda.sh:
#
# Task is now RUNNING!
# To connect, run:
# aws ecs execute-command \
#   --cluster rosa-boundary-dev \
#   --task arn:aws:ecs:us-east-2:123456789012:task/rosa-boundary-dev/abc123... \
#   --container rosa-boundary \
#   --interactive \
#   --command "/bin/bash"
```

Or use the manual scripts in `deploy/regional/examples/`:

```bash
cd deploy/regional/examples

# Get task ID from create-investigation-lambda.sh output
TASK_ID="abc123def456"

# Connect
./join_task.sh $TASK_ID
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

### Terminal multiplexing

Use tmux or screen to manage multiple connections:

```bash
# Start tmux
tmux

# Create windows for each investigation
Ctrl-B C  # New window
aws ecs execute-command --cluster rosa-boundary-dev --task <task1-arn> ...

Ctrl-B C  # Another window
aws ecs execute-command --cluster rosa-boundary-dev --task <task2-arn> ...

# Switch between windows
Ctrl-B N  # Next window
Ctrl-B P  # Previous window
```

### List your investigations

```bash
# List tasks tagged with your OIDC sub claim
aws ecs list-tasks --cluster rosa-boundary-dev

# Describe tasks to see details
aws ecs describe-tasks \
  --cluster rosa-boundary-dev \
  --tasks <task-arn> \
  --query 'tasks[0].{taskArn:taskArn,lastStatus:lastStatus,tags:tags}'
```

## Troubleshooting

### "Authentication failed" in OIDC flow

1. Check Keycloak is accessible:
   ```bash
   curl -I https://keycloak-keycloak.apps.rosa.dev.dyee.p3.openshiftapps.com/realms/rosa-boundary/.well-known/openid-configuration
   ```

2. Verify your credentials:
   - Visit: https://keycloak-keycloak.apps.rosa.dev.dyee.p3.openshiftapps.com
   - Log in with your credentials

3. Check group membership:
   - In Keycloak admin console or ask administrator
   - Verify you're in `sre-team` group

### "AccessDenied" from Lambda

1. Verify group membership - Lambda requires `sre-team` group
2. Check Lambda function URL is correct
3. Verify OIDC token is valid (try `./get-oidc-token.sh --force`)

### "Task not found" or "Task not running"

1. Check if task is still running:
   ```bash
   aws ecs describe-tasks \
     --cluster rosa-boundary-dev \
     --tasks <task-arn> \
     --query 'tasks[0].lastStatus'
   ```

2. If task stopped, create new investigation with `create-investigation-lambda.sh`

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
cd tools/sre-auth
./get-oidc-token.sh --force

# Clear token cache manually
rm -f ~/.sre-auth/id-token.cache
```

## Security Best Practices

1. **Lock your workstation** when stepping away (sessions remain active)
2. **Exit sessions** when done (triggers audit sync to S3)
3. **Rotate passwords** in Keycloak regularly
4. **Enable MFA** in Keycloak for your account
5. **Review CloudWatch Logs** periodically (`/ecs/rosa-boundary-*/ssm-sessions`)
6. **Never share credentials** or OIDC tokens
7. **Use tag-based isolation** - you can only access your own tasks

## Getting Help

- **Keycloak login issues**: Contact identity team
- **Lambda invocation issues**: Contact AWS administrators
- **AWS permission issues**: Check IAM role policies for tag-based access
- **Container/tool issues**: Check container documentation in `/CLAUDE.md`

## Next Steps

- [Investigation Workflow](investigation-workflow.md) - Full investigation lifecycle from admin perspective
- [Troubleshooting](troubleshooting.md) - Detailed troubleshooting guide
