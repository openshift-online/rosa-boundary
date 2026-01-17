# User Access Guide

## Overview

This guide provides step-by-step instructions for SRE users to access incident containers via HCP Boundary and Keycloak OIDC authentication.

## Prerequisites

Before you can access incident containers, you need:

1. ✅ Keycloak account with group membership (sre-operators or sre-admins)
2. ✅ AWS IAM user or federated identity with ECS Exec permissions
3. ✅ Boundary CLI installed on your workstation
4. ✅ AWS CLI installed and configured
5. ✅ Integration scripts installed

## One-Time Setup

### 1. Install Boundary CLI

**macOS:**
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/boundary
```

**Linux:**
```bash
wget https://releases.hashicorp.com/boundary/0.15.0/boundary_0.15.0_linux_amd64.zip
unzip boundary_0.15.0_linux_amd64.zip
sudo mv boundary /usr/local/bin/
```

**Verify installation:**
```bash
boundary version
```

### 2. Configure Boundary

Create `~/.boundary/config.hcl`:

```hcl
addr = "https://<your-cluster>.boundary.hashicorp.cloud"
```

Or set environment variable:
```bash
export BOUNDARY_ADDR="https://<your-cluster>.boundary.hashicorp.cloud"
```

### 3. Install Integration Scripts

```bash
# Create scripts directory
mkdir -p ~/.boundary

# Download scripts
curl -o ~/.boundary/ecs-exec.sh \
  https://raw.githubusercontent.com/cuppett/rosa-boundary/main/deploy/boundary/scripts/ecs-exec.sh

curl -o ~/.boundary/boundary-ecs-connect.sh \
  https://raw.githubusercontent.com/cuppett/rosa-boundary/main/deploy/boundary/scripts/boundary-ecs-connect.sh

# Make executable
chmod +x ~/.boundary/*.sh
```

### 4. Configure AWS Credentials

**Option A: AWS CLI Profile**
```bash
aws configure --profile rosa-boundary
# Enter Access Key ID, Secret Access Key, Region (us-east-2)
```

**Option B: AWS SSO**
```bash
aws configure sso
# Follow prompts to set up SSO profile
```

**Verify credentials:**
```bash
aws sts get-caller-identity --profile rosa-boundary
```

## Daily Usage

### Step 1: Authenticate to Boundary

```bash
# Authenticate via Keycloak OIDC
boundary authenticate oidc

# This will:
# 1. Open your browser to Keycloak
# 2. Prompt for username/password
# 3. Redirect back to Boundary
# 4. Store session token in ~/.boundary/token
```

**Alternative: Specify auth method ID**
```bash
boundary authenticate oidc -auth-method-id amoidc_<id>
```

### Step 2: List Available Incidents

```bash
# List all targets you have access to
boundary targets list -scope-id <project-scope-id>

# Filter by incident number
boundary targets list -scope-id <project-scope-id> -filter '"123" in "/item/name"'

# Get target details
boundary targets read -id ttcp_<target-id>
```

### Step 3: Connect to Incident Container

**Method A: Using boundary-ecs-connect.sh (Recommended)**

```bash
# Simple connection using target ID
~/.boundary/boundary-ecs-connect.sh ttcp_<target-id>
```

**Method B: Manual connection**

```bash
# Get target metadata
CLUSTER=$(boundary targets read -id ttcp_<target-id> -format json | jq -r '.item.attributes.ecs_cluster')
TASK_ARN=$(boundary targets read -id ttcp_<target-id> -format json | jq -r '.item.attributes.ecs_task_arn')

# Connect with -exec
boundary connect \
  -target-id ttcp_<target-id> \
  -exec ~/.boundary/ecs-exec.sh -- \
  "$CLUSTER" \
  "$TASK_ARN" \
  rosa-boundary
```

### Step 4: Work in the Container

Once connected, you're in an interactive shell as the `sre` user:

```bash
# Check environment
echo $CLUSTER_ID
echo $INCIDENT_NUMBER
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

The container's entrypoint will automatically sync `/home/sre` to S3 on exit.

## Session Management

### View active sessions

```bash
# List your active sessions
boundary sessions list -scope-id <project-scope-id>

# Get session details
boundary sessions read -id s_<session-id>
```

### Cancel a session

```bash
# Cancel your own session
boundary sessions cancel -id s_<session-id>

# Admins can cancel any session
boundary sessions cancel -id s_<session-id>
```

## Working with Multiple Incidents

### Terminal multiplexing

Use tmux or screen to manage multiple connections:

```bash
# Start tmux
tmux

# Create windows for each incident
Ctrl-B C  # New window
~/.boundary/boundary-ecs-connect.sh ttcp_incident1

Ctrl-B C  # Another window
~/.boundary/boundary-ecs-connect.sh ttcp_incident2

# Switch between windows
Ctrl-B N  # Next window
Ctrl-B P  # Previous window
```

### Session naming

Add aliases for common incidents:

```bash
# In ~/.bashrc
alias incident123='~/.boundary/boundary-ecs-connect.sh ttcp_abc123xyz'
alias incident124='~/.boundary/boundary-ecs-connect.sh ttcp_def456uvw'
```

## Troubleshooting

### "Authentication failed"

1. Check Boundary session is valid:
   ```bash
   boundary authenticate oidc
   ```

2. Verify Keycloak credentials work:
   - Visit: https://keycloak-keycloak.apps.rosa.dev.dyee.p3.openshiftapps.com
   - Log in with your credentials

3. Check group membership:
   - In Keycloak admin console
   - Verify you're in `sre-operators` or `sre-admins` group

### "Permission denied" or "Not authorized"

1. Verify Boundary grants:
   ```bash
   boundary targets read -id ttcp_<target-id>
   ```

   If you get "not found", you don't have access to this target.

2. Contact your Boundary administrator to verify role assignments

### "Task not found" or "Task not running"

1. Verify task ARN in target metadata:
   ```bash
   boundary targets read -id ttcp_<target-id> -format json | jq '.item.attributes'
   ```

2. Check if task is still running:
   ```bash
   aws ecs describe-tasks \
     --cluster rosa-boundary-dev \
     --tasks <task-arn> \
     --query 'tasks[0].lastStatus'
   ```

3. If task stopped, contact incident owner to launch new task

### "WebIdentityErr: failed to retrieve credentials"

Your AWS credentials expired. Refresh them:

```bash
# For AWS CLI profiles
aws sso login --profile rosa-boundary

# For IAM users with MFA
aws sts get-session-token --serial-number arn:aws:iam::xxx:mfa/username
```

### "ECS Exec is not enabled for this task"

The task was launched without `--enable-execute-command`. This should not happen with properly created incidents. Contact the administrator.

## Security Best Practices

1. **Lock your workstation** when stepping away (sessions remain active)
2. **Exit sessions** when done (triggers audit sync to S3)
3. **Rotate passwords** in Keycloak regularly
4. **Enable MFA** in Keycloak for your account
5. **Review session logs** in Boundary console periodically
6. **Never share credentials** or session tokens

## Getting Help

- **Boundary authentication issues**: Contact Boundary administrators
- **Keycloak login issues**: Contact identity team
- **AWS permission issues**: Contact AWS administrators
- **Container/tool issues**: Check container documentation in `/CLAUDE.md`

## Next Steps

- [Incident Workflow](incident-workflow.md) - Full incident lifecycle from admin perspective
- [Troubleshooting](troubleshooting.md) - Detailed troubleshooting guide
