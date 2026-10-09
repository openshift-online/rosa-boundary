# User Access Guide

## Overview

This guide provides step-by-step instructions for SRE users to create investigations and access containers using the `rosa-boundary` CLI with Keycloak OIDC authentication and AWS ECS Exec.
Replace all `<...>` placeholders with approved values before running commands;
angle brackets in a shell command are redirection operators, not literal syntax.

## Getting Access

The create-investigation Lambda checks membership in the deployment's `required_groups`. IAM role trust can impose additional OIDC claim or session-tag requirements *before* Lambda is invoked. Ask the deployment operator which access requirements apply.

### Red Hat EmployeeIDP (staging and shared deployments)

EmployeeIDP tokens carry group memberships as LDAP-synced realm roles under `realm_access.roles`. No Keycloak admin action is needed — membership is managed upstream:

1. **Identify the required group** — ask the deployment operator which group(s) are configured in `required_groups` (e.g., `ai-sd-sre`).
2. **Request membership** — group membership is managed via LDAP. Depending on the group, this is done through either:
   - **[app-interface](https://gitlab.cee.redhat.com/service/app-interface)** — for groups defined in app-interface role files (e.g., [sd-sre/roles/sre.yml](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/data/teams/sd-sre/roles/sre.yml)). Submit an MR adding your rover ID to the appropriate role.
   - **[Rover](https://rover.redhat.com)** — for standalone LDAP groups not managed through app-interface. Request group membership directly through rover.
3. **Verify** — after membership propagates, authenticate and try an approved investigation. An STS denial may indicate a trust/claim problem before Lambda; a Lambda 403 may indicate group or ABAC-claim authorization failure. Ask the operator to identify the failing stage.

### Self-managed Keycloak (developer deployments)

For deployments using a self-hosted Keycloak instance, groups are created and assigned manually by the Keycloak administrator. See [Keycloak Realm Setup](../configuration/keycloak-realm-setup.md) for group and user configuration.

## Prerequisites

Before you can access investigation containers, you need:

1. ✅ Membership in a `required_groups` group (see [Getting Access](#getting-access) above)
2. ✅ `session-manager-plugin` installed (required for `join-task`)
3. ✅ `rosa-boundary` CLI built or installed

The Boundary CLI uses OIDC to obtain AWS credentials; existing AWS credentials and the AWS CLI are **not** prerequisites for normal CLI use. The separate audit-inspection commands in the [investigation workflow](investigation-workflow.md) require an AWS CLI and an appropriately authorized audit-reader identity.

## One-Time Setup

### 1. Install session-manager-plugin

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

### 2. Build the rosa-boundary CLI

```bash
# From the repo root
make build-cli

# Or install into the configured Go binary directory
make install-cli
```

### 3. Configure CLI

Run auto-discovery with the deployment's AWS account ID, region, project
(base name without the stage suffix), and environment. For example, a deployment
named `rosa-boundary-stage` uses project `rosa-boundary` and environment `stage`:

```bash
./bin/rosa-boundary configure \
  --account-id <account-id> \
  --region <region> \
  --project rosa-boundary \
  --environment stage
```

Auto-discovery logs in to Red Hat SSO using the default `EmployeeIDP` realm and
`rosa-boundary-sre` client, obtains a fresh ID token, assumes the derived invoker
role, and fetches the remaining settings from Lambda. It does not use an existing
`config.yaml` to choose the OIDC provider. For deployments using a different
provider, supply `--keycloak-url`, `--realm`, and `--client-id` explicitly (or the
corresponding `ROSA_BOUNDARY_*` environment variables). To enter all settings
without auto-discovery, use `configure --auto-discover=false`.

Confirm the discovered account, region, cluster, role ARNs, Lambda, and EFS filesystem match the intended deployment. If discovery is unavailable, ask the operator for these settings before using interactive configuration.

## Daily Usage

### Step 1: Authenticate

```bash
./bin/rosa-boundary login
```

This opens a browser for Keycloak PKCE authentication when a fresh token is needed. The token is cached under `${XDG_CACHE_HOME:-$HOME/.cache}/rosa-boundary/token-cache` and reused until shortly before expiry. Use the identity provider saved during `configure` (or override it explicitly for a different deployment).

### Step 2: Start Investigation

```bash
./bin/rosa-boundary start-task \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id>
```

This will:
1. Assume the invoker role via STS
2. Invoke the create-investigation Lambda with your cached OIDC token
3. Lambda validates group membership (against `required_groups`)
4. Lambda creates an EFS access point and per-investigation task definition
5. Lambda launches the ECS task with identity and investigation tags (including the deployment's ABAC tag)
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

# Check OpenShift context (if configured)
oc config get-contexts

# Run AWS CLI
aws sts get-caller-identity

# Use Claude Code
claude
```

### Step 5: Disconnect from ECS Exec

```bash
# Exit shell
exit

# Or press Ctrl-D
```

This only ends the interactive ECS Exec session. The task continues running; disconnecting does **not** trigger S3 audit sync.

### Step 6: Stop Task and Verify Audit

```bash
./bin/rosa-boundary stop-task <task-id> --wait
```

Stopping the task attempts the S3 sync. `--wait` confirms STOPPED, **not** that the upload succeeded. Check container logs for sync warnings and verify the expected S3 audit objects using an authorized audit-reader identity; see [audit retrieval and investigation closure](investigation-workflow.md#verify-audit-evidence). Close the investigation when finished.

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

1. Force a fresh login:
   ```bash
   ./bin/rosa-boundary login --force
   ```

2. Verify your Keycloak credentials by logging in at the Keycloak URL

3. Check group membership — see [Getting Access](#getting-access)

### "AccessDenied" from Lambda

1. Verify group membership — see [Getting Access](#getting-access)
2. Confirm the invoker role ARN in your config matches what the administrator provided
3. If the cached token is stale, force a fresh login (see above); distinguish STS role-trust denials from Lambda authorization errors.

### "Task not found" or "Task not running"

1. Check task status:
   ```bash
   ./bin/rosa-boundary list-tasks
   ```

2. If the task stopped, start a new task in the same investigation (if still open):
   ```bash
   ./bin/rosa-boundary start-task --cluster-id <id> --investigation-id <id>
   ```

### "AccessDenied" when executing ECS Exec

ECS Exec is ABAC-scoped by the deployment's configured tag key (for example, `uuid`), not necessarily by username. An operator with permission to inspect tasks can check the tags:

```bash
# Check task tags
aws ecs describe-tasks \
  --cluster <ecs-cluster> \
  --tasks <task-arn> \
  --include TAGS \
  --query 'tasks[0].tags'

```

Compare the task's configured ABAC tag with the identity provider's session tag; `aws sts get-caller-identity` on your workstation does not show the CLI's OIDC-assumed role session tags.

### "ECS Exec is not enabled for this task"

The task was launched without `--enable-execute-command`. This should not happen
with properly created investigations via the Lambda. Contact the administrator.

### session-manager-plugin: connection drops immediately

The container exec agent may not have finished opening its data channel. If it still fails, verify the task has ECS Exec enabled:

```bash
aws ecs describe-tasks \
  --cluster <ecs-cluster> \
  --tasks <task-arn> \
  --query 'tasks[0].enableExecuteCommand'
```

## Security Best Practices

1. **Lock your workstation** when stepping away (sessions remain active)
2. **Stop tasks** when done and verify audit evidence; merely exiting the shell does not trigger sync
3. **Rotate passwords** in Keycloak regularly
4. **Enable MFA** in Keycloak for your account
5. **Review CloudWatch session logs** using an authorized audit-reader identity
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
