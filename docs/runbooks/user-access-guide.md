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

For a server without a local browser or callback port, add **explicit**
`--use-device-code` to `configure`: it displays a verification URL and user code
on stderr; open the URL on another device, enter the code, and approve as the
authorized SRE while the CLI waits. For example:

```bash
./bin/rosa-boundary configure \
  --account-id <account-id> --region <region> \
  --project rosa-boundary --environment stage --use-device-code
```

This writes `oidc_use_device_code: true` (a YAML boolean) to
`${XDG_CONFIG_HOME:-$HOME/.config}/rosa-boundary/config.yaml` and uses device
approval for future fresh Boundary **and OCM** authentication. Without an
explicit true flag (including `--use-device-code=false`), `configure` uses
browser bootstrap and **writes `oidc_use_device_code: false`**, even if the
previous config or `ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE` says true. This is an
intentional exception to normal command precedence. With `--auto-discover=false`,
it writes the selected boolean but does not attempt OIDC login; manual setup
may still prompt for configuration fields.

Confirm the discovered account, region, cluster, role ARNs, Lambda, and EFS filesystem match the intended deployment. If discovery is unavailable, ask the operator for these settings before using interactive configuration.

## Daily Usage

### Step 1: Authenticate

```bash
./bin/rosa-boundary login
```

By default this opens a browser for Keycloak PKCE authentication when a fresh
Boundary ID token is needed. With the saved device preference it instead shows
a URL and code on stderr and waits for human approval on another device; it
does not open a browser or bind a callback port on the server. The token is
cached under `${XDG_CACHE_HOME:-$HOME/.cache}/rosa-boundary/token-cache` and
reused until shortly before the token's actual expiry (`exp`), regardless of
the selected flow. `login --force` or global `--force-login` requests a fresh
token; ordinary commands can also request fresh approval after cache expiry or
STS rejection. The selected flow is retained for retries, with no automatic
fallback to a browser. Use the identity provider saved during `configure` (or
override it explicitly for a different deployment).

For **normal commands**, flow selection is explicit `--use-device-code=true|false`
(bare flag means true) > `ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE` > saved YAML
`oidc_use_device_code` > default `false`. An explicit false overrides a saved
true for both Boundary and OCM; invalid environment or config booleans fail
instead of falling back. This setting chooses the login flow, not the provider.

### Script-driven, human-approved login

Automation can surface approval challenges, but **cannot issue user credentials
unattended**: a human must approve each fresh device request. For every command
that might authenticate, pass `-o json` (or `--output json`) to that **leaf
command**, even after a successful `login -o json`; another command may see
an expired token or an STS retry. Auth events are prefixed JSON lines on
**stderr**, while existing operation result JSON (for example, `start-task`)
remains a single document on **stdout**. Other stderr diagnostics can coexist.
`login`, `configure`, `stop-task`, and OCM credential commands have no JSON
result on stdout; `join-task` remains an interactive terminal session, not a
JSON shell. Do not capture a device challenge into a shared CI log or file.

For a noninteractive auth-bearing command, this Python example inherits its
stdout (so result JSON is unchanged), drains stderr **while it runs**, and
shows both provider challenges only on the operator's private terminal. Invoke
it with an approved channel to the SRE and a command such as
`python3 approve_boundary.py ./bin/rosa-boundary start-task --cluster-id CLUSTER --with-credentials ocm -o json`.
Do not use this example for interactive `join-task`, `start-task --connect`, or
manual `configure` (those need terminal input/session I/O).

```python
#!/usr/bin/env python3
import json
import subprocess
import sys

PREFIX = "ROSA_BOUNDARY_AUTH_EVENT "
args = sys.argv[2:]
json_output = any(
    (arg in ("-o", "--output") and i + 1 < len(args) and args[i + 1] == "json")
    or arg in ("-o=json", "--output=json")
    for i, arg in enumerate(args)
)
if not json_output:
    sys.exit("Pass a noninteractive rosa-boundary command with -o json")

with open("/dev/tty", "w", encoding="utf-8") as terminal:
    child = subprocess.Popen(
        sys.argv[1:], stdin=subprocess.DEVNULL, stdout=sys.stdout,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1,
    )
    for line in child.stderr:
        if not line.startswith(PREFIX):
            sys.stderr.write(line)  # Other diagnostics are not auth events.
            continue
        event = json.loads(line[len(PREFIX):])
        provider = event["provider"]  # "boundary" and "ocm" are separate approvals.
        if event["event"] == "device_authorization":
            terminal.write(
                f"{provider}: open {event['verification_uri']} on another device "
                f"and enter {event['user_code']} (expires in {event['expires_in']}s).\n"
            )
            terminal.flush()  # Do not wait for process exit before notifying the SRE.
        elif event["event"] == "authentication_failed":
            terminal.write(f"{provider} authentication failed: {event['reason']}\n")
            terminal.flush()
        # "authenticated" is token acquisition, not command success.
    sys.exit(child.wait())  # Check exit status before acting on stdout results.
```

Each `device_authorization` event has `version: 1`, `provider`,
`verification_uri`, `user_code`, and `expires_in`; `authenticated` has a
`source` (`cache`, `device`, or `browser`; cache is Boundary-only), and
`authentication_failed` has a sanitized reason. A cached Boundary success
can be followed by a fresh Boundary challenge on STS rejection; OCM approval
can follow in the same command. The process may fail **after** either
`authenticated` event. Handle the short-lived URL and code as sensitive
operational information; never pass them in arguments, store them in logs,
or print tokens. Do not retry denied or expired requests indefinitely. See
the [authentication model](../architecture/cli-authentication.md#authentication-events-for-scripts)
for the complete event and stream contract.

For OCM credentials, `start-task --with-credentials ocm` and
`credentials configure ocm <task-id>` use the same saved/global device
preference by default but request a **different issuer/client's OCM access
token**, never the Boundary ID token. Explicit `--ocm-auth-flow auth-code|device`
on `start-task` or `--auth-flow auth-code|device` on `credentials configure ocm`
overrides **OCM only** for that invocation. An explicit `auth-code` requires a
local callback even when Boundary uses device mode; explicit `device` remains
headless. If both providers require fresh authentication, expect **two separate
human approvals**. OCM tokens are transferred to task-scoped, audit-excluded
storage; they are not printed or stored in the Boundary token cache.

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
./bin/rosa-boundary list-tasks --ecs-cluster <ecs-cluster>

# Or via AWS CLI for tag details
aws ecs describe-tasks \
  --cluster <ecs-cluster> \
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

4. On a headless host, verify that the saved YAML boolean or explicit flag
   selects device mode; `configure` does **not** inherit the environment/file
   preference for its bootstrap. If a challenge expires, is denied, or is
   canceled, request a new login after addressing the cause; check that the
   operator approved the correct provider (`boundary` or `ocm`). Device mode
   does not fall back to browser mode. For OCM, check whether an explicit
   `--ocm-auth-flow auth-code` / `--auth-flow auth-code` requested a callback.
   If OCM configuration fails after task creation, retain the reported task ID
   and follow the cleanup/retry guidance; a failed command does not stop the task.

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
