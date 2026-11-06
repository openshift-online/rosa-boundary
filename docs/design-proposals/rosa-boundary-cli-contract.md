# Proposed `rosa-boundary` CLI contract

This is a proposal for the **user-facing interface**, not a transcript of the current `rosa-boundary` CLI. It covers Boundary investigation and session workflows, not OCM CLI replacement or other tools. Examples use placeholder IDs. The help below is illustrative proposed `--help` text, not a claim that the commands already exist.

Conventions throughout this proposal:

- `<cluster-id>`, `<investigation-id>`, and `<session-id>` are required positional arguments where shown. A session is the SRE's access to an underlying ECS task; session IDs may be ECS task IDs or full task ARNs, but users do not need to manage ECS directly. An investigation may outlive its individual sessions.
- `-o, --output text|json` defaults to `text` wherever shown. JSON results include the selected profile name and applicable cluster, investigation, and/or session identifiers; credentials and tokens never appear in output. Text output that supplies a follow-up command includes `--profile <name>` so it still targets the same deployment after `config use`.
- A named configuration profile selects one Boundary deployment (AWS account, environment, and region). `--profile` on a Boundary command selects a saved profile for that invocation without changing the active profile. Without it, commands use the active profile; if none exists, commands requiring a deployment fail rather than guessing. Profiles do not select the ROSA cluster under investigation.
- `--region` and `--ecs-cluster` override the selected Boundary deployment's values, **not** the ROSA cluster under investigation. They are available only on commands that use them. `--efs-filesystem-id` likewise identifies the investigation store when a command needs it.
- The root `rosa-boundary` flags `--profile <name>`, `--verbose` (no `-v`) and `--timeout <duration>` are inherited. The timeout bounds non-interactive work; an explicitly supplied timeout also bounds interactive sessions. Interactive commands are not constrained by the default timeout. Every command accepts `-h, --help`. Help is available without login or network access.
- For Boundary operations, command-specific flags override environment settings, which override saved values in the selected profile, which override defaults. Profile selection is independent: explicit `--profile` overrides the saved active profile; environment variables cannot silently change it. `rosa-boundary config get` reads saved YAML only, without resolving environment values or defaults. Commands that need missing deployment settings fail with a message identifying the setting; they do not guess a deployment.
- Parent commands without a child display their help. Prompts require a terminal; non-interactive callers must provide the indicated flags. Progress and prompts go to stderr; results go to stdout. One Boundary config file holds multiple named profiles and an active profile; it does not store access tokens.
- `--session-timeout` requests the underlying task's lifetime subject to the deployment's Lambda policy (default minimum 30s, maximum 24h). A zero lifetime disables expiry **only if** the deployment sets `TASK_TIMEOUT_MINIMUM=0`; the normal deployment rejects zero. The CLI reports Lambda policy rejections rather than bypassing them.

## `rosa-boundary --help`

```text
Manage internal ROSA investigation workspaces and sessions.

Usage:
  rosa-boundary [command]

Available Commands:
  config         Manage Boundary deployment profiles
  login          Sign in for Boundary operations
  investigation  Manage investigation workspaces
  session        Manage investigation sessions and their credentials

Use "rosa-boundary [command] --help" for command-specific options.

Global Flags:
  -h, --help                 Show help
      --profile string       Saved Boundary deployment profile (active if omitted)
      --timeout duration     Deadline for non-interactive operations (default 5m)
      --verbose              Show debug diagnostics (never secrets)
```

## Setup

### `rosa-boundary config --help`

```text
Manage named Boundary deployment profiles in one YAML file under the
rosa-boundary configuration directory. These commands do not manage login
sessions or credentials.

Usage:
  rosa-boundary config [command]

Available Commands:
  init  Add a deployment profile to the Boundary configuration file
  list  List saved profiles and the active profile
  use   Set the active profile for subsequent commands
  get   Read a saved profile or one key
```

The file at `${XDG_CONFIG_HOME:-~/.config}/rosa-boundary/config.yaml` has this shape (illustrative values):

```yaml
active_profile: stage-east
profiles:
  stage-east:
    account_id: "123456789012"
    environment: stage
    project: rosa-boundary
    aws_region: us-east-1
    keycloak_url: https://auth.example.com
    keycloak_realm: EmployeeIDP
    oidc_client_id: rosa-boundary-sre
    lambda_function_name: rosa-boundary-stage-create-investigation
    invoker_role_arn: arn:aws:iam::123456789012:role/example-invoker
    sre_role_arn: arn:aws:iam::123456789012:role/example-sre
    ecs_cluster_name: rosa-boundary-stage
    efs_filesystem_id: fs-example
  prod-west:
    account_id: "210987654321"
    environment: prod
    project: rosa-boundary
    aws_region: us-west-1
    # Other deployment values are saved here by config init.
```

The profile names are user-chosen and unique within the file. No credentials or tokens are stored. `config use` changes only `active_profile`; `--profile` temporarily selects another saved profile for Boundary operations or `config get` (it is not needed by `config init`, `list`, or `use`). The first initialized profile becomes active; later additions do not change the active profile unless `--use` is specified. An unknown profile is an error. Profile-specific OIDC settings and token reuse must not silently authenticate against a different provider: login uses the selected profile's identity provider and only reuses a cached token valid for it.

### `rosa-boundary config init --help`

```text
Add a named Boundary deployment profile for subsequent commands.
Discovers available settings by default; use --auto-discover=false to enter
settings interactively. Requires a terminal if required values are not supplied.
Preserves other profiles. Refuses to replace an existing profile unless
--overwrite is supplied; replacing one requires confirmation unless --yes is
supplied. Does not save access tokens.
Writes to ${XDG_CONFIG_HOME:-~/.config}/rosa-boundary/config.yaml.

Usage:
  rosa-boundary config init [flags]

Flags:
      --name string           Profile name (required without a terminal)
      --account-id string     AWS account containing the Boundary deployment
      --region string         AWS region of the Boundary deployment
      --project string        Deployment project name (default "rosa-boundary")
      --environment string    Deployment environment (default "prod")
      --auto-discover          Discover deployment settings (default true;
                             use --auto-discover=false for manual setup)
      --use                    Make this profile active after saving it
      --overwrite              Allow replacing an existing profile
      --yes                    Skip replacement confirmation (requires --overwrite)
  -h, --help                  Show help

Examples:
  rosa-boundary config init --name stage-east --account-id 123456789012 --region us-east-1
  rosa-boundary config init --name prod-west --account-id 210987654321 --region us-west-1 --use
  rosa-boundary config init --name personal-dev --auto-discover=false
```

### `rosa-boundary config list --help`

```text
List saved Boundary deployment profiles. Show the active profile, account ID,
environment, and deployment region from the YAML file. Never show tokens.

Usage:
  rosa-boundary config list

Flags:
  -h, --help  Show help
```

### `rosa-boundary config use --help`

```text
Set the active profile for subsequent Boundary commands. The profile must
already exist. This updates only active_profile in the Boundary YAML file.

Usage:
  rosa-boundary config use <name>

Flags:
  -h, --help  Show help

Example:
  rosa-boundary config use prod-west
```

### `rosa-boundary config get --help`

```text
Read the active saved profile, or select another with --profile. With no key,
print that profile's saved values as YAML. With a key, print the saved value.
A missing profile or key is an error; environment variables and defaults are
never included. To see available profiles, use config list.

Usage:
  rosa-boundary config get [key]

The supported keys are: account_id, environment, project, keycloak_url,
keycloak_realm, oidc_client_id, lambda_function_name, invoker_role_arn,
sre_role_arn, aws_region, ecs_cluster_name, efs_filesystem_id.

Flags:
      --profile string  Read this saved profile (active if omitted)
  -h, --help  Show help

Examples:
  rosa-boundary config get
  rosa-boundary config get aws_region
  rosa-boundary config get aws_region --profile prod-west
```

### `rosa-boundary login --help`

```text
Sign in to the configured Boundary identity provider.
Opens a browser; never prints the resulting credentials or tokens.

Usage:
  rosa-boundary login [flags]

Flags:
      --force                Sign in again rather than reuse a valid session
  -h, --help                 Show help

Example:
  rosa-boundary login
```

## Investigation lifecycle

### `rosa-boundary investigation --help`

```text
Manage investigation workspaces. An investigation can exist without a running session.

Usage:
  rosa-boundary investigation [command]

Available Commands:
  create  Create an investigation without starting a session
  list    List investigation workspaces, including idle ones
  close   Close an investigation workspace
```

### `rosa-boundary investigation create --help`

```text
Create a persistent investigation workspace without starting a session.
If --investigation-id is omitted, a new ID is generated and reported.

Usage:
  rosa-boundary investigation create <cluster-id> [flags]

Flags:
      --investigation-id string   Requested investigation ID
      --region string             Boundary deployment region (configured if omitted)
  -o, --output string             Result format: text or json (default "text")
  -h, --help                      Show help

Example:
  rosa-boundary investigation create my-cluster --investigation-id incident-42
```

### `rosa-boundary investigation list --help`

```text
List investigation workspaces, whether or not they have running sessions.

Usage:
  rosa-boundary investigation list [flags]

Flags:
      --cluster-id string        Limit results to a ROSA cluster (default: all)
      --efs-filesystem-id string Investigation store (configured if omitted)
      --region string            Boundary deployment region (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

Example:
  rosa-boundary investigation list --cluster-id my-cluster -o json
```

### `rosa-boundary investigation close --help`

```text
Close an investigation workspace. Removes its access point and underlying ECS
task definitions; the investigation's stored files remain. Refuses to close
while sessions are running unless --force is set. --force stops those sessions
first. Shows the resolved target and asks for confirmation unless --yes is set.
--dry-run makes no changes.

Usage:
  rosa-boundary investigation close <cluster-id> <investigation-id> [flags]

Flags:
      --force                    Stop running sessions before closing
      --yes                      Skip confirmation (required without a terminal)
      --dry-run                  Show target and planned actions without changing it
      --efs-filesystem-id string Investigation store (configured if omitted)
      --ecs-cluster string       Boundary ECS cluster (configured if omitted)
      --region string            Boundary deployment region (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

Example:
  rosa-boundary investigation close my-cluster incident-42 --dry-run
```

## Session lifecycle

### `rosa-boundary session --help`

```text
Manage investigation sessions and session-scoped credentials. A session runs
on an ECS task; stopping it does not close the investigation workspace.

Usage:
  rosa-boundary session [command]

Available Commands:
  start        Start an investigation session
  list         List investigation sessions
  join         Open a shell in a running session
  stop         Stop an investigation session
  credentials  Manage credentials in a running session
```

### `rosa-boundary session start --help`

```text
Start a session for an investigation, creating the investigation if necessary.
If --investigation-id is omitted, a new ID is generated and reported. By default,
waits until the session is running and prints its ID and a join command.

Usage:
  rosa-boundary session start <cluster-id> [flags]

Flags:
      --investigation-id string  Investigation to use (generated if omitted)
      --oc-version string        OpenShift CLI version in the session (default "4.20")
      --session-timeout duration Session lifetime (default 1h; deployment minimum
                                 defaults to 30s; maximum 24h)
      --connect                  Join the session after it starts (interactive; text only)
      --no-wait                  Return without waiting for the session to be running
      --with-credentials string  Configure credentials after startup: ocm
      --ocm-url string           OCM environment: production, staging, integration,
                                 or an approved canonical URL
      --ocm-auth-flow string     OCM sign-in: auth-code or device (default "auth-code")
      --region string            Boundary deployment region (configured if omitted)
      --ecs-cluster string       Boundary ECS cluster (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

--no-wait cannot be used with --connect or --with-credentials. --ocm-url and
--ocm-auth-flow require --with-credentials ocm. If setup after session creation
fails, the error includes the created session ID and how to stop it. No local OCM
token is copied into the session; OCM sign-in obtains fresh session-scoped access.

Examples:
  rosa-boundary session start my-cluster --connect
  rosa-boundary session start my-cluster --investigation-id incident-42 --with-credentials ocm --ocm-url production
```

### `rosa-boundary session list --help`

```text
List sessions and their cluster, investigation, owner, and status.

Usage:
  rosa-boundary session list [flags]

Flags:
      --status string       RUNNING, STOPPED, or all (default "RUNNING")
      --ecs-cluster string  Boundary ECS cluster (configured if omitted)
      --region string       Boundary deployment region (configured if omitted)
  -o, --output string       Result format: text or json (default "text")
  -h, --help                Show help

Example:
  rosa-boundary session list --status all -o json
```

### `rosa-boundary session join --help`

```text
Open an interactive shell in a running session you are authorized to access.
Requires the AWS session-manager-plugin on the workstation. The default command
opens a login shell as the session's SRE user. Exiting the shell disconnects;
the session continues running until stopped or expired.

Usage:
  rosa-boundary session join <session-id> [flags]

Flags:
      --container string    Container to enter (default "rosa-boundary")
      --command string      Command to run (default: SRE login shell)
      --no-wait             Do not wait for the session to reach RUNNING (still
                            requires a ready ECS Exec agent)
      --ecs-cluster string  Boundary ECS cluster (configured if omitted)
      --region string       Boundary deployment region (configured if omitted)
  -h, --help                Show help

Example:
  rosa-boundary session join abc123
```

### `rosa-boundary session stop --help`

```text
Stop a session without closing its investigation. Underlying ECS task shutdown
attempts an audit sync of non-credential workspace files. Shows the session and
asks for confirmation unless --yes is set. --wait waits for the stopped state;
stopping is not proof that the audit sync succeeded.

Usage:
  rosa-boundary session stop <session-id> [flags]

Flags:
      --reason string      Audit reason (default "Investigation complete")
      --wait               Wait until the session has stopped
      --yes                Skip confirmation (required without a terminal)
      --ecs-cluster string Boundary ECS cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -o, --output string      Result format: text or json (default "text")
  -h, --help               Show help

Example:
  rosa-boundary session stop abc123 --reason "Investigation complete" --wait
```

## Session credentials

### `rosa-boundary session credentials --help`

```text
Manage credentials inside a running Boundary session. Does not manage the
workstation's OCM login. Stopping the session removes session-scoped credentials.

Usage:
  rosa-boundary session credentials [command]

Available Commands:
  configure  Obtain and configure credentials in a running session
  clear      Remove credentials from a running session
```

### `rosa-boundary session credentials configure --help`

```text
Obtain and configure credentials in a running session.

Usage:
  rosa-boundary session credentials configure [command]

Available Commands:
  ocm  Obtain fresh OCM access for a session
```

### `rosa-boundary session credentials configure ocm --help`

```text
Sign in for fresh OCM access and configure it in a running session.
Never copies the workstation's saved OCM tokens into the session and never prints
the new token. If --ocm-url is omitted, uses the workstation's configured OCM
environment URL, if available; otherwise requires --ocm-url.

Usage:
  rosa-boundary session credentials configure ocm <session-id> [flags]

Flags:
      --ocm-url string     production, staging, integration, or an approved
                           canonical OCM URL
      --auth-flow string   auth-code or device (default "auth-code")
      --ecs-cluster string Boundary ECS cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -h, --help               Show help

Example:
  rosa-boundary session credentials configure ocm abc123 --ocm-url production
```

### `rosa-boundary session credentials clear --help`

```text
Remove credentials from a running session.

Usage:
  rosa-boundary session credentials clear [command]

Available Commands:
  ocm  Remove OCM credentials and derived kubeconfig state
```

### `rosa-boundary session credentials clear ocm --help`

```text
Remove OCM credentials and credential-derived kubeconfig state from a running
session. Does not change credentials on the workstation.

Usage:
  rosa-boundary session credentials clear ocm <session-id> [flags]

Flags:
      --ecs-cluster string Boundary ECS cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -h, --help               Show help

Example:
  rosa-boundary session credentials clear ocm abc123
```

`rosa-boundary version`, `rosa-boundary completion`, and `rosa-boundary help` are proposed top-level commands outside the investigation and session groups.
