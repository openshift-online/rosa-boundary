# Proposed `rosa-boundary` CLI contract

This is a proposal for the **user-facing interface**, not a transcript of the current `rosa-boundary` CLI. It covers Boundary investigation and task workflows, not OCM CLI replacement or other tools. Examples use placeholder IDs. The help below is illustrative proposed `--help` text, not a claim that the commands already exist.

Conventions throughout this proposal:

- `<cluster-id>`, `<investigation-id>`, and `<task-id>` are required positional arguments. Task IDs may be full task ARNs. An investigation may outlive its individual tasks.
- `-o, --output text|json` defaults to `text` wherever shown. JSON results include the applicable cluster, investigation, and/or task identifiers; credentials and tokens never appear in output.
- `--region` and `--ecs-cluster` select the Boundary deployment, **not** the ROSA cluster under investigation. They are available only on commands that use them; configured deployment values apply when omitted. `--efs-filesystem-id` likewise identifies the investigation store when a command needs it.
- The root `rosa-boundary` flags `--verbose` (no `-v`) and `--timeout <duration>` are inherited. The timeout bounds non-interactive work; an explicitly supplied timeout also bounds interactive sessions. Interactive commands are not constrained by the default timeout. Every command accepts `-h, --help`. Help is available without login or network access.
- Flags override environment settings, which override saved configuration, which overrides defaults when running Boundary commands. `rosa-boundary config get` is different: it reads only the Boundary YAML file, without resolving flags, environment variables, or defaults. Commands that need missing deployment settings fail with a message identifying the setting; they do not guess a deployment.
- Parent commands without a child display their help. Prompts require a terminal; non-interactive callers must provide the indicated flags. Progress and prompts go to stderr; results go to stdout. This contract specifies one Boundary config file; choosing between multiple region/environment configs is reserved for a future contract.
- `--task-timeout` requests a task lifetime subject to the deployment's Lambda policy (default minimum 30s, maximum 24h). A zero lifetime disables expiry **only if** the deployment sets `TASK_TIMEOUT_MINIMUM=0`; the normal deployment rejects zero. The CLI reports Lambda policy rejections rather than bypassing them.

## `rosa-boundary --help`

```text
Manage internal ROSA investigation workspaces and tasks.

Usage:
  rosa-boundary [command]

Available Commands:
  config         Initialize and read Boundary configuration
  login          Sign in for Boundary operations
  investigation  Manage investigation workspaces
  task           Manage investigation tasks and their credentials

Use "rosa-boundary [command] --help" for command-specific options.

Global Flags:
  -h, --help                 Show help
      --timeout duration     Deadline for non-interactive operations (default 5m)
      --verbose              Show debug diagnostics (never secrets)
```

## Setup

### `rosa-boundary config --help`

```text
Initialize and read Boundary configuration. Configuration is stored as YAML
under the rosa-boundary configuration directory. These commands do not manage login
sessions or credentials.

Usage:
  rosa-boundary config [command]

Available Commands:
  init  Create a Boundary configuration file
  get   Read the Boundary configuration file or one key
```

### `rosa-boundary config init --help`

```text
Create a Boundary YAML configuration file for subsequent commands.
Discovers available settings by default; use --auto-discover=false to enter
settings interactively. Requires a terminal if required values are not supplied.
Refuses to replace an existing file unless --overwrite is supplied; replacing
one requires confirmation unless --yes is supplied. Does not save access tokens.
Writes to ${XDG_CONFIG_HOME:-~/.config}/rosa-boundary/config.yaml.

Usage:
  rosa-boundary config init [flags]

Flags:
      --account-id string     AWS account containing the Boundary deployment
      --region string         AWS region of the Boundary deployment
      --project string        Deployment project name (default "rosa-boundary")
      --environment string    Deployment environment (default "prod")
      --auto-discover          Discover deployment settings (default true;
                             use --auto-discover=false for manual setup)
      --overwrite              Allow replacing an existing configuration file
      --yes                    Skip replacement confirmation (requires --overwrite)
  -h, --help                  Show help

Examples:
  rosa-boundary config init --account-id 123456789012 --region us-east-2
  rosa-boundary config init --auto-discover=false
```

### `rosa-boundary config get --help`

```text
Read the Boundary YAML configuration file. With no key, print the full saved
configuration as YAML. With a key, print that key's saved value. A missing key
is an error; environment variables and defaults are never included.

Usage:
  rosa-boundary config get [key]

The supported keys are: keycloak_url, keycloak_realm, oidc_client_id,
lambda_function_name, invoker_role_arn, sre_role_arn, aws_region,
ecs_cluster_name, efs_filesystem_id.

Flags:
  -h, --help  Show help

Examples:
  rosa-boundary config get
  rosa-boundary config get aws_region
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
Manage investigation workspaces. An investigation can exist without a running task.

Usage:
  rosa-boundary investigation [command]

Available Commands:
  create  Create an investigation without starting a task
  list    List investigation workspaces, including idle ones
  close   Close an investigation workspace
```

### `rosa-boundary investigation create --help`

```text
Create a persistent investigation workspace without starting a task.
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
List investigation workspaces, whether or not they have running tasks.

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
Close an investigation workspace. Removes its access point and task definitions;
the investigation's stored files remain. Refuses to close while tasks are running
unless --force is set. --force stops those tasks first. Shows the resolved target
and asks for confirmation unless --yes is set. --dry-run makes no changes.

Usage:
  rosa-boundary investigation close <cluster-id> <investigation-id> [flags]

Flags:
      --force                    Stop running tasks before closing
      --yes                      Skip confirmation (required without a terminal)
      --dry-run                  Show target and planned actions without changing it
      --efs-filesystem-id string Investigation store (configured if omitted)
      --ecs-cluster string       Boundary task cluster (configured if omitted)
      --region string            Boundary deployment region (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

Example:
  rosa-boundary investigation close my-cluster incident-42 --dry-run
```

## Task lifecycle

### `rosa-boundary task --help`

```text
Manage investigation tasks and task-scoped credentials.

Usage:
  rosa-boundary task [command]

Available Commands:
  start        Start an investigation task
  list         List investigation tasks
  join         Open a session in a running task
  stop         Stop an investigation task
  credentials  Manage credentials in a running task
```

### `rosa-boundary task start --help`

```text
Start a task for an investigation, creating the investigation if necessary.
If --investigation-id is omitted, a new ID is generated and reported. By default,
waits until the task is running and prints its ID and a join command.

Usage:
  rosa-boundary task start <cluster-id> [flags]

Flags:
      --investigation-id string  Investigation to use (generated if omitted)
      --oc-version string        OpenShift CLI version in the task (default "4.20")
      --task-timeout duration    Task lifetime (default 1h; deployment minimum
                                 defaults to 30s; maximum 24h)
      --connect                  Join the task after it starts (interactive; text only)
      --no-wait                  Return without waiting for the task to be running
      --with-credentials string  Configure credentials after startup: ocm
      --ocm-url string           OCM environment: production, staging, integration,
                                 or an approved canonical URL
      --ocm-auth-flow string     OCM sign-in: auth-code or device (default "auth-code")
      --region string            Boundary deployment region (configured if omitted)
      --ecs-cluster string       Boundary task cluster (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

--no-wait cannot be used with --connect or --with-credentials. --ocm-url and
--ocm-auth-flow require --with-credentials ocm. If setup after task creation
fails, the error includes the created task ID and how to stop it. No local OCM
token is copied into the task; OCM sign-in obtains fresh task-scoped access.

Examples:
  rosa-boundary task start my-cluster --connect
  rosa-boundary task start my-cluster --investigation-id incident-42 --with-credentials ocm --ocm-url production
```

### `rosa-boundary task list --help`

```text
List tasks and their cluster, investigation, owner, and status.

Usage:
  rosa-boundary task list [flags]

Flags:
      --status string       RUNNING, STOPPED, or all (default "RUNNING")
      --ecs-cluster string  Boundary task cluster (configured if omitted)
      --region string       Boundary deployment region (configured if omitted)
  -o, --output string       Result format: text or json (default "text")
  -h, --help                Show help

Example:
  rosa-boundary task list --status all -o json
```

### `rosa-boundary task join --help`

```text
Open an interactive session in a running task you are authorized to access.
Requires the AWS session-manager-plugin on the workstation. The default command
opens a login shell as the task's SRE user. Exiting the shell ends the session,
not the task.

Usage:
  rosa-boundary task join <task-id> [flags]

Flags:
      --container string    Container to enter (default "rosa-boundary")
      --command string      Command to run (default: SRE login shell)
      --no-wait             Do not wait for the task to reach RUNNING (still
                            requires a ready ECS Exec agent)
      --ecs-cluster string  Boundary task cluster (configured if omitted)
      --region string       Boundary deployment region (configured if omitted)
  -h, --help                Show help

Example:
  rosa-boundary task join abc123
```

### `rosa-boundary task stop --help`

```text
Stop a task without closing its investigation. Task shutdown triggers an audit
sync of non-credential workspace files. Shows the task and asks for confirmation
unless --yes is set. --wait waits for the stopped state.

Usage:
  rosa-boundary task stop <task-id> [flags]

Flags:
      --reason string      Audit reason (default "Investigation complete")
      --wait               Wait until the task has stopped
      --yes                Skip confirmation (required without a terminal)
      --ecs-cluster string Boundary task cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -o, --output string      Result format: text or json (default "text")
  -h, --help               Show help

Example:
  rosa-boundary task stop abc123 --reason "Investigation complete" --wait
```

## Task credentials

### `rosa-boundary task credentials --help`

```text
Manage credentials inside a running Boundary task. Does not manage the
workstation's OCM login. Stopping the task removes task-scoped credentials.

Usage:
  rosa-boundary task credentials [command]

Available Commands:
  configure  Obtain and configure credentials in a running task
  clear      Remove credentials from a running task
```

### `rosa-boundary task credentials configure --help`

```text
Obtain and configure credentials in a running task.

Usage:
  rosa-boundary task credentials configure [command]

Available Commands:
  ocm  Obtain fresh OCM access for a task
```

### `rosa-boundary task credentials configure ocm --help`

```text
Sign in for fresh OCM access and configure it in a running task.
Never copies the workstation's saved OCM tokens into the task and never prints
the new token. If --ocm-url is omitted, uses the workstation's configured OCM
environment URL, if available; otherwise requires --ocm-url.

Usage:
  rosa-boundary task credentials configure ocm <task-id> [flags]

Flags:
      --ocm-url string     production, staging, integration, or an approved
                           canonical OCM URL
      --auth-flow string   auth-code or device (default "auth-code")
      --ecs-cluster string Boundary task cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -h, --help               Show help

Example:
  rosa-boundary task credentials configure ocm abc123 --ocm-url production
```

### `rosa-boundary task credentials clear --help`

```text
Remove credentials from a running task.

Usage:
  rosa-boundary task credentials clear [command]

Available Commands:
  ocm  Remove OCM credentials and derived kubeconfig state
```

### `rosa-boundary task credentials clear ocm --help`

```text
Remove OCM credentials and credential-derived kubeconfig state from a running
task. Does not change credentials on the workstation.

Usage:
  rosa-boundary task credentials clear ocm <task-id> [flags]

Flags:
      --ecs-cluster string Boundary task cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -h, --help               Show help

Example:
  rosa-boundary task credentials clear ocm abc123
```

`rosa-boundary version`, `rosa-boundary completion`, and `rosa-boundary help` are proposed top-level commands outside the investigation and task groups.
