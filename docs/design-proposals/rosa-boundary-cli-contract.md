# Proposed `rosa-boundary` CLI contract

This is a proposal for the **user-facing interface**, not a transcript of the current `rosa-boundary` CLI. It covers Boundary investigation and session workflows, not OCM CLI replacement or other tools. Examples use placeholder IDs. The help below is illustrative proposed `--help` text, not a claim that the commands already exist.

Conventions throughout this proposal:

- `<cluster-id>`, `<investigation-id>`, and `<session-id>` are required positional arguments where shown. A Boundary session is the investigation's underlying ECS task; its ID is the ECS task ID (a full task ARN is also accepted). An ECS Exec connection made by `session join` has a separate, short-lived SSM session ID, which is **not** a Boundary `<session-id>` and cannot be used with `session stop` or `credentials`. Disconnecting an Exec shell does not stop the Boundary session. An investigation may outlive its sessions.
- `-o, --output text|json` defaults to `text` wherever shown. JSON results include the selected profile name and applicable cluster, investigation, and/or session identifiers; credentials and tokens never appear in output. Text output that supplies a follow-up command includes `--profile <name>` so it still targets the same deployment after `config use`.
- A named configuration profile selects one Boundary deployment (AWS account, environment, and region). `--profile` on a Boundary command selects a saved profile for that invocation without changing the active profile. Without it, commands use the active profile; if none exists, commands requiring a deployment fail rather than guessing. Profiles do not select the ROSA cluster under investigation.
- `--region` and `--ecs-cluster` override the selected Boundary deployment's values, **not** the ROSA cluster under investigation. They are available only on commands that use them. `--efs-filesystem-id` likewise identifies the investigation store when a command needs it.
- The root `rosa-boundary` flags `--profile <name>`, `--verbose` (no `-v`), `--timeout <duration>`, and `--use-device-code[=true|false]` are inherited. The flow flag chooses Boundary OIDC authentication for that invocation and the default OCM flow when OCM is requested; an explicit OCM flow flag overrides it for OCM only. It does not change the issuer or issue unattended credentials. Every command accepts `-h, --help`. Help is available without login or network access.
- For Boundary operations, command-specific flags override environment settings, which override saved values in the selected profile, which override defaults. Profile selection is independent: explicit `--profile` overrides the saved active profile; environment variables cannot silently change it. `rosa-boundary config get` reads saved YAML only, without resolving environment values or defaults. Commands that need missing deployment settings fail with a message identifying the setting; they do not guess a deployment.
- Parent commands without a child display their help. Prompts require a terminal; non-interactive callers must provide the indicated flags. Progress and prompts go to stderr; results go to stdout. One Boundary config file holds multiple named profiles and an active profile; it does not store access tokens.
- `--session-timeout` requests the underlying task's lifetime subject to the deployment's Lambda policy (default minimum 30s, maximum 24h). A zero lifetime disables expiry **only if** the deployment sets `TASK_TIMEOUT_MINIMUM=0`; the normal deployment rejects zero. The CLI reports Lambda policy rejections rather than bypassing them.

### Authentication and output contract

Browser authorization-code PKCE is the default. Device authorization can be selected by `--use-device-code` or `--use-device-code=true` (and explicitly disabled with `--use-device-code=false`); otherwise `ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE` overrides the selected profile's `oidc_use_device_code`, which defaults to `false`. Invalid boolean values fail rather than falling back. `config init` is the bootstrap exception: its OIDC discovery uses device mode only when explicitly passed `--use-device-code=true`, regardless of the environment or existing configuration, and saves that choice on the new profile; manual initialization saves the explicit choice without authenticating. A profile's cached Boundary ID token is reused only when valid for its issuer and client; STS rejection may cause a fresh human-approved challenge during **any** authenticated command. OCM uses a separate issuer and a fresh session-scoped access token. `--ocm-auth-flow`/`--auth-flow` select OCM only; `auth-code` requires a browser callback, and `device` requires human approval on another device. Starting with OCM credentials can involve two distinct approvals.

`-o, --output json` is available on every auth-bearing leaf command, including `config init` (auto-discovery), `login`, `session join`, `session stop`, and OCM credential commands. It selects machine-readable **auth events** even where the command has no JSON result (config init, login, join, credential commands); `session stop` and the data commands also return one JSON result document on stdout. Offline `config list`, `use`, and `get` do not emit auth events. Text-mode instructions go to stderr. In JSON mode, each event is flushed immediately as a separate stderr line prefixed `ROSA_BOUNDARY_AUTH_EVENT `; other diagnostics may share stderr. The event schema is version 1: `provider` is `boundary` or `ocm`; `device_authorization` carries `verification_uri`, `user_code`, and `expires_in` seconds; `authenticated` carries `source` (`cache`, `device`, or `browser`; `cache` is Boundary-only); `authentication_failed` has a sanitized `reason` (`denied`, `expired`, `canceled`, `network`, `invalid_response`, or `other`). Events must never contain tokens, OAuth `device_code`, PKCE verifiers, or raw token responses. Device user codes and URLs are short-lived operational secrets: share privately, not in shared CI logs. A script must drain stderr while the process runs so a person can approve a challenge, including a retry during an authenticated command. An `authenticated` event is **not** operation success; only the process exit status determines that. `session join` and `session start --connect` always require a terminal for shell I/O; JSON mode never turns a shell into structured output.

For example, a script running `rosa-boundary --profile stage-east --use-device-code session start my-cluster -o json` must monitor stderr for `ROSA_BOUNDARY_AUTH_EVENT {"version":1,"provider":"boundary","event":"device_authorization","verification_uri":"https://...","user_code":"ABCD-EFGH","expires_in":600}` and present the challenge privately for a human to approve. The event may occur even after a prior `login -o json` or after an earlier `authenticated` event if STS rejects a cached token. A later OCM challenge uses `provider:"ocm"`. Only a zero exit status and the final stdout result establish that the operation completed.

### Deadlines and post-creation failures

Invocations without a controlling terminal default to a five-minute **whole-command** deadline (including device approval, STS, Lambda, ECS waits, and credential setup). No default whole-command deadline applies with a controlling terminal (including prompts and interactive shells). An explicit `--timeout` sets a whole-command deadline in either mode, including an interactive shell; on expiry, terminate the local ECS Exec plugin/connection, return nonzero, but do **not** imply the task stopped. The ECS RUNNING/STOPPED waiter has its own ten-minute maximum; the effective limit is the earlier of that maximum and the whole-command deadline. For a headless start or stop that may take longer than five minutes, pass e.g. `--timeout 12m` (the waiter itself still caps at ten minutes). Authentication approval must finish within the chosen deadline; scripts cannot bypass human approval by setting a longer timeout. `--session-timeout` is independent: it controls task expiry, not how long the CLI waits.

With `session start` (except `--no-wait`), a RUNNING wait failure is a nonzero failure, **not** a warning followed by a successful start or credential configuration. After the Lambda returns a task ARN, any error (role assumption, wait, credential setup, connection, output failure, or deadline) must identify the created Boundary session ID, cluster/investigation when known, selected profile, and a profile-qualified cleanup command (`rosa-boundary --profile <name> session stop <session-id> --yes`); it must not silently stop the task. A session that failed to reach RUNNING may already be STOPPED; inspect `session list --status all` if a stop fails. `--no-wait` reports creation/launch, not readiness. JSON success output must not be emitted for a failed wait or credential setup; errors and recovery information go to stderr. For `--connect`, the ready-session result may be emitted before opening the shell; if Exec later fails or the explicit deadline expires, return nonzero with recovery guidance even though the result was already printed. Exiting a shell normally is not an error and does not stop the task. Audit sync remains a separate verification step after stop/close.

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
      --timeout duration     Whole-command deadline (default 5m without terminal)
      --use-device-code      Use device approval for Boundary and default OCM flow
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
    oidc_use_device_code: false
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

This is a **new opt-in file format**, not a migration. The existing CLI's single-profile `config.yaml` must not be interpreted as a named profile, merged, or silently overwritten. On detecting the legacy shape, the new profile commands fail with an actionable message: back up/move the old file, then run `config init --name <name> ...` for each intended deployment and `config use <name>`. Do not import legacy deployment values automatically. Users who have not opted into the new CLI/config contract keep using the existing CLI until they deliberately install the version implementing this proposal; the rollout documentation must call out the incompatible config and command names.

### `rosa-boundary config init --help`

```text
Add a named Boundary deployment profile for subsequent commands.
Discovers available settings by default; use --auto-discover=false to supply
all deployment settings via flags or enter missing values interactively.
Without a terminal, reports all missing required settings before saving.
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
      --keycloak-url string   OIDC provider base URL (required in manual mode)
      --realm string          OIDC realm (default "EmployeeIDP")
      --client-id string      OIDC client ID (default "rosa-boundary-sre")
      --lambda-function-name string  Create-investigation Lambda (manual mode)
      --invoker-role-arn string      Lambda invoker role ARN (manual mode)
      --sre-role-arn string          SRE role ARN (manual mode)
      --ecs-cluster string          Boundary ECS cluster name (manual mode)
      --efs-filesystem-id string    Investigation EFS filesystem (manual mode)
      --auto-discover          Discover deployment settings (default true;
                               use --auto-discover=false for manual setup)
      --use                    Make this profile active after saving it
      --overwrite              Allow replacing an existing profile
      --yes                    Skip replacement confirmation (requires --overwrite)
  -o, --output string         text or json auth events on stderr (default "text")
  -h, --help                  Show help

Examples:
  rosa-boundary config init --name stage-east --account-id 123456789012 --region us-east-1
  rosa-boundary config init --name prod-west --account-id 210987654321 --region us-west-1 --use
  rosa-boundary config init --name personal-dev --auto-discover=false
  rosa-boundary config init --name personal-dev --account-id 123456789012 \
    --region us-east-1 --auto-discover=false --keycloak-url https://auth.example.com \
    --realm EmployeeIDP --client-id rosa-boundary-sre \
    --lambda-function-name example-create-investigation \
    --invoker-role-arn arn:aws:iam::123456789012:role/example-invoker \
    --sre-role-arn arn:aws:iam::123456789012:role/example-sre \
    --ecs-cluster example-ecs --efs-filesystem-id fs-example --use-device-code
```

Manual mode requires a name, account ID, region, Keycloak URL, Lambda name, invoker and SRE role ARNs, ECS cluster, and EFS filesystem ID; project, environment, realm, client ID, and device preference have the displayed defaults. Values for manual initialization come from its flags or terminal prompts/defaults, **not** ambient deployment environment variables or the old single-profile file. Auto-discovery requires the name, account ID, and region (prompted if a terminal is available), and uses the supplied OIDC bootstrap flags or documented defaults; it does not reuse an existing profile's issuer or device preference. `--output json` on init emits auth events during discovery on stderr but no JSON result on stdout.

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
keycloak_realm, oidc_client_id, oidc_use_device_code, lambda_function_name,
invoker_role_arn, sre_role_arn, aws_region, ecs_cluster_name, efs_filesystem_id.

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
Sign in to the selected profile's Boundary identity provider. Uses a browser
unless device authorization is selected. Never prints credentials or tokens.

Usage:
  rosa-boundary login [flags]

Flags:
      --force                Sign in again rather than reuse a valid session
  -o, --output string        text or json auth events on stderr (default "text")
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
Close an investigation workspace. Removes its access point and associated ECS
task definitions; stored files remain. Resolves the target and complete action
set before confirmation: account, region, ECS cluster, EFS filesystem/access
point, cluster/investigation IDs, active session IDs to stop, and task
definition ARNs to deregister. Refuses active (including pending) sessions
without --force.
--force plans their stops and waits before deregistration/deletion. --dry-run
only previews the plan; it never stops sessions, deregisters definitions, or
deletes an access point. --yes skips the confirmation, not plan validation.

Usage:
  rosa-boundary investigation close <cluster-id> <investigation-id> [flags]

Flags:
      --force                    Stop active sessions before closing
      --yes                      Skip confirmation (required without a terminal
                                 unless --dry-run)
      --dry-run                  Show target and planned actions without changing it
      --efs-filesystem-id string Investigation store (configured if omitted)
      --ecs-cluster string       Boundary ECS cluster (configured if omitted)
      --region string            Boundary deployment region (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

Example:
  rosa-boundary investigation close my-cluster incident-42 --dry-run
```

Resolution is read-only and must finish before any mutation, including with `--yes`. Display the **same complete action set** for `--dry-run` and the confirmation preview (text to stderr; JSON dry-run as one stdout document); an ambiguous or incomplete target is an error, not a partial plan. Confirm once, then stop planned active sessions (if forced), wait for them to stop, deregister the planned task definitions, and delete the access point. Recheck the access point, active sessions, and task definitions immediately before mutation; if the plan changed, abort and require a new preview/confirmation rather than silently acting on newly discovered resources. If any action fails, return nonzero with completed and remaining actions and do not claim the investigation closed. A preview cannot make concurrent AWS changes atomic; post-confirmation failures are possible. Audit sync is attempted on task shutdown and must be verified separately.

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
      --connect                  Join the session after it starts (requires a terminal)
      --no-wait                  Return without waiting for the session to be running
      --with-credentials string  Configure credentials after startup: ocm
      --ocm-url string           OCM environment: production, staging, integration,
                                 or an approved canonical URL
      --ocm-auth-flow string     OCM-only sign-in override: auth-code or device
      --region string            Boundary deployment region (configured if omitted)
      --ecs-cluster string       Boundary ECS cluster (configured if omitted)
  -o, --output string            Result format: text or json (default "text")
  -h, --help                     Show help

--no-wait cannot be used with --connect or --with-credentials. --ocm-url and
--ocm-auth-flow require --with-credentials ocm. If anything after session creation
fails (including the RUNNING wait), the error includes the created session ID and a
`--profile`-qualified stop command. No local OCM token is copied into the
session; OCM sign-in obtains fresh session-scoped access.

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
  -o, --output string       text or json auth events on stderr (default "text")
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
      --auth-flow string   OCM-only override: auth-code or device
      --ecs-cluster string Boundary ECS cluster (configured if omitted)
      --region string      Boundary deployment region (configured if omitted)
  -o, --output string      text or json auth events on stderr (default "text")
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
  -o, --output string      text or json auth events on stderr (default "text")
  -h, --help               Show help

Example:
  rosa-boundary session credentials clear ocm abc123
```

`rosa-boundary version`, `rosa-boundary completion`, and `rosa-boundary help` are proposed top-level commands outside the investigation and session groups.
