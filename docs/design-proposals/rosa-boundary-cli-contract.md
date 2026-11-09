# Proposed `rosa-boundary` CLI contract

This document records the proposed **user-facing Boundary CLI contract** and reconciles it with the implementation at commit `75117d6` in [draft PR #447](https://github.com/openshift-online/rosa-boundary/pull/447). PR #354 is the earlier design-proposal PR; the implementation is on a separate, unmerged branch. This is not a claim that the contract has merged to main, been deployed, or been validated against a live Boundary environment. Current source and tests, not illustrative examples here, govern the draft implementation. The CLI manages Boundary investigations and sessions; it does not replace the OCM CLI.

## Conventions and command tree

- `<cluster-id>` is the ROSA cluster being investigated; `--ecs-cluster` is the Boundary deployment's ECS cluster, **not** that ROSA cluster. A Boundary `<session-id>` is its ECS task ID (a full task ARN is also accepted where ECS accepts it); the short-lived SSM Exec session ID is different and is not an argument to `session close` or credential commands. An investigation can outlive its tasks. Leaving an Exec shell neither closes the task nor closes the investigation.
- A saved profile selects one Boundary deployment (account, environment, region and other settings), not a ROSA cluster. Root `--profile <name>` selects a saved profile for this invocation without changing the active one. Otherwise the saved active profile is used; if none exists, commands requiring a deployment fail rather than guessing. Environment variables cannot select a profile. For deployment settings, explicit command flags override `ROSA_BOUNDARY_*` environment settings, then saved profile values, then defaults. Only relevant commands offer `--region`, `--ecs-cluster`, or `--efs-filesystem-id`.
- Root flags are `--profile`, `--verbose` (no `-v`), `--timeout <duration>`, and `--use-device-code` (a boolean flag; `--use-device-code=false` explicitly selects browser mode). All commands accept `-h, --help`; parent commands with no child show help without authentication. `version` is also a top-level command; Cobra exposes `help` and `completion`.
- For leaves that offer it, `-o, --output text|json` defaults to `text`. Progress, prompts, authentication guidance and errors go to stderr; results go to stdout. Text success suggestions include `--profile` and only deployment override flags needed to preserve the effective region/ECS target (including when an environment override would otherwise change it). Failure cleanup/retry commands may pin both region and ECS cluster for recovery even when they match the saved profile. Commands without `-o` (such as offline profile listing/selection/get and `version`) are not JSON-result commands.
- Input errors identify the missing or unexpected positional argument or bad flag, show the command's usage line and point to its `--help`, without dumping the entire help page. Validate user-correctable input before authentication or AWS mutation wherever possible. Commands needing missing deployment settings name them rather than guessing. Non-interactive callers must supply required flags instead of relying on prompts.

The public command groups and leaves on draft PR #447 are:

```text
rosa-boundary config init
rosa-boundary config list-profiles
rosa-boundary config use-profile <name>
rosa-boundary config get [key]
rosa-boundary login
rosa-boundary investigation create <cluster-id>
rosa-boundary investigation list
rosa-boundary investigation close <cluster-id> <investigation-id>
rosa-boundary session create <cluster-id>
rosa-boundary session list
rosa-boundary session join <session-id>
rosa-boundary session close <session-id>
rosa-boundary session credentials configure ocm [session-id]
rosa-boundary session credentials clear ocm [session-id]
```

The earlier names `config list`, `config use`, `session start`, and `session stop` are **rejected**, not aliases. They return guidance for `config list-profiles`, `config use-profile <name>`, `session create <cluster-id>`, and `session close <session-id>` respectively; the old session-stop diagnostic also says the investigation remains open. Rollout documentation and scripts must account for these incompatible verbs.

## Named deployment profiles

`config init --name <name> --account-id <account> --region <boundary-region>` creates a profile. The file is `${XDG_CONFIG_HOME:-$HOME/.config}/rosa-boundary/config.yaml`; it holds named profiles and `active_profile`, **not** access tokens or credentials. For example:

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
```

Profile names are unique, user-chosen names. The first initialized profile becomes active; later additions preserve the active selection unless `config init --use` is supplied. `--overwrite` allows replacement of an existing profile, with confirmation unless `--yes` is also passed; `--yes` alone is invalid. `--profile` selects a saved profile for Boundary operations or `config get`, but is not used by `config init` or `config use-profile`. An unknown profile fails rather than changing the selection.

By default, `config init` authenticates to the bootstrap OIDC issuer and discovers deployment settings through the derived invoker role and Lambda. Supply `--keycloak-url`, `--realm`, `--client-id`, `--project` and `--environment` when the bootstrap defaults do not identify the intended deployment. Discovery checks issuer/region and role-account consistency before saving; it does not inherit another profile or ambient deployment environment values. `--auto-discover=false` instead collects required deployment values from flags or terminal prompts without authenticating: `--name`, `--account-id`, `--region`, `--keycloak-url`, `--lambda-function-name`, `--invoker-role-arn`, `--sre-role-arn`, `--ecs-cluster`, and `--efs-filesystem-id`. It reports missing required settings in a headless invocation before saving. Project, environment, realm and client ID have defaults. Explicit `--use-device-code=true` (or the bare flag) alone selects device-mode **bootstrap** and saves that preference; absent/false saves browser mode even if an environment variable or another profile prefers device mode. Manual init saves the explicit preference without signing in.

The named-profile parser does **not** migrate or import the old flat single-profile `config.yaml`. Such a file fails ordinary named-profile schema validation with guidance to back it up or move it aside and run `config init` from scratch. There is no separate legacy-shape detection, automatic merge, or silent overwrite. Treat the file-format change as an intentional rollout incompatibility.

`config list-profiles`, `config use-profile`, and `config get` work offline against saved YAML, not resolved environment overrides. `config list-profiles` shows sorted saved rows with headers `ACTIVE`, `PROFILE`, `ACCOUNT ID`, `ENVIRONMENT`, `REGION`, a separator and `*` for the active row. With a missing file or empty `profiles: {}`, it says `No profiles found. Run 'rosa-boundary config init --help' to create one.`; malformed config remains an error. `config use-profile <name>` changes only `active_profile` and confirms the active name, **saved** account ID and **saved** region on separate lines:

```text
Active profile: stage-east
AWS account ID: 123456789012
AWS region: us-east-1
```

`config get [key]` prints a selected profile's saved YAML or one saved key; missing/unsupported keys fail. Its supported keys are `account_id`, `environment`, `project`, `aws_region`, `keycloak_url`, `keycloak_realm`, `oidc_client_id`, `oidc_use_device_code`, `lambda_function_name`, `invoker_role_arn`, `sre_role_arn`, `ecs_cluster_name`, and `efs_filesystem_id`. Neither defaults nor environment overrides appear in `config get`.

## Authentication, JSON and deadlines

`login [--force]` signs in for the selected Boundary profile; `--force` asks for a fresh token. Browser authorization-code PKCE is the default. For normal authenticated commands, explicit `--use-device-code=true|false` overrides `ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE`, then the selected profile's saved `oidc_use_device_code`, then the default `false`; invalid booleans fail. `config init` uses the bootstrap exception above. The flag selects a flow, not an issuer or an unattended credential. A cached Boundary **ID token** is reused only while valid for the selected issuer/client; STS rejection of a cached token can trigger a fresh approval during any authenticated command. Boundary obtains temporary, identity-scoped AWS role sessions instead of requiring existing workstation AWS keys.

OCM credentials are separate from the Boundary ID token: `session create --with-credentials ocm` or `session credentials configure ocm <session-id>` obtains a **fresh OCM access token** for the chosen OCM environment, never copies the workstation's saved OCM token into the session, and injects it into task-scoped, audit-excluded storage. The default OCM flow follows the effective Boundary device preference; `--ocm-auth-flow auth-code|device` on create and `--auth-flow auth-code|device` on configure override OCM **only**. An explicit `auth-code` requires a local browser callback. Boundary sign-in and OCM authorization may require two separate human approvals. `--ocm-url` accepts production/staging/integration aliases or approved canonical URLs; if omitted for an actual configure, the CLI reads only the URL from local OCM configuration and fails if none is available. No OCM token is acquired merely to suggest a credential command.

Every leaf offering `-o json` produces **one JSON object on stdout**, including on failure; it does not emit a JSON-auth-event stream. Authentication challenges remain **human-readable stderr** in both modes (device verification URL and user code, or browser guidance). There is no `ROSA_BOUNDARY_AUTH_EVENT` protocol. Scripts must drain stderr **while the command runs** so a human can approve every challenge, including retries; do not put short-lived codes/URLs in shared logs. Tokens, OAuth `device_code`, PKCE verifiers and raw token responses are not output. Authentication alone is not operation success: check the exit status before consuming JSON. The failure object is `{"error":{"code":"command_failed","message":"..."}}` with a useful diagnostic also on stderr, not a success-shaped result. Invalid `--output` does not select JSON mode; if stdout cannot be written, no complete JSON document can be guaranteed.

Success results include the selected `profile` and relevant identifiers; existing data-command JSON fields remain. In particular, `login -o json` reports `profile` and `authenticated: true`; `config init -o json` reports `profile`, `active` and `discovered`; OCM credential actions report `profile`, `provider: "ocm"`, `action`, `session_id` (plus `environment` when configured). JSON is a **result on stdout**, not merely a way to obtain stderr auth notifications. The interactive `session join -o json` and `session create --connect -o json` require a controlling terminal; ECS Exec shell I/O goes to `/dev/tty`, not result stdout. They emit their single success object **after** successful shell exit, with `status: "disconnected"`, `task_closed: false`, `investigation_closed: false`. Exec failure emits only the failure JSON, never an earlier success object. Disconnect does not stop the task or prove audit sync.

Without a controlling terminal, the default whole-command deadline is five minutes; with one there is no default whole-command deadline. An explicit positive `--timeout` applies to the entire invocation, including approval and an interactive shell. On expiry, cancel the local ECS Exec plugin/connection, not the underlying task. ECS RUNNING/STOPPED waiters have a separate ten-minute maximum; the earlier effective deadline wins. `--session-timeout` is **task lifetime**, not a CLI waiter: the default is one hour, CLI accepts whole seconds from zero through 24 hours, and Lambda policy controls the minimum (normally 30 seconds) and maximum (24 hours). Zero disables task expiry only if the deployment explicitly allows `TASK_TIMEOUT_MINIMUM=0`; a rejection is reported, not bypassed.

## Investigation lifecycle

| Command | Contract / relevant flags |
| --- | --- |
| `investigation create <cluster-id>` | Create a persistent EFS investigation workspace **without** a task. `--investigation-id` requests a specific ID; otherwise generate and report one. `--region` overrides the Boundary region; `-o json` returns profile, cluster/investigation IDs and access-point ID. |
| `investigation list` | List workspaces, including idle ones. Optional `--cluster-id` filters the ROSA cluster; `--efs-filesystem-id` and `--region` target the deployment store; `-o json` returns a profile and `investigations` array. |
| `investigation close <cluster-id> <investigation-id>` | Plan cleanup of the access point and associated task definitions; stored EFS files remain. `--dry-run` previews only; `--force` stops/waits for active or pending sessions; `--yes` skips confirmation, not plan validation. `--ecs-cluster`, `--efs-filesystem-id`, `--region` select deployment resources; `-o json` returns one plan on dry-run or a close result on success. Without `--yes`, a non-dry-run close needs a terminal. |

Text `investigation create` separates progress from the final success and gives a profile-qualified next command, for example:

```text
Investigation created.
Cluster: my-cluster
Investigation: incident-42
Access point ID: fsap-example

To create a session, run:
  rosa-boundary --profile "stage-east" session create "my-cluster" --investigation-id "incident-42"
```

Add `--region` to that suggestion only if needed to preserve an unsaved effective Boundary region. A Lambda error can have an unknown creation outcome; inspect before retrying rather than assuming no resource exists.

For `investigation close`, resolve the target and check the authenticated owner's immutable OIDC subject against the access-point owner tag. A dry-run shows the action set without mutation: profile, account, region, ECS cluster, EFS filesystem/access point, investigation IDs, sessions to stop or already stopping, and task definitions to deregister (JSON dry-run as one stdout object; text preview on stderr). Without `--force` or `--dry-run`, active sessions cause an error **before** the plan is displayed; use `--dry-run` to inspect it. Otherwise, a non-dry-run close shows the same plan before confirmation or mutation. Refuse ambiguous, incomplete or non-Lambda-managed targets. Re-resolve before mutation and abort if the plan changed; after forced stops, recheck for active tasks before deleting the access point. Concurrent AWS activity cannot be made atomic: return nonzero and identify partial cleanup if an action fails. Neither a preview nor success proves audit sync; verify audit evidence separately.

## Session lifecycle

`session --help` on the implementation branch includes these four illustrative workflows; placeholders require approved values before use:

```text
# New session and automatically generated investigation ID
rosa-boundary session create <cluster-id>

# New session in an existing investigation
rosa-boundary session create <cluster-id> --investigation-id <investigation-id>

# Fresh OCM credentials in an existing running session
rosa-boundary session credentials configure ocm <session-id>

# New session and investigation, then fresh OCM credentials
rosa-boundary session create <cluster-id> --with-credentials ocm
```

The OCM examples deliberately do not choose an environment: supply `--ocm-url` if local OCM configuration does not contain an approved URL. Credential injection cannot be paired with `--no-wait`; OCM may require a separate approval.

| Command | Contract / relevant flags |
| --- | --- |
| `session create <cluster-id>` | Create a task for a new or existing investigation. `--investigation-id` chooses the existing ID (otherwise generated); `--oc-version` defaults to `4.20`; `--session-timeout` defaults to `1h`. `--region` and `--ecs-cluster` target the Boundary deployment. By default wait for RUNNING; `--no-wait` reports a launch, **not** readiness. `--connect` opens an interactive shell only after readiness; `--with-credentials ocm` configures fresh credentials only after task and Exec agent readiness. `--no-wait` cannot combine with `--connect` or `--with-credentials`; `--ocm-url` and `--ocm-auth-flow` require `--with-credentials ocm`. |
| `session list` | List session ID, status, ROSA cluster, investigation and owner; `--status RUNNING|STOPPED|all` (default RUNNING), `--ecs-cluster`, `--region`; `-o json` returns a profile and `sessions` array. A list request is not credential-session auto-selection. |
| `session join <session-id>` | Join a running task through the local `session-manager-plugin`, defaulting to an SRE login shell. `--container` (default `rosa-boundary`), `--command`, `--no-wait`, `--ecs-cluster`, `--region` are available. Without `--no-wait`, wait for RUNNING if needed; in either case the Exec agent must be ready. A terminal is required even with `-o json`. Leaving the shell leaves task and investigation open. |
| `session close <session-id>` | Stop only the task, **not** the investigation. `--reason` defaults to `Investigation complete`; `--wait` waits for STOPPED, otherwise result is a stop request; `--yes` skips confirmation (required without a terminal); `--ecs-cluster`, `--region` select the target deployment. An already STOPPED task is an error with audit/cleanup guidance. |

On create success, the text result has a single summary after progress, then a copyable follow-up command, for example:

```text
Session created and RUNNING.
Cluster: my-cluster
Investigation: incident-42
Session ID: abc123

To join this session, run:
  rosa-boundary --profile "stage-east" session join "abc123"
```

The corresponding JSON success uses `status: "RUNNING"`; `--no-wait` uses `status: "launched"` and text says RUNNING has **not** been confirmed. For `--connect`, there is no success result before Exec succeeds and the shell disconnects; text says the task and investigation remain open, and JSON reports `disconnected` with both closed fields false. Text join suggestions retain only region/ECS override flags needed to target the same deployment. `--no-wait` suggests joining **once RUNNING**, not immediately.

A RUNNING wait, role assumption, credential configuration, Exec, deadline or output failure **after Lambda returned a task ARN** is nonzero; it includes the created session ID, investigation/cluster where known, profile and a profile-qualified `session close <session-id> --yes` cleanup command with target region/ECS cluster. It does not silently stop the task or print a success result. A task may already be STOPPED; inspect `session list --status all` if cleanup fails. A Lambda invocation error can have an unknown outcome; inspect the investigation/session before retrying. Credential failure may offer a fresh configure retry. No-wait success means only launch; do not infer RUNNING or completed credential injection.

Before `session close` confirmation, stderr shows separately labeled profile, account, region, session ID, ROSA cluster, investigation and owner, and states that the investigation remains open. JSON close success reports `status: "STOPPING"` with `waited: false` or `status: "STOPPED"` with `waited: true`. The container entrypoint **attempts** an S3 sync of non-credential workspace files on task shutdown; neither a stop request nor a STOPPED waiter proves CloudWatch/S3 evidence is complete. Verify audit separately before `investigation close`.

## Task-scoped OCM credentials

`session credentials configure ocm [session-id]` and `session credentials clear ocm [session-id]` affect the running Boundary task, not the workstation's OCM login. Configure requests fresh OCM access then injects it through a bounded ECS Exec helper; clear removes task-scoped OCM credentials and derived kubeconfig state. Both require a running task and ready Exec agent **when an ID is supplied**; `--ecs-cluster` and `--region` select the deployment. Configure also offers `--ocm-url` and `--auth-flow`. Neither command prints tokens. Stopping a task removes its task-scoped credentials; do not store credentials on persistent EFS home or in audit escrow.

Omitting the session ID is **discovery-only**, never permission to configure or clear automatically. After Boundary authentication, filter tasks in the selected ECS deployment by the authenticated immutable `sub` matching the `oidc_sub` owner tag and **actual** status `RUNNING` (not merely desired RUNNING; exclude tasks stopping). Missing/malformed ownership fails closed and other users' task metadata is not revealed. Zero eligible sessions produces guidance to create/select one; multiple eligible sessions directs the user to inspect their sessions and specify an ID. Exactly one shows its session ID, cluster, investigation and status plus a profile-qualified command to rerun **with** that ID; it still changes no credentials and acquires no OCM token. Suggestions retain effective unsaved region/ECS overrides; the unique-session suggestion also retains explicitly supplied auth-flow/device flags. A configure suggestion includes `--ocm-url` **only if supplied**; otherwise the subsequent actual configure uses normal local OCM URL selection. For example, with a uniquely eligible task:

```text
Session ID: "abc123"
Cluster: "my-cluster"
Investigation: "incident-42"
Status: RUNNING
No credentials were changed. To configure OCM credentials, run:
  rosa-boundary --profile 'stage-east' session credentials configure ocm 'abc123'
```

An omitted-ID `-o json` result has `status: "selection_required"`, `eligible_count`, `credentials_changed: false`, `profile`, `provider: "ocm"` and `action` (`configure` or `clear`). Only the unique-session case includes `session_id`, `cluster_id`, `investigation_id`, `session_status` and `suggested_command`; zero/multiple cases expose no candidate identifiers. This suggestion-only result is a successful discovery response, **not** successful credential mutation. With an explicit ID, successful JSON configure/clear results use `action: "configured"` / `"cleared"` and include `session_id` (and configured `environment`). A bad ID or failed authentication/transfer returns nonzero with the single failure JSON when JSON was selected.

Finally, normal Boundary CLI access needs neither existing workstation AWS credentials nor an AWS CLI. Independent CloudWatch and S3 audit verification does require separately authorized operator/audit-reader access in the correct account and region; task shutdown and investigation cleanup are distinct from that verification. These boundaries describe the draft implementation, not evidence of successful staging or production operation.
