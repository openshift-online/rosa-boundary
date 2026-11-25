# CLI Authentication Model

The CLI uses a Boundary OIDC ID token from the **selected named deployment profile** to assume temporary AWS roles; it does not require existing workstation AWS credentials. Consult [`internal/cmd/cli.go`](../../internal/cmd/cli.go), [`internal/config/profiles.go`](../../internal/config/profiles.go), [`internal/auth/token.go`](../../internal/auth/token.go), and [`internal/aws/sts.go`](../../internal/aws/sts.go) for implementation. The [user access guide](../runbooks/user-access-guide.md) covers setup.

## Profile setup and identity

1. `rosa-boundary config init --name <name> --account-id <account> --region <region>` bootstraps a profile. Auto-discovery authenticates to the specified OIDC provider, assumes the derived invoker role, and asks Lambda for deployment settings. It does **not** inherit an existing profile or ambient deployment settings. `--auto-discover=false` collects all required settings from flags or prompts without authenticating. Bootstrap uses device mode only if `--use-device-code=true` is explicitly passed; it saves that preference. The account, region, issuer, and role accounts are checked against discovery responses before saving. See [`internal/cmd/config_commands.go`](../../internal/cmd/config_commands.go).
2. Profiles are saved in `${XDG_CONFIG_HOME:-$HOME/.config}/rosa-boundary/config.yaml`. The parser validates only the named-profile schema; other shapes fail ordinary config validation. If you have an old flat file, delete or move it and run `config init` to create profiles from scratch—there is no migration. `config list-profiles`, `config use-profile`, and `config get` are offline. `config get` reads saved YAML, not environment overrides or runtime defaults. An explicit `--profile` selects one saved profile per invocation; otherwise the active profile is used. No environment variable selects the profile.
3. `rosa-boundary login` obtains or reuses an ID token for the selected profile's issuer and client, cached under `XDG_CACHE_HOME`; `login --force` requests fresh authentication. Browser authorization-code PKCE is the default; the device flow shows a URL and user code on stderr for human approval, with no local browser callback. Cached tokens are reused until shortly before JWT expiry when valid for that issuer and client. STS rejection of a cached token can prompt a fresh login in the selected flow during **any** authenticated operation, without silently switching to another flow. A cached ID token is not a standing AWS access key.

## AWS roles and ABAC

`investigation create` and `session create` assume the Lambda-invoker role through `AssumeRoleWithWebIdentity` and call Lambda with temporary SigV4 credentials; Lambda validates identity, group membership and ABAC claims before creating resources. `session create` subsequently assumes the SRE role to wait for or join the ECS task. Investigation listing and close preview use the SRE role; close requests and status use the Lambda-invoker role. The CLI does not export these credentials to the user's shell. The shared *role* issues distinct temporary sessions, not shared credential material. `session join` hands ECS Exec to the workstation's `session-manager-plugin`.

AWS STS derives session tags from the token's `https://aws.amazon.com/tags` claim when the role trust permits tagging. IAM compares the principal tag with the ECS task tag under the deployment's configured ABAC key; **do not assume that key is `username`**. A missing or mismatched claim can prevent role assumption or ECS Exec. See [system architecture](overview.md), current IAM policies, and Lambda tests for the deployment-specific configuration. The close service checks the caller's Boundary authorization, not the access point creator's identity. No shell may be attached when it accepts a close request. This service check is not an IAM owner constraint on other AWS clients. See [investigation workflow](../runbooks/investigation-workflow.md#phase-6-close-investigation).

Task identity is the current task creator's identity; the reused EFS access point retains its original creator tags. Handover creates a replacement task, not permission to join the predecessor's task. See [actual tags and creator-versus-actor semantics](session-lifecycle.md#actual-resource-tags-creator-versus-actor) and [handover](session-lifecycle.md#handover-is-replacement-not-joining-another-users-task).

## Flow selection and headless approvals

For ordinary authenticated commands, explicit `--use-device-code=true|false` (bare flag means true) overrides `ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE`, then the selected profile's saved `oidc_use_device_code`, then default `false`. Invalid booleans fail. The `config init` bootstrap exception is described above. This flag selects a flow, not an issuer or an unattended credential.

Boundary uses an OIDC **ID token** for STS and Lambda. `session create` configures a **fresh OCM access token** by default (equivalent to `--with-credentials ocm`); `--with-credentials none` opts out. `session credentials configure ocm` retries configuration on a running task. After OCM is configured, `session create` also runs `ocm backplane login <cluster-id>` in the task before connecting; failure warns with retry and cleanup commands (JSON `backplane_login: false`) and is skipped with `--with-credentials none`, `--no-wait`, or an OCM failure. OCM tokens are injected into task-scoped, audit-excluded storage rather than EFS home or the Boundary token cache. OCM follows the same device preference by default; `--ocm-auth-flow auth-code|device` on create and `--auth-flow auth-code|device` on configure override **OCM only**. Explicit `auth-code` requires a browser callback even if Boundary uses device mode. One create command may need two separate human approvals; a cached Boundary ID token cannot replace OCM approval. `session create --no-wait` skips injection and warns with a follow-up command; explicitly combining `--no-wait` and `--with-credentials ocm` is rejected.

An attached `session create` schedules OCM renewal only after a confirmed initial
upload with a usable expiry and online refresh grant. An older helper
automatically gets the original one-shot request, without renewal.
Use `--no-ocm-renewal` to explicitly configure once,
`--with-credentials none` to skip all OCM authorization, or `--no-connect` to
configure once without attaching. Plain `session join` never replaces existing
credentials. `session join <session-id> --renew-ocm` explicitly authorizes and
replaces the task token before opening the default `rosa-boundary` login shell;
it cannot be used with another container, custom command, or `--no-wait`.

On create and opt-in join, explicit `--ocm-url` takes precedence over
`ROSA_BOUNDARY_OCM_URL`, the selected profile, and the URL-only local OCM
configuration fallback. Explicit `--ocm-auth-flow auth-code|device` overrides
the effective Boundary device preference (flag, environment, then profile) for
OCM only. The CLI reports when it cannot schedule renewal. On refresh rejection
or an unconfirmed replacement, the shell stays open and the CLI offers a
profile-qualified one-shot configure command. Renewal never switches OCM flows
or automatically requests fresh OCM approval. New helper connections may require
separate Boundary sign-in when STS credentials approach expiry. The CLI budgets
for that sign-in before exchanging the OCM grant, and configures only once if
the initial token lifetime is too short for renewal. Scheduled and
successful renewals are silent by default; use `--verbose` to see their status.
Approval prompts and failure warnings still go to local stderr and may interrupt
the shell display. Use one-shot configuration if uninterrupted full-screen
terminal output is required.

## Human-approved authentication and JSON output

Every auth-bearing leaf offers `-o json` / `--output json`. Authentication guidance is human-readable **stderr**, not a machine-readable event API. Device approvals display the verification URL and user code on stderr even with `-o json`; browser authorization guidance remains on stderr. Tokens, OAuth `device_code`, PKCE verifiers, and raw token responses are not printed. Monitor stderr **while the process runs** to approve each challenge, including an STS retry. Treat URLs/codes as sensitive operational output and share them privately, never in shared CI logs. Check the process exit status before acting on any result: completing authentication does not mean the command succeeded. See the [script-driven example](../runbooks/user-access-guide.md#script-driven-human-approved-login).

Every leaf offering `-o json` emits exactly one JSON object on stdout, including on failure. A failed command exits nonzero and returns `{"error":{"code":"command_failed","message":"..."}}` instead of a success-shaped result. The code is stable; the message is the actionable CLI error also shown on stderr (and may include usage or cleanup guidance). Parse stdout as one document, then check exit status before using any success fields. Invalid `--output` values do not select JSON mode, so they retain text error behavior. If stdout itself cannot be written, a complete JSON object cannot be guaranteed. Existing success data-command fields are retained. `login` returns `profile` and `authenticated`; `config init` returns `profile`, `active`, and `discovered`. OCM credential commands return `profile`, `provider`, `action`, `session_id` (and `environment` for configure). With no credential session ID, discovery returns `status: selection_required`, `eligible_count`, and `credentials_changed: false`; only a unique owned RUNNING session adds its identifiers and `suggested_command`. No OCM token is obtained and no credentials are changed on this path.

Interactive `session join -o json` and `session create -o json` require a controlling terminal: ECS Exec shell I/O uses `/dev/tty`, never JSON stdout. The single success result is emitted **after** successful shell exit, with `status: disconnected`, `task_closed: false`, and `investigation_closed: false`. Disconnecting does not close the task or investigation. If Exec fails, only the failure JSON is emitted (no success JSON); a failed create reports the created session ID and cleanup command in both the failure message and stderr. OCM configuration failure after launch instead warns on stderr with the session ID, retry and cleanup commands and returns a successful session result; JSON includes `warnings` and omits `credentials` when injection was not confirmed. `session create --no-wait -o json` returns `status: launched` (not RUNNING), omits `credentials`, and includes a warning with the configure command; waiting for readiness returns `status: RUNNING`. Check process exit status and warnings before consuming any result.

## Timeouts and audit access

Without a controlling terminal, commands have a default five-minute whole-command deadline; with a terminal there is no default deadline. Explicit `--timeout <duration>` applies to the whole invocation (including human approval and interactive ECS Exec). On expiry the local Exec plugin/connection is canceled, **not** the underlying task. ECS RUNNING/STOPPED waiters cap at ten minutes. `session create --session-timeout` is a separate shell-less task age threshold: CLI default **1h**, not Terraform's **8h** omitted-request default. CLI accepts whole seconds from 0 through 8h, but Lambda's default 30-second minimum rejects zero. Explicit global `--timeout 0s` is invalid. See the [CLI/Terraform/Lambda/SSM timeout matrix](session-lifecycle.md#timeout-matrix) for zero, minimum, reaper and connection semantics. At eight hours of task age, a shell no longer exempts the task from reaping. After a task is created, later failures return its ID and a profile-qualified cleanup command; no implicit stop or audit success is implied.

Independent `aws logs` and `aws s3` retrieval requires an AWS CLI and a separately authorized operator/audit-reader identity in the correct account and region. Neither is required for ordinary Boundary CLI operations. See [Verify Audit Evidence](../runbooks/investigation-workflow.md#verify-audit-evidence).
