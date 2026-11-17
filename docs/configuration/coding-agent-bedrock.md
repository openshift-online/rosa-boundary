# Coding agents on Amazon Bedrock

The image includes Claude Code, pi, OpenCode and Codex. Pi's search dependencies
`fd` 10.5.2 and ripgrep (`rg`) 15.2.0 are installed on PATH. Both are pinned,
architecture-specific upstream musl builds (release lookup: 2026-11-17).
Ripgrep is verified against its published release checksum file; fd, which
publishes no checksum file, is verified against the GitHub-published asset
SHA256 digests pinned for AMD64 and ARM64 in `Containerfile`. Update fd's pin and
both hashes together. Search-tool version updates are manual; the image's offline
acceptance checks enforce executable architecture and exact versions. Neither
search tool is added to the separate six-tool SRE inventory.

The UBI `procps-ng` runtime package supplies `ps` for agent app-server process
tracking. Image acceptance checks process lookup as the unprivileged runtime
user, in addition to version and search-tool probes.

All four coding agents can use the
short-lived ECS task-role credential chain; no API key, AWS credentials file,
login token or proxy is needed. Do not run provider login or save credentials
under the persistent `/home/sre` workspace, which is included in audit escrow.

The entrypoint runs `rosa-boundary-agent-defaults.py` as `sre` to initialize:

| Agent | Configuration | Default |
|---|---|---|
| Claude Code | Existing `CLAUDE_CODE_USE_BEDROCK=1`, `ANTHROPIC_MODEL` task environment | Deployment-approved Claude model |
| pi | `~/.pi/agent/settings.json` | `defaultProvider: amazon-bedrock`, `defaultModel` from `ANTHROPIC_MODEL` |
| OpenCode 2.x | `~/.config/opencode/opencode.json` | `model: amazon-bedrock/<ANTHROPIC_MODEL>`, native provider region |
| Codex 0.169.0 | `~/.codex/config.toml` | Native `model_provider = "amazon-bedrock-runtime"`, AWS SDK authentication and region |

`AWS_REGION` is set in the task definition so ECS Exec processes receive it too;
exports in the entrypoint alone do not reach an independently started Exec shell.
The initializer uses `AWS_DEFAULT_REGION`, then `us-east-1`, if `AWS_REGION` is
unset. Pi uses its standard AWS SDK region configuration.

**Codex uses Bedrock's Responses-compatible API, not Converse or Anthropic
Messages.** Do not reuse `ANTHROPIC_MODEL` for Codex. With no explicit model,
the initializer warns and does not create Codex configuration: the upstream
Runtime default can select global routing regardless of `AWS_REGION`. Set regional Terraform
`codex_default_model` (default empty), passed as `BOUNDARY_CODEX_BEDROCK_MODEL`
in the task environment before initialization, to select a separately approved,
Responses-compatible Bedrock Runtime model. The current personal dev deployment
selects `us.openai.gpt-6.1-sol`. For an existing home whose config is preserved,
select explicitly with `codex --model us.openai.gpt-6.1-sol` while using the
`amazon-bedrock-runtime` provider.
Availability, model agreements, IAM and endpoint policies must be checked for
that model; Claude access alone does not prove Codex inference will work. This
change does not subscribe the account to more models or broaden IAM policies.

Initialization creates only absent configuration files, with mode 0600. Existing
files (including OpenCode JSONC), even malformed ones, are preserved, as are
user-selected providers/models. Existing configurations therefore require an
explicit user edit to switch providers. Changes to deployment defaults do not
overwrite a previously initialized home. A missing `ANTHROPIC_MODEL` emits a
warning and skips pi/OpenCode initialization rather than inventing a model.
The helper honors `PI_CODING_AGENT_DIR`, `XDG_CONFIG_HOME` and `CODEX_HOME`.

Seeding errors warn independently for each agent and do not block other agents
or container startup; existing personal settings remain unchanged.

`BOUNDARY_AI_USE_BEDROCK=0` disables initialization without deleting settings.
When unset or empty, it follows `CLAUDE_CODE_USE_BEDROCK` (default `1`). Explicit `1`
enables initialization even when Claude's switch is disabled. These are startup
defaults, not an enforcement boundary: project configuration and CLI options can
override provider selection. Use IAM and network controls for enforcement.

## Model-access onboarding

Complete the [Bedrock model-access approval gate](../runbooks/bedrock-model-access.md)
before testing agents. Anthropic first-use form submission, model activation,
propagation and actual inference are separate checks. Account operators approve
terms; investigation tasks must not self-subscribe. An IAM-looking Marketplace
error can persist during activation propagation even when the operator's policy
allows the actions. Do not broaden task permissions as a workaround.

## Regional model selection

The shared US default for Claude Code, pi and OpenCode is
`us.anthropic.claude-sonnet-5-5` (Sonnet 5.5), selected after
a successful user-run pi inference test. Codex retains its separate Responses-compatible model. The default does
not activate or subscribe to a model: an account operator must complete the
Anthropic first-use form and review any required model agreement. Catalog
availability alone does not establish working inference. Runtime task roles do
not receive Marketplace subscription permissions.

Existing HCP workspace pins and model-agreement manifests are not changed
automatically. Review those together through the normal PR and HCP plan process
before changing staging or production.

Read-only inventory checks on 2026-11-17 found the following ACTIVE profiles:

| Source region checked | Claude Sonnet 5.5 | Codex GPT-6.1 Sol |
|---|---|---|
| `us-east-1` | `us.anthropic.claude-sonnet-5-5` | `us.openai.gpt-6.1-sol` |
| `eu-west-1` | `eu.anthropic.claude-sonnet-5-5` | `global.openai.gpt-6.1-sol` |
| `ap-southeast-1` | `global.anthropic.claude-sonnet-5-5` | `global.openai.gpt-6.1-sol` |

This is inventory evidence in the personal dev account, not proof of model
inference, target-account access, or availability in every European/Asian
region. No APAC-scoped Sonnet 5.5 or EU/APAC-scoped GPT-6.1 Sol profile appeared
in those checked regional inventories. Do not invent a prefix or silently use
global routing: it can process prompts outside the deployment's geography.
Obtain residency approval and verify the exact target region/account, task-role
permissions, SCPs and endpoint policies before choosing a global profile.
Terraform rejects US profiles in non-US regions, and EU Claude profiles outside
EU regions; this guard is not a complete AWS support matrix. Non-US deployments
must explicitly select supported, approved model profiles. An empty Codex model
skips Codex initialization. Set an approved profile explicitly before using
Codex; manually launching it without one can still use upstream global defaults.

To select the shared test model in an already-running US session:

```bash
claude --model us.anthropic.claude-sonnet-5-5
pi --provider amazon-bedrock --model us.anthropic.claude-sonnet-5-5
```

For OpenCode, select `amazon-bedrock/us.anthropic.claude-sonnet-5-5`.

The new task definition does not change existing processes or persisted pi and
OpenCode settings. Select the new model explicitly in those tools when reusing
an initialized investigation home.

## Codex denied on `project/default`

Bedrock Runtime's OpenAI-compatible `/openai/v1/responses` path also authorizes
`bedrock:InvokeModel` on the source region/account's `project/default` resource.
A model or inference-profile grant alone is insufficient. A denial saying
"no VPC endpoint policy allows" this action is an authorization-policy failure,
not a reason to replace task-role credentials or run provider login.

Both the task-role Bedrock inline policy and the Bedrock Runtime endpoint policy
include a separate `InvokeDefaultProjectResponses` statement. It grants only
`bedrock:InvokeModel` on the exact regional/account `project/default` ARN. The
endpoint statement retains the exact task-role principal; existing model/profile
grants remain unchanged. No project wildcard, project-management action, endpoint
bypass, or subscription permission is added. Tests check east/west region scope,
principal and the exact allowed action/resource.

These are authorization-policy changes: review and approve the owning regional
Terraform plan before applying. They do not require an image rebuild. Existing
sessions can retry after the policies propagate; no task restart is needed solely
for this policy repair. A passing mock test does not prove a live model response,
SCP compatibility, or Responses API audit-log coverage.

## Verification and rollout

Run `make test-github-dl`, `bats tests/shell/entrypoint.bats` and ShellCheck on
`entrypoint.sh`. Build through `make build-amd64`, then run
`make verify-image-tools TOOL_IMAGE=<built-image>`. Agent `--version` probes
prove binaries start, not that inference is authorized. Offline tests can verify
configuration parsing without using real credentials or sending prompts.

Roll out the image and task environment together, then create a new session;
existing sessions do not acquire these settings. Real inference requires a
separately approved live test. Do not use customer data for test prompts.

## Upstream references for the pinned versions

- [pi 1.5.2 providers](https://github.com/earendil-works/pi/blob/v1.5.2/packages/coding-agent/docs/providers.md)
  and [settings](https://github.com/earendil-works/pi/blob/v1.5.2/packages/coding-agent/docs/settings.md)
- [OpenCode Bedrock setup](https://opencode.ai/docs/providers/#bedrock)
  and [2.3.0 provider configuration](https://github.com/anomalyco/opencode/blob/v2.3.0/packages/core/src/config/plugin/provider.ts)
- [Codex 0.169.0 built-in Bedrock providers](https://github.com/openai/codex/blob/rust-v0.169.0/codex-rs/model-provider-info/src/lib.rs)
  and [native AWS authentication](https://github.com/openai/codex/blob/rust-v0.169.0/codex-rs/model-provider/src/amazon_bedrock/auth.rs)
