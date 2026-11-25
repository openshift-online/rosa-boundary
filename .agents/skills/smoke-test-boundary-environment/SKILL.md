---
name: smoke-test-boundary-environment
description: Runs the environment readiness runbook only when the user explicitly asks to smoke-test an already-deployed ROSA Boundary environment for general SRE use, such as “validate staging.” Uses the rosa-boundary CLI and in-session rta action list/describe reads without modifying a cluster. Not for verifying a PR, commit, or working-tree change, or for requests to plan or explain tests.
---

# Smoke-test a Boundary environment

Read the current [environment readiness runbook](../../../docs/runbooks/environment-readiness.md) in full on every invocation. Follow it for prerequisites, commands, checks, and cleanup. If it is missing or a step cannot be followed safely, report the blocker rather than substituting another procedure.

## Preflight before questions or resource creation

Run the bundled local, read-only preflight; do not reconstruct its checks:

```sh
bash <skill-directory>/scripts/preflight.sh --environment staging
```

Replace the environment with the requested deployment; pass `--region REGION` if the user specified one. The script selects by saved environment/region, including region-specific profiles such as `stage-us-east-1`, `prod-eu-west-1` and `devel-us-west-2`. Without a requested region, it selects the lexically first available region in that environment. It reports account/region/OCM, compares environment overrides without printing their values, and checks required saved settings, installed CLI close capabilities and Session Manager plugin. It does not sign in, change configuration or contact AWS/OCM.

If multiple profiles match the selected region, ask only which listed profile to use and rerun with `--profile NAME`. If the installed CLI is missing or lacks required flags (especially async-close `--status`), stop and tell the user what is missing and to run `make install-cli` from a local checkout, then rerun preflight. A `dev` version string alone does not establish capabilities. Do not install, rebuild or switch binaries as part of the smoke test; never modify the active profile.

Use the reported profile and OCM URL rather than asking for discoverable values. Confirm the resolved account and region against the requested deployment; ask only about missing approval or genuine ambiguity. Treat TA as expected unless the operator explicitly identifies it as intentionally absent.

Do not change running clusters, environments, or configuration without explicit user approval. Before creating anything, confirm approval covers creating and closing this run’s disposable Boundary resources in the named environment. A readiness request is not permission to edit a CLI profile, repair a deployment, or touch another investigation.

Keep the target cluster untouched: do not log in to it or submit a Trusted Action, including a dry run. If a check fails, report what was observed and follow the runbook’s cleanup guidance. Treat any proposed fix as a separate task requiring explicit approval.

## Execute the runbook, not an automated smoke-test wrapper

- Run `bash <skill-directory>/scripts/generate-cluster-id.sh` once and retain its output as the synthetic cluster ID for both investigations; do not discover a real cluster through OCM. OCM authentication for TA discovery is still required.
- Interpret “TA catalog” as `rta action list` and `rta action describe get`, never `rta catalog` or `rta action run get`. No expected-action question is needed.
- Keep a ledger of the selected CLI/profile, cluster, and A/B investigation, session and access-point IDs as they are returned. Shell variables do not persist across separate tool calls; explicitly supply saved values without guessing IDs.
- Run the actual CLI steps individually and interpret their results. Capture exit status before parsing JSON; use `set -o pipefail` for pipelines and do not interpret failed authentication as empty data. Handle the deliberate duplicate's expected nonzero exit explicitly.
- Use the bounded PTY helper below for the runbook's join/in-session commands from a headless shell; do not infer attachment failure from the workstation's TTY state.
- On failure or unknown create outcome, stop new creates, reconcile exact run resources using lists, and perform scoped cleanup. Never retry an uncertain create, close unrelated resources, edit verification tags, or force cleanup.
- For current async close, a missing receipt in the preview does not prevent submitting the normal close request. Review identity/scope, submit, and check status once. Distinguish rejected, accepted/pending, and completed; do not wait for a reaper cycle in this runbook.

## Run one in-session command through a PTY

Use Linux and Python 3 (standard library only). After configuring OCM for B, run each command separately against the saved B task ID:

```sh
python3 <skill-directory>/scripts/session-command.py --profile "$PROFILE" --session "$SESSION_B" --timeout 60 -- rta version -o json
python3 <skill-directory>/scripts/session-command.py --profile "$PROFILE" --session "$SESSION_B" --timeout 60 -- rta --timeout 15s action list -o json
python3 <skill-directory>/scripts/session-command.py --profile "$PROFILE" --session "$SESSION_B" --timeout 60 -- rta --timeout 15s action describe get -o json
```

Interpret each result before running the next; skip description if listing fails. If TA is intentionally absent, run only version. Keep the shell tool's timeout above the helper's deadline plus its three-second shutdown allowance (for example, 75 seconds). The helper joins the existing task through the installed CLI, runs one allow-listed command as `sre` in an interactive login shell, and disconnects. It never creates resources, configures credentials, retries commands, stops tasks, or requests close. CLI JSON mode suppresses the exit-close prompt; no terminal input or approval answers are injected.

Require helper exit 0, `outcome: completed`, and `command_exit_status: 0`; inspect `output` using the runbook's assertions. `join_exit_status` alone does not prove command success. Treat timeout, interrupted, unverified, or output-limit results as incomplete; retain exact IDs, do not replay an unknown-outcome command, and proceed to scoped runbook cleanup. A forced local disconnect does not prove remote command termination or task cleanup. Report `diagnostics` without publishing authentication material. Do not replace this helper with `script`, blind piped input, direct AWS execution, or an end-to-end wrapper.

## Report

Give the environment and run IDs, the result of each check (passed, failed, blocked, or not applicable), and the cleanup disposition for each resource. Identify anything still open and who needs to follow up. Omit tokens, approval codes, transcripts, and customer data. Report only what the smoke test established; it does not verify audit delivery, workspace persistence, cross-user isolation, or timeout enforcement.

Report task STOPPED separately from investigation close requested/completed. Pending accepted closure is not a confirmed close or, by itself, a service bug. Use the requester as the default follow-up owner unless they name another; include the exact executable/profile/IDs/status command for pending work. For rejected, retained or cleanup-incomplete results, include the error or phase/reason/retryability and what remains. Do not claim general readiness if required join/TA checks were blocked. Describe observed errors separately from suspected causes; do not turn diagnosis into an unapproved repair.
