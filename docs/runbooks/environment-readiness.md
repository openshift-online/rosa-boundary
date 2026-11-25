---
updated_at: 11-25-2026
created_at: 11-25-2026
---
# Environment readiness smoke test

Can an SRE start a fresh Boundary session, read the Trusted Actions (TA) catalog from it, and clean up? Test one deployed region with one disposable investigation. Create and close resources **only in Boundary**. Do not log in to the target cluster or submit any Trusted Action, including a dry run.

**Before starting:** Have a terminal, the Session Manager plugin installed, and an SRE available for private Boundary and OCM sign-in prompts. Confirm the named profile (`$PROFILE`), account, region, approved test cluster (`$CLUSTER`), OCM environment (`$OCM`), and permission to create and close one disposable investigation. Confirm whether TA is expected and which catalog action should be available. Substitute these values in the commands; workstation variables are not inherited by the joined shell.

These steps should generally take five minutes or less. Do not retry session creation or wait for expiry, renewal, or a reaper cycle.

### 1. Workstation: open and join one session

```sh
INV="smoke-test-$(date +%s)"  # Generate once; keep this value through cleanup.
rosa-boundary --profile "$PROFILE" config get
rosa-boundary --profile "$PROFILE" login
rosa-boundary --profile "$PROFILE" session create "$CLUSTER" --investigation-id "$INV" \
  --with-credentials none --no-connect -o json
```

Check the saved account and region **before creating**; stop on mismatch or conflicting environment overrides. Save `session_id` as `$SESSION`. Require the intended cluster and investigation and `status: RUNNING`. Configure OCM in the running task as a separate step so creation doesn't initiate Backplane login.

```sh
rosa-boundary --profile "$PROFILE" investigation list --cluster-id "$CLUSTER"
rosa-boundary --profile "$PROFILE" session list --status RUNNING
rosa-boundary --profile "$PROFILE" session credentials configure ocm "$SESSION" --ocm-url "$OCM" -o json
rosa-boundary --profile "$PROFILE" session join "$SESSION"
```

Match the investigation and session IDs in the lists, confirm credentials were configured for that session and OCM environment, and expect a usable shell on join.

### 2. Inside that session: check the shipped client and deployed service

```sh
rta version -o json
rta --timeout 15s action list
rta --timeout 15s action describe <expected-action>
```

Replace `<expected-action>` with the agreed name. Require a client version, the expected action in the live catalog, and a matching description. Use the session's defaults: no `--server`, `--token`, or manual credential setup. If TA is intentionally not configured, check the version and mark the two API checks **not applicable**; if TA is expected, a missing endpoint or denied request is a failure. Discovery does not prove permission to execute an action.

Stop after catalog discovery; if listing fails, skip description. Disconnect with Ctrl-D and decline any close prompt so cleanup below is explicit.

### 3. Workstation: clean up even after a failed check

```sh
rosa-boundary --profile "$PROFILE" session close "$SESSION" --wait --yes
rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER" "$INV" --dry-run
```

If the stop wait expires, check `session list --status all` for the exact session. Proceed only if the task is STOPPED and the plan matches this run with no finalization block. Otherwise retain the workspace and hand off the blocker. For a CLI supporting asynchronous close:

```sh
rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER" "$INV" --yes
rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER" "$INV" --status
```

Confirm the task stopped and inspect the dry-run plan **before** submitting: close only this run's workspace. If creation was interrupted or returned no ID, use `session list --status all` and `investigation list --cluster-id` on the same profile to locate the exact run; never guess, force close, or close all sessions. An accepted request is not a completed close. Check status once; hand pending or uncertain cleanup to a named operator with the profile, IDs and status command.

**Report:** Give the environment, run IDs, pass/fail/blocked/not-applicable per check, and cleanup disposition. Omit tokens, approval codes, transcripts and customer data. This is a readiness check, not evidence of audit delivery, workspace persistence, cross-user isolation or timeout enforcement.
