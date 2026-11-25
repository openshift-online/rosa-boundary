# Environment readiness smoke test

Test both ways to start a Boundary session in one deployed region: start one in an existing investigation, then let session creation open a new investigation. Expect exactly two successful sessions. Read the Trusted Actions (TA) catalog from the second. Create and close resources **only in Boundary**. Do not log in to the target cluster or submit any Trusted Action, including a dry run.

**Before starting:** Have a terminal, the Session Manager plugin installed, and an SRE available for private Boundary and OCM sign-in prompts. Confirm the named profile (`$PROFILE`), account, region, approved test cluster (`$CLUSTER`), OCM environment (`$OCM`), and permission to create and clean up both disposable investigations and their sessions. Confirm whether TA is expected and which catalog action should be available. Workstation variables are not inherited by the joined shell.

These steps should generally take five minutes or less. Make the deliberate duplicate attempt in step 2 only once; never retry a create with an unknown outcome. Do not wait for expiry, renewal, or a reaper cycle.

### 1. Workstation: create the investigation first, then its session

```sh
INV_A="smoke-test-$(date +%s)"
rosa-boundary --profile "$PROFILE" config get
rosa-boundary --profile "$PROFILE" login
```

Check the saved account and region **before creating**; stop on mismatch or conflicting environment overrides.

```sh
rosa-boundary --profile "$PROFILE" investigation create "$CLUSTER" --investigation-id "$INV_A" -o json
rosa-boundary --profile "$PROFILE" session create "$CLUSTER" --investigation-id "$INV_A" \
  --with-credentials none --no-connect -o json
```

Require both results to name `$CLUSTER`, `$INV_A`, and the same `access_point_id`. Save the RUNNING `session_id` as `$SESSION_A`. Leave it running.

### 2. Workstation: verify a duplicate is refused

As the same user, attempt one more session **in the same investigation**:

```sh
rosa-boundary --profile "$PROFILE" session create "$CLUSTER" --investigation-id "$INV_A" \
  --with-credentials none --no-connect -o json
rosa-boundary --profile "$PROFILE" session list --status all
```

Require a nonzero exit **because this user already has a task for this investigation** (409 conflict), not an authentication error or timeout. In the list, `$SESSION_A` must still be RUNNING and the only session for `$CLUSTER`/`$INV_A`. If the duplicate succeeds or its outcome is unclear, fail the check, skip the next create, and clean up only confirmed run resources (step 5).

### 3. Workstation: let session creation make the investigation

```sh
rosa-boundary --profile "$PROFILE" session close "$SESSION_A" --wait --yes
rosa-boundary --profile "$PROFILE" session create "$CLUSTER" --with-credentials none --no-connect -o json
```

Confirm A is STOPPED before creating B. **Omit `--investigation-id`** and do not run `investigation create` again. Save the returned `investigation_id` as `$INV_B` and `session_id` as `$SESSION_B`. Require the intended cluster, `status: RUNNING`, and IDs distinct from A. Keep both ID pairs through cleanup.

```sh
rosa-boundary --profile "$PROFILE" investigation list --cluster-id "$CLUSTER"
rosa-boundary --profile "$PROFILE" session list --status RUNNING
rosa-boundary --profile "$PROFILE" session credentials configure ocm "$SESSION_B" --ocm-url "$OCM" -o json
rosa-boundary --profile "$PROFILE" session join "$SESSION_B"
```

Match B's IDs in the lists. Configuring OCM separately avoids automatic Backplane login during creation. Confirm credentials were configured for B and the intended OCM environment; expect a usable shell on join.

### 4. Inside session B: check the shipped client and deployed service

```sh
rta version -o json
rta --timeout 15s action list
rta --timeout 15s action describe <expected-action>
```

Replace `<expected-action>` with the agreed name. Require a client version, the expected action in the live catalog, and a matching description. Use the session's defaults: no `--server`, `--token`, or manual credential setup. If TA is intentionally not configured, check the version and mark the two API checks **not applicable**; if TA is expected, a missing endpoint or denied request is a failure. Discovery does not prove permission to execute an action.

Stop after catalog discovery; if listing fails, skip description. Disconnect with Ctrl-D and decline any close prompt so cleanup below is explicit.

### 5. Workstation: clean up both investigations, even after a failed check

For **each** investigation this run created (`$INV_A`, `$INV_B` if created), set `$INV` to its saved ID. For each of its confirmed sessions not already STOPPED, set `$SESSION` to that session ID and stop it. Skip the session command if only the workspace was created. Review and close each workspace separately.

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
