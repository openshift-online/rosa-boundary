# Environment readiness smoke test

Test both ways to start a Boundary session in one deployed region: start one in an existing investigation, then let session creation open a new investigation. Expect exactly two successful sessions. From the second session, use the shipped `rta` client to list Trusted Action (TA) definitions and describe the built-in `get` definition without executing it. Create resources **only in Boundary**, stop both tasks, and request asynchronous closure of both investigations. A requested close is not a completed close. Do not log in to a cluster or submit any Trusted Action, including a dry run.

**Before starting:** Have your Boundary CLI profile (`$PROFILE`), account, region, OCM URL (`$OCM`), terminal and Session Manager plugin ready. Be ready to complete private Boundary/OCM sign-in and ensure you have permission to create, stop and request close for both disposable investigations/sessions. Expect TA unless it is intentionally absent from this deployment. Workstation variables are not inherited by the joined shell.

Set `$CLUSTER` to a valid cluster ID if you have one. Otherwise, an arbitrary value such as `smoke-test-$(date +%s)` is accepted for session/investigation creation. Actions performed with `rta` against a cluster within a session require a valid cluster ID; this runbook only lists and describes action definitions.

Make the deliberate duplicate attempt in step 2 only once; never retry a create with an unknown outcome. Do not wait for expiry, renewal, or a reaper cycle. Record each returned investigation/session/access-point ID immediately; retain both sets for cleanup. Check each command's exit status before parsing output. For pipelines, enable `set -o pipefail`; authentication errors or null fields are not successful empty results.

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

### 4. Inside session B: list and describe TA definitions

```sh
rta version -o json
rta --timeout 15s action list -o json
rta --timeout 15s action describe get -o json
```

Check successful exit codes and a client version. The list's JSON array must contain `name: get`, `scope: kube-api`, `type: read`; the description object must identify the same action with its parameter definitions (including `resource` and `version`). No exact catalog size or description wording is required. **Do not use `action run get`**, even though `get` has type `read`.

Use the session's defaults: no `--server`, `--token`, or manual credential setup. If TA is intentionally absent, check the version; the two API checks are **not applicable**. Otherwise, a missing endpoint or denied request is a failure. Discovery does not prove permission to execute an action.

If listing fails, skip description. Disconnect with Ctrl-D and decline any close prompt so cleanup below is explicit.

### 5. Workstation: stop tasks and request close for both investigations, even after a failed check

For **each** investigation this run created (`$INV_A`, `$INV_B` if created), set `$INV` to its saved ID. For each of its confirmed sessions not already STOPPED, set `$SESSION` to that session ID and stop it. Skip the session command if only the workspace was created. Review and request close for each workspace separately.

```sh
rosa-boundary --profile "$PROFILE" session close "$SESSION" --wait --yes
rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER" "$INV" --dry-run
```

If the stop wait expires, check `session list --status all` for the exact session. Confirm STOPPED and inspect the dry-run plan's cluster, investigation, access point and task identities before submission: close only this run's workspace. If the stop is uncertain or the identity/scope does not match, retain the workspace and report the blocker.

**Do not require a pre-existing verified receipt before requesting async close.** A preview may report a missing seal, audit bucket tag or receipt because the close service has not produced it yet. This is not, by itself, a submission blocker. Submit the normal request; let the service enforce holds, authorization and verification. Never add tags, fabricate receipts or force cleanup:

```sh
rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER" "$INV" --yes
rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER" "$INV" --status
```

If creation was interrupted or returned no ID, use `session list --status all` and `investigation list --cluster-id "$CLUSTER"` on the same profile to locate the exact run; never guess, force close, or close all sessions. On an unknown close submission outcome, look up status rather than blindly resubmitting.

Check status once; do not wait for a reaper cycle. A STOPPED task does not mean its investigation is closed:

| Result | Disposition |
| --- | --- |
| Request rejected | Cleanup failed/blocked; the error identifies why |
| Accepted, queued, waiting or verifying | Close requested; completion pending, not a confirmed close or evidence of a bug by itself |
| Completed | Service reports close completed; this runbook still does not independently verify audit delivery |
| Retained or cleanup incomplete | Inspect phase, reason, retryability and remaining resources; do not bypass guards |

If closure is pending, keep both investigation IDs and use the status command above to follow through after the scheduled reaper runs. You remain responsible for checking completion or arranging follow-up. These checks do not independently verify audit delivery, persistence, cross-user isolation or timeout enforcement.
