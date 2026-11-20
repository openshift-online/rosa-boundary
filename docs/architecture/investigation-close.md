# Automated investigation close

How an investigation stops being open, who is allowed to ask for that, and what
the resulting receipt does and does not prove.

This describes implemented behaviour. Verify consequential details against the
code it names — `lambda/create-investigation/close_requests.py`,
`lambda/reap-investigations/`, `internal/cmd/close_investigation.go` and
`internal/cmd/session_close_hook.go` — and their tests.

## The shape of it

Closing an investigation is a request, not a command. An authenticated SRE asks
the close service to close a workspace; the scheduled investigation reaper does
the work and is the only component that may seal, drain, copy, verify, publish a
receipt or delete anything.

```
SRE (CLI)                 create-investigation Lambda        reap-investigations Lambda
  investigation close ──▶  authenticate (OIDC + groups)
  session exit prompt      apply the authorization matrix
  --auto-close             record an immutable request  ──▶   (on its schedule)
                           answer status questions             revalidate authorization
                                                               seal, drain, copy
                                                               verify independently
                                                               publish receipt
                                                               clean up, record status
```

Three things follow from that split:

* an SRE's request can never double as its own audit evidence, because the
  request handler cannot write evidence;
* losing the CLI loses nothing — the request is persisted before the CLI is
  told it was accepted, and the schedule is the recovery path; and
* **accepted is not closed.** Every status surface keeps those distinct.

No database, workflow service, admission protocol or attachment heartbeat is
involved. The storage is the audit bucket that already exists.

## Who may close

An investigation has one current owner at a time. Ownership is transferable by
handover and is *not* conferred permanently by having created the workspace:
the access point's `oidc_sub` tag is recorded for provenance only.

| Observed state | Who may request seal/close |
| --- | --- |
| Held by SRE A | A only. Another SRE — including whoever created it — may not close A's investigation while A holds it. |
| Handed over from A to B | B only. A's earlier request and auto-close intent are superseded, not inherited consent. |
| No active sessions | Any authenticated SRE authorized to use Boundary. No creator match and no handover is required to close an idle investigation, and a task left running does not reserve it for whoever launched it. |
| Incomplete, contradictory or unavailable | Unknown. Nobody may close; the request is deferred and retried. Unknown is never treated as idle. |

### What "held" is observed from

Two service-side signals, which answer different questions:

* the active SSM sessions attached to the investigation's tasks — **this is
  what decides who holds it**; and
* the non-terminal ECS tasks themselves, whose `oidc_sub` tag records the SRE
  each task was launched for.

The task tag is provenance, reported as `task_owner_subs`, and never authority:

* a RUNNING task is **not** proof that a shell is attached. An investigation
  whose SRE detached but whose task is still running is **idle**, and any
  eligible SRE may request its close.
* reading a running task as "held" would be worse than wrong, it would be
  unclearable: the SRE who walked away would hold an exclusive claim that
  nobody else could release, which is exactly the creator-forever rule this
  design rejects.
* having launched a task confers no more authority than having created the
  workspace.

Anything that could not be read completely is `unknown`: a scan that failed, a
description that came back short, a non-terminal task with no owner tag or no
session target — where "no session attached" cannot be distinguished from "not
observed" — or two SREs attached at once.

Idle is not a licence to destroy anything. Idle widens who may *ask*; it does
not stop a task, and the finalizer still refuses to measure, copy or delete a
workspace while any task is non-terminal. See the stop-consent table below.

The matrix is enforced twice: once by the request handler when a request is
recorded, and again by the reaper immediately before it mutates anything. The
two implementations are packaged in different artifacts, so
`tests/unit/test_close_authorization_contract.py` drives both with identical
fakes and requires identical verdicts.

### Authorization is not consent to stop tasks

Being allowed to close is separate from being allowed to stop someone's work:

| Stop scope | Meaning |
| --- | --- |
| `none` | Stop nothing. While any task is non-terminal the close waits. This is the default for `investigation close`. |
| `session_task` | Stop only the named tasks. Other tasks keep the close waiting. This is what the exit prompt and `--auto-close` ask for. |
| `investigation` | Stop every task of the investigation. `investigation close --force` and `--auto-close-stop-all` ask for this. |

This is what makes an idle investigation with a running task safe: any
eligible SRE may request its close, the request is recorded and the workspace
is sealed, but the task keeps running and the close waits until that SRE
explicitly consents to stopping it. The scheduled stale sweep carries no human
consent at all, so it never seals an investigation that still has a running
task — it waits for the task to stop on its own.

Consent travels with the request that carried it. A second request cannot widen
an earlier one, and `--force` is not an authorization override: it does not let
a former holder close the current holder's active investigation.

## What a seal means, and what it does not

A managed seal is an access-point tag set by the reaper:
`AuditCloseSeal=<uuid>` plus `AuditCloseManagedBy=rosa-boundary-reaper` and
`AuditCloseRequest=<request token>`. Once it is observed, Boundary's own create,
reconnect and handover paths reject the investigation.

That is **best effort**. There is still a check-to-launch race: a launch that
already passed its marker check can appear after a reaper observation. The
create Lambda checks the marker at lookup and again as late as practical before
launching, and stops a late task if it sees the marker afterwards. That narrows
the window; it does not close it.

Nothing in the code, the documentation or a receipt may describe this as atomic
exclusion. The protections that follow from accepting the weaker guarantee are:

* two task observations separated by a configurable quiet interval before the
  workspace is measured;
* a third observation after the copy, which invalidates the attempt if a task
  appeared; and
* receipts that state what was observed rather than what was prevented.

A seal set by hand, or any seal without the managed marker, is a retention
hold. The reaper never replaces it, and IAM refuses to overwrite an existing
seal of any kind regardless of what the handler asks for.

## Where the control records live

Everything lives under the `_boundary-close/` prefix of the existing regional
audit bucket, which the investigation task role is explicitly denied. The
bucket's object lock keeps each written version immutable; progress is recorded
as new versions rather than by replacing history.

| Key | Written by | Contents |
| --- | --- | --- |
| `_boundary-close/requests/<cluster>/<investigation>/<time>-<token>.json` | request handler, and the reaper for a stale sweep or an activated intent | an immutable close request: identity, requester, observation, stop consent, trigger |
| `_boundary-close/intents/<cluster>/<investigation>/<task>.json` | request handler; the reaper marks one cancelled or activated | auto-close intent for one session's task |
| `_boundary-close/status/<cluster>/<investigation>.json` | reaper | current phase, reason and cleanup disposition |
| `_boundary-close/evidence/<ap>/attempts/<attempt>/workspace/…` | reaper | this attempt's own copy of the workspace |
| `_boundary-close/evidence/<ap>/attempts/<attempt>/{source-manifest,verification}.json` | reaper | measurements and the independent comparison |
| `_boundary-close/<ap>/<seal>.json` | reaper | the close receipt |

Status is keyed by cluster and investigation, not by access point, so it still
answers after the access point is deleted, and it records the workspace path
because access-point discovery will no longer find it.

The request time leads the request filename for the same reason the records
exist at all: the bucket is object-locked, so the finalizer deletes nothing. A
finalizer that had to read every historical record to find the new ones would
eventually spend its whole budget on history and starve the newest requests.
With the time in the key, an answered request is skipped without being read.

The historical shared `reaper-final-backup/` prefix is no longer written. A
shared prefix cannot show which attempt produced which bytes, so each close
copies into an attempt prefix of its own and never overwrites another attempt.

### Why the audit bucket rather than a control directory on EFS

Requests, intents and in-progress status are service-control records, not audit
evidence, and a protected directory on the reaper's own EFS mount would have
held them just as well in principle. They live in the audit bucket because the
component that has to write them cannot reach EFS:

* The request handler authenticates the SRE's OIDC token, which means fetching
  JWKS from Keycloak over the internet, so it shares the create-investigation
  artifact where that dependency and the authentication convention already
  live. Mounting EFS requires VPC attachment, which would change the
  networking of the existing production create path; avoiding that would mean
  a second Lambda artifact, image and build pipeline for three small files.
* `PutObject` is atomic, so a reader never sees a half-written record. The EFS
  variant would have needed a publication protocol to promise the same thing.
* Object Lock makes a written version immutable in storage rather than by
  convention, which is the stronger property for a record that authorizes
  later work.

Two consequences are deliberate and worth knowing:

* **Records accumulate.** A written version cannot be overwritten or erased
  while the bucket's COMPLIANCE-mode Object Lock retention still covers it
  (`retention_days`), so request history grows rather than being tidied up.
  Object Lock does not prevent a `DeleteObject` from adding a delete marker,
  and the bucket's lifecycle rule already expires those markers and old
  versions — immutability here is time-bounded and version-scoped, not
  absolute. The request time leads the key so answered requests are skipped
  without being read; any further pruning is a decision about the audit
  bucket's existing retention and lifecycle rules, not about this feature.
* **Records replicate** to the audit account wherever
  `audit_replication_bucket_arn` is configured, carrying `requester_sub` and
  `requester_username`. That is the same class of identity data already in
  access-point tags, receipts and CloudWatch, but it is a new object type in
  the replica, and it inherits the bucket's retention and replication rules
  rather than defining its own.

Service metadata is protected by IAM, not by obscurity: the task role is denied
`PutObject` under `_boundary-close/*` and is explicitly denied use of the
reaper's root-mounted access point, which would otherwise satisfy its
access-point-agnostic EFS grant. The SRE role holds no write grant anywhere in
the bucket, and its one read grant — `_boundary-close/fsap-*/*.json`, for close
receipts — is why attempt evidence lives under `evidence/` rather than directly
beneath the access point: a workspace copied to a key of that shape would have
exposed every `.json` file in it through a grant meant for receipts alone.

## The finalization sequence

Every route — an explicit request, an activated auto-close intent, and the
stale sweep — runs the same pipeline. There is no second, less-verified path to
deletion.

1. **Revalidate.** Re-derive the observation and reapply the matrix. A handover
   supersedes the request; an unknown state defers it.
2. **Seal.** Apply a fresh managed marker, or reuse an existing managed one.
   Never replace a manual or legacy seal.
3. **Drain.** Stop only the consented tasks. Anything outside that scope leaves
   the close waiting.
4. **Confirm quiet.** Observe again after the configured quiet interval. A task
   observed here ends the pass.
5. **Measure.** Walk the workspace with the trusted mount, recording relative
   path, length and SHA-256 for every eligible regular file. Credential
   directories (`.kube/`, `.config/ocm/`) are excluded, symlinks and special
   files are recorded as skipped, and an unreadable tree, an unsafe path name
   or a file that changes while it is read invalidates the attempt. A task's
   own upload report is never the source of truth.
6. **Copy and verify.** Copy into this attempt's prefix, then compare the exact
   destination key set, lengths, digests and S3 object versions against the
   manifest, using the same comparator the operator script uses.
7. **Recheck.** Re-measure the source and re-enumerate tasks. Any difference, a
   new task, a read error or an ambiguous answer invalidates the attempt, which
   is retained and retried as a fresh attempt rather than published.
8. **Record, clean up, then publish.** Write a status naming the verified
   attempt *before* anything destructive runs, so a later failure still points
   at the data. Then deregister this investigation's task definitions and
   delete the access point — but only if every earlier cleanup step succeeded,
   because the access point is the sole handle to a directory that was not
   reclaimed. Finally publish a receipt describing exactly what happened,
   including what was *not* cleaned up.

Every status says whether the reaper will come back to it. A retention the
reaper can resolve by itself — a throttled API call, an invalidated attempt, a
task that appeared late — is marked retryable and is picked up on a later pass.
A retention that needs a person — a manual hold, a superseded request, a
missing or conflicting workspace — is not, and neither the CLI nor this
document promises a retry that will not happen.

The scheduled sweep records its own request before it begins, for the same
reason: sealing happens early and the sweep skips sealed access points, so an
interrupted pass with nothing on file would leave a sealed workspace that
nothing ever revisits.

Every stage checks the remaining runtime first. A stage that cannot finish is
not started; the pass records its status and the next scheduled invocation
resumes. A timer expiry never becomes a completed close.

Finalization is serialized to one invocation per deployment
(`reserved_concurrent_executions = 1`). That is an operational constraint on
finalizers, not a lock against session creation or any other EFS client.

## Receipts

Schema v2 states its assurance level explicitly:

```json
{"schema_version":2,"assurance":"observed-quiescence","status":"verified",
 "seal":"…","request_token":"…","attempt_id":"…",
 "manifest_ref":"s3://…/attempts/<attempt>/source-manifest.json",
 "verification_ref":"s3://…/attempts/<attempt>/verification.json",
 "manifest_sha256":"…","directory_retained":true,"cleanup_complete":true,
 "limitations":["Verified against the recorded source observations; writes after the final observation are not excluded.", "…"]}
```

A v2 receipt is accepted only when it names the same cluster, investigation,
access point and seal, carries the request token the close was authorized
under, and references the *same attempt* in both evidence references. A
non-empty manifest reference is not enough.

Schema v1 — the operator receipt — is unchanged and still accepted, including
its requirement for a separate `AuditCloseVerified` tag. The reaper does **not**
set that generic tag alongside v2 evidence, which is exactly why an older
client refuses a v2 close rather than mistaking it for the stronger v1
guarantee. Any other schema version is refused outright instead of being
interpreted optimistically.

## What close leaves behind

* **Normal close retains the EFS directory.** The access point and the
  investigation's task definitions are removed; the directory stays. Reclaiming
  it is a stricter, separate decision.
* **Undated managed investigation access points are retired, not reused.** Without a `CreatedAt` tag, new launches and handovers are refused. The scheduled stale sweep applies no age grace to these access points; active tasks, manual holds and failed verification still prevent destructive cleanup.
* **Stale reaping may reclaim the directory**, but only behind the same
  verified gate, and only when `investigation_stale_reclaim_directories` is
  enabled. If reclamation fails, the verified copy and evidence are kept and
  the status says `cleanup_incomplete`.
* **A retained directory stays discoverable.** The status record survives access
  point deletion and names the path, because access-point discovery will not.
* **Deleting an access point does not evict an existing mount**, and no receipt
  claims it does.
* **A cleanup step that failed keeps its access point.** It is the only handle
  to a directory that was not reclaimed, so it is not deleted until the rest of
  the cleanup succeeded.
* An investigation ID whose workspace was retained after a completed close must
  not be reused; choose a distinct identity.

## CLI behaviour

### `investigation close`

Previews read-only (`--dry-run`), confirms unless `--yes`, then submits a
request and prints its token. `--wait` polls until the service reports an outcome it
will not leave by itself, and bounds itself in wall-clock time because an
interactive command has no deadline. Stopping the wait does not cancel the
request, and a request whose submission timed out has an **unknown** outcome
that must be looked up rather than blindly resubmitted. A `retained` or
`cleanup_incomplete` outcome is reported as a failure, not as a close, and
says whether the reaper will retry it.

The close service is contacted only when a close is actually going to be
requested, and the request carries the identity token minted with those
credentials. A session can easily outlive the token its command started with.

Eligibility is enforced by the service, not by the CLI: the CLI has no way to
observe attached sessions.

### After an attached session exits

One shared hook serves `session create` and `session join`.

* With no flags, after a *normal* interactive exit the hook offers to request
  close. **The default is no.** It does not prompt for machine-readable output,
  a failed attachment, a timeout, a cancellation or a lost connection. On
  `session join` it identifies the investigation from the task's own tags
  rather than from the command line; on `session create` it uses the identity
  the service just returned for the task it launched.
* `--auto-close` persists the intent through the request service **before**
  attaching, tied to the selected task. A normal disconnect then requests close
  immediately and suppresses the prompt. If the intent cannot be persisted the
  command fails rather than attaching without the promised behaviour, and if
  the session then fails to attach at all the intent is withdrawn — the SRE
  asked to close when their session ended, not when it failed to start.
* `--auto-close-stop-all` additionally consents to stopping the investigation's
  other tasks. Without it, other tasks keep the close waiting.

**No heartbeat is added.** If the laptop disappears while the task keeps
running, there is no immediate disconnect detection and no short grace timer.
The reaper activates the persisted intent once that task is observed stopped,
and the existing staleness policy provides eventual sealing. A handover to
another active SRE supersedes the intent instead of closing the new holder's
session.

## Recovery

| Symptom | Meaning | Action |
| --- | --- | --- |
| `accepted` for several schedules | the reaper has not reached it yet, or it keeps checkpointing | check the reaper's logs and runtime; raise `investigation_close_requests_per_run` if requests are backing up |
| `waiting_for_tasks` | a task outside the consented stop scope is running | stop it, or resubmit with wider consent from an eligible SRE |
| `retained` after a handover | the request was superseded | submit a fresh request from the current holder |
| `retained` with a verification reason | the attempt could not be trusted | the data is intact and the status is marked retryable; the next pass starts a new attempt. Investigate repeated failures before forcing anything |
| `retained` because the directory is missing | the reaper could not measure a source at the expected EFS path | investigate the mount and workspace disposition before requesting close again; a missing directory is not a verified empty directory |
| `retained` with a manual seal | a retention hold is in place | review the hold; it is deliberately not removed automatically |
| `cleanup_incomplete` | the evidence is good, a cleanup step is not | the status names what remains; retry against the same identity |

Repeated failures, old pending requests and retained directories need sanitized
logs and metrics and the same authorization rules — no additional human
principal, and no new orchestration service.

## Deliberately out of scope

* A database, workflow service or guaranteed atomic admission cutoff.
* An attachment heartbeat or lease to detect a disconnected laptop immediately.
* Changing audit retention or releasing manual holds automatically.
* Reclaiming the directory on a normal explicit close.
* Proving that an arbitrary externally managed EFS client cannot write.
