# Automated investigation close

This first layer defines the close contract; it does not enable requests or finalization.

## Who may close

Any authenticated SRE authorized to use this Boundary deployment may explicitly
request close. Neither creating the workspace nor holding its attached session
is required. The access point's `oidc_sub` is provenance only.

| Observed state | Who may request seal/close |
| --- | --- |
| Held by SRE A | Any authorized SRE may explicitly request close. If someone other than A asks, the reaper waits for A to detach before sealing or draining, even with stop consent. |
| Handed over from A to B | An explicit request remains pending. A session-exit callback or auto-close intent from A is superseded, not inherited consent. |
| No active sessions | Any authenticated SRE authorized to use Boundary. No creator match and no handover is required to close an idle investigation, and a task left running does not reserve it for whoever launched it. |
| Incomplete, contradictory or unavailable | Unknown. A new request is refused as retryable; the reaper defers an already recorded request. Unknown is never treated as idle. |

### What "held" is observed from

Two service-side signals, which answer different questions:

* the active SSM sessions attached to the investigation's tasks — **this is
  what decides who holds it**; and
* the non-terminal ECS tasks themselves, whose `oidc_sub` tag records the SRE
  each task was launched for.

A RUNNING task is **not** proof that a shell is attached. An investigation
whose SRE detached but whose task is still running is **idle**. The task's
owner is still reported in `task_owner_subs` for provenance, not permission.

Anything that could not be read completely is `unknown`: a scan that failed, a
description that came back short, a non-terminal task with no owner tag or no
session target — where "no session attached" cannot be distinguished from "not
observed" — or two SREs attached at once.

Idle is not a licence to destroy anything. Detaching does
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

For example, B requests close without stop consent while A is attached. The
service records B’s request; the reaper reports `waiting_for_tasks`. When A
detaches, the reaper may seal, but it still waits for A’s task to stop. Once
quiet, it processes **the same request** through backup verification and normal
close. The scheduled stale sweep has no stop consent and waits for running
tasks to stop before it seals.

Consent travels with the request that carried it. A second request cannot widen
an earlier one, and `--force` is not an authorization override: it does not permit the reaper to interrupt a different attached holder.

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
