"""Service-control record contract for automated investigation close.

Close requests, auto-close intents and finalization status live under the
service-only ``_boundary-close/`` prefix of the existing audit bucket. That
prefix is already denied to the investigation task role, so a workload cannot
forge a request, a status or a receipt. No new storage service is introduced
and no lifecycle database exists: these are retry metadata, not a transactional
state machine.

Two deployment artifacts read and write this contract — the authenticated
request/status handler shipped with the create-investigation Lambda and the
investigation reaper. They are packaged separately, so the request side
re-declares the same constants and ``tests/unit/test_close_records_contract.py``
pins the two declarations together.

Writers:

* the request handler writes requests and intents only — never status,
  evidence or receipts;
* the reaper alone writes status, manifests, verification reports and
  receipts. It also records a request of its own for a stale sweep, and one
  for an auto-close intent it activates, so an interrupted pass can resume;
  and it marks an intent cancelled or activated. Those intent updates are new
  object versions — the bucket is object-locked, so nothing is overwritten in
  place.

Nothing here grants authority. A record is a request to be revalidated, never
a decision that has already been made.
"""

import json
import re
from datetime import datetime, timezone

CONTROL_PREFIX = '_boundary-close'

REQUEST_SCHEMA_VERSION = 1
INTENT_SCHEMA_VERSION = 1
STATUS_SCHEMA_VERSION = 1
# Receipt v2 records observed quiescence. v1 claimed an operator-verified seal
# and is still accepted by existing clients; v2 must never be published as v1.
RECEIPT_SCHEMA_VERSION = 2
RECEIPT_ASSURANCE = 'observed-quiescence'

KIND_REQUEST = 'close_request'
KIND_INTENT = 'auto_close_intent'
KIND_STATUS = 'close_status'

# Access-point tags. The legacy AuditCloseSeal tag keeps its meaning so older
# clients and manual seals behave exactly as before; the managed marker only
# distinguishes seals this feature created from seals it must not touch.
TAG_SEAL = 'AuditCloseSeal'
TAG_VERIFIED = 'AuditCloseVerified'
TAG_BUCKET = 'AuditCloseBucket'
TAG_MANAGED = 'AuditCloseManagedBy'
TAG_REQUEST = 'AuditCloseRequest'
MANAGED_BY = 'rosa-boundary-reaper'
# The create Lambda's own marker on every investigation access point. Close
# refuses to act on anything else.
MANAGED_BY_LAMBDA = 'rosa-boundary-lambda'

# Stop scope is consent, never authority. ``session_task`` permits stopping only
# the tasks named in the request; other tasks keep the close waiting.
STOP_NONE = 'none'
STOP_SESSION_TASK = 'session_task'
STOP_INVESTIGATION = 'investigation'
STOP_SCOPES = (STOP_NONE, STOP_SESSION_TASK, STOP_INVESTIGATION)

# Triggers an authenticated SRE may submit. Scheduled reconciliation uses its
# own trigger, which is deliberately not accepted from a client.
TRIGGERS = ('cli_close', 'session_exit_prompt', 'auto_close')
TRIGGER_STALE = 'stale_reconciliation'

# Observation states. ``active`` means an interactive session was observed
# attached, which is what gives the investigation a current holder; a running
# task with no attached session is ``idle``. Unknown is never treated as idle.
STATE_ACTIVE = 'active'
STATE_IDLE = 'idle'
STATE_UNKNOWN = 'unknown'

# CLI-facing status values. Each one must stay distinguishable: an accepted
# request is not a completed close, and a retained workspace is not a failure
# that may be retried destructively.
STATUS_ACCEPTED = 'accepted'
STATUS_WAITING_FOR_TASKS = 'waiting_for_tasks'
STATUS_VERIFYING = 'verifying'
STATUS_RETAINED = 'retained'
STATUS_CLEANUP_INCOMPLETE = 'cleanup_incomplete'
STATUS_COMPLETED = 'completed'
STATUS_UNKNOWN = 'unknown'
TERMINAL_STATUSES = (STATUS_COMPLETED, STATUS_RETAINED)

REQUEST_TOKEN_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
ACCESS_POINT_PATTERN = re.compile(r'^fsap-[0-9a-f]{8,}$')
# ECS task IDs are 32 hex characters; the older 8-4-4-4-12 form is also accepted.
TASK_ID_PATTERN = re.compile(r'^[0-9a-f]{32}$|^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')

# Control records are small by construction: identity, consent and a phase.
MAX_RECORD_BYTES = 16 << 10
# Evidence documents carry one entry per workspace file, so they are bounded by
# the workspace rather than by the record contract. The limit exists so an
# oversized workspace produces a visible retained result instead of an
# unbounded object or a failed invocation.
MAX_EVIDENCE_BYTES = 8 << 20


# Seconds reserved at the end of every invocation so a pass can always record
# what it did before Lambda stops it.
CLEANUP_RESERVE_SECONDS = 30


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def work_seconds(context) -> float:
    """Seconds available for new work, excluding the cleanup reserve."""
    if context is None:
        return 300.0
    remaining = context.get_remaining_time_in_millis() - CLEANUP_RESERVE_SECONDS * 1000
    return max(0, remaining) / 1000


def safe_segment(value: str) -> str:
    """Return ``value`` when it is a safe single key segment, else raise."""
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.match(value) or '/' in value:
        raise ValueError('unsafe key segment')
    return value


def requests_prefix(cluster_id: str, investigation_id: str) -> str:
    return (f'{CONTROL_PREFIX}/requests/{safe_segment(cluster_id)}/'
            f'{safe_segment(investigation_id)}/')


def request_stamp(moment: str) -> str:
    """Render an ISO 8601 instant as a sortable UTC key segment."""
    parsed = datetime.fromisoformat(moment)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def request_key(cluster_id: str, investigation_id: str, request_token: str,
                requested_at: str) -> str:
    """Build the key for one immutable close request.

    The request time leads the filename so the finalizer can tell, from the
    key alone, whether a recorded terminal outcome already answers a request.
    Records are never deleted — the audit bucket is object-locked — so a scan
    that had to read every historical record to find the new ones would
    eventually starve the newest requests.
    """
    if not REQUEST_TOKEN_PATTERN.match(request_token or ''):
        raise ValueError('request token must be a lowercase UUIDv4')
    return (requests_prefix(cluster_id, investigation_id)
            + f'{request_stamp(requested_at)}-{request_token}.json')


REQUEST_FILENAME = re.compile(
    r'^(?P<stamp>\d{8}T\d{6}Z)-(?P<token>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}'
    r'-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json$')


def parse_request_filename(name: str):
    """Return ``(stamp, token)`` for a request key's final segment, or None."""
    match = REQUEST_FILENAME.match(name or '')
    if not match:
        return None
    return match.group('stamp'), match.group('token')


def intents_prefix(cluster_id: str, investigation_id: str) -> str:
    return (f'{CONTROL_PREFIX}/intents/{safe_segment(cluster_id)}/'
            f'{safe_segment(investigation_id)}/')


def intent_key(cluster_id: str, investigation_id: str, task_id: str) -> str:
    if not TASK_ID_PATTERN.match(task_id or ''):
        raise ValueError('task id is not an ECS task identifier')
    return intents_prefix(cluster_id, investigation_id) + task_id + '.json'


def status_key(cluster_id: str, investigation_id: str) -> str:
    return (f'{CONTROL_PREFIX}/status/{safe_segment(cluster_id)}/'
            f'{safe_segment(investigation_id)}.json')


def _access_point(access_point_id: str) -> str:
    if not ACCESS_POINT_PATTERN.match(access_point_id or ''):
        raise ValueError('access point id is malformed')
    return access_point_id


def attempt_prefix(access_point_id: str, attempt_id: str) -> str:
    """Service-only prefix for one close attempt's independent copy.

    Deliberately distinct from the historical ``reaper-final-backup/`` prefix
    and from task-written escrow: neither is evidence of this attempt.

    It also sits under ``evidence/`` rather than directly under the access
    point, because the SRE role's narrow read grant for close receipts is
    ``_boundary-close/fsap-*/*.json``. Copying a workspace to a key starting
    with ``_boundary-close/<access point>/`` would have made every ``.json``
    file in that workspace readable through a grant meant for receipts alone.
    """
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', attempt_id or ''):
        raise ValueError('attempt id must be a lowercase UUID')
    return (f'{CONTROL_PREFIX}/evidence/{_access_point(access_point_id)}'
            f'/attempts/{attempt_id}/')


def attempt_workspace_prefix(access_point_id: str, attempt_id: str) -> str:
    return attempt_prefix(access_point_id, attempt_id) + 'workspace/'


EVIDENCE_DOCUMENTS = ('source-manifest.json', 'verification.json')


def attempt_evidence_key(access_point_id: str, attempt_id: str, name: str) -> str:
    if name not in EVIDENCE_DOCUMENTS:
        raise ValueError('unknown evidence document')
    return attempt_prefix(access_point_id, attempt_id) + name


def receipt_key(access_point_id: str, seal: str) -> str:
    """Existing receipt location, unchanged so current CLI readers keep working."""
    if not REQUEST_TOKEN_PATTERN.match(seal or ''):
        raise ValueError('seal must be a lowercase UUIDv4')
    return f'{CONTROL_PREFIX}/{_access_point(access_point_id)}/{seal}.json'


def encode_record(record: dict) -> bytes:
    """Serialize one complete control record; partial JSON is never published."""
    body = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(body) > MAX_RECORD_BYTES:
        raise ValueError('control record exceeds the published size limit')
    return body


def encode_evidence(document: dict) -> bytes:
    """Serialize one complete evidence document.

    Evidence grows with the workspace, so it is not held to the control-record
    limit. A workspace large enough to exceed even this limit cannot be
    described in one document, which is reported as a retained, unsupported
    result rather than published partially.
    """
    body = json.dumps(document, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(body) > MAX_EVIDENCE_BYTES:
        raise ValueError('workspace is too large to describe in one evidence document')
    return body


def decode_record(body: bytes, kind: str) -> dict:
    """Parse a control record, rejecting anything that is not the stated kind.

    A corrupt, oversized or mislabelled record raises; callers turn that into a
    retained, actionable error rather than an inferred successful close.
    """
    if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_RECORD_BYTES:
        raise ValueError('control record is missing or oversized')
    record = json.loads(body.decode('utf-8'))
    if not isinstance(record, dict):
        raise ValueError('control record is not an object')
    if record.get('kind') != kind:
        raise ValueError(f'control record is not a {kind}')
    return record


def validate_request(record: dict) -> dict:
    """Validate an immutable close request read back from the audit bucket.

    ``TRIGGER_STALE`` is accepted here but not by the request handler: the
    scheduled sweep records its own request so an interrupted stale pass can
    be resumed, and that trigger must never be submittable by a client.
    """
    if record.get('schema_version') != REQUEST_SCHEMA_VERSION:
        raise ValueError('unsupported close request schema version')
    for field in ('request_token', 'cluster_id', 'investigation_id', 'access_point_id',
                  'stop_scope', 'trigger', 'requested_at'):
        if not isinstance(record.get(field), str) or not record[field]:
            raise ValueError(f'close request is missing {field}')
    if record['trigger'] != TRIGGER_STALE and not record.get('requester_sub'):
        # Only the scheduled sweep may record a request with no requester.
        raise ValueError('close request is missing requester_sub')
    if not REQUEST_TOKEN_PATTERN.match(record['request_token']):
        raise ValueError('close request token is malformed')
    if record['stop_scope'] not in STOP_SCOPES:
        raise ValueError('close request stop scope is unknown')
    if record['trigger'] not in TRIGGERS + (TRIGGER_STALE,):
        raise ValueError('close request trigger is unknown')
    stop_task_ids = record.get('stop_task_ids', [])
    if not isinstance(stop_task_ids, list) or not all(
            isinstance(task_id, str) and TASK_ID_PATTERN.match(task_id)
            for task_id in stop_task_ids):
        raise ValueError('close request stop_task_ids are malformed')
    if record['stop_scope'] == STOP_SESSION_TASK and not stop_task_ids:
        raise ValueError('session_task consent names no task')
    _access_point(record['access_point_id'])
    safe_segment(record['cluster_id'])
    safe_segment(record['investigation_id'])
    return record


def validate_intent(record: dict) -> dict:
    """Validate a persisted auto-close intent."""
    if record.get('schema_version') != INTENT_SCHEMA_VERSION:
        raise ValueError('unsupported auto-close intent schema version')
    for field in ('cluster_id', 'investigation_id', 'access_point_id', 'task_id',
                  'requester_sub', 'stop_scope', 'created_at'):
        if not isinstance(record.get(field), str) or not record[field]:
            raise ValueError(f'auto-close intent is missing {field}')
    if not TASK_ID_PATTERN.match(record['task_id']):
        raise ValueError('auto-close intent task id is malformed')
    # The activation path reads this straight out of the record; an intent
    # without it would raise past the reaper's error handling and take the
    # whole invocation down, including the unrelated stale sweep.
    _access_point(record['access_point_id'])
    if record['stop_scope'] not in (STOP_NONE, STOP_SESSION_TASK, STOP_INVESTIGATION):
        raise ValueError('auto-close intent stop scope is unknown')
    safe_segment(record['cluster_id'])
    safe_segment(record['investigation_id'])
    return record


def build_status(cluster_id: str, investigation_id: str, status: str, *,
                 phase: str, reason: str = '', access_point_id: str = '',
                 access_point_path: str = '', request_token: str = '', attempt_id: str = '',
                 receipt_key_name: str = '', directory_retained: bool = True,
                 access_point_deleted: bool = False, task_definitions_removed: int = 0,
                 retryable: bool = False, observations=None) -> dict:
    """Build a reaper status record.

    ``directory_retained`` defaults to true: normal close keeps the EFS
    directory, and no caller may imply reclamation it did not perform.

    ``retryable`` says whether the scheduled reaper will pick this request up
    again by itself. It is false for outcomes that need a person — a manual
    hold, a superseded request, a missing or conflicting workspace — and true
    for anything that may simply have gone differently on a later pass. Nothing
    may promise a retry that will not happen.
    """
    if status not in (STATUS_ACCEPTED, STATUS_WAITING_FOR_TASKS, STATUS_VERIFYING,
                      STATUS_RETAINED, STATUS_CLEANUP_INCOMPLETE, STATUS_COMPLETED):
        raise ValueError('unknown close status')
    return {
        'schema_version': STATUS_SCHEMA_VERSION,
        'kind': KIND_STATUS,
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'access_point_id': access_point_id,
        # Recorded because access-point discovery stops working once the access
        # point is deleted, and a retained directory still has to be findable.
        'access_point_path': access_point_path or f'/{cluster_id}/{investigation_id}',
        'request_token': request_token,
        'status': status,
        'phase': phase,
        'reason': reason,
        'attempt_id': attempt_id,
        'receipt_key': receipt_key_name,
        'directory_retained': bool(directory_retained),
        'access_point_deleted': bool(access_point_deleted),
        'task_definitions_removed': int(task_definitions_removed),
        'retryable': bool(retryable),
        'observations': list(observations or []),
        'updated_at': now_iso(),
    }
