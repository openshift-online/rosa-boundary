"""Authenticated close-request and status actions for investigations.

This module is the SRE-facing front door of automated investigation close. It
authenticates nothing by itself: ``handler.lambda_handler`` has already
validated the OIDC token and the caller's group membership when it dispatches
here, exactly as it does for investigation creation.

What this module does own is narrow and deliberate:

* resolve the trusted investigation identity (access point, filesystem, path);
* observe who currently holds the investigation and apply the authorization
  matrix;
* record an immutable close request, or a durable auto-close intent, under the
  service-only ``_boundary-close/`` prefix of the audit bucket; and
* report the finalizer's status, including after the access point is gone.

What it must never do is seal, stop tasks, copy data, verify a backup, publish
a receipt or delete anything. Those are the investigation reaper's work, and
keeping them there is what stops an SRE's request from also being its own
audit evidence. A recorded request is a request, not a decision.

The record contract is shared with ``lambda/reap-investigations``. The two
Lambdas ship as separate artifacts, so the constants, key layout and
authorization matrix are declared in both and pinned together by
``tests/unit/test_close_records_contract.py`` and
``tests/unit/test_close_authorization_contract.py``.
"""

import json
import logging
import re
import uuid
from contextlib import closing
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

CONTROL_PREFIX = '_boundary-close'

REQUEST_SCHEMA_VERSION = 1
INTENT_SCHEMA_VERSION = 1

KIND_REQUEST = 'close_request'
KIND_INTENT = 'auto_close_intent'
KIND_STATUS = 'close_status'

TAG_SEAL = 'AuditCloseSeal'
TAG_MANAGED = 'AuditCloseManagedBy'
TAG_REQUEST = 'AuditCloseRequest'
MANAGED_BY = 'rosa-boundary-reaper'
MANAGED_BY_LAMBDA = 'rosa-boundary-lambda'

STOP_NONE = 'none'
STOP_SESSION_TASK = 'session_task'
STOP_INVESTIGATION = 'investigation'
STOP_SCOPES = (STOP_NONE, STOP_SESSION_TASK, STOP_INVESTIGATION)

TRIGGERS = ('cli_close', 'session_exit_prompt', 'auto_close')

STATE_ACTIVE = 'active'
STATE_IDLE = 'idle'
STATE_UNKNOWN = 'unknown'

STATUS_ACCEPTED = 'accepted'
STATUS_WAITING_FOR_TASKS = 'waiting_for_tasks'
STATUS_VERIFYING = 'verifying'
STATUS_RETAINED = 'retained'
STATUS_CLEANUP_INCOMPLETE = 'cleanup_incomplete'
STATUS_COMPLETED = 'completed'
STATUS_UNKNOWN = 'unknown'
STATUS_NONE = 'none'
TERMINAL_STATUSES = (STATUS_COMPLETED, STATUS_RETAINED)

# Several of the constants above are not used by this module. They are part of
# the shared record contract and are pinned by
# tests/unit/test_close_records_contract.py; removing one here would break the
# agreement with the finalizer rather than tidy anything up.

REQUEST_TOKEN_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
ACCESS_POINT_PATTERN = re.compile(r'^fsap-[0-9a-f]{8,}$')
TASK_ID_PATTERN = re.compile(r'^[0-9a-f]{32}$|^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')

MAX_RECORD_BYTES = 16 << 10
DESCRIBE_CHUNK = 100

ACTIONS = ('request_close', 'close_status', 'register_auto_close', 'cancel_auto_close')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_segment(value: str) -> str:
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

    The request time leads the filename so the finalizer can tell, from the key
    alone, whether a recorded outcome already answers a request. See the
    matching builder in the reaper's record module.
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


def encode_record(record: dict) -> bytes:
    body = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(body) > MAX_RECORD_BYTES:
        raise ValueError('control record exceeds the published size limit')
    return body


# --------------------------------------------------------------------------
# Ownership observation and the authorization matrix.
#
# Mirrors lambda/reap-investigations/investigation_sessions.py. The reaper
# re-derives this for itself before it mutates anything; agreeing here only
# means a request is accepted, never that it will be acted on.
# --------------------------------------------------------------------------


def _chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _task_owner_subs(tasks):
    """Provenance only: who the non-terminal tasks were launched for."""
    return sorted({task['oidc_sub'] for task in tasks or []
                   if task['last_status'] != 'STOPPED' and task['oidc_sub']})


def _active_session_count(ssm, ecs_cluster, task_id, containers):
    """Count active ECS Exec sessions attached to one task.

    Mirrors the reaper helper of the same name, including the order of its
    checks: every container is scanned before ``incomplete`` is reported, so
    both implementations make the same API calls and record the same reason.
    """
    total = 0
    incomplete = not containers
    for container in containers:
        runtime_id = container.get('runtimeId')
        if not runtime_id:
            incomplete = True
            continue
        sessions = ssm.describe_sessions(
            State='Active',
            Filters=[{'key': 'Target',
                      'value': f'ecs:{ecs_cluster}_{task_id}_{runtime_id}'}],
        ).get('Sessions', [])
        total += len(sessions)
    return total, incomplete


def _unknown(reason, tasks=None, active_sessions=0):
    return {
        'state': STATE_UNKNOWN,
        'holder_sub': None,
        'active_sessions': active_sessions,
        'tasks': tasks or [],
        'task_owner_subs': _task_owner_subs(tasks),
        'reason': reason,
        'observed_at': now_iso(),
    }


def _list_task_arns(ecs, ecs_cluster, started_by):
    paginator = ecs.get_paginator('list_tasks')
    # startedBy must be the only ECS filter. Its default desired status is
    # RUNNING; also look for tasks asked to stop but not yet terminal.
    matching = {arn for page in paginator.paginate(cluster=ecs_cluster, startedBy=started_by)
                for arn in page.get('taskArns', [])}
    stopping = {arn for page in paginator.paginate(cluster=ecs_cluster, desiredStatus='STOPPED')
                for arn in page.get('taskArns', [])}
    return matching, sorted(matching | stopping)


def observe_investigation(ecs, ssm, ecs_cluster, started_by):
    """Observe the current holder of an investigation; see the reaper module.

    The attached SSM sessions decide who holds the investigation. A RUNNING
    task with no attached session is idle, not held: its ``oidc_sub`` tag is
    provenance. Anything that could not be read completely is ``unknown``.
    """
    try:
        matching, arns = _list_task_arns(ecs, ecs_cluster, started_by)
    except (ClientError, BotoCoreError):
        return _unknown('task scan failed; investigation state is unknown')

    described = []
    for chunk in _chunks(arns, DESCRIBE_CHUNK):
        try:
            response = ecs.describe_tasks(cluster=ecs_cluster, tasks=chunk, include=['TAGS'])
        except (ClientError, BotoCoreError):
            return _unknown('task description failed; investigation state is unknown')
        if response.get('failures'):
            return _unknown('task description reported failures; investigation state is unknown')
        tasks = response.get('tasks', [])
        if {task.get('taskArn') for task in tasks} != set(chunk):
            return _unknown('task description is incomplete; investigation state is unknown')
        described.extend(task for task in tasks
                         if task.get('taskArn') in matching or task.get('startedBy') == started_by)

    observed = []
    session_holders = set()
    active_sessions = 0
    for task in described:
        task_id = (task.get('taskArn') or '').rsplit('/', 1)[-1]
        last_status = task.get('lastStatus', '')
        tags = {tag['key']: tag['value'] for tag in task.get('tags', [])}
        entry = {
            'task_id': task_id,
            'last_status': last_status,
            'desired_status': task.get('desiredStatus', ''),
            'oidc_sub': tags.get('oidc_sub', ''),
            'active_sessions': 0,
        }
        observed.append(entry)
        if last_status == 'STOPPED':
            continue
        if not task_id:
            return _unknown('a non-terminal task has no identifier; investigation state is unknown',
                            tasks=observed)
        if not entry['oidc_sub']:
            return _unknown('a non-terminal task has no owner tag; investigation state is unknown',
                            tasks=observed)
        try:
            count, incomplete = _active_session_count(
                ssm, ecs_cluster, task_id, task.get('containers', []))
        except (ClientError, BotoCoreError):
            return _unknown('session scan failed; investigation state is unknown',
                            tasks=observed, active_sessions=active_sessions)
        if incomplete:
            return _unknown('a non-terminal task exposes no session target; '
                            'investigation state is unknown', tasks=observed,
                            active_sessions=active_sessions)
        entry['active_sessions'] = count
        active_sessions += count
        if count:
            session_holders.add(entry['oidc_sub'])

    nonterminal = [task for task in observed if task['last_status'] != 'STOPPED']
    owners = _task_owner_subs(observed)
    if len(session_holders) > 1:
        return _unknown('attached sessions report two different holders', tasks=observed,
                        active_sessions=active_sessions)
    if session_holders:
        return {
            'state': STATE_ACTIVE,
            'holder_sub': next(iter(session_holders)),
            'active_sessions': active_sessions,
            'tasks': observed,
            'task_owner_subs': owners,
            'reason': (f'{active_sessions} attached session(s) across '
                       f'{len(nonterminal)} non-terminal task(s)'),
            'observed_at': now_iso(),
        }
    return {
        'state': STATE_IDLE,
        'holder_sub': None,
        'active_sessions': 0,
        'tasks': observed,
        'task_owner_subs': owners,
        'reason': (f'no attached sessions; {len(nonterminal)} non-terminal task(s) running'
                   if nonterminal else 'no non-terminal tasks and no attached sessions'),
        'observed_at': now_iso(),
    }


def nonterminal_task_ids(observation):
    return [task['task_id'] for task in observation.get('tasks', [])
            if task['last_status'] != 'STOPPED']


def authorize_close(observation, requester_sub, *, explicit=False):
    """Apply the close authorization matrix; see the reaper module for details."""
    state = observation.get('state')
    if state not in (STATE_ACTIVE, STATE_IDLE):
        return False, STATE_UNKNOWN, observation.get('reason') or 'investigation state is unknown'
    if not requester_sub:
        return False, 'unauthenticated', 'the requester has no authenticated subject'
    if state == STATE_IDLE:
        return True, STATE_IDLE, ''
    if requester_sub == observation.get('holder_sub'):
        return True, 'holder', ''
    if explicit:
        return True, 'authorized_sre', ''
    return False, 'not_holder', 'session close callback refused: another SRE is attached'


# --------------------------------------------------------------------------
# Audit-bucket control records.
# --------------------------------------------------------------------------


def _s3():
    return boto3.client('s3')


def _put_record(s3, bucket, key, record, account_id):
    """Publish one complete record. Partial JSON is never exposed."""
    kwargs = {
        'Bucket': bucket,
        'Key': key,
        'Body': encode_record(record),
        'ContentType': 'application/json',
    }
    if account_id:
        kwargs['ExpectedBucketOwner'] = account_id
    s3.put_object(**kwargs)


def _get_json(s3, bucket, key, account_id):
    kwargs = {'Bucket': bucket, 'Key': key}
    if account_id:
        kwargs['ExpectedBucketOwner'] = account_id
    try:
        response = s3.get_object(**kwargs)
    except ClientError as error:
        code = error.response.get('Error', {}).get('Code')
        if code in ('NoSuchKey', '404', 'NotFound'):
            return None
        if code in ('AccessDenied', '403'):
            # A missing GET can be forbidden with prefix-scoped ListBucket. An
            # exact key sorts first; only a successful list can prove absence.
            page = s3.list_objects_v2(Bucket=bucket, Prefix=key, MaxKeys=1,
                                         **({'ExpectedBucketOwner': account_id} if account_id else {}))
            if not any(obj['Key'] == key for obj in page.get('Contents', [])):
                return None
        raise
    with closing(response['Body']) as stream:
        body = stream.read(MAX_RECORD_BYTES + 1)
    if len(body) > MAX_RECORD_BYTES:
        raise ValueError('control record is oversized')
    record = json.loads(body.decode('utf-8'))
    if not isinstance(record, dict):
        raise ValueError('control record is not an object')
    return record


def _list_requests(s3, bucket, cluster_id, investigation_id, account_id):
    prefix = requests_prefix(cluster_id, investigation_id)
    keys = []
    kwargs = {'Bucket': bucket, 'Prefix': prefix}
    if account_id:
        kwargs['ExpectedBucketOwner'] = account_id
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(**kwargs):
        keys.extend(obj['Key'] for obj in page.get('Contents', []))
    return sorted(keys)


# --------------------------------------------------------------------------
# Investigation identity.
# --------------------------------------------------------------------------


def resolve_investigation(efs, efs_filesystem_id, cluster_id, investigation_id):
    """Find the managed access point for an investigation.

    Unlike the creation path, a sealed access point is not an error here: a
    close request may legitimately follow a managed seal. Conflicting identity
    is always an error — cleanup is refused rather than guessed.
    """
    expected_path = f'/{cluster_id}/{investigation_id}'
    match = None
    paginator = efs.get_paginator('describe_access_points')
    for page in paginator.paginate(FileSystemId=efs_filesystem_id):
        for access_point in page.get('AccessPoints', []):
            if (access_point.get('RootDirectory', {}).get('Path') or '') != expected_path:
                continue
            if match is not None:
                raise ValueError('multiple access points share this workspace path; '
                                 'close refused until the duplicate is resolved')
            match = access_point
    if match is None:
        return None
    tags = {tag['Key']: tag['Value'] for tag in match.get('Tags', [])}
    if tags.get('ClusterID') != cluster_id or tags.get('InvestigationID') != investigation_id:
        raise ValueError('access point identity tags conflict with its path; close refused')
    if tags.get('ManagedBy') != MANAGED_BY_LAMBDA:
        raise ValueError('access point is not Lambda-managed; close refused')
    access_point_id = match.get('AccessPointId', '')
    if not ACCESS_POINT_PATTERN.match(access_point_id):
        raise ValueError('access point identifier is malformed; close refused')
    return {
        'access_point_id': access_point_id,
        'file_system_id': match.get('FileSystemId', ''),
        'available': match.get('LifeCycleState') == 'available',
        'path': expected_path,
        'tags': tags,
    }


# --------------------------------------------------------------------------
# Actions.
# --------------------------------------------------------------------------


class CloseRequestError(Exception):
    """Reported to the caller with an explicit status code and no internals."""

    def __init__(self, status_code, message, **extra):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.extra = extra


def _validate_stop_scope(body):
    stop_scope = body.get('stop_scope', STOP_NONE)
    if stop_scope not in STOP_SCOPES:
        raise CloseRequestError(400, f'stop_scope must be one of {", ".join(STOP_SCOPES)}')
    stop_task_ids = body.get('stop_task_ids') or []
    if not isinstance(stop_task_ids, list) or not all(
            isinstance(task_id, str) and TASK_ID_PATTERN.match(task_id)
            for task_id in stop_task_ids):
        raise CloseRequestError(400, 'stop_task_ids must be ECS task identifiers')
    if stop_scope == STOP_SESSION_TASK and not stop_task_ids:
        raise CloseRequestError(400, 'stop_scope session_task requires stop_task_ids')
    if stop_scope != STOP_SESSION_TASK and stop_task_ids:
        raise CloseRequestError(400, 'stop_task_ids are only meaningful with '
                                     'stop_scope session_task')
    return stop_scope, sorted(set(stop_task_ids))


def _existing_equivalent_request(s3, bucket, account_id, cluster_id, investigation_id,
                                 requester_sub, stop_scope, stop_task_ids, trigger, status_record):
    """Return a prior pending request from the same SRE with the same consent.

    Duplicate submissions must not reset a seal, expand consent or multiply
    work, so an identical resubmission is answered with the request already on
    file. A different trigger has different handover semantics. Different
    consent — a wider scope or a different task — also needs a new request: silently answering it with the old one would drop the
    consent the SRE just gave.

    A terminal outcome ends de-duplication. After a retained close the SRE has
    to be able to ask again.
    """
    if status_record and status_record.get('status') in TERMINAL_STATUSES:
        return None
    for key in _list_requests(s3, bucket, cluster_id, investigation_id, account_id):
        try:
            record = _get_json(s3, bucket, key, account_id)
        except (ClientError, BotoCoreError, ValueError):
            continue
        if not record or record.get('kind') != KIND_REQUEST:
            continue
        if (record.get('requester_sub') == requester_sub
                and record.get('trigger') == trigger
                and record.get('stop_scope') == stop_scope
                and sorted(record.get('stop_task_ids') or []) == stop_task_ids):
            return record
    return None


def handle_request_close(body, identity, config, clients):
    """Record an authenticated, authorized close request."""
    cluster_id = body['cluster_id']
    investigation_id = body['investigation_id']
    stop_scope, stop_task_ids = _validate_stop_scope(body)
    trigger = body.get('trigger', 'cli_close')
    if trigger not in TRIGGERS:
        raise CloseRequestError(400, f'trigger must be one of {", ".join(TRIGGERS)}')

    investigation = _require_investigation(config, clients, cluster_id, investigation_id)
    observation = observe_investigation(
        clients['ecs'], clients['ssm'], config['ecs_cluster'],
        config['started_by'](cluster_id, investigation_id))
    allowed, basis, reason = authorize_close(
        observation, identity['sub'], explicit=trigger == 'cli_close')
    if not allowed:
        # Unknown is retryable and must not be reported as a permission denial.
        status_code = 409 if basis == STATE_UNKNOWN else 403
        raise CloseRequestError(status_code, reason, state=observation['state'])

    if stop_scope == STOP_SESSION_TASK:
        observed_tasks = set(nonterminal_task_ids(observation))
        unknown_tasks = [task for task in stop_task_ids if task not in observed_tasks]
        if unknown_tasks:
            raise CloseRequestError(
                409, 'stop consent names tasks that are not part of this investigation')

    s3 = clients['s3']
    bucket = config['audit_bucket']
    account_id = config['account_id']
    status_record = _get_json(s3, bucket, status_key(cluster_id, investigation_id), account_id)
    existing = _existing_equivalent_request(
        s3, bucket, account_id, cluster_id, investigation_id, identity['sub'],
        stop_scope, stop_task_ids, trigger, status_record)
    if existing:
        return {
            'action': 'request_close',
            'request_token': existing['request_token'],
            'duplicate': True,
            'status': (status_record or {}).get('status', STATUS_ACCEPTED),
            'state': observation['state'],
            'access_point_id': investigation['access_point_id'],
            'stop_scope': existing['stop_scope'],
            'message': 'An equivalent request is already recorded; it was not resubmitted.',
        }

    request_token = str(uuid.uuid4())
    requested_at = now_iso()
    record = {
        'schema_version': REQUEST_SCHEMA_VERSION,
        'kind': KIND_REQUEST,
        'request_token': request_token,
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'access_point_id': investigation['access_point_id'],
        'file_system_id': investigation['file_system_id'],
        'access_point_path': investigation['path'],
        # Provenance only. Creating an investigation never confers permanent
        # authority over it.
        'original_creator_sub': investigation['tags'].get('oidc_sub', ''),
        'observed_holder_sub': observation.get('holder_sub') or '',
        'requester_sub': identity['sub'],
        'requester_username': identity.get('username', ''),
        'authorization_basis': basis,
        'observation': {
            'state': observation['state'],
            'active_sessions': observation['active_sessions'],
            'nonterminal_task_ids': nonterminal_task_ids(observation),
            # Provenance: an idle investigation may still have a task running,
            # and the record should show whose it was.
            'task_owner_subs': observation.get('task_owner_subs', []),
            'observed_at': observation['observed_at'],
        },
        'stop_scope': stop_scope,
        'stop_task_ids': stop_task_ids,
        'trigger': trigger,
        'requested_at': requested_at,
        'deployment': config['ecs_cluster'],
    }
    _put_record(s3, bucket,
                request_key(cluster_id, investigation_id, request_token, requested_at),
                record, account_id)
    logger.info('Recorded close request for %s/%s (basis=%s, scope=%s)',
                cluster_id, investigation_id, basis, stop_scope)
    return {
        'action': 'request_close',
        'request_token': request_token,
        'duplicate': False,
        'status': STATUS_ACCEPTED,
        'state': observation['state'],
        'access_point_id': investigation['access_point_id'],
        'stop_scope': stop_scope,
        'message': ('Close requested. Finalization runs in the scheduled reaper; '
                    'accepted is not closed.'),
    }


def handle_register_auto_close(body, identity, config, clients):
    """Persist auto-close intent for one attached session before it attaches."""
    cluster_id = body['cluster_id']
    investigation_id = body['investigation_id']
    task_id = body.get('task_id', '')
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.match(task_id):
        raise CloseRequestError(400, 'task_id must be an ECS task identifier')
    stop_scope = body.get('stop_scope', STOP_SESSION_TASK)
    if stop_scope not in (STOP_SESSION_TASK, STOP_INVESTIGATION):
        raise CloseRequestError(
            400, 'auto-close stop scope must be session_task or investigation')

    investigation = _require_investigation(config, clients, cluster_id, investigation_id)
    observation = observe_investigation(
        clients['ecs'], clients['ssm'], config['ecs_cluster'],
        config['started_by'](cluster_id, investigation_id))
    allowed, basis, reason = authorize_close(observation, identity['sub'])
    if not allowed:
        raise CloseRequestError(409 if basis == STATE_UNKNOWN else 403, reason,
                                state=observation['state'])

    record = {
        'schema_version': INTENT_SCHEMA_VERSION,
        'kind': KIND_INTENT,
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'access_point_id': investigation['access_point_id'],
        'task_id': task_id,
        'requester_sub': identity['sub'],
        'requester_username': identity.get('username', ''),
        'stop_scope': stop_scope,
        'authorization_basis': basis,
        'cancelled': False,
        'created_at': now_iso(),
        'deployment': config['ecs_cluster'],
    }
    _put_record(clients['s3'], config['audit_bucket'],
                intent_key(cluster_id, investigation_id, task_id), record,
                config['account_id'])
    return {
        'action': 'register_auto_close',
        'registered': True,
        'task_id': task_id,
        'stop_scope': stop_scope,
        'access_point_id': investigation['access_point_id'],
        'message': ('Auto-close intent recorded. The reaper activates it only after this '
                    'task is observed stopped and the requester is still eligible.'),
    }


def handle_cancel_auto_close(body, identity, config, clients):
    """Withdraw a previously recorded auto-close intent."""
    cluster_id = body['cluster_id']
    investigation_id = body['investigation_id']
    task_id = body.get('task_id', '')
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.match(task_id):
        raise CloseRequestError(400, 'task_id must be an ECS task identifier')
    key = intent_key(cluster_id, investigation_id, task_id)
    existing = _get_json(clients['s3'], config['audit_bucket'], key, config['account_id'])
    if not existing or existing.get('kind') != KIND_INTENT:
        return {'action': 'cancel_auto_close', 'cancelled': False,
                'message': 'No auto-close intent is recorded for this task.'}
    if existing.get('requester_sub') != identity['sub']:
        raise CloseRequestError(403, 'only the SRE that recorded an auto-close intent '
                                     'may withdraw it')
    record = dict(existing)
    record['cancelled'] = True
    record['cancelled_at'] = now_iso()
    _put_record(clients['s3'], config['audit_bucket'], key, record, config['account_id'])
    return {'action': 'cancel_auto_close', 'cancelled': True, 'task_id': task_id}


def handle_close_status(body, identity, config, clients):
    """Report finalization status, including after the access point is deleted.

    Status is resolved from service metadata keyed by cluster and investigation
    rather than by access point, so a completed close stays discoverable once
    the access point no longer exists.
    """
    cluster_id = body['cluster_id']
    investigation_id = body['investigation_id']
    s3 = clients['s3']
    bucket = config['audit_bucket']
    account_id = config['account_id']

    try:
        status_record = _get_json(s3, bucket, status_key(cluster_id, investigation_id),
                                  account_id)
    except (ClientError, BotoCoreError, ValueError):
        raise CloseRequestError(503, 'close status could not be read; retry before '
                                     'assuming any outcome')

    recorded_requests = []
    request_keys = _list_requests(s3, bucket, cluster_id, investigation_id, account_id)
    for key in request_keys:
        parsed = parse_request_filename(key.rsplit('/', 1)[-1])
        if parsed:
            recorded_requests.append(parsed)
    # Keys sort by request time, so the last one is the most recent.
    recorded_requests.sort()

    access_point_present = False
    seal_state = 'none'
    try:
        investigation = resolve_investigation(
            clients['efs'], config['efs_filesystem_id'], cluster_id, investigation_id)
    except ValueError as error:
        investigation = None
        seal_state = f'unresolved: {error}'
    if investigation:
        access_point_present = True
        tags = investigation['tags']
        if TAG_SEAL in tags:
            seal_state = 'managed' if tags.get(TAG_MANAGED) == MANAGED_BY else 'legacy'

    if status_record:
        status = status_record.get('status', STATUS_UNKNOWN)
        result = {
            'action': 'close_status',
            'status': status,
            'phase': status_record.get('phase', ''),
            'reason': status_record.get('reason', ''),
            'request_token': status_record.get('request_token', ''),
            'attempt_id': status_record.get('attempt_id', ''),
            'directory_retained': bool(status_record.get('directory_retained', True)),
            'access_point_deleted': bool(status_record.get('access_point_deleted', False)),
            'access_point_path': status_record.get('access_point_path', ''),
            # Whether the scheduled reaper will pick this up again by itself.
            'retryable': bool(status_record.get('retryable', False)),
            'updated_at': status_record.get('updated_at', ''),
        }
    elif recorded_requests:
        result = {
            'action': 'close_status',
            'status': STATUS_ACCEPTED,
            'phase': 'queued',
            'reason': 'a close request is recorded and has not been picked up yet',
            'request_token': recorded_requests[-1][1],
            'attempt_id': '',
            'directory_retained': True,
            'access_point_deleted': False,
            'access_point_path': f'/{cluster_id}/{investigation_id}',
            'retryable': True,
            'updated_at': '',
        }
    else:
        result = {
            'action': 'close_status',
            'status': STATUS_NONE,
            'phase': '',
            'reason': 'no close request is recorded for this investigation',
            'request_token': '',
            'attempt_id': '',
            'directory_retained': True,
            'access_point_deleted': False,
            'access_point_path': f'/{cluster_id}/{investigation_id}',
            'retryable': False,
            'updated_at': '',
        }
    result.update({
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'open_requests': len(recorded_requests),
        'access_point_present': access_point_present,
        # Positive proof for newer CLI clients: never join an old task on the
        # strength of a different AP now occupying its investigation path.
        'join_access_point_id': (investigation['access_point_id'] if investigation
                                 and investigation['available'] and tags.get('CreatedAt')
                                 and seal_state == 'none' and status_record is None
                                 and not request_keys else ''),
        'seal': seal_state,
    })
    return result


def _require_investigation(config, clients, cluster_id, investigation_id):
    try:
        investigation = resolve_investigation(
            clients['efs'], config['efs_filesystem_id'], cluster_id, investigation_id)
    except ValueError as error:
        raise CloseRequestError(409, str(error))
    except (ClientError, BotoCoreError):
        raise CloseRequestError(503, 'the investigation workspace could not be resolved; '
                                     'retry before assuming any outcome')
    if investigation is None:
        raise CloseRequestError(404, 'investigation workspace not found')
    return investigation


_HANDLERS = {
    'request_close': handle_request_close,
    'register_auto_close': handle_register_auto_close,
    'cancel_auto_close': handle_cancel_auto_close,
    'close_status': handle_close_status,
}


def dispatch(action, body, identity, config, clients=None):
    """Run one close action and return its response body.

    ``config`` carries the deployment values the handler already resolved
    (``audit_bucket``, ``ecs_cluster``, ``efs_filesystem_id``, ``account_id``
    and the shared ``started_by`` function). ``clients`` is injected by tests.
    """
    if action not in _HANDLERS:
        raise CloseRequestError(400, f'unsupported action: {action}')
    if not config.get('audit_bucket'):
        raise CloseRequestError(500, 'close requests are not configured in this deployment')
    clients = clients or {}
    if 's3' not in clients:
        clients['s3'] = _s3()
    try:
        return _HANDLERS[action](body, identity, config, clients)
    except CloseRequestError:
        raise
    except ValueError as error:
        raise CloseRequestError(400, str(error))
    except (ClientError, BotoCoreError):
        # Outcome unknown: never let a transport failure read as a completed close.
        logger.exception('Close action %s failed against AWS', action)
        raise CloseRequestError(503, 'the close service could not complete this request; '
                                     'look up its status before retrying')
