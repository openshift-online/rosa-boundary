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
