"""Observe who currently holds an investigation, and who may close it.

An investigation has one current owner at a time. Ownership is transferable by
handover and is *not* conferred permanently by having created the workspace:
the access point's ``oidc_sub`` tag is provenance only.

The trusted service-side signal is the pair of observations the service can
make for itself — the non-terminal ECS tasks launched for the investigation
(whose ``oidc_sub`` tag records the SRE the task was launched for) and the
active SSM sessions attached to those tasks. They answer two different
questions, and only one of them decides who holds the investigation:

* the **attached sessions** decide. A task's ``oidc_sub`` tag names the SRE a
  task was launched for; it is provenance, reported as ``task_owner_subs``,
  and it is never by itself authority over the investigation.
* a RUNNING task is **not** proof that an interactive session is attached. A
  running task with no attached session is an idle investigation: the SRE's
  shell is gone, so there is no holder for an exclusive right to belong to.
  Treating a running task as held would hand a departed CLI a permanent veto
  that nobody can clear.

Idle is not a licence to destroy anything. Being eligible to *request* close is
separate from consenting to stop a running task: the finalizer stops only tasks
the request's ``stop_scope`` consented to, and will not measure, copy or delete
a workspace while any task is non-terminal. A new request requires a confirmed
shell-free observation, and an admitted request waits if a shell later appears.

Anything incomplete, contradictory or unavailable is reported as ``unknown``:
a scan that failed, a non-terminal task whose owner tag or session target
cannot be read (so "no session attached" cannot be distinguished from "not
observed"), or two SREs attached at once. Unknown is never treated as idle and
never grants permission; it is retried.

The investigation reaper re-derives this observation before it mutates
anything; the authenticated request handler derives it when a request is
submitted. ``tests/unit/test_close_authorization_contract.py`` drives both
implementations with the same fakes so the matrix cannot drift between them.
"""

import logging

from botocore.exceptions import BotoCoreError, ClientError

from boundary_close_records import (
    STATE_ACTIVE,
    STATE_IDLE,
    STATE_UNKNOWN,
    now_iso,
)

logger = logging.getLogger(__name__)

# describe_tasks accepts at most 100 identifiers per call.
DESCRIBE_CHUNK = 100


def _chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _list_task_arns(ecs, ecs_cluster, started_by):
    paginator = ecs.get_paginator('list_tasks')
    # startedBy must be the only ECS filter. Its default desired status is
    # RUNNING; also look for tasks asked to stop but not yet terminal.
    def inventory(**filters):
        arns = set()
        for page in paginator.paginate(cluster=ecs_cluster, **filters):
            if not isinstance(page.get('taskArns'), list):
                raise ValueError('missing ECS task inventory')
            arns.update(page['taskArns'])
        return arns

    matching = inventory(startedBy=started_by)
    stopping = inventory(desiredStatus='STOPPED')
    return matching, sorted(matching | stopping)


def _active_session_count(ssm, ecs_cluster, task_id, containers):
    """Scan every runtime target and page; partial evidence cannot prove idle."""
    total = 0
    incomplete = not containers
    for container in containers:
        runtime_id = container.get('runtimeId')
        if not runtime_id:
            incomplete = True
            continue
        params = {'State': 'Active', 'Filters': [
            {'key': 'Target', 'value': f'ecs:{ecs_cluster}_{task_id}_{runtime_id}'}]}
        seen = set()
        while True:
            page = ssm.describe_sessions(**params)
            sessions = page.get('Sessions') if isinstance(page, dict) else None
            if not isinstance(sessions, list):
                incomplete = True
                break
            total += len(sessions)
            if 'NextToken' not in page:
                break
            token = page['NextToken']
            if not isinstance(token, str) or not token or token in seen:
                incomplete = True
                break
            seen.add(token)
            params['NextToken'] = token
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


def _task_owner_subs(tasks):
    """Provenance only: who the non-terminal tasks were launched for.

    Recorded so an operator reading a request or a status can see that a task
    is still running and who launched it. It is deliberately not consulted by
    ``authorize_close``.
    """
    return sorted({task['oidc_sub'] for task in tasks or []
                   if task['last_status'] != 'STOPPED' and task['oidc_sub']})


def observe_investigation(ecs, ssm, ecs_cluster, started_by):
    """Return the current ownership observation for one investigation.

    ``started_by`` is the deterministic launch marker shared by the create and
    reaper Lambdas; it is set at launch time and so avoids the tag-propagation
    race that a cluster-wide tag scan would hit.
    """
    try:
        matching, arns = _list_task_arns(ecs, ecs_cluster, started_by)
    except (ValueError, ClientError, BotoCoreError) as error:
        logger.warning('Cannot list investigation tasks: %s', type(error).__name__)
        return _unknown('task scan failed; investigation state is unknown')

    described = []
    for chunk in _chunks(arns, DESCRIBE_CHUNK):
        try:
            response = ecs.describe_tasks(cluster=ecs_cluster, tasks=chunk, include=['TAGS'])
        except (ClientError, BotoCoreError) as error:
            logger.warning('Cannot describe investigation tasks: %s', type(error).__name__)
            return _unknown('task description failed; investigation state is unknown')
        if response.get('failures'):
            return _unknown('task description reported failures; investigation state is unknown')
        tasks = response.get('tasks', [])
        if {task.get('taskArn') for task in tasks} != set(chunk):
            # A listed task that cannot be described is an incomplete scan, not
            # an absent task.
            return _unknown('task description is incomplete; investigation state is unknown')
        described.extend(task for task in tasks
                         if task.get('taskArn') in matching or task.get('startedBy') == started_by)

    observed = []
    session_holders = set()
    active_sessions = 0
    for task in described:
        task_id = (task.get('taskArn') or '').rsplit('/', 1)[-1]
        last_status = task.get('lastStatus', '')
        desired_status = task.get('desiredStatus', '')
        tags = {tag['key']: tag['value'] for tag in task.get('tags', [])}
        entry = {
            'task_id': task_id,
            'last_status': last_status,
            'desired_status': desired_status,
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
            # The owner tag is missing, so an attached session could not be
            # attributed to anyone. That is an unreadable observation, not an
            # idle investigation.
            return _unknown('a non-terminal task has no owner tag; investigation state is unknown',
                            tasks=observed)
        try:
            count, incomplete = _active_session_count(
                ssm, ecs_cluster, task_id, task.get('containers', []))
        except (ClientError, BotoCoreError) as error:
            logger.warning('Cannot describe sessions: %s', type(error).__name__)
            return _unknown('session scan failed; investigation state is unknown', tasks=observed,
                            active_sessions=active_sessions)
        if incomplete:
            # Without a session target there is no way to tell an unattached
            # task from an unobserved one. Fail closed rather than guess idle.
            return _unknown('a non-terminal task has incomplete session evidence; '
                            'investigation state is unknown', tasks=observed,
                            active_sessions=active_sessions)
        entry['active_sessions'] = count
        active_sessions += count
        if count:
            session_holders.add(entry['oidc_sub'])

    nonterminal = [task for task in observed if task['last_status'] != 'STOPPED']
    owners = _task_owner_subs(observed)
    if len(session_holders) > 1:
        # Two SREs are attached at once. Which one holds it is genuinely
        # contradictory, so nobody closes it on this observation.
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
    # No attached session was observed anywhere, and every non-terminal task
    # was read completely. The investigation is idle even if a task is still
    # RUNNING: the running task is reported so the caller can see it, and the
    # finalizer still needs stop consent before it touches that task.
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
    """Apply the close authorization matrix.

    Returns ``(allowed, basis, reason)``. ``basis`` is ``holder`` when the
    requester is the SRE whose session is attached and ``idle`` when no session
    is attached. An explicit requester does not lose standing on handover. Actor eligibility
    alone does not admit a new request or authorize sealing with a shell attached.

    ``task_owner_subs`` is deliberately not consulted: having launched a task,
    like having created the workspace, is provenance and not authority.
    """
    state = observation.get('state')
    if state not in (STATE_ACTIVE, STATE_IDLE):
        return False, STATE_UNKNOWN, observation.get('reason') or 'investigation state is unknown'
    if not requester_sub:
        return False, 'unauthenticated', 'the requester has no authenticated subject'
    if state == STATE_IDLE:
        # No attached session, so no current holder: any authenticated SRE
        # authorized to use Boundary may seal and close. Creating the
        # investigation, or having launched a task that is still running,
        # confers no extra authority and imposes no extra restriction.
        return True, STATE_IDLE, ''
    if requester_sub == observation.get('holder_sub'):
        return True, 'holder', ''
    if explicit:
        return True, 'authorized_sre', ''
    return False, 'not_holder', 'session close callback refused: another SRE is attached'


def request_superseded(request, observation):
    """Return a reason when a persisted request may no longer be acted on.

    Handover supersedes session callbacks and intents, not explicit requests.
    """
    allowed, basis, reason = authorize_close(
        observation, request.get('requester_sub', ''), explicit=request.get('trigger') == 'cli_close')
    if allowed:
        return ''
    if basis == 'not_holder':
        return ('superseded: the investigation changed hands after this request; '
                'a fresh request from an eligible SRE is required')
    return reason or 'the request could not be revalidated'
