"""Drive both close-authorization implementations with the same observations.

The matrix is enforced twice on purpose: the request handler decides whether to
record a request, and the reaper re-derives the answer for itself immediately
before it mutates anything. That independence is a feature — but only if the
two agree about what they are looking at. These tests feed identical fake ECS
and SSM clients to both and require identical verdicts.

The matrix under test:

  held by SRE A      -> only A may close (the creator has no standing)
  handed over to B   -> only B may close; A's earlier request is superseded
  no active sessions -> any authenticated Boundary SRE may close
  anything unclear   -> unknown; nobody may close, retry later

"Held" is observed from the *attached session*, never from the task. A RUNNING
task whose SRE has detached is idle: its `oidc_sub` tag is provenance, and
letting it confer ownership would give a departed CLI a veto nobody can clear.
What a running task does still control is stop consent, which is enforced
separately by the finalizer and is not part of this matrix.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
REAPER = ROOT / 'lambda' / 'reap-investigations'
CREATE = ROOT / 'lambda' / 'create-investigation'


def load(path, name, extra_paths=()):
    for extra in extra_paths:
        if str(extra) not in sys.path:
            sys.path.insert(0, str(extra))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# investigation_sessions imports boundary_close_records by plain module name,
# exactly as it does inside the Lambda bundle.
sessions = load(REAPER / 'investigation_sessions.py', 'investigation_sessions', (REAPER,))
with patch('boto3.client'):
    requests = load(CREATE / 'close_requests.py', 'close_requests_contract')

HOLDER = 'sre-a'
OTHER = 'sre-b'
CREATOR = 'sre-creator'
TASK_A = 'a' * 32
TASK_B = 'b' * 32
CLUSTER = 'test-cluster'


def task(task_id, sub, status='RUNNING', runtime='runtime-1', tagged=True, containers=None):
    return {
        'taskArn': f'arn:aws:ecs:us-east-1:1:task/{CLUSTER}/{task_id}',
        'lastStatus': status,
        'desiredStatus': status,
        'tags': [{'key': 'oidc_sub', 'value': sub}] if tagged else [],
        'containers': (containers if containers is not None
                       else ([{'runtimeId': runtime}] if runtime else [{}])),
    }


def clients(tasks=(), sessions_active=0, sessions_by_task=None, describe_error=False,
            session_error=False, describe_tasks=None, failures=(), list_error=False):
    ecs = MagicMock()
    ssm = MagicMock()
    task_list = list(tasks)
    paginator = MagicMock()
    if list_error:
        paginator.paginate.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'ListTasks')
    else:
        paginator.paginate.return_value = [{'taskArns': [t['taskArn'] for t in task_list]}]
    ecs.get_paginator.return_value = paginator
    if describe_error:
        ecs.describe_tasks.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'DescribeTasks')
    else:
        ecs.describe_tasks.return_value = {
            'tasks': task_list if describe_tasks is None else describe_tasks,
            'failures': list(failures),
        }
    if session_error:
        ssm.describe_sessions.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'DescribeSessions')
    elif sessions_by_task is not None:
        # The SSM target embeds the task id, so per-task session counts are
        # what let a test attach one SRE and leave another's task detached.
        def answer(State, Filters):
            target = Filters[0]['value']
            count = next((n for task_id, n in sessions_by_task.items() if task_id in target), 0)
            return {'Sessions': [{'SessionId': f's{i}'} for i in range(count)]}

        ssm.describe_sessions.side_effect = answer
    else:
        ssm.describe_sessions.return_value = {
            'Sessions': [{'SessionId': f's{i}'} for i in range(sessions_active)]}
    return ecs, ssm


SCENARIOS = {
    'idle': dict(tasks=()),
    'held with an attached session': dict(tasks=[task(TASK_A, HOLDER)], sessions_active=1),
    # The settled rule: a task that is still RUNNING after its SRE detached
    # does not hold the investigation.
    'running task with no attached session': dict(tasks=[task(TASK_A, HOLDER)],
                                                  sessions_active=0),
    'handed over to another SRE': dict(tasks=[task(TASK_B, OTHER)], sessions_active=1),
    'only stopped tasks': dict(tasks=[task(TASK_A, HOLDER, status='STOPPED')]),
    'one of two tasks is attached': dict(tasks=[task(TASK_A, HOLDER), task(TASK_B, OTHER)],
                                         sessions_by_task={TASK_A: 1, TASK_B: 0}),
    'two SREs attached at once': dict(tasks=[task(TASK_A, HOLDER), task(TASK_B, OTHER)],
                                      sessions_by_task={TASK_A: 1, TASK_B: 1}),
    'two detached tasks of different SREs': dict(tasks=[task(TASK_A, HOLDER),
                                                        task(TASK_B, OTHER)]),
    'untagged running task': dict(tasks=[task(TASK_A, HOLDER, tagged=False)]),
    'task with no session target': dict(tasks=[task(TASK_A, HOLDER, runtime=None)]),
    # A task reporting no containers at all tells us nothing about its
    # sessions, which is not the same as telling us none are attached.
    'task reporting no containers': dict(tasks=[task(TASK_A, HOLDER, containers=[])]),
    # One container is attached and a second has no session target: the
    # attached count must not be published from a half-read task.
    'half-readable multi-container task': dict(
        tasks=[task(TASK_A, HOLDER, containers=[{'runtimeId': 'r1'}, {}])],
        sessions_active=1),
    'task list failed': dict(tasks=[task(TASK_A, HOLDER)], list_error=True),
    'task description failed': dict(tasks=[task(TASK_A, HOLDER)], describe_error=True),
    'session scan failed': dict(tasks=[task(TASK_A, HOLDER)], session_error=True),
    'incomplete description': dict(tasks=[task(TASK_A, HOLDER)], describe_tasks=[]),
    'described with failures': dict(tasks=[task(TASK_A, HOLDER)],
                                    failures=[{'reason': 'MISSING'}]),
}


def observe_both(**kwargs):
    reaper = sessions.observe_investigation(*clients(**kwargs), CLUSTER, 'started-by')
    handler = requests.observe_investigation(*clients(**kwargs), CLUSTER, 'started-by')
    return reaper, handler


def comparable(observation):
    """Everything the two implementations must agree on.

    `reason` is included deliberately: it is what the status record and the
    retained evidence show an operator, so a silent divergence there is still
    a divergence.
    """
    return (observation['state'], observation['holder_sub'], observation['active_sessions'],
            observation['reason'],
            tuple(observation['task_owner_subs']),
            tuple(sorted(t['task_id'] for t in observation['tasks'])),
            tuple(sorted((t['task_id'], t['active_sessions']) for t in observation['tasks'])))


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_both_implementations_observe_the_same_thing(name):
    reaper, handler = observe_both(**SCENARIOS[name])
    assert comparable(reaper) == comparable(handler), name


@pytest.mark.parametrize('name,expected_state,expected_holder', [
    ('idle', 'idle', None),
    ('held with an attached session', 'active', HOLDER),
    ('running task with no attached session', 'idle', None),
    ('handed over to another SRE', 'active', OTHER),
    ('only stopped tasks', 'idle', None),
    ('one of two tasks is attached', 'active', HOLDER),
    ('two SREs attached at once', 'unknown', None),
    ('two detached tasks of different SREs', 'idle', None),
    ('untagged running task', 'unknown', None),
    ('task with no session target', 'unknown', None),
    ('task reporting no containers', 'unknown', None),
    ('half-readable multi-container task', 'unknown', None),
    ('task list failed', 'unknown', None),
    ('task description failed', 'unknown', None),
    ('session scan failed', 'unknown', None),
    ('incomplete description', 'unknown', None),
    ('described with failures', 'unknown', None),
])
def test_observed_states_match_the_documented_matrix(name, expected_state, expected_holder):
    reaper, _ = observe_both(**SCENARIOS[name])
    assert reaper['state'] == expected_state
    assert reaper['holder_sub'] == expected_holder


# The full state x actor matrix. Rows are what the service observed; columns
# are who asked. This is the authorization contract in one place, so a change
# to either implementation has to come here and argue with it.
MATRIX = {
    #                                           HOLDER  OTHER  CREATOR  anonymous
    'idle':                                    (True,  True,  True,  False),
    'only stopped tasks':                      (True,  True,  True,  False),
    'running task with no attached session':   (True,  True,  True,  False),
    'two detached tasks of different SREs':    (True,  True,  True,  False),
    'held with an attached session':           (True,  False, False, False),
    'one of two tasks is attached':            (True,  False, False, False),
    'handed over to another SRE':              (False, True,  False, False),
    'two SREs attached at once':               (False, False, False, False),
    'untagged running task':                   (False, False, False, False),
    'task with no session target':             (False, False, False, False),
    'task reporting no containers':            (False, False, False, False),
    'half-readable multi-container task':      (False, False, False, False),
    'task list failed':                        (False, False, False, False),
    'task description failed':                 (False, False, False, False),
    'session scan failed':                     (False, False, False, False),
    'incomplete description':                  (False, False, False, False),
    'described with failures':                 (False, False, False, False),
}


@pytest.mark.parametrize('name', sorted(MATRIX))
def test_the_state_by_actor_matrix_is_exactly_this(name):
    reaper, handler = observe_both(**SCENARIOS[name])
    for requester, expected in zip((HOLDER, OTHER, CREATOR, ''), MATRIX[name]):
        assert sessions.authorize_close(reaper, requester)[0] is expected, (name, requester)
        assert requests.authorize_close(handler, requester)[0] is expected, (name, requester)


def test_every_scenario_is_in_the_matrix():
    assert set(MATRIX) == set(SCENARIOS)


def test_a_running_task_alone_does_not_make_an_investigation_held():
    """The regression this matrix exists for.

    A RUNNING task whose SRE detached used to report `active`, held by the
    task's `oidc_sub` tag. That gave a departed CLI an exclusive claim that
    only its owner could clear, which is not the rule: the task tag is
    provenance, and with no session attached the investigation is idle.
    """
    reaper, handler = observe_both(**SCENARIOS['running task with no attached session'])
    for observation in (reaper, handler):
        assert observation['state'] == 'idle'
        assert observation['holder_sub'] is None
        # The running task is still reported, and so is whose it was.
        assert observation['task_owner_subs'] == [HOLDER]
        assert sessions.nonterminal_task_ids(observation) == [TASK_A]
        # Any eligible SRE may now ask, including one who never touched it.
        for requester in (HOLDER, OTHER, CREATOR):
            allowed, basis, _ = sessions.authorize_close(observation, requester)
            assert allowed is True
            assert basis == 'idle'


def test_idle_with_a_running_task_still_reports_the_task_for_stop_consent():
    """Authorization widened; consent did not.

    Being allowed to request close says nothing about being allowed to stop
    the task. The finalizer reads the same non-terminal task list to enforce
    stop scope, so the observation must keep reporting it.
    """
    reaper, _ = observe_both(**SCENARIOS['running task with no attached session'])
    assert reaper['state'] == 'idle'
    assert sessions.nonterminal_task_ids(reaper) == [TASK_A]
    assert reaper['active_sessions'] == 0


def test_a_detached_task_does_not_hide_an_attached_session_on_another_task():
    reaper, _ = observe_both(**SCENARIOS['one of two tasks is attached'])
    assert reaper['state'] == 'active'
    assert reaper['holder_sub'] == HOLDER
    assert reaper['active_sessions'] == 1
    # Both tasks are still reported, with the attachment recorded per task.
    counts = {t['task_id']: t['active_sessions'] for t in reaper['tasks']}
    assert counts == {TASK_A: 1, TASK_B: 0}


def test_two_SREs_attached_at_once_is_unknown_rather_than_a_guess():
    reaper, _ = observe_both(**SCENARIOS['two SREs attached at once'])
    assert reaper['state'] == 'unknown'
    assert reaper['holder_sub'] is None
    assert sessions.authorize_close(reaper, HOLDER)[1] == 'unknown'


@pytest.mark.parametrize('name', sorted(SCENARIOS))
@pytest.mark.parametrize('requester', [HOLDER, OTHER, CREATOR, ''])
def test_both_implementations_authorize_identically(name, requester):
    reaper, handler = observe_both(**SCENARIOS[name])
    assert (sessions.authorize_close(reaper, requester)[:2]
            == requests.authorize_close(handler, requester)[:2])


def test_the_creator_gets_nothing_from_having_created_the_investigation():
    reaper, _ = observe_both(**SCENARIOS['held with an attached session'])
    assert sessions.authorize_close(reaper, CREATOR)[0] is False
    assert sessions.authorize_close(reaper, HOLDER)[0] is True


def test_unknown_is_never_treated_as_idle():
    for name in ('two SREs attached at once', 'task list failed', 'task description failed',
                 'session scan failed', 'incomplete description', 'untagged running task',
                 'task with no session target', 'task reporting no containers',
                 'half-readable multi-container task', 'described with failures'):
        reaper, _ = observe_both(**SCENARIOS[name])
        allowed, basis, _ = sessions.authorize_close(reaper, HOLDER)
        assert allowed is False
        assert basis == 'unknown', name


def test_an_idle_investigation_is_closable_by_any_authenticated_sre():
    reaper, _ = observe_both(**SCENARIOS['idle'])
    for requester in (HOLDER, OTHER, CREATOR, 'sre-on-call'):
        assert sessions.authorize_close(reaper, requester)[0] is True
    # Still not by an unauthenticated caller.
    assert sessions.authorize_close(reaper, '')[0] is False


def test_a_handover_supersedes_an_earlier_request_rather_than_honouring_it():
    reaper, _ = observe_both(**SCENARIOS['handed over to another SRE'])
    request = {'requester_sub': HOLDER}
    reason = sessions.request_superseded(request, reaper)
    assert 'superseded' in reason
    # The new holder's own request is still actionable.
    assert sessions.request_superseded({'requester_sub': OTHER}, reaper) == ''


def test_an_idle_investigation_lets_an_earlier_request_proceed_after_revalidation():
    reaper, _ = observe_both(**SCENARIOS['idle'])
    assert sessions.request_superseded({'requester_sub': HOLDER}, reaper) == ''


def test_a_partially_readable_task_never_publishes_a_session_count_as_idle():
    """Half an observation is not an observation.

    One container reports an attached session and another exposes no session
    target. Neither "idle" nor a holder may be concluded from that, and the
    count that was read must not be presented as the whole truth.
    """
    for name in ('half-readable multi-container task', 'task reporting no containers'):
        reaper, handler = observe_both(**SCENARIOS[name])
        for observation in (reaper, handler):
            assert observation['state'] == 'unknown', name
            assert observation['holder_sub'] is None, name
        # And both implementations agree on every observable detail, including
        # how far each got before giving up.
        assert comparable(reaper) == comparable(handler), name


def test_an_unknown_observation_defers_a_request_without_rejecting_its_author():
    reaper, _ = observe_both(**SCENARIOS['task description failed'])
    reason = sessions.request_superseded({'requester_sub': HOLDER}, reaper)
    assert reason
    assert 'superseded' not in reason
