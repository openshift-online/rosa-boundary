"""
Unit tests for the authenticated close request/status actions.

The front door's job is to decide who may ask, to record what they asked for,
and to answer status questions. These tests concentrate on the decisions that
would be dangerous to get wrong: granting a close from an old creator tag,
treating an unknown observation as idle, letting a duplicate request widen
consent, or reporting a persisted request when nothing was written.
"""

import io
import json
import re
from unittest.mock import MagicMock, Mock, patch

import pytest
from botocore.exceptions import ClientError

import close_requests

CLUSTER = 'cluster-1'
INVESTIGATION = 'inv-1'
ACCESS_POINT = 'fsap-00000000'
HOLDER = 'sre-a'
OTHER_SRE = 'sre-b'
CREATOR = 'sre-creator'
TASK_ID = 'a' * 32
OTHER_TASK = 'b' * 32


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.put_calls = []

    def put_object(self, Bucket, Key, Body, **kwargs):  # noqa: N803
        self.put_calls.append(Key)
        self.objects[Key] = Body if isinstance(Body, bytes) else Body.encode()
        return {}

    def get_object(self, Bucket, Key, **kwargs):  # noqa: N803
        if Key not in self.objects:
            raise ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        return {'Body': io.BytesIO(self.objects[Key])}

    def list_objects_v2(self, Bucket, Prefix, MaxKeys, **kwargs):
        return {'Contents': [{'Key': key} for key in sorted(self.objects)
                             if key.startswith(Prefix)][:MaxKeys]}

    def get_paginator(self, name):
        assert name == 'list_objects_v2'
        store = self

        class Paginator:
            def paginate(self, Bucket, Prefix='', **kwargs):  # noqa: N803
                yield {'Contents': [{'Key': key} for key in sorted(store.objects)
                                    if key.startswith(Prefix)]}

        return Paginator()

    def json_at(self, key):
        return json.loads(self.objects[key].decode())


def test_missing_or_unreadable_record_with_prefix_scoped_list_permission():
    s3 = MagicMock()
    s3.get_object.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'GetObject')
    key = '_boundary-close/status/c/i.json'
    s3.list_objects_v2.return_value = {'Contents': [{'Key': key + '.other'}]}
    assert close_requests._get_json(s3, 'audit', key, '123') is None
    s3.list_objects_v2.assert_called_once_with(Bucket='audit', Prefix=key, MaxKeys=1,
                                              ExpectedBucketOwner='123')
    s3.list_objects_v2.return_value = {'Contents': [{'Key': key}]}
    with pytest.raises(ClientError):
        close_requests._get_json(s3, 'audit', key, '123')


def access_point_page(tags=None, path=None, ap_id=ACCESS_POINT):
    tags = tags or {'ClusterID': CLUSTER, 'InvestigationID': INVESTIGATION,
                    'ManagedBy': 'rosa-boundary-lambda', 'oidc_sub': CREATOR}
    return {'AccessPoints': [{
        'AccessPointId': ap_id,
        'FileSystemId': 'fs-1',
        'LifeCycleState': 'available',
        'RootDirectory': {'Path': path or f'/{CLUSTER}/{INVESTIGATION}'},
        'Tags': [{'Key': key, 'Value': value} for key, value in tags.items()],
    }]}


def task(task_id=TASK_ID, sub=HOLDER, status='RUNNING', runtime='runtime-1'):
    containers = [{'runtimeId': runtime}] if runtime else [{}]
    return {
        'taskArn': f'arn:aws:ecs:us-east-1:1:task/test-cluster/{task_id}',
        'lastStatus': status,
        'desiredStatus': status,
        'tags': [{'key': 'oidc_sub', 'value': sub}],
        'containers': containers,
    }


class Harness:
    def __init__(self, tasks=(), sessions=0, pages=None):
        self.s3 = FakeS3()
        self.ecs = MagicMock()
        self.efs = MagicMock()
        self.ssm = MagicMock()

        task_list = list(tasks)
        list_paginator = MagicMock()
        list_paginator.paginate.return_value = [
            {'taskArns': [entry['taskArn'] for entry in task_list]}]
        self.ecs.get_paginator.return_value = list_paginator
        self.ecs.describe_tasks.return_value = {'tasks': task_list, 'failures': []}
        self.ssm.describe_sessions.return_value = {
            'Sessions': [{'SessionId': f's{i}'} for i in range(sessions)]}

        efs_paginator = MagicMock()
        efs_paginator.paginate.return_value = pages if pages is not None else [
            access_point_page()]
        self.efs.get_paginator.return_value = efs_paginator

        self.config = {
            'audit_bucket': 'audit',
            'ecs_cluster': 'test-cluster',
            'efs_filesystem_id': 'fs-1',
            'account_id': '123456789012',
            'started_by': lambda cluster, investigation: 'started-by',
        }
        self.clients = {'ecs': self.ecs, 'efs': self.efs, 'ssm': self.ssm, 's3': self.s3}

    def request_key_for(self, token):
        """Find the recorded request by its token; the key leads with its time."""
        return next(key for key in self.s3.objects
                    if key.startswith(close_requests.requests_prefix(CLUSTER, INVESTIGATION))
                    and key.endswith(f'{token}.json'))

    def dispatch(self, action, body=None, sub=HOLDER, username='alice'):
        payload = {'cluster_id': CLUSTER, 'investigation_id': INVESTIGATION}
        payload.update(body or {})
        return close_requests.dispatch(action, payload, {'sub': sub, 'username': username},
                                       self.config, dict(self.clients))


def idle():
    return Harness()


def held_by(sub, sessions=1, tasks=None):
    return Harness(tasks=tasks or [task(sub=sub)], sessions=sessions)


# ---------------------------------------------------------------------------
# Observation and the authorization matrix
# ---------------------------------------------------------------------------


def test_no_tasks_and_no_sessions_is_idle():
    harness = idle()
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_IDLE
    assert result['holder_sub'] is None


def test_a_running_task_with_no_attached_session_is_idle_not_held():
    """A RUNNING task is not proof that an interactive session is attached.

    The task's `oidc_sub` tag is provenance. Reading it as ownership would let
    a detached CLI hold the investigation against every other SRE until its
    own owner came back, which is not the authorization rule.
    """
    harness = held_by(HOLDER, sessions=0)
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_IDLE
    assert result['holder_sub'] is None
    assert result['active_sessions'] == 0
    # The running task and its provenance are still reported: the finalizer
    # needs the task for stop consent, and an operator needs to see whose it is.
    assert result['task_owner_subs'] == [HOLDER]
    assert close_requests.nonterminal_task_ids(result) == [TASK_ID]
    assert close_requests.authorize_close(result, OTHER_SRE)[0] is True


def test_detached_tasks_of_different_SREs_are_idle_not_a_conflict():
    """With nobody attached there is no holder for two owners to contradict."""
    harness = Harness(tasks=[task(sub=HOLDER), task(OTHER_TASK, sub=OTHER_SRE)], sessions=0)
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_IDLE
    assert result['task_owner_subs'] == sorted([HOLDER, OTHER_SRE])


def test_two_attached_SREs_are_unknown_not_a_guess():
    harness = Harness(tasks=[task(sub=HOLDER), task(OTHER_TASK, sub=OTHER_SRE)], sessions=1)
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_UNKNOWN
    assert result['holder_sub'] is None


def test_an_incomplete_scan_is_unknown():
    harness = Harness(tasks=[task()])
    harness.ecs.describe_tasks.return_value = {'tasks': [], 'failures': []}
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_UNKNOWN


def test_a_failed_session_scan_is_unknown():
    harness = held_by(HOLDER)
    harness.ssm.describe_sessions.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'DescribeSessions')
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_UNKNOWN


def test_a_task_without_an_owner_tag_is_unknown():
    entry = task()
    entry['tags'] = []
    harness = Harness(tasks=[entry])
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_UNKNOWN


def test_stopped_tasks_do_not_hold_an_investigation():
    harness = Harness(tasks=[task(status='STOPPED')])
    result = close_requests.observe_investigation(harness.ecs, harness.ssm, 'test-cluster',
                                                  'started-by')
    assert result['state'] == close_requests.STATE_IDLE


@pytest.mark.parametrize('state,holder,requester,allowed', [
    (close_requests.STATE_IDLE, None, 'anyone', True),
    (close_requests.STATE_ACTIVE, HOLDER, HOLDER, True),
    (close_requests.STATE_ACTIVE, HOLDER, OTHER_SRE, False),
    (close_requests.STATE_ACTIVE, HOLDER, CREATOR, False),
    (close_requests.STATE_UNKNOWN, None, HOLDER, False),
    (close_requests.STATE_IDLE, None, '', False),
])
def test_authorization_matrix(state, holder, requester, allowed):
    observation = {'state': state, 'holder_sub': holder, 'reason': 'r'}
    assert close_requests.authorize_close(observation, requester)[0] is allowed


# ---------------------------------------------------------------------------
# request_close
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('trigger', close_requests.TRIGGERS)
@pytest.mark.parametrize('requester', [HOLDER, OTHER_SRE, CREATOR])
def test_attached_shell_refuses_close_without_recording(trigger, requester):
    harness = held_by(HOLDER)
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close', {'trigger': trigger, 'stop_scope': 'investigation'},
                         sub=requester)
    assert error.value.status_code == 409
    assert error.value.extra['state'] == close_requests.STATE_ACTIVE
    assert harness.s3.put_calls == []
    harness.ecs.stop_task.assert_not_called()


def test_an_idle_record_names_the_running_tasks_owner_without_making_them_holder():
    """What an operator needs to reconstruct an idle-with-running-task close.

    The record must show that a task was running and whose it was, while
    still recording that nobody held the investigation and that the close was
    authorized on the idle rule.
    """
    harness = held_by(HOLDER, sessions=0)
    result = harness.dispatch('request_close', sub=OTHER_SRE)
    assert result['status'] == close_requests.STATUS_ACCEPTED
    record = harness.s3.json_at(harness.request_key_for(result['request_token']))
    assert re.fullmatch(close_requests.REQUEST_TOKEN_PATTERN, result['request_token'])
    assert record['original_creator_sub'] == CREATOR
    assert record['authorization_basis'] == close_requests.STATE_IDLE
    assert record['requester_sub'] == OTHER_SRE
    assert record['observed_holder_sub'] == ''
    assert record['observation']['state'] == close_requests.STATE_IDLE
    assert record['observation']['active_sessions'] == 0
    assert record['observation']['task_owner_subs'] == [HOLDER]
    assert record['observation']['nonterminal_task_ids'] == [TASK_ID]


def test_explicit_request_does_not_reuse_a_session_callback_token():
    harness = Harness(tasks=[task()])
    callback = harness.dispatch('request_close', {'trigger': 'auto_close'})
    explicit = harness.dispatch('request_close')
    assert explicit['request_token'] != callback['request_token']


def test_an_idle_investigation_may_be_closed_by_any_authorized_sre():
    harness = idle()
    result = harness.dispatch('request_close', sub='sre-c')
    record = harness.s3.json_at(harness.request_key_for(result['request_token']))
    assert record['authorization_basis'] == close_requests.STATE_IDLE


def test_reattachment_blocks_duplicate_request_before_token_reuse():
    harness = Harness(tasks=[task()])
    harness.dispatch('request_close')
    writes = list(harness.s3.put_calls)
    harness.ssm.describe_sessions.side_effect = [
        {'Sessions': [], 'NextToken': 'more'}, {'Sessions': [{'SessionId': 'new'}]}]
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close')
    assert error.value.status_code == 409
    assert harness.s3.put_calls == writes


@pytest.mark.parametrize('trigger', close_requests.TRIGGERS)
def test_incomplete_session_scan_refuses_close_without_a_record(trigger):
    harness = Harness(tasks=[task()])
    harness.ssm.describe_sessions.side_effect = [{'Sessions': [], 'NextToken': 'more'}, {}]
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close', {'trigger': trigger})
    assert error.value.status_code == 409
    assert error.value.extra['state'] == close_requests.STATE_UNKNOWN
    assert harness.s3.put_calls == []


def test_an_unknown_state_is_retryable_not_a_permission_denial():
    harness = held_by(HOLDER)
    harness.ecs.describe_tasks.return_value = {'tasks': [], 'failures': []}
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close', sub=HOLDER)
    assert error.value.status_code == 409
    assert harness.s3.put_calls == []


def test_stop_consent_must_name_tasks_of_this_investigation():
    harness = Harness(tasks=[task()])
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close', {'stop_scope': 'session_task',
                                           'stop_task_ids': [OTHER_TASK]}, sub=HOLDER)
    assert error.value.status_code == 409


def test_stop_scope_validation_rejects_incoherent_consent():
    harness = idle()
    for body in ({'stop_scope': 'everything'},
                 {'stop_scope': 'session_task'},
                 {'stop_scope': 'investigation', 'stop_task_ids': [TASK_ID]},
                 {'stop_scope': 'session_task', 'stop_task_ids': ['not-a-task']}):
        with pytest.raises(close_requests.CloseRequestError) as error:
            harness.dispatch('request_close', body)
        assert error.value.status_code == 400


def test_an_unknown_trigger_is_refused():
    harness = idle()
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close', {'trigger': 'because'})
    assert error.value.status_code == 400


def test_the_request_key_leads_with_the_request_time():
    """The finalizer skips answered requests from the key alone; records are
    object-locked and never deleted."""
    harness = idle()
    result = harness.dispatch('request_close')
    key = harness.request_key_for(result['request_token'])
    parsed = close_requests.parse_request_filename(key.rsplit('/', 1)[-1])
    assert parsed is not None
    stamp, token = parsed
    assert token == result['request_token']
    record = harness.s3.json_at(key)
    assert close_requests.request_stamp(record['requested_at']) == stamp


def test_a_terminal_outcome_lets_the_same_sre_ask_again():
    """After a retained close the SRE must be able to resubmit; answering with
    the old token would leave the close with no way forward."""
    harness = Harness(tasks=[task()])
    first = harness.dispatch('request_close', sub=HOLDER)
    harness.s3.objects[close_requests.status_key(CLUSTER, INVESTIGATION)] = json.dumps({
        'kind': close_requests.KIND_STATUS, 'status': close_requests.STATUS_RETAINED,
        'request_token': first['request_token'], 'updated_at': '2026-01-01T00:00:00+00:00',
    }).encode()
    second = harness.dispatch('request_close', sub=HOLDER)
    assert second['duplicate'] is False
    assert second['request_token'] != first['request_token']
    assert len([key for key in harness.s3.objects if '/requests/' in key]) == 2


def test_consent_naming_a_different_task_is_a_new_request():
    """Dropping the newly consented task would leave the close waiting on it
    forever."""
    other = 'c' * 32
    harness = Harness(tasks=[task(sub=HOLDER), task(other, sub=HOLDER)])
    first = harness.dispatch('request_close', {'stop_scope': 'session_task',
                                               'stop_task_ids': [TASK_ID]}, sub=HOLDER)
    second = harness.dispatch('request_close', {'stop_scope': 'session_task',
                                                'stop_task_ids': [other]}, sub=HOLDER)
    assert second['duplicate'] is False
    assert second['request_token'] != first['request_token']


def test_a_duplicate_request_returns_the_existing_one_without_widening_consent():
    harness = Harness(tasks=[task()])
    first = harness.dispatch('request_close', sub=HOLDER)
    second = harness.dispatch('request_close', sub=HOLDER)
    assert second['duplicate'] is True
    assert second['request_token'] == first['request_token']
    assert len([key for key in harness.s3.objects if '/requests/' in key]) == 1


def test_a_request_with_wider_consent_is_recorded_separately():
    """Consent is per request: a narrow one never silently becomes a wide one."""
    harness = Harness(tasks=[task()])
    harness.dispatch('request_close', sub=HOLDER)
    harness.dispatch('request_close', {'stop_scope': 'investigation'}, sub=HOLDER)
    assert len([key for key in harness.s3.objects if '/requests/' in key]) == 2


def test_the_request_handler_never_seals_or_writes_status():
    harness = Harness(tasks=[task()])
    harness.dispatch('request_close', sub=HOLDER)
    harness.efs.tag_resource.assert_not_called()
    assert all('/requests/' in key for key in harness.s3.put_calls)


# ---------------------------------------------------------------------------
# Investigation identity
# ---------------------------------------------------------------------------


def test_a_missing_workspace_is_reported_as_not_found():
    harness = Harness(pages=[{'AccessPoints': []}])
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close')
    assert error.value.status_code == 404


def test_duplicate_access_points_refuse_the_close():
    page = access_point_page()
    page['AccessPoints'].append(dict(page['AccessPoints'][0], AccessPointId='fsap-11111111'))
    harness = Harness(pages=[page])
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close')
    assert error.value.status_code == 409


def test_conflicting_identity_tags_refuse_the_close():
    harness = Harness(pages=[access_point_page(tags={
        'ClusterID': 'somewhere-else', 'InvestigationID': INVESTIGATION,
        'ManagedBy': 'rosa-boundary-lambda'})])
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close')
    assert error.value.status_code == 409


def test_an_unmanaged_access_point_refuses_the_close():
    harness = Harness(pages=[access_point_page(tags={
        'ClusterID': CLUSTER, 'InvestigationID': INVESTIGATION, 'ManagedBy': 'someone'})])
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close')
    assert error.value.status_code == 409


def test_a_sealed_workspace_still_accepts_a_request():
    """Finalization can be resumed after a managed seal is already in place."""
    harness = Harness(pages=[access_point_page(tags={
        'ClusterID': CLUSTER, 'InvestigationID': INVESTIGATION,
        'ManagedBy': 'rosa-boundary-lambda', 'oidc_sub': CREATOR,
        close_requests.TAG_SEAL: '11111111-2222-4333-8444-555555555555',
        close_requests.TAG_MANAGED: close_requests.MANAGED_BY})])
    assert harness.dispatch('request_close')['status'] == close_requests.STATUS_ACCEPTED


# ---------------------------------------------------------------------------
# Auto-close intents
# ---------------------------------------------------------------------------


def test_registering_an_intent_records_the_selected_task():
    harness = held_by(HOLDER)
    result = harness.dispatch('register_auto_close', {'task_id': TASK_ID}, sub=HOLDER)
    assert result['registered'] is True
    record = harness.s3.json_at(close_requests.intent_key(CLUSTER, INVESTIGATION, TASK_ID))
    assert record['task_id'] == TASK_ID
    assert record['stop_scope'] == close_requests.STOP_SESSION_TASK
    assert record['cancelled'] is False


def test_an_intent_from_a_non_holder_is_refused():
    harness = held_by(HOLDER)
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('register_auto_close', {'task_id': TASK_ID}, sub=OTHER_SRE)
    assert error.value.status_code == 403


def test_an_intent_needs_a_real_task_identifier():
    harness = held_by(HOLDER)
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('register_auto_close', {'task_id': 'nope'}, sub=HOLDER)
    assert error.value.status_code == 400


def test_an_intent_cannot_be_registered_with_an_undefined_scope():
    harness = held_by(HOLDER)
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('register_auto_close', {'task_id': TASK_ID, 'stop_scope': 'none'},
                         sub=HOLDER)
    assert error.value.status_code == 400


def test_only_its_author_may_withdraw_an_intent():
    harness = held_by(HOLDER)
    harness.dispatch('register_auto_close', {'task_id': TASK_ID}, sub=HOLDER)
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('cancel_auto_close', {'task_id': TASK_ID}, sub=OTHER_SRE)
    assert error.value.status_code == 403
    result = harness.dispatch('cancel_auto_close', {'task_id': TASK_ID}, sub=HOLDER)
    assert result['cancelled'] is True
    assert harness.s3.json_at(
        close_requests.intent_key(CLUSTER, INVESTIGATION, TASK_ID))['cancelled'] is True


def test_cancelling_an_absent_intent_is_harmless():
    harness = held_by(HOLDER)
    assert harness.dispatch('cancel_auto_close', {'task_id': TASK_ID},
                            sub=HOLDER)['cancelled'] is False


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def test_status_reports_whether_a_retention_will_be_retried():
    harness = Harness(pages=[{'AccessPoints': []}])
    for retryable in (True, False):
        harness.s3.objects[close_requests.status_key(CLUSTER, INVESTIGATION)] = json.dumps({
            'kind': close_requests.KIND_STATUS, 'status': close_requests.STATUS_RETAINED,
            'phase': 'verify', 'reason': 'a task was observed after the copy',
            'retryable': retryable, 'directory_retained': True,
            'access_point_path': f'/{CLUSTER}/{INVESTIGATION}',
        }).encode()
        result = harness.dispatch('close_status')
        assert result['retryable'] is retryable
        # A retained directory must stay findable once the access point is gone.
        assert result['access_point_path'] == f'/{CLUSTER}/{INVESTIGATION}'


def test_status_without_any_request_says_so():
    harness = idle()
    result = harness.dispatch('close_status')
    assert result['status'] == close_requests.STATUS_NONE
    assert result['open_requests'] == 0


def test_status_reports_an_accepted_request_before_the_reaper_runs():
    harness = idle()
    submitted = harness.dispatch('request_close')
    result = harness.dispatch('close_status')
    assert result['status'] == close_requests.STATUS_ACCEPTED
    assert result['request_token'] == submitted['request_token']


def test_status_survives_access_point_deletion():
    harness = Harness(pages=[{'AccessPoints': []}])
    harness.s3.objects[close_requests.status_key(CLUSTER, INVESTIGATION)] = json.dumps({
        'kind': close_requests.KIND_STATUS, 'status': close_requests.STATUS_COMPLETED,
        'phase': 'finished', 'request_token': 'token-1', 'attempt_id': 'attempt-1',
        'directory_retained': True, 'access_point_deleted': True,
        'updated_at': '2026-01-01T00:00:00+00:00'}).encode()
    result = harness.dispatch('close_status')
    assert result['status'] == close_requests.STATUS_COMPLETED
    assert result['access_point_present'] is False
    assert result['directory_retained'] is True


def test_status_distinguishes_a_managed_seal_from_a_legacy_one():
    for tags, expected in (
        ({close_requests.TAG_SEAL: 'x', close_requests.TAG_MANAGED:
          close_requests.MANAGED_BY}, 'managed'),
        ({close_requests.TAG_SEAL: 'x'}, 'legacy'),
        ({}, 'none'),
    ):
        base = {'ClusterID': CLUSTER, 'InvestigationID': INVESTIGATION,
                'ManagedBy': 'rosa-boundary-lambda'}
        base.update(tags)
        harness = Harness(pages=[access_point_page(tags=base)])
        assert harness.dispatch('close_status')['seal'] == expected


def test_an_unreadable_status_is_not_reported_as_an_outcome():
    harness = idle()
    harness.s3.objects[close_requests.status_key(CLUSTER, INVESTIGATION)] = b'{}'
    with patch.object(harness.s3, 'get_object', side_effect=ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'GetObject')):
        with pytest.raises(close_requests.CloseRequestError) as error:
            harness.dispatch('close_status')
    assert error.value.status_code == 503


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_an_unsupported_action_is_refused():
    harness = idle()
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('delete_everything')
    assert error.value.status_code == 400


def test_a_deployment_without_an_audit_bucket_cannot_take_requests():
    harness = idle()
    harness.config['audit_bucket'] = ''
    with pytest.raises(close_requests.CloseRequestError) as error:
        harness.dispatch('request_close')
    assert error.value.status_code == 500


def test_a_transport_failure_never_reads_as_a_persisted_request():
    harness = Harness(tasks=[task()])
    with patch.object(harness.s3, 'put_object', side_effect=ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'PutObject')):
        with pytest.raises(close_requests.CloseRequestError) as error:
            harness.dispatch('request_close', sub=HOLDER)
    assert error.value.status_code == 503
    assert 'status before retrying' in error.value.message


def test_control_keys_reject_unsafe_identifiers():
    for cluster in ('../escape', 'a/b', '', '.hidden'):
        with pytest.raises(ValueError):
            close_requests.status_key(cluster, INVESTIGATION)


# ---------------------------------------------------------------------------
# Handler integration: dispatch and the best-effort launch checks
# ---------------------------------------------------------------------------

with patch('boto3.client'):
    import handler


@pytest.fixture(autouse=True)
def _no_real_aws_clients(monkeypatch):
    monkeypatch.setenv('S3_AUDIT_BUCKET', 'test-audit')
    monkeypatch.setenv('AWS_ACCOUNT_ID', '123456789012')
    with patch('boto3.client') as client:
        client.return_value.list_objects_v2.return_value = {'KeyCount': 0, 'IsTruncated': False}
        yield


def test_close_actions_reach_the_dispatcher_with_claims_identity():
    """Identity comes from the validated token, never from the request body."""
    with patch.object(close_requests, 'dispatch', return_value={'ok': True}) as dispatched:
        response = handler.handle_close_action(
            'request_close', {'cluster_id': CLUSTER, 'investigation_id': INVESTIGATION,
                              'requester_sub': 'forged'},
            'sre-real', 'alice')
    assert response['statusCode'] == 200
    identity = dispatched.call_args.args[2]
    assert identity == {'sub': 'sre-real', 'username': 'alice'}


def test_a_refused_close_action_keeps_its_status_code():
    error = close_requests.CloseRequestError(403, 'held by another SRE', state='active')
    with patch.object(close_requests, 'dispatch', side_effect=error):
        response = handler.handle_close_action('request_close', {}, 'sre', 'alice')
    assert response['statusCode'] == 403
    assert json.loads(response['body'])['state'] == 'active'


def _marker_pages(tags):
    paginator = MagicMock()
    paginator.paginate.return_value = [access_point_page(tags=tags)]
    return paginator


def test_close_marker_distinguishes_managed_from_legacy_seals():
    base = {'ClusterID': CLUSTER, 'InvestigationID': INVESTIGATION,
            'ManagedBy': 'rosa-boundary-lambda'}
    cases = [
        ({'CreatedAt': '2026-01-01T00:00:00Z'}, None),
        ({}, 'Legacy investigation workspace is retiring'),
        ({close_requests.TAG_SEAL: 'x'}, 'sealed for audit verification'),
        ({close_requests.TAG_SEAL: 'x',
          close_requests.TAG_MANAGED: close_requests.MANAGED_BY}, 'automated close'),
    ]
    for tags, expected in cases:
        with patch.object(handler, 'efs') as efs:
            efs.get_paginator.return_value = _marker_pages({**base, **tags})
            reason = handler.close_marker('fs-1', CLUSTER, INVESTIGATION)
        if expected is None:
            assert reason is None
        else:
            assert expected in reason


def test_a_retiring_workspace_cannot_be_reused_for_handover():
    with patch.object(handler, 'efs') as efs:
        efs.get_paginator.return_value = _marker_pages({
            'ClusterID': CLUSTER, 'InvestigationID': INVESTIGATION,
            'ManagedBy': 'rosa-boundary-lambda'})
        with pytest.raises(handler.HandoverFailedError, match='retiring'):
            handler.find_existing_access_point('fs-1', CLUSTER, INVESTIGATION)


@pytest.mark.parametrize('skip', [True, False])
@pytest.mark.parametrize('record,expected', [('request', 409), ('status', 409), ('denied', 503),
                                             ('incomplete', 503)])
def test_durable_admission_precedes_workspace_lookup_and_all_mutations(skip, record, expected):
    requests = close_requests.requests_prefix(CLUSTER, INVESTIGATION)
    status = close_requests.status_key(CLUSTER, INVESTIGATION)

    def listing(Bucket, ExpectedBucketOwner, MaxKeys, Prefix):
        assert (Bucket, ExpectedBucketOwner, MaxKeys) == ('test-audit', '123456789012', 1)
        assert Prefix in (requests, status)
        if record == 'denied':
            raise ClientError({'Error': {'Code': 'AccessDenied'}}, 'ListObjectsV2')
        if record == 'incomplete':
            return {}
        key = requests + 'unparsed' if record == 'request' else status
        contents = [{'Key': key}] if key.startswith(Prefix) else []
        return {'KeyCount': len(contents), 'Contents': contents, 'IsTruncated': False}

    with patch('boto3.client') as client, patch.object(handler, 'efs') as efs, \
            patch.object(handler, 'ecs') as ecs:
        client.return_value.list_objects_v2.side_effect = listing
        with pytest.raises(handler.HandoverFailedError) as failure:
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1', skip_task=skip)
        assert failure.value.status_code == expected
        assert not efs.mock_calls and not ecs.mock_calls


def test_close_accepted_during_handover_preflight_does_not_stop_the_old_task():
    existing = task(sub=OTHER_SRE)
    existing['tags'].append({'key': 'username', 'value': 'previous-user'})
    with patch.object(handler, 'require_durable_admission', side_effect=[
            None, handler.HandoverFailedError('Close accepted', status_code=409)]), \
            patch.object(handler, 'find_existing_access_point', return_value={'AccessPointId': ACCESS_POINT}), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[existing['taskArn']]), \
            patch.object(handler, 'ecs') as ecs, patch.object(handler, 'ssm') as ssm:
        ecs.describe_tasks.return_value = {'tasks': [existing]}
        ssm.describe_sessions.return_value = {'Sessions': []}
        with pytest.raises(handler.HandoverFailedError, match='Close accepted'):
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
        ssm.describe_sessions.assert_called_once()
        ecs.stop_task.assert_not_called()
        ecs.run_task.assert_not_called()


@pytest.mark.parametrize('accepted_after', ['ap', 'definition', 'launch', 'tag'])
def test_close_racing_creation_retains_the_ap_named_by_the_request(accepted_after):
    accepted = False

    def mutation(stage, result):
        def invoke(**kwargs):
            nonlocal accepted
            accepted |= stage == accepted_after
            return result
        return invoke

    def listing(**kwargs):
        prefix = close_requests.requests_prefix(CLUSTER, INVESTIGATION)
        contents = [{'Key': prefix + 'request'}] if accepted and kwargs['Prefix'] == prefix else []
        return {'KeyCount': len(contents), 'Contents': contents, 'IsTruncated': False}

    with patch('boto3.client') as s3, patch.object(handler, 'efs') as efs, \
            patch.object(handler, 'ecs') as ecs, patch.object(handler, 'sts'), \
            patch.object(handler, 'find_existing_access_point', return_value=None), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         side_effect=mutation('definition', 'def-1')) as register:
        s3.return_value.list_objects_v2.side_effect = listing
        efs.create_access_point.side_effect = mutation('ap', {'AccessPointId': ACCESS_POINT})
        ecs.run_task.side_effect = mutation('launch', {'tasks': [{'taskArn': 'arn:task/late'}]})
        ecs.tag_resource.side_effect = mutation('tag', {})
        with pytest.raises(handler.HandoverFailedError) as failure:
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
        assert failure.value.status_code == 409
        efs.delete_access_point.assert_not_called()
        assert register.called == (accepted_after != 'ap')
        assert ecs.deregister_task_definition.called == register.called
        assert ecs.tag_resource.called == (accepted_after == 'tag')
        assert ecs.run_task.called == (accepted_after in ('launch', 'tag'))
        assert ecs.stop_task.called == ecs.run_task.called


def test_join_proof_requires_the_current_available_dated_ap_and_no_records():
    page = access_point_page()
    ap = page['AccessPoints'][0]
    harness = Harness(pages=[page])

    def proof():
        return harness.dispatch('close_status')['join_access_point_id']

    assert not proof()  # retiring, undated AP
    ap['Tags'].append({'Key': 'CreatedAt', 'Value': '2026-01-01T00:00:00Z'})
    assert proof() == ACCESS_POINT
    ap['LifeCycleState'] = 'deleting'
    assert not proof()
    ap['LifeCycleState'] = 'available'
    harness.s3.objects[close_requests.status_key(CLUSTER, INVESTIGATION)] = b'{}'
    assert not proof()  # even a malformed status is not open
    harness.s3.objects.clear()
    harness.s3.objects[close_requests.requests_prefix(CLUSTER, INVESTIGATION) + 'malformed'] = b'{}'
    assert not proof()


def test_a_marker_observed_before_launch_stops_the_launch():
    """The pre-launch check fails closed and leaves nothing behind."""
    with patch.object(handler, 'close_marker', return_value='closing'), \
            patch.object(handler, 'find_existing_access_point',
                         return_value={'AccessPointId': ACCESS_POINT}), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         return_value='task-def-arn'), \
            patch.object(handler, 'sts') as sts, \
            patch.object(handler, 'ecs') as ecs:
        sts.get_caller_identity.return_value = {'Account': '1'}
        with pytest.raises(handler.HandoverFailedError) as error:
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
    assert error.value.status_code == 409
    ecs.run_task.assert_not_called()
    ecs.deregister_task_definition.assert_called_once_with(taskDefinition='task-def-arn')


def test_a_marker_observed_after_launch_stops_the_late_task():
    """Best effort, honestly: the late task is stopped and close stays pending."""
    markers = [None, 'closing']
    with patch.object(handler, 'close_marker', side_effect=lambda *a: markers.pop(0)), \
            patch.object(handler, 'find_existing_access_point',
                         return_value={'AccessPointId': ACCESS_POINT}), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         return_value='task-def-arn'), \
            patch.object(handler, 'sts') as sts, \
            patch.object(handler, 'ecs') as ecs:
        sts.get_caller_identity.return_value = {'Account': '1'}
        ecs.run_task.return_value = {'tasks': [{'taskArn': 'arn:task/late'}], 'failures': []}
        with pytest.raises(handler.HandoverFailedError) as error:
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
    assert error.value.status_code == 409
    assert 'remains pending' in str(error.value)
    ecs.stop_task.assert_called_once()
    ecs.deregister_task_definition.assert_called_once_with(taskDefinition='task-def-arn')


def test_an_unreadable_recheck_after_launch_leaves_the_session_running():
    """Ambiguity after launch is not a reason to kill a user's session; the
    reaper re-enumerates tasks before it attests to anything."""
    markers = [None, ClientError({'Error': {'Code': 'Throttling'}}, 'DescribeAccessPoints')]

    def marker(*_args):
        value = markers.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    with patch.object(handler, 'close_marker', side_effect=marker), \
            patch.object(handler, 'find_existing_access_point',
                         return_value={'AccessPointId': ACCESS_POINT}), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         return_value='task-def-arn'), \
            patch.object(handler, 'sts') as sts, \
            patch.object(handler, 'ecs') as ecs:
        sts.get_caller_identity.return_value = {'Account': '1'}
        ecs.run_task.return_value = {'tasks': [{'taskArn': 'arn:task/ok'}], 'failures': []}
        result = handler.create_investigation_task(
            cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
            username='alice', abac_tag_key='username', abac_tag_value='alice',
            investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
            security_group='sg', efs_filesystem_id='fs-1')
    assert result['taskArn'] == 'arn:task/ok'
    ecs.stop_task.assert_not_called()


@pytest.fixture
def authenticated_lambda(monkeypatch):
    """Configure handler.lambda_handler with a valid, group-authorized token."""
    for name, value in {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test',
        'KEYCLOAK_CLIENT_ID': 'test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': ['subnet-test'],
        'SECURITY_GROUP': 'sg-test',
        'EFS_FILESYSTEM_ID': 'fs-1',
        'SHARED_ROLE_ARN': 'test-role',
        'REQUIRED_GROUPS': ['sre-team'],
        'ABAC_TAG_KEY': 'username',
    }.items():
        monkeypatch.setattr(handler, name, value)
    claims = {'sub': HOLDER, 'preferred_username': 'alice', 'groups': ['sre-team']}
    token = Mock(return_value=claims)
    monkeypatch.setattr(handler, 'validate_oidc_token', token)
    return token


def close_event(**body):
    payload = {'action': 'request_close', 'cluster_id': CLUSTER,
               'investigation_id': INVESTIGATION}
    payload.update(body)
    return {'headers': {'x-oidc-token': 'token'}, 'body': json.dumps(payload)}


def test_the_dispatch_route_uses_the_validated_claims_not_the_request_body(authenticated_lambda):
    """A caller must not be able to name the requester it wants to be."""
    with patch.object(close_requests, 'dispatch', return_value={'ok': True}) as dispatched:
        response = handler.lambda_handler(close_event(requester_sub='forged'), None)
    assert response['statusCode'] == 200
    assert dispatched.call_args.args[2] == {'sub': HOLDER, 'username': 'alice'}


def test_a_close_action_is_refused_before_dispatch_when_the_token_is_invalid(
        authenticated_lambda):
    authenticated_lambda.return_value = None
    with patch.object(close_requests, 'dispatch') as dispatched:
        response = handler.lambda_handler(close_event(), None)
    assert response['statusCode'] == 401
    dispatched.assert_not_called()


def test_a_close_action_is_refused_before_dispatch_without_group_membership(
        authenticated_lambda):
    authenticated_lambda.return_value = {'sub': HOLDER, 'preferred_username': 'alice',
                                         'groups': ['someone-else']}
    with patch.object(close_requests, 'dispatch') as dispatched:
        response = handler.lambda_handler(close_event(), None)
    assert response['statusCode'] == 403
    dispatched.assert_not_called()


def test_a_close_action_never_emits_a_task_creation_metric(authenticated_lambda, capsys):
    with patch.object(close_requests, 'dispatch', return_value={'ok': True}):
        handler.lambda_handler(close_event(), None)
    assert 'TaskCreationRequests' not in capsys.readouterr().out


def test_a_marker_observed_before_launch_discards_an_access_point_it_created():
    """A second access point on the path would make every later close refuse
    the workspace as ambiguous."""
    with patch.object(handler, 'close_marker', return_value='closing'), \
            patch.object(handler, 'find_existing_access_point', return_value=None), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         return_value='task-def-arn'), \
            patch.object(handler, 'sts') as sts, \
            patch.object(handler, 'efs') as efs, \
            patch.object(handler, 'ecs'):
        sts.get_caller_identity.return_value = {'Account': '1'}
        efs.create_access_point.return_value = {'AccessPointId': ACCESS_POINT}
        with pytest.raises(handler.HandoverFailedError):
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
        efs.delete_access_point.assert_called_once_with(AccessPointId=ACCESS_POINT)


def test_a_marker_observed_after_launch_discards_an_access_point_it_created():
    markers = [None, 'closing']
    with patch.object(handler, 'close_marker', side_effect=lambda *a: markers.pop(0)), \
            patch.object(handler, 'find_existing_access_point', return_value=None), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         return_value='task-def-arn'), \
            patch.object(handler, 'sts') as sts, \
            patch.object(handler, 'efs') as efs, \
            patch.object(handler, 'ecs') as ecs:
        sts.get_caller_identity.return_value = {'Account': '1'}
        efs.create_access_point.return_value = {'AccessPointId': ACCESS_POINT}
        ecs.run_task.return_value = {'tasks': [{'taskArn': 'arn:task/late'}], 'failures': []}
        with pytest.raises(handler.HandoverFailedError):
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
        ecs.stop_task.assert_called_once()
        efs.delete_access_point.assert_called_once_with(AccessPointId=ACCESS_POINT)


def test_an_unreadable_marker_before_launch_fails_closed_and_cleans_up():
    with patch.object(handler, 'close_marker', side_effect=ClientError(
            {'Error': {'Code': 'Throttling'}}, 'DescribeAccessPoints')), \
            patch.object(handler, 'find_existing_access_point', return_value=None), \
            patch.object(handler, 'find_running_tasks_for_investigation', return_value=[]), \
            patch.object(handler, 'register_investigation_task_definition',
                         return_value='task-def-arn'), \
            patch.object(handler, 'sts') as sts, \
            patch.object(handler, 'efs') as efs, \
            patch.object(handler, 'ecs') as ecs:
        sts.get_caller_identity.return_value = {'Account': '1'}
        efs.create_access_point.return_value = {'AccessPointId': ACCESS_POINT}
        with pytest.raises(ClientError):
            handler.create_investigation_task(
                cluster='test-cluster', task_def='boundary', oidc_sub=HOLDER,
                username='alice', abac_tag_key='username', abac_tag_value='alice',
                investigation_id=INVESTIGATION, cluster_id=CLUSTER, subnets=['subnet'],
                security_group='sg', efs_filesystem_id='fs-1')
        ecs.run_task.assert_not_called()
        ecs.deregister_task_definition.assert_called_once_with(taskDefinition='task-def-arn')
        efs.delete_access_point.assert_called_once_with(AccessPointId=ACCESS_POINT)
