"""
Unit tests for the shared investigation close finalization pipeline.

The pipeline is the only route to deletion, so these tests concentrate on what
must *not* happen: closing on someone else's authority, attesting to a copy
that was never verified, deleting a directory a normal close promised to keep,
and reporting a timer expiry or a partial copy as a completed close.

The fakes are deliberately literal — an in-memory versioned S3, a real
temporary workspace on disk — so the copy and the independent comparison are
exercised rather than mocked past.
"""

import hashlib
import io
import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

import boundary_close_records as records
import close_finalization
import workspace_verification

CLUSTER = 'cluster-1'
INVESTIGATION = 'inv-1'
ACCESS_POINT = 'fsap-00000000'
HOLDER = 'sre-a'
OTHER_SRE = 'sre-b'
TASK_ID = 'a' * 32
REQUEST_TOKEN = '11111111-2222-4333-8444-555555555555'


class FakeS3:
    """Minimal versioned object store with the calls the finalizer uses."""

    def __init__(self):
        self.objects = {}
        self.version = 0
        self.put_failures = set()

    # -- writes ---------------------------------------------------------

    def _store(self, key, body):
        self.version += 1
        self.objects[key] = {'body': body, 'version': f'v{self.version}'}

    def put_object(self, Bucket, Key, Body, **kwargs):  # noqa: N803 (boto3 casing)
        if Key in self.put_failures:
            raise ClientError({'Error': {'Code': 'AccessDenied'}}, 'PutObject')
        self._store(Key, Body if isinstance(Body, bytes) else Body.encode())
        return {'VersionId': self.objects[Key]['version']}

    def upload_fileobj(self, Fileobj, Bucket, Key, ExtraArgs=None):  # noqa: N803
        self._store(Key, Fileobj.read())

    # -- reads ----------------------------------------------------------

    def get_object(self, Bucket, Key, **kwargs):  # noqa: N803
        if Key not in self.objects:
            raise ClientError({'Error': {'Code': 'NoSuchKey'}}, 'GetObject')
        entry = self.objects[Key]
        return {'Body': io.BytesIO(entry['body']), 'VersionId': entry['version']}

    def get_paginator(self, name):
        assert name == 'list_objects_v2'
        store = self

        class Paginator:
            def paginate(self, Bucket, Prefix='', **kwargs):  # noqa: N803
                contents = [{'Key': key} for key in sorted(store.objects)
                            if key.startswith(Prefix)]
                yield {'Contents': contents}

        return Paginator()

    # -- helpers --------------------------------------------------------

    def json_at(self, key):
        return json.loads(self.objects[key]['body'].decode())

    def keys_under(self, prefix):
        return sorted(key for key in self.objects if key.startswith(prefix))


class FakeContext:
    def __init__(self, seconds=600):
        self.seconds = seconds

    def get_remaining_time_in_millis(self):
        return int(self.seconds * 1000) + 30000


def observation(state, holder=None, tasks=(), active_sessions=None):
    tasks = list(tasks)
    if active_sessions is None:
        active_sessions = sum(task.get('active_sessions', 0) for task in tasks)
    return {
        'state': state,
        'holder_sub': holder,
        'active_sessions': active_sessions,
        'tasks': tasks,
        # Provenance of the non-terminal tasks; never authority. An idle
        # investigation can still list owners here if a task is running.
        'task_owner_subs': sorted({task['oidc_sub'] for task in tasks
                                   if task['last_status'] != 'STOPPED' and task['oidc_sub']}),
        'reason': 'test observation',
        'observed_at': '2026-01-01T00:00:00+00:00',
    }


def running_task(task_id=TASK_ID, sub=HOLDER, active_sessions=0):
    return {'task_id': task_id, 'last_status': 'RUNNING', 'desired_status': 'RUNNING',
            'oidc_sub': sub, 'active_sessions': active_sessions}


def attached_task(task_id=TASK_ID, sub=HOLDER):
    """A task with a live shell on it — the only thing that makes a holder."""
    return running_task(task_id, sub, active_sessions=1)


def stopped_task(task_id=TASK_ID, sub=HOLDER):
    return {'task_id': task_id, 'last_status': 'STOPPED', 'desired_status': 'STOPPED',
            'oidc_sub': sub, 'active_sessions': 0}


class FinalizerCase(unittest.TestCase):
    def setUp(self):
        self.s3 = FakeS3()
        self.ecs = MagicMock()
        self.efs = MagicMock()
        self.ssm = MagicMock()
        self.root = Path(self.enterContext(__import__('tempfile').TemporaryDirectory()))
        self.workspace = self.root / CLUSTER / INVESTIGATION
        self.workspace.mkdir(parents=True)
        (self.workspace / 'notes.txt').write_text('investigation notes')
        (self.workspace / 'nested').mkdir()
        (self.workspace / 'nested' / 'log').write_text('line\n')
        # Credential material must never be copied into audit evidence.
        (self.workspace / '.kube').mkdir()
        (self.workspace / '.kube' / 'config').write_text('secret kubeconfig')
        (self.workspace / '.config' / 'ocm').mkdir(parents=True)
        (self.workspace / '.config' / 'ocm' / 'token').write_text('secret ocm token')

        self.enterContext(patch('close_finalization.os.path.ismount', return_value=True))
        # No test should wait for the quiet interval in real time.
        self.sleeps = []

        paginator = MagicMock()
        paginator.paginate.return_value = [{'taskDefinitionArns': []}]
        self.ecs.get_paginator.return_value = paginator

        self.finalizer = close_finalization.Finalizer(
            ecs=self.ecs, efs=self.efs, s3=self.s3, ssm=self.ssm,
            ecs_cluster='test-cluster', efs_filesystem_id='fs-1', audit_bucket='audit',
            account_id='123456789012', mount_path=str(self.root),
            started_by=lambda c, i: 'started-by', task_definition_family='boundary',
            quiet_seconds=1)

        self.observations = [observation(records.STATE_IDLE)]
        self.finalizer.observe = MagicMock(side_effect=self._next_observation)

    def _next_observation(self, *_args):
        if len(self.observations) > 1:
            return self.observations.pop(0)
        return self.observations[0]

    def sleep(self, seconds):
        self.sleeps.append(seconds)

    def access_point(self, tags=None):
        return {'id': ACCESS_POINT, 'tags': dict(tags or {}), 'file_system_id': 'fs-1',
                'path': f'/{CLUSTER}/{INVESTIGATION}'}

    def request(self, **overrides):
        record = {
            'request_token': REQUEST_TOKEN,
            'cluster_id': CLUSTER,
            'investigation_id': INVESTIGATION,
            'access_point_id': ACCESS_POINT,
            'requester_sub': HOLDER,
            'stop_scope': records.STOP_NONE,
            'stop_task_ids': [],
            'trigger': 'cli_close',
            'requested_at': '2026-01-01T00:00:00+00:00',
        }
        record.update(overrides)
        return record

    def finalize(self, mode='request', access_point=None, request=None, seconds=600):
        return self.finalizer.finalize(
            cluster_id=CLUSTER, investigation_id=INVESTIGATION,
            access_point=access_point or self.access_point(),
            request=request or self.request(), mode=mode,
            context=FakeContext(seconds), sleep=self.sleep)

    def receipt(self):
        seal = self.efs.tag_resource.call_args.kwargs['Tags'][0]['Value']
        return self.s3.json_at(records.receipt_key(ACCESS_POINT, seal))


class TestOptionalRecord(FinalizerCase):
    def test_access_denied_is_absent_only_if_a_scoped_list_confirms_it(self):
        s3 = self.finalizer.s3 = MagicMock()
        s3.get_object.side_effect = ClientError({'Error': {'Code': '403'}}, 'GetObject')
        key = records.status_key(CLUSTER, INVESTIGATION)
        s3.list_objects_v2.return_value = {}
        self.assertIsNone(self.finalizer.get_json(key, records.KIND_STATUS))
        s3.list_objects_v2.assert_called_once_with(Bucket='audit', Prefix=key, MaxKeys=1,
                                                  ExpectedBucketOwner='123456789012')
        s3.list_objects_v2.return_value = {'Contents': [{'Key': key}]}
        with self.assertRaises(ClientError):
            self.finalizer.get_json(key, records.KIND_STATUS)


class TestHappyPath(FinalizerCase):
    def test_normal_close_verifies_then_retains_the_directory(self):
        status = self.finalize()

        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        self.assertTrue(status['directory_retained'])
        self.assertTrue(status['access_point_deleted'])
        # Normal close keeps the workspace on EFS.
        self.assertTrue(self.workspace.exists())
        self.efs.delete_access_point.assert_called_once_with(AccessPointId=ACCESS_POINT)

    def test_evidence_excludes_credentials_and_covers_every_file(self):
        self.finalize()
        attempt = self.s3.json_at(records.status_key(CLUSTER, INVESTIGATION))['attempt_id']
        manifest = self.s3.json_at(
            records.attempt_evidence_key(ACCESS_POINT, attempt, 'source-manifest.json'))
        keys = {entry['key'] for entry in manifest['entries']}
        self.assertEqual(keys, {'notes.txt', 'nested/log'})
        copied = self.s3.keys_under(records.attempt_workspace_prefix(ACCESS_POINT, attempt))
        self.assertEqual(len(copied), 2)
        for key in self.s3.objects:
            self.assertNotIn('secret', self.s3.objects[key]['body'].decode(errors='ignore'))

    def test_receipt_states_its_assurance_and_binds_to_this_attempt(self):
        self.finalize()
        receipt = self.receipt()
        self.assertEqual(receipt['schema_version'], 2)
        self.assertEqual(receipt['assurance'], 'observed-quiescence')
        self.assertEqual(receipt['request_token'], REQUEST_TOKEN)
        self.assertIn(receipt['attempt_id'], receipt['manifest_ref'])
        self.assertIn(receipt['attempt_id'], receipt['verification_ref'])
        self.assertTrue(receipt['directory_retained'])
        self.assertTrue(any('not excluded' in note for note in receipt['limitations']))

    def test_the_quiet_recheck_happens_before_measuring(self):
        self.finalize()
        self.assertEqual(self.sleeps, [1])
        # Initial observation, quiet recheck, final recheck after the copy.
        self.assertEqual(self.finalizer.observe.call_count, 3)

    def test_an_empty_workspace_still_produces_evidence(self):
        for path in (self.workspace / 'notes.txt', self.workspace / 'nested' / 'log'):
            path.unlink()
        (self.workspace / 'nested').rmdir()
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        manifest = self.s3.json_at(records.attempt_evidence_key(
            ACCESS_POINT, status['attempt_id'], 'source-manifest.json'))
        self.assertEqual(manifest['entries'], [])

    def test_a_missing_workspace_is_not_a_verified_empty_backup(self):
        import shutil
        shutil.rmtree(self.workspace)
        for mode in ('request', 'stale'):
            with self.subTest(mode=mode):
                status = self.finalize(mode=mode)
                self.assertEqual(status['status'], records.STATUS_RETAINED)
                self.assertIn('directory is missing', status['reason'])
                self.efs.delete_access_point.assert_not_called()
                self.assertFalse(self.s3.keys_under(f'_boundary-close/{ACCESS_POINT}/'))


class TestAuthorization(FinalizerCase):
    def test_auto_close_is_superseded_when_the_investigation_changed_hands(self):
        self.observations = [observation(records.STATE_ACTIVE, OTHER_SRE,
                                         [attached_task(sub=OTHER_SRE)])]
        status = self.finalize(request=self.request(trigger='auto_close',
                                                    stop_scope=records.STOP_INVESTIGATION))
        self.ecs.stop_task.assert_not_called()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('superseded', status['reason'])
        self.assertFalse(status['retryable'])
        self.efs.tag_resource.assert_not_called()
        self.efs.delete_access_point.assert_not_called()

    def test_the_current_holder_may_still_close_while_holding(self):
        self.observations = [observation(records.STATE_ACTIVE, HOLDER, [running_task()]),
                             observation(records.STATE_IDLE)]
        status = self.finalize(request=self.request(stop_scope=records.STOP_SESSION_TASK,
                                                    stop_task_ids=[TASK_ID]))
        # Stopping is requested; the pass ends waiting for the task to stop.
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.ecs.stop_task.assert_called_once()

    def test_an_idle_investigation_may_be_closed_by_any_eligible_requester(self):
        status = self.finalize(request=self.request(requester_sub='sre-c'))
        self.assertEqual(status['status'], records.STATUS_COMPLETED)

    def test_unknown_state_never_authorizes_anything(self):
        self.observations = [observation(records.STATE_UNKNOWN)]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.efs.tag_resource.assert_not_called()

    def test_an_inconclusive_revalidation_is_retried_not_held_against_the_request(self):
        """A throttled API call must not end a valid close request.

        `retained` without `retryable` is terminal: the scan treats it as the
        request's answer and never looks at it again. Unknown is not an
        answer, and the documented matrix promises a retry.
        """
        self.observations = [observation(records.STATE_UNKNOWN)]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertTrue(status['retryable'])
        self.assertIn('inconclusive', status['reason'])

    def test_explicit_request_waits_for_other_holder_then_completes_without_resubmission(self):
        request = self.request(requester_sub=OTHER_SRE)
        self.observations = [observation(records.STATE_ACTIVE, HOLDER, [attached_task()])]
        waiting = self.finalize(request=request)
        self.assertEqual(waiting['status'], records.STATUS_WAITING_FOR_TASKS)
        self.assertTrue(waiting['retryable'])
        self.efs.tag_resource.assert_not_called()

        self.observations = [observation(records.STATE_IDLE, tasks=[running_task()])]
        self.assertEqual(self.finalize(request=request)['status'], records.STATUS_WAITING_FOR_TASKS)
        self.efs.delete_access_point.assert_not_called()
        self.observations = [observation(records.STATE_IDLE, tasks=[stopped_task()])]
        self.assertEqual(self.finalize(request=request)['status'], records.STATUS_COMPLETED)
        self.assertEqual(self.receipt()['request_token'], request['request_token'])
        self.ecs.stop_task.assert_not_called()

    def test_force_does_not_stop_another_attached_holder(self):
        self.observations = [observation(records.STATE_ACTIVE, HOLDER, [attached_task()])]
        status = self.finalize(request=self.request(requester_sub=OTHER_SRE,
                                                    stop_scope=records.STOP_INVESTIGATION))
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.ecs.stop_task.assert_not_called()

    def test_a_stale_candidate_that_is_not_idle_is_left_alone(self):
        self.observations = [observation(records.STATE_ACTIVE, HOLDER, [attached_task()])]
        status = self.finalize(mode='stale')
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.efs.tag_resource.assert_not_called()
        # The sweep comes back to it; nothing here needs a person.
        self.assertTrue(status['retryable'])

    def test_a_stale_candidate_with_a_running_task_is_not_sealed_by_the_sweep(self):
        """Idle now means "nobody attached", which a RUNNING task allows.

        The scheduled sweep carries no human consent, so it must still wait
        for the task rather than sealing an investigation that is running
        work. Only an SRE's own request can seal past a live task, and only
        with the stop consent that request carried.
        """
        self.observations = [observation(records.STATE_IDLE, tasks=[running_task()])]
        status = self.finalize(mode='stale')
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.assertIn('running task', status['reason'])
        self.efs.tag_resource.assert_not_called()
        self.ecs.stop_task.assert_not_called()
        self.assertTrue(status['retryable'])

    def test_a_detached_task_does_not_reserve_the_investigation_for_its_owner(self):
        """The regression: a RUNNING task used to report ACTIVE/held by its tag.

        Any eligible SRE may request close of an idle investigation, and a
        task left running by a departed CLI does not make it held.
        """
        self.observations = [observation(records.STATE_IDLE, tasks=[running_task(sub=HOLDER)]),
                             observation(records.STATE_IDLE, tasks=[stopped_task()])]
        status = self.finalize(request=self.request(requester_sub='sre-c',
                                                    stop_scope=records.STOP_INVESTIGATION))
        # Not superseded, not refused: the stop consent it carried is used.
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.ecs.stop_task.assert_called_once()
        self.assertEqual(self.ecs.stop_task.call_args.kwargs['task'], TASK_ID)

    def test_an_inconclusive_observation_is_not_promised_a_retry_it_will_get(self):
        """Unknown state is retryable; a superseded request is not."""
        self.observations = [observation(records.STATE_UNKNOWN)]
        self.assertTrue(self.finalize(mode='stale')['retryable'])


class TestSealing(FinalizerCase):
    def test_a_manual_or_legacy_seal_is_never_replaced(self):
        status = self.finalize(access_point=self.access_point(
            {records.TAG_SEAL: 'operator-hold'}))
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('manual seal', status['reason'])
        # A hold needs a person, so nothing may promise an automatic retry.
        self.assertFalse(status['retryable'])
        self.efs.tag_resource.assert_not_called()
        self.efs.delete_access_point.assert_not_called()

    def test_an_existing_managed_seal_is_reused(self):
        existing = '99999999-8888-4777-8666-555555555555'
        status = self.finalize(access_point=self.access_point({
            records.TAG_SEAL: existing,
            records.TAG_MANAGED: records.MANAGED_BY,
        }))
        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        self.efs.tag_resource.assert_not_called()
        self.assertIn(records.receipt_key(ACCESS_POINT, existing), self.s3.objects)

    def test_a_malformed_managed_seal_retains_rather_than_guessing(self):
        status = self.finalize(access_point=self.access_point({
            records.TAG_SEAL: 'not-a-uuid', records.TAG_MANAGED: records.MANAGED_BY}))
        self.assertEqual(status['status'], records.STATUS_RETAINED)

    def test_the_managed_marker_records_the_request_it_serves(self):
        self.finalize()
        tags = {tag['Key']: tag['Value']
                for tag in self.efs.tag_resource.call_args.kwargs['Tags']}
        self.assertEqual(tags[records.TAG_MANAGED], records.MANAGED_BY)
        self.assertEqual(tags[records.TAG_REQUEST], REQUEST_TOKEN)
        self.assertEqual(tags[records.TAG_BUCKET], 'audit')


class TestDraining(FinalizerCase):
    def test_without_consent_a_running_task_makes_the_close_wait(self):
        self.observations = [observation(records.STATE_ACTIVE, HOLDER, [attached_task()])]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.ecs.stop_task.assert_not_called()

    def test_an_idle_investigation_with_a_running_task_still_needs_stop_consent(self):
        """Authorization widened to any SRE; consent to stop work did not.

        This is the half of the rule that keeps "idle with a running task"
        safe: the request is accepted and the workspace is sealed, but the
        task is not touched and nothing is measured, copied or deleted.
        """
        self.observations = [observation(records.STATE_IDLE, tasks=[running_task()])]
        status = self.finalize(request=self.request(requester_sub='sre-c',
                                                    stop_scope=records.STOP_NONE))
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.assertIn('no stop consent', status['reason'])
        self.ecs.stop_task.assert_not_called()
        self.efs.delete_access_point.assert_not_called()
        self.assertTrue(status['retryable'])

    def test_consent_for_one_task_does_not_stop_another(self):
        other = 'b' * 32
        self.observations = [observation(records.STATE_ACTIVE, HOLDER,
                                         [running_task(), running_task(other)])]
        status = self.finalize(request=self.request(stop_scope=records.STOP_SESSION_TASK,
                                                    stop_task_ids=[TASK_ID]))
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.assertIn('outside the consented stop scope', status['reason'])
        self.ecs.stop_task.assert_not_called()

    def test_whole_investigation_consent_stops_every_task(self):
        other = 'b' * 32
        self.observations = [observation(records.STATE_ACTIVE, HOLDER,
                                         [running_task(), running_task(other)])]
        self.finalize(request=self.request(stop_scope=records.STOP_INVESTIGATION))
        stopped = {call.kwargs['task'] for call in self.ecs.stop_task.call_args_list}
        self.assertEqual(stopped, {TASK_ID, other})

    def test_a_task_appearing_after_the_drain_blocks_the_attempt(self):
        self.observations = [observation(records.STATE_IDLE),
                             observation(records.STATE_ACTIVE, HOLDER, [running_task()])]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.assertIn('appeared quiet', status['reason'])

    def test_an_inconclusive_recheck_retains(self):
        self.observations = [observation(records.STATE_IDLE),
                             observation(records.STATE_UNKNOWN)]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)


class TestVerification(FinalizerCase):
    def test_a_late_task_after_the_copy_invalidates_the_attempt(self):
        self.observations = [observation(records.STATE_IDLE),
                             observation(records.STATE_IDLE),
                             observation(records.STATE_ACTIVE, HOLDER, [running_task()])]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('after the workspace was copied', status['reason'])
        # The data is intact, so the next pass starts a fresh attempt.
        self.assertTrue(status['retryable'])
        self.efs.delete_access_point.assert_not_called()
        self.assertEqual([k for k in self.s3.objects if k.endswith('verification.json')], [])

    def test_an_inconclusive_final_observation_invalidates_the_attempt(self):
        self.observations = [observation(records.STATE_IDLE),
                             observation(records.STATE_IDLE),
                             observation(records.STATE_UNKNOWN)]
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.efs.delete_access_point.assert_not_called()

    def test_a_source_that_changes_during_the_copy_invalidates_the_attempt(self):
        original = close_finalization.build_source_manifest
        calls = []

        def changing(directory_path, context):
            manifest, skipped = original(directory_path, context)
            calls.append(manifest)
            if len(calls) == 2:
                manifest = manifest[:-1]
            return manifest, skipped

        with patch('close_finalization.build_source_manifest', side_effect=changing):
            status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('changed while it was being copied', status['reason'])
        self.efs.delete_access_point.assert_not_called()

    def test_a_short_or_corrupt_destination_object_fails_verification(self):
        real_upload = self.s3.upload_fileobj

        def truncate(Fileobj, Bucket, Key, ExtraArgs=None):  # noqa: N803
            real_upload(Fileobj, Bucket, Key)
            self.s3.objects[Key]['body'] = self.s3.objects[Key]['body'][:-1]

        with patch.object(self.s3, 'upload_fileobj', side_effect=truncate):
            status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('verification failed', status['reason'])
        self.efs.delete_access_point.assert_not_called()

    def test_an_extra_object_under_the_attempt_prefix_fails_verification(self):
        real_upload = self.s3.upload_fileobj
        injected = []

        def inject(Fileobj, Bucket, Key, ExtraArgs=None):  # noqa: N803
            real_upload(Fileobj, Bucket, Key)
            if not injected:
                injected.append(Key)
                prefix = Key.rsplit('/', 1)[0]
                self.s3._store(f'{prefix}/unexpected', b'extra')

        with patch.object(self.s3, 'upload_fileobj', side_effect=inject):
            status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('unexpected_key', status['reason'])

    def test_an_interrupted_copy_never_publishes_a_receipt(self):
        def fail(Fileobj, Bucket, Key, ExtraArgs=None):  # noqa: N803
            raise ClientError({'Error': {'Code': 'AccessDenied'}}, 'PutObject')

        with patch.object(self.s3, 'upload_fileobj', side_effect=fail):
            status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertFalse([k for k in self.s3.objects if k.endswith('.json')
                          and '/attempts/' not in k and '/status/' not in k])
        self.efs.delete_access_point.assert_not_called()

    def test_a_missing_object_version_fails_verification(self):
        """Evidence records exact object versions; unversioned storage is refused."""
        real_get = self.s3.get_object

        def unversioned(Bucket, Key, **kwargs):  # noqa: N803
            response = real_get(Bucket=Bucket, Key=Key, **kwargs)
            if '/workspace/' in Key:
                response['VersionId'] = 'null'
            return response

        with patch.object(self.s3, 'get_object', side_effect=unversioned):
            status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('missing_version', status['reason'])

    def test_each_attempt_uses_its_own_prefix(self):
        first = self.finalize()
        self.observations = [observation(records.STATE_IDLE)]
        second = self.finalize(request=self.request(
            request_token='22222222-3333-4444-8555-666666666666'))
        self.assertNotEqual(first['attempt_id'], second['attempt_id'])
        self.assertTrue(self.s3.keys_under(
            records.attempt_workspace_prefix(ACCESS_POINT, first['attempt_id'])))
        self.assertTrue(self.s3.keys_under(
            records.attempt_workspace_prefix(ACCESS_POINT, second['attempt_id'])))


class TestLargeWorkspaces(FinalizerCase):
    """Evidence grows with the workspace; the control-record limit must not
    turn an ordinary close into a failed invocation."""

    def test_a_workspace_with_many_files_closes_normally(self):
        for index in range(400):
            (self.workspace / f'file-{index:04d}').write_text(str(index))
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        manifest = self.s3.json_at(records.attempt_evidence_key(
            ACCESS_POINT, status['attempt_id'], 'source-manifest.json'))
        self.assertEqual(manifest['file_count'], 402)

    def test_a_workspace_too_large_to_describe_is_retained_not_crashed(self):
        with patch.object(records, 'MAX_EVIDENCE_BYTES', 64):
            status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_RETAINED)
        self.assertIn('too large', status['reason'])
        self.efs.delete_access_point.assert_not_called()
        self.assertTrue(self.workspace.exists())


class TestSourceMeasurement(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(__import__('tempfile').TemporaryDirectory()))

    def test_symlinks_and_special_files_are_recorded_as_skipped(self):
        (self.root / 'real').write_text('data')
        os.symlink(self.root / 'real', self.root / 'link')
        manifest, skipped = close_finalization.build_source_manifest(
            str(self.root), FakeContext())
        self.assertEqual([entry['key'] for entry in manifest], ['real'])
        self.assertEqual(len(skipped), 1)
        # Skipped names are hashed: evidence must not leak workspace contents.
        self.assertNotIn('link', json.dumps(skipped))

    def test_a_symlink_swapped_in_after_measurement_is_not_followed(self):
        """The workspace is untrusted: the open must not re-resolve a path."""
        (self.root / 'real').write_text('data')
        with patch('close_finalization.os.lstat') as lstat:
            lstat.return_value = os.stat_result(
                (0o100644, 0, 0, 1, 0, 0, 4, 0, 0, 0))
            os.unlink(self.root / 'real')
            os.symlink('/etc/hostname', self.root / 'real')
            with self.assertRaises(close_finalization.AttemptInvalid):
                close_finalization.build_source_manifest(str(self.root), FakeContext())

    def test_an_unsafe_path_name_invalidates_the_attempt(self):
        (self.root / 'bad\nname').write_text('data')
        with self.assertRaises(close_finalization.AttemptInvalid):
            close_finalization.build_source_manifest(str(self.root), FakeContext())

    def test_an_unreadable_subtree_invalidates_the_attempt(self):
        blocked = self.root / 'blocked'
        blocked.mkdir()
        (blocked / 'file').write_text('data')
        blocked.chmod(0o000)
        self.addCleanup(blocked.chmod, 0o755)
        if os.geteuid() == 0:
            self.skipTest('root bypasses directory permissions')
        with self.assertRaises(OSError):
            close_finalization.build_source_manifest(str(self.root), FakeContext())

    def test_digests_match_the_bytes_on_disk(self):
        (self.root / 'file').write_bytes(b'0123456789')
        manifest, _ = close_finalization.build_source_manifest(str(self.root), FakeContext())
        self.assertEqual(manifest[0]['length'], 10)
        self.assertEqual(manifest[0]['sha256'], hashlib.sha256(b'0123456789').hexdigest())

    def test_an_exhausted_deadline_invalidates_rather_than_shortening(self):
        (self.root / 'file').write_text('data')
        with self.assertRaises(close_finalization.AttemptInvalid):
            close_finalization.build_source_manifest(str(self.root), FakeContext(seconds=0))


class TestCleanup(FinalizerCase):
    def test_stale_reaping_reclaims_only_behind_the_same_verified_gate(self):
        status = self.finalize(mode='stale')
        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        self.assertFalse(status['directory_retained'])
        self.assertFalse(self.workspace.exists())

    def test_stale_reclamation_can_be_disabled_without_losing_the_backup(self):
        self.finalizer.stale_reclaim = False
        status = self.finalize(mode='stale')
        self.assertTrue(status['directory_retained'])
        self.assertTrue(self.workspace.exists())
        self.assertIn('reclamation is disabled', status['reason'])
        self.assertTrue(self.s3.keys_under(
            records.attempt_workspace_prefix(ACCESS_POINT, status['attempt_id'])))

    def test_a_blocked_directory_removal_keeps_its_access_point(self):
        """The access point is the only handle to a directory that was not
        reclaimed; deleting it would make the leftover unreachable."""
        with patch('close_finalization.shutil.rmtree', side_effect=OSError('busy')):
            status = self.finalize(mode='stale')
        self.assertEqual(status['status'], records.STATUS_CLEANUP_INCOMPLETE)
        self.assertTrue(status['directory_retained'])
        self.assertFalse(status['access_point_deleted'])
        self.efs.delete_access_point.assert_not_called()
        self.assertTrue(status['retryable'])
        self.assertTrue(self.s3.keys_under(
            records.attempt_workspace_prefix(ACCESS_POINT, status['attempt_id'])))

    def test_a_failed_access_point_deletion_is_reported_not_assumed(self):
        self.efs.delete_access_point.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'DeleteAccessPoint')
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_CLEANUP_INCOMPLETE)
        self.assertFalse(status['access_point_deleted'])
        self.assertFalse(self.receipt()['cleanup_complete'])

    def test_a_status_always_names_the_workspace_path(self):
        """Access-point discovery stops working once the access point is gone,
        so a retained directory has to stay findable another way."""
        status = self.finalize()
        self.assertEqual(status['access_point_path'], f'/{CLUSTER}/{INVESTIGATION}')

    def test_an_already_deleted_access_point_is_not_an_error(self):
        self.efs.delete_access_point.side_effect = ClientError(
            {'Error': {'Code': 'AccessPointNotFound'}}, 'DeleteAccessPoint')
        status = self.finalize()
        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        self.assertTrue(status['access_point_deleted'])

    def test_task_definition_failure_does_not_delete_the_access_point(self):
        self.ecs.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'ListTaskDefinitions')
        status = self.finalize(mode='stale')
        self.assertEqual(status['status'], records.STATUS_CLEANUP_INCOMPLETE)
        self.assertIn('task definitions', status['reason'])
        self.efs.delete_access_point.assert_not_called()
        self.assertFalse(status['access_point_deleted'])

    def test_a_receipt_that_cannot_be_published_reports_what_cleanup_did(self):
        """Reporting the optimistic defaults here would tell an operator the
        data is untouched after the directory had already been reclaimed."""
        real_put = self.s3.put_object

        def fail_receipt(Bucket, Key, Body, **kwargs):  # noqa: N803
            if Key.endswith('.json') and '/attempts/' not in Key and '/status/' not in Key:
                raise ClientError({'Error': {'Code': 'ServiceUnavailable'}}, 'PutObject')
            return real_put(Bucket=Bucket, Key=Key, Body=Body, **kwargs)

        with patch.object(self.s3, 'put_object', side_effect=fail_receipt):
            status = self.finalize(mode='stale')
        self.assertEqual(status['status'], records.STATUS_CLEANUP_INCOMPLETE)
        self.assertFalse(status['directory_retained'])
        self.assertTrue(status['access_point_deleted'])
        self.assertTrue(status['attempt_id'])
        self.assertFalse(self.workspace.exists())

    def test_the_verified_evidence_is_recorded_before_anything_destructive(self):
        statuses = []
        real_put = self.s3.put_object

        def capture(Bucket, Key, Body, **kwargs):  # noqa: N803
            if '/status/' in Key:
                statuses.append(json.loads(Body.decode()))
            return real_put(Bucket=Bucket, Key=Key, Body=Body, **kwargs)

        with patch.object(self.s3, 'put_object', side_effect=capture):
            self.finalize()
        verified = [entry for entry in statuses if entry['phase'] == 'verified']
        self.assertEqual(len(verified), 1)
        self.assertTrue(verified[0]['attempt_id'])
        self.assertEqual(verified[0]['access_point_path'], f'/{CLUSTER}/{INVESTIGATION}')

    def test_only_this_investigations_task_definitions_are_deregistered(self):
        family = f'arn:aws:ecs:us-east-1:1:task-definition/boundary-{CLUSTER}-{INVESTIGATION}'
        launched = f'{family}-20260101T000000:1'
        collision = f'{family}-20260101T000000:2'
        adjacent = f'{family}-extra-20260101T000000:1'
        states = dict.fromkeys([launched, collision, adjacent], 'ACTIVE')

        def pages(*, status, familyPrefix=None):
            # AWS accepts only a complete family, not a partial name.
            matched = [arn for arn in states if states[arn] == status and
                       (not familyPrefix or arn.split('/')[-1].rsplit(':', 1)[0] == familyPrefix)]
            return [{'taskDefinitionArns': [arn]} for arn in reversed(matched)]

        def describe(taskDefinition):  # noqa: N803
            ap = ACCESS_POINT if taskDefinition == launched else 'fsap-other'
            return {'taskDefinition': {'taskDefinitionArn': taskDefinition, 'status': states[taskDefinition],
                    'volumes': [{'name': 'sre-home', 'efsVolumeConfiguration': {
                        'fileSystemId': 'fs-1', 'authorizationConfig': {'accessPointId': ap}}}]}}

        def deregister(taskDefinition):  # noqa: N803
            states[taskDefinition] = 'INACTIVE'
            return describe(taskDefinition)

        self.ecs.get_paginator.return_value.paginate.side_effect = pages
        self.ecs.describe_task_definition.side_effect = describe
        self.ecs.deregister_task_definition.side_effect = deregister
        status = self.finalize()
        self.assertEqual(status['task_definitions_removed'], 1)
        self.assertEqual(states, {launched: 'INACTIVE', collision: 'ACTIVE', adjacent: 'ACTIVE'})
        self.ecs.deregister_task_definition.assert_called_once_with(taskDefinition=launched)

    def test_unconfirmed_deregistration_retains_access_point(self):
        arn = f'arn:aws:ecs:us-east-1:1:task-definition/boundary-{CLUSTER}-{INVESTIGATION}-20260101T000000:1'
        self.ecs.get_paginator.return_value.paginate.return_value = [{'taskDefinitionArns': [arn]}]
        td = {'taskDefinitionArn': arn, 'status': 'ACTIVE', 'volumes': [{'name': 'sre-home',
              'efsVolumeConfiguration': {'fileSystemId': 'fs-1', 'authorizationConfig': {'accessPointId': ACCESS_POINT}}}]}
        self.ecs.describe_task_definition.return_value = {'taskDefinition': td}
        self.ecs.deregister_task_definition.return_value = {'taskDefinition': td}
        self.assertEqual(self.finalize()['status'], records.STATUS_CLEANUP_INCOMPLETE)
        self.efs.delete_access_point.assert_not_called()


class TestRecovery(FinalizerCase):
    def retry(self, ap, mode):
        # Exercise the production dispatch, including an AP that no longer
        # exists. No in-process progress from the previous pass is required.
        with patch('boto3.client'):
            import handler
        with patch.object(self.finalizer, 'find_access_point', return_value=ap):
            return handler.finalize_one(self.finalizer, CLUSTER, INVESTIGATION,
                                        self.request(), mode, FakeContext())

    def interrupted(self, stage, mode):
        ap = self.access_point()
        if stage == 'directory':
            obj, method = close_finalization.shutil, 'rmtree'
        elif stage == 'ap':
            obj, method = self.efs, 'delete_access_point'
        else:
            obj, method = self.finalizer, 'publish_receipt'
        original = getattr(obj, method)

        def crash_after(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError('simulated runtime exit')

        with patch.object(obj, method, side_effect=crash_after):
            with self.assertRaisesRegex(RuntimeError, 'runtime exit'):
                self.finalize(mode, access_point=ap)
        self.finalizer._attempt_id = ''
        self.finalizer._cleanup = None
        self.finalizer._verification_digest = None
        return ap if stage == 'directory' else None

    def check_recovery(self, stage, mode):
        ap = self.interrupted(stage, mode)
        status_key = records.status_key(CLUSTER, INVESTIGATION)
        attempt = self.s3.json_at(status_key)['attempt_id']
        prefix = records.attempt_workspace_prefix(ACCESS_POINT, attempt)
        original = {k: self.s3.objects[k].copy() for k in self.s3.keys_under(prefix)}
        self.assertEqual(len(original), 2)
        if stage == 'receipt':
            receipt_key = self.s3.keys_under(f'{records.CONTROL_PREFIX}/{ACCESS_POINT}/')[0]
            receipt_version = self.s3.objects[receipt_key]['version']
        self.assertTrue(self.retry(ap, mode))
        status = self.s3.json_at(status_key)
        self.assertEqual(status['status'], records.STATUS_COMPLETED)
        self.assertEqual(status['attempt_id'], attempt)
        self.assertEqual(self.receipt()['attempt_id'], attempt)
        self.assertEqual(status['directory_retained'], mode == 'request')
        self.assertEqual(self.workspace.exists(), mode == 'request')
        self.assertTrue(status['access_point_deleted'])
        self.assertEqual(self.receipt()['object_versions'], 2)
        self.assertTrue(self.receipt()['cleanup_complete'])
        if stage == 'receipt':
            self.assertEqual(self.s3.objects[receipt_key]['version'], receipt_version)
        for k, v in original.items():
            self.assertEqual(self.s3.objects[k], v)
        version = self.s3.version
        self.assertTrue(self.retry(None, mode))
        self.assertEqual(self.s3.version, version, 'second retry rewrote completion')

    def test_crash_after_stale_directory_removal(self):
        self.check_recovery('directory', 'stale')

    def test_crash_after_ap_deletion(self):
        self.check_recovery('ap', 'request')

    def test_crash_after_receipt_publication(self):
        self.check_recovery('receipt', 'stale')

    def test_partial_rmtree_is_not_verified_as_a_new_smaller_workspace(self):
        ap = self.access_point()

        def partial_removal(_directory):
            (self.workspace / 'notes.txt').unlink()
            raise OSError('interrupted during removal')

        with patch('close_finalization.shutil.rmtree', side_effect=partial_removal):
            status = self.finalize('stale', access_point=ap)
        self.assertEqual(status['status'], records.STATUS_CLEANUP_INCOMPLETE)
        version = self.s3.version
        for _ in range(2):
            self.assertFalse(self.retry(ap, 'stale'))
        self.assertEqual(self.s3.version, version)
        self.assertTrue((self.workspace / 'nested' / 'log').exists())
        self.efs.delete_access_point.assert_not_called()

    def test_late_write_after_ap_deletion_blocks_completion(self):
        self.interrupted('ap', 'request')
        (self.workspace / 'notes.txt').write_text('updated since verification')
        version = self.s3.version
        self.assertFalse(self.retry(None, 'request'))
        self.assertEqual(self.s3.version, version)
        self.assertEqual((self.workspace / 'notes.txt').read_text(), 'updated since verification')

    def test_recovery_requires_the_original_managed_seal(self):
        ap = self.interrupted('directory', 'stale')
        del ap['tags'][records.TAG_MANAGED]
        self.assertFalse(self.retry(ap, 'stale'))
        self.efs.delete_access_point.assert_not_called()

    def test_changed_backup_version_cannot_authorize_cleanup(self):
        ap = self.interrupted('directory', 'stale')
        status = self.s3.json_at(records.status_key(CLUSTER, INVESTIGATION))
        key = records.attempt_workspace_prefix(ACCESS_POINT, status['attempt_id']) + 'notes.txt'
        self.s3._store(key, self.s3.objects[key]['body'])
        version = self.s3.version
        for _ in range(2):
            self.assertFalse(self.retry(ap, 'stale'))
        self.assertEqual(self.s3.version, version)
        self.efs.delete_access_point.assert_not_called()

    def test_missing_evidence_cannot_authorize_cleanup(self):
        ap = self.interrupted('directory', 'stale')
        status = self.s3.json_at(records.status_key(CLUSTER, INVESTIGATION))
        del self.s3.objects[records.attempt_evidence_key(
            ACCESS_POINT, status['attempt_id'], 'verification.json')]
        self.assertFalse(self.retry(ap, 'stale'))
        self.assertEqual(status, self.s3.json_at(records.status_key(CLUSTER, INVESTIGATION)))
        self.efs.delete_access_point.assert_not_called()


class TestRuntimeBudget(FinalizerCase):
    def test_too_little_time_to_seal_stops_before_mutating_anything(self):
        status = self.finalize(seconds=5)
        self.assertEqual(status['status'], records.STATUS_ACCEPTED)
        self.efs.tag_resource.assert_not_called()
        self.efs.delete_access_point.assert_not_called()

    def test_the_quiet_recheck_is_never_skipped_to_fit_the_budget(self):
        self.finalizer.quiet_seconds = 60
        status = self.finalize(seconds=30)
        self.assertEqual(status['status'], records.STATUS_WAITING_FOR_TASKS)
        self.assertEqual(self.sleeps, [])
        # The seal survives for the next invocation to resume behind.
        self.efs.tag_resource.assert_called_once()
        self.efs.delete_access_point.assert_not_called()
        persisted = self.s3.json_at(records.status_key(CLUSTER, INVESTIGATION))
        self.assertEqual(persisted['status'], records.STATUS_WAITING_FOR_TASKS)


class TestRecordContract(unittest.TestCase):
    def test_keys_stay_inside_the_service_only_prefix(self):
        for key in (records.request_key(CLUSTER, INVESTIGATION, REQUEST_TOKEN,
                                        '2026-01-01T00:00:00+00:00'),
                    records.intent_key(CLUSTER, INVESTIGATION, TASK_ID),
                    records.status_key(CLUSTER, INVESTIGATION),
                    records.attempt_workspace_prefix(ACCESS_POINT, REQUEST_TOKEN),
                    records.receipt_key(ACCESS_POINT, REQUEST_TOKEN)):
            self.assertTrue(key.startswith(records.CONTROL_PREFIX + '/'), key)

    def test_unsafe_identifiers_cannot_build_a_key(self):
        for cluster in ('../escape', 'a/b', '', '.hidden'):
            with self.subTest(cluster=cluster), self.assertRaises(ValueError):
                records.status_key(cluster, INVESTIGATION)

    def test_the_attempt_prefix_is_what_the_shared_comparator_accepts(self):
        uri = ('s3://audit/'
               + records.attempt_workspace_prefix(ACCESS_POINT, REQUEST_TOKEN))
        self.assertTrue(workspace_verification.DEST.fullmatch(uri))

    def test_attempt_evidence_is_outside_the_receipt_read_grant(self):
        """The SRE role may read close receipts via `_boundary-close/fsap-*/*.json`.
        A workspace copy under that shape would expose every .json file in the
        workspace through a grant meant only for receipts."""
        receipt_grant = f'{records.CONTROL_PREFIX}/fsap-'
        for key in (records.attempt_workspace_prefix(ACCESS_POINT, REQUEST_TOKEN) + 'a.json',
                    records.attempt_evidence_key(ACCESS_POINT, REQUEST_TOKEN,
                                                 'source-manifest.json'),
                    records.attempt_evidence_key(ACCESS_POINT, REQUEST_TOKEN,
                                                 'verification.json')):
            self.assertFalse(key.startswith(receipt_grant), key)
        # The receipt itself stays where existing clients already read it.
        self.assertTrue(
            records.receipt_key(ACCESS_POINT, REQUEST_TOKEN).startswith(receipt_grant))

    def test_the_request_key_carries_its_request_time(self):
        """The finalizer must be able to skip answered requests without reading
        them: records are object-locked and never deleted."""
        key = records.request_key(CLUSTER, INVESTIGATION, REQUEST_TOKEN,
                                  '2026-03-04T05:06:07+00:00')
        assert key.endswith(f'20260304T050607Z-{REQUEST_TOKEN}.json')
        self.assertEqual(records.parse_request_filename(key.rsplit('/', 1)[-1]),
                         ('20260304T050607Z', REQUEST_TOKEN))
        self.assertIsNone(records.parse_request_filename(f'{REQUEST_TOKEN}.json'))
        self.assertIsNone(records.parse_request_filename('20260304T050607Z-nope.json'))

    def test_the_request_time_is_normalised_to_utc(self):
        self.assertEqual(records.request_stamp('2026-03-04T06:06:07+01:00'),
                         '20260304T050607Z')

    def test_only_the_scheduled_sweep_may_omit_a_requester(self):
        base = {
            'schema_version': records.REQUEST_SCHEMA_VERSION,
            'kind': records.KIND_REQUEST,
            'request_token': REQUEST_TOKEN,
            'cluster_id': CLUSTER,
            'investigation_id': INVESTIGATION,
            'access_point_id': ACCESS_POINT,
            'requester_sub': '',
            'stop_scope': records.STOP_NONE,
            'stop_task_ids': [],
            'trigger': 'cli_close',
            'requested_at': '2026-01-01T00:00:00+00:00',
        }
        with self.assertRaises(ValueError):
            records.validate_request(base)
        records.validate_request(dict(base, trigger=records.TRIGGER_STALE))

    def test_evidence_is_not_held_to_the_control_record_limit(self):
        """A manifest grows with the workspace; the control limit would turn an
        ordinary close into a failed invocation."""
        document = {'entries': [{'key': f'file-{i}', 'length': 1,
                                 'sha256': '0' * 64} for i in range(1000)]}
        with self.assertRaises(ValueError):
            records.encode_record(document)
        self.assertGreater(len(records.encode_evidence(document)), records.MAX_RECORD_BYTES)
        with self.assertRaises(ValueError):
            records.encode_evidence({'entries': ['x' * (records.MAX_EVIDENCE_BYTES + 1)]})

    def test_a_request_record_must_name_the_tasks_its_consent_covers(self):
        base = {
            'schema_version': records.REQUEST_SCHEMA_VERSION,
            'kind': records.KIND_REQUEST,
            'request_token': REQUEST_TOKEN,
            'cluster_id': CLUSTER,
            'investigation_id': INVESTIGATION,
            'access_point_id': ACCESS_POINT,
            'requester_sub': HOLDER,
            'stop_scope': records.STOP_SESSION_TASK,
            'stop_task_ids': [],
            'trigger': 'cli_close',
            'requested_at': '2026-01-01T00:00:00+00:00',
        }
        with self.assertRaises(ValueError):
            records.validate_request(base)
        records.validate_request(dict(base, stop_task_ids=[TASK_ID]))

    def test_a_record_of_the_wrong_kind_is_refused(self):
        body = json.dumps({'kind': records.KIND_STATUS}).encode()
        with self.assertRaises(ValueError):
            records.decode_record(body, records.KIND_REQUEST)

    def test_an_oversized_record_is_refused(self):
        with self.assertRaises(ValueError):
            records.decode_record(b'x' * (records.MAX_RECORD_BYTES + 1), records.KIND_REQUEST)

    def test_status_defaults_to_retaining_the_directory(self):
        status = records.build_status(CLUSTER, INVESTIGATION, records.STATUS_ACCEPTED,
                                      phase='accepted')
        self.assertTrue(status['directory_retained'])
        self.assertFalse(status['access_point_deleted'])


if __name__ == '__main__':
    unittest.main()
