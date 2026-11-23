"""
Unit tests for the investigation reaper Lambda handler.

These cover the handler's own responsibilities: discovery, staleness, the skip
rules that protect sealed and unmanaged workspaces, and the orchestration of
explicit close requests and auto-close intents. The finalization pipeline
itself — seal, drain, copy, verify, publish, clean up — is covered by
test_close_finalization.py, which every route now goes through.
"""

import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Set environment variables before importing handler
os.environ['AWS_DEFAULT_REGION'] = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
os.environ['ECS_CLUSTER'] = 'test-cluster'
os.environ['EFS_FILESYSTEM_ID'] = 'fs-12345678'
os.environ['GRACE_PERIOD_HOURS'] = '72'

# Mock client construction before import: unit tests must not resolve workstation
# AWS regions/credentials or contact AWS. Tests replace these clients per case.
with patch('boto3.client'):
    import handler
    import boundary_close_records as records

from botocore.exceptions import ClientError


def access_point(ap_id='fsap-123456', cluster='test-cluster', investigation='inv-123',
                 age_hours=100, extra_tags=None, path=None, with_root=True):
    created_at = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    tags = {
        'ClusterID': cluster,
        'InvestigationID': investigation,
        'ManagedBy': 'rosa-boundary-lambda',
        'CreatedAt': created_at.isoformat(),
    }
    tags.update(extra_tags or {})
    entry = {
        'AccessPointId': ap_id,
        'Tags': [{'Key': key, 'Value': value} for key, value in tags.items()],
    }
    if with_root:
        entry['RootDirectory'] = {'Path': path or f'/{cluster}/{investigation}'}
    return entry


class TestReaperDiscovery(unittest.TestCase):
    """The scan that decides which investigations are even considered."""

    def setUp(self):
        client_patcher = patch('boto3.client')
        client_patcher.start()
        self.addCleanup(client_patcher.stop)
        self.mock_ecs = MagicMock()
        self.mock_efs = MagicMock()
        self.mock_context = MagicMock()
        self.mock_context.get_remaining_time_in_millis.return_value = 300000

        paginator = MagicMock()
        paginator.paginate.return_value = [{'taskArns': []}]
        self.mock_ecs.get_paginator.return_value = paginator
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        self.enterContext(patch('handler.ecs', self.mock_ecs))
        self.enterContext(patch('handler.efs', self.mock_efs))
        # Close-request processing has its own tests; keep discovery isolated.
        self.close_work = self.enterContext(patch(
            'handler.process_close_work',
            return_value={'requests_finalized': 0, 'intents_activated': 0, 'close_errors': 0}))
        self.reap = self.enterContext(patch('handler.reap_investigation', return_value=True))

    def run_handler(self, context=False):
        return handler.lambda_handler({}, self.mock_context if context else None)

    def test_invocation_inside_reserve_does_not_start_discovery(self):
        self.mock_context.get_remaining_time_in_millis.return_value = 29999
        result = handler.lambda_handler({}, self.mock_context)
        self.assertEqual(result['checked'], 0)
        self.mock_efs.describe_access_points.assert_not_called()

    def test_no_access_points(self):
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': []}
        result = self.run_handler()
        self.assertEqual((result['checked'], result['reaped'], result['skipped'], result['errors']),
                         (0, 0, 0, 0))
        self.mock_efs.describe_access_points.assert_called_once()

    def test_sealed_access_point_skipped(self):
        """A seal of any kind takes the workspace out of the stale sweep.

        A managed seal is finished through its own request; a legacy or manual
        seal stays retained for review. Neither is reaped here.
        """
        for seal_tags in ({'AuditCloseSeal': ''},
                          {'AuditCloseSeal': 'abc',
                           'AuditCloseManagedBy': records.MANAGED_BY}):
            with self.subTest(seal_tags=seal_tags):
                self.reap.reset_mock()
                self.mock_efs.describe_access_points.return_value = {
                    'AccessPoints': [access_point(extra_tags=seal_tags)]}
                result = self.run_handler()
                self.assertEqual(result['skipped'], 1)
                self.reap.assert_not_called()

    def test_unmanaged_access_point_skipped(self):
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point(extra_tags={'ManagedBy': 'someone-else'})]}
        result = self.run_handler()
        self.assertEqual(result['skipped'], 1)
        self.reap.assert_not_called()

    def test_skip_access_point_missing_tags(self):
        entry = access_point()
        entry['Tags'] = [{'Key': 'ClusterID', 'Value': 'test-cluster'},
                         {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'}]
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [entry]}
        result = self.run_handler()
        self.assertEqual((result['checked'], result['skipped'], result['errors']), (1, 1, 0))

    def test_access_point_path_mismatch_is_an_error(self):
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point(path='/wrong-cluster/wrong-investigation')]}
        result = self.run_handler()
        self.assertEqual((result['errors'], result['reaped'], result['skipped']), (1, 0, 0))

    def test_access_point_missing_root_directory_is_an_error(self):
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point(with_root=False)]}
        result = self.run_handler()
        self.assertEqual((result['errors'], result['reaped']), (1, 0))

    def test_invalid_identifiers_are_errors(self):
        for cluster, investigation in (('../escape', 'inv-123'), ('test-cluster', '..')):
            with self.subTest(cluster=cluster, investigation=investigation):
                entry = access_point(cluster=cluster, investigation=investigation)
                self.mock_efs.describe_access_points.return_value = {'AccessPoints': [entry]}
                result = self.run_handler()
                self.assertEqual(result['errors'], 1)
                self.reap.assert_not_called()

    def test_skip_investigation_with_running_tasks(self):
        task_arn = 'arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123'
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [access_point()]}
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {'tasks': [{
            'taskArn': task_arn,
            'tags': [{'key': 'cluster_id', 'value': 'test-cluster'},
                     {'key': 'investigation_id', 'value': 'inv-123'}]}]}
        result = self.run_handler()
        self.assertEqual((result['checked'], result['reaped'], result['skipped']), (1, 0, 1))
        self.reap.assert_not_called()

    def test_legacy_access_point_goes_to_verified_cleanup_without_grace(self):
        ap = access_point(age_hours=0)
        ap['Tags'] = [tag for tag in ap['Tags'] if tag['Key'] != 'CreatedAt']
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [ap]}
        result = self.run_handler()
        self.assertEqual(result['reaped'], 1)
        self.reap.assert_called_once_with('test-cluster', 'inv-123', ap['AccessPointId'], None)

    def test_skip_investigation_within_grace_period(self):
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point(age_hours=24)]}
        result = self.run_handler()
        self.assertEqual((result['checked'], result['reaped'], result['skipped']), (1, 0, 1))
        self.reap.assert_not_called()

    def test_stale_investigation_goes_through_the_shared_gate(self):
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [access_point()]}
        result = self.run_handler()
        self.assertEqual((result['checked'], result['reaped'], result['errors']), (1, 1, 0))
        self.reap.assert_called_once_with('test-cluster', 'inv-123', 'fsap-123456', None)

    def test_reap_multiple_investigations(self):
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [
            access_point(ap_id=f'fsap-{i}', investigation=f'inv-{i}') for i in range(3)]}
        result = self.run_handler()
        self.assertEqual((result['checked'], result['reaped']), (3, 3))
        self.assertEqual(self.reap.call_count, 3)

    def test_failed_reap_counts_as_an_error(self):
        self.reap.return_value = False
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [access_point()]}
        result = self.run_handler()
        self.assertEqual((result['reaped'], result['errors']), (0, 1))

    def test_task_reappearing_before_reap_cancels_it(self):
        """The refresh immediately before reaping is a real gate, not a log line."""
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [access_point()]}
        paginator = MagicMock()
        paginator.paginate.return_value = [{'taskArns': ['arn:aws:ecs:::task/x/late']}]
        self.mock_ecs.get_paginator.return_value = paginator
        result = self.run_handler()
        self.assertEqual((result['reaped'], result['skipped']), (0, 1))
        self.reap.assert_not_called()

    def test_access_point_pagination(self):
        pages = [
            {'AccessPoints': [access_point(ap_id='fsap-1', investigation='inv-1')],
             'NextToken': 'next'},
            {'AccessPoints': [access_point(ap_id='fsap-2', investigation='inv-2')]},
        ]
        self.mock_efs.describe_access_points.side_effect = pages
        result = self.run_handler()
        self.assertEqual(result['checked'], 2)
        self.assertEqual(self.mock_efs.describe_access_points.call_count, 2)

    def test_running_task_pagination(self):
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [access_point()]}
        self.mock_ecs.list_tasks.side_effect = [
            {'taskArns': ['arn:aws:ecs:::task/c/one'], 'nextToken': 'next'},
            {'taskArns': ['arn:aws:ecs:::task/c/two']},
        ]
        self.mock_ecs.describe_tasks.return_value = {'tasks': [{
            'taskArn': 'arn:aws:ecs:::task/c/one',
            'tags': [{'key': 'cluster_id', 'value': 'test-cluster'},
                     {'key': 'investigation_id', 'value': 'inv-123'}]}]}
        result = self.run_handler()
        self.assertEqual(self.mock_ecs.list_tasks.call_count, 2)
        self.assertEqual(result['skipped'], 1)

    def test_describe_tasks_failure_stops_the_run(self):
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': [access_point()]}
        self.mock_ecs.list_tasks.return_value = {'taskArns': ['arn:aws:ecs:::task/c/one']}
        self.mock_ecs.describe_tasks.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'denied'}}, 'DescribeTasks')
        result = self.run_handler()
        self.assertIn('error', result)
        self.reap.assert_not_called()

    def test_missing_configuration_fails_loudly(self):
        for variable in ('ECS_CLUSTER', 'EFS_FILESYSTEM_ID'):
            with self.subTest(variable=variable), patch.object(handler, variable, None):
                with self.assertRaises(ValueError):
                    handler.lambda_handler({}, None)


class TestStaleness(unittest.TestCase):
    """Creation-age versus inactivity semantics are unchanged by close work."""

    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def test_running_task_is_never_stale(self):
        tasks = [{'cluster_id': 'c', 'investigation_id': 'i'}]
        result = handler.is_investigation_stale('c', 'i', self.now - timedelta(days=30),
                                                self.now, tasks)
        self.assertFalse(result['is_stale'])
        self.assertEqual(result['running_tasks'], 1)

    def test_idle_and_old_is_stale(self):
        result = handler.is_investigation_stale('c', 'i', self.now - timedelta(hours=100),
                                                self.now, [])
        self.assertTrue(result['is_stale'])

    def test_idle_and_recent_is_not_stale(self):
        result = handler.is_investigation_stale('c', 'i', self.now - timedelta(hours=1),
                                                self.now, [])
        self.assertFalse(result['is_stale'])

    def test_exactly_at_grace_period_is_not_stale(self):
        result = handler.is_investigation_stale(
            'c', 'i', self.now - timedelta(hours=handler.GRACE_PERIOD_HOURS), self.now, [])
        self.assertFalse(result['is_stale'])

    def test_missing_creation_tag_backfills(self):
        result = handler.is_investigation_stale('c', 'i', None, self.now, [])
        self.assertTrue(result['is_stale'])
        self.assertIn('legacy', result['reason'])

    def test_other_investigations_tasks_are_ignored(self):
        tasks = [{'cluster_id': 'other', 'investigation_id': 'i'}]
        result = handler.is_investigation_stale('c', 'i', self.now - timedelta(hours=100),
                                                self.now, tasks)
        self.assertTrue(result['is_stale'])


class TestIdentifierValidation(unittest.TestCase):
    def test_accepts_valid_values(self):
        for value in ('cluster-1', 'INV_123', 'a.b-c', '0'):
            handler.validate_identifier(value, 'ClusterID')

    def test_rejects_traversal_and_empty(self):
        for value in ('', '.', '..', '../etc', 'a/b', '-leading', '.hidden'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                handler.validate_identifier(value, 'ClusterID')

    def test_control_root_cannot_be_an_investigation(self):
        """The control prefix lives outside any workspace the CLI can name."""
        with self.assertRaises(ValueError):
            handler.validate_identifier('.boundary-control', 'ClusterID')


TOKEN = '11111111-2222-4333-8444-555555555555'
REQUESTED_AT = '2026-01-01T00:00:00+00:00'


class TestCloseWorkOrchestration(unittest.TestCase):
    """Requests and intents, bounded and fair, before the stale sweep."""

    def setUp(self):
        self.finalizer = MagicMock()
        self.finalizer.list_keys.return_value = []
        self.context = MagicMock()
        self.context.get_remaining_time_in_millis.return_value = 300000
        self.enterContext(patch('handler.build_finalizer', return_value=self.finalizer))
        self.enterContext(patch.object(handler, 'S3_AUDIT_BUCKET', 'audit-bucket'))
        self.enterContext(patch.object(handler, 'ECS_CLUSTER', 'test-cluster'))

    def request_record(self, token=TOKEN, requested_at=REQUESTED_AT, **overrides):
        record = {
            'schema_version': records.REQUEST_SCHEMA_VERSION,
            'kind': records.KIND_REQUEST,
            'request_token': token,
            'cluster_id': 'cluster',
            'investigation_id': 'inv',
            'access_point_id': 'fsap-00000000',
            'requester_sub': 'sre-a',
            'stop_scope': records.STOP_NONE,
            'stop_task_ids': [],
            'trigger': 'cli_close',
            'requested_at': requested_at,
        }
        record.update(overrides)
        return record

    def key_for(self, record):
        return records.request_key(record['cluster_id'], record['investigation_id'],
                                   record['request_token'], record['requested_at'])

    def queue(self, *recorded, status=None):
        """Serve the given request records and one status record."""
        by_key = {self.key_for(record): record for record in recorded}
        self.finalizer.list_keys.side_effect = lambda prefix: (
            sorted(by_key) if prefix.endswith('/requests/') else [])

        def get_json(key, kind):
            if kind == records.KIND_REQUEST:
                return by_key.get(key)
            if kind == records.KIND_STATUS:
                return status
            return None

        self.finalizer.get_json.side_effect = get_json
        self.finalizer.find_access_point.return_value = {
            'id': 'fsap-00000000', 'tags': {}, 'path': '/cluster/inv'}
        self.finalizer.finalize.return_value = {'status': records.STATUS_COMPLETED}
        return by_key

    def status_record(self, **overrides):
        record = {'kind': records.KIND_STATUS, 'status': records.STATUS_COMPLETED,
                  'request_token': TOKEN, 'updated_at': '2026-01-02T00:00:00+00:00',
                  'retryable': False}
        record.update(overrides)
        return record

    def test_without_an_audit_bucket_no_close_work_runs(self):
        with patch.object(handler, 'S3_AUDIT_BUCKET', ''):
            summary = handler.process_close_work(self.context)
        self.assertEqual(summary['requests_processed'], 0)

    def test_request_is_finalized_through_the_shared_pipeline(self):
        self.queue(self.request_record())
        summary = handler.process_close_work(self.context)
        self.assertEqual(summary['requests_processed'], 1)
        self.assertEqual(self.finalizer.finalize.call_args.kwargs['mode'], 'request')

    def test_a_scheduled_sweep_request_resumes_on_the_stale_route(self):
        """An interrupted stale pass leaves a sealed workspace; its recorded
        request is what brings the sweep back to it."""
        self.queue(self.request_record(trigger=records.TRIGGER_STALE, requester_sub=''))
        handler.process_close_work(self.context)
        self.assertEqual(self.finalizer.finalize.call_args.kwargs['mode'], 'stale')

    def test_a_terminal_status_for_this_request_is_not_reprocessed(self):
        self.queue(self.request_record(), status=self.status_record())
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()

    def test_an_older_retention_does_not_answer_a_newer_request(self):
        self.queue(self.request_record(token='22222222-3333-4444-8555-666666666666',
                                       requested_at='2026-02-01T00:00:00+00:00'),
                   status=self.status_record(status=records.STATUS_RETAINED,
                                             updated_at='2026-01-02T00:00:00+00:00'))
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_called_once()

    def test_a_newer_outcome_answers_an_older_request(self):
        self.queue(self.request_record(token='22222222-3333-4444-8555-666666666666',
                                       requested_at='2026-01-01T00:00:00+00:00'),
                   status=self.status_record(updated_at='2026-03-01T00:00:00+00:00'))
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()

    def test_a_retryable_retention_is_picked_up_again(self):
        """A throttled API call must not end a close request forever."""
        self.queue(self.request_record(),
                   status=self.status_record(status=records.STATUS_RETAINED, retryable=True))
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_called_once()

    def test_a_final_retention_is_not_picked_up_again(self):
        self.queue(self.request_record(),
                   status=self.status_record(status=records.STATUS_RETAINED, retryable=False))
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()

    def test_a_request_whose_identity_disagrees_with_its_key_is_refused(self):
        record = self.request_record()
        key = self.key_for(record)
        self.finalizer.list_keys.side_effect = lambda prefix: (
            [key] if prefix.endswith('/requests/') else [])
        self.finalizer.get_json.side_effect = lambda k, kind: (
            dict(record, cluster_id='other') if kind == records.KIND_REQUEST else None)
        summary = handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()
        self.assertEqual(summary['close_errors'], 1)

    def test_a_malformed_request_is_an_error_not_a_close(self):
        key = self.key_for(self.request_record())
        self.finalizer.list_keys.side_effect = lambda prefix: (
            [key] if prefix.endswith('/requests/') else [])
        self.finalizer.get_json.side_effect = lambda k, kind: (
            {'kind': records.KIND_REQUEST} if kind == records.KIND_REQUEST else None)
        summary = handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()
        self.assertEqual(summary['close_errors'], 1)

    def test_a_key_the_scan_cannot_parse_is_skipped(self):
        for key in (f'{records.CONTROL_PREFIX}/requests/cluster/inv/{TOKEN}.json',
                    f'{records.CONTROL_PREFIX}/requests/../inv/20260101T000000Z-{TOKEN}.json',
                    f'{records.CONTROL_PREFIX}/requests/cluster/20260101T000000Z-x.json'):
            with self.subTest(key=key):
                self.finalizer.get_json.reset_mock()
                self.finalizer.list_keys.side_effect = lambda prefix: (
                    [key] if prefix.endswith('/requests/') else [])
                handler.process_close_work(self.context)
                self.finalizer.finalize.assert_not_called()

    def test_requests_are_capped_per_run_so_the_stale_sweep_is_not_starved(self):
        self.queue(*[self.request_record(token=f'1111111{i}-2222-4333-8444-555555555555',
                                         investigation_id=f'inv{i}') for i in range(5)])
        with patch.object(handler, 'CLOSE_REQUESTS_PER_RUN', 2):
            summary = handler.process_close_work(self.context)
        self.assertEqual(summary['requests_processed'], 2)

    def test_a_waiting_request_does_not_starve_every_later_one(self):
        """The budget rotates; it is not spent on the head of the key space.

        A request waiting for a task to stop stays unanswered for as long as
        the wait lasts. Taking the first few keys every run would let a
        handful of waiting investigations hold the whole budget forever, so a
        request recorded behind them would never be finalized at all.
        """
        waiting = [self.request_record(token=f'1111111{i}-2222-4333-8444-555555555555',
                                       investigation_id=f'inv{i}') for i in range(3)]
        latecomer = self.request_record(token='99999999-2222-4333-8444-555555555555',
                                        investigation_id='zzz-last')
        by_key = {self.key_for(record): record for record in waiting + [latecomer]}
        # Each waiting investigation already has a non-terminal status; the
        # latecomer has none, so it has waited longest by definition.
        waiting_status = {
            records.status_key(r['cluster_id'], r['investigation_id']): {
                'kind': records.KIND_STATUS, 'status': records.STATUS_WAITING_FOR_TASKS,
                'request_token': r['request_token'], 'retryable': True,
                'updated_at': '2026-01-02T00:00:00+00:00'}
            for r in waiting}
        self.finalizer.list_keys.side_effect = lambda prefix: (
            sorted(by_key) if prefix.endswith('/requests/') else [])
        self.finalizer.get_json.side_effect = lambda key, kind: (
            by_key.get(key) if kind == records.KIND_REQUEST else waiting_status.get(key))
        self.finalizer.find_access_point.return_value = {
            'id': 'fsap-00000000', 'tags': {}, 'path': '/cluster/inv'}
        self.finalizer.finalize.return_value = {'status': records.STATUS_WAITING_FOR_TASKS}

        with patch.object(handler, 'CLOSE_REQUESTS_PER_RUN', 3):
            handler.process_close_work(self.context)

        finalized = [call.kwargs['investigation_id']
                     for call in self.finalizer.finalize.call_args_list]
        self.assertIn('zzz-last', finalized,
                      'a request behind three waiting ones was never finalized')

    def test_an_investigation_already_closed_does_not_come_back_every_run(self):
        """Even a later request is answered by the original completion."""
        late = self.request_record(token='99999999-2222-4333-8444-555555555555',
                                   requested_at='2026-02-01T00:00:00+00:00')
        self.queue(late, status=self.status_record(
            request_token=TOKEN, updated_at='2026-01-02T00:00:00+00:00'))
        self.finalizer.find_access_point.return_value = None

        handler.process_close_work(self.context)

        self.finalizer.write_status.assert_not_called()
        self.finalizer.finalize.assert_not_called()
        self.finalizer.find_access_point.assert_not_called()

    def test_the_scan_stops_when_the_runtime_budget_runs_out(self):
        self.queue(*[self.request_record(token=f'1111111{i}-2222-4333-8444-555555555555',
                                         investigation_id=f'inv{i}') for i in range(5)])
        self.context.get_remaining_time_in_millis.return_value = 31000
        summary = handler.process_close_work(self.context)
        self.assertEqual(summary['requests_processed'], 0)
        self.finalizer.finalize.assert_not_called()

    def test_an_answered_request_is_skipped_without_reading_it(self):
        """Records are object-locked and never deleted, so the scan has to be
        able to pass over history cheaply."""
        answered = self.request_record()
        self.queue(answered, status=self.status_record())
        handler.process_close_work(self.context)
        read_kinds = [call.args[1] for call in self.finalizer.get_json.call_args_list]
        self.assertNotIn(records.KIND_REQUEST, read_kinds)

    def test_the_status_record_is_read_once_per_investigation(self):
        self.queue(*[self.request_record(token=f'1111111{i}-2222-4333-8444-555555555555',
                                         requested_at=f'2026-01-0{i + 1}T00:00:00+00:00')
                     for i in range(3)])
        with patch.object(handler, 'CLOSE_REQUESTS_PER_RUN', 1):
            handler.process_close_work(self.context)
        status_reads = [call for call in self.finalizer.get_json.call_args_list
                        if call.args[1] == records.KIND_STATUS]
        self.assertEqual(len(status_reads), 1)

    def test_a_request_does_not_follow_the_name_to_a_replacement_access_point(self):
        self.queue(self.request_record())
        self.finalizer.find_access_point.return_value = {'id': 'fsap-11111111'}
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()
        status = self.finalizer.write_status.call_args
        self.assertEqual(status.args[2], records.STATUS_RETAINED)
        self.assertEqual(status.kwargs['access_point_id'], 'fsap-00000000')

    def test_a_missing_workspace_records_a_terminal_status(self):
        self.queue(self.request_record())
        self.finalizer.find_access_point.return_value = None
        handler.process_close_work(self.context)
        self.finalizer.finalize.assert_not_called()
        self.finalizer.write_status.assert_called_once()
        self.assertEqual(self.finalizer.write_status.call_args.args[2], records.STATUS_RETAINED)

    def test_a_completed_close_is_not_overwritten_by_a_late_request(self):
        """An auto-close intent activated after an explicit close finished must
        not turn a verified close into a reported failure."""
        self.queue(self.request_record(token='22222222-3333-4444-8555-666666666666',
                                       requested_at='2026-02-01T00:00:00+00:00'),
                   status=self.status_record(updated_at='2026-01-02T00:00:00+00:00'))
        self.finalizer.find_access_point.return_value = None
        handler.process_close_work(self.context)
        self.finalizer.write_status.assert_not_called()


class TestStaleReapRoute(unittest.TestCase):
    """The scheduled sweep uses the same gate, with no stop consent."""

    def setUp(self):
        self.finalizer = MagicMock()
        self.finalizer.find_access_point.return_value = {
            'id': 'fsap-00000000', 'tags': {}, 'path': '/cluster/inv'}
        self.finalizer.get_json.return_value = None
        self.finalizer.finalize.return_value = {'status': records.STATUS_COMPLETED}
        self.context = MagicMock()
        self.context.get_remaining_time_in_millis.return_value = 300000
        self.enterContext(patch('handler.build_finalizer', return_value=self.finalizer))
        self.enterContext(patch.object(handler, 'S3_AUDIT_BUCKET', 'audit-bucket'))

        self.finalizer.observe.return_value = {'state': records.STATE_IDLE, 'tasks': []}

    def test_a_stopping_task_with_a_shell_blocks_the_stale_request_itself(self):
        self.finalizer.observe.return_value = {
            'state': records.STATE_ACTIVE,
            'tasks': [{'task_id': 'a' * 32, 'last_status': 'STOPPING'}],
        }
        self.assertFalse(handler.reap_investigation('cluster', 'inv', 'fsap-00000000',
                                                    self.context))
        self.finalizer.put_json.assert_not_called()
        self.finalizer.finalize.assert_not_called()

    def test_the_stale_route_carries_no_stop_consent(self):
        self.assertTrue(handler.reap_investigation('cluster', 'inv', 'fsap-00000000',
                                                   self.context))
        request = self.finalizer.finalize.call_args.kwargs['request']
        self.assertEqual(self.finalizer.finalize.call_args.kwargs['mode'], 'stale')
        self.assertEqual(request['stop_scope'], records.STOP_NONE)
        self.assertEqual(request['stop_task_ids'], [])
        self.assertEqual(request['trigger'], records.TRIGGER_STALE)
        self.assertEqual(request['requester_sub'], '')

    def test_the_stale_request_is_recorded_before_the_pass_begins(self):
        """Sealing happens early and the sweep skips sealed access points, so
        an unrecorded pass that stops halfway would strand the workspace."""
        handler.reap_investigation('cluster', 'inv', 'fsap-00000000', self.context)
        key, record = self.finalizer.put_json.call_args.args
        records.validate_request(record)
        self.assertEqual(key, records.request_key('cluster', 'inv', record['request_token'],
                                                  record['requested_at']))
        self.assertLess(self.finalizer.put_json.call_count,
                        self.finalizer.finalize.call_count + 1)

    def test_a_request_that_cannot_be_recorded_defers_the_pass(self):
        self.finalizer.put_json.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'PutObject')
        self.assertFalse(handler.reap_investigation('cluster', 'inv', 'fsap-00000000',
                                                    self.context))
        self.finalizer.finalize.assert_not_called()

    def test_too_little_runtime_defers_the_pass(self):
        self.context.get_remaining_time_in_millis.return_value = 31000
        self.assertFalse(handler.reap_investigation('cluster', 'inv', 'fsap-00000000',
                                                    self.context))
        self.finalizer.finalize.assert_not_called()

    def test_without_an_audit_bucket_nothing_is_reaped(self):
        with patch.object(handler, 'S3_AUDIT_BUCKET', ''):
            self.assertFalse(handler.reap_investigation('cluster', 'inv', 'fsap-00000000',
                                                        self.context))
        self.finalizer.finalize.assert_not_called()


class TestAutoCloseIntents(unittest.TestCase):
    def setUp(self):
        self.finalizer = MagicMock()
        self.context = MagicMock()
        self.context.get_remaining_time_in_millis.return_value = 300000
        self.key = f'{records.CONTROL_PREFIX}/intents/cluster/inv/{"a" * 32}.json'
        self.finalizer.list_keys.return_value = [self.key]
        self.enterContext(patch.object(handler, 'ECS_CLUSTER', 'test-cluster'))

    def intent(self, **overrides):
        record = {
            'schema_version': records.INTENT_SCHEMA_VERSION,
            'kind': records.KIND_INTENT,
            'cluster_id': 'cluster',
            'investigation_id': 'inv',
            'access_point_id': 'fsap-00000000',
            'task_id': 'a' * 32,
            'requester_sub': 'sre-a',
            'stop_scope': records.STOP_SESSION_TASK,
            'created_at': '2026-01-01T00:00:00+00:00',
            'cancelled': False,
        }
        record.update(overrides)
        return record

    def observation(self, state, holder=None, tasks=()):
        return {'state': state, 'holder_sub': holder, 'active_sessions': 0,
                'tasks': list(tasks), 'reason': '', 'observed_at': '2026-01-01T00:00:00+00:00'}

    def test_intent_waits_while_its_own_task_runs(self):
        self.finalizer.get_json.return_value = self.intent()
        self.finalizer.observe.return_value = self.observation(
            records.STATE_ACTIVE, 'sre-a',
            [{'task_id': 'a' * 32, 'last_status': 'RUNNING', 'oidc_sub': 'sre-a'}])
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 0)

    def test_intent_activates_once_its_task_has_stopped(self):
        self.finalizer.get_json.return_value = self.intent()
        self.finalizer.observe.return_value = self.observation(records.STATE_IDLE)
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 1)
        written = [call.args[1] for call in self.finalizer.put_json.call_args_list]
        request = next(r for r in written if r.get('kind') == records.KIND_REQUEST)
        records.validate_request(request)
        self.assertEqual(request['trigger'], 'auto_close')
        self.assertEqual(request['stop_task_ids'], ['a' * 32])

    def test_handover_supersedes_an_intent_instead_of_closing_the_new_holder(self):
        self.finalizer.get_json.return_value = self.intent()
        self.finalizer.observe.return_value = self.observation(
            records.STATE_ACTIVE, 'sre-b',
            [{'task_id': 'b' * 32, 'last_status': 'RUNNING', 'oidc_sub': 'sre-b'}])
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 0)
        cancelled = self.finalizer.put_json.call_args.args[1]
        self.assertTrue(cancelled['cancelled'])
        self.assertIn('superseded', cancelled['cancelled_reason'])

    def test_stop_all_intent_defers_while_requester_has_another_shell(self):
        self.finalizer.get_json.return_value = self.intent(stop_scope=records.STOP_INVESTIGATION)
        self.finalizer.observe.return_value = self.observation(
            records.STATE_ACTIVE, 'sre-a',
            [{'task_id': 'b' * 32, 'last_status': 'RUNNING', 'oidc_sub': 'sre-a'}])
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 0)
        self.finalizer.put_json.assert_not_called()

    def test_unknown_state_defers_rather_than_closing(self):
        self.finalizer.get_json.return_value = self.intent()
        self.finalizer.observe.return_value = self.observation(records.STATE_UNKNOWN)
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 0)
        self.finalizer.put_json.assert_not_called()

    def test_another_sres_detached_task_defers_the_intent_without_cancelling_it(self):
        """Idle is not consent to seal around somebody else's running task.

        A's own task has stopped and B is not attached, so the investigation
        reads idle and A's request is not superseded. A only consented to
        stopping their own task, so the intent waits for B's task rather than
        sealing a workspace B may still be using.
        """
        self.finalizer.get_json.return_value = self.intent()
        self.finalizer.observe.return_value = self.observation(
            records.STATE_IDLE,
            tasks=[{'task_id': 'b' * 32, 'last_status': 'RUNNING', 'oidc_sub': 'sre-b'}])
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 0)
        # Deferred, not cancelled: it is still valid once the task stops.
        self.finalizer.put_json.assert_not_called()

    def test_explicit_whole_investigation_consent_activates_despite_a_running_task(self):
        """The SRE did authorize stopping every task, so the wait is waived."""
        self.finalizer.get_json.return_value = self.intent(
            stop_scope=records.STOP_INVESTIGATION)
        self.finalizer.observe.return_value = self.observation(
            records.STATE_IDLE,
            tasks=[{'task_id': 'b' * 32, 'last_status': 'RUNNING', 'oidc_sub': 'sre-b'}])
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 1)
        written = [call.args[1] for call in self.finalizer.put_json.call_args_list]
        request = next(r for r in written if r.get('kind') == records.KIND_REQUEST)
        records.validate_request(request)
        self.assertEqual(request['stop_scope'], records.STOP_INVESTIGATION)

    def test_intent_activation_is_capped_so_requests_still_get_the_budget(self):
        """Intents run first, so an unbounded burst would starve requests."""
        keys = [f'{records.CONTROL_PREFIX}/intents/cluster/inv{i}/{"a" * 32}.json'
                for i in range(5)]
        self.finalizer.list_keys.return_value = keys
        self.finalizer.get_json.side_effect = lambda key, kind: self.intent()
        self.finalizer.observe.return_value = self.observation(records.STATE_IDLE)
        with patch.object(handler, 'CLOSE_REQUESTS_PER_RUN', 2):
            self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 2)

    def test_an_intent_without_an_access_point_is_rejected_not_a_crash(self):
        """A KeyError here would escape the reaper's handling and take the
        whole invocation down, stale sweep included."""
        intent = self.intent()
        del intent['access_point_id']
        self.finalizer.get_json.return_value = intent
        self.finalizer.observe.return_value = self.observation(records.STATE_IDLE)
        self.assertEqual(handler.activate_auto_close_intents(self.finalizer, self.context), 0)
        self.finalizer.put_json.assert_not_called()

    def test_cancelled_and_already_activated_intents_are_ignored(self):
        for overrides in ({'cancelled': True},
                          {'activated_request_token': '11111111-2222-4333-8444-555555555555'}):
            with self.subTest(overrides=overrides):
                self.finalizer.put_json.reset_mock()
                self.finalizer.get_json.return_value = self.intent(**overrides)
                self.assertEqual(
                    handler.activate_auto_close_intents(self.finalizer, self.context), 0)
                self.finalizer.put_json.assert_not_called()


class TestKeyParsing(unittest.TestCase):
    def test_unsafe_control_keys_are_ignored(self):
        prefix = f'{records.CONTROL_PREFIX}/requests/'
        self.assertIsNone(handler._identifiers_from_key(f'{prefix}../x/y.json', prefix, 3))
        self.assertIsNone(handler._identifiers_from_key(f'{prefix}a/b.json', prefix, 3))
        self.assertIsNone(handler._identifiers_from_key('other/a/b/c.json', prefix, 3))
        self.assertEqual(handler._identifiers_from_key(f'{prefix}a/b/c.json', prefix, 3),
                         ['a', 'b', 'c'])


if __name__ == '__main__':
    unittest.main()
