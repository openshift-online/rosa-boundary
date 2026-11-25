"""
Unit tests for reaper Lambda handler.

Tests the periodic task timeout enforcement using mocked boto3 clients.
"""

import os
import json
import unittest
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, call

# Set environment variables before importing handler
os.environ['ECS_CLUSTER'] = 'test-cluster'

# Mock client construction before import: unit tests must not resolve workstation
# AWS regions/credentials or contact AWS. Tests replace these clients per case.
with patch('boto3.client'):
    import handler


class TestReaperLambda(unittest.TestCase):
    """Test cases for reaper Lambda handler"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_ecs = MagicMock()
        self.patcher = patch('handler.ecs', self.mock_ecs)
        self.patcher.start()

        self.mock_ssm = MagicMock()
        self.ssm_patcher = patch('handler.ssm', self.mock_ssm)
        self.ssm_patcher.start()
        # Default: no active sessions. Individual tests override as needed.
        self.mock_ssm.describe_sessions.return_value = {'Sessions': []}

    def tearDown(self):
        """Clean up patches"""
        self.patcher.stop()
        self.ssm_patcher.stop()

    @staticmethod
    def _exec_task(task_arn, deadline, containers=None):
        """Build a describe_tasks entry for an ECS Exec-enabled task.

        Mirrors the real DescribeTasks shape: a task-level enableExecuteCommand
        flag plus a containers array whose RUNNING entries carry a runtimeId.
        """
        if containers is None:
            containers = [{
                'name': 'rosa-boundary',
                'lastStatus': 'RUNNING',
                'runtimeId': 'runtime-abc'
            }]
        return {
            'taskArn': task_arn,
            'enableExecuteCommand': True,
            'containers': containers,
            'tags': [{'key': 'deadline', 'value': deadline}]
        }

    def test_independent_age_limit(self):
        now = datetime.now(timezone.utc)
        task = self._exec_task('task-1', (now + timedelta(hours=1)).isoformat())
        task['tags'] += [{'key': 'investigation_id', 'value': 'inv'},
                         {'key': 'oidc_sub', 'value': 'creator'}]
        task['createdAt'] = now - timedelta(hours=8) + timedelta(seconds=1)
        self.assertEqual(handler.reap_reason(task, now), (None, False))
        task['createdAt'] -= timedelta(seconds=1)
        self.assertTrue(handler.reap_reason(task, now)[1])
        # No configured deadline and an attached shell cannot defer this timer.
        task['tags'].pop(0)
        self.mock_ssm.describe_sessions.return_value = {'Sessions': [{'SessionId': 'shell'}]}
        self.mock_ecs.list_tasks.return_value = {'taskArns': ['task-1']}
        self.mock_ecs.describe_tasks.return_value = {'tasks': [task]}
        self.assertEqual(handler.lambda_handler({}, None)['stopped'], 1)
        self.mock_ssm.describe_sessions.assert_not_called()

    def test_configured_timer_uses_task_age_not_prelaunch_deadline(self):
        now = datetime.now(timezone.utc)
        task = self._exec_task('task-1', (now - timedelta(minutes=1)).isoformat())
        task['tags'] += [{'key': 'investigation_id', 'value': 'inv'},
                         {'key': 'oidc_sub', 'value': 'creator'},
                         {'key': 'task_timeout', 'value': '3600'}]
        self.assertEqual(handler.reap_reason(task, now), (None, False))  # Unknown task age.
        task['createdAt'] = now - timedelta(seconds=3599)
        self.assertEqual(handler.reap_reason(task, now), (None, False))
        task['createdAt'] -= timedelta(seconds=1)
        self.assertEqual(handler.reap_reason(task, now), (
            'IDLE session reached configured timeout (3600s)', False))
        task['tags'][-1]['value'] = '0'
        self.assertEqual(handler.reap_reason(task, now), (None, False))

    def test_incomplete_session_page_does_not_establish_idle(self):
        task = self._exec_task('task-1', '2000-01-01')
        self.mock_ecs.list_tasks.return_value = {'taskArns': ['task-1']}
        self.mock_ecs.describe_tasks.return_value = {'tasks': [task]}
        for page in ({}, {'Sessions': [], 'NextToken': ''}, {'Sessions': [], 'NextToken': 'repeated'}):
            with self.subTest(page=page):
                self.mock_ssm.describe_sessions.return_value = page
                result = handler.lambda_handler({}, None)
                self.assertEqual(result['errors'], 1)
                self.mock_ecs.stop_task.assert_not_called()

    def test_deadline_equality(self):
        now = datetime.now(timezone.utc)
        task = self._exec_task('task-1', now.isoformat())
        reason, hard = handler.reap_reason(task, now)
        self.assertTrue(reason)
        self.assertFalse(hard)

    def test_no_running_tasks(self):
        """Test reaper with no running tasks"""
        # Mock empty task list
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 0
        assert result['stopped'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == 0

        # Verify list_tasks was called
        self.mock_ecs.list_tasks.assert_called_once()

    def test_stop_task_with_past_deadline(self):
        """Test that tasks with past deadline are stopped"""
        # Create past deadline
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        # Mock task list
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}

        # Mock describe_tasks (non-exec task: safe to reap without a session check)
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'enableExecuteCommand': False,
                'tags': [
                    {'key': 'deadline', 'value': past_deadline},
                    {'key': 'oidc_sub', 'value': 'test-user-123'},
                    {'key': 'username', 'value': 'testuser'},
                    {'key': 'investigation_id', 'value': 'inv-123'}
                ]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 1
        assert result['skipped'] == 0
        assert result['errors'] == 0

        # Verify stop_task was called
        self.mock_ecs.stop_task.assert_called_once_with(
            cluster='test-cluster',
            task=task_arn,
            reason=f'Task deadline exceeded (deadline: {past_deadline})'
        )

    def test_skip_task_without_deadline_tag(self):
        """Test that tasks without deadline tag are skipped"""
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        # Mock task list
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}

        # Mock describe_tasks (no deadline tag)
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'tags': [
                    {'key': 'investigation_id', 'value': 'inv-123'}
                ]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['skipped'] == 1
        assert result['errors'] == 0

        # Verify stop_task was NOT called
        self.mock_ecs.stop_task.assert_not_called()

    def test_skip_task_with_future_deadline(self):
        """Test that tasks with future deadline are skipped"""
        # Create future deadline
        future_deadline = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        # Mock task list
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}

        # Mock describe_tasks
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'tags': [
                    {'key': 'deadline', 'value': future_deadline}
                ]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['skipped'] == 1
        assert result['errors'] == 0

        # Verify stop_task was NOT called
        self.mock_ecs.stop_task.assert_not_called()

    def test_handle_stop_task_error_gracefully(self):
        """Test that stop_task errors don't prevent processing other tasks"""
        from botocore.exceptions import ClientError

        # Create two tasks with past deadlines
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task1_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task1'
        task2_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task2'

        # Mock task list
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task1_arn, task2_arn]}

        # Mock describe_tasks (non-exec tasks: safe to reap without a session check)
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [
                {
                    'taskArn': task1_arn,
                    'enableExecuteCommand': False,
                    'tags': [{'key': 'deadline', 'value': past_deadline}]
                },
                {
                    'taskArn': task2_arn,
                    'enableExecuteCommand': False,
                    'tags': [{'key': 'deadline', 'value': past_deadline}]
                }
            ]
        }

        # First stop_task fails, second succeeds
        self.mock_ecs.stop_task.side_effect = [
            ClientError({'Error': {'Code': 'TaskNotFound', 'Message': 'Task not found'}}, 'StopTask'),
            None  # Second call succeeds
        ]

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 2
        assert result['stopped'] == 1  # Only second task stopped successfully
        assert result['skipped'] == 0
        assert result['errors'] == 1

        # Verify stop_task was called twice
        assert self.mock_ecs.stop_task.call_count == 2

    def test_handle_stop_task_non_client_error_gracefully(self):
        """Non-ClientError exceptions from stop_task must not abort the reaper run."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task1_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task1'
        task2_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task2'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task1_arn, task2_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [
                {'taskArn': task1_arn, 'enableExecuteCommand': False,
                 'tags': [{'key': 'deadline', 'value': past_deadline}]},
                {'taskArn': task2_arn, 'enableExecuteCommand': False,
                 'tags': [{'key': 'deadline', 'value': past_deadline}]},
            ]
        }

        # First stop_task raises a generic network error (not a ClientError)
        self.mock_ecs.stop_task.side_effect = [
            ConnectionError('Network unreachable'),
            None,  # second task stops successfully
        ]

        result = handler.lambda_handler({}, None)

        # Reaper must continue to the second task despite the network error on the first
        assert result['checked'] == 2
        assert result['stopped'] == 1
        assert result['errors'] == 1
        assert self.mock_ecs.stop_task.call_count == 2
        assert 'error' not in result  # outer handler must not have aborted

    def test_skip_task_with_invalid_deadline_format(self):
        """Test that tasks with invalid deadline format are skipped"""
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        # Mock task list
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}

        # Mock describe_tasks with invalid deadline
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'tags': [
                    {'key': 'deadline', 'value': 'not-a-date'}
                ]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['skipped'] == 1
        assert result['errors'] == 0

        # Verify stop_task was NOT called
        self.mock_ecs.stop_task.assert_not_called()

    def test_missing_ecs_cluster_env_var(self):
        with patch.object(handler, 'ECS_CLUSTER', None):
            with self.assertRaisesRegex(RuntimeError, 'ECS_CLUSTER'):
                handler.lambda_handler({}, None)
        self.mock_ecs.list_tasks.assert_not_called()

    def test_listing_later_page_fails(self):
        from botocore.exceptions import ClientError

        self.mock_ecs.list_tasks.side_effect = [
            {'taskArns': ['first'], 'nextToken': 'next'},
            ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'ListTasks'),
        ]
        with self.assertRaises(ClientError):
            handler.lambda_handler({}, None)
        self.mock_ecs.list_tasks.assert_called_with(
            cluster='test-cluster', desiredStatus='RUNNING', nextToken='next')
        self.mock_ecs.describe_tasks.assert_not_called()

    def test_first_listing_failure(self):
        self.mock_ecs.list_tasks.side_effect = ConnectionError('offline')
        with self.assertRaises(ConnectionError):
            handler.lambda_handler({}, None)
        self.mock_ecs.describe_tasks.assert_not_called()

    def test_all_describe_batches_fail(self):
        tasks = [f'task-{i}' for i in range(101)]
        self.mock_ecs.list_tasks.return_value = {'taskArns': tasks}
        cause = ConnectionError('offline')
        self.mock_ecs.describe_tasks.side_effect = cause
        with self.assertRaises(ConnectionError) as caught:
            handler.lambda_handler({}, None)
        self.assertIs(caught.exception, cause)
        self.assertEqual(self.mock_ecs.describe_tasks.call_count, 2)
        self.mock_ecs.stop_task.assert_not_called()

    def test_describe_returns_only_resource_failures(self):
        self.mock_ecs.list_tasks.return_value = {'taskArns': ['missing']}
        self.mock_ecs.describe_tasks.return_value = {
            'failures': [{'arn': 'missing', 'reason': 'MISSING'}],
        }
        result = handler.lambda_handler({}, None)
        self.assertEqual(result, dict(checked=0, skipped=0, protected=0, stopped=0, errors=1))
        self.mock_ecs.stop_task.assert_not_called()

    def test_partial_describe_failure_processes_later_batch(self):
        tasks = [f'task-{i}' for i in range(102)]
        self.mock_ecs.list_tasks.return_value = {'taskArns': tasks}
        self.mock_ecs.describe_tasks.side_effect = [
            ConnectionError('offline'),
            {'tasks': [{'taskArn': tasks[-1]}],
             'failures': [{'arn': tasks[-2], 'reason': 'MISSING'}]},
        ]
        result = handler.lambda_handler({}, None)
        self.assertEqual(result, dict(checked=1, skipped=1, protected=0, stopped=0, errors=101))

    def test_partial_describe_with_no_returned_tasks(self):
        tasks = [f'task-{i}' for i in range(101)]
        self.mock_ecs.list_tasks.return_value = {'taskArns': tasks}
        missing = {'failures': [{'arn': tasks[-1], 'reason': 'MISSING'}]}
        for code in ['AccessDeniedException', 'ClusterNotFoundException']:
            with self.subTest(code=code):
                cause = ClientError({'Error': {'Code': code}}, 'DescribeTasks')
                self.mock_ecs.describe_tasks.side_effect = [cause, missing]
                if code == 'ClusterNotFoundException':
                    with self.assertRaises(ClientError) as caught:
                        handler.lambda_handler({}, None)
                    self.assertIs(caught.exception, cause)
                else:
                    self.assertEqual(handler.lambda_handler({}, None)['errors'], 101)
                self.mock_ecs.stop_task.assert_not_called()

    def _expired_and_skipped(self, n):
        tasks = [self._exec_task(f'expired-{i}', '2000-01-01') for i in range(n)]
        tasks.append({'taskArn': 'other'})
        self.mock_ecs.list_tasks.return_value = {'taskArns': [t['taskArn'] for t in tasks]}
        self.mock_ecs.describe_tasks.return_value = {'tasks': tasks}

    def test_ssm_outcomes(self):
        for codes, systemic in [
            (['InternalServerError'], False),
            (['InternalServerError', 'ThrottlingException'], False),
            (['InvalidFilter', 'InvalidFilter'], False),
            (['InternalServerError', 'InternalServerError'], True),
            (['InternalServerError', 'InternalServerError', None], False),
            (['AccessDeniedException', None], True),
        ]:
            with self.subTest(codes=codes):
                self._expired_and_skipped(len(codes))
                responses = [ClientError({'Error': {'Code': c}}, 'DescribeSessions')
                             if c else {'Sessions': []} for c in codes]
                self.mock_ssm.describe_sessions.side_effect = responses
                self.mock_ecs.stop_task.reset_mock()
                if systemic:
                    with self.assertRaises(ClientError) as caught:
                        handler.lambda_handler({}, None)
                    self.assertIs(caught.exception, responses[0])
                else:
                    result = handler.lambda_handler({}, None)
                    self.assertEqual(result['errors'], len(codes) - codes.count(None))
                if None in codes:
                    self.mock_ecs.stop_task.assert_called_once_with(
                        cluster='test-cluster', task=f'expired-{codes.index(None)}',
                        reason='Task deadline exceeded (deadline: 2000-01-01)')
                else:
                    self.mock_ecs.stop_task.assert_not_called()

    def test_single_stop_failure_scope(self):
        self._expired_and_skipped(1)
        for code in ['TaskNotFound', 'AccessDeniedException', 'ClusterNotFoundException']:
            with self.subTest(code=code):
                cause = ClientError({'Error': {'Code': code}}, 'StopTask')
                self.mock_ecs.stop_task.side_effect = cause
                if code == 'ClusterNotFoundException':
                    with self.assertRaises(ClientError) as caught:
                        handler.lambda_handler({}, None)
                    self.assertIs(caught.exception, cause)
                else:
                    result = handler.lambda_handler({}, None)
                    self.assertEqual(result, dict(checked=2, protected=0, skipped=1,
                                                  stopped=0, errors=1))

    def test_pagination_with_multiple_pages(self):
        """Test that pagination works correctly for large task lists"""
        # Create 250 task ARNs (will require 3 batches of 100)
        task_arns = [
            f'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task{i}'
            for i in range(250)
        ]

        # Mock paginated list_tasks responses
        self.mock_ecs.list_tasks.side_effect = [
            {'taskArns': task_arns[:100], 'nextToken': 'token1'},
            {'taskArns': task_arns[100:200], 'nextToken': 'token2'},
            {'taskArns': task_arns[200:250]}
        ]

        # Mock describe_tasks to return tasks without deadlines (skip all)
        def mock_describe(cluster, tasks, include):
            return {
                'tasks': [
                    {'taskArn': arn, 'tags': []}
                    for arn in tasks
                ]
            }

        self.mock_ecs.describe_tasks.side_effect = mock_describe

        result = handler.lambda_handler({}, None)

        # Should have checked all 250 tasks
        assert result['checked'] == 250
        assert result['stopped'] == 0
        assert result['skipped'] == 250
        assert result['errors'] == 0

        # Verify list_tasks was called 3 times for pagination
        assert self.mock_ecs.list_tasks.call_count == 3

        # Verify describe_tasks was called 3 times (batches of 100, 100, 50)
        assert self.mock_ecs.describe_tasks.call_count == 3

    # ------------------------------------------------------------------
    # ROSAENG-66967: protect active ECS Exec / SSM sessions from reaping
    # ------------------------------------------------------------------

    def test_expired_task_with_active_session_is_protected(self):
        """A: expired task with an active SSM session is NOT stopped."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [self._exec_task(task_arn, past_deadline)]
        }
        # Active session present on the container.
        self.mock_ssm.describe_sessions.return_value = {
            'Sessions': [{'SessionId': 'rosa-boundary-0abc', 'Status': 'Connected'}]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['protected'] == 1
        assert result['errors'] == 0
        self.mock_ecs.stop_task.assert_not_called()

        # Session lookup used the create-investigation target convention.
        self.mock_ssm.describe_sessions.assert_called_once_with(
            State='Active',
            Filters=[{'key': 'Target', 'value': 'ecs:test-cluster_abc123_runtime-abc'}]
        )

    def test_expired_task_without_active_session_is_stopped(self):
        """B: expired task with no active session is stopped (existing behavior)."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [self._exec_task(task_arn, past_deadline)]
        }
        self.mock_ssm.describe_sessions.return_value = {'Sessions': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 1
        assert result['protected'] == 0
        assert result['errors'] == 0
        self.mock_ecs.stop_task.assert_called_once_with(
            cluster='test-cluster',
            task=task_arn,
            reason=f'Task deadline exceeded (deadline: {past_deadline})'
        )

    def test_future_deadline_does_not_query_sessions(self):
        """C: a task whose deadline has not expired never triggers a session lookup."""
        future_deadline = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/abc123'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [self._exec_task(task_arn, future_deadline)]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['skipped'] == 1
        assert result['protected'] == 0
        assert result['errors'] == 0
        self.mock_ecs.stop_task.assert_not_called()
        self.mock_ssm.describe_sessions.assert_not_called()

    def test_expired_task_session_api_failure_fails_closed(self):
        """D: SSM DescribeSessions failure must fail closed and record an error."""
        from botocore.exceptions import ClientError

        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task1_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task1'
        task2_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/task2'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task1_arn, task2_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [
                self._exec_task(task1_arn, past_deadline,
                                containers=[{'name': 'rosa-boundary', 'lastStatus': 'RUNNING',
                                             'runtimeId': 'runtime-1'}]),
                self._exec_task(task2_arn, past_deadline,
                                containers=[{'name': 'rosa-boundary', 'lastStatus': 'RUNNING',
                                             'runtimeId': 'runtime-2'}]),
            ]
        }
        # First task's session check fails; second returns no sessions.
        self.mock_ssm.describe_sessions.side_effect = [
            ClientError({'Error': {'Code': 'InternalServerError', 'Message': 'boom'}},
                        'DescribeSessions'),
            {'Sessions': []},
        ]

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 2
        assert result['stopped'] == 1        # second task still processed and stopped
        assert result['protected'] == 0
        assert result['errors'] == 1         # first task's failure recorded
        # First task never stopped; only the second was stopped.
        self.mock_ecs.stop_task.assert_called_once_with(
            cluster='test-cluster',
            task=task2_arn,
            reason=f'Task deadline exceeded (deadline: {past_deadline})'
        )

    def test_expired_task_multiple_containers_any_active_protects(self):
        """E: an active session on any relevant container protects the task."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/multi'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [self._exec_task(task_arn, past_deadline, containers=[
                {'name': 'rosa-boundary', 'lastStatus': 'RUNNING', 'runtimeId': 'runtime-main'},
                {'name': 'kube-proxy', 'lastStatus': 'RUNNING', 'runtimeId': 'runtime-proxy'},
            ])]
        }
        # No session on the first container, active session on the second.
        self.mock_ssm.describe_sessions.side_effect = [
            {'Sessions': []},
            {'Sessions': [{'SessionId': 'rosa-boundary-1def'}]},
        ]

        result = handler.lambda_handler({}, None)

        assert result['protected'] == 1
        assert result['stopped'] == 0
        assert result['errors'] == 0
        self.mock_ecs.stop_task.assert_not_called()
        assert self.mock_ssm.describe_sessions.call_count == 2

    def test_expired_exec_task_missing_runtime_id_fails_closed(self):
        """F: exec-enabled task with a RUNNING container but no runtimeId fails closed."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/noruntime'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [self._exec_task(task_arn, past_deadline, containers=[
                {'name': 'rosa-boundary', 'lastStatus': 'RUNNING'},  # no runtimeId
            ])]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['protected'] == 0
        assert result['errors'] == 1
        self.mock_ecs.stop_task.assert_not_called()
        # Could not even address a target, so no session lookup was made.
        self.mock_ssm.describe_sessions.assert_not_called()

    def test_expired_task_missing_exec_flag_fails_closed(self):
        """F (missing flag): a missing enableExecuteCommand field fails closed.

        An absent flag is NOT treated as 'not exec-capable' — exec capability is
        unknown, so the task must not be stopped.
        """
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/noflag'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                # enableExecuteCommand intentionally absent
                'containers': [{'name': 'rosa-boundary', 'lastStatus': 'RUNNING',
                                'runtimeId': 'runtime-abc'}],
                'tags': [{'key': 'deadline', 'value': past_deadline}]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['stopped'] == 0
        assert result['protected'] == 0
        assert result['errors'] == 1
        self.mock_ecs.stop_task.assert_not_called()
        # Exec capability unknown — no session lookup is attempted.
        self.mock_ssm.describe_sessions.assert_not_called()

    def test_expired_non_exec_task_is_stopped_without_session_lookup(self):
        """F (non-exec variant): a task without ECS Exec is reaped, no session lookup."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/noexec'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'enableExecuteCommand': False,
                'containers': [{'name': 'rosa-boundary', 'lastStatus': 'RUNNING'}],
                'tags': [{'key': 'deadline', 'value': past_deadline}]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['stopped'] == 1
        assert result['protected'] == 0
        assert result['errors'] == 0
        self.mock_ecs.stop_task.assert_called_once()
        self.mock_ssm.describe_sessions.assert_not_called()

    def test_multiple_expired_tasks_mixed_session_states(self):
        """G: mixed batch — active protected, inactive stopped, API failure isolated."""
        from botocore.exceptions import ClientError

        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        active_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/active'
        inactive_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/inactive'
        failing_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/failing'

        self.mock_ecs.list_tasks.return_value = {
            'taskArns': [active_arn, inactive_arn, failing_arn]
        }
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [
                self._exec_task(active_arn, past_deadline,
                                containers=[{'name': 'rosa-boundary', 'lastStatus': 'RUNNING',
                                             'runtimeId': 'rt-active'}]),
                self._exec_task(inactive_arn, past_deadline,
                                containers=[{'name': 'rosa-boundary', 'lastStatus': 'RUNNING',
                                             'runtimeId': 'rt-inactive'}]),
                self._exec_task(failing_arn, past_deadline,
                                containers=[{'name': 'rosa-boundary', 'lastStatus': 'RUNNING',
                                             'runtimeId': 'rt-failing'}]),
            ]
        }

        def describe_sessions(State, Filters):
            target = Filters[0]['value']
            if target.endswith('rt-active'):
                return {'Sessions': [{'SessionId': 'rosa-boundary-2ghi'}]}
            if target.endswith('rt-inactive'):
                return {'Sessions': []}
            raise ClientError(
                {'Error': {'Code': 'ThrottlingException', 'Message': 'slow down'}},
                'DescribeSessions'
            )

        self.mock_ssm.describe_sessions.side_effect = describe_sessions

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 3
        assert result['protected'] == 1   # active task
        assert result['stopped'] == 1     # inactive task
        assert result['errors'] == 1      # failing task fails closed
        # Only the inactive task was stopped.
        self.mock_ecs.stop_task.assert_called_once_with(
            cluster='test-cluster',
            task=inactive_arn,
            reason=f'Task deadline exceeded (deadline: {past_deadline})'
        )

    def test_active_session_detected_across_pagination(self):
        """An Active session on a later DescribeSessions page still protects the task."""
        past_deadline = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        task_arn = 'arn:aws:ecs:us-east-2:123456789012:task/test-cluster/paged'

        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [self._exec_task(task_arn, past_deadline)]
        }
        self.mock_ssm.describe_sessions.side_effect = [
            {'Sessions': [], 'NextToken': 'page2'},
            {'Sessions': [{'SessionId': 'rosa-boundary-3jkl'}]},
        ]

        result = handler.lambda_handler({}, None)

        assert result['protected'] == 1
        assert result['stopped'] == 0
        self.mock_ecs.stop_task.assert_not_called()
        assert self.mock_ssm.describe_sessions.call_count == 2


if __name__ == '__main__':
    unittest.main()
