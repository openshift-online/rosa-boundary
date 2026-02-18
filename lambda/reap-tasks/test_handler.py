"""
Unit tests for reaper Lambda handler.

Tests the periodic task timeout enforcement using mocked boto3 clients.
"""

import os
import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, call

# Set environment variables before importing handler
os.environ['ECS_CLUSTER'] = 'test-cluster'

import handler


class TestReaperLambda(unittest.TestCase):
    """Test cases for reaper Lambda handler"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_ecs = MagicMock()
        self.patcher = patch('handler.ecs', self.mock_ecs)
        self.patcher.start()

    def tearDown(self):
        """Clean up patches"""
        self.patcher.stop()

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

        # Mock describe_tasks
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'tags': [
                    {'key': 'deadline', 'value': past_deadline},
                    {'key': 'owner_sub', 'value': 'test-user-123'},
                    {'key': 'owner_username', 'value': 'testuser'},
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

        # Mock describe_tasks
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [
                {
                    'taskArn': task1_arn,
                    'tags': [{'key': 'deadline', 'value': past_deadline}]
                },
                {
                    'taskArn': task2_arn,
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
        """Test error handling when ECS_CLUSTER is not set"""
        # Temporarily remove ECS_CLUSTER env var
        original_cluster = os.environ.get('ECS_CLUSTER')
        if 'ECS_CLUSTER' in os.environ:
            del os.environ['ECS_CLUSTER']

        # Reload handler module to pick up env change
        import importlib
        importlib.reload(handler)

        result = handler.lambda_handler({}, None)

        assert 'error' in result
        assert 'ECS_CLUSTER' in result['error']
        assert result['checked'] == 0
        assert result['stopped'] == 0

        # Restore env var
        if original_cluster:
            os.environ['ECS_CLUSTER'] = original_cluster
        importlib.reload(handler)

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


if __name__ == '__main__':
    unittest.main()
