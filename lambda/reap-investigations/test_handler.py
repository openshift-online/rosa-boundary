"""
Unit tests for investigation reaper Lambda handler.

Tests the periodic garbage collection using mocked boto3 clients.
"""

import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, call

# Set environment variables before importing handler
os.environ['AWS_DEFAULT_REGION'] = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
os.environ['ECS_CLUSTER'] = 'test-cluster'
os.environ['EFS_FILESYSTEM_ID'] = 'fs-12345678'
os.environ['GRACE_PERIOD_HOURS'] = '72'

import handler


class TestReaperLambda(unittest.TestCase):
    """Test cases for investigation reaper Lambda handler"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_ecs = MagicMock()
        self.mock_efs = MagicMock()
        self.mock_shutil = MagicMock()
        self.mock_os_path = MagicMock()
        self.mock_context = MagicMock()
        self.mock_context.get_remaining_time_in_millis.return_value = 300000  # 5 minutes

        self.ecs_patcher = patch('handler.ecs', self.mock_ecs)
        self.efs_patcher = patch('handler.efs', self.mock_efs)
        self.shutil_patcher = patch('handler.shutil', self.mock_shutil)
        self.os_path_patcher = patch('handler.os.path', self.mock_os_path)

        self.ecs_patcher.start()
        self.efs_patcher.start()
        self.shutil_patcher.start()
        self.os_path_patcher.start()

    def tearDown(self):
        """Clean up patches"""
        self.ecs_patcher.stop()
        self.efs_patcher.stop()
        self.shutil_patcher.stop()
        self.os_path_patcher.stop()

    def test_no_access_points(self):
        """Test reaper with no investigation access points"""
        # Mock empty access point list
        self.mock_efs.describe_access_points.return_value = {'AccessPoints': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 0
        assert result['reaped'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == 0

        # Verify describe_access_points was called
        self.mock_efs.describe_access_points.assert_called_once()

    def test_skip_investigation_with_running_tasks(self):
        """Test that investigations with running tasks are skipped"""
        # Create access point
        created_at = datetime.utcnow() - timedelta(hours=100)  # Old enough to be stale
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        # Mock access point list
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        # Mock running task
        task_arn = 'arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123'
        self.mock_ecs.list_tasks.return_value = {'taskArns': [task_arn]}
        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [{
                'taskArn': task_arn,
                'tags': [
                    {'key': 'cluster_id', 'value': 'test-cluster'},
                    {'key': 'investigation_id', 'value': 'inv-123'}
                ]
            }]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 1
        assert result['errors'] == 0

        # Verify no cleanup operations were called
        self.mock_efs.delete_access_point.assert_not_called()

    def test_skip_investigation_within_grace_period(self):
        """Test that recent investigations are skipped"""
        # Create recent access point (within grace period)
        created_at = datetime.utcnow() - timedelta(hours=24)  # Only 24 hours old
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        # Mock access point list
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        # Mock no running tasks
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 1
        assert result['errors'] == 0

        # Verify no cleanup operations were called
        self.mock_efs.delete_access_point.assert_not_called()

    def test_reap_stale_investigation(self):
        """Test reaping a stale investigation (happy path)"""
        # Create old access point (past grace period)
        created_at = datetime.utcnow() - timedelta(hours=100)  # 100 hours old
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'RootDirectory': {
                'Path': '/test-cluster/inv-123'
            },
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        # Mock access point list
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        # Mock no running tasks
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Mock EFS mount verification
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True

        # Mock successful subprocess
        # shutil.rmtree returns None on success

        # Mock successful access point deletion
        self.mock_efs.delete_access_point.return_value = {}

        # Mock task definition list (no task definitions)
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 1
        assert result['skipped'] == 0
        assert result['errors'] == 0

        # Verify cleanup operations were called
        self.mock_shutil.rmtree.assert_called_once()  # Directory deletion
        self.mock_efs.delete_access_point.assert_called_once_with(
            AccessPointId='fsap-123456'
        )

    def test_reap_multiple_investigations(self):
        """Test reaping multiple stale investigations"""
        # Create multiple old access points
        created_at = datetime.utcnow() - timedelta(hours=100)
        access_points = [
            {
                'AccessPointId': f'fsap-{i}',
                'CreationTime': created_at,
                'RootDirectory': {
                    'Path': f'/test-cluster/inv-{i}'
                },
                'Tags': [
                    {'Key': 'ClusterID', 'Value': 'test-cluster'},
                    {'Key': 'InvestigationID', 'Value': f'inv-{i}'}
                ]
            }
            for i in range(3)
        ]

        # Mock access point list
        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': access_points
        }

        # Mock no running tasks for all investigations
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Mock EFS operations
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        # shutil.rmtree returns None on success
        self.mock_efs.delete_access_point.return_value = {}
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 3
        assert result['reaped'] == 3
        assert result['skipped'] == 0
        assert result['errors'] == 0

        # Verify cleanup was called for each investigation
        assert self.mock_efs.delete_access_point.call_count == 3

    def test_skip_access_point_missing_tags(self):
        """Test that access points without required tags are skipped"""
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': datetime.utcnow(),
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'}
                # Missing InvestigationID tag
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 1
        assert result['errors'] == 0

    def test_access_point_path_mismatch(self):
        """Test that access points with mismatched paths are counted as errors"""
        access_point = {
            'AccessPointId': 'fsap-path-mismatch',
            'CreationTime': datetime.utcnow() - timedelta(hours=100),
            'RootDirectory': {
                'Path': '/wrong-cluster/wrong-investigation'  # Doesn't match tags
            },
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        result = handler.lambda_handler({}, None)

        # Should count as error (not skip, not reap)
        assert result['errors'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 0

    def test_access_point_missing_root_directory(self):
        """Test that access points without RootDirectory are counted as errors"""
        access_point = {
            'AccessPointId': 'fsap-no-root',
            'CreationTime': datetime.utcnow() - timedelta(hours=100),
            # RootDirectory missing entirely
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        result = handler.lambda_handler({}, None)

        # Should count as error
        assert result['errors'] == 1
        assert result['reaped'] == 0

    def test_handle_directory_deletion_error_gracefully(self):
        """Test that directory deletion errors prevent access point deletion"""
        created_at = datetime.utcnow() - timedelta(hours=100)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Mock directory deletion failure
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        self.mock_shutil.rmtree.side_effect = OSError("Permission denied")

        # Mock task definitions
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == 1

        # Verify access point deletion was NOT called when directory deletion fails
        # This prevents orphaned directories (once AP is deleted, we lose the tags)
        self.mock_efs.delete_access_point.assert_not_called()

    def test_handle_access_point_deletion_error_gracefully(self):
        """Test that access point deletion errors don't prevent task def cleanup"""
        created_at = datetime.utcnow() - timedelta(hours=100)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Mock successful directory deletion
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        # shutil.rmtree returns None on success

        # Mock access point deletion failure
        from botocore.exceptions import ClientError
        self.mock_efs.delete_access_point.side_effect = ClientError(
            {'Error': {'Code': 'InternalServerError', 'Message': 'Server error'}},
            'DeleteAccessPoint'
        )

        # Mock task definition cleanup
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == 1

        # Verify task definition cleanup was still attempted
        self.mock_ecs.list_task_definitions.assert_called_once()

    def test_handle_task_definition_error_gracefully(self):
        """Test that task definition errors don't crash the reaper"""
        created_at = datetime.utcnow() - timedelta(hours=100)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Mock successful directory and access point deletion
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        # shutil.rmtree returns None on success
        self.mock_efs.delete_access_point.return_value = {}

        # Mock task definition list failure
        from botocore.exceptions import ClientError
        self.mock_ecs.list_task_definitions.side_effect = ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}},
            'ListTaskDefinitions'
        )

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 1
        assert result['reaped'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == 1

    def test_missing_ecs_cluster(self):
        """Test that missing ECS_CLUSTER raises ValueError"""
        with patch('handler.ECS_CLUSTER', None):
            with self.assertRaises(ValueError) as cm:
                handler.lambda_handler({}, None)
            assert 'ECS_CLUSTER' in str(cm.exception)

    def test_missing_efs_filesystem_id(self):
        """Test that missing EFS_FILESYSTEM_ID raises ValueError"""
        with patch('handler.EFS_FILESYSTEM_ID', None):
            with self.assertRaises(ValueError) as cm:
                handler.lambda_handler({}, None)
            assert 'EFS_FILESYSTEM_ID' in str(cm.exception)

    def test_pagination_with_many_access_points(self):
        """Test pagination when listing many access points"""
        # Create multiple access points across pages
        created_at = datetime.utcnow() - timedelta(hours=100)
        page1_aps = [
            {
                'AccessPointId': f'fsap-{i}',
                'CreationTime': created_at,
                'Tags': [
                    {'Key': 'ClusterID', 'Value': 'test-cluster'},
                    {'Key': 'InvestigationID', 'Value': f'inv-{i}'}
                ]
            }
            for i in range(50)
        ]
        page2_aps = [
            {
                'AccessPointId': f'fsap-{i}',
                'CreationTime': created_at,
                'Tags': [
                    {'Key': 'ClusterID', 'Value': 'test-cluster'},
                    {'Key': 'InvestigationID', 'Value': f'inv-{i}'}
                ]
            }
            for i in range(50, 100)
        ]

        # Mock paginated response
        self.mock_efs.describe_access_points.side_effect = [
            {'AccessPoints': page1_aps, 'NextToken': 'token123'},
            {'AccessPoints': page2_aps}
        ]

        self.mock_ecs.list_tasks.return_value = {'taskArns': []}
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        # shutil.rmtree returns None on success
        self.mock_efs.delete_access_point.return_value = {}
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}

        result = handler.lambda_handler({}, None)

        assert result['checked'] == 100
        assert result['reaped'] == 100
        assert result['skipped'] == 0
        assert result['errors'] == 0

        # Verify pagination worked
        assert self.mock_efs.describe_access_points.call_count == 2

    def test_staleness_calculation_edge_cases(self):
        """Test staleness calculation boundary conditions"""
        # Test exactly at grace period boundary (72 hours)
        created_at = datetime.utcnow() - timedelta(hours=72, minutes=0)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Add mocks for reaping operations
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}
        self.mock_efs.delete_access_point.return_value = {}
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        # shutil.rmtree returns None on success

        # At exactly 72 hours, should not be stale yet (needs to be > grace period)
        result = handler.lambda_handler({}, None)

        # Depending on clock precision, might be skipped or reaped
        # The important thing is it doesn't error
        assert 'error' not in result
        assert result['checked'] == 1

    def test_directory_deletion_with_large_directory(self):
        """Test directory deletion with simulated large directory"""
        # Simulate deletion taking significant time but completing
        # shutil.rmtree returns None on success
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True

        result = handler.delete_investigation_directory('test-cluster', 'inv-large', self.mock_context)

        assert result is True

    def test_directory_deletion_failure(self):
        """Test directory deletion failure handling"""
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        # shutil.rmtree raises OSError on failure
        self.mock_shutil.rmtree.side_effect = OSError("Permission denied")

        result = handler.delete_investigation_directory('test-cluster', 'inv-fail', self.mock_context)

        assert result is False

    def test_directory_deletion_nonexistent_directory(self):
        """Test that nonexistent directories are handled gracefully"""
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = False  # Directory doesn't exist

        result = handler.delete_investigation_directory('test-cluster', 'inv-missing', self.mock_context)

        # Should return True (directory already deleted)
        assert result is True
        # Should not call subprocess
        self.mock_shutil.rmtree.assert_not_called()

    def test_directory_deletion_efs_not_mounted(self):
        """Test error when EFS is not mounted"""
        self.mock_os_path.ismount.return_value = False  # EFS not mounted

        result = handler.delete_investigation_directory('test-cluster', 'inv-unmounted', self.mock_context)

        assert result is False
        self.mock_shutil.rmtree.assert_not_called()

    def test_access_point_already_deleted(self):
        """Test that already-deleted access points are handled gracefully"""
        from botocore.exceptions import ClientError

        self.mock_efs.delete_access_point.side_effect = ClientError(
            {'Error': {'Code': 'AccessPointNotFound', 'Message': 'Not found'}},
            'DeleteAccessPoint'
        )

        result = handler.delete_access_point('fsap-nonexistent')

        # Should return True (already deleted is success)
        assert result is True

    def test_task_definition_deregistration_with_multiple_revisions(self):
        """Test deregistering multiple task definition revisions"""
        # Simulate multiple revisions of same family
        task_def_arns = [
            'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-test-cluster-inv:1',
            'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-test-cluster-inv:2',
            'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-test-cluster-inv:3',
        ]

        self.mock_ecs.list_task_definitions.return_value = {
            'taskDefinitionArns': task_def_arns
        }

        with patch('handler.TASK_DEFINITION_FAMILY', 'rosa-boundary'):
            count = handler.delete_task_definitions('test-cluster', 'inv-123')

        assert count == 3
        assert self.mock_ecs.deregister_task_definition.call_count == 3

    def test_task_definition_deregistration_failure_continues(self):
        """Test that task def deregistration continues on individual failures"""
        task_def_arns = [
            'arn:aws:ecs:us-east-1:123:task-definition/cluster-test-inv:1',
            'arn:aws:ecs:us-east-1:123:task-definition/cluster-test-inv:2',
        ]

        self.mock_ecs.list_task_definitions.return_value = {
            'taskDefinitionArns': task_def_arns
        }

        # First deregister fails, second succeeds
        from botocore.exceptions import ClientError
        self.mock_ecs.deregister_task_definition.side_effect = [
            ClientError(
                {'Error': {'Code': 'InvalidParameterException', 'Message': 'Bad param'}},
                'DeregisterTaskDefinition'
            ),
            {}  # Success
        ]

        with patch('handler.TASK_DEFINITION_FAMILY', 'rosa-boundary'):
            count = handler.delete_task_definitions('test-cluster', 'inv-123')

        # Should still count the successful one
        assert count == 1
        assert self.mock_ecs.deregister_task_definition.call_count == 2

    def test_staleness_check_ecs_error_increments_errors(self):
        """Test that ECS API errors during staleness check increment error count"""
        from botocore.exceptions import ClientError

        created_at = datetime.utcnow() - timedelta(hours=100)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        # ECS list_tasks fails with throttling
        self.mock_ecs.list_tasks.side_effect = ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}},
            'ListTasks'
        )

        result = handler.lambda_handler({}, None)

        # Should increment errors, not skipped
        assert result['errors'] == 1
        assert result['skipped'] == 0
        assert result['reaped'] == 0

    def test_describe_tasks_failure_after_list_tasks(self):
        """Test that describe_tasks failure is handled correctly"""
        from botocore.exceptions import ClientError

        created_at = datetime.utcnow() - timedelta(hours=100)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        # list_tasks succeeds but describe_tasks fails
        self.mock_ecs.list_tasks.return_value = {
            'taskArns': ['arn:aws:ecs:us-east-1:123:task/cluster/abc123']
        }
        self.mock_ecs.describe_tasks.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'No permission'}},
            'DescribeTasks'
        )

        result = handler.lambda_handler({}, None)

        # Should increment errors
        assert result['errors'] == 1
        assert result['reaped'] == 0

    def test_list_access_points_failure_returns_aws_error(self):
        """Test that access point listing failure is handled correctly"""
        from botocore.exceptions import ClientError

        self.mock_efs.describe_access_points.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'No permission'}},
            'DescribeAccessPoints'
        )

        result = handler.lambda_handler({}, None)

        # Should return AWS API error dict (not raise)
        assert 'error' in result
        assert 'AWS API error' in result['error']
        assert result['checked'] == 0

    def test_timezone_aware_creation_time(self):
        """Test that timezone-aware CreationTime is handled correctly"""
        from datetime import timezone

        # Create timezone-aware datetime (as AWS returns)
        created_at = datetime.now(timezone.utc) - timedelta(hours=100)
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': created_at,  # Timezone-aware
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }
        self.mock_ecs.list_tasks.return_value = {'taskArns': []}

        # Mock successful directory deletion
        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True
        self.mock_shutil.rmtree.return_value = MagicMock(returncode=0)
        self.mock_efs.delete_access_point.return_value = {}
        self.mock_ecs.list_task_definitions.return_value = {'taskDefinitionArns': []}

        result = handler.lambda_handler({}, None)

        # Should successfully reap without timezone comparison errors
        assert result['reaped'] == 1
        assert result['errors'] == 0

    def test_staleness_with_no_creation_time_zero_grace_period(self):
        """Test investigations with no CreationTime are reaped if grace period is 0"""
        with patch('handler.GRACE_PERIOD_HOURS', 0):
            result = handler.is_investigation_stale(
                'cluster', 'inv', None, datetime.utcnow(), []
            )

            assert result['is_stale'] is True
            assert 'zero grace period' in result['reason']

    def test_staleness_with_no_creation_time_nonzero_grace_period(self):
        """Test investigations with no CreationTime are NOT reaped if grace period > 0"""
        result = handler.is_investigation_stale(
            'cluster', 'inv', None, datetime.utcnow(), []
        )

        assert result['is_stale'] is False
        assert 'creation time unavailable' in result['reason']

    def test_invalid_cluster_id_increments_errors(self):
        """Test that invalid cluster_id in tags increments error count"""
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': datetime.utcnow(),
            'Tags': [
                {'Key': 'ClusterID', 'Value': '../../../etc'},  # Path traversal attempt
                {'Key': 'InvestigationID', 'Value': 'inv-123'}
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        result = handler.lambda_handler({}, None)

        # Should increment errors due to validation failure
        assert result['errors'] == 1
        assert result['reaped'] == 0

    def test_invalid_investigation_id_increments_errors(self):
        """Test that invalid investigation_id in tags increments error count"""
        access_point = {
            'AccessPointId': 'fsap-123456',
            'CreationTime': datetime.utcnow(),
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'valid-cluster'},
                {'Key': 'InvestigationID', 'Value': '../../secrets'}  # Path traversal attempt
            ]
        }

        self.mock_efs.describe_access_points.return_value = {
            'AccessPoints': [access_point]
        }

        result = handler.lambda_handler({}, None)

        # Should increment errors due to validation failure
        assert result['errors'] == 1
        assert result['reaped'] == 0

    def test_task_pagination_with_many_running_tasks(self):
        """Test task listing pagination when > 100 tasks exist"""
        # Create two pages of tasks (AWS max is 100 per page)
        page1_tasks = [f'arn:aws:ecs:us-east-1:123:task/cluster/task-{i}' for i in range(100)]
        page2_tasks = [f'arn:aws:ecs:us-east-1:123:task/cluster/task-{i}' for i in range(100, 150)]

        # Mock paginated list_tasks responses
        self.mock_ecs.list_tasks.side_effect = [
            {'taskArns': page1_tasks, 'nextToken': 'token123'},
            {'taskArns': page2_tasks}  # No nextToken on last page
        ]

        # Mock describe_tasks to return tasks matching our investigation
        def describe_side_effect(cluster, tasks, include):
            return {
                'tasks': [
                    {
                        'taskArn': arn,
                        'tags': [
                            {'key': 'cluster_id', 'value': 'test-cluster'},
                            {'key': 'investigation_id', 'value': 'test-inv'}
                        ]
                    }
                    for arn in tasks
                ]
            }

        self.mock_ecs.describe_tasks.side_effect = describe_side_effect

        # Call list_tasks_by_investigation
        result = handler.list_tasks_by_investigation('test-cluster', 'test-inv')

        # Should find all 150 tasks across both pages
        assert len(result) == 150, f"Expected 150 tasks, got {len(result)}"
        assert self.mock_ecs.list_tasks.call_count == 2, "Should have made 2 paginated calls"
        assert self.mock_ecs.describe_tasks.call_count == 2, "Should describe both pages"

    def test_staleness_just_before_grace_period(self):
        """Test investigation just before grace period expires (should NOT reap)"""
        now = datetime.utcnow()
        # 71 hours 59 minutes old (just before 72h grace period)
        created_at = now - timedelta(hours=71, minutes=59)

        result = handler.is_investigation_stale('cluster', 'inv', created_at, now, [])

        assert result['is_stale'] is False, "Should not be stale yet"
        assert 'within grace period' in result['reason']

    def test_staleness_just_after_grace_period(self):
        """Test investigation just after grace period expires (SHOULD reap)"""
        now = datetime.utcnow()
        # 72 hours 1 minute old (just after 72h grace period)
        created_at = now - timedelta(hours=72, minutes=1)

        result = handler.is_investigation_stale('cluster', 'inv', created_at, now, [])

        assert result['is_stale'] is True, "Should be stale"
        assert 'no tasks' in result['reason']
        assert '72h old' in result['reason']

    def test_staleness_exactly_at_grace_period(self):
        """Test investigation exactly at grace period boundary (should NOT reap, requires >)"""
        now = datetime.utcnow()
        # Exactly 72 hours old
        created_at = now - timedelta(hours=72)

        result = handler.is_investigation_stale('cluster', 'inv', created_at, now, [])

        # The code uses `age > grace_period`, so exactly equal should NOT be stale
        assert result['is_stale'] is False, "Should not be stale at exact boundary"

    def test_task_filtering_by_tags(self):
        """Test that only tasks matching both cluster_id AND investigation_id are returned"""
        # Return mixed tasks: some match, some don't
        self.mock_ecs.list_tasks.return_value = {
            'taskArns': [
                'arn:aws:ecs:us-east-1:123:task/cluster/task-match',
                'arn:aws:ecs:us-east-1:123:task/cluster/task-wrong-cluster',
                'arn:aws:ecs:us-east-1:123:task/cluster/task-wrong-inv',
                'arn:aws:ecs:us-east-1:123:task/cluster/task-no-tags',
            ]
        }

        self.mock_ecs.describe_tasks.return_value = {
            'tasks': [
                {
                    'taskArn': 'arn:aws:ecs:us-east-1:123:task/cluster/task-match',
                    'tags': [
                        {'key': 'cluster_id', 'value': 'test-cluster'},
                        {'key': 'investigation_id', 'value': 'test-inv'}
                    ]
                },
                {
                    'taskArn': 'arn:aws:ecs:us-east-1:123:task/cluster/task-wrong-cluster',
                    'tags': [
                        {'key': 'cluster_id', 'value': 'other-cluster'},
                        {'key': 'investigation_id', 'value': 'test-inv'}
                    ]
                },
                {
                    'taskArn': 'arn:aws:ecs:us-east-1:123:task/cluster/task-wrong-inv',
                    'tags': [
                        {'key': 'cluster_id', 'value': 'test-cluster'},
                        {'key': 'investigation_id', 'value': 'other-inv'}
                    ]
                },
                {
                    'taskArn': 'arn:aws:ecs:us-east-1:123:task/cluster/task-no-tags',
                    'tags': []
                }
            ]
        }

        result = handler.list_tasks_by_investigation('test-cluster', 'test-inv')

        # Only the exact match should be returned
        assert len(result) == 1, f"Expected 1 matching task, got {len(result)}"
        assert result[0] == 'arn:aws:ecs:us-east-1:123:task/cluster/task-match'

    def test_validate_identifier_accepts_valid_values(self):
        """Test that validate_identifier accepts valid cluster/investigation IDs"""
        valid_ids = [
            'cluster-1',
            'inv_123',
            'test.cluster',
            'a',  # Single char
            'cluster-name-with-many-dashes',
            'cluster_with_underscores',
            'cluster.with.dots',
            'MixedCase123',
        ]

        for valid_id in valid_ids:
            # Should not raise
            handler.validate_identifier(valid_id, 'test')

    def test_validate_identifier_rejects_invalid_values(self):
        """Test that validate_identifier rejects invalid identifiers"""
        invalid_ids = [
            '',  # Empty
            '..',  # Dot-dot
            '.',  # Single dot
            '../etc',  # Path traversal
            'test/slash',  # Slash
            '/etc',  # Leading slash
            '-leading-dash',  # Leading dash not allowed
            '_leading-underscore',  # Leading underscore not allowed
        ]

        for invalid_id in invalid_ids:
            with self.assertRaises(ValueError):
                handler.validate_identifier(invalid_id, 'test')

    @patch('handler.subprocess.run')
    @patch('handler.os.path.exists')
    def test_s3_backup_success(self, mock_exists, mock_subprocess):
        """Test successful S3 backup before directory deletion"""
        mock_exists.return_value = True
        mock_subprocess.return_value = MagicMock(returncode=0)

        with patch('handler.S3_AUDIT_BUCKET', 'test-bucket'):
            result = handler.backup_investigation_to_s3('cluster-1', 'inv-1', '/mnt/efs/cluster-1/inv-1', self.mock_context)

        assert result is True
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]
        assert 'aws' in call_args
        assert 's3' in call_args
        assert 'sync' in call_args
        assert '/mnt/efs/cluster-1/inv-1' in call_args
        assert 's3://test-bucket/cluster-1/inv-1/reaper-final-backup/' in call_args
        assert '--exclude' in call_args
        assert '.config/ocm/*' in call_args
        assert '.kube/*' in call_args
        assert '--no-follow-symlinks' in call_args

    @patch('handler.subprocess.run')
    @patch('handler.os.path.exists')
    def test_s3_backup_failure(self, mock_exists, mock_subprocess):
        """Test failed S3 backup prevents directory deletion"""
        from subprocess import CalledProcessError
        mock_exists.return_value = True
        mock_subprocess.side_effect = CalledProcessError(1, 'aws', stderr='Access denied')

        with patch('handler.S3_AUDIT_BUCKET', 'test-bucket'):
            result = handler.backup_investigation_to_s3('cluster-1', 'inv-1', '/mnt/efs/cluster-1/inv-1', self.mock_context)

        assert result is False

    @patch('handler.os.path.exists')
    def test_s3_backup_missing_config(self, mock_exists):
        """Test S3 backup skipped when S3_AUDIT_BUCKET not configured"""
        mock_exists.return_value = True

        with patch('handler.S3_AUDIT_BUCKET', ''):
            result = handler.backup_investigation_to_s3('cluster-1', 'inv-1', '/mnt/efs/cluster-1/inv-1', self.mock_context)

        # Not configured is not a failure - returns True
        assert result is True

    @patch('handler.subprocess.run')
    @patch('handler.os.path.exists')
    def test_s3_backup_timeout(self, mock_exists, mock_subprocess):
        """Test S3 backup timeout prevents directory deletion"""
        from subprocess import TimeoutExpired
        mock_exists.return_value = True
        mock_subprocess.side_effect = TimeoutExpired('aws', 300)

        with patch('handler.S3_AUDIT_BUCKET', 'test-bucket'):
            result = handler.backup_investigation_to_s3('cluster-1', 'inv-1', '/mnt/efs/cluster-1/inv-1', self.mock_context)

        assert result is False

    @patch('handler.backup_investigation_to_s3')
    def test_directory_deletion_blocked_by_failed_backup(self, mock_backup):
        """Test that directory deletion is blocked when S3 backup fails"""
        mock_backup.return_value = False

        self.mock_os_path.ismount.return_value = True
        self.mock_os_path.exists.return_value = True

        result = handler.delete_investigation_directory('cluster-1', 'inv-1', self.mock_context)

        assert result is False
        self.mock_shutil.rmtree.assert_not_called()

    def test_task_definition_deregistration_missing_family(self):
        """Test that task definition deregistration skips when TASK_DEFINITION_FAMILY not configured"""
        with patch('handler.TASK_DEFINITION_FAMILY', ''):
            count = handler.delete_task_definitions('test-cluster', 'inv-123')

        assert count == 0
        self.mock_ecs.list_task_definitions.assert_not_called()


if __name__ == '__main__':
    unittest.main()
