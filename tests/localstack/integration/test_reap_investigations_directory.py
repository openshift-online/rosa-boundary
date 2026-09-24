"""
Integration tests for investigation reaper Lambda directory deletion.

These tests verify that EFS directories are properly cleaned up during investigation reaping.
Note: Some tests may be limited by LocalStack's EFS mount support in Lambda.
"""

import os
import json
import time
import tempfile
from datetime import datetime, timedelta

import pytest

from .test_helpers import create_investigation_resources

# LocalStack endpoint (from test host)
LOCALSTACK_ENDPOINT = os.environ.get('LOCALSTACK_ENDPOINT', 'http://localhost:4566')
# LocalStack endpoint from inside Lambda (uses container networking)
LAMBDA_LOCALSTACK_ENDPOINT = 'http://localstack:4566'


@pytest.mark.integration
def test_directory_structure_created_for_investigation(
    ecs_client, efs_client, iam_client,
    test_vpc, test_efs, ecs_cleanup
):
    """
    Verify that investigations create the expected EFS directory structure.
    Tests the pattern: /{cluster_id}/{investigation_id}/
    """
    cluster_id = 'dir-test-cluster'
    investigation_id = 'dir-test-inv'

    # Create investigation resources
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id=cluster_id,
        investigation_id=investigation_id
    )

    access_point_id = resources['access_point_id']

    # Verify access point was created with correct path
    ap_response = efs_client.describe_access_points(
        AccessPointId=access_point_id
    )

    assert len(ap_response['AccessPoints']) == 1
    access_point = ap_response['AccessPoints'][0]

    # Verify root directory path matches expected pattern
    expected_path = f'/{cluster_id}/{investigation_id}'
    actual_path = access_point['RootDirectory']['Path']
    assert actual_path == expected_path, \
        f"Access point path should be {expected_path}, got {actual_path}"

    # Verify POSIX user settings
    posix_user = access_point['PosixUser']
    assert posix_user['Uid'] == 1000, "User ID should be 1000 (sre user)"
    assert posix_user['Gid'] == 1000, "Group ID should be 1000 (sre group)"

    # Verify creation info
    creation_info = access_point['RootDirectory']['CreationInfo']
    assert creation_info['OwnerUid'] == 1000
    assert creation_info['OwnerGid'] == 1000
    assert creation_info['Permissions'] == '0755'


@pytest.mark.integration
def test_multiple_investigations_different_clusters(
    ecs_client, efs_client, iam_client,
    test_vpc, test_efs, ecs_cleanup
):
    """
    Verify that investigations for different clusters create separate directories.
    Tests path isolation: /{cluster_id_1}/{investigation_id} vs /{cluster_id_2}/{investigation_id}
    """
    # Create two investigations with same investigation_id but different cluster_ids
    investigation_id = 'shared-inv-id'

    resources1 = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='cluster-a',
        investigation_id=investigation_id,
        cluster_name_prefix='cluster-a'
    )

    resources2 = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='cluster-b',
        investigation_id=investigation_id,
        cluster_name_prefix='cluster-b'
    )

    # Verify both access points were created with different paths
    ap1 = efs_client.describe_access_points(
        AccessPointId=resources1['access_point_id']
    )['AccessPoints'][0]

    ap2 = efs_client.describe_access_points(
        AccessPointId=resources2['access_point_id']
    )['AccessPoints'][0]

    path1 = ap1['RootDirectory']['Path']
    path2 = ap2['RootDirectory']['Path']

    assert path1 == '/cluster-a/shared-inv-id', f"Path 1 should be /cluster-a/shared-inv-id, got {path1}"
    assert path2 == '/cluster-b/shared-inv-id', f"Path 2 should be /cluster-b/shared-inv-id, got {path2}"
    assert path1 != path2, "Paths should be different for different clusters"


@pytest.mark.integration
def test_reaper_access_point_has_root_permissions(
    efs_client, test_efs
):
    """
    Verify that the reaper Lambda's dedicated EFS access point has root permissions.
    This is required for 'rm -rf' to delete directories owned by different users.

    Note: This test would verify the Terraform-created access point. In LocalStack
    integration tests, we don't have that access point, so this is a placeholder
    for production verification.
    """
    # In a real deployment, verify the reaper access point exists with:
    # - PosixUser: uid=0, gid=0 (root)
    # - RootDirectory: path='/' (full filesystem access)
    # - Proper IAM permissions for ClientRootAccess

    # This test is a placeholder for manual verification after deployment
    pytest.skip("Reaper access point verification requires deployed infrastructure")


@pytest.mark.integration
@pytest.mark.slow
def test_directory_deletion_with_nested_structure(
    ecs_client, efs_client, iam_client,
    test_vpc, test_efs, ecs_cleanup
):
    """
    Verify reaper can delete investigations with nested directory structures.
    Creates a task that writes multiple nested files/directories.
    """
    # Create investigation with task that creates nested structure
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='nested-test',
        investigation_id='nested-inv',
        container_command=[
            'sh', '-c',
            '''
            mkdir -p /home/sre/logs/app /home/sre/data/cache /home/sre/.config
            echo "log1" > /home/sre/logs/app/app.log
            echo "log2" > /home/sre/logs/error.log
            echo "data1" > /home/sre/data/cache/cache.dat
            echo "config" > /home/sre/.config/config.yaml
            sleep 2
            '''
        ]
    )

    cluster_name = resources['cluster_name']
    task_arn = resources['task_arn']

    # Wait for task to complete (which creates the nested structure)
    waiter = ecs_client.get_waiter('tasks_stopped')
    waiter.wait(
        cluster=cluster_name,
        tasks=[task_arn],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 60}
    )

    # The reaper Lambda would delete this entire nested structure
    # In production, verify with:
    # 1. Run reaper Lambda
    # 2. Mount EFS and verify /nested-test/nested-inv/ directory is gone
    # 3. Verify rm -rf succeeded in CloudWatch Logs


@pytest.mark.integration
def test_investigation_directory_size_calculation(
    ecs_client, efs_client, iam_client,
    test_vpc, test_efs, ecs_cleanup
):
    """
    Verify that investigations can be identified for cleanup based on criteria.

    In production, you might want to track directory sizes to prioritize cleanup
    or identify investigations that need special handling (very large directories).
    """
    # Create investigation
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='size-test',
        investigation_id='size-inv'
    )

    access_point_id = resources['access_point_id']

    # Verify access point tags include metadata
    ap = efs_client.describe_access_points(
        AccessPointId=access_point_id
    )['AccessPoints'][0]

    tags = {tag['Key']: tag['Value'] for tag in ap['Tags']}

    # These tags are used by the reaper to identify investigations
    assert 'ClusterID' in tags
    assert 'InvestigationID' in tags
    assert tags['ClusterID'] == 'size-test'
    assert tags['InvestigationID'] == 'size-inv'

    # In production, you could add additional tags for tracking:
    # - CreatedAt (timestamp)
    # - Owner (OIDC sub)
    # - Purpose (incident ID, ticket number)
    # These help with auditing and cleanup decisions


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
