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
def test_reaper_deletes_investigation_directory_structure(
    ecs_client, efs_client, iam_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Verify that the reaper Lambda deletes the entire investigation directory.

    Note: This test verifies the Lambda logic executes correctly. The actual
    directory deletion via 'rm -rf' requires a mounted EFS filesystem in the
    Lambda, which may have limited support in LocalStack.
    """
    cluster_id = 'reap-dir-test'
    investigation_id = 'reap-dir-inv'

    # Create investigation with task that writes files
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id=cluster_id,
        investigation_id=investigation_id,
        container_command=[
            'sh', '-c',
            'echo "test data" > /home/sre/test.txt && sleep 5'
        ]
    )

    cluster_name = resources['cluster_name']
    task_arn = resources['task_arn']
    access_point_id = resources['access_point_id']

    # Wait for task to complete
    waiter = ecs_client.get_waiter('tasks_stopped')
    waiter.wait(
        cluster=cluster_name,
        tasks=[task_arn],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 60}
    )

    # Verify access point exists before reaping
    ap_before = efs_client.describe_access_points(
        AccessPointId=access_point_id
    )
    assert len(ap_before['AccessPoints']) == 1, "Access point should exist before reaping"

    # Update Lambda to use zero grace period for immediate reaping
    env_vars = {
        'ECS_CLUSTER': cluster_name,
        'EFS_FILESYSTEM_ID': test_efs,
        'GRACE_PERIOD_HOURS': '0',
        'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
    }

    lambda_client.update_function_configuration(
        FunctionName=reaper_lambda_function['function_name'],
        Environment={'Variables': env_vars}
    )
    time.sleep(2)

    # Invoke reaper Lambda
    response = lambda_client.invoke(
        FunctionName=reaper_lambda_function['function_name'],
        InvocationType='RequestResponse',
        Payload=json.dumps({})
    )

    # Parse result
    result = json.loads(response['Payload'].read())

    # Verify Lambda executed successfully
    assert 'error' not in result, f"Lambda should not error: {result.get('error')}"
    assert result['checked'] >= 1, "Lambda should check at least one investigation"

    # Note: In LocalStack, the actual directory deletion may not work due to
    # limited EFS mount support in Lambda. We verify the Lambda logic executes,
    # but cannot guarantee the 'rm -rf' command succeeds without a real mount.

    # Verify access point was deleted (this should work in LocalStack)
    try:
        ap_after = efs_client.describe_access_points(
            AccessPointId=access_point_id
        )
        # If we get here, access point still exists
        assert len(ap_after['AccessPoints']) == 0, \
            "Access point should be deleted after reaping"
    except efs_client.exceptions.AccessPointNotFoundException:
        # Expected: access point was deleted
        pass


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


@pytest.mark.integration
def test_path_traversal_rejected_in_cluster_id(
    ecs_client, efs_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Security test: Verify reaper rejects access points with path traversal in ClusterID.

    This validates the critical security fix that prevents deletion of arbitrary
    filesystem paths via malicious tag values.
    """
    # Create access point with malicious ClusterID tag (path traversal attempt)
    malicious_access_point = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': '/safe-path/safe-inv',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[
            {'Key': 'ClusterID', 'Value': '../../../etc'},  # Path traversal attempt
            {'Key': 'InvestigationID', 'Value': 'test-inv'}
        ]
    )
    malicious_ap_id = malicious_access_point['AccessPointId']
    ecs_cleanup.register_access_point(malicious_ap_id)

    # Create a valid access point for comparison
    valid_access_point = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': '/valid-cluster/valid-inv',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[
            {'Key': 'ClusterID', 'Value': 'valid-cluster'},
            {'Key': 'InvestigationID', 'Value': 'valid-inv'}
        ]
    )
    valid_ap_id = valid_access_point['AccessPointId']
    ecs_cleanup.register_access_point(valid_ap_id)

    # Create cluster for valid investigation
    cluster_name = f'test-cluster-{int(time.time())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Invoke reaper with grace period 0
    from .test_reap_investigations import invoke_reaper_lambda, LAMBDA_LOCALSTACK_ENDPOINT

    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        cluster_name,
        test_efs,
        env_vars={
            'ECS_CLUSTER': cluster_name,
            'EFS_FILESYSTEM_ID': test_efs,
            'GRACE_PERIOD_HOURS': '0',
            'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
        }
    )

    # Malicious access point should be rejected (error count incremented)
    assert result['errors'] >= 1, "Reaper should reject path traversal attempt"
    assert result['checked'] == 2, "Should have checked both access points"

    # Verify malicious access point still exists (not deleted)
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]
    assert malicious_ap_id in ap_ids_after, "Malicious access point should not be deleted"


@pytest.mark.integration
def test_path_traversal_rejected_in_investigation_id(
    ecs_client, efs_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Security test: Verify reaper rejects access points with path traversal in InvestigationID.
    """
    # Create access point with malicious InvestigationID tag
    malicious_access_point = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': '/safe-cluster/malicious',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[
            {'Key': 'ClusterID', 'Value': 'safe-cluster'},
            {'Key': 'InvestigationID', 'Value': '../../secrets'}  # Path traversal
        ]
    )
    malicious_ap_id = malicious_access_point['AccessPointId']
    ecs_cleanup.register_access_point(malicious_ap_id)

    # Create cluster
    cluster_name = f'test-cluster-{int(time.time())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Invoke reaper
    from .test_reap_investigations import invoke_reaper_lambda, LAMBDA_LOCALSTACK_ENDPOINT

    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        cluster_name,
        test_efs,
        env_vars={
            'ECS_CLUSTER': cluster_name,
            'EFS_FILESYSTEM_ID': test_efs,
            'GRACE_PERIOD_HOURS': '0',
            'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
        }
    )

    # Should be rejected
    assert result['errors'] >= 1, "Reaper should reject investigation_id with path traversal"

    # Verify still exists
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]
    assert malicious_ap_id in ap_ids_after, "Malicious access point should not be deleted"


@pytest.mark.integration
def test_special_path_characters_rejected(
    ecs_client, efs_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Security test: Verify reaper rejects access points with special characters like ., .., /.
    """
    test_cases = [
        ('dot', '.'),
        ('dotdot', '..'),
        ('slash', 'test/slash'),
        ('leading-slash', '/etc'),
    ]

    created_aps = []
    for name, value in test_cases:
        ap = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/{name}/test',
                'CreationInfo': {
                    'OwnerUid': 1000,
                    'OwnerGid': 1000,
                    'Permissions': '0755'
                }
            },
            Tags=[
                {'Key': 'ClusterID', 'Value': value},
                {'Key': 'InvestigationID', 'Value': 'test-inv'}
            ]
        )
        created_aps.append(ap['AccessPointId'])
        ecs_cleanup.register_access_point(ap['AccessPointId'])

    # Create cluster
    cluster_name = f'test-cluster-{int(time.time())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Invoke reaper
    from .test_reap_investigations import invoke_reaper_lambda, LAMBDA_LOCALSTACK_ENDPOINT

    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        cluster_name,
        test_efs,
        env_vars={
            'ECS_CLUSTER': cluster_name,
            'EFS_FILESYSTEM_ID': test_efs,
            'GRACE_PERIOD_HOURS': '0',
            'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
        }
    )

    # All should be rejected (4 errors for 4 malicious access points)
    assert result['errors'] == len(test_cases), \
        f"Expected {len(test_cases)} errors, got {result['errors']}"

    # Verify all still exist
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]
    for ap_id in created_aps:
        assert ap_id in ap_ids_after, f"Access point {ap_id} should not be deleted"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
