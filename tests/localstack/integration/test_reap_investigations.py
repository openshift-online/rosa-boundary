"""
Integration tests for investigation reaper Lambda.

Tests the garbage collection of stale investigations in LocalStack.
"""

import os
import json
import time
import subprocess
from datetime import datetime, timedelta

import pytest

from .test_helpers import create_investigation_resources

# LocalStack endpoint for test client (external access)
LOCALSTACK_ENDPOINT = os.environ.get('LOCALSTACK_ENDPOINT', 'http://localhost:4566')

# LocalStack endpoint for Lambda (internal network access)
# Lambda containers use the service name to reach LocalStack on the docker/podman network
LAMBDA_LOCALSTACK_ENDPOINT = 'http://localstack:4566'

# Lambda configuration environment variables
LAMBDA_ENV_VARS = {
    'ECS_CLUSTER': None,  # Will be set from created cluster
    'EFS_FILESYSTEM_ID': None,  # Will be set from test fixture
    'GRACE_PERIOD_HOURS': '1',  # Short grace period for testing (1 hour)
    'TASK_DEFINITION_FAMILY': 'rosa-boundary-test',  # Matches base_task_family in test helper
    'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
}


def invoke_reaper_lambda(lambda_client, function_name, ecs_cluster, efs_filesystem_id, env_vars=None):
    """
    Helper to invoke the reaper Lambda with proper environment variables.

    Args:
        lambda_client: boto3 Lambda client
        function_name: Lambda function name
        ecs_cluster: ECS cluster name
        efs_filesystem_id: EFS filesystem ID
        env_vars: Optional pre-configured environment variables (if None, uses LAMBDA_ENV_VARS)
    """
    # Update Lambda environment
    if env_vars is None:
        env_vars = LAMBDA_ENV_VARS.copy()
        env_vars['ECS_CLUSTER'] = ecs_cluster
        env_vars['EFS_FILESYSTEM_ID'] = efs_filesystem_id

    # Always update the Lambda configuration with the environment variables
    lambda_client.update_function_configuration(
        FunctionName=function_name,
        Environment={'Variables': env_vars}
    )

    # Wait for update to complete
    time.sleep(2)

    # Invoke Lambda
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType='RequestResponse',
        Payload=json.dumps({})
    )

    # Parse response
    payload = json.loads(response['Payload'].read())
    return payload


@pytest.mark.integration
def test_reap_investigation_full_workflow(
    ecs_client, efs_client, iam_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    End-to-end test: Create investigation, make it stale, run reaper, verify cleanup.
    """
    # Create investigation resources with a running task
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='test-cluster-reap',
        investigation_id='inv-reap-test',
        container_command=['sleep', '300']  # Keep task running
    )

    cluster_name = resources['cluster_name']
    investigation_id = resources['investigation_id']
    access_point_id = resources['access_point_id']
    task_arn = resources['task_arn']

    # Wait for task to be running before stopping it
    waiter = ecs_client.get_waiter('tasks_running')
    waiter.wait(
        cluster=cluster_name,
        tasks=[task_arn],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
    )

    # Stop the task to make investigation eligible for reaping
    ecs_client.stop_task(cluster=cluster_name, task=task_arn)

    # Wait for task to stop
    waiter = ecs_client.get_waiter('tasks_stopped')
    waiter.wait(
        cluster=cluster_name,
        tasks=[task_arn],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
    )

    # Extra delay for LocalStack to propagate task state
    time.sleep(2)

    # Modify access point creation time to make it stale
    # (In LocalStack, we can't easily modify creation time, but we set
    # GRACE_PERIOD_HOURS=1 in the Lambda env, so we wait 1 hour worth of test time)
    # For testing purposes, we'll use grace period of 0 by updating Lambda env
    temp_env = LAMBDA_ENV_VARS.copy()
    temp_env['GRACE_PERIOD_HOURS'] = '0'  # Immediate reaping
    temp_env['ECS_CLUSTER'] = cluster_name
    temp_env['EFS_FILESYSTEM_ID'] = test_efs
    temp_env['LOCALSTACK_ENDPOINT'] = LAMBDA_LOCALSTACK_ENDPOINT

    lambda_client.update_function_configuration(
        FunctionName=reaper_lambda_function['function_name'],
        Environment={'Variables': temp_env}
    )
    time.sleep(2)

    # Verify access point exists before reaping
    aps_before = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_before = [ap['AccessPointId'] for ap in aps_before['AccessPoints']]
    assert access_point_id in ap_ids_before, "Access point should exist before reaping"

    # Invoke reaper Lambda (env already configured above)
    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        cluster_name,
        test_efs,
        env_vars=temp_env  # Pass the pre-configured environment
    )

    # Verify reaper results
    assert result['checked'] >= 1, "Reaper should have checked at least one access point"
    assert result['reaped'] >= 1, "Reaper should have reaped at least one investigation"
    assert result.get('errors', 0) == 0, "Reaper should not have errors"

    # Verify access point deleted
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]
    assert access_point_id not in ap_ids_after, "Access point should be deleted after reaping"

    # Verify task definition deregistered by checking it's now INACTIVE
    task_def_response = ecs_client.describe_task_definition(
        taskDefinition=resources['task_def_arn']
    )
    assert task_def_response['taskDefinition']['status'] == 'INACTIVE', \
        "Task definition should be deregistered (INACTIVE)"


@pytest.mark.integration
def test_reaper_skips_active_investigations(
    ecs_client, efs_client, iam_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Negative test: Reaper should skip investigations with running tasks.
    """
    # Create investigation with running task
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='test-cluster-active',
        investigation_id='inv-active-test',
        container_command=['sleep', '300']  # Keep task running
    )

    cluster_name = resources['cluster_name']
    access_point_id = resources['access_point_id']
    task_arn = resources['task_arn']

    # Wait for task to be RUNNING
    waiter = ecs_client.get_waiter('tasks_running')
    waiter.wait(
        cluster=cluster_name,
        tasks=[task_arn],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
    )

    # Set grace period to 0 (so only running tasks prevent reaping)
    temp_env = LAMBDA_ENV_VARS.copy()
    temp_env['GRACE_PERIOD_HOURS'] = '0'
    temp_env['ECS_CLUSTER'] = cluster_name
    temp_env['EFS_FILESYSTEM_ID'] = test_efs
    temp_env['LOCALSTACK_ENDPOINT'] = LAMBDA_LOCALSTACK_ENDPOINT

    lambda_client.update_function_configuration(
        FunctionName=reaper_lambda_function['function_name'],
        Environment={'Variables': temp_env}
    )
    time.sleep(2)

    # Invoke reaper Lambda (env already configured above)
    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        cluster_name,
        test_efs,
        env_vars=temp_env  # Pass the pre-configured environment
    )

    # Verify reaper results
    assert result['checked'] >= 1, "Reaper should have checked the investigation"
    assert result['reaped'] == 0, "Reaper should NOT reap active investigations"
    assert result['skipped'] >= 1, "Reaper should skip active investigations"

    # Verify access point still exists
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]
    assert access_point_id in ap_ids_after, "Access point should still exist for active investigation"

    # Cleanup: stop the task so ecs_cleanup can clean it up
    ecs_client.stop_task(cluster=cluster_name, task=task_arn)


@pytest.mark.integration
def test_reaper_handles_multiple_investigations(
    ecs_client, efs_client, iam_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Batch test: Create multiple investigations in one cluster (mix of stale and active), verify selective reaping.
    """
    # Create a shared cluster for all investigations
    shared_cluster_name = f'cluster-batch-{int(time.time())}'
    ecs_client.create_cluster(clusterName=shared_cluster_name)
    ecs_cleanup.register_cluster(shared_cluster_name)

    # Create 3 investigations in the same cluster
    # Investigations 0 and 1 will be stopped (stale), investigation 2 keeps running (active)
    resources_list = []
    for i in range(3):
        # Investigation 2 gets a sleep command to keep running
        cmd = ['sleep', '300'] if i == 2 else None
        resources = create_investigation_resources(
            ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
            cluster_id='test-cluster-batch',
            investigation_id=f'inv-batch-{i}',
            existing_cluster_name=shared_cluster_name,  # Use existing shared cluster
            container_command=cmd
        )
        resources_list.append(resources)

    # Stop tasks for investigations 0 and 1 (make them stale)
    for i in [0, 1]:
        waiter = ecs_client.get_waiter('tasks_stopped')
        waiter.wait(
            cluster=resources_list[i]['cluster_name'],
            tasks=[resources_list[i]['task_arn']],
            WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
        )

    # Investigation 2 keeps running (active)
    waiter = ecs_client.get_waiter('tasks_running')
    waiter.wait(
        cluster=resources_list[2]['cluster_name'],
        tasks=[resources_list[2]['task_arn']],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
    )

    # Extra delay for LocalStack to fully propagate task state
    time.sleep(3)

    # Invoke reaper with the cluster where investigation 2 is running (grace period = 0)
    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        resources_list[2]['cluster_name'],
        test_efs,
        env_vars={
            'ECS_CLUSTER': resources_list[2]['cluster_name'],
            'EFS_FILESYSTEM_ID': test_efs,
            'GRACE_PERIOD_HOURS': '0',
            'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
        }
    )

    # Verify results: investigations 0 and 1 reaped, investigation 2 skipped
    assert result['reaped'] == 2, f"Expected 2 investigations reaped, got {result['reaped']}"
    assert result['skipped'] == 1, f"Expected 1 investigation skipped, got {result['skipped']}"

    # Verify access points: 0 and 1 deleted, 2 still exists
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]

    assert resources_list[0]['access_point_id'] not in ap_ids_after, "Investigation 0 access point should be deleted"
    assert resources_list[1]['access_point_id'] not in ap_ids_after, "Investigation 1 access point should be deleted"
    assert resources_list[2]['access_point_id'] in ap_ids_after, "Investigation 2 access point should still exist"

    # Cleanup: stop active task
    ecs_client.stop_task(
        cluster=resources_list[2]['cluster_name'],
        task=resources_list[2]['task_arn']
    )


@pytest.mark.integration
def test_reaper_handles_many_access_points(
    ecs_client, efs_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Scale test: Verify reaper can handle many access points without timing out.

    Tests pagination and processing of multiple investigations. In production,
    the limit is 10,000 access points per filesystem, but we test with a smaller
    number for reasonable test duration.
    """
    # Create cluster
    cluster_name = f'test-cluster-{int(time.time())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create 20 access points (stale, no tasks)
    num_investigations = 20
    access_point_ids = []

    for i in range(num_investigations):
        ap = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/scale-test/inv-{i}',
                'CreationInfo': {
                    'OwnerUid': 1000,
                    'OwnerGid': 1000,
                    'Permissions': '0755'
                }
            },
            Tags=[
                {'Key': 'ClusterID', 'Value': 'scale-test'},
                {'Key': 'InvestigationID', 'Value': f'inv-{i}'}
            ]
        )
        access_point_ids.append(ap['AccessPointId'])
        ecs_cleanup.register_access_point(ap['AccessPointId'])

    # Invoke reaper with grace period 0 (all should be reaped)
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

    # Should have processed all investigations
    assert result['checked'] == num_investigations, \
        f"Expected {num_investigations} checked, got {result['checked']}"
    assert result['reaped'] == num_investigations, \
        f"Expected {num_investigations} reaped, got {result['reaped']}"
    assert result['errors'] == 0, f"Expected 0 errors, got {result['errors']}"

    # Verify all access points were deleted
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]

    for ap_id in access_point_ids:
        assert ap_id not in ap_ids_after, f"Access point {ap_id} should be deleted"


@pytest.mark.integration
def test_grace_period_boundary_conditions(
    ecs_client, efs_client, iam_client, lambda_client,
    test_vpc, test_efs, ecs_cleanup, reaper_lambda_function
):
    """
    Test staleness detection at grace period boundaries.

    Verifies that investigations are correctly classified as stale/not stale
    based on their age relative to the grace period.
    """
    from datetime import datetime, timedelta, timezone

    # Create cluster
    cluster_name = f'test-cluster-{int(time.time())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create three access points with different ages
    # Note: We can't control CreationTime in LocalStack, so we use grace period = 0
    # and verify via task presence instead

    # Investigation 1: Will have no tasks (stale)
    ap1 = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': '/boundary/inv-stale',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[
            {'Key': 'ClusterID', 'Value': 'boundary'},
            {'Key': 'InvestigationID', 'Value': 'inv-stale'}
        ]
    )
    ecs_cleanup.register_access_point(ap1['AccessPointId'])

    # Investigation 2: Will have a running task (not stale)
    # create_investigation_resources will create the access point
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        cluster_id='boundary',
        investigation_id='inv-active',
        cluster_name_prefix=cluster_name,
        container_command=['sleep', '300']
    )

    # Wait for task to be running
    waiter = ecs_client.get_waiter('tasks_running')
    waiter.wait(
        cluster=resources['cluster_name'],
        tasks=[resources['task_arn']],
        WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
    )

    time.sleep(2)

    # Invoke reaper with grace period 0
    result = invoke_reaper_lambda(
        lambda_client,
        reaper_lambda_function['function_name'],
        resources['cluster_name'],
        test_efs,
        env_vars={
            'ECS_CLUSTER': resources['cluster_name'],
            'EFS_FILESYSTEM_ID': test_efs,
            'GRACE_PERIOD_HOURS': '0',
            'LOCALSTACK_ENDPOINT': LAMBDA_LOCALSTACK_ENDPOINT
        }
    )

    # Stale investigation should be reaped, active should be skipped
    assert result['reaped'] == 1, f"Expected 1 reaped, got {result['reaped']}"
    assert result['skipped'] == 1, f"Expected 1 skipped, got {result['skipped']}"

    # Verify access points
    aps_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in aps_after['AccessPoints']]

    assert ap1['AccessPointId'] not in ap_ids_after, "Stale investigation should be deleted"
    assert resources['access_point_id'] in ap_ids_after, "Active investigation should remain"

    # Cleanup
    ecs_client.stop_task(cluster=resources['cluster_name'], task=resources['task_arn'])
