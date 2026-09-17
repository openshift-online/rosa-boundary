"""Regression coverage for close-investigation task-definition cleanup."""

import re
from datetime import datetime
from pathlib import Path

import pytest


def _load_sre_policy_source():
    """Load the Terraform source for the shared SRE permissions policy."""
    test_dir = Path(__file__).resolve().parent
    repo_root = test_dir.parents[2]
    oidc_path = repo_root / 'deploy' / 'regional' / 'oidc.tf'
    return oidc_path.read_text(encoding='utf-8')


@pytest.mark.integration
def test_sre_policy_allows_task_definition_cleanup():
    """Ensure the shared SRE role can list and deregister task definitions."""
    policy_source = _load_sre_policy_source()
    statement_start = policy_source.index('Sid    = "DescribeListAndCleanupECS"')
    statement_end = policy_source.index(
        'Sid      = "EFSReadAccessPoints"', statement_start
    )
    statement = policy_source[statement_start:statement_end]

    assert 'Effect = "Allow"' in statement
    assert 'Resource = "*"' in statement
    assert '"ecs:ListTaskDefinitions"' in statement
    assert '"ecs:DeregisterTaskDefinition"' in statement
    assert 'Sid    = "DeregisterTaskDefinition"' not in policy_source

    # The SRE role must not gain direct access-point deletion; that remains a
    # separate brokered operation documented by issue #242.
    assert 'elasticfilesystem:DeleteAccessPoint' not in policy_source


@pytest.mark.integration
def test_close_cleanup_lists_and_deregisters_task_definitions(ecs_client, ecs_cleanup):
    """Exercise the ECS list/deregister sequence used by close-investigation."""
    timestamp = int(datetime.now().timestamp())
    family = f'rosa-boundary-dev-cluster-{timestamp}-investigation'
    task_definition_arns = []

    for _ in range(2):
        response = ecs_client.register_task_definition(
            family=family,
            networkMode='awsvpc',
            requiresCompatibilities=['FARGATE'],
            cpu='256',
            memory='512',
            containerDefinitions=[{
                'name': 'test-container',
                'image': 'public.ecr.aws/docker/library/alpine:latest',
            }]
        )
        task_definition_arn = response['taskDefinition']['taskDefinitionArn']
        task_definition_arns.append(task_definition_arn)
        ecs_cleanup.register_task_definition(task_definition_arn)

    list_response = ecs_client.list_task_definitions(
        familyPrefix=family,
        status='ACTIVE'
    )
    listed_arns = list_response.get('taskDefinitionArns', [])

    assert set(task_definition_arns).issubset(listed_arns)

    for task_definition_arn in listed_arns:
        ecs_client.deregister_task_definition(taskDefinition=task_definition_arn)

    for task_definition_arn in task_definition_arns:
        describe_response = ecs_client.describe_task_definition(
            taskDefinition=task_definition_arn
        )
        assert describe_response['taskDefinition']['status'] == 'INACTIVE'


@pytest.mark.integration
def test_close_cleanup_family_prefix_excludes_other_investigations(ecs_client, ecs_cleanup):
    """Ensure the familyPrefix limits cleanup to the requested investigation."""
    timestamp = int(datetime.now().timestamp())
    target_family = f'rosa-boundary-dev-cluster-{timestamp}-target'
    other_family = f'rosa-boundary-dev-cluster-{timestamp}-other'
    families = [target_family, other_family]

    for family in families:
        response = ecs_client.register_task_definition(
            family=family,
            networkMode='awsvpc',
            requiresCompatibilities=['FARGATE'],
            cpu='256',
            memory='512',
            containerDefinitions=[{
                'name': 'test-container',
                'image': 'public.ecr.aws/docker/library/alpine:latest',
            }]
        )
        ecs_cleanup.register_task_definition(
            response['taskDefinition']['taskDefinitionArn']
        )

    list_response = ecs_client.list_task_definitions(
        familyPrefix=target_family,
        status='ACTIVE'
    )
    listed_families = {
        re.search(r'/([^/]+):\d+$', arn).group(1)
        for arn in list_response.get('taskDefinitionArns', [])
    }

    assert target_family in listed_families
    assert other_family not in listed_families

@pytest.mark.integration
def test_close_investigation_finds_cluster_dynamically(ecs_client, efs_client, test_efs, ecs_cleanup):
    """
    Verify that invoking the actual close-investigation CLI command works
    and correctly derives the cluster ID from the EFS access point.
    """
    import subprocess
    import os
    import platform
    import shutil
    from pathlib import Path

    go_path = shutil.which("go")
    if go_path is None:
        pytest.skip("Go compiler not found in PATH")

    investigation_id = f"test-inv-{int(datetime.now().timestamp())}"
    cluster_id = f"test-cluster-{int(datetime.now().timestamp())}"
    cluster_name = "test-cluster-name"

    # Create the ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create the access point to simulate a live investigation
    response = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': f'/{cluster_id}/{investigation_id}',
            'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'}
        },
        Tags=[
            {'Key': 'InvestigationID', 'Value': investigation_id},
            {'Key': 'ClusterID', 'Value': cluster_id}
        ]
    )
    ap_id = response['AccessPointId']
    ecs_cleanup.register_access_point(ap_id)

    # Set up environment variables to point the CLI to localstack
    env = os.environ.copy()
    env["ROSA_BOUNDARY_EFS_FILESYSTEM_ID"] = test_efs
    env["ROSA_BOUNDARY_ECS_CLUSTER_NAME"] = cluster_name

    # We need to compile the Go CLI first to make sure it's up to date
    repo_root = Path(__file__).resolve().parents[3]
    bin_path = repo_root / "bin" / "rosa-boundary"
    subprocess.run([go_path, "build", "-o", str(bin_path), "./cmd/rosa-boundary"], cwd=repo_root, check=True)

    # Setup AWS endpoints to point to LocalStack
    endpoint_url = "http://localhost:4566"
    if "LOCALSTACK_HOSTNAME" in env:
        endpoint_url = f"http://{env['LOCALSTACK_HOSTNAME']}:4566"

    env["AWS_ENDPOINT_URL"] = endpoint_url

    # We need dummy credentials for the CLI
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "test"
    env["AWS_DEFAULT_REGION"] = "us-east-1"

    # Run the close-investigation command
    cmd = [
        str(bin_path),
        "close-investigation",
        "--investigation-id", investigation_id,
        "--yes"
    ]

    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, f"Command failed: {result.stderr}\nStdout: {result.stdout}"

    # Verify the derived ClusterID is shown in the output
    assert cluster_id in result.stderr

    # Verify the access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_id not in remaining_ids


@pytest.mark.integration
def test_close_investigation_detects_ambiguous_investigation_id(ecs_client, efs_client, test_efs, ecs_cleanup):
    """
    Verify that close-investigation errors when the same investigation ID exists
    across multiple clusters and --cluster-id is not provided.
    """
    import subprocess
    import os
    import shutil
    from pathlib import Path

    go_path = shutil.which("go")
    if go_path is None:
        pytest.skip("Go compiler not found in PATH")

    investigation_id = f"ambiguous-inv-{int(datetime.now().timestamp())}"
    cluster_id_1 = f"cluster-1-{int(datetime.now().timestamp())}"
    cluster_id_2 = f"cluster-2-{int(datetime.now().timestamp())}"
    cluster_name = "test-cluster-name"

    # Create the ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create two access points with the same investigation ID but different cluster IDs
    ap_ids = []
    for cluster_id in [cluster_id_1, cluster_id_2]:
        response = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/{cluster_id}/{investigation_id}',
                'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'}
            },
            Tags=[
                {'Key': 'InvestigationID', 'Value': investigation_id},
                {'Key': 'ClusterID', 'Value': cluster_id}
            ]
        )
        ap_id = response['AccessPointId']
        ap_ids.append(ap_id)
        ecs_cleanup.register_access_point(ap_id)

    # Set up environment
    env = os.environ.copy()
    env["ROSA_BOUNDARY_EFS_FILESYSTEM_ID"] = test_efs
    env["ROSA_BOUNDARY_ECS_CLUSTER_NAME"] = cluster_name
    env["AWS_ENDPOINT_URL"] = "http://localhost:4566"
    if "LOCALSTACK_HOSTNAME" in env:
        env["AWS_ENDPOINT_URL"] = f"http://{env['LOCALSTACK_HOSTNAME']}:4566"
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "test"
    env["AWS_DEFAULT_REGION"] = "us-east-1"

    repo_root = Path(__file__).resolve().parents[3]
    bin_path = repo_root / "bin" / "rosa-boundary"
    subprocess.run([go_path, "build", "-o", str(bin_path), "./cmd/rosa-boundary"], cwd=repo_root, check=True)

    # Attempt to close without --cluster-id should fail with ambiguity error
    cmd_without_cluster = [
        str(bin_path),
        "close-investigation",
        "--investigation-id", investigation_id,
        "--yes"
    ]

    result = subprocess.run(cmd_without_cluster, env=env, capture_output=True, text=True, timeout=10)

    assert result.returncode != 0, "Command should fail when investigation ID is ambiguous"
    assert "ambiguous" in result.stderr.lower(), f"Error should mention ambiguity: {result.stderr}"
    assert cluster_id_1 in result.stderr and cluster_id_2 in result.stderr, "Error should list conflicting cluster IDs"

    # Now try with --cluster-id, which should succeed
    cmd_with_cluster = [
        str(bin_path),
        "close-investigation",
        "--cluster-id", cluster_id_1,
        "--investigation-id", investigation_id,
        "--yes"
    ]

    result = subprocess.run(cmd_with_cluster, env=env, capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, f"Command with --cluster-id should succeed: {result.stderr}\nStdout: {result.stdout}"

    # Verify only the first access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_ids[0] not in remaining_ids, "First access point should be deleted"
    assert ap_ids[1] in remaining_ids, "Second access point should still exist"


@pytest.mark.integration
def test_close_investigation_only_stops_tasks_from_same_cluster(ecs_client, test_efs, test_vpc, efs_client, ecs_cleanup):
    """
    Verify that close-investigation with --force only stops tasks matching both
    the investigation ID and cluster ID, not tasks from other clusters with the
    same investigation ID.
    """
    import subprocess
    import os
    import shutil
    from pathlib import Path
    import time

    go_path = shutil.which("go")
    if go_path is None:
        pytest.skip("Go compiler not found in PATH")

    timestamp = int(datetime.now().timestamp())
    investigation_id = f"shared-inv-{timestamp}"
    cluster_id_1 = f"cluster-a-{timestamp}"
    cluster_id_2 = f"cluster-b-{timestamp}"
    cluster_name = "test-cluster"

    # Create the ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create access points for both clusters with the same investigation ID
    ap_ids = []
    for cluster_id in [cluster_id_1, cluster_id_2]:
        response = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/{cluster_id}/{investigation_id}',
                'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'}
            },
            Tags=[
                {'Key': 'InvestigationID', 'Value': investigation_id},
                {'Key': 'ClusterID', 'Value': cluster_id}
            ]
        )
        ap_id = response['AccessPointId']
        ap_ids.append(ap_id)
        ecs_cleanup.register_access_point(ap_id)

    # Create task definition
    family = f'{cluster_name}-task-def-{timestamp}'
    td_response = ecs_client.register_task_definition(
        family=family,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        containerDefinitions=[{
            'name': 'rosa-boundary',
            'image': 'public.ecr.aws/docker/library/alpine:latest',
            'command': ['sleep', '300']
        }]
    )
    task_def_arn = td_response['taskDefinition']['taskDefinitionArn']
    ecs_cleanup.register_task_definition(task_def_arn)

    # Run tasks for both clusters with the SAME investigation ID
    task_arns = []
    for cluster_id in [cluster_id_1, cluster_id_2]:
        run_response = ecs_client.run_task(
            cluster=cluster_name,
            taskDefinition=task_def_arn,
            launchType='FARGATE',
            networkConfiguration={
                'awsvpcConfiguration': {
                    'subnets': test_vpc['subnet_ids'],
                    'securityGroups': [test_vpc['security_group_id']],
                    'assignPublicIp': 'ENABLED'
                }
            },
            tags=[
                {'key': 'cluster_id', 'value': cluster_id},
                {'key': 'investigation_id', 'value': investigation_id},
            ]
        )
        if run_response.get('failures'):
            pytest.skip(f"LocalStack task launch failed: {run_response['failures']}")

        task_arn = run_response['tasks'][0]['taskArn']
        task_arns.append(task_arn)
        ecs_cleanup.register_task(cluster_name, task_arn)

    # Poll until both tasks reach RUNNING state
    for _ in range(24):  # up to 120s
        desc_response = ecs_client.describe_tasks(cluster=cluster_name, tasks=task_arns, include=['TAGS'])
        if len(desc_response['tasks']) == 2:
            if all(task.get('lastStatus') == 'RUNNING' for task in desc_response['tasks']):
                break
        time.sleep(5)
    else:
        statuses = [task.get('lastStatus') for task in desc_response.get('tasks', [])]
        pytest.fail(f"Tasks never reached RUNNING; statuses={statuses}")

    # Verify both tasks are running with correct tags
    task_by_arn = {task['taskArn']: task for task in desc_response['tasks']}
    assert len(task_by_arn) == 2, f"Expected 2 tasks, got {len(task_by_arn)}"
    assert task_arns[0] in task_by_arn, f"Task {task_arns[0]} not found in response"
    assert task_arns[1] in task_by_arn, f"Task {task_arns[1]} not found in response"

    for task_arn, expected_cluster in zip(task_arns, [cluster_id_1, cluster_id_2]):
        task = task_by_arn[task_arn]
        tags = {t['key']: t['value'] for t in task.get('tags', [])}
        assert tags.get('cluster_id') == expected_cluster, \
            f"Task {task_arn} should have cluster_id={expected_cluster}, got {tags.get('cluster_id')}"
        assert tags.get('investigation_id') == investigation_id

    # Set up environment
    env = os.environ.copy()
    env["ROSA_BOUNDARY_EFS_FILESYSTEM_ID"] = test_efs
    env["ROSA_BOUNDARY_ECS_CLUSTER_NAME"] = cluster_name
    env["AWS_ENDPOINT_URL"] = "http://localhost:4566"
    if "LOCALSTACK_HOSTNAME" in env:
        env["AWS_ENDPOINT_URL"] = f"http://{env['LOCALSTACK_HOSTNAME']}:4566"
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "test"
    env["AWS_DEFAULT_REGION"] = "us-east-1"

    repo_root = Path(__file__).resolve().parents[3]
    bin_path = repo_root / "bin" / "rosa-boundary"
    subprocess.run([go_path, "build", "-o", str(bin_path), "./cmd/rosa-boundary"], cwd=repo_root, check=True)

    # Close investigation for cluster_id_1 only with --force to stop tasks
    cmd = [
        str(bin_path),
        "close-investigation",
        "--cluster-id", cluster_id_1,
        "--investigation-id", investigation_id,
        "--force",
        "--yes"
    ]

    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)

    assert result.returncode == 0, f"Command should succeed: {result.stderr}\nStdout: {result.stdout}"

    # Verify only the first cluster's access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_ids[0] not in remaining_ids, "First cluster's access point should be deleted"
    assert ap_ids[1] in remaining_ids, "Second cluster's access point should still exist"

    # Verify the output mentions the correct cluster and task stop
    assert cluster_id_1 in result.stderr, "Output should show the correct cluster ID"
    assert cluster_id_2 not in result.stderr, "Output should not mention the other cluster"

    # Check task states: cluster_id_1's task should be stopped/stopping, cluster_id_2's should still be running
    desc_after = ecs_client.describe_tasks(cluster=cluster_name, tasks=task_arns)

    # Map tasks by ARN for reliable lookup
    tasks_after_by_arn = {task['taskArn']: task for task in desc_after['tasks']}
    assert len(tasks_after_by_arn) == 2, f"Expected 2 tasks in response, got {len(tasks_after_by_arn)}"
    assert task_arns[0] in tasks_after_by_arn, f"Task {task_arns[0]} not found in post-close response"
    assert task_arns[1] in tasks_after_by_arn, f"Task {task_arns[1]} not found in post-close response"

    # Task 1 (cluster_id_1) should be stopped or stopping
    task1_status = tasks_after_by_arn[task_arns[0]]['lastStatus']
    assert task1_status in ['STOPPED', 'STOPPING', 'DEACTIVATING'], \
        f"Task for cluster_id_1 ({task_arns[0]}) should be stopped/stopping, got {task1_status}"

    # Task 2 (cluster_id_2) should still be running (not stopped by close-investigation)
    task2_status = tasks_after_by_arn[task_arns[1]]['lastStatus']
    assert task2_status in ['RUNNING', 'PENDING', 'PROVISIONING'], \
        f"Task for cluster_id_2 ({task_arns[1]}) should still be running, got {task2_status} - it should NOT have been stopped"
