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
def test_close_investigation_finds_cluster_dynamically(efs_client, test_efs, ecs_cleanup):
    """
    Verify that invoking the actual close-investigation CLI command works
    and correctly derives the cluster ID from the EFS access point.
    """
    import subprocess
    import os
    import platform
    from pathlib import Path
    
    investigation_id = f"test-inv-{int(datetime.now().timestamp())}"
    cluster_id = f"test-cluster-{int(datetime.now().timestamp())}"
    cluster_name = "test-cluster-name"

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
    subprocess.run(["go", "build", "-o", str(bin_path), "./cmd/rosa-boundary"], cwd=repo_root, check=True)
    
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
    
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    
    assert result.returncode == 0, f"Command failed: {result.stderr}\nStdout: {result.stdout}"
    
    # Verify the derived ClusterID is shown in the output
    assert cluster_id in result.stderr
    
    # Verify the access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_id not in remaining_ids
