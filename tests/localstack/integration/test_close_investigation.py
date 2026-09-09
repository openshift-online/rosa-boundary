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
def test_close_investigation_finds_cluster_dynamically(efs_client, efs_filesystem, efs_cleanup):
    """
    Verify that providing only the investigation ID retrieves an access point,
    even when the request omits the cluster ID.
    """
    investigation_id = f"test-inv-{int(datetime.now().timestamp())}"
    cluster_id = f"test-cluster-{int(datetime.now().timestamp())}"

    # Create the access point to simulate a live investigation
    response = efs_client.create_access_point(
        FileSystemId=efs_filesystem,
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
    efs_cleanup.register_access_point(ap_id)

    # Now attempt to find it WITHOUT providing the cluster_id.
    # We replicate the exact API call from efs.go FindAccessPointByTags.
    paginator = efs_client.get_paginator('describe_access_points')
    found_ap = None
    for page in paginator.paginate(FileSystemId=efs_filesystem):
        for ap in page.get('AccessPoints', []):
            if ap.get('LifeCycleState') != 'available':
                continue
            tags = {t['Key']: t['Value'] for t in ap.get('Tags', [])}
            # Simulate the Go condition: (clusterID == "" || tags["ClusterID"] == clusterID) && tags["InvestigationID"] == investigationID
            if tags.get('InvestigationID') == investigation_id:
                found_ap = ap
                break
        if found_ap:
            break

    assert found_ap is not None
    assert found_ap['AccessPointId'] == ap_id
    
    # We should be able to derive the ClusterID from the found access point
    found_tags = {t['Key']: t['Value'] for t in found_ap.get('Tags', [])}
    assert found_tags.get('ClusterID') == cluster_id

