"""End-to-end investigation creation workflow test"""

import pytest
import json
from datetime import datetime


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.slow
def test_complete_investigation_creation(
    ecs_client, efs_client, iam_client, test_vpc, test_efs
):
    """Test complete investigation creation workflow (simulating Lambda logic)"""
    cluster_id = 'rosa-dev'
    investigation_id = f'inv-e2e-{int(datetime.now().timestamp())}'
    owner_sub = 'test-user-e2e-123'

    # Step 1: Create/get IAM role for user
    role_name = f'rosa-boundary-user-{owner_sub.replace("/", "-")}'
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }
        ]
    }

    role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description=f'Tag-based access for OIDC user {owner_sub}'
    )
    role_arn = role_response['Role']['Arn']

    # Attach tag-based policy
    tag_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'ExecuteCommandOnOwnedTasks',
                'Effect': 'Allow',
                'Action': 'ecs:ExecuteCommand',
                'Resource': 'arn:aws:ecs:*:*:task/*',
                'Condition': {
                    'StringEquals': {
                        'ecs:ResourceTag/owner_sub': owner_sub
                    }
                }
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='TagBasedECSExec',
        PolicyDocument=json.dumps(tag_policy)
    )

    # Step 2: Create EFS access point
    access_point_response = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': f'/{cluster_id}/{investigation_id}',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[
            {'Key': 'Name', 'Value': f'{cluster_id}-{investigation_id}'},
            {'Key': 'ClusterID', 'Value': cluster_id},
            {'Key': 'InvestigationID', 'Value': investigation_id},
            {'Key': 'OwnerSub', 'Value': owner_sub}
        ]
    )

    access_point_id = access_point_response['AccessPointId']

    # Step 3: Create ECS cluster
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'
    ecs_client.create_cluster(clusterName=cluster_name)

    # Step 4: Register task definition
    task_family = f'{cluster_id}-{investigation_id}-{int(datetime.now().timestamp())}'

    task_def_response = ecs_client.register_task_definition(
        family=task_family,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        executionRoleArn=role_arn,
        taskRoleArn=role_arn,
        containerDefinitions=[
            {
                'name': 'rosa-boundary',
                'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
                'essential': True,
                'mountPoints': [
                    {
                        'sourceVolume': 'efs-home',
                        'containerPath': '/home/sre',
                        'readOnly': False
                    }
                ],
                'environment': [
                    {'name': 'CLUSTER_ID', 'value': cluster_id},
                    {'name': 'INVESTIGATION_ID', 'value': investigation_id},
                    {'name': 'OC_VERSION', 'value': '4.20'}
                ]
            }
        ],
        volumes=[
            {
                'name': 'efs-home',
                'efsVolumeConfiguration': {
                    'fileSystemId': test_efs,
                    'transitEncryption': 'ENABLED',
                    'authorizationConfig': {
                        'accessPointId': access_point_id
                    }
                }
            }
        ]
    )

    task_def_arn = task_def_response['taskDefinition']['taskDefinitionArn']

    # Step 5: Launch ECS task
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
            {'key': 'owner_sub', 'value': owner_sub},
            {'key': 'investigation_id', 'value': investigation_id},
            {'key': 'cluster_id', 'value': cluster_id}
        ],
        enableExecuteCommand=True
    )

    assert len(run_response['tasks']) == 1
    task_arn = run_response['tasks'][0]['taskArn']

    # Step 6: Verify complete workflow
    # Verify role exists
    role = iam_client.get_role(RoleName=role_name)
    assert role['Role']['RoleName'] == role_name

    # Verify access point exists
    access_points = efs_client.describe_access_points(AccessPointId=access_point_id)
    assert len(access_points['AccessPoints']) == 1

    # Verify task has correct tags
    tags = ecs_client.list_tags_for_resource(resourceArn=task_arn)
    tag_dict = {t['key']: t['value'] for t in tags['tags']}
    assert tag_dict['owner_sub'] == owner_sub
    assert tag_dict['investigation_id'] == investigation_id

    # Verify task definition has EFS mount
    task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
    volumes = task_def['taskDefinition']['volumes']
    assert len(volumes) == 1
    assert volumes[0]['efsVolumeConfiguration']['fileSystemId'] == test_efs
    assert volumes[0]['efsVolumeConfiguration']['authorizationConfig']['accessPointId'] == access_point_id

    # Cleanup
    ecs_client.stop_task(cluster=cluster_name, task=task_arn, reason='E2E test complete')
    ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
    efs_client.delete_access_point(AccessPointId=access_point_id)
    iam_client.delete_role_policy(RoleName=role_name, PolicyName='TagBasedECSExec')
    iam_client.delete_role(RoleName=role_name)
    ecs_client.delete_cluster(cluster=cluster_name)


@pytest.mark.integration
@pytest.mark.e2e
def test_idempotent_role_creation(iam_client):
    """Test idempotent IAM role creation (same user gets same role)"""
    owner_sub = 'test-user-idempotent-456'
    role_name = f'rosa-boundary-user-{owner_sub.replace("/", "-")}'

    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }
        ]
    }

    # Create role first time
    role1 = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role1_arn = role1['Role']['Arn']

    # Try to get existing role (simulating Lambda idempotency)
    try:
        role2 = iam_client.get_role(RoleName=role_name)
        role2_arn = role2['Role']['Arn']

        # Should get same role
        assert role1_arn == role2_arn

    except iam_client.exceptions.NoSuchEntityException:
        pytest.fail('Role should exist from first creation')

    # Cleanup
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
@pytest.mark.e2e
def test_efs_access_point_cleanup_on_failure(efs_client, test_efs):
    """Test EFS access point rollback on task launch failure"""
    investigation_id = f'inv-rollback-{int(datetime.now().timestamp())}'

    # Create access point
    response = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': f'/rollback-test/{investigation_id}',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        }
    )

    access_point_id = response['AccessPointId']

    # Verify it exists
    access_points = efs_client.describe_access_points(AccessPointId=access_point_id)
    assert len(access_points['AccessPoints']) == 1

    # Simulate cleanup on failure
    efs_client.delete_access_point(AccessPointId=access_point_id)

    # Verify it's deleted
    access_points_after = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points_after['AccessPoints']]
    assert access_point_id not in remaining_ids
