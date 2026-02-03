"""Test ECS cluster and task lifecycle (no container execution)"""

import pytest
import json
from datetime import datetime


@pytest.mark.integration
def test_create_ecs_cluster(ecs_client):
    """Test ECS cluster creation"""
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'

    response = ecs_client.create_cluster(
        clusterName=cluster_name,
        tags=[
            {'key': 'Environment', 'value': 'test'},
            {'key': 'Purpose', 'value': 'integration-testing'}
        ]
    )

    assert response['cluster']['clusterName'] == cluster_name
    assert response['cluster']['status'] == 'ACTIVE'

    # Cleanup
    ecs_client.delete_cluster(cluster=cluster_name)


@pytest.mark.integration
def test_register_task_definition_with_efs(ecs_client, test_efs, iam_client):
    """Test ECS task definition registration with EFS volume"""
    # Create execution role
    role_name = f'test-exec-role-{int(datetime.now().timestamp())}'
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
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role_response['Role']['Arn']

    # Register task definition
    family_name = f'test-task-{int(datetime.now().timestamp())}'

    response = ecs_client.register_task_definition(
        family=family_name,
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
                    {'name': 'CLUSTER_ID', 'value': 'rosa-dev'},
                    {'name': 'INVESTIGATION_ID', 'value': 'inv-123'}
                ]
            }
        ],
        volumes=[
            {
                'name': 'efs-home',
                'efsVolumeConfiguration': {
                    'fileSystemId': test_efs,
                    'transitEncryption': 'ENABLED'
                }
            }
        ]
    )

    task_def_arn = response['taskDefinition']['taskDefinitionArn']
    assert response['taskDefinition']['family'] == family_name
    assert len(response['taskDefinition']['volumes']) == 1
    assert response['taskDefinition']['volumes'][0]['efsVolumeConfiguration']['fileSystemId'] == test_efs

    # Cleanup
    ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
@pytest.mark.slow
def test_run_fargate_task_with_tags(ecs_client, test_vpc, iam_client):
    """Test running Fargate task with owner tags (verify task submission only)"""
    # Create cluster
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'
    ecs_client.create_cluster(clusterName=cluster_name)

    # Create execution role
    role_name = f'test-role-{int(datetime.now().timestamp())}'
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
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role_response['Role']['Arn']

    # Register task definition
    family_name = f'test-task-{int(datetime.now().timestamp())}'
    task_def_response = ecs_client.register_task_definition(
        family=family_name,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        executionRoleArn=role_arn,
        taskRoleArn=role_arn,
        containerDefinitions=[
            {
                'name': 'test-container',
                'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
                'essential': True,
                'command': ['sleep', '3600']
            }
        ]
    )

    task_def_arn = task_def_response['taskDefinition']['taskDefinitionArn']

    # Run task with tags
    owner_sub = 'test-user-456'
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
            {'key': 'investigation_id', 'value': 'inv-456'},
            {'key': 'cluster_id', 'value': 'rosa-dev'}
        ],
        enableExecuteCommand=True
    )

    assert len(run_response['tasks']) == 1
    task_arn = run_response['tasks'][0]['taskArn']

    # Verify tags via list-tags-for-resource
    tags_response = ecs_client.list_tags_for_resource(resourceArn=task_arn)
    tag_dict = {t['key']: t['value'] for t in tags_response['tags']}

    assert tag_dict['owner_sub'] == owner_sub
    assert tag_dict['investigation_id'] == 'inv-456'

    # Stop task
    ecs_client.stop_task(cluster=cluster_name, task=task_arn, reason='Test complete')

    # Cleanup
    ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
    iam_client.delete_role(RoleName=role_name)
    ecs_client.delete_cluster(cluster=cluster_name)


@pytest.mark.integration
def test_describe_tasks_with_tag_filter(ecs_client, test_vpc, iam_client):
    """Test describing tasks with tag filters (authorization model)"""
    # Create cluster
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'
    ecs_client.create_cluster(clusterName=cluster_name)

    # Create role
    role_name = f'test-role-{int(datetime.now().timestamp())}'
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
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role_response['Role']['Arn']

    # Register task definition
    family_name = f'test-task-{int(datetime.now().timestamp())}'
    task_def_response = ecs_client.register_task_definition(
        family=family_name,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        executionRoleArn=role_arn,
        taskRoleArn=role_arn,
        containerDefinitions=[
            {
                'name': 'test-container',
                'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
                'essential': True
            }
        ]
    )

    task_def_arn = task_def_response['taskDefinition']['taskDefinitionArn']

    # Run task with specific owner tag
    owner_sub = 'user-789'
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
            {'key': 'owner_sub', 'value': owner_sub}
        ]
    )

    task_arn = run_response['tasks'][0]['taskArn']

    # Describe task
    describe_response = ecs_client.describe_tasks(
        cluster=cluster_name,
        tasks=[task_arn],
        include=['TAGS']
    )

    assert len(describe_response['tasks']) == 1
    task = describe_response['tasks'][0]

    # Verify tag exists
    tag_dict = {t['key']: t['value'] for t in task.get('tags', [])}
    assert tag_dict.get('owner_sub') == owner_sub

    # Cleanup
    ecs_client.stop_task(cluster=cluster_name, task=task_arn, reason='Test complete')
    ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
    iam_client.delete_role(RoleName=role_name)
    ecs_client.delete_cluster(cluster=cluster_name)
