"""Test tag-based authorization model without container execution"""

import pytest
import json
from datetime import datetime
from .test_helpers import get_policy_document


@pytest.mark.integration
def test_tag_based_iam_policy_evaluation(iam_client):
    """Test IAM policy with tag conditions (simulates authorization model)"""
    user1_sub = 'user-abc-123'
    user2_sub = 'user-def-456'

    # Create role for user1 with tag-based policy
    role1_name = f'test-user1-role-{int(datetime.now().timestamp())}'
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

    iam_client.create_role(
        RoleName=role1_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    # Create tag-based policy for user1
    policy1 = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'ExecuteCommandOnOwnedTasks',
                'Effect': 'Allow',
                'Action': 'ecs:ExecuteCommand',
                'Resource': 'arn:aws:ecs:*:*:task/*',
                'Condition': {
                    'StringEquals': {
                        'ecs:ResourceTag/owner_sub': user1_sub
                    }
                }
            },
            {
                'Sid': 'DescribeAllTasks',
                'Effect': 'Allow',
                'Action': 'ecs:DescribeTasks',
                'Resource': '*'
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role1_name,
        PolicyName='TagBasedAccess',
        PolicyDocument=json.dumps(policy1)
    )

    # Create role for user2 with different tag condition
    role2_name = f'test-user2-role-{int(datetime.now().timestamp())}'
    iam_client.create_role(
        RoleName=role2_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    policy2 = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'ExecuteCommandOnOwnedTasks',
                'Effect': 'Allow',
                'Action': 'ecs:ExecuteCommand',
                'Resource': 'arn:aws:ecs:*:*:task/*',
                'Condition': {
                    'StringEquals': {
                        'ecs:ResourceTag/owner_sub': user2_sub
                    }
                }
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role2_name,
        PolicyName='TagBasedAccess',
        PolicyDocument=json.dumps(policy2)
    )

    # Verify policies are different
    policy1_doc = iam_client.get_role_policy(RoleName=role1_name, PolicyName='TagBasedAccess')
    policy2_doc = iam_client.get_role_policy(RoleName=role2_name, PolicyName='TagBasedAccess')

    p1 = get_policy_document(policy1_doc['PolicyDocument'])
    p2 = get_policy_document(policy2_doc['PolicyDocument'])

    assert p1['Statement'][0]['Condition']['StringEquals']['ecs:ResourceTag/owner_sub'] == user1_sub
    assert p2['Statement'][0]['Condition']['StringEquals']['ecs:ResourceTag/owner_sub'] == user2_sub

    # Cleanup
    iam_client.delete_role_policy(RoleName=role1_name, PolicyName='TagBasedAccess')
    iam_client.delete_role_policy(RoleName=role2_name, PolicyName='TagBasedAccess')
    iam_client.delete_role(RoleName=role1_name)
    iam_client.delete_role(RoleName=role2_name)


@pytest.mark.integration
def test_multiple_tasks_different_owners(ecs_client, test_vpc, iam_client, ecs_cleanup):
    """Test task tagging for multiple users (authorization boundary)"""
    # Create cluster
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

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
    ecs_cleanup.register_role(role_name)

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
    ecs_cleanup.register_task_definition(task_def_arn)

    # Run tasks for different users
    user1_sub = 'user-001'
    user2_sub = 'user-002'

    task1_response = ecs_client.run_task(
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
            {'key': 'owner_sub', 'value': user1_sub},
            {'key': 'investigation_id', 'value': 'inv-001'}
        ]
    )

    task2_response = ecs_client.run_task(
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
            {'key': 'owner_sub', 'value': user2_sub},
            {'key': 'investigation_id', 'value': 'inv-002'}
        ]
    )

    task1_arn = task1_response['tasks'][0]['taskArn']
    task2_arn = task2_response['tasks'][0]['taskArn']
    ecs_cleanup.register_task(cluster_name, task1_arn)
    ecs_cleanup.register_task(cluster_name, task2_arn)

    # Verify tags are different
    tags1 = ecs_client.list_tags_for_resource(resourceArn=task1_arn)
    tags2 = ecs_client.list_tags_for_resource(resourceArn=task2_arn)

    tags1_dict = {t['key']: t['value'] for t in tags1['tags']}
    tags2_dict = {t['key']: t['value'] for t in tags2['tags']}

    assert tags1_dict['owner_sub'] == user1_sub
    assert tags2_dict['owner_sub'] == user2_sub
    assert tags1_dict['investigation_id'] != tags2_dict['investigation_id']


@pytest.mark.integration
def test_cross_user_task_access_prevention(iam_client):
    """Test IAM policy prevents cross-user task access"""
    user_a_sub = 'user-aaa'
    user_b_sub = 'user-bbb'

    # Create role for user A
    role_a_name = f'test-user-a-role-{int(datetime.now().timestamp())}'
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

    iam_client.create_role(
        RoleName=role_a_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    # Policy for user A - can only access tasks tagged with user_a_sub
    policy_a = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'ExecuteCommandOnOwnedTasks',
                'Effect': 'Allow',
                'Action': 'ecs:ExecuteCommand',
                'Resource': 'arn:aws:ecs:*:*:task/*',
                'Condition': {
                    'StringEquals': {
                        'ecs:ResourceTag/owner_sub': user_a_sub
                    }
                }
            },
            {
                'Sid': 'DenyOtherUserTasks',
                'Effect': 'Deny',
                'Action': 'ecs:ExecuteCommand',
                'Resource': 'arn:aws:ecs:*:*:task/*',
                'Condition': {
                    'StringNotEquals': {
                        'ecs:ResourceTag/owner_sub': user_a_sub
                    }
                }
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role_a_name,
        PolicyName='StrictTagBasedAccess',
        PolicyDocument=json.dumps(policy_a)
    )

    # Verify policy has explicit deny for other users
    retrieved_policy = iam_client.get_role_policy(
        RoleName=role_a_name,
        PolicyName='StrictTagBasedAccess'
    )

    policy_doc = get_policy_document(retrieved_policy['PolicyDocument'])
    deny_statement = [s for s in policy_doc['Statement'] if s['Effect'] == 'Deny'][0]

    assert deny_statement['Condition']['StringNotEquals']['ecs:ResourceTag/owner_sub'] == user_a_sub
    assert 'ecs:ExecuteCommand' in deny_statement['Action']

    # Cleanup
    iam_client.delete_role_policy(RoleName=role_a_name, PolicyName='StrictTagBasedAccess')
    iam_client.delete_role(RoleName=role_a_name)
