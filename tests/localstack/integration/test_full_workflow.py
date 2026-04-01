"""End-to-end investigation creation workflow test"""

import pytest
import json
from datetime import datetime


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.slow
def test_complete_investigation_creation(
    ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup
):
    """Test complete investigation creation workflow (simulating Lambda logic).

    Uses the shared ABAC role pattern: a single role with ${aws:PrincipalTag/username}
    in the condition serves all SREs, with per-user isolation enforced via session tags.
    """
    cluster_id = 'rosa-dev'
    investigation_id = f'inv-e2e-{int(datetime.now().timestamp())}'
    oidc_sub = 'test-user-e2e-123'
    username = 'sre-e2e-user'
    oidc_provider_arn = 'arn:aws:iam::123456789012:oidc-provider/keycloak.example.com/realms/sre-ops'
    oidc_domain = 'keycloak.example.com/realms/sre-ops'
    oidc_client_id = 'aws-sre-access'

    # Step 1: Create shared SRE role (single role for all SREs, ABAC-scoped via session tags)
    role_name = f'rosa-boundary-sre-shared-{int(datetime.now().timestamp())}'
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'Federated': oidc_provider_arn},
                'Action': ['sts:AssumeRoleWithWebIdentity', 'sts:TagSession'],
                'Condition': {
                    'StringEquals': {
                        f'{oidc_domain}:aud': oidc_client_id
                    }
                }
            }
        ]
    }

    sre_role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='Shared SRE role with ABAC for per-user task isolation'
    )
    sre_role_arn = sre_role_response['Role']['Arn']
    ecs_cleanup.register_role(role_name, ['ECSExecABAC'])

    # Attach ABAC policy using dynamic ${aws:PrincipalTag/username} (not hardcoded username)
    abac_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'ExecuteCommandOnOwnedTasks',
                'Effect': 'Allow',
                'Action': 'ecs:ExecuteCommand',
                'Resource': '*',
                'Condition': {
                    'StringEquals': {
                        'ecs:ResourceTag/username': '${aws:PrincipalTag/username}'
                    }
                }
            },
            {
                'Sid': 'DescribeAndListECS',
                'Effect': 'Allow',
                'Action': ['ecs:DescribeTasks', 'ecs:ListTasks', 'ecs:DescribeTaskDefinition'],
                'Resource': '*'
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='ECSExecABAC',
        PolicyDocument=json.dumps(abac_policy)
    )

    # Create a separate ECS task/execution role trusted by ecs-tasks.amazonaws.com.
    # The SRE role above is for human callers (AssumeRoleWithWebIdentity); ECS tasks
    # need a distinct role with the ECS service principal in the trust policy.
    ecs_role_name = f'rosa-boundary-ecs-task-{int(datetime.now().timestamp())}'
    ecs_trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
            'Action': 'sts:AssumeRole'
        }]
    }
    ecs_role_response = iam_client.create_role(
        RoleName=ecs_role_name,
        AssumeRolePolicyDocument=json.dumps(ecs_trust_policy),
        Description='ECS task/execution role for rosa-boundary container'
    )
    ecs_role_arn = ecs_role_response['Role']['Arn']
    ecs_cleanup.register_role(ecs_role_name, [])

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
            {'Key': 'oidc_sub', 'Value': oidc_sub},
            {'Key': 'username', 'Value': username}
        ]
    )

    access_point_id = access_point_response['AccessPointId']
    ecs_cleanup.register_access_point(access_point_id)

    # Step 3: Create ECS cluster
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Step 4: Register task definition
    task_family = f'{cluster_id}-{investigation_id}-{int(datetime.now().timestamp())}'

    task_def_response = ecs_client.register_task_definition(
        family=task_family,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        executionRoleArn=ecs_role_arn,
        taskRoleArn=ecs_role_arn,
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
    ecs_cleanup.register_task_definition(task_def_arn)

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
            {'key': 'oidc_sub', 'value': oidc_sub},
            {'key': 'username', 'value': username},
            {'key': 'investigation_id', 'value': investigation_id},
            {'key': 'cluster_id', 'value': cluster_id}
        ],
        enableExecuteCommand=True
    )

    assert len(run_response['tasks']) == 1
    task_arn = run_response['tasks'][0]['taskArn']
    ecs_cleanup.register_task(cluster_name, task_arn)

    # Step 6: Verify complete workflow
    # Verify shared SRE role exists with correct ABAC policy (dynamic PrincipalTag, not hardcoded username)
    role = iam_client.get_role(RoleName=role_name)
    assert role['Role']['RoleName'] == role_name
    retrieved_policy = iam_client.get_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    from .test_helpers import get_policy_document
    policy_doc = get_policy_document(retrieved_policy['PolicyDocument'])
    exec_stmts = [s for s in policy_doc['Statement'] if s.get('Sid') == 'ExecuteCommandOnOwnedTasks']
    assert len(exec_stmts) == 1
    condition_val = exec_stmts[0]['Condition']['StringEquals']['ecs:ResourceTag/username']
    assert condition_val == '${aws:PrincipalTag/username}', (
        f"ABAC policy must use dynamic PrincipalTag, got: {condition_val!r}"
    )

    # Verify access point exists
    access_points = efs_client.describe_access_points(AccessPointId=access_point_id)
    assert len(access_points['AccessPoints']) == 1

    # Verify task has correct tags (use describe_tasks, more reliable than list_tags_for_resource in LocalStack)
    desc = ecs_client.describe_tasks(cluster=cluster_name, tasks=[task_arn], include=['TAGS'])
    tag_dict = {t['key']: t['value'] for t in desc['tasks'][0].get('tags', [])}
    assert tag_dict['oidc_sub'] == oidc_sub
    assert tag_dict['username'] == username
    assert tag_dict['investigation_id'] == investigation_id

    # Verify task definition has EFS mount
    task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
    volumes = task_def['taskDefinition']['volumes']
    assert len(volumes) == 1
    assert volumes[0]['efsVolumeConfiguration']['fileSystemId'] == test_efs
    assert volumes[0]['efsVolumeConfiguration']['authorizationConfig']['accessPointId'] == access_point_id


@pytest.mark.integration
@pytest.mark.e2e
def test_idempotent_role_creation(iam_client):
    """Test idempotent IAM role creation (same user gets same role)"""
    oidc_sub = 'test-user-idempotent-456'
    role_name = f'rosa-boundary-user-{oidc_sub.replace("/", "-")}'

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
