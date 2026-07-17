"""Helper functions for integration tests"""

import json
from datetime import datetime


def get_policy_document(policy_doc_field):
    """
    Extract policy document from IAM response.

    LocalStack may return policies as dicts or JSON strings depending on version.
    This helper handles both cases.

    Args:
        policy_doc_field: The PolicyDocument field from IAM API response

    Returns:
        dict: The policy document as a Python dict
    """
    if isinstance(policy_doc_field, dict):
        return policy_doc_field
    return json.loads(policy_doc_field)


def create_investigation_resources(
    ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
    *,
    cluster_id='rosa-dev',
    investigation_id=None,
    oidc_sub='test-user-e2e',
    username='sre-e2e-user',
    cluster_name_prefix='test-cluster',
    ecs_role_name_prefix='rosa-boundary-ecs',
    extra_efs_tags=None,
    extra_env_vars=None,
    extra_task_tags=None,
    container_command=None,
):
    """Create the common investigation infrastructure: IAM role, EFS access point,
    ECS cluster, task definition, and launched task.

    Returns a dict with all created resource identifiers:
        cluster_id, investigation_id, oidc_sub, username,
        ecs_role_arn, access_point_id, cluster_name, task_def_arn, task_arn
    """
    ts = int(datetime.now().timestamp())
    if investigation_id is None:
        investigation_id = f'inv-e2e-{ts}'

    # ECS task execution role (trusted by ecs-tasks.amazonaws.com)
    ecs_role_name = f'{ecs_role_name_prefix}-{ts}'
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

    # EFS access point at investigation-scoped path
    efs_tags = [
        {'Key': 'Name', 'Value': f'{cluster_id}-{investigation_id}'},
        {'Key': 'ClusterID', 'Value': cluster_id},
        {'Key': 'InvestigationID', 'Value': investigation_id},
        {'Key': 'oidc_sub', 'Value': oidc_sub},
        {'Key': 'username', 'Value': username},
    ]
    if extra_efs_tags:
        efs_tags.extend(extra_efs_tags)

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
        Tags=efs_tags
    )
    access_point_id = access_point_response['AccessPointId']
    ecs_cleanup.register_access_point(access_point_id)

    # ECS cluster
    cluster_name = f'{cluster_name_prefix}-{ts}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Task definition with EFS mount
    task_family = f'{cluster_id}-{investigation_id}-{ts}'
    env_vars = [
        {'name': 'CLUSTER_ID', 'value': cluster_id},
        {'name': 'INVESTIGATION_ID', 'value': investigation_id},
    ]
    if extra_env_vars:
        env_vars.extend(extra_env_vars)

    container_def = {
        'name': 'rosa-boundary',
        'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
        'essential': True,
        'mountPoints': [{
            'sourceVolume': 'efs-home',
            'containerPath': '/home/sre',
            'readOnly': False
        }],
        'environment': env_vars,
    }
    if container_command:
        container_def['command'] = container_command

    task_def_response = ecs_client.register_task_definition(
        family=task_family,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        executionRoleArn=ecs_role_arn,
        taskRoleArn=ecs_role_arn,
        containerDefinitions=[container_def],
        volumes=[{
            'name': 'efs-home',
            'efsVolumeConfiguration': {
                'fileSystemId': test_efs,
                'transitEncryption': 'ENABLED',
                'authorizationConfig': {'accessPointId': access_point_id}
            }
        }]
    )
    task_def_arn = task_def_response['taskDefinition']['taskDefinitionArn']
    ecs_cleanup.register_task_definition(task_def_arn)

    # Launch task
    task_tags = [
        {'key': 'oidc_sub', 'value': oidc_sub},
        {'key': 'username', 'value': username},
        {'key': 'investigation_id', 'value': investigation_id},
        {'key': 'cluster_id', 'value': cluster_id},
    ]
    if extra_task_tags:
        task_tags.extend(extra_task_tags)

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
        tags=task_tags,
        enableExecuteCommand=True
    )
    assert len(run_response['tasks']) == 1, (
        f"Expected 1 task, got {len(run_response['tasks'])}. "
        f"Failures: {run_response.get('failures', [])}"
    )
    task_arn = run_response['tasks'][0]['taskArn']
    ecs_cleanup.register_task(cluster_name, task_arn)

    return {
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'oidc_sub': oidc_sub,
        'username': username,
        'ecs_role_arn': ecs_role_arn,
        'access_point_id': access_point_id,
        'cluster_name': cluster_name,
        'task_def_arn': task_def_arn,
        'task_arn': task_arn,
    }
