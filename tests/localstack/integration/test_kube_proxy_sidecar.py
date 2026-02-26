"""Integration tests for the kube-proxy sidecar pattern in ECS task definitions."""

import json
import pytest
from datetime import datetime


def _make_role(iam_client):
    """Create a minimal ECS task execution role for testing."""
    role_name = f'test-kube-proxy-role-{int(datetime.now().timestamp())}'
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
    response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    return role_name, response['Role']['Arn']


def _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name):
    """Register a task definition with both rosa-boundary and kube-proxy containers."""
    return ecs_client.register_task_definition(
        family=family_name,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='1024',
        memory='2048',
        executionRoleArn=role_arn,
        taskRoleArn=role_arn,
        volumes=[
            {
                'name': 'sre-home',
                'efsVolumeConfiguration': {
                    'fileSystemId': test_efs,
                    'transitEncryption': 'ENABLED'
                }
            },
            {
                'name': 'proxy-tmp'  # bind mount, no EFS config
            }
        ],
        containerDefinitions=[
            {
                'name': 'rosa-boundary',
                'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
                'essential': True,
                'dependsOn': [
                    {'containerName': 'kube-proxy', 'condition': 'HEALTHY'}
                ],
                'environment': [
                    {'name': 'CLAUDE_CODE_USE_BEDROCK', 'value': '1'},
                    {'name': 'TASK_TIMEOUT', 'value': '3600'},
                    {'name': 'KUBE_PROXY_PORT', 'value': '8001'},
                ],
                'mountPoints': [
                    {'sourceVolume': 'sre-home', 'containerPath': '/home/sre', 'readOnly': False}
                ],
                'logConfiguration': {
                    'logDriver': 'awslogs',
                    'options': {
                        'awslogs-group': '/ecs/test',
                        'awslogs-region': 'us-east-2',
                        'awslogs-stream-prefix': 'rosa-boundary'
                    }
                }
            },
            {
                'name': 'kube-proxy',
                'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
                'essential': True,
                'readonlyRootFilesystem': True,
                'command': [
                    'sh', '-c',
                    'printf \'%s\' "$KUBECONFIG_DATA" > /tmp/kubeconfig && '
                    'exec oc proxy --address=127.0.0.1 --port=8001 --kubeconfig=/tmp/kubeconfig'
                ],
                'environment': [
                    {'name': 'HOME', 'value': '/tmp'}
                ],
                'secrets': [
                    {
                        'name': 'KUBECONFIG_DATA',
                        'valueFrom': 'arn:aws:secretsmanager:us-east-2:123456789012:'
                                     'secret:rosa-boundary/clusters/test-cluster/kubeconfig'
                    }
                ],
                'healthCheck': {
                    'command': ['CMD-SHELL', 'curl -sf http://127.0.0.1:8001/version || exit 1'],
                    'interval': 10,
                    'timeout': 5,
                    'retries': 3,
                    'startPeriod': 30
                },
                'mountPoints': [
                    {'sourceVolume': 'proxy-tmp', 'containerPath': '/tmp', 'readOnly': False}
                ],
                'logConfiguration': {
                    'logDriver': 'awslogs',
                    'options': {
                        'awslogs-group': '/ecs/test',
                        'awslogs-region': 'us-east-2',
                        'awslogs-stream-prefix': 'kube-proxy'
                    }
                }
            }
        ]
    )


@pytest.mark.integration
def test_register_multi_container_task_definition(ecs_client, iam_client, efs_client, test_efs):
    """Test that a multi-container task definition with kube-proxy sidecar registers successfully."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        task_def = response['taskDefinition']
        assert task_def['family'] == family_name
        assert len(task_def['containerDefinitions']) == 2
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_kube_proxy_has_readonly_root_filesystem(ecs_client, iam_client, test_efs):
    """Test that the kube-proxy container has readonlyRootFilesystem set to True."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-ro-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        container_defs = response['taskDefinition']['containerDefinitions']
        proxy_cd = next(cd for cd in container_defs if cd['name'] == 'kube-proxy')
        assert proxy_cd.get('readonlyRootFilesystem') is True
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_volume_mount_configuration(ecs_client, iam_client, test_efs):
    """Test that volumes are correctly mounted: sre-home in SRE only, proxy-tmp in sidecar only."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-mounts-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        container_defs = response['taskDefinition']['containerDefinitions']
        sre_cd = next(cd for cd in container_defs if cd['name'] == 'rosa-boundary')
        proxy_cd = next(cd for cd in container_defs if cd['name'] == 'kube-proxy')

        sre_mounts = {mp['sourceVolume'] for mp in sre_cd.get('mountPoints', [])}
        proxy_mounts = {mp['sourceVolume'] for mp in proxy_cd.get('mountPoints', [])}

        assert 'sre-home' in sre_mounts
        assert 'proxy-tmp' not in sre_mounts
        assert 'proxy-tmp' in proxy_mounts
        assert 'sre-home' not in proxy_mounts
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_proxy_tmp_volume_has_no_efs_config(ecs_client, iam_client, test_efs):
    """Test that the proxy-tmp volume is a plain bind mount with no EFS configuration."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-vol-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        volumes = response['taskDefinition']['volumes']
        proxy_vol = next(v for v in volumes if v['name'] == 'proxy-tmp')
        assert 'efsVolumeConfiguration' not in proxy_vol
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_depend_on_ordering(ecs_client, iam_client, test_efs):
    """Test that the SRE container has dependsOn kube-proxy with HEALTHY condition."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-dep-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        container_defs = response['taskDefinition']['containerDefinitions']
        sre_cd = next(cd for cd in container_defs if cd['name'] == 'rosa-boundary')
        depend_on = sre_cd.get('dependsOn', [])
        assert len(depend_on) == 1
        assert depend_on[0]['containerName'] == 'kube-proxy'
        assert depend_on[0]['condition'] == 'HEALTHY'
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_kube_proxy_has_secrets_manager_reference(ecs_client, iam_client, test_efs):
    """Test that the kube-proxy container references the cluster kubeconfig from Secrets Manager."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-secrets-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        container_defs = response['taskDefinition']['containerDefinitions']
        proxy_cd = next(cd for cd in container_defs if cd['name'] == 'kube-proxy')
        secrets = {s['name']: s['valueFrom'] for s in proxy_cd.get('secrets', [])}
        assert 'KUBECONFIG_DATA' in secrets
        kubeconfig_ref = secrets['KUBECONFIG_DATA']
        assert 'secretsmanager' in kubeconfig_ref
        assert 'rosa-boundary/clusters/test-cluster/kubeconfig' in kubeconfig_ref
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_sre_container_does_not_have_kubeconfig_secret(ecs_client, iam_client, test_efs):
    """Test that the SRE container does not have the kubeconfig secret (credential isolation)."""
    role_name, role_arn = _make_role(iam_client)
    family_name = f'test-kube-proxy-iso-{int(datetime.now().timestamp())}'

    try:
        response = _register_multi_container_task_def(ecs_client, role_arn, test_efs, family_name)

        container_defs = response['taskDefinition']['containerDefinitions']
        sre_cd = next(cd for cd in container_defs if cd['name'] == 'rosa-boundary')
        secret_names = [s['name'] for s in sre_cd.get('secrets', [])]
        assert 'KUBECONFIG_DATA' not in secret_names
    finally:
        task_def_arn = response['taskDefinition']['taskDefinitionArn']
        ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
        iam_client.delete_role(RoleName=role_name)
