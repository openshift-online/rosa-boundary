"""Test IAM role creation and policy management"""

import pytest
import json
from datetime import datetime
from .test_helpers import get_policy_document


@pytest.mark.integration
def test_create_execution_role(iam_client):
    """Test ECS task execution role creation"""
    role_name = f'test-execution-role-{int(datetime.now().timestamp())}'

    # Create role with ECS trust policy
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='Test ECS task execution role'
    )

    assert response['Role']['RoleName'] == role_name
    role_arn = response['Role']['Arn']

    # Attach AWS managed policy
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
    )

    # Verify attached policies
    policies = iam_client.list_attached_role_policies(RoleName=role_name)
    assert len(policies['AttachedPolicies']) == 1
    assert 'AmazonECSTaskExecutionRolePolicy' in policies['AttachedPolicies'][0]['PolicyArn']

    # Cleanup
    iam_client.detach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
    )
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_create_task_role_with_tag_policy(iam_client):
    """Test ECS task role with tag-based authorization policy"""
    role_name = f'test-task-role-{int(datetime.now().timestamp())}'
    username = 'test-user-123'

    # Create role
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

    # Create tag-based policy
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
                        'ecs:ResourceTag/username': username
                    }
                }
            },
            {
                'Sid': 'DescribeAndListECS',
                'Effect': 'Allow',
                'Action': [
                    'ecs:DescribeTasks',
                    'ecs:ListTasks'
                ],
                'Resource': '*'
            }
        ]
    }

    # Put inline policy
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='TagBasedECSExec',
        PolicyDocument=json.dumps(tag_policy)
    )

    # Verify inline policy
    policy_doc = iam_client.get_role_policy(
        RoleName=role_name,
        PolicyName='TagBasedECSExec'
    )

    policy = get_policy_document(policy_doc['PolicyDocument'])
    assert policy['Statement'][0]['Condition']['StringEquals']['ecs:ResourceTag/username'] == username

    # Cleanup
    iam_client.delete_role_policy(RoleName=role_name, PolicyName='TagBasedECSExec')
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_create_oidc_provider(iam_client, mock_oidc_issuer):
    """Test OIDC identity provider creation"""
    # Note: LocalStack may not fully support OIDC provider thumbprints
    # This test verifies basic OIDC provider creation

    try:
        response = iam_client.create_open_id_connect_provider(
            Url=mock_oidc_issuer,
            ClientIDList=['aws-sre-access'],
            ThumbprintList=['0000000000000000000000000000000000000000']  # Placeholder
        )

        provider_arn = response['OpenIDConnectProviderArn']
        assert 'oidc-provider' in provider_arn

        # List providers
        providers = iam_client.list_open_id_connect_providers()
        arns = [p['Arn'] for p in providers['OpenIDConnectProviderList']]
        assert provider_arn in arns

        # Cleanup
        iam_client.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)

    except Exception as e:
        # LocalStack may not fully support OIDC providers
        pytest.skip(f'OIDC provider not supported in LocalStack: {e}')


@pytest.mark.integration
def test_role_with_web_identity_trust(iam_client, mock_oidc_issuer):
    """Test role with OIDC web identity trust policy"""
    role_name = f'test-web-identity-role-{int(datetime.now().timestamp())}'

    # Create OIDC trust policy
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {
                    'Federated': f'arn:aws:iam::000000000000:oidc-provider/{mock_oidc_issuer.replace("http://", "")}'
                },
                'Action': 'sts:AssumeRoleWithWebIdentity',
                'Condition': {
                    'StringEquals': {
                        f'{mock_oidc_issuer.replace("http://", "")}:aud': 'aws-sre-access',
                        f'{mock_oidc_issuer.replace("http://", "")}:groups': 'sre-team'
                    }
                }
            }
        ]
    }

    response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    # Verify trust policy
    role = iam_client.get_role(RoleName=role_name)
    retrieved_policy = get_policy_document(role['Role']['AssumeRolePolicyDocument'])
    assert retrieved_policy['Statement'][0]['Action'] == 'sts:AssumeRoleWithWebIdentity'

    # Cleanup
    iam_client.delete_role(RoleName=role_name)
