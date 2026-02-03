"""Test KMS key creation and management"""

import pytest
import json
from datetime import datetime


@pytest.mark.integration
def test_create_kms_key_for_ecs_exec(kms_client, iam_client):
    """Test KMS key creation for ECS Exec encryption"""
    # Create test role for key policy
    role_name = f'test-ecs-role-{int(datetime.now().timestamp())}'
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

    # Create KMS key with policy allowing ECS task role
    key_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'Enable IAM User Permissions',
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::000000000000:root'
                },
                'Action': 'kms:*',
                'Resource': '*'
            },
            {
                'Sid': 'Allow ECS task role to use the key',
                'Effect': 'Allow',
                'Principal': {
                    'AWS': role_arn
                },
                'Action': [
                    'kms:Decrypt',
                    'kms:GenerateDataKey'
                ],
                'Resource': '*'
            }
        ]
    }

    response = kms_client.create_key(
        Description='Test ECS Exec encryption key',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS',
        Policy=json.dumps(key_policy)
    )

    key_id = response['KeyMetadata']['KeyId']
    assert response['KeyMetadata']['KeyState'] == 'Enabled'

    # Create alias
    alias_name = f'alias/test-ecs-exec-{int(datetime.now().timestamp())}'
    kms_client.create_alias(
        AliasName=alias_name,
        TargetKeyId=key_id
    )

    # Verify alias
    aliases = kms_client.list_aliases()
    alias_names = [a['AliasName'] for a in aliases['Aliases']]
    assert alias_name in alias_names

    # Test key policy
    key_policy_response = kms_client.get_key_policy(
        KeyId=key_id,
        PolicyName='default'
    )
    retrieved_policy = json.loads(key_policy_response['Policy'])
    assert len(retrieved_policy['Statement']) == 2
    assert retrieved_policy['Statement'][1]['Sid'] == 'Allow ECS task role to use the key'

    # Cleanup
    kms_client.delete_alias(AliasName=alias_name)
    kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_kms_key_tags(kms_client):
    """Test KMS key tagging"""
    response = kms_client.create_key(
        Description='Test key with tags',
        Tags=[
            {'TagKey': 'Environment', 'TagValue': 'test'},
            {'TagKey': 'Purpose', 'TagValue': 'ecs-exec'}
        ]
    )

    key_id = response['KeyMetadata']['KeyId']

    # List tags
    tags = kms_client.list_resource_tags(KeyId=key_id)
    tag_dict = {t['TagKey']: t['TagValue'] for t in tags['Tags']}

    assert tag_dict['Environment'] == 'test'
    assert tag_dict['Purpose'] == 'ecs-exec'

    # Cleanup
    kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
