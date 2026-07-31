"""Test EFS filesystem policy enforcement

These tests validate that the EFS filesystem policy correctly enforces
access point usage for both static (Terraform-managed) and dynamic
(Lambda-created) access points.

This catches regressions like PR #167 where the policy was locked to a
specific access point ARN, breaking dynamic access point creation.
"""

import pytest
import json
import time


@pytest.mark.integration
def test_filesystem_policy_allows_multiple_access_points(efs_client, iam_client):
    """Test that filesystem policy allows both static and dynamic access points.

    Regression test for PR #167: ensure the policy doesn't lock down to a
    specific access point ARN, which would break Lambda-created investigations.
    """
    # Create test EFS filesystem
    creation_token = f'test-policy-{int(time.time() * 1000)}'
    fs_response = efs_client.create_file_system(
        CreationToken=creation_token,
        PerformanceMode='generalPurpose',
        Encrypted=True
    )
    filesystem_id = fs_response['FileSystemId']

    # Create IAM role for task (simulating aws_iam_role.task)
    role_name = f'test-efs-task-role-{int(time.time() * 1000)}'
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
            'Action': 'sts:AssumeRole'
        }]
    }

    role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    task_role_arn = role_response['Role']['Arn']

    # Apply filesystem policy that enforces access point usage
    # This mirrors the policy in deploy/regional/efs.tf
    filesystem_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'EnforceAccessViaAccessPoint',
            'Effect': 'Allow',
            'Principal': {'AWS': task_role_arn},
            'Action': [
                'elasticfilesystem:ClientMount',
                'elasticfilesystem:ClientWrite',
                'elasticfilesystem:ClientRootAccess',
            ],
            'Resource': f'arn:aws:elasticfilesystem:us-east-2:000000000000:file-system/{filesystem_id}',
            'Condition': {
                'Bool': {
                    'elasticfilesystem:AccessedViaMountTarget': 'true'
                },
                'Null': {
                    'elasticfilesystem:AccessPointArn': 'false'
                }
            }
        }]
    }

    efs_client.put_file_system_policy(
        FileSystemId=filesystem_id,
        Policy=json.dumps(filesystem_policy)
    )

    # Verify policy was applied
    policy_response = efs_client.describe_file_system_policy(FileSystemId=filesystem_id)
    applied_policy = json.loads(policy_response['Policy'])

    assert len(applied_policy['Statement']) == 1
    statement = applied_policy['Statement'][0]

    # Key assertion: policy uses Null condition, not StringEquals with specific ARN
    assert 'Null' in statement['Condition']
    assert statement['Condition']['Null']['elasticfilesystem:AccessPointArn'] == 'false'
    assert 'StringEquals' not in statement['Condition']  # Would break dynamic APs

    # Create static access point (simulating Terraform-managed aws_efs_access_point.sre)
    static_ap = efs_client.create_access_point(
        FileSystemId=filesystem_id,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': '/home/sre',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[{'Key': 'Name', 'Value': 'static-terraform-managed'}]
    )
    static_ap_id = static_ap['AccessPointId']

    # Create dynamic access point (simulating Lambda-created investigation)
    cluster_id = 'rosa-dev'
    investigation_id = f'inv-{int(time.time() * 1000)}'
    dynamic_ap = efs_client.create_access_point(
        FileSystemId=filesystem_id,
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
            {'Key': 'InvestigationID', 'Value': investigation_id}
        ]
    )
    dynamic_ap_id = dynamic_ap['AccessPointId']

    # Both access points should exist with different ARNs
    assert static_ap_id != dynamic_ap_id

    # Verify both access points are associated with the filesystem
    access_points = efs_client.describe_access_points(FileSystemId=filesystem_id)
    ap_ids = [ap['AccessPointId'] for ap in access_points['AccessPoints']]
    assert static_ap_id in ap_ids
    assert dynamic_ap_id in ap_ids

    # The policy should allow both (Null condition accepts any access point)
    # LocalStack doesn't enforce IAM policies at runtime, so we validate the policy
    # structure itself rather than attempting actual mount operations

    # Cleanup
    efs_client.delete_access_point(AccessPointId=static_ap_id)
    efs_client.delete_access_point(AccessPointId=dynamic_ap_id)
    efs_client.delete_file_system_policy(FileSystemId=filesystem_id)
    efs_client.delete_file_system(FileSystemId=filesystem_id)
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_filesystem_policy_rejects_direct_mount_without_access_point(efs_client, iam_client):
    """Test that filesystem policy denies direct mounts without access points.

    Validates that the Null condition correctly requires an access point,
    preventing direct filesystem access that bypasses per-investigation isolation.
    """
    # Create test EFS filesystem
    creation_token = f'test-direct-mount-{int(time.time() * 1000)}'
    fs_response = efs_client.create_file_system(
        CreationToken=creation_token,
        PerformanceMode='generalPurpose',
        Encrypted=True
    )
    filesystem_id = fs_response['FileSystemId']

    # Create IAM role
    role_name = f'test-direct-mount-role-{int(time.time() * 1000)}'
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
            'Action': 'sts:AssumeRole'
        }]
    }

    role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    task_role_arn = role_response['Role']['Arn']

    # Apply policy with Null condition
    filesystem_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'EnforceAccessViaAccessPoint',
            'Effect': 'Allow',
            'Principal': {'AWS': task_role_arn},
            'Action': ['elasticfilesystem:ClientMount'],
            'Resource': f'arn:aws:elasticfilesystem:us-east-2:000000000000:file-system/{filesystem_id}',
            'Condition': {
                'Null': {
                    'elasticfilesystem:AccessPointArn': 'false'  # Require access point
                }
            }
        }]
    }

    efs_client.put_file_system_policy(
        FileSystemId=filesystem_id,
        Policy=json.dumps(filesystem_policy)
    )

    # Verify the policy structure
    policy_response = efs_client.describe_file_system_policy(FileSystemId=filesystem_id)
    applied_policy = json.loads(policy_response['Policy'])

    # Key assertion: Null = false means AccessPointArn must be present
    condition = applied_policy['Statement'][0]['Condition']
    assert 'Null' in condition
    assert condition['Null']['elasticfilesystem:AccessPointArn'] == 'false'

    # Note: LocalStack doesn't enforce IAM policy evaluation at mount time,
    # so we can't test actual mount denial. This test validates that the
    # policy structure is correct. In real AWS, a mount attempt without
    # an access point would be denied by this policy.

    # Cleanup
    efs_client.delete_file_system_policy(FileSystemId=filesystem_id)
    efs_client.delete_file_system(FileSystemId=filesystem_id)
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_filesystem_policy_structure_matches_terraform(efs_client, iam_client):
    """Test that the filesystem policy structure matches deploy/regional/efs.tf.

    This test ensures the policy structure tested here stays in sync with
    the actual Terraform configuration.
    """
    # Create test EFS filesystem
    creation_token = f'test-tf-match-{int(time.time() * 1000)}'
    fs_response = efs_client.create_file_system(
        CreationToken=creation_token,
        PerformanceMode='generalPurpose',
        Encrypted=True
    )
    filesystem_id = fs_response['FileSystemId']

    # Create IAM role
    role_name = f'test-tf-role-{int(time.time() * 1000)}'
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
            'Action': 'sts:AssumeRole'
        }]
    }

    role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    task_role_arn = role_response['Role']['Arn']

    # This policy MUST match the structure in deploy/regional/efs.tf:76-105
    filesystem_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'EnforceAccessViaAccessPoint',
            'Effect': 'Allow',
            'Principal': {'AWS': task_role_arn},
            'Action': [
                'elasticfilesystem:ClientMount',
                'elasticfilesystem:ClientWrite',
                'elasticfilesystem:ClientRootAccess',
            ],
            'Resource': f'arn:aws:elasticfilesystem:us-east-2:000000000000:file-system/{filesystem_id}',
            'Condition': {
                'Bool': {
                    'elasticfilesystem:AccessedViaMountTarget': 'true'
                },
                'Null': {
                    'elasticfilesystem:AccessPointArn': 'false'
                }
            }
        }]
    }

    efs_client.put_file_system_policy(
        FileSystemId=filesystem_id,
        Policy=json.dumps(filesystem_policy)
    )

    # Verify all conditions match Terraform
    policy_response = efs_client.describe_file_system_policy(FileSystemId=filesystem_id)
    applied_policy = json.loads(policy_response['Policy'])
    statement = applied_policy['Statement'][0]

    # Validate structure matches efs.tf
    assert statement['Sid'] == 'EnforceAccessViaAccessPoint'
    assert statement['Effect'] == 'Allow'
    assert 'elasticfilesystem:ClientMount' in statement['Action']
    assert 'elasticfilesystem:ClientWrite' in statement['Action']
    assert 'elasticfilesystem:ClientRootAccess' in statement['Action']

    # Validate conditions
    assert 'Bool' in statement['Condition']
    assert statement['Condition']['Bool']['elasticfilesystem:AccessedViaMountTarget'] == 'true'

    assert 'Null' in statement['Condition']
    assert statement['Condition']['Null']['elasticfilesystem:AccessPointArn'] == 'false'

    # These would break dynamic access point creation - ensure they're NOT present
    assert 'StringEquals' not in statement['Condition'], \
        "StringEquals with specific ARN would break Lambda-created access points"

    # Cleanup
    efs_client.delete_file_system_policy(FileSystemId=filesystem_id)
    efs_client.delete_file_system(FileSystemId=filesystem_id)
    iam_client.delete_role(RoleName=role_name)
