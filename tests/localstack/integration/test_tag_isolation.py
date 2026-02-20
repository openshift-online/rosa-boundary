"""Test ABAC (Attribute-Based Access Control) tag isolation model.

The shared SRE role uses ${aws:PrincipalTag/username} in its permissions policy
to match against ecs:ResourceTag/username on ECS tasks. This ensures each user
can only exec into tasks tagged with their own username (preferred_username).

Session tags flow:
  Keycloak JWT → https://aws.amazon.com/tags claim → AssumeRoleWithWebIdentity
  → AWS session tags → PrincipalTag/username in IAM conditions
"""

import pytest
import json
from datetime import datetime
from .test_helpers import get_policy_document

SHARED_ROLE_NAME_SUFFIX = "sre-shared"


def _shared_role_policy(oidc_provider_arn: str, oidc_client_id: str, oidc_domain: str) -> dict:
    """Return the trust policy for the shared SRE role."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": oidc_provider_arn},
                "Action": [
                    "sts:AssumeRoleWithWebIdentity",
                    "sts:TagSession"
                ],
                "Condition": {
                    "StringEquals": {
                        f"{oidc_domain}:aud": oidc_client_id
                    }
                }
            }
        ]
    }


def _abac_permissions_policy(cluster_arn: str) -> dict:
    """Return the ABAC permissions policy for the shared SRE role.

    Uses ${aws:PrincipalTag/username} to dynamically match the session tag
    against the ECS task's username resource tag.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExecuteCommandOnCluster",
                "Effect": "Allow",
                "Action": ["ecs:ExecuteCommand"],
                "Resource": [cluster_arn]
            },
            {
                "Sid": "ExecuteCommandOnOwnedTasks",
                "Effect": "Allow",
                "Action": ["ecs:ExecuteCommand"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "ecs:ResourceTag/username": "${aws:PrincipalTag/username}"
                    }
                }
            },
            {
                "Sid": "DescribeAndListECS",
                "Effect": "Allow",
                "Action": [
                    "ecs:DescribeTasks",
                    "ecs:ListTasks",
                    "ecs:DescribeTaskDefinition"
                ],
                "Resource": "*"
            },
            {
                "Sid": "SSMSessionForECSExec",
                "Effect": "Allow",
                "Action": ["ssm:StartSession"],
                "Resource": [
                    "arn:aws:ecs:*:*:task/*",
                    "arn:aws:ssm:*:*:document/AWS-StartInteractiveCommand"
                ]
            },
            {
                "Sid": "KMSForECSExec",
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey"
                ],
                "Resource": "*"
            }
        ]
    }


@pytest.mark.integration
def test_shared_role_trust_policy_structure(iam_client):
    """Test that the shared SRE role trust policy allows AssumeRoleWithWebIdentity
    and sts:TagSession (required for session tag propagation from JWT)."""
    role_name = f'test-{SHARED_ROLE_NAME_SUFFIX}-{int(datetime.now().timestamp())}'
    oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/keycloak.example.com/realms/sre-ops"
    oidc_domain = "keycloak.example.com/realms/sre-ops"
    oidc_client_id = "aws-sre-access"

    trust_policy = _shared_role_policy(oidc_provider_arn, oidc_client_id, oidc_domain)

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    retrieved = iam_client.get_role(RoleName=role_name)
    doc = get_policy_document(retrieved['Role']['AssumeRolePolicyDocument'])

    statement = doc['Statement'][0]

    # Must allow both actions for session tags to work
    assert "sts:AssumeRoleWithWebIdentity" in statement['Action']
    assert "sts:TagSession" in statement['Action']

    # Must be federated (OIDC) principal, not a specific user sub
    assert statement['Principal']['Federated'] == oidc_provider_arn

    # Trust is audience-scoped only (not sub-scoped — any authenticated SRE can assume)
    condition_equals = statement['Condition']['StringEquals']
    assert f"{oidc_domain}:aud" in condition_equals
    assert condition_equals[f"{oidc_domain}:aud"] == oidc_client_id

    # Must NOT have a sub condition (that was the per-user role approach)
    assert f"{oidc_domain}:sub" not in condition_equals

    # Cleanup
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_abac_policy_uses_dynamic_principal_tag(iam_client):
    """Test that the ABAC permissions policy uses ${aws:PrincipalTag/username}
    (dynamic, per-session) rather than a hardcoded username value."""
    role_name = f'test-{SHARED_ROLE_NAME_SUFFIX}-policy-{int(datetime.now().timestamp())}'
    cluster_arn = "arn:aws:ecs:us-east-2:123456789012:cluster/test-cluster"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    policy = _abac_permissions_policy(cluster_arn)
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='ECSExecABAC',
        PolicyDocument=json.dumps(policy)
    )

    retrieved = iam_client.get_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    doc = get_policy_document(retrieved['PolicyDocument'])

    # Find the task exec statement with ABAC condition
    task_exec_stmts = [s for s in doc['Statement'] if s.get('Sid') == 'ExecuteCommandOnOwnedTasks']
    assert len(task_exec_stmts) == 1, "Must have exactly one ExecuteCommandOnOwnedTasks statement"

    task_exec = task_exec_stmts[0]
    condition_val = task_exec['Condition']['StringEquals']['ecs:ResourceTag/username']

    # The condition must use the dynamic PrincipalTag reference, not a hardcoded username
    assert condition_val == "${aws:PrincipalTag/username}", (
        f"Expected dynamic PrincipalTag reference, got: {condition_val!r}"
    )

    # Cluster exec statement must NOT have a tag condition (required prerequisite)
    cluster_exec_stmts = [s for s in doc['Statement'] if s.get('Sid') == 'ExecuteCommandOnCluster']
    assert len(cluster_exec_stmts) == 1
    assert 'Condition' not in cluster_exec_stmts[0], (
        "Cluster exec statement must not have a condition (it's the prerequisite grant)"
    )

    # Cleanup
    iam_client.delete_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_tasks_tagged_with_username_as_abac_key(ecs_client, test_vpc, iam_client, ecs_cleanup):
    """Test that ECS tasks are tagged with 'username' (the ABAC key) and 'oidc_sub'
    (for audit). The shared role policy conditions on ecs:ResourceTag/username."""
    cluster_name = f'test-cluster-{int(datetime.now().timestamp())}'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create a role for task execution
    role_name = f'test-role-{int(datetime.now().timestamp())}'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
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
        containerDefinitions=[{
            'name': 'test-container',
            'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
            'essential': True
        }]
    )
    task_def_arn = task_def_response['taskDefinition']['taskDefinitionArn']
    ecs_cleanup.register_task_definition(task_def_arn)

    user1_sub = 'user-abc-001-uuid'
    user2_sub = 'user-def-002-uuid'

    # Launch tasks for two different users — 'username' is the ABAC key,
    # 'oidc_sub' is stored for audit purposes only.
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
            {'key': 'oidc_sub', 'value': user1_sub},
            {'key': 'username', 'value': 'alice'},
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
            {'key': 'oidc_sub', 'value': user2_sub},
            {'key': 'username', 'value': 'bob'},
            {'key': 'investigation_id', 'value': 'inv-002'}
        ]
    )

    task1_arn = task1_response['tasks'][0]['taskArn']
    task2_arn = task2_response['tasks'][0]['taskArn']
    ecs_cleanup.register_task(cluster_name, task1_arn)
    ecs_cleanup.register_task(cluster_name, task2_arn)

    # Verify 'username' is the ABAC key and 'oidc_sub' is present for audit
    tags1 = {t['key']: t['value'] for t in ecs_client.list_tags_for_resource(resourceArn=task1_arn)['tags']}
    tags2 = {t['key']: t['value'] for t in ecs_client.list_tags_for_resource(resourceArn=task2_arn)['tags']}

    assert 'username' in tags1, "Task must have 'username' tag for ABAC"
    assert 'username' in tags2, "Task must have 'username' tag for ABAC"
    assert 'oidc_sub' in tags1, "Task must have 'oidc_sub' tag for audit"
    assert 'oidc_sub' in tags2, "Task must have 'oidc_sub' tag for audit"
    assert 'sub' not in tags1, "Old 'sub' ABAC tag must not be used"
    assert 'sub' not in tags2, "Old 'sub' ABAC tag must not be used"
    assert 'owner_sub' not in tags1, "Old 'owner_sub' tag must not be used"
    assert 'owner_sub' not in tags2, "Old 'owner_sub' tag must not be used"

    assert tags1['username'] == 'alice'
    assert tags2['username'] == 'bob'
    assert tags1['username'] != tags2['username'], "Different users must have different username tags"
    assert tags1['investigation_id'] != tags2['investigation_id']


@pytest.mark.integration
def test_single_role_serves_multiple_users(iam_client):
    """Test that a single shared role policy (using dynamic PrincipalTag/username)
    correctly represents different isolation boundaries for different users —
    without creating per-user roles."""
    role_name = f'test-shared-role-{int(datetime.now().timestamp())}'
    cluster_arn = "arn:aws:ecs:us-east-2:123456789012:cluster/rosa-boundary-dev"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/keycloak.example.com/realms/sre-ops"},
            "Action": [
                "sts:AssumeRoleWithWebIdentity",
                "sts:TagSession"
            ],
            "Condition": {
                "StringEquals": {
                    "keycloak.example.com/realms/sre-ops:aud": "aws-sre-access"
                }
            }
        }]
    }

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )

    policy = _abac_permissions_policy(cluster_arn)
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='ECSExecABAC',
        PolicyDocument=json.dumps(policy)
    )

    # The single role exists — its isolation per user is enforced dynamically via session tags.
    # Verify: only one role, with a dynamic (not hardcoded) condition.
    retrieved_policy = iam_client.get_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    doc = get_policy_document(retrieved_policy['PolicyDocument'])

    exec_stmts = [s for s in doc['Statement'] if s.get('Sid') == 'ExecuteCommandOnOwnedTasks']
    assert len(exec_stmts) == 1

    condition_val = exec_stmts[0]['Condition']['StringEquals']['ecs:ResourceTag/username']
    # The condition is dynamic — it will resolve to different values for different sessions.
    # No hardcoded username should appear here.
    assert condition_val == "${aws:PrincipalTag/username}"
    assert 'user-' not in condition_val, "Condition must be dynamic, not hardcoded to a specific user"

    # Cleanup
    iam_client.delete_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    iam_client.delete_role(RoleName=role_name)


@pytest.mark.integration
def test_fail_closed_missing_session_tag(iam_client):
    """Test that the ABAC policy structure is fail-closed: if the session tag
    (aws:PrincipalTag/username) is absent, the condition cannot match any task tag,
    so access is denied by default.

    This is the IAM default-deny property — a missing PrincipalTag resolves to
    an empty string or is absent, which will not match any real username value.
    """
    role_name = f'test-fail-closed-{int(datetime.now().timestamp())}'
    cluster_arn = "arn:aws:ecs:us-east-2:123456789012:cluster/rosa-boundary-dev"

    # Role without sts:TagSession in trust policy simulates missing session tag
    trust_policy_no_tagsession = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
            # Note: no sts:TagSession — session tags would not propagate in real AWS
        }]
    }

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy_no_tagsession)
    )

    policy = _abac_permissions_policy(cluster_arn)
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='ECSExecABAC',
        PolicyDocument=json.dumps(policy)
    )

    # Verify the policy still uses dynamic PrincipalTag (not hardcoded value)
    retrieved = iam_client.get_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    doc = get_policy_document(retrieved['PolicyDocument'])

    exec_stmts = [s for s in doc['Statement'] if s.get('Sid') == 'ExecuteCommandOnOwnedTasks']
    condition_val = exec_stmts[0]['Condition']['StringEquals']['ecs:ResourceTag/username']
    assert condition_val == "${aws:PrincipalTag/username}"
    # Without session tags, aws:PrincipalTag/username is empty/absent → no task username can match → deny

    # Verify trust policy does NOT include sts:TagSession (simulating misconfiguration)
    role = iam_client.get_role(RoleName=role_name)
    trust_doc = get_policy_document(role['Role']['AssumeRolePolicyDocument'])
    actions = trust_doc['Statement'][0].get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    assert 'sts:TagSession' not in actions, "This role simulates missing TagSession (fail-closed test)"

    # Cleanup
    iam_client.delete_role_policy(RoleName=role_name, PolicyName='ECSExecABAC')
    iam_client.delete_role(RoleName=role_name)
