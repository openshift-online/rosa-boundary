"""End-to-end investigation creation workflow test"""

import os
import time
import pytest
import json
from datetime import datetime

from .test_helpers import create_investigation_resources


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
    oidc_provider_arn = 'arn:aws:iam::123456789012:oidc-provider/keycloak.example.com/realms/sre-ops'
    oidc_domain = 'keycloak.example.com/realms/sre-ops'
    oidc_client_id = 'aws-sre-access'

    # Step 1: Create shared SRE role (single role for all SREs, ABAC-scoped via session tags)
    # This role is unique to the investigation creation test — the reaper test doesn't need it.
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

    # Steps 2-5: Create investigation infrastructure (ECS role, EFS AP, cluster, task def, task)
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        oidc_sub='test-user-e2e-123',
        username='sre-e2e-user',
        extra_env_vars=[{'name': 'OC_VERSION', 'value': '4.20'}],
    )

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
    access_points = efs_client.describe_access_points(
        AccessPointId=resources['access_point_id']
    )
    assert len(access_points['AccessPoints']) == 1

    # Verify task has correct tags (use describe_tasks, more reliable than list_tags_for_resource in LocalStack)
    desc = ecs_client.describe_tasks(
        cluster=resources['cluster_name'],
        tasks=[resources['task_arn']],
        include=['TAGS']
    )
    tag_dict = {t['key']: t['value'] for t in desc['tasks'][0].get('tags', [])}
    assert tag_dict['oidc_sub'] == resources['oidc_sub']
    assert tag_dict['username'] == resources['username']
    assert tag_dict['investigation_id'] == resources['investigation_id']

    # Verify task definition has EFS mount
    task_def = ecs_client.describe_task_definition(
        taskDefinition=resources['task_def_arn']
    )
    volumes = task_def['taskDefinition']['volumes']
    assert len(volumes) == 1
    assert volumes[0]['efsVolumeConfiguration']['fileSystemId'] == test_efs
    assert volumes[0]['efsVolumeConfiguration']['authorizationConfig']['accessPointId'] == resources['access_point_id']


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


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.slow
def test_investigation_with_reaper_enforcement(
    ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup
):
    """Chain investigation creation (EFS access point + ECS task with ABAC/deadline tags)
    with reaper enforcement to validate the full deadline tag lifecycle end-to-end.

    What this proves: the reaper correctly identifies an investigation task whose
    deadline tag (set at creation) is in the past, given the full tag set from the
    investigation creation flow.
    """
    from datetime import timedelta, timezone

    past_deadline = (
        datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    ).isoformat()

    # Steps 1-5: Create investigation infrastructure with a past deadline tag
    resources = create_investigation_resources(
        ecs_client, efs_client, iam_client, test_vpc, test_efs, ecs_cleanup,
        oidc_sub='test-user-reaper-e2e',
        username='sre-reaper-e2e',
        cluster_name_prefix='test-reaper-e2e',
        ecs_role_name_prefix='rosa-boundary-reaper-e2e',
        container_command=['sleep', '60'],
        extra_task_tags=[{'key': 'deadline', 'value': past_deadline}],
    )
    cluster_name = resources['cluster_name']
    task_arn = resources['task_arn']

    # Poll until task reaches RUNNING so the reaper's desiredStatus=RUNNING filter sees it
    deadline_tag_dict = {}
    for _ in range(24):  # up to 120s
        desc = ecs_client.describe_tasks(
            cluster=cluster_name, tasks=[task_arn], include=['TAGS']
        )
        task_state = desc['tasks'][0]
        deadline_tag_dict = {t['key']: t['value'] for t in task_state.get('tags', [])}
        if task_state.get('lastStatus') == 'RUNNING':
            break
        time.sleep(5)
    else:
        pytest.fail(f"Task never reached RUNNING; lastStatus={task_state.get('lastStatus')}")

    assert 'deadline' in deadline_tag_dict, \
        f"Expected 'deadline' tag, got tags: {list(deadline_tag_dict.keys())}"
    assert deadline_tag_dict['deadline'] == past_deadline

    # Step 6: Invoke reaper handler directly.
    # Load via explicit path to avoid sys.modules cache collisions between the two handler.py files.
    # ECS_CLUSTER is read at module level in handler.py — must be set before exec_module.
    import importlib.util
    _lambda_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../../../lambda/reap-tasks/handler.py')
    )
    _prev_cluster = os.environ.get('ECS_CLUSTER')
    try:
        os.environ['ECS_CLUSTER'] = cluster_name
        _spec = importlib.util.spec_from_file_location('reap_tasks_handler', _lambda_path)
        reaper_handler = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(reaper_handler)
        result = reaper_handler.lambda_handler({}, None)
        assert result['checked'] >= 1, f"Reaper should have checked at least one task, got: {result}"
        assert result['stopped'] >= 1, f"Reaper should have stopped the overdue task, got: {result}"
        assert 'error' not in result, f"Reaper returned an error: {result}"
    finally:
        if _prev_cluster is None:
            os.environ.pop('ECS_CLUSTER', None)
        else:
            os.environ['ECS_CLUSTER'] = _prev_cluster
