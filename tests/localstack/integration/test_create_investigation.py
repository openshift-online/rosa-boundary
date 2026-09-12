"""Integration tests for the create-investigation Lambda handler.

Exercises the handler's AWS-facing logic (ECS, EFS, STS) end-to-end through
LocalStack, complementing the unit tests that mock all AWS calls.

The handler creates module-level boto3 clients and reads environment variables at
import time, so AWS_ENDPOINT_URL and all required env vars must be set before the
module is loaded via importlib. The load_handler() helper manages this.
"""

import importlib.util
import json
import logging
import os
import time
from unittest.mock import patch

import pytest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOCALSTACK_ENDPOINT = os.getenv('LOCALSTACK_ENDPOINT', 'http://localhost:4566')
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-2')
ECS_EXECUTOR = os.getenv('ECS_EXECUTOR', 'local')

# Mock OIDC claims returned by the patched validate_oidc_token
MOCK_CLAIMS = {
    'sub': 'test-user-id',
    'preferred_username': 'test-sre',
    'email': 'test-sre@example.com',
    'groups': ['sre-team'],
    'https://aws.amazon.com/tags': {
        'principal_tags': {
            'username': ['test-sre']
        }
    }
}


# ---------------------------------------------------------------------------
# Handler loader
# ---------------------------------------------------------------------------

def load_handler(env_overrides=None):
    """Load the create-investigation handler module with LocalStack-aware env vars.

    Must be called AFTER test-specific env vars are set, because the handler reads
    environment variables and creates boto3 clients at module level.

    Args:
        env_overrides: Optional dict of env vars to set before loading.

    Returns:
        The loaded handler module.
    """
    # Ensure boto3 clients inside the handler connect to LocalStack
    os.environ.setdefault('AWS_ENDPOINT_URL', LOCALSTACK_ENDPOINT)
    os.environ.setdefault('AWS_DEFAULT_REGION', AWS_REGION)
    os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
    os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')

    if env_overrides:
        os.environ.update(env_overrides)

    handler_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../../../lambda/create-investigation/handler.py')
    )
    # Each call gets a unique module name so Python's import system treats it as a
    # fresh module. The handler creates boto3 clients and reads env vars at module
    # scope, so we need a full re-execution — not importlib.reload(), which can
    # skip re-initialization in some edge cases.
    module_name = f'create_investigation_handler_{int(time.time() * 1000)}'
    spec = importlib.util.spec_from_file_location(module_name, handler_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_event(body_dict, token='mock-oidc-token'):
    """Build a Lambda Function URL event."""
    event = {
        'requestContext': {
            'http': {
                'method': 'POST',
                'path': '/',
            }
        },
        'headers': {
            'content-type': 'application/json',
        },
        'body': json.dumps(body_dict),
        'isBase64Encoded': False,
    }
    if token:
        event['headers']['x-oidc-token'] = token
    return event


def invoke_handler(handler_env, ecs_cleanup, *, cluster_id, investigation_id,
                   skip_task=True, task_timeout=None, expected_status=200):
    """Load the handler, patch OIDC validation, invoke, and parse the response.

    Registers created resources (access points, task defs, tasks) with
    ecs_cleanup for automatic teardown.

    Returns:
        (handler_module, response_body_dict)
    """
    handler = load_handler(handler_env['env'])
    body_dict = {
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
    }
    if skip_task:
        body_dict['skip_task'] = True
    if task_timeout is not None:
        body_dict['task_timeout'] = task_timeout

    with patch.object(handler, 'validate_oidc_token', return_value=MOCK_CLAIMS):
        event = make_event(body_dict)
        result = handler.lambda_handler(event, None)

    assert result['statusCode'] == expected_status, (
        f"Expected {expected_status}, got {result['statusCode']}: {result['body']}"
    )
    body = json.loads(result['body'])

    # Register created resources for cleanup
    if body.get('access_point_id'):
        ecs_cleanup.register_access_point(body['access_point_id'])
    if body.get('task_definition_arn'):
        ecs_cleanup.register_task_definition(body['task_definition_arn'])
    if body.get('task_arn'):
        ecs_cleanup.register_task(handler_env['cluster_name'], body['task_arn'])

    return handler, body


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def handler_env(test_vpc, test_efs, ecs_client, iam_client, ecs_cleanup):
    """Set up infrastructure and env vars required by the handler.

    Creates an ECS cluster, IAM roles, and a base task definition, then
    returns a dict of environment variable overrides for load_handler().
    """
    ts = int(time.time())
    cluster_name = f'test-create-inv-{ts}'
    base_task_family = f'rosa-boundary-base-{ts}'

    # ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # IAM execution role
    exec_role_name = f'test-exec-role-{ts}'
    trust_policy = json.dumps({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
            'Action': 'sts:AssumeRole'
        }]
    })
    exec_role = iam_client.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=trust_policy,
    )
    exec_role_arn = exec_role['Role']['Arn']
    ecs_cleanup.register_role(exec_role_name, [])

    # IAM task role
    task_role_name = f'test-task-role-{ts}'
    task_role = iam_client.create_role(
        RoleName=task_role_name,
        AssumeRolePolicyDocument=trust_policy,
    )
    task_role_arn = task_role['Role']['Arn']
    ecs_cleanup.register_role(task_role_name, [])

    # Base task definition (the handler clones this into per-investigation defs)
    base_td = ecs_client.register_task_definition(
        family=base_task_family,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        executionRoleArn=exec_role_arn,
        taskRoleArn=task_role_arn,
        containerDefinitions=[{
            'name': 'rosa-boundary',
            'image': 'test-image:latest',
            'essential': True,
            'linuxParameters': {'initProcessEnabled': True},
            'environment': [],
        }],
    )
    base_td_arn = base_td['taskDefinition']['taskDefinitionArn']
    ecs_cleanup.register_task_definition(base_td_arn)

    subnets_csv = ','.join(test_vpc['subnet_ids'])

    env = {
        'KEYCLOAK_URL': 'http://localhost:8080',
        'KEYCLOAK_REALM': 'sre-ops',
        'KEYCLOAK_CLIENT_ID': 'rosa-boundary',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123456789012:oidc-provider/localhost',
        'ECS_CLUSTER': cluster_name,
        'TASK_DEFINITION': base_task_family,
        'SUBNETS': subnets_csv,
        'SECURITY_GROUP': test_vpc['security_group_id'],
        'EFS_FILESYSTEM_ID': test_efs,
        'SHARED_ROLE_ARN': 'arn:aws:iam::123456789012:role/sre-shared-role',
        'REQUIRED_GROUPS': 'sre-team',
        'ABAC_TAG_KEY': 'username',
        'TASK_TIMEOUT_DEFAULT': '3600',
        'TASK_TIMEOUT_MINIMUM': '30',
        'S3_AUDIT_BUCKET': 'test-audit-bucket',
        'INVOKER_ROLE_ARN': 'arn:aws:iam::123456789012:role/lambda-invoker',
        'AWS_REGION': AWS_REGION,
        'AWS_ENDPOINT_URL': LOCALSTACK_ENDPOINT,
        'AWS_DEFAULT_REGION': AWS_REGION,
        'AWS_ACCESS_KEY_ID': 'test',
        'AWS_SECRET_ACCESS_KEY': 'test',
    }

    return {
        'env': env,
        'cluster_name': cluster_name,
        'base_task_family': base_task_family,
        'exec_role_arn': exec_role_arn,
        'task_role_arn': task_role_arn,
    }


# ---------------------------------------------------------------------------
# Tests — non-slow (no ECS task launch required)
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_create_investigation_creates_efs_access_point(
    handler_env, efs_client, ecs_cleanup
):
    """Handler creates an EFS access point with correct path, POSIX user, and tags."""
    cluster_id = 'test-cluster-ap'
    investigation_id = f'inv-ap-{int(time.time())}'

    _, body = invoke_handler(handler_env, ecs_cleanup,
                             cluster_id=cluster_id, investigation_id=investigation_id)
    ap_id = body['access_point_id']
    assert ap_id, "access_point_id should not be empty"

    # Verify the access point via EFS API
    ap_resp = efs_client.describe_access_points(AccessPointId=ap_id)
    ap = ap_resp['AccessPoints'][0]

    assert ap['RootDirectory']['Path'] == f'/{cluster_id}/{investigation_id}'
    assert ap['PosixUser']['Uid'] == 1000
    assert ap['PosixUser']['Gid'] == 1000

    tag_dict = {t['Key']: t['Value'] for t in ap.get('Tags', [])}
    assert tag_dict.get('ClusterID') == cluster_id
    assert tag_dict.get('InvestigationID') == investigation_id
    assert tag_dict.get('username') == 'test-sre'
    assert tag_dict.get('ManagedBy') == 'rosa-boundary-lambda'


@pytest.mark.integration
def test_create_investigation_registers_task_definition(
    handler_env, ecs_client, ecs_cleanup
):
    """Handler registers a per-investigation task def with correct family, EFS volume, and env vars.

    Strategy: use skip_task=True to create the access point (prerequisite), then call
    register_investigation_task_definition() directly. This avoids run_task side effects
    in the local executor while still exercising real task definition registration
    against LocalStack's ECS API.
    """
    cluster_id = 'test-cluster-td'
    investigation_id = f'inv-td-{int(time.time())}'

    handler, body = invoke_handler(handler_env, ecs_cleanup,
                                   cluster_id=cluster_id, investigation_id=investigation_id)
    ap_id = body['access_point_id']

    # Call register_investigation_task_definition directly (see docstring for why)
    td_arn = handler.register_investigation_task_definition(
        task_def=handler_env['base_task_family'],
        cluster_id=cluster_id,
        investigation_id=investigation_id,
        access_point_id=ap_id,
        efs_filesystem_id=handler_env['env']['EFS_FILESYSTEM_ID'],
        oc_version='4.18',
        task_timeout=1800,
        s3_audit_bucket='test-audit-bucket',
        aws_region=AWS_REGION,
        aws_account_id='123456789012',
    )
    ecs_cleanup.register_task_definition(td_arn)

    # Verify the registered task definition
    td_resp = ecs_client.describe_task_definition(taskDefinition=td_arn)
    td = td_resp['taskDefinition']

    # Family name pattern: {base}-{cluster_id}-{investigation_id}-{timestamp}
    assert cluster_id in td['family']
    assert investigation_id in td['family']

    # EFS volume with the per-investigation access point
    efs_volumes = [v for v in td.get('volumes', []) if 'efsVolumeConfiguration' in v]
    assert len(efs_volumes) >= 1, "Should have at least one EFS volume"
    efs_vol = efs_volumes[0]
    assert efs_vol['efsVolumeConfiguration']['fileSystemId'] == handler_env['env']['EFS_FILESYSTEM_ID']
    assert efs_vol['efsVolumeConfiguration']['authorizationConfig']['accessPointId'] == ap_id

    # Environment variables baked into the rosa-boundary container
    rosa_container = next(
        (c for c in td['containerDefinitions'] if c['name'] == 'rosa-boundary'), None
    )
    assert rosa_container is not None, "rosa-boundary container not found in task def"
    env_dict = {e['name']: e['value'] for e in rosa_container.get('environment', [])}
    assert env_dict.get('CLUSTER_ID') == cluster_id
    assert env_dict.get('INVESTIGATION_ID') == investigation_id
    assert env_dict.get('OC_VERSION') == '4.18'
    assert env_dict.get('TASK_TIMEOUT') == '1800'
    assert env_dict.get('S3_AUDIT_BUCKET') == 'test-audit-bucket'


@pytest.mark.integration
def test_skip_task_creates_access_point_only(
    handler_env, ecs_client, efs_client, ecs_cleanup
):
    """skip_task=True creates an EFS access point but does NOT register a task def or launch a task."""
    cluster_id = 'test-cluster-skip'
    investigation_id = f'inv-skip-{int(time.time())}'

    _, body = invoke_handler(handler_env, ecs_cleanup,
                             cluster_id=cluster_id, investigation_id=investigation_id)

    assert body['task_arn'] == '', "task_arn should be empty when skip_task=True"
    assert body['task_definition_arn'] == '', "task_definition_arn should be empty when skip_task=True"
    assert body['access_point_id'], "access_point_id should be set"

    # Verify the access point exists
    ap_resp = efs_client.describe_access_points(AccessPointId=body['access_point_id'])
    assert len(ap_resp['AccessPoints']) == 1

    # Verify NO per-investigation task definitions were registered beyond the base
    families = ecs_client.list_task_definition_families(
        familyPrefix=f"{handler_env['base_task_family']}-{cluster_id}"
    )
    assert len(families.get('families', [])) == 0, (
        "No per-investigation task definition should be registered when skip_task=True"
    )


@pytest.mark.integration
def test_idempotent_access_point_reuse(
    handler_env, efs_client, ecs_cleanup
):
    """Second invocation for the same cluster/investigation reuses the existing access point."""
    cluster_id = 'test-cluster-idem'
    investigation_id = f'inv-idem-{int(time.time())}'

    # First invocation — creates the access point
    _, body1 = invoke_handler(handler_env, ecs_cleanup,
                              cluster_id=cluster_id, investigation_id=investigation_id)

    # Second invocation — should reuse the same access point
    _, body2 = invoke_handler(handler_env, ecs_cleanup,
                              cluster_id=cluster_id, investigation_id=investigation_id)

    assert body1['access_point_id'] == body2['access_point_id'], (
        f"Expected same access point ID, got {body1['access_point_id']} and {body2['access_point_id']}"
    )

    # Verify only one access point exists for this cluster/investigation
    all_aps = efs_client.describe_access_points(
        FileSystemId=handler_env['env']['EFS_FILESYSTEM_ID']
    )
    matching = [
        ap for ap in all_aps['AccessPoints']
        if ap['RootDirectory']['Path'] == f'/{cluster_id}/{investigation_id}'
    ]
    assert len(matching) == 1, f"Expected 1 access point, found {len(matching)}"


# ---------------------------------------------------------------------------
# Tests — slow (require ECS task launch / ECS_EXECUTOR != local)
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.skipif(
    ECS_EXECUTOR == 'local',
    reason=f'ECS_EXECUTOR=local: tasks are not fully executed (current: {ECS_EXECUTOR})'
)
def test_create_investigation_launches_ecs_task(
    handler_env, ecs_client, ecs_cleanup
):
    """Full invocation with mocked OIDC token launches an ECS task with correct tags.

    Also validates:
    - startedBy matches the deterministic investigation_started_by() format
    - deadline tag is present and within a few seconds of now + task_timeout
    """
    from datetime import datetime, timedelta

    cluster_id = 'test-cluster-run'
    investigation_id = f'inv-run-{int(time.time())}'
    task_timeout = 1800

    # Bracket the invocation with timestamps to verify deadline arithmetic
    before = datetime.utcnow()
    handler, body = invoke_handler(handler_env, ecs_cleanup,
                                   cluster_id=cluster_id, investigation_id=investigation_id,
                                   skip_task=False, task_timeout=task_timeout)
    after = datetime.utcnow()

    task_arn = body['task_arn']
    assert task_arn, "task_arn should not be empty"

    # Verify task tags via describe_tasks
    desc = ecs_client.describe_tasks(
        cluster=handler_env['cluster_name'],
        tasks=[task_arn],
        include=['TAGS'],
    )
    assert len(desc['tasks']) == 1
    task = desc['tasks'][0]
    tag_dict = {t['key']: t['value'] for t in task.get('tags', [])}

    assert tag_dict.get('cluster_id') == cluster_id
    assert tag_dict.get('investigation_id') == investigation_id
    assert tag_dict.get('username') == 'test-sre'
    assert tag_dict.get('oc_version') == '4.20'  # default
    assert tag_dict.get('task_timeout') == str(task_timeout)

    # Deadline tag arithmetic
    assert 'deadline' in tag_dict, f"Expected 'deadline' tag, got tags: {list(tag_dict.keys())}"
    deadline = datetime.fromisoformat(tag_dict['deadline'])
    expected_earliest = before + timedelta(seconds=task_timeout)
    expected_latest = after + timedelta(seconds=task_timeout)
    assert expected_earliest <= deadline <= expected_latest, (
        f"Deadline {deadline} not within expected range [{expected_earliest}, {expected_latest}]"
    )

    # startedBy matches the deterministic format
    expected_started_by = handler.investigation_started_by(cluster_id, investigation_id)
    assert task.get('startedBy') == expected_started_by


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.skipif(
    ECS_EXECUTOR == 'local',
    reason=f'ECS_EXECUTOR=local: tasks never reach RUNNING so duplicate check finds 0 tasks (current: {ECS_EXECUTOR})'
)
def test_duplicate_investigation_returns_409(
    handler_env, ecs_client, ecs_cleanup
):
    """Creating a second task for the same investigation returns 409."""
    cluster_id = 'test-cluster-dup'
    investigation_id = f'inv-dup-{int(time.time())}'

    # First invocation — launches a task
    _, body1 = invoke_handler(handler_env, ecs_cleanup,
                              cluster_id=cluster_id, investigation_id=investigation_id,
                              skip_task=False)

    # The duplicate check queries for RUNNING tasks with a matching startedBy
    # value. Wait for the first task to reach RUNNING before invoking again.
    task_arn = body1['task_arn']
    for _ in range(24):  # 24 × 5s = 120s max
        desc = ecs_client.describe_tasks(
            cluster=handler_env['cluster_name'], tasks=[task_arn]
        )
        if desc['tasks'][0].get('lastStatus') == 'RUNNING':
            break
        time.sleep(5)
    else:
        pytest.skip("Task never reached RUNNING — cannot test duplicate detection")

    # Second invocation — should get 409
    _, body2 = invoke_handler(handler_env, ecs_cleanup,
                              cluster_id=cluster_id, investigation_id=investigation_id,
                              skip_task=False, expected_status=409)
    assert 'already has a running task' in body2['error']
