"""Regression coverage for close-investigation task-definition cleanup."""

import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import pytest


@pytest.fixture
def close_cli_env(localstack_cli_env, test_efs):
    """Create an isolated named deployment profile for the test-built CLI."""
    def configure(ecs_cluster):
        env = localstack_cli_env.copy()
        role_arn = env.pop('ROSA_BOUNDARY_SRE_ROLE_ARN')
        keycloak_url = env.pop('ROSA_BOUNDARY_KEYCLOAK_URL')
        realm = env.pop('ROSA_BOUNDARY_KEYCLOAK_REALM')
        client_id = env.pop('ROSA_BOUNDARY_OIDC_CLIENT_ID')
        env.pop('ROSA_BOUNDARY_AWS_REGION')
        env.pop('ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE')
        profile = {
            'account_id': role_arn.split(':')[4],
            'aws_region': env['AWS_DEFAULT_REGION'],
            'keycloak_url': keycloak_url,
            'keycloak_realm': realm,
            'oidc_client_id': client_id,
            'oidc_use_device_code': False,
            'sre_role_arn': role_arn,
            'ecs_cluster_name': ecs_cluster,
            'efs_filesystem_id': test_efs,
        }
        config_path = Path(env['XDG_CONFIG_HOME']) / 'rosa-boundary' / 'config.yaml'
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # JSON is valid YAML; avoid depending on a YAML emitter in the fixture.
        config_path.write_text(json.dumps({
            'active_profile': 'localstack-close',
            'profiles': {'localstack-close': profile},
        }), encoding='utf-8')
        config_path.chmod(0o600)
        return env

    return configure


def _load_sre_policy_source():
    """Load the Terraform source for the shared SRE permissions policy."""
    test_dir = Path(__file__).resolve().parent
    repo_root = test_dir.parents[2]
    iam_path = repo_root / 'deploy' / 'regional' / 'iam.tf'
    return iam_path.read_text(encoding='utf-8')


def _policy_statement(policy_source, sid):
    """Extract a statement without depending on Terraform's whitespace alignment."""
    start = re.search(rf'Sid\s*=\s*"{sid}"', policy_source)
    assert start is not None, f'Missing IAM statement: {sid}'
    next_sid = re.search(r'\bSid\s*=', policy_source[start.end():])
    assert next_sid is not None, f'Missing statement after: {sid}'
    return policy_source[start.start():start.end() + next_sid.start()]


@pytest.mark.integration
def test_close_rejects_invalid_config_without_mutation(tmp_path, localstack_cli_binary):
    """Invalid profile configuration fails validation before any AWS mutation."""
    config_path = tmp_path / 'rosa-boundary' / 'config.yaml'
    config_path.parent.mkdir()
    invalid = 'aws_region: us-east-2\necs_cluster_name: old-deployment\nefs_filesystem_id: fs-old\n'
    config_path.write_text(invalid, encoding='utf-8')
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('AWS_', 'ROSA_BOUNDARY_'))}
    env['XDG_CONFIG_HOME'] = str(tmp_path)
    result = subprocess.run([
        str(localstack_cli_binary), 'investigation', 'close',
        'my-cluster', 'my-investigation', '--yes',
    ], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'field aws_region not found' in result.stderr
    assert config_path.read_text(encoding='utf-8') == invalid


@pytest.mark.integration
def test_sre_policy_allows_task_definition_cleanup():
    """Ensure the shared SRE role can list and deregister task definitions."""
    policy_source = _load_sre_policy_source()
    assert 'role = data.aws_iam_role.sre_shared.id' in policy_source
    statement = _policy_statement(policy_source, 'DescribeListAndCleanupECS')

    assert re.search(r'Effect\s*=\s*"Allow"', statement)
    assert re.search(r'Resource\s*=\s*"\*"', statement)
    assert '"ecs:ListTaskDefinitions"' in statement
    assert '"ecs:DeregisterTaskDefinition"' in statement
    assert not re.search(r'Sid\s*=\s*"DeregisterTaskDefinition"', policy_source)


@pytest.mark.integration
def test_sre_policy_allows_scoped_access_point_deletion():
    """The shared SRE role must be able to delete ROSA Boundary-managed EFS
    access points (ROSAENG-66963), but only those — not arbitrary access points.

    IAM itself does not scope deletion per-investigation or per-caller, even
    though the CLI also checks ownership. IAM scopes deletion to Boundary-managed
    access points via the ManagedBy tag the Lambda applies at creation time.
    """
    policy_source = _load_sre_policy_source()
    statement = _policy_statement(policy_source, 'EFSDeleteManagedAccessPoints')

    # DeleteAccessPoint is granted...
    assert 'elasticfilesystem:DeleteAccessPoint' in statement
    assert re.search(r'Effect\s*=\s*"Allow"', statement)

    # ...but NOT against every access point in the account. It must target the
    # access-point resource type (not the file-system ARN, not "*") ...
    assert ':access-point/*"' in statement
    assert not re.search(r'Resource\s*=\s*"\*"', statement)

    # ...and it must be restricted to Boundary-managed access points via the
    # authoritative ManagedBy tag (see lambda/create-investigation/handler.py),
    # so unrelated / non-Boundary access points are not deletable.
    assert '"aws:ResourceTag/ManagedBy" = "rosa-boundary-lambda"' in statement


@pytest.mark.integration
def test_close_cleanup_lists_and_deregisters_task_definitions(ecs_client, ecs_cleanup):
    """Exercise the ECS list/deregister sequence used by close-investigation."""
    timestamp = int(datetime.now().timestamp())
    family = f'rosa-boundary-dev-cluster-{timestamp}-investigation'
    task_definition_arns = []

    for _ in range(2):
        response = ecs_client.register_task_definition(
            family=family,
            networkMode='awsvpc',
            requiresCompatibilities=['FARGATE'],
            cpu='256',
            memory='512',
            containerDefinitions=[{
                'name': 'test-container',
                'image': 'public.ecr.aws/docker/library/alpine:latest',
            }]
        )
        task_definition_arn = response['taskDefinition']['taskDefinitionArn']
        task_definition_arns.append(task_definition_arn)
        ecs_cleanup.register_task_definition(task_definition_arn)

    list_response = ecs_client.list_task_definitions(
        familyPrefix=family,
        status='ACTIVE'
    )
    listed_arns = list_response.get('taskDefinitionArns', [])

    assert set(task_definition_arns).issubset(listed_arns)

    for task_definition_arn in listed_arns:
        ecs_client.deregister_task_definition(taskDefinition=task_definition_arn)

    for task_definition_arn in task_definition_arns:
        describe_response = ecs_client.describe_task_definition(
            taskDefinition=task_definition_arn
        )
        assert describe_response['taskDefinition']['status'] == 'INACTIVE'


@pytest.mark.integration
def test_close_cleanup_family_prefix_excludes_other_investigations(ecs_client, ecs_cleanup):
    """Ensure the familyPrefix limits cleanup to the requested investigation."""
    timestamp = int(datetime.now().timestamp())
    target_family = f'rosa-boundary-dev-cluster-{timestamp}-target'
    other_family = f'rosa-boundary-dev-cluster-{timestamp}-other'
    families = [target_family, other_family]

    for family in families:
        response = ecs_client.register_task_definition(
            family=family,
            networkMode='awsvpc',
            requiresCompatibilities=['FARGATE'],
            cpu='256',
            memory='512',
            containerDefinitions=[{
                'name': 'test-container',
                'image': 'public.ecr.aws/docker/library/alpine:latest',
            }]
        )
        ecs_cleanup.register_task_definition(
            response['taskDefinition']['taskDefinitionArn']
        )

    list_response = ecs_client.list_task_definitions(
        familyPrefix=target_family,
        status='ACTIVE'
    )
    listed_families = {
        re.search(r'/([^/]+):\d+$', arn).group(1)
        for arn in list_response.get('taskDefinitionArns', [])
    }

    assert target_family in listed_families
    assert other_family not in listed_families

@pytest.mark.integration
def test_close_investigation_requires_cluster_and_closes_exact_target(ecs_client, efs_client, test_efs, ecs_cleanup, close_cli_env, localstack_cli_binary):
    """
    The CLI must require a cluster even when only one investigation matches,
    then close exactly the explicitly selected target.
    """

    investigation_id = f"test-inv-{int(datetime.now().timestamp())}"
    cluster_id = f"test-cluster-{int(datetime.now().timestamp())}"
    cluster_name = "test-cluster-name"

    # Create the ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create the access point to simulate a live investigation
    response = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': f'/{cluster_id}/{investigation_id}',
            'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'}
        },
        Tags=[
            {'Key': 'InvestigationID', 'Value': investigation_id},
            {'Key': 'ClusterID', 'Value': cluster_id},
            {'Key': 'oidc_sub', 'Value': 'localstack-test-sre'},
            {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
        ]
    )
    ap_id = response['AccessPointId']
    ecs_cleanup.register_access_point(ap_id)

    # Match Lambda's family convention and EFS mount. The CLI must select the
    # target definition, but neither an adjacent investigation nor a definition
    # in the same family with a different access point.
    stamp = datetime.now().strftime('%Y%m%dT%H%M%S')
    family = f'{cluster_name}-{cluster_id}-{investigation_id}-{stamp}'

    def register_home_definition(name, mount_ap):
        registered = ecs_client.register_task_definition(
            family=name, networkMode='awsvpc', requiresCompatibilities=['FARGATE'],
            cpu='256', memory='512',
            containerDefinitions=[{
                'name': 'rosa-boundary',
                'image': 'public.ecr.aws/docker/library/alpine:latest',
                'mountPoints': [{'sourceVolume': 'sre-home', 'containerPath': '/home/sre'}],
            }],
            volumes=[{
                'name': 'sre-home',
                'efsVolumeConfiguration': {
                    'fileSystemId': test_efs,
                    'authorizationConfig': {'accessPointId': mount_ap, 'iam': 'ENABLED'},
                    'transitEncryption': 'ENABLED',
                },
            }],
        )['taskDefinition']['taskDefinitionArn']
        ecs_cleanup.register_task_definition(registered)
        return registered

    target_definition = register_home_definition(family, ap_id)
    other_definition = register_home_definition(family, 'fsap-other')
    adjacent_definition = register_home_definition(f'{family}-extra', ap_id)
    # LocalStack matches exact family names but not partial familyPrefix queries.
    # The localstack-tagged CLI instead scans ACTIVE definitions and filters them.
    listed = ecs_client.list_task_definitions(familyPrefix=family)
    assert target_definition in listed['taskDefinitionArns']
    target_volume = ecs_client.describe_task_definition(taskDefinition=target_definition)['taskDefinition']['volumes'][0]
    assert target_volume['efsVolumeConfiguration']['authorizationConfig']['accessPointId'] == ap_id

    env = close_cli_env(cluster_name)

    bin_path = localstack_cli_binary

    # A missing cluster ID must fail before deleting even a unique match.
    missing_cluster = subprocess.run([
        str(bin_path), '--profile', 'localstack-close',
        'investigation', 'close', investigation_id, '--yes',
    ], env=env, capture_output=True, text=True, timeout=10)
    assert missing_cluster.returncode != 0
    assert 'missing required argument <investigation-id>' in missing_cluster.stderr.lower()
    assert ap_id in [ap['AccessPointId'] for ap in efs_client.describe_access_points(FileSystemId=test_efs)['AccessPoints']]

    # An idle investigation owned by another identity cannot be closed.
    efs_client.tag_resource(ResourceId=ap_id, Tags=[{'Key': 'oidc_sub', 'Value': 'another-sre'}])
    not_owner = subprocess.run([
        str(bin_path), '--profile', 'localstack-close', 'investigation', 'close',
        cluster_id, investigation_id, '--yes',
    ], env=env, capture_output=True, text=True, timeout=10)
    assert not_owner.returncode != 0
    assert 'owner' in not_owner.stderr.lower()
    assert ap_id in [ap['AccessPointId'] for ap in efs_client.describe_access_points(FileSystemId=test_efs)['AccessPoints']]
    efs_client.tag_resource(ResourceId=ap_id, Tags=[{'Key': 'oidc_sub', 'Value': 'localstack-test-sre'}])

    preview = subprocess.run([
        str(bin_path), '--profile', 'localstack-close', 'investigation', 'close',
        cluster_id, investigation_id, '--dry-run', '-o', 'json',
    ], env=env, capture_output=True, text=True, timeout=10)
    assert preview.returncode == 0, preview.stderr
    plan = json.loads(preview.stdout)
    assert plan['access_point_id'] == ap_id
    assert plan['task_definitions_to_deregister'] == [target_definition], plan
    assert ap_id in [ap['AccessPointId'] for ap in efs_client.describe_access_points(FileSystemId=test_efs)['AccessPoints']]

    # Run the close command with the required cluster/investigation pair.
    cmd = [
        str(bin_path),
        '--profile', 'localstack-close',
        'investigation', 'close', cluster_id, investigation_id,
        "--yes"
    ]

    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, f"Command failed: {result.stderr}\nStdout: {result.stdout}"

    # Verify the explicitly selected ClusterID is shown in the preview.
    assert cluster_id in result.stderr

    # Verify the access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_id not in remaining_ids
    assert ecs_client.describe_task_definition(taskDefinition=target_definition)['taskDefinition']['status'] == 'INACTIVE'
    for arn in (other_definition, adjacent_definition):
        assert ecs_client.describe_task_definition(taskDefinition=arn)['taskDefinition']['status'] == 'ACTIVE'


@pytest.mark.integration
def test_close_investigation_detects_ambiguous_investigation_id(ecs_client, efs_client, test_efs, ecs_cleanup, close_cli_env, localstack_cli_binary):
    """
    A shared investigation ID requires an explicit, exact cluster; omitting
    or mistyping it must not delete either access point.
    """

    investigation_id = f"ambiguous-inv-{int(datetime.now().timestamp())}"
    cluster_id_1 = f"cluster-1-{int(datetime.now().timestamp())}"
    cluster_id_2 = f"cluster-2-{int(datetime.now().timestamp())}"
    cluster_name = "test-cluster-name"

    # Create the ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create two access points with the same investigation ID but different cluster IDs
    ap_ids = []
    for cluster_id in [cluster_id_1, cluster_id_2]:
        response = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/{cluster_id}/{investigation_id}',
                'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'}
            },
            Tags=[
                {'Key': 'InvestigationID', 'Value': investigation_id},
                {'Key': 'ClusterID', 'Value': cluster_id},
                {'Key': 'oidc_sub', 'Value': 'localstack-test-sre'},
                {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
            ]
        )
        ap_id = response['AccessPointId']
        ap_ids.append(ap_id)
        ecs_cleanup.register_access_point(ap_id)

    env = close_cli_env(cluster_name)
    bin_path = localstack_cli_binary

    # Missing required cluster fails before ambiguous resources can be touched.
    cmd_without_cluster = [
        str(bin_path),
        '--profile', 'localstack-close',
        'investigation', 'close', investigation_id,
        "--yes"
    ]

    result = subprocess.run(cmd_without_cluster, env=env, capture_output=True, text=True, timeout=10)

    assert result.returncode != 0, "Command should require a cluster ID for ambiguous investigation IDs"
    assert 'missing required argument <investigation-id>' in result.stderr.lower()
    remaining_ids = [ap['AccessPointId'] for ap in efs_client.describe_access_points(FileSystemId=test_efs)['AccessPoints']]
    assert set(ap_ids).issubset(remaining_ids), 'Missing cluster must not delete either investigation'

    # A wrong cluster must not fall back to an investigation-ID-only match.
    wrong_cluster = subprocess.run([
        str(bin_path), '--profile', 'localstack-close', 'investigation', 'close',
        f'other-{cluster_id_1}', investigation_id, '--yes',
    ], env=env, capture_output=True, text=True, timeout=10)
    assert wrong_cluster.returncode != 0
    assert 'not found' in wrong_cluster.stderr.lower()
    remaining_ids = [ap['AccessPointId'] for ap in efs_client.describe_access_points(FileSystemId=test_efs)['AccessPoints']]
    assert set(ap_ids).issubset(remaining_ids), 'Wrong cluster must not delete either investigation'

    # Now explicitly select one cluster; the other must remain untouched.
    cmd_with_cluster = [
        str(bin_path),
        '--profile', 'localstack-close',
        'investigation', 'close', cluster_id_1, investigation_id,
        "--yes"
    ]

    result = subprocess.run(cmd_with_cluster, env=env, capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, f"Command with --cluster-id should succeed: {result.stderr}\nStdout: {result.stdout}"

    # Verify only the first access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_ids[0] not in remaining_ids, "First access point should be deleted"
    assert ap_ids[1] in remaining_ids, "Second access point should still exist"


@pytest.mark.integration
def test_close_investigation_only_stops_tasks_from_same_cluster(ecs_client, test_efs, test_vpc, efs_client, ecs_cleanup, close_cli_env, localstack_cli_binary):
    """
    Verify that investigation close with --force only stops tasks matching both
    the investigation ID and cluster ID, not tasks from other clusters with the
    same investigation ID.
    """
    import time

    timestamp = int(datetime.now().timestamp())
    investigation_id = f"shared-inv-{timestamp}"
    cluster_id_1 = f"cluster-a-{timestamp}"
    cluster_id_2 = f"cluster-b-{timestamp}"
    cluster_name = "test-cluster"

    # Create the ECS cluster
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)

    # Create access points for both clusters with the same investigation ID
    ap_ids = []
    for cluster_id in [cluster_id_1, cluster_id_2]:
        response = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/{cluster_id}/{investigation_id}',
                'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'}
            },
            Tags=[
                {'Key': 'InvestigationID', 'Value': investigation_id},
                {'Key': 'ClusterID', 'Value': cluster_id},
                {'Key': 'oidc_sub', 'Value': 'localstack-test-sre'},
                {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
            ]
        )
        ap_id = response['AccessPointId']
        ap_ids.append(ap_id)
        ecs_cleanup.register_access_point(ap_id)

    # Create task definition
    family = f'{cluster_name}-task-def-{timestamp}'
    td_response = ecs_client.register_task_definition(
        family=family,
        networkMode='awsvpc',
        requiresCompatibilities=['FARGATE'],
        cpu='256',
        memory='512',
        containerDefinitions=[{
            'name': 'rosa-boundary',
            'image': 'public.ecr.aws/docker/library/alpine:latest',
            'command': ['sleep', '300']
        }]
    )
    task_def_arn = td_response['taskDefinition']['taskDefinitionArn']
    ecs_cleanup.register_task_definition(task_def_arn)

    # Run tasks for both clusters with the SAME investigation ID
    task_arns = []
    for cluster_id in [cluster_id_1, cluster_id_2]:
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
                {'key': 'cluster_id', 'value': cluster_id},
                {'key': 'investigation_id', 'value': investigation_id},
            ]
        )
        if run_response.get('failures'):
            pytest.skip(f"LocalStack task launch failed: {run_response['failures']}")

        task_arn = run_response['tasks'][0]['taskArn']
        task_arns.append(task_arn)
        ecs_cleanup.register_task(cluster_name, task_arn)

    # Poll until both tasks reach RUNNING state
    for _ in range(24):  # up to 120s
        desc_response = ecs_client.describe_tasks(cluster=cluster_name, tasks=task_arns, include=['TAGS'])
        if len(desc_response['tasks']) == 2:
            if all(task.get('lastStatus') == 'RUNNING' for task in desc_response['tasks']):
                break
        time.sleep(5)
    else:
        statuses = [task.get('lastStatus') for task in desc_response.get('tasks', [])]
        pytest.fail(f"Tasks never reached RUNNING; statuses={statuses}")

    # Verify both tasks are running with correct tags
    task_by_arn = {task['taskArn']: task for task in desc_response['tasks']}
    assert len(task_by_arn) == 2, f"Expected 2 tasks, got {len(task_by_arn)}"
    assert task_arns[0] in task_by_arn, f"Task {task_arns[0]} not found in response"
    assert task_arns[1] in task_by_arn, f"Task {task_arns[1]} not found in response"

    for task_arn, expected_cluster in zip(task_arns, [cluster_id_1, cluster_id_2]):
        task = task_by_arn[task_arn]
        tags = {t['key']: t['value'] for t in task.get('tags', [])}
        assert tags.get('cluster_id') == expected_cluster, \
            f"Task {task_arn} should have cluster_id={expected_cluster}, got {tags.get('cluster_id')}"
        assert tags.get('investigation_id') == investigation_id

    env = close_cli_env(cluster_name)
    bin_path = localstack_cli_binary

    # Without --force, an active session must block closure without side effects.
    without_force = subprocess.run([
        str(bin_path), '--profile', 'localstack-close', 'investigation', 'close',
        cluster_id_1, investigation_id, '--yes',
    ], env=env, capture_output=True, text=True, timeout=30)
    assert without_force.returncode != 0
    assert 'force' in without_force.stderr.lower()
    remaining_ids = [ap['AccessPointId'] for ap in efs_client.describe_access_points(FileSystemId=test_efs)['AccessPoints']]
    assert set(ap_ids).issubset(remaining_ids)
    before_force = ecs_client.describe_tasks(cluster=cluster_name, tasks=task_arns)['tasks']
    assert all(task['lastStatus'] == 'RUNNING' for task in before_force)

    # Close investigation for cluster_id_1 only with --force to stop tasks
    cmd = [
        str(bin_path),
        '--profile', 'localstack-close',
        'investigation', 'close', cluster_id_1, investigation_id,
        "--force",
        "--yes"
    ]

    # ECS StopTask and the SDK waiter are asynchronous; 15s is shorter than
    # normal container shutdown plus waiter polling. Keep a bounded E2E budget.
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)

    assert result.returncode == 0, f"Command should succeed: {result.stderr}\nStdout: {result.stdout}"

    # Verify only the first cluster's access point was deleted
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    remaining_ids = [ap['AccessPointId'] for ap in access_points.get('AccessPoints', [])]
    assert ap_ids[0] not in remaining_ids, "First cluster's access point should be deleted"
    assert ap_ids[1] in remaining_ids, "Second cluster's access point should still exist"

    # Verify the output mentions the correct cluster and task stop
    assert cluster_id_1 in result.stderr, "Output should show the correct cluster ID"
    assert cluster_id_2 not in result.stderr, "Output should not mention the other cluster"

    # Check task states: cluster_id_1's task should be stopped/stopping, cluster_id_2's should still be running
    desc_after = ecs_client.describe_tasks(cluster=cluster_name, tasks=task_arns)

    # Map tasks by ARN for reliable lookup
    tasks_after_by_arn = {task['taskArn']: task for task in desc_after['tasks']}
    assert len(tasks_after_by_arn) == 2, f"Expected 2 tasks in response, got {len(tasks_after_by_arn)}"
    assert task_arns[0] in tasks_after_by_arn, f"Task {task_arns[0]} not found in post-close response"
    assert task_arns[1] in tasks_after_by_arn, f"Task {task_arns[1]} not found in post-close response"

    # Task 1 (cluster_id_1) should be stopped or stopping
    task1_status = tasks_after_by_arn[task_arns[0]]['lastStatus']
    assert task1_status in ['STOPPED', 'STOPPING', 'DEACTIVATING'], \
        f"Task for cluster_id_1 ({task_arns[0]}) should be stopped/stopping, got {task1_status}"

    # Task 2 (cluster_id_2) should still be running (not stopped by close-investigation)
    task2_status = tasks_after_by_arn[task_arns[1]]['lastStatus']
    assert task2_status in ['RUNNING', 'PENDING', 'PROVISIONING'], \
        f"Task for cluster_id_2 ({task_arns[1]}) should still be running, got {task2_status} - it should NOT have been stopped"
