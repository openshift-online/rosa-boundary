"""Integration coverage for the `investigation close` request protocol.

`investigation close` no longer performs the close. It resolves and previews
the workspace, then records a request with the close service; the scheduled
reaper seals, drains, copies, verifies and only then removes the access point.
The tests here are written against that protocol, so the central assertion of
almost every one of them is the opposite of what it used to be: after the CLI
runs, **nothing has been deleted, deregistered or stopped**.

What runs here and what does not:

* The CLI half runs in full. The test binary resolves real LocalStack EFS and
  ECS state, previews it, and reaches the submission step, which fails on this
  profile because no close service is configured. That failure is the proof
  the command got that far without mutating anything.
* The service half — the request handler and the reaper finalizer — is not
  deployed as a Lambda in the LocalStack stack, so these tests do not drive
  it. It is covered by `lambda/create-investigation/test_close_requests.py`,
  `lambda/reap-investigations/test_close_finalization.py` and the two
  cross-artifact contract suites under `tests/unit/`, and end to end only by
  the live validation in `docs/architecture/investigation-close.md`.

The legacy v1 path these tests originally covered — an operator receipt plus
an `AuditCloseVerified` tag, with the CLI doing the deletion — is retained for
old clients, and its IAM grants are still asserted below.
"""

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

# Default to 'local' for direct pytest invocations (e.g., local development)
# where ECS_EXECUTOR is not set. In Prow CI, ci-run.sh exports ECS_EXECUTOR=docker
# before invoking pytest, which disables these skips.
ECS_EXECUTOR = os.getenv('ECS_EXECUTOR', 'local')


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


@pytest.fixture
def stage_operator_receipt(s3_client, efs_client):
    """Model independent operator evidence outside the task/CLI identity.

    Writes a legacy schema-v1 receipt and its separate `AuditCloseVerified`
    tag. `stage_close_receipt` covers the reaper's v2 receipt.
    """
    bucket = f'close-audit-{uuid4().hex}'
    region = s3_client.meta.region_name
    location = {} if region == 'us-east-1' else {
        'CreateBucketConfiguration': {'LocationConstraint': region},
    }
    s3_client.create_bucket(Bucket=bucket, **location)
    keys = []

    def stage(cluster, investigation, ap):
        seal = str(uuid4())
        key = f'_boundary-close/{ap}/{seal}.json'
        body = json.dumps({
            'schema_version': 1, 'cluster_id': cluster, 'investigation_id': investigation,
            'access_point_id': ap, 'seal': seal, 'status': 'verified',
            'manifest_ref': f'operator-manifests/{seal}',
        }).encode()
        assert len(body) <= 16 * 1024
        # Split these steps to test that tags alone cannot authorize deletion.
        efs_client.tag_resource(ResourceId=ap, Tags=[
            {'Key': 'AuditCloseBucket', 'Value': bucket},
            {'Key': 'AuditCloseSeal', 'Value': seal},
            {'Key': 'AuditCloseVerified', 'Value': seal},
        ])

        def publish():
            keys.append(key)
            s3_client.put_object(Bucket=bucket, Key=key, Body=body, ContentType='application/json')
            return hashlib.sha256(body).hexdigest()

        return publish

    yield stage
    for key in keys:
        s3_client.delete_object(Bucket=bucket, Key=key)
    s3_client.delete_bucket(Bucket=bucket)


@pytest.fixture
def stage_close_receipt(s3_client, efs_client):
    """Stage a reaper-style schema-v2 receipt for an access point.

    A v2 receipt deliberately does **not** come with an `AuditCloseVerified`
    tag: that tag is the v1 contract, and setting it beside weaker evidence is
    exactly how an older client would mistake observed quiescence for the
    stronger guarantee. The reaper does not set it, and this fixture does not
    either.
    """
    bucket = f'close-audit-{uuid4().hex}'
    region = s3_client.meta.region_name
    location = {} if region == 'us-east-1' else {
        'CreateBucketConfiguration': {'LocationConstraint': region},
    }
    s3_client.create_bucket(Bucket=bucket, **location)
    keys = []

    def stage(cluster, investigation, ap, *, attempt_id=None, assurance='observed-quiescence',
              request_token=None, manifest_sha256=None, evidence_attempt=None):
        seal = str(uuid4())
        attempt = attempt_id or str(uuid4())
        # evidence_attempt lets a test point the evidence references at a
        # different attempt, which the client must refuse.
        referenced = evidence_attempt or attempt
        prefix = f'_boundary-close/evidence/{ap}/attempts/{referenced}'
        key = f'_boundary-close/{ap}/{seal}.json'
        body = json.dumps({
            'schema_version': 2, 'kind': 'close_receipt', 'assurance': assurance,
            'cluster_id': cluster, 'investigation_id': investigation,
            'access_point_id': ap, 'seal': seal, 'status': 'verified',
            'attempt_id': attempt,
            'request_token': request_token or str(uuid4()),
            'manifest_sha256': manifest_sha256 or hashlib.sha256(seal.encode()).hexdigest(),
            'manifest_ref': f's3://{bucket}/{prefix}/source-manifest.json',
            'verification_ref': f's3://{bucket}/{prefix}/verification.json',
            'directory_retained': True,
        }).encode()
        efs_client.tag_resource(ResourceId=ap, Tags=[
            {'Key': 'AuditCloseBucket', 'Value': bucket},
            {'Key': 'AuditCloseSeal', 'Value': seal},
            {'Key': 'AuditCloseManagedBy', 'Value': 'rosa-boundary-reaper'},
        ])
        keys.append(key)
        s3_client.put_object(Bucket=bucket, Key=key, Body=body, ContentType='application/json')
        return hashlib.sha256(body).hexdigest()

    yield stage
    for key in keys:
        s3_client.delete_object(Bucket=bucket, Key=key)
    s3_client.delete_bucket(Bucket=bucket)


def _managed_investigation(efs_client, ecs_cleanup, filesystem_id, cluster_id, investigation_id,
                           oidc_sub='localstack-test-sre'):
    """Create an access point that looks exactly like a Lambda-created one."""
    response = efs_client.create_access_point(
        FileSystemId=filesystem_id,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': f'/{cluster_id}/{investigation_id}',
            'CreationInfo': {'OwnerUid': 1000, 'OwnerGid': 1000, 'Permissions': '0755'},
        },
        Tags=[
            {'Key': 'InvestigationID', 'Value': investigation_id},
            {'Key': 'ClusterID', 'Value': cluster_id},
            {'Key': 'oidc_sub', 'Value': oidc_sub},
            {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
        ],
    )
    access_point_id = response['AccessPointId']
    ecs_cleanup.register_access_point(access_point_id)
    return access_point_id


def _close(bin_path, env, *args, timeout=30):
    return subprocess.run(
        [str(bin_path), '--profile', 'localstack-close', 'investigation', 'close', *args],
        env=env, capture_output=True, text=True, timeout=timeout)


def _preview(bin_path, env, cluster_id, investigation_id):
    """Run the read-only preview and return its JSON plan."""
    result = _close(bin_path, env, cluster_id, investigation_id, '--dry-run', '-o', 'json')
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# The submission step reports this when the profile names no close service.
# Reaching it proves the CLI resolved, previewed and accepted the workspace
# and then tried to hand it to the service instead of acting by itself.
NO_SERVICE = 'no close service configured'


def _assert_nothing_was_mutated(efs_client, ecs_client, filesystem_id, access_point_ids,
                                task_definition_arns=(), task_arns=(), ecs_cluster=None):
    """The close CLI is not allowed to delete, deregister or stop anything."""
    remaining = {ap['AccessPointId']
                 for ap in efs_client.describe_access_points(
                     FileSystemId=filesystem_id)['AccessPoints']}
    assert set(access_point_ids).issubset(remaining), 'the CLI must not delete access points'
    for arn in task_definition_arns:
        status = ecs_client.describe_task_definition(
            taskDefinition=arn)['taskDefinition']['status']
        assert status == 'ACTIVE', 'the CLI must not deregister task definitions'
    if task_arns:
        described = ecs_client.describe_tasks(cluster=ecs_cluster, tasks=list(task_arns))['tasks']
        # Check the count first: `all()` over an empty list is True, which
        # would make the central claim of this helper pass vacuously if ECS
        # reported the tasks as failures instead of returning them.
        assert len(described) == len(task_arns), 'every task must still be describable'
        assert all(task['lastStatus'] == 'RUNNING' for task in described), \
            'the CLI must not stop tasks; the service does that with recorded consent'


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
def test_close_command_surface_matches_the_request_protocol(tmp_path, localstack_cli_binary):
    """The asynchronous protocol's flags, checked against the real binary.

    `--wait` waits for the service; it is meaningless with `--dry-run`, which
    submits nothing. Without a terminal there is nobody to confirm to, so
    `--yes` is required unless the run is a preview.
    """
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('AWS_', 'ROSA_BOUNDARY_'))}
    env['XDG_CONFIG_HOME'] = str(tmp_path)

    def run(*args):
        # start_new_session detaches the controlling terminal. requireTerminal
        # opens /dev/tty rather than stdin, so without this the no-terminal
        # assertion below would pass in CI and fail for a developer running
        # the suite from their own shell.
        return subprocess.run([str(localstack_cli_binary), 'investigation', 'close', *args],
                              env=env, capture_output=True, text=True, timeout=10,
                              stdin=subprocess.DEVNULL, start_new_session=True)

    incompatible = run('c', 'i', '--dry-run', '--wait')
    assert incompatible.returncode != 0
    assert 'submits nothing' in incompatible.stderr

    unconfirmable = run('c', 'i')
    assert unconfirmable.returncode != 0
    assert '--yes is required without a terminal' in unconfirmable.stderr

    help_text = run('--help')
    assert help_text.returncode == 0
    # The help states the authorization rule the service enforces, including
    # that a running task does not reserve the investigation.
    assert 'session attached' in help_text.stdout
    assert 'any authorized Boundary SRE' in help_text.stdout
    assert 'stopping that task is separate consent' in help_text.stdout
    # And that a recorded request is not a finished close.
    assert 'not a completed close' in help_text.stdout


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
    assert re.search(r'"aws:ResourceTag/ManagedBy"\s*=\s*"rosa-boundary-lambda"', statement)
    assert re.search(r'"aws:ResourceTag/AuditCloseVerified"\s*=\s*"\$\$\{aws:ResourceTag/AuditCloseSeal\}"', statement)


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
def test_close_investigation_requires_cluster_and_closes_exact_target(ecs_client, efs_client, test_efs, ecs_cleanup, close_cli_env, localstack_cli_binary, stage_operator_receipt):
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
    every_definition = (target_definition, other_definition, adjacent_definition)

    # A missing cluster ID must fail before resolving anything at all.
    missing_cluster = _close(bin_path, env, investigation_id, '--yes', timeout=10)
    assert missing_cluster.returncode != 0
    assert 'missing required argument <investigation-id>' in missing_cluster.stderr.lower()
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, [ap_id], every_definition)

    # Ownership is no longer decided here. The access point's `oidc_sub` tag is
    # provenance, and the authorization matrix — current holder, or any
    # eligible SRE when no session is attached — is applied by the service
    # against observed sessions, which the CLI cannot see. The command must
    # therefore carry the request to the service rather than refusing locally.
    efs_client.tag_resource(ResourceId=ap_id, Tags=[{'Key': 'oidc_sub', 'Value': 'another-sre'}])
    not_creator = _close(bin_path, env, cluster_id, investigation_id, '--yes')
    assert not_creator.returncode != 0
    assert NO_SERVICE in not_creator.stderr, not_creator.stderr
    assert 'owner' not in not_creator.stderr.lower(), \
        'close eligibility is service-side; the CLI must not re-impose a creator check'
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, [ap_id], every_definition)
    efs_client.tag_resource(ResourceId=ap_id, Tags=[{'Key': 'oidc_sub', 'Value': 'localstack-test-sre'}])

    # Before any receipt exists the preview says why finalization is blocked,
    # and still submits nothing.
    unsealed = _preview(bin_path, env, cluster_id, investigation_id)
    assert unsealed['access_point_id'] == ap_id
    assert unsealed['cluster_id'] == cluster_id
    assert unsealed['task_definitions_to_deregister'] == [target_definition], unsealed
    assert unsealed['sessions_to_stop'] == []
    assert unsealed['managed_close_seal'] is False
    assert unsealed['finalization_blocked_reason']
    assert 'receipt_sha256' not in unsealed or not unsealed['receipt_sha256']

    # A legacy v1 receipt is still read and still requires its separate
    # verification tag, so an old deployment behaves exactly as before.
    publish = stage_operator_receipt(cluster_id, investigation_id, ap_id)
    staged_but_unpublished = _preview(bin_path, env, cluster_id, investigation_id)
    assert 'cannot read close receipt' in staged_but_unpublished['finalization_blocked_reason']

    digest = publish()
    plan = _preview(bin_path, env, cluster_id, investigation_id)
    assert plan['receipt_sha256'] == digest
    assert plan['receipt_assurance'] == 'operator-verified (schema v1)'
    assert plan['finalization_blocked_reason'] == ''
    assert plan['task_definitions_to_deregister'] == [target_definition], plan
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, [ap_id], every_definition)

    # Submitting reaches the close service. The CLI performs no cleanup of its
    # own even with a complete, verified receipt in place: "accepted" is not
    # "closed", and the access point survives until the reaper has sealed,
    # verified and cleaned up under its own authorization recheck.
    submitted = _close(bin_path, env, cluster_id, investigation_id, '--yes')
    assert submitted.returncode != 0
    assert NO_SERVICE in submitted.stderr, submitted.stderr
    assert cluster_id in submitted.stderr
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, [ap_id], every_definition)


@pytest.mark.integration
def test_close_preview_reports_the_v2_assurance_and_refuses_mismatched_evidence(
        ecs_client, efs_client, test_efs, ecs_cleanup, close_cli_env, localstack_cli_binary,
        stage_close_receipt):
    """The client reads a reaper v2 receipt, and refuses a forged one.

    v2 carries the weaker observed-quiescence assurance, so the client states
    that level explicitly and accepts the receipt only when both evidence
    references name the receipt's own attempt.
    """
    stamp = int(datetime.now().timestamp())
    cluster_id, investigation_id = f'v2-cluster-{stamp}', f'v2-inv-{stamp}'
    cluster_name = 'test-cluster-name'
    ecs_client.create_cluster(clusterName=cluster_name)
    ecs_cleanup.register_cluster(cluster_name)
    ap_id = _managed_investigation(efs_client, ecs_cleanup, test_efs, cluster_id, investigation_id)

    env = close_cli_env(cluster_name)
    bin_path = localstack_cli_binary

    digest = stage_close_receipt(cluster_id, investigation_id, ap_id)
    plan = _preview(bin_path, env, cluster_id, investigation_id)
    assert plan['receipt_sha256'] == digest
    assert plan['receipt_assurance'].startswith('observed quiescence (schema v2)')
    assert 'not an atomic cutoff' in plan['receipt_assurance']
    assert plan['finalization_blocked_reason'] == ''
    # The reaper's own marker is visible, and the v1 verification tag is not
    # set beside v2 evidence.
    assert plan['managed_close_seal'] is True
    tags = {tag['Key']: tag['Value'] for tag in
            efs_client.describe_access_points(AccessPointId=ap_id)['AccessPoints'][0]['Tags']}
    assert 'AuditCloseVerified' not in tags

    # Evidence that names a different attempt is refused, not averaged out.
    stage_close_receipt(cluster_id, investigation_id, ap_id, evidence_attempt=str(uuid4()))
    forged = _preview(bin_path, env, cluster_id, investigation_id)
    assert 'do not name its own attempt' in forged['finalization_blocked_reason']
    assert not forged.get('receipt_sha256')

    # So is a v2 receipt that does not state its assurance level.
    stage_close_receipt(cluster_id, investigation_id, ap_id, assurance='')
    unstated = _preview(bin_path, env, cluster_id, investigation_id)
    assert 'observed-quiescence assurance' in unstated['finalization_blocked_reason']

    # A receipt naming no close request, and one carrying no manifest digest,
    # are the other two ways v2 evidence can fail to identify its own attempt.
    stage_close_receipt(cluster_id, investigation_id, ap_id, request_token='not-a-uuid')
    tokenless = _preview(bin_path, env, cluster_id, investigation_id)
    assert 'names no close request' in tokenless['finalization_blocked_reason']

    stage_close_receipt(cluster_id, investigation_id, ap_id, manifest_sha256='short')
    digestless = _preview(bin_path, env, cluster_id, investigation_id)
    assert 'no manifest digest' in digestless['finalization_blocked_reason']

    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, [ap_id])


@pytest.mark.integration
def test_close_investigation_detects_ambiguous_investigation_id(ecs_client, efs_client, test_efs, ecs_cleanup, close_cli_env, localstack_cli_binary, stage_operator_receipt):
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

    # Now explicitly select one cluster. The request names exactly that
    # investigation, and the CLI touches neither access point.
    publish = stage_operator_receipt(cluster_id_1, investigation_id, ap_ids[0])
    publish()
    plan = _preview(bin_path, env, cluster_id_1, investigation_id)
    assert plan['access_point_id'] == ap_ids[0]
    assert plan['cluster_id'] == cluster_id_1

    result = _close(bin_path, env, cluster_id_1, investigation_id, '--yes')
    assert result.returncode != 0
    assert NO_SERVICE in result.stderr, result.stderr
    assert cluster_id_2 not in result.stderr, 'the other investigation must not be named'
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, ap_ids)


@pytest.mark.integration
@pytest.mark.skipif(
    ECS_EXECUTOR == 'local',
    reason=f'ECS_EXECUTOR=local: tasks never reach RUNNING state so reaper finds 0 tasks (current: {ECS_EXECUTOR})'
)
def test_close_scopes_stop_consent_to_one_cluster_and_stops_nothing_itself(ecs_client, test_efs, test_vpc, efs_client, ecs_cleanup, close_cli_env, localstack_cli_binary, stage_operator_receipt):
    """`--force` is consent, recorded with the request, and scoped to one
    investigation.

    Two clusters share an investigation ID and each has a running task. The
    plan and the request must cover only the selected cluster's task, and the
    CLI must not stop even that one: stopping is the finalizer's action, taken
    after it rechecks authorization against the consent the request carried.
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
    task_id_1, task_id_2 = (arn.split('/')[-1] for arn in task_arns)

    # The preview scopes the running session to this investigation only, and
    # says finalization is blocked while it runs.
    plan = _preview(bin_path, env, cluster_id_1, investigation_id)
    assert plan['sessions_to_stop'] == [task_id_1], plan
    assert task_id_2 not in json.dumps(plan), 'the other cluster must not appear in the plan'
    assert 'tasks have not stopped' in plan['finalization_blocked_reason']

    # Without --force, a running session blocks submission. Consent to stop
    # someone's work is explicit, and withholding it stops nothing.
    without_force = _close(bin_path, env, cluster_id_1, investigation_id, '--yes')
    assert without_force.returncode != 0
    assert 'force' in without_force.stderr.lower()
    assert 'running task' in without_force.stderr.lower()
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, ap_ids,
                                task_arns=task_arns, ecs_cluster=cluster_name)

    # With --force the command proceeds to the service carrying investigation
    # stop consent. It still does not stop the task itself: the reaper stops
    # the consented set after rechecking authorization, so the task is still
    # RUNNING when the CLI returns.
    forced = _close(bin_path, env, cluster_id_1, investigation_id, '--force', '--yes',
                    timeout=120)
    assert forced.returncode != 0
    assert NO_SERVICE in forced.stderr, forced.stderr
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, ap_ids,
                                task_arns=task_arns, ecs_cluster=cluster_name)

    # A verified receipt does not change that. Even with complete evidence the
    # CLI deletes nothing, and the second cluster's identically named
    # investigation is never in scope.
    publish = stage_operator_receipt(cluster_id_1, investigation_id, ap_ids[0])
    publish()
    result = _close(bin_path, env, cluster_id_1, investigation_id, '--force', '--yes')
    assert result.returncode != 0
    assert NO_SERVICE in result.stderr, result.stderr
    assert cluster_id_1 in result.stderr, 'output should show the selected cluster ID'
    assert cluster_id_2 not in result.stderr, 'output should not mention the other cluster'
    _assert_nothing_was_mutated(efs_client, ecs_client, test_efs, ap_ids,
                                task_arns=task_arns, ecs_cluster=cluster_name)
