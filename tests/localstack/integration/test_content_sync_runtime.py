"""Runtime evidence, not just ECS lifecycle API assertions. No real AWS endpoints."""

import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
import time
from urllib.parse import urlsplit
import uuid

import pytest


SCRIPT = Path(__file__).resolve().parents[3] / 'deploy/regional/content-sync.sh'
FILES = {
    'rosa-claude-plugins/skills/nested/triage/SKILL.md': b'# Triage\nFixture skill\n',
    'rosa-claude-plugins/skills/nested/triage/assets/example.json': b'{"fixture": true}\n',
    'ops-sop/nested/README.md': b'# Fixture SOP\n',
    'managed-notifications/nested/notification.yaml': b'fixture: notification\n',
}
pytestmark = pytest.mark.integration


def local_endpoint(value):
    """Fail closed before any runtime receives credentials or an endpoint."""
    parsed = urlsplit(value)
    host = parsed.hostname or ''
    try:
        address = ipaddress.ip_address(host)
        local = (address.is_loopback or address.is_private) and not (
            address.is_link_local or address.is_unspecified or address.is_multicast)
    except ValueError:
        local = host in {'localhost', 'localstack', 'localstack_localstack_1'}
    if (parsed.scheme != 'http' or not local or parsed.port != 4566
            or parsed.username or parsed.password or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment):
        raise ValueError('content-sync tests require an explicit local HTTP endpoint on port 4566')
    return value


def wait_for(check, description, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    pytest.fail(f'Timed out waiting for {description}')


def runtime_env(bucket, endpoint, region):
    return {
        'AWS_ACCESS_KEY_ID': 'test', 'AWS_SECRET_ACCESS_KEY': 'test',
        'AWS_REGION': region, 'AWS_DEFAULT_REGION': region,
        'AWS_ENDPOINT_URL': local_endpoint(endpoint),
        'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_CONFIG_FILE': '/dev/null',
        'AWS_SHARED_CREDENTIALS_FILE': '/dev/null', 'AWS_PAGER': '',
        'CONTENT_BUCKET': bucket, 'CONTENT_PREFIXES': 'ops-sop/ rosa-claude-plugins/ managed-notifications/',
        'CONTENT_SYNC_INTERVAL': '1', 'CONTENT_SYNC_BACKOFF': '1',
        'CONTENT_SYNC_TIMEOUT': '15',
    }


@pytest.fixture
def content_buckets(s3_client):
    local_endpoint(s3_client.meta.endpoint_url)
    names = ['content-runtime-' + uuid.uuid4().hex for _ in range(2)]

    def create(name):
        args = {'Bucket': name}
        region = s3_client.meta.region_name
        if region != 'us-east-1':
            args['CreateBucketConfiguration'] = {'LocationConstraint': region}
        s3_client.create_bucket(**args)

    # Only the control bucket exists initially: sync must survive NoSuchBucket.
    create(names[1])
    try:
        yield names[0], names[1], create
    finally:
        for name in names:
            try:
                pages = s3_client.get_paginator('list_objects_v2').paginate(Bucket=name)
                for page in pages:
                    for obj in page.get('Contents', []):
                        s3_client.delete_object(Bucket=name, Key=obj['Key'])
                s3_client.delete_bucket(Bucket=name)
            except s3_client.exceptions.NoSuchBucket:
                pass


@pytest.fixture
def runtime_image():
    image = os.getenv('CONTENT_SYNC_TEST_IMAGE')
    if not image:
        pytest.skip('set CONTENT_SYNC_TEST_IMAGE to a prebuilt Boundary image with bash/timeout/aws')
    return image


@pytest.fixture
def engine(runtime_image):
    executable = shutil.which(os.getenv('CONTENT_SYNC_TEST_ENGINE', 'podman'))
    if not executable:
        pytest.skip('content-sync runtime requires a container engine')
    # Do not pass personal AWS credentials, profile, or endpoint overrides to children.
    env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}

    def run(*args, check=True):
        result = subprocess.run([executable, *args], env=env, text=True,
                                capture_output=True, timeout=40)
        if check and result.returncode:
            pytest.fail(f'container engine {args[0]} failed: {result.stderr}')
        return result

    run('image', 'inspect', runtime_image)  # Never implicitly pull a missing image.
    return run


def test_shipped_sync_s3_recovery_update_delete(engine, runtime_image, content_buckets,
                                               s3_client, tmp_path):
    bucket, _, create = content_buckets
    name = 'content-sync-' + uuid.uuid4().hex
    volume = name + '-data'
    # Join the existing test network, including on macOS's remote Podman VM.
    # Do not join/reconfigure the shared Compose pod or server namespace.
    network = os.getenv('CONTENT_SYNC_TEST_NETWORK', 'rosa-boundary-test')
    endpoint = os.getenv('CONTENT_SYNC_CONTAINER_ENDPOINT', 'http://localstack:4566')
    env = runtime_env(bucket, endpoint, s3_client.meta.region_name)
    engine('volume', 'create', volume)
    try:
        args = ['run', '-d', '--name', name, '--pull=never', '--user', '0',
                '--read-only', '--cap-drop', 'ALL',
                '--network', network, '--entrypoint', '/bin/bash',
                '-v', volume + ':/opt/rosa-content']
        for key, value in env.items():
            args.extend(['-e', f'{key}={value}'])
        # Same bytes Terraform embeds, not a stub aws or test-only script variant.
        engine(*args, runtime_image, '-c', SCRIPT.read_text() + '\nmain')
        wait_for(lambda: all(f'prefix={prefix} attempt=3 status=' in engine('logs', name).stdout
                             for prefix in ('ops-sop/', 'rosa-claude-plugins/', 'managed-notifications/')),
                 'bounded retries for every prefix against the missing test bucket')
        assert 'status=0' not in engine('logs', name).stdout
        assert engine('inspect', '-f', '{{.State.Running}}', name).stdout.strip() == 'true'
        create(bucket)
        for key, body in FILES.items():
            s3_client.put_object(Bucket=bucket, Key=key, Body=body)

        def matches(key, body):
            result = engine('exec', name, 'cat', '/opt/rosa-content/' + key, check=False)
            return result.returncode == 0 and result.stdout == body.decode()

        wait_for(lambda: all(matches(k, v) for k, v in FILES.items()),
                 'all three nested prefixes to recover and download')
        key = 'rosa-claude-plugins/skills/nested/triage/SKILL.md'
        updated = b'# Updated skill with different size\n'
        s3_client.put_object(Bucket=bucket, Key=key, Body=updated)
        deleted = 'managed-notifications/nested/notification.yaml'
        s3_client.delete_object(Bucket=bucket, Key=deleted)
        wait_for(lambda: matches(key, updated), 'periodic content update')
        wait_for(lambda: engine('exec', name, 'test', '!', '-e',
                               '/opt/rosa-content/' + deleted, check=False).returncode == 0,
                 'periodic --delete propagation')
        assert matches('ops-sop/nested/README.md', FILES['ops-sop/nested/README.md'])
    finally:
        # Capture script diagnostics even on failure, before removing only our container.
        logs = engine('logs', name, check=False)
        (tmp_path / 'content-sync.log').write_text(logs.stdout + logs.stderr)
        print(f'content-sync runtime log: {tmp_path / "content-sync.log"}')
        try:
            engine('rm', '-f', name)
        finally:
            engine('volume', 'rm', volume)


@pytest.mark.slow
@pytest.mark.skipif(os.getenv('ECS_EXECUTOR', 'local') != 'docker',
                    reason='ECS_EXECUTOR=local: lifecycle APIs do not execute sidecar/consumer containers')
def test_ecs_sidecar_shared_readonly_volume(runtime_image, content_buckets, ecs_client,
                                           ecs_cleanup, s3_client):
    endpoint = os.getenv('CONTENT_SYNC_ECS_ENDPOINT')
    if not endpoint:
        pytest.skip('set CONTENT_SYNC_ECS_ENDPOINT to the local S3 endpoint reachable from ECS containers')
    local_endpoint(endpoint)
    local_endpoint(ecs_client.meta.endpoint_url)
    bucket, control, create = content_buckets
    name = 'content-ecs-' + uuid.uuid4().hex
    env = runtime_env(bucket, endpoint, s3_client.meta.region_name)
    env['CONTROL_BUCKET'] = control
    environment = [{'name': k, 'value': v} for k, v in env.items()]
    # Startup marker precedes any content: no dependsOn/health gate. Markers are
    # written by the consumer itself, never inferred from ECS RUNNING status.
    consumer = '''set -eu
aws s3 cp /dev/null "s3://${CONTROL_BUCKET}/started" --only-show-errors
if touch /opt/rosa-content/consumer-must-not-write 2>/dev/null; then exit 41; fi
for attempt in $(seq 1 120); do
  if [[ -f /opt/rosa-content/rosa-claude-plugins/skills/nested/triage/SKILL.md &&
        -f /opt/rosa-content/ops-sop/nested/README.md &&
        -f /opt/rosa-content/managed-notifications/nested/notification.yaml ]]; then
    grep -q 'Fixture skill' /opt/rosa-content/rosa-claude-plugins/skills/nested/triage/SKILL.md
    grep -q 'fixture' /opt/rosa-content/rosa-claude-plugins/skills/nested/triage/assets/example.json
    grep -q 'Fixture SOP' /opt/rosa-content/ops-sop/nested/README.md
    grep -q 'notification' /opt/rosa-content/managed-notifications/nested/notification.yaml
    aws s3 cp /dev/null "s3://${CONTROL_BUCKET}/verified" --only-show-errors
    exit 0
  fi
  sleep 1
done
exit 42
'''
    ecs_client.create_cluster(clusterName=name)
    ecs_cleanup.register_cluster(name)
    definition = ecs_client.register_task_definition(
        family=name, networkMode='bridge', volumes=[{'name': 'content', 'host': {}}],
        containerDefinitions=[
            {'name': 'content-sync', 'image': runtime_image, 'essential': False,
             'memory': 256, 'user': '0', 'environment': environment,
             'readonlyRootFilesystem': True,
             'linuxParameters': {'capabilities': {'drop': ['ALL']}, 'initProcessEnabled': True},
             'entryPoint': ['/bin/bash', '-c', SCRIPT.read_text() + '\nmain'],
             'mountPoints': [{'sourceVolume': 'content', 'containerPath': '/opt/rosa-content', 'readOnly': False}]},
            {'name': 'consumer', 'image': runtime_image, 'essential': True,
             'memory': 256, 'user': '0', 'environment': environment,
             'entryPoint': ['/bin/bash', '-c', consumer],
             'mountPoints': [{'sourceVolume': 'content', 'containerPath': '/opt/rosa-content', 'readOnly': True}]},
        ])['taskDefinition']['taskDefinitionArn']
    ecs_cleanup.register_task_definition(definition)
    response = ecs_client.run_task(cluster=name, taskDefinition=definition, launchType='EC2')
    for task in response.get('tasks', []):
        ecs_cleanup.register_task(name, task['taskArn'])
    assert not response.get('failures'), response.get('failures')
    assert len(response.get('tasks', [])) == 1

    def marker(key):
        return bool(s3_client.list_objects_v2(Bucket=control, Prefix=key).get('Contents'))

    wait_for(lambda: marker('started'), 'actual consumer startup while content bucket is absent')
    assert not marker('verified')
    create(bucket)
    for key, body in FILES.items():
        s3_client.put_object(Bucket=bucket, Key=key, Body=body)
    wait_for(lambda: marker('verified'), 'consumer reading real sidecar writes and rejecting RO writes', 180)
