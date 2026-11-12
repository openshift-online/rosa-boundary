"""S3 Files API and real ECS-mounted content tests; no sync sidecar.

API support is optional on older LocalStack releases/licenses. Runtime success
requires consumer-written log markers, never just ECS RUNNING status. This does
not establish AWS IAM enforcement or Fargate/network fidelity.
"""

from contextlib import ExitStack
import json
import os
import time
from urllib.parse import urlparse
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError, UnknownServiceError
import pytest


PREFIXES = ('ops-sop', 'rosa-claude-plugins', 'managed-notifications')


def unsupported_service(error):
    """Skip only explicit unsupported-service responses, not arbitrary failures."""
    code = error.response.get('Error', {}).get('Code', '')
    return (
        error.response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 501
        or code in {'NotImplemented', 'NotImplementedException',
                    'UnknownService', 'UnknownServiceException'}
    )


def eventually(check, description, timeout=120):
    """Bound asynchronous operations and retain the last observed response."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = check()
        if last:
            return last
        time.sleep(1)
    pytest.fail(f'Timed out waiting for {description}; last result: {last!r}')


@pytest.fixture
def content_files_client(localstack_available, s3_client, boto_config):
    """Use only the existing local endpoint and synthetic credentials."""
    endpoint = s3_client.meta.endpoint_url
    parsed = urlparse(endpoint)
    assert parsed.scheme == 'http' and parsed.hostname in {
        'localhost', '127.0.0.1', '::1'
    }, 'S3 Files tests require an explicit loopback LocalStack HTTP endpoint'
    # Older servers route the unsigned-looking REST path /file-systems to S3
    # and return NoSuchBucket, not an unsupported-service error. Consult the
    # server's service registry before sending any S3 Files API request. Reuse
    # the readiness reader so redirects, proxies and malformed health fail shut.
    from check_ready import require_ready

    health = require_ready(endpoint)
    state = health['services'].get('s3files')
    if state in (None, 'disabled'):
        pytest.skip('LocalStack does not advertise an enabled S3 Files service; '
                    'requires a supporting version/license and SERVICES=s3files')
    assert state in ('available', 'running'), f'LocalStack S3 Files is not ready: {state}'
    try:
        client = boto3.client(
            's3files', endpoint_url=endpoint, config=boto_config,
            aws_access_key_id='test', aws_secret_access_key='test',
            aws_session_token='',
        )
    except UnknownServiceError:
        pytest.skip('Installed boto3 lacks S3 Files; update the SDK to run this coverage')
    try:
        client.list_file_systems()
    except ClientError as error:
        if unsupported_service(error):
            pytest.skip('S3 Files is not implemented/enabled by this LocalStack server')
        raise
    return client


@pytest.fixture
def published_files(content_files_client, s3_client, iam_client):
    """Create unique versioned storage and per-prefix managed filesystems."""
    client = content_files_client
    name = f'test-content-files-{uuid4().hex[:16]}'
    region = s3_client.meta.region_name
    with ExitStack() as cleanup:
        kwargs = {} if region == 'us-east-1' else {
            'CreateBucketConfiguration': {'LocationConstraint': region}
        }
        s3_client.create_bucket(Bucket=name, **kwargs)

        def delete_bucket():
            paginator = s3_client.get_paginator('list_object_versions')
            for page in paginator.paginate(Bucket=name):
                objects = [
                    {'Key': obj['Key'], 'VersionId': obj['VersionId']}
                    for obj in page.get('Versions', []) + page.get('DeleteMarkers', [])
                ]
                if objects:
                    s3_client.delete_objects(Bucket=name, Delete={'Objects': objects})
            s3_client.delete_bucket(Bucket=name)

        cleanup.callback(delete_bucket)
        s3_client.put_bucket_versioning(
            Bucket=name, VersioningConfiguration={'Status': 'Enabled'})
        s3_client.put_bucket_notification_configuration(
            Bucket=name, NotificationConfiguration={'EventBridgeConfiguration': {}})
        role = iam_client.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                    'Principal': {'Service': 'elasticfilesystem.amazonaws.com'},
                }],
            }),
        )['Role']['Arn']
        cleanup.callback(iam_client.delete_role, RoleName=name)
        iam_client.put_role_policy(
            RoleName=name, PolicyName='content', PolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow',
                    'Action': ['s3:ListBucket', 's3:ListBucketVersions', 's3:GetObject*',
                               's3:PutObject*', 's3:DeleteObject*', 's3:AbortMultipartUpload'],
                    'Resource': [f'arn:aws:s3:::{name}', f'arn:aws:s3:::{name}/*'],
                }],
            }),
        )
        cleanup.callback(iam_client.delete_role_policy, RoleName=name, PolicyName='content')
        filesystems = {}
        for prefix in PREFIXES:
            s3_client.put_object(Bucket=name, Key=f'{prefix}/nested/content.txt',
                                 Body=f'initial-{prefix}'.encode())
            s3_client.put_object(Bucket=name, Key=f'{prefix}/sentinel.txt',
                                 Body=f'stable-{prefix}'.encode())
            fs = client.create_file_system(
                bucket=f'arn:aws:s3:::{name}', prefix=f'{prefix}/', roleArn=role)
            cleanup.callback(delete_filesystem, client, fs['fileSystemId'])

            def available(fs_id=fs['fileSystemId']):
                result = client.get_file_system(fileSystemId=fs_id)
                assert result['status'] != 'error', result
                return result if result['status'] == 'available' else None

            filesystems[prefix] = eventually(available, f'{prefix} filesystem availability')
        yield {'name': name, 'filesystems': filesystems}


def delete_filesystem(client, fs_id):
    """Wait for deletion before removing backing storage and service identity."""
    client.delete_file_system(fileSystemId=fs_id)

    def deleted():
        try:
            return client.get_file_system(fileSystemId=fs_id)['status'] == 'deleted'
        except ClientError as error:
            if error.response['Error']['Code'] in {'ResourceNotFoundException', 'FileSystemNotFound', 'FileSystemNotFoundException'}:
                return True
            raise
        return False

    eventually(deleted, 'filesystem deletion')


@pytest.mark.integration
def test_content_files_api(published_files, content_files_client):
    """Check actual emulated per-prefix filesystem resources, not Terraform mocks."""
    for prefix, fs in published_files['filesystems'].items():
        assert fs['bucket'] == f"arn:aws:s3:::{published_files['name']}"
        assert fs['prefix'] == f'{prefix}/'
        policy = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Deny', 'Principal': '*',
            'Action': ['s3files:ClientWrite', 's3files:ClientRootAccess'],
            'Resource': fs['fileSystemArn'],
        }]}
        content_files_client.put_file_system_policy(
            fileSystemId=fs['fileSystemId'], policy=json.dumps(policy))
        actual = content_files_client.get_file_system_policy(fileSystemId=fs['fileSystemId'])
        assert json.loads(actual['policy']) == policy  # Round trip, not authorization proof.


# Each phase requires all prefixes to match. A read-only write failure and
# byte-exact nested reads must occur inside the actual consuming ECS container.
CONSUMER = '''set -eu
wait_phase() {
    phase="$1"
    for attempt in $(seq 1 180); do
        ok=1
        for prefix in ops-sop rosa-claude-plugins managed-notifications; do
            file="/opt/rosa-content/$prefix/nested/content.txt"
            sentinel="/opt/rosa-content/$prefix/sentinel.txt"
            [ "$(cat "$sentinel" 2>/dev/null || true)" = "stable-$prefix" ] || ok=0
            if [ "$phase" = deleted ]; then
                [ ! -e "$file" ] || ok=0
            else
                [ "$(cat "$file" 2>/dev/null || true)" = "$phase-$prefix" ] || ok=0
            fi
        done
        if [ "$ok" = 1 ]; then echo "CONTENT:$phase"; return; fi
        sleep 1
    done
    exit 41
}
wait_phase initial
for prefix in ops-sop rosa-claude-plugins managed-notifications; do
    if touch "/opt/rosa-content/$prefix/forbidden" 2>/dev/null; then exit 42; fi
done
echo CONTENT:readonly
wait_phase updated
wait_phase deleted
echo CONTENT:complete
'''


@pytest.fixture
def content_executor():
    """Skip before provisioning when no real task-container executor is selected."""
    if os.getenv('ECS_EXECUTOR', 'local') != 'docker':
        pytest.skip('S3 Files runtime requires a server configured with ECS_EXECUTOR=docker')


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.usefixtures('content_executor')
def test_ecs_content_files_runtime(
    published_files, content_files_client, ecs_client, iam_client,
    logs_client, s3_client, ecs_cleanup, request,
):
    """Read, update, delete and reject writes through real managed ECS mounts."""
    # Resolve the session-scoped VPC fixture only after the function-scoped
    # capability gate has passed. Pytest otherwise initializes it before the
    # gate and can issue unrelated API requests even when S3 Files is absent.
    test_vpc = request.getfixturevalue('test_vpc')
    name = published_files['name']
    with ExitStack() as cleanup:
        for fs in published_files['filesystems'].values():
            target = content_files_client.create_mount_target(
                fileSystemId=fs['fileSystemId'], subnetId=test_vpc['subnet_ids'][0],
                securityGroups=[test_vpc['security_group_id']])
            cleanup.callback(delete_mount_target, content_files_client, target['mountTargetId'])
            eventually(
                lambda target_id=target['mountTargetId']: (
                    content_files_client.get_mount_target(mountTargetId=target_id)['status'] == 'available'
                ), 'mount target availability')
        role = iam_client.create_role(
            RoleName=f'{name}-task', AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                    'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
                }],
            }))['Role']['Arn']
        ecs_cleanup.register_role(f'{name}-task', ['mount-content'])
        iam_client.put_role_policy(
            RoleName=f'{name}-task', PolicyName='mount-content',
            PolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow', 'Action': 's3files:ClientMount',
                    'Resource': [fs['fileSystemArn'] for fs in published_files['filesystems'].values()],
                }, {
                    'Effect': 'Deny',
                    'Action': ['s3files:ClientWrite', 's3files:ClientRootAccess'],
                    'Resource': [fs['fileSystemArn'] for fs in published_files['filesystems'].values()],
                }, {
                    'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                    'Resource': f'arn:aws:logs:{s3_client.meta.region_name}:*:log-group:{name}:*',
                }],
            }))
        logs_client.create_log_group(logGroupName=name)
        cleanup.callback(logs_client.delete_log_group, logGroupName=name)
        ecs_client.create_cluster(clusterName=name)
        ecs_cleanup.register_cluster(name)
        definition = ecs_client.register_task_definition(
            family=name, networkMode='awsvpc', requiresCompatibilities=['FARGATE'],
            cpu='256', memory='512', taskRoleArn=role, executionRoleArn=role,
            volumes=[{'name': prefix, 's3filesVolumeConfiguration': {
                'fileSystemArn': fs['fileSystemArn'], 'rootDirectory': '/',
            }} for prefix, fs in published_files['filesystems'].items()],
            containerDefinitions=[{
                'name': 'consumer', 'image': 'public.ecr.aws/amazonlinux/amazonlinux:2023',
                'essential': True, 'entryPoint': ['/bin/sh', '-c'], 'command': [CONSUMER],
                'mountPoints': [{'sourceVolume': prefix,
                                 'containerPath': f'/opt/rosa-content/{prefix}', 'readOnly': True}
                                for prefix in PREFIXES],
                'logConfiguration': {'logDriver': 'awslogs', 'options': {
                    'awslogs-group': name, 'awslogs-region': s3_client.meta.region_name,
                    'awslogs-stream-prefix': 'content',
                }},
            }])['taskDefinition']['taskDefinitionArn']
        ecs_cleanup.register_task_definition(definition)
        response = ecs_client.run_task(
            cluster=name, taskDefinition=definition, launchType='FARGATE',
            networkConfiguration={'awsvpcConfiguration': {
                'subnets': [test_vpc['subnet_ids'][0]],
                'securityGroups': [test_vpc['security_group_id']], 'assignPublicIp': 'ENABLED',
            }})
        assert not response.get('failures'), response
        task = response['tasks'][0]['taskArn']
        ecs_cleanup.register_task(name, task)
        # Stop before mount targets/filesystems are removed, even on assertion failure.
        cleanup.callback(stop_consumer, ecs_client, name, task)

        def marker(phase):
            messages = []
            for page in logs_client.get_paginator('filter_log_events').paginate(logGroupName=name):
                messages.extend(event['message'].strip() for event in page['events'])
            return f'CONTENT:{phase}' in messages

        eventually(lambda: marker('readonly'), 'consumer reads and rejected filesystem writes', 240)
        for prefix in PREFIXES:
            s3_client.put_object(Bucket=name, Key=f'{prefix}/nested/content.txt',
                                 Body=f'updated-{prefix}'.encode())
        eventually(lambda: marker('updated'), 'bucket updates visible in mounted files', 200)
        for prefix in PREFIXES:
            s3_client.delete_object(Bucket=name, Key=f'{prefix}/nested/content.txt')
        eventually(lambda: marker('complete'), 'bucket deletes visible in mounted files', 200)
        eventually(lambda: ecs_client.describe_tasks(cluster=name, tasks=[task])['tasks'][0]['lastStatus'] == 'STOPPED',
                   'consumer exit')
        stopped = ecs_client.describe_tasks(cluster=name, tasks=[task])['tasks'][0]
        assert stopped['containers'][0].get('exitCode') == 0, stopped


def stop_consumer(client, cluster, task):
    """Release filesystem users before deleting test-owned mount resources."""
    client.stop_task(cluster=cluster, task=task)
    eventually(lambda: client.describe_tasks(cluster=cluster, tasks=[task])['tasks'][0]['lastStatus'] == 'STOPPED',
               'consumer shutdown')


def delete_mount_target(client, target_id):
    """Wait for asynchronous target deletion before deleting its filesystem."""
    client.delete_mount_target(mountTargetId=target_id)

    def deleted():
        try:
            return client.get_mount_target(mountTargetId=target_id)['status'] == 'deleted'
        except ClientError as error:
            if error.response['Error']['Code'] in {'ResourceNotFoundException', 'MountTargetNotFound', 'MountTargetNotFoundException'}:
                return True
            raise
        return False

    eventually(deleted, 'mount target deletion')
