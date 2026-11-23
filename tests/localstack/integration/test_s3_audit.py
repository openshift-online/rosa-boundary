"""Test S3 audit bucket with WORM compliance."""

import io
import re
from contextlib import closing
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError


@pytest.mark.integration
def test_reaper_aborts_failed_multipart_backup_then_uploads_a_fresh_copy(s3_client, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3] / 'lambda/reap-investigations'))
    from boundary_close_records import attempt_workspace_prefix
    from close_finalization import MULTIPART_THRESHOLD, Finalizer

    bucket = f'test-reaper-multipart-{uuid4().hex}'
    prefix = '_boundary-close/'
    failed_key, retry_key = (
        attempt_workspace_prefix('fsap-12345678', str(uuid4())) + 'file.bin' for _ in range(2)
    )
    payload = b'x' * MULTIPART_THRESHOLD + b'last part'
    finalizer = Finalizer(ecs=None, efs=None, s3=s3_client, ssm=None, ecs_cluster='',
                          efs_filesystem_id='', audit_bucket=bucket, account_id='',
                          mount_path='', started_by=None, task_definition_family='')
    real_upload_part = s3_client.upload_part

    def fail_second_part(**kwargs):
        if kwargs['PartNumber'] == 2:
            raise ClientError({'Error': {'Code': 'InternalError'}}, 'UploadPart')
        return real_upload_part(**kwargs)

    s3_client.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': 'us-east-2'})
    try:
        with monkeypatch.context() as patch:
            patch.setattr(s3_client, 'upload_part', fail_second_part)
            with pytest.raises(ClientError, match='InternalError'):
                finalizer.upload_workspace_file(io.BytesIO(payload), failed_key, len(payload), None)

        assert not s3_client.list_multipart_uploads(Bucket=bucket, Prefix=prefix).get('Uploads')
        assert not s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix).get('Contents')

        finalizer.upload_workspace_file(io.BytesIO(payload), retry_key, len(payload), None)
        with closing(s3_client.get_object(Bucket=bucket, Key=retry_key)['Body']) as body:
            assert body.read() == payload
        assert not s3_client.list_multipart_uploads(Bucket=bucket, Prefix=prefix).get('Uploads')
    finally:
        for upload in s3_client.list_multipart_uploads(Bucket=bucket).get('Uploads', []):
            s3_client.abort_multipart_upload(Bucket=bucket, Key=upload['Key'], UploadId=upload['UploadId'])
        for key in (failed_key, retry_key):
            s3_client.delete_object(Bucket=bucket, Key=key)
        s3_client.delete_bucket(Bucket=bucket)


@pytest.mark.integration
def test_create_bucket_with_versioning(s3_client):
    """Test S3 bucket creation with versioning enabled"""
    bucket_name = f'test-audit-bucket-{int(datetime.now().timestamp())}'

    # Create bucket
    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': 'us-east-2'}
    )

    # Enable versioning
    s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )

    # Verify versioning
    response = s3_client.get_bucket_versioning(Bucket=bucket_name)
    assert response['Status'] == 'Enabled'

    # Cleanup
    s3_client.delete_bucket(Bucket=bucket_name)


@pytest.mark.integration
def test_bucket_object_lock(s3_client):
    """Test S3 Object Lock configuration"""
    bucket_name = f'test-lock-bucket-{int(datetime.now().timestamp())}'

    # Create bucket with Object Lock enabled
    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': 'us-east-2'},
        ObjectLockEnabledForBucket=True
    )

    # Configure Object Lock retention
    s3_client.put_object_lock_configuration(
        Bucket=bucket_name,
        ObjectLockConfiguration={
            'ObjectLockEnabled': 'Enabled',
            'Rule': {
                'DefaultRetention': {
                    'Mode': 'COMPLIANCE',
                    'Days': 7
                }
            }
        }
    )

    # Verify Object Lock configuration
    response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
    assert response['ObjectLockConfiguration']['ObjectLockEnabled'] == 'Enabled'
    assert response['ObjectLockConfiguration']['Rule']['DefaultRetention']['Mode'] == 'COMPLIANCE'
    assert response['ObjectLockConfiguration']['Rule']['DefaultRetention']['Days'] == 7

    # Cleanup
    s3_client.delete_bucket(Bucket=bucket_name)


@pytest.mark.integration
def test_bucket_lifecycle_policy(s3_client):
    """Test S3 lifecycle policy configuration"""
    bucket_name = f'test-lifecycle-bucket-{int(datetime.now().timestamp())}'

    # Create bucket
    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': 'us-east-2'}
    )

    # Enable versioning (required for lifecycle policies)
    s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )

    # Configure lifecycle policy
    s3_client.put_bucket_lifecycle_configuration(
        Bucket=bucket_name,
        LifecycleConfiguration={
            'Rules': [
                {
                    'ID': 'expire-old-versions',
                    'Status': 'Enabled',
                    'Filter': {'Prefix': ''},
                    'NoncurrentVersionExpiration': {'NoncurrentDays': 90}
                }
            ]
        }
    )

    # Verify lifecycle configuration
    response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    assert len(response['Rules']) == 1
    assert response['Rules'][0]['ID'] == 'expire-old-versions'
    assert response['Rules'][0]['NoncurrentVersionExpiration']['NoncurrentDays'] == 90

    # Cleanup
    s3_client.delete_bucket(Bucket=bucket_name)


@pytest.mark.integration
def test_s3_sync_behavior(s3_client, tmp_path):
    """Test entrypoint-equivalent filtering uploads controls but not credentials."""
    bucket_name = f'test-sync-bucket-{int(datetime.now().timestamp())}'
    object_prefix = 'investigation-123/'
    raw_token_canary = 'raw-token-canary-4e2d54'
    base64_token_canary = 'cmF3LXRva2VuLWNhbmFyeS00ZTJkNTQ='
    account_response_canary = 'account-response-canary-user-29817'
    canaries = (raw_token_canary, base64_token_canary, account_response_canary)

    # Create bucket
    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': 'us-east-2'}
    )

    files = {
        'control.txt': 'ordinary audit control',
        '.config/rosa-boundary/config.yaml': 'unrelated persistent configuration',
        '.config/ocm/ocm.json': raw_token_canary,
        '.config/ocm/.ocm.json.upload.tmp': base64_token_canary,
        '.config/ocm/cache/account.json': account_response_canary,
        '.kube/config': raw_token_canary,
        '.kube/cache/discovery/response.json': account_response_canary,
    }
    for relative_path, contents in files.items():
        test_file = tmp_path / relative_path
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(contents)

    # Read the production patterns so this simulation fails if entrypoint
    # filtering drifts from the expected complete credential subtrees.
    entrypoint = Path(__file__).parents[3] / 'entrypoint.sh'
    exclude_patterns = re.findall(r'--exclude "([^"]+)"', entrypoint.read_text())
    assert exclude_patterns == ['.config/ocm/*', '.kube/*']
    assert all(not pattern.startswith('/') for pattern in exclude_patterns)

    for test_file in tmp_path.rglob('*'):
        if not test_file.is_file():
            continue
        relative_path = test_file.relative_to(tmp_path).as_posix()
        if any(fnmatch(relative_path, pattern) for pattern in exclude_patterns):
            continue
        s3_client.upload_file(
            str(test_file),
            bucket_name,
            f'{object_prefix}{relative_path}'
        )

    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=object_prefix)
    assert response['KeyCount'] == 2

    keys = sorted([obj['Key'] for obj in response['Contents']])
    assert keys == [
        'investigation-123/.config/rosa-boundary/config.yaml',
        'investigation-123/control.txt',
    ]
    assert not any('/.config/ocm/' in key or '/.kube/' in key for key in keys)

    uploaded_bodies = ''.join(
        s3_client.get_object(Bucket=bucket_name, Key=key)['Body'].read().decode()
        for key in keys
    )
    assert all(canary not in uploaded_bodies for canary in canaries)

    # Cleanup
    for obj in response['Contents']:
        s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
    s3_client.delete_bucket(Bucket=bucket_name)
