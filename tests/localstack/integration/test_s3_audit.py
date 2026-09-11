"""Test S3 audit bucket with WORM compliance."""

import re
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path

import pytest


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
