"""Test S3 audit bucket with WORM compliance"""

import pytest
from datetime import datetime


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
    """Test S3 sync behavior (simulating entrypoint.sh backup)"""
    bucket_name = f'test-sync-bucket-{int(datetime.now().timestamp())}'

    # Create bucket
    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': 'us-east-2'}
    )

    # Create test files
    test_file1 = tmp_path / 'test1.txt'
    test_file1.write_text('Test content 1')

    test_file2 = tmp_path / 'subdir' / 'test2.txt'
    test_file2.parent.mkdir(parents=True, exist_ok=True)
    test_file2.write_text('Test content 2')

    # Upload files
    s3_client.upload_file(str(test_file1), bucket_name, 'investigation-123/test1.txt')
    s3_client.upload_file(str(test_file2), bucket_name, 'investigation-123/subdir/test2.txt')

    # Verify files exist
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix='investigation-123/')
    assert response['KeyCount'] == 2

    keys = sorted([obj['Key'] for obj in response['Contents']])
    assert keys == ['investigation-123/subdir/test2.txt', 'investigation-123/test1.txt']

    # Cleanup
    for obj in response['Contents']:
        s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
    s3_client.delete_bucket(Bucket=bucket_name)
