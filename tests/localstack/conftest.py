"""
pytest fixtures for LocalStack integration tests.
Provides boto3 clients configured for LocalStack endpoints.
"""

import os
import pytest
import boto3
from botocore.config import Config
import requests
import time

# LocalStack endpoint
LOCALSTACK_ENDPOINT = os.getenv('LOCALSTACK_ENDPOINT', 'http://localhost:4566')
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-2')

# Mock OIDC server
MOCK_OIDC_URL = os.getenv('MOCK_OIDC_URL', 'http://localhost:8080/realms/sre-ops')


@pytest.fixture(scope='session')
def localstack_available():
    """Check if LocalStack is running and skip tests if not"""
    try:
        response = requests.get(f'{LOCALSTACK_ENDPOINT}/_localstack/health', timeout=5)
        response.raise_for_status()
        health = response.json()

        # Check required services
        required_services = ['s3', 'iam', 'lambda', 'ecs', 'efs', 'kms']
        for service in required_services:
            if service not in health.get('services', {}):
                pytest.skip(f'LocalStack service not available: {service}')

        return True
    except (requests.ConnectionError, requests.Timeout):
        pytest.skip('LocalStack not running. Start with: make localstack-up')


@pytest.fixture(scope='session')
def mock_oidc_available():
    """Check if mock OIDC server is running"""
    try:
        response = requests.get(f'{MOCK_OIDC_URL}/../health', timeout=5)
        response.raise_for_status()
        return True
    except (requests.ConnectionError, requests.Timeout):
        pytest.skip('Mock OIDC server not running. Start with: make localstack-up')


@pytest.fixture(scope='session')
def boto_config():
    """Boto3 configuration for LocalStack"""
    return Config(
        region_name=AWS_REGION,
        signature_version='v4',
        retries={'max_attempts': 3, 'mode': 'standard'}
    )


@pytest.fixture
def s3_client(localstack_available, boto_config):
    """S3 client configured for LocalStack"""
    return boto3.client(
        's3',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def iam_client(localstack_available, boto_config):
    """IAM client configured for LocalStack"""
    return boto3.client(
        'iam',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def lambda_client(localstack_available, boto_config):
    """Lambda client configured for LocalStack"""
    return boto3.client(
        'lambda',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def ecs_client(localstack_available, boto_config):
    """ECS client configured for LocalStack"""
    return boto3.client(
        'ecs',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def efs_client(localstack_available, boto_config):
    """EFS client configured for LocalStack"""
    return boto3.client(
        'efs',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def kms_client(localstack_available, boto_config):
    """KMS client configured for LocalStack"""
    return boto3.client(
        'kms',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def logs_client(localstack_available, boto_config):
    """CloudWatch Logs client configured for LocalStack"""
    return boto3.client(
        'logs',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def sts_client(localstack_available, boto_config):
    """STS client configured for LocalStack"""
    return boto3.client(
        'sts',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def ec2_client(localstack_available, boto_config):
    """EC2 client configured for LocalStack"""
    return boto3.client(
        'ec2',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def ssm_client(localstack_available, boto_config):
    """SSM client configured for LocalStack"""
    return boto3.client(
        'ssm',
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=boto_config
    )


@pytest.fixture
def test_vpc(ssm_client):
    """Get VPC and subnet IDs created by init-aws.sh"""
    vpc_id = ssm_client.get_parameter(Name='/test/vpc-id')['Parameter']['Value']
    subnet1_id = ssm_client.get_parameter(Name='/test/subnet-1-id')['Parameter']['Value']
    subnet2_id = ssm_client.get_parameter(Name='/test/subnet-2-id')['Parameter']['Value']
    sg_id = ssm_client.get_parameter(Name='/test/security-group-id')['Parameter']['Value']

    return {
        'vpc_id': vpc_id,
        'subnet_ids': [subnet1_id, subnet2_id],
        'security_group_id': sg_id
    }


@pytest.fixture
def test_efs(efs_client):
    """Create EFS filesystem for testing"""
    # Create filesystem
    response = efs_client.create_file_system(
        CreationToken=f'test-efs-{int(time.time())}',
        PerformanceMode='generalPurpose',
        Encrypted=True,
        Tags=[
            {'Key': 'Name', 'Value': 'test-efs'},
            {'Key': 'Environment', 'Value': 'test'}
        ]
    )

    filesystem_id = response['FileSystemId']

    # Wait for filesystem to become available
    waiter = efs_client.get_waiter('file_system_available')
    waiter.wait(FileSystemId=filesystem_id)

    yield filesystem_id

    # Cleanup: delete all access points first
    try:
        access_points = efs_client.describe_access_points(FileSystemId=filesystem_id)
        for ap in access_points.get('AccessPoints', []):
            try:
                efs_client.delete_access_point(AccessPointId=ap['AccessPointId'])
            except Exception:
                pass
    except Exception:
        pass

    # Delete filesystem
    try:
        efs_client.delete_file_system(FileSystemId=filesystem_id)
    except Exception:
        pass


@pytest.fixture
def mock_oidc_issuer():
    """Mock OIDC issuer URL"""
    return MOCK_OIDC_URL


@pytest.fixture
def test_token_generator(mock_oidc_available):
    """
    Fixture that provides token generation function.
    Imports from mock_jwks module.
    """
    import sys
    import importlib.util

    # Load mock_jwks module
    spec = importlib.util.spec_from_file_location(
        "mock_jwks",
        "/Users/jjaggars/code/rosa-boundary/tests/localstack/oidc/mock_jwks.py"
    )
    mock_jwks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mock_jwks)

    return mock_jwks.create_test_token
