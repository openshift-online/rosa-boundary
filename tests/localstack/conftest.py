"""
pytest fixtures for LocalStack integration tests.
Provides boto3 clients configured for LocalStack endpoints.
"""

import os
import logging
import pytest
import boto3
from botocore.config import Config
import requests
import time

logger = logging.getLogger(__name__)

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
        # Mock OIDC server has /health endpoint at root
        base_url = MOCK_OIDC_URL.rsplit('/realms', 1)[0]
        response = requests.get(f'{base_url}/health', timeout=5)
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
    import time

    # Wait for init-aws.sh to complete (runs async in LocalStack ready.d/)
    max_retries = 12
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            vpc_id = ssm_client.get_parameter(Name='/test/vpc-id')['Parameter']['Value']
            subnet1_id = ssm_client.get_parameter(Name='/test/subnet-1-id')['Parameter']['Value']
            subnet2_id = ssm_client.get_parameter(Name='/test/subnet-2-id')['Parameter']['Value']
            sg_id = ssm_client.get_parameter(Name='/test/security-group-id')['Parameter']['Value']

            return {
                'vpc_id': vpc_id,
                'subnet_ids': [subnet1_id, subnet2_id],
                'security_group_id': sg_id
            }
        except ssm_client.exceptions.ParameterNotFound:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                raise


@pytest.fixture
def test_efs(efs_client):
    """Create EFS filesystem for testing"""
    # Use unique creation token to avoid conflicts
    creation_token = f'test-efs-{int(time.time() * 1000)}'

    # Create filesystem
    response = efs_client.create_file_system(
        CreationToken=creation_token,
        PerformanceMode='generalPurpose',
        Encrypted=True,
        Tags=[
            {'Key': 'Name', 'Value': 'test-efs'},
            {'Key': 'Environment', 'Value': 'test'}
        ]
    )

    filesystem_id = response['FileSystemId']

    # LocalStack doesn't support EFS waiters, so just wait a bit
    time.sleep(2)

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
def test_token_generator(mock_oidc_available, mock_oidc_issuer):
    """
    Fixture that provides token generation function.
    Creates JWT tokens directly without importing mock_jwks.
    """
    import sys
    from datetime import datetime, timedelta

    # Temporarily remove lambda directory from path to avoid importing Linux binaries
    lambda_dir = '/Users/jjaggars/code/rosa-boundary/lambda/create-investigation'
    original_path = sys.path.copy()
    sys.path = [p for p in sys.path if not p.startswith(lambda_dir)]

    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
    finally:
        sys.path = original_path

    # Load private key
    keys_path = '/Users/jjaggars/code/rosa-boundary/tests/localstack/oidc/test_keys'
    with open(f'{keys_path}/private.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    def create_test_token(sub='test-user', groups=None, email='test@example.com',
                         exp_minutes=60, extra_claims=None):
        """Create a test JWT token"""
        if groups is None:
            groups = ['sre-team']

        now = datetime.utcnow()

        claims = {
            'iss': mock_oidc_issuer,
            'sub': sub,
            'aud': 'aws-sre-access',
            'exp': int((now + timedelta(minutes=exp_minutes)).timestamp()),
            'iat': int(now.timestamp()),
            'email': email,
            'email_verified': True,
            'groups': groups,
        }

        if extra_claims:
            claims.update(extra_claims)

        return jwt.encode(claims, private_key, algorithm='RS256', headers={'kid': 'test-key-1'})

    return create_test_token


class ECSCleanupTracker:
    """Track ECS resources for cleanup in dependency order"""

    def __init__(self, ecs_client, iam_client, efs_client):
        self.ecs_client = ecs_client
        self.iam_client = iam_client
        self.efs_client = efs_client
        self.tasks = []  # (cluster, task_arn)
        self.task_definitions = []  # task_def_arn
        self.clusters = []  # cluster_name
        self.roles = []  # (role_name, [policy_names])
        self.access_points = []  # access_point_id

    def register_task(self, cluster, task_arn):
        """Register task for cleanup"""
        self.tasks.append((cluster, task_arn))

    def register_task_definition(self, task_def_arn):
        """Register task definition for cleanup"""
        self.task_definitions.append(task_def_arn)

    def register_cluster(self, cluster_name):
        """Register cluster for cleanup"""
        self.clusters.append(cluster_name)

    def register_role(self, role_name, policy_names=None):
        """Register IAM role for cleanup"""
        if policy_names is None:
            policy_names = []
        self.roles.append((role_name, policy_names))

    def register_access_point(self, access_point_id):
        """Register EFS access point for cleanup"""
        self.access_points.append(access_point_id)

    def cleanup(self):
        """Cleanup resources in dependency order"""
        # Step 1: Stop tasks
        for cluster, task_arn in self.tasks:
            try:
                self.ecs_client.stop_task(cluster=cluster, task=task_arn, reason='Test cleanup')
            except Exception as e:
                logger.warning(f"Failed to stop task {task_arn}: {e}")

        # Step 2: Deregister task definitions
        for task_def_arn in self.task_definitions:
            try:
                self.ecs_client.deregister_task_definition(taskDefinition=task_def_arn)
            except Exception as e:
                logger.warning(f"Failed to deregister task definition {task_def_arn}: {e}")

        # Step 3: Delete IAM role policies and roles
        for role_name, policy_names in self.roles:
            for policy_name in policy_names:
                try:
                    self.iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                except Exception as e:
                    logger.warning(f"Failed to delete role policy {policy_name} from {role_name}: {e}")
            try:
                self.iam_client.delete_role(RoleName=role_name)
            except Exception as e:
                logger.warning(f"Failed to delete role {role_name}: {e}")

        # Step 4: Delete EFS access points
        for access_point_id in self.access_points:
            try:
                self.efs_client.delete_access_point(AccessPointId=access_point_id)
            except Exception as e:
                logger.warning(f"Failed to delete access point {access_point_id}: {e}")

        # Step 5: Delete clusters
        for cluster_name in self.clusters:
            try:
                self.ecs_client.delete_cluster(cluster=cluster_name)
            except Exception as e:
                logger.warning(f"Failed to delete cluster {cluster_name}: {e}")


@pytest.fixture
def ecs_cleanup(ecs_client, iam_client, efs_client):
    """Fixture for ECS resource cleanup"""
    tracker = ECSCleanupTracker(ecs_client, iam_client, efs_client)
    yield tracker
    tracker.cleanup()
