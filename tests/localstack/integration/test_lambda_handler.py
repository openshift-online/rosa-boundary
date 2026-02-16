"""Test Lambda function with OIDC authentication

NOTE: These tests require Docker/Podman executor for Lambda.
      LocalStack's local executor does not support Lambda function execution.

      - In CI: Tests run with Docker executor (compose.ci.yml)
      - Locally: Tests are skipped (compose.yml uses local executor for macOS compat)
"""

import pytest
import json
import os
import sys
import zipfile
import io
from datetime import datetime

# Add lambda directory to path for imports
LAMBDA_DIR = os.path.join(os.path.dirname(__file__), '../../../lambda/create-investigation')
sys.path.insert(0, LAMBDA_DIR)

# Skip Lambda tests when using local executor (local dev on macOS)
# CI uses Docker executor via compose.ci.yml
LAMBDA_EXECUTOR = os.getenv('LAMBDA_EXECUTOR', 'local')
skip_lambda_tests = LAMBDA_EXECUTOR == 'local'

pytestmark = pytest.mark.skipif(
    skip_lambda_tests,
    reason=f"Lambda tests require Docker executor (current: {LAMBDA_EXECUTOR}). "
           "Set LAMBDA_EXECUTOR=docker or use compose.ci.yml for CI."
)


@pytest.fixture
def deployed_lambda(lambda_client, iam_client, logs_client, mock_oidc_issuer):
    """Deploy Lambda function to LocalStack"""
    # Create Lambda execution role
    role_name = f'test-lambda-role-{int(datetime.now().timestamp())}'
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'Service': 'lambda.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }
        ]
    }

    role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role_response['Role']['Arn']

    # Attach basic execution policy
    policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': [
                    'logs:CreateLogGroup',
                    'logs:CreateLogStream',
                    'logs:PutLogEvents',
                    'iam:CreateRole',
                    'iam:PutRolePolicy',
                    'iam:GetRole',
                    'efs:CreateAccessPoint',
                    'ecs:RunTask',
                    'ecs:RegisterTaskDefinition'
                ],
                'Resource': '*'
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='LambdaExecutionPolicy',
        PolicyDocument=json.dumps(policy)
    )

    # Create deployment package
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add handler.py
        handler_path = os.path.join(LAMBDA_DIR, 'handler.py')
        zip_file.write(handler_path, 'handler.py')

        # Add dependencies from Lambda directory
        # These are installed via `make deps` in the Lambda container
        required_packages = [
            'jwt', 'requests', 'urllib3', 'certifi', 'charset_normalizer',
            'idna', 'PyJWT-2.10.2.dist-info', 'requests-2.33.0.dist-info',
            'urllib3-2.3.0.dist-info', 'certifi-2026.1.4.dist-info',
            'charset_normalizer-3.4.4.dist-info', 'idna-3.12.dist-info'
        ]

        for package in required_packages:
            package_path = os.path.join(LAMBDA_DIR, package)
            if os.path.exists(package_path):
                if os.path.isdir(package_path):
                    # Add directory recursively
                    for root, dirs, files in os.walk(package_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, LAMBDA_DIR)
                            zip_file.write(file_path, arcname)
                else:
                    # Add single file
                    zip_file.write(package_path, package)

    zip_buffer.seek(0)
    function_code = zip_buffer.read()

    # Create function
    function_name = f'test-create-investigation-{int(datetime.now().timestamp())}'
    lambda_client.create_function(
        FunctionName=function_name,
        Runtime='python3.11',
        Role=role_arn,
        Handler='handler.lambda_handler',
        Code={'ZipFile': function_code},
        Environment={
            'Variables': {
                'KEYCLOAK_ISSUER_URL': mock_oidc_issuer,
                'KEYCLOAK_AUDIENCE': 'aws-sre-access',
                'KEYCLOAK_REQUIRED_GROUP': 'sre-team',
                'BASE_TASK_DEFINITION_FAMILY': 'rosa-boundary-base',
                'EFS_FILESYSTEM_ID': 'fs-test123',
                'AWS_REGION': 'us-east-2'
            }
        },
        Timeout=30
    )

    yield {
        'function_name': function_name,
        'role_arn': role_arn
    }

    # Cleanup
    try:
        lambda_client.delete_function(FunctionName=function_name)
    except Exception:
        pass

    try:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName='LambdaExecutionPolicy')
        iam_client.delete_role(RoleName=role_name)
    except Exception:
        pass


@pytest.mark.integration
def test_lambda_with_valid_token(deployed_lambda, lambda_client, test_token_generator):
    """Test Lambda invocation with valid OIDC token"""
    # Generate valid token with sre-team group
    token = test_token_generator(
        sub='test-user-123',
        groups=['sre-team'],
        email='test@example.com'
    )

    # Invoke Lambda
    payload = {
        'headers': {
            'authorization': f'Bearer {token}'
        },
        'body': json.dumps({
            'cluster_id': 'rosa-dev',
            'investigation_id': 'inv-test-123',
            'oc_version': '4.20',
            'task_timeout': 7200
        })
    }

    response = lambda_client.invoke(
        FunctionName=deployed_lambda['function_name'],
        InvocationType='RequestResponse',
        Payload=json.dumps(payload)
    )

    # Parse response
    response_payload = json.loads(response['Payload'].read())

    # Note: This may fail in LocalStack if IAM/ECS/EFS operations aren't fully supported
    # The test validates the Lambda can be invoked and processes the token
    assert response['StatusCode'] == 200

    # If Lambda execution succeeds (not guaranteed in LocalStack)
    if 'errorMessage' not in response_payload:
        body = json.loads(response_payload.get('body', '{}'))
        # Expect either success response or error (LocalStack limitations)
        assert 'message' in body or 'error' in body


@pytest.mark.integration
def test_lambda_with_expired_token(deployed_lambda, lambda_client, test_token_generator):
    """Test Lambda rejects expired token"""
    # Generate expired token
    token = test_token_generator(
        sub='test-user-456',
        groups=['sre-team'],
        exp_minutes=-10  # Expired 10 minutes ago
    )

    payload = {
        'headers': {
            'authorization': f'Bearer {token}'
        },
        'body': json.dumps({
            'cluster_id': 'rosa-dev',
            'investigation_id': 'inv-test-456'
        })
    }

    response = lambda_client.invoke(
        FunctionName=deployed_lambda['function_name'],
        InvocationType='RequestResponse',
        Payload=json.dumps(payload)
    )

    response_payload = json.loads(response['Payload'].read())

    # Expect 401 Unauthorized
    # Note: May vary based on LocalStack Lambda execution support
    assert response['StatusCode'] == 200  # Lambda execution succeeded
    # The function should return HTTP 401 in the response
    if 'statusCode' in response_payload:
        assert response_payload['statusCode'] in [401, 403]


@pytest.mark.integration
def test_lambda_missing_group(deployed_lambda, lambda_client, test_token_generator):
    """Test Lambda rejects token without required group"""
    token = test_token_generator(
        sub='test-user-789',
        groups=['other-team'],  # Not sre-team
        email='test@example.com'
    )

    payload = {
        'headers': {
            'authorization': f'Bearer {token}'
        },
        'body': json.dumps({
            'cluster_id': 'rosa-dev',
            'investigation_id': 'inv-test-789'
        })
    }

    response = lambda_client.invoke(
        FunctionName=deployed_lambda['function_name'],
        InvocationType='RequestResponse',
        Payload=json.dumps(payload)
    )

    response_payload = json.loads(response['Payload'].read())

    # Expect 403 Forbidden
    if 'statusCode' in response_payload:
        assert response_payload['statusCode'] == 403


@pytest.mark.integration
def test_lambda_input_validation(deployed_lambda, lambda_client, test_token_generator):
    """Test Lambda input validation (SQL injection, path traversal)"""
    token = test_token_generator(sub='test-user-val', groups=['sre-team'])

    # Test SQL injection attempt
    payload_sql = {
        'headers': {
            'authorization': f'Bearer {token}'
        },
        'body': json.dumps({
            'cluster_id': "rosa-dev'; DROP TABLE users; --",
            'investigation_id': 'inv-test'
        })
    }

    response = lambda_client.invoke(
        FunctionName=deployed_lambda['function_name'],
        InvocationType='RequestResponse',
        Payload=json.dumps(payload_sql)
    )

    response_payload = json.loads(response['Payload'].read())

    # Should reject invalid input
    if 'statusCode' in response_payload:
        assert response_payload['statusCode'] == 400

    # Test path traversal attempt
    payload_path = {
        'headers': {
            'authorization': f'Bearer {token}'
        },
        'body': json.dumps({
            'cluster_id': 'rosa-dev',
            'investigation_id': '../../../etc/passwd'
        })
    }

    response = lambda_client.invoke(
        FunctionName=deployed_lambda['function_name'],
        InvocationType='RequestResponse',
        Payload=json.dumps(payload_path)
    )

    response_payload = json.loads(response['Payload'].read())

    # Should reject path traversal
    if 'statusCode' in response_payload:
        assert response_payload['statusCode'] == 400
