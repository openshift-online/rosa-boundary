"""
Unit tests for Lambda handler with security fixes.

Tests cover:
- Input validation (investigation_id, cluster_id)
- Authorization header redaction in logs
- Error response sanitization
- OIDC token validation
- IAM role management
- ECS task creation
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

# Import the handler
import handler


class TestInputValidation:
    """Test input validation for investigation_id and cluster_id."""

    def test_valid_alphanumeric_identifier(self):
        """Valid identifiers with alphanumeric characters."""
        assert handler.validate_identifier("test123", "test_field") is True
        assert handler.validate_identifier("cluster-456", "test_field") is True
        assert handler.validate_identifier("inv_789", "test_field") is True
        assert handler.validate_identifier("Rosa-Boundary-Dev", "test_field") is True

    def test_invalid_special_characters(self):
        """Invalid identifiers with special characters."""
        with pytest.raises(ValueError, match="must contain only alphanumeric"):
            handler.validate_identifier("test; DROP TABLE;", "test_field")

        with pytest.raises(ValueError, match="must contain only alphanumeric"):
            handler.validate_identifier("inv@123", "test_field")

        with pytest.raises(ValueError, match="must contain only alphanumeric"):
            handler.validate_identifier("test/../../etc/passwd", "test_field")

        with pytest.raises(ValueError, match="must contain only alphanumeric"):
            handler.validate_identifier("inv 123", "test_field")

    def test_invalid_length(self):
        """Invalid identifiers that are too long or empty."""
        with pytest.raises(ValueError, match="must be 64 characters or less"):
            handler.validate_identifier("a" * 65, "test_field")

        with pytest.raises(ValueError, match="cannot be empty"):
            handler.validate_identifier("", "test_field")

    def test_boundary_conditions(self):
        """Test boundary conditions for length."""
        assert handler.validate_identifier("a", "test_field") is True  # minimum length
        assert handler.validate_identifier("a" * 64, "test_field") is True  # maximum length


class TestHeaderRedaction:
    """Test that sensitive headers are redacted in logs."""

    @patch('handler.logger')
    def test_authorization_header_redacted(self, mock_logger):
        """Test that Authorization header is redacted in event logging."""
        event = {
            'headers': {
                'authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
                'content-type': 'application/json'
            },
            'body': json.dumps({
                'cluster_id': 'test-cluster',
                'investigation_id': 'inv-123'
            })
        }
        context = Mock()

        # Mock all the dependencies to get to the logging code
        with patch('handler.validate_oidc_token', return_value=None):
            handler.lambda_handler(event, context)

        # Check that logger.info was called with redacted headers
        calls = [str(call) for call in mock_logger.info.call_args_list]
        headers_logged = [call for call in calls if 'Headers:' in call]

        assert len(headers_logged) > 0, "Headers should be logged"

        # Verify the actual token is NOT in the logs
        for call in headers_logged:
            assert 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' not in call, \
                "Token should not appear in logs"
            assert 'REDACTED' in call or 'authorization' not in call.lower(), \
                "Authorization should be redacted"

    @patch('handler.logger')
    def test_x_oidc_token_header_redacted(self, mock_logger):
        """Test that X-OIDC-Token header is redacted in event logging."""
        event = {
            'headers': {
                'x-oidc-token': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
                'content-type': 'application/json'
            },
            'body': json.dumps({
                'cluster_id': 'test-cluster',
                'investigation_id': 'inv-123'
            })
        }
        context = Mock()

        with patch('handler.validate_oidc_token', return_value=None):
            handler.lambda_handler(event, context)

        calls = [str(call) for call in mock_logger.info.call_args_list]
        headers_logged = [call for call in calls if 'Headers:' in call]

        assert len(headers_logged) > 0, "Headers should be logged"
        for call in headers_logged:
            assert 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' not in call, \
                "OIDC token should not appear in logs"

    @patch('handler.logger')
    def test_other_headers_not_redacted(self, mock_logger):
        """Test that non-sensitive headers are still logged."""
        event = {
            'headers': {
                'authorization': 'Bearer secret-token',
                'content-type': 'application/json',
                'user-agent': 'test-client/1.0'
            },
            'body': json.dumps({
                'cluster_id': 'test',
                'investigation_id': 'inv-123'
            })
        }
        context = Mock()

        with patch('handler.validate_oidc_token', return_value=None):
            handler.lambda_handler(event, context)

        # Check that content-type is logged (not redacted)
        calls = [str(call) for call in mock_logger.info.call_args_list]
        headers_logged = [call for call in calls if 'Headers:' in call]

        # At least one log should contain content-type
        assert any('application/json' in call for call in headers_logged), \
            "Non-sensitive headers should be logged"


class TestErrorSanitization:
    """Test that error responses don't leak internal details."""

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    @patch('handler.logger')
    def test_generic_error_response(self, mock_logger):
        """Test that 500 errors return generic message without exception details."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test'},
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        # Force an exception
        with patch('handler.validate_oidc_token', side_effect=Exception("Internal database connection failed")):
            response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 500
        body = json.loads(response['body'])

        # Should have generic error
        assert 'error' in body
        assert body['error'] == 'Internal server error'

        # Should NOT leak internal details
        assert 'details' not in body, "Error details should not be in response"
        assert 'database' not in json.dumps(body).lower(), \
            "Internal error details should not leak"

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_exception_logged_but_not_returned(self):
        """Test that exceptions are logged server-side but not returned to client."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test'},
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        error_message = "Sensitive internal error: DB password incorrect"
        with patch('handler.logger') as mock_logger:
            with patch('handler.validate_oidc_token', side_effect=Exception(error_message)):
                response = handler.lambda_handler(event, context)

            # Error should be logged
            error_calls = [str(call) for call in mock_logger.error.call_args_list]
            assert any(error_message in call for call in error_calls), \
                "Exception should be logged server-side"

        # But not returned to client
        body = json.loads(response['body'])
        assert error_message not in json.dumps(body), \
            "Internal error should not be returned to client"


class TestLambdaHandler:
    """Test the main Lambda handler function."""

    def test_missing_oidc_token(self):
        """Test that missing OIDC token in all supported headers returns 401."""
        event = {
            'headers': {},
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 401
        body = json.loads(response['body'])
        assert 'OIDC token' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_x_oidc_token_header_accepted(self):
        """Test that X-OIDC-Token header is accepted (SigV4 flow)."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'x-oidc-token': 'test-token'},
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        with patch('handler.validate_oidc_token', return_value=None):
            response = handler.lambda_handler(event, context)

        # 401 from OIDC validation (not from missing token), meaning token was extracted
        assert response['statusCode'] == 401
        body = json.loads(response['body'])
        assert 'Invalid or expired token' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_authorization_bearer_fallback_accepted(self):
        """Test that Authorization: Bearer fallback is still accepted for backward compat."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test-token'},
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        with patch('handler.validate_oidc_token', return_value=None):
            response = handler.lambda_handler(event, context)

        # 401 from OIDC validation (not from missing token), meaning token was extracted
        assert response['statusCode'] == 401
        body = json.loads(response['body'])
        assert 'Invalid or expired token' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_x_oidc_token_takes_precedence_over_authorization(self):
        """Test that X-OIDC-Token is preferred over Authorization: Bearer."""
        import importlib
        importlib.reload(handler)

        captured_tokens = []

        def capture_token(token, *args, **kwargs):
            captured_tokens.append(token)
            return None

        event = {
            'headers': {
                'x-oidc-token': 'oidc-header-token',
                'authorization': 'Bearer bearer-token'
            },
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        with patch('handler.validate_oidc_token', side_effect=capture_token):
            handler.lambda_handler(event, context)

        assert len(captured_tokens) == 1
        assert captured_tokens[0] == 'oidc-header-token', \
            "X-OIDC-Token should be preferred over Authorization: Bearer"

    def test_invalid_authorization_format(self):
        """Test that non-Bearer Authorization and no X-OIDC-Token returns 401."""
        event = {
            'headers': {'authorization': 'Basic dXNlcjpwYXNz'},
            'body': json.dumps({'cluster_id': 'test', 'investigation_id': 'inv-123'})
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 401
        body = json.loads(response['body'])
        assert 'OIDC token' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_missing_required_fields(self):
        """Test that missing cluster_id or investigation_id returns 400."""
        event = {
            'headers': {'authorization': 'Bearer test-token'},
            'body': json.dumps({'oc_version': '4.20'})
        }
        context = Mock()

        # Reload globals after patching environment
        import importlib
        importlib.reload(handler)

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'Missing required fields' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_invalid_investigation_id(self):
        """Test that invalid investigation_id returns 400."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test-token'},
            'body': json.dumps({
                'cluster_id': 'valid-cluster',
                'investigation_id': 'invalid; DROP TABLE;'
            })
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'Invalid investigation_id' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_invalid_cluster_id(self):
        """Test that invalid cluster_id returns 400."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test-token'},
            'body': json.dumps({
                'cluster_id': 'cluster@invalid',
                'investigation_id': 'valid-inv'
            })
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'Invalid cluster_id' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    def test_invalid_json_body(self):
        """Test that invalid JSON returns 400."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test-token'},
            'body': 'not valid json{'
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'Invalid JSON' in body['error']

    @patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'us-east-2'}, clear=True)
    def test_missing_environment_variables(self):
        """Test that missing env vars returns 500.

        Note: AWS_DEFAULT_REGION is preserved because boto3 clients are
        initialized at module level and require a region.
        """
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer test-token'},
            'body': json.dumps({
                'cluster_id': 'test',
                'investigation_id': 'inv-123'
            })
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'configuration error' in body['error'].lower()

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared'
    })
    @patch('handler.validate_oidc_token')
    def test_invalid_oidc_token(self, mock_validate):
        """Test that invalid OIDC token returns 401."""
        import importlib
        importlib.reload(handler)

        mock_validate.return_value = None

        event = {
            'headers': {'authorization': 'Bearer invalid-token'},
            'body': json.dumps({
                'cluster_id': 'test',
                'investigation_id': 'inv-123'
            })
        }
        context = Mock()

        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 401
        body = json.loads(response['body'])
        assert 'Invalid or expired token' in body['error']

    @patch.dict('os.environ', {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared',
        'REQUIRED_GROUP': 'sre-team'
    })
    def test_missing_group_membership(self):
        """Test that users without required group get 403."""
        import importlib
        importlib.reload(handler)

        event = {
            'headers': {'authorization': 'Bearer valid-token'},
            'body': json.dumps({
                'cluster_id': 'test',
                'investigation_id': 'inv-123'
            })
        }
        context = Mock()

        with patch('handler.validate_oidc_token') as mock_validate:
            mock_validate.return_value = {
                'sub': 'user-123',
                'email': 'test@example.com',
                'groups': ['other-group']
            }

            response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 403
        body = json.loads(response['body'])
        assert 'not authorized' in body['error'].lower()


class TestResponseHelper:
    """Test the response helper function."""

    def test_response_format(self):
        """Test that response helper creates proper API Gateway response."""
        result = handler.response(200, {'message': 'success'})

        assert result['statusCode'] == 200
        assert 'body' in result
        body = json.loads(result['body'])
        assert body['message'] == 'success'

    def test_response_headers(self):
        """Test that CORS headers are included."""
        result = handler.response(200, {'data': 'test'})

        assert 'headers' in result
        assert 'Content-Type' in result['headers']
        assert result['headers']['Content-Type'] == 'application/json'


class TestSkipTask:
    """Test skip_task parameter and idempotent access point creation."""

    ENV_VARS = {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'test-task',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared',
        'REQUIRED_GROUP': 'sre-team'
    }

    def _make_event(self, extra_body=None):
        body = {'cluster_id': 'test-cluster', 'investigation_id': 'test-inv'}
        if extra_body:
            body.update(extra_body)
        return {
            'headers': {'authorization': 'Bearer valid-token'},
            'body': json.dumps(body)
        }

    def _mock_claims(self):
        return {
            'sub': 'user-123',
            'email': 'sre@example.com',
            'preferred_username': 'sre-user',
            'groups': ['sre-team']
        }

    BASE_TASK_DEF = {
        'taskDefinition': {
            'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-dev:1',
            'family': 'rosa-boundary-dev',
            'taskRoleArn': 'arn:aws:iam::123:role/task-role',
            'executionRoleArn': 'arn:aws:iam::123:role/exec-role',
            'networkMode': 'awsvpc',
            'containerDefinitions': [{'name': 'rosa-boundary', 'environment': []}],
            'volumes': [],
            'requiresCompatibilities': ['FARGATE'],
            'cpu': '256',
            'memory': '512',
        }
    }

    REGISTERED_TASK_DEF = {
        'taskDefinition': {
            'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-dev-test-cluster-test-inv-20260101T000000:1'
        }
    }

    @patch.dict('os.environ', ENV_VARS)
    def test_skip_task_default_false(self):
        """Test that skip_task defaults to False (backward compat)."""
        import importlib
        importlib.reload(handler)

        event = self._make_event()
        context = Mock()

        mock_ap = {'AccessPointId': 'fsap-new'}
        mock_task = {'tasks': [{'taskArn': 'arn:aws:ecs:us-east-1:123:task/abc123'}], 'failures': []}

        with patch('handler.validate_oidc_token', return_value=self._mock_claims()):
            with patch('handler.find_existing_access_point', return_value=None):
                with patch('handler.efs') as mock_efs:
                    with patch('handler.ecs') as mock_ecs:
                        mock_efs.create_access_point.return_value = mock_ap
                        mock_ecs.describe_task_definition.return_value = self.BASE_TASK_DEF
                        mock_ecs.register_task_definition.return_value = self.REGISTERED_TASK_DEF
                        mock_ecs.run_task.return_value = mock_task
                        mock_ecs.tag_resource.return_value = {}

                        response = handler.lambda_handler(event, context)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['message'] == 'Investigation task created successfully'
        assert body['task_arn'] != ''
        assert body['task_definition_arn'] != ''

    @patch.dict('os.environ', ENV_VARS)
    def test_skip_task_creates_access_point_only(self):
        """Test that skip_task=True creates EFS access point without launching ECS task."""
        import importlib
        importlib.reload(handler)

        event = self._make_event({'skip_task': True})
        context = Mock()

        mock_ap = {'AccessPointId': 'fsap-new'}

        with patch('handler.validate_oidc_token', return_value=self._mock_claims()):
            with patch('handler.find_existing_access_point', return_value=None):
                with patch('handler.efs') as mock_efs:
                    with patch('handler.ecs') as mock_ecs:
                        mock_efs.create_access_point.return_value = mock_ap

                        response = handler.lambda_handler(event, context)

                        # ECS task should NOT be launched and no task def registered
                        mock_ecs.run_task.assert_not_called()
                        mock_ecs.register_task_definition.assert_not_called()

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['message'] == 'Investigation created (no task launched)'
        assert body['access_point_id'] == 'fsap-new'
        assert body['task_arn'] == ''

    @patch.dict('os.environ', ENV_VARS)
    def test_idempotent_access_point_reuse(self):
        """Test that existing access point is reused instead of creating a new one."""
        import importlib
        importlib.reload(handler)

        event = self._make_event({'skip_task': True})
        context = Mock()

        existing_ap = {'AccessPointId': 'fsap-existing', 'LifeCycleState': 'available'}

        with patch('handler.validate_oidc_token', return_value=self._mock_claims()):
            with patch('handler.find_existing_access_point', return_value=existing_ap):
                with patch('handler.efs') as mock_efs:
                    with patch('handler.ecs') as mock_ecs:
                        response = handler.lambda_handler(event, context)

                        # EFS create should NOT be called when AP already exists
                        mock_efs.create_access_point.assert_not_called()
                        mock_ecs.run_task.assert_not_called()

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['access_point_id'] == 'fsap-existing'

    def test_find_existing_access_point_returns_none_when_not_found(self):
        """Test find_existing_access_point returns None when no matching AP exists."""
        with patch('handler.efs') as mock_efs:
            mock_efs.get_paginator.return_value.paginate.return_value = [
                {'AccessPoints': [
                    {
                        'AccessPointId': 'fsap-other',
                        'LifeCycleState': 'available',
                        'Tags': [
                            {'Key': 'ClusterID', 'Value': 'other-cluster'},
                            {'Key': 'InvestigationID', 'Value': 'other-inv'}
                        ]
                    }
                ]}
            ]

            result = handler.find_existing_access_point('fs-123', 'test-cluster', 'test-inv')

        assert result is None

    def test_find_existing_access_point_returns_match(self):
        """Test find_existing_access_point returns matching access point."""
        expected_ap = {
            'AccessPointId': 'fsap-match',
            'LifeCycleState': 'available',
            'Tags': [
                {'Key': 'ClusterID', 'Value': 'test-cluster'},
                {'Key': 'InvestigationID', 'Value': 'test-inv'}
            ]
        }

        with patch('handler.efs') as mock_efs:
            mock_efs.get_paginator.return_value.paginate.return_value = [
                {'AccessPoints': [expected_ap]}
            ]

            result = handler.find_existing_access_point('fs-123', 'test-cluster', 'test-inv')

        assert result is not None
        assert result['AccessPointId'] == 'fsap-match'

    def test_find_existing_access_point_skips_non_available(self):
        """Test that access points not in 'available' state are skipped."""
        with patch('handler.efs') as mock_efs:
            mock_efs.get_paginator.return_value.paginate.return_value = [
                {'AccessPoints': [
                    {
                        'AccessPointId': 'fsap-deleting',
                        'LifeCycleState': 'deleting',
                        'Tags': [
                            {'Key': 'ClusterID', 'Value': 'test-cluster'},
                            {'Key': 'InvestigationID', 'Value': 'test-inv'}
                        ]
                    }
                ]}
            ]

            result = handler.find_existing_access_point('fs-123', 'test-cluster', 'test-inv')

        assert result is None


class TestPerInvestigationTaskDef:
    """Test per-investigation task definition registration."""

    ENV_VARS = {
        'KEYCLOAK_URL': 'https://keycloak.test',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'OIDC_PROVIDER_ARN': 'arn:aws:iam::123:oidc-provider/test',
        'ECS_CLUSTER': 'test-cluster',
        'TASK_DEFINITION': 'rosa-boundary-dev',
        'SUBNETS': 'subnet-1,subnet-2',
        'SECURITY_GROUP': 'sg-123',
        'EFS_FILESYSTEM_ID': 'fs-123',
        'SHARED_ROLE_ARN': 'arn:aws:iam::123:role/test-sre-shared',
        'REQUIRED_GROUP': 'sre-team',
        'S3_AUDIT_BUCKET': 'my-audit-bucket',
    }

    BASE_TASK_DEF = {
        'taskDefinition': {
            'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-dev:1',
            'family': 'rosa-boundary-dev',
            'taskRoleArn': 'arn:aws:iam::123:role/task-role',
            'executionRoleArn': 'arn:aws:iam::123:role/exec-role',
            'networkMode': 'awsvpc',
            'containerDefinitions': [{
                'name': 'rosa-boundary',
                'environment': [
                    {'name': 'CLAUDE_CODE_USE_BEDROCK', 'value': '1'},
                    {'name': 'TASK_TIMEOUT', 'value': '3600'},
                ]
            }],
            'volumes': [],
            'requiresCompatibilities': ['FARGATE'],
            'cpu': '256',
            'memory': '512',
        }
    }

    def _make_registered_td(self, family_suffix):
        return {
            'taskDefinition': {
                'taskDefinitionArn': f'arn:aws:ecs:us-east-1:123:task-definition/{family_suffix}:1'
            }
        }

    def test_run_task_uses_per_investigation_task_def_arn(self):
        """Test that run_task is called with the registered per-investigation task def ARN."""
        per_inv_arn = 'arn:aws:ecs:us-east-1:123:task-definition/rosa-boundary-dev-c1-inv1-20260101T000000:1'

        with patch('handler.ecs') as mock_ecs:
            with patch('handler.efs') as mock_efs:
                mock_ecs.describe_task_definition.return_value = self.BASE_TASK_DEF
                mock_ecs.register_task_definition.return_value = {
                    'taskDefinition': {'taskDefinitionArn': per_inv_arn}
                }
                mock_ecs.run_task.return_value = {
                    'tasks': [{'taskArn': 'arn:aws:ecs:us-east-1:123:task/abc'}],
                    'failures': []
                }
                mock_ecs.tag_resource.return_value = {}
                mock_efs.get_paginator.return_value.paginate.return_value = [{'AccessPoints': []}]
                mock_efs.create_access_point.return_value = {'AccessPointId': 'fsap-new'}

                result = handler.create_investigation_task(
                    cluster='test-cluster',
                    task_def='rosa-boundary-dev',
                    oidc_sub='sub-123',
                    username='sre-user',
                    investigation_id='inv1',
                    cluster_id='c1',
                    subnets=['subnet-1'],
                    security_group='sg-123',
                    efs_filesystem_id='fs-123',
                    oc_version='4.20',
                    task_timeout=3600
                )

        # run_task must use the per-investigation ARN, not the base family name
        call_kwargs = mock_ecs.run_task.call_args[1]
        assert call_kwargs['taskDefinition'] == per_inv_arn
        assert result['taskDefinitionArn'] == per_inv_arn

    def test_volume_config_contains_per_investigation_access_point_id(self):
        """Test that register_task_definition is called with the per-investigation access point ID."""
        access_point_id = 'fsap-per-inv-123'

        with patch('handler.ecs') as mock_ecs:
            mock_ecs.describe_task_definition.return_value = self.BASE_TASK_DEF
            mock_ecs.register_task_definition.return_value = {
                'taskDefinition': {'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123:task-definition/test:1'}
            }

            handler.register_investigation_task_definition(
                task_def='rosa-boundary-dev',
                cluster_id='cluster1',
                investigation_id='inv1',
                access_point_id=access_point_id,
                efs_filesystem_id='fs-123',
                oc_version='4.20',
                task_timeout=3600,
                s3_audit_bucket='my-bucket'
            )

        call_kwargs = mock_ecs.register_task_definition.call_args[1]
        volumes = call_kwargs['volumes']
        assert len(volumes) == 1
        assert volumes[0]['name'] == 'sre-home'
        efs_config = volumes[0]['efsVolumeConfiguration']
        assert efs_config['authorizationConfig']['accessPointId'] == access_point_id
        assert efs_config['fileSystemId'] == 'fs-123'
        assert efs_config['transitEncryption'] == 'ENABLED'
        assert efs_config['authorizationConfig']['iam'] == 'ENABLED'

    def test_family_name_matches_expected_pattern(self):
        """Test that the registered task definition family name matches the expected pattern."""
        import re

        with patch('handler.ecs') as mock_ecs:
            mock_ecs.describe_task_definition.return_value = self.BASE_TASK_DEF
            mock_ecs.register_task_definition.return_value = {
                'taskDefinition': {'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123:task-definition/test:1'}
            }

            handler.register_investigation_task_definition(
                task_def='rosa-boundary-dev',
                cluster_id='my-cluster',
                investigation_id='my-inv',
                access_point_id='fsap-123',
                efs_filesystem_id='fs-123',
                oc_version='4.20',
                task_timeout=3600,
                s3_audit_bucket='bucket'
            )

        call_kwargs = mock_ecs.register_task_definition.call_args[1]
        family = call_kwargs['family']
        # Pattern: {base_family}-{cluster_id}-{investigation_id}-{timestamp}
        pattern = r'^rosa-boundary-dev-my-cluster-my-inv-\d{8}T\d{6}$'
        assert re.match(pattern, family), f"Family name '{family}' does not match expected pattern"

    def test_env_vars_baked_into_task_definition(self):
        """Test that investigation-specific env vars are baked into the task definition."""
        with patch('handler.ecs') as mock_ecs:
            mock_ecs.describe_task_definition.return_value = self.BASE_TASK_DEF
            mock_ecs.register_task_definition.return_value = {
                'taskDefinition': {'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123:task-definition/test:1'}
            }

            handler.register_investigation_task_definition(
                task_def='rosa-boundary-dev',
                cluster_id='cluster1',
                investigation_id='inv1',
                access_point_id='fsap-123',
                efs_filesystem_id='fs-123',
                oc_version='4.18',
                task_timeout=7200,
                s3_audit_bucket='my-bucket'
            )

        call_kwargs = mock_ecs.register_task_definition.call_args[1]
        container_defs = call_kwargs['containerDefinitions']
        assert len(container_defs) == 1
        env = {e['name']: e['value'] for e in container_defs[0]['environment']}
        assert env['CLUSTER_ID'] == 'cluster1'
        assert env['INVESTIGATION_ID'] == 'inv1'
        assert env['OC_VERSION'] == '4.18'
        assert env['S3_AUDIT_BUCKET'] == 'my-bucket'
        assert env['TASK_TIMEOUT'] == '7200'
        # Base env vars preserved
        assert env['CLAUDE_CODE_USE_BEDROCK'] == '1'

    @patch.dict('os.environ', ENV_VARS)
    def test_skip_task_does_not_register_task_definition(self):
        """Test that skip_task=True does not call register_task_definition."""
        import importlib
        importlib.reload(handler)

        with patch('handler.ecs') as mock_ecs:
            with patch('handler.efs') as mock_efs:
                mock_efs.get_paginator.return_value.paginate.return_value = [{'AccessPoints': []}]
                mock_efs.create_access_point.return_value = {'AccessPointId': 'fsap-new'}

                handler.create_investigation_task(
                    cluster='test-cluster',
                    task_def='rosa-boundary-dev',
                    oidc_sub='sub-123',
                    username='sre-user',
                    investigation_id='inv1',
                    cluster_id='c1',
                    subnets=['subnet-1'],
                    security_group='sg-123',
                    efs_filesystem_id='fs-123',
                    oc_version='4.20',
                    task_timeout=3600,
                    skip_task=True
                )

                mock_ecs.register_task_definition.assert_not_called()
                mock_ecs.run_task.assert_not_called()

    @patch.dict('os.environ', ENV_VARS)
    def test_registration_failure_cleans_up_newly_created_access_point(self):
        """Test that task def registration failure deletes a newly created access point."""
        import importlib
        importlib.reload(handler)

        with patch('handler.ecs') as mock_ecs:
            with patch('handler.efs') as mock_efs:
                mock_efs.get_paginator.return_value.paginate.return_value = [{'AccessPoints': []}]
                mock_efs.create_access_point.return_value = {'AccessPointId': 'fsap-new'}
                mock_ecs.describe_task_definition.side_effect = Exception("Registration failed")

                with pytest.raises(Exception, match="Registration failed"):
                    handler.create_investigation_task(
                        cluster='test-cluster',
                        task_def='rosa-boundary-dev',
                        oidc_sub='sub-123',
                        username='sre-user',
                        investigation_id='inv1',
                        cluster_id='c1',
                        subnets=['subnet-1'],
                        security_group='sg-123',
                        efs_filesystem_id='fs-123',
                        oc_version='4.20',
                        task_timeout=3600
                    )

                # Newly created access point should be cleaned up
                mock_efs.delete_access_point.assert_called_once_with(AccessPointId='fsap-new')

    @patch.dict('os.environ', ENV_VARS)
    def test_registration_failure_does_not_delete_reused_access_point(self):
        """Test that task def registration failure does not delete a reused access point."""
        import importlib
        importlib.reload(handler)

        existing_ap = {'AccessPointId': 'fsap-existing', 'LifeCycleState': 'available'}

        with patch('handler.ecs') as mock_ecs:
            with patch('handler.efs') as mock_efs:
                mock_efs.get_paginator.return_value.paginate.return_value = [
                    {'AccessPoints': [{
                        'AccessPointId': 'fsap-existing',
                        'LifeCycleState': 'available',
                        'Tags': [
                            {'Key': 'ClusterID', 'Value': 'c1'},
                            {'Key': 'InvestigationID', 'Value': 'inv1'}
                        ]
                    }]}
                ]
                mock_ecs.describe_task_definition.side_effect = Exception("Registration failed")

                with pytest.raises(Exception, match="Registration failed"):
                    handler.create_investigation_task(
                        cluster='test-cluster',
                        task_def='rosa-boundary-dev',
                        oidc_sub='sub-123',
                        username='sre-user',
                        investigation_id='inv1',
                        cluster_id='c1',
                        subnets=['subnet-1'],
                        security_group='sg-123',
                        efs_filesystem_id='fs-123',
                        oc_version='4.20',
                        task_timeout=3600
                    )

                # Reused access point should NOT be deleted
                mock_efs.delete_access_point.assert_not_called()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
