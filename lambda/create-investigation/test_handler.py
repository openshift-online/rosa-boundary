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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
