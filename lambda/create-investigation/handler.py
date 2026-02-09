"""
AWS Lambda handler for creating investigation tasks with OIDC authentication.

This Lambda validates Keycloak OIDC tokens, manages per-user IAM roles with
tag-based authorization, creates EFS access points, and launches ECS tasks.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

import boto3
import jwt
import requests
from jwt import PyJWKClient
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
iam = boto3.client('iam')
ecs = boto3.client('ecs')
efs = boto3.client('efs')

# Environment variables
KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL')
KEYCLOAK_REALM = os.environ.get('KEYCLOAK_REALM')
KEYCLOAK_CLIENT_ID = os.environ.get('KEYCLOAK_CLIENT_ID')
OIDC_PROVIDER_ARN = os.environ.get('OIDC_PROVIDER_ARN')
ECS_CLUSTER = os.environ.get('ECS_CLUSTER')
TASK_DEFINITION = os.environ.get('TASK_DEFINITION')
SUBNETS = os.environ.get('SUBNETS', '').split(',')
SECURITY_GROUP = os.environ.get('SECURITY_GROUP')
EFS_FILESYSTEM_ID = os.environ.get('EFS_FILESYSTEM_ID')
REQUIRED_GROUP = os.environ.get('REQUIRED_GROUP', 'sre-team')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for creating investigation tasks.

    Args:
        event: API Gateway event containing Authorization header and request body
        context: Lambda context object

    Returns:
        API Gateway response with status code and body
    """
    try:
        # Debug: log event structure (redact sensitive headers)
        logger.info(f"Event keys: {list(event.keys())}")
        headers_redacted = {k: '***REDACTED***' if k.lower() == 'authorization' else v
                           for k, v in event.get('headers', {}).items()}
        logger.info(f"Headers: {headers_redacted}")

        # Extract and validate Authorization header
        headers = event.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("Missing or invalid Authorization header")
            return response(401, {'error': 'Missing or invalid Authorization header'})

        token = auth_header.split(' ', 1)[1]

        # Validate environment configuration
        missing_vars = []
        for var_name in ['KEYCLOAK_URL', 'KEYCLOAK_REALM', 'KEYCLOAK_CLIENT_ID',
                         'OIDC_PROVIDER_ARN', 'ECS_CLUSTER', 'TASK_DEFINITION',
                         'SUBNETS', 'SECURITY_GROUP', 'EFS_FILESYSTEM_ID']:
            if not globals()[var_name] or (var_name == 'SUBNETS' and not SUBNETS[0]):
                missing_vars.append(var_name)

        if missing_vars:
            logger.error(f"Missing required environment variables: {missing_vars}")
            return response(500, {'error': 'Lambda configuration error'})

        # Parse request body
        try:
            body = json.loads(event.get('body', '{}'))
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in request body")
            return response(400, {'error': 'Invalid JSON in request body'})

        investigation_id = body.get('investigation_id')
        cluster_id = body.get('cluster_id')
        oc_version = body.get('oc_version', '4.20')

        if not investigation_id or not cluster_id:
            logger.warning("Missing required fields: investigation_id or cluster_id")
            return response(400, {'error': 'Missing required fields: investigation_id, cluster_id'})

        # Validate identifiers for safe characters
        try:
            validate_identifier(investigation_id, 'investigation_id')
            validate_identifier(cluster_id, 'cluster_id')
        except ValueError as e:
            logger.warning(f"Invalid input: {str(e)}")
            return response(400, {'error': str(e)})

        # Validate OIDC token
        logger.info("Validating OIDC token")
        claims = validate_oidc_token(token, KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID)

        if not claims:
            logger.warning("Token validation failed")
            return response(401, {'error': 'Invalid or expired token'})

        # Extract user info from claims
        user_sub = claims.get('sub')
        user_email = claims.get('email', 'unknown')
        username = claims.get('preferred_username', user_email)
        groups = claims.get('groups', [])

        logger.info(f"Token validated for user: {username} (sub: {user_sub})")

        # Check group membership
        if REQUIRED_GROUP not in groups:
            logger.warning(f"User {username} not in required group {REQUIRED_GROUP}")
            return response(403, {
                'error': f'User not authorized: missing {REQUIRED_GROUP} group membership',
                'groups': groups
            })

        logger.info(f"User {username} authorized with group {REQUIRED_GROUP}")

        # Get or create user role
        logger.info(f"Getting or creating IAM role for user {username}")
        role_arn, role_created = get_or_create_user_role(
            user_sub,
            KEYCLOAK_CLIENT_ID,
            OIDC_PROVIDER_ARN
        )

        if role_created:
            logger.info(f"Created new IAM role: {role_arn}")
        else:
            logger.info(f"Using existing IAM role: {role_arn}")

        # Create investigation task
        logger.info(f"Creating investigation task: {investigation_id} for cluster {cluster_id}")
        task_info = create_investigation_task(
            cluster=ECS_CLUSTER,
            task_def=TASK_DEFINITION,
            owner_sub=user_sub,
            owner_username=username,
            investigation_id=investigation_id,
            cluster_id=cluster_id,
            subnets=SUBNETS,
            security_group=SECURITY_GROUP,
            efs_filesystem_id=EFS_FILESYSTEM_ID,
            oc_version=oc_version
        )

        logger.info(f"Investigation task created successfully: {task_info['taskArn']}")

        # Return success response
        return response(200, {
            'message': 'Investigation task created successfully',
            'role_arn': role_arn,
            'role_created': role_created,
            'task_arn': task_info['taskArn'],
            'access_point_id': task_info['accessPointId'],
            'investigation_id': investigation_id,
            'cluster_id': cluster_id,
            'owner': username,
            'oc_version': oc_version
        })

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return response(500, {'error': 'Internal server error'})


def validate_identifier(identifier: str, field_name: str) -> bool:
    """
    Validate that an identifier contains only safe characters.

    Args:
        identifier: The identifier to validate
        field_name: Name of the field (for error messages)

    Returns:
        True if valid, raises ValueError if invalid
    """
    import re

    # Check length first
    if len(identifier) < 1:
        raise ValueError(f"Invalid {field_name}: cannot be empty")

    if len(identifier) > 64:
        raise ValueError(f"Invalid {field_name}: must be 64 characters or less")

    # Allow alphanumeric, hyphens, and underscores only
    if not re.match(r'^[a-zA-Z0-9_-]+$', identifier):
        raise ValueError(f"Invalid {field_name}: must contain only alphanumeric characters, hyphens, and underscores")

    return True


def validate_oidc_token(token: str, keycloak_url: str, realm: str, client_id: str) -> Optional[Dict[str, Any]]:
    """
    Validate OIDC token and extract claims.

    Args:
        token: JWT token string
        keycloak_url: Keycloak server URL
        realm: Keycloak realm name
        client_id: Expected audience claim

    Returns:
        Decoded token claims or None if validation fails
    """
    try:
        # Construct JWKS URL
        jwks_url = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/certs"
        logger.info(f"Fetching JWKS from: {jwks_url}")

        # Create JWKS client
        jwks_client = PyJWKClient(jwks_url)

        # Get signing key from token
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Decode and validate token
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True
            }
        )

        logger.info(f"Token validated successfully for subject: {claims.get('sub')}")
        return claims

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidAudienceError:
        logger.warning(f"Token audience does not match expected client_id: {client_id}")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None
    except requests.RequestException as e:
        logger.error(f"Failed to fetch JWKS: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}", exc_info=True)
        return None


def get_or_create_user_role(sub: str, aud: str, oidc_provider_arn: str) -> Tuple[str, bool]:
    """
    Get or create IAM role for user with tag-based ECS Exec permissions.

    Args:
        sub: OIDC subject claim (unique user identifier)
        aud: OIDC audience claim (client_id)
        oidc_provider_arn: ARN of the OIDC identity provider

    Returns:
        Tuple of (role_arn, was_created)
    """
    # Generate deterministic role name from subject hash
    sub_hash = hashlib.sha256(sub.encode()).hexdigest()[:8]
    role_name = f"rosa-boundary-user-{sub_hash}"

    # Check if role exists
    try:
        logger.info(f"Checking for existing role: {role_name}")
        get_response = iam.get_role(RoleName=role_name)
        role_arn = get_response['Role']['Arn']
        logger.info(f"Found existing role: {role_arn}")
        return role_arn, False

    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise

        logger.info(f"Role does not exist, creating: {role_name}")

    # Create trust policy for OIDC provider
    # Extract provider domain from ARN (everything after 'oidc-provider/')
    # Example: arn:aws:iam::123:oidc-provider/keycloak.example.com/realms/sre-ops
    # Results in: keycloak.example.com/realms/sre-ops
    oidc_provider_domain = oidc_provider_arn.split('oidc-provider/')[-1]

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": oidc_provider_arn
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{oidc_provider_domain}:sub": sub,
                        f"{oidc_provider_domain}:aud": aud
                    }
                }
            }
        ]
    }

    # Create role
    try:
        create_response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"ROSA Boundary user role for OIDC sub: {sub}",
            Tags=[
                {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
                {'Key': 'OIDCSubject', 'Value': sub},
                {'Key': 'OIDCAudience', 'Value': aud}
            ]
        )
        role_arn = create_response['Role']['Arn']
        logger.info(f"Created role: {role_arn}")

    except ClientError as e:
        logger.error(f"Failed to create role: {str(e)}")
        raise

    # Create inline policy with tag-based permissions
    # Get account ID and region from environment
    account_id = os.environ.get('AWS_ACCOUNT_ID', '*')
    region = os.environ.get('AWS_REGION', 'us-east-2')  # Lambda sets this automatically
    cluster_name = os.environ.get('ECS_CLUSTER', '*')

    # IAM Policy Design: Two-Statement Structure for ECS Exec Isolation
    #
    # ecs:ExecuteCommand requires permissions on BOTH the cluster AND the task.
    # This is AWS's design for layered access control.
    #
    # Statement 1 (ExecuteCommandOnCluster):
    #   - Grants permission on the cluster resource
    #   - No condition - all users with this role can pass the cluster check
    #   - This alone grants NO task access
    #   - Think of it as: "badge to enter the building"
    #
    # Statement 2 (ExecuteCommandOnOwnedTasks):
    #   - Grants permission on task resources with tag-based condition
    #   - Condition MUST match: ecs:ResourceTag/owner_sub == user's OIDC sub
    #   - Only grants access to tasks explicitly tagged with matching owner_sub
    #   - Denies access to: tasks with different owner_sub, untagged tasks, all other tasks
    #   - Think of it as: "key to your specific office"
    #
    # Why both are required:
    #   - Cluster permission alone: cannot exec into any tasks (tested)
    #   - Task permission alone: fails cluster authorization check (tested)
    #   - Both together: can only exec into tasks with matching owner_sub tag
    #
    # Security properties:
    #   - Users CANNOT access tasks tagged to other users
    #   - Users CANNOT access untagged tasks (missing tag fails condition)
    #   - Users CANNOT bypass isolation by launching untagged tasks
    #   - Provides strong isolation via IAM-enforced resource tagging
    #
    # See tests/localstack/integration/test_tag_isolation.py for comprehensive tests.
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExecuteCommandOnCluster",
                "Effect": "Allow",
                "Action": [
                    "ecs:ExecuteCommand"
                ],
                "Resource": [
                    f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster_name}"
                ]
                # No condition - required prerequisite for all ECS exec operations
                # This alone does NOT grant access to any tasks
            },
            {
                "Sid": "ExecuteCommandOnOwnedTasks",
                "Effect": "Allow",
                "Action": [
                    "ecs:ExecuteCommand"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "ecs:ResourceTag/owner_sub": sub
                    }
                }
                # Tag-based isolation: only tasks with matching owner_sub tag
                # This is where actual access control happens
            },
            {
                "Sid": "DescribeAndListECS",
                "Effect": "Allow",
                "Action": [
                    "ecs:DescribeTasks",
                    "ecs:ListTasks",
                    "ecs:DescribeTaskDefinition"
                ],
                "Resource": "*"
            },
            {
                "Sid": "SSMSessionForECSExec",
                "Effect": "Allow",
                "Action": [
                    "ssm:StartSession"
                ],
                "Resource": [
                    "arn:aws:ecs:*:*:task/*",
                    "arn:aws:ssm:*:*:document/AWS-StartInteractiveCommand"
                ]
                # No tag condition here - access control is enforced by ecs:ExecuteCommand
                # The SSM API doesn't have access to ECS resource tags
            },
            {
                "Sid": "KMSForECSExec",
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey"
                ],
                "Resource": "*"
            }
        ]
    }

    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='ECSExecTagBasedPolicy',
            PolicyDocument=json.dumps(policy_document)
        )
        logger.info(f"Attached inline policy to role: {role_name}")

    except ClientError as e:
        logger.error(f"Failed to attach policy to role: {str(e)}")
        # Try to delete the role since it's incomplete
        try:
            iam.delete_role(RoleName=role_name)
        except Exception:
            pass
        raise

    return role_arn, True


def create_investigation_task(
    cluster: str,
    task_def: str,
    owner_sub: str,
    owner_username: str,
    investigation_id: str,
    cluster_id: str,
    subnets: list,
    security_group: str,
    efs_filesystem_id: str,
    oc_version: str
) -> Dict[str, Any]:
    """
    Create EFS access point and launch ECS task for investigation.

    Args:
        cluster: ECS cluster name
        task_def: ECS task definition name/ARN
        owner_sub: OIDC subject (user identifier)
        owner_username: User's preferred username
        investigation_id: Investigation identifier
        cluster_id: ROSA cluster identifier
        subnets: List of subnet IDs
        security_group: Security group ID
        efs_filesystem_id: EFS filesystem ID
        oc_version: OpenShift CLI version

    Returns:
        Dictionary with task ARN and access point ID
    """
    # Create EFS access point for investigation
    access_point_path = f"/{cluster_id}/{investigation_id}"

    try:
        logger.info(f"Creating EFS access point: {access_point_path}")
        ap_response = efs.create_access_point(
            FileSystemId=efs_filesystem_id,
            PosixUser={
                'Uid': 1000,  # sre user
                'Gid': 1000
            },
            RootDirectory={
                'Path': access_point_path,
                'CreationInfo': {
                    'OwnerUid': 1000,
                    'OwnerGid': 1000,
                    'Permissions': '0755'
                }
            },
            Tags=[
                {'Key': 'Name', 'Value': f"{cluster_id}-{investigation_id}"},
                {'Key': 'ClusterID', 'Value': cluster_id},
                {'Key': 'InvestigationID', 'Value': investigation_id},
                {'Key': 'OwnerSub', 'Value': owner_sub},
                {'Key': 'OwnerUsername', 'Value': owner_username},
                {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'}
            ]
        )

        access_point_id = ap_response['AccessPointId']
        logger.info(f"Created EFS access point: {access_point_id}")

    except ClientError as e:
        logger.error(f"Failed to create EFS access point: {str(e)}")
        raise

    # Prepare task environment variables
    environment = [
        {'name': 'OC_VERSION', 'value': oc_version},
        {'name': 'CLUSTER_ID', 'value': cluster_id},
        {'name': 'INVESTIGATION_ID', 'value': investigation_id},
        {'name': 'S3_AUDIT_BUCKET', 'value': os.environ.get('S3_AUDIT_BUCKET', '')}
    ]

    # Launch ECS task
    try:
        logger.info(f"Launching ECS task in cluster: {cluster}")
        run_response = ecs.run_task(
            cluster=cluster,
            taskDefinition=task_def,
            launchType='FARGATE',
            platformVersion='LATEST',
            enableExecuteCommand=True,
            enableECSManagedTags=True,
            networkConfiguration={
                'awsvpcConfiguration': {
                    'subnets': subnets,
                    'securityGroups': [security_group],
                    'assignPublicIp': 'DISABLED'
                }
            },
            overrides={
                'containerOverrides': [
                    {
                        'name': 'rosa-boundary',
                        'environment': environment
                    }
                ]
            },
            tags=[
                {'key': 'owner_sub', 'value': owner_sub},
                {'key': 'owner_username', 'value': owner_username},
                {'key': 'investigation_id', 'value': investigation_id},
                {'key': 'cluster_id', 'value': cluster_id},
                {'key': 'oc_version', 'value': oc_version},
                {'key': 'access_point_id', 'value': access_point_id},
                {'key': 'created_at', 'value': datetime.utcnow().isoformat()}
            ]
        )

        if run_response.get('failures'):
            logger.error(f"Task launch failures: {run_response['failures']}")
            # Clean up access point
            try:
                efs.delete_access_point(AccessPointId=access_point_id)
            except Exception:
                pass
            raise Exception(f"Failed to launch task: {run_response['failures']}")

        task_arn = run_response['tasks'][0]['taskArn']
        logger.info(f"Launched ECS task: {task_arn}")

        # Apply tags explicitly using TagResource API
        # (tags in run_task don't always apply immediately for IAM evaluation)
        logger.info(f"Applying tags to task: {task_arn}")
        ecs.tag_resource(
            resourceArn=task_arn,
            tags=[
                {'key': 'owner_sub', 'value': owner_sub},
                {'key': 'owner_username', 'value': owner_username},
                {'key': 'investigation_id', 'value': investigation_id},
                {'key': 'cluster_id', 'value': cluster_id},
                {'key': 'oc_version', 'value': oc_version},
                {'key': 'access_point_id', 'value': access_point_id},
                {'key': 'created_at', 'value': datetime.utcnow().isoformat()}
            ]
        )
        logger.info("Tags applied successfully")

        return {
            'taskArn': task_arn,
            'accessPointId': access_point_id
        }

    except ClientError as e:
        logger.error(f"Failed to launch ECS task: {str(e)}")
        # Clean up access point
        try:
            efs.delete_access_point(AccessPointId=access_point_id)
        except Exception:
            pass
        raise


def response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format API Gateway response.

    Args:
        status_code: HTTP status code
        body: Response body dictionary

    Returns:
        API Gateway response object
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps(body)
    }
