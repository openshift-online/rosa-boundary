"""
AWS Lambda handler for creating investigation tasks with OIDC authentication.

This Lambda validates Keycloak OIDC tokens, verifies group membership, creates
EFS access points, and launches ECS tasks. Authorization uses a shared IAM role
with ABAC (Attribute-Based Access Control) via OIDC session tags — no per-user
role management required.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

import boto3
import jwt
import requests
from jwt import PyJWKClient
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
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
SHARED_ROLE_ARN = os.environ.get('SHARED_ROLE_ARN')
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
        headers_redacted = {k: '***REDACTED***' if k.lower() in ('authorization', 'x-oidc-token') else v
                           for k, v in event.get('headers', {}).items()}
        logger.info(f"Headers: {headers_redacted}")

        # Extract OIDC token: prefer X-OIDC-Token header (SigV4 flow); fall back to
        # Authorization: Bearer for backward compatibility during migration.
        headers = event.get('headers', {})
        oidc_token = headers.get('x-oidc-token')
        if not oidc_token:
            auth_header = headers.get('authorization') or headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                oidc_token = auth_header.split(' ', 1)[1]
        if not oidc_token:
            logger.warning("Missing OIDC token: no x-oidc-token header or Authorization: Bearer")
            return response(401, {'error': 'Missing OIDC token. Provide X-OIDC-Token header.'})

        token = oidc_token

        # Validate environment configuration
        missing_vars = []
        for var_name in ['KEYCLOAK_URL', 'KEYCLOAK_REALM', 'KEYCLOAK_CLIENT_ID',
                         'ECS_CLUSTER', 'TASK_DEFINITION',
                         'SUBNETS', 'SECURITY_GROUP', 'EFS_FILESYSTEM_ID', 'SHARED_ROLE_ARN']:
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
        task_timeout = body.get('task_timeout', int(os.environ.get('TASK_TIMEOUT_DEFAULT', '3600')))
        skip_task = body.get('skip_task', False)

        if not investigation_id or not cluster_id:
            logger.warning("Missing required fields: investigation_id or cluster_id")
            return response(400, {'error': 'Missing required fields: investigation_id, cluster_id'})

        # Validate task_timeout
        try:
            task_timeout = int(task_timeout)
            if task_timeout < 0 or task_timeout > 86400:
                raise ValueError("Task timeout out of range")
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid task_timeout: {task_timeout}")
            return response(400, {'error': 'task_timeout must be an integer between 0 and 86400'})

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

        # Use shared ABAC role — session tags from the OIDC token (https://aws.amazon.com/tags
        # claim) propagate automatically during AssumeRoleWithWebIdentity and are matched
        # against ecs:ResourceTag/username in the role's permissions policy.
        role_arn = SHARED_ROLE_ARN
        logger.info(f"Using shared SRE role: {role_arn}")

        # Create investigation task
        logger.info(f"Creating investigation: {investigation_id} for cluster {cluster_id} (skip_task={skip_task})")
        task_info = create_investigation_task(
            cluster=ECS_CLUSTER,
            task_def=TASK_DEFINITION,
            oidc_sub=user_sub,
            username=username,
            investigation_id=investigation_id,
            cluster_id=cluster_id,
            subnets=SUBNETS,
            security_group=SECURITY_GROUP,
            efs_filesystem_id=EFS_FILESYSTEM_ID,
            oc_version=oc_version,
            task_timeout=task_timeout,
            skip_task=skip_task
        )

        if skip_task:
            logger.info(f"Investigation created (no task launched): {task_info['accessPointId']}")
            message = 'Investigation created (no task launched)'
        else:
            logger.info(f"Investigation task created successfully: {task_info['taskArn']}")
            message = 'Investigation task created successfully'

        # Return success response
        return response(200, {
            'message': message,
            'role_arn': role_arn,
            'task_arn': task_info['taskArn'],
            'access_point_id': task_info['accessPointId'],
            'task_definition_arn': task_info.get('taskDefinitionArn', ''),
            'investigation_id': investigation_id,
            'cluster_id': cluster_id,
            'owner': username,
            'oc_version': oc_version,
            'task_timeout': task_timeout
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


def find_existing_access_point(efs_filesystem_id: str, cluster_id: str, investigation_id: str) -> Optional[Dict[str, Any]]:
    """
    Find an existing EFS access point by ClusterID and InvestigationID tags.

    Args:
        efs_filesystem_id: EFS filesystem ID to search
        cluster_id: Cluster identifier to match
        investigation_id: Investigation identifier to match

    Returns:
        Access point dict or None if not found
    """
    try:
        paginator = efs.get_paginator('describe_access_points')
        for page in paginator.paginate(FileSystemId=efs_filesystem_id):
            for ap in page.get('AccessPoints', []):
                if ap.get('LifeCycleState') != 'available':
                    continue
                tags = {t['Key']: t['Value'] for t in ap.get('Tags', [])}
                if tags.get('ClusterID') == cluster_id and tags.get('InvestigationID') == investigation_id:
                    return ap
    except ClientError as e:
        logger.warning(f"Failed to search for existing access points: {str(e)}")
    return None


def register_investigation_task_definition(
    task_def: str,
    cluster_id: str,
    investigation_id: str,
    access_point_id: str,
    efs_filesystem_id: str,
    oc_version: str,
    task_timeout: int,
    s3_audit_bucket: str
) -> str:
    """
    Register a per-investigation ECS task definition with the per-investigation EFS access point.

    Fetches the base task definition, overrides the volume config with the per-investigation
    access point, and bakes investigation-specific environment variables into the container
    definition. Returns the registered task definition ARN.

    Args:
        task_def: Base task definition family name
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        access_point_id: Per-investigation EFS access point ID
        efs_filesystem_id: EFS filesystem ID
        oc_version: OpenShift CLI version
        task_timeout: Task timeout in seconds
        s3_audit_bucket: S3 bucket name for audit logs

    Returns:
        ARN of the registered per-investigation task definition
    """
    base_td = ecs.describe_task_definition(taskDefinition=task_def)['taskDefinition']

    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%S')
    family = f"{base_td['family']}-{cluster_id}-{investigation_id}-{timestamp}"

    volumes = [{
        'name': 'sre-home',
        'efsVolumeConfiguration': {
            'fileSystemId': efs_filesystem_id,
            'transitEncryption': 'ENABLED',
            'authorizationConfig': {
                'accessPointId': access_point_id,
                'iam': 'ENABLED'
            }
        }
    }]

    env_overrides = {
        'CLUSTER_ID': cluster_id,
        'INVESTIGATION_ID': investigation_id,
        'OC_VERSION': oc_version,
        'S3_AUDIT_BUCKET': s3_audit_bucket,
        'TASK_TIMEOUT': str(task_timeout),
    }

    container_defs = []
    for cd in base_td.get('containerDefinitions', []):
        new_cd = dict(cd)
        existing_env = {e['name']: e['value'] for e in new_cd.get('environment', [])}
        existing_env.update(env_overrides)
        new_cd['environment'] = [{'name': k, 'value': v} for k, v in existing_env.items()]
        container_defs.append(new_cd)

    register_kwargs = {
        'family': family,
        'taskRoleArn': base_td['taskRoleArn'],
        'executionRoleArn': base_td['executionRoleArn'],
        'networkMode': base_td['networkMode'],
        'containerDefinitions': container_defs,
        'volumes': volumes,
        'requiresCompatibilities': base_td.get('requiresCompatibilities', ['FARGATE']),
        'cpu': base_td['cpu'],
        'memory': base_td['memory'],
    }

    reg_response = ecs.register_task_definition(**register_kwargs)
    task_def_arn = reg_response['taskDefinition']['taskDefinitionArn']
    logger.info(f"Registered per-investigation task definition: {task_def_arn}")
    return task_def_arn


def create_investigation_task(
    cluster: str,
    task_def: str,
    oidc_sub: str,
    username: str,
    investigation_id: str,
    cluster_id: str,
    subnets: list,
    security_group: str,
    efs_filesystem_id: str,
    oc_version: str,
    task_timeout: int = 3600,
    skip_task: bool = False
) -> Dict[str, Any]:
    """
    Create EFS access point and launch ECS task for investigation.

    Args:
        cluster: ECS cluster name
        task_def: ECS task definition name/ARN
        oidc_sub: OIDC subject claim (UUID, stored for audit purposes)
        username: User's preferred username (used as task tag for ABAC)
        investigation_id: Investigation identifier
        cluster_id: ROSA cluster identifier
        subnets: List of subnet IDs
        security_group: Security group ID
        efs_filesystem_id: EFS filesystem ID
        oc_version: OpenShift CLI version
        task_timeout: Task timeout in seconds (0 = no timeout, default: 3600)

    Returns:
        Dictionary with task ARN and access point ID
    """
    # Create EFS access point for investigation (idempotent: reuse if already exists)
    access_point_path = f"/{cluster_id}/{investigation_id}"

    existing_ap = find_existing_access_point(efs_filesystem_id, cluster_id, investigation_id)
    ap_newly_created = False
    if existing_ap:
        access_point_id = existing_ap['AccessPointId']
        logger.info(f"Reusing existing EFS access point: {access_point_id}")
    else:
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
                    {'Key': 'oidc_sub', 'Value': oidc_sub},
                    {'Key': 'username', 'Value': username},
                    {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'}
                ]
            )

            access_point_id = ap_response['AccessPointId']
            ap_newly_created = True
            logger.info(f"Created EFS access point: {access_point_id}")

        except ClientError as e:
            logger.error(f"Failed to create EFS access point: {str(e)}")
            raise

    # When skip_task=True, return immediately without launching an ECS task
    if skip_task:
        return {
            'taskArn': '',
            'accessPointId': access_point_id
        }

    # Register a per-investigation task definition with the correct EFS access point baked in.
    # This ensures each investigation gets its own isolated EFS directory rather than all
    # Lambda-launched tasks sharing the static access point from the base task definition.
    investigation_task_def_arn = None
    try:
        investigation_task_def_arn = register_investigation_task_definition(
            task_def=task_def,
            cluster_id=cluster_id,
            investigation_id=investigation_id,
            access_point_id=access_point_id,
            efs_filesystem_id=efs_filesystem_id,
            oc_version=oc_version,
            task_timeout=task_timeout,
            s3_audit_bucket=os.environ.get('S3_AUDIT_BUCKET', '')
        )
    except Exception as e:
        logger.error(f"Failed to register investigation task definition: {str(e)}")
        if ap_newly_created:
            try:
                efs.delete_access_point(AccessPointId=access_point_id)
            except Exception:
                pass
        raise

    # Build task tags (used for both run_task and tag_resource)
    # The 'username' tag is the ABAC key: the shared SRE role policy conditions on
    # ecs:ResourceTag/username == ${aws:PrincipalTag/username} to enforce per-user isolation.
    # The 'oidc_sub' tag stores the immutable OIDC subject UUID for audit purposes.
    created_at = datetime.utcnow()
    task_tags = [
        {'key': 'oidc_sub', 'value': oidc_sub},
        {'key': 'username', 'value': username},
        {'key': 'investigation_id', 'value': investigation_id},
        {'key': 'cluster_id', 'value': cluster_id},
        {'key': 'oc_version', 'value': oc_version},
        {'key': 'access_point_id', 'value': access_point_id},
        {'key': 'task_timeout', 'value': str(task_timeout)},
        {'key': 'created_at', 'value': created_at.isoformat()}
    ]

    # Add deadline tag if timeout is enabled
    if task_timeout > 0:
        deadline = created_at + timedelta(seconds=task_timeout)
        task_tags.append({'key': 'deadline', 'value': deadline.isoformat()})

    # Launch ECS task using the per-investigation task definition
    task_arn = None
    try:
        logger.info(f"Launching ECS task in cluster: {cluster}")
        run_response = ecs.run_task(
            cluster=cluster,
            taskDefinition=investigation_task_def_arn,
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
            tags=task_tags
        )

        if run_response.get('failures'):
            logger.error(f"Task launch failures: {run_response['failures']}")
            try:
                ecs.deregister_task_definition(taskDefinition=investigation_task_def_arn)
            except Exception:
                pass
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
        try:
            ecs.tag_resource(
                resourceArn=task_arn,
                tags=task_tags
            )
            logger.info("Tags applied successfully")
        except ClientError as tag_error:
            logger.error(f"Failed to tag task: {str(tag_error)}")
            # Stop task and clean up
            try:
                ecs.deregister_task_definition(taskDefinition=investigation_task_def_arn)
            except Exception:
                pass
            try:
                ecs.stop_task(cluster=cluster, task=task_arn, reason='Tagging failed')
            except Exception:
                pass
            try:
                efs.delete_access_point(AccessPointId=access_point_id)
            except Exception:
                pass
            raise

        return {
            'taskArn': task_arn,
            'accessPointId': access_point_id,
            'taskDefinitionArn': investigation_task_def_arn
        }

    except ClientError as e:
        logger.error(f"Failed to launch ECS task: {str(e)}")
        if investigation_task_def_arn:
            try:
                ecs.deregister_task_definition(taskDefinition=investigation_task_def_arn)
            except Exception:
                pass
        # Stop task if it was created
        if task_arn:
            try:
                ecs.stop_task(cluster=cluster, task=task_arn, reason='Launch failed')
            except Exception:
                pass
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
