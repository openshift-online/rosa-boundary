"""
AWS Lambda handler for creating investigation tasks with OIDC authentication.

This Lambda validates Keycloak OIDC tokens, verifies group membership, creates
EFS access points, and launches ECS tasks. Authorization uses a shared IAM role
with ABAC (Attribute-Based Access Control) via OIDC session tags — no per-user
role management required.
"""

import hashlib
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

class DuplicateInvestigationError(Exception):
    """Raised when an investigation already has a running task."""
    def __init__(self, message: str, existing_tasks: list = None, access_point_id: str = ''):
        super().__init__(message)
        self.existing_tasks = existing_tasks or []
        self.access_point_id = access_point_id


def investigation_started_by(cluster_id: str, investigation_id: str) -> str:
    """
    Return a deterministic ECS startedBy value for the given investigation.

    Used both when launching a task (run_task startedBy=...) and when querying
    for existing tasks (list_tasks startedBy=...). Because startedBy is set at
    task launch time — not asynchronously like tags — filtering by it avoids the
    tag-propagation race condition and eliminates the need for a cluster-wide
    describe_tasks scan.

    ECS startedBy is limited to 36 characters.
    """
    key = f"{cluster_id}:{investigation_id}"
    return hashlib.sha256(key.encode()).hexdigest()[:36]


# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
ecs = boto3.client('ecs')
efs = boto3.client('efs')
sts = boto3.client('sts')

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
REQUIRED_GROUPS = [g.strip() for g in os.environ.get('REQUIRED_GROUPS', '').split(',') if g.strip()]
ABAC_TAG_KEY = os.environ.get('ABAC_TAG_KEY', 'username')
STAGE_KEYCLOAK_ISSUER_URL = os.environ.get('STAGE_KEYCLOAK_ISSUER_URL', '').rstrip('/')
STAGE_OIDC_CLIENT_ID = os.environ.get('STAGE_OIDC_CLIENT_ID', '')
PROD_KEYCLOAK_ISSUER_URL = os.environ.get('PROD_KEYCLOAK_ISSUER_URL', '').rstrip('/')
PROD_OIDC_CLIENT_ID = os.environ.get('PROD_OIDC_CLIENT_ID', '')


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

        if not REQUIRED_GROUPS:
            logger.error("REQUIRED_GROUPS is empty after parsing — check required_groups Terraform variable")
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

        # Validate oc_version against the set of versions installed in the container.
        # Type-check first: unhashable types (list, dict) would raise TypeError on set
        # membership test, causing a 500 instead of a 400.
        VALID_OC_VERSIONS = {'4.14', '4.15', '4.16', '4.17', '4.18', '4.19', '4.20'}
        if not isinstance(oc_version, str):
            logger.warning(f"Invalid oc_version type: {type(oc_version).__name__}")
            return response(400, {'error': 'oc_version must be a string'})
        if oc_version not in VALID_OC_VERSIONS:
            logger.warning(f"Invalid oc_version: {oc_version}")
            return response(400, {'error': f'Invalid oc_version: must be one of {sorted(VALID_OC_VERSIONS)}'})


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

        # Support both flat groups array (dev Keycloak) and realm_access.roles (EmployeeIDP).
        # Type-guard each level: realm_access may be absent or non-dict in malformed tokens.
        flat_groups = claims.get('groups')
        groups = flat_groups if isinstance(flat_groups, list) else []
        if not groups:
            realm_access = claims.get('realm_access')
            realm_roles = realm_access.get('roles', []) if isinstance(realm_access, dict) else []
            groups = realm_roles if isinstance(realm_roles, list) else []

        # Extract ABAC identifier from the https://aws.amazon.com/tags principal_tags.
        # The tag key is configurable (ABAC_TAG_KEY env var) to support both dev
        # (username → preferred_username) and stage (uuid → rhatUUID).
        # Guard against non-dict claim shapes that would cause AttributeError at runtime.
        aws_tags = claims.get('https://aws.amazon.com/tags')
        if not isinstance(aws_tags, dict):
            aws_tags = {}
        principal_tags = aws_tags.get('principal_tags')
        if not isinstance(principal_tags, dict):
            principal_tags = {}
        abac_values = principal_tags.get(ABAC_TAG_KEY, [])
        if isinstance(abac_values, str):
            abac_values = [abac_values]
        elif not isinstance(abac_values, list):
            abac_values = []

        if abac_values:
            abac_tag_value = abac_values[0]
        elif ABAC_TAG_KEY != 'username':
            # Non-default ABAC key configured but not present in token — fail fast rather
            # than silently falling back to username, which would produce a task whose ABAC
            # tag can't be matched by the shared SRE role's PrincipalTag condition.
            logger.warning(f"ABAC tag key '{ABAC_TAG_KEY}' not found in principal_tags for user {username}")
            return response(403, {'error': f'Missing required ABAC claim: {ABAC_TAG_KEY}'})
        else:
            abac_tag_value = username

        logger.info(f"Token validated for user: {username} (sub: {user_sub}, {ABAC_TAG_KEY}: {abac_tag_value})")

        # Check group membership (user must be in at least one of the required groups)
        matched_groups = [g for g in REQUIRED_GROUPS if g in groups]
        if not matched_groups:
            logger.warning(f"User {username} not in any required group {REQUIRED_GROUPS}")
            return response(403, {
                'error': f'User not authorized: must be a member of at least one of {REQUIRED_GROUPS}',
                'groups': groups
            })

        logger.info(f"User {username} authorized via group(s): {matched_groups}")

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
            abac_tag_key=ABAC_TAG_KEY,
            abac_tag_value=abac_tag_value,
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

    except DuplicateInvestigationError as e:
        logger.warning(f"Duplicate investigation: {str(e)}")
        return response(409, {
            'error': str(e),
            'existing_tasks': e.existing_tasks,
            'access_point_id': e.access_point_id
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


def _validate_with_jwks(token: str, jwks_url: str, client_id: str) -> Optional[Dict[str, Any]]:
    """
    Validate a JWT against a specific JWKS endpoint and audience.

    Returns decoded claims on success, None on any validation failure.
    """
    try:
        logger.info(f"Fetching JWKS from: {jwks_url}")
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
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


def validate_oidc_token(token: str, keycloak_url: str, realm: str, client_id: str) -> Optional[Dict[str, Any]]:
    """
    Validate OIDC token and extract claims.

    Routes to the correct issuer by inspecting the unverified 'iss' claim, then
    validates with full signature/audience verification against that issuer's JWKS.
    Supports a primary Keycloak issuer and an optional stage OIDC provider
    (configured via STAGE_KEYCLOAK_ISSUER_URL / STAGE_OIDC_CLIENT_ID env vars).

    Args:
        token: JWT token string
        keycloak_url: Primary Keycloak server base URL
        realm: Primary Keycloak realm name
        client_id: Primary expected audience claim

    Returns:
        Decoded token claims or None if validation fails
    """
    # Peek at the 'iss' claim without verifying signature to route to the correct issuer.
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        token_iss = unverified.get('iss', '').rstrip('/')
    except Exception as e:
        logger.warning(f"Failed to decode token for issuer detection: {str(e)}")
        return None

    primary_iss = f"{keycloak_url.rstrip('/')}/realms/{realm}"
    primary_jwks_url = f"{primary_iss}/protocol/openid-connect/certs"

    if STAGE_KEYCLOAK_ISSUER_URL and token_iss == STAGE_KEYCLOAK_ISSUER_URL:
        logger.info(f"Token issuer matches stage OIDC provider: {STAGE_KEYCLOAK_ISSUER_URL}")
        stage_jwks_url = f"{STAGE_KEYCLOAK_ISSUER_URL}/protocol/openid-connect/certs"
        return _validate_with_jwks(token, stage_jwks_url, STAGE_OIDC_CLIENT_ID)
    elif PROD_KEYCLOAK_ISSUER_URL and token_iss == PROD_KEYCLOAK_ISSUER_URL:
        logger.info(f"Token issuer matches prod OIDC provider: {PROD_KEYCLOAK_ISSUER_URL}")
        prod_jwks_url = f"{PROD_KEYCLOAK_ISSUER_URL}/protocol/openid-connect/certs"
        return _validate_with_jwks(token, prod_jwks_url, PROD_OIDC_CLIENT_ID)
    elif token_iss == primary_iss:
        return _validate_with_jwks(token, primary_jwks_url, client_id)
    else:
        logger.warning(f"Token issuer '{token_iss}' does not match any configured OIDC provider "
                       f"(primary: '{primary_iss}', stage: '{STAGE_KEYCLOAK_ISSUER_URL or 'not configured'}', "
                       f"prod: '{PROD_KEYCLOAK_ISSUER_URL or 'not configured'}')")
        return None


def find_running_tasks_for_investigation(cluster: str, cluster_id: str, investigation_id: str) -> list:
    """
    Find RUNNING ECS tasks that already belong to the given investigation.

    Filters by the deterministic startedBy value set at task launch rather than
    by tags. This avoids the tag-propagation delay and eliminates the need to
    describe every running task in the cluster.

    Args:
        cluster: ECS cluster name
        cluster_id: ROSA cluster identifier
        investigation_id: Investigation identifier

    Returns:
        List of task ARNs that are RUNNING for this investigation
    """
    started_by = investigation_started_by(cluster_id, investigation_id)
    matching = []
    paginator = ecs.get_paginator('list_tasks')
    for page in paginator.paginate(cluster=cluster, desiredStatus='RUNNING', startedBy=started_by):
        matching.extend(page.get('taskArns', []))
    return matching


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
    s3_audit_bucket: str,
    aws_region: str,
    aws_account_id: str
) -> str:
    """
    Register a per-investigation ECS task definition with the per-investigation EFS access point.

    Fetches the base task definition, overrides the volume config with the per-investigation
    access point, and bakes investigation-specific environment variables into the SRE container.
    Injects the cluster kubeconfig Secrets Manager reference into the kube-proxy sidecar.
    Returns the registered task definition ARN.

    Args:
        task_def: Base task definition family name
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        access_point_id: Per-investigation EFS access point ID
        efs_filesystem_id: EFS filesystem ID
        oc_version: OpenShift CLI version
        task_timeout: Task timeout in seconds
        s3_audit_bucket: S3 bucket name for audit logs
        aws_region: AWS region for Secrets Manager ARN construction
        aws_account_id: AWS account ID for Secrets Manager ARN construction

    Returns:
        ARN of the registered per-investigation task definition
    """
    base_td = ecs.describe_task_definition(taskDefinition=task_def)['taskDefinition']

    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%S')
    family = f"{base_td['family']}-{cluster_id}-{investigation_id}-{timestamp}"

    volumes = [
        {
            'name': 'sre-home',
            'efsVolumeConfiguration': {
                'fileSystemId': efs_filesystem_id,
                'transitEncryption': 'ENABLED',
                'authorizationConfig': {
                    'accessPointId': access_point_id,
                    'iam': 'ENABLED'
                }
            }
        },
        {
            'name': 'proxy-tmp'  # ephemeral bind mount, no EFS config
        }
    ]

    env_overrides = {
        'CLUSTER_ID': cluster_id,
        'INVESTIGATION_ID': investigation_id,
        'OC_VERSION': oc_version,
        'S3_AUDIT_BUCKET': s3_audit_bucket,
        'TASK_TIMEOUT': str(task_timeout),
    }

    # Partial ARN (no random suffix) — ECS accepts partial ARNs for Secrets Manager valueFrom
    kubeconfig_secret_arn = (
        f'arn:aws:secretsmanager:{aws_region}:{aws_account_id}:'
        f'secret:rosa-boundary/clusters/{cluster_id}/kubeconfig'
    )

    container_defs = []
    for cd in base_td.get('containerDefinitions', []):
        new_cd = dict(cd)
        if new_cd['name'] == 'rosa-boundary':
            # Apply investigation-specific env vars to the SRE container
            existing_env = {e['name']: e['value'] for e in new_cd.get('environment', [])}
            existing_env.update(env_overrides)
            new_cd['environment'] = [{'name': k, 'value': v} for k, v in existing_env.items()]
        elif new_cd['name'] == 'kube-proxy':
            # Inject cluster kubeconfig secret reference into the proxy sidecar
            existing_secrets = list(new_cd.get('secrets', []))
            existing_secrets.append({
                'name': 'KUBECONFIG_DATA',
                'valueFrom': kubeconfig_secret_arn
            })
            new_cd['secrets'] = existing_secrets
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
    abac_tag_key: str,
    abac_tag_value: str,
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

    # Reject if a task is already running for this investigation. This check runs before any
    # new EFS access point is created so there is no access point to clean up on rejection.
    if not skip_task:
        existing_tasks = find_running_tasks_for_investigation(cluster, cluster_id, investigation_id)
        if existing_tasks:
            logger.warning(f"Investigation {investigation_id} already has {len(existing_tasks)} running task(s): {existing_tasks}")
            raise DuplicateInvestigationError(
                f"Investigation '{investigation_id}' already has a running task",
                existing_tasks=existing_tasks,
                access_point_id=existing_ap['AccessPointId'] if existing_ap else ''
            )

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

    # Derive AWS region and account ID for Secrets Manager ARN construction in the task def.
    aws_region = os.environ.get('AWS_REGION', 'us-east-1')
    aws_account_id = sts.get_caller_identity()['Account']

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
            s3_audit_bucket=os.environ.get('S3_AUDIT_BUCKET', ''),
            aws_region=aws_region,
            aws_account_id=aws_account_id
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
    # The ABAC tag (key = ABAC_TAG_KEY env var, e.g. 'username' or 'uuid') enforces
    # per-user isolation: the shared SRE role policy conditions on
    # ecs:ResourceTag/<key> == ${aws:PrincipalTag/<key>}.
    # The 'oidc_sub' tag stores the immutable OIDC subject UUID for audit purposes.
    created_at = datetime.utcnow()
    task_tags = [
        {'key': 'oidc_sub', 'value': oidc_sub},
        {'key': abac_tag_key, 'value': abac_tag_value},
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
            startedBy=investigation_started_by(cluster_id, investigation_id),
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
