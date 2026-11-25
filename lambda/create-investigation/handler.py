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
import posixpath
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from uuid import UUID

import boto3
import jwt
import requests
from jwt import PyJWKClient
from botocore.exceptions import ClientError, BotoCoreError, WaiterError

import close_requests

class HandoverFailedError(Exception):
    """Raised when an existing investigation task cannot be stopped for handover."""
    def __init__(self, message: str, failed_tasks: list = None, status_code: int = 500,
                 existing_session_id: Optional[str] = None):
        super().__init__(message)
        self.failed_tasks = failed_tasks or []
        self.status_code = status_code
        self.existing_session_id = existing_session_id

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
ssm = boto3.client('ssm')

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
TASK_TIMEOUT_MINIMUM = int(os.environ.get('TASK_TIMEOUT_MINIMUM', '30'))
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
    task_creation_outcome = None
    actor_uuid = None
    try:
        # Debug: log event structure (redact sensitive headers)
        logger.info(f"Event keys: {list(event.keys())}")
        headers_redacted = {k: '***REDACTED***' if k.lower() in ('authorization', 'x-oidc-token') else v
                           for k, v in event.get('headers', {}).items()}
        logger.info(f"Headers: {headers_redacted}")

        # CLI discovery uses its OIDC token at STS, not in the invocation payload.
        try:
            body = json.loads(event.get('body', '{}'))
        except (json.JSONDecodeError, TypeError):
            return response(400, {'error': 'Invalid JSON in request body'})
        if not isinstance(body, dict):
            return response(400, {'error': 'Request body must be a JSON object'})

        if body.get('action') == 'get_config':
            return get_config_response()

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

        if 'action' in body and body['action'] not in close_requests.ACTIONS:
            return response(400, {'error': 'Unsupported action'})

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

        investigation_id = body.get('investigation_id')
        cluster_id = body.get('cluster_id')
        skip_task = body.get('skip_task', False)

        if not investigation_id or not cluster_id:
            logger.warning("Missing required fields: investigation_id or cluster_id")
            return response(400, {'error': 'Missing required fields: investigation_id, cluster_id'})

        # A close/status action does not create a task. Its availability must
        # not depend on the configured default satisfying the launch minimum.
        if 'action' not in body:
            task_timeout = body.get('task_timeout', os.environ.get('TASK_TIMEOUT_DEFAULT', '3600'))
            try:
                if isinstance(task_timeout, (float, bool)):
                    raise ValueError("Expected a whole number of seconds")
                task_timeout = int(task_timeout)
                if task_timeout < 0 or task_timeout > 28800:
                    raise ValueError("Task timeout out of range")
                if TASK_TIMEOUT_MINIMUM > 0 and task_timeout < TASK_TIMEOUT_MINIMUM:
                    raise ValueError(f"task_timeout below minimum ({TASK_TIMEOUT_MINIMUM}s)")
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid task_timeout: {task_timeout} — {str(e)}")
                return response(400, {
                    'error': f'task_timeout must be an integer between {TASK_TIMEOUT_MINIMUM} and 28800'
                })

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
        if not isinstance(user_sub, str) or not user_sub.strip():
            return response(401, {'error': 'Missing OIDC subject'})
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

        # Close request/status actions reuse this authenticated front door but
        # share none of the creation path. Only close_session may stop a task.
        action = body.get('action')
        if action in close_requests.ACTIONS:
            return handle_close_action(action, body, user_sub, username)

        # EmployeeIDP's uuid principal tag is the corporate UUID, not OIDC sub.
        # Keep this optional log property separate from the metric dimensions.
        uuid_value = principal_tags.get('uuid')
        if isinstance(uuid_value, list):
            uuid_value = uuid_value[0] if len(uuid_value) == 1 else None
        if isinstance(uuid_value, str):
            try:
                actor_uuid = str(UUID(uuid_value))
            except ValueError:
                pass

        # Use shared ABAC role — session tags from the OIDC token (https://aws.amazon.com/tags
        # claim) propagate automatically during AssumeRoleWithWebIdentity and are matched
        # against ecs:ResourceTag/username in the role's permissions policy.
        role_arn = SHARED_ROLE_ARN
        logger.info(f"Using shared SRE role: {role_arn}")

        # Create investigation task
        logger.info(f"Creating investigation: {investigation_id} for cluster {cluster_id} (skip_task={skip_task})")
        if not skip_task:
            task_creation_outcome = 'failure'
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
            task_timeout=task_timeout,
            skip_task=skip_task
        )
        if not skip_task:
            task_creation_outcome = 'success'

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
            'task_timeout': task_timeout
        })

    except HandoverFailedError as e:
        if task_creation_outcome is not None and e.status_code == 409:
            task_creation_outcome = 'blocked'
        logger.error(f"Investigation handover failed: {str(e)}")
        body = {'error': str(e), 'failed_tasks': e.failed_tasks}
        if e.existing_session_id:
            body['existing_session_id'] = e.existing_session_id
        return response(e.status_code, body)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return response(500, {'error': 'Internal server error'})
    finally:
        if task_creation_outcome is not None:
            emit_task_creation_metric(task_creation_outcome, actor_uuid)


def emit_task_creation_metric(outcome: str, actor_uuid: Optional[str] = None) -> None:
    """Emit a bounded EMF count without affecting the task-creation response."""
    try:
        metric = {
            '_aws': {
                'Timestamp': time.time_ns() // 1_000_000,
                'CloudWatchMetrics': [{
                    'Namespace': 'ROSABoundary',
                    'Dimensions': [['ECSCluster', 'Outcome']],
                    'Metrics': [{
                        'Name': 'TaskCreationRequests',
                        'Unit': 'Count',
                        'StorageResolution': 60
                    }]
                }]
            },
            'ECSCluster': ECS_CLUSTER,
            'Outcome': outcome,
            'TaskCreationRequests': 1
        }
        if actor_uuid is not None:
            metric['ActorUUID'] = actor_uuid
        # EMF requires a standalone JSON log event, without a logger prefix.
        print(json.dumps(metric), flush=True)
    except Exception:
        logger.warning('Failed to emit task-creation metric')


def handle_close_action(action: str, body: Dict[str, Any], user_sub: str,
                        username: str) -> Dict[str, Any]:
    """Run one authenticated close request/status action.

    Identity comes from the already-validated OIDC claims, never from the
    request body. Errors are returned with their own status codes so the CLI
    can tell "not authorized" from "state unknown, retry" from "outcome
    unknown".
    """
    config = {
        'audit_bucket': os.environ.get('S3_AUDIT_BUCKET', ''),
        'ecs_cluster': ECS_CLUSTER,
        'efs_filesystem_id': EFS_FILESYSTEM_ID,
        'account_id': os.environ.get('AWS_ACCOUNT_ID', ''),
        'started_by': investigation_started_by,
    }
    clients = {'ecs': ecs, 'efs': efs, 'ssm': ssm}
    try:
        return response(200, close_requests.dispatch(action, body, {'sub': user_sub,
                                                                    'username': username},
                                                     config, clients))
    except close_requests.CloseRequestError as error:
        logger.warning("Close action %s refused (%d): %s", action, error.status_code,
                       error.message)
        return response(error.status_code, {'error': error.message, **error.extra})


def require_durable_admission(client, cluster_id: str, investigation_id: str) -> None:
    """Any request or status retires the ID, including after AP deletion.

    A request prefix ends in '/'; an exact status key sorts before longer
    keys sharing its prefix. One list result suffices regardless of history.
    Intents alone are not requests. This observation is not a cross-service lock.
    """
    bucket = os.environ.get('S3_AUDIT_BUCKET')
    owner = os.environ.get('AWS_ACCOUNT_ID')
    if not bucket or not owner:
        raise HandoverFailedError('Close admission is not configured', status_code=503)
    requests = close_requests.requests_prefix(cluster_id, investigation_id)
    status = close_requests.status_key(cluster_id, investigation_id)
    try:
        for prefix in (requests, status):
            page = client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1,
                                          ExpectedBucketOwner=owner)
            keys = [item['Key'] for item in page.get('Contents', [])]
            if page['KeyCount'] != len(keys) or (not keys and page['IsTruncated']):
                raise ValueError('incomplete admission listing')
            if keys and (prefix == requests or keys[0] == status):
                raise HandoverFailedError(
                    'Investigation has a durable close record; start a new investigation ID',
                    status_code=409)
    except (ClientError, BotoCoreError, KeyError, ValueError) as error:
        raise HandoverFailedError('Cannot verify durable close state', status_code=503) from error


def close_marker(efs_filesystem_id: str, cluster_id: str, investigation_id: str) -> Optional[str]:
    """Return a reason when a close marker is observed on the workspace path.

    Sealing is best effort. This check narrows the window in which a launch can
    race a finalization; it does not create an atomic admission barrier, and no
    caller may describe it as one.
    """
    expected_path = f"/{cluster_id}/{investigation_id}"
    paginator = efs.get_paginator('describe_access_points')
    for page in paginator.paginate(FileSystemId=efs_filesystem_id):
        for access_point in page.get('AccessPoints', []):
            if (access_point.get('RootDirectory', {}).get('Path') or '') != expected_path:
                continue
            tags = {t['Key']: t['Value'] for t in access_point.get('Tags', [])}
            reason = close_requests.workspace_admission_block(tags)
            if reason:
                return reason
    return None


def _discard_investigation_task_definition(task_def_arn: Optional[str]) -> None:
    """Best-effort cleanup of a definition registered for a launch we abandoned."""
    if not task_def_arn:
        return
    try:
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
    except (ClientError, BotoCoreError) as error:
        logger.error("Failed to deregister abandoned task definition: %s", type(error).__name__)


def _discard_new_access_point(access_point_id: str, cluster_id: str,
                              investigation_id: str) -> None:
    """Best-effort cleanup of an access point this invocation just created."""
    try:
        efs.delete_access_point(AccessPointId=access_point_id)
    except ClientError as error:
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code not in ('AccessPointNotFound', 'FileSystemNotFound'):
            logger.error("Failed to clean up access point after abandoning a launch for "
                         "%s/%s: %s", cluster_id, investigation_id, code)
    except Exception as error:
        logger.error("Unexpected error cleaning up access point: %s", type(error).__name__)


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

    # Allow alphanumeric, hyphens, and underscores, and require an
    # alphanumeric first character. The leading-character rule matches the
    # reaper's long-standing identifier pattern and the close-record key
    # segments: an identifier the finalizer cannot represent would create an
    # investigation nobody could close or reap.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', identifier):
        raise ValueError(f"Invalid {field_name}: must start with a letter or digit and contain only alphanumeric characters, hyphens, and underscores")

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
    for page in paginator.paginate(cluster=cluster, startedBy=started_by):
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
    expected_path = f"/{cluster_id}/{investigation_id}"
    match = None
    try:
        paginator = efs.get_paginator('describe_access_points')
        for page in paginator.paginate(FileSystemId=efs_filesystem_id):
            for ap in page.get('AccessPoints', []):
                tags = {t['Key']: t['Value'] for t in ap.get('Tags', [])}
                # A seal applies to the workspace, not just this mount handle. Scan
                # all pages so an older, duplicate AP cannot hide a sealed one.
                if ap.get('RootDirectory', {}).get('Path') == expected_path:
                    reason = close_requests.workspace_admission_block(tags)
                    if reason:
                        raise HandoverFailedError(reason, status_code=409)
                if ap.get('LifeCycleState') != 'available':
                    continue
                if tags.get('ClusterID') != cluster_id or tags.get('InvestigationID') != investigation_id:
                    continue
                # Verify the root path matches what the tags claim — guards against tag
                # manipulation redirecting an investigation to a different EFS directory.
                actual_path = ap.get('RootDirectory', {}).get('Path', '')
                if actual_path != expected_path:
                    logger.warning(
                        f"Access point {ap['AccessPointId']} tags match but path mismatch: "
                        f"expected {expected_path!r}, got {actual_path!r}; skipping"
                    )
                    continue
                if match is not None:
                    raise HandoverFailedError('Multiple access points match the workspace; contact the operator', status_code=409)
                match = ap
    except ClientError:
        logger.error('Cannot determine whether the investigation workspace is sealed')
        raise
    return match


def register_investigation_task_definition(
    task_def: str,
    cluster_id: str,
    investigation_id: str,
    access_point_id: str,
    efs_filesystem_id: str,
    task_timeout: int,
    s3_audit_bucket: str,
    aws_region: str,
    aws_account_id: str
) -> str:
    """
    Register a per-investigation ECS task definition with the per-investigation EFS access point.

    Fetches the base task definition, replaces the EFS access point, preserves unrelated
    volumes and mounts, and enforces task-scoped OCM and kubeconfig overlays. Bakes
    investigation-specific environment variables into the SRE container and injects the
    cluster kubeconfig Secrets Manager reference into the kube-proxy sidecar.
    Returns the registered task definition ARN.

    Args:
        task_def: Base task definition family name
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        access_point_id: Per-investigation EFS access point ID
        efs_filesystem_id: EFS filesystem ID
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

    credential_volumes = {
        'ocm-config': '/home/sre/.config/ocm',
        'kubeconfig': '/home/sre/.kube',
    }
    credential_paths = tuple(credential_volumes.values())

    def protected_mount_path(container_path: str, include_home: bool = False) -> bool:
        """Return whether a canonical mount path can mask protected task storage."""
        if not isinstance(container_path, str) or not container_path.startswith('/'):
            raise ValueError('Base task definition contains an invalid container mount path')
        if '..' in container_path.split('/'):
            raise ValueError('Base task definition container mount path contains traversal')

        canonical_path = posixpath.normpath('/' + container_path.lstrip('/'))
        if include_home and canonical_path == '/home/sre':
            return True
        return any(
            canonical_path == credential_path
            or canonical_path.startswith(f'{credential_path}/')
            for credential_path in credential_paths
        )

    has_kube_proxy = any(
        container.get('name') == 'kube-proxy'
        for container in base_td.get('containerDefinitions', [])
    )

    # Preserve base volumes such as the sidecar-only proxy volume. Replace the
    # investigation EFS volume and credential volumes so the latter cannot
    # inherit persistent storage configuration from a stale base definition.
    volumes = [
        dict(volume) for volume in base_td.get('volumes', [])
        if volume.get('name') not in {'sre-home', *credential_volumes}
        and (volume.get('name') != 'proxy-tmp' or has_kube_proxy)
    ]
    volumes.extend([
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
        *({'name': name} for name in credential_volumes),
    ])

    env_overrides = {
        'CLUSTER_ID': cluster_id,
        'INVESTIGATION_ID': investigation_id,
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
        new_cd['mountPoints'] = [
            dict(mount) for mount in new_cd.get('mountPoints', [])
            if mount.get('sourceVolume') not in credential_volumes
            and not protected_mount_path(
                mount.get('containerPath'),
                include_home=new_cd.get('name') == 'rosa-boundary',
            )
        ]
        if new_cd['name'] == 'rosa-boundary':
            # Apply investigation-specific env vars to the SRE container
            existing_env = {e['name']: e['value'] for e in new_cd.get('environment', [])}
            existing_env.update(env_overrides)
            new_cd['environment'] = [{'name': k, 'value': v} for k, v in existing_env.items()]

            # Preserve unrelated base mounts, replace the investigation home,
            # and enforce task-scoped overlays for credential-bearing paths.
            mount_points = [
                mount for mount in new_cd['mountPoints']
                if mount.get('sourceVolume') != 'sre-home'
            ]
            mount_points.extend([
                {
                    'sourceVolume': 'sre-home',
                    'containerPath': '/home/sre',
                    'readOnly': False,
                },
                *(
                    {
                        'sourceVolume': name,
                        'containerPath': path,
                        'readOnly': False,
                    }
                    for name, path in credential_volumes.items()
                ),
            ])
            new_cd['mountPoints'] = mount_points
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


def verify_handover(cluster, investigation_id, task_arns, oidc_sub, abac_tag_key, abac_tag_value):
    """Require a known different owner and no active sessions on every candidate."""
    candidates = []
    for arn in task_arns:
        try:
            result = ecs.describe_tasks(cluster=cluster, tasks=[arn], include=['TAGS'])
        except (ClientError, BotoCoreError) as error:
            logger.error(f"Failed to describe task {arn}: {error}")
            raise HandoverFailedError(
                "Cannot verify task ownership due to AWS API error", failed_tasks=[arn]
            ) from error

        tasks = result.get('tasks', [])
        if result.get('failures') or len(tasks) != 1 or tasks[0].get('taskArn') != arn:
            raise HandoverFailedError(
                f"Cannot verify session state for task {arn}: describe_tasks returned no matching details",
                failed_tasks=[arn]
            )

        task = tasks[0]
        tags = {tag['key']: tag.get('value') for tag in task.get('tags', [])}
        owner = tags.get(abac_tag_key)
        subject = tags.get('oidc_sub')
        # Either match blocks replacement, but Join requires both identities.
        if owner == abac_tag_value or subject == oidc_sub:
            if owner != abac_tag_value or subject != oidc_sub:
                raise HandoverFailedError(
                    "Existing session identity only partially matches; replacement refused. "
                    "Check the selected profile and contact the operator.",
                    failed_tasks=[arn], status_code=409
                )
            raise HandoverFailedError(
                f"You already have a task for investigation '{investigation_id}'. "
                "Use 'rosa-boundary session list' to find it, then "
                "'rosa-boundary session join <session-id>' with the same profile.",
                failed_tasks=[arn], status_code=409,
                existing_session_id=arn.rsplit('/', 1)[-1]
            )
        candidates.append((arn, task, owner, subject))

    for arn, task, owner, subject in candidates:
        if not all(isinstance(value, str) and value.strip() for value in (owner, subject)):
            raise HandoverFailedError("Cannot verify existing task ownership", failed_tasks=[arn])

        try:
            active, incomplete = close_requests.active_session_count(
                ssm, cluster, arn.rsplit('/', 1)[-1], task.get('containers', []))
        except (ClientError, BotoCoreError) as error:
            logger.error(f"Failed to describe sessions for {arn}: {error}")
            raise HandoverFailedError(
                f"Cannot verify active sessions for investigation '{investigation_id}' due to AWS API error",
                failed_tasks=[arn]
            ) from error
        if active:
            raise HandoverFailedError(
                f"Investigation '{investigation_id}' is currently locked by an active session.",
                failed_tasks=[arn], status_code=409
            )
        if incomplete:
            raise HandoverFailedError(
                "Cannot verify session state for existing task: incomplete session evidence",
                failed_tasks=[arn]
            )


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
        task_timeout: Task timeout in seconds (0 = no timeout, default: 3600)

    Returns:
        Dictionary with task ARN and access point ID
    """
    # Create EFS access point for investigation (idempotent: reuse if already exists)
    access_point_path = f"/{cluster_id}/{investigation_id}"

    admission_client = boto3.client('s3')

    def check_admission():
        require_durable_admission(admission_client, cluster_id, investigation_id)

    check_admission()
    existing_ap = find_existing_access_point(efs_filesystem_id, cluster_id, investigation_id)
    ap_newly_created = False

    # Preflight the entire set before issuing any stop.
    if not skip_task:
        existing_tasks = find_running_tasks_for_investigation(cluster, cluster_id, investigation_id)
        if existing_tasks:
            verify_handover(cluster, investigation_id, existing_tasks,
                            oidc_sub, abac_tag_key, abac_tag_value)
            logger.info(f"Stopping existing tasks for investigation {investigation_id} handover: {existing_tasks}")
            failed_stops = []
            tasks_to_wait_for = []

            for existing_task in existing_tasks:
                try:
                    check_admission()
                    reason = close_marker(efs_filesystem_id, cluster_id, investigation_id)
                    if reason:
                        raise HandoverFailedError(reason, status_code=409)
                    ecs.stop_task(
                        cluster=cluster,
                        task=existing_task,
                        reason="Investigation handover: replaced by new task"
                    )
                    tasks_to_wait_for.append(existing_task)
                    logger.info(f"Initiated stop for existing task: {existing_task}")
                except (ClientError, BotoCoreError) as e:
                    logger.error(f"Failed to initiate stop for existing task {existing_task}: {str(e)}")
                    failed_stops.append(existing_task)

            if tasks_to_wait_for:
                try:
                    waiter = ecs.get_waiter('tasks_stopped')
                    waiter.wait(
                        cluster=cluster,
                        tasks=tasks_to_wait_for,
                        WaiterConfig={
                            'Delay': 6,
                            'MaxAttempts': 25
                        }
                    )
                    logger.info(f"Successfully confirmed termination of existing tasks: {tasks_to_wait_for}")
                except (ClientError, BotoCoreError, WaiterError) as e:
                    logger.error(f"Failed waiting for tasks to reach STOPPED state: {str(e)}")
                    failed_stops.extend(tasks_to_wait_for)

            if failed_stops:
                raise HandoverFailedError(
                    "Failed to stop or wait for termination of existing tasks during handover",
                    failed_tasks=failed_stops
                )

    if existing_ap:
        access_point_id = existing_ap['AccessPointId']
        logger.info(f"Reusing existing EFS access point: {access_point_id}")
    else:
        try:
            logger.info(f"Creating EFS access point: {access_point_path}")
            check_admission()
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
                    {'Key': 'BoundaryResource', 'Value': 'investigation'},
                    {'Key': 'ClusterID', 'Value': cluster_id},
                    {'Key': 'InvestigationID', 'Value': investigation_id},
                    {'Key': 'oidc_sub', 'Value': oidc_sub},
                    {'Key': 'username', 'Value': username},
                    {'Key': 'ManagedBy', 'Value': 'rosa-boundary-lambda'},
                    {'Key': 'CreatedAt', 'Value': datetime.utcnow().isoformat() + 'Z'}
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
        check_admission()
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
    # A request racing AP creation may now name that very AP. Preserve it
    # for the finalizer if admission fails; it is not a failed registration.
    check_admission()
    try:
        investigation_task_def_arn = register_investigation_task_definition(
            task_def=task_def,
            cluster_id=cluster_id,
            investigation_id=investigation_id,
            access_point_id=access_point_id,
            efs_filesystem_id=efs_filesystem_id,
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
            except ClientError as cleanup_error:
                error_code = cleanup_error.response.get('Error', {}).get('Code', 'Unknown')
                if error_code in ('AccessPointNotFound', 'FileSystemNotFound'):
                    logger.info(f"Access point {access_point_id} already deleted during cleanup")
                else:
                    logger.error(
                        f"Failed to clean up access point {access_point_id} after task definition registration failure. "
                        f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {error_code}"
                    )
            except Exception as cleanup_error:
                logger.error(
                    f"Unexpected error cleaning up access point {access_point_id}. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(cleanup_error)}"
                )
        raise

    # Build task tags (used for both run_task and tag_resource)
    # The ABAC tag (key = ABAC_TAG_KEY env var, e.g. 'username' or 'uuid') enforces
    # per-user isolation: the shared SRE role policy conditions on
    # ecs:ResourceTag/<key> == ${aws:PrincipalTag/<key>}.
    # The 'oidc_sub' tag stores the immutable OIDC subject UUID for audit purposes.
    created_at = datetime.utcnow()
    task_tags = [
        {'key': 'BoundaryResource', 'value': 'session'},
        {'key': 'oidc_sub', 'value': oidc_sub},
        {'key': abac_tag_key, 'value': abac_tag_value},
        {'key': 'investigation_id', 'value': investigation_id},
        {'key': 'cluster_id', 'value': cluster_id},
        {'key': 'access_point_id', 'value': access_point_id},
        {'key': 'task_timeout', 'value': str(task_timeout)},
        {'key': 'created_at', 'value': created_at.isoformat()}
    ]

    # Add deadline tag if timeout is enabled
    if task_timeout > 0:
        deadline = created_at + timedelta(seconds=task_timeout)
        task_tags.append({'key': 'deadline', 'value': deadline.isoformat()})

    # Late close check, as close to the launch as practical. This narrows the
    # window between the lookup above and the launch below; it does not remove
    # it. A launch that already passed this check can still become visible
    # after a reaper observation, which is why the reaper re-enumerates tasks
    # and invalidates its attempt rather than trusting a single quiet scan.
    # An ambiguous answer here fails closed: no task is launched.
    try:
        check_admission()
        late_reason = close_marker(efs_filesystem_id, cluster_id, investigation_id)
    except HandoverFailedError:
        _discard_investigation_task_definition(investigation_task_def_arn)
        raise  # The finalizer may need this AP, including a newly created one.
    except (ClientError, BotoCoreError):
        # An unreadable answer here fails closed, and the definition and any
        # access point this invocation created are discarded with it rather
        # than left behind for the next attempt to trip over.
        logger.error("Could not check the close marker before launching for %s/%s",
                     cluster_id, investigation_id)
        _discard_investigation_task_definition(investigation_task_def_arn)
        if ap_newly_created:
            _discard_new_access_point(access_point_id, cluster_id, investigation_id)
        raise
    if late_reason:
        logger.warning("Close marker observed before launch for %s/%s", cluster_id, investigation_id)
        _discard_investigation_task_definition(investigation_task_def_arn)
        if ap_newly_created:
            _discard_new_access_point(access_point_id, cluster_id, investigation_id)
        raise HandoverFailedError(late_reason, status_code=409)

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
            except ClientError as e:
                logger.error(
                    f"Failed to deregister task definition {investigation_task_def_arn} during cleanup. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {e.response.get('Error', {}).get('Code', 'Unknown')}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error deregistering task definition. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(e)}"
                )
            if ap_newly_created:
                try:
                    efs.delete_access_point(AccessPointId=access_point_id)
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code not in ('AccessPointNotFound', 'FileSystemNotFound'):
                        logger.error(
                            f"Failed to delete access point {access_point_id} during cleanup. "
                            f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {error_code}"
                        )
                except Exception as e:
                    logger.error(
                        f"Unexpected error deleting access point. "
                        f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(e)}"
                    )
            raise Exception(f"Failed to launch task: {run_response['failures']}")

        task_arn = run_response['tasks'][0]['taskArn']
        logger.info(f"Launched ECS task: {task_arn}")

        def stop_late_task():
            try:
                ecs.stop_task(cluster=cluster, task=task_arn,
                              reason='Investigation close observed after launch')
            except (ClientError, BotoCoreError):
                logger.error('Could not stop late task %s; verify it stops before closing', task_arn)
            _discard_investigation_task_definition(investigation_task_def_arn)

        def recheck_launched_task():
            try:
                check_admission()
            except HandoverFailedError:
                stop_late_task()
                # The request may name this AP; leave it for the finalizer.
                raise

        recheck_launched_task()
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
            except ClientError as e:
                logger.error(
                    f"Failed to deregister task definition during cleanup after tag failure. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {e.response.get('Error', {}).get('Code', 'Unknown')}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error deregistering task definition. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(e)}"
                )
            try:
                ecs.stop_task(cluster=cluster, task=task_arn, reason='Tagging failed')
            except ClientError as e:
                logger.error(
                    f"Failed to stop task during cleanup after tag failure. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {e.response.get('Error', {}).get('Code', 'Unknown')}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error stopping task. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(e)}"
                )
            if ap_newly_created:
                try:
                    efs.delete_access_point(AccessPointId=access_point_id)
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code not in ('AccessPointNotFound', 'FileSystemNotFound'):
                        logger.error(
                            f"Failed to delete access point during cleanup after tag failure. "
                            f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {error_code}"
                        )
                except Exception as e:
                    logger.error(
                        f"Unexpected error deleting access point. "
                        f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(e)}"
                    )
            raise

        # The marker can still appear between the pre-launch check and here.
        # Stop what we started: a late task that keeps running would invalidate
        # the finalization attempt and leave the workspace retained anyway.
        # An ambiguous EFS answer leaves the task alone only after durable
        # admission succeeds. The reaper still re-enumerates before attesting.
        recheck_launched_task()
        try:
            late_reason = close_marker(efs_filesystem_id, cluster_id, investigation_id)
        except (ClientError, BotoCoreError):
            logger.warning(
                "Could not recheck the close marker after launching for %s/%s; the reaper "
                "re-enumerates tasks before attesting", cluster_id, investigation_id)
            late_reason = None
        if late_reason:
            logger.warning("Close marker observed after launch for %s/%s; stopping the late task",
                           cluster_id, investigation_id)
            stop_late_task()
            if ap_newly_created:
                # A second access point on this path would make every later
                # close refuse the workspace as ambiguous.
                _discard_new_access_point(access_point_id, cluster_id, investigation_id)
            raise HandoverFailedError(
                f'{late_reason}; session stop requested and close remains pending',
                status_code=409)

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
            except ClientError as cleanup_error:
                logger.error(
                    f"Failed to deregister task definition during cleanup. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {cleanup_error.response.get('Error', {}).get('Code', 'Unknown')}"
                )
            except Exception as cleanup_error:
                logger.error(
                    f"Unexpected error deregistering task definition. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(cleanup_error)}"
                )
        # Stop task if it was created
        if task_arn:
            try:
                ecs.stop_task(cluster=cluster, task=task_arn, reason='Launch failed')
            except ClientError as cleanup_error:
                logger.error(
                    f"Failed to stop task during cleanup. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {cleanup_error.response.get('Error', {}).get('Code', 'Unknown')}"
                )
            except Exception as cleanup_error:
                logger.error(
                    f"Unexpected error stopping task. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(cleanup_error)}"
                )
        # Clean up access point only if newly created
        if ap_newly_created:
            try:
                efs.delete_access_point(AccessPointId=access_point_id)
            except ClientError as cleanup_error:
                error_code = cleanup_error.response.get('Error', {}).get('Code', 'Unknown')
                if error_code not in ('AccessPointNotFound', 'FileSystemNotFound'):
                    logger.error(
                        f"Failed to delete access point during cleanup. "
                        f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {error_code}"
                    )
            except Exception as cleanup_error:
                logger.error(
                    f"Unexpected error deleting access point. "
                    f"Investigation: {investigation_id}, Cluster: {cluster_id}, Error: {str(cleanup_error)}"
                )
        raise


def get_config_response() -> Dict[str, Any]:
    """Return CLI configuration values from Lambda environment variables.

    AWS authorizes invocation. Any principal with effective invoke permission
    can read this allowlist of deployment metadata without an application token.
    """
    logger.info("Returning CLI configuration (get_config action)")
    return response(200, {
        'action': 'get_config',
        'config': {
            'supports_close_session': True,
            'lambda_function_name': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', ''),
            'invoker_role_arn': os.environ.get('INVOKER_ROLE_ARN', ''),
            'sre_role_arn': os.environ.get('SHARED_ROLE_ARN', ''),
            'efs_filesystem_id': os.environ.get('EFS_FILESYSTEM_ID', ''),
            'ecs_cluster_name': os.environ.get('ECS_CLUSTER', ''),
            'aws_region': os.environ.get('AWS_REGION', ''),
            'keycloak_url': os.environ.get('KEYCLOAK_URL', ''),
            'keycloak_realm': os.environ.get('KEYCLOAK_REALM', ''),
            'oidc_client_id': os.environ.get('KEYCLOAK_CLIENT_ID', ''),
        }
    })


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
