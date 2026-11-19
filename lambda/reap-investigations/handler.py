"""
AWS Lambda handler for periodic garbage collection of stale investigations.

This Lambda runs on a schedule (default: every 8 hours) to:
1. List all EFS access points with investigation tags
2. Check each investigation for staleness (no running tasks + grace period elapsed)
3. Delete: EFS directory, access point, and associated task definitions

Environment Variables:
- ECS_CLUSTER: ECS cluster name
- EFS_FILESYSTEM_ID: EFS filesystem ID
- GRACE_PERIOD_HOURS: Staleness threshold (default: 72)
- S3_AUDIT_BUCKET: Optional S3 bucket for investigation backups
- TASK_DEFINITION_FAMILY: Task definition family prefix for cleanup
"""

import os
import logging
import re
import stat
import shutil
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ecs = boto3.client(
    'ecs',
    config=BotocoreConfig(connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'})
)

efs = boto3.client(
    'efs',
    config=BotocoreConfig(connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'})
)

ECS_CLUSTER = os.environ.get('ECS_CLUSTER')
EFS_FILESYSTEM_ID = os.environ.get('EFS_FILESYSTEM_ID')
GRACE_PERIOD_HOURS = int(os.environ.get('GRACE_PERIOD_HOURS', '72'))
S3_AUDIT_BUCKET = os.environ.get('S3_AUDIT_BUCKET', '')
TASK_DEFINITION_FAMILY = os.environ.get('TASK_DEFINITION_FAMILY', '')
EFS_MOUNT_PATH = '/mnt/efs'

# Identifier validation pattern (must match create-investigation Lambda)
IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')


def investigation_started_by(cluster_id: str, investigation_id: str) -> str:
    """
    Return a deterministic ECS startedBy value for the given investigation.

    Used when querying for existing tasks (list_tasks startedBy=...). Because
    startedBy is set at task launch time — not asynchronously like tags —
    filtering by it avoids the tag-propagation race condition and eliminates
    the need for a cluster-wide describe_tasks scan.

    Must match create-investigation Lambda's implementation.

    ECS startedBy is limited to 36 characters.
    """
    key = f"{cluster_id}:{investigation_id}"
    return hashlib.sha256(key.encode()).hexdigest()[:36]


def validate_identifier(value: str, name: str) -> None:
    """
    Validate cluster_id or investigation_id to prevent path traversal.

    Raises:
        ValueError: If identifier contains invalid characters or path components
    """
    if not value or not IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"{name} contains invalid characters: {value}")

    if value in ('.', '..') or '/' in value:
        raise ValueError(f"{name} contains path traversal characters: {value}")


def work_seconds(context: Any) -> float:
    """Time for new work, excluding the 30-second cleanup reserve."""
    if context is None:
        return 300.0
    return max(0, context.get_remaining_time_in_millis() - 30000) / 1000


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for reaping stale investigations.

    Args:
        event: EventBridge event (periodic trigger)
        context: Lambda context object

    Returns:
        Summary with checked, reaped, skipped, and error counts
    """
    if not ECS_CLUSTER:
        logger.error("Missing required environment variable: ECS_CLUSTER")
        raise ValueError("Lambda configuration error: ECS_CLUSTER not set")

    if not EFS_FILESYSTEM_ID:
        logger.error("Missing required environment variable: EFS_FILESYSTEM_ID")
        raise ValueError("Lambda configuration error: EFS_FILESYSTEM_ID not set")

    logger.info("Checking for stale investigations (grace period: %dh)", GRACE_PERIOD_HOURS)

    checked = 0
    reaped = 0
    skipped = 0
    errors = 0
    now = datetime.now(timezone.utc)

    if not work_seconds(context):
        logger.warning("Insufficient time for investigation discovery")
        return {'checked': 0, 'reaped': 0, 'skipped': 0, 'errors': 0}

    try:
        # List all access points with investigation tags
        access_points = list_investigation_access_points()
        logger.info("Found %d investigation access point(s)", len(access_points))

        # Build running tasks set once to avoid repeated cluster-wide pagination
        running_tasks = list_all_running_tasks()
        logger.info("Found %d running task(s) in cluster", len(running_tasks))

        # Fetch all active task definitions once to avoid repeated pagination
        all_task_def_arns = list_all_task_definitions() if TASK_DEFINITION_FAMILY else []
        logger.info("Found %d active task definition(s)", len(all_task_def_arns))

        for ap in access_points:
            # Check deadline before processing each investigation
            if not work_seconds(context):
                logger.warning("Reaping deadline reached - stopping investigation processing")
                break

            checked += 1
            ap_id = ap['AccessPointId']
            tags = {tag['Key']: tag['Value'] for tag in ap.get('Tags', [])}
            cluster_id = tags.get('ClusterID', '')
            investigation_id = tags.get('InvestigationID', '')

            if 'AuditCloseSeal' in tags:
                logger.info("Skipping sealed access point %s", ap_id)
                skipped += 1
                continue

            # Verify ManagedBy tag before cleanup (defense-in-depth)
            # IAM policy restricts DeleteAccessPoint, but directory deletion happens through EFS mount
            if tags.get('ManagedBy') != 'rosa-boundary-lambda':
                logger.warning("Access point %s missing or invalid ManagedBy tag, skipping", ap_id)
                skipped += 1
                continue

            if not cluster_id or not investigation_id:
                logger.warning("Access point %s missing ClusterID or InvestigationID tags, skipping", ap_id)
                skipped += 1
                continue

            # Validate identifiers to prevent path traversal
            try:
                validate_identifier(cluster_id, 'ClusterID')
                validate_identifier(investigation_id, 'InvestigationID')
            except ValueError as e:
                logger.error("Access point %s has invalid identifier: %s", ap_id, e)
                errors += 1
                continue

            # Validate access point path matches expected path from tags
            expected_path = f'/{cluster_id}/{investigation_id}'
            access_point_path = (ap.get('RootDirectory') or {}).get('Path')

            if access_point_path != expected_path:
                logger.error(
                    "Access point %s path %r does not match expected path %r",
                    ap_id, access_point_path, expected_path
                )
                errors += 1
                continue

            logger.info("Checking: cluster=%s investigation=%s ap=%s",
                       cluster_id, investigation_id, ap_id)

            try:
                # Read creation timestamp from CreatedAt tag (EFS API doesn't provide CreationTime)
                created_at_str = tags.get('CreatedAt')
                if not created_at_str:
                    logger.warning("Access point %s missing CreatedAt tag, checking tasks only", ap_id)
                    staleness = is_investigation_stale(cluster_id, investigation_id, None, now, running_tasks)
                else:
                    # Parse ISO 8601 timestamp from tag
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                    staleness = is_investigation_stale(cluster_id, investigation_id, created_at, now, running_tasks)

                if not staleness['is_stale']:
                    logger.info("Skipping %s/%s: %s",
                               cluster_id, investigation_id, staleness['reason'])
                    skipped += 1
                    continue
            except Exception as e:
                logger.error("Error checking staleness for %s/%s: %s",
                            cluster_id, investigation_id, e, exc_info=True)
                errors += 1
                continue

            logger.info("Reaping stale investigation: %s/%s (%s)",
                       cluster_id, investigation_id, staleness['reason'])

            # Refresh task state before deletion to ensure current
            try:
                current_tasks = list_tasks_by_investigation(cluster_id, investigation_id)
                if current_tasks:
                    logger.info("Investigation %s/%s now has running tasks, skipping reap",
                               cluster_id, investigation_id)
                    skipped += 1
                    continue
            except (ClientError, BotoCoreError) as e:
                logger.error("Failed to refresh task state for %s/%s: %s",
                            cluster_id, investigation_id, e, exc_info=True)
                errors += 1
                continue

            reap_success = reap_investigation(cluster_id, investigation_id, ap_id, context, all_task_def_arns)

            if reap_success:
                reaped += 1
            else:
                errors += 1

    except (ClientError, BotoCoreError) as e:
        logger.error("AWS API error during investigation reaping: %s", e, exc_info=True)
        return {
            'error': f'AWS API error: {str(e)}',
            'checked': checked,
            'reaped': reaped,
            'skipped': skipped,
            'errors': errors
        }
    except Exception as e:
        logger.error("Unexpected error during investigation reaping: %s", e, exc_info=True)
        raise  # Re-raise for Lambda to fail properly

    logger.info("Reaper completed: checked=%d, reaped=%d, skipped=%d, errors=%d",
               checked, reaped, skipped, errors)

    return {
        'checked': checked,
        'reaped': reaped,
        'skipped': skipped,
        'errors': errors
    }


def is_investigation_stale(cluster_id: str, investigation_id: str,
                          access_point_created_at: Optional[datetime], now: datetime,
                          running_tasks: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Determine if an investigation is stale using hybrid criteria.

    Hybrid approach prevents premature deletion:
    1. Active tasks (RUNNING status) → not stale (regardless of age)
    2. No tasks + age > grace period → stale and safe to delete
    3. No tasks + missing CreatedAt tag → stale (legacy backfill)

    This ensures investigations with long-running debug sessions are never
    reaped while the task is active, while cleaning up abandoned investigations
    after the grace period expires.

    Investigations without a CreatedAt tag were created before PR #300 (2026-10-12)
    and are treated as stale when idle to enable one-time backfill cleanup.

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        access_point_created_at: Access point creation timestamp (None for legacy investigations)
        now: Current UTC timestamp
        running_tasks: Pre-fetched list of all running tasks with their tags

    Returns:
        dict with 'is_stale' (bool), 'reason' (str), 'running_tasks' (int)
    """
    # Filter running tasks for this investigation
    investigation_tasks = [
        task for task in running_tasks
        if task['cluster_id'] == cluster_id and task['investigation_id'] == investigation_id
    ]

    if investigation_tasks:
        return {
            'is_stale': False,
            'reason': f'{len(investigation_tasks)} running task(s)',
            'running_tasks': len(investigation_tasks)
        }

    if access_point_created_at is None:
        # Legacy backfill: investigations created before CreatedAt tag was added (PR #300, 2026-10-12)
        # lack this tag. Since all such investigations are necessarily old (>11 days), treat them
        # as stale when idle. The task check above already prevents deletion of active work.
        # New investigations always have CreatedAt (verified in create-investigation handler),
        # so this only affects the one-time backfill of pre-tag investigations.
        return {
            'is_stale': True,
            'reason': 'no tasks, legacy investigation (missing CreatedAt tag)',
            'running_tasks': 0
        }

    grace_period = timedelta(hours=GRACE_PERIOD_HOURS)
    age = now - access_point_created_at

    if age > grace_period:
        hours_old = int(age.total_seconds() / 3600)
        return {
            'is_stale': True,
            'reason': f'no tasks, {hours_old}h old (grace: {GRACE_PERIOD_HOURS}h)',
            'running_tasks': 0
        }
    else:
        hours_remaining = int((grace_period - age).total_seconds() / 3600)
        return {
            'is_stale': False,
            'reason': f'no tasks but within grace period ({hours_remaining}h remaining)',
            'running_tasks': 0
        }


def list_all_running_tasks() -> List[Dict[str, str]]:
    """
    List all RUNNING tasks in the cluster with their tags.
    Returns list of dicts with 'arn', 'cluster_id', and 'investigation_id'.
    """
    tasks = []
    next_token = None

    while True:
        try:
            kwargs = {
                'cluster': ECS_CLUSTER,
                'desiredStatus': 'RUNNING'
            }

            if next_token:
                kwargs['nextToken'] = next_token

            response = ecs.list_tasks(**kwargs)

            if response.get('taskArns'):
                described = ecs.describe_tasks(
                    cluster=ECS_CLUSTER,
                    tasks=response['taskArns'],
                    include=['TAGS']
                )

                for task in described.get('tasks', []):
                    tags = {tag['key']: tag['value'] for tag in task.get('tags', [])}
                    tasks.append({
                        'arn': task['taskArn'],
                        'cluster_id': tags.get('cluster_id', ''),
                        'investigation_id': tags.get('investigation_id', '')
                    })

            next_token = response.get('nextToken')
            if not next_token:
                break

        except (ClientError, BotoCoreError) as e:
            logger.error("Failed to list running tasks: %s", e, exc_info=True)
            raise

    return tasks


def list_all_task_definitions() -> List[str]:
    """
    List all ACTIVE task definitions.
    Returns list of task definition ARNs.
    Fetched once per Lambda invocation to avoid repeated pagination.
    """
    task_def_arns = []
    next_token = None

    while True:
        try:
            kwargs = {
                'status': 'ACTIVE'
            }

            if next_token:
                kwargs['nextToken'] = next_token

            response = ecs.list_task_definitions(**kwargs)
            task_def_arns.extend(response.get('taskDefinitionArns', []))

            next_token = response.get('nextToken')
            if not next_token:
                break

        except (ClientError, BotoCoreError) as e:
            logger.error("Failed to list task definitions: %s", e, exc_info=True)
            raise

    return task_def_arns


def list_tasks_by_investigation(cluster_id: str, investigation_id: str) -> List[str]:
    """
    List RUNNING tasks for the given investigation.

    Filters by the deterministic startedBy value set at task launch rather than
    by tags. This avoids the tag-propagation delay and eliminates the need to
    describe every running task in the cluster.

    Returns:
        List of task ARNs that are RUNNING for this investigation
    """
    started_by = investigation_started_by(cluster_id, investigation_id)
    task_arns = []

    try:
        paginator = ecs.get_paginator('list_tasks')
        for page in paginator.paginate(
            cluster=ECS_CLUSTER,
            desiredStatus='RUNNING',
            startedBy=started_by
        ):
            task_arns.extend(page.get('taskArns', []))
    except (ClientError, BotoCoreError) as e:
        logger.error("Failed to list tasks for %s/%s: %s",
                    cluster_id, investigation_id, e, exc_info=True)
        raise

    return task_arns


def list_investigation_access_points() -> List[Dict[str, Any]]:
    """
    List all EFS access points (caller will filter by investigation tags).
    """
    access_points = []
    next_token = None

    while True:
        try:
            kwargs = {
                'FileSystemId': EFS_FILESYSTEM_ID
            }

            if next_token:
                kwargs['NextToken'] = next_token

            response = efs.describe_access_points(**kwargs)

            # Collect all access points (filtering happens in main handler)
            access_points.extend(response.get('AccessPoints', []))

            next_token = response.get('NextToken')
            if not next_token:
                break

        except (ClientError, BotoCoreError) as e:
            logger.error("Failed to list access points: %s", e, exc_info=True)
            raise

    return access_points


def still_unsealed(access_point_id: str, cluster_id: str, investigation_id: str) -> bool:
    """Require one unsealed AP on this path; a duplicate may hold the seal."""
    path = f'/{cluster_id}/{investigation_id}'
    points = [point for point in list_investigation_access_points()
              if point.get('RootDirectory', {}).get('Path') == path]
    return (len(points) == 1 and points[0]['AccessPointId'] == access_point_id
            and 'Tags' in points[0]
            and not any(t['Key'] == 'AuditCloseSeal' for t in points[0]['Tags']))


def cleanup_allowed(access_point_id: str, cluster_id: str, investigation_id: str, context: Any) -> bool:
    """Refresh the seal, then check the time left after the EFS lookup."""
    return still_unsealed(access_point_id, cluster_id, investigation_id) and work_seconds(context) > 0


def reap_investigation(cluster_id: str, investigation_id: str, access_point_id: str, context: Any, task_def_arns: List[str]) -> bool:
    """
    Reap a stale investigation by deleting directory, access point, and task definitions.

    Directory must be deleted before access point - once the access point is gone,
    we lose the tags that identify the directory location, making it unreclaimable.

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        access_point_id: EFS access point ID to delete
        context: Lambda context object for timeout calculation
        task_def_arns: Pre-fetched list of all active task definition ARNs

    Returns:
        True if all steps succeeded, False if any step failed
    """
    if not work_seconds(context):
        return False

    try:
        if not delete_investigation_directory(cluster_id, investigation_id, context, access_point_id):
            return False
        if not cleanup_allowed(access_point_id, cluster_id, investigation_id, context):
            return False
        all_success = delete_access_point(access_point_id)
    except (ClientError, BotoCoreError, OSError, ValueError) as e:
        logger.error("Cleanup deferred for %s: %s", access_point_id, e, exc_info=True)
        return False

    # Deregister task definitions after workspace cleanup
    try:
        deregistered = delete_task_definitions(cluster_id, investigation_id, task_def_arns)
        logger.info("Deregistered %d task definition(s) for %s/%s",
                   deregistered, cluster_id, investigation_id)
    except (ClientError, BotoCoreError) as e:
        logger.error("Error deregistering task definitions for %s/%s: %s",
                    cluster_id, investigation_id, e, exc_info=True)
        all_success = False

    return all_success


def backup_investigation_to_s3(cluster_id: str, investigation_id: str, directory_path: str, context: Any) -> bool:
    """
    Upload investigation directory to S3 before deletion.

    Uploads to s3://{bucket}/{cluster_id}/{investigation_id}/reaper-final-backup/
    with the same exclusions as entrypoint.sh (.config/ocm/*, .kube/*).

    Uses boto3 S3 client for uploading (AWS CLI not available in Lambda runtime).

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        directory_path: Local EFS directory path to backup
        context: Lambda context object for timeout calculation

    Returns:
        True only if the complete eligible tree was uploaded within budget

    Raises:
        ValueError: If configuration is invalid
    """
    if not S3_AUDIT_BUCKET:
        logger.error("S3_AUDIT_BUCKET not configured - cannot backup %s/%s",
                    cluster_id, investigation_id)
        return False  # Missing S3 configuration prevents deletion

    upload_timeout = work_seconds(context)
    if not upload_timeout:
        logger.warning("Insufficient time for backup; retaining workspace")
        return False

    # S3 prefix for uploaded files
    s3_prefix = f"{cluster_id}/{investigation_id}/reaper-final-backup/"

    logger.info("Backing up %s to s3://%s/%s (timeout: %.1fs)",
                directory_path, S3_AUDIT_BUCKET, s3_prefix, upload_timeout)

    try:
        # Create S3 client with timeout configuration matching upload window
        s3 = boto3.client(
            's3',
            config=BotocoreConfig(
                connect_timeout=5,
                read_timeout=min(10, upload_timeout),
                retries={'max_attempts': 3, 'mode': 'standard'}
            )
        )

        file_count = 0
        bytes_uploaded = 0

        def fail_walk(error):
            raise error  # os.walk silently skips unreadable subtrees by default

        # Walk directory tree (followlinks=False prevents symlink exfiltration)
        for root, dirs, files in os.walk(directory_path, onerror=fail_walk, followlinks=False):
            # Check deadline before processing each directory
            if not work_seconds(context):
                logger.error("Upload deadline reached for %s/%s - directory retained",
                            cluster_id, investigation_id)
                return False

            # Calculate relative path from investigation directory
            rel_root = os.path.relpath(root, directory_path)

            # Prune excluded trees before scandir: they need not be readable.
            if rel_root == '.' and '.kube' in dirs:
                dirs.remove('.kube')
            if rel_root == '.config' and 'ocm' in dirs:
                dirs.remove('ocm')

            # Skip excluded directories (.config/ocm/*, .kube/*)
            if rel_root != '.':
                path_parts = rel_root.split(os.sep)

                # Skip .config/ocm/* paths
                if len(path_parts) >= 2 and path_parts[0] == '.config' and path_parts[1] == 'ocm':
                    continue

                # Skip .kube/* paths
                if path_parts[0] == '.kube':
                    continue

            # Upload each file in this directory
            for filename in files:
                # Check deadline before each file upload
                if not work_seconds(context):
                    logger.error("Upload deadline reached for %s/%s - directory retained",
                                cluster_id, investigation_id)
                    return False

                local_path = os.path.join(root, filename)

                # Use lstat to check file type without following symlinks
                # OSError propagates to outer handler which returns False and retains directory
                file_stat = os.lstat(local_path)

                # Only upload regular files, skip symlinks and other types
                if not stat.S_ISREG(file_stat.st_mode):
                    continue

                # Calculate S3 key: prefix + relative path from investigation directory
                if rel_root == '.':
                    relative_path = filename
                else:
                    relative_path = os.path.join(rel_root, filename)

                s3_key = f"{s3_prefix}{relative_path}"

                # Upload file to S3
                s3.upload_file(local_path, S3_AUDIT_BUCKET, s3_key)

                file_count += 1
                bytes_uploaded += file_stat.st_size

        if not work_seconds(context):
            logger.warning("Backup exhausted its budget; retaining workspace")
            return False

        logger.info("Successfully backed up %d file(s) (%d bytes) to S3 for %s/%s",
                   file_count, bytes_uploaded, cluster_id, investigation_id)
        return True

    except ClientError as e:
        # Do not log file paths or S3 keys (may contain investigation identifiers)
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        logger.error("S3 backup failed for %s/%s with error code %s",
                    cluster_id, investigation_id, error_code)
        return False
    except BotoCoreError as e:
        logger.error("S3 backup failed for %s/%s: boto3 error",
                    cluster_id, investigation_id)
        return False
    except OSError as e:
        # File read errors (permissions, disk errors, etc.)
        logger.error("S3 backup failed for %s/%s: filesystem error",
                    cluster_id, investigation_id)
        return False
    except Exception as e:
        logger.error("Unexpected error during S3 backup for %s/%s: %s",
                    cluster_id, investigation_id, type(e).__name__, exc_info=True)
        return False


def delete_investigation_directory(cluster_id: str, investigation_id: str, context: Any, access_point_id: str) -> bool:
    """
    Delete investigation directory from mounted EFS filesystem.

    Validates path to prevent traversal, verifies EFS is mounted, backs up to S3,
    then deletes the directory tree.

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        context: Lambda context object for timeout calculation

    Returns:
        True if deletion succeeded, False otherwise

    Raises:
        ValueError: If path validation fails
    """
    # Build and validate directory path
    directory_path = os.path.join(EFS_MOUNT_PATH, cluster_id, investigation_id)
    real_path = os.path.realpath(directory_path)

    # Verify path is within EFS mount (prevents traversal)
    validate_identifier(cluster_id, 'ClusterID')
    validate_identifier(investigation_id, 'InvestigationID')
    if real_path != os.path.join(os.path.realpath(EFS_MOUNT_PATH), cluster_id, investigation_id):
        raise ValueError(f"Path traversal detected: {directory_path} resolves to {real_path}")

    # Verify mount exists
    if not os.path.ismount(EFS_MOUNT_PATH):
        logger.error("EFS not mounted at %s", EFS_MOUNT_PATH)
        return False

    try:
        if not stat.S_ISDIR(os.lstat(directory_path).st_mode):
            logger.error("Workspace is not a directory; refusing cleanup")
            return False
    except FileNotFoundError:
        logger.info("Directory %s does not exist (already deleted or never created)",
                   directory_path)
        return True

    # Backup to S3 before deletion (required step)
    backup_success = backup_investigation_to_s3(cluster_id, investigation_id, directory_path, context)
    if not backup_success:
        logger.error("S3 backup failed for %s/%s - refusing to delete directory",
                    cluster_id, investigation_id)
        return False

    if not cleanup_allowed(access_point_id, cluster_id, investigation_id, context):
        logger.warning("Workspace cleanup deferred for %s", access_point_id)
        return False

    logger.info("Deleting directory: %s", directory_path)
    try:
        shutil.rmtree(directory_path)
        logger.info("Successfully deleted directory: %s", directory_path)
        return True
    except OSError as e:
        logger.error("Failed to delete directory %s: %s", directory_path, e, exc_info=True)
        return False


def delete_access_point(access_point_id: str) -> bool:
    """
    Delete EFS access point.

    Returns:
        True if deletion succeeded, False otherwise
    """
    try:
        efs.delete_access_point(AccessPointId=access_point_id)
        logger.info("Deleted access point: %s", access_point_id)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessPointNotFound':
            logger.warning("Access point %s already deleted", access_point_id)
            return True
        logger.error("Failed to delete access point %s: %s",
                    access_point_id, e, exc_info=True)
        return False
    except Exception as e:
        logger.error("Unexpected error deleting access point %s: %s",
                    access_point_id, e, exc_info=True)
        return False


def delete_task_definitions(cluster_id: str, investigation_id: str, all_task_def_arns: List[str]) -> int:
    """
    Deregister all task definitions for an investigation.
    Family prefix: {TASK_DEFINITION_FAMILY}-{cluster_id}-{investigation_id}

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        all_task_def_arns: Pre-fetched list of all active task definition ARNs

    Returns:
        Number of task definitions deregistered
    """
    if not TASK_DEFINITION_FAMILY:
        logger.warning("TASK_DEFINITION_FAMILY not configured - cannot deregister task definitions")
        return 0

    family_prefix = f'{TASK_DEFINITION_FAMILY}-{cluster_id}-{investigation_id}'
    deregistered = 0

    logger.info("Searching for task definitions with familyPrefix: %s", family_prefix)

    try:
        # Filter pre-fetched task definitions by parsing ARN structure
        # ARN format: arn:aws:ecs:region:account:task-definition/family-cluster-investigation-timestamp:revision
        # Must match exact family, cluster_id, and investigation_id to prevent name collisions
        matching_arns = []
        for arn in all_task_def_arns:
            # Extract task definition name from ARN
            if ':task-definition/' not in arn:
                continue

            task_def_name = arn.split(':task-definition/', 1)[1]
            # Reject malformed ARNs before matching an investigation's family.
            family_with_timestamp, separator, revision = task_def_name.rpartition(':')
            if not separator or not revision.isdigit():
                continue

            # Expected format: {family_prefix}-{timestamp}
            # Check if it starts with family_prefix followed by '-' and timestamp
            if not family_with_timestamp.startswith(f'{family_prefix}-'):
                continue

            # Verify timestamp format follows immediately (YYYYMMDDTHHMMSS pattern)
            suffix = family_with_timestamp[len(family_prefix) + 1:]  # +1 for the '-'
            if re.fullmatch(r'\d{8}T\d{6}', suffix):
                matching_arns.append(arn)

        logger.info("Found %d task definition(s) matching prefix %s",
                   len(matching_arns), family_prefix)

        for arn in matching_arns:
            try:
                ecs.deregister_task_definition(taskDefinition=arn)
                deregistered += 1
                logger.info("Deregistered task definition: %s", arn)
            except (ClientError, BotoCoreError) as e:
                logger.error("Failed to deregister task definition %s: %s",
                           arn, e, exc_info=True)

        return deregistered

    except Exception as e:
        logger.error("Error filtering task definitions for %s: %s",
                    family_prefix, e, exc_info=True)
        raise
