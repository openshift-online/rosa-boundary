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
- LOCALSTACK_ENDPOINT: Optional LocalStack endpoint for testing
"""

import os
import logging
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ecs = boto3.client(
    'ecs',
    endpoint_url=os.environ.get('LOCALSTACK_ENDPOINT'),
    config=BotocoreConfig(connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'})
)

efs = boto3.client(
    'efs',
    endpoint_url=os.environ.get('LOCALSTACK_ENDPOINT'),
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
            checked += 1
            ap_id = ap['AccessPointId']
            tags = {tag['Key']: tag['Value'] for tag in ap.get('Tags', [])}
            cluster_id = tags.get('ClusterID', '')
            investigation_id = tags.get('InvestigationID', '')

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
                created_at = ap.get('CreationTime')
                if not created_at:
                    logger.warning("Access point %s missing CreationTime (LocalStack limitation), checking tasks only", ap_id)
                    staleness = is_investigation_stale(cluster_id, investigation_id, None, now, running_tasks)
                else:
                    # Ensure created_at is timezone-aware (boto3 returns aware datetime for AWS API times)
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
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

    This ensures investigations with long-running debug sessions are never
    reaped while the task is active, while cleaning up abandoned investigations
    after the grace period expires.

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        access_point_created_at: Access point creation timestamp (may be None for LocalStack)
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
        if GRACE_PERIOD_HOURS == 0:
            return {
                'is_stale': True,
                'reason': 'no tasks, no creation time, zero grace period',
                'running_tasks': 0
            }
        else:
            return {
                'is_stale': False,
                'reason': f'no tasks but creation time unavailable (need {GRACE_PERIOD_HOURS}h grace period)',
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
    List RUNNING tasks tagged with cluster_id and investigation_id.
    Returns list of task ARNs.
    """
    task_arns = []
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
                    if (tags.get('cluster_id') == cluster_id and
                        tags.get('investigation_id') == investigation_id):
                        task_arns.append(task['taskArn'])

            next_token = response.get('nextToken')
            if not next_token:
                break

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
    all_success = True
    dir_deleted = False

    # Step 1: Delete EFS directory
    try:
        dir_deleted = delete_investigation_directory(cluster_id, investigation_id, context)
        if not dir_deleted:
            logger.error("Failed to delete directory for %s/%s", cluster_id, investigation_id)
            all_success = False
    except (OSError, ValueError) as e:
        logger.error("Error deleting directory for %s/%s: %s",
                    cluster_id, investigation_id, e, exc_info=True)
        all_success = False

    # Step 2: Delete access point (only if directory deletion succeeded)
    if dir_deleted:
        try:
            ap_deleted = delete_access_point(access_point_id)
            if not ap_deleted:
                logger.error("Failed to delete access point %s", access_point_id)
                all_success = False
        except (ClientError, BotoCoreError) as e:
            logger.error("Error deleting access point %s: %s",
                        access_point_id, e, exc_info=True)
            all_success = False
    else:
        logger.warning("Skipping access point deletion for %s - directory deletion failed", access_point_id)

    # Step 3: Delete task definitions (even if previous steps failed)
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

    Args:
        cluster_id: Cluster identifier
        investigation_id: Investigation identifier
        directory_path: Local EFS directory path to backup
        context: Lambda context object for timeout calculation

    Returns:
        True if upload succeeded or S3_AUDIT_BUCKET not configured, False if upload failed

    Raises:
        ValueError: If configuration is invalid
    """
    if not S3_AUDIT_BUCKET:
        logger.warning("S3_AUDIT_BUCKET not configured - skipping backup for %s/%s",
                      cluster_id, investigation_id)
        return True  # Not configured is not a failure condition

    if not os.path.exists(directory_path):
        logger.info("Directory %s does not exist - nothing to backup", directory_path)
        return True

    # Build S3 path for reaper final backup
    s3_path = f"s3://{S3_AUDIT_BUCKET}/{cluster_id}/{investigation_id}/reaper-final-backup/"

    # Calculate timeout dynamically: reserve 30s for error handling/cleanup
    remaining_ms = context.get_remaining_time_in_millis()
    sync_timeout = max(10, (remaining_ms / 1000) - 30)  # Minimum 10s, reserve 30s buffer

    logger.info("Backing up %s to %s (timeout: %.1fs)", directory_path, s3_path, sync_timeout)

    try:
        # Use aws s3 cp --recursive with same exclusions as entrypoint.sh
        # cp --recursive ensures all files are uploaded fresh (vs sync which skips based on size/time)
        # --no-follow-symlinks: prevents symlink target exfiltration
        # --only-show-errors: reduces log noise
        cmd = [
            'aws', 's3', 'cp',
            directory_path,
            s3_path,
            '--recursive',
            '--exclude', '.config/ocm/*',
            '--exclude', '.kube/*',
            '--no-follow-symlinks',
            '--only-show-errors'
        ]

        result = subprocess.run(
            cmd,
            timeout=sync_timeout,
            capture_output=True,
            text=True,
            check=True
        )

        logger.info("Successfully backed up %s to S3", directory_path)
        return True

    except subprocess.TimeoutExpired:
        logger.error("S3 sync timed out after %.1fs for %s/%s",
                    sync_timeout, cluster_id, investigation_id)
        return False
    except subprocess.CalledProcessError as e:
        logger.error("S3 sync failed for %s/%s: %s\nStderr: %s",
                    cluster_id, investigation_id, e, e.stderr)
        return False
    except Exception as e:
        logger.error("Unexpected error during S3 backup for %s/%s: %s",
                    cluster_id, investigation_id, e, exc_info=True)
        return False


def delete_investigation_directory(cluster_id: str, investigation_id: str, context: Any) -> bool:
    """
    Delete investigation directory from mounted EFS filesystem.

    Validates path to prevent traversal, verifies EFS is mounted, backs up to S3,
    then deletes the directory tree. In test environments with LOCALSTACK_ENDPOINT set,
    skips actual deletion if EFS is not mounted.

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
    if not real_path.startswith(os.path.realpath(EFS_MOUNT_PATH) + os.sep):
        raise ValueError(f"Path traversal detected: {directory_path} resolves to {real_path}")

    # Verify mount exists
    if not os.path.ismount(EFS_MOUNT_PATH):
        if os.environ.get('LOCALSTACK_ENDPOINT'):
            logger.warning("EFS not mounted (LocalStack limitation) - skipping directory deletion for %s",
                         directory_path)
            return True
        logger.error("EFS not mounted at %s", EFS_MOUNT_PATH)
        return False

    if not os.path.exists(directory_path):
        logger.info("Directory %s does not exist (already deleted or never created)",
                   directory_path)
        return True

    # Backup to S3 before deletion (required step)
    backup_success = backup_investigation_to_s3(cluster_id, investigation_id, directory_path, context)
    if not backup_success:
        logger.error("S3 backup failed for %s/%s - refusing to delete directory",
                    cluster_id, investigation_id)
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
        # Filter pre-fetched task definitions by family prefix
        # Match exact family (followed by :revision) to prevent prefix collisions
        # e.g., match "inv-1:5" but not "inv-10:5" when searching for "inv-1"
        matching_arns = [
            arn for arn in all_task_def_arns
            if f'task-definition/{family_prefix}:' in arn
        ]

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
