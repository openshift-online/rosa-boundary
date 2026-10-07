"""
AWS Lambda handler for periodic reaping of expired ECS tasks.

This Lambda runs on a schedule (default: every 15 minutes) to check all
RUNNING ECS tasks and stop any that have exceeded their deadline tag.
"""

import os
import logging
from typing import Dict, Any, List
from datetime import datetime

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
# LOCALSTACK_ENDPOINT is set in LocalStack test environments; absent in production.
ecs = boto3.client(
    'ecs',
    endpoint_url=os.environ.get('LOCALSTACK_ENDPOINT'),
    config=BotocoreConfig(connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'})
)

# SSM client, used to detect active ECS Exec sessions before reaping a task.
ssm = boto3.client(
    'ssm',
    endpoint_url=os.environ.get('LOCALSTACK_ENDPOINT'),
    config=BotocoreConfig(connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'})
)

# Environment variables
ECS_CLUSTER = os.environ.get('ECS_CLUSTER')


class SessionCheckError(Exception):
    """Raised when active ECS Exec / SSM session state cannot be reliably determined.

    The reaper fails closed on this error: it skips stopping the affected task and
    records an error, leaving the task to be re-evaluated on a subsequent run.
    """


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for reaping expired ECS tasks.

    Args:
        event: EventBridge event (periodic trigger)
        context: Lambda context object

    Returns:
        Summary with checked, stopped, skipped, and error counts
    """
    if not ECS_CLUSTER:
        logger.error("Missing required environment variable: ECS_CLUSTER")
        return {
            'error': 'Lambda configuration error: ECS_CLUSTER not set',
            'checked': 0,
            'stopped': 0,
            'skipped': 0,
            'protected': 0,
            'errors': 0
        }

    logger.info(f"Checking for expired tasks in cluster: {ECS_CLUSTER}")

    checked = 0
    stopped = 0
    skipped = 0
    protected = 0
    errors = 0
    now = datetime.utcnow()

    try:
        # Get all RUNNING tasks
        task_arns = list_running_tasks(ECS_CLUSTER)
        logger.info(f"Found {len(task_arns)} running tasks")

        if not task_arns:
            return {
                'checked': 0,
                'stopped': 0,
                'skipped': 0,
                'protected': 0,
                'errors': 0
            }

        # Describe tasks in batches of 100 (AWS API limit)
        batch_size = 100
        for i in range(0, len(task_arns), batch_size):
            batch = task_arns[i:i + batch_size]

            try:
                response = ecs.describe_tasks(
                    cluster=ECS_CLUSTER,
                    tasks=batch,
                    include=['TAGS']
                )

                for task in response.get('tasks', []):
                    checked += 1
                    task_arn = task['taskArn']
                    task_id = task_arn.split('/')[-1]

                    # Extract deadline tag
                    deadline_str = None
                    for tag in task.get('tags', []):
                        if tag['key'] == 'deadline':
                            deadline_str = tag['value']
                            break

                    # Skip tasks without deadline tag
                    if not deadline_str:
                        skipped += 1
                        logger.debug(f"Task {task_id} has no deadline tag, skipping")
                        continue

                    # Parse deadline as ISO 8601
                    try:
                        deadline = datetime.fromisoformat(deadline_str.replace('Z', '+00:00'))

                        # Remove timezone info for comparison (both are UTC)
                        if deadline.tzinfo is not None:
                            deadline = deadline.replace(tzinfo=None)

                        # Check if deadline has passed
                        if now > deadline:
                            logger.info(f"Task {task_id} deadline exceeded: {deadline_str}")

                            # Protect tasks with an active ECS Exec / SSM session: an SRE
                            # may still be working in the task when the deadline expires.
                            # Fail closed - if session state cannot be determined, skip
                            # reaping so a potentially active session is not interrupted.
                            try:
                                if has_active_ssm_session(ECS_CLUSTER, task_id, task):
                                    protected += 1
                                    logger.info(
                                        "Task %s deadline exceeded but has an active ECS Exec "
                                        "session; skipping reap this run", task_id
                                    )
                                    continue
                            except SessionCheckError as e:
                                errors += 1
                                logger.error(
                                    "Could not verify ECS Exec session state for task %s; "
                                    "skipping reap (fail-closed): %s", task_id, e
                                )
                                continue

                            try:
                                ecs.stop_task(
                                    cluster=ECS_CLUSTER,
                                    task=task_arn,
                                    reason=f'Task deadline exceeded (deadline: {deadline_str})'
                                )
                                stopped += 1
                                logger.info(f"Stopped task {task_id} (deadline: {deadline_str})")

                            except (ClientError, BotoCoreError, ConnectionError) as e:
                                logger.error("Failed to stop task %s: %s", task_id, e, exc_info=True)
                                errors += 1
                        else:
                            skipped += 1
                            logger.debug(f"Task {task_id} deadline not yet reached: {deadline_str}")

                    except (ValueError, AttributeError) as e:
                        logger.warning(f"Invalid deadline format for task {task_id}: {deadline_str} - {str(e)}")
                        skipped += 1

                for failure in response.get('failures', []):
                    logger.warning("Could not describe task %s: %s (%s)",
                                   failure.get('arn'), failure.get('reason'), failure.get('detail', ''))
                    errors += 1

            except (ClientError, BotoCoreError) as e:
                logger.error("Failed to describe tasks batch: %s", e, exc_info=True)
                errors += len(batch)

    except Exception as e:
        logger.error(f"Unexpected error during task reaping: {str(e)}", exc_info=True)
        return {
            'error': 'Unexpected error during task reaping',
            'checked': checked,
            'stopped': stopped,
            'skipped': skipped,
            'protected': protected,
            'errors': errors
        }

    logger.info(
        f"Reaper completed: checked={checked}, stopped={stopped}, "
        f"skipped={skipped}, protected={protected}, errors={errors}"
    )

    return {
        'checked': checked,
        'stopped': stopped,
        'skipped': skipped,
        'protected': protected,
        'errors': errors
    }


def list_running_tasks(cluster: str) -> List[str]:
    """
    List all RUNNING tasks in a cluster with pagination.

    Args:
        cluster: ECS cluster name

    Returns:
        List of task ARNs
    """
    task_arns = []
    next_token = None

    while True:
        try:
            kwargs = {
                'cluster': cluster,
                'desiredStatus': 'RUNNING'
            }

            if next_token:
                kwargs['nextToken'] = next_token

            response = ecs.list_tasks(**kwargs)
            task_arns.extend(response.get('taskArns', []))

            next_token = response.get('nextToken')
            if not next_token:
                break

        except (ClientError, BotoCoreError) as e:
            logger.error("Failed to list tasks: %s", e, exc_info=True)
            raise

    return task_arns


def has_active_ssm_session(cluster: str, task_id: str, task: Dict[str, Any]) -> bool:
    """
    Return True if the task has at least one active ECS Exec / SSM session.

    Reuses the create-investigation handover convention for the SSM target:

        ecs:{cluster}_{task_id}_{runtime_id}

    The task object is the entry from ecs.describe_tasks (which already includes
    the ``containers`` array and ``enableExecuteCommand`` flag), so no additional
    DescribeTasks call is required.

    Args:
        cluster: ECS cluster name
        task_id: ECS task ID (last segment of the task ARN)
        task: Task dict from describe_tasks

    Returns:
        True if an active session is confirmed on any relevant container,
        False only when it is confirmed that no active session can exist.

    Raises:
        SessionCheckError: when the session state cannot be reliably determined
            (SSM API failure, or an exec-enabled container whose runtimeId is not
            yet available). Callers must fail closed and skip reaping.
    """
    # Distinguish the exec flag's three cases, since this guard decides whether a
    # task may be stopped:
    #   - explicit False -> genuinely non-exec-capable, safe to reap.
    #   - explicit True  -> run the SSM session check below.
    #   - missing/unexpected -> session state is unknown; fail closed.
    exec_enabled = task.get('enableExecuteCommand')
    if exec_enabled is False:
        return False
    if exec_enabled is not True:
        raise SessionCheckError(
            f"enableExecuteCommand missing or non-boolean ({exec_enabled!r}); "
            "cannot determine exec capability"
        )

    containers = task.get('containers', [])
    if not containers:
        # Exec is enabled but describe_tasks returned no container detail:
        # session state is unknown, so fail closed rather than assume inactive.
        raise SessionCheckError(
            "execute-command enabled but describe_tasks returned no container detail"
        )

    checked_any = False
    for container in containers:
        # Only a RUNNING container can host an active exec session. A container in
        # any other state (e.g. a sidecar that already stopped) cannot, so skip it.
        last_status = container.get('lastStatus')
        if last_status is not None and last_status != 'RUNNING':
            continue

        runtime_id = container.get('runtimeId')
        if not runtime_id:
            # Exec is enabled and the container is (or may be) RUNNING, but the
            # runtimeId needed to address the SSM target is missing. The session
            # state is temporarily unknown - do NOT assume "no active session".
            raise SessionCheckError(
                f"execute-command enabled but container "
                f"{container.get('name', '<unknown>')!r} has no runtimeId"
            )

        checked_any = True
        target = f"ecs:{cluster}_{task_id}_{runtime_id}"
        if _target_has_active_session(target):
            return True

    if not checked_any:
        # Exec enabled but no RUNNING container was available to check: inconclusive.
        raise SessionCheckError(
            "execute-command enabled but no running container available to check"
        )

    return False


def _target_has_active_session(target: str) -> bool:
    """
    Return True if SSM reports any Active session for the given ECS Exec target.

    Paginates DescribeSessions so that a session beyond the first page is still
    detected. Raises SessionCheckError on any SSM API failure so the caller can
    fail closed.

    Args:
        target: ECS Exec SSM target (ecs:{cluster}_{task_id}_{runtime_id})

    Returns:
        True if at least one Active session exists for the target, else False.

    Raises:
        SessionCheckError: when the SSM DescribeSessions call fails.
    """
    next_token = None
    try:
        while True:
            kwargs = {
                'State': 'Active',
                'Filters': [{'key': 'Target', 'value': target}],
            }
            if next_token:
                kwargs['NextToken'] = next_token

            resp = ssm.describe_sessions(**kwargs)
            if resp.get('Sessions'):
                return True

            next_token = resp.get('NextToken')
            if not next_token:
                return False
    except (ClientError, BotoCoreError, ConnectionError) as e:
        raise SessionCheckError(f"SSM DescribeSessions failed: {e}") from e
