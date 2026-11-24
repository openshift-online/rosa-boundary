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
from botocore.exceptions import (
    BotoCoreError, ClientError, ConnectionError as SDKConnectionError,
    HTTPClientError, NoCredentialsError, PartialCredentialsError,
)

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


class SessionAPIError(SessionCheckError):
    """SSM lookup failed, as distinct from incomplete task metadata."""


def _error_code(error):
    if isinstance(error, ClientError):
        return error.response.get('Error', {}).get('Code')
    return None


def _deployment_failure(operation, error):
    if isinstance(error, (NoCredentialsError, PartialCredentialsError)):
        return True
    code = _error_code(error)
    if code in {'ExpiredToken', 'ExpiredTokenException', 'InvalidClientTokenId',
                'UnrecognizedClientException'}:
        return True  # All calls use the same execution credentials.
    if operation == 'DescribeSessions':
        # The target is a filter; authorization is not scoped to its task ARN.
        return code in {'AccessDenied', 'AccessDeniedException'}
    # Both ECS operations use the configured cluster. In contrast, IAM
    # denial on DescribeTasks or StopTask can be specific to the task ARN.
    return code == 'ClusterNotFoundException'


def _ssm_dependency_reason(error):
    code = _error_code(error)
    if code in {'InternalServerError', 'InternalServerException', 'Throttling',
                'ThrottlingException', 'ServiceUnavailable', 'ServiceUnavailableException'}:
        return code
    if isinstance(error, (ConnectionError, SDKConnectionError, HTTPClientError)):
        return type(error)
    return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for reaping expired ECS tasks.

    Args:
        event: EventBridge event (periodic trigger)
        context: Lambda context object

    Returns:
        Summary for a no-op, successful, or partially successful run.

    Raises:
        Configuration and listing failures propagate. After processing all batches,
        raise for deployment-wide failures, total DescribeTasks call failure,
        or repeated uniform SSM dependency failures. Inconclusive task
        metadata is local: leave the task running for the next scheduled check.
    """
    if not ECS_CLUSTER:
        raise RuntimeError("ECS_CLUSTER not set")

    now = datetime.utcnow()
    task_arns = list_running_tasks(ECS_CLUSTER)
    logger.info("Found %d running tasks", len(task_arns))

    checked = stopped = skipped = protected = errors = 0
    describe_succeeded = False
    describe_failure = deployment_failure = None
    session_check_succeeded = False
    session_failure_count = 0
    session_failure = None
    session_failure_reasons = set()
    batch_size = 100  # DescribeTasks API limit
    for i in range(0, len(task_arns), batch_size):
        batch = task_arns[i:i + batch_size]
        try:
            response = ecs.describe_tasks(cluster=ECS_CLUSTER, tasks=batch, include=['TAGS'])
        except (ClientError, BotoCoreError, ConnectionError) as e:
            describe_failure = e
            if _deployment_failure('DescribeTasks', e):
                deployment_failure = e
            logger.exception("Failed to describe tasks batch starting at offset %d", i)
            errors += len(batch)
            continue

        describe_succeeded = True  # A successful call can return only per-ARN failures.
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
            except (ValueError, AttributeError) as e:
                logger.warning(f"Invalid deadline format for task {task_id}: {deadline_str} - {str(e)}")
                skipped += 1
                continue

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
                    active = has_active_ssm_session(ECS_CLUSTER, task_id, task)
                    if task.get('enableExecuteCommand') is True:
                        session_check_succeeded = True
                    if active:
                        protected += 1
                        logger.info(
                            "Task %s deadline exceeded but has an active ECS Exec "
                            "session; skipping reap this run", task_id
                        )
                        continue
                except SessionCheckError as e:
                    if isinstance(e, SessionAPIError):
                        cause = e.__cause__
                        session_failure_count += 1
                        if session_failure is None:
                            session_failure = cause
                        session_failure_reasons.add(_ssm_dependency_reason(cause))
                        if _deployment_failure('DescribeSessions', cause):
                            deployment_failure = cause
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
                    if _deployment_failure('StopTask', e):
                        deployment_failure = e
                    logger.error("Failed to stop task %s: %s", task_id, e, exc_info=True)
                    errors += 1
            else:
                skipped += 1
                logger.debug(f"Task {task_id} deadline not yet reached: {deadline_str}")

        for failure in response.get('failures', []):
            logger.warning("Could not describe task %s: %s (%s)",
                           failure.get('arn'), failure.get('reason'), failure.get('detail', ''))
            errors += 1

    logger.info(
        f"Reaper summary: checked={checked}, stopped={stopped}, "
        f"skipped={skipped}, protected={protected}, errors={errors}"
    )

    if deployment_failure is not None:
        raise deployment_failure
    if not describe_succeeded and describe_failure is not None:
        raise describe_failure
    if (not session_check_succeeded and session_failure_count > 1
            and len(session_failure_reasons) == 1 and None not in session_failure_reasons):
        raise session_failure

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
        raise SessionAPIError(f"SSM DescribeSessions failed: {e}") from e
