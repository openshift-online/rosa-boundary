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
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
ecs = boto3.client('ecs')

# Environment variables
ECS_CLUSTER = os.environ.get('ECS_CLUSTER')


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
            'errors': 0
        }

    logger.info(f"Checking for expired tasks in cluster: {ECS_CLUSTER}")

    checked = 0
    stopped = 0
    skipped = 0
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

                            try:
                                ecs.stop_task(
                                    cluster=ECS_CLUSTER,
                                    task=task_arn,
                                    reason=f'Task deadline exceeded (deadline: {deadline_str})'
                                )
                                stopped += 1
                                logger.info(f"Stopped task {task_id}")

                            except ClientError as e:
                                logger.error(f"Failed to stop task {task_id}: {str(e)}")
                                errors += 1
                        else:
                            skipped += 1
                            logger.debug(f"Task {task_id} deadline not yet reached: {deadline_str}")

                    except (ValueError, AttributeError) as e:
                        logger.warning(f"Invalid deadline format for task {task_id}: {deadline_str} - {str(e)}")
                        skipped += 1

            except ClientError as e:
                logger.error(f"Failed to describe tasks batch: {str(e)}")
                errors += len(batch)

    except Exception as e:
        logger.error(f"Unexpected error during task reaping: {str(e)}", exc_info=True)
        return {
            'error': str(e),
            'checked': checked,
            'stopped': stopped,
            'skipped': skipped,
            'errors': errors
        }

    logger.info(f"Reaper completed: checked={checked}, stopped={stopped}, skipped={skipped}, errors={errors}")

    return {
        'checked': checked,
        'stopped': stopped,
        'skipped': skipped,
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

        except ClientError as e:
            logger.error(f"Failed to list tasks: {str(e)}")
            raise

    return task_arns
