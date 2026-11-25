"""
AWS Lambda handler for investigation close finalization and garbage collection.

This Lambda runs on a schedule (default: every 8 hours) and is the only
component that finalizes an investigation. Each invocation:

1. Finishes explicit close requests recorded by authenticated SREs
2. Activates auto-close intents whose session task has stopped
3. Records scheduled closure at expiry or after the investigation idle window

All three routes run through one bounded pipeline — seal, drain, copy, verify,
publish, clean up — so there is no alternative, less-verified way to reach
deletion. The schedule is the recovery path: a request survives a lost CLI, and
an invocation that runs out of runtime resumes on the next one.

Finalization is intended to run one invocation at a time per deployment
(``reserved_concurrent_executions = 1`` in the regional Terraform). That is an
operational serialization constraint on finalizers, not a lock against session
creation or against any other EFS client.

Environment Variables:
- ECS_CLUSTER: ECS cluster name
- EFS_FILESYSTEM_ID: EFS filesystem ID
- INVESTIGATION_EXPIRY_HOURS: Maximum investigation age (default: 168)
- S3_AUDIT_BUCKET: Audit bucket holding close requests, evidence and receipts
- AWS_ACCOUNT_ID: Expected audit bucket owner
- TASK_DEFINITION_FAMILY: Task definition family prefix for cleanup
- CLOSE_QUIET_SECONDS: Interval between the two quiet observations (default 15)
- CLOSE_REQUESTS_PER_RUN: Explicit requests finalized per invocation (default 3)
- CLOSE_STALE_RECLAIM: Whether stale reaping may reclaim directories (default true)
"""

import os
import logging
import re
import hashlib
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError

import boundary_close_records as records
import close_finalization
import investigation_sessions as sessions

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

s3 = boto3.client(
    's3',
    config=BotocoreConfig(connect_timeout=5, read_timeout=30, retries={'max_attempts': 3, 'mode': 'standard'})
)

ssm = boto3.client(
    'ssm',
    config=BotocoreConfig(connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'})
)

ECS_CLUSTER = os.environ.get('ECS_CLUSTER')
EFS_FILESYSTEM_ID = os.environ.get('EFS_FILESYSTEM_ID')
EXPIRY_HOURS = float(os.environ.get('INVESTIGATION_EXPIRY_HOURS', '168'))
IDLE_WINDOW = timedelta(hours=8)
S3_AUDIT_BUCKET = os.environ.get('S3_AUDIT_BUCKET', '')
AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '')
TASK_DEFINITION_FAMILY = os.environ.get('TASK_DEFINITION_FAMILY', '')
CLOSE_QUIET_SECONDS = int(os.environ.get('CLOSE_QUIET_SECONDS', '15'))
CLOSE_REQUESTS_PER_RUN = int(os.environ.get('CLOSE_REQUESTS_PER_RUN', '3'))
CLOSE_STALE_RECLAIM = os.environ.get('CLOSE_STALE_RECLAIM', 'true').lower() != 'false'
EFS_MOUNT_PATH = '/mnt/efs'

# A finalization needs room for the quiet recheck, a copy and the cleanup
# reserve. Starting one with less time would checkpoint immediately and burn
# budget that explicit requests and stale candidates both need.
CLOSE_MIN_SECONDS = 60

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


# One definition of the runtime budget, shared with the finalization pipeline.
work_seconds = records.work_seconds


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

    if not S3_AUDIT_BUCKET or not AWS_ACCOUNT_ID:
        raise ValueError("Lambda configuration error: S3_AUDIT_BUCKET and AWS_ACCOUNT_ID are required")

    logger.info("Checking investigation idle and expiry thresholds (expiry: %gh)", EXPIRY_HOURS)

    checked = 0
    reaped = 0
    skipped = 0
    errors = 0
    now = datetime.now(timezone.utc)

    if not work_seconds(context):
        logger.warning("Insufficient time for investigation discovery")
        return {'checked': 0, 'reaped': 0, 'skipped': 0, 'errors': 0,
                'requests_processed': 0, 'intents_activated': 0, 'close_errors': 0}

    # Explicit requests run first, under their own per-run cap, so neither they
    # nor the stale sweep can starve the other.
    discovery_errors = []
    close_summary = process_close_work(context, discovery_errors)

    try:
        access_points = list_investigation_access_points()

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
                # Missing CreatedAt identifies a retired legacy investigation.
                stamp = tags.get('CreatedAt')
                created = datetime.fromisoformat(stamp.replace('Z', '+00:00')) if stamp else None
                expired = created is None or now - created >= timedelta(hours=EXPIRY_HOURS)
                if not expired and now - created < IDLE_WINDOW:
                    skipped += 1
                    continue
                reap_success = reap_investigation(cluster_id, investigation_id, ap_id, context,
                                                 created=created, now=now, expired=expired)
            except (ValueError, TypeError, KeyError, close_finalization.TaskDefinitionCleanupError,
                    ClientError, BotoCoreError):
                logger.exception("Scheduled close failed for %s/%s", cluster_id, investigation_id)
                errors += 1
                continue

            if reap_success is None:
                skipped += 1
                continue
            if reap_success:
                reaped += 1
            else:
                errors += 1

    except Exception as e:
        logger.exception("Stale sweep failed: checked=%d reaped=%d skipped=%d errors=%d close=%s",
                         checked, reaped, skipped, errors, close_summary)
        if discovery_errors:
            raise ExceptionGroup("Multiple reaper phases failed", [*discovery_errors, e]) from None
        raise

    if discovery_errors:
        logger.error("Close discovery incomplete: checked=%d reaped=%d skipped=%d errors=%d close=%s",
                     checked, reaped, skipped, errors, close_summary)
    if len(discovery_errors) == 1:
        raise discovery_errors[0]
    if discovery_errors:
        raise ExceptionGroup("Close discovery failed", discovery_errors)

    logger.info("Reaper completed: checked=%d, reaped=%d, skipped=%d, errors=%d",
               checked, reaped, skipped, errors)

    return {
        'checked': checked,
        'reaped': reaped,
        'skipped': skipped,
        'errors': errors,
        **close_summary,
    }


def build_finalizer() -> close_finalization.Finalizer:
    """Build the single finalization pipeline used by every close route."""
    return close_finalization.Finalizer(
        ecs=ecs, efs=efs, s3=s3, ssm=ssm,
        ecs_cluster=ECS_CLUSTER,
        efs_filesystem_id=EFS_FILESYSTEM_ID,
        audit_bucket=S3_AUDIT_BUCKET,
        account_id=AWS_ACCOUNT_ID,
        mount_path=EFS_MOUNT_PATH,
        started_by=investigation_started_by,
        task_definition_family=TASK_DEFINITION_FAMILY,
        quiet_seconds=CLOSE_QUIET_SECONDS,
        stale_reclaim=CLOSE_STALE_RECLAIM,
    )


def process_close_work(context: Any, discovery_errors: List[Exception]) -> Dict[str, int]:
    """Finalize explicit close requests and activate eligible auto-close intents.

    Discovery/configuration failures invalidate the run and propagate to Lambda.
    Once a record is identified, isolate its failure and continue with its peers.
    """
    # requests_processed counts passes, not successes: a pass that retained the
    # workspace also increments close_errors.
    summary = {'requests_processed': 0, 'intents_activated': 0, 'close_errors': 0}
    finalizer = build_finalizer()
    # The inventories are independent. Fail the invocation after safe work,
    # not at the first unavailable prefix. Record-level exceptions are handled
    # inside each processor and never turn into a discovery failure by count.
    for field, process in (('intents_activated', activate_auto_close_intents),
                           ('requests_processed', finalize_close_requests)):
        try:
            summary[field] = process(finalizer, context, summary)
        except (ClientError, BotoCoreError) as error:
            logger.exception("Could not discover close work for %s", field)
            discovery_errors.append(error)
    return summary


def _identifiers_from_key(key: str, prefix: str, depth: int) -> Optional[List[str]]:
    """Split a control key into validated identifier segments, or None."""
    if not key.startswith(prefix):
        return None
    parts = key[len(prefix):].split('/')
    if len(parts) != depth:
        return None
    parts[-1] = parts[-1].removesuffix('.json')
    try:
        for part in parts:
            records.safe_segment(part)
    except ValueError:
        logger.warning("Ignoring control record with an unsafe key")
        return None
    return parts


def _request_identity(key: str) -> Optional[List[str]]:
    """Split a request key into cluster, investigation, request time and token."""
    prefix = f'{records.CONTROL_PREFIX}/requests/'
    if not key.startswith(prefix):
        return None
    parts = key[len(prefix):].split('/')
    if len(parts) != 3:
        return None
    parsed = records.parse_request_filename(parts[2])
    if parsed is None:
        return None
    try:
        records.safe_segment(parts[0])
        records.safe_segment(parts[1])
    except ValueError:
        logger.warning("Ignoring close request with an unsafe key")
        return None
    return [parts[0], parts[1], parsed[0], parsed[1]]


def _answered(status: Optional[Dict[str, Any]], token: str, stamp: str) -> bool:
    """Return whether a recorded outcome already answers this request.

    A retained outcome the reaper can resolve by itself is *not* an answer:
    treating one as final is how a single throttled API call would end a close
    request forever, while the CLI and the runbook promise a retry.
    """
    if not status or status.get('status') not in records.TERMINAL_STATUSES:
        return False
    # Completion belongs to the investigation, not just one request. Keep
    # its original token, receipt and attempt intact even for a later request.
    if status.get('status') == records.STATUS_COMPLETED:
        return True
    if status.get('status') == records.STATUS_RETAINED and status.get('retryable'):
        return False
    if status.get('request_token') == token:
        return True
    # An outcome recorded after this request was written already covers it; an
    # older outcome does not. Both sides are compared as sortable UTC stamps.
    try:
        return records.request_stamp(status.get('updated_at', '')) >= stamp
    except (TypeError, ValueError):
        return False


def finalize_close_requests(finalizer, context: Any, summary: Dict[str, int]) -> int:
    """Finalize recorded close requests within this invocation's budget.

    Records are object-locked and never deleted, so the scan must be able to
    pass over an answered request without reading it. The request time is in
    the key and the status record is read once per investigation, which keeps
    a long history from starving the newest requests.

    Within a run the budget goes to the investigations that have waited
    longest, not to whichever keys sort first. A request that cannot finish in
    one pass — one waiting for a task to stop, most commonly — stays
    unanswered for as long as the wait lasts, so always taking the head of the
    key space would let a few waiting investigations hold the entire budget
    and starve every request recorded behind them indefinitely. Ordering by
    the last recorded progress rotates the queue, because each attempt writes
    a status and so sends that investigation to the back.
    """
    statuses: Dict[Any, Optional[Dict[str, Any]]] = {}
    candidates: Dict[Any, Any] = {}
    unreadable = set()
    for key in finalizer.list_keys(f'{records.CONTROL_PREFIX}/requests/'):
        if work_seconds(context) < CLOSE_MIN_SECONDS:
            break
        identity = _request_identity(key)
        if identity is None:
            continue
        cluster_id, investigation_id, stamp, token = identity
        investigation = (cluster_id, investigation_id)
        if investigation in unreadable:
            continue
        if investigation not in statuses:
            try:
                statuses[investigation] = finalizer.get_json(
                    records.status_key(cluster_id, investigation_id), records.KIND_STATUS)
            except (ValueError, ClientError, BotoCoreError):
                # Unknown is not absent: never start fresh over a possible checkpoint.
                logger.exception("Cannot read close status for %s/%s", *investigation)
                unreadable.add(investigation)
                summary['close_errors'] += 1
                continue
        if _answered(statuses[investigation], token, stamp):
            continue
        # One attempt per investigation per run: a second request for the same
        # workspace is governed by the outcome of the first, and that outcome
        # is not known until this run has written it.
        prior = statuses[investigation] or {}
        if _cleanup_pending(prior) and token != prior.get('request_token'):
            continue  # Only the request that verified this backup can resume cleanup.
        candidates.setdefault(investigation, (key, stamp, token))

    def waited_longest(item):
        investigation, (_key, stamp, _token) = item
        status = statuses[investigation] or {}
        # An investigation nobody has attempted yet has no progress stamp, so
        # it sorts ahead of every investigation that has one.
        return (str(status.get('updated_at', '')), stamp)

    finalized = 0
    for investigation, (key, stamp, token) in sorted(candidates.items(), key=waited_longest):
        if finalized >= CLOSE_REQUESTS_PER_RUN or work_seconds(context) < CLOSE_MIN_SECONDS:
            break
        cluster_id, investigation_id = investigation
        try:
            request = records.validate_request(
                finalizer.get_json(key, records.KIND_REQUEST) or {})
        except (ValueError, ClientError, BotoCoreError):
            logger.exception("Cannot read close request for %s/%s", *investigation)
            summary['close_errors'] += 1
            continue
        if (request['cluster_id'] != cluster_id
                or request['investigation_id'] != investigation_id
                or request['request_token'] != token):
            logger.warning("Ignoring close request whose identity disagrees with its key")
            summary['close_errors'] += 1
            continue
        mode = 'stale' if request['trigger'] == records.TRIGGER_STALE else 'request'
        try:
            complete = finalize_one(finalizer, cluster_id, investigation_id, request, mode,
                                    context, existing=statuses[investigation])
        except (ValueError, ClientError, BotoCoreError):
            logger.exception("Close pass failed for %s/%s", *investigation)
            complete = False
        if not complete:
            summary['close_errors'] += 1
        finalized += 1
    return finalized


_UNREAD = object()


def _cleanup_pending(status):
    return status and status.get('status') != records.STATUS_COMPLETED and (
        'verification_sha256' in status or status.get('phase') == 'verified'
        or status.get('status') == records.STATUS_CLEANUP_INCOMPLETE)


def finalize_one(finalizer, cluster_id: str, investigation_id: str,
                 request: Dict[str, Any], mode: str, context: Any, existing=_UNREAD) -> bool:
    """Resolve the workspace and run one finalization pass."""
    if existing is _UNREAD:
        existing = finalizer.get_json(records.status_key(cluster_id, investigation_id),
                                      records.KIND_STATUS)
    if existing and existing.get('status') == records.STATUS_COMPLETED:
        return True
    try:
        access_point = finalizer.find_access_point(cluster_id, investigation_id)
        if _cleanup_pending(existing):
            try:
                outcome = finalizer.resume_verified(cluster_id, investigation_id, access_point,
                                                    request, mode, context, existing)
            except (ValueError, TypeError, KeyError, OSError, ClientError, BotoCoreError,
                    close_finalization.AttemptInvalid):
                logger.warning('Cannot resume verified close for %s/%s; preserving checkpoint',
                               cluster_id, investigation_id, exc_info=True)
                return False
            return outcome['status'] == records.STATUS_COMPLETED
    except close_finalization.Retained as stop:
        if _cleanup_pending(existing):
            return False
        finalizer.write_status(cluster_id, investigation_id, stop.status, phase=stop.phase,
                               reason=stop.reason, request_token=request['request_token'])
        return False
    if access_point is None:
        finalizer.write_status(
            cluster_id, investigation_id, records.STATUS_RETAINED, phase='resolve',
            reason='no managed access point exists for this workspace', retryable=True,
            request_token=request['request_token'])
        return False
    if access_point['id'] != request['access_point_id']:
        finalizer.write_status(cluster_id, investigation_id, records.STATUS_RETAINED, phase='resolve',
                               reason='access point changed since this close request was recorded',
                               request_token=request['request_token'],
                               access_point_id=request['access_point_id'])
        return False
    status = finalizer.finalize(cluster_id=cluster_id, investigation_id=investigation_id,
                                access_point=access_point, request=request, mode=mode,
                                context=context)
    return status.get('status') == records.STATUS_COMPLETED


def activate_auto_close_intents(finalizer, context: Any, summary=None) -> int:
    """Turn eligible auto-close intents into recorded close requests.

    An intent is activated only once its own task is observed stopped and the
    SRE that recorded it is still eligible. A handover to another active SRE
    supersedes the intent: it is not inherited consent to close the new
    holder's investigation.

    Another SRE's task left running is a weaker signal than an attached
    session — the investigation reads as idle — but activating into it would
    still seal a workspace somebody may be running work in, on nobody's
    present say-so. So an intent waits for the whole investigation to go
    quiet unless its author explicitly consented to stopping every task.
    """
    activated = 0
    prefix = f'{records.CONTROL_PREFIX}/intents/'
    for key in finalizer.list_keys(prefix):
        # Intents run before requests, so they get the same per-run cap: an
        # unbounded burst of activations would otherwise spend the invocation
        # before a single recorded request was finalized.
        if activated >= CLOSE_REQUESTS_PER_RUN or work_seconds(context) < CLOSE_MIN_SECONDS:
            break
        parts = _identifiers_from_key(key, prefix, 3)
        if parts is None:
            continue
        cluster_id, investigation_id, _task = parts
        try:
            if activate_one_intent(finalizer, key, cluster_id, investigation_id):
                activated += 1
        except (ValueError, ClientError, BotoCoreError):
            logger.exception("Cannot process auto-close intent for %s/%s", cluster_id, investigation_id)
            if summary is not None:
                summary['close_errors'] += 1
    return activated


def activate_one_intent(finalizer, key, cluster_id, investigation_id) -> bool:
    intent = records.validate_intent(finalizer.get_json(key, records.KIND_INTENT) or {})
    if intent.get('cancelled') or intent.get('activated_request_token'):
        return False
    observation = finalizer.observe(cluster_id, investigation_id)
    if observation['state'] == records.STATE_UNKNOWN:
        logger.info("Auto-close intent deferred: investigation state is unknown")
        return False
    remaining = sessions.nonterminal_task_ids(observation)
    if intent['task_id'] in remaining:
        return False
    # Supersession is decided before the wait below, so a handover still
    # cancels a stale intent instead of leaving it deferred forever.
    superseded = sessions.request_superseded(intent, observation)
    if superseded:
        logger.info("Auto-close intent superseded for %s/%s", cluster_id, investigation_id)
        finalizer.put_json(key, dict(intent, cancelled=True,
                                     cancelled_at=records.now_iso(),
                                     cancelled_reason=superseded))
        return False
    if observation['state'] != records.STATE_IDLE:
        # Intent is not pending closure: even stop-all consent cannot
        # activate it while the requester has another shell attached.
        return False
    if remaining and intent['stop_scope'] != records.STOP_INVESTIGATION:
        # Another task is still running and this intent was not consent to
        # stop it. Wait for it rather than seal around work in progress.
        logger.info("Auto-close intent deferred: another task is still running")
        return False
    request_token = str(uuid.uuid4())
    requested_at = records.now_iso()
    request = {
        'schema_version': records.REQUEST_SCHEMA_VERSION,
        'kind': records.KIND_REQUEST,
        'request_token': request_token,
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'access_point_id': intent['access_point_id'],
        'requester_sub': intent['requester_sub'],
        'requester_username': intent.get('requester_username', ''),
        'stop_scope': intent['stop_scope'],
        'stop_task_ids': ([intent['task_id']]
                          if intent['stop_scope'] == records.STOP_SESSION_TASK else []),
        'trigger': 'auto_close',
        'requested_at': requested_at,
        'activated_from_intent': intent['task_id'],
        'deployment': ECS_CLUSTER,
    }
    finalizer.put_json(
        records.request_key(cluster_id, investigation_id, request_token, requested_at),
        request)
    finalizer.put_json(key, dict(intent, activated_request_token=request_token,
                                 activated_at=records.now_iso()))
    return True


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


def reap_investigation(cluster_id: str, investigation_id: str, access_point_id: str,
                       context: Any, *, created, now, expired) -> Optional[bool]:
    """Record scheduled closure intent and attempt the shared verified gate.

    Stale reaping has no separate, backup-only destructive path. It runs the
    same pipeline an explicit close runs — seal, observe, copy, independently
    verify, publish, then clean up — and reclaims the directory only when that
    gate passed. It carries no stop consent: a scheduled, unattended job never
    stops a task. Expiry closes admission even if shells still need to drain.

    The request is recorded before the pass begins. Sealing happens early, and
    the stale sweep skips sealed access points, so without a persisted request
    an interrupted pass would leave a sealed workspace that nothing ever
    revisits. With one, the request route resumes it on the next invocation.
    """
    if work_seconds(context) < CLOSE_MIN_SECONDS:
        logger.info("Not enough runtime left to reap %s; deferring to the next invocation",
                    access_point_id)
        return False
    if not S3_AUDIT_BUCKET:
        logger.error("S3_AUDIT_BUCKET is not configured; refusing to reap %s", access_point_id)
        return False
    finalizer = build_finalizer()
    # A durable immutable request closes admission, even before it is safe to
    # seal. Don't queue another scheduled request on every pass while draining.
    keys = finalizer.list_keys(records.requests_prefix(cluster_id, investigation_id))
    if keys:
        status = finalizer.get_json(records.status_key(cluster_id, investigation_id),
                                    records.KIND_STATUS)
        if status and status.get('status') == records.STATUS_COMPLETED:
            return None
        for key in keys:
            identity = _request_identity(key)
            if identity and not _answered(status, identity[3], identity[2]):
                return None
    request_token = str(uuid.uuid4())
    if not expired:
        # A detach is not durably observable. Launch-specific task definitions
        # outlive stopped-task history; registration immediately precedes launch.
        deadline = finalizer.latest_session_deadline(cluster_id, investigation_id, access_point_id)
        if now - max(created, deadline or created) < IDLE_WINDOW:
            return None
        if finalizer.observe(cluster_id, investigation_id)['state'] != records.STATE_IDLE:
            return None
    requested_at = records.now_iso()
    request = {
        'schema_version': records.REQUEST_SCHEMA_VERSION,
        'kind': records.KIND_REQUEST,
        'request_token': request_token,
        'cluster_id': cluster_id,
        'investigation_id': investigation_id,
        'access_point_id': access_point_id,
        'requester_sub': '',
        'stop_scope': records.STOP_NONE,
        'stop_task_ids': [],
        'trigger': records.TRIGGER_STALE,
        'requested_at': requested_at,
        'deployment': ECS_CLUSTER,
    }
    try:
        finalizer.put_json(
            records.request_key(cluster_id, investigation_id, request_token, requested_at),
            request)
    except (ClientError, BotoCoreError, ValueError):
        logger.error("Could not record the stale close request for %s; deferring",
                     access_point_id, exc_info=True)
        return False
    return finalize_one(finalizer, cluster_id, investigation_id, request, 'stale', context)
