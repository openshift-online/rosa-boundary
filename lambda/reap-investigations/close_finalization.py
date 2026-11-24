"""Finalize investigation close: seal, drain, copy, verify, publish, clean up.

This is the one path that may mutate an investigation's audit state. It serves
both routes — an SRE's explicit close request and an eligible stale workspace —
so there is no second, weaker way to reach deletion.

What the sequence does and does not promise
-------------------------------------------
A managed seal makes Boundary's own create, reconnect and handover paths reject
the investigation once they observe the marker. It is **not** an atomic
admission barrier: a launch that already passed its check can still appear
afterwards. The sequence therefore re-enumerates tasks after draining, after a
configurable quiet interval and again after copying, and treats any late task,
read error, changed source or ambiguous answer as an invalid attempt. Two quiet
scans and matching digests are evidence of what was observed, never proof that
no later write can happen. Receipts say exactly that.

Every destructive step is gated on re-reading the request, the seal, the holds
and the evidence. A failed copy, a failed verification or an unknown result is
never converted into success to satisfy a timer: the workspace is retained with
a reason, and the next scheduled invocation resumes.

Normal close keeps the EFS directory. Only the stale route may reclaim one, and
only when the same verified gate passed; if reclamation cannot be justified the
directory stays with its reason recorded.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import time
import uuid

from contextlib import closing

from botocore.exceptions import BotoCoreError, ClientError

import boundary_close_records as records
import investigation_sessions as sessions
import workspace_verification

logger = logging.getLogger(__name__)

# Credential material is excluded from escrow and from close evidence alike.
EXCLUDED_TOP_LEVEL = ('.kube',)
EXCLUDED_NESTED = (('.config', 'ocm'),)

# Minimum seconds a stage needs before it may start. A stage that cannot finish
# inside the invocation is not started; its progress is resumed on the next one.
STAGE_RESERVE_SECONDS = 20

# Match the SDK's usual multipart threshold. Read one part at a time and
# bound its memory cost in the 256 MiB reaper, even for very large files.
MULTIPART_THRESHOLD = 8 << 20
MAX_PART_SIZE = 32 << 20
MAX_PARTS = 10_000


class TaskDefinitionCleanupError(Exception):
    """ECS did not confirm the exact revision or its expected state."""


class AttemptInvalid(Exception):
    """A finalization attempt cannot be trusted and must be retried fresh.

    Always retryable: the data is intact and a later pass starts a new
    attempt. Nothing published from an invalid attempt is treated as evidence.
    """


class Retained(Exception):
    """Work stopped deliberately; the workspace is kept with a stated reason.

    ``retryable`` decides whether the scheduled reaper will pick the request up
    again by itself. It defaults to false, so a new stop reason has to say
    explicitly that automation can resolve it: promising a retry that never
    happens is worse than asking a person to look.
    """

    def __init__(self, status, reason, phase, retryable=False):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.phase = phase
        self.retryable = retryable


_budget = records.work_seconds


def _excluded(relative_parts):
    if not relative_parts:
        return False
    if relative_parts[0] in EXCLUDED_TOP_LEVEL:
        return True
    return any(tuple(relative_parts[:len(nested)]) == nested for nested in EXCLUDED_NESTED)


def build_source_manifest(directory_path, context):
    """Measure every eligible regular file under a workspace directory.

    The reaper measures the filesystem itself; a task's own upload report is
    never accepted as the source of truth. Unreadable trees and unsafe names
    invalidate the attempt instead of silently shrinking the manifest.
    Symlinks, sockets and devices are recorded as skipped so the evidence says
    what was not copied.
    """
    entries = []
    skipped = []

    def fail_walk(error):
        raise error  # os.walk silently skips unreadable subtrees by default

    for root, dirs, files in os.walk(directory_path, onerror=fail_walk, followlinks=False):
        if _budget(context) <= 0:
            raise AttemptInvalid('deadline reached while measuring the workspace')
        relative_root = os.path.relpath(root, directory_path)
        parts = [] if relative_root == '.' else relative_root.split(os.sep)
        # Prune excluded trees before descending: they need not be readable.
        dirs[:] = [name for name in dirs if not _excluded(parts + [name])]
        if _excluded(parts):
            continue
        for filename in sorted(files):
            local_path = os.path.join(root, filename)
            file_stat = os.lstat(local_path)
            key = '/'.join(parts + [filename])
            if not stat.S_ISREG(file_stat.st_mode):
                skipped.append({'key_sha256': hashlib.sha256(key.encode()).hexdigest(),
                                'reason': 'not a regular file'})
                continue
            if not workspace_verification.valid_workspace_key(key):
                raise AttemptInvalid('workspace contains an unsafe path name')
            digest = hashlib.sha256()
            length = 0
            # O_NOFOLLOW closes the window between the lstat above and this
            # open: the workspace is untrusted, so a symlink swapped in here
            # must not redirect the read.
            try:
                descriptor = os.open(local_path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                raise AttemptInvalid('workspace changed while it was being measured')
            with os.fdopen(descriptor, 'rb') as handle:
                while chunk := handle.read(1024 * 1024):
                    length += len(chunk)
                    digest.update(chunk)
            if length != file_stat.st_size:
                # The file changed while it was being measured.
                raise AttemptInvalid('workspace changed while it was being measured')
            entries.append({'key': key, 'length': length, 'sha256': digest.hexdigest()})
    entries.sort(key=lambda item: item['key'])
    return entries, skipped


class Finalizer:
    """One bounded finalization pipeline shared by both close routes."""

    def __init__(self, *, ecs, efs, s3, ssm, ecs_cluster, efs_filesystem_id, audit_bucket,
                 account_id, mount_path, started_by, task_definition_family,
                 quiet_seconds=15, stale_reclaim=True):
        self.ecs = ecs
        self.efs = efs
        self.s3 = s3
        self.ssm = ssm
        self.ecs_cluster = ecs_cluster
        self.efs_filesystem_id = efs_filesystem_id
        self.audit_bucket = audit_bucket
        self.account_id = account_id
        self.mount_path = mount_path
        self.started_by = started_by
        self.task_definition_family = task_definition_family
        self.quiet_seconds = quiet_seconds
        self.stale_reclaim = stale_reclaim
        # Per-pass progress, reset at the start of every finalize() call.
        self._attempt_id = ''
        self._cleanup = None

    # -- S3 helpers -------------------------------------------------------

    def _owner(self, kwargs):
        if self.account_id:
            kwargs['ExpectedBucketOwner'] = self.account_id
        return kwargs

    def put_json(self, key, record):
        """Publish a complete control record (small, bounded by its contract)."""
        self._put(key, records.encode_record(record))

    def put_evidence(self, key, document):
        """Publish a complete evidence document (bounded by the workspace)."""
        self._put(key, records.encode_evidence(document))

    def _put(self, key, body):
        self.s3.put_object(**self._owner({
            'Bucket': self.audit_bucket,
            'Key': key,
            'Body': body,
            'ContentType': 'application/json',
        }))

    def upload_workspace_file(self, handle, key, length, context):
        """Upload measured bytes, keeping the upload ID for deadline-aware cleanup."""
        target = self._owner({'Bucket': self.audit_bucket, 'Key': key})

        def check_deadline():
            if _budget(context) <= 0:
                raise AttemptInvalid('deadline reached while copying the workspace')

        def read_chunk(size):
            check_deadline()
            chunk = handle.read(size)
            if len(chunk) != size:
                raise AttemptInvalid('a measured file became shorter during copying')
            check_deadline()
            return chunk

        if length < MULTIPART_THRESHOLD:
            self.s3.put_object(**target, Body=read_chunk(length))
            return

        # Grow parts as necessary to respect S3's part count limit, but do
        # not risk OOM for a file too large for this invocation to back up.
        part_size = max(MULTIPART_THRESHOLD, (length + MAX_PARTS - 1) // MAX_PARTS)
        if part_size > MAX_PART_SIZE:
            raise AttemptInvalid('a workspace file exceeds the reaper multipart size limit')

        # Managed transfers hide the upload ID and swallow abort failures.
        # Serial parts let us stop before starting the next request and avoid
        # racing the abort against other parts still running in this process.
        check_deadline()
        upload = self.s3.create_multipart_upload(**target, ChecksumAlgorithm='CRC32')
        target['UploadId'] = upload['UploadId']
        try:
            parts = []
            for number, offset in enumerate(range(0, length, part_size), 1):
                part = self.s3.upload_part(**target, PartNumber=number,
                                           Body=read_chunk(min(part_size, length - offset)),
                                           ChecksumAlgorithm='CRC32')
                parts.append({'PartNumber': number, 'ETag': part['ETag'],
                              'ChecksumCRC32': part['ChecksumCRC32']})
            check_deadline()
            self.s3.complete_multipart_upload(**target, MultipartUpload={'Parts': parts})
        except Exception:
            # Preserve the original failure and never let this attempt authorize
            # deletion, even if S3 completed the upload but lost the response.
            # Hard termination, unknown upload IDs and failed aborts fall back
            # to the audit bucket's incomplete multipart lifecycle rule.
            try:
                self.s3.abort_multipart_upload(**target)
            except (ClientError, BotoCoreError) as error:
                code = error.response.get('Error', {}).get('Code') if isinstance(error, ClientError) else None
                if code != 'NoSuchUpload':
                    logger.warning('Could not abort incomplete workspace upload (%s); '
                                   'audit bucket lifecycle cleanup remains the fallback',
                                   type(error).__name__)
            raise

    def get_json(self, key, kind, *, evidence=False):
        try:
            response = self.s3.get_object(**self._owner({'Bucket': self.audit_bucket,
                                                         'Key': key}))
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code')
            if code in ('NoSuchKey', '404', 'NotFound'):
                return None
            if code in ('AccessDenied', '403'):
                # A missing GET can be forbidden with prefix-scoped ListBucket. An
                # exact key sorts first; only a successful list can prove absence.
                page = self.s3.list_objects_v2(**self._owner({
                    'Bucket': self.audit_bucket, 'Prefix': key, 'MaxKeys': 1}))
                if not any(obj['Key'] == key for obj in page.get('Contents', [])):
                    return None
            raise
        with closing(response['Body']) as stream:
            limit = records.MAX_EVIDENCE_BYTES if evidence else records.MAX_RECORD_BYTES
            body = stream.read(limit + 1)
        if evidence:
            if len(body) > limit:
                raise ValueError('oversized recovery evidence')
            document = json.loads(body)
            if not isinstance(document, dict) or document.get('kind') != kind:
                raise ValueError('invalid recovery evidence')
            return document
        return records.decode_record(body, kind)

    def list_keys(self, prefix):
        keys = []
        paginator = self.s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(**self._owner({'Bucket': self.audit_bucket,
                                                      'Prefix': prefix})):
            keys.extend(obj['Key'] for obj in page.get('Contents', []))
        return sorted(keys)

    def write_status(self, cluster_id, investigation_id, status, *, verification_digest=None,
                     **kwargs):
        record = records.build_status(cluster_id, investigation_id, status, **kwargs)
        if verification_digest is not None:
            record['verification_sha256'] = verification_digest
        self.put_json(records.status_key(cluster_id, investigation_id), record)
        return record

    # -- discovery --------------------------------------------------------

    def find_access_point(self, cluster_id, investigation_id):
        """Resolve the single managed access point for a workspace path."""
        expected_path = f'/{cluster_id}/{investigation_id}'
        match = None
        paginator = self.efs.get_paginator('describe_access_points')
        for page in paginator.paginate(FileSystemId=self.efs_filesystem_id):
            for access_point in page.get('AccessPoints', []):
                if (access_point.get('RootDirectory', {}).get('Path') or '') != expected_path:
                    continue
                if match is not None:
                    raise Retained(records.STATUS_RETAINED,
                                   'multiple access points share this workspace path',
                                   'resolve')
                match = access_point
        if match is None:
            return None
        tags = {tag['Key']: tag['Value'] for tag in match.get('Tags', [])}
        if (tags.get('ClusterID') != cluster_id
                or tags.get('InvestigationID') != investigation_id):
            raise Retained(records.STATUS_RETAINED,
                           'access point identity tags conflict with its path', 'resolve')
        if tags.get('ManagedBy') != records.MANAGED_BY_LAMBDA:
            raise Retained(records.STATUS_RETAINED,
                           'access point is not Lambda-managed', 'resolve')
        return {'id': match['AccessPointId'], 'tags': tags, 'path': expected_path,
                'file_system_id': match.get('FileSystemId', '')}

    def observe(self, cluster_id, investigation_id):
        return sessions.observe_investigation(
            self.ecs, self.ssm, self.ecs_cluster,
            self.started_by(cluster_id, investigation_id))

    # -- stages -----------------------------------------------------------

    def ensure_seal(self, access_point, request_token, context):
        """Set a fresh managed seal, or reuse one; never replace another seal.

        An existing seal without the managed marker is a manual or legacy hold.
        It stays exactly as it is and the workspace is retained for review.
        """
        tags = access_point['tags']
        existing = tags.get(records.TAG_SEAL)
        if existing:
            if tags.get(records.TAG_MANAGED) != records.MANAGED_BY:
                raise Retained(records.STATUS_RETAINED,
                               'an unexplained or manual seal is present; '
                               'the workspace is retained for review', 'seal')
            if not records.REQUEST_TOKEN_PATTERN.match(existing):
                raise Retained(records.STATUS_RETAINED,
                               'the existing managed seal is malformed', 'seal')
            return existing
        if _budget(context) < STAGE_RESERVE_SECONDS:
            raise Retained(records.STATUS_ACCEPTED, 'not enough runtime left to seal', 'seal',
                           retryable=True)
        seal = str(uuid.uuid4())
        self.efs.tag_resource(
            ResourceId=access_point['id'],
            Tags=[
                {'Key': records.TAG_SEAL, 'Value': seal},
                {'Key': records.TAG_MANAGED, 'Value': records.MANAGED_BY},
                {'Key': records.TAG_REQUEST, 'Value': request_token},
                {'Key': records.TAG_BUCKET, 'Value': self.audit_bucket},
            ])
        access_point['tags'] = dict(tags, **{
            records.TAG_SEAL: seal,
            records.TAG_MANAGED: records.MANAGED_BY,
            records.TAG_REQUEST: request_token,
            records.TAG_BUCKET: self.audit_bucket,
        })
        logger.info('Applied managed close seal to %s', access_point['id'])
        return seal

    def drain(self, observation, stop_scope, stop_task_ids, context):
        """Stop only the tasks the requester consented to stop, then wait.

        Without consent the close waits: an SRE asking to close their own
        session never authorizes stopping someone else's work.
        """
        nonterminal = sessions.nonterminal_task_ids(observation)
        if not nonterminal:
            return
        if stop_scope == records.STOP_NONE:
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           f'{len(nonterminal)} task(s) are still running and the request '
                           'carries no stop consent', 'drain', retryable=True)
        consented = (set(nonterminal) if stop_scope == records.STOP_INVESTIGATION
                     else set(stop_task_ids))
        # Consent can only reach this investigation's own tasks, whatever the
        # request named.
        permitted = consented & set(nonterminal)
        remaining = [task for task in nonterminal if task not in permitted]
        if remaining:
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           f'{len(remaining)} task(s) outside the consented stop scope are '
                           'still running', 'drain', retryable=True)
        if _budget(context) < STAGE_RESERVE_SECONDS:
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           'not enough runtime left to stop tasks', 'drain', retryable=True)
        for task_id in sorted(permitted):
            try:
                self.ecs.stop_task(cluster=self.ecs_cluster, task=task_id,
                                   reason='Investigation close requested')
            except (ClientError, BotoCoreError):
                raise Retained(records.STATUS_WAITING_FOR_TASKS,
                               'a consented task could not be stopped', 'drain',
                               retryable=True)
        raise Retained(records.STATUS_WAITING_FOR_TASKS,
                       'stop requested; waiting for the tasks to reach STOPPED', 'drain',
                       retryable=True)

    def confirm_quiet(self, cluster_id, investigation_id, context, sleep=time.sleep):
        """Require a second quiet observation after a configurable interval.

        This reduces exposure to a task that appears just after a scan. It does
        not remove that window, and nothing downstream may claim it does.
        """
        if _budget(context) < self.quiet_seconds + STAGE_RESERVE_SECONDS:
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           'not enough runtime left for the quiet recheck', 'quiet',
                           retryable=True)
        sleep(self.quiet_seconds)
        observation = self.observe(cluster_id, investigation_id)
        if observation['state'] == records.STATE_UNKNOWN:
            raise Retained(records.STATUS_RETAINED,
                           f'recheck inconclusive: {observation["reason"]}', 'quiet',
                           retryable=True)
        if sessions.nonterminal_task_ids(observation):
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           'a task was observed after the workspace appeared quiet', 'quiet',
                           retryable=True)
        return observation

    def copy_workspace(self, access_point_id, attempt_id, directory_path, manifest, context):
        """Copy the measured files into this attempt's own service-only prefix."""
        prefix = records.attempt_workspace_prefix(access_point_id, attempt_id)
        uploaded = 0
        for entry in manifest:
            if _budget(context) <= 0:
                raise AttemptInvalid('deadline reached while copying the workspace')
            local_path = os.path.join(directory_path, *entry['key'].split('/'))
            # Re-open without following symlinks and confirm the measurement
            # still holds: the path is re-resolved here, so a workspace that
            # changed between measuring and copying must not be copied blind.
            try:
                descriptor = os.open(local_path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                raise AttemptInvalid('a measured file could not be reopened for copying')
            with os.fdopen(descriptor, 'rb') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size != entry['length']:
                    raise AttemptInvalid('a measured file changed before it was copied')
                self.upload_workspace_file(handle, prefix + entry['key'], entry['length'], context)
            uploaded += 1
        logger.info('Copied %d file(s) into attempt %s', uploaded, attempt_id)
        return f's3://{self.audit_bucket}/{prefix}'

    def verify_copy(self, destination_uri, manifest_bytes):
        """Compare the destination against the manifest, independently of the copy."""
        try:
            return workspace_verification.compare(self.s3, destination_uri, manifest_bytes,
                                                  self.account_id or None)
        except workspace_verification.ComparisonError as error:
            raise AttemptInvalid(f'verification failed: {error.reason.value}')

    # -- the pipeline -----------------------------------------------------

    def finalize(self, *, cluster_id, investigation_id, access_point, request, mode, context,
                 sleep=time.sleep):
        """Run one bounded finalization pass and return the status record written.

        Every exit writes a status record, and every status record describes
        what actually happened: once cleanup has started, the disposition it
        reported is carried into whatever status is written next, so a later
        failure can never claim a directory or an access point still exists.
        """
        request_token = request['request_token']
        self._attempt_id = ''
        self._cleanup = None
        self._verification_digest = None
        try:
            return self._finalize(cluster_id=cluster_id, investigation_id=investigation_id,
                                  access_point=access_point, request=request, mode=mode,
                                  context=context, sleep=sleep)
        except Retained as stop:
            logger.info('Close for %s/%s %s: %s', cluster_id, investigation_id,
                        stop.status, stop.reason)
            return self._write_outcome(cluster_id, investigation_id, access_point,
                                       request_token, stop.status, stop.phase, stop.reason,
                                       stop.retryable)
        except AttemptInvalid as invalid:
            logger.warning('Close attempt for %s/%s invalidated: %s', cluster_id,
                           investigation_id, invalid)
            return self._write_outcome(cluster_id, investigation_id, access_point,
                                       request_token, records.STATUS_RETAINED, 'verify',
                                       str(invalid), True)
        except ValueError as invalid:
            # A malformed or oversized record retains one workspace; it must
            # never abort the invocation and stop every other close.
            logger.error('Close for %s/%s could not be recorded: %s', cluster_id,
                         investigation_id, invalid)
            return self._write_outcome(cluster_id, investigation_id, access_point,
                                       request_token, records.STATUS_RETAINED, 'record',
                                       str(invalid), False)
        except (ClientError, BotoCoreError, OSError) as error:
            logger.error('Close for %s/%s could not continue: %s', cluster_id,
                         investigation_id, type(error).__name__, exc_info=True)
            return self._write_outcome(
                cluster_id, investigation_id, access_point, request_token,
                records.STATUS_RETAINED, 'error',
                'finalization could not continue; the workspace is retained and the next '
                'scheduled invocation retries it', True)

    def _write_outcome(self, cluster_id, investigation_id, access_point, request_token,
                       status, phase, reason, retryable):
        if self._verification_digest and self._cleanup is None:
            # Disposition is uncertain. Preserve the verified checkpoint.
            return self.get_json(records.status_key(cluster_id, investigation_id),
                                 records.KIND_STATUS)
        cleanup = self._cleanup or {}
        if cleanup:
            # Cleanup already ran: report its disposition, not the defaults.
            status = (records.STATUS_CLEANUP_INCOMPLETE
                      if status == records.STATUS_RETAINED else status)
            reason = f'{reason}; cleanup had already run'
        return self.write_status(
            cluster_id, investigation_id, status, phase=phase, reason=reason,
            access_point_id=access_point['id'], access_point_path=access_point.get('path', ''),
            request_token=request_token, attempt_id=self._attempt_id, retryable=retryable,
            verification_digest=self._verification_digest,
            directory_retained=cleanup.get('directory_retained', True),
            access_point_deleted=cleanup.get('access_point_deleted', False),
            task_definitions_removed=cleanup.get('task_definitions_removed', 0))

    def _finalize(self, *, cluster_id, investigation_id, access_point, request, mode, context,
                  sleep):
        request_token = request['request_token']
        access_point_id = access_point['id']

        # 1. Revalidate authorization against the current observation. Handover
        #    supersedes a session callback, but not an explicit close.
        initial = self.observe(cluster_id, investigation_id)
        if mode == 'request':
            if initial['state'] == records.STATE_UNKNOWN:
                # Inconclusive is not a verdict on the request. A single
                # throttled ListTasks would otherwise end a valid close
                # permanently, because a non-retryable retention is terminal
                # and answers the request for good.
                raise Retained(records.STATUS_RETAINED,
                               f'revalidation inconclusive: {initial["reason"]}', 'authorize',
                               retryable=True)
            superseded = sessions.request_superseded(request, initial)
            if superseded:
                # A handover is a real answer: this requester is no longer
                # eligible and an eligible SRE has to ask again.
                raise Retained(records.STATUS_RETAINED, superseded, 'authorize')
            if initial['state'] == records.STATE_ACTIVE:
                # A shell may have attached after the request was accepted.
                # Stop consent never overrides the shell check, even for its owner.
                raise Retained(records.STATUS_WAITING_FOR_TASKS,
                               'an SSM shell is active; waiting for detachment',
                               'authorize', retryable=True)
        elif initial['state'] != records.STATE_IDLE:
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           f'stale candidate is not idle: {initial["reason"]}', 'authorize',
                           retryable=True)
        elif sessions.nonterminal_task_ids(initial):
            # Idle now means "no attached session", which a RUNNING task no
            # longer contradicts. The scheduled sweep has no human consent
            # behind it, so it waits for the task instead of sealing an
            # investigation somebody may still be running work in.
            raise Retained(records.STATUS_WAITING_FOR_TASKS,
                           'stale candidate still has a running task', 'authorize',
                           retryable=True)

        # 2. Seal (never replacing a manual hold), then drain with consent only.
        seal = self.ensure_seal(access_point, request_token, context)
        self.write_status(cluster_id, investigation_id, records.STATUS_ACCEPTED,
                          phase='sealed', access_point_id=access_point_id,
                          access_point_path=access_point.get('path', ''),
                          request_token=request_token, retryable=True,
                          reason='managed close marker applied')
        self.drain(initial, request.get('stop_scope', records.STOP_NONE),
                   request.get('stop_task_ids', []), context)

        # 3. Two quiet observations separated by the configured interval.
        quiet = self.confirm_quiet(cluster_id, investigation_id, context, sleep=sleep)
        self.write_status(cluster_id, investigation_id, records.STATUS_VERIFYING,
                          phase='measuring', access_point_id=access_point_id,
                          access_point_path=access_point.get('path', ''),
                          request_token=request_token, retryable=True)

        directory_path = os.path.join(self.mount_path, cluster_id, investigation_id)
        if not os.path.ismount(self.mount_path):
            raise Retained(records.STATUS_RETAINED, 'the control filesystem is not mounted',
                           'measure')
        real_path = os.path.realpath(directory_path)
        if real_path != os.path.join(os.path.realpath(self.mount_path), cluster_id,
                                     investigation_id):
            raise Retained(records.STATUS_RETAINED,
                           'workspace path does not resolve inside the filesystem', 'measure')
        try:
            if not stat.S_ISDIR(os.lstat(directory_path).st_mode):
                raise Retained(records.STATUS_RETAINED,
                               'workspace is not a directory; cleanup refused', 'measure')
        except FileNotFoundError:
            raise Retained(records.STATUS_RETAINED,
                           'workspace directory is missing; cannot verify its contents', 'measure')

        attempt_id = str(uuid.uuid4())
        self._attempt_id = attempt_id
        manifest, skipped = build_source_manifest(directory_path, context)

        manifest_bytes = json.dumps(manifest, sort_keys=True,
                                            separators=(',', ':')).encode('utf-8')
        source_document = {
            'schema_version': records.RECEIPT_SCHEMA_VERSION,
            'kind': 'close_source_manifest',
            'attempt_id': attempt_id,
            'access_point_id': access_point_id,
            'cluster_id': cluster_id,
            'investigation_id': investigation_id,
            'seal': seal,
            'request_token': request_token,
            'workspace_present': True,
            'file_count': len(manifest),
            'skipped': skipped,
            'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
            'entries': manifest,
            'observed_at': records.now_iso(),
        }
        self.put_evidence(records.attempt_evidence_key(access_point_id, attempt_id,
                                                       'source-manifest.json'),
                          source_document)

        # 4. Copy into this attempt's own prefix and verify it independently.
        if _budget(context) < STAGE_RESERVE_SECONDS:
            raise Retained(records.STATUS_VERIFYING, 'not enough runtime left to copy',
                           'copy', retryable=True)
        destination_uri = self.copy_workspace(access_point_id, attempt_id, directory_path,
                                              manifest, context)
        evidence = self.verify_copy(destination_uri, manifest_bytes)

        # 5. Re-measure the source and re-enumerate tasks. A difference, a new
        #    task or a read error invalidates this attempt; a new attempt runs
        #    next time rather than publishing from a partial copy.
        final_observation = self.observe(cluster_id, investigation_id)
        if final_observation['state'] == records.STATE_UNKNOWN:
            raise AttemptInvalid(f'final recheck inconclusive: {final_observation["reason"]}')
        if sessions.nonterminal_task_ids(final_observation):
            raise AttemptInvalid('a task was observed after the workspace was copied')
        recheck, _ = build_source_manifest(directory_path, context)
        if recheck != manifest:
            raise AttemptInvalid('the workspace changed while it was being copied')

        verification_document = {
            'schema_version': records.RECEIPT_SCHEMA_VERSION,
            'kind': 'close_verification',
            'deployment': self.ecs_cluster,
            'filesystem': self.efs_filesystem_id,
            'path': access_point['path'],
            'mode': mode,
            'reclaim': mode == 'stale' and self.stale_reclaim,
            'source_sha256': hashlib.sha256(records.encode_evidence(source_document)).hexdigest(),
            'assurance': records.RECEIPT_ASSURANCE,
            'attempt_id': attempt_id,
            'access_point_id': access_point_id,
            'seal': seal,
            'request_token': request_token,
            'destination_uri_sha256': evidence['workspace_uri_sha256'],
            'manifest_sha256': evidence['manifest_sha256'],
            'version_ids_in_manifest_order': evidence['version_ids_in_manifest_order'],
            'initial_observation': _observation_summary(initial),
            'quiet_observation': _observation_summary(quiet),
            'final_observation': _observation_summary(final_observation),
            'verified_at': records.now_iso(),
        }
        self.put_evidence(records.attempt_evidence_key(access_point_id, attempt_id,
                                                       'verification.json'),
                          verification_document)

        # 6. Point at the verified evidence before anything destructive runs,
        #    so a failure between here and the receipt still leaves a record
        #    naming the attempt that holds the data.
        digest = hashlib.sha256(records.encode_evidence(verification_document)).hexdigest()
        self.write_status(cluster_id, investigation_id, records.STATUS_VERIFYING,
                          phase='verified', verification_digest=digest, access_point_id=access_point_id,
                          access_point_path=access_point.get('path', ''),
                          request_token=request_token, attempt_id=attempt_id, retryable=True,
                          reason='backup verified; cleanup pending')

        # 7. Clean up what this route is allowed to clean up, then publish a
        #    receipt describing exactly what happened.
        self._verification_digest = digest
        return self.finish_verified(cluster_id, investigation_id, access_point, request_token,
                                    directory_path, mode, verification_document, evidence)

    def resume_verified(self, cluster_id, investigation_id, ap, request, mode, context, status):
        """Replay only the recorded attempt. Any uncertainty leaves its pointer intact."""
        token = request['request_token']
        ap_id = request['access_point_id']
        attempt = status['attempt_id']
        path = f'/{cluster_id}/{investigation_id}'
        identity = dict(attempt_id=attempt, access_point_id=ap_id, request_token=token)

        def require(condition):
            if not condition:
                raise ValueError('cleanup recovery evidence or current state disagrees')

        def matches(document, fields):
            return document and all(document.get(k) == v for k, v in fields.items())

        require(matches(status, dict(identity, cluster_id=cluster_id,
                                     investigation_id=investigation_id, access_point_path=path)))
        prefix = records.attempt_prefix(ap_id, attempt)
        source = self.get_json(prefix + 'source-manifest.json', 'close_source_manifest',
                               evidence=True)
        proof = self.get_json(prefix + 'verification.json', 'close_verification', evidence=True)
        require(matches(source, dict(identity, cluster_id=cluster_id,
                                     investigation_id=investigation_id, workspace_present=True)))
        require(proof and hashlib.sha256(records.encode_evidence(proof)).hexdigest()
                == status.get('verification_sha256'))
        require(hashlib.sha256(records.encode_evidence(source)).hexdigest()
                == proof.get('source_sha256'))
        seal = source['seal']
        records.receipt_key(ap_id, seal)  # Validate even if the AP is gone.
        require(matches(proof, dict(identity, seal=seal, mode=mode, path=path,
                                    filesystem=self.efs_filesystem_id, deployment=self.ecs_cluster,
                                    assurance=records.RECEIPT_ASSURANCE,
                                    schema_version=records.RECEIPT_SCHEMA_VERSION)))
        reclaim = proof['reclaim']
        require(type(reclaim) is bool and (not reclaim or mode == 'stale'))
        for key in ('quiet_observation', 'final_observation'):
            require(matches(proof[key], dict(state=records.STATE_IDLE, nonterminal_tasks=0,
                                             active_sessions=0)))
        manifest = source['entries']
        require(isinstance(manifest, list) and len(manifest) == source['file_count'])
        body = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        uri = f's3://{self.audit_bucket}/{records.attempt_workspace_prefix(ap_id, attempt)}'
        evidence = self.verify_copy(uri, body)
        require(source['manifest_sha256'] == evidence['manifest_sha256']
                and matches(proof, dict(manifest_sha256=evidence['manifest_sha256'],
                                        destination_uri_sha256=evidence['workspace_uri_sha256'],
                                        version_ids_in_manifest_order=evidence[
                                            'version_ids_in_manifest_order'])))
        prepared = self.get_json(prefix + 'delete-ap.json', 'delete_ap')
        if prepared is not None:
            require(matches(prepared, dict(identity, seal=seal,
                                           verification_sha256=status['verification_sha256']))
                    and prepared['complete'] is True
                    and prepared['directory_retained'] is (not reclaim)
                    and prepared['access_point_deleted'] is False
                    and type(prepared['task_definitions_removed']) is int)
        absent = ap is None
        if absent:
            require(prepared is not None)
            ap = dict(id=ap_id, path=path, file_system_id=self.efs_filesystem_id)
        else:
            require(matches(ap, dict(id=ap_id, path=path, file_system_id=self.efs_filesystem_id))
                    and matches(ap['tags'], {records.TAG_SEAL: seal,
                                             records.TAG_MANAGED: records.MANAGED_BY}))
        directory = os.path.join(self.mount_path, cluster_id, investigation_id)
        require(os.path.ismount(self.mount_path)
                and os.path.realpath(directory) == os.path.realpath(self.mount_path) + path)
        # Do not use exists(): permission and I/O failures are not absence.
        try:
            require(stat.S_ISDIR(os.lstat(directory).st_mode))
            removed = False
        except FileNotFoundError:
            removed = True
        require(not removed or reclaim)
        if prepared is not None:
            require(removed == reclaim)
        # An absent AP doesn't evict an existing mount. Don't declare a
        # retained workspace complete if a late writer changed it on recovery.
        observed = self.observe(cluster_id, investigation_id)
        require(observed['state'] == records.STATE_IDLE
                and not sessions.nonterminal_task_ids(observed))
        if not removed:
            require(build_source_manifest(directory, context)[0] == manifest)
        require(not reclaim or removed or self.stale_reclaim)
        self._verification_digest = status['verification_sha256']
        return self.finish_verified(cluster_id, investigation_id, ap, token, directory,
                                    mode, proof, evidence, directory_removed=removed,
                                    prepared=prepared, ap_absent=absent)

    def finish_verified(self, cluster_id, investigation_id, access_point, request_token,
                        directory_path, mode, verification_document, evidence, *,
                        directory_removed=False, prepared=None, ap_absent=False):
        access_point_id = access_point['id']
        attempt_id = verification_document['attempt_id']
        seal = verification_document['seal']
        ready_key = records.attempt_prefix(access_point_id, attempt_id) + 'delete-ap.json'

        def prepare(result):
            self.put_json(ready_key, dict(result, kind='delete_ap', attempt_id=attempt_id,
                                          seal=seal, request_token=request_token,
                                          access_point_id=access_point_id,
                                          verification_sha256=self._verification_digest))

        cleanup = self.cleanup(cluster_id, investigation_id, access_point_id, directory_path,
                               mode, verification_document['reclaim'], prepare,
                               directory_removed, prepared, ap_absent)
        self._cleanup = cleanup
        receipt = self.publish_receipt(cluster_id, investigation_id, access_point, seal,
                                       request_token, attempt_id, evidence,
                                       verification_document, cleanup)
        status = (records.STATUS_COMPLETED if cleanup['complete']
                  else records.STATUS_CLEANUP_INCOMPLETE)
        return self.write_status(
            cluster_id, investigation_id, status, phase='finished',
            reason=cleanup['reason'], access_point_id=access_point_id,
            access_point_path=access_point.get('path', ''),
            request_token=request_token, attempt_id=attempt_id,
            receipt_key_name=receipt, retryable=not cleanup['complete'],
            verification_digest=self._verification_digest,
            directory_retained=cleanup['directory_retained'],
            access_point_deleted=cleanup['access_point_deleted'],
            task_definitions_removed=cleanup['task_definitions_removed'],
            observations=[verification_document[k] for k in (
                'initial_observation', 'quiet_observation', 'final_observation')])

    def cleanup(self, cluster_id, investigation_id, access_point_id, directory_path, mode,
                reclaim, prepare, directory_removed, prepared, ap_absent):
        """Remove what the route permits, recording each step separately.

        Normal close retains the EFS directory: reclaiming it is a separate,
        stricter decision. The stale route may reclaim, but only behind the
        same verified gate, and only when reclamation is enabled and succeeds.
        """
        result = {'directory_retained': True, 'access_point_deleted': False,
                  'task_definitions_removed': 0, 'complete': True, 'reason': ''}
        reasons = []

        if prepared is not None:
            result.update(prepared)
        elif directory_removed:
            result['directory_retained'] = False
        elif mode == 'stale':
            if not reclaim:
                reasons.append('directory reclamation is disabled; the workspace is retained')
            else:
                try:
                    shutil.rmtree(directory_path)
                    result['directory_retained'] = False
                except OSError:
                    result['complete'] = False
                    reasons.append('the workspace directory could not be removed; the '
                                   'verified copy and evidence are kept')
        else:
            reasons.append('normal close retains the EFS directory')

        try:
            if prepared is None:
                result['task_definitions_removed'] = self.deregister_task_definitions(
                    cluster_id, investigation_id, access_point_id)
        except (ClientError, BotoCoreError, TaskDefinitionCleanupError):
            result['complete'] = False
            reasons.append('task definitions could not be deregistered')

        if result['complete']:
            if prepared is None:
                result['reason'] = '; '.join(reasons)
                prepare(result)
            try:
                if not ap_absent:
                    self.efs.delete_access_point(AccessPointId=access_point_id)
                result['access_point_deleted'] = True
            except ClientError as error:
                if error.response.get('Error', {}).get('Code') == 'AccessPointNotFound':
                    result['access_point_deleted'] = True
                else:
                    result['complete'] = False
                    reasons.append('the access point could not be deleted')
            except BotoCoreError:
                result['complete'] = False
                reasons.append('the access point could not be deleted')
        # Deleting an access point does not evict an existing mount and is not
        # evidence that one was evicted.
        if reasons:
            result['reason'] = '; '.join(reasons)
        return result

    def deregister_task_definitions(self, cluster_id, investigation_id, access_point_id):
        if not self.task_definition_family:
            raise TaskDefinitionCleanupError('Missing task definition family')
        prefix = f'{self.task_definition_family}-{cluster_id}-{investigation_id}'
        # ECS familyPrefix is an exact family name. The timestamp is part of
        # that name, so discover revisions before mutating the paginated list.
        candidates = []
        paginator = self.ecs.get_paginator('list_task_definitions')
        for page in paginator.paginate(status='ACTIVE'):
            for arn in page.get('taskDefinitionArns', []):
                name = arn.split(':task-definition/', 1)[-1]
                family, separator, revision = name.rpartition(':')
                if not separator or not revision.isdigit():
                    continue
                suffix = family[len(prefix) + 1:] if family.startswith(prefix + '-') else None
                if suffix is None or not re.fullmatch(r'\d{8}T\d{6}', suffix):
                    continue
                candidates.append(arn)

        removed = 0
        for arn in candidates:
            td = self.ecs.describe_task_definition(taskDefinition=arn).get('taskDefinition', {})
            if td.get('taskDefinitionArn') != arn or td.get('status') not in ('ACTIVE', 'INACTIVE'):
                raise TaskDefinitionCleanupError(f'Unexpected description for {arn}')
            if td['status'] == 'INACTIVE':
                continue
            # Hyphenated cluster and investigation IDs can produce identical
            # family names. Bind cleanup to the verified workspace, as in the CLI.
            home = next((v.get('efsVolumeConfiguration', {}) for v in td.get('volumes', [])
                         if v.get('name') == 'sre-home'), {})
            if (home.get('fileSystemId') != self.efs_filesystem_id or
                    home.get('authorizationConfig', {}).get('accessPointId') != access_point_id):
                continue
            result = self.ecs.deregister_task_definition(taskDefinition=arn).get('taskDefinition', {})
            if result.get('taskDefinitionArn') != arn or result.get('status') != 'INACTIVE':
                raise TaskDefinitionCleanupError(f'Deregistration not confirmed for {arn}')
            removed += 1
        return removed

    def publish_receipt(self, cluster_id, investigation_id, access_point, seal, request_token,
                        attempt_id, evidence, verification_document, cleanup):
        """Publish a v2 receipt for a fully verified attempt only.

        v2 states its assurance level explicitly. It is bound to the
        deployment, the workspace identity, the seal and request token and the
        exact evidence references, so a receipt from another attempt cannot be
        replayed against this one.
        """
        receipt = {
            'schema_version': records.RECEIPT_SCHEMA_VERSION,
            'assurance': records.RECEIPT_ASSURANCE,
            'cluster_id': cluster_id,
            'investigation_id': investigation_id,
            'access_point_id': access_point['id'],
            'file_system_id': access_point.get('file_system_id', ''),
            'access_point_path': access_point.get('path', ''),
            'deployment': self.ecs_cluster,
            'seal': seal,
            'request_token': request_token,
            'attempt_id': attempt_id,
            'status': 'verified',
            'manifest_ref': (f's3://{self.audit_bucket}/'
                             + records.attempt_evidence_key(access_point['id'], attempt_id,
                                                            'source-manifest.json')),
            'verification_ref': (f's3://{self.audit_bucket}/'
                                 + records.attempt_evidence_key(access_point['id'], attempt_id,
                                                                'verification.json')),
            'manifest_sha256': evidence['manifest_sha256'],
            'workspace_uri_sha256': evidence['workspace_uri_sha256'],
            'object_versions': len(evidence['version_ids_in_manifest_order']),
            'directory_retained': cleanup['directory_retained'],
            'access_point_deleted': cleanup['access_point_deleted'],
            'cleanup_complete': cleanup['complete'],
            'limitations': [
                'Verified against the recorded source observations; writes after the final '
                'observation are not excluded.',
                'Sealing is best effort: a launch that already passed its check can appear '
                'after a reaper observation.',
                'Deleting the access point does not evict an existing mount.',
            ],
        }
        key = records.receipt_key(access_point['id'], seal)
        existing = self.get_json(key, None)
        if existing:
            existing.pop('issued_at', None)
        if existing != receipt:
            receipt['issued_at'] = records.now_iso()
            self.put_json(key, receipt)
        return key


def _observation_summary(observation):
    return {
        'state': observation['state'],
        'active_sessions': observation['active_sessions'],
        'nonterminal_tasks': len(sessions.nonterminal_task_ids(observation)),
        'task_owner_subs': observation.get('task_owner_subs', []),
        'observed_at': observation['observed_at'],
    }
