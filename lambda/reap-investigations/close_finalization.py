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

    def upload_workspace_file(self, handle, key):
        """Copy one already-opened workspace file into the attempt prefix.

        The bytes come from the descriptor the finalizer measured, and the
        bucket-owner guard applies here exactly as it does to every record.
        """
        extra = {'ExpectedBucketOwner': self.account_id} if self.account_id else None
        self.s3.upload_fileobj(handle, self.audit_bucket, key, ExtraArgs=extra)

    def get_json(self, key, kind):
        try:
            response = self.s3.get_object(**self._owner({'Bucket': self.audit_bucket,
                                                         'Key': key}))
        except ClientError as error:
            if error.response.get('Error', {}).get('Code') in ('NoSuchKey', '404', 'NotFound'):
                return None
            raise
        with closing(response['Body']) as stream:
            body = stream.read(records.MAX_RECORD_BYTES + 1)
        return records.decode_record(body, kind)

    def list_keys(self, prefix):
        keys = []
        paginator = self.s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(**self._owner({'Bucket': self.audit_bucket,
                                                      'Prefix': prefix})):
            keys.extend(obj['Key'] for obj in page.get('Contents', []))
        return sorted(keys)

    def write_status(self, cluster_id, investigation_id, status, **kwargs):
        record = records.build_status(cluster_id, investigation_id, status, **kwargs)
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
                self.upload_workspace_file(handle, prefix + entry['key'])
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
            directory_retained=cleanup.get('directory_retained', True),
            access_point_deleted=cleanup.get('access_point_deleted', False),
            task_definitions_removed=cleanup.get('task_definitions_removed', 0))

    def _finalize(self, *, cluster_id, investigation_id, access_point, request, mode, context,
                  sleep):
        request_token = request['request_token']
        access_point_id = access_point['id']

        # 1. Revalidate authorization against the current observation. A request
        #    that was valid when accepted is not authority once the
        #    investigation changes hands.
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
        self.write_status(cluster_id, investigation_id, records.STATUS_VERIFYING,
                          phase='verified', access_point_id=access_point_id,
                          access_point_path=access_point.get('path', ''),
                          request_token=request_token, attempt_id=attempt_id, retryable=True,
                          reason='backup verified; cleanup pending')

        # 7. Clean up what this route is allowed to clean up, then publish a
        #    receipt describing exactly what happened.
        cleanup = self.cleanup(cluster_id, investigation_id, access_point_id, directory_path,
                               mode)
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
            directory_retained=cleanup['directory_retained'],
            access_point_deleted=cleanup['access_point_deleted'],
            task_definitions_removed=cleanup['task_definitions_removed'],
            observations=[_observation_summary(initial), _observation_summary(quiet),
                          _observation_summary(final_observation)])

    def cleanup(self, cluster_id, investigation_id, access_point_id, directory_path, mode):
        """Remove what the route permits, recording each step separately.

        Normal close retains the EFS directory: reclaiming it is a separate,
        stricter decision. The stale route may reclaim, but only behind the
        same verified gate, and only when reclamation is enabled and succeeds.
        """
        result = {'directory_retained': True, 'access_point_deleted': False,
                  'task_definitions_removed': 0, 'complete': True, 'reason': ''}
        reasons = []

        if mode == 'stale':
            if not self.stale_reclaim:
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
            result['task_definitions_removed'] = self.deregister_task_definitions(
                cluster_id, investigation_id)
        except (ClientError, BotoCoreError):
            result['complete'] = False
            reasons.append('task definitions could not be deregistered')

        if result['complete']:
            try:
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
        result['reason'] = '; '.join(reasons)
        return result

    def deregister_task_definitions(self, cluster_id, investigation_id):
        if not self.task_definition_family:
            return 0
        prefix = f'{self.task_definition_family}-{cluster_id}-{investigation_id}'
        removed = 0
        paginator = self.ecs.get_paginator('list_task_definitions')
        for page in paginator.paginate(familyPrefix=prefix, status='ACTIVE'):
            for arn in page.get('taskDefinitionArns', []):
                name = arn.split(':task-definition/', 1)[-1]
                family, separator, revision = name.rpartition(':')
                if not separator or not revision.isdigit():
                    continue
                suffix = family[len(prefix) + 1:] if family.startswith(prefix + '-') else None
                if suffix is None or not re.fullmatch(r'\d{8}T\d{6}', suffix):
                    continue
                self.ecs.deregister_task_definition(taskDefinition=arn)
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
            'issued_at': records.now_iso(),
        }
        key = records.receipt_key(access_point['id'], seal)
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
