"""Reusable comparison of an uploaded S3 workspace against a private manifest.

Extracted from ``scripts/verify_workspace.py`` so the investigation reaper and
the operator script share one comparator. The comparator is deliberately
path-agnostic: callers supply a complete destination URI and own their own
prefix assumptions. Task attempt escrow (``<cluster>/<investigation>/<date>/
<task>/attempts/<uuid>/workspace/``) and reaper close attempts
(``_boundary-close/evidence/<access point>/attempts/<uuid>/workspace/``) are
different layouts and must not be conflated: only the shape below is enforced
here. The ``evidence/`` segment in the close layout is load-bearing — a copy
placed directly under ``_boundary-close/<access point>/`` would fall inside
the SRE role's ``_boundary-close/fsap-*/*.json`` receipt read grant.

Evidence indexes refer to the original manifest array (zero based). This is a
reader comparison of observed versions, not an atomic snapshot or a close
receipt: it proves what the reader saw, not that no later write can occur.
"""

from contextlib import closing
from enum import Enum
import hashlib
import json
import re


UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
DEST = re.compile(r's3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/'
                  rf'((?:[A-Za-z0-9_-][A-Za-z0-9._-]*/)*attempts/{UUID}/workspace/)')

# Credential material never leaves the workspace in escrow or close evidence.
EXCLUDED_KEY_PREFIXES = ('.config/ocm/', '.kube/')


class Reason(Enum):
    INVALID_URI = 'invalid_uri'
    INVALID_MANIFEST = 'invalid_manifest'
    UNEXPECTED_KEY = 'unexpected_key'
    DUPLICATE_KEY = 'duplicate_key'
    MISSING_KEY = 'missing_key'
    MISSING_VERSION = 'missing_version'
    SHORT_OBJECT = 'short_object'
    LONG_OBJECT = 'long_object'
    DIGEST_MISMATCH = 'digest_mismatch'


class ComparisonError(ValueError):
    def __init__(self, reason: Reason):
        super().__init__(reason.value)
        self.reason = reason


def unique_fields(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError('duplicate JSON field')
    return obj


def valid_workspace_key(key) -> bool:
    """Return whether a manifest key is a safe, in-scope relative workspace path."""
    return (isinstance(key, str) and key.isprintable() and '\\' not in key
            and not any(part in ('', '.', '..') for part in key.split('/'))
            and not key.startswith(EXCLUDED_KEY_PREFIXES))


def parse_manifest(raw):
    entries = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_fields)
    if not isinstance(entries, list):
        raise ValueError('expected array')
    expected = {}
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'key', 'length', 'sha256'}:
            raise ValueError('invalid manifest fields')
        key = item['key']
        if not valid_workspace_key(key) or key in expected:
            raise ValueError('invalid or duplicate workspace key')
        if (type(item['length']) is not int or item['length'] < 0
                or not isinstance(item['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise ValueError('invalid manifest measurement')
        expected[key] = item
    return expected


def compare(s3, destination, raw, expected_bucket_owner=None):
    """Compare every object under ``destination`` with the manifest in ``raw``.

    Returns evidence describing what was read: the manifest digest, a digest of
    the destination URI and the exact observed S3 version IDs in manifest order.
    Raises ComparisonError when the destination does not match the manifest.

    ``expected_bucket_owner`` guards against reading a bucket that is no longer
    the account's own; callers that can supply it should.
    """
    match = DEST.fullmatch(destination)
    if not match:
        raise ComparisonError(Reason.INVALID_URI)
    bucket, prefix = match.groups()
    owner = {'ExpectedBucketOwner': expected_bucket_owner} if expected_bucket_owner else {}
    try:
        expected = parse_manifest(raw)
    except ValueError:
        raise ComparisonError(Reason.INVALID_MANIFEST) from None
    seen = set()
    pages = s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix, **owner)
    for page in pages:
        for obj in page.get('Contents', []):
            key = obj['Key']
            if not key.startswith(prefix):
                raise ComparisonError(Reason.UNEXPECTED_KEY)
            relative = key[len(prefix):]
            if relative not in expected:
                raise ComparisonError(Reason.UNEXPECTED_KEY)
            if relative in seen:
                raise ComparisonError(Reason.DUPLICATE_KEY)
            seen.add(relative)
    if seen != expected.keys():
        raise ComparisonError(Reason.MISSING_KEY)

    versions = []
    for key, item in expected.items():
        response = s3.get_object(Bucket=bucket, Key=prefix + key, **owner)
        with closing(response['Body']) as body:
            version = response.get('VersionId')
            if not isinstance(version, str) or not version.strip() or version.strip().lower() == 'null':
                raise ComparisonError(Reason.MISSING_VERSION)
            digest = hashlib.sha256()
            length = 0
            while chunk := body.read(1024 * 1024):
                length += len(chunk)
                if length > item['length']:
                    raise ComparisonError(Reason.LONG_OBJECT)
                digest.update(chunk)
        if length < item['length']:
            raise ComparisonError(Reason.SHORT_OBJECT)
        if digest.hexdigest() != item['sha256']:
            raise ComparisonError(Reason.DIGEST_MISMATCH)
        versions.append(version)
    return {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'workspace_uri_sha256': hashlib.sha256(destination.encode()).hexdigest(),
            'version_ids_in_manifest_order': versions}
