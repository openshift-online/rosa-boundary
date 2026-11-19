"""Compare one quiescent attempt's current S3 workspace to a private cutoff manifest.

Evidence indexes refer to the original manifest array (zero based). This is a
reader comparison of observed versions, not an atomic snapshot or close receipt.
"""

import argparse
from contextlib import closing
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
DEST = re.compile(r's3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/'
                  rf'((?:[A-Za-z0-9_-][A-Za-z0-9._-]*/)*attempts/{UUID}/workspace/)')


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


def parse_manifest(raw):
    entries = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_fields)
    if not isinstance(entries, list):
        raise ValueError('expected array')
    expected = {}
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'key', 'length', 'sha256'}:
            raise ValueError('invalid manifest fields')
        key = item['key']
        if (not isinstance(key, str) or not key.isprintable() or '\\' in key
                or any(part in ('', '.', '..') for part in key.split('/'))
                or key.startswith(('.config/ocm/', '.kube/')) or key in expected):
            raise ValueError('invalid or duplicate workspace key')
        if (type(item['length']) is not int or item['length'] < 0
                or not isinstance(item['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise ValueError('invalid manifest measurement')
        expected[key] = item
    return expected


def compare(s3, destination, raw):
    match = DEST.fullmatch(destination)
    if not match:
        raise ComparisonError(Reason.INVALID_URI)
    bucket, prefix = match.groups()
    try:
        expected = parse_manifest(raw)
    except ValueError:
        raise ComparisonError(Reason.INVALID_MANIFEST) from None
    seen = set()
    pages = s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix)
    for page in pages:
        for obj in page.get('Contents', []):
            key = obj['Key']
            relative = key[len(prefix):]
            if not key.startswith(prefix) or relative not in expected:
                raise ComparisonError(Reason.UNEXPECTED_KEY)
            if relative in seen:
                raise ComparisonError(Reason.DUPLICATE_KEY)
            seen.add(relative)
    if seen != expected.keys():
        raise ComparisonError(Reason.MISSING_KEY)

    versions = []
    for key, item in expected.items():
        response = s3.get_object(Bucket=bucket, Key=prefix + key)
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


def save(evidence, path):
    # Publish complete evidence only, mode 0600, never replace an existing file.
    with tempfile.NamedTemporaryFile(dir=path.parent, mode='w', encoding='utf-8') as out:
        json.dump(evidence, out)
        out.write('\n')
        out.flush()
        os.link(out.name, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace-uri', required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    try:
        import boto3

        evidence = compare(boto3.client('s3'), args.workspace_uri, args.manifest.read_bytes())
        save(evidence, args.evidence)
    except ComparisonError as exc:
        code = exc.reason.value
    except Exception:
        # Neither third-party exception names nor their messages are public.
        code = 'verification_error'
    else:
        return 0
    print(f'Workspace comparison unsuccessful ({code}).', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
