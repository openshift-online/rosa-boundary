"""Compare one quiescent attempt's current S3 workspace to a private cutoff manifest.

Evidence indexes refer to the original manifest array (zero based). This is a
reader comparison of observed versions, not an atomic snapshot or close receipt.
"""

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
DEST = re.compile(r's3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/'
                  rf'((?:[A-Za-z0-9_-][A-Za-z0-9._-]*/)+attempts/{UUID}/workspace/)')


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
        raise ValueError('expected single attempt workspace URI')
    bucket, prefix = match.groups()
    expected = parse_manifest(raw)
    seen = set()
    pages = s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix)
    for page in pages:
        for obj in page.get('Contents', []):
            key = obj['Key']
            relative = key[len(prefix):]
            if not key.startswith(prefix) or relative not in expected or relative in seen:
                raise ValueError('unexpected listed key')
            seen.add(relative)
    if seen != expected.keys():
        raise ValueError('missing listed key')

    versions = []
    for key, item in expected.items():
        response = s3.get_object(Bucket=bucket, Key=prefix + key)
        with closing(response['Body']) as body:
            version = response.get('VersionId')
            if not isinstance(version, str) or not version.strip() or version.strip().lower() == 'null':
                raise ValueError('missing object version')
            digest = hashlib.sha256()
            length = 0
            while chunk := body.read(1024 * 1024):
                length += len(chunk)
                if length > item['length']:
                    raise ValueError('object too long')
                digest.update(chunk)
        if length != item['length'] or digest.hexdigest() != item['sha256']:
            raise ValueError('object mismatch')
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
    except Exception as exc:
        # SDK errors and parser diagnostics may contain private names or bytes.
        print(f'Workspace comparison unsuccessful ({type(exc).__name__}).', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
