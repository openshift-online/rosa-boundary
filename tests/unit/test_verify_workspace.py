"""Offline operator verification tests: fake exposes only LIST and GET."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location('verify_workspace', Path(__file__).resolve().parents[2] / 'scripts/verify_workspace.py')
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


PREFIX = 'cluster/investigation/date/task/attempts/12345678-abcd-abcd-abcd-123456789abc/workspace/'
URI = 's3://audit-fixture/' + PREFIX
FILES = {'private/nested name': b'private bytes', '.empty': b''}


def entry(key, data):
    return {'key': key, 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


RAW = json.dumps([entry(k, v) for k, v in FILES.items()]).encode()


class Body(io.BytesIO):
    def read(self, size=-1):
        assert 0 < size <= 1024 * 1024
        return super().read(min(size, 3))


class S3:
    def __init__(self, prefix=PREFIX):
        self.prefix = prefix
        self.files = dict(FILES)
        self.listed = list(reversed(FILES))
        self.metadata = {'VersionId': 'v1'}
        self.bodies = []

    def get_paginator(self, name):
        assert name == 'list_objects_v2'
        return self

    def paginate(self, *, Bucket, Prefix):
        assert (Bucket, Prefix) == ('audit-fixture', self.prefix)
        for key in self.listed:
            yield {'Contents': [{'Key': self.prefix + key}]}

    def get_object(self, *, Bucket, Key):
        assert Bucket == 'audit-fixture' and Key.startswith(self.prefix)
        body = Body(self.files[Key[len(self.prefix):]])
        self.bodies.append(body)
        return {'Body': body, **(self.metadata if not Key.endswith('.empty') else {'VersionId': 'v2'})}


def test_private_evidence(tmp_path):
    s3 = S3()
    result = verifier.compare(s3, URI, RAW)
    assert all(body.closed for body in s3.bodies)
    path = tmp_path / 'evidence'
    verifier.save(result, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_bytes()) == {
        'manifest_sha256': hashlib.sha256(RAW).hexdigest(),
        'workspace_uri_sha256': hashlib.sha256(URI.encode()).hexdigest(),
        'version_ids_in_manifest_order': ['v1', 'v2'],
    }
    with pytest.raises(FileExistsError):
        verifier.save({}, path)
    assert json.loads(path.read_bytes()) == result


def test_bucket_root_attempt():
    prefix = PREFIX[PREFIX.index('attempts/'):]
    result = verifier.compare(S3(prefix), 's3://audit-fixture/' + prefix, RAW)
    assert result['version_ids_in_manifest_order'] == ['v1', 'v2']


@pytest.mark.parametrize(('case', 'code'), [
    ('uri', 'invalid_uri'), ('manifest', 'invalid_manifest'),
    ('extra', 'unexpected_key'), ('duplicate', 'duplicate_key'), ('missing', 'missing_key'),
    ('version', 'missing_version'), ('short', 'short_object'), ('long', 'long_object'),
    ('digest', 'digest_mismatch'), ('sdk', 'verification_error'), ('save', 'verification_error'),
])
def test_cli_failure(case, code, tmp_path, monkeypatch, capsys):
    manifest = tmp_path / 'manifest'
    manifest.write_bytes(RAW)
    path = tmp_path / 'evidence'
    s3 = S3()
    uri = URI
    key = 'private/nested name'
    if case == 'uri':
        uri += '../private/'
    elif case == 'manifest':
        manifest.write_bytes(b'private malformed manifest')
    elif case == 'extra':
        s3.listed.append('private extra')
    elif case == 'duplicate':
        s3.listed.append(key)
    elif case == 'missing':
        s3.listed.remove(key)
    elif case == 'version':
        s3.metadata.clear()
    elif case in ('short', 'long', 'digest'):
        size = len(FILES[key]) + {'short': -1, 'long': 1, 'digest': 0}[case]
        s3.files[key] = b'x' * size
    elif case == 'sdk':
        class PrivateSDKError(Exception):
            pass
        s3.get_object = Mock(side_effect=PrivateSDKError(key))
    elif case == 'save':
        path.write_bytes(b'previous private evidence')
    monkeypatch.setitem(sys.modules, 'boto3', Mock(client=Mock(return_value=s3)))
    monkeypatch.setattr(sys, 'argv', ['verify', '--workspace-uri', uri, '--manifest', str(manifest),
                                     '--evidence', str(path)])
    assert verifier.main() == 1
    if case == 'save':
        assert path.read_bytes() == b'previous private evidence'
    else:
        assert not path.exists()
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == f'Workspace comparison unsuccessful ({code}).\n'


@pytest.mark.parametrize('listed', [[], [*FILES, 'extra'], [*FILES, '.empty']])
def test_exact_set(listed):
    s3 = S3()
    s3.listed = listed
    with pytest.raises(ValueError):
        verifier.compare(s3, URI, RAW)
    assert not s3.bodies


@pytest.mark.parametrize('data', [b'', b'changed bytes', b'too many private bytes'])
def test_get_mismatch(data):
    s3 = S3()
    s3.files['private/nested name'] = data
    with pytest.raises(ValueError):
        verifier.compare(s3, URI, RAW)
    assert s3.bodies[0].closed


@pytest.mark.parametrize('metadata', [{}, {'VersionId': 'null'}, {'VersionId': ' '}])
def test_requires_real_version(metadata):
    s3 = S3()
    s3.metadata = metadata
    with pytest.raises(ValueError):
        verifier.compare(s3, URI, RAW)
    assert s3.bodies[0].closed


@pytest.mark.parametrize('uri', [URI[:-1], URI + '../', URI.replace('/date/', '/../'),
                                 URI.split('attempts/')[0], URI.replace('12345678-', '*-')])
def test_unsafe_prefix_before_list(uri):
    with pytest.raises(ValueError):
        verifier.compare(None, uri, RAW)


@pytest.mark.parametrize('raw', [b'{}', b'[', b'[{}]', b'[{"key":"x","key":"y"}]',
                                 json.dumps([entry('x', b'')] * 2).encode()])
def test_invalid_manifest(raw):
    with pytest.raises(ValueError):
        verifier.compare(None, URI, raw)


@pytest.mark.parametrize('bad', [{'length': True}, {'length': -1}, {'sha256': 'etag'},
                                 {'key': '/abs'}, {'key': 'x/../y'}, {'key': '.kube/config'}])
def test_invalid_entry(bad):
    with pytest.raises(ValueError):
        verifier.compare(None, URI, json.dumps([{**entry('x', b''), **bad}]).encode())
