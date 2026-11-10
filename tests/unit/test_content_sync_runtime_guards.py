"""Offline regressions for the runtime harness's fail-closed endpoint guard."""

import importlib.util
from pathlib import Path
import warnings

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'localstack/integration/test_content_sync_runtime.py'
SPEC = importlib.util.spec_from_file_location('content_sync_runtime', SOURCE)
runtime = importlib.util.module_from_spec(SPEC)
# LocalStack's pytest.ini registers these marks; offline unit collection does not.
with warnings.catch_warnings():
    warnings.simplefilter('ignore', pytest.PytestUnknownMarkWarning)
    SPEC.loader.exec_module(runtime)


@pytest.mark.parametrize('endpoint', [
    'http://localhost:4566', 'http://127.0.0.1:4566', 'http://[::1]:4566',
    'http://localstack:4566', 'http://172.18.0.2:4566',
])
def test_accepts_explicit_local_endpoint(endpoint):
    assert runtime.local_endpoint(endpoint) == endpoint


@pytest.mark.parametrize('endpoint', [
    'https://s3.amazonaws.com', 'http://s3.amazonaws.com:4566',
    'http://8.8.8.8:4566', 'http://169.254.169.254:4566',
    'http://0.0.0.0:4566', 'http://localhost:443', 'https://localhost:4566',
    'http://test:secret@localhost:4566', 'http://localhost:4566/path',
    'http://localhost:4566?redirect=aws', 'http://localhost:4566#fragment',
    'http://untrusted.example:4566',
])
def test_rejects_nonlocal_or_ambiguous_endpoint(endpoint):
    with pytest.raises(ValueError):
        runtime.local_endpoint(endpoint)


def test_runtime_environment_uses_only_dummy_credentials(monkeypatch):
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'personal-token-must-not-propagate')
    monkeypatch.setenv('AWS_PROFILE', 'personal-profile')
    env = runtime.runtime_env('fixture-bucket', 'http://localhost:4566', 'us-east-2')
    assert env['AWS_ACCESS_KEY_ID'] == env['AWS_SECRET_ACCESS_KEY'] == 'test'
    assert 'AWS_SESSION_TOKEN' not in env
    assert 'AWS_PROFILE' not in env
    assert env['AWS_SHARED_CREDENTIALS_FILE'] == env['AWS_CONFIG_FILE'] == '/dev/null'
    assert env['AWS_EC2_METADATA_DISABLED'] == 'true'
