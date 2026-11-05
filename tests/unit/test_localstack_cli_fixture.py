"""The CLI integration identity must never reuse contributor credentials/cache."""

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/localstack"))


def test_cli_binary_build_is_tagged_and_temporary(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("cli_binary_fixtures", ROOT / "tests/localstack/conftest.py")
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    which = Mock(return_value='/test/bin/go')
    run = Mock()
    monkeypatch.setattr('shutil.which', which)
    monkeypatch.setattr('subprocess.run', run)
    factory = Mock()
    factory.mktemp.return_value = tmp_path
    binary = fixtures.localstack_cli_binary.__wrapped__(factory)
    which.assert_called_once_with('go')
    assert binary == tmp_path / 'rosa-boundary'
    run.assert_called_once_with(
        ['/test/bin/go', 'build', '-tags', 'localstack', '-o', str(binary), './cmd/rosa-boundary'],
        cwd=ROOT, check=True,
    )


def test_cli_identity_is_private_synthetic_and_region_consistent(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("cli_integration_fixtures", ROOT / "tests/localstack/conftest.py")
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'personal-credential-sentinel')
    monkeypatch.setenv('ROSA_BOUNDARY_SRE_ROLE_ARN', 'personal-role-sentinel')
    monkeypatch.setenv('KEYCLOAK_URL', 'https://personal.invalid')
    iam = Mock()
    iam.create_role.return_value = {'Role': {'Arn': 'arn:aws:iam::000000000000:role/test-cli'}}
    cleanup = Mock()
    env = fixtures.localstack_cli_env.__wrapped__(tmp_path, iam, SimpleNamespace(region_name='us-east-2'), cleanup)
    assert env['AWS_SECRET_ACCESS_KEY'] == 'test'
    assert env['ROSA_BOUNDARY_SRE_ROLE_ARN'] == iam.create_role.return_value['Role']['Arn']
    assert env['ROSA_BOUNDARY_AWS_REGION'] == env['AWS_DEFAULT_REGION'] == 'us-east-2'
    assert env['LOCALSTACK_ENDPOINT'] == fixtures.LOCALSTACK_ENDPOINT
    assert 'KEYCLOAK_URL' not in env
    assert env['ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE'] == 'true'
    assert Path(env['XDG_CONFIG_HOME']).is_relative_to(tmp_path)
    cache = Path(env['XDG_CACHE_HOME']) / 'rosa-boundary/token-cache'
    assert cache.is_relative_to(tmp_path)
    assert cache.stat().st_mode & 0o777 == 0o600
    entry = json.loads(cache.read_text())
    assert entry['issuer'] == env['ROSA_BOUNDARY_KEYCLOAK_URL'] + '/realms/' + env['ROSA_BOUNDARY_KEYCLOAK_REALM']
    assert entry['client_id'] == env['ROSA_BOUNDARY_OIDC_CLIENT_ID']
    cleanup.register_role.assert_called_once()
