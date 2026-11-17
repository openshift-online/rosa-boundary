"""Offline contracts for credential-free provider configuration."""
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    'agent_defaults', Path(__file__).resolve().parents[1]
    / 'utils/rosa-boundary-agent-defaults.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    for key in ('PI_CODING_AGENT_DIR', 'XDG_CONFIG_HOME', 'CODEX_HOME',
                'BOUNDARY_AI_USE_BEDROCK', 'CLAUDE_CODE_USE_BEDROCK',
                'AWS_REGION', 'AWS_DEFAULT_REGION', 'BOUNDARY_CODEX_BEDROCK_MODEL'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('ANTHROPIC_MODEL', 'us.anthropic.approved-model')
    return tmp_path


def test_defaults_use_deployment_model_and_native_aws_auth(home, monkeypatch):
    monkeypatch.setenv('AWS_REGION', 'eu-west-1')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'must-not-persist')
    helper.main()
    assert json.loads((home / '.pi/agent/settings.json').read_text()) == {
        'defaultProvider': 'amazon-bedrock',
        'defaultModel': 'us.anthropic.approved-model'}
    config = json.loads((home / '.config/opencode/opencode.json').read_text())
    assert config['model'] == 'amazon-bedrock/us.anthropic.approved-model'
    assert config['providers']['amazon-bedrock']['settings'] == {'region': 'eu-west-1'}
    codex = (home / '.codex/config.toml').read_text()
    assert 'model_provider = "amazon-bedrock-runtime"' in codex
    assert '[model_providers.amazon-bedrock-runtime.aws]' in codex
    assert 'region = "eu-west-1"' in codex
    assert '\nmodel = ' not in codex  # Never pass a Claude model to Responses.
    for path in home.rglob('*'):
        if path.is_file():
            assert 'must-not-persist' not in path.read_text()
            assert path.stat().st_mode & 0o777 == 0o600


def test_explicit_codex_model_is_separate(home, monkeypatch):
    monkeypatch.setenv('BOUNDARY_CODEX_BEDROCK_MODEL', 'us.openai.approved-model')
    helper.main()
    assert 'model = "us.openai.approved-model"' in (home / '.codex/config.toml').read_text()


@pytest.mark.parametrize('switch', ['BOUNDARY_AI_USE_BEDROCK', 'CLAUDE_CODE_USE_BEDROCK'])
def test_opt_out_writes_nothing(home, monkeypatch, switch):
    monkeypatch.setenv(switch, '0')
    helper.main()
    assert not list(home.iterdir())


def test_explicit_enable_overrides_claude_switch(home, monkeypatch):
    monkeypatch.setenv('CLAUDE_CODE_USE_BEDROCK', '0')
    monkeypatch.setenv('BOUNDARY_AI_USE_BEDROCK', '1')
    helper.main()
    assert (home / '.pi/agent/settings.json').exists()


def test_existing_config_including_jsonc_is_never_overwritten(home, monkeypatch):
    paths = [home / '.pi/agent/settings.json',
             home / '.config/opencode/opencode.jsonc', home / '.codex/config.toml']
    for path in paths:
        path.parent.mkdir(parents=True)
        path.write_text('user-owned configuration\n')
    helper.main()
    for path in paths:
        assert path.read_text() == 'user-owned configuration\n'
    assert not (home / '.config/opencode/opencode.json').exists()


def test_repeated_initialization_preserves_user_changes(home):
    helper.main()
    config = home / '.pi/agent/settings.json'
    config.write_text('{"defaultProvider": "user-choice"}')
    helper.main()
    assert json.loads(config.read_text()) == {'defaultProvider': 'user-choice'}
    assert not list(home.rglob('tmp*'))


def test_missing_claude_model_does_not_invent_one(home, monkeypatch, capsys):
    monkeypatch.delenv('ANTHROPIC_MODEL')
    helper.main()
    assert not (home / '.pi').exists()
    assert not (home / '.config/opencode').exists()
    assert (home / '.codex/config.toml').exists()
    assert 'ANTHROPIC_MODEL is unset' in capsys.readouterr().err


def test_standard_config_locations_and_region_fallback(home, monkeypatch):
    monkeypatch.setenv('PI_CODING_AGENT_DIR', str(home / 'pi-custom'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / 'config-custom'))
    monkeypatch.setenv('CODEX_HOME', str(home / 'codex-custom'))
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'ap-southeast-2')
    helper.main()
    assert (home / 'pi-custom/settings.json').exists()
    config = json.loads((home / 'config-custom/opencode/opencode.json').read_text())
    assert config['providers']['amazon-bedrock']['settings']['region'] == 'ap-southeast-2'
    assert 'region = "ap-southeast-2"' in (home / 'codex-custom/config.toml').read_text()
