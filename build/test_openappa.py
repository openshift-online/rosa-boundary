"""Offline packaging, policy and launch contracts; never use model/cloud accounts."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib
from unittest.mock import patch

import pytest

import openappa as appa

ROOT = Path(__file__).resolve().parents[1]


def launcher():
    loader = importlib.machinery.SourceFileLoader('boundary_claude', str(ROOT / 'utils/boundary-claude'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize('arch,prefix', [('amd64', 'x86_64'), ('arm64', 'aarch64')])
def test_exact_assets(arch, prefix):
    assert appa.asset_name('v0.40.1', arch) == f'appa-{prefix}-unknown-linux-gnu.tar.gz'


@pytest.mark.parametrize('version,arch', [('latest', 'amd64'), ('v1.2.3-rc1', 'arm64'),
    ('v1.2.3/escape', 'amd64'), ('v1.2.3', 'unknown')])
def test_invalid_download_selection(version, arch):
    with pytest.raises(ValueError):
        appa.asset_name(version, arch)


def test_verified_exact_download(tmp_path):
    from unittest.mock import MagicMock
    github = MagicMock()
    github.resolve_token.return_value = None
    github.get_checksum.return_value = 'a' * 64 + '  appa-x86_64-unknown-linux-gnu.tar.gz'
    github.get_binary.return_value = b'archive'
    github.validate_binary.return_value = True
    with patch.dict('sys.modules', {'github_dl': github}), patch('sre_tools.extract_binary') as extract:
        appa.download('v0.40.1', 'amd64', tmp_path / 'appa')
        assert github.get_checksum.call_args.kwargs['asset_name'] == 'appa-x86_64-unknown-linux-gnu.tar.gz'
        assert extract.call_args.args[1:] == ('appa', tmp_path / 'appa')


@pytest.mark.parametrize('checksum,valid', [('', True), ('a' * 64 + '  appa.tar.gz', False)])
def test_integrity_failure_never_extracts(tmp_path, checksum, valid):
    from unittest.mock import MagicMock
    github = MagicMock()
    github.resolve_token.return_value = None
    github.get_checksum.return_value = checksum
    github.get_binary.return_value = b'bad'
    github.validate_binary.return_value = valid
    with patch.dict('sys.modules', {'github_dl': github}), patch('sre_tools.extract_binary') as extract:
        with pytest.raises(ValueError):
            appa.download('v0.40.1', 'amd64', tmp_path / 'appa')
        extract.assert_not_called()


def test_policy_has_no_declassification_or_unknown_tool_fallback():
    config = tomllib.loads((ROOT / 'config/openappa/appa.toml').read_text())
    policy = config['policy']
    assert policy['deployment']['starting_label']['audience'] == ['internal']
    assert not any(key in policy for key in ('authority', 'sanitizer', 'annotator'))
    tools = {tool['name']: tool for tool in policy['tool']}
    assert '*' not in tools
    for tool in ('WebFetch', 'WebSearch'):
        assert tools[f'host/claude-code/{tool}']['requires']['audience']['contains'] == ['public']
    # Bash is internal with no egress carve-outs: egress is a network-layer control,
    # not a command-string glob that would be bypassable and block internal curl.
    assert tools['host/claude-code/Bash']['delta']['audience'] == ['internal']
    assert 'requires' not in tools['host/claude-code/Bash']
    assert not any(name.startswith('host/claude-code/Bash(') for name in tools)
    assert config['reporting']['agent_yell'] is False
    assert json.loads((ROOT / 'config/openappa/mcp.json').read_text()) == {'mcpServers': {}}


def test_hook_lifecycle_and_deadlines():
    settings = appa.hook_settings()
    hooks = settings['hooks']
    assert set(hooks) == {'SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse',
        'PostToolUseFailure', 'PermissionDenied', 'SubagentStart', 'SubagentStop', 'Stop', 'StopFailure'}
    start = hooks['SessionStart'][0]['hooks'][0]
    assert start['command'] == '/usr/local/bin/appa'
    assert start['timeout'] == 160
    assert '--ensure-runtime' in start['args']
    assert '/home/sre' not in appa.STATE
    assert start['args'][-1] == appa.STATE
    for event in ('PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied'):
        assert hooks[event][0]['matcher'] == '*'
        assert hooks[event][0]['hooks'][0]['timeout'] == 130
    assert hooks['Stop'][0]['hooks'][0]['args'][-1] == '--turn-end'


def prepared_launcher(tmp_path):
    module = launcher()
    module.STATE = tmp_path / 'state'
    module.STATE.mkdir(mode=0o700)
    module.CONFIG = tmp_path / 'config'
    module.CONFIG.mkdir()
    for name in ('appa.toml', 'claude-settings.json', 'mcp.json'):
        (module.CONFIG / name).write_text('{}')
    return module


def test_launch_preserves_provider_but_not_policy_overrides(tmp_path):
    module = prepared_launcher(tmp_path)
    with patch.dict(os.environ, {'APPA_CONFIG_DIR': '/untrusted', 'APPA_GATE': '0',
        'APPA_DB': '/untrusted.db', 'APPA_RUNTIME_URL': 'https://external.invalid',
        'ANTHROPIC_MODEL': 'approved-profile', 'CLAUDE_CODE_USE_BEDROCK': '1',
        'BUN_OPTIONS': 'evil', 'CLAUDE_CODE_SIMPLE': '1'}):
        env = module.launch_environment()
    assert env['ANTHROPIC_MODEL'] == 'approved-profile'
    assert env['CLAUDE_CODE_USE_BEDROCK'] == '1'
    assert env['APPA_CONFIG_DIR'] == str(module.CONFIG)
    assert env['APPA_RUNTIME_URL'] == appa.RUNTIME_URL
    assert env['APPA_GATE'] == '1'
    assert not any(key in env for key in ('APPA_DB', 'BUN_OPTIONS', 'CLAUDE_CODE_SIMPLE'))
    assert env['OTEL_SDK_DISABLED'] == 'true'
    assert env['CLAUDE_CODE_DISABLE_AGENT_VIEW'] == '1'


def test_managed_launch_without_touching_persistent_settings(tmp_path):
    module = prepared_launcher(tmp_path)
    with patch.object(module.os, 'geteuid', side_effect=[1000, module.STATE.stat().st_uid]), \
         patch.object(module.subprocess, 'run') as run, patch.object(module.os, 'execve') as execute:
        module.main(['--print', 'inspect cluster'])
    run.assert_called_once()
    command = execute.call_args.args[1]
    assert command[:2] == [str(module.CLAUDE), '--settings']
    assert '--messaging-socket-path' not in command
    assert '--setting-sources=' in command
    assert '--strict-mcp-config' in command
    assert command[-2:] == ['--', 'inspect cluster']
    assert not any('bypassPermissions' in arg for arg in command)


@pytest.mark.parametrize('args', [['--resume', 'old'], ['--continue'], ['--settings', '{}'],
    ['--scope', 'public'], ['--mcp-config', '{}'], ['--dangerously-skip-permissions']])
def test_no_guardrail_override_arguments(tmp_path, args):
    module = prepared_launcher(tmp_path)
    with patch.object(module.os, 'execve') as execute, pytest.raises(SystemExit):
        module.main(args)
    execute.assert_not_called()


@pytest.mark.parametrize('failure', [FileNotFoundError('appa missing'),
    subprocess.TimeoutExpired('appa', 30), subprocess.CalledProcessError(1, 'appa')])
def test_preflight_failure_never_launches_plain_claude(tmp_path, failure):
    module = prepared_launcher(tmp_path)
    with patch.object(module.os, 'geteuid', side_effect=[1000, module.STATE.stat().st_uid]), \
         patch.object(module.subprocess, 'run', side_effect=failure), \
         patch.object(module.os, 'execve') as execute:
        assert module.main([]) == 1
    execute.assert_not_called()


def test_state_symlink_rejected(tmp_path):
    module = prepared_launcher(tmp_path)
    link = tmp_path / 'state-link'
    link.symlink_to(module.STATE, target_is_directory=True)
    module.STATE = link
    with patch.object(module.os, 'geteuid', return_value=1000), \
         patch.object(module.os, 'execve') as execute:
        assert module.main([]) == 1
    execute.assert_not_called()


def test_root_launch_rejected(tmp_path):
    module = prepared_launcher(tmp_path)
    with patch.object(module.os, 'geteuid', return_value=0), pytest.raises(SystemExit):
        module.main([])


@pytest.mark.skipif(not os.environ.get('APPA_BIN'), reason='set APPA_BIN to the pinned binary for real policy replay')
def test_actual_policy_replay(tmp_path):
    binary = str(Path(os.environ['APPA_BIN']).resolve())
    env = {'PATH': os.environ['PATH'], 'HOME': str(tmp_path), 'TMPDIR': str(tmp_path),
           'OTEL_SDK_DISABLED': 'true'}
    result = subprocess.run([binary, 'replay', '--config', str(ROOT / 'config/openappa/appa.toml'),
                             str(ROOT / 'tests/openappa/restricted.appa'), '--json'],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    steps = [json.loads(line) for line in result.stdout.splitlines()]
    assert steps[-1]['summary'] == {'ok': 1, 'failed': 0, 'cannot_run': 0}
    assert not any(step.get('offers') for step in steps)


@pytest.mark.skipif(not os.environ.get('APPA_BIN'), reason='set APPA_BIN for undeclared-tool refusal checks')
@pytest.mark.parametrize('tool', ['mcp/github/create_issue', 'host/claude-code/Agent'])
def test_actual_undeclared_tools_refused(tmp_path, tool):
    trace = tmp_path / 'undeclared.appa'
    trace.write_text(f'{tool} {{}}\nexpect deny\n')
    env = {'PATH': os.environ['PATH'], 'HOME': str(tmp_path), 'TMPDIR': str(tmp_path),
           'OTEL_SDK_DISABLED': 'true'}
    result = subprocess.run([os.environ['APPA_BIN'], 'replay', '--config',
        str(ROOT / 'config/openappa/appa.toml'), str(trace), '--json'],
        env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
    first = json.loads(result.stdout.splitlines()[0])
    assert first['outcome'] == 'cannot_run'
    assert 'refused before it runs' in first['detail']


def test_image_keeps_secrets_out_of_binary_execution():
    source = (ROOT / 'Containerfile').read_text()
    assert 'ARG OPENAPPA_VERSION="v0.40.1"' in source
    runs = source.replace('\\\n', ' ').split('RUN ')[1:]
    check = next(run for run in runs if '/opt/openappa/appa --version' in run)
    assert check.startswith('--network=none ')
    assert 'type=secret' not in check
    assert '/var/lib/rosa-boundary/openappa' in source
