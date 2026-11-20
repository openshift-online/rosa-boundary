"""Offline acceptance regressions for the freshly built in-tree rta CLI."""
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

import pytest

import verify_sre_tools as verify

SHA = 'a' * 40
ROOT = Path(__file__).resolve().parents[1]


def elf(machine=62, kinds=(1,)):
    """Small ELF64 fixture with a complete program header table."""
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, machine, 1, 0, 64,
                         0, 0, 64, 56, len(kinds), 0, 0, 0)
    return header + b''.join(struct.pack('<IIQQQQQQ', kind, 5, 0, 0, 0,
                                        64 + 56 * len(kinds), 64 + 56 * len(kinds), 4096)
                             for kind in kinds)


@pytest.fixture
def rta(tmp_path, monkeypatch):
    binary = tmp_path / 'rta'
    binary.write_bytes(elf())
    binary.chmod(0o755)
    monkeypatch.setattr(verify, 'RTA_PATH', binary)
    monkeypatch.setattr(verify, 'RTA_BUILD_PATHS', (tmp_path / 'absent',))
    monkeypatch.setattr(verify.shutil, 'which', lambda _: None)
    info = {'version': '0.0.1', 'platform': 'linux/amd64', 'commit': SHA,
            'build_date': '2026-11-19T12:00:00Z'}
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        assert kwargs['check'] is True
        assert kwargs['capture_output'] is True
        assert kwargs['text'] is True
        assert kwargs['stdin'] == subprocess.DEVNULL
        assert kwargs['timeout'] == 30
        env = kwargs['env']
        assert env['HOME'] == kwargs['cwd'] == env['XDG_CONFIG_HOME']
        assert Path(env['HOME']).is_dir()
        assert not list(Path(env['HOME']).iterdir())
        assert env['AWS_EC2_METADATA_DISABLED'] == 'true'
        assert env['HTTP_PROXY'] == env['HTTPS_PROXY'] == 'http://127.0.0.1:9'
        assert not {'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_PROFILE',
                    'RTA_TOKEN', 'KUBECONFIG', 'OCM_TOKEN'} & env.keys()
        assert command in ([str(binary), 'version', '-o', 'json'], [str(binary), '--help'])
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(info),
                                           stderr='not a source of version metadata')

    monkeypatch.setattr(verify.subprocess, 'run', run)
    return binary, info, calls


@pytest.mark.parametrize('commit', [SHA, SHA + '-dirty', 'unknown'])
@pytest.mark.parametrize('exact', [False, True])
def test_rta_valid_offline_metadata(rta, monkeypatch, commit, exact):
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'must-not-inherit')
    monkeypatch.setenv('RTA_TOKEN', 'must-not-inherit')
    _, info, calls = rta
    info['commit'] = commit
    verify.accept_rta(' \n0.0.1\n', 'amd64', commit if exact else None)
    assert [command[1:] for command, _ in calls] == [['version', '-o', 'json'], ['--help']]
    assert not Path(calls[0][1]['env']['HOME']).exists()


def test_rta_arm64_metadata_and_elf(rta):
    binary, info, _ = rta
    binary.write_bytes(elf(machine=183))
    info['platform'] = 'linux/arm64'
    verify.accept_rta('0.0.1', 'arm64', SHA)


@pytest.mark.parametrize('field,value,message', [
    ('version', '0.0.2', 'expected version'),
    ('version', 'v0.0.1', 'expected version'),
    ('version', None, 'expected version'),
    ('platform', 'linux/arm64', 'platform'),
    ('platform', 'darwin/amd64', 'platform'),
    ('platform', None, 'platform'),
    ('commit', '', 'invalid rta commit'),
    ('commit', 'a' * 39, 'invalid rta commit'),
    ('commit', 'A' * 40, 'invalid rta commit'),
    ('commit', SHA + '-other', 'invalid rta commit'),
    ('commit', None, 'invalid rta commit'),
    ('commit', 123, 'invalid rta commit'),
    ('build_date', '', 'build date'),
    ('build_date', ' \n', 'build date'),
    ('build_date', None, 'build date'),
    ('build_date', 123, 'build date'),
])
def test_rta_rejects_wrong_or_missing_metadata(rta, field, value, message):
    _, info, calls = rta
    if value is None:
        del info[field]
    else:
        info[field] = value
    with pytest.raises(ValueError, match=message):
        verify.accept_rta('0.0.1', 'amd64')
    assert len(calls) == 1


def test_rta_accepts_unknown_direct_build_date(rta):
    rta[1]['build_date'] = 'unknown'
    verify.accept_rta('0.0.1', 'amd64')


@pytest.mark.parametrize('expected', ['b' * 40, SHA + '-dirty', 'unknown', ''])
def test_rta_expected_commit_is_exact(rta, expected):
    with pytest.raises(ValueError, match='expected commit'):
        verify.accept_rta('0.0.1', 'amd64', expected)


@pytest.mark.parametrize('stdout', ['', '{', '[]', 'null', '"0.0.1"', '{}'])
def test_rta_rejects_malformed_version_json(rta, monkeypatch, stdout):
    monkeypatch.setattr(verify.subprocess, 'run', lambda *a, **kw:
                        subprocess.CompletedProcess(a, 0, stdout=stdout))
    with pytest.raises(ValueError):
        verify.accept_rta('0.0.1', 'amd64')


@pytest.mark.parametrize('command', ['version', '--help'])
@pytest.mark.parametrize('failure', [subprocess.CalledProcessError, subprocess.TimeoutExpired])
def test_rta_probe_failure_blocks_acceptance(rta, monkeypatch, command, failure):
    original = verify.subprocess.run

    def run(args, **kwargs):
        if args[1] == command:
            raise failure(args, 30) if failure is subprocess.TimeoutExpired else failure(1, args)
        return original(args, **kwargs)

    monkeypatch.setattr(verify.subprocess, 'run', run)
    with pytest.raises(failure):
        verify.accept_rta('0.0.1', 'amd64')


def test_rta_missing_binary_fails(rta):
    rta[0].unlink()
    with pytest.raises(FileNotFoundError):
        verify.accept_rta('0.0.1', 'amd64')
    assert not rta[2]


def test_rta_empty_source_version_fails(rta):
    with pytest.raises(ValueError, match='empty rta VERSION'):
        verify.accept_rta(' \n', 'amd64')
    assert not rta[2]


@pytest.mark.parametrize('mode', [0o4755, 0o2755, 0o775, 0o757, 0o777])
def test_rta_rejects_elevated_or_writable_mode(rta, mode):
    rta[0].chmod(mode)
    with pytest.raises(ValueError, match='elevated or writable'):
        verify.accept_rta('0.0.1', 'amd64')
    assert not rta[2]


def test_rta_rejects_wrong_elf_architecture(rta):
    rta[0].write_bytes(elf(machine=183))
    with pytest.raises(ValueError, match='wrong executable architecture'):
        verify.accept_rta('0.0.1', 'amd64')
    assert not rta[2]


@pytest.mark.parametrize('kind', [2, 3])
def test_rta_rejects_dynamic_elf(rta, kind):
    rta[0].write_bytes(elf(kinds=(1, kind)))
    with pytest.raises(ValueError, match='dynamic ELF'):
        verify.accept_rta('0.0.1', 'amd64')
    assert not rta[2]


@pytest.mark.parametrize('length', [0, 20, 63, 64, 100, 119])
def test_static_elf_rejects_truncation(tmp_path, length):
    binary = tmp_path / 'rta'
    binary.write_bytes(elf()[:length])
    with pytest.raises(ValueError):
        verify.static_elf(binary)


@pytest.mark.parametrize('offset,fmt,value', [
    (0, '4s', b'nope'), (4, 'B', 1), (5, 'B', 2), (6, 'B', 0),
    (20, 'I', 0), (32, 'Q', 63), (32, 'Q', 2**63),
    (52, 'H', 63), (54, 'H', 55), (56, 'H', 0), (56, 'H', 0xffff),
    (72, 'Q', 121), (96, 'Q', 121),
])
def test_static_elf_rejects_malformed_headers(tmp_path, offset, fmt, value):
    data = bytearray(elf())
    struct.pack_into('<' + fmt, data, offset, value)
    binary = tmp_path / 'rta'
    binary.write_bytes(data)
    with pytest.raises(ValueError):
        verify.static_elf(binary)


@pytest.mark.parametrize('path', ['/usr/local/go', '/go/pkg/mod', '/src/trusted-actions'])
def test_rta_rejects_known_build_material(rta, monkeypatch, tmp_path, path):
    forbidden = tmp_path / path.lstrip('/')
    forbidden.mkdir(parents=True)
    monkeypatch.setattr(verify, 'RTA_BUILD_PATHS', (forbidden,))
    with pytest.raises(ValueError, match='build material remains'):
        verify.accept_rta('0.0.1', 'amd64')
    assert not rta[2]


def test_rta_rejects_compiler_on_path(rta, monkeypatch):
    monkeypatch.setattr(verify.shutil, 'which', lambda tool: '/bin/go' if tool == 'go' else None)
    with pytest.raises(ValueError, match='Go compiler remains'):
        verify.accept_rta('0.0.1', 'amd64')
    assert not rta[2]


def test_runtime_requires_component_version_file(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['verify', 'runtime', '--containerfile', 'Containerfile'])
    with pytest.raises(SystemExit) as error:
        verify.main()
    assert error.value.code == 2


def test_runtime_cli_passes_source_version_and_expected_commit(tmp_path, monkeypatch):
    inventory = tmp_path / 'inventory.json'
    inventory.write_text('[]')
    source = tmp_path / 'Containerfile'
    source.write_text('')
    version = tmp_path / 'VERSION'
    version.write_text('0.0.1\n')
    monkeypatch.setattr(verify, 'pins', lambda _: {})
    monkeypatch.setattr(verify, 'agent_pins', lambda _: {})
    monkeypatch.setattr(verify, 'declared_pins', lambda *args: {})
    calls = []
    monkeypatch.setattr(verify, 'runtime', lambda *args: calls.append(args))
    monkeypatch.setattr(sys, 'argv', ['verify', 'runtime', '--inventory', str(inventory),
                        '--containerfile', str(source), '--rta-version-file', str(version),
                        '--rta-commit', SHA])
    verify.main()
    assert calls == [([], {}, {}, {}, '0.0.1', SHA)]


def test_rta_stays_outside_external_tool_contracts():
    assert 'rta' not in verify.TOOLS
    assert 'rta' not in verify.AGENTS
    assert 'rta' not in verify.ARGS
    assert verify.RTA_BUILD_PATHS == (Path('/usr/local/go'), Path('/go/pkg/mod'),
                                      Path('/src/trusted-actions'))


def test_rta_native_builder_ships_only_the_static_cli():
    source = (ROOT / 'Containerfile').read_text()
    stage = re.search(r'^FROM ([^\n]+) AS rta-builder\n(.*?)(?=^FROM )',
                      source, re.M | re.S)
    assert stage is not None
    assert re.fullmatch(r'registry\.access\.redhat\.com/hi/go:[\w.-]+@sha256:[a-f0-9]{64}',
                        stage[1])
    builder = stage[2]
    for required in ('GOTOOLCHAIN=local', 'CGO_ENABLED=0', '-mod=readonly',
                     '-trimpath', '-s -w', '-o /out/rta ./cmd/rta',
                     'go env GOARCH', '${TARGETARCH}', 'GOOS=linux',
                     'internal/rta.Version=${version}', 'internal/rta.Commit=${RTA_COMMIT}',
                     'internal/rta.BuildDate=${RTA_BUILD_DATE}'):
        assert required in builder
    assert 'go build' in builder and 'cmd/server' not in builder
    for required in ('go.mod', 'go.sum', 'cmd/rta/', 'internal/', 'VERSION'):
        assert 'components/trusted-actions/' + required in builder
    copies = re.findall(r'^COPY [^\n]*--from=rta-builder[^\n]*', source, re.M)
    assert len(copies) == 1
    assert copies[0].endswith(' /out/rta /usr/local/bin/rta')
    final = source.split(' AS final\n', 1)[1]
    assert 'org.opencontainers.image.revision="${RTA_COMMIT}"' in final
    assert '--rta-version-file /verify-src/components/trusted-actions/VERSION' in final
    assert '--rta-commit "${RTA_COMMIT}"' in final


@pytest.mark.parametrize('pipeline', ['pull-request', 'push'])
def test_boundary_pipeline_filters_include_rta_inputs(pipeline):
    source = (ROOT / f'.tekton/rosa-boundary-{pipeline}.yaml').read_text()
    patterns = [pattern.replace('\\\\', '\\')
                for pattern in re.findall(r"x\.matches\('([^']+)'\)", source)]
    assert patterns
    for path in ('cmd/rta/main.go', 'internal/rta/version.go', 'go.mod', 'go.sum', 'VERSION'):
        assert any(re.search(pattern, 'components/trusted-actions/' + path)
                   for pattern in patterns), path
