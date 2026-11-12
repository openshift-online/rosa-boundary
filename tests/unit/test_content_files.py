"""Offline regressions for S3 Files test assertions; not managed-mount evidence."""

import importlib.util
from pathlib import Path
import subprocess
import threading

from botocore.exceptions import ClientError
import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'localstack/integration/test_content_files.py'


@pytest.fixture(scope='module')
def content_files(pytestconfig):
    # This unit-suite configuration does not load LocalStack's pytest.ini.
    pytestconfig.addinivalue_line('markers', 'integration: LocalStack integration')
    pytestconfig.addinivalue_line('markers', 'slow: runtime integration')
    spec = importlib.util.spec_from_file_location('content_files_tests', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('code,expected', [
    ('NotImplemented', True), ('NotImplementedException', True),
    ('UnknownServiceException', True), ('AccessDeniedException', False),
    ('InternalFailure', False), ('ValidationException', False),
])
def test_capability_skip_is_narrow(content_files, code, expected):
    error = ClientError({'Error': {'Code': code}}, 'ListFileSystems')
    assert content_files.unsupported_service(error) is expected


def test_http_not_implemented_is_a_capability_skip(content_files):
    error = ClientError({'Error': {'Code': 'InternalFailure'},
                         'ResponseMetadata': {'HTTPStatusCode': 501}}, 'ListFileSystems')
    assert content_files.unsupported_service(error)


def test_missing_files_cannot_produce_success_marker(content_files, tmp_path):
    script = content_files.CONSUMER.replace('/opt/rosa-content', str(tmp_path))
    script = script.replace('seq 1 180', 'seq 1 2').replace('sleep 1', 'sleep 0.01')
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 41
    assert 'CONTENT:' not in result.stdout


def test_writable_mount_cannot_produce_readonly_marker(content_files, tmp_path):
    for prefix in content_files.PREFIXES:
        file = tmp_path / prefix / 'nested/content.txt'
        file.parent.mkdir(parents=True)
        file.write_text(f'initial-{prefix}')
        (tmp_path / prefix / 'sentinel.txt').write_text(f'stable-{prefix}')
    script = content_files.CONSUMER.replace('/opt/rosa-content', str(tmp_path))
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 42
    assert 'CONTENT:initial' in result.stdout
    assert 'CONTENT:readonly' not in result.stdout


def test_consumer_requires_all_prefixes_and_update_delete_phases(content_files, tmp_path):
    files = []
    for prefix in content_files.PREFIXES:
        file = tmp_path / prefix / 'nested/content.txt'
        file.parent.mkdir(parents=True)
        file.write_text(f'initial-{prefix}')
        (tmp_path / prefix / 'sentinel.txt').write_text(f'stable-{prefix}')
        files.append(file)
    # Fake only write denial to exercise the consumer protocol offline. The
    # integration test uses real mount readOnly enforcement, with no override.
    script = content_files.CONSUMER.replace('/opt/rosa-content', str(tmp_path))
    script = 'touch() { return 1; };\n' + script
    process = subprocess.Popen(['sh', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    timer = threading.Timer(10, process.kill)
    timer.start()
    try:
        assert process.stdout.readline().strip() == 'CONTENT:initial'
        assert process.stdout.readline().strip() == 'CONTENT:readonly'
        for file in files:
            file.write_text(f'updated-{file.parent.parent.name}')
        assert process.stdout.readline().strip() == 'CONTENT:updated'
        for file in files:
            file.unlink()
        assert process.stdout.readline().strip() == 'CONTENT:deleted'
        assert process.stdout.readline().strip() == 'CONTENT:complete'
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
        timer.cancel()


@pytest.mark.parametrize('failure', ['duplicated-mount', 'lost-mount'])
def test_wrong_or_missing_mount_cannot_pass(content_files, tmp_path, failure):
    for index, prefix in enumerate(content_files.PREFIXES):
        if failure == 'lost-mount' and index == 0:
            continue
        directory = tmp_path / prefix / 'nested'
        directory.mkdir(parents=True)
        identity = content_files.PREFIXES[0] if failure == 'duplicated-mount' else prefix
        (directory.parent / 'sentinel.txt').write_text(f'stable-{identity}')
        if failure == 'duplicated-mount':
            (directory / 'content.txt').write_text(f'initial-{identity}')
    script = content_files.CONSUMER.replace('/opt/rosa-content', str(tmp_path))
    script = script.replace('seq 1 180', 'seq 1 2').replace('sleep 1', 'sleep 0.01')
    if failure == 'lost-mount':
        script = script.replace('wait_phase initial', 'wait_phase deleted')
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 41
    assert 'CONTENT:' not in result.stdout


@pytest.mark.parametrize('kind', ['filesystem', 'mount_target'])
@pytest.mark.parametrize('terminal', ['deleted', 'not-found'])
def test_cleanup_accepts_both_terminal_states(content_files, kind, terminal):
    from unittest.mock import Mock

    client = Mock()
    method = client.get_file_system if kind == 'filesystem' else client.get_mount_target
    if terminal == 'deleted':
        method.return_value = {'status': 'deleted'}
    else:
        method.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException'}}, 'GetResource')
    cleanup = content_files.delete_filesystem if kind == 'filesystem' else content_files.delete_mount_target
    cleanup(client, 'test-owned-id')
    method.assert_called_once()
