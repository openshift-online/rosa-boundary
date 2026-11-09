"""Opt-in real Claude/APPA hook check with a loopback-only model fixture.

Set APPA_BIN and CLAUDE_BIN to verified, pinned binaries. No provider account,
model invocation or cloud access is used. This is not a Fargate assertion.
"""
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    not (os.environ.get('APPA_BIN') and os.environ.get('CLAUDE_BIN')),
    reason='set APPA_BIN and CLAUDE_BIN for the real, account-free harness check')


def event_stream(message):
    """Encode the small subset of Anthropic SSE used by these fixed exchanges."""
    events = [('message_start', {'type': 'message_start', 'message': {
        **message, 'content': [], 'stop_reason': None}})]
    for index, block in enumerate(message['content']):
        text = block['type'] == 'text'
        initial = {'type': 'text', 'text': ''} if text else {**block, 'input': {}}
        delta = {'type': 'text_delta', 'text': block['text']} if text else {
            'type': 'input_json_delta', 'partial_json': json.dumps(block['input'])}
        events.extend([
            ('content_block_start', {'type': 'content_block_start', 'index': index, 'content_block': initial}),
            ('content_block_delta', {'type': 'content_block_delta', 'index': index, 'delta': delta}),
            ('content_block_stop', {'type': 'content_block_stop', 'index': index}),
        ])
    events.extend([
        ('message_delta', {'type': 'message_delta', 'delta': {
            'stop_reason': message['stop_reason'], 'stop_sequence': None}, 'usage': {'output_tokens': 1}}),
        ('message_stop', {'type': 'message_stop'}),
    ])
    return ''.join(f'event: {name}\ndata: {json.dumps(value)}\n\n' for name, value in events).encode()


class Fixture(ThreadingHTTPServer):
    """A model fixture and deny-all proxy: unexpected outbound requests cannot pass."""
    def __init__(self, calls):
        super().__init__(('127.0.0.1', 0), Handler)
        self.calls = calls
        self.requests = []
        self.outbound = []
        self.results = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f'http://127.0.0.1:{self.server_port}'

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        self.server.outbound.append(self.path)
        self.send_error(403)

    def do_GET(self):
        self.server.outbound.append(self.path)
        self.send_error(403)

    def do_POST(self):
        size = int(self.headers.get('Content-Length', '-1'))
        if self.path.split('?')[0] != '/v1/messages' or not 0 <= size <= 4 * 1024 * 1024:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(size))
        self.server.requests.append(request)
        results = [block for message in request.get('messages', [])
                   if isinstance(message.get('content'), list) for block in message['content']
                   if block.get('type') == 'tool_result']
        self.server.results = results
        if len(results) < len(self.server.calls):
            tool, arguments = self.server.calls[len(results)]
            names = [t.get('name') for t in request.get('tools', [])]
            if tool not in names:
                self.send_error(400, 'fixture tool missing')
                return
            content = [{'type': 'tool_use', 'id': f'toolu_boundary_{len(results)}',
                        'name': tool, 'input': arguments}]
            reason = 'tool_use'
        else:
            content = [{'type': 'text', 'text': 'fixture complete'}]
            reason = 'end_turn'
        message = {'id': 'msg_boundary', 'type': 'message', 'role': 'assistant',
                   'model': request.get('model', 'fixture'), 'content': content,
                   'stop_reason': reason, 'stop_sequence': None,
                   'usage': {'input_tokens': 1, 'output_tokens': 1}}
        body = event_stream(message) if request.get('stream') else json.dumps(message).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream' if request.get('stream') else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize('sink', ['WebFetch', 'WebSearch', 'Write'])
def test_pinned_harness_applies_restricted_policy(tmp_path, sink):
    spec = importlib.util.spec_from_file_location('openappa_build', ROOT / 'build/openappa.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    appa = str(Path(os.environ['APPA_BIN']).resolve())
    claude = str(Path(os.environ['CLAUDE_BIN']).resolve())
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    (config_dir / 'appa.toml').write_bytes((ROOT / 'config/openappa/appa.toml').read_bytes())
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    settings = config_dir / 'claude-settings.json'
    settings.write_text(json.dumps(helper.hook_settings(appa, str(config_dir), str(state), url)))
    (config_dir / 'mcp.json').write_text('{"mcpServers":{}}')
    (tmp_path / 'evidence.txt').write_text('synthetic-boundary-canary')
    arguments = {'file_path': str(tmp_path / 'notes.txt'), 'content': 'local notes'} if sink == 'Write' else (
        {'url': 'https://example.com/?evidence=synthetic-boundary-canary', 'prompt': 'read page'}
        if sink == 'WebFetch' else {'query': 'synthetic-boundary-canary'})
    fixture = Fixture([('Read', {'file_path': str(tmp_path / 'evidence.txt')}), (sink, arguments)])
    # No inherited real credentials, plugins, provider settings or model endpoints.
    env = {'PATH': os.environ['PATH'],
           'HOME': str(tmp_path), 'TMPDIR': str(tmp_path),
           'APPA_CONFIG_DIR': str(config_dir), 'APPA_DATA_DIR': str(state), 'APPA_RUNTIME_URL': url,
           'APPA_GATE': '1',
           'ANTHROPIC_BASE_URL': fixture.url, 'ANTHROPIC_API_KEY': 'fixture-only',
           'ANTHROPIC_MODEL': 'sonnet',
           'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1',
           'OTEL_SDK_DISABLED': 'true', 'HTTP_PROXY': fixture.url, 'HTTPS_PROXY': fixture.url,
           'NO_PROXY': '127.0.0.1,localhost'}
    runtime = subprocess.Popen([appa, 'runtime', '--listen', f'127.0.0.1:{port}',
        '--config', str(config_dir / 'appa.toml'), '--db', str(state / 'appa.db')],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(url + '/health', timeout=1) as response:
                    if response.read() == b'ok':
                        break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail('fixture runtime did not become healthy')
        loader = importlib.machinery.SourceFileLoader('boundary_launcher', str(ROOT / 'utils/boundary-claude'))
        launch_spec = importlib.util.spec_from_loader(loader.name, loader)
        launcher = importlib.util.module_from_spec(launch_spec)
        loader.exec_module(launcher)
        launcher.APPA, launcher.CLAUDE = Path(appa), Path(claude)
        launcher.CONFIG, launcher.STATE = config_dir, state
        with patch.object(launcher, 'launch_environment', return_value=env), \
             patch.object(launcher.os, 'geteuid', side_effect=[1000, state.stat().st_uid]), \
             patch.object(launcher.os, 'execve') as execute:
            launcher.main(['--print', 'Execute the fixture investigation tools.'])
        command = execute.call_args.args[1]
        # Grant just the fixture tools natively to prove APPA still denies the
        # sinks. Production never adds these grants or bypassPermissions.
        end = command.index('--')
        command[end:end] = ['--allowedTools=Read,Write,WebFetch,WebSearch', '--no-session-persistence']
        result = subprocess.run(command,
            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        assert len(fixture.results) == 2, result.stdout + result.stderr
        assert 'synthetic-boundary-canary' in json.dumps(fixture.results[0])
        last = fixture.results[-1]
        if sink == 'Write':
            assert (tmp_path / 'notes.txt').read_text() == 'local notes'
        else:
            assert last.get('is_error') is True
            assert 'audience' in json.dumps(last).lower(), last
            assert not fixture.outbound
    finally:
        runtime.terminate()
        runtime.wait(timeout=10)
        fixture.close()
