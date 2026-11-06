"""Exercise real urllib redirect handling with only the HTTPS transport mocked."""
from email.message import Message
import io
import subprocess
import urllib.error
import urllib.request
import urllib.response
from unittest.mock import Mock

import pytest
import sre_tools as s

SOURCE = 'https://mirror.openshift.com/pinned/sha256sum.txt.gpg'
CDN = 'https://cdn.example.test/pinned/sha256sum.txt.gpg'


@pytest.fixture
def transport(monkeypatch):
    routes = {}
    requests = []

    def open_https(handler, request):
        requests.append(request)
        status, location, body = routes[request.full_url]
        headers = Message()
        if location is not None:
            headers['Location'] = location
        response = urllib.response.addinfourl(io.BytesIO(body), headers, request.full_url, status)
        response.msg = 'test response'
        return response

    def unexpected_http(*args):
        raise AssertionError('HTTP transport must never be used')

    monkeypatch.setattr(urllib.request, 'getproxies', lambda: {})
    monkeypatch.setattr(urllib.request.HTTPSHandler, 'https_open', open_https)
    monkeypatch.setattr(urllib.request.HTTPHandler, 'http_open', unexpected_http)
    return routes, requests


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('location,target', [
    (CDN, CDN),
    ('/relocated/signature', 'https://mirror.openshift.com/relocated/signature'),
    ('//cdn.example.test/pinned/sha256sum.txt.gpg', CDN),
])
def test_download_follows_redirects(tmp_path, transport, monkeypatch, status, location, target):
    routes, requests = transport
    monkeypatch.setenv('GITHUB_TOKEN', 'must-not-be-sent')
    routes[SOURCE] = (status, location, b'not the artifact')
    routes[target] = (200, None, b'verifiable artifact bytes')
    destination = tmp_path / 'signature'
    s.download(SOURCE, destination)
    assert destination.read_bytes() == b'verifiable artifact bytes'
    assert [r.full_url for r in requests] == [SOURCE, target]
    assert all(not r.has_header('Authorization') for r in requests)


@pytest.mark.parametrize('location', [
    'http://cdn.example.test/signature',
    'https://user:password@cdn.example.test/signature',
])
def test_unsafe_redirect_not_followed(tmp_path, transport, location):
    routes, requests = transport
    routes[SOURCE] = (302, location, b'')
    with pytest.raises(ValueError, match='requires HTTPS'):
        s.download(SOURCE, tmp_path / 'signature')
    assert len(requests) == 1
    assert not (tmp_path / 'signature').exists()


@pytest.mark.parametrize('loop', [True, False])
def test_redirect_limits(tmp_path, transport, loop):
    routes, requests = transport
    for i in range(20):
        routes[f'https://cdn.example.test/{i}'] = (
            302, f'https://cdn.example.test/{0 if loop else i + 1}', b'')
    with pytest.raises(urllib.error.HTTPError):
        s.download('https://cdn.example.test/0', tmp_path / 'signature')
    assert len(requests) < 20
    assert not (tmp_path / 'signature').exists()


@pytest.mark.parametrize('failure', ['signature', 'checksum'])
def test_redirect_does_not_bypass_oc_integrity(tmp_path, transport, monkeypatch, failure):
    routes, _ = transport
    root = 'https://mirror.openshift.com/pub/openshift-v4/amd64/clients/ocp/4.8.7/'
    archive = 'openshift-client-linux-4.8.7.tar.gz'
    for name in ('sha256sum.txt.gpg', archive):
        target = 'https://cdn.example.test/' + name
        routes[root + name] = (302, target, b'')
        routes[target] = (200, None, b'invalid artifact')

    def verify(tool, data, signature, keys, output=None):
        assert data.read_bytes() == b'invalid artifact'
        if failure == 'signature':
            raise subprocess.CalledProcessError(1, 'gpg')
        output.write_text('a' * 64 + '  ' + archive + '\n')

    monkeypatch.setattr(s, 'verify_signature', verify)
    extract = Mock()
    monkeypatch.setattr(s, 'extract_binary', extract)
    error = subprocess.CalledProcessError if failure == 'signature' else ValueError
    with pytest.raises(error):
        s.install('oc', '4.8.7', 'amd64', tmp_path / 'out', tmp_path / 'keys')
    extract.assert_not_called()
    assert not (tmp_path / 'out/inventory').exists()
