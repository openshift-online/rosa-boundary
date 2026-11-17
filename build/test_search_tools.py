"""Pinned search dependencies and downloader integrity regression tests."""
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import github_dl as dl
import verify_sre_tools as verify

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('corrupt', [False, True])
def test_explicit_published_sha256_is_enforced(tmp_path, monkeypatch, corrupt):
    payload = b'verified release archive'
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('REQUIRE_GITHUB_TOKEN', 'false')
    monkeypatch.setattr(sys, 'argv', ['github_dl', 'download', '--url',
        'https://api.github.com/repos/sharkdp/fd/releases/tags/v1.2.3',
        '--sha256', digest, '--exact_asset', 'fd.tar.gz'])
    monkeypatch.setattr(dl, 'resolve_token', lambda: None)
    monkeypatch.setattr(dl, 'list_assets', lambda *args: [{}])
    def download(assets, checksum, token):
        assert checksum == f'{digest}  fd.tar.gz'
        return b'corrupt' if corrupt else payload
    monkeypatch.setattr(dl, 'get_binary', download)
    if corrupt:
        with pytest.raises(SystemExit):
            dl.main()
        assert not (tmp_path / 'fd.tar.gz').exists()
    else:
        dl.main()
        assert (tmp_path / 'fd.tar.gz').read_bytes() == payload


@pytest.mark.parametrize('options', [
    ['--sha256', 'bad', '--exact_asset', 'fd.tar.gz'],
    ['--sha256', 'a' * 64, '--platform', 'linux'],
    ['--sha256', 'a' * 64, '--exact_asset', '../fd.tar.gz'],
    ['--sha256', 'a' * 64, '--checksum_file', 'SHA256SUMS', '--exact_asset', 'fd.tar.gz'],
])
def test_invalid_integrity_options_fail_before_authentication(monkeypatch, options):
    monkeypatch.setattr(sys, 'argv', ['github_dl', 'download', '--url', 'https://api.github.com/release', *options])
    def unexpected():
        pytest.fail('authentication must not run for invalid arguments')
    monkeypatch.setattr(dl, 'resolve_token', unexpected)
    with pytest.raises(SystemExit) as error:
        dl.main()
    assert error.value.code == 2


@pytest.mark.parametrize('stdout,valid', [
    ('ripgrep 15.2.0\nPCRE2 10.45 is available\n', True),
    ('ripgrep 15.2.0 (rev e89fff89ac)\n', True),
    ('ripgrep 15.2.0-beta\n', False),
    ('ripgrep 15.1.0\n', False), ('', False),
])
def test_offline_search_version_acceptance(tmp_path, monkeypatch, stdout, valid):
    (tmp_path / 'rg').write_bytes(b'binary')
    monkeypatch.setattr(verify, 'Path', lambda _: tmp_path)
    monkeypatch.setattr(verify, 'elf_arch', lambda *args: None)
    monkeypatch.setattr(verify.subprocess, 'run', lambda *a, **kw:
                        subprocess.CompletedProcess(a, 0, stdout=stdout))
    if valid:
        verify.accept_search_tools({'rg': '15.2.0'}, 'amd64')
    else:
        with pytest.raises(ValueError):
            verify.accept_search_tools({'rg': '15.2.0'}, 'amd64')


@pytest.mark.parametrize('stdout,valid', [('12345 python3 verify.py\n', True), ('', False), ('9 wrong-process\n', False)])
def test_process_lookup_acceptance(monkeypatch, stdout, valid):
    monkeypatch.setattr(verify.os, 'getpid', lambda: 12345)
    def run(command, **kwargs):
        assert command == ['ps', '-p', '12345', '-o', 'pid=,args=']
        assert kwargs['check'] is True
        return subprocess.CompletedProcess(command, 0, stdout=stdout)
    monkeypatch.setattr(verify.subprocess, 'run', run)
    if valid:
        verify.accept_process_tools()
    else:
        with pytest.raises(ValueError):
            verify.accept_process_tools()


def test_missing_ps_fails_acceptance(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError('ps')
    monkeypatch.setattr(verify.subprocess, 'run', missing)
    with pytest.raises(FileNotFoundError):
        verify.accept_process_tools()


def test_search_tools_remain_outside_six_tool_inventory():
    source = (ROOT / 'Containerfile').read_text()
    pins = verify.declared_pins(source, 'ENV', verify.SEARCH_TOOLS, r'\d+\.\d+\.\d+')
    assert set(pins) == {'fd', 'rg'}
    assert len(verify.pins(ROOT / 'Containerfile')) == 6
    assert 'COPY --from=search-builder /opt/search/fd /opt/search/rg /usr/local/bin/' in source
    assert '--sha256 "${fd_sha}"' in source
    assert '--checksum_file "ripgrep-${RIPGREP_VERSION}-${arch}-unknown-linux-musl.tar.gz.sha256"' in source
    assert 'FD_SHA256_AMD64=' in source and 'FD_SHA256_ARM64=' in source
