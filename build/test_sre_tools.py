"""Offline security and inventory contracts; no external binaries downloaded."""
import io
import json
from pathlib import Path
import stat
import tarfile
from unittest.mock import patch
import zipfile

import pytest
import sre_tools as s
import verify_sre_tools as v


def tarball(path, members):
    with tarfile.open(path, 'w:gz') as tar:
        for name, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = 1 if kind == tarfile.REGTYPE else 0
            tar.addfile(info, io.BytesIO(b'x') if info.size else None)


@pytest.mark.parametrize('name,kind', [('../oc', tarfile.REGTYPE), ('/oc', tarfile.REGTYPE),
    ('oc', tarfile.SYMTYPE), ('oc', tarfile.LNKTYPE), ('oc', tarfile.CHRTYPE)])
def test_tar_unsafe(tmp_path, name, kind):
    archive = tmp_path / 'a.tgz'
    tarball(archive, [(name, kind)])
    with pytest.raises(ValueError):
        s.extract_binary(archive, 'oc', tmp_path / 'oc')
    assert not (tmp_path / 'oc').exists()


@pytest.mark.parametrize('target', ['oc', '../oc', '/oc', 'other'])
def test_oc_kubectl_hardlink_is_never_extracted(tmp_path, target):
    archive = tmp_path / 'oc.tgz'
    with tarfile.open(archive, 'w:gz') as tar:
        executable = tarfile.TarInfo('oc')
        executable.size = 1
        tar.addfile(executable, io.BytesIO(b'x'))
        alias = tarfile.TarInfo('kubectl')
        alias.type = tarfile.LNKTYPE
        alias.linkname = target
        tar.addfile(alias)
    if target == 'oc':
        s.extract_binary(archive, 'oc', tmp_path / 'oc')
        assert (tmp_path / 'oc').read_bytes() == b'x'
        assert not (tmp_path / 'kubectl').exists()
    else:
        with pytest.raises(ValueError):
            s.extract_binary(archive, 'oc', tmp_path / 'oc')


def test_tar_exact(tmp_path):
    archive = tmp_path / 'a.tgz'
    tarball(archive, [('oc', tarfile.REGTYPE), ('kubectl', tarfile.REGTYPE)])
    s.extract_binary(archive, 'oc', tmp_path / 'oc')
    assert (tmp_path / 'oc').read_bytes() == b'x'
    assert not (tmp_path / 'kubectl').exists()
    tarball(archive, [('oc', tarfile.REGTYPE), ('oc', tarfile.REGTYPE)])
    with pytest.raises(ValueError):
        s.extract_binary(archive, 'oc', tmp_path / 'out')


@pytest.mark.parametrize('name,mode', [('../escape', stat.S_IFREG), ('/escape', stat.S_IFREG),
    ('aws/dist/link', stat.S_IFLNK), ('aws/dist/device', stat.S_IFCHR)])
def test_zip_unsafe(tmp_path, name, mode):
    archive = tmp_path / 'a.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        info = zipfile.ZipInfo(name)
        info.external_attr = (mode | 0o755) << 16
        z.writestr(info, b'x')
    with pytest.raises(ValueError):
        s.extract_aws(archive, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_zip_distribution_only(tmp_path):
    archive = tmp_path / 'a.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('aws/install', 'installer')
        z.writestr('aws/dist/LICENSE.txt', 'normal distribution file')
        info = zipfile.ZipInfo('aws/dist/aws')
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        z.writestr(info, b'executable')
    dest = tmp_path / 'dist'
    s.extract_aws(archive, dest)
    assert (dest / 'aws').stat().st_mode & 0o111
    assert not (dest / 'install').exists()
    assert (dest / 'LICENSE.txt').read_text() == 'normal distribution file'


@pytest.mark.parametrize('actual', ['1.2.2', '1.2.4', 'garbage'])
def test_exact_version(actual):
    with pytest.raises(ValueError):
        s.require_version('ocm', 'v1.2.3', actual)


@pytest.mark.parametrize('tool,pin', [('aws', '1.2.3'), ('yq', 'v5.0.0'), ('oc', '3.0.0'),
                                      ('ocm', 'latest'), ('ocm', 'v1.2.3;id')])
def test_bad_pins(tool, pin):
    with pytest.raises(ValueError):
        s.pin_version(tool, pin)


def test_checksum():
    line = 'a' * 64 + '  oc.tar.gz'
    assert s.checksum(line, 'oc.tar.gz') == 'a' * 64
    for text in [line + '\n' + line, line.replace('oc.tar.gz', '../oc.tar.gz'), 'xyz  oc.tar.gz']:
        with pytest.raises(ValueError):
            s.checksum(text, 'oc.tar.gz')


def fixtures():
    expected = {t: ('2.3.4' if t == 'aws' else '4.3.4' if t == 'oc' else 'v4.3.4') for t in s.TOOLS}
    entries = [dict(tool=t, expected_pin=p, actual_version=p.removeprefix('v'), architecture='amd64',
                    sha256='a' * 64, signature_identity=s.SIGNERS.get(t)) for t, p in expected.items()]
    return expected, entries


def test_inventory_cross_arch():
    expected, left = fixtures()
    right = [dict(e, architecture='arm64', sha256='b' * 64) for e in left]
    v.compare(left, right, expected)
    for field, value in [('actual_version', '9.0.0'), ('expected_pin', 'v9.0.0'), ('architecture', 'amd64')]:
        bad = [dict(e) for e in right]
        bad[0][field] = value
        with pytest.raises(ValueError):
            v.compare(left, bad, expected)
    with pytest.raises(ValueError):
        v.validate(left[:-1] + [left[0]], expected, 'amd64')


def test_pin_parser(tmp_path):
    expected, _ = fixtures()
    source = '\r\n'.join(f'ARG {v.ARGS[t]}="{p}"' for t, p in expected.items())
    path = tmp_path / 'Containerfile'
    path.write_text(source)
    assert v.pins(path) == expected
    path.write_text(source + '\nARG OCM_VERSION="v4.3.4"')
    with pytest.raises(ValueError):
        v.pins(path)


def test_signature_wrong_identity(tmp_path):
    class Result:
        stdout = '[GNUPG:] VALIDSIG ' + '0' * 40 + ' 2026 1 0 4 0 1 8 00\n'
    with patch('sre_tools.subprocess.run', return_value=Result()):
        with pytest.raises(ValueError):
            s.verify_signature('aws', tmp_path / 'data', tmp_path / 'sig', tmp_path)


@pytest.mark.parametrize('output', ['v1.2.3', '1.2.3'])
def test_version_output(output):
    class Result:
        stdout = output
        stderr = ''
    with patch('sre_tools.subprocess.run', return_value=Result()):
        assert s.actual_version('ocm', Path('/binary')) == '1.2.3'


def test_elf_arch(tmp_path):
    path = tmp_path / 'binary'
    path.write_bytes(b'\x7fELF\x02\x01' + b'\x00' * 12 + (183).to_bytes(2, 'little'))
    v.elf_arch(path, 'arm64')
    with pytest.raises(ValueError):
        v.elf_arch(path, 'amd64')


def test_osdctl_json_version_not_latest():
    class Result:
        stdout = '{"version":"0.67.0","latest":"0.68.0","commit":"abc"}'
        stderr = ''
    with patch('sre_tools.subprocess.run', return_value=Result()):
        assert s.actual_version('osdctl', Path('/binary')) == '0.67.0'


def test_signature_primary_subkey(tmp_path):
    class Result:
        stdout = '[GNUPG:] VALIDSIG ' + '1' * 40 + ' 2026-11-06 1 0 4 0 1 8 00 ' + s.SIGNERS['aws'] + '\n'
    with patch('sre_tools.subprocess.run', return_value=Result()):
        s.verify_signature('aws', tmp_path / 'data', tmp_path / 'sig', tmp_path)


def test_nested_executable_rejected(tmp_path):
    archive = tmp_path / 'a.tgz'
    tarball(archive, [('unexpected/oc', tarfile.REGTYPE)])
    with pytest.raises(ValueError):
        s.extract_binary(archive, 'oc', tmp_path / 'out')


def test_only_selected_binary_extracted(tmp_path):
    archive = tmp_path / 'a.tgz'
    tarball(archive, [('oc', tarfile.REGTYPE), ('LICENSE', tarfile.REGTYPE)])
    s.extract_binary(archive, 'oc', tmp_path / 'oc')
    assert not (tmp_path / 'LICENSE').exists()


def test_runtime_validation_directory_mount_contract():
    source = (Path(__file__).resolve().parents[1] / 'Containerfile').read_text()
    runs = source.replace('\\\n', ' ').split('RUN ')[1:]
    validations = [run for run in runs if 'verify_sre_tools.py runtime' in run]
    assert len(validations) == 1
    run = validations[0]
    assert run.startswith('--network=none ')
    assert run.count('--mount=') == 1
    assert '--mount=type=bind,source=.,target=/verify-src,ro ' in run
    assert 'runuser --user sre -- python3 /verify-src/build/verify_sre_tools.py runtime' in run
    assert '--containerfile /verify-src/Containerfile' in run


def test_secret_free_validation_contract():
    source = (Path(__file__).resolve().parents[1] / 'Containerfile').read_text()
    runs = source.replace('\\\n', ' ').split('RUN ')[1:]
    validations = [run for run in runs if '--validate-installed' in run]
    assert len(validations) == 6
    for run in validations:
        assert run.startswith('--network=none ')
        assert 'type=secret' not in run
    import inspect
    assert 'actual_version(' not in inspect.getsource(s.install)


@pytest.mark.parametrize('tool,output', [('yq', 'yq version v4.3.4-beta'),
    ('aws', 'aws-cli/2.3.4+other'), ('oc', 'Client Version: 4.3.4.5'), ('ocm', 'not a version')])
def test_malformed_version_output(tool, output):
    class Result:
        stdout = output
        stderr = ''
    with patch('sre_tools.subprocess.run', return_value=Result()):
        with pytest.raises(ValueError):
            s.actual_version(tool, Path('/binary'))


def test_missing_executable():
    with patch('sre_tools.subprocess.run', side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            s.actual_version('ocm', Path('/missing'))


def test_gpg_failure_propagates(tmp_path):
    import subprocess
    with patch('sre_tools.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'gpg')):
        with pytest.raises(subprocess.CalledProcessError):
            s.verify_signature('aws', tmp_path / 'data', tmp_path / 'missing', tmp_path)
