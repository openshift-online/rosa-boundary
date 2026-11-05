"""Prow's Python 3.11 directory-install contract must survive local tooling changes."""

from pathlib import Path
import runpy
import email
import subprocess
import zipfile
import shutil
import sys
import tomllib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('dependencies', [
    ['pytest>=9.1.1', 'boto3>=1.43.67'],
    ['requests>=2.34.2'],
])
def test_ci_package_reads_root_group_instead_of_a_duplicate_list(tmp_path, monkeypatch, dependencies):
    directory = tmp_path / 'tests/localstack'
    directory.mkdir(parents=True)
    shutil.copy2(ROOT / 'tests/localstack/setup.py', directory / 'setup.py')
    (tmp_path / 'pyproject.toml').write_text('[dependency-groups]\nlocalstack = ' + repr(dependencies) + '\n')
    setup = Mock()
    monkeypatch.setitem(sys.modules, 'setuptools', SimpleNamespace(setup=setup))
    runpy.run_path(str(directory / 'setup.py'))
    setup.assert_called_once_with(install_requires=dependencies)


def test_direct_dependencies_are_pinned_to_locked_versions():
    manifest = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    lock = tomllib.loads((ROOT / 'uv.lock').read_text())
    versions = {package['name']: package['version'] for package in lock['package']}
    for requirement in manifest['project']['dependencies'] + manifest['dependency-groups']['localstack']:
        name, version = requirement.split('==')
        assert versions[name.lower().replace('_', '-')] == version


def test_ci_package_reads_real_root_group(monkeypatch):
    manifest = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    dependencies = manifest['dependency-groups']['localstack']
    assert dependencies
    setup = Mock()
    monkeypatch.setitem(sys.modules, 'setuptools', SimpleNamespace(setup=setup))
    runpy.run_path(str(ROOT / 'tests/localstack/setup.py'))
    setup.assert_called_once_with(install_requires=dependencies)


def test_ci_package_builds_with_python311(tmp_path):
    # Do not download an interpreter as a unit-test side effect. A missing local
    # prerequisite is explicit skipped coverage (INCOMPLETE in test-all).
    interpreter = subprocess.run(
        ['uv', 'python', 'find', '--no-python-downloads', '3.11'],
        capture_output=True, text=True, check=False,
    )
    if interpreter.returncode:
        pytest.skip('Python 3.11 is required for the CI wheel-build contract test')
    root = tmp_path / 'source'
    directory = root / 'tests/localstack'
    directory.mkdir(parents=True)
    shutil.copy2(ROOT / 'pyproject.toml', root / 'pyproject.toml')
    for name in ('setup.py', 'pyproject.toml'):
        shutil.copy2(ROOT / 'tests/localstack' / name, directory / name)
    output = tmp_path / 'wheels'
    result = subprocess.run(
        ['uv', 'build', '--offline', '--python', interpreter.stdout.strip(),
         '--wheel', '--out-dir', str(output), str(directory)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheel, = output.glob('*.whl')
    with zipfile.ZipFile(wheel) as archive:
        metadata_path, = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
        metadata = email.message_from_bytes(archive.read(metadata_path))
    dependencies = tomllib.loads((ROOT / 'pyproject.toml').read_text())['dependency-groups']['localstack']
    normalize = lambda value: value.lower().replace(' ', '')
    assert sorted(map(normalize, metadata.get_all('Requires-Dist', []))) == sorted(map(normalize, dependencies))
    assert metadata['Requires-Python'] == '>=3.11'


def test_ci_project_preserves_python311_directory_install_contract():
    with (ROOT / 'tests/localstack/pyproject.toml').open('rb') as stream:
        manifest = tomllib.load(stream)
    assert manifest['project']['name'] == 'rosa-boundary-localstack-tests'
    assert manifest['project']['requires-python'] == '>=3.11'
    assert manifest['project']['dynamic'] == ['dependencies']
    assert 'dependencies' not in manifest['project']
    assert manifest['tool']['setuptools']['py-modules'] == []
    assert manifest['build-system']['build-backend'] == 'setuptools.build_meta'
