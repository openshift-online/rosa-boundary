"""Prow's Python 3.11 directory-install contract must survive local tooling changes."""

from pathlib import Path
import runpy
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


def test_ci_project_preserves_python311_directory_install_contract():
    with (ROOT / 'tests/localstack/pyproject.toml').open('rb') as stream:
        manifest = tomllib.load(stream)
    assert manifest['project']['name'] == 'rosa-boundary-localstack-tests'
    assert manifest['project']['requires-python'] == '>=3.11'
    assert manifest['project']['dynamic'] == ['dependencies']
    assert 'dependencies' not in manifest['project']
    assert manifest['tool']['setuptools']['py-modules'] == []
    assert manifest['build-system']['build-backend'] == 'setuptools.build_meta'
