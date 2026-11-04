"""Keep Prow's directory install compatible without duplicating dependencies.

The external CI image installs this directory from a complete repository checkout
with Python 3.11. It does not install the Python 3.13 root project itself.
"""

from pathlib import Path
import tomllib

from setuptools import setup

root = Path(__file__).resolve().parents[2]
with (root / "pyproject.toml").open("rb") as stream:
    dependencies = tomllib.load(stream)["dependency-groups"]["localstack"]

setup(install_requires=dependencies)
