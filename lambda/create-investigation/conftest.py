"""
pytest configuration for create-investigation Lambda unit tests.

With --import-mode=importlib (set in pytest.ini), pytest does not add the lambda
directory to sys.path automatically. We add it here at the END so that uv-installed
macOS-native packages (already at the front of sys.path from the virtual env) are
found before the bundled Linux x86_64 .so files in this directory.
"""

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.append(_this_dir)

# Pin a closed credential environment BEFORE test_handler imports handler.
# Do not clear keys and leave the default chain open — that can still resolve
# ambient ~/.aws, IMDS, or container credentials. Use explicit test-only keys
# (moto convention) and disable every ambient provider.
os.environ['AWS_ACCESS_KEY_ID'] = 'testing'  # noqa: S105
os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'  # noqa: S105
os.environ['AWS_SESSION_TOKEN'] = 'testing'  # noqa: S105
os.environ['AWS_SECURITY_TOKEN'] = 'testing'  # noqa: S105
os.environ['AWS_SHARED_CREDENTIALS_FILE'] = '/nonexistent'
os.environ['AWS_CONFIG_FILE'] = '/nonexistent'
os.environ['AWS_EC2_METADATA_DISABLED'] = 'true'
os.environ.pop('AWS_PROFILE', None)
os.environ.pop('AWS_DEFAULT_PROFILE', None)
os.environ.pop('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', None)
os.environ.pop('AWS_CONTAINER_CREDENTIALS_FULL_URI', None)
os.environ.pop('AWS_WEB_IDENTITY_TOKEN_FILE', None)
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-2')
os.environ.setdefault('AWS_ACCOUNT_ID', '123456789012')


@pytest.fixture(autouse=True)
def _no_ambient_aws_credentials(monkeypatch):
    """Re-assert the closed credential environment for every test (incl. reloads)."""
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')  # noqa: S105
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')  # noqa: S105
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'testing')  # noqa: S105
    monkeypatch.setenv('AWS_SECURITY_TOKEN', 'testing')  # noqa: S105
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', '/nonexistent')
    monkeypatch.setenv('AWS_CONFIG_FILE', '/nonexistent')
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-2')
    monkeypatch.setenv('AWS_ACCOUNT_ID', '123456789012')
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    monkeypatch.delenv('AWS_DEFAULT_PROFILE', raising=False)
    monkeypatch.delenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', raising=False)
    monkeypatch.delenv('AWS_CONTAINER_CREDENTIALS_FULL_URI', raising=False)
    monkeypatch.delenv('AWS_WEB_IDENTITY_TOKEN_FILE', raising=False)
