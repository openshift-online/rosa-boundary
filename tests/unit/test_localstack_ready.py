"""Readiness gates must block test execution without a live, healthy service."""

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/localstack"))
import check_ready


def test_healthy_services_are_required():
    services = {service: "available" for service in check_ready.REQUIRED}
    with patch.object(check_ready.urllib.request, "build_opener") as factory:
        factory.return_value.open.return_value = io.StringIO(json.dumps({"services": services}))
        check_ready.require_ready("http://localhost:4566")
        factory.return_value.open.assert_called_once_with("http://localhost:4566/_localstack/health", timeout=5)


@pytest.mark.parametrize("health", [[], {}, {"services": None}, {"services": []}, {"services": {"ecs": "starting"}}])
def test_bad_health_blocks_tests(health):
    with patch.object(check_ready.urllib.request, "build_opener") as factory:
        factory.return_value.open.return_value = io.StringIO(json.dumps(health))
        with pytest.raises(check_ready.NotReady):
            check_ready.require_ready("http://localhost:4566")


def test_connection_failure_blocks_tests():
    with patch.object(check_ready.urllib.request, "build_opener") as factory:
        factory.return_value.open.side_effect = ConnectionRefusedError()
        with pytest.raises(check_ready.NotReady):
            check_ready.require_ready("http://localhost:4566")


def test_direct_pytest_fixture_fails_instead_of_skipping():
    spec = importlib.util.spec_from_file_location("integration_fixtures", ROOT / "tests/localstack/conftest.py")
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    with patch.object(fixtures, "require_ready", side_effect=check_ready.NotReady("down")), patch.object(fixtures.boto3, "client") as client:
        with pytest.raises(pytest.fail.Exception, match="down"):
            fixtures.localstack_available.__wrapped__()
        # Cached session clients cannot bypass the per-test guard.
        with pytest.raises(pytest.fail.Exception, match="down"):
            fixtures.localstack_ready_for_each_test.__wrapped__(SimpleNamespace(fixturenames=['ecs_client', 'localstack_available']))
        client.assert_not_called()


@pytest.mark.parametrize("arguments", [
    ["test-localstack-fast"],
    ["-o", "localstack-up", "test-localstack"],
    ["-C", "lambda/create-investigation", "test-localstack"],
    ["-C", "lambda/create-investigation", "test-e2e-localstack"],
])
def test_make_never_launches_pytest_when_readiness_fails(tmp_path, arguments):
    python = tmp_path / "python3"
    python.write_text('#!/bin/sh\necho "readiness failed" >&2\nexit 1\n')
    python.chmod(0o755)
    marker = tmp_path / "pytest-launched"
    uv = tmp_path / "uv"
    uv.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 0\n')
    uv.chmod(0o755)
    result = subprocess.run([shutil.which("make"), *arguments], cwd=ROOT, env=dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}"), capture_output=True, text=True)
    assert result.returncode != 0
    assert "readiness failed" in result.stdout + result.stderr
    assert not marker.exists()


def test_test_all_never_launches_integration_when_down(tmp_path):
    spec = importlib.util.spec_from_file_location("all_runner_readiness", ROOT / "scripts/test_all.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    runner = module.Runner(tmp_path)
    with patch.object(module, "require_ready", side_effect=check_ready.NotReady("down")), patch.object(runner, "run") as run:
        module.localstack_check(runner)
        run.assert_not_called()
    assert not runner.results[0]["passed"]


@pytest.mark.parametrize('target', ['test-localstack', 'test-e2e-localstack'])
def test_lambda_integration_targets_keep_readiness_and_select_existing_workflow(tmp_path, target):
    # Execute Make's wiring with harmless stubs, not AWS/LocalStack calls.
    python = tmp_path / 'python3'
    python.write_text('#!/bin/sh\nexit 0\n')
    python.chmod(0o755)
    uv = tmp_path / 'uv'
    uv.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$UV_ARGS_FILE"\npwd > "$UV_CWD_FILE"\n')
    uv.chmod(0o755)
    args_file = tmp_path / 'args'
    cwd_file = tmp_path / 'cwd'
    env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}", UV_ARGS_FILE=str(args_file), UV_CWD_FILE=str(cwd_file))
    result = subprocess.run([shutil.which('make'), '-C', 'lambda/create-investigation', target], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    args = args_file.read_text().splitlines()
    assert args[:5] == ['run', '--group', 'localstack', 'pytest', 'tests/localstack/integration/test_full_workflow.py']
    assert (ROOT / args[4]).is_file()
    assert cwd_file.read_text().strip() == str(ROOT)
    assert 'localstack-ready' in result.stdout
