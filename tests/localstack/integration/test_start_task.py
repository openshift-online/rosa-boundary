"""Integration tests for rosa-boundary start-task command with LocalStack Lambda."""

import json
import os
import subprocess
import shutil
from datetime import datetime
from pathlib import Path

import pytest


@pytest.fixture
def lambda_function_name(ssm_client):
    """Get Lambda function name from SSM parameter."""
    try:
        response = ssm_client.get_parameter(Name='/test/lambda-function-name')
        return response['Parameter']['Value']
    except ssm_client.exceptions.ParameterNotFound:
        pytest.skip("Lambda not deployed in LocalStack (handler source not available)")


@pytest.fixture
def rosa_boundary_cli():
    """Build and return path to rosa-boundary CLI."""
    go_path = shutil.which("go")
    if go_path is None:
        pytest.skip("Go compiler not found in PATH")

    repo_root = Path(__file__).resolve().parents[3]
    bin_path = repo_root / "bin" / "rosa-boundary"

    # Build CLI
    subprocess.run(
        [go_path, "build", "-o", str(bin_path), "./cmd/rosa-boundary"],
        cwd=repo_root,
        check=True,
        capture_output=True
    )

    return bin_path


@pytest.fixture
def localstack_env(test_vpc, test_efs, lambda_function_name):
    """Environment variables for rosa-boundary CLI pointed at LocalStack."""
    env = os.environ.copy()

    # LocalStack endpoint
    endpoint_url = "http://localhost:4566"
    if "LOCALSTACK_HOSTNAME" in env:
        endpoint_url = f"http://{env['LOCALSTACK_HOSTNAME']}:4566"

    env["AWS_ENDPOINT_URL"] = endpoint_url
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "test"
    env["AWS_DEFAULT_REGION"] = "us-east-1"

    # rosa-boundary config
    env["ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME"] = lambda_function_name
    env["ROSA_BOUNDARY_EFS_FILESYSTEM_ID"] = test_efs
    env["ROSA_BOUNDARY_ECS_CLUSTER_NAME"] = "rosa-boundary-localstack"

    return env


@pytest.mark.integration
def test_start_task_creates_investigation(
    rosa_boundary_cli, localstack_env, efs_client, ecs_client, ecs_cleanup, test_efs
):
    """Test that start-task creates an EFS access point and ECS task."""
    timestamp = int(datetime.now().timestamp())
    cluster_id = f"test-cluster-{timestamp}"
    investigation_id = f"test-inv-{timestamp}"

    cmd = [
        str(rosa_boundary_cli),
        "start-task",
        "--cluster-id", cluster_id,
        "--investigation-id", investigation_id,
        "--oc-version", "4.20"
    ]

    result = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode == 0, f"Command failed: {result.stderr}\nStdout: {result.stdout}"

    # Parse JSON output from stdout
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    assert 'task_arn' in output
    assert 'access_point_id' in output

    task_arn = output['task_arn']
    access_point_id = output['access_point_id']

    # Register for cleanup
    ecs_cleanup.register_task("rosa-boundary-localstack", task_arn)
    ecs_cleanup.register_access_point(access_point_id)

    # Verify EFS access point was created
    access_points = efs_client.describe_access_points(
        FileSystemId=test_efs,
        AccessPointId=access_point_id
    )
    assert len(access_points['AccessPoints']) == 1
    ap = access_points['AccessPoints'][0]
    assert ap['RootDirectory']['Path'] == f'/{cluster_id}/{investigation_id}'

    # Verify task tags
    ap_tags = {t['Key']: t['Value'] for t in ap.get('Tags', [])}
    assert ap_tags.get('ClusterID') == cluster_id
    assert ap_tags.get('InvestigationID') == investigation_id


@pytest.mark.integration
def test_start_task_reuses_existing_investigation(
    rosa_boundary_cli, localstack_env, efs_client, ecs_client, ecs_cleanup, test_efs
):
    """Test that calling start-task twice reuses the same EFS access point."""
    timestamp = int(datetime.now().timestamp())
    cluster_id = f"test-cluster-reuse-{timestamp}"
    investigation_id = f"test-inv-reuse-{timestamp}"

    cmd = [
        str(rosa_boundary_cli),
        "start-task",
        "--cluster-id", cluster_id,
        "--investigation-id", investigation_id
    ]

    # First invocation
    result1 = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result1.returncode == 0, f"First invocation failed: {result1.stderr}"
    output1 = json.loads(result1.stdout)
    access_point_id_1 = output1['access_point_id']
    task_arn_1 = output1['task_arn']

    # Register for cleanup
    ecs_cleanup.register_task("rosa-boundary-localstack", task_arn_1)
    ecs_cleanup.register_access_point(access_point_id_1)

    # Second invocation
    result2 = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result2.returncode == 0, f"Second invocation failed: {result2.stderr}"
    output2 = json.loads(result2.stdout)
    access_point_id_2 = output2['access_point_id']
    task_arn_2 = output2['task_arn']

    # Register second task for cleanup
    ecs_cleanup.register_task("rosa-boundary-localstack", task_arn_2)

    # Access point ID should be the same (reused)
    assert access_point_id_1 == access_point_id_2, \
        "Second invocation should reuse the same access point"

    # Task ARNs should be different (new task each time)
    assert task_arn_1 != task_arn_2, \
        "Each invocation should create a new task"


@pytest.mark.integration
def test_start_task_invalid_investigation_id(
    rosa_boundary_cli, localstack_env
):
    """Test that start-task validates investigation_id format."""
    cmd = [
        str(rosa_boundary_cli),
        "start-task",
        "--cluster-id", "valid-cluster",
        "--investigation-id", "invalid; DROP TABLE;"  # SQL injection attempt
    ]

    result = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    # Should fail with validation error (Lambda returns 400)
    assert result.returncode != 0, "Invalid investigation_id should be rejected"
    assert "alphanumeric" in result.stderr.lower() or "invalid" in result.stderr.lower()


@pytest.mark.integration
def test_start_task_missing_required_args(rosa_boundary_cli, localstack_env):
    """Test that start-task requires both cluster-id and investigation-id."""
    # Missing investigation-id
    cmd = [
        str(rosa_boundary_cli),
        "start-task",
        "--cluster-id", "test-cluster"
    ]

    result = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode != 0, "Missing investigation-id should fail"

    # Missing cluster-id
    cmd = [
        str(rosa_boundary_cli),
        "start-task",
        "--investigation-id", "test-inv"
    ]

    result = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode != 0, "Missing cluster-id should fail"


@pytest.mark.integration
def test_start_task_with_custom_timeout(
    rosa_boundary_cli, localstack_env, efs_client, ecs_client, ecs_cleanup, test_efs
):
    """Test that start-task accepts custom timeout values."""
    timestamp = int(datetime.now().timestamp())
    cluster_id = f"test-cluster-timeout-{timestamp}"
    investigation_id = f"test-inv-timeout-{timestamp}"

    cmd = [
        str(rosa_boundary_cli),
        "start-task",
        "--cluster-id", cluster_id,
        "--investigation-id", investigation_id,
        "--task-timeout", "7200"  # 2 hours
    ]

    result = subprocess.run(
        cmd,
        env=localstack_env,
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode == 0, f"Command failed: {result.stderr}"
    output = json.loads(result.stdout)

    # Register for cleanup
    ecs_cleanup.register_task("rosa-boundary-localstack", output['task_arn'])
    ecs_cleanup.register_access_point(output['access_point_id'])

    # Verify task was created successfully
    assert 'task_arn' in output
