#!/usr/bin/env bash
# CI entrypoint for LocalStack integration tests.
# Called by the openshift/release Prow job; expects:
#   LOCALSTACK_AUTH_TOKEN  - injected from vault secret
#   ARTIFACT_DIR           - Prow artifact directory for JUnit output
set -euo pipefail

LOCALSTACK_VERSION="${LOCALSTACK_VERSION:-4.11.0}"
LOCALSTACK_IMAGE="public.ecr.aws/localstack/localstack-pro:${LOCALSTACK_VERSION}"

export AWS_DEFAULT_REGION=us-east-2
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export LOCALSTACK_ENDPOINT=http://localhost:4566
# Prow injects its own STS session token; clear it so boto3 clients that read
# credentials from env vars don't send an invalid token to LocalStack.
unset AWS_SESSION_TOKEN

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${ARTIFACT_DIR:?ARTIFACT_DIR must be set — Prow injects this automatically}"
: "${LOCALSTACK_AUTH_TOKEN:?LOCALSTACK_AUTH_TOKEN must be set — inject from vault secret}"

echo "=== LocalStack CI Run ==="
echo "  image:        ${LOCALSTACK_IMAGE}"
echo "  region:       ${AWS_DEFAULT_REGION}"
echo "  endpoint:     ${LOCALSTACK_ENDPOINT}"
echo "  artifact_dir: ${ARTIFACT_DIR}"
echo "  script_dir:   ${SCRIPT_DIR}"
echo "========================="

PODMAN_SERVICE_PID=""

# Collect LocalStack stdout and internal log files into ARTIFACT_DIR on any
# exit so Docker executor errors are visible in Prow artifacts.
collect_localstack_logs() {
    if [[ -n "${PODMAN_SERVICE_PID}" ]]; then
        echo "Stopping Podman socket daemon (pid=${PODMAN_SERVICE_PID})..."
        kill "${PODMAN_SERVICE_PID}" 2>/dev/null || true
    else
        echo "Podman socket daemon not started; skipping kill."
    fi
    echo "Collecting LocalStack container logs..."
    timeout 60 podman logs localstack > "${ARTIFACT_DIR}/localstack.log" 2>&1 \
        || echo "WARN: podman logs timed out or failed" >&2
    echo "Copying LocalStack internal log directory..."
    timeout 60 podman cp localstack:/tmp/localstack-logs "${ARTIFACT_DIR}/localstack-logs" 2>/dev/null \
        || echo "WARN: podman cp timed out or failed (no internal logs)" >&2
    echo "Log collection complete."
}
trap collect_localstack_logs EXIT

# Start the Podman REST API (docker-compat) socket so LocalStack's ECS executor
# can spawn real task containers. The Prow CI container image does not auto-start
# this service, so we start it explicitly to avoid a missing DOCKER_HOST socket
# that would cause ECS task runs to fail silently.
# Use /tmp — always writable in Prow; XDG_RUNTIME_DIR is often unset and
# /run/user/<uid> may not be creatable without loginctl setup.
PODMAN_SOCK="/tmp/podman-$(id --user).sock"
export DOCKER_HOST="unix://${PODMAN_SOCK}"

podman system service --time=0 "${DOCKER_HOST}" &
PODMAN_SERVICE_PID=$!

echo "Waiting for Podman socket (${PODMAN_SOCK})..."
for i in $(seq 1 30); do
    [ -S "${PODMAN_SOCK}" ] && break
    sleep 1
done
[ -S "${PODMAN_SOCK}" ] || { echo "ERROR: Podman socket not ready after 30s"; exit 1; }
echo "Podman socket ready."

# Signal to pytest that Docker is available — ECS task tests should not skip.
export ECS_EXECUTOR=docker

echo "Pulling ${LOCALSTACK_IMAGE} from ECR Public..."
if ! timeout 300 podman pull "${LOCALSTACK_IMAGE}"; then
    echo "ERROR: failed to pull ${LOCALSTACK_IMAGE} within 300s" >&2
    echo "  Connectivity check: $(curl --silent --write-out '%{http_code}' --output /dev/null --max-time 10 https://public.ecr.aws/ 2>&1 || echo 'curl failed')" >&2
    exit 1
fi
echo "Pull complete."

if ! CONTAINER_ID=$(podman run -d \
  --name localstack \
  --user root \
  -p 4566:4566 \
  --volume "${PODMAN_SOCK}:/var/run/docker.sock:z" \
  -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN}" \
  -e SERVICES=s3,iam,lambda,logs,kms,sts,ec2,ecs,efs,ssm \
  -e LAMBDA_EXECUTOR=local \
  -e DEBUG=1 \
  -e AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION}" \
  -e PERSISTENCE=0 \
  -e LOCALSTACK_LOG_DIR=/tmp/localstack-logs \
  --volume "${SCRIPT_DIR}/init-aws.sh:/etc/localstack/init/ready.d/init-aws.sh:z" \
  "${LOCALSTACK_IMAGE}"); then
    echo "ERROR: failed to start LocalStack container from ${LOCALSTACK_IMAGE}" >&2
    echo "  Possible causes: invalid LOCALSTACK_AUTH_TOKEN, stale 'localstack' container," >&2
    echo "  SELinux denial on socket volume, or insufficient memory." >&2
    exit 1
fi
echo "LocalStack container started: ${CONTAINER_ID}"

echo "Waiting for LocalStack ECS service (timeout: 180s)..."
TIMEOUT=180; elapsed=0
until curl --silent --fail http://localhost:4566/_localstack/health 2>/dev/null | \
    python3 -c "import sys,json; h=json.load(sys.stdin); exit(0 if h['services'].get('ecs') in ('available','running') else 1)" 2>/dev/null; do
  [ $elapsed -ge $TIMEOUT ] && { echo "ERROR: LocalStack did not become ready"; exit 1; }
  health=$(curl --silent --fail http://localhost:4566/_localstack/health 2>/dev/null || echo '(no response)')
  printf "  waiting... (%ds) health=%s\n" "$elapsed" "$health"
  sleep 5; elapsed=$((elapsed + 5))
done
echo "LocalStack ready."

cd "${SCRIPT_DIR}"
echo "Running: pytest integration/ -v --tb=short --junit-xml=${ARTIFACT_DIR}/junit_localstack.xml"
pytest integration/ -v --tb=short --junit-xml="${ARTIFACT_DIR}/junit_localstack.xml"
