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
    timeout 60 podman cp localstack:/tmp/localstack-logs "${ARTIFACT_DIR}/localstack-logs" 2>&1 \
        || echo "WARN: podman cp timed out or failed (no internal logs; see above for reason)" >&2
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

if ! CONTAINER_ID=$(podman run --detach \
  --name localstack \
  --user root \
  --publish 4566:4566 \
  --volume "${PODMAN_SOCK}:/var/run/docker.sock:z" \
  --env LOCALSTACK_AUTH_TOKEN \
  --env SERVICES=s3,iam,logs,kms,sts,ec2,ecs,efs,ssm \
  --env DEBUG=1 \
  --env AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION}" \
  --env PERSISTENCE=0 \
  --env LOCALSTACK_LOG_DIR=/tmp/localstack-logs \
  --volume "${SCRIPT_DIR}/init-aws.sh:/etc/localstack/init/ready.d/init-aws.sh:ro,z" \
  "${LOCALSTACK_IMAGE}"); then
    echo "ERROR: failed to start LocalStack container from ${LOCALSTACK_IMAGE}" >&2
    echo "  Possible causes: invalid LOCALSTACK_AUTH_TOKEN, stale 'localstack' container," >&2
    echo "  SELinux denial on socket volume, or insufficient memory." >&2
    exit 1
fi
echo "LocalStack container started: ${CONTAINER_ID}"

python3 -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}')
from required_services import REQUIRED
if not REQUIRED:
    print('ERROR: REQUIRED list in required_services.py is empty', file=sys.stderr)
    sys.exit(1)
print(f'Pre-flight: {len(REQUIRED)} required services: {REQUIRED}')
" || {
    echo "ERROR: required_services.py is not importable or REQUIRED is empty — verify the file exists in ${SCRIPT_DIR} and has no syntax errors" >&2
    exit 1
}

echo "Waiting for LocalStack services (timeout: 180s)..."
TIMEOUT=180
_ready_deadline=$(( SECONDS + TIMEOUT ))
while true; do
  _ready_rc=0
  { curl --silent --fail --connect-timeout 5 --max-time 10 http://localhost:4566/_localstack/health 2>/dev/null | \
      python3 -c "
import sys, json
try:
    sys.path.insert(0, '${SCRIPT_DIR}')
    from required_services import REQUIRED
except ImportError as e:
    print(f'FATAL: cannot import REQUIRED: {e}', file=sys.stderr)
    sys.exit(2)
try:
    h = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    sys.exit(1)
if not isinstance(h, dict):
    sys.exit(1)
svcs = h.get('services')
if svcs is not None and not isinstance(svcs, dict):
    sys.exit(1)
svcs = svcs or {}
not_ready = [s for s in REQUIRED if svcs.get(s) not in ('available', 'running')]
if not_ready:
    print('  not ready: ' + ', '.join(not_ready), file=sys.stderr)
    sys.exit(1)
"; } || _ready_rc=$?
  [ $_ready_rc -eq 0 ] && break
  [ $_ready_rc -eq 2 ] && { echo "FATAL: required_services.py import failed — see stderr above" >&2; exit 1; }
  _ready_remaining=$(( _ready_deadline - SECONDS ))
  [ $_ready_remaining -le 0 ] && {
    echo "ERROR: LocalStack did not become ready after ${TIMEOUT}s" >&2
    exit 1
  }
  _ready_sleep=$(( _ready_remaining < 5 ? _ready_remaining : 5 ))
  printf "  waiting... (%ds elapsed)\n" "$(( TIMEOUT - _ready_remaining ))"
  sleep "$_ready_sleep"
done
echo "LocalStack ready."

# Poll /test/security-group-id as a sentinel: it is the last parameter written by
# init-aws.sh (after vpc-id, subnet-1-id, subnet-2-id), so its presence guarantees
# all four parameters exist. If init-aws.sh ever writes new parameters after that
# line, update this sentinel to match the new last-written parameter.
echo "Waiting for init-aws.sh SSM sentinel (/test/security-group-id, timeout: 120s)..."
python3 -c "import boto3, botocore.config, botocore.exceptions" || {
    echo "ERROR: boto3 or botocore is not importable — check Python environment" >&2
    exit 1
}
INIT_TIMEOUT=120
_ssm_deadline=$(( SECONDS + INIT_TIMEOUT ))
while true; do
  _ssm_rc=0
  python3 -c "
import sys, os, boto3, botocore.config, botocore.exceptions
c = boto3.client('ssm', endpoint_url=os.environ['LOCALSTACK_ENDPOINT'],
    region_name=os.environ['AWS_DEFAULT_REGION'],
    config=botocore.config.Config(connect_timeout=5, read_timeout=10))
try:
    c.get_parameter(Name='/test/security-group-id')
except botocore.exceptions.ClientError as e:
    code = e.response.get('Error', {}).get('Code', '')
    if not code:
        print(f'FATAL: malformed ClientError response: {e}', file=sys.stderr)
        sys.exit(2)
    if code in ('ParameterNotFound', 'ThrottlingException', 'RequestThrottled', 'Throttling',
                'InternalServerError', 'ServiceUnavailable'):
        sys.exit(1)
    print(f'FATAL SSM error: {e}', file=sys.stderr)
    sys.exit(2)
except (botocore.exceptions.EndpointConnectionError,
        botocore.exceptions.ConnectTimeoutError,
        botocore.exceptions.ReadTimeoutError):
    sys.exit(1)
except botocore.exceptions.BotoCoreError as e:
    print(f'FATAL boto3 error: {e}', file=sys.stderr)
    sys.exit(2)
except Exception as e:
    print(f'FATAL: unexpected error in SSM readiness check ({type(e).__name__}): {e}', file=sys.stderr)
    sys.exit(2)
" || _ssm_rc=$?
  [ $_ssm_rc -eq 0 ] && break
  [ $_ssm_rc -ge 128 ] && { echo "ERROR: Python poll interrupted (signal, rc=${_ssm_rc})" >&2; exit 1; }
  [ $_ssm_rc -eq 2 ] && { echo "ERROR: Fatal SSM error — see stderr above" >&2; exit 1; }
  _ssm_remaining=$(( _ssm_deadline - SECONDS ))
  [ $_ssm_remaining -le 0 ] && {
    echo "ERROR: /test/security-group-id not found in SSM after ${INIT_TIMEOUT}s — init-aws.sh may have failed" >&2
    exit 1
  }
  _ssm_sleep=$(( _ssm_remaining < 5 ? _ssm_remaining : 5 ))
  printf "  waiting for SSM parameters... (%ds elapsed)\n" "$(( INIT_TIMEOUT - _ssm_remaining ))"
  sleep "$_ssm_sleep"
done
echo "SSM parameters ready."

cd "${SCRIPT_DIR}"
echo "Running: pytest integration/ --verbose --tb=short --junit-xml=${ARTIFACT_DIR}/junit_localstack.xml"
pytest integration/ --verbose --tb=short --junit-xml="${ARTIFACT_DIR}/junit_localstack.xml"

# Guard against a silent-success run where all tests are skipped due to a
# service outage — pytest exits 0 even when everything is skipped.
python3 <<EOF
import xml.etree.ElementTree as ET, sys, os

xml_path = "${ARTIFACT_DIR}/junit_localstack.xml"
if not os.path.exists(xml_path):
    print(f'ERROR: JUnit XML not found at {xml_path} — pytest may have crashed before writing results', file=sys.stderr)
    sys.exit(1)

try:
    tree = ET.parse(xml_path)
except ET.ParseError as exc:
    print(f'ERROR: JUnit XML is malformed: {exc}', file=sys.stderr)
    sys.exit(1)

root = tree.getroot()
suite = root if root.tag == 'testsuite' else root.find('testsuite')
if suite is None:
    print('ERROR: No <testsuite> element in JUnit XML — unexpected format', file=sys.stderr)
    sys.exit(1)


total = int(suite.get('tests', 0))
skipped = int(suite.get('skipped', 0))
if total < 0 or skipped < 0 or skipped > total:
    print(f'ERROR: invalid test counters (tests={total}, skipped={skipped}) — XML may be malformed', file=sys.stderr)
    sys.exit(1)
ran = total - skipped
if ran <= 0:
    print(f'ERROR: 0/{total} tests ran ({skipped} skipped) — possible service outage or suite misconfiguration', file=sys.stderr)
    sys.exit(1)
print(f'Test gate passed: {ran}/{total} tests ran ({skipped} skipped)')
EOF
