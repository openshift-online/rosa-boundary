#!/usr/bin/env bash
# CI entrypoint for LocalStack integration tests.
# Called by the openshift/release Prow job; expects:
#   LOCALSTACK_AUTH_TOKEN  - injected from vault secret
#   ARTIFACT_DIR           - Prow artifact directory for JUnit output
set -euo pipefail

export AWS_DEFAULT_REGION=us-east-2
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export LOCALSTACK_ENDPOINT=http://localhost:4566

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

podman run -d \
  --name localstack \
  --user root \
  -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN}" \
  -e SERVICES=s3,iam,lambda,logs,kms,sts,ec2,ecs,efs,ssm \
  -e LAMBDA_EXECUTOR=local \
  -e ECS_EXECUTOR=local \
  -e DEBUG=1 \
  -e AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION}" \
  -e PERSISTENCE=0 \
  -e LOCALSTACK_LOG_DIR=/tmp/localstack-logs \
  -v "${SCRIPT_DIR}/init-aws.sh:/etc/localstack/init/ready.d/init-aws.sh:z" \
  localstack/localstack-pro:latest

echo "Waiting for LocalStack ECS service (timeout: 180s)..."
TIMEOUT=180; elapsed=0
until curl -sf http://localhost:4566/_localstack/health 2>/dev/null | \
    python3 -c "import sys,json; h=json.load(sys.stdin); exit(0 if h['services'].get('ecs') in ('available','running') else 1)" 2>/dev/null; do
  [ $elapsed -ge $TIMEOUT ] && { echo "ERROR: LocalStack did not become ready"; exit 1; }
  printf "  waiting... (%ds)\n" "$elapsed"
  sleep 5; elapsed=$((elapsed + 5))
done
echo "LocalStack ready."

cd "${SCRIPT_DIR}"
pytest integration/ -v --tb=short --junit-xml="${ARTIFACT_DIR}/junit_localstack.xml"
