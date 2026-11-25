#!/bin/bash
set -euo pipefail

# Provisions the development database: a licensed LocalStack RDS PostgreSQL
# instance with IAM database authentication, bootstrapped by the server
# binary's `bootstrap` subcommand, and writes .env.localstack-db for
# `make run`. Idempotent: re-running reuses the existing instance.
#
# Requires LOCALSTACK_AUTH_TOKEN in the environment (Pro license; RDS is a
# pro feature). The token is passed to the container only — never written to
# the env file, the repo, or any log.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/compose.localstack-db.yml"
ENV_FILE="$REPO_ROOT/.env.localstack-db"

CONTAINER="rosa-ta-localstack-db"
ENDPOINT="http://127.0.0.1:4567"
REGION="us-east-1"
DB_IDENTIFIER="trusted-actions"
DB_NAME="trusted_actions"
MASTER_USER="master"
# LocalStack accepts any master password; generated per run, never written
# anywhere except the one-shot bootstrap DSN.
MASTER_PASSWORD="$(openssl rand -hex 24)"
APP_USER="trusted_actions_app"

log() { echo -e "\033[1;33m==>\033[0m $*"; }
ok()   { echo -e "\033[0;32m✓\033[0m $*"; }
fail() { echo -e "\033[0;31mERROR:\033[0m $*" >&2; exit 1; }

for bin in jq openssl curl go; do
    command -v "$bin" >/dev/null 2>&1 || fail "'$bin' is required but not found on PATH"
done

# Container runtime: podman when present, docker otherwise. The runtime is
# also used inside the container for the aws CLI (both images ship it).
if command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
elif command -v docker >/dev/null 2>&1; then
    RUNTIME="docker"
    docker info >/dev/null 2>&1 || fail "docker daemon is not reachable"
else
    fail "neither podman nor docker is on PATH"
fi

# COMPOSE invocation for the selected runtime.
compose() {
    if [ "$RUNTIME" = "podman" ]; then
        podman compose -p rosa-ta-localstack-db -f "$COMPOSE_FILE" "$@"
    else
        docker compose -p rosa-ta-localstack-db -f "$COMPOSE_FILE" "$@"
    fi
}

runtime_exec() {
    if [ "$RUNTIME" = "podman" ]; then
        podman exec "$@"
    else
        docker exec "$@"
    fi
}

runtime_container_exists() {
    if [ "$RUNTIME" = "podman" ]; then
        podman container exists "$CONTAINER" 2>/dev/null
    else
        [ -n "$(docker ps -aq --filter name="^${CONTAINER}$" 2>/dev/null)" ]
    fi
}

runtime_start() {
    if [ "$RUNTIME" = "podman" ]; then
        podman start "$CONTAINER"
    else
        docker start "$CONTAINER"
    fi
}

runtime_inspect_status() {
    if [ "$RUNTIME" = "podman" ]; then
        podman inspect -f '{{.State.Status}}' "$CONTAINER"
    else
        docker inspect -f '{{.State.Status}}' "$CONTAINER"
    fi
}
# AWS CLI against the local endpoint. awslocal (bundled in the LocalStack
# image) points at the gateway itself, sidestepping endpoint/SSL resolution.
aws_local() {
    runtime_exec "$CONTAINER" awslocal "$@"
}

# --- 1. Start LocalStack (licensed) ---
log "Starting licensed LocalStack (RDS)"
if ! runtime_container_exists; then
    compose up -d --wait ||
        fail "failed to start LocalStack (is LOCALSTACK_AUTH_TOKEN valid?)"
else
    state="$(runtime_inspect_status)"
    if [ "$state" != "running" ]; then
        runtime_start "$CONTAINER"
    fi
    log "reusing running LocalStack container"
fi

for i in $(seq 1 60); do
    curl -sf "$ENDPOINT/_localstack/health" >/dev/null 2>&1 && break
    sleep 2
done
curl -sf "$ENDPOINT/_localstack/health" >/dev/null 2>&1 || fail "LocalStack did not become healthy"
ok "LocalStack is healthy"

# --- 2. Create (or reuse) the RDS PostgreSQL instance ---
# Dynamic port: LocalStack assigns a random host port for the DB instance;
# it is discovered from the describe output and written to the env file.
if ! aws_local rds describe-db-instances --db-instance-identifier "$DB_IDENTIFIER" \
        --query 'DBInstances[0]' --output json 2>/dev/null | jq -e '.DBInstanceIdentifier' >/dev/null; then
    log "Creating RDS PostgreSQL instance '$DB_IDENTIFIER' (IAM auth enabled)"
    aws_local rds create-db-instance \
        --db-instance-identifier "$DB_IDENTIFIER" \
        --db-instance-class db.t3.micro \
        --engine postgres \
        --engine-version 16.4 \
        --allocated-storage 20 \
        --master-username "$MASTER_USER" \
        --master-user-password "$MASTER_PASSWORD" \
        --db-name "$DB_NAME" \
        --enable-iam-database-authentication \
        --no-publicly-accessible \
        >/dev/null || fail "failed to create RDS instance"
else
    # The development database is disposable: LocalStack does not apply
    # master-password changes via modify-db-instance, and each run
    # generates a fresh password, so the existing instance is replaced.
    # The bootstrap SQL is idempotent and the server's migrations re-apply,
    # so the state that matters is rebuilt automatically.
    log "Replacing existing RDS instance '$DB_IDENTIFIER' (fresh master password per run)"
    aws_local rds delete-db-instance \
        --db-instance-identifier "$DB_IDENTIFIER" \
        --skip-final-snapshot >/dev/null 2>&1
    for i in $(seq 1 30); do
        aws_local rds describe-db-instances --db-instance-identifier "$DB_IDENTIFIER" \
            >/dev/null 2>&1 || break
        sleep 2
    done
    aws_local rds create-db-instance \
        --db-instance-identifier "$DB_IDENTIFIER" \
        --db-instance-class db.t3.micro \
        --engine postgres \
        --engine-version 16.4 \
        --allocated-storage 20 \
        --master-username "$MASTER_USER" \
        --master-user-password "$MASTER_PASSWORD" \
        --db-name "$DB_NAME" \
        --enable-iam-database-authentication \
        --no-publicly-accessible \
        >/dev/null || fail "failed to re-create RDS instance"
fi

log "Waiting for the RDS instance to become available"
for i in $(seq 1 90); do
    status="$(aws_local rds describe-db-instances --db-instance-identifier "$DB_IDENTIFIER" \
        --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || echo "creating")"
    [ "$status" = "available" ] && break
    sleep 2
done
[ "$status" = "available" ] || fail "RDS instance did not become available (status: $status)"
ok "RDS instance is available"

DB_ENDPOINT="$(aws_local rds describe-db-instances --db-instance-identifier "$DB_IDENTIFIER" \
    --query 'DBInstances[0].Endpoint' --output json)"
DB_HOST="$(echo "$DB_ENDPOINT" | jq -r '.Address')"
DB_PORT="$(echo "$DB_ENDPOINT" | jq -r '.Port')"
[ -n "$DB_PORT" ] && [ "$DB_PORT" != "null" ] || fail "could not discover DB endpoint port"

# The DB port is published only inside the container's network, so the host
# reaches the instance through the container's IP. (The gateway hostname
# resolves to 127.0.0.1, where only the API port is forwarded.)
if [ "$RUNTIME" = "podman" ]; then
    CONTAINER_IP="$(podman inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER")"
else
    CONTAINER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER")"
fi
[ -n "$CONTAINER_IP" ] && [ "$CONTAINER_IP" != "null" ] || fail "could not discover LocalStack container IP"
DB_HOST="$CONTAINER_IP"
ok "endpoint: $DB_HOST:$DB_PORT"

# --- 3. Bootstrap the application database ---
log "Bootstrapping the application database (idempotent)"
DSN="postgres://${MASTER_USER}:${MASTER_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"
if ! (cd "$REPO_ROOT" && ROSA_TA_DB_MASTER_DSN="$DSN" go run ./cmd/server bootstrap); then
    fail "bootstrap subcommand failed"
fi
ok "database bootstrapped (role $APP_USER, rds_iam, CREATEDB, ownership transferred)"

# --- 4. Write the env file for `make run` ---
# No password and no master credentials in this file: the server mints IAM
# tokens from the static LocalStack credentials below.
old_umask=$(umask)
umask 077
cat > "$ENV_FILE" <<EOF
# Generated by make localstack-db — gitignored. No password lives here:
# the server authenticates with per-connection IAM tokens.
ROSA_TA_DB_HOST=${DB_HOST}
ROSA_TA_DB_PORT=${DB_PORT}
ROSA_TA_DB_NAME=${DB_NAME}
ROSA_TA_DB_USER=${APP_USER}
ROSA_TA_DB_SSLMODE=disable
AWS_REGION=${REGION}
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test

# Local development contract: mock auth (the 'roles' requirement and JWT
# validation are production concerns) and AWS traffic pinned to LocalStack
# — required by the server whenever auth is disabled. Point
# ROSA_TA_KUBECONFIG at a kind cluster (make itest-up) to run actions.
ROSA_TA_AUTH=disabled
ROSA_TA_AWS_ENDPOINT_URL=http://127.0.0.1:4567
EOF
umask "$old_umask"
ok "wrote $ENV_FILE (gitignored)"

echo
ok "Development database ready: source $ENV_FILE (or use 'make run-localstack-db') and start the server"
