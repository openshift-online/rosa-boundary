#!/bin/bash
set -euo pipefail

# Provisions the development database: a licensed LocalStack RDS PostgreSQL
# instance with IAM database authentication, bootstrapped by the server
# binary's `bootstrap` subcommand, and writes .env.localstack-db for
# `make run-localstack-db`.
#
# Reruns replace the RDS instance and its data: a fresh master password is
# generated each run and LocalStack does not apply master-password changes,
# so the previous instance (and any rows in it) is discarded and rebuilt.
# The LocalStack container itself is reused. Treat the dev database as
# disposable — schema is rebuilt by bootstrap + migrations, row data is not.
#
# Requires LOCALSTACK_AUTH_TOKEN in the environment (Pro license; RDS is a
# pro feature). The token is passed to the container only — never written to
# the env file, the repo, or any log.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-up}"
if [ "$MODE" != "up" ] && [ "$MODE" != "down" ]; then
    echo "usage: $0 [up|down]" >&2
    exit 2
fi

if [ "$MODE" = "down" ]; then
    # Teardown must not require the license token (compose no longer
    # demands it) and must reuse the same runtime selection as setup.
    if [ -n "${COMPOSE:-}" ]; then
        case "$COMPOSE" in
            podman*) RT="podman" ;;
            docker*) RT="docker" ;;
            *) echo "unsupported COMPOSE value: $COMPOSE" >&2; exit 1 ;;
        esac
    elif command -v podman >/dev/null 2>&1; then
        RT="podman"
    elif command -v docker >/dev/null 2>&1; then
        RT="docker"
    else
        echo "neither podman nor docker is on PATH" >&2
        exit 1
    fi
    if [ "$RT" = "podman" ]; then
        podman compose -p rosa-ta-localstack-db -f "$REPO_ROOT/compose.localstack-db.yml" down -v
    else
        docker compose -p rosa-ta-localstack-db -f "$REPO_ROOT/compose.localstack-db.yml" down -v
    fi
    rm -f "$REPO_ROOT/.env.localstack-db"
    exit 0
fi
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

# Container runtime: honor the caller's COMPOSE selection (same variable the
# Makefile uses) so setup and teardown agree on one runtime. The default
# mirrors the Makefile's COMPOSE detection exactly: Podman only when a
# compose backend is also present, otherwise Docker.
if [ -n "${COMPOSE:-}" ]; then
    case "$COMPOSE" in
        podman*) RUNTIME="podman" ;;
        docker*) RUNTIME="docker" ;;
        *) fail "unsupported COMPOSE value: $COMPOSE (use 'podman compose' or 'docker compose')" ;;
    esac
elif command -v podman >/dev/null 2>&1 \
      && { command -v podman-compose >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1; }; then
    RUNTIME="podman"
elif command -v docker >/dev/null 2>&1; then
    RUNTIME="docker"
else
    fail "neither podman (with a compose backend) nor docker is on PATH"
fi
if [ "$RUNTIME" = "docker" ]; then
    docker info >/dev/null 2>&1 || fail "docker daemon is not reachable"
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

# --- 2. Create (or replace) the RDS PostgreSQL instance ---
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
    # generates a fresh password, so the existing instance — and any rows
    # in it — is discarded. Only the schema is rebuilt (bootstrap SQL +
    # migrations); row data is not restored.
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

# --- 4. Write the env file for `make run-localstack-db` ---
# No password and no master credentials in this file: the server mints IAM
# tokens from the static LocalStack credentials below. Written to a temp
# file and renamed into place so a concurrent `make run-localstack-db`
# never sources a half-written file.
old_umask=$(umask)
umask 077
env_tmp="$(mktemp "$ENV_FILE.XXXXXX")"
cat > "$env_tmp" <<EOF
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
# — required by the server whenever auth is disabled. Loopback listen
# address: disabled auth must not accept connections from other hosts.
# ROSA_TA_KUBECONFIG must point at a kubeconfig (e.g. kind via make
# itest-up) or the server refuses to start with auth disabled.
ROSA_TA_AUTH=disabled
ROSA_TA_AWS_ENDPOINT_URL=http://127.0.0.1:4567
ROSA_TA_LISTEN_ADDR=127.0.0.1:8080
EOF
mv -f "$env_tmp" "$ENV_FILE"
umask "$old_umask"
ok "wrote $ENV_FILE (gitignored)"

echo
ok "Development database ready: run 'make run-localstack-db' (needs ROSA_TA_KUBECONFIG set to a valid kubeconfig — e.g. kind via 'make itest-up', or your own)"
