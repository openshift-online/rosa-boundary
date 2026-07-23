#!/usr/bin/env bats
# Tests for ci-run.sh — no real LocalStack or Podman required.
# Install: dnf install bats  (Fedora)  |  brew install bats-core  (macOS)
# Run:     bats tests/localstack/ci-run.bats
#
# Note: the Prow job IS ci-run.sh, so these tests cannot run in CI.
# They exist for local development only.

BATS_SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
CI_SCRIPT="$BATS_SCRIPT_DIR/ci-run.sh"
JUNIT_GATE="$BATS_SCRIPT_DIR/test/junit-gate"
READINESS_CHECK="$BATS_SCRIPT_DIR/test/readiness-check"

setup() {
    ARTIFACT_DIR="$(mktemp -d)"
    STUBS="$(mktemp -d)"
    export ARTIFACT_DIR STUBS BATS_SCRIPT_DIR
}

teardown() {
    rm -rf "$ARTIFACT_DIR" "$STUBS"
}

# ── JUnit gate ───────────────────────────────────────────────────────────────

@test "junit gate: passes when tests ran" {
    printf '<testsuite tests="5" skipped="1"/>' > "$ARTIFACT_DIR/j.xml"
    run python3 "$JUNIT_GATE" "$ARTIFACT_DIR/j.xml"
    [ "$status" -eq 0 ]
    [[ "$output" == *"4/5 tests ran"* ]]
}

@test "junit gate: fails when all tests skipped" {
    printf '<testsuite tests="3" skipped="3"/>' > "$ARTIFACT_DIR/j.xml"
    run python3 "$JUNIT_GATE" "$ARTIFACT_DIR/j.xml"
    [ "$status" -eq 1 ]
}

@test "junit gate: fails when xml missing" {
    run python3 "$JUNIT_GATE" "$ARTIFACT_DIR/nonexistent.xml"
    [ "$status" -eq 1 ]
}

@test "junit gate: fails when xml malformed" {
    printf 'not-xml' > "$ARTIFACT_DIR/j.xml"
    run python3 "$JUNIT_GATE" "$ARTIFACT_DIR/j.xml"
    [ "$status" -eq 1 ]
}

# ── collect_localstack_logs ──────────────────────────────────────────────────

# Write a self-contained runner script so the function body can be injected
# without wrestling with nested quoting in bash -c.
_write_log_runner() {
    local stub_body="$1" runner="$STUBS/run_collect.sh"
    printf '#!/usr/bin/env bash\ncase "$1" in\n%s\nesac\n' "$stub_body" \
        > "$STUBS/podman" && chmod +x "$STUBS/podman"
    {
        sed -n '/^collect_localstack_logs()/,/^}/p' "$CI_SCRIPT"
        printf '\ncollect_localstack_logs 2>&1\n'
    } > "$runner" && chmod +x "$runner"
    printf '%s' "$runner"
}

@test "collect_localstack_logs: warns when podman logs fails" {
    local runner
    runner="$(_write_log_runner 'logs) exit 1;; *) exit 0;;')"
    run env PATH="$STUBS:$PATH" PODMAN_SERVICE_PID="" ARTIFACT_DIR="$ARTIFACT_DIR" \
        bash "$runner"
    [[ "$output" == *"WARN: podman logs"* ]]
}

@test "collect_localstack_logs: warns when podman cp fails" {
    local runner
    runner="$(_write_log_runner 'cp) exit 1;; *) exit 0;;')"
    run env PATH="$STUBS:$PATH" PODMAN_SERVICE_PID="" ARTIFACT_DIR="$ARTIFACT_DIR" \
        bash "$runner"
    [[ "$output" == *"WARN: podman cp"* ]]
}

# ── readiness check: Python logic ────────────────────────────────────────────

@test "readiness check: passes when all services available" {
    local json
    json="$(python3 -c "
import sys; sys.path.insert(0, '$BATS_SCRIPT_DIR'); from required_services import REQUIRED
import json; print(json.dumps({'services': {s: 'available' for s in REQUIRED}}))
")"
    run python3 "$READINESS_CHECK" "$BATS_SCRIPT_DIR" "$json"
    [ "$status" -eq 0 ]
}

@test "readiness check: fails when service not ready" {
    run python3 "$READINESS_CHECK" "$BATS_SCRIPT_DIR" '{"services": {"s3": "starting"}}'
    [ "$status" -eq 1 ]
}

@test "readiness check: exits 2 when required_services.py missing" {
    run python3 "$READINESS_CHECK" "/tmp/no-such-dir-bats-$$" '{}'
    [ "$status" -eq 2 ]
}
