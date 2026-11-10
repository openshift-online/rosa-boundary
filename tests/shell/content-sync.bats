#!/usr/bin/env bats

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../../deploy/regional/content-sync.sh"
    source "$SCRIPT"
    export CONTENT_BUCKET=test CONTENT_PREFIXES='ops/ nested/plugins/' AWS_REGION=us-east-1
    export CONTENT_SYNC_INTERVAL=30 CONTENT_SYNC_BACKOFF=1 CONTENT_SYNC_TIMEOUT=1
    export CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$BATS_TEST_TMPDIR/bin"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> "$CALLS"\nexit "${AWS_STATUS:-0}"\n' > "$BATS_TEST_TMPDIR/bin/aws"
    chmod +x "$BATS_TEST_TMPDIR/bin/aws"
}

@test "sync uses prefix VALUE paths and deletion without symlink following" {
    content_sync_prefix nested/plugins/
    grep -q 's3://test/nested/plugins/ /opt/rosa-content/nested/plugins/ --region us-east-1 --delete --no-follow-symlinks' "$CALLS"
    [ "$(wc -l < "$CALLS")" -eq 1 ]
}

@test "failures retry three times with capped backoff and sanitized logs" {
    export AWS_STATUS=42 CONTENT_SYNC_BACKOFF=40
    content_sync_sleep() { echo "sleep=$1"; }
    run content_sync_prefix ops/
    [ "$status" -eq 1 ]
    [[ "$output" == *'sleep=40'*'sleep=60'*'attempt=3 status=42'* ]]
    [ "$(wc -l < "$CALLS")" -eq 3 ]
}

@test "AWS output is suppressed so logs contain only prefix and exit status" {
    printf '#!/bin/bash\necho credential-marker\necho credential-marker >&2\nexit 2\n' > "$BATS_TEST_TMPDIR/bin/aws"
    content_sync_sleep() { :; }
    run content_sync_prefix ops/
    [ "$status" -eq 1 ]
    [[ "$output" != *'credential-marker'* ]]
    [[ "$output" == *'prefix=ops/ attempt=3 status=2'* ]]
}

@test "failure does not suppress subsequent prefixes or cadence" {
    content_sync_prefix() { echo "prefix=$1"; return 1; }
    content_sync_sleep() { echo "cadence=$1"; exit 0; }
    run main
    [ "$status" -eq 0 ]
    [[ "$output" == *'prefix=ops/'*'prefix=nested/plugins/'*'cadence=30'* ]]
}

@test "hung AWS process is forcibly bounded" {
    printf '#!/bin/bash\ntrap "" TERM\nsleep 60\n' > "$BATS_TEST_TMPDIR/bin/aws"
    export CONTENT_SYNC_TIMEOUT=0.1
    content_sync_sleep() { :; }
    run content_sync_prefix ops/
    [ "$status" -eq 1 ]
    [[ "$output" == *'attempt=3 status='* ]]
}

@test "TERM interrupts a cadence sleep promptly" {
    bash "$SCRIPT" > "$BATS_TEST_TMPDIR/log" 2>&1 &
    pid=$!
    sleep 0.3
    kill -TERM "$pid"
    wait "$pid"
}

@test "TERM interrupts an active AWS attempt" {
    printf '#!/bin/bash\nsleep 60\n' > "$BATS_TEST_TMPDIR/bin/aws"
    bash "$SCRIPT" > "$BATS_TEST_TMPDIR/log" 2>&1 &
    pid=$!
    sleep 0.3
    kill -TERM "$pid"
    wait "$pid"
}
