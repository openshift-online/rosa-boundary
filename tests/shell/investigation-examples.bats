#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    SCRIPT="$REPO_ROOT/deploy/regional/examples/create_investigation.sh"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    printf '#!/bin/bash\necho unexpected-aws-call >&2\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/aws"
    chmod +x "$BATS_TEST_TMPDIR/bin/aws"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "example can be sourced without AWS calls" {
    run bash -c 'source "$1"' _ "$SCRIPT"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "example rejects invalid timeout before AWS" {
    run bash "$SCRIPT" cluster investigation invalid
    [ "$status" -eq 1 ]
    [[ "$output" == *"task-timeout must be nonnegative integer seconds"* ]]
    [[ "$output" != *"unexpected-aws-call"* ]]
}

@test "example rejects extra arguments before AWS" {
    run bash "$SCRIPT" cluster investigation 3600 extra
    [ "$status" -eq 1 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" != *"unexpected-aws-call"* ]]
}

@test "example task template configures the investigation and preserves base environment" {
    printf '%s' '{"containerDefinitions":[{"environment":[{"name":"KEEP","value":"yes"}]}]}' > "$BATS_TEST_TMPDIR/base.json"
    run jq -f "$REPO_ROOT/deploy/regional/examples/build-task-def.jq" \
        --arg family test --arg task_role task --arg exec_role exec \
        --arg efs_id fs --arg access_point ap --arg cluster_id cluster \
        --arg investigation investigation --arg bucket audit --arg task_timeout 3600 \
        "$BATS_TEST_TMPDIR/base.json"
    [ "$status" -eq 0 ]
    printf '%s' "$output" > "$BATS_TEST_TMPDIR/task.json"
    run jq -e '.containerDefinitions[0].environment |
        any(.name == "KEEP" and .value == "yes") and
        any(.name == "CLUSTER_ID" and .value == "cluster") and
        any(.name == "INVESTIGATION_ID" and .value == "investigation") and
        any(.name == "TASK_TIMEOUT" and .value == "3600")' "$BATS_TEST_TMPDIR/task.json"
    [ "$status" -eq 0 ]
    [ "$output" = true ]
}
