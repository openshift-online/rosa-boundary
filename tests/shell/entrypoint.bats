#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    ENTRYPOINT="${REPO_ROOT}/entrypoint.sh"
    export TRACE="$BATS_TEST_TMPDIR/trace" REPORT="$BATS_TEST_TMPDIR/report" READY="$BATS_TEST_TMPDIR/ready"
    export FIXTURE="$BATS_TEST_TMPDIR/fixture"
    export TASK=0123456789abcdef0123456789abcdef INVESTIGATION_ID=inv-test
    export S3_AUDIT_ESCROW=s3://audit/prefix/ ECS_CONTAINER_METADATA_URI_V4=http://metadata.invalid
    export PATH="$BATS_TEST_TMPDIR:$PATH"
    export KUBE_PROXY_PORT='' CLAUDE_CODE_USE_BEDROCK=0 TASK_TIMEOUT=0
    cat >"$BATS_TEST_TMPDIR/curl" <<'STUB'
#!/bin/bash
printf '{"TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/cluster/%s"}\n' "$TASK"
STUB
    cat >"$BATS_TEST_TMPDIR/aws" <<'STUB'
#!/bin/bash
echo "$*" >>"$TRACE"
case "$2" in
    sync)
        if [[ -e $FIXTURE ]]; then cp "$FIXTURE" "$FIXTURE.uploaded"; fi
        if [[ -n ${STALL:-} ]]; then exec sleep 30; fi
        exit "${TRANSFER_RC:-0}" ;;
    cp) cat >"$REPORT"; exit "${REPORT_RC:-0}" ;;
    *) exit 99 ;;
esac
STUB
    chmod +x "$BATS_TEST_TMPDIR/"{curl,aws}
}

@test "skill reconciler runs as sre with explicit home and can be disabled" {
    run bash -c '
        source "$1"
        runuser() { printf "runuser:%s\n" "$*"; }
        start_skill_reconciler "$1"
        wait "$SKILL_RECONCILER_PID"
        SKILL_RECONCILER_PID=""
        BOUNDARY_SKILLS_ENABLED=0 start_skill_reconciler "$1"
        test -z "$SKILL_RECONCILER_PID"
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "runuser:--user sre -- env HOME=/home/sre bash ${ENTRYPOINT}" ]
}

@test "nonzero workload exit still reports transfer and preserves workload status" {
    run bash -c '
        source "$1"
        verify_credential_mounts() { :; }
        initialize_credential_mounts() { :; }
        runuser() { return 7; }
        main false
    ' bash "${ENTRYPOINT}"
    [ "${status}" -eq 7 ]
    jq -e '.status == "unverified" and .transfer_rc == 0' "$REPORT"
}

@test "agent defaults run as sre with explicit HOME and support opt out" {
    run bash -c '
        source "$1"
        runuser() { printf "runuser:%s\n" "$*"; }
        unset BOUNDARY_AI_USE_BEDROCK CLAUDE_CODE_USE_BEDROCK
        configure_agent_defaults
        CLAUDE_CODE_USE_BEDROCK=0 configure_agent_defaults
        BOUNDARY_AI_USE_BEDROCK=0 configure_agent_defaults
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "runuser:--user sre -- env HOME=/home/sre python3 /usr/local/libexec/rosa-boundary-agent-defaults.py" ]
}

@test "optional agent defaults failure does not terminate set-e startup" {
    run bash -e -c '
        source "$1"
        runuser() { return 9; }
        BOUNDARY_AI_USE_BEDROCK=1 configure_agent_defaults
        printf "workload-continues\\n"
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"optional agent defaults helper failed"* ]]
    [[ "${output}" == *"workload-continues"* ]]
}

@test "empty agent switches use the shell default-on fallback" {
    run bash -e -c '
        source "$1"
        runuser() { printf "seed\\n"; }
        BOUNDARY_AI_USE_BEDROCK="" CLAUDE_CODE_USE_BEDROCK="" configure_agent_defaults
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "seed" ]
}

@test "entrypoint is safely sourceable" {
    run bash -c 'source "$1"; printf "%s\n" sourced' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "sourced" ]
}

@test "credential mount verification requires non-NFS mount overlays" {
    run bash -c '
        mountpoint() { return 0; }
        findmnt() { printf "%s\\n" "ext4"; }
        source "$1"
        verify_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
}

@test "credential mount verification fails for a missing overlay" {
    run bash -c '
        mountpoint() { return 1; }
        source "$1"
        verify_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -ne 0 ]
    [[ "${output}" == *"not a task-scoped mount: /home/sre/.config/ocm"* ]]
}

@test "credential mount verification rejects an EFS-backed overlay" {
    run bash -c '
        mountpoint() { return 0; }
        findmnt() { printf "%s\\n" "nfs4"; }
        source "$1"
        verify_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -ne 0 ]
    [[ "${output}" == *"backed by NFS/EFS: /home/sre/.config/ocm"* ]]
}

@test "main verifies credential mounts before initialization" {
    run env \
        KUBE_PROXY_PORT="" \
        CLAUDE_CODE_USE_BEDROCK="0" \
        S3_AUDIT_ESCROW="s3://audit-bucket/investigation/" \
        TASK_TIMEOUT="0" \
        bash -c '
            source "$1"
            verify_credential_mounts() { printf "verify\\n"; }
            initialize_credential_mounts() { printf "initialize\\n"; }
            runuser() { :; }
            main true
        ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == $'verify\ninitialize\n'* ]]
}

@test "credential mounts are initialized with sre ownership and mode 0700" {
    run bash -c '
        mkdir() { printf "mkdir:%s\n" "$*"; }
        chown() { printf "chown:%s\n" "$*"; }
        chmod() { printf "chmod:%s\n" "$*"; }
        source "$1"
        initialize_credential_mounts
    ' bash "${ENTRYPOINT}"

    [ "${status}" -eq 0 ]
    [ "${lines[0]}" = "mkdir:--parents /home/sre/.config/ocm" ]
    [ "${lines[1]}" = "chown:sre:sre /home/sre/.config/ocm" ]
    [ "${lines[2]}" = "chmod:0700 /home/sre/.config/ocm" ]
    [ "${lines[3]}" = "mkdir:--parents /home/sre/.kube" ]
    [ "${lines[4]}" = "chown:sre:sre /home/sre/.kube" ]
    [ "${lines[5]}" = "chmod:0700 /home/sre/.kube" ]
    [ "${#lines[@]}" -eq 6 ]
}

@test "explicit and generated destinations use fresh attempts, exclusions and correlated reports" {
    for mode in explicit generated; do
        if [[ $mode == generated ]]; then
            unset S3_AUDIT_ESCROW
            export S3_AUDIT_BUCKET=audit CLUSTER_ID=cluster-test
        fi
        previous=""
        for retry in 1 2; do
            : >"$TRACE"
            run bash -c 'source "$1"; sync_to_s3' bash "$ENTRYPOINT"
            [ "$status" -eq 0 ]
            uri=$(jq -er '.workspace_uri' "$REPORT")
            attempt=$(jq -er '.attempt_id' "$REPORT")
            [ "$previous" != "$attempt" ]
            previous="$attempt"
            if [[ $mode == explicit ]]; then
                [ "$uri" = "s3://audit/prefix/attempts/$attempt/workspace/" ]
            else
                [[ $uri == s3://audit/cluster-test/inv-test/????????/"$TASK/attempts/$attempt/workspace/" ]]
            fi
            jq -e --arg t "$TASK" '.schema_version == 1 and .status == "unverified" and .task_id == $t and .investigation_id == "inv-test" and .transfer_rc == 0' "$REPORT"
            [ "$(head -1 "$TRACE")" = "s3 sync /home/sre $uri --exclude .config/ocm/* --exclude .kube/* --no-follow-symlinks --quiet" ]
            [ "$(tail -1 "$TRACE")" = "s3 cp - ${uri%workspace/}report.json --content-type application/json --quiet" ]
            [ "$(wc -l <"$TRACE")" -eq 2 ]
        done
    done
}

@test "missing correlation or configuration does not upload" {
    for field in INVESTIGATION_ID ECS_CONTAINER_METADATA_URI_V4 S3_AUDIT_ESCROW TASK; do
        run env "$field=" bash -c 'source "$1"; sync_to_s3' bash "$ENTRYPOINT"
        [ "$status" -ne 0 ]
        [[ "$output" == *result=unverified* ]]
        [ ! -e "$TRACE" ]
    done
}

@test "sync timeout overrides cannot disable or exceed the bound" {
    for v in "" 0 91 123 bad 1d -1 09 999999999999999999999 85 1; do
        run env SYNC_TIMEOUT="$v" bash -c '
            source "$1"
            timeout() {
                while [[ $1 == --* ]]; do shift; done
                if [[ $4 == sync ]]; then printf "budget=%s\n" "$1"; else cat >/dev/null; fi
            }
            sync_to_s3
        ' bash "$ENTRYPOINT"
        [ "$status" -eq 0 ]
        expected=85
        if [[ $v == 1 ]]; then expected=1; fi
        grep -Fx "budget=$expected" <<<"$output"
    done
}

@test "partial transfer, timeout and report write failure never claim verification" {
    echo partial >"$FIXTURE"
    for fault in TRANSFER_RC=9 STALL=1 REPORT_RC=3; do
        rm -f "$REPORT"
        run env "$fault" SYNC_TIMEOUT=1 bash -c 'source "$1"; cleanup' bash "$ENTRYPOINT"
        [ "$status" -ne 0 ]
        [[ "$output" == *result=unverified* ]]
        cmp "$FIXTURE" "$FIXTURE.uploaded"
        jq -e '.status == "unverified"' "$REPORT"
        case $fault in
            TRANSFER*) [ "$status" -eq 9 ]; jq -e '.transfer_rc == 9' "$REPORT" ;;
            STALL*) [ "$status" -eq 124 ]; jq -e '.transfer_rc == 124' "$REPORT" ;;
            REPORT*) [[ "$output" == *reason=report_failed* ]] ;;
        esac
    done
}

@test "whole-shutdown watchdog interrupts a blocked upload without a terminal report" {
    run env STALL=1 bash -c '
        source "$1"
        # Shorten only the outer test clock; the actual sync timeout is 85s.
        SHUTDOWN_SECONDS=1
        cleanup
    ' bash "$ENTRYPOINT"
    [ "$status" -eq 124 ]
    [[ "$output" == *result=unverified*shutdown_rc=124* ]]
    [ "$(wc -l <"$TRACE")" -eq 1 ]
    [ ! -e "$REPORT" ]
}

@test "hard kill after partial upload leaves no report for this attempt; retained fixture can retry" {
    export STALL=1
    printf 'retained bytes' >"$FIXTURE"
    printf '{"status":"verified","task_id":"another-task"}' >"$BATS_TEST_TMPDIR/stale.json"
    run python3 - "$ENTRYPOINT" <<'PY'
import os, pathlib, signal, subprocess, sys, time
p = subprocess.Popen(['bash', '-c', 'source "$1"; sync_to_s3', 'bash', sys.argv[1]], start_new_session=True)
try:
    for _ in range(100):
        if pathlib.Path(os.environ['FIXTURE'] + '.uploaded').exists(): break
        time.sleep(.05)
    else: raise AssertionError('upload did not begin')
finally:
    os.killpg(p.pid, signal.SIGKILL)
    p.wait(timeout=5)
PY
    [ "$status" -eq 0 ]
    [ ! -e "$REPORT" ]
    first=$(cut -d' ' -f4 "$TRACE")
    rm "$FIXTURE.uploaded"
    unset STALL
    run bash -c 'source "$1"; sync_to_s3' bash "$ENTRYPOINT"
    [ "$status" -eq 0 ]
    [ "$(jq -r .workspace_uri "$REPORT")" != "$first" ]
    jq -e '.status == "unverified" and .transfer_rc == 0' "$REPORT"
    [ "$(<"$FIXTURE.uploaded")" = 'retained bytes' ]
}

@test "TERM INT HUP on waiting entrypoint allow final managed write and report once" {
    # Avoid SIGINT being ignored by asynchronous jobs of noninteractive Bash.
    run python3 - "$ENTRYPOINT" <<'PY'
import os, pathlib, signal, subprocess, sys, time
ready, trace, fixture = map(pathlib.Path, map(os.environ.get, ("READY", "TRACE", "FIXTURE")))
script = r"""
source "$1"
verify_credential_mounts() { :; }
initialize_credential_mounts() { :; }
runuser() {
    trap 'echo final >"$FIXTURE"; exit 0' TERM
    echo initial >"$FIXTURE"; touch "$READY"
    while :; do sleep .05; done
}
main workload
"""
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    ready.unlink(missing_ok=True)
    trace.unlink(missing_ok=True)
    with subprocess.Popen(["bash", "-c", script, "bash", sys.argv[1]], start_new_session=True) as p:
        try:
            for _ in range(100):
                if ready.exists(): break
                time.sleep(.05)
            assert ready.exists()
            p.send_signal(sig)
            assert p.wait(timeout=8) == 0
            assert len(trace.read_text().splitlines()) == 2
            assert pathlib.Path(str(fixture)+".uploaded").read_text() == "final\n"
        finally:
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
PY
    [ "$status" -eq 0 ]
}
