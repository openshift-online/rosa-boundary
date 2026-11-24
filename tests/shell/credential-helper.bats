#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    HELPER="${REPO_ROOT}/utils/rosa-boundary-credential-helper"
    TEST_ROOT="${BATS_TEST_TMPDIR}/credential-helper-${BATS_TEST_NUMBER}"
    OCM_DIR="${TEST_ROOT}/ocm"
    KUBE_DIR="${TEST_ROOT}/kube"
    STUBS="${TEST_ROOT}/bin"
    mkdir --parents "${OCM_DIR}" "${KUBE_DIR}" "${STUBS}"

    cat >"${STUBS}/stty" <<'STUB'
#!/bin/bash
exit 0
STUB
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
if [[ "${OCM_TEST_RESULT:-success}" == success ]]; then
    jq --exit-status '.access_token != "" and .url != ""' "${OCM_CONFIG}" >/dev/null || exit 1
    if [[ -n "${OCM_TEST_GATE:-}" ]]; then
        touch "${OCM_TEST_GATE}.ready"
        read -r _ <"${OCM_TEST_GATE}"
    fi
else
    printf 'sensitive account response\n'
    exit 1
fi
STUB
    chmod 0755 "${STUBS}/stty" "${STUBS}/ocm"
}

request() {
    jq --compact-output --null-input \
        --arg access_token "$1" \
        --arg url "${2:-https://api.openshift.com}" \
        '{access_token: $access_token, url: $url}' |
        base64 --wrap=0
}

run_configure() {
    local encoded_request="$1"
    shift
    run credential_op "${encoded_request}" configure "$@"
}

credential_op() {
    local encoded="$1" operation="$2"
    shift 2
    env PATH="${STUBS}:${PATH}" "$@" bash -c '
        source "$1"
        OCM_CONFIG_DIR="$2"
        KUBECONFIG_DIR="$3"
        main "$4" ocm
    ' bash "${HELPER}" "${OCM_DIR}" "${KUBE_DIR}" "${operation}" <<<"${encoded}"
}

generation_request() {
    jq -cn --arg token "$1" --arg gen "$2" --arg expected "${3:-}" '
        {access_token: $token, url: "https://api.openshift.com", generation: $gen} +
        (if $expected == "" then {} else {expected_generation: $expected} end)
    ' | base64 --wrap=0
}

run_clear() {
    run env PATH="${STUBS}:${PATH}" "$@" bash -c '
        source "$1"
        OCM_CONFIG_DIR="$2"
        KUBECONFIG_DIR="$3"
        clear_ocm
    ' bash "${HELPER}" "${OCM_DIR}" "${KUBE_DIR}"
}

@test "helper is safely sourceable and rejects arbitrary operations" {
    run bash -c 'source "$1"; printf "sourced\n"' bash "${HELPER}"
    [ "${status}" -eq 0 ]
    [ "${output}" = sourced ]

    run bash "${HELPER}" configure other
    [ "${status}" -eq 2 ]
    [[ "${output}" != *READY* ]]
}

@test "configure writes a minimal mode-0600 OCM configuration" {
    token='raw-token-canary-success'
    encoded="$(request "${token}")"
    run_configure "${encoded}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"__ROSA_BOUNDARY_CREDENTIAL_OCM_GENERATIONS_V1__"*"__ROSA_BOUNDARY_CREDENTIAL_OCM_READY__"* ]]
    [[ "${output}" == *"__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"* ]]
    [[ "${output}" != *"${token}"* ]]
    [[ "${output}" != *"${encoded}"* ]]
    [ "$(stat --format='%a' "${OCM_DIR}/ocm.json")" = 600 ]
    run jq --exit-status '
        (keys | sort) == ["access_token", "client_id", "scopes", "token_url", "url"] and
        .access_token == "raw-token-canary-success" and
        .client_id == "ocm-cli" and
        .scopes == ["openid"] and
        .url == "https://api.openshift.com" and
        (has("refresh_token") | not)
    ' "${OCM_DIR}/ocm.json"
    [ "${status}" -eq 0 ]
}

@test "configure rejects invalid base64 without leaking it" {
    encoded='not-base64-token-canary!'
    run_configure "${encoded}"
    [ "${status}" -ne 0 ]
    [[ "${output}" != *"${encoded}"* ]]
    [ ! -e "${OCM_DIR}/ocm.json" ]
}

@test "configure rejects malformed and non-object JSON" {
    for body in '{' '[]' '"value"' '{"access_token":"a","url":"https://api.openshift.com"} {"access_token":"b","url":"https://api.openshift.com"}'; do
        run_configure "$(printf '%s' "${body}" | base64 --wrap=0)"
        [ "${status}" -ne 0 ]
        [ ! -e "${OCM_DIR}/ocm.json" ]
    done
}

@test "configure rejects extra refresh offline and unknown fields" {
    for field in refresh_token offline_token token extra; do
        body="$(jq --compact-output --null-input --arg field "${field}" \
            '{access_token:"raw-token-canary",url:"https://api.openshift.com"} + {($field):"forbidden-canary"}')"
        encoded="$(printf '%s' "${body}" | base64 --wrap=0)"
        run_configure "${encoded}"
        [ "${status}" -ne 0 ]
        [[ "${output}" != *raw-token-canary* ]]
        [[ "${output}" != *forbidden-canary* ]]
        [[ "${output}" != *"${encoded}"* ]]
    done
}

@test "configure accepts only approved canonical OCM URLs" {
    for url in \
        https://api.openshift.com \
        https://api.stage.openshift.com \
        https://api.integration.openshift.com; do
        run_configure "$(request token "${url}")"
        [ "${status}" -eq 0 ]
        [ "$(jq --raw-output .url "${OCM_DIR}/ocm.json")" = "${url}" ]
    done

    for url in production http://api.openshift.com https://attacker.example $'https://api.openshift.com\n'; do
        run_configure "$(request token "${url}")"
        [ "${status}" -ne 0 ]
    done
}

@test "validation failure preserves the previous configuration and sanitizes output" {
    printf '%s\n' '{"access_token":"old-working-token"}' >"${OCM_DIR}/ocm.json"
    encoded="$(request raw-token-canary-failed)"
    run_configure "${encoded}" OCM_TEST_RESULT=failure

    [ "${status}" -ne 0 ]
    [ "$(cat "${OCM_DIR}/ocm.json")" = '{"access_token":"old-working-token"}' ]
    [[ "${output}" != *raw-token-canary-failed* ]]
    [[ "${output}" != *"${encoded}"* ]]
    [[ "${output}" != *"sensitive account response"* ]]
    [[ "${output}" == *"OCM credential validation failed"* ]]
    [ -z "$(find "${OCM_DIR}" -name '.rosa-boundary-credential-*' -print -quit)" ]
}

@test "installation failure preserves the previous configuration and does not report success" {
    printf '%s\n' '{"access_token":"old-working-token"}' >"${OCM_DIR}/ocm.json"
    cat >"${STUBS}/mv" <<'STUB'
#!/bin/bash
exit 1
STUB
    chmod 0755 "${STUBS}/mv"

    run_configure "$(request replacement-token)"

    [ "${status}" -ne 0 ]
    [ "$(cat "${OCM_DIR}/ocm.json")" = '{"access_token":"old-working-token"}' ]
    [[ "${output}" == *"unable to install OCM configuration"* ]]
    [[ "${output}" != *"__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"* ]]
    [ -z "$(find "${OCM_DIR}" -name '.rosa-boundary-credential-*' ! -name '.rosa-boundary-credential-lock' -print -quit)" ]
}

@test "configure bounds request input and restores terminal echo" {
    cat >"${STUBS}/stty" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >>"${TEST_ROOT}/stty.log"
STUB
    chmod 0755 "${STUBS}/stty"
    run_configure "$(head --bytes=65537 /dev/zero | tr '\0' A)"
    [ "${status}" -ne 0 ]
    [ "$(sed --quiet '1p' "${TEST_ROOT}/stty.log")" = -echo ]
    [ "$(sed --quiet '2p' "${TEST_ROOT}/stty.log")" = echo ]
}

@test "configure starts after one line while ECS stdin remains open" {
    encoded="$(request token-with-open-stdin)"
    fifo="${TEST_ROOT}/stdin.fifo"
    mkfifo "${fifo}"

    run env PATH="${STUBS}:${PATH}" timeout 1 bash -c '
        { printf "%s\n" "$5"; sleep 5; } >"$1" &
        writer=$!
        bash -c '\''
            source "$1"
            OCM_CONFIG_DIR="$2"
            KUBECONFIG_DIR="$3"
            main configure ocm
        '\'' bash "$2" "$3" "$4" <"$1"
        result=$?
        kill "${writer}" 2>/dev/null || true
        wait "${writer}" 2>/dev/null || true
        exit "${result}"
    ' bash "${fifo}" "${HELPER}" "${OCM_DIR}" "${KUBE_DIR}" "${encoded}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"* ]]
}

@test "clear removes OCM helper state and credential-bearing kubeconfig idempotently" {
    touch "${OCM_DIR}/ocm.json" \
        "${OCM_DIR}/.rosa-boundary-credential-request.old" \
        "${OCM_DIR}/.rosa-boundary-credential-candidate.old" \
        "${KUBE_DIR}/config"

    run_clear
    [ "${status}" -eq 0 ]
    [ "${output}" = __ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__ ]
    [ -z "$(find "${OCM_DIR}" -type f ! -name '.rosa-boundary-credential-lock' -print -quit)" ]
    [ ! -e "${KUBE_DIR}/config" ]

    run_clear
    [ "${status}" -eq 0 ]
}

@test "renew installs only the current generation and strips metadata" {
    first=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    next=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    last=cccccccccccccccccccccccccccccccc
    run_configure "$(generation_request initial-token "${first}")"
    [ "${status}" -eq 0 ]
    run credential_op "$(generation_request bad-token "${next}" "${first}")" renew OCM_TEST_RESULT=failure
    [ "${status}" -ne 0 ]
    [[ "${output}" != *bad-token* ]]
    [ "$(jq -r .access_token "${OCM_DIR}/ocm.json")" = initial-token ]
    run credential_op "$(generation_request renewed-token "${next}" "${first}")" renew
    [ "${status}" -eq 0 ]
    [[ "${output}" != *renewed-token* ]]
    jq -e '.access_token == "renewed-token" and (has("generation") | not)' "${OCM_DIR}/ocm.json"
    run credential_op "$(generation_request stale-token "${last}" "${first}")" renew
    [ "${status}" -ne 0 ]
    [[ "${output}" == *"generation changed"* ]]
    [ "$(jq -r .access_token "${OCM_DIR}/ocm.json")" = renewed-token ]
    run_configure "$(request manual-token)"
    [ "${status}" -eq 0 ]
    run credential_op "$(generation_request stale-token "${last}" "${next}")" renew
    [ "${status}" -ne 0 ]
    [ "$(jq -r .access_token "${OCM_DIR}/ocm.json")" = manual-token ]
}

@test "clear wins while a renewal is validating" {
    first=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    next=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    run_configure "$(generation_request initial-token "${first}")"
    [ "${status}" -eq 0 ]
    gate="${TEST_ROOT}/release"
    mkfifo "${gate}"
    credential_op "$(generation_request delayed-token "${next}" "${first}")" renew OCM_TEST_GATE="${gate}" >"${TEST_ROOT}/renew.log" 2>&1 &
    worker=$!
    for ((i = 0; i < 100; ++i)); do
        [[ -f "${gate}.ready" ]] && break
        sleep 0.02
    done
    if [[ ! -f "${gate}.ready" ]]; then
        kill "${worker}" 2>/dev/null || true
        wait "${worker}" || true
        return 1
    fi
    run_clear
    printf 'continue\n' >"${gate}"
    [ "${status}" -eq 0 ]
    ! wait "${worker}"
    [ ! -e "${OCM_DIR}/ocm.json" ]
    grep -q 'generation changed' "${TEST_ROOT}/renew.log"
    ! grep -Eq 'delayed-token|SUCCESS__' "${TEST_ROOT}/renew.log"
}

run_login() {
    run env PATH="${STUBS}:${PATH}" "$@" bash -c '
        source "$1"
        OCM_CONFIG_DIR="$2"
        KUBECONFIG_DIR="$3"
        BACKPLANE_LOGIN_TIMEOUT="${5:-40}"
        login_backplane "$4"
    ' bash "${HELPER}" "${OCM_DIR}" "${KUBE_DIR}" "${CLUSTER_ID-2abc}" "${LOGIN_TIMEOUT:-40}"
}

stub_backplane() {
    cat >"${STUBS}/ocm" <<STUB
#!/bin/bash
[[ "\$1 \$2" == "backplane login" ]] || exit 2
printf 'sensitive cluster detail\\n'
exit ${1}
STUB
    chmod 0755 "${STUBS}/ocm"
}

@test "backplane login succeeds with OCM configured" {
    stub_backplane 0
    printf '{}' >"${OCM_DIR}/ocm.json"
    run_login
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"* ]]
    [[ "${output}" != *"sensitive"* ]]
}

@test "backplane login failure reports Backplane's last lines" {
    stub_backplane 1
    printf '{}' >"${OCM_DIR}/ocm.json"
    run_login
    [ "${status}" -ne 0 ]
    [[ "${output}" != *"SUCCESS"* ]]
    [[ "${output}" == *"__ROSA_BOUNDARY_BACKPLANE_MESSAGE__ sensitive cluster detail"* ]]
}

@test "backplane login failure message is capped and sanitized" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
for n in 1 2 3 4 5; do printf 'line %s\n' "${n}"; done
printf '\033[31mred\033[0m bell\a %0400d\n' 0
exit 1
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    run_login
    [ "${status}" -ne 0 ]
    [ "$(grep -c '__ROSA_BOUNDARY_BACKPLANE_MESSAGE__' <<<"${output}")" -eq 3 ]
    [[ "${output}" != *"line 1"* && "${output}" != *"line 2"* ]]
    [[ "${output}" == *"line 5"* ]]
    [[ "${output}" != *$'\033'* && "${output}" != *$'\a'* ]]
    ! grep -E "MESSAGE__ .{301,}" <<<"${output}"
}

@test "backplane login failure removes partial kubeconfig" {
    stub_backplane 1
    printf '{}' >"${OCM_DIR}/ocm.json"
    printf 'partial' >"${KUBE_DIR}/config"
    run_login
    [ "${status}" -ne 0 ]
    [ ! -e "${KUBE_DIR}/config" ]
}

@test "backplane login times out when Backplane hangs" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
sleep 30
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    SECONDS=0
    LOGIN_TIMEOUT=1 run_login
    [ "${status}" -ne 0 ]
    [ "${SECONDS}" -lt 15 ]
    [[ "${output}" != *"SUCCESS"* ]]
}

@test "backplane login requires OCM credentials" {
    stub_backplane 0
    run_login
    [ "${status}" -ne 0 ]
    [[ "${output}" != *"SUCCESS"* ]]
}

@test "backplane login passes the cluster ID to Backplane unmodified" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
printf '%s|%s\n' "$3" "$4" >"${OCM_ARGS_FILE}"
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    CLUSTER_ID='my-cluster.1' run_login OCM_ARGS_FILE="${TEST_ROOT}/args"
    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_ROOT}/args")" = '--|my-cluster.1' ]
}

@test "backplane login passes IDs that look like options or shell syntax unmodified after --" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
printf '%s|%s\n' "$3" "$4" >"${OCM_ARGS_FILE}"
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    for id in '--help' 'a b' 'foo;bar' '$(touch pwned)' "it's"; do
        CLUSTER_ID="${id}" run_login OCM_ARGS_FILE="${TEST_ROOT}/args"
        [ "${status}" -eq 0 ]
        [ "$(cat "${TEST_ROOT}/args")" = "--|${id}" ]
    done
    [ ! -e pwned ]
}

@test "backplane diagnostics cannot forge protocol markers" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
printf "failed to get cluster '__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__'\n"
printf 'x __ROSA_BOUNDARY_CREDENTIAL_OCM_READY__ __ROSA_BOUNDARY_CREDENTIAL_OCM_GENERATIONS_V1__\n'
printf '__ROSA_BOUNDARY_CREDENTIAL_OCM_SUC\001CESS__\n'
exit 1
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    run_login
    [ "${status}" -ne 0 ]
    [[ "${output}" != *"__ROSA_BOUNDARY_CREDENTIAL_OCM_"* ]]
    [[ "${output}" == *"__ROSA_BOUNDARY_BACKPLANE_MESSAGE__ failed to get cluster '[marker]'"* ]]
}

@test "backplane login that outlives clear leaves no kubeconfig and fails" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
printf 'late' >"${STUB_KUBE_DIR}/config"
rm --force -- "${STUB_OCM_DIR}/ocm.json"
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    run_login STUB_KUBE_DIR="${KUBE_DIR}" STUB_OCM_DIR="${OCM_DIR}"
    [ "${status}" -ne 0 ]
    [[ "${output}" != *"SUCCESS"* ]]
    [ ! -e "${KUBE_DIR}/config" ]
}

@test "backplane login keeps the kubeconfig when OCM credentials remain" {
    cat >"${STUBS}/ocm" <<'STUB'
#!/bin/bash
printf 'kept' >"${STUB_KUBE_DIR}/config"
STUB
    chmod 0755 "${STUBS}/ocm"
    printf '{}' >"${OCM_DIR}/ocm.json"
    run_login STUB_KUBE_DIR="${KUBE_DIR}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"* ]]
    [ "$(cat "${KUBE_DIR}/config")" = kept ]
}
