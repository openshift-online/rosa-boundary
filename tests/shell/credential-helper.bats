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
    jq --exit-status '.access_token != "" and .url != ""' "${OCM_CONFIG}" >/dev/null
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
    run env PATH="${STUBS}:${PATH}" "$@" bash -c '
        source "$1"
        OCM_CONFIG_DIR="$2"
        KUBECONFIG_DIR="$3"
        configure_ocm
    ' bash "${HELPER}" "${OCM_DIR}" "${KUBE_DIR}" <<<"${encoded_request}"
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
    [[ "${output}" == *"__ROSA_BOUNDARY_CREDENTIAL_OCM_READY__"* ]]
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
    for body in '{' '[]' '"value"'; do
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

    for url in production http://api.openshift.com https://attacker.example; do
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
            configure_ocm
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
    [ -z "$(find "${OCM_DIR}" -type f -print -quit)" ]
    [ ! -e "${KUBE_DIR}/config" ]

    run_clear
    [ "${status}" -eq 0 ]
}
