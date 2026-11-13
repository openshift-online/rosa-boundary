#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    HELPER="${REPO_ROOT}/utils/rosa-boundary-skill-sync.sh"
    SOURCE="${BATS_TEST_TMPDIR}/source"
    DEST="${BATS_TEST_TMPDIR}/skills"
    STAGING="${BATS_TEST_TMPDIR}/staging"
    mkdir -p "${SOURCE}/collection/skills/example" "${DEST}"
    printf 'instructions\n' > "${SOURCE}/collection/skills/example/SKILL.md"
    printf 'asset\n' > "${SOURCE}/collection/skills/example/asset.txt"
}

sync_once() {
    bash -c 'source "$1"; sync_skills "$2" "$3" "$4"' bash "${HELPER}" "${SOURCE}" "${DEST}" "${STAGING}"
}

@test "sync mirrors links, exposes asset updates immediately, and deletes stale collections" {
    sync_once
    [ -f "${DEST}/boundary--collection--example/SKILL.md" ]
    [ -L "${DEST}/boundary--collection--example" ]
    [ "$(readlink "${DEST}/boundary--collection--example")" = "$(realpath -e "${SOURCE}/collection/skills/example")" ]
    printf 'updated asset\n' > "${SOURCE}/collection/skills/example/asset.txt"
    [ "$(< "${DEST}/boundary--collection--example/asset.txt")" = 'updated asset' ]
    printf 'stale\n' > "${DEST}/obsolete"
    rm -rf "${STAGING}"
    sync_once
    [ "$(< "${DEST}/boundary--collection--example/asset.txt")" = 'updated asset' ]
    [ -f "${DEST}/obsolete" ]
    rm -rf "${SOURCE}/collection" "${STAGING}"
    sync_once
    [ ! -L "${DEST}/boundary--collection--example" ]
    [ -f "${DEST}/obsolete" ]
}

@test "new collections appear without a fixed list" {
    mkdir -p "${SOURCE}/new/skills/new-skill"
    printf 'new\n' > "${SOURCE}/new/skills/new-skill/SKILL.md"
    sync_once
    [ -f "${DEST}/boundary--new--new-skill/SKILL.md" ]
}

@test "missing source and failed discovery preserve existing skills" {
    printf 'keep\n' > "${DEST}/existing"
    run bash -c 'source "$1"; sync_skills "$2/missing" "$3" "$4"' bash "${HELPER}" "${SOURCE}" "${DEST}" "${STAGING}"
    [ "${status}" -ne 0 ]
    [ -f "${DEST}/existing" ]
    run bash -c 'source "$1"; find() { return 1; }; sync_skills "$2" "$3" "$4"' bash "${HELPER}" "${SOURCE}" "${DEST}" "${STAGING}"
    [ "${status}" -ne 0 ]
    [ -f "${DEST}/existing" ]
}

@test "failed staging cannot authorize deletion" {
    printf 'keep\n' > "${DEST}/existing"
    run bash -c 'source "$1"; ln() { return 1; }; sync_skills "$2" "$3" "$4"' bash "${HELPER}" "${SOURCE}" "${DEST}" "${STAGING}"
    [ "${status}" -ne 0 ]
    [ -f "${DEST}/existing" ]
}

@test "linked skill preserves executable scripts and relative assets without copying content" {
    printf '#!/bin/sh\nexit 0\n' > "${SOURCE}/collection/skills/example/script.sh"
    chmod +x "${SOURCE}/collection/skills/example/script.sh"
    ln -s asset.txt "${SOURCE}/collection/skills/example/local-link"
    sync_once
    [ -x "${DEST}/boundary--collection--example/script.sh" ]
    [ "$(< "${DEST}/boundary--collection--example/local-link")" = asset ]
    [ -L "${DEST}/boundary--collection--example" ]
    [ -L "${STAGING}/tree/boundary--collection--example" ]
}

@test "plugin payloads and symlinked skill definitions fail closed" {
    mkdir "${SOURCE}/collection/skills/example/.claude-plugin"
    run sync_once
    [ "${status}" -ne 0 ]
    rmdir "${SOURCE}/collection/skills/example/.claude-plugin"
    rm "${SOURCE}/collection/skills/example/SKILL.md"
    ln -s /etc/passwd "${SOURCE}/collection/skills/example/SKILL.md"
    run sync_once
    [ "${status}" -ne 0 ]
}

@test "conflicting directories are preserved without altering source" {
    mkdir -p "${DEST}/boundary--collection--example"
    printf 'old copy\n' > "${DEST}/boundary--collection--example/old.txt"
    sync_once
    [ ! -L "${DEST}/boundary--collection--example" ]
    [ "$(< "${DEST}/boundary--collection--example/old.txt")" = 'old copy' ]
    [ ! -e "${SOURCE}/collection/skills/example/old.txt" ]
    [ -f "${SOURCE}/collection/skills/example/SKILL.md" ]
}

@test "conflicting files and external or relative symlinks are never overwritten" {
    printf 'user file\n' > "${DEST}/boundary--collection--example"
    sync_once
    [ "$(< "${DEST}/boundary--collection--example")" = 'user file' ]
    rm "${DEST}/boundary--collection--example"
    ln -s /unrelated/missing "${DEST}/boundary--collection--example"
    rm -rf "${STAGING}"
    sync_once
    [ "$(readlink "${DEST}/boundary--collection--example")" = /unrelated/missing ]
    rm "${DEST}/boundary--collection--example"
    ln -s ../personal "${DEST}/boundary--collection--example"
    rm -rf "${STAGING}"
    sync_once
    [ "$(readlink "${DEST}/boundary--collection--example")" = ../personal ]
}

@test "cleanup preserves unrelated links even with Boundary names or target prefixes" {
    root=$(realpath -e "${SOURCE}")
    ln -s "${root}/collection/skills/example" "${DEST}/personal-name"
    ln -s /unrelated/missing "${DEST}/boundary--external"
    ln -s "${root}/../outside" "${DEST}/boundary--escape"
    ln -s "${root}-other/missing" "${DEST}/boundary--prefix"
    sync_once
    rm -rf "${SOURCE}/collection" "${STAGING}"
    sync_once
    [ ! -L "${DEST}/boundary--collection--example" ]
    for name in personal-name boundary--external boundary--escape boundary--prefix; do
        [ -L "${DEST}/${name}" ]
    done
}

@test "managed links can be retargeted without modifying either source" {
    root=$(realpath -e "${SOURCE}")
    mkdir -p "${SOURCE}/previous"
    ln -s "${root}/previous" "${DEST}/boundary--collection--example"
    sync_once
    [ "$(readlink "${DEST}/boundary--collection--example")" = "${root}/collection/skills/example" ]
    [ -d "${SOURCE}/previous" ]
}

@test "failed rsync skips stale-link cleanup" {
    root=$(realpath -e "${SOURCE}")
    ln -s "${root}/old/missing" "${DEST}/boundary--old"
    run bash -c '
        source "$1"
        mirror_skill_links() { return 23; }
        sync_skills "$2" "$3" "$4"
    ' bash "${HELPER}" "${SOURCE}" "${DEST}" "${STAGING}"
    [ "${status}" -ne 0 ]
    [ -L "${DEST}/boundary--old" ]
}

@test "escaping discovered directories are rejected before mirroring" {
    printf 'keep\n' > "${DEST}/existing"
    mkdir -p "${BATS_TEST_TMPDIR}/external/skills/evil"
    printf 'external\n' > "${BATS_TEST_TMPDIR}/external/skills/evil/SKILL.md"
    run bash -c '
        source "$1"
        ESCAPE="$5"
        find() { printf "%s\\0" "${ESCAPE}"; }
        sync_skills "$2" "$3" "$4"
    ' bash "${HELPER}" "${SOURCE}" "${DEST}" "${STAGING}" "${BATS_TEST_TMPDIR}/external/skills/evil"
    [ "${status}" -ne 0 ]
    [ -f "${DEST}/existing" ]
}

@test "settings outside the skills directory are untouched" {
    printf '{"theme":"dark"}\n' > "${BATS_TEST_TMPDIR}/settings.json"
    sync_once
    [ "$(< "${BATS_TEST_TMPDIR}/settings.json")" = '{"theme":"dark"}' ]
}

@test "helper is sourceable and rejects invalid intervals before touching home" {
    run bash -c 'source "$1"; echo sourced' bash "${HELPER}"
    [ "${status}" -eq 0 ]
    [ "${output}" = sourced ]
    run env HOME="${BATS_TEST_TMPDIR}/home" BOUNDARY_SKILL_RECONCILE_INTERVAL=0 bash "${HELPER}"
    [ "${status}" -ne 0 ]
    [[ "${output}" == *'interval must be'* ]]
    [ ! -e "${BATS_TEST_TMPDIR}/home/.claude" ]
}

@test "shutdown terminates active copy group and sleep then removes staging" {
    run bash -c '
        source "$1"
        RSYNC_PID=12345 SLEEP_PID=12346 STAGING=fixture
        kill() { printf "kill:%s\n" "$*" >&3; }
        wait() { printf "wait:%s\n" "$*" >&3; }
        rm() { printf "rm:%s\n" "$*"; }
        cleanup_skill_sync 3>&1
    ' bash "${HELPER}"
    [ "${status}" -eq 0 ]
    [[ "${output}" == *'kill:-TERM -- -12345'* ]]
    [[ "${output}" == *'wait:12345'* ]]
    [[ "${output}" == *'kill:-TERM 12346'* ]]
    [[ "${output}" == *'rm:--recursive --force -- fixture'* ]]
}
