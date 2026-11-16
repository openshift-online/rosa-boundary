#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    HELPER="${REPO_ROOT}/utils/rosa-boundary-skill-sync.sh"
    SOURCE="${BATS_TEST_TMPDIR}/source"
    DEST="${BATS_TEST_TMPDIR}/skills"
    mkdir -p "${SOURCE}/collection/skills/example" "${DEST}"
    printf 'instructions\n' > "${SOURCE}/collection/skills/example/SKILL.md"
    printf 'asset\n' > "${SOURCE}/collection/skills/example/asset.txt"
}

sync_once() {
    bash -c 'source "$1"; sync_skills "$2" "$3"' bash "${HELPER}" "${SOURCE}" "${DEST}"
}

@test "sync creates links, exposes asset updates immediately, and deletes stale collections" {
    sync_once
    [ -f "${DEST}/boundary--collection--example/SKILL.md" ]
    [ -L "${DEST}/boundary--collection--example" ]
    [ "$(readlink "${DEST}/boundary--collection--example")" = "$(realpath -e "${SOURCE}/collection/skills/example")" ]
    printf 'updated asset\n' > "${SOURCE}/collection/skills/example/asset.txt"
    [ "$(< "${DEST}/boundary--collection--example/asset.txt")" = 'updated asset' ]
    printf 'stale\n' > "${DEST}/obsolete"
    sync_once
    [ "$(< "${DEST}/boundary--collection--example/asset.txt")" = 'updated asset' ]
    [ -f "${DEST}/obsolete" ]
    rm -rf "${SOURCE}/collection"
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

@test "missing source preserves existing managed links" {
    sync_once
    mv "${SOURCE}" "${SOURCE}-offline"
    run sync_once
    [ "${status}" -ne 0 ]
    [ -L "${DEST}/boundary--collection--example" ]
}

@test "failed link update skips stale-link cleanup" {
    ln -s "${SOURCE}/old/missing" "${DEST}/boundary--old"
    run bash -c 'source "$1"; ln() { return 1; }; sync_skills "$2" "$3"' bash "${HELPER}" "${SOURCE}" "${DEST}"
    [ "${status}" -ne 0 ]
    [ -L "${DEST}/boundary--old" ]
}

@test "linked skill preserves executable scripts and relative assets without copying content" {
    printf '#!/bin/sh\nexit 0\n' > "${SOURCE}/collection/skills/example/script.sh"
    chmod +x "${SOURCE}/collection/skills/example/script.sh"
    ln -s asset.txt "${SOURCE}/collection/skills/example/local-link"
    sync_once
    [ -x "${DEST}/boundary--collection--example/script.sh" ]
    [ "$(< "${DEST}/boundary--collection--example/local-link")" = asset ]
    [ -L "${DEST}/boundary--collection--example" ]
}

@test "directory symlinks and symlinked definitions are not imported" {
    ln -s collection "${SOURCE}/alias"
    ln -s example "${SOURCE}/collection/skills/alias"
    mkdir "${SOURCE}/other"
    ln -s "${SOURCE}/collection/skills" "${SOURCE}/other/skills"
    sync_once
    [ -L "${DEST}/boundary--collection--example" ]
    [ ! -L "${DEST}/boundary--alias--example" ]
    [ ! -L "${DEST}/boundary--collection--alias" ]
    [ ! -L "${DEST}/boundary--other--example" ]
    rm "${SOURCE}/collection/skills/example/SKILL.md"
    ln -s /etc/passwd "${SOURCE}/collection/skills/example/SKILL.md"
    sync_once
    [ -z "$(ls -A "${DEST}")" ]
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
    sync_once
    [ "$(readlink "${DEST}/boundary--collection--example")" = /unrelated/missing ]
    rm "${DEST}/boundary--collection--example"
    ln -s ../personal "${DEST}/boundary--collection--example"
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
    rm -rf "${SOURCE}/collection"
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

sync_home_once() {
    bash -c 'source "$1"; sync_home_skills "$2" "$3"' bash "${HELPER}" "${SOURCE}" "${BATS_TEST_TMPDIR}/home"
}

@test "both discovery roots receive skills and assets, additions and stale-link cleanup" {
    sync_home_once
    for root in .claude .agents; do
        dest="${BATS_TEST_TMPDIR}/home/${root}/skills"
        [ -L "${dest}/boundary--collection--example" ]
        [ "$(< "${dest}/boundary--collection--example/asset.txt")" = asset ]
        printf 'personal\n' > "${dest}/personal"
    done
    printf 'updated\n' > "${SOURCE}/collection/skills/example/asset.txt"
    mkdir -p "${SOURCE}/collection/skills/added"
    printf 'new\n' > "${SOURCE}/collection/skills/added/SKILL.md"
    sync_home_once
    for root in .claude .agents; do
        dest="${BATS_TEST_TMPDIR}/home/${root}/skills"
        [ "$(< "${dest}/boundary--collection--example/asset.txt")" = updated ]
        [ -L "${dest}/boundary--collection--added" ]
    done
    rm -rf "${SOURCE}/collection"
    sync_home_once
    for root in .claude .agents; do
        dest="${BATS_TEST_TMPDIR}/home/${root}/skills"
        [ ! -L "${dest}/boundary--collection--example" ]
        [ ! -L "${dest}/boundary--collection--added" ]
        [ "$(< "${dest}/personal")" = personal ]
    done
}

@test "agents collisions and settings are preserved without blocking Claude links" {
    dest="${BATS_TEST_TMPDIR}/home/.agents"
    mkdir -p "${dest}/skills/boundary--collection--example"
    printf 'personal\n' > "${dest}/skills/boundary--collection--example/mine"
    printf 'settings\n' > "${dest}/settings.json"
    sync_home_once
    [ "$(< "${dest}/skills/boundary--collection--example/mine")" = personal ]
    [ "$(< "${dest}/settings.json")" = settings ]
    [ -L "${BATS_TEST_TMPDIR}/home/.claude/skills/boundary--collection--example" ]
}

@test "symlinked discovery roots are rejected independently" {
    for root in .claude .agents; do
        for component in root skills; do
            home="${BATS_TEST_TMPDIR}/home"
            rm -rf "${home}"
            mkdir -p "${home}/${root}" "${BATS_TEST_TMPDIR}/external"
            if [ "${component}" = root ]; then
                rmdir "${home}/${root}"
                ln -s "${BATS_TEST_TMPDIR}/external" "${home}/${root}"
            else
                ln -s "${BATS_TEST_TMPDIR}/external" "${home}/${root}/skills"
            fi
            run sync_home_once
            [ "${status}" -ne 0 ]
            [ -z "$(ls -A "${BATS_TEST_TMPDIR}/external")" ]
            if [ "${root}" = .claude ]; then other=.agents; else other=.claude; fi
            [ -L "${home}/${other}/skills/boundary--collection--example" ]
        done
    done
}

@test "missing source preserves managed links in both discovery roots" {
    sync_home_once
    mv "${SOURCE}" "${SOURCE}-offline"
    run sync_home_once
    [ "${status}" -ne 0 ]
    for root in .claude .agents; do
        [ -L "${BATS_TEST_TMPDIR}/home/${root}/skills/boundary--collection--example" ]
    done
}

@test "shutdown terminates the active sleep" {
    run timeout 5 bash -c '
        source "$1"
        flock() { return 1; }
        HOME="$2" main &
        pid=$!
        sleep 0.2
        kill -TERM "${pid}"
        wait "${pid}"
    ' bash "${HELPER}" "${BATS_TEST_TMPDIR}/home"
    [ "${status}" -eq 0 ]
}
