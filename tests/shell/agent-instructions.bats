#!/usr/bin/env bats

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    SKELETON="${REPO_ROOT}/skel/sre"
    TEST_HOME="${BATS_TEST_TMPDIR}/home"
    mkdir -p "${TEST_HOME}"
}

@test "skeleton ships one shared instruction file with global compatibility links" {
    [ -s "${SKELETON}/AGENTS.md" ]
    [ "$(readlink "${SKELETON}/.claude/CLAUDE.md")" = "../AGENTS.md" ]
    [ "$(readlink "${SKELETON}/.codex/AGENTS.md")" = "../AGENTS.md" ]
    [ "$(readlink "${SKELETON}/.config/opencode/AGENTS.md")" = "../../AGENTS.md" ]
}

@test "entrypoint-style copy preserves working instruction links in a fresh home" {
    cp -rn "${SKELETON}/." "${TEST_HOME}/"

    for path in .claude/CLAUDE.md .codex/AGENTS.md .config/opencode/AGENTS.md; do
        [ -L "${TEST_HOME}/${path}" ]
        [ "$(readlink -f "${TEST_HOME}/${path}")" = "${TEST_HOME}/AGENTS.md" ]
        cmp "${TEST_HOME}/AGENTS.md" "${TEST_HOME}/${path}"
    done
    cmp "${SKELETON}/AGENTS.md" "${TEST_HOME}/AGENTS.md"
}

@test "repeated skeleton copy preserves customized instructions and adds missing paths" {
    mkdir -p "${TEST_HOME}/.claude"
    printf 'Existing Claude instructions\n' > "${TEST_HOME}/.claude/CLAUDE.md"
    printf 'Existing shared instructions\n' > "${TEST_HOME}/AGENTS.md"

    cp -rn "${SKELETON}/." "${TEST_HOME}/"
    cp -rn "${SKELETON}/." "${TEST_HOME}/"

    [ ! -L "${TEST_HOME}/.claude/CLAUDE.md" ]
    [ "$(cat "${TEST_HOME}/.claude/CLAUDE.md")" = "Existing Claude instructions" ]
    [ "$(cat "${TEST_HOME}/AGENTS.md")" = "Existing shared instructions" ]
    cmp "${TEST_HOME}/AGENTS.md" "${TEST_HOME}/.codex/AGENTS.md"
    cmp "${TEST_HOME}/AGENTS.md" "${TEST_HOME}/.config/opencode/AGENTS.md"
}
