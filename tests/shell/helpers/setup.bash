# Common setup/teardown for all rosa-boundary bats tests.
# Creates an isolated tmpdir with a stubs directory prepended to PATH,
# and a clean HOME for testing bashrc.d scripts.

# Repository root — resolve relative to this helper file, not the test file.
# This file is at tests/shell/helpers/setup.bash → three levels up.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# Load bats libraries
load "${REPO_ROOT}/tests/shell/lib/bats-support/load"
load "${REPO_ROOT}/tests/shell/lib/bats-assert/load"
load "${REPO_ROOT}/tests/shell/lib/bats-file/load"

setup() {
    # Create isolated temp directory for this test run
    TEST_TMPDIR="$(mktemp --directory)"
    export TEST_TMPDIR

    # Stubs directory — prepended to PATH for command mocking
    STUBS_DIR="${TEST_TMPDIR}/stubs"
    mkdir --parents "${STUBS_DIR}"
    export PATH="${STUBS_DIR}:${PATH}"

    # Isolated HOME for testing shell configs
    export HOME="${TEST_TMPDIR}/home"
    mkdir --parents "${HOME}/.session" "${HOME}/.kube" "${HOME}/.bashrc.d"
}

teardown() {
    rm --recursive --force "${TEST_TMPDIR}"
}
