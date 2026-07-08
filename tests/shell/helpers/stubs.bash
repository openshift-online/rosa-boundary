# PATH-based command stubs for bats tests.
# Creates executable scripts in STUBS_DIR that return fixed output/exit codes.

# Create a stub command in STUBS_DIR.
# Usage: create_stub <command> [exit_code] [stdout_output]
create_stub() {
    local cmd="${1}"
    local exit_code="${2:-0}"
    local output="${3:-}"

    cat > "${STUBS_DIR}/${cmd}" <<STUB
#!/bin/bash
echo "${output}"
exit ${exit_code}
STUB
    chmod +x "${STUBS_DIR}/${cmd}"
}

# Create a stub that captures its arguments to a file for later assertion.
# Usage: create_capturing_stub <command> [exit_code] [stdout_output]
# Arguments are written to STUBS_DIR/<command>.args (one invocation per line)
create_capturing_stub() {
    local cmd="${1}"
    local exit_code="${2:-0}"
    local output="${3:-}"

    cat > "${STUBS_DIR}/${cmd}" <<STUB
#!/bin/bash
echo "\$*" >> "${STUBS_DIR}/${cmd}.args"
echo "${output}"
exit ${exit_code}
STUB
    chmod +x "${STUBS_DIR}/${cmd}"
}

# Read captured arguments from a capturing stub.
# Usage: stub_args <command>
stub_args() {
    cat "${STUBS_DIR}/${1}.args" 2>/dev/null
}
