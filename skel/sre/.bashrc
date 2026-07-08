# ~/.bashrc — sourced for interactive non-login shells
# Sources system defaults, then loads modular configs from ~/.bashrc.d/

# Source system-wide defaults
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# Source modular shell configuration in numeric order
if [ -d "${HOME}/.bashrc.d" ]; then
    for file in "${HOME}/.bashrc.d"/*.bashrc; do
        # shellcheck source=/dev/null
        [ -f "${file}" ] && source "${file}"
    done
    unset file
fi
