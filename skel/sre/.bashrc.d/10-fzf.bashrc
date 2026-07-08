# shellcheck shell=bash
# fzf key bindings (Ctrl-R for history search, Ctrl-T for file finder)
# and completion (** trigger). Shell scripts installed from fzf GitHub release.

if [ -f /usr/share/fzf/shell/key-bindings.bash ]; then
    source /usr/share/fzf/shell/key-bindings.bash
fi

if [ -f /usr/share/fzf/shell/completion.bash ]; then
    source /usr/share/fzf/shell/completion.bash
fi
