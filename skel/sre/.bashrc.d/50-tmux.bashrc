# shellcheck shell=bash
# tmux auto-start — ENV-gated, default OFF.
# Set TMUX_AUTOSTART=1 to replace the login shell with a tmux session.
# Only activates in interactive shells not already inside tmux.

if [ "${TMUX_AUTOSTART}" = "1" ] && [ -z "${TMUX}" ] && [[ $- == *i* ]]; then
    exec tmux new-session -A -s investigation
fi
