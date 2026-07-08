# shellcheck shell=bash
# Shell history configuration — larger history, deduplication, append mode

export HISTSIZE=10000
export HISTFILESIZE=20000
shopt -s histappend
HISTCONTROL=ignoredups:ignorespace
