# shellcheck shell=bash
# Tab completion framework and CLI-specific completers.
# Build-time generated completions live in /etc/bash_completion.d/ and are
# loaded automatically by the bash-completion package.

# Source bash-completion framework if not already loaded
if [ -f /etc/profile.d/bash_completion.sh ]; then
    source /etc/profile.d/bash_completion.sh
fi

# AWS CLI completer (uses the aws_completer binary, not a static file)
if command -v /usr/local/aws-cli/v2/current/bin/aws_completer &>/dev/null; then
    complete -C '/usr/local/aws-cli/v2/current/bin/aws_completer' aws
fi
