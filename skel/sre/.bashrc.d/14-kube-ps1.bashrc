# shellcheck shell=bash
# PS1 prompt configuration with kube-ps1 context display.
# Format: [directory {ocm_environment} (context:namespace)]$
#
# OCM_ENVIRONMENT is passed as an env var from the Lambda/task definition
# (e.g., "production", "staging"). Falls back to "unknown" if unset.

# shellcheck disable=SC2154
export PS1="[\W {\[\033[1;32m\]${OCM_ENVIRONMENT:-unknown}\[\033[0m\]} \$(kube_ps1)]\$ "
export KUBE_PS1_BINARY=oc
export KUBE_PS1_CLUSTER_FUNCTION=cluster_function
export KUBE_PS1_SYMBOL_ENABLE=false
