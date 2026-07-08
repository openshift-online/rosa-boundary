# shellcheck shell=bash
# Display cluster context metadata on first login via osdctl.
# Gated by SHOW_CLUSTER_CONTEXT (default: on).
# Only runs once per session via sentinel file.

if [ -n "$CLUSTER_ID" ] && [ "${SHOW_CLUSTER_CONTEXT:-1}" = "1" ] && \
   [ ! -f "${HOME}/.session/osdctl-context-attempted" ]; then
    mkdir --parents "${HOME}/.session"
    touch "${HOME}/.session/osdctl-context-attempted"
    echo "Fetching context for cluster ${CLUSTER_ID}..."
    osdctl cluster context --cluster-id "$CLUSTER_ID" 2>/dev/null || true
fi
