# shellcheck shell=bash
# Auto cluster login on shell entry if CLUSTER_ID is set.
#
# CLUSTER_AUTH_METHOD controls the login path:
#   backplane (default): runs sre-login to call ocm backplane login
#   proxy: verifies kube-proxy sidecar connectivity (no login needed)
#
# Only attempts login once per session via a sentinel file to prevent
# repeated attempts in terminal multiplexer panes.

if ! oc config current-context &>/dev/null && [ -z "$SKIP_CLUSTER_LOGIN" ] && [ -n "$CLUSTER_ID" ]; then
    if [ -f "${HOME}/.session/sre-login-attempted" ]; then
        echo "Skipping automatic cluster login (previous attempt detected). Run 'sre-login $CLUSTER_ID' to retry manually."
    else
        mkdir --parents "${HOME}/.session"
        touch "${HOME}/.session/sre-login-attempted"

        if [[ "${CLUSTER_AUTH_METHOD:-backplane}" == "proxy" ]]; then
            # Proxy sidecar mode: verify connectivity instead of logging in
            if oc version --client &>/dev/null && oc get --raw /version &>/dev/null; then
                echo "Cluster access verified via kube-proxy sidecar"
                rm --force "${HOME}/.session/sre-login-attempted"
            else
                echo "Warning: kube-proxy sidecar not responding. Run 'oc get nodes' to check connectivity." >&2
            fi
        else
            # Backplane mode: use sre-login
            sre-login "$CLUSTER_ID"
        fi
    fi
fi
