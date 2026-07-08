# shellcheck shell=bash
# cluster_function() — transforms raw kube context into human-readable display
# for kube-ps1. Plugged in via KUBE_PS1_CLUSTER_FUNCTION.
#
# Supports dual auth paths:
#   CLUSTER_AUTH_METHOD=backplane (default): uses ocm backplane status
#   CLUSTER_AUTH_METHOD=proxy: uses CLUSTER_ID env var directly

cluster_function() {
  if [[ "${CLUSTER_AUTH_METHOD:-backplane}" == "proxy" ]]; then
    # Proxy sidecar mode: no backplane, show CLUSTER_ID from env
    echo "${CLUSTER_ID:-unknown}"
    return
  fi

  # Backplane mode: derive cluster name from ocm backplane status
  local info clustername baseid
  info="$(ocm backplane status 2>/dev/null)" || return
  clustername=$(grep "Cluster Name" <<< "${info}" | awk '{print $3}')
  baseid=$(grep "Cluster Basedomain" <<< "${info}" | awk '{print $3}' | cut --delimiter='.' --fields=1,2)
  echo "${clustername}.${baseid}"
}
