#!/usr/bin/env bash
# Run local Compose commands with the container engine's socket, not a host guess.
set -euo pipefail

# Podman info reports the server-side socket, including paths inside macOS VMs.
main() {
    local socket="${LOCALSTACK_PODMAN_SOCKET:-}"
    if [[ -z "$socket" ]]; then
        if ! socket="$(podman info --format '{{.Host.RemoteSocket.Path}}')"; then
            printf '%s\n' 'ERROR: Cannot query Podman. Start your Podman machine or socket first.' >&2
            return 1
        fi
        socket="${socket#unix://}"
    fi
    if [[ "$socket" != /* || "$socket" == *$'\n'* ]]; then
        printf '%s\n' 'ERROR: Podman did not report an absolute socket path. Set LOCALSTACK_PODMAN_SOCKET to the socket path on the Podman server.' >&2
        return 1
    fi
    export LOCALSTACK_PODMAN_SOCKET="$socket"
    cd "$(dirname "${BASH_SOURCE[0]}")"
    exec podman-compose "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
