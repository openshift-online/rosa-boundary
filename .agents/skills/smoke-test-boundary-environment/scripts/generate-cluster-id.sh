#!/usr/bin/env bash
# Generate a short, syntax-valid synthetic cluster ID; never query OCM.
main() {
    printf 'smoke-test-%s-%s\n' "$(date +%s)" "${RANDOM}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
