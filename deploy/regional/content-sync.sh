#!/usr/bin/env bash
# Embedded verbatim in the ECS entryPoint; never runs the image audit entrypoint.

# Stop the active timeout/sleep process and wait for its bounded cleanup.
content_sync_stop() {
    trap '' TERM INT HUP
    if [[ -n ${content_sync_child:-} ]]; then
        kill -TERM "$content_sync_child" 2>/dev/null || true
        wait "$content_sync_child" 2>/dev/null || true
    fi
    exit 0
}

# Wait asynchronously so task shutdown interrupts cadence and backoff sleeps.
content_sync_sleep() {
    sleep "$1" &
    content_sync_child=$!
    wait "$content_sync_child"
    content_sync_child=
}

# Retry one prefix at most three times; timeout bounds even a stuck AWS client.
content_sync_prefix() {
    local prefix=$1 attempt status delay=$CONTENT_SYNC_BACKOFF
    for attempt in 1 2 3; do
        timeout --signal=TERM --kill-after=5 "$CONTENT_SYNC_TIMEOUT" \
            aws s3 sync "s3://${CONTENT_BUCKET}/${prefix}" "/opt/rosa-content/${prefix}" \
            --region "$AWS_REGION" --delete --no-follow-symlinks --only-show-errors \
            --cli-connect-timeout 10 --cli-read-timeout 30 >/dev/null 2>&1 &
        content_sync_child=$!
        if wait "$content_sync_child"; then status=0; else status=$?; fi
        content_sync_child=
        printf 'content-sync prefix=%s attempt=%s status=%s\n' "$prefix" "$attempt" "$status"
        [[ $status == 0 ]] && return 0
        if ((attempt < 3)); then
            content_sync_sleep "$delay"
            delay=$((delay * 2))
            ((delay > 60)) && delay=60
        fi
    done
    return 1
}

# Terraform validates configuration; all prefixes get a turn even on failures.
main() {
    trap content_sync_stop TERM INT HUP
    export AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=2 AWS_PAGER=""
    local prefix
    local -a prefixes
    read -r -a prefixes <<<"$CONTENT_PREFIXES"
    while true; do
        for prefix in "${prefixes[@]}"; do
            content_sync_prefix "$prefix" || true
        done
        content_sync_sleep "$CONTENT_SYNC_INTERVAL"
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
