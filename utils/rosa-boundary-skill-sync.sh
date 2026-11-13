#!/bin/bash
# Mirror the sole published skill source into the fully managed Claude skills root.

# Run each copy with a timeout; retain its process group for shutdown cleanup.
copy_skills() {
    timeout --kill-after=2s 120s rsync --recursive --links --perms --times \
        --safe-links --chmod=Du+rwx,Fu+rw,ugo-s "$@" &
    RSYNC_PID=$!
    local result=0
    wait "${RSYNC_PID}" || result=$?
    RSYNC_PID=""
    return "${result}"
}

# Stage all collections before allowing rsync to delete any destination files.
sync_skills() {
    local source="$1" destination="$2" staging="$3" skill collection name
    [ -d "${source}" ] && [ ! -L "${source}" ] || return 1
    mkdir --parents "${staging}/tree" || return 1
    # find must complete successfully, including directory reads, before copying.
    # Do not follow collection/directory symlinks outside the mounted source.
    find "${source}" -mindepth 3 -maxdepth 3 -type d -path '*/skills/*' -print0 \
        > "${staging}/paths" || return 1
    while IFS= read -r -d '' skill; do
        [[ "${skill%/*}" == */skills ]] || continue
        [ ! -L "${skill}/SKILL.md" ] || return 1
        [ -f "${skill}/SKILL.md" ] || continue
        [ ! -e "${skill}/.claude-plugin" ] && [ ! -L "${skill}/.claude-plugin" ] || return 1
        collection=$(basename "$(dirname "$(dirname "${skill}")")")
        name=$(basename "${skill}")
        [[ "${collection}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || return 1
        [[ "${name}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || return 1
        name="boundary--${collection}--${name}"
        [ "${#name}" -le 240 ] && [ ! -e "${staging}/tree/${name}" ] || return 1
        copy_skills -- "${skill}/" "${staging}/tree/${name}/" || return 1
        [ -f "${staging}/tree/${name}/SKILL.md" ] || return 1
        [ ! -e "${staging}/tree/${name}/.claude-plugin" ] && \
            [ ! -L "${staging}/tree/${name}/.claude-plugin" ] || return 1
    done < "${staging}/paths"
    copy_skills --delete --delay-updates -- "${staging}/tree/" "${destination}/"
}

# Stop active copies (including rsync children) and remove task-local staging.
cleanup_skill_sync() {
    if [ -n "${RSYNC_PID:-}" ]; then
        kill -TERM -- "-${RSYNC_PID}" 2>/dev/null || kill -TERM "${RSYNC_PID}" 2>/dev/null || true
        wait "${RSYNC_PID}" 2>/dev/null || true
    fi
    if [ -n "${SLEEP_PID:-}" ]; then
        kill -TERM "${SLEEP_PID}" 2>/dev/null || true
        wait "${SLEEP_PID}" 2>/dev/null || true
    fi
    [ -z "${STAGING:-}" ] || rm --recursive --force -- "${STAGING}"
    return 0
}

# Run as sre; content failures never gate the workload or cause tight retries.
main() {
    local source="/opt/rosa-content/rosa-claude-plugins"
    local claude="${HOME}/.claude" interval="${BOUNDARY_SKILL_RECONCILE_INTERVAL:-60}"
    if [[ ! "${interval}" =~ ^[0-9]{1,5}$ ]] || ((10#${interval} < 5 || 10#${interval} > 86400)); then
        echo "boundary-skills: interval must be 5..86400 seconds" >&2
        return 1
    fi
    interval=$((10#${interval}))
    [ ! -L "${claude}" ] && [ ! -L "${claude}/skills" ] || return 1
    mkdir --parents "${claude}/skills" || return 1
    [ ! -L "${claude}/.boundary-skills.lock" ] || return 1
    exec 9> "${claude}/.boundary-skills.lock" || return 1
    trap cleanup_skill_sync EXIT
    trap 'exit 0' TERM INT HUP
    while true; do
        if flock --nonblock 9; then
            STAGING=$(mktemp -d /tmp/boundary-skills.XXXXXX) || return 1
            if ! sync_skills "${source}" "${claude}/skills" "${STAGING}"; then
                echo "boundary-skills: sync failed; retrying in ${interval}s" >&2
            fi
            rm --recursive --force -- "${STAGING}"
            STAGING=""
            flock --unlock 9
        fi
        sleep "${interval}" &
        SLEEP_PID=$!
        wait "${SLEEP_PID}" || true
        SLEEP_PID=""
    done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
