#!/bin/bash
# Maintain only Boundary-namespaced links; preserve all other user-global skills.

# Mirror validated links without dereferencing them; bound shutdown and runtime.
mirror_skill_links() {
    # Absolute links into /opt are intentional: neither --safe-links nor
    # --copy-links belongs here. No skill content is copied into the home.
    timeout --kill-after=2s 120s rsync --recursive --links "$@" &
    RSYNC_PID=$!
    local result=0
    wait "${RSYNC_PID}" || result=$?
    RSYNC_PID=""
    return "${result}"
}

# Recognize managed links by both namespace and a target inside the content root.
# Normalize even dangling targets so ../ or redirected paths cannot escape scope.
is_boundary_skill_link() {
    local link="$1" source="$2" target
    [[ "${link##*/}" == boundary--* ]] && [ -L "${link}" ] || return 1
    target=$(readlink -- "${link}") || return 1
    [[ "${target}" == "${source}/"* ]] || return 1
    target=$(realpath -m -- "${target}") || return 1
    [[ "${target}" == "${source}/"* ]]
}

# Stage all collections before updating links or removing stale Boundary links.
sync_skills() {
    local source="$1" destination="$2" staging="$3" skill target collection name link
    local -a links=()
    [ -d "${source}" ] && [ ! -L "${source}" ] || return 1
    source=$(realpath -e -- "${source}") || return 1
    mkdir --parents "${staging}/tree" || return 1
    # Complete discovery before changing the managed destination.
    # Do not follow collection/directory symlinks outside the mounted source.
    find "${source}" -mindepth 3 -maxdepth 3 -type d -path '*/skills/*' -print0 \
        > "${staging}/paths" || return 1
    while IFS= read -r -d '' skill; do
        [[ "${skill%/*}" == */skills ]] || continue
        [ ! -L "${skill}/SKILL.md" ] || return 1
        [ -f "${skill}/SKILL.md" ] || continue
        target=$(realpath -e -- "${skill}") || return 1
        [[ "${target}" == "${source}/"* ]] || return 1
        [ ! -e "${skill}/.claude-plugin" ] && [ ! -L "${skill}/.claude-plugin" ] || return 1
        collection=$(basename "$(dirname "$(dirname "${skill}")")")
        name=$(basename "${skill}")
        [[ "${collection}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || return 1
        [[ "${name}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || return 1
        name="boundary--${collection}--${name}"
        [ "${#name}" -le 240 ] && [ ! -e "${staging}/tree/${name}" ] || return 1
        ln --symbolic -- "${target}" "${staging}/tree/${name}" || return 1
    done < "${staging}/paths"
    for link in "${staging}/tree/"*; do
        [ -L "${link}" ] || continue
        name="${link##*/}"
        if { [ -e "${destination}/${name}" ] || [ -L "${destination}/${name}" ]; } && \
            ! is_boundary_skill_link "${destination}/${name}" "${source}"; then
            echo "boundary-skills: preserving conflicting entry: ${name}" >&2
            continue
        fi
        links+=("${link}")
    done
    # No --delete: rsync may update only these prevalidated destination entries.
    if [ "${#links[@]}" -gt 0 ]; then
        mirror_skill_links -- "${links[@]}" "${destination}/" || return 1
    fi
    for link in "${destination}/"boundary--*; do
        is_boundary_skill_link "${link}" "${source}" || continue
        [ -L "${staging}/tree/${link##*/}" ] || rm -- "${link}" || return 1
    done
}

# Stop active rsync children and remove task-local link staging.
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
