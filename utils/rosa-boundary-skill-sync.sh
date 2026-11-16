#!/bin/bash
# Keep ~/.claude/skills and ~/.agents/skills up to date with published skills.
# Link each published <collection>/skills/<skill> directory, add new skills,
# and remove retired links without copying content or touching personal skills.

# Only namespaced links targeting the content root belong to this helper.
is_boundary_skill_link() {
    local link="$1" source="$2" target
    [[ "${link##*/}" == boundary--* ]] && [ -L "${link}" ] || return 1
    target=$(readlink -- "${link}") || return 1
    [[ "${target}" == "${source}/"* ]] || return 1
    target=$(realpath -m -- "${target}") || return 1
    [[ "${target}" == "${source}/"* ]]
}

# Refresh links for current skills, then remove only stale managed links.
sync_skills() {
    local source="$1" destination="$2" collection skill name link present
    local -a current=()
    [ -d "${source}" ] && [ -r "${source}" ] && [ -x "${source}" ] || return 1
    source=$(realpath -e -- "${source}") || return 1
    for collection in "${source}/"*; do
        [ -d "${collection}/skills" ] || continue
        [ ! -L "${collection}" ] && [ ! -L "${collection}/skills" ] || continue
        for skill in "${collection}/skills/"*; do
            [ -d "${skill}" ] && [ -f "${skill}/SKILL.md" ] || continue
            [ ! -L "${skill}" ] && [ ! -L "${skill}/SKILL.md" ] || continue
            name="boundary--${collection##*/}--${skill##*/}"
            current+=("${name}")
            link="${destination}/${name}"
            if { [ -e "${link}" ] || [ -L "${link}" ]; } &&
                ! is_boundary_skill_link "${link}" "${source}"; then
                echo "boundary-skills: preserving conflicting entry: ${name}" >&2
                continue
            fi
            ln --symbolic --force --no-target-directory -- "${skill}" "${link}" || return 1
        done
    done
    for link in "${destination}/"boundary--*; do
        is_boundary_skill_link "${link}" "${source}" || continue
        present=false
        for name in "${current[@]}"; do
            [[ "${link##*/}" != "${name}" ]] || present=true
        done
        "${present}" || rm -- "${link}" || return 1
    done
}

# Reconcile both discovery roots independently, preserving unsafe/conflicting roots.
sync_home_skills() {
    local source="$1" home="$2" root failed=0
    for root in "${home}/.claude" "${home}/.agents"; do
        if [ -L "${root}" ] || [ -L "${root}/skills" ] ||
            ! mkdir --parents "${root}/skills" ||
            ! sync_skills "${source}" "${root}/skills"; then
            echo "boundary-skills: sync failed for ${root}/skills; retrying next pass" >&2
            failed=1
        fi
    done
    return "${failed}"
}

# Run independently of the workload; retry every 60 seconds by default.
main() {
    local source="/opt/rosa-content/rosa-claude-plugins"
    local lock="${HOME}/.boundary-skills.lock" interval="${BOUNDARY_SKILL_RECONCILE_INTERVAL:-60}"
    if [[ ! "${interval}" =~ ^[0-9]{1,5}$ ]] || ((10#${interval} < 5 || 10#${interval} > 86400)); then
        echo "boundary-skills: interval must be 5..86400 seconds" >&2
        return 1
    fi
    trap 'kill "${SLEEP_PID:-}" 2>/dev/null || true; exit 0' TERM INT HUP
    while true; do
        # Keep the lock independent of either discovery root. Open it only after
        # rejecting symlinks; a subshell closes the descriptor after each pass.
        if ! (
            [ ! -L "${lock}" ] || exit 1
            exec 9> "${lock}" || exit 1
            if flock --nonblock 9; then
                sync_home_skills "${source}" "${HOME}"
            fi
        ); then
            echo "boundary-skills: sync failed; retrying in ${interval}s" >&2
        fi
        sleep "$((10#${interval}))" &
        SLEEP_PID=$!
        wait "${SLEEP_PID}"
        SLEEP_PID=""
    done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
