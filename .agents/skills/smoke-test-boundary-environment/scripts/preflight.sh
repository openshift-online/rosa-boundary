#!/usr/bin/env bash
# Inspect local prerequisites only; never authenticate, edit profiles or call AWS.

# Print a consistent blocker without exposing configuration/override values.
block() {
    printf 'BLOCKED: %s\n' "$*" >&2
    return 1
}

# Match common user-facing environment aliases to saved deployment environments.
normalize_environment() {
    case "$1" in
        staging | stage | stg) printf 'stage\n' ;;
        production | prod) printf 'prod\n' ;;
        integration | int) printf 'int\n' ;;
        development | devel | dev) printf 'dev\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# Resolve one saved target and check installed capabilities without changing it.
main() (
    set -euo pipefail
    local environment='' profile='' region_filter='' cli profiles row name account saved_env region selected_region
    local candidates=() key value variable saved help_text
    while (($#)); do
        case "$1" in
            --environment | --profile | --region)
                [[ $# -ge 2 && -n "$2" ]] || { block "Missing value for $1"; return 1; }
                case "$1" in
                    --environment) environment=$(normalize_environment "$2") ;;
                    --profile) profile=$2 ;;
                    --region) region_filter=$2 ;;
                esac
                shift 2
                ;;
            --help)
                printf 'Usage: bash preflight.sh --environment ENV [--region REGION] [--profile NAME]\nRead-only and local. Exit 0 means local prerequisites passed, not authorization or live readiness.\n'
                return 0
                ;;
            *) block "Unknown argument: $1"; return 1 ;;
        esac
    done
    [[ -n "$environment" ]] || { block '--environment is required'; return 1; }
    command -v python3 >/dev/null || { block 'Python 3 is required for the skill PTY helper.'; return 1; }
    cli=$(command -v rosa-boundary) || { block 'Boundary CLI not found. Use `make install-cli` to install the CLI from a local checkout, then rerun preflight.'; return 1; }
    command -v session-manager-plugin >/dev/null || { block 'Session Manager plugin not found.'; return 1; }
    printf 'CLI=%s\n' "$cli"
    profiles=$("$cli" config list-profiles) || { block 'Cannot list saved profiles.'; return 1; }
    printf '%s\n' "$profiles"
    # list-profiles currently exposes a table, not JSON. Accept only its data rows.
    while read -r row; do
        row=${row#\*}
        read -r name account saved_env region <<< "$row"
        [[ "$account" =~ ^[0-9]{12}$ && -n "$region" ]] || continue
        [[ -z "$profile" || "$name" == "$profile" ]] || continue
        [[ "$(normalize_environment "$saved_env")" == "$environment" ]] || continue
        [[ -z "$region_filter" || "$region" == "$region_filter" ]] || continue
        candidates+=("$region $name")
    done <<< "$profiles"
    [[ ${#candidates[@]} -gt 0 ]] || { block 'No saved profile matches the requested environment/profile/region.'; return 1; }
    # Regional profile names are arbitrary: select by saved environment and region.
    # Without a requested region, use the lexically first region, not the active profile.
    selected_region=$(printf '%s\n' "${candidates[@]}" | LC_ALL=C sort)
    selected_region=${selected_region%%$'\n'*}
    selected_region=${selected_region%% *}
    local matching_profiles=()
    for row in "${candidates[@]}"; do
        [[ "${row%% *}" == "$selected_region" ]] && matching_profiles+=("${row#* }")
    done
    candidates=("${matching_profiles[@]}")
    [[ ${#candidates[@]} -eq 1 ]] || {
        block "Multiple profiles match region $selected_region. Select --profile NAME; do not use-profile or edit configuration."
        return 1
    }
    profile=${candidates[0]}
    printf 'PROFILE=%s\n' "$profile"
    # config get reads SAVED values. Compare runtime overrides explicitly; never print them.
    while read -r variable; do
        [[ "$variable" == ROSA_BOUNDARY_* ]] || continue
        key=$(printf '%s' "${variable#ROSA_BOUNDARY_}" | tr '[:upper:]' '[:lower:]')
        case "$key" in
            account_id | environment | project | aws_region | keycloak_url | keycloak_realm | ocm_url | oidc_client_id | oidc_use_device_code | lambda_function_name | invoker_role_arn | sre_role_arn | ecs_cluster_name | efs_filesystem_id)
                saved=$("$cli" --profile "$profile" config get "$key") || return 1
                [[ "${!variable}" == "$saved" ]] || {
                    block "Conflicting $variable override (value omitted); resolve separately and rerun."
                    return 1
                }
                ;;
            *) block "Unrecognized $variable override (value omitted); review separately."; return 1 ;;
        esac
    done < <(compgen -e)
    for key in account_id environment aws_region ocm_url keycloak_url keycloak_realm oidc_client_id lambda_function_name invoker_role_arn sre_role_arn ecs_cluster_name efs_filesystem_id; do
        value=$("$cli" --profile "$profile" config get "$key") || {
            block "Cannot read saved $key"; return 1;
        }
        [[ -n "$value" ]] || { block "Saved $key is missing; configuration repair is a separate task."; return 1; }
        case "$key" in
            account_id)
                [[ "$value" =~ ^[0-9]{12}$ ]] || { block 'Invalid saved account_id'; return 1; }
                printf 'ACCOUNT=%s\n' "$value"
                ;;
            environment)
                [[ "$(normalize_environment "$value")" == "$environment" ]] || { block 'Saved environment mismatch'; return 1; }
                ;;
            aws_region) printf 'REGION=%s\n' "$value" ;;
            ocm_url)
                case "$value" in
                    https://api.openshift.com | https://api.stage.openshift.com | https://api.integration.openshift.com) ;;
                    *) block 'Saved ocm_url is not a canonical supported OCM URL.'; return 1 ;;
                esac
                printf 'OCM=%s\n' "$value"
                ;;
        esac
    done
    help_text=$("$cli" investigation close --help) || return 1
    [[ "$help_text" == *"--status"* && "$help_text" == *"--dry-run"* && "$help_text" == *"--yes"* ]] || {
        block 'Installed CLI does not support the required asynchronous close flags (--status, --dry-run, --yes). Stop here. Use `make install-cli` to install the CLI from a local checkout, then rerun preflight.'
        return 1
    }
    help_text=$("$cli" session join --help) || return 1
    [[ "$help_text" == *"--command"* ]] || {
        block 'Installed CLI does not support the expected session join flags. Stop here. Use `make install-cli` to install the CLI from a local checkout, then rerun preflight.'
        return 1
    }
    printf 'PREFLIGHT=passed\nLocal checks only. Confirm the resolved account/region and approval; authentication, terminal interaction and deployed service compatibility remain live checks.\n'
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
