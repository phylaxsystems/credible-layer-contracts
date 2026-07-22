#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PASSWORD_FILE=""
FORGE_OUTPUT_FILE=""
CURSOR_HIDDEN=false
COLOR_RESET=""
COLOR_BOLD=""
COLOR_DIM=""
COLOR_RED=""
COLOR_GREEN=""
COLOR_YELLOW=""
COLOR_BLUE=""
COLOR_MAGENTA=""
COLOR_CYAN=""

cleanup() {
    if [[ "$CURSOR_HIDDEN" == "true" ]]; then
        { printf '\033[?25h' >/dev/tty; } 2>/dev/null || true
    fi
    if [[ -n "$PASSWORD_FILE" && -f "$PASSWORD_FILE" ]]; then
        rm -f "$PASSWORD_FILE"
    fi
    if [[ -n "$FORGE_OUTPUT_FILE" && -f "$FORGE_OUTPUT_FILE" ]]; then
        rm -f "$FORGE_OUTPUT_FILE"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

usage() {
    cat <<'EOF'
Usage: ./shell/deploy_wizard.sh

Interactively configures and deploys the Credible Layer contracts. Use the
arrow keys to move, Space to toggle multi-select entries, and Enter to accept.

The wizard reads existing values from these variables as prompt defaults:
  RPC_URL or ETH_RPC_URL
  ETHERSCAN_API_KEY
  STATE_ORACLE_MAX_ASSERTIONS_PER_AA
  STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS
  STATE_ORACLE_ADMIN_ADDRESS
  STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA
  STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS
  DA_PROVER_ADDRESS
  ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS
  TEST_ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS
EOF
}

die() {
    printf '%sError:%s %s\n' "${COLOR_BOLD}${COLOR_RED}" "$COLOR_RESET" "$*" >&2
    exit 1
}

init_colors() {
    if [[ -n ${NO_COLOR+x} || ${TERM:-} == "dumb" ]]; then
        return
    fi

    COLOR_RESET=$'\033[0m'
    COLOR_BOLD=$'\033[1m'
    COLOR_DIM=$'\033[2m'
    COLOR_RED=$'\033[31m'
    COLOR_GREEN=$'\033[32m'
    COLOR_YELLOW=$'\033[33m'
    COLOR_BLUE=$'\033[34m'
    COLOR_MAGENTA=$'\033[35m'
    COLOR_CYAN=$'\033[36m'
}

tty_print() {
    printf '%s' "$*" >/dev/tty
}

tty_println() {
    printf '%s\n' "$*" >/dev/tty
}

tty_heading() {
    tty_println "${COLOR_BOLD}${COLOR_CYAN}$*${COLOR_RESET}"
}

tty_section() {
    tty_println "${COLOR_BOLD}${COLOR_MAGENTA}$*${COLOR_RESET}"
}

tty_hint() {
    tty_println "${COLOR_DIM}$*${COLOR_RESET}"
}

tty_warn() {
    tty_println "${COLOR_BOLD}${COLOR_YELLOW}Warning:${COLOR_RESET} $*"
}

tty_success() {
    tty_println "${COLOR_BOLD}${COLOR_GREEN}$*${COLOR_RESET}"
}

tty_field() {
    local label=$1
    shift
    printf '  %s%-21s%s %s%s%s\n' \
        "$COLOR_CYAN" "${label}:" "$COLOR_RESET" "$COLOR_GREEN" "$*" "$COLOR_RESET" >/dev/tty
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

read_key() {
    local key suffix
    IFS= read -rsn1 key </dev/tty || exit 1
    if [[ "$key" == $'\033' ]]; then
        suffix=""
        IFS= read -rsn2 -t 0.2 suffix </dev/tty || true
        key="${key}${suffix}"
    fi
    KEY_RESULT="$key"
}

menu_select_one() {
    local question=$1
    shift
    local items=("$@")
    local selected=0
    local rendered=0
    local count=${#items[@]}
    local i prefix

    tty_println ""
    tty_heading "$question"
    tty_hint "  ↑/↓ move · Enter select"
    printf '\033[?25l' >/dev/tty
    CURSOR_HIDDEN=true

    while true; do
        if [[ $rendered -eq 1 ]]; then
            printf '\033[%dA' "$count" >/dev/tty
        fi
        for ((i = 0; i < count; i++)); do
            prefix="  "
            if [[ $i -eq $selected ]]; then
                prefix="${COLOR_BOLD}${COLOR_BLUE}› "
                printf '\r\033[2K%s%s%s\n' "$prefix" "${items[$i]}" "$COLOR_RESET" >/dev/tty
            else
                printf '\r\033[2K%s%s\n' "$prefix" "${items[$i]}" >/dev/tty
            fi
        done
        rendered=1

        read_key
        case "$KEY_RESULT" in
            $'\033[A')
                selected=$(((selected - 1 + count) % count))
                ;;
            $'\033[B')
                selected=$(((selected + 1) % count))
                ;;
            "")
                break
                ;;
        esac
    done

    printf '\033[?25h' >/dev/tty
    CURSOR_HIDDEN=false
    MENU_INDEX=$selected
    MENU_VALUE=${items[$selected]}
}

menu_select_many() {
    local question=$1
    shift
    local items=("$@")
    local cursor=0
    local rendered=0
    local count=${#items[@]}
    local selected_count i marker prefix

    MULTI_SELECTED=()
    for ((i = 0; i < count; i++)); do
        MULTI_SELECTED[$i]=0
    done

    tty_println ""
    tty_heading "$question"
    tty_hint "  ↑/↓ move · Space toggle · Enter continue"
    printf '\033[?25l' >/dev/tty
    CURSOR_HIDDEN=true

    while true; do
        if [[ $rendered -eq 1 ]]; then
            printf '\033[%dA' "$count" >/dev/tty
        fi
        for ((i = 0; i < count; i++)); do
            marker="[ ]"
            prefix="  "
            if [[ ${MULTI_SELECTED[$i]} -eq 1 ]]; then
                marker="${COLOR_BOLD}${COLOR_GREEN}[x]${COLOR_RESET}"
            fi
            if [[ $i -eq $cursor ]]; then
                prefix="${COLOR_BOLD}${COLOR_BLUE}› ${COLOR_RESET}"
            fi
            printf '\r\033[2K%s%s %s\n' "$prefix" "$marker" "${items[$i]}" >/dev/tty
        done
        rendered=1

        read_key
        case "$KEY_RESULT" in
            $'\033[A')
                cursor=$(((cursor - 1 + count) % count))
                ;;
            $'\033[B')
                cursor=$(((cursor + 1) % count))
                ;;
            " ")
                if [[ ${MULTI_SELECTED[$cursor]} -eq 1 ]]; then
                    MULTI_SELECTED[$cursor]=0
                else
                    MULTI_SELECTED[$cursor]=1
                fi
                ;;
            "")
                selected_count=0
                for ((i = 0; i < count; i++)); do
                    selected_count=$((selected_count + MULTI_SELECTED[i]))
                done
                if [[ $selected_count -gt 0 ]]; then
                    break
                fi
                printf '\a' >/dev/tty
                ;;
        esac
    done

    printf '\033[?25h' >/dev/tty
    CURSOR_HIDDEN=false
}

prompt_value() {
    local label=$1
    local default_value=${2:-}
    local value

    while true; do
        if [[ -n "$default_value" ]]; then
            printf '%s%s%s %s[%s]%s: ' \
                "$COLOR_BOLD" "$label" "$COLOR_RESET" "$COLOR_DIM" "$default_value" "$COLOR_RESET" >/dev/tty
        else
            printf '%s%s%s: ' "$COLOR_BOLD" "$label" "$COLOR_RESET" >/dev/tty
        fi
        IFS= read -r value </dev/tty
        if [[ -z "$value" ]]; then
            value=$default_value
        fi
        if [[ -n "$value" ]]; then
            PROMPT_RESULT=$value
            return
        fi
        tty_warn "A value is required."
    done
}

prompt_secret() {
    local label=$1
    local value
    printf '%s%s%s: ' "$COLOR_BOLD" "$label" "$COLOR_RESET" >/dev/tty
    IFS= read -rs value </dev/tty
    tty_println ""
    [[ -n "$value" ]] || return 1
    PROMPT_RESULT=$value
}

prompt_address() {
    local label=$1
    local default_value=${2:-}
    local checksum lower

    while true; do
        prompt_value "$label" "$default_value"
        if checksum=$(cast to-check-sum-address "$PROMPT_RESULT" 2>/dev/null); then
            lower=$(printf '%s' "$checksum" | tr '[:upper:]' '[:lower:]')
            if [[ "$lower" != "0x0000000000000000000000000000000000000000" ]]; then
                PROMPT_RESULT=$checksum
                return
            fi
        fi
        tty_warn "Enter a non-zero Ethereum address."
    done
}

decimal_le() {
    local value=$1
    local maximum=$2

    value=$(printf '%s' "$value" | sed 's/^0*//')
    [[ -n "$value" ]] || value=0
    if [[ ${#value} -lt ${#maximum} ]]; then
        return 0
    fi
    if [[ ${#value} -gt ${#maximum} ]]; then
        return 1
    fi
    [[ "$value" == "$maximum" || "$value" < "$maximum" ]]
}

prompt_uint() {
    local label=$1
    local default_value=$2
    local maximum=$3

    while true; do
        prompt_value "$label" "$default_value"
        if [[ "$PROMPT_RESULT" =~ ^[0-9]+$ ]] && [[ "$PROMPT_RESULT" != "0" ]] \
            && decimal_le "$PROMPT_RESULT" "$maximum"; then
            PROMPT_RESULT=$(printf '%s' "$PROMPT_RESULT" | sed 's/^0*//')
            [[ -n "$PROMPT_RESULT" ]] || PROMPT_RESULT=0
            return
        fi
        tty_warn "Enter an integer from 1 through $maximum."
    done
}

bool_for_selection() {
    if [[ $1 -eq 1 ]]; then
        printf 'true'
    else
        printf 'false'
    fi
}

join_by_comma() {
    local joined=""
    local value
    for value in "$@"; do
        if [[ -n "$joined" ]]; then
            joined="${joined},${value}"
        else
            joined=$value
        fi
    done
    printf '%s' "$joined"
}

print_redacted_command() {
    local item redact_next=false
    tty_println ""
    tty_section "Wallet password validation command"
    printf '  cast wallet address --account %q --password-file <temporary-password-file>\n' "$wallet_account" >/dev/tty
    tty_println ""
    tty_section "Forge deployment command"
    tty_println "  env \\"
    for item in "${env_unset_args[@]}"; do
        printf '    %q \\\n' "$item" >/dev/tty
    done
    for item in "${env_args[@]}"; do
        case "$item" in
            ETH_RPC_URL=*) item='ETH_RPC_URL=<configured>' ;;
            ETHERSCAN_API_KEY=*) item='ETHERSCAN_API_KEY=<configured>' ;;
        esac
        printf '    %q \\\n' "$item" >/dev/tty
    done
    tty_print "    forge"
    for item in "${forge_args[@]}"; do
        if [[ "$redact_next" == "true" ]]; then
            item='<configured>'
            redact_next=false
        elif [[ "$item" == "--rpc-url" ]]; then
            redact_next=true
        elif [[ "$item" == "$PASSWORD_FILE" ]]; then
            item='<temporary-password-file>'
        fi
        printf ' %q' "$item" >/dev/tty
    done
    tty_println ""
}

lookup_transaction() {
    local broadcast_file=$1
    local address=$2
    jq -r --arg address "$address" '
        [.transactions[]
          | select(
              ((.contractAddress // "") | ascii_downcase) == ($address | ascii_downcase)
              or any(
                  .additionalContracts[]?;
                  ((.address // "") | ascii_downcase) == ($address | ascii_downcase)
              )
            )]
        | last
        | .hash // empty
    ' "$broadcast_file"
}

lookup_block_hex() {
    local broadcast_file=$1
    local transaction_hash=$2
    jq -r --arg hash "$transaction_hash" '
        [.receipts[] | select((.transactionHash // "") == $hash)]
        | last
        | .blockNumber // empty
    ' "$broadcast_file"
}

print_deployment_summary() {
    local broadcast_file=$1
    local deployments label address transaction_hash block_hex block_number proxy_admin

    deployments=$(sed -nE \
        's/^.*WIZARD_DEPLOYMENT\|([^|]+)\|[[:space:]]*(0x[[:xdigit:]]{40}).*$/\1|\2/p' \
        "$FORGE_OUTPUT_FILE" | awk -F'|' '!seen[$1 "|" tolower($2)]++')

    tty_println ""
    tty_success "Deployment complete"
    tty_field "Chain ID" "$chain_id"
    tty_field "Deployer" "$wallet_address ($wallet_account)"
    tty_field "Broadcast data" "$broadcast_file"
    tty_println ""

    if [[ -z "$deployments" ]]; then
        tty_warn "Foundry completed, but no deployment markers were found in its output."
        return
    fi

    while IFS='|' read -r label address; do
        transaction_hash=$(lookup_transaction "$broadcast_file" "$address")
        block_hex=""
        block_number="unknown"
        if [[ -n "$transaction_hash" ]]; then
            block_hex=$(lookup_block_hex "$broadcast_file" "$transaction_hash")
            if [[ -n "$block_hex" ]]; then
                block_number=$(printf '%d' "$block_hex")
            fi
        else
            transaction_hash="unknown"
        fi

        tty_section "$label"
        tty_field "Address" "$address"
        tty_field "Block" "$block_number"
        tty_field "Transaction" "$transaction_hash"

        case "$label" in
            *"State Oracle Proxy")
                proxy_admin=$(jq -r --arg hash "$transaction_hash" '
                    .transactions[]
                    | select((.hash // "") == $hash)
                    | .additionalContracts[]?
                    | select(.contractName == "ProxyAdmin")
                    | .address
                ' "$broadcast_file" | tail -n 1)
                if [[ -n "$proxy_admin" ]]; then
                    tty_field "Proxy admin" "$proxy_admin (same block and transaction)"
                fi
                ;;
        esac
        tty_println ""
    done <<EOF
$deployments
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
    usage
    exit 0
fi
[[ $# -eq 0 ]] || die "Unknown argument: $1"
if ! { : </dev/tty; } 2>/dev/null || ! { : >/dev/tty; } 2>/dev/null; then
    die "This wizard requires an interactive terminal"
fi

init_colors
require_command forge
require_command cast
require_command jq

cd "$ROOT_DIR"

tty_heading "Credible Layer deployment wizard"
tty_hint "================================"

menu_select_one "What kind of deployment is this?" "Production" "Testing"
deployment_kind=$MENU_VALUE
deployment_is_testing=false
if [[ "$deployment_kind" == "Testing" ]]; then
    deployment_is_testing=true
fi

menu_select_one "Deploy a staging State Oracle as well?" "No" "Yes"
deploy_staging=false
if [[ "$MENU_VALUE" == "Yes" ]]; then
    deploy_staging=true
fi

admin_options=("Owner" "Whitelist")
if [[ "$deployment_is_testing" == "true" ]]; then
    admin_options[2]="Super Admin (test-only)"
    admin_options[3]="Always Approve (test-only, unsafe)"
fi
menu_select_many "Which admin verifiers should be deployed?" "${admin_options[@]}"
admin_selected=("${MULTI_SELECTED[@]}")

admin_production=(0 0 0 0)
admin_staging=(0 0 0 0)
while true; do
    admin_production=(0 0 0 0)
    admin_staging=(0 0 0 0)
    for ((i = 0; i < ${#admin_options[@]}; i++)); do
        [[ ${admin_selected[$i]} -eq 1 ]] || continue
        if [[ "$deploy_staging" == "true" ]]; then
            menu_select_many "Add ${admin_options[$i]} to which State Oracle(s)?" "Production" "Staging"
            admin_production[$i]=${MULTI_SELECTED[0]}
            admin_staging[$i]=${MULTI_SELECTED[1]}
        else
            menu_select_many "Add ${admin_options[$i]} to which State Oracle(s)?" "Production"
            admin_production[$i]=${MULTI_SELECTED[0]}
        fi
    done

    production_count=0
    staging_count=0
    for ((i = 0; i < ${#admin_options[@]}; i++)); do
        production_count=$((production_count + admin_production[i]))
        staging_count=$((staging_count + admin_staging[i]))
    done
    if [[ $production_count -gt 0 ]] && { [[ "$deploy_staging" == "false" ]] || [[ $staging_count -gt 0 ]]; }; then
        break
    fi
    tty_warn "Each State Oracle needs at least one admin verifier. Please assign them again."
done

da_options=("ECDSA signatures" "On-chain bytecode")
menu_select_many "Which DA verifiers should be deployed?" "${da_options[@]}"
da_selected=("${MULTI_SELECTED[@]}")

da_production=(0 0)
da_staging=(0 0)
while true; do
    da_production=(0 0)
    da_staging=(0 0)
    for ((i = 0; i < ${#da_options[@]}; i++)); do
        [[ ${da_selected[$i]} -eq 1 ]] || continue
        if [[ "$deploy_staging" == "true" ]]; then
            menu_select_many "Add ${da_options[$i]} to which State Oracle(s)?" "Production" "Staging"
            da_production[$i]=${MULTI_SELECTED[0]}
            da_staging[$i]=${MULTI_SELECTED[1]}
        else
            menu_select_many "Add ${da_options[$i]} to which State Oracle(s)?" "Production"
            da_production[$i]=${MULTI_SELECTED[0]}
        fi
    done

    production_count=$((da_production[0] + da_production[1]))
    staging_count=$((da_staging[0] + da_staging[1]))
    if [[ $production_count -gt 0 ]] && { [[ "$deploy_staging" == "false" ]] || [[ $staging_count -gt 0 ]]; }; then
        break
    fi
    tty_warn "Each State Oracle needs at least one DA verifier. Please assign them again."
done

menu_select_one "Should the State Oracle whitelist be enabled?" "Enabled" "Disabled"
whitelist_enabled=true
if [[ "$MENU_VALUE" == "Disabled" ]]; then
    whitelist_enabled=false
fi

whitelist_addresses=()
if [[ "$whitelist_enabled" == "true" ]]; then
    menu_select_one "Add addresses to the initial whitelist?" "No" "Yes"
    if [[ "$MENU_VALUE" == "Yes" ]]; then
        while true; do
            prompt_address "Address to whitelist" ""
            candidate=$PROMPT_RESULT
            duplicate=false
            for existing in "${whitelist_addresses[@]-}"; do
                if [[ "$(printf '%s' "$existing" | tr '[:upper:]' '[:lower:]')" \
                    == "$(printf '%s' "$candidate" | tr '[:upper:]' '[:lower:]')" ]]; then
                    duplicate=true
                fi
            done
            if [[ "$duplicate" == "true" ]]; then
                tty_warn "That address is already in the initial whitelist."
            else
                whitelist_addresses[${#whitelist_addresses[@]}]=$candidate
            fi

            menu_select_one "Initial whitelist now contains ${#whitelist_addresses[@]} address(es)." \
                "Add another address" "Done"
            [[ "$MENU_VALUE" == "Add another address" ]] || break
        done
    fi
fi

menu_select_one "Verify deployed contracts on the block explorer?" "Yes" "No"
verify_contracts=false
etherscan_api_key=""
if [[ "$MENU_VALUE" == "Yes" ]]; then
    verify_contracts=true
    etherscan_api_key=${ETHERSCAN_API_KEY:-}
    if [[ -z "$etherscan_api_key" ]]; then
        while ! prompt_secret "ETHERSCAN_API_KEY"; do
            tty_warn "An API key is required when verification is enabled."
        done
        etherscan_api_key=$PROMPT_RESULT
        PROMPT_RESULT=""
    else
        tty_success "Using the non-empty ETHERSCAN_API_KEY from the environment."
    fi
fi

default_rpc=${RPC_URL:-${ETH_RPC_URL:-}}
while true; do
    prompt_value "RPC URL" "$default_rpc"
    rpc_url=$PROMPT_RESULT
    if chain_id=$(cast chain-id --rpc-url "$rpc_url" 2>/dev/null); then
        break
    fi
    tty_warn "Could not connect to that RPC URL."
done
tty_success "Connected to chain ID $chain_id."

prompt_uint "Maximum assertions per adopter" "${STATE_ORACLE_MAX_ASSERTIONS_PER_AA:-}" "65535"
max_assertions=$PROMPT_RESULT
prompt_uint "Assertion timelock in blocks" "${STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS:-}" \
    "115792089237316195423570985008687907853269984665640564039457584007913129639935"
assertion_timelock=$PROMPT_RESULT
prompt_address "State Oracle admin" "${STATE_ORACLE_ADMIN_ADDRESS:-}"
state_oracle_admin=$PROMPT_RESULT

staging_max_assertions=""
staging_assertion_timelock=""
if [[ "$deploy_staging" == "true" ]]; then
    prompt_uint "Staging maximum assertions per adopter" \
        "${STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA:-}" "65535"
    staging_max_assertions=$PROMPT_RESULT
    prompt_uint "Staging assertion timelock in blocks" \
        "${STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS:-}" \
        "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    staging_assertion_timelock=$PROMPT_RESULT
fi

da_prover=""
if [[ ${da_selected[0]} -eq 1 ]]; then
    prompt_address "DA prover address" "${DA_PROVER_ADDRESS:-}"
    da_prover=$PROMPT_RESULT
fi

admin_verifier_whitelist_admin=""
if [[ ${admin_selected[1]} -eq 1 ]]; then
    prompt_address "Admin Verifier Whitelist owner" "${ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS:-}"
    admin_verifier_whitelist_admin=$PROMPT_RESULT
fi

test_super_admin=""
if [[ ${admin_selected[2]:-0} -eq 1 ]]; then
    prompt_address "Testing Super Admin address" "${TEST_ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS:-}"
    test_super_admin=$PROMPT_RESULT
fi

wallet_output=$(cast wallet list 2>/dev/null) || die "Unable to list Foundry keystore accounts"
wallet_names=()
wallet_labels=()
while IFS= read -r wallet_line; do
    [[ -n "$wallet_line" ]] || continue
    wallet_labels[${#wallet_labels[@]}]=$wallet_line
    wallet_names[${#wallet_names[@]}]=${wallet_line%% (*}
done <<EOF
$wallet_output
EOF
[[ ${#wallet_names[@]} -gt 0 ]] || die "No accounts found in the Foundry keystore"

menu_select_one "Which Foundry wallet should deploy the contracts?" "${wallet_labels[@]}"
wallet_account=${wallet_names[$MENU_INDEX]}

while true; do
    while ! prompt_secret "Password for $wallet_account"; do
        tty_warn "A password is required."
    done
    wallet_password=$PROMPT_RESULT
    PROMPT_RESULT=""

    PASSWORD_FILE=$(mktemp "${TMPDIR:-/tmp}/credible-layer-wallet.XXXXXX")
    chmod 600 "$PASSWORD_FILE"
    printf '%s' "$wallet_password" >"$PASSWORD_FILE"
    wallet_password=""

    if wallet_address=$(cast wallet address --account "$wallet_account" --password-file "$PASSWORD_FILE" 2>/dev/null); then
        break
    fi

    rm -f "$PASSWORD_FILE"
    PASSWORD_FILE=""
    tty_warn "That password did not unlock $wallet_account. Try again."
done

if ! wallet_balance_wei=$(cast balance "$wallet_address" --rpc-url "$rpc_url" 2>/dev/null); then
    die "Unable to read the balance for $wallet_address on chain $chain_id"
fi
if [[ ! "$wallet_balance_wei" =~ ^[0-9]+$ ]]; then
    die "Received an invalid balance for $wallet_address on chain $chain_id"
fi
if [[ "$wallet_balance_wei" =~ ^0+$ ]]; then
    die "Selected wallet $wallet_address has no funds on chain $chain_id. Fund it before deploying."
fi

wallet_balance=$(cast balance --ether "$wallet_address" --rpc-url "$rpc_url" 2>/dev/null || printf 'unknown')
wallet_nonce=$(cast nonce "$wallet_address" --rpc-url "$rpc_url" 2>/dev/null || printf 'unknown')
tty_success "Wallet unlocked successfully: $wallet_address"

env_args=(
    "ETH_RPC_URL=$rpc_url"
    "DEPLOYMENT_IS_TESTING=$deployment_is_testing"
    "DEPLOY_STAGING_STATE_ORACLE=$deploy_staging"
    "STATE_ORACLE_WHITELIST_ENABLED=$whitelist_enabled"
    "STATE_ORACLE_MAX_ASSERTIONS_PER_AA=$max_assertions"
    "STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS=$assertion_timelock"
    "STATE_ORACLE_ADMIN_ADDRESS=$state_oracle_admin"
    "DA_VERIFIER_ECDSA_PRODUCTION=$(bool_for_selection "${da_production[0]}")"
    "DA_VERIFIER_ECDSA_STAGING=$(bool_for_selection "${da_staging[0]}")"
    "DA_VERIFIER_ONCHAIN_PRODUCTION=$(bool_for_selection "${da_production[1]}")"
    "DA_VERIFIER_ONCHAIN_STAGING=$(bool_for_selection "${da_staging[1]}")"
    "ADMIN_VERIFIER_OWNER_PRODUCTION=$(bool_for_selection "${admin_production[0]}")"
    "ADMIN_VERIFIER_OWNER_STAGING=$(bool_for_selection "${admin_staging[0]}")"
    "ADMIN_VERIFIER_WHITELIST_PRODUCTION=$(bool_for_selection "${admin_production[1]}")"
    "ADMIN_VERIFIER_WHITELIST_STAGING=$(bool_for_selection "${admin_staging[1]}")"
    "ADMIN_VERIFIER_SUPER_ADMIN_PRODUCTION=$(bool_for_selection "${admin_production[2]}")"
    "ADMIN_VERIFIER_SUPER_ADMIN_STAGING=$(bool_for_selection "${admin_staging[2]}")"
    "ADMIN_VERIFIER_ALWAYS_APPROVE_PRODUCTION=$(bool_for_selection "${admin_production[3]}")"
    "ADMIN_VERIFIER_ALWAYS_APPROVE_STAGING=$(bool_for_selection "${admin_staging[3]}")"
)
env_unset_args=(-u STATE_ORACLE_INITIAL_WHITELIST)

if [[ "$deploy_staging" == "true" ]]; then
    env_args[${#env_args[@]}]="STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA=$staging_max_assertions"
    env_args[${#env_args[@]}]="STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS=$staging_assertion_timelock"
fi
if [[ -n "$da_prover" ]]; then
    env_args[${#env_args[@]}]="DA_PROVER_ADDRESS=$da_prover"
fi
if [[ -n "$admin_verifier_whitelist_admin" ]]; then
    env_args[${#env_args[@]}]="ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS=$admin_verifier_whitelist_admin"
fi
if [[ -n "$test_super_admin" ]]; then
    env_args[${#env_args[@]}]="TEST_ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS=$test_super_admin"
fi
if [[ ${#whitelist_addresses[@]} -gt 0 ]]; then
    whitelist_csv=$(join_by_comma "${whitelist_addresses[@]}")
    env_args[${#env_args[@]}]="STATE_ORACLE_INITIAL_WHITELIST=$whitelist_csv"
fi
if [[ "$verify_contracts" == "true" ]]; then
    env_args[${#env_args[@]}]="ETHERSCAN_API_KEY=$etherscan_api_key"
fi

forge_args=(
    script
    "script/DeployWizard.s.sol:DeployWizard"
    --rpc-url "$rpc_url"
    --account "$wallet_account"
    --sender "$wallet_address"
    --password-file "$PASSWORD_FILE"
    --broadcast
)
if [[ "$verify_contracts" == "true" ]]; then
    forge_args[${#forge_args[@]}]=--verify
fi

production_admin_summary=""
staging_admin_summary=""
for ((i = 0; i < ${#admin_options[@]}; i++)); do
    if [[ ${admin_production[$i]} -eq 1 ]]; then
        production_admin_summary="${production_admin_summary}${production_admin_summary:+, }${admin_options[$i]}"
    fi
    if [[ ${admin_staging[$i]} -eq 1 ]]; then
        staging_admin_summary="${staging_admin_summary}${staging_admin_summary:+, }${admin_options[$i]}"
    fi
done
production_da_summary=""
staging_da_summary=""
for ((i = 0; i < ${#da_options[@]}; i++)); do
    if [[ ${da_production[$i]} -eq 1 ]]; then
        production_da_summary="${production_da_summary}${production_da_summary:+, }${da_options[$i]}"
    fi
    if [[ ${da_staging[$i]} -eq 1 ]]; then
        staging_da_summary="${staging_da_summary}${staging_da_summary:+, }${da_options[$i]}"
    fi
done

tty_println ""
tty_section "Deployment summary"
tty_field "Kind" "$deployment_kind"
tty_field "Chain ID" "$chain_id"
tty_field "Wallet" "$wallet_account ($wallet_address)"
tty_field "Wallet balance" "$wallet_balance ETH"
tty_field "Wallet nonce" "$wallet_nonce"
tty_field "State Oracle admin" "$state_oracle_admin"
tty_field "Staging oracle" "$deploy_staging"
tty_field "Whitelist enabled" "$whitelist_enabled"
tty_field "Verify contracts" "$verify_contracts"
tty_field "Production limits" "$max_assertions assertions, $assertion_timelock blocks"
tty_field "Production admin" "$production_admin_summary"
tty_field "Production DA" "$production_da_summary"
if [[ "$deploy_staging" == "true" ]]; then
    tty_field "Staging limits" "$staging_max_assertions assertions, $staging_assertion_timelock blocks"
    tty_field "Staging admin" "$staging_admin_summary"
    tty_field "Staging DA" "$staging_da_summary"
fi
if [[ -n "$da_prover" ]]; then
    tty_field "DA prover" "$da_prover"
fi
if [[ -n "$admin_verifier_whitelist_admin" ]]; then
    tty_field "Verifier WL owner" "$admin_verifier_whitelist_admin"
fi
if [[ -n "$test_super_admin" ]]; then
    tty_field "Test super admin" "$test_super_admin"
fi
if [[ ${#whitelist_addresses[@]} -gt 0 ]]; then
    tty_field "Initial whitelist" "$(join_by_comma "${whitelist_addresses[@]}")"
fi
if [[ "$deployment_kind" == "Production" ]]; then
    tty_println ""
    tty_warn "Production deployment selected. Confirm the chain, admin, and wallet carefully."
fi

print_redacted_command

menu_select_one "Ready to continue?" "Deploy now" "Print command only" "Cancel"
case "$MENU_VALUE" in
    "Print command only")
        tty_success "No transactions were sent."
        exit 0
        ;;
    "Cancel")
        tty_warn "Deployment cancelled."
        exit 0
        ;;
esac

FORGE_OUTPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/credible-layer-forge.XXXXXX")
set +e
env "${env_unset_args[@]}" "${env_args[@]}" forge "${forge_args[@]}" 2>&1 | tee "$FORGE_OUTPUT_FILE"
forge_status=${PIPESTATUS[0]}
set -e
[[ $forge_status -eq 0 ]] || die "Forge deployment failed with status $forge_status"

broadcast_file="$ROOT_DIR/broadcast/DeployWizard.s.sol/$chain_id/run-latest.json"
[[ -f "$broadcast_file" ]] || die "Deployment succeeded, but the broadcast receipt was not found at $broadcast_file"
print_deployment_summary "$broadcast_file"
