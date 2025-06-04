#!/usr/bin/env bash

# Pre-requisites:
# - foundry (https://getfoundry.sh)

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# Get the root directory of the project (one level up from shell directory)
ROOT_DIR="$(cd "$SCRIPT_DIR/.." &>/dev/null && pwd)"

# Strict mode: https://gist.github.com/vncsna/64825d5609c146e80de8b1fd623011ca
set -euo pipefail

cd "${ROOT_DIR}"

cast send --private-key "${FUNDER_PRIVATE_KEY}" --rpc-url "${RPC_URL}" --value 0.5ether 0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5
cast publish "$(cat "shell/presigned-transactions/createx_deploy_tx.json")" --rpc-url "${RPC_URL}"
