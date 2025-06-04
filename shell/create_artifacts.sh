#!/usr/bin/env bash

# Pre-requisites:
# - foundry (https://getfoundry.sh)
# - jq (for JSON processing)

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# Get the root directory of the project (one level up from shell directory)
ROOT_DIR="$(cd "$SCRIPT_DIR/.." &>/dev/null && pwd)"

# Strict mode: https://gist.github.com/vncsna/64825d5609c146e80de8b1fd623011ca
set -euo pipefail

# Function to extract ABI
extract_abi() {
  local source_file=$1
  local target_dir=$2
  local output_name=${3:-$(basename "$source_file")}

  jq '.abi' "$source_file" >"$target_dir/$output_name"
  echo "Extracted ABI to $target_dir/$output_name"
}

# Change to the root directory before running forge
cd "$ROOT_DIR"

# Generate the artifacts with Forge
forge build

# Delete the current artifacts
ARTIFACTS="$ROOT_DIR/artifacts"
rm -rf "$ARTIFACTS"

# Create the new artifacts directories
mkdir -p "$ARTIFACTS" \
  "$ARTIFACTS/interfaces" \
  "$ARTIFACTS/libraries"

# Extract ABIs for main contracts
extract_abi "$ROOT_DIR/out/StateOracle.sol/StateOracle.json" "${ARTIFACTS}"
extract_abi "$ROOT_DIR/out/AdminVerifierOwner.sol/AdminVerifierOwner.json" "${ARTIFACTS}"
extract_abi "$ROOT_DIR/out/DAVerifierECDSA.sol/DAVerifierECDSA.json" "${ARTIFACTS}"

# Extract ABIs for interfaces
INTERFACES="${ARTIFACTS}/interfaces"
extract_abi "$ROOT_DIR/out/IBatch.sol/IBatch.json" "${INTERFACES}"
extract_abi "$ROOT_DIR/out/IDAVerifier.sol/IDAVerifier.json" "${INTERFACES}"
extract_abi "$ROOT_DIR/out/IAdminVerifier.sol/IAdminVerifier.json" "${INTERFACES}"

# Extract ABIs for libraries
LIBRARIES="${ARTIFACTS}/libraries"
extract_abi "$ROOT_DIR/out/AdminVerifierRegistry.sol/AdminVerifierRegistry.json" "${LIBRARIES}"
