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

# Normalize an ABI for comparison while ignoring constructor entries and
# Solidity-only internal type annotations. Duplicate entries are collapsed
# because inherited errors can appear more than once in implementation ABIs.
normalize_public_abi() {
  jq -S '
    [.abi[]
      | select(.type != "constructor")
      | walk(if type == "object" then del(.internalType) else . end)]
    | unique
    | sort_by(.type, (.name // ""), ((.inputs // []) | tostring), ((.outputs // []) | tostring))
  ' "$1"
}

# Change to the root directory before running forge
cd "$ROOT_DIR"

# Generate the artifacts with Forge
forge build

# The versioned interface is the canonical consumer boundary used by the Rust
# crate. Refuse to publish if it drifts from the implementation surface.
if ! diff -u \
  <(normalize_public_abi "$ROOT_DIR/out/StateOracle.sol/StateOracle.json") \
  <(normalize_public_abi "$ROOT_DIR/out/IStateOracleV1.sol/IStateOracleV1.json"); then
  echo "StateOracle implementation ABI differs from IStateOracleV1" >&2
  exit 1
fi

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
extract_abi "$ROOT_DIR/out/IStateOracleV1.sol/IStateOracleV1.json" "${INTERFACES}"

# Extract ABIs for libraries
LIBRARIES="${ARTIFACTS}/libraries"
extract_abi "$ROOT_DIR/out/AdminVerifierRegistry.sol/AdminVerifierRegistry.json" "${LIBRARIES}"

# Keep the committed Rust binding input byte-for-byte aligned with the
# versioned interface ABI published to npm. This snapshot lets Cargo git
# dependencies build without Foundry or initialized submodules.
RUST_BINDINGS_ABI="${ROOT_DIR}/bindings/rust/abi"
mkdir -p "${RUST_BINDINGS_ABI}"
cp "${INTERFACES}/IStateOracleV1.json" "${RUST_BINDINGS_ABI}/IStateOracleV1.json"
echo "Synced IStateOracleV1 ABI to ${RUST_BINDINGS_ABI}/IStateOracleV1.json"
