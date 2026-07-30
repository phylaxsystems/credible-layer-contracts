// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

interface ITriggerManifestValidator {
    /// @notice Validates a trigger manifest and returns its accounting.
    /// @param schemaId Schema selected by the StateOracle registry.
    /// @param data Canonically encoded trigger manifest.
    function validate(bytes32 schemaId, bytes calldata data)
        external
        view
        returns (uint32 triggerCount, uint64 triggerUnits);
}
