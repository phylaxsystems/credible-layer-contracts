// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

interface ITriggerManifestValidator {
    /// @notice Authenticates and validates a trigger manifest, then returns its accounting.
    /// @param deploymentCodeHash Hash of the final assertion creation payload.
    /// @param schemaId Schema selected by the StateOracle registry.
    /// @param data Canonically encoded trigger manifest.
    /// @param proof Schema-specific evidence binding the manifest to the deployment payload.
    function validate(bytes32 deploymentCodeHash, bytes32 schemaId, bytes calldata data, bytes calldata proof)
        external
        view
        returns (uint32 triggerCount, uint64 triggerUnits);
}
