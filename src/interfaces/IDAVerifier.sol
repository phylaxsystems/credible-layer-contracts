// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

interface IDAVerifier {
    /// @notice Error thrown when a proof is invalid
    error InvalidProof();

    /// @notice Verifies a data availability proof for an assertion
    /// @param assertionId The unique identifier of the assertion
    /// @param metadata The metadata of the assertion, needed to verify the proof
    /// @param proof The proof proving data availability
    /// @return verified True if the proof is valid, false otherwise
    function verifyDA(bytes32 assertionId, bytes calldata metadata, bytes calldata proof)
        external
        view
        returns (bool verified);
}
