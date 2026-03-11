// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IDAVerifier} from "../../interfaces/IDAVerifier.sol";

/// @title DAVerifierOnChain
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Verifies data availability by checking that keccak256(proof) equals the assertion ID
/// @dev The proof field contains the deployable bytecode itself; the hash of the bytecode must match the assertion ID
contract DAVerifierOnChain is IDAVerifier {
    /// @notice Verifies a data availability proof for an assertion
    /// @dev Returns true when keccak256(proof) matches the assertionId
    /// @dev metadata is not used for verification, but is included for compatibility with other DA verifiers
    /// @inheritdoc IDAVerifier
    function verifyDA(bytes32 assertionId, bytes calldata, bytes calldata proof) external pure returns (bool verified) {
        return keccak256(proof) == assertionId;
    }
}
