// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAdminVerifier} from "../../interfaces/IAdminVerifier.sol";

/// @title AdminVerifierAlwaysApprove
/// @notice Test-only admin verifier that accepts every requester for every assertion adopter.
/// @dev WARNING: This component is intended strictly for internal testing. Deploying this
/// contract in production would allow any address to register as manager for any adopter.
contract AdminVerifierAlwaysApprove is IAdminVerifier {
    /// @inheritdoc IAdminVerifier
    /// @notice Always returns true.
    function verifyAdmin(address, address, bytes calldata) external pure returns (bool) {
        return true;
    }
}
