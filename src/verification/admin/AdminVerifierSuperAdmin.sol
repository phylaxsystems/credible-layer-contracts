// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Ownable} from "solady/auth/Ownable.sol";
import {IAdminVerifier} from "../../interfaces/IAdminVerifier.sol";

/// @title AdminVerifierSuperAdmin
/// @notice Test-only admin verifier that accepts a single super admin address.
/// @dev WARNING: This component is intended strictly for internal testing. The configured
/// owner is treated as the verified admin for every assertion adopter. Deploying this
/// contract in production would grant a single address full control over all adopters.
contract AdminVerifierSuperAdmin is Ownable, IAdminVerifier {
    constructor(address superAdmin) {
        _initializeOwner(superAdmin);
    }

    /// @inheritdoc IAdminVerifier
    /// @notice Returns true when the requester is the contract owner (super admin).
    function verifyAdmin(address, address requester, bytes calldata) external view returns (bool) {
        return requester == owner();
    }
}
