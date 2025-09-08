// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

import {IAdminVerifier} from "../interfaces/IAdminVerifier.sol";

/// @title AdminVerifierRegistry
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Manages the registration of admin verifiers
library AdminVerifierRegistry {
    /// @notice Thrown when attempting to add an admin verifier that is already registered
    error AdminVerifierAlreadyRegistered();
    /// @notice Thrown when attempting to remove an unregistered admin verifier
    error AdminVerifierNotRegistered();

    /// @notice Emitted when an admin verifier is added
    /// @param adminVerifier The admin verifier that was added
    event AdminVerifierAdded(IAdminVerifier adminVerifier);

    /// @notice Emitted when an admin verifier is removed
    /// @param adminVerifier The admin verifier that was removed
    event AdminVerifierRemoved(IAdminVerifier adminVerifier);

    /// @notice Checks if an admin verifier is registered
    /// @param adminVerifiers The mapping of admin verifiers to their registration status
    /// @param adminVerifier The admin verifier to check
    /// @return isRegistered True if the admin verifier is registered, false otherwise
    function isRegistered(mapping(IAdminVerifier => bool) storage adminVerifiers, IAdminVerifier adminVerifier)
        internal
        view
        returns (bool)
    {
        return adminVerifiers[adminVerifier];
    }

    /// @notice Adds an admin verifier to the registry
    /// @param adminVerifiers The mapping of admin verifiers to their registration status
    /// @param adminVerifier The admin verifier to add
    /// @dev Throws an error if the admin verifier is already registered
    function add(mapping(IAdminVerifier => bool) storage adminVerifiers, IAdminVerifier adminVerifier) internal {
        if (!isRegistered(adminVerifiers, adminVerifier)) revert AdminVerifierAlreadyRegistered();
        adminVerifiers[adminVerifier] = true;
        emit AdminVerifierAdded(adminVerifier);
    }

    /// @notice Removes an admin verifier from the registry
    /// @param adminVerifiers The mapping of admin verifiers to their registration status
    /// @param adminVerifier The admin verifier to remove
    /// @dev Throws an error if the admin verifier is not registered
    function remove(mapping(IAdminVerifier => bool) storage adminVerifiers, IAdminVerifier adminVerifier) internal {
        if (!isRegistered(adminVerifiers, adminVerifier)) revert AdminVerifierNotRegistered();
        adminVerifiers[adminVerifier] = false;
        emit AdminVerifierRemoved(adminVerifier);
    }
}
