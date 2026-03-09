// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IDAVerifier} from "../interfaces/IDAVerifier.sol";

/// @title DAVerifierRegistry
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Manages the registration of DA verifiers
library DAVerifierRegistry {
    /// @notice Thrown when attempting to add a DA verifier that is already registered
    error DAVerifierAlreadyRegistered();
    /// @notice Thrown when attempting to remove an unregistered DA verifier
    error DAVerifierNotRegistered();

    /// @notice Emitted when a DA verifier is added
    /// @param daVerifier The DA verifier that was added
    event DAVerifierAdded(IDAVerifier daVerifier);

    /// @notice Emitted when a DA verifier is removed
    /// @param daVerifier The DA verifier that was removed
    event DAVerifierRemoved(IDAVerifier daVerifier);

    /// @notice Checks if a DA verifier is registered
    /// @param daVerifiers The mapping of DA verifiers to their registration status
    /// @param daVerifier The DA verifier to check
    /// @return isRegistered True if the DA verifier is registered, false otherwise
    function isRegistered(mapping(IDAVerifier => bool) storage daVerifiers, IDAVerifier daVerifier)
        internal
        view
        returns (bool)
    {
        return daVerifiers[daVerifier];
    }

    /// @notice Adds a DA verifier to the registry
    /// @param daVerifiers The mapping of DA verifiers to their registration status
    /// @param daVerifier The DA verifier to add
    /// @dev Throws an error if the DA verifier is already registered
    function add(mapping(IDAVerifier => bool) storage daVerifiers, IDAVerifier daVerifier) internal {
        require(!isRegistered(daVerifiers, daVerifier), DAVerifierAlreadyRegistered());
        daVerifiers[daVerifier] = true;
        emit DAVerifierAdded(daVerifier);
    }

    /// @notice Removes a DA verifier from the registry
    /// @param daVerifiers The mapping of DA verifiers to their registration status
    /// @param daVerifier The DA verifier to remove
    /// @dev Throws an error if the DA verifier is not registered
    function remove(mapping(IDAVerifier => bool) storage daVerifiers, IDAVerifier daVerifier) internal {
        require(isRegistered(daVerifiers, daVerifier), DAVerifierNotRegistered());
        daVerifiers[daVerifier] = false;
        emit DAVerifierRemoved(daVerifier);
    }
}
