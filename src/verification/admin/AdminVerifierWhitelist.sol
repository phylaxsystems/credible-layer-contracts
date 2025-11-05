// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Ownable} from "solady/auth/Ownable.sol";
import {IAdminVerifier} from "../../interfaces/IAdminVerifier.sol";

/// @title AdminVerifierWhitelist
/// @notice Verifies administrators against an owner-managed whitelist with optional self-controlled exclusions.
contract AdminVerifierWhitelist is Ownable, IAdminVerifier {
    /// -----------------------------------------------------------------------
    /// Errors
    /// -----------------------------------------------------------------------
    error InvalidAssertionAdopter();
    error AlreadyWhitelisted();
    error AddressExcluded();
    error NotWhitelisted();
    error InvalidReleaser();
    error NoExclusion();
    error NotExclusionReleaser();

    /// @dev Maps assertion adopters to the admin address they authorize.
    mapping(address assertionAdopter => address admin) public whitelist;

    /// @dev Stores exclusion entries. Presence in the mapping means the assertion adopter is excluded from using the whitelist.
    mapping(address assertionAdopter => address releaser) public exclusions;

    event WhitelistAdded(address indexed assertionAdopter, address indexed admin);
    event WhitelistRemoved(address indexed assertionAdopter, address indexed admin);
    event ExclusionAdded(address indexed assertionAdopter, address indexed releaser);
    event ExclusionReleased(address indexed assertionAdopter);

    constructor(address admin) {
        _initializeOwner(admin);
    }

    /// @notice Adds an admin to the whitelist for a specific assertion adopter.
    /// @param assertionAdopter The address of the assertion adopter contract.
    /// @param admin The admin address to be verified.
    function addToWhitelist(address assertionAdopter, address admin) external onlyOwner {
        if (assertionAdopter == address(0) || admin == address(0)) revert InvalidAssertionAdopter();
        if (exclusions[assertionAdopter] != address(0)) revert AddressExcluded();
        if (whitelist[assertionAdopter] != address(0)) revert AlreadyWhitelisted();

        whitelist[assertionAdopter] = admin;
        emit WhitelistAdded(assertionAdopter, admin);
    }

    /// @notice Removes an admin for a specific assertion adopter from the whitelist.
    /// @param assertionAdopter The address of the assertion adopter contract.
    /// @param admin The admin address to be removed from the whitelist.
    function removeFromWhitelist(address assertionAdopter, address admin) external onlyOwner {
        if (whitelist[assertionAdopter] != admin) revert NotWhitelisted();
        _removeFromWhitelist(assertionAdopter, admin);
    }

    /// @notice Internal helper to clear an adopter-admin mapping and emit the corresponding event.
    /// @param assertionAdopter The adopter whose admin entry is removed.
    /// @param admin The admin address being removed.
    function _removeFromWhitelist(address assertionAdopter, address admin) internal {
        delete whitelist[assertionAdopter];
        emit WhitelistRemoved(assertionAdopter, admin);
    }

    /// @notice Excludes the admin for a specific assertion adopter until the releaser clears it.
    /// @param assertionAdopter The adopter address to exclude from whitelisting.
    /// @param releaser The address allowed to lift the exclusion.
    function exclude(address assertionAdopter, address releaser) external onlyOwner {
        if (assertionAdopter == address(0)) revert InvalidAssertionAdopter();
        if (releaser == address(0)) revert InvalidReleaser();

        exclusions[assertionAdopter] = releaser;
        address admin = whitelist[assertionAdopter];
        if (admin != address(0)) {
            _removeFromWhitelist(assertionAdopter, admin);
        }
        emit ExclusionAdded(assertionAdopter, releaser);
    }

    /// @notice Removes the exclusion entry for an assertion adopter, allowing it to whitelist an admin again.
    /// @param assertionAdopter The adopter whose exclusion should be cleared.
    function releaseExclusion(address assertionAdopter) external {
        address releaser = exclusions[assertionAdopter];
        if (releaser == address(0)) revert NoExclusion();
        if (msg.sender != releaser) revert NotExclusionReleaser();

        delete exclusions[assertionAdopter];
        emit ExclusionReleased(assertionAdopter);
    }

    /// @inheritdoc IAdminVerifier
    /// @param assertionAdopter The adopter whose admin is being verified.
    /// @param requester The address claiming admin rights.
    /// @return True if the requester is the whitelisted admin and the adopter is not excluded.
    function verifyAdmin(address assertionAdopter, address requester, bytes calldata) external view returns (bool) {
        return whitelist[assertionAdopter] == requester;
    }

    /// @notice Returns whether an assertion adopter is currently excluded from using the whitelist.
    /// @param assertionAdopter The adopter address to query.
    /// @return True if the adopter is excluded.
    function isExcluded(address assertionAdopter) external view returns (bool) {
        return exclusions[assertionAdopter] != address(0);
    }

    /// @notice Checks if an admin is whitelisted for a specific assertion adopter.
    /// @param assertionAdopter The adopter contract address.
    /// @param admin The admin address to check.
    /// @return True if the given admin is currently authorized for the adopter.
    function isWhitelisted(address assertionAdopter, address admin) external view returns (bool) {
        return whitelist[assertionAdopter] == admin;
    }
}

