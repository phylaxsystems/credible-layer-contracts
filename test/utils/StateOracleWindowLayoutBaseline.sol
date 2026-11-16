// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {Batch} from "../../src/Batch.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

/// @notice Seeds independently defined legacy oracle storage for migration tests.
/// @dev Storage-only fixture pinned to StateOracle at ba82c66118828b08416279acf91b7a0976d5535e.
/// The inheritance order and declarations below are copied independently of the implementation under test.
/// Keep the legacy OpenZeppelin inheritance independent of the new administration base.
/// Seed helpers replace unrelated lifecycle and role administration logic.
contract StateOracleWindowLayoutBaseline is Batch, Initializable, Ownable2Step, AccessControl {
    uint256 public immutable ASSERTION_TIMELOCK_BLOCKS;

    struct AssertionAdopter {
        address manager;
        address pendingManager;
        uint16 assertionCount;
        mapping(bytes32 assertionId => AssertionWindow assertionWindow) assertions;
    }

    struct AssertionWindow {
        uint256 activationBlock;
        uint256 deactivationBlock;
    }

    mapping(address => AssertionAdopter) public assertionAdopters;
    mapping(IAdminVerifier adminVerifier => bool isRegistered) public adminVerifiers;
    mapping(IDAVerifier daVerifier => bool isRegistered) public daVerifiers;
    mapping(address => bool) public whitelist;
    bool public whitelistEnabled;
    uint16 public maxAssertionsPerAA;

    constructor(uint256 assertionTimelockBlocks) Ownable(msg.sender) {
        ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
        renounceOwnership();
        _disableInitializers();
    }

    /// @notice Initializes a version-1 fixture using the legacy role and registry policy.
    /// @param admin Initial owner and role holder.
    /// @param adminVerifier Registered admin verifier.
    /// @param daVerifier Registered DA verifier.
    /// @param maximumAssertions Initial assertion cap.
    /// @param whitelistedManager Admitted manager account.
    function initializeForTest(
        address admin,
        IAdminVerifier adminVerifier,
        IDAVerifier daVerifier,
        uint16 maximumAssertions,
        address whitelistedManager
    ) external initializer {
        _transferOwnership(admin);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _setRoleAdmin(keccak256("GUARDIAN_ROLE"), keccak256("GUARDIAN_ADMIN_ROLE"));
        _setRoleAdmin(keccak256("OPERATOR_ROLE"), keccak256("OPERATOR_ADMIN_ROLE"));
        _grantRole(keccak256("GOVERNANCE_ROLE"), admin);
        _grantRole(keccak256("GUARDIAN_ADMIN_ROLE"), admin);
        _grantRole(keccak256("OPERATOR_ADMIN_ROLE"), admin);
        _grantRole(keccak256("GUARDIAN_ROLE"), admin);
        _grantRole(keccak256("OPERATOR_ROLE"), admin);
        adminVerifiers[adminVerifier] = true;
        daVerifiers[daVerifier] = true;
        whitelist[whitelistedManager] = true;
        whitelistEnabled = true;
        maxAssertionsPerAA = maximumAssertions;
    }

    /// @notice Seeds a legacy governance role without a delay.
    /// @param account Role recipient.
    function grantGovernanceRole(address account) external onlyOwner {
        _grantRole(keccak256("GOVERNANCE_ROLE"), account);
    }

    /// @notice Seeds a legacy guardian-admin role without a delay.
    /// @param account Role recipient.
    function grantGuardianAdminRole(address account) external onlyOwner {
        _grantRole(keccak256("GUARDIAN_ADMIN_ROLE"), account);
    }

    /// @notice Seeds a legacy operator-admin role without a delay.
    /// @param account Role recipient.
    function grantOperatorAdminRole(address account) external onlyOwner {
        _grantRole(keccak256("OPERATOR_ADMIN_ROLE"), account);
    }

    /// @notice Seeds a legacy guardian role without a delay.
    /// @param account Role recipient.
    function grantGuardianRole(address account) external onlyOwner {
        _grantRole(keccak256("GUARDIAN_ROLE"), account);
    }

    /// @notice Seeds a legacy operator role without a delay.
    /// @param account Role recipient.
    function grantOperatorRole(address account) external onlyOwner {
        _grantRole(keccak256("OPERATOR_ROLE"), account);
    }

    function seedAdopter(address adopter, address manager, address pendingManager, uint16 assertionCount)
        external
        onlyOwner
    {
        assertionAdopters[adopter].manager = manager;
        assertionAdopters[adopter].pendingManager = pendingManager;
        assertionAdopters[adopter].assertionCount = assertionCount;
    }

    function seedWindow(address adopter, bytes32 assertionId, uint256 activationBlock, uint256 deactivationBlock)
        external
        onlyOwner
    {
        assertionAdopters[adopter].assertions[assertionId] = AssertionWindow(activationBlock, deactivationBlock);
    }
}
