// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {Batch} from "../../src/Batch.sol";
import {StateOracleAccessControl} from "../../src/StateOracleAccessControl.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

/// @dev Storage-only fixture pinned to StateOracle at ba82c66118828b08416279acf91b7a0976d5535e.
/// The inheritance order and declarations below are copied independently of the implementation under test.
/// Its base contracts are unchanged by the reactivation change. Seed helpers replace unrelated lifecycle logic.
contract StateOracleWindowLayoutBaseline is Batch, Initializable, StateOracleAccessControl {
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

    function initializeForTest(
        address admin,
        IAdminVerifier adminVerifier,
        IDAVerifier daVerifier,
        uint16 maximumAssertions,
        address whitelistedManager
    ) external initializer {
        _initializeRoles(admin);
        adminVerifiers[adminVerifier] = true;
        daVerifiers[daVerifier] = true;
        whitelist[whitelistedManager] = true;
        whitelistEnabled = true;
        maxAssertionsPerAA = maximumAssertions;
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
