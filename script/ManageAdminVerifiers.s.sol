// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {StateOracle} from "../src/StateOracle.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";

/// @title ManageAdminVerifiers
/// @notice Foundry script for adding or removing admin verifiers on an existing `StateOracle`.
/// @dev
/// Environment variables expected (all optional except `STATE_ORACLE_ADDRESS`):
/// - `STATE_ORACLE_ADDRESS`: address of the deployed `StateOracle` proxy/instance.
/// - `ADMIN_VERIFIER_TO_ADD`: address of the admin verifier to add (single address).
/// - `ADMIN_VERIFIER_TO_REMOVE`: address of the admin verifier to remove (single address).
///
/// Example:
/// ```bash
/// STATE_ORACLE_ADDRESS=0xOracle \
/// ADMIN_VERIFIER_TO_ADD=0xVerifier \
/// forge script script/ManageAdminVerifiers.s.sol --broadcast --rpc-url $RPC_URL
/// ```
contract ManageAdminVerifiers is Script {
    modifier broadcast() {
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function addAdminVerifier(StateOracle oracle, address verifier) public broadcast {
        IAdminVerifier adminVerifier = IAdminVerifier(verifier);
        if (oracle.isAdminVerifierRegistered(adminVerifier)) {
            console2.log("Admin verifier already registered:", verifier);
            return;
        }

        oracle.addAdminVerifier(adminVerifier);
        console2.log("Added admin verifier:", verifier);
    }

    function removeAdminVerifier(StateOracle oracle, address verifier) public broadcast {
        IAdminVerifier adminVerifier = IAdminVerifier(verifier);
        if (!oracle.isAdminVerifierRegistered(adminVerifier)) {
            console2.log("Admin verifier not registered, skipping removal:", verifier);
            return;
        }

        oracle.removeAdminVerifier(adminVerifier);
        console2.log("Removed admin verifier:", verifier);
    }
}

