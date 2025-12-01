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
    error NoAdminVerifierAction();

    modifier broadcast() {
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() external broadcast {
        StateOracle oracle = StateOracle(vm.envAddress("STATE_ORACLE_ADDRESS"));
        address verifierToAdd = vm.envOr("ADMIN_VERIFIER_TO_ADD", address(0));
        address verifierToRemove = vm.envOr("ADMIN_VERIFIER_TO_REMOVE", address(0));
        require(verifierToAdd != address(0) || verifierToRemove != address(0), NoAdminVerifierAction());

        if (verifierToAdd != address(0)) _addAdminVerifier(oracle, verifierToAdd);
        if (verifierToRemove != address(0)) _removeAdminVerifier(oracle, verifierToRemove);
    }

    function addAdminVerifier(StateOracle oracle, address verifier) public broadcast {
        _addAdminVerifier(oracle, verifier);
    }

    function removeAdminVerifier(StateOracle oracle, address verifier) public broadcast {
        _removeAdminVerifier(oracle, verifier);
    }

    function _addAdminVerifier(StateOracle oracle, address verifier) internal {
        IAdminVerifier adminVerifier = IAdminVerifier(verifier);
        if (oracle.isAdminVerifierRegistered(adminVerifier)) {
            console2.log("Admin verifier already registered:", verifier);
            return;
        }

        oracle.addAdminVerifier(adminVerifier);
        console2.log("Added admin verifier:", verifier);
    }

    function _removeAdminVerifier(StateOracle oracle, address verifier) internal {
        IAdminVerifier adminVerifier = IAdminVerifier(verifier);
        if (!oracle.isAdminVerifierRegistered(adminVerifier)) {
            console2.log("Admin verifier not registered, skipping removal:", verifier);
            return;
        }

        oracle.removeAdminVerifier(adminVerifier);
        console2.log("Removed admin verifier:", verifier);
    }
}
