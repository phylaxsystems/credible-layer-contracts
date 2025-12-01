// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {AdminVerifierSuperAdmin} from "../../src/verification/admin/AdminVerifierSuperAdmin.sol";

/// @title DeployAdminVerifierSuperAdmin
/// @notice Deploys the test-only verifier outside the production core deployment flow.
contract DeployAdminVerifierSuperAdmin is Script {
    error InvalidSuperAdmin();

    function run() external returns (AdminVerifierSuperAdmin verifier) {
        address superAdmin = vm.envAddress("ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS");
        require(superAdmin != address(0), InvalidSuperAdmin());

        vm.startBroadcast();
        verifier = new AdminVerifierSuperAdmin(superAdmin);
        vm.stopBroadcast();

        console2.log("Admin Verifier (Super Admin) deployed at", address(verifier));
    }
}
