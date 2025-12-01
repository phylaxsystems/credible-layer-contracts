// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {DeployAdminVerifierSuperAdmin} from "../script/test/DeployAdminVerifierSuperAdmin.s.sol";
import {ManageAdminVerifiers} from "../script/ManageAdminVerifiers.s.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierSuperAdmin} from "../src/verification/admin/AdminVerifierSuperAdmin.sol";

contract AdminVerifierRegistryMock {
    mapping(IAdminVerifier verifier => bool registered) public isAdminVerifierRegistered;

    function addAdminVerifier(IAdminVerifier verifier) external {
        isAdminVerifierRegistered[verifier] = true;
    }

    function removeAdminVerifier(IAdminVerifier verifier) external {
        isAdminVerifierRegistered[verifier] = false;
    }
}

contract ManagementScriptsTest is Test {
    function test_ManageAdminVerifiersRunAddsAndRemovesConfiguredVerifiers() public {
        ManageAdminVerifiers script = new ManageAdminVerifiers();
        AdminVerifierRegistryMock oracle = new AdminVerifierRegistryMock();
        IAdminVerifier verifierToAdd = IAdminVerifier(makeAddr("verifierToAdd"));
        IAdminVerifier verifierToRemove = IAdminVerifier(makeAddr("verifierToRemove"));
        oracle.addAdminVerifier(verifierToRemove);

        vm.setEnv("STATE_ORACLE_ADDRESS", vm.toString(address(oracle)));
        vm.setEnv("ADMIN_VERIFIER_TO_ADD", vm.toString(address(verifierToAdd)));
        vm.setEnv("ADMIN_VERIFIER_TO_REMOVE", vm.toString(address(verifierToRemove)));

        script.run();

        assertTrue(oracle.isAdminVerifierRegistered(verifierToAdd));
        assertFalse(oracle.isAdminVerifierRegistered(verifierToRemove));
    }

    function test_DeployAdminVerifierSuperAdminUsesConfiguredOwner() public {
        address superAdmin = makeAddr("superAdmin");
        vm.setEnv("ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS", vm.toString(superAdmin));

        AdminVerifierSuperAdmin verifier = new DeployAdminVerifierSuperAdmin().run();

        assertEq(verifier.owner(), superAdmin);
    }
}
