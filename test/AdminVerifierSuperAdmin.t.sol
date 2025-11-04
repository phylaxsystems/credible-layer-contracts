// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AdminVerifierSuperAdmin} from "../src/verification/admin/AdminVerifierSuperAdmin.sol";

contract AdminVerifierSuperAdminTest is Test {
    AdminVerifierSuperAdmin verifier;
    address constant SUPER_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierSuperAdmin.SUPER_ADMIN")))));
    address constant OTHER = address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierSuperAdmin.OTHER")))));
    address constant ADOPTER =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierSuperAdmin.ADOPTER")))));

    function setUp() public {
        verifier = new AdminVerifierSuperAdmin(SUPER_ADMIN);
    }

    function test_verifyAdminReturnsTrueForOwner() public view {
        assertTrue(verifier.verifyAdmin(ADOPTER, SUPER_ADMIN, ""));
    }

    function test_verifyAdminReturnsFalseForOthers() public view {
        assertFalse(verifier.verifyAdmin(ADOPTER, OTHER, ""));
    }

    function test_verifyAdminReflectsOwnershipTransfer() public {
        vm.prank(SUPER_ADMIN);
        verifier.transferOwnership(OTHER);

        assertTrue(verifier.verifyAdmin(ADOPTER, OTHER, ""));
        assertFalse(verifier.verifyAdmin(ADOPTER, SUPER_ADMIN, ""));
    }
}
