// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AdminVerifierAlwaysApprove} from "../src/verification/admin/AdminVerifierAlwaysApprove.sol";

contract AdminVerifierAlwaysApproveTest is Test {
    AdminVerifierAlwaysApprove verifier;
    address constant REQUESTER =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierAlwaysApprove.REQUESTER")))));
    address constant OTHER =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierAlwaysApprove.OTHER")))));
    address constant ADOPTER =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierAlwaysApprove.ADOPTER")))));

    function setUp() public {
        verifier = new AdminVerifierAlwaysApprove();
    }

    function test_verifyAdminReturnsTrueForAnyRequester() public view {
        assertTrue(verifier.verifyAdmin(ADOPTER, REQUESTER, ""));
        assertTrue(verifier.verifyAdmin(ADOPTER, OTHER, ""));
    }

    function test_verifyAdminReturnsTrueForZeroAddresses() public view {
        assertTrue(verifier.verifyAdmin(address(0), address(0), ""));
    }

    function test_verifyAdminReturnsTrueWithData() public view {
        assertTrue(verifier.verifyAdmin(ADOPTER, REQUESTER, abi.encode("ignored")));
    }
}
