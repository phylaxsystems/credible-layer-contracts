// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AdminVerifierWhitelist} from "../src/verification/admin/AdminVerifierWhitelist.sol";

contract AdminVerifierWhitelistTest is Test {
    AdminVerifierWhitelist verifier;
    address constant OWNER = address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierWhitelist.OWNER")))));
    address constant ADOPTER =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierWhitelist.ADOPTER")))));
    address constant ADMIN = address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierWhitelist.ADMIN")))));
    address constant RELEASER =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierWhitelist.RELEASER")))));
    address constant OTHER_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.AdminVerifierWhitelist.OTHER_ADMIN")))));

    function setUp() public {
        verifier = new AdminVerifierWhitelist(OWNER);
    }

    function test_addToWhitelist() public {
        vm.prank(OWNER);
        verifier.addToWhitelist(ADOPTER, ADMIN);

        assertEq(verifier.whitelist(ADOPTER), ADMIN);
        assertTrue(verifier.isWhitelisted(ADOPTER, ADMIN));
    }

    function test_RevertIf_addToWhitelistWithZeroAdmin() public {
        vm.prank(OWNER);
        vm.expectRevert(AdminVerifierWhitelist.InvalidAssertionAdopter.selector);
        verifier.addToWhitelist(ADOPTER, address(0));
    }

    function test_RevertIf_addToWhitelistWithZeroAdopter() public {
        vm.prank(OWNER);
        vm.expectRevert(AdminVerifierWhitelist.InvalidAssertionAdopter.selector);
        verifier.addToWhitelist(address(0), ADMIN);
    }

    function test_RevertIf_addToWhitelistAlreadyWhitelisted() public {
        vm.startPrank(OWNER);
        verifier.addToWhitelist(ADOPTER, ADMIN);
        vm.expectRevert(AdminVerifierWhitelist.AlreadyWhitelisted.selector);
        verifier.addToWhitelist(ADOPTER, OTHER_ADMIN);
        vm.stopPrank();
    }

    function test_RevertIf_addToWhitelistWhileExcluded() public {
        vm.startPrank(OWNER);
        verifier.exclude(ADOPTER, RELEASER);
        vm.expectRevert(AdminVerifierWhitelist.AddressExcluded.selector);
        verifier.addToWhitelist(ADOPTER, ADMIN);
        vm.stopPrank();
    }

    function test_removeFromWhitelist() public {
        vm.startPrank(OWNER);
        verifier.addToWhitelist(ADOPTER, ADMIN);
        verifier.removeFromWhitelist(ADOPTER, ADMIN);
        vm.stopPrank();

        assertEq(verifier.whitelist(ADOPTER), address(0));
        assertFalse(verifier.isWhitelisted(ADOPTER, ADMIN));
    }

    function test_RevertIf_removeFromWhitelistNotWhitelisted() public {
        vm.prank(OWNER);
        vm.expectRevert(AdminVerifierWhitelist.NotWhitelisted.selector);
        verifier.removeFromWhitelist(ADOPTER, ADMIN);
    }

    function test_excludeRemovesExistingWhitelist() public {
        vm.startPrank(OWNER);
        verifier.addToWhitelist(ADOPTER, ADMIN);
        verifier.exclude(ADOPTER, RELEASER);
        vm.stopPrank();

        assertEq(verifier.whitelist(ADOPTER), address(0));
        assertTrue(verifier.isExcluded(ADOPTER));
    }

    function test_excludeRemovesWhitelistEntry() public {
        vm.startPrank(OWNER);
        verifier.addToWhitelist(ADOPTER, ADMIN);
        verifier.exclude(ADOPTER, RELEASER);
        vm.stopPrank();

        assertEq(verifier.whitelist(ADOPTER), address(0));
        assertFalse(verifier.isWhitelisted(ADOPTER, ADMIN));
        assertFalse(verifier.verifyAdmin(ADOPTER, ADMIN, ""));
    }

    function test_RevertIf_excludeWithInvalidReleaser() public {
        vm.prank(OWNER);
        vm.expectRevert(AdminVerifierWhitelist.InvalidReleaser.selector);
        verifier.exclude(ADOPTER, address(0));
    }

    function test_releaseExclusionByReleaser() public {
        vm.startPrank(OWNER);
        verifier.exclude(ADOPTER, RELEASER);
        vm.stopPrank();

        vm.prank(RELEASER);
        verifier.releaseExclusion(ADOPTER);

        assertFalse(verifier.isExcluded(ADOPTER));
    }

    function test_RevertIf_releaseExclusionByNonReleaser(address nonReleaser) public {
        vm.assume(nonReleaser != RELEASER && nonReleaser != address(0));

        vm.prank(OWNER);
        verifier.exclude(ADOPTER, RELEASER);

        vm.prank(nonReleaser);
        vm.expectRevert(AdminVerifierWhitelist.NotExclusionReleaser.selector);
        verifier.releaseExclusion(ADOPTER);
    }

    function test_RevertIf_releaseExclusionWithoutEntry() public {
        vm.expectRevert(AdminVerifierWhitelist.NoExclusion.selector);
        verifier.releaseExclusion(ADOPTER);
    }

    function test_verifyAdmin() public {
        vm.prank(OWNER);
        verifier.addToWhitelist(ADOPTER, ADMIN);

        assertTrue(verifier.verifyAdmin(ADOPTER, ADMIN, ""));
        assertFalse(verifier.verifyAdmin(ADOPTER, OTHER_ADMIN, ""));

        vm.prank(OWNER);
        verifier.exclude(ADOPTER, RELEASER);

        assertFalse(verifier.verifyAdmin(ADOPTER, ADMIN, ""));
    }
}
