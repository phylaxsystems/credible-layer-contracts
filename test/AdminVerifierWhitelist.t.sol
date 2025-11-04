// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AdminVerifierWhitelist} from "../src/verification/admin/AdminVerifierWhitelist.sol";

contract AdminVerifierWhitelistTest is Test {
    AdminVerifierWhitelist verifier;
    address owner = address(0xA11CE);
    address adopter = address(0xAD0BEEF);
    address admin = address(0xADD1);
    address releaser = address(0xBEEF);

    function setUp() public {
        verifier = new AdminVerifierWhitelist(owner);
    }

    function test_addToWhitelist() public {
        vm.prank(owner);
        verifier.addToWhitelist(adopter, admin);

        assertEq(verifier.whitelist(adopter), admin);
        assertTrue(verifier.isWhitelisted(adopter, admin));
    }

    function test_RevertIf_addToWhitelistWithZeroAdmin() public {
        vm.prank(owner);
        vm.expectRevert(AdminVerifierWhitelist.InvalidAssertionAdopter.selector);
        verifier.addToWhitelist(adopter, address(0));
    }

    function test_RevertIf_addToWhitelistWithZeroAdopter() public {
        vm.prank(owner);
        vm.expectRevert(AdminVerifierWhitelist.InvalidAssertionAdopter.selector);
        verifier.addToWhitelist(address(0), admin);
    }

    function test_RevertIf_addToWhitelistAlreadyWhitelisted() public {
        vm.startPrank(owner);
        verifier.addToWhitelist(adopter, admin);
        vm.expectRevert(AdminVerifierWhitelist.AlreadyWhitelisted.selector);
        verifier.addToWhitelist(adopter, address(0xCAFE));
        vm.stopPrank();
    }

    function test_RevertIf_addToWhitelistWhileExcluded() public {
        vm.startPrank(owner);
        verifier.exclude(adopter, releaser);
        vm.expectRevert(AdminVerifierWhitelist.AddressExcluded.selector);
        verifier.addToWhitelist(adopter, admin);
        vm.stopPrank();
    }

    function test_removeFromWhitelist() public {
        vm.startPrank(owner);
        verifier.addToWhitelist(adopter, admin);
        verifier.removeFromWhitelist(adopter, admin);
        vm.stopPrank();

        assertEq(verifier.whitelist(adopter), address(0));
        assertFalse(verifier.isWhitelisted(adopter, admin));
    }

    function test_RevertIf_removeFromWhitelistNotWhitelisted() public {
        vm.prank(owner);
        vm.expectRevert(AdminVerifierWhitelist.NotWhitelisted.selector);
        verifier.removeFromWhitelist(adopter, admin);
    }

    function test_excludeRemovesExistingWhitelist() public {
        vm.startPrank(owner);
        verifier.addToWhitelist(adopter, admin);
        verifier.exclude(adopter, releaser);
        vm.stopPrank();

        assertEq(verifier.whitelist(adopter), address(0));
        assertTrue(verifier.isExcluded(adopter));
    }

    function test_excludeRemovesWhitelistEntry() public {
        vm.startPrank(owner);
        verifier.addToWhitelist(adopter, admin);
        verifier.exclude(adopter, releaser);
        vm.stopPrank();

        assertEq(verifier.whitelist(adopter), address(0));
        assertFalse(verifier.isWhitelisted(adopter, admin));
        assertFalse(verifier.verifyAdmin(adopter, admin, ""));
    }

    function test_RevertIf_excludeWithInvalidReleaser() public {
        vm.prank(owner);
        vm.expectRevert(AdminVerifierWhitelist.InvalidReleaser.selector);
        verifier.exclude(adopter, address(0));
    }

    function test_releaseExclusionByReleaser() public {
        vm.startPrank(owner);
        verifier.exclude(adopter, releaser);
        vm.stopPrank();

        vm.prank(releaser);
        verifier.releaseExclusion(adopter);

        assertFalse(verifier.isExcluded(adopter));
    }

    function test_RevertIf_releaseExclusionByNonReleaser(address nonReleaser) public {
        vm.assume(nonReleaser != releaser && nonReleaser != address(0));

        vm.prank(owner);
        verifier.exclude(adopter, releaser);

        vm.prank(nonReleaser);
        vm.expectRevert(AdminVerifierWhitelist.NotExclusionReleaser.selector);
        verifier.releaseExclusion(adopter);
    }

    function test_RevertIf_releaseExclusionWithoutEntry() public {
        vm.expectRevert(AdminVerifierWhitelist.NoExclusion.selector);
        verifier.releaseExclusion(adopter);
    }

    function test_verifyAdmin() public {
        vm.prank(owner);
        verifier.addToWhitelist(adopter, admin);

        assertTrue(verifier.verifyAdmin(adopter, admin, ""));
        assertFalse(verifier.verifyAdmin(adopter, address(0xDEAD), ""));

        vm.prank(owner);
        verifier.exclude(adopter, releaser);

        assertFalse(verifier.verifyAdmin(adopter, admin, ""));
    }
}
