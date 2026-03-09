// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {DAVerifierRegistry} from "../src/lib/DAVerifierRegistry.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";

contract DAVerifierRegistryHarness {
    using DAVerifierRegistry for mapping(IDAVerifier => bool);

    mapping(IDAVerifier => bool) public daVerifiers;

    function add(IDAVerifier daVerifier) external {
        daVerifiers.add(daVerifier);
    }

    function remove(IDAVerifier daVerifier) external {
        daVerifiers.remove(daVerifier);
    }

    function isRegistered(IDAVerifier daVerifier) external view returns (bool) {
        return daVerifiers.isRegistered(daVerifier);
    }
}

contract DAVerifierRegistryTest is Test {
    DAVerifierRegistryHarness public harness;
    DAVerifierMock public verifier1;
    DAVerifierMock public verifier2;

    function setUp() public {
        harness = new DAVerifierRegistryHarness();
        verifier1 = new DAVerifierMock();
        verifier2 = new DAVerifierMock();
    }

    function test_add() public {
        harness.add(IDAVerifier(address(verifier1)));
        assertTrue(harness.isRegistered(IDAVerifier(address(verifier1))));
    }

    function test_add_emitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit DAVerifierRegistry.DAVerifierAdded(IDAVerifier(address(verifier1)));
        harness.add(IDAVerifier(address(verifier1)));
    }

    function test_add_RevertIf_AlreadyRegistered() public {
        harness.add(IDAVerifier(address(verifier1)));
        vm.expectRevert(DAVerifierRegistry.DAVerifierAlreadyRegistered.selector);
        harness.add(IDAVerifier(address(verifier1)));
    }

    function test_remove() public {
        harness.add(IDAVerifier(address(verifier1)));
        harness.remove(IDAVerifier(address(verifier1)));
        assertFalse(harness.isRegistered(IDAVerifier(address(verifier1))));
    }

    function test_remove_emitsEvent() public {
        harness.add(IDAVerifier(address(verifier1)));
        vm.expectEmit(true, true, true, true);
        emit DAVerifierRegistry.DAVerifierRemoved(IDAVerifier(address(verifier1)));
        harness.remove(IDAVerifier(address(verifier1)));
    }

    function test_remove_RevertIf_NotRegistered() public {
        vm.expectRevert(DAVerifierRegistry.DAVerifierNotRegistered.selector);
        harness.remove(IDAVerifier(address(verifier1)));
    }

    function test_isRegistered_returnsFalseByDefault() public view {
        assertFalse(harness.isRegistered(IDAVerifier(address(verifier1))));
    }

    function test_isRegistered_returnsTrueAfterAdd() public {
        harness.add(IDAVerifier(address(verifier1)));
        assertTrue(harness.isRegistered(IDAVerifier(address(verifier1))));
    }

    function test_isRegistered_returnsFalseAfterRemove() public {
        harness.add(IDAVerifier(address(verifier1)));
        harness.remove(IDAVerifier(address(verifier1)));
        assertFalse(harness.isRegistered(IDAVerifier(address(verifier1))));
    }
}
