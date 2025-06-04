// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {DAVerifierECDSA} from "../../src/verification/da/DAVerifierECDSA.sol";
import {StateOracle} from "../../src/StateOracle.sol";
import {OwnableAdopter} from "../utils/Adopter.sol";
import {StateOracleBase} from "../StateOracle.t.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../../src/verification/admin/AdminVerifierOwner.sol";

contract StateOracleWithDAVerifierECDSATest is StateOracleBase {
    address adopter;
    uint256 immutable PROVER =
        uint256(keccak256(abi.encode("pcl.test.integration.StateOracleWithDAVerifierECDSA.PROVER")));

    function setUp() public override {
        DAVerifierECDSA daVerifier = new DAVerifierECDSA(vm.addr(PROVER));
        IAdminVerifier adminVerifier = new AdminVerifierOwner();
        IAdminVerifier[] memory verifiers = new IAdminVerifier[](1);
        verifiers[0] = adminVerifier;
        bytes memory data = abi.encodeWithSelector(StateOracle.initialize.selector, ADMIN, verifiers);
        stateOracle = StateOracle(
            deployProxy(address(new StateOracle(TIMEOUT, address(daVerifier), MAX_ASSERTIONS_PER_AA)), data)
        );
        vm.startPrank(OWNER);
        adopter = address(new OwnableAdopter(OWNER));
        stateOracle.registerAssertionAdopter(adopter, adminVerifier, new bytes(0));
    }

    function testFuzz_addAssertionWithECDSAProof(bytes32 assertionId, bytes calldata metadata) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PROVER, assertionId);
        bytes memory signature = abi.encodePacked(r, s, v);
        stateOracle.addAssertion(address(adopter), assertionId, metadata, signature);
        vm.stopPrank();

        assertTrue(stateOracle.hasAssertion(address(adopter), assertionId), "Assertion should have been added");
    }

    function testFuzz_RevertIf_addAssertionWithWrongProver(
        bytes32 assertionId,
        bytes calldata metadata,
        uint256 fakeProver
    ) public {
        fakeProver = bound(fakeProver, 1, ECDSA.N - 1);
        vm.assume(fakeProver != PROVER);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeProver, assertionId);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(StateOracle.InvalidProof.selector);
        stateOracle.addAssertion(address(adopter), assertionId, metadata, signature);
        vm.stopPrank();
    }
}
