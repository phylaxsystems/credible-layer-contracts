// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

contract DAVerifierECDSATest is Test {
    DAVerifierECDSA public verifier;
    uint256 public daProver;

    function setUp() public {
        daProver = 0x123;
        verifier = new DAVerifierECDSA(vm.addr(daProver));
    }

    function testFuzz_verifyDA(bytes32 assertionId, bytes calldata metadata) public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(daProver, assertionId);

        bytes memory signature = abi.encodePacked(r, s, v);

        assertTrue(verifier.verifyDA(assertionId, metadata, signature), "Signature should be valid");
    }

    function testFuzz_RevertIf_verifyDAWithWrongProver(bytes32 assertionId, bytes calldata metadata, uint256 fakeProver)
        public
        view
    {
        vm.assume(fakeProver != 0 && fakeProver < ECDSA.N);
        vm.assume(fakeProver != daProver);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeProver, assertionId);

        bytes memory signature = abi.encodePacked(r, s, v);
        assertFalse(verifier.verifyDA(assertionId, metadata, signature), "Signature should be invalid");
    }

    function testFuzz_RevertIf_verifyDAwithInvalidSignature(
        bytes32 assertionId,
        bytes calldata metadata,
        bytes calldata signature
    ) public {
        vm.assume(signature.length != 64 && signature.length != 65);
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        verifier.verifyDA(assertionId, metadata, signature);
    }
}
