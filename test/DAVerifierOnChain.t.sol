// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DAVerifierOnChain} from "../src/verification/da/DAVerifierOnChain.sol";

contract DAVerifierOnChainTest is Test {
    DAVerifierOnChain public verifier;

    function setUp() public {
        verifier = new DAVerifierOnChain();
    }

    function testFuzz_verifyDA_validProof(bytes calldata proof, bytes calldata metadata) public view {
        bytes32 assertionId = keccak256(proof);
        assertTrue(verifier.verifyDA(assertionId, metadata, proof), "Valid proof should verify");
    }

    function testFuzz_verifyDA_invalidProof(bytes32 assertionId, bytes calldata proof, bytes calldata metadata)
        public
        view
    {
        vm.assume(keccak256(proof) != assertionId);
        assertFalse(verifier.verifyDA(assertionId, metadata, proof), "Invalid proof should not verify");
    }

    function test_verifyDA_emptyProof() public view {
        assertTrue(verifier.verifyDA(keccak256(""), "", ""), "Empty proof should verify against its hash");
    }

    function test_verifyDA_emptyProofMismatch() public view {
        assertFalse(
            verifier.verifyDA(bytes32(uint256(1)), "", ""), "Empty proof should not verify against mismatched hash"
        );
    }

    function testFuzz_verifyDA_metadataIgnored(bytes calldata proof, bytes calldata metadata1, bytes calldata metadata2)
        public
        view
    {
        bytes32 assertionId = keccak256(proof);
        bool result1 = verifier.verifyDA(assertionId, metadata1, proof);
        bool result2 = verifier.verifyDA(assertionId, metadata2, proof);
        assertEq(result1, result2, "Metadata should not affect verification result");
    }

    function test_verifyDA_deterministicPure() public view {
        bytes memory proof = hex"deadbeef";
        bytes32 assertionId = keccak256(proof);
        bool result1 = verifier.verifyDA(assertionId, "", proof);
        bool result2 = verifier.verifyDA(assertionId, "", proof);
        assertEq(result1, result2, "Same inputs should always produce same output");
    }
}
