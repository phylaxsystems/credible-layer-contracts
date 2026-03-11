// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracleAssertionFlowBase} from "./StateOracleAssertionFlowBase.sol";
import {AdminVerifierOwner} from "../../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierOnChain} from "../../src/verification/da/DAVerifierOnChain.sol";
import {OwnableAdopter} from "../utils/Adopter.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

/// @title StateOracleOwnerOnChainTest
/// @notice Integration test: AdminVerifierOwner + DAVerifierOnChain
contract StateOracleOwnerOnChainTest is StateOracleAssertionFlowBase {
    function _deployAdminVerifier() internal override returns (IAdminVerifier) {
        return IAdminVerifier(new AdminVerifierOwner());
    }

    function _deployDAVerifier() internal override returns (IDAVerifier) {
        return IDAVerifier(address(new DAVerifierOnChain()));
    }

    function _registerAdopter(address, address admin) internal override {
        OwnableAdopter ownableAdopter = new OwnableAdopter(admin);
        adopter = address(ownableAdopter);
        vm.prank(admin);
        stateOracle.registerAssertionAdopter(adopter, adminVerifier, new bytes(0));
    }

    function _generateValidAssertion(bytes32 seed)
        internal
        pure
        override
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof)
    {
        // For DAVerifierOnChain: keccak256(proof) must equal assertionId
        proof = abi.encode(seed);
        assertionId = keccak256(proof);
        metadata = new bytes(0);
    }

    function _generateInvalidAssertion(bytes32 seed)
        internal
        pure
        override
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof)
    {
        // Proof whose hash does NOT match the assertionId
        proof = abi.encode(seed);
        // Use a different assertionId that won't match keccak256(proof)
        assertionId = keccak256(abi.encode("invalid", seed));
        metadata = new bytes(0);
    }
}
