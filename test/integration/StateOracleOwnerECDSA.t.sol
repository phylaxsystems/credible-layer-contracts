// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracleAssertionFlowBase} from "./StateOracleAssertionFlowBase.sol";
import {AdminVerifierOwner} from "../../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierECDSA} from "../../src/verification/da/DAVerifierECDSA.sol";
import {OwnableAdopter} from "../utils/Adopter.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

/// @title StateOracleOwnerECDSATest
/// @notice Integration test: AdminVerifierOwner + DAVerifierECDSA
contract StateOracleOwnerECDSATest is StateOracleAssertionFlowBase {
    uint256 constant PROVER = uint256(keccak256(abi.encode("pcl.test.integration.OwnerECDSA.PROVER")));

    function _deployAdminVerifier() internal override returns (IAdminVerifier) {
        return IAdminVerifier(new AdminVerifierOwner());
    }

    function _deployDAVerifier() internal override returns (IDAVerifier) {
        return IDAVerifier(address(new DAVerifierECDSA(vm.addr(PROVER))));
    }

    function _registerAdopter(address, address admin) internal override {
        OwnableAdopter ownableAdopter = new OwnableAdopter(admin);
        adopter = address(ownableAdopter);
        vm.prank(admin);
        stateOracle.registerAssertionAdopter(adopter, adminVerifier, new bytes(0));
    }

    function _generateValidAssertion(bytes32 seed)
        internal
        override
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof)
    {
        assertionId = seed;
        metadata = new bytes(0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PROVER, assertionId);
        proof = abi.encodePacked(r, s, v);
    }

    function _generateInvalidAssertion(bytes32 seed)
        internal
        pure
        override
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof)
    {
        assertionId = seed;
        metadata = new bytes(0);
        // Garbage signature that will not recover to the PROVER address
        proof = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));
    }
}
