// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracleAssertionFlowBase} from "./StateOracleAssertionFlowBase.sol";
import {AdminVerifierWhitelist} from "../../src/verification/admin/AdminVerifierWhitelist.sol";
import {DAVerifierECDSA} from "../../src/verification/da/DAVerifierECDSA.sol";
import {OwnableAdopter} from "../utils/Adopter.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

/// @title StateOracleWhitelistECDSATest
/// @notice Integration test: AdminVerifierWhitelist + DAVerifierECDSA
contract StateOracleWhitelistECDSATest is StateOracleAssertionFlowBase {
    uint256 constant PROVER = uint256(keccak256(abi.encode("pcl.test.integration.WhitelistECDSA.PROVER")));
    address constant WHITELIST_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.integration.WhitelistECDSA.WHITELIST_ADMIN")))));

    AdminVerifierWhitelist whitelistVerifier;

    function _deployAdminVerifier() internal override returns (IAdminVerifier) {
        whitelistVerifier = new AdminVerifierWhitelist(WHITELIST_ADMIN);
        return IAdminVerifier(address(whitelistVerifier));
    }

    function _deployDAVerifier() internal override returns (IDAVerifier) {
        return IDAVerifier(address(new DAVerifierECDSA(vm.addr(PROVER))));
    }

    function _registerAdopter(address, address admin) internal override {
        // Deploy an adopter contract (address is independent of owner for whitelist verifier)
        OwnableAdopter ownableAdopter = new OwnableAdopter(admin);
        adopter = address(ownableAdopter);

        // Whitelist verifier requires setting the admin mapping before registration
        vm.prank(WHITELIST_ADMIN);
        whitelistVerifier.addToWhitelist(adopter, admin);

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
        proof = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));
    }
}
