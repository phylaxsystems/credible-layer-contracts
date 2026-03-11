// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracleAssertionFlowBase} from "./StateOracleAssertionFlowBase.sol";
import {AdminVerifierWhitelist} from "../../src/verification/admin/AdminVerifierWhitelist.sol";
import {DAVerifierOnChain} from "../../src/verification/da/DAVerifierOnChain.sol";
import {OwnableAdopter} from "../utils/Adopter.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

/// @title StateOracleWhitelistOnChainTest
/// @notice Integration test: AdminVerifierWhitelist + DAVerifierOnChain
contract StateOracleWhitelistOnChainTest is StateOracleAssertionFlowBase {
    address constant WHITELIST_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.integration.WhitelistOnChain.WHITELIST_ADMIN")))));

    AdminVerifierWhitelist whitelistVerifier;

    function _deployAdminVerifier() internal override returns (IAdminVerifier) {
        whitelistVerifier = new AdminVerifierWhitelist(WHITELIST_ADMIN);
        return IAdminVerifier(address(whitelistVerifier));
    }

    function _deployDAVerifier() internal override returns (IDAVerifier) {
        return IDAVerifier(address(new DAVerifierOnChain()));
    }

    function _registerAdopter(address, address admin) internal override {
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
        pure
        override
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof)
    {
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
        proof = abi.encode(seed);
        assertionId = keccak256(abi.encode("invalid", seed));
        metadata = new bytes(0);
    }
}
