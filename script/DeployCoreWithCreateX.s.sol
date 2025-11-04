// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {ICreateX, CREATE_X_ADDRESS} from "./ICreateX.sol";
import {DeployCore} from "./DeployCore.s.sol";
import {console2} from "forge-std/console2.sol";

contract DeployCoreWithCreateX is DeployCore {
    ICreateX internal constant CREATE_X = ICreateX(CREATE_X_ADDRESS);

    function deployCreate3(string memory name, bytes memory initCode) internal returns (address) {
        bytes32 salt = generateCreateXSalt(msg.sender, name);
        return CREATE_X.deployCreate3(salt, initCode);
    }

    // Set salt with frontrunning protection, i.e. first 20 bytes = deployer;
    // 0 byte to switch off cross-chain redeploy protection; 11 bytes salt
    // Details: https://github.com/pcaversaccio/createx#permissioned-deploy-protection-and-cross-chain-redeploy-protection
    function generateCreateXSalt(address sender, string memory name) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(sender, hex"00", bytes11(keccak256(bytes(name)))));
    }

    function _deployDAVerifier() internal override returns (address) {
        bytes memory daVerifierCode = abi.encodePacked(type(DAVerifierECDSA).creationCode, abi.encode(daProver));
        address daVerifier = deployCreate3("credible-layer-da-verifier-ecdsa", daVerifierCode);
        console2.log("DA Verifier deployed at", daVerifier);
        return daVerifier;
    }

    function _deployAdminVerifier() internal override returns (address) {
        bytes memory adminVerifierCode = abi.encodePacked(type(AdminVerifierOwner).creationCode);
        address adminVerifier = deployCreate3("credible-layer-admin-verifier-owner", adminVerifierCode);
        console2.log("Admin Verifier deployed at", adminVerifier);
        return adminVerifier;
    }

    function _deployStateOracle(address daVerifier) public override returns (address) {
        bytes memory stateOracleCode = abi.encodePacked(
            type(StateOracle).creationCode, abi.encode(assertionTimelockBlocks, daVerifier, maxAssertionsPerAA)
        );
        address stateOracle = deployCreate3("credible-layer-state-oracle-implementation", stateOracleCode);
        console2.log("State Oracle Implementation deployed at", stateOracle);
        return stateOracle;
    }

    function _deployStateOracleProxy(address stateOracle, address adminVerifier) public override returns (address) {
        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](1);
        adminVerifiers[0] = IAdminVerifier(adminVerifier);
        bytes memory initCallData = abi.encodeWithSelector(StateOracle.initialize.selector, admin, adminVerifiers);
        bytes memory proxyConstructorArgs = abi.encode(address(stateOracle), admin, initCallData);
        address proxyAddress = deployCreate3(
            "credible-layer-state-oracle-proxy",
            abi.encodePacked(type(TransparentUpgradeableProxy).creationCode, proxyConstructorArgs)
        );
        console2.log("State Oracle Proxy deployed at", proxyAddress);
        return proxyAddress;
    }
}
