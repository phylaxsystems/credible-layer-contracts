// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

import {StateOracle} from "../src/StateOracle.sol";
import {TransparentUpgradeableProxy} from
    "openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {console2} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";
import {ICreateX, CREATE_X_ADDRESS} from "./ICreateX.sol";

contract DeployCore is Script {
    ICreateX internal constant CREATE_X = ICreateX(CREATE_X_ADDRESS);
    address admin;
    uint128 assertionTimelockBlocks;
    uint32 maxAssertionsPerAA;
    address daProver;

    function setUp() public {
        maxAssertionsPerAA = uint32(vm.envUint("STATE_ORACLE_MAX_ASSERTIONS_PER_AA"));
        assertionTimelockBlocks = uint128(vm.envUint("STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS"));
        admin = vm.envAddress("STATE_ORACLE_ADMIN_ADDRESS");
        daProver = vm.envAddress("DA_PROVER_ADDRESS");

        assert(daProver != address(0));
        assert(assertionTimelockBlocks > 0);
        assert(admin != address(0));
    }

    function run() public {
        vm.startBroadcast();

        // Deploy DA Verifier (ECDSA)
        bytes memory daVerifierCode = abi.encodePacked(type(DAVerifierECDSA).creationCode, abi.encode(daProver));
        address daVerifier = deployCreate3("credible-layer-da-verifier-ecdsa", daVerifierCode);
        console2.log("DA Verifier deployed at", daVerifier);

        // Deploy Admin Verifier (Owner)
        address adminVerifier = deployCreate3(
            "credible-layer-admin-verifier-owner", abi.encodePacked(type(AdminVerifierOwner).creationCode)
        );
        console2.log("Admin Verifier deployed at", adminVerifier);

        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](1);
        adminVerifiers[0] = IAdminVerifier(adminVerifier);

        // Deploy State Oracle
        bytes memory stateOracleCode = abi.encodePacked(
            type(StateOracle).creationCode, abi.encode(assertionTimelockBlocks, daVerifier, maxAssertionsPerAA)
        );
        address stateOracle = deployCreate3("credible-layer-state-oracle-implementation", stateOracleCode);
        console2.log("State Oracle deployed at", stateOracle);

        // Deploy State Oracle Proxy
        bytes memory initCallData = abi.encodeWithSelector(StateOracle.initialize.selector, admin, adminVerifiers);
        bytes memory proxyConstructorArgs = abi.encode(address(stateOracle), admin, initCallData);
        address proxyAddress = deployCreate3(
            "credible-layer-state-oracle-proxy",
            abi.encodePacked(type(TransparentUpgradeableProxy).creationCode, proxyConstructorArgs)
        );
        console2.log("State Oracle Proxy deployed at", proxyAddress);

        vm.stopBroadcast();
    }

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
}
