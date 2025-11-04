// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {console2} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";

contract DeployCore is Script {
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

    modifier broadcast() {
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() public broadcast {
        // Deploy DA Verifier (ECDSA)
        address daVerifier = _deployDAVerifier();
        // Deploy Admin Verifier (Owner)
        address adminVerifier = _deployAdminVerifier();
        // Deploy State Oracle
        address stateOracle = _deployStateOracle(daVerifier);
        // Deploy State Oracle Proxy
        _deployStateOracleProxy(stateOracle, adminVerifier);
    }

    function deployDAVerifier() public broadcast {
        _deployDAVerifier();
    }

    function deployAdminVerifier() public broadcast {
        _deployAdminVerifier();
    }

    function deployStateOracle(address daVerifier) public broadcast {
        _deployStateOracle(daVerifier);
    }

    function deployStateOracleProxy(address stateOracle, address adminVerifier) public broadcast {
        _deployStateOracleProxy(stateOracle, adminVerifier);
    }

    function _deployDAVerifier() internal virtual returns (address) {
        address daVerifier = address(new DAVerifierECDSA(daProver));
        console2.log("DA Verifier deployed at", daVerifier);
        return daVerifier;
    }

    function _deployAdminVerifier() internal virtual returns (address) {
        address adminVerifier = address(new AdminVerifierOwner());
        console2.log("Admin Verifier deployed at", adminVerifier);
        return adminVerifier;
    }

    function _deployStateOracle(address daVerifier) public virtual returns (address) {
        address stateOracle = address(new StateOracle(assertionTimelockBlocks, daVerifier, maxAssertionsPerAA));
        console2.log("State Oracle Implementation deployed at", stateOracle);
        return stateOracle;
    }

    function _deployStateOracleProxy(address stateOracle, address adminVerifier) public virtual returns (address) {
        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](1);
        adminVerifiers[0] = IAdminVerifier(adminVerifier);
        bytes memory initCallData = abi.encodeWithSelector(StateOracle.initialize.selector, admin, adminVerifiers);
        address proxyAddress = address(new TransparentUpgradeableProxy(address(stateOracle), admin, initCallData));
        console2.log("State Oracle Proxy deployed at", proxyAddress);
        return proxyAddress;
    }
}
