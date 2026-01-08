// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCore} from "./DeployCore.s.sol";
import {console2} from "forge-std/console2.sol";

contract DeployCoreWithStaging is DeployCore {
    uint128 stagingAssertionTimelockBlocks;
    uint16 stagingMaxAssertionsPerAA;

    function setUp() public override {
        super.setUp();

        // Staging state oracle parameters
        stagingMaxAssertionsPerAA = uint16(vm.envUint("STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA"));
        stagingAssertionTimelockBlocks = uint128(vm.envUint("STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS"));

        assert(stagingAssertionTimelockBlocks > 0);
        assert(stagingMaxAssertionsPerAA > 0);
    }

    function run() public override broadcast {
        // Fund persistent accounts with 1 wei if empty
        _fundPersistentAccounts();

        // Deploy DA Verifier (ECDSA)
        address daVerifier = _deployDAVerifier();
        // Deploy Admin Verifiers
        address[] memory adminVerifierDeployments = _deployAdminVerifiers();

        // Deploy Production State Oracle
        address stateOracle = _deployStateOracle(daVerifier, assertionTimelockBlocks);
        // Deploy State Oracle Proxy
        _deployStateOracleProxy(stateOracle, adminVerifierDeployments, maxAssertionsPerAA);

        // Deploy staging State Oracle
        address stagingOracle = _deployStateOracle(daVerifier, stagingAssertionTimelockBlocks);
        // Deploy staging State Oracle Proxy
        _deployStateOracleProxy(stagingOracle, adminVerifierDeployments, stagingMaxAssertionsPerAA);
    }
}
