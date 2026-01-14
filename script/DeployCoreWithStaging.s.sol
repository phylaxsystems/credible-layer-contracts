// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCore} from "./DeployCore.s.sol";

contract DeployCoreWithStaging is DeployCore {
    uint128 stagingAssertionTimelockBlocks;
    uint16 stagingMaxAssertionsPerAA;

    address public deployedDAVerifier;
    address[] public deployedAdminVerifiers;
    address public deployedProductionOracle;
    address public deployedStagingOracle;

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
        deployedDAVerifier = _deployDAVerifier();
        // Deploy Admin Verifiers
        deployedAdminVerifiers = _deployAdminVerifiers();
        // Deploy state Oracle
        address stateOracle = _deployStateOracle(deployedDAVerifier, assertionTimelockBlocks, "State Oracle");
        // Deploy State Oracle Proxy
        deployedProductionOracle = _deployStateOracleProxy(stateOracle, deployedAdminVerifiers, maxAssertionsPerAA);

        // Deploy staging State Oracle
        address stagingOracle =
            _deployStateOracle(deployedDAVerifier, stagingAssertionTimelockBlocks, "Staging State Oracle");
        // Deploy staging State Oracle Proxy
        deployedStagingOracle =
            _deployStateOracleProxy(stagingOracle, deployedAdminVerifiers, stagingMaxAssertionsPerAA);
    }
}
