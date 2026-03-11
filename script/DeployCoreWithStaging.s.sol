// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCore} from "./DeployCore.s.sol";

contract DeployCoreWithStaging is DeployCore {
    uint256 stagingAssertionTimelockBlocks;
    uint16 stagingMaxAssertionsPerAA;

    address public deployedDAVerifier;
    address public deployedDAVerifierOnChain;
    address[] public deployedAdminVerifiers;
    address public deployedProductionOracle;
    address public deployedStagingOracle;

    function setUp() public override {
        super.setUp();

        // Staging state oracle parameters
        stagingMaxAssertionsPerAA = uint16(vm.envUint("STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA"));
        stagingAssertionTimelockBlocks = vm.envUint("STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS");

        assert(stagingAssertionTimelockBlocks > 0);
        assert(stagingMaxAssertionsPerAA > 0);
    }

    function run() public override broadcast {
        // Fund persistent accounts with 1 wei if empty
        _fundPersistentAccounts();

        // Deploy shared verifiers
        deployedDAVerifier = _deployDAVerifier();
        deployedDAVerifierOnChain = _deployDAVerifierOnChain();
        deployedAdminVerifiers = _deployAdminVerifiers();

        // Shared DA verifier list for both oracles
        address[] memory daVerifiers = new address[](2);
        daVerifiers[0] = deployedDAVerifier;
        daVerifiers[1] = deployedDAVerifierOnChain;

        // Production oracle
        address stateOracle = _deployStateOracle(assertionTimelockBlocks, "State Oracle");
        deployedProductionOracle =
            _deployStateOracleProxy(stateOracle, deployedAdminVerifiers, daVerifiers, maxAssertionsPerAA);

        // Staging oracle
        address stagingOracle = _deployStateOracle(stagingAssertionTimelockBlocks, "Staging State Oracle");
        deployedStagingOracle =
            _deployStateOracleProxy(stagingOracle, deployedAdminVerifiers, daVerifiers, stagingMaxAssertionsPerAA);
    }
}
