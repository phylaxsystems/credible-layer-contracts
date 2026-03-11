// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCore} from "./DeployCore.s.sol";

contract DeployCoreWithStaging is DeployCore {
    uint256 stagingAssertionTimelockBlocks;
    uint16 stagingMaxAssertionsPerAA;

    address public deployedDAVerifier;
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

        // Deploy shared DA Verifier (ECDSA)
        deployedDAVerifier = _deployDAVerifier();
        // Deploy shared Admin Verifiers
        deployedAdminVerifiers = _deployAdminVerifiers();

        // Production oracle
        address prodDAVerifierOnChain = _deployDAVerifierOnChain();
        address stateOracle = _deployStateOracle(assertionTimelockBlocks, "State Oracle");
        address[] memory prodDAVerifiers = new address[](2);
        prodDAVerifiers[0] = deployedDAVerifier;
        prodDAVerifiers[1] = prodDAVerifierOnChain;
        deployedProductionOracle =
            _deployStateOracleProxy(stateOracle, deployedAdminVerifiers, prodDAVerifiers, maxAssertionsPerAA);

        // Staging oracle
        address stagingDAVerifierOnChain = _deployDAVerifierOnChain();
        address stagingOracle = _deployStateOracle(stagingAssertionTimelockBlocks, "Staging State Oracle");
        address[] memory stagingDAVerifiers = new address[](2);
        stagingDAVerifiers[0] = deployedDAVerifier;
        stagingDAVerifiers[1] = stagingDAVerifierOnChain;
        deployedStagingOracle = _deployStateOracleProxy(
            stagingOracle, deployedAdminVerifiers, stagingDAVerifiers, stagingMaxAssertionsPerAA
        );
    }
}
