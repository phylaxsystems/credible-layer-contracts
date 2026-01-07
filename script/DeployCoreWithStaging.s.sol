// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCore} from "./DeployCore.s.sol";
import {console2} from "forge-std/console2.sol";

// Address used to deploy the assertion contract to the forked db, and to call assertion functions.
address constant CALLER = 0x00000000000000000000000000000000000001a4;

// Fixed address of the assertion contract is used to deploy assertion contracts.
// Deploying assertion contracts via the caller address @ nonce 0 results in this address.
address constant ASSERTION_CONTRACT = 0x63F9abBE8aA6Ba1261Ef3B0CBfb25A5Ff8eEeD10;

// Precompile address
address constant PRECOMPILE_ADDRESS = 0x4461812e00718ff8D80929E3bF595AEaaa7b881E;

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

    function _fundPersistentAccounts() internal {
        _fundIfEmpty(CALLER, "CALLER");
        _fundIfEmpty(ASSERTION_CONTRACT, "ASSERTION_CONTRACT");
        _fundIfEmpty(PRECOMPILE_ADDRESS, "PRECOMPILE_ADDRESS");
    }

    function _fundIfEmpty(address account, string memory name) internal {
        if (account.balance == 0) {
            (bool success,) = account.call{value: 1}("");
            require(success, string.concat("Failed to fund ", name));
            console2.log("Funded", name, "with 1 wei:", account);
        } else {
            console2.log("Already funded", name, "balance:", account.balance);
        }
    }
}
