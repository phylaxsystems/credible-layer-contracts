// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ASSERTION_CONTRACT_ADDRESS, CALLER_ADDRESS, PRECOMPILE_ADDRESS} from "../../script/DeployCore.s.sol";
import {DeployCoreWithStaging} from "../../script/DeployCoreWithStaging.s.sol";
import {CREATE_X_ADDRESS} from "../../script/ICreateX.sol";
import {StateOracle} from "../../src/StateOracle.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {CreateXTestDouble} from "../utils/CreateXTestDouble.sol";

contract DeployCoreWithStagingScriptIntegrationTest is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant DA_PROVER = address(0xDA);

    DeployCoreWithStaging internal deployment;

    function setUp() public {
        vm.deal(CALLER_ADDRESS, 1);
        vm.deal(ASSERTION_CONTRACT_ADDRESS, 1);
        vm.deal(PRECOMPILE_ADDRESS, 1);

        CreateXTestDouble createXImplementation = new CreateXTestDouble();
        vm.etch(CREATE_X_ADDRESS, address(createXImplementation).code);

        vm.setEnv("STATE_ORACLE_MAX_ASSERTIONS_PER_AA", "10");
        vm.setEnv("STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS", "10");
        vm.setEnv("STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA", "20");
        vm.setEnv("STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS", "10");
        vm.setEnv("STATE_ORACLE_ADMIN_ADDRESS", vm.toString(ADMIN));
        vm.setEnv("DA_PROVER_ADDRESS", vm.toString(DA_PROVER));
        vm.setEnv("ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS", vm.toString(ADMIN));
        vm.setEnv("DEPLOY_ADMIN_VERIFIER_OWNER", "true");
        vm.setEnv("DEPLOY_ADMIN_VERIFIER_WHITELIST", "false");
        vm.setEnv("DEPLOY_ADMIN_VERIFIER_ALWAYS_APPROVE", "false");
        vm.setEnv("STATE_ORACLE_WHITELIST_ENABLED", "true");
        vm.setEnv("DEPLOYMENT_IS_TESTING", "false");

        deployment = new DeployCoreWithStaging();
    }

    function test_CompleteDeterministicDeploymentSupportsTestingConfiguration() public {
        uint256 cleanDeployment = vm.snapshotState();

        deployment.setUp();
        deployment.run();

        assertEq(CreateXTestDouble(CREATE_X_ADDRESS).deploymentCount(), 7);
        address productionOracle = deployment.deployedProductionOracle();
        address stagingOracle = deployment.deployedStagingOracle();
        assertNotEq(productionOracle, address(0));
        assertNotEq(stagingOracle, address(0));
        assertTrue(StateOracle(productionOracle).whitelistEnabled());
        assertTrue(StateOracle(stagingOracle).whitelistEnabled());

        assertTrue(vm.revertToState(cleanDeployment));

        vm.expectRevert("Always Approve verifier is test-only");
        deployment.deployAlwaysApproveAdminVerifier();

        vm.setEnv("STATE_ORACLE_WHITELIST_ENABLED", "false");
        vm.setEnv("DEPLOY_ADMIN_VERIFIER_OWNER", "false");
        vm.setEnv("DEPLOY_ADMIN_VERIFIER_ALWAYS_APPROVE", "true");

        vm.expectRevert("Always Approve verifier is test-only");
        deployment.setUp();

        vm.setEnv("DEPLOYMENT_IS_TESTING", "true");
        deployment.setUp();
        deployment.run();

        address verifier = deployment.deployedAdminVerifiers(0);
        StateOracle production = StateOracle(deployment.deployedProductionOracle());
        StateOracle staging = StateOracle(deployment.deployedStagingOracle());

        assertEq(CreateXTestDouble(CREATE_X_ADDRESS).deploymentCount(), 7);
        assertEq(address(production), productionOracle);
        assertEq(address(staging), stagingOracle);
        assertFalse(production.whitelistEnabled());
        assertFalse(staging.whitelistEnabled());
        assertTrue(production.isAdminVerifierRegistered(IAdminVerifier(verifier)));
        assertTrue(staging.isAdminVerifierRegistered(IAdminVerifier(verifier)));
        assertTrue(IAdminVerifier(verifier).verifyAdmin(address(0xBEEF), address(0xCAFE), ""));
    }
}
