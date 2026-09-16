// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ASSERTION_CONTRACT_ADDRESS, CALLER_ADDRESS, PRECOMPILE_ADDRESS} from "../../script/DeployCore.s.sol";
import {DeployWizard} from "../../script/DeployWizard.s.sol";
import {CREATE_X_ADDRESS} from "../../script/ICreateX.sol";
import {StateOracle} from "../../src/StateOracle.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {CreateXTestDouble} from "../utils/CreateXTestDouble.sol";

contract DeployWizardCreateXHarness is DeployWizard {
    function configureForTest(address _admin, address _superAdmin) external {
        testingDeployment = true;
        deployStaging = true;
        stateOracleWhitelistEnabled = false;
        admin = _admin;
        assertionTimelockBlocks = 10;
        maxAssertionsPerAA = 10;
        stagingAssertionTimelockBlocks = 20;
        stagingMaxAssertionsPerAA = 20;
        daOnChainProduction = true;
        daOnChainStaging = true;
        adminSuperAdminProduction = true;
        adminSuperAdminStaging = true;
        adminAlwaysApproveProduction = true;
        adminAlwaysApproveStaging = true;
        testSuperAdmin = _superAdmin;
        initialWhitelist = new address[](0);
    }
}

contract DeployWizardCreateXIntegrationTest is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant SUPER_ADMIN = address(0x5A);

    DeployWizardCreateXHarness internal deployment;

    function setUp() public {
        vm.deal(CALLER_ADDRESS, 1);
        vm.deal(ASSERTION_CONTRACT_ADDRESS, 1);
        vm.deal(PRECOMPILE_ADDRESS, 1);

        CreateXTestDouble createXImplementation = new CreateXTestDouble();
        vm.etch(CREATE_X_ADDRESS, address(createXImplementation).code);

        deployment = new DeployWizardCreateXHarness();
        deployment.configureForTest(ADMIN, SUPER_ADMIN);
    }

    function test_TestingDeploymentUsesCreateXForEveryContract() public {
        deployment.run();

        CreateXTestDouble createX = CreateXTestDouble(CREATE_X_ADDRESS);
        assertEq(createX.deploymentCount(), 7);

        IAdminVerifier superAdminVerifier = IAdminVerifier(createX.deployments(1));
        IAdminVerifier alwaysApproveVerifier = IAdminVerifier(createX.deployments(2));
        StateOracle production = StateOracle(createX.deployments(4));
        StateOracle staging = StateOracle(createX.deployments(6));

        assertFalse(production.whitelistEnabled());
        assertFalse(staging.whitelistEnabled());
        assertTrue(production.isAdminVerifierRegistered(superAdminVerifier));
        assertTrue(production.isAdminVerifierRegistered(alwaysApproveVerifier));
        assertTrue(staging.isAdminVerifierRegistered(superAdminVerifier));
        assertTrue(staging.isAdminVerifierRegistered(alwaysApproveVerifier));
        assertTrue(superAdminVerifier.verifyAdmin(address(0xBEEF), SUPER_ADMIN, ""));
        assertTrue(alwaysApproveVerifier.verifyAdmin(address(0xBEEF), address(0xCAFE), ""));
    }
}
