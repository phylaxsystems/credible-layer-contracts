// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CALLER_ADDRESS, ASSERTION_CONTRACT_ADDRESS, PRECOMPILE_ADDRESS} from "../../script/DeployCore.s.sol";
import {StateOracle} from "../../src/StateOracle.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {AdminVerifierOwner} from "../../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierECDSA} from "../../src/verification/da/DAVerifierECDSA.sol";
import {OwnableAdopter} from "../utils/Adopter.sol";

contract DeployCoreWithStagingIntegrationTest is Test {
    address public admin = address(0x1);
    address public daProver = address(0x2);
    address public user = address(0x3);

    StateOracle public productionOracle;
    StateOracle public stagingOracle;
    IAdminVerifier public adminVerifier;

    function setUp() public {
        vm.deal(admin, 100 ether);

        // Fund persistent accounts
        vm.deal(CALLER_ADDRESS, 1);
        vm.deal(ASSERTION_CONTRACT_ADDRESS, 1);
        vm.deal(PRECOMPILE_ADDRESS, 1);

        vm.startPrank(admin);

        // Deploy shared components
        DAVerifierECDSA daVerifier = new DAVerifierECDSA(daProver);
        adminVerifier = IAdminVerifier(address(new AdminVerifierOwner()));

        IAdminVerifier[] memory verifiers = new IAdminVerifier[](1);
        verifiers[0] = adminVerifier;

        // Deploy production oracle
        StateOracle prodImpl = new StateOracle(100, address(daVerifier));
        productionOracle = StateOracle(
            address(
                new TransparentUpgradeableProxy(
                    address(prodImpl), admin, abi.encodeCall(StateOracle.initialize, (admin, verifiers, 10))
                )
            )
        );

        // Deploy staging oracle
        StateOracle stagingImpl = new StateOracle(10, address(daVerifier));
        stagingOracle = StateOracle(
            address(
                new TransparentUpgradeableProxy(
                    address(stagingImpl), admin, abi.encodeCall(StateOracle.initialize, (admin, verifiers, 5))
                )
            )
        );

        vm.stopPrank();
    }

    function test_PersistentAccountsFunded() public view {
        assertEq(CALLER_ADDRESS.balance, 1, "CALLER_ADDRESS should have 1 wei");
        assertEq(ASSERTION_CONTRACT_ADDRESS.balance, 1, "ASSERTION_CONTRACT_ADDRESS should have 1 wei");
        assertEq(PRECOMPILE_ADDRESS.balance, 1, "PRECOMPILE_ADDRESS should have 1 wei");
    }

    function test_BothOraclesDeployed() public view {
        assertTrue(address(productionOracle) != address(0), "Production oracle not deployed");
        assertTrue(address(stagingOracle) != address(0), "Staging oracle not deployed");
        assertTrue(address(productionOracle) != address(stagingOracle), "Oracles should be different");
    }

    function test_BothOraclesShareSameAdminVerifier() public view {
        assertTrue(productionOracle.isAdminVerifierRegistered(IAdminVerifier(adminVerifier)));
        assertTrue(stagingOracle.isAdminVerifierRegistered(IAdminVerifier(adminVerifier)));
    }

    function test_OraclesHaveDifferentConfigs() public view {
        assertEq(productionOracle.maxAssertionsPerAA(), 10);
        assertEq(stagingOracle.maxAssertionsPerAA(), 5);
        assertEq(productionOracle.ASSERTION_TIMELOCK_BLOCKS(), 100);
        assertEq(stagingOracle.ASSERTION_TIMELOCK_BLOCKS(), 10);
    }

    function test_AddToWhitelistOnBothOracles() public {
        vm.startPrank(admin);
        productionOracle.addToWhitelist(user);
        stagingOracle.addToWhitelist(user);
        vm.stopPrank();

        assertTrue(productionOracle.isWhitelisted(user));
        assertTrue(stagingOracle.isWhitelisted(user));
    }

    function test_RegisterContractOnBothOracles() public {
        // Deploy Ownable contract
        vm.prank(user);
        OwnableAdopter adopter = new OwnableAdopter(user);

        // Whitelist user
        vm.startPrank(admin);
        productionOracle.addToWhitelist(user);
        stagingOracle.addToWhitelist(user);
        vm.stopPrank();

        // Register on both
        vm.startPrank(user);
        productionOracle.registerAssertionAdopter(address(adopter), IAdminVerifier(adminVerifier), "");
        stagingOracle.registerAssertionAdopter(address(adopter), IAdminVerifier(adminVerifier), "");
        vm.stopPrank();

        // Verify
        assertEq(productionOracle.getManager(address(adopter)), user);
        assertEq(stagingOracle.getManager(address(adopter)), user);
    }

    function test_FullWorkflow_WhitelistAndRegisterOnBothOracles() public {
        // Whitelist user on both oracles
        vm.startPrank(admin);
        productionOracle.addToWhitelist(user);
        stagingOracle.addToWhitelist(user);
        vm.stopPrank();

        assertTrue(productionOracle.isWhitelisted(user), "User not whitelisted on production");
        assertTrue(stagingOracle.isWhitelisted(user), "User not whitelisted on staging");

        // Deploy Ownable contract
        vm.prank(user);
        OwnableAdopter adopter = new OwnableAdopter(user);
        assertEq(adopter.owner(), user, "User should own adopter");

        // Register on production oracle
        vm.prank(user);
        productionOracle.registerAssertionAdopter(address(adopter), IAdminVerifier(adminVerifier), "");
        assertEq(productionOracle.getManager(address(adopter)), user, "Wrong manager on production");

        // Register on staging Oracle with same contract/verifier
        vm.prank(user);
        stagingOracle.registerAssertionAdopter(address(adopter), IAdminVerifier(adminVerifier), "");
        assertEq(stagingOracle.getManager(address(adopter)), user, "Wrong manager on staging");

        // Verify both oracles use shared admin verifier
        assertTrue(
            productionOracle.isAdminVerifierRegistered(IAdminVerifier(adminVerifier)),
            "Admin verifier not registered on production"
        );
        assertTrue(
            stagingOracle.isAdminVerifierRegistered(IAdminVerifier(adminVerifier)),
            "Admin verifier not registered on staging"
        );
    }
}
