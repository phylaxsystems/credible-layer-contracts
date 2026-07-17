// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DeployCore} from "../script/DeployCore.s.sol";
import {DeployTestingAdminVerifiers} from "../script/DeployTestingAdminVerifiers.s.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {StateOracle} from "../src/StateOracle.sol";
import {AdminVerifierSuperAdmin} from "../src/verification/admin/AdminVerifierSuperAdmin.sol";
import {AdminVerifierWhitelist} from "../src/verification/admin/AdminVerifierWhitelist.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";
import {OwnableAdopter} from "./utils/Adopter.sol";

contract DeployCoreHarness is DeployCore {
    function configureAdminVerifiers(
        address _admin,
        bool _deployOwnerVerifier,
        bool _deployWhitelistVerifier,
        address _whitelistAdmin
    ) external {
        admin = _admin;
        deployOwnerVerifier = _deployOwnerVerifier;
        deployWhitelistVerifier = _deployWhitelistVerifier;
        whitelistAdmin = _whitelistAdmin;
    }

    function deployAdminVerifiersForTest() external returns (address[] memory) {
        return _deployAdminVerifiers();
    }

    function deployStateOracleProxyForTest(
        address stateOracle,
        address[] memory adminVerifierDeployments,
        address[] memory daVerifierAddresses,
        uint16 maxAssertions
    ) external returns (address) {
        return _deployStateOracleProxy(stateOracle, adminVerifierDeployments, daVerifierAddresses, maxAssertions);
    }
}

contract DeployTestingAdminVerifiersHarness is DeployTestingAdminVerifiers {
    function configureTestingAdminVerifiers(
        address _stateOracle,
        address _superAdmin,
        bool _deploySuperAdminVerifier,
        bool _deployAlwaysApproveVerifier,
        bool _addToStateOracle
    ) external {
        stateOracle = _stateOracle;
        superAdmin = _superAdmin;
        deploySuperAdminVerifierEnabled = _deploySuperAdminVerifier;
        deployAlwaysApproveVerifierEnabled = _deployAlwaysApproveVerifier;
        addToStateOracle = _addToStateOracle;
    }

    function runForTest() external returns (address[] memory) {
        return _run();
    }
}

contract DeployAdminVerifiersTest is Test {
    address constant ADMIN = address(uint160(uint256(keccak256(abi.encode("pcl.test.DeployAdminVerifiers.ADMIN")))));
    address constant OWNER = address(uint160(uint256(keccak256(abi.encode("pcl.test.DeployAdminVerifiers.OWNER")))));
    address constant WHITELIST_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.DeployAdminVerifiers.WHITELIST_ADMIN")))));
    address constant SUPER_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.DeployAdminVerifiers.SUPER_ADMIN")))));
    address constant OTHER = address(uint160(uint256(keccak256(abi.encode("pcl.test.DeployAdminVerifiers.OTHER")))));
    uint16 constant MAX_ASSERTIONS_PER_AA = 5;

    function test_coreDeployAdminVerifiersAddsOnlyProductionVerifiersToStateOracle() public {
        DeployCoreHarness deployer = new DeployCoreHarness();
        deployer.configureAdminVerifiers(ADMIN, true, true, WHITELIST_ADMIN);

        address[] memory verifiers = deployer.deployAdminVerifiersForTest();
        assertEq(verifiers.length, 2);

        OwnableAdopter adopter = new OwnableAdopter(OWNER);
        assertTrue(IAdminVerifier(verifiers[0]).verifyAdmin(address(adopter), OWNER, ""));
        assertTrue(AdminVerifierWhitelist(verifiers[1]).hasRole(bytes32(0), WHITELIST_ADMIN));
        assertTrue(
            AdminVerifierWhitelist(verifiers[1])
                .hasRole(AdminVerifierWhitelist(verifiers[1]).WHITELIST_ADMIN_ROLE(), WHITELIST_ADMIN)
        );

        address[] memory daVerifiers = new address[](1);
        daVerifiers[0] = address(new DAVerifierMock());
        StateOracle stateOracle = StateOracle(
            deployer.deployStateOracleProxyForTest(
                address(_deployStateOracleImplementation()), verifiers, daVerifiers, MAX_ASSERTIONS_PER_AA
            )
        );

        for (uint256 i = 0; i < verifiers.length; i++) {
            assertTrue(stateOracle.isAdminVerifierRegistered(IAdminVerifier(verifiers[i])));
        }
    }

    function test_RevertIf_coreDeployWhitelistVerifierWithoutAdmin() public {
        DeployCoreHarness deployer = new DeployCoreHarness();
        deployer.configureAdminVerifiers(ADMIN, false, true, address(0));

        vm.expectRevert(bytes("Invalid whitelist admin"));
        deployer.deployAdminVerifiersForTest();
    }

    function test_testingScriptDeploysAndAddsTestVerifiersToStateOracle() public {
        DeployTestingAdminVerifiersHarness deployer = new DeployTestingAdminVerifiersHarness();
        StateOracle stateOracle = _deployStateOracle(address(deployer), new IAdminVerifier[](0));
        deployer.configureTestingAdminVerifiers(address(stateOracle), SUPER_ADMIN, true, true, true);

        address[] memory verifiers = deployer.runForTest();
        assertEq(verifiers.length, 2);

        assertTrue(AdminVerifierSuperAdmin(verifiers[0]).verifyAdmin(address(1), SUPER_ADMIN, ""));
        assertTrue(IAdminVerifier(verifiers[1]).verifyAdmin(address(1), OTHER, ""));
        assertTrue(stateOracle.isAdminVerifierRegistered(IAdminVerifier(verifiers[0])));
        assertTrue(stateOracle.isAdminVerifierRegistered(IAdminVerifier(verifiers[1])));
    }

    function test_RevertIf_testingScriptDeploysSuperAdminVerifierWithoutAdmin() public {
        DeployTestingAdminVerifiersHarness deployer = new DeployTestingAdminVerifiersHarness();
        deployer.configureTestingAdminVerifiers(address(1), address(0), true, false, false);

        vm.expectRevert(bytes("Invalid super admin"));
        deployer.runForTest();
    }

    function test_RevertIf_testingScriptAddsVerifiersWithoutStateOracle() public {
        DeployTestingAdminVerifiersHarness deployer = new DeployTestingAdminVerifiersHarness();
        deployer.configureTestingAdminVerifiers(address(0), SUPER_ADMIN, false, true, true);

        vm.expectRevert(bytes("Invalid state oracle"));
        deployer.runForTest();
    }

    function _deployStateOracle(address oracleAdmin, IAdminVerifier[] memory adminVerifiers)
        internal
        returns (StateOracle)
    {
        StateOracle implementation = _deployStateOracleImplementation();
        IDAVerifier[] memory daVerifiers = new IDAVerifier[](1);
        daVerifiers[0] = IDAVerifier(address(new DAVerifierMock()));
        bytes memory initCallData = abi.encodeWithSelector(
            StateOracle.initialize.selector, oracleAdmin, adminVerifiers, daVerifiers, MAX_ASSERTIONS_PER_AA
        );
        return
            StateOracle(address(new TransparentUpgradeableProxy(address(implementation), address(this), initCallData)));
    }

    function _deployStateOracleImplementation() internal returns (StateOracle) {
        return new StateOracle(10);
    }
}
