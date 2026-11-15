// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {StateOracle} from "../src/StateOracle.sol";
import {StateOracleTimelock} from "../src/StateOracleTimelock.sol";
import {StateOracleAccessControl} from "../src/StateOracleAccessControl.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {OwnableAdopter} from "./utils/Adopter.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";
import {ProxyHelper} from "./utils/ProxyHelper.t.sol";
import {StateOracleWindowLayoutBaseline} from "./utils/StateOracleWindowLayoutBaseline.sol";

/// @notice Tests in-place upgrade of populated legacy oracle storage.
contract StateOracleUpgradeTest is ProxyHelper {
    uint256 constant TIMELOCK = 100;
    uint16 constant MAX_ASSERTIONS = 7;
    uint256 constant OPEN_ACTIVATION = 170;
    uint256 constant REMOVED_ACTIVATION = 180;
    uint256 constant OLD_DEACTIVATION = 200;
    bytes32 constant OPEN_ASSERTION = keccak256("open assertion");
    bytes32 constant REMOVED_ASSERTION = keccak256("removed assertion");

    address oracleOwner;
    address nextOwner;
    address manager;
    address nextManager;
    address governance;
    address guardianAdmin;
    address operatorAdmin;
    address guardian;
    address operator;
    address adopter;
    IAdminVerifier adminVerifier;
    IDAVerifier daVerifier;
    StateOracle stateOracle;
    address originalProxy;
    address originalProxyAdmin;
    bytes32 originalProxyCodeHash;

    /// @notice Seeds a legacy proxy and migrates it atomically through its existing ProxyAdmin.
    function setUp() public {
        vm.roll(OLD_DEACTIVATION - 1);
        oracleOwner = makeAddr("oracle owner");
        nextOwner = makeAddr("pending oracle owner");
        manager = makeAddr("manager");
        nextManager = makeAddr("pending manager");
        governance = makeAddr("governance");
        guardianAdmin = makeAddr("guardian admin");
        operatorAdmin = makeAddr("operator admin");
        guardian = makeAddr("guardian");
        operator = makeAddr("operator");
        adopter = address(new OwnableAdopter(manager));
        adminVerifier = new AdminVerifierOwner();
        daVerifier = new DAVerifierMock();

        StateOracleWindowLayoutBaseline baseline = new StateOracleWindowLayoutBaseline(TIMELOCK);
        bytes memory data = abi.encodeCall(
            StateOracleWindowLayoutBaseline.initializeForTest,
            (oracleOwner, adminVerifier, daVerifier, MAX_ASSERTIONS, manager)
        );
        StateOracleWindowLayoutBaseline proxy = StateOracleWindowLayoutBaseline(deployProxy(address(baseline), data));
        originalProxy = address(proxy);
        originalProxyAdmin = getProxyAdmin(originalProxy);
        originalProxyCodeHash = originalProxy.codehash;

        vm.startPrank(oracleOwner);
        proxy.seedAdopter(adopter, manager, nextManager, 1);
        proxy.seedWindow(adopter, OPEN_ASSERTION, OPEN_ACTIVATION, 0);
        proxy.seedWindow(adopter, REMOVED_ASSERTION, REMOVED_ACTIVATION, OLD_DEACTIVATION);
        proxy.grantGovernanceRole(governance);
        proxy.grantGuardianAdminRole(guardianAdmin);
        proxy.grantOperatorAdminRole(operatorAdmin);
        proxy.grantGuardianRole(guardian);
        proxy.grantOperatorRole(operator);
        proxy.transferOwnership(nextOwner);
        vm.stopPrank();

        StateOracle implementation = new StateOracle(TIMELOCK);
        ProxyAdmin proxyAdmin = ProxyAdmin(getProxyAdmin(address(proxy)));
        assertEq(proxyAdmin.owner(), ADMIN, "Upgrade must use the existing ProxyAdmin owner");
        vm.prank(ADMIN);
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(proxy)),
            address(implementation),
            abi.encodeCall(StateOracle.initializeTimelockV2, ())
        );
        stateOracle = StateOracle(address(proxy));

        assertEq(
            address(uint160(uint256(vm.load(address(proxy), ERC1967Utils.IMPLEMENTATION_SLOT)))),
            address(implementation),
            "Proxy must execute the new implementation"
        );
    }

    /// @notice Migration preserves proxy identity and all populated application state.
    function test_upgradePreservesPopulatedWindowState() public {
        assertEq(address(stateOracle), originalProxy);
        assertEq(address(stateOracle).codehash, originalProxyCodeHash);
        assertEq(getProxyAdmin(address(stateOracle)), originalProxyAdmin);
        assertEq(ProxyAdmin(originalProxyAdmin).owner(), ADMIN);
        assertEq(stateOracle.registrationAvailableAt(adopter), 0);
        assertEq(stateOracle.owner(), oracleOwner);
        assertEq(stateOracle.pendingOwner(), nextOwner);
        assertTrue(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), oracleOwner));
        assertFalse(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), nextOwner));
        assertFalse(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), address(0)));
        assertFalse(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), ADMIN));
        assertTrue(stateOracle.hasRole(stateOracle.GOVERNANCE_ROLE(), governance));
        assertTrue(stateOracle.hasRole(stateOracle.GUARDIAN_ADMIN_ROLE(), guardianAdmin));
        assertTrue(stateOracle.hasRole(stateOracle.OPERATOR_ADMIN_ROLE(), operatorAdmin));
        assertTrue(stateOracle.hasRole(stateOracle.GUARDIAN_ROLE(), guardian));
        assertTrue(stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), operator));
        assertEq(stateOracle.getRoleAdmin(stateOracle.GOVERNANCE_ROLE()), stateOracle.DEFAULT_ADMIN_ROLE());
        assertEq(stateOracle.getRoleAdmin(stateOracle.GUARDIAN_ADMIN_ROLE()), stateOracle.DEFAULT_ADMIN_ROLE());
        assertEq(stateOracle.getRoleAdmin(stateOracle.OPERATOR_ADMIN_ROLE()), stateOracle.DEFAULT_ADMIN_ROLE());
        assertEq(stateOracle.getRoleAdmin(stateOracle.GUARDIAN_ROLE()), stateOracle.GUARDIAN_ADMIN_ROLE());
        assertEq(stateOracle.getRoleAdmin(stateOracle.OPERATOR_ROLE()), stateOracle.OPERATOR_ADMIN_ROLE());

        assertEq(stateOracle.getManager(adopter), manager);
        assertEq(stateOracle.getPendingManager(adopter), nextManager);
        assertEq(stateOracle.getAssertionCount(adopter), 1);
        assertEq(stateOracle.maxAssertionsPerAA(), MAX_ASSERTIONS);
        assertEq(stateOracle.ASSERTION_TIMELOCK_BLOCKS(), TIMELOCK);
        assertTrue(stateOracle.adminVerifiers(adminVerifier));
        assertTrue(stateOracle.daVerifiers(daVerifier));
        assertTrue(stateOracle.whitelistEnabled());
        assertTrue(stateOracle.whitelist(manager));
        assertFalse(stateOracle.whitelist(nextManager));
        assertTrue(stateOracle.hasAssertion(adopter, OPEN_ASSERTION));
        assertTrue(stateOracle.hasAssertion(adopter, REMOVED_ASSERTION));
        _assertWindow(OPEN_ASSERTION, OPEN_ACTIVATION, 0);
        _assertWindow(REMOVED_ASSERTION, REMOVED_ACTIVATION, OLD_DEACTIVATION);
    }

    /// @notice Recovery records its deadline outside the oracle and only clears existing manager fields.
    function test_recoveryWritesOnlyExistingManagerSlots() public {
        StateOracleTimelock controller = stateOracle.timelock();
        vm.prank(guardian);
        vm.expectPartialRevert(bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")));
        controller.startManagerRecovery(adopter);
        assertEq(stateOracle.registrationAvailableAt(adopter), 0);
        uint256 deadline = block.timestamp + 3 days;
        vm.record();
        vm.prank(guardian);
        stateOracle.revokeManager(adopter);
        (, bytes32[] memory writes) = vm.accesses(address(stateOracle));
        bytes32 managerSlot = keccak256(abi.encode(adopter, uint256(3)));
        assertEq(writes.length, 2);
        assertEq(writes[0], managerSlot);
        assertEq(writes[1], bytes32(uint256(managerSlot) + 1));
        assertEq(controller.registrationAvailableAt(address(stateOracle), adopter), deadline);
        assertEq(controller.registrationAvailableAt(makeAddr("other oracle"), adopter), 0);
        assertEq(stateOracle.registrationAvailableAt(adopter), deadline);
        assertEq(stateOracle.getManager(adopter), address(0));
        assertEq(stateOracle.getPendingManager(adopter), address(0));
        _assertWindow(OPEN_ASSERTION, OPEN_ACTIVATION, 0);
        _assertWindow(REMOVED_ASSERTION, REMOVED_ACTIVATION, OLD_DEACTIVATION);
        vm.warp(deadline);
        vm.prank(manager);
        stateOracle.registerAssertionAdopter(adopter, adminVerifier, "");
        assertEq(stateOracle.getManager(adopter), manager);
        assertEq(stateOracle.owner(), oracleOwner);
    }

    /// @notice Both fresh initializers reject an already initialized upgraded proxy.
    function test_upgradePreservesInitializationGuard() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        stateOracle.initializeWithWhitelist(
            nextOwner, new IAdminVerifier[](0), new IDAVerifier[](0), MAX_ASSERTIONS, true, new address[](0)
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        stateOracle.initialize(nextOwner, new IAdminVerifier[](0), new IDAVerifier[](0), MAX_ASSERTIONS);
        assertEq(stateOracle.owner(), oracleOwner);
    }

    /// @notice A pre-upgrade nomination needs a fresh delayed authorization before acceptance.
    function test_legacyPendingOwnerCannotAcceptWithoutFreshDelay() public {
        vm.prank(nextOwner);
        vm.expectRevert(StateOracleAccessControl.OwnershipNotReady.selector);
        stateOracle.acceptOwnership();
        vm.prank(oracleOwner);
        stateOracle.transferOwnership(nextOwner);
        vm.prank(nextOwner);
        vm.expectRevert(StateOracleAccessControl.OwnershipNotReady.selector);
        stateOracle.acceptOwnership();
        executeLast(stateOracle);
        vm.prank(nextOwner);
        stateOracle.acceptOwnership();
        assertEq(stateOracle.owner(), nextOwner);
        _assertWindow(OPEN_ASSERTION, OPEN_ACTIVATION, 0);
    }

    function test_upgradeReaddWaitsForPreservedDeactivation() public {
        vm.startPrank(manager);
        vm.expectRevert(StateOracle.AssertionAlreadyExists.selector);
        stateOracle.addAssertion(adopter, REMOVED_ASSERTION, daVerifier, "", "");
        _assertWindow(REMOVED_ASSERTION, REMOVED_ACTIVATION, OLD_DEACTIVATION);
        assertEq(stateOracle.getAssertionCount(adopter), 1);

        vm.roll(OLD_DEACTIVATION);
        vm.expectEmit(true, true, true, true, address(stateOracle));
        emit StateOracle.AssertionAdded(adopter, REMOVED_ASSERTION, OLD_DEACTIVATION + TIMELOCK, daVerifier, "", "");
        stateOracle.addAssertion(adopter, REMOVED_ASSERTION, daVerifier, "", "");
        _assertWindow(REMOVED_ASSERTION, OLD_DEACTIVATION + TIMELOCK, 0);
        assertEq(stateOracle.getAssertionCount(adopter), 2);

        vm.roll(OLD_DEACTIVATION + TIMELOCK);
        uint256 newDeactivation = block.number + TIMELOCK;
        vm.expectEmit(true, true, false, true, address(stateOracle));
        emit StateOracle.AssertionRemoved(adopter, REMOVED_ASSERTION, newDeactivation);
        stateOracle.removeAssertion(adopter, REMOVED_ASSERTION);
        vm.expectRevert(StateOracle.AssertionAlreadyRemoved.selector);
        stateOracle.removeAssertion(adopter, REMOVED_ASSERTION);
        vm.stopPrank();

        _assertWindow(REMOVED_ASSERTION, OLD_DEACTIVATION + TIMELOCK, newDeactivation);
        _assertWindow(OPEN_ASSERTION, OPEN_ACTIVATION, 0);
        assertEq(stateOracle.getAssertionCount(adopter), 1);
        assertEq(stateOracle.getManager(adopter), manager);
        assertEq(stateOracle.getPendingManager(adopter), nextManager);
    }

    function _assertWindow(bytes32 assertionId, uint256 activationBlock, uint256 deactivationBlock) internal view {
        (uint256 storedActivation, uint256 storedDeactivation) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(storedActivation, activationBlock, "Unexpected activation block");
        assertEq(storedDeactivation, deactivationBlock, "Unexpected deactivation block");
    }
}
