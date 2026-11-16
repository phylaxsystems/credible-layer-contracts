// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {StateOracleTimelock} from "../src/StateOracleTimelock.sol";
import {StateOracleAdministration} from "../src/StateOracleAdministration.sol";
import {StateOracleAccessControl} from "../src/StateOracleAccessControl.sol";
import {Batch} from "../src/Batch.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {ProxyHelper} from "./utils/ProxyHelper.t.sol";
import {StateOracleWindowLayoutBaseline} from "./utils/StateOracleWindowLayoutBaseline.sol";

/// @notice Exercises fresh initialization, authenticated migration and independent oracle queues.
contract StateOracleAdministrationTest is ProxyHelper {
    StateOracle internal oracle;
    StateOracle internal peer;
    StateOracleTimelock internal controller;
    StateOracle internal implementation;
    address internal governor = address(0xA11CE);

    /// @notice Deploys two fresh oracles directly, without prediction or migration.
    function setUp() public virtual {
        implementation = new StateOracle(75);
        bytes memory data = abi.encodeCall(
            StateOracle.initializeWithWhitelist,
            (governor, new IAdminVerifier[](0), new IDAVerifier[](0), 20, false, new address[](0))
        );
        oracle = StateOracle(deployProxy(address(implementation), data));
        peer = StateOracle(deployProxy(address(new StateOracle(25)), data));
        controller = oracle.timelock();
    }

    /// @notice Creates an independently defined version-1 storage fixture, only for migration tests.
    /// @return target Initialized legacy proxy without a timelock.
    function _legacyProxy() internal returns (StateOracle target) {
        StateOracleWindowLayoutBaseline baseline = new StateOracleWindowLayoutBaseline(75);
        target = StateOracle(
            deployProxy(
                address(baseline),
                abi.encodeCall(
                    StateOracleWindowLayoutBaseline.initializeForTest,
                    (governor, IAdminVerifier(address(0xA)), IDAVerifier(address(0xB)), 20, governor)
                )
            )
        );
    }

    /// @notice Performs the authenticated V2 upgrade on a legacy proxy.
    /// @param target Legacy proxy to migrate.
    function _migrate(StateOracle target) internal {
        ProxyAdmin admin = ProxyAdmin(getProxyAdmin(address(target)));
        vm.prank(ADMIN);
        admin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(target)),
            address(implementation),
            abi.encodeCall(StateOracle.initializeTimelockV2, ())
        );
    }

    /// @notice Advances to readiness and relays one operation.
    /// @param target Oracle holding the proposal.
    /// @param id Proposal identifier.
    function _execute(StateOracle target, bytes32 id) internal {
        vm.warp(target.administrationOperation(id).readyAt);
        target.executeAdministration(id);
    }

    /// @notice Each fresh oracle has a distinct controller and exactly one proposer/executor.
    function test_controllerHasOnlyFixedMechanicalAuthority() public {
        assertNotEq(address(controller), address(peer.timelock()));
        assertEq(controller.ORACLE(), address(oracle));
        assertEq(peer.timelock().ORACLE(), address(peer));
        assertEq(oracle.ASSERTION_TIMELOCK_BLOCKS(), 75);
        assertEq(peer.ASSERTION_TIMELOCK_BLOCKS(), 25);
        assertTrue(controller.hasRole(controller.DEFAULT_ADMIN_ROLE(), address(controller)));
        assertFalse(controller.hasRole(controller.DEFAULT_ADMIN_ROLE(), governor));
        assertTrue(controller.hasRole(controller.PROPOSER_ROLE(), address(oracle)));
        assertTrue(controller.hasRole(controller.EXECUTOR_ROLE(), address(oracle)));
        assertFalse(controller.hasRole(controller.EXECUTOR_ROLE(), address(peer)));
        assertFalse(controller.hasRole(controller.PROPOSER_ROLE(), address(peer)));
        assertFalse(controller.hasRole(controller.EXECUTOR_ROLE(), address(0)));
        assertFalse(controller.hasRole(controller.CANCELLER_ROLE(), address(oracle)));
        bytes32 proposer = controller.PROPOSER_ROLE();
        vm.expectRevert(StateOracleTimelock.UnsupportedOperation.selector);
        controller.grantRole(proposer, governor);
        vm.prank(address(controller));
        vm.expectRevert(StateOracleTimelock.UnsupportedOperation.selector);
        controller.grantRole(proposer, governor);
        vm.prank(address(oracle));
        vm.expectRevert(StateOracleTimelock.UnsupportedOperation.selector);
        controller.renounceRole(proposer, address(oracle));
        vm.expectRevert(StateOracleTimelock.UnsupportedOperation.selector);
        controller.cancel(bytes32(0));
    }

    /// @notice Delay changes serialize per oracle, remain independent, and wait the old delay.
    function test_delayChangesSerializeIndependentlyAndUseCurrentDelay() public {
        vm.prank(governor);
        bytes32 increase = oracle.scheduleDelayUpdate(5 days);
        uint256 ready = block.timestamp + 3 days;
        assertEq(controller.getTimestamp(increase), ready);
        vm.prank(governor);
        vm.expectRevert(abi.encodeWithSelector(StateOracleTimelock.AdministrationOperationPending.selector, increase));
        oracle.scheduleDelayUpdate(4 days);
        vm.prank(governor);
        bytes32 peerIncrease = peer.scheduleDelayUpdate(4 days);
        vm.warp(ready - 1);
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        oracle.executeAdministration(increase);
        vm.warp(ready);
        oracle.executeAdministration(increase);
        assertEq(oracle.administrationDelay(), 5 days);
        assertEq(peer.administrationDelay(), 3 days);
        peer.executeAdministration(peerIncrease);
        assertEq(peer.administrationDelay(), 4 days);
        vm.prank(governor);
        bytes32 decrease = oracle.scheduleDelayUpdate(3 days);
        assertEq(controller.getTimestamp(decrease), ready + 5 days);
        vm.warp(ready + 5 days - 1);
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        oracle.executeAdministration(decrease);
        _execute(oracle, decrease);
        assertEq(oracle.administrationDelay(), 3 days);
        assertEq(peer.administrationDelay(), 4 days);
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        oracle.executeAdministration(increase);
    }

    /// @notice Neither a below-floor delay, a changed payload nor a peer relay can bypass the queue.
    function test_floorAndExactPayloadCannotBeBypassed() public {
        assertEq(controller.getMinDelay(), 3 days);
        vm.prank(governor);
        vm.expectRevert(StateOracleTimelock.DelayBelowFloor.selector);
        oracle.scheduleDelayUpdate(3 days - 1);
        vm.prank(address(controller));
        vm.expectRevert(StateOracleTimelock.DelayBelowFloor.selector);
        controller.updateDelay(0);
        vm.prank(governor);
        bytes32 id = oracle.scheduleDelayUpdate(4 days);
        StateOracleTimelock.Operation memory operation = oracle.administrationOperation(id);
        vm.prank(address(oracle));
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        controller.execute(address(controller), 0, abi.encodeCall(controller.updateDelay, (6 days)), 0, operation.salt);
        vm.expectRevert(StateOracleAdministration.UnknownAdministrationOperation.selector);
        peer.executeAdministration(id);
        _execute(oracle, id);
        assertEq(controller.getMinDelay(), 4 days);
    }

    /// @notice Migration rejects ordinary callers, fresh instances and replay while preserving legacy state.
    function test_migrationIsAuthenticatedOneTimeAndCannotResetState() public {
        StateOracle target = _legacyProxy();
        ProxyAdmin admin = ProxyAdmin(getProxyAdmin(address(target)));
        vm.prank(ADMIN);
        admin.upgradeAndCall(ITransparentUpgradeableProxy(address(target)), address(implementation), "");
        assertEq(address(target.timelock()), address(0));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        target.initialize(governor, new IAdminVerifier[](0), new IDAVerifier[](0), 1);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        target.initializeWithWhitelist(
            governor, new IAdminVerifier[](0), new IDAVerifier[](0), 1, false, new address[](0)
        );
        vm.prank(governor);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        target.initializeTimelockV2();
        _migrate(target);
        assertEq(target.timelock().ORACLE(), address(target));
        assertEq(target.owner(), governor);
        assertEq(target.maxAssertionsPerAA(), 20);
        assertTrue(target.whitelist(governor));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        _migrate(target);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        _migrate(oracle);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        implementation.initializeTimelockV2();
    }

    /// @notice A later implementation upgrade retains the controller, its delay and pending queue.
    function test_laterUpgradeKeepsTimelockAndPendingOperations() public {
        vm.prank(governor);
        bytes32 id = oracle.scheduleDelayUpdate(4 days);
        ProxyAdmin admin = ProxyAdmin(getProxyAdmin(address(oracle)));
        StateOracle next = new StateOracle(75);
        vm.prank(ADMIN);
        admin.upgradeAndCall(ITransparentUpgradeableProxy(address(oracle)), address(next), "");
        assertEq(address(oracle.timelock()), address(controller));
        assertEq(oracle.latestAdministrationOperation(), id);
        _execute(oracle, id);
        assertEq(oracle.administrationDelay(), 4 days);
    }

    /// @notice The controller rejects untrusted callers, external targets and batch bypasses.
    function test_rawCallsCannotBypassTypedQueueOrDelay() public {
        bytes memory data = abi.encodeCall(controller.updateDelay, (4 days));
        vm.expectPartialRevert(bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")));
        controller.schedule(address(controller), 0, data, 0, 0, 3 days);
        vm.prank(address(peer));
        vm.expectPartialRevert(bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")));
        controller.schedule(address(controller), 0, data, 0, 0, 3 days);
        vm.prank(address(oracle));
        vm.expectPartialRevert(TimelockController.TimelockInsufficientDelay.selector);
        controller.schedule(address(controller), 0, data, 0, 0, 3 days - 1);
        vm.prank(address(oracle));
        vm.expectRevert(StateOracleTimelock.UnsupportedOperation.selector);
        controller.schedule(address(peer), 0, data, 0, 0, 3 days);
        vm.prank(address(oracle));
        vm.expectRevert(StateOracleTimelock.UnsupportedOperation.selector);
        controller.scheduleBatch(new address[](0), new uint256[](0), new bytes[](0), 0, 0, 3 days);
        vm.expectPartialRevert(TimelockController.TimelockUnauthorizedCaller.selector);
        controller.updateDelay(4 days);
    }

    /// @notice Migration adds only the ERC-7201 controller reference; queue operations write no oracle slots.
    function test_migrationWritesControllerNamespaceAndQueueStaysExternal() public {
        StateOracle target = _legacyProxy();
        bytes32 controllerSlot = keccak256(
            abi.encode(uint256(keccak256("phylax.storage.StateOracleAdministration")) - 1)
        ) & ~bytes32(uint256(0xff));
        assertEq(vm.load(address(target), controllerSlot), bytes32(0));
        vm.record();
        _migrate(target);
        (, bytes32[] memory writes) = vm.accesses(address(target));
        bytes32 versionSlot = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffbf601132;
        assertGt(writes.length, 0);
        for (uint256 i; i < writes.length; ++i) {
            assertTrue(
                writes[i] == ERC1967Utils.IMPLEMENTATION_SLOT || writes[i] == versionSlot || writes[i] == controllerSlot
            );
        }
        assertEq(address(uint160(uint256(vm.load(address(target), controllerSlot)))), address(target.timelock()));
        assertEq(address(uint160(uint256(vm.load(address(oracle), controllerSlot)))), address(controller));
        assertEq(uint256(vm.load(address(target), versionSlot)), 4);
        vm.record();
        vm.prank(governor);
        bytes32 id = target.scheduleDelayUpdate(4 days);
        (, writes) = vm.accesses(address(target));
        assertEq(writes.length, 0, "Queue belongs to controller, not oracle");
        vm.warp(target.administrationOperation(id).readyAt);
        vm.record();
        target.executeAdministration(id);
        (, writes) = vm.accesses(address(target));
        assertEq(writes.length, 0);
        assertTrue(target.timelock().isOperationDone(id));
    }

    /// @notice Every delegatable role waits D for grants, revocations and self-renunciation.
    function test_allRolesWaitForGrantRevokeAndSelfRenunciation() public {
        bytes32[5] memory roles = [
            oracle.GOVERNANCE_ROLE(),
            oracle.GUARDIAN_ADMIN_ROLE(),
            oracle.GUARDIAN_ROLE(),
            oracle.OPERATOR_ADMIN_ROLE(),
            oracle.OPERATOR_ROLE()
        ];
        address account = address(0xB0B);
        for (uint256 i; i < roles.length; ++i) {
            vm.prank(governor);
            oracle.grantRole(roles[i], account);
            bytes32 id = oracle.latestAdministrationOperation();
            assertFalse(oracle.hasRole(roles[i], account));
            vm.warp(oracle.administrationOperation(id).readyAt - 1);
            vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
            oracle.executeAdministration(id);
            _execute(oracle, id);
            assertTrue(oracle.hasRole(roles[i], account));
            vm.prank(governor);
            oracle.revokeRole(roles[i], account);
            assertTrue(oracle.hasRole(roles[i], account));
            executeLast(oracle);
            assertFalse(oracle.hasRole(roles[i], account));
            vm.prank(governor);
            oracle.grantRole(roles[i], account);
            executeLast(oracle);
            vm.prank(account);
            oracle.renounceRole(roles[i], account);
            assertTrue(oracle.hasRole(roles[i], account));
            executeLast(oracle);
            assertFalse(oracle.hasRole(roles[i], account));
        }
    }

    /// @notice Pending roles confer no authority and neither callbacks nor batching bypass the delay.
    function test_roleEscalationCallbacksAndBatchCannotSkipWait() public {
        bytes32 role = oracle.GUARDIAN_ADMIN_ROLE();
        address account = address(0xB0B);
        vm.prank(governor);
        oracle.grantRole(role, account);
        bytes32 id = oracle.latestAdministrationOperation();
        vm.prank(account);
        vm.expectPartialRevert(bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")));
        oracle.grantGuardianRole(account);
        vm.prank(governor);
        vm.expectRevert(StateOracleAdministration.CallerNotTimelock.selector);
        oracle.applyRoleChange(role, account, true);
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(oracle.executeAdministration, (id));
        vm.prank(governor);
        vm.expectPartialRevert(Batch.BatchError.selector);
        oracle.batch(calls);
        vm.prank(governor);
        vm.expectPartialRevert(StateOracleAdministration.AdministrationOperationPending.selector);
        oracle.revokeRole(role, account);
        _execute(oracle, id);
        vm.prank(account);
        oracle.grantGuardianRole(account);
        assertFalse(oracle.hasRole(oracle.GUARDIAN_ROLE(), account));
    }

    /// @notice Ownership requires a matured exact nomination and preserves the owner/default-admin invariant.
    function test_ownershipEligibilityBindsExactRecipientAndPreservesRoles() public {
        address first = address(0xB0B);
        address second = address(0xCAFE);
        vm.record();
        vm.prank(governor);
        oracle.transferOwnership(first);
        (, bytes32[] memory writes) = vm.accesses(address(oracle));
        assertEq(writes.length, 1);
        assertEq(writes[0], bytes32(uint256(1)), "Only existing pendingOwner changes");
        vm.prank(first);
        vm.expectRevert(StateOracleAccessControl.OwnershipNotReady.selector);
        oracle.acceptOwnership();
        vm.record();
        executeLast(oracle);
        (, writes) = vm.accesses(address(oracle));
        assertEq(writes.length, 0, "Eligibility lives in the completed controller operation");
        vm.prank(governor);
        oracle.transferOwnership(second);
        vm.prank(second);
        vm.expectRevert(StateOracleAccessControl.OwnershipNotReady.selector);
        oracle.acceptOwnership();
        assertEq(oracle.owner(), governor);
        executeLast(oracle);
        vm.prank(first);
        vm.expectRevert();
        oracle.acceptOwnership();
        vm.prank(second);
        oracle.acceptOwnership();
        assertEq(oracle.owner(), second);
        assertTrue(oracle.hasRole(oracle.DEFAULT_ADMIN_ROLE(), second));
        assertFalse(oracle.hasRole(oracle.DEFAULT_ADMIN_ROLE(), governor));
        assertTrue(oracle.hasRole(oracle.GUARDIAN_ROLE(), second));
        assertFalse(oracle.hasRole(oracle.GUARDIAN_ROLE(), governor));
        vm.prank(second);
        oracle.renounceOwnership();
        assertEq(oracle.owner(), second);
        executeLast(oracle);
        assertEq(oracle.owner(), address(0));
        assertTrue(oracle.hasRole(oracle.DEFAULT_ADMIN_ROLE(), address(0)));
        assertFalse(oracle.hasRole(oracle.DEFAULT_ADMIN_ROLE(), second));
    }

    /// @notice Generic role mutation cannot break ownership coupling or self-renunciation confirmation.
    function test_defaultAdminInvariantAndSelfConfirmationCannotBeBypassed() public {
        bytes32 root = oracle.DEFAULT_ADMIN_ROLE();
        vm.startPrank(governor);
        vm.expectRevert(StateOracleAccessControl.CannotGrantDefaultAdminRole.selector);
        oracle.grantRole(root, address(0xB0B));
        vm.expectRevert(StateOracleAccessControl.CannotRevokeOwnerDefaultAdminRole.selector);
        oracle.revokeRole(root, governor);
        vm.expectRevert(StateOracleAccessControl.CannotRenounceOwnerDefaultAdminRole.selector);
        oracle.renounceRole(root, governor);
        bytes32 role = oracle.GUARDIAN_ROLE();
        vm.expectRevert(bytes4(keccak256("AccessControlBadConfirmation()")));
        oracle.renounceRole(role, address(0xB0B));
        vm.expectRevert();
        oracle.transferOwnership(address(0));
        vm.stopPrank();
    }
}
