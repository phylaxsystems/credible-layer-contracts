// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {StateOracleTimelock} from "../src/StateOracleTimelock.sol";
import {StateOracleUpgradeTimelock} from "../src/StateOracleUpgradeTimelock.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {ProxyHelper} from "./utils/ProxyHelper.t.sol";

/// @notice Test implementation for a later authenticated migration.
contract UpgradeMigrationOracle is StateOracle {
    /// @notice Preserves the oracle's assertion lifecycle configuration.
    /// @param blocks_ Assertion lifecycle delay in blocks.
    constructor(uint256 blocks_) StateOracle(blocks_) {}

    /// @notice Exercises a replay-protected migration through the proxy's own admin.
    function migrateV3() external reinitializer(3) {
        require(msg.sender == ERC1967Utils.getAdmin(), "Wrong migration caller");
    }

    /// @notice Identifies the test implementation after upgrade.
    /// @return The test implementation revision.
    function revision() external pure returns (uint256) {
        return 3;
    }
}

/// @notice Tests independent delayed upgrade authority using freshly initialized oracles.
contract StateOracleUpgradeTimelockTest is ProxyHelper {
    StateOracle internal oracle;
    StateOracle internal peer;
    ProxyAdmin internal admin;
    ProxyAdmin internal peerAdmin;
    StateOracleTimelock internal administration;
    StateOracleUpgradeTimelock internal upgrades;
    UpgradeMigrationOracle internal next;
    bytes internal upgradeData;
    bytes32 internal constant SALT = keccak256("upgrade");
    bytes4 internal constant UNAUTHORIZED = bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)"));

    /// @notice Deploys two oracles and transfers their ProxyAdmins to the upgrade controller.
    function setUp() public {
        StateOracle implementation = new StateOracle(75);
        bytes memory init = abi.encodeCall(
            StateOracle.initializeWithWhitelist,
            (ADMIN, new IAdminVerifier[](0), new IDAVerifier[](0), 10, true, new address[](0))
        );
        oracle = StateOracle(deployProxy(address(implementation), init));
        peer = StateOracle(deployProxy(address(implementation), init));
        admin = ProxyAdmin(getProxyAdmin(address(oracle)));
        peerAdmin = ProxyAdmin(getProxyAdmin(address(peer)));
        administration = oracle.timelock();
        upgrades = new StateOracleUpgradeTimelock(
            address(oracle), address(admin), address(peer), address(peerAdmin), ADMIN, 3 days
        );
        vm.startPrank(ADMIN);
        admin.transferOwnership(address(upgrades));
        peerAdmin.transferOwnership(address(upgrades));
        vm.stopPrank();
        next = new UpgradeMigrationOracle(75);
        upgradeData = abi.encodeCall(
            ProxyAdmin.upgradeAndCall,
            (ITransparentUpgradeableProxy(address(oracle)), address(next), abi.encodeCall(next.migrateV3, ()))
        );
    }

    /// @notice Queues a test operation as the upgrade authority.
    /// @param target Upgrade controller or configured ProxyAdmin.
    /// @param data Complete operation payload.
    /// @param salt Operation salt.
    /// @return id Scheduled identifier.
    function _schedule(address target, bytes memory data, bytes32 salt) internal returns (bytes32 id) {
        vm.prank(ADMIN);
        upgrades.schedule(target, 0, data, 0, salt, 3 days);
        return upgrades.hashOperation(target, 0, data, 0, salt);
    }

    /// @notice Executes a test operation as the upgrade authority.
    /// @param target Scheduled target.
    /// @param data Scheduled payload.
    /// @param salt Scheduled salt.
    function _execute(address target, bytes memory data, bytes32 salt) internal {
        vm.prank(ADMIN);
        upgrades.execute(target, 0, data, 0, salt);
    }

    /// @notice Verifies authentication, payload commitment, maturity, migration and replay prevention.
    function test_upgradeRequiresAuthorityExactPayloadAndMaturity() public {
        vm.expectPartialRevert(UNAUTHORIZED);
        upgrades.schedule(address(admin), 0, upgradeData, 0, SALT, 3 days);
        bytes32 id = _schedule(address(admin), upgradeData, SALT);
        bytes32 oldImpl = vm.load(address(oracle), ERC1967Utils.IMPLEMENTATION_SLOT);
        vm.warp(upgrades.getTimestamp(id) - 1);
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        _execute(address(admin), upgradeData, SALT);
        assertEq(vm.load(address(oracle), ERC1967Utils.IMPLEMENTATION_SLOT), oldImpl);
        vm.warp(block.timestamp + 1);
        vm.expectPartialRevert(UNAUTHORIZED);
        upgrades.execute(address(admin), 0, upgradeData, 0, SALT);
        vm.expectRevert(StateOracleUpgradeTimelock.ImplementationChanged.selector);
        _execute(address(admin), upgradeData, bytes32("different salt"));
        bytes memory changed = abi.encodeCall(
            ProxyAdmin.upgradeAndCall, (ITransparentUpgradeableProxy(address(oracle)), address(next), bytes(""))
        );
        vm.expectRevert(StateOracleUpgradeTimelock.ImplementationChanged.selector);
        _execute(address(admin), changed, SALT);
        _execute(address(admin), upgradeData, SALT);
        assertTrue(upgrades.isOperationDone(id));
        assertEq(UpgradeMigrationOracle(address(oracle)).revision(), 3);
        assertEq(vm.load(address(oracle), ERC1967Utils.IMPLEMENTATION_SLOT), bytes32(uint256(uint160(address(next)))));
        assertEq(address(oracle.timelock()), address(administration));
        assertEq(oracle.ASSERTION_TIMELOCK_BLOCKS(), 75);
        assertEq(oracle.owner(), ADMIN);
        assertEq(admin.owner(), address(upgrades));
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        _execute(address(admin), upgradeData, SALT);
    }

    /// @notice Verifies pending proposals survive rotation but only the successor may act on them.
    function test_authorityMovesBothRightsAndPendingProposalTogether() public {
        bytes32 id = _schedule(address(admin), upgradeData, SALT);
        address successor = address(0xB0B);
        bytes memory rotation = abi.encodeCall(upgrades.updateUpgradeAuthority, (successor));
        _schedule(address(upgrades), rotation, bytes32("rotate"));
        vm.prank(successor);
        vm.expectPartialRevert(UNAUTHORIZED);
        upgrades.execute(address(upgrades), 0, rotation, 0, bytes32("rotate"));
        vm.expectPartialRevert(TimelockController.TimelockUnauthorizedCaller.selector);
        upgrades.updateUpgradeAuthority(successor);
        vm.warp(upgrades.getTimestamp(id) - 1);
        vm.expectPartialRevert(TimelockController.TimelockUnexpectedOperationState.selector);
        _execute(address(upgrades), rotation, bytes32("rotate"));
        assertEq(upgrades.upgradeAuthority(), ADMIN);
        vm.warp(block.timestamp + 1);
        _execute(address(upgrades), rotation, bytes32("rotate"));
        assertEq(upgrades.upgradeAuthority(), successor);
        assertFalse(upgrades.hasRole(upgrades.PROPOSER_ROLE(), ADMIN));
        assertFalse(upgrades.hasRole(upgrades.EXECUTOR_ROLE(), ADMIN));
        assertTrue(upgrades.hasRole(upgrades.PROPOSER_ROLE(), successor));
        assertTrue(upgrades.hasRole(upgrades.EXECUTOR_ROLE(), successor));
        vm.expectPartialRevert(UNAUTHORIZED);
        _execute(address(admin), upgradeData, SALT);
        vm.expectPartialRevert(UNAUTHORIZED);
        _schedule(address(upgrades), abi.encodeCall(upgrades.updateDelay, (4 days)), 0);
        vm.prank(successor);
        upgrades.execute(address(admin), 0, upgradeData, 0, SALT);
        vm.prank(successor);
        upgrades.schedule(address(upgrades), 0, abi.encodeCall(upgrades.updateDelay, (4 days)), 0, 0, 3 days);
        assertEq(admin.owner(), address(upgrades));
        assertEq(peerAdmin.owner(), address(upgrades));
    }

    /// @notice Verifies the upgrade clock's floor and serialization independently of oracle administration.
    function test_floorAndSerializedDelayChangesUseIndependentClock() public {
        vm.expectRevert(StateOracleUpgradeTimelock.DelayBelowFloor.selector);
        new StateOracleUpgradeTimelock(
            address(oracle), address(admin), address(peer), address(peerAdmin), ADMIN, 3 days - 1
        );
        vm.expectRevert(StateOracleUpgradeTimelock.DelayBelowFloor.selector);
        _schedule(address(upgrades), abi.encodeCall(upgrades.updateDelay, (0)), 0);
        vm.prank(address(upgrades));
        vm.expectRevert(StateOracleUpgradeTimelock.DelayBelowFloor.selector);
        upgrades.updateDelay(0);
        vm.expectPartialRevert(TimelockController.TimelockUnauthorizedCaller.selector);
        upgrades.updateDelay(5 days);
        bytes memory increase = abi.encodeCall(upgrades.updateDelay, (5 days));
        bytes memory decrease = abi.encodeCall(upgrades.updateDelay, (3 days));
        bytes32 id = _schedule(address(upgrades), increase, 0);
        vm.prank(ADMIN);
        vm.expectPartialRevert(StateOracleUpgradeTimelock.OperationPending.selector);
        upgrades.schedule(address(upgrades), 0, decrease, id, SALT, 3 days);
        vm.warp(upgrades.getTimestamp(id));
        vm.expectPartialRevert(StateOracleUpgradeTimelock.OperationPending.selector);
        _schedule(address(upgrades), decrease, SALT);
        _execute(address(upgrades), increase, 0);
        assertEq(administration.getMinDelay(), 3 days);
        assertEq(upgrades.getMinDelay(), 5 days);
        vm.prank(ADMIN);
        vm.expectPartialRevert(TimelockController.TimelockInsufficientDelay.selector);
        upgrades.schedule(address(upgrades), 0, decrease, 0, SALT, 3 days);
        vm.prank(ADMIN);
        upgrades.schedule(address(upgrades), 0, decrease, 0, SALT, 5 days);
        id = upgrades.hashOperation(address(upgrades), 0, decrease, 0, SALT);
        assertEq(upgrades.getTimestamp(id), block.timestamp + 5 days);
        vm.warp(upgrades.getTimestamp(id));
        _execute(address(upgrades), decrease, SALT);
        assertEq(upgrades.getMinDelay(), 3 days);
    }

    /// @notice Rejects conflicting upgrades and runtime code changes after scheduling.
    function test_upgradeConflictsAndChangedCodeCannotExecute() public {
        bytes32 id = _schedule(address(admin), upgradeData, SALT);
        vm.expectPartialRevert(StateOracleUpgradeTimelock.OperationPending.selector);
        _schedule(address(admin), upgradeData, bytes32("second"));
        vm.warp(upgrades.getTimestamp(id));
        vm.etch(address(next), hex"60006000fd");
        vm.expectRevert(StateOracleUpgradeTimelock.ImplementationChanged.selector);
        _execute(address(admin), upgradeData, SALT);
        assertFalse(upgrades.isOperationDone(id));
    }

    /// @notice Rejects unconfigured targets, mismatched proxies, value and mechanical-role bypasses.
    function test_rejectsTargetsPairsSelectorsValueAndAuthorityEscapes() public {
        bytes32 executor = upgrades.EXECUTOR_ROLE();
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        _schedule(address(oracle), upgradeData, SALT);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        _schedule(address(peerAdmin), upgradeData, SALT);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        _schedule(address(admin), abi.encodeWithSignature("transferOwnership(address)", ADMIN), SALT);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        _schedule(address(upgrades), abi.encodeCall(upgrades.grantRole, (executor, address(0))), SALT);
        vm.expectRevert(StateOracleUpgradeTimelock.InvalidConfiguration.selector);
        _schedule(address(upgrades), abi.encodeCall(upgrades.updateUpgradeAuthority, (address(0))), SALT);
        vm.expectRevert(StateOracleUpgradeTimelock.InvalidConfiguration.selector);
        _schedule(address(upgrades), abi.encodeCall(upgrades.updateUpgradeAuthority, (address(upgrades))), SALT);
        vm.startPrank(ADMIN);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.schedule(address(admin), 1, upgradeData, 0, SALT, 3 days);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.grantRole(0, ADMIN);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.revokeRole(0, ADMIN);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.renounceRole(0, ADMIN);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.cancel(0);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.scheduleBatch(new address[](0), new uint256[](0), new bytes[](0), 0, 0, 3 days);
        vm.expectRevert(StateOracleUpgradeTimelock.UnsupportedOperation.selector);
        upgrades.executeBatch(new address[](0), new uint256[](0), new bytes[](0), 0, 0);
        vm.stopPrank();
        assertTrue(upgrades.hasRole(upgrades.DEFAULT_ADMIN_ROLE(), address(upgrades)));
        assertFalse(upgrades.hasRole(upgrades.DEFAULT_ADMIN_ROLE(), ADMIN));
        assertFalse(upgrades.hasRole(upgrades.CANCELLER_ROLE(), ADMIN));
        assertFalse(upgrades.hasRole(upgrades.EXECUTOR_ROLE(), address(0)));
    }
}
