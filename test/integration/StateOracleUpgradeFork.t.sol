// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StateOracle} from "../../src/StateOracle.sol";
import {StateOracleTimelock} from "../../src/StateOracleTimelock.sol";
import {StateOracleUpgradeTimelock} from "../../src/StateOracleUpgradeTimelock.sol";
import {UpgradeMigrationOracle} from "../StateOracleUpgradeTimelock.t.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

/// @notice Minimal interface to the deployed Safe used by migration rehearsals.
interface IMigrationSafe {
    /// @notice Returns the current Safe owners.
    /// @return Owner addresses.
    function getOwners() external view returns (address[] memory);
    /// @notice Returns the number of approvals required for execution.
    /// @return Required approval count.
    function getThreshold() external view returns (uint256);
    /// @notice Returns the next transaction nonce.
    /// @return Current Safe nonce.
    function nonce() external view returns (uint256);
    /// @notice Records an owner's approval for a Safe transaction hash.
    /// @param hash Transaction hash approved by the caller.
    function approveHash(bytes32 hash) external;
    /// @notice Computes the hash signed by Safe owners.
    /// @param to Transaction destination.
    /// @param value ETH value.
    /// @param data Encoded call payload.
    /// @param operation Zero for CALL, one for DELEGATECALL.
    /// @param safeTxGas Gas budget for the inner transaction.
    /// @param baseGas Gas overhead used for refunds.
    /// @param gasPrice Refund gas price.
    /// @param gasToken Refund token, or zero for ETH.
    /// @param refundReceiver Refund recipient, or zero for the executor.
    /// @param nonce_ Safe transaction nonce.
    /// @return Transaction hash requiring owner approval.
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce_
    ) external view returns (bytes32);
    /// @notice Executes an owner-approved Safe transaction.
    /// @param to Transaction destination.
    /// @param value ETH value.
    /// @param data Encoded call payload.
    /// @param operation Zero for CALL, one for DELEGATECALL.
    /// @param safeTxGas Gas budget for the inner transaction.
    /// @param baseGas Gas overhead used for refunds.
    /// @param gasPrice Refund gas price.
    /// @param gasToken Refund token, or zero for ETH.
    /// @param refundReceiver Refund recipient, or zero for the executor.
    /// @param signatures Sorted owner signatures or prevalidated approvals.
    /// @return Whether the inner transaction succeeded.
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external returns (bool);
}

/// @notice Rehearses migration and delayed upgrades against deployed mainnet proxies and Safe.
/// @dev Opt in with MAINNET_RPC_URL. Uses the deployed Safe and MultiSendCallOnly, with fork-only
/// owner impersonation/prevalidated signatures. No private keys, broadcast or live owner approvals.
contract StateOracleUpgradeForkTest is Test {
    address constant PRODUCTION = 0x14386aF70E91dFE12aC6243D4B5e087870d7f14D;
    address constant ALERTING = 0xDE55F19430b3Ec5Fa7e5978B49E4467e74C4175b;
    address constant PROD_ADMIN = 0x003C71246D92fae09ae3F3CAeFF234c8B8242F2E;
    address constant ALERT_ADMIN = 0xD1DCB08980c3af919c26245870B1284CaF9435C8;
    IMigrationSafe constant SAFE = IMigrationSafe(0xa4556B53286206A9B50e65700C4372c9Be62b934);
    address constant MULTISEND = 0x40A2aCCbd92BCA938b02010E17A5b8929b49130D;
    uint256 constant FORK_BLOCK = 26_416_409;
    bytes32 constant VERSION_SLOT = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffbf601132;
    StateOracleTimelock administration;
    StateOracleTimelock alertingAdministration;
    StateOracleUpgradeTimelock upgrades;
    StateOracle productionImplementation;
    StateOracle alertingImplementation;

    /// @notice Loads the pinned mainnet fork and prepares implementations and upgrade authority.
    function setUp() public {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc, FORK_BLOCK);
        assertGt(MULTISEND.code.length, 0);
        assertEq(ProxyAdmin(PROD_ADMIN).owner(), address(SAFE));
        assertEq(ProxyAdmin(ALERT_ADMIN).owner(), address(SAFE));
        assertEq(address(uint160(uint256(vm.load(PRODUCTION, ERC1967Utils.ADMIN_SLOT)))), PROD_ADMIN);
        assertEq(address(uint160(uint256(vm.load(ALERTING, ERC1967Utils.ADMIN_SLOT)))), ALERT_ADMIN);
        assertEq(uint256(vm.load(PRODUCTION, VERSION_SLOT)), 2);
        assertEq(uint256(vm.load(ALERTING, VERSION_SLOT)), 2);
        upgrades = new StateOracleUpgradeTimelock(PRODUCTION, PROD_ADMIN, ALERTING, ALERT_ADMIN, address(SAFE), 3 days);
        productionImplementation = new StateOracle(75);
        alertingImplementation = new StateOracle(25);
    }

    /// @notice Executes through the real Safe with fork-local owner approvals.
    /// @param target Safe transaction destination.
    /// @param data Complete call payload.
    /// @param operation CALL or DELEGATECALL operation code.
    /// @param succeeds Whether execution must succeed rather than revert.
    function _safeCall(address target, bytes memory data, uint8 operation, bool succeeds) internal {
        address[] memory owners = SAFE.getOwners();
        for (uint256 i; i < owners.length; ++i) {
            for (uint256 j = i + 1; j < owners.length; ++j) {
                if (owners[j] < owners[i]) (owners[i], owners[j]) = (owners[j], owners[i]);
            }
        }
        uint256 threshold = SAFE.getThreshold();
        bytes32 hash =
            SAFE.getTransactionHash(target, 0, data, operation, 0, 0, 0, address(0), address(0), SAFE.nonce());
        bytes memory signatures;
        for (uint256 i; i < threshold; ++i) {
            vm.prank(owners[i]);
            SAFE.approveHash(hash);
            signatures =
                bytes.concat(signatures, abi.encodePacked(bytes32(uint256(uint160(owners[i]))), bytes32(0), uint8(1)));
        }
        if (!succeeds) vm.expectRevert();
        bool result =
            SAFE.execTransaction(target, 0, data, operation, 0, 0, 0, address(0), payable(address(0)), signatures);
        if (succeeds) assertTrue(result);
    }

    /// @notice Encodes one zero-value MultiSend CALL.
    /// @param target Destination address.
    /// @param data Complete calldata.
    /// @return Packed transaction in MultiSend format.
    function _transaction(address target, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), target, uint256(0), uint256(data.length), data);
    }

    /// @notice Rehearses atomic migration and both ProxyAdmin ownership handovers.
    /// @param failAtEnd Whether an invalid final call must roll back every preceding change.
    function _migration(bool failAtEnd) internal {
        bytes memory init = abi.encodeCall(StateOracle.initializeTimelockV2, ());
        bytes memory calls = bytes.concat(
            _transaction(
                PROD_ADMIN,
                abi.encodeCall(
                    ProxyAdmin.upgradeAndCall,
                    (ITransparentUpgradeableProxy(PRODUCTION), address(productionImplementation), init)
                )
            ),
            _transaction(
                ALERT_ADMIN,
                abi.encodeCall(
                    ProxyAdmin.upgradeAndCall,
                    (ITransparentUpgradeableProxy(ALERTING), address(alertingImplementation), init)
                )
            ),
            _transaction(PROD_ADMIN, abi.encodeWithSignature("transferOwnership(address)", address(upgrades))),
            _transaction(ALERT_ADMIN, abi.encodeWithSignature("transferOwnership(address)", address(upgrades)))
        );
        if (failAtEnd) {
            calls = bytes.concat(
                calls, _transaction(PROD_ADMIN, abi.encodeWithSignature("transferOwnership(address)", address(SAFE)))
            );
        }
        _safeCall(MULTISEND, abi.encodeWithSignature("multiSend(bytes)", calls), 1, !failAtEnd);
        if (!failAtEnd) {
            administration = StateOracle(PRODUCTION).timelock();
            alertingAdministration = StateOracle(ALERTING).timelock();
        }
    }

    /// @notice Schedules through the Safe with the current upgrade delay.
    /// @param target Configured ProxyAdmin or upgrade controller.
    /// @param data Complete scheduled payload.
    /// @param salt Operation salt.
    /// @return id Scheduled identifier.
    function _schedule(address target, bytes memory data, bytes32 salt) internal returns (bytes32 id) {
        _safeCall(
            address(upgrades),
            abi.encodeCall(upgrades.schedule, (target, 0, data, bytes32(0), salt, upgrades.getMinDelay())),
            0,
            true
        );
        return upgrades.hashOperation(target, 0, data, 0, salt);
    }

    /// @notice Executes an upgrade-controller proposal through the Safe.
    /// @param target Scheduled target.
    /// @param data Scheduled payload.
    /// @param salt Scheduled salt.
    /// @param succeeds Expected execution outcome.
    function _execute(address target, bytes memory data, bytes32 salt, bool succeeds) internal {
        _safeCall(address(upgrades), abi.encodeCall(upgrades.execute, (target, 0, data, bytes32(0), salt)), 0, succeeds);
    }

    /// @notice Verifies real-proxy migration, independent controllers and subsequent delayed upgrades.
    function test_forkSafeMigrationAndLaterDelayedUpgrades() public {
        bytes32 prodCode = PRODUCTION.codehash;
        bytes32 alertCode = ALERTING.codehash;
        vm.record();
        _migration(false);
        _assertMigrationWrites(PRODUCTION);
        _assertMigrationWrites(ALERTING);
        assertEq(PRODUCTION.codehash, prodCode);
        assertEq(ALERTING.codehash, alertCode);
        assertEq(address(uint160(uint256(vm.load(PRODUCTION, ERC1967Utils.ADMIN_SLOT)))), PROD_ADMIN);
        assertEq(address(uint160(uint256(vm.load(ALERTING, ERC1967Utils.ADMIN_SLOT)))), ALERT_ADMIN);
        assertEq(ProxyAdmin(PROD_ADMIN).owner(), address(upgrades));
        assertEq(ProxyAdmin(ALERT_ADMIN).owner(), address(upgrades));
        assertEq(StateOracle(PRODUCTION).ASSERTION_TIMELOCK_BLOCKS(), 75);
        assertEq(StateOracle(ALERTING).ASSERTION_TIMELOCK_BLOCKS(), 25);
        assertEq(address(StateOracle(PRODUCTION).timelock()), address(administration));
        assertEq(address(StateOracle(ALERTING).timelock()), address(alertingAdministration));
        assertNotEq(address(administration), address(alertingAdministration));
        assertEq(administration.ORACLE(), PRODUCTION);
        assertEq(alertingAdministration.ORACLE(), ALERTING);
        assertFalse(administration.hasRole(administration.PROPOSER_ROLE(), ALERTING));
        assertFalse(alertingAdministration.hasRole(alertingAdministration.PROPOSER_ROLE(), PRODUCTION));
        assertTrue(StateOracle(PRODUCTION).hasRole(0, StateOracle(PRODUCTION).owner()));
        assertTrue(StateOracle(ALERTING).hasRole(0, StateOracle(ALERTING).owner()));

        UpgradeMigrationOracle next = new UpgradeMigrationOracle(75);
        bytes memory payload = abi.encodeCall(
            ProxyAdmin.upgradeAndCall,
            (ITransparentUpgradeableProxy(PRODUCTION), address(next), abi.encodeCall(next.migrateV3, ()))
        );
        // The old Safe has no direct ProxyAdmin bypass after the handover.
        _safeCall(PROD_ADMIN, payload, 0, false);
        bytes32 id = _schedule(PROD_ADMIN, payload, bytes32("production"));
        UpgradeMigrationOracle alertNext = new UpgradeMigrationOracle(25);
        bytes memory alertPayload = abi.encodeCall(
            ProxyAdmin.upgradeAndCall,
            (ITransparentUpgradeableProxy(ALERTING), address(alertNext), abi.encodeCall(alertNext.migrateV3, ()))
        );
        _schedule(ALERT_ADMIN, alertPayload, bytes32("alerting"));
        vm.warp(upgrades.getTimestamp(id) - 1);
        _execute(PROD_ADMIN, payload, bytes32("production"), false);
        vm.warp(block.timestamp + 1);
        _execute(PROD_ADMIN, payload, bytes32("production"), true);
        _execute(ALERT_ADMIN, alertPayload, bytes32("alerting"), true);
        assertEq(UpgradeMigrationOracle(PRODUCTION).revision(), 3);
        assertEq(UpgradeMigrationOracle(ALERTING).revision(), 3);
        assertEq(uint256(vm.load(PRODUCTION, VERSION_SLOT)), 6);
        assertEq(uint256(vm.load(ALERTING, VERSION_SLOT)), 6);
        assertEq(address(StateOracle(PRODUCTION).timelock()), address(administration));
        assertEq(PRODUCTION.codehash, prodCode);
        assertEq(ALERTING.codehash, alertCode);
        _execute(PROD_ADMIN, payload, bytes32("production"), false);
    }

    /// @notice Verifies the Safe can execute independently queued upgrades in one atomic batch.
    function test_forkPairedLaterUpgradesSucceedAtomically() public {
        _pairedLaterUpgrades(false);
    }

    /// @notice Verifies failure in the second migration restores both implementations and queue states.
    function test_forkSecondLaterUpgradeFailureRollsBackPair() public {
        _pairedLaterUpgrades(true);
    }

    /// @notice Executes a paired upgrade using distinct proposal timestamps.
    /// @param revertSecond Whether the second migration must revert and undo the whole batch.
    function _pairedLaterUpgrades(bool revertSecond) internal {
        _migration(false);
        UpgradeMigrationOracle prodNext = new UpgradeMigrationOracle(75);
        UpgradeMigrationOracle alertNext = new UpgradeMigrationOracle(25);
        bytes memory alertMigration = abi.encodeCall(alertNext.migrateV3, ());
        if (revertSecond) {
            // Revert in the second migration after its reinitializer writes the version slot.
            alertMigration = abi.encodeCall(alertNext.migrateV3AndRevert, ());
        }
        bytes memory prodPayload = abi.encodeCall(
            ProxyAdmin.upgradeAndCall,
            (ITransparentUpgradeableProxy(PRODUCTION), address(prodNext), abi.encodeCall(prodNext.migrateV3, ()))
        );
        bytes memory alertPayload = abi.encodeCall(
            ProxyAdmin.upgradeAndCall, (ITransparentUpgradeableProxy(ALERTING), address(alertNext), alertMigration)
        );
        bytes32 prodId = _schedule(PROD_ADMIN, prodPayload, bytes32("production"));
        // Distinct scheduling times ensure both operations, not only the first, have matured.
        vm.warp(block.timestamp + 1 hours);
        bytes32 alertId = _schedule(ALERT_ADMIN, alertPayload, bytes32("alerting"));
        vm.warp(upgrades.getTimestamp(alertId));
        assertTrue(upgrades.isOperationReady(prodId));
        assertTrue(upgrades.isOperationReady(alertId));
        bytes memory calls = bytes.concat(
            _transaction(
                address(upgrades),
                abi.encodeCall(upgrades.execute, (PROD_ADMIN, 0, prodPayload, bytes32(0), bytes32("production")))
            ),
            _transaction(
                address(upgrades),
                abi.encodeCall(upgrades.execute, (ALERT_ADMIN, 0, alertPayload, bytes32(0), bytes32("alerting")))
            )
        );
        _safeCall(MULTISEND, abi.encodeWithSignature("multiSend(bytes)", calls), 1, !revertSecond);
        assertEq(
            vm.load(PRODUCTION, ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(revertSecond ? address(productionImplementation) : address(prodNext))))
        );
        assertEq(
            vm.load(ALERTING, ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(revertSecond ? address(alertingImplementation) : address(alertNext))))
        );
        assertEq(uint256(vm.load(PRODUCTION, VERSION_SLOT)), revertSecond ? 4 : 6);
        assertEq(uint256(vm.load(ALERTING, VERSION_SLOT)), revertSecond ? 4 : 6);
        assertEq(upgrades.isOperationDone(prodId), !revertSecond);
        assertEq(upgrades.isOperationDone(alertId), !revertSecond);
        assertEq(upgrades.isOperationReady(prodId), revertSecond);
        assertEq(upgrades.isOperationReady(alertId), revertSecond);
        assertEq(ProxyAdmin(PROD_ADMIN).owner(), address(upgrades));
        assertEq(ProxyAdmin(ALERT_ADMIN).owner(), address(upgrades));
    }

    /// @notice Checks migration touched only implementation/version slots and the ERC-7201 controller reference.
    /// @param proxy Oracle proxy whose recorded writes are checked.
    function _assertMigrationWrites(address proxy) internal {
        (, bytes32[] memory writes) = vm.accesses(proxy);
        bytes32 controllerSlot = keccak256(
            abi.encode(uint256(keccak256("phylax.storage.StateOracleAdministration")) - 1)
        ) & ~bytes32(uint256(0xff));
        assertGt(writes.length, 0);
        for (uint256 i; i < writes.length; ++i) {
            assertTrue(
                writes[i] == VERSION_SLOT || writes[i] == ERC1967Utils.IMPLEMENTATION_SLOT
                    || writes[i] == controllerSlot
            );
        }
        assertEq(address(uint160(uint256(vm.load(proxy, controllerSlot)))), address(StateOracle(proxy).timelock()));
        assertEq(uint256(vm.load(proxy, VERSION_SLOT)), 4);
    }

    /// @notice Verifies late failure rolls back both upgrades and both ownership handovers.
    function test_forkLateFailureRollsBackWholeMigration() public {
        bytes32 prodImpl = vm.load(PRODUCTION, ERC1967Utils.IMPLEMENTATION_SLOT);
        bytes32 alertImpl = vm.load(ALERTING, ERC1967Utils.IMPLEMENTATION_SLOT);
        _migration(true);
        assertEq(vm.load(PRODUCTION, ERC1967Utils.IMPLEMENTATION_SLOT), prodImpl);
        assertEq(vm.load(ALERTING, ERC1967Utils.IMPLEMENTATION_SLOT), alertImpl);
        assertEq(uint256(vm.load(PRODUCTION, VERSION_SLOT)), 2);
        assertEq(uint256(vm.load(ALERTING, VERSION_SLOT)), 2);
        assertEq(ProxyAdmin(PROD_ADMIN).owner(), address(SAFE));
        assertEq(ProxyAdmin(ALERT_ADMIN).owner(), address(SAFE));
    }

    /// @notice Verifies delayed authority rotation and independent clocks against the deployed Safe.
    function test_forkSafeAuthorityChangeMovesQueueAndExecutionTogether() public {
        _migration(false);
        address successor = makeAddr("successor upgrade authority");
        bytes memory change = abi.encodeCall(upgrades.updateUpgradeAuthority, (successor));
        bytes32 id = _schedule(address(upgrades), change, bytes32("authority"));
        vm.warp(upgrades.getTimestamp(id) - 1);
        _execute(address(upgrades), change, bytes32("authority"), false);
        assertEq(upgrades.upgradeAuthority(), address(SAFE));
        vm.warp(block.timestamp + 1);
        _execute(address(upgrades), change, bytes32("authority"), true);
        assertEq(upgrades.upgradeAuthority(), successor);
        assertFalse(upgrades.hasRole(upgrades.PROPOSER_ROLE(), address(SAFE)));
        assertFalse(upgrades.hasRole(upgrades.EXECUTOR_ROLE(), address(SAFE)));
        assertTrue(upgrades.hasRole(upgrades.PROPOSER_ROLE(), successor));
        assertTrue(upgrades.hasRole(upgrades.EXECUTOR_ROLE(), successor));
        bytes memory increase = abi.encodeCall(upgrades.updateDelay, (4 days));
        _safeCall(
            address(upgrades),
            abi.encodeCall(upgrades.schedule, (address(upgrades), 0, increase, bytes32(0), bytes32(0), 3 days)),
            0,
            false
        );
        vm.prank(successor);
        upgrades.schedule(address(upgrades), 0, increase, 0, 0, 3 days);
        vm.warp(block.timestamp + 3 days);
        _execute(address(upgrades), increase, 0, false);
        vm.prank(successor);
        upgrades.execute(address(upgrades), 0, increase, 0, 0);
        assertEq(upgrades.getMinDelay(), 4 days);
        assertEq(administration.getMinDelay(), 3 days);
        assertEq(ProxyAdmin(PROD_ADMIN).owner(), address(upgrades));
        assertEq(ProxyAdmin(ALERT_ADMIN).owner(), address(upgrades));
    }
}
