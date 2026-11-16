// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracleTimelock} from "./StateOracleTimelock.sol";
import {Initializable} from "solady/utils/Initializable.sol";

/// @title StateOracleAdministration
/// @notice Deploys one administration timelock per oracle and stores its address in an ERC-7201 namespace.
/// @dev The namespace leaves the existing sequential storage layout unchanged.
/// Public execution relays an ID, never caller-supplied target/calldata.
abstract contract StateOracleAdministration is Initializable {
    /// @notice Persistent controller address; queue and recovery records belong to the controller.
    /// @custom:storage-location erc7201:phylax.storage.StateOracleAdministration
    struct AdministrationStorage {
        /// @notice This oracle's administration controller, or zero before initialization.
        StateOracleTimelock controller;
    }

    /// @notice ERC-7201 root for the administration controller reference.
    /// @dev keccak256(abi.encode(uint256(keccak256("phylax.storage.StateOracleAdministration")) - 1)) & ~bytes32(uint256(0xff)).
    bytes32 private constant ADMINISTRATION_STORAGE_LOCATION =
        0xa27a3a56378cd4589a75ea8f4f1cc5bafc02e0071014ad47e88f7ab84961b300;

    /// @notice The oracle has not deployed its administration timelock.
    error TimelockNotInitialized();
    /// @notice An effective administration callback was invoked by someone other than the controller.
    error CallerNotTimelock();
    /// @notice A resource already has a pending administration operation.
    /// @param id The pending operation identifier.
    error AdministrationOperationPending(bytes32 id);
    /// @notice The requested operation is absent from this oracle's controller queue.
    error UnknownAdministrationOperation();

    /// @notice Emitted when the oracle deploys its administration timelock.
    /// @param controller The oracle's administration controller.
    event TimelockInitialized(address indexed controller);
    /// @notice Emitted when an authorized caller queues an exact administration action.
    /// @param id The controller operation identifier used for execution and status lookup.
    /// @param resource The oracle-local key serializing conflicting changes.
    /// @param proposer The caller authorized by the oracle's typed scheduling method.
    /// @param readyAt The earliest execution timestamp, in seconds.
    event AdministrationScheduled(
        bytes32 indexed id, bytes32 indexed resource, address indexed proposer, uint256 readyAt
    );
    /// @notice Emitted after a relayed administration operation succeeds.
    /// @param id The executed controller operation identifier.
    /// @param executedAt The execution timestamp, in seconds.
    event AdministrationExecuted(bytes32 indexed id, uint256 executedAt);

    /// @notice Restricts effective changes to this oracle's deployed controller.
    modifier onlyTimelock() {
        _requireAdministrationReady();
        require(msg.sender == address(timelock()), CallerNotTimelock());
        _;
    }

    /// @notice Rejects administration until fresh initialization or V2 migration deploys the controller.
    function _requireAdministrationReady() internal view {
        require(address(timelock()).code.length != 0, TimelockNotInitialized());
    }

    /// @notice Returns the administration controller stored during initialization.
    /// @return The controller address, or zero before setup.
    function timelock() public view returns (StateOracleTimelock) {
        return _administrationStorage().controller;
    }

    /// @notice Accesses the ERC-7201 namespace without allocating sequential storage.
    /// @return s The persistent administration storage reference.
    function _administrationStorage() private pure returns (AdministrationStorage storage s) {
        assembly ("memory-safe") {
            s.slot := ADMINISTRATION_STORAGE_LOCATION
        }
    }

    /// @notice Returns the effective timestamp-based administration delay.
    /// @dev Requires controller deployment and independently clamps the result to the three-day floor.
    /// @return The delay in seconds; independent of the assertion lifecycle's block delay.
    function administrationDelay() public view returns (uint256) {
        _requireAdministrationReady();
        uint256 delay = timelock().getMinDelay();
        return delay < 3 days ? 3 days : delay;
    }

    /// @notice Returns the most recently scheduled operation for this oracle.
    /// @return The latest identifier, or zero if none has been scheduled; not an execution-status flag.
    function latestAdministrationOperation() public view returns (bytes32) {
        return timelock().latestAdministrationOperation(address(this));
    }

    /// @notice Reads the exact stored payload for an operation in this oracle's queue.
    /// @param id The operation identifier.
    /// @return The stored operation, or a zero-valued record if unknown.
    function administrationOperation(bytes32 id) external view returns (StateOracleTimelock.Operation memory) {
        return timelock().administrationOperation(address(this), id);
    }

    /// @notice Deploys this oracle's timelock exactly once, initially with a three-day delay.
    /// @dev Both guarded initialization paths use plain CREATE and persist the resulting address.
    function _initializeTimelock() internal {
        StateOracleTimelock controller = new StateOracleTimelock(address(this));
        _administrationStorage().controller = controller;
        emit TimelockInitialized(address(controller));
    }

    /// @notice Queues an exact typed action using the current administration delay.
    /// @dev The calling entrypoint must authenticate the proposer; this helper does not check user roles.
    /// @param resource The oracle-local key serializing conflicting changes.
    /// @param target This oracle or the controller for a delay update.
    /// @param data The complete effective-call calldata; execution sends no ETH.
    /// @return id The controller operation identifier.
    function _scheduleAdministration(bytes32 resource, address target, bytes memory data)
        internal
        returns (bytes32 id)
    {
        uint256 delay = administrationDelay();
        id = timelock().scheduleAdministration(resource, target, data);
        emit AdministrationScheduled(id, resource, msg.sender, block.timestamp + delay);
    }

    /// @notice Permissionless relay of a previously authorized, exact operation once ready.
    /// @dev Loads the target and calldata from the controller; reverting execution leaves the operation pending.
    /// @param id The operation identifier emitted when this oracle scheduled the action.
    function executeAdministration(bytes32 id) public {
        _requireAdministrationReady();
        StateOracleTimelock controller = timelock();
        StateOracleTimelock.Operation memory operation = controller.administrationOperation(address(this), id);
        require(operation.target != address(0), UnknownAdministrationOperation());
        controller.execute(operation.target, 0, operation.data, bytes32(0), operation.salt);
        emit AdministrationExecuted(id, block.timestamp);
    }
}
