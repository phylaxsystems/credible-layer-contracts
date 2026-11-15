// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title StateOracleTimelock
/// @notice Administration clock owned mechanically by one oracle proxy.
/// @dev Mechanical roles are fixed. Cancellation and arbitrary external targets are deliberately
/// unavailable; ProxyAdmin integration is a separate migration, not part of this foundation.
contract StateOracleTimelock is TimelockController {
    /// @notice Hard minimum administration delay in seconds.
    uint256 public constant MIN_ADMIN_DELAY = 3 days;
    /// @notice The only oracle permitted to propose and execute operations.
    address public immutable ORACLE;
    /// @notice Pending delay-change identifier, or zero when no delay change is pending.
    bytes32 public pendingDelayUpdate;

    /// @notice Exact payload and earliest execution time for an oracle proposal.
    struct Operation {
        /// @notice Oracle or this controller for a delay change.
        address target;
        /// @notice Encoded effective call.
        bytes data;
        /// @notice Unique operation salt.
        bytes32 salt;
        /// @notice Key serializing conflicting changes.
        bytes32 resource;
        /// @notice Earliest execution timestamp in seconds.
        uint256 readyAt;
    }

    /// @notice Queue and resource locks kept outside oracle storage.
    struct OracleAdministration {
        /// @notice Monotonically increasing proposal nonce.
        uint256 nonce;
        /// @notice Most recently scheduled identifier.
        bytes32 latestOperation;
        /// @notice Exact payloads indexed by operation identifier.
        mapping(bytes32 => Operation) operations;
        /// @notice Latest operation holding each resource lock.
        mapping(bytes32 => bytes32) pending;
    }

    /// @notice Queue indexed by the proposing oracle.
    mapping(address => OracleAdministration) private administration;
    /// @notice Fixed registration deadlines indexed by oracle and adopter; zero before revocation.
    mapping(address oracle => mapping(address adopter => uint256 deadline)) public registrationAvailableAt;

    /// @notice The oracle address is zero.
    error InvalidOracle();
    /// @notice A requested delay is below three days.
    error DelayBelowFloor();
    /// @notice This oracle already has a pending delay change.
    error DelayUpdatePending();
    /// @notice The call is not an allowed typed administration action.
    error UnsupportedOperation();
    /// @notice A resource already has a pending operation.
    /// @param id Identifier of the blocking operation.
    error AdministrationOperationPending(bytes32 id);
    /// @notice The requested operation is not recorded.
    error UnknownAdministrationOperation();

    /// @notice Creates a self-administered controller with a three-day initial delay.
    /// @dev No external administrator or canceller; only the oracle proposes and executes.
    /// @param oracle The proxy deploying this controller through plain CREATE.
    constructor(address oracle) TimelockController(MIN_ADMIN_DELAY, _oracle(oracle), _oracle(oracle), address(0)) {
        ORACLE = oracle;
        _revokeRole(CANCELLER_ROLE, oracle);
    }

    /// @notice Builds the sole mechanical-role member list.
    /// @param oracle The nonzero oracle proxy.
    /// @return accounts One-element role member list.
    function _oracle(address oracle) private pure returns (address[] memory accounts) {
        require(oracle != address(0), InvalidOracle());
        accounts = new address[](1);
        accounts[0] = oracle;
    }

    /// @notice Returns the last proposal for an oracle.
    /// @param oracle Oracle whose queue is queried.
    /// @return Latest identifier, or zero before the first proposal.
    function latestAdministrationOperation(address oracle) external view returns (bytes32) {
        return administration[oracle].latestOperation;
    }

    /// @notice Returns the exact payload of a recorded proposal.
    /// @param oracle Oracle whose queue is queried.
    /// @param id Operation identifier.
    /// @return Recorded payload, or an empty record if unknown.
    function administrationOperation(address oracle, bytes32 id) external view returns (Operation memory) {
        return administration[oracle].operations[id];
    }

    /// @notice Returns the latest operation holding a resource lock.
    /// @param oracle Oracle whose queue is queried.
    /// @param resource Conflicting-action key.
    /// @return Latest identifier; check its operation state to determine whether it remains pending.
    function pendingAdministrationOperation(address oracle, bytes32 resource) external view returns (bytes32) {
        return administration[oracle].pending[resource];
    }

    /// @notice Snapshots recovery using the current delay for this controller's oracle.
    /// @param adopter Adopter whose management is being revoked.
    /// @return deadline Earliest re-registration timestamp, unaffected by subsequent delay changes.
    function startManagerRecovery(address adopter) external onlyRole(PROPOSER_ROLE) returns (uint256 deadline) {
        deadline = block.timestamp + getMinDelay();
        registrationAvailableAt[msg.sender][adopter] = deadline;
    }

    /// @notice Records a proposal in the calling oracle's domain without writing oracle storage.
    /// @param resource Key serializing conflicting changes.
    /// @param target Oracle or this controller for a delay change.
    /// @param data Exact effective-call calldata.
    /// @return id Identifier used for execution and status lookup.
    function scheduleAdministration(bytes32 resource, address target, bytes calldata data)
        external
        onlyRole(PROPOSER_ROLE)
        returns (bytes32 id)
    {
        OracleAdministration storage s = administration[msg.sender];
        bytes32 previous = s.pending[resource];
        require(!isOperationPending(previous), AdministrationOperationPending(previous));
        bytes32 salt = keccak256(abi.encode(block.chainid, address(this), msg.sender, ++s.nonce));
        id = hashOperation(target, 0, data, bytes32(0), salt);
        uint256 delay = getMinDelay();
        s.operations[id] = Operation(target, data, salt, resource, block.timestamp + delay);
        s.pending[resource] = id;
        s.latestOperation = id;
        schedule(target, 0, data, bytes32(0), salt, delay);
    }

    /// @notice Schedules an allowed call no earlier than the current delay.
    /// @dev Only the oracle may call; its typed wrappers supply the authorized payload.
    /// @param target Oracle or this controller.
    /// @param value Must be zero.
    /// @param data Exact effective-call calldata.
    /// @param predecessor Operation that must complete first, or zero.
    /// @param salt Unique operation salt.
    /// @param delay Seconds before execution; cannot be below the current delay.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public override onlyRole(PROPOSER_ROLE) {
        _validateCall(target, value, data);
        if (target == address(this)) {
            require(pendingDelayUpdate == bytes32(0), DelayUpdatePending());
            pendingDelayUpdate = hashOperation(target, value, data, predecessor, salt);
        }
        super.schedule(target, value, data, predecessor, salt, delay);
    }

    /// @notice Executes an exact matured proposal through the oracle relay.
    /// @param target Scheduled target.
    /// @param value Must be zero.
    /// @param data Scheduled calldata.
    /// @param predecessor Scheduled predecessor.
    /// @param salt Scheduled salt.
    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        public
        payable
        override
        onlyRole(EXECUTOR_ROLE)
    {
        _validateCall(target, value, data);
        super.execute(target, value, data, predecessor, salt);
    }

    /// @notice Rejects arbitrary targets, ETH transfers and below-floor delay changes.
    /// @param target Proposed target.
    /// @param value Proposed ETH value.
    /// @param data Proposed calldata.
    function _validateCall(address target, uint256 value, bytes calldata data) private view {
        require(value == 0, UnsupportedOperation());
        if (target == address(this)) {
            require(data.length == 36 && bytes4(data[:4]) == this.updateDelay.selector, UnsupportedOperation());
            require(abi.decode(data[4:], (uint256)) >= MIN_ADMIN_DELAY, DelayBelowFloor());
        } else {
            // The oracle cannot use its raw controller role to administer another contract.
            require(target == msg.sender, UnsupportedOperation());
        }
    }

    /// @notice Applies a matured delay change and releases the delay-change lock.
    /// @dev Only a scheduled self-call can succeed; the old delay governed this operation.
    /// @param newDelay New delay in seconds, at least three days.
    function updateDelay(uint256 newDelay) public override {
        require(newDelay >= MIN_ADMIN_DELAY, DelayBelowFloor());
        super.updateDelay(newDelay);
        delete pendingDelayUpdate;
    }

    /// @notice Disabled: mechanical roles are fixed at deployment.
    /// @inheritdoc AccessControl
    function grantRole(bytes32, address) public pure override {
        revert UnsupportedOperation();
    }

    /// @notice Disabled: mechanical roles are fixed at deployment.
    /// @inheritdoc AccessControl
    function revokeRole(bytes32, address) public pure override {
        revert UnsupportedOperation();
    }

    /// @notice Disabled: the oracle cannot abandon its mechanical roles.
    /// @inheritdoc AccessControl
    function renounceRole(bytes32, address) public pure override {
        revert UnsupportedOperation();
    }

    /// @notice Disabled: accepted proposals cannot be cancelled.
    /// @inheritdoc TimelockController
    function cancel(bytes32) public pure override {
        revert UnsupportedOperation();
    }

    /// @notice Disabled: proposals must pass through individual typed oracle wrappers.
    /// @inheritdoc TimelockController
    function scheduleBatch(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32, bytes32, uint256)
        public
        pure
        override
    {
        revert UnsupportedOperation();
    }

    /// @notice Disabled: the oracle relays individual recorded proposals.
    /// @inheritdoc TimelockController
    function executeBatch(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32, bytes32)
        public
        payable
        override
    {
        revert UnsupportedOperation();
    }
}
