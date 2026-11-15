// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

/// @title StateOracleUpgradeTimelock
/// @notice Independent upgrade clock owning the two existing ProxyAdmins.
/// @dev The single authority uses schedule/execute directly, never through an oracle.
/// Only exact upgradeAndCall payloads and delayed self-administration are supported.
/// Pending proposals survive authority rotation; only the new authority may execute them.
contract StateOracleUpgradeTimelock is TimelockController {
    /// @notice Hard minimum upgrade delay in seconds.
    uint256 public constant MIN_UPGRADE_DELAY = 3 days;
    /// @notice First oracle proxy eligible for delayed upgrades.
    address public immutable PROXY_A;
    /// @notice Second oracle proxy eligible for delayed upgrades.
    address public immutable PROXY_B;
    /// @notice Existing upgrade admin of the first proxy.
    address public immutable PROXY_ADMIN_A;
    /// @notice Existing upgrade admin of the second proxy.
    address public immutable PROXY_ADMIN_B;
    /// @notice Sole authority permitted to schedule and execute delayed upgrades and self-administration.
    address public upgradeAuthority;

    /// @notice Latest operation per ProxyAdmin or self-administration selector; check its operation state.
    mapping(bytes32 resource => bytes32 operation) public pendingOperation;
    /// @notice Runtime code hash committed when an upgrade is scheduled, indexed by operation identifier.
    mapping(bytes32 operation => bytes32 codeHash) public implementationCodeHash;

    /// @notice A proxy/admin pair, implementation or authority is invalid.
    error InvalidConfiguration();
    /// @notice A target, selector, value or disabled entrypoint is not allowed.
    error UnsupportedOperation();
    /// @notice The proposed upgrade delay is below three days.
    error DelayBelowFloor();
    /// @notice An unexecuted proposal already locks the requested resource.
    /// @param id Identifier of the blocking operation.
    error OperationPending(bytes32 id);
    /// @notice The implementation runtime does not match the hash committed by this proposal.
    error ImplementationChanged();
    /// @notice This controller does not own the targeted ProxyAdmin.
    error ProxyAdminNotOwned();

    /// @notice Both scheduling and execution authority moved together.
    /// @param previousAuthority Former authority, or zero during construction.
    /// @param newAuthority New sole proposer and executor.
    event UpgradeAuthorityChanged(address indexed previousAuthority, address indexed newAuthority);

    /// @notice Creates the independent upgrade controller without an external admin or canceller.
    /// @dev Deployment does not transfer ProxyAdmin ownership; the current owner must perform that handover.
    /// @param proxyA First existing oracle proxy.
    /// @param adminA Existing ProxyAdmin belonging to proxyA.
    /// @param proxyB Second existing oracle proxy.
    /// @param adminB Existing ProxyAdmin belonging to proxyB.
    /// @param authority Sole initial proposer and executor, normally the existing Safe.
    /// @param delay Initial upgrade delay in seconds, at least three days.
    constructor(address proxyA, address adminA, address proxyB, address adminB, address authority, uint256 delay)
        TimelockController(delay, _authority(authority), _authority(authority), address(0))
    {
        require(delay >= MIN_UPGRADE_DELAY, DelayBelowFloor());
        require(authority != address(this), InvalidConfiguration());
        require(
            proxyA.code.length != 0 && proxyB.code.length != 0 && adminA.code.length != 0 && adminB.code.length != 0
                && proxyA != proxyB && adminA != adminB && proxyA != adminA && proxyA != adminB && proxyB != adminA
                && proxyB != adminB,
            InvalidConfiguration()
        );
        PROXY_A = proxyA;
        PROXY_B = proxyB;
        PROXY_ADMIN_A = adminA;
        PROXY_ADMIN_B = adminB;
        upgradeAuthority = authority;
        _revokeRole(CANCELLER_ROLE, authority);
        emit UpgradeAuthorityChanged(address(0), authority);
    }

    /// @notice Builds the single-member mechanical-role list.
    /// @param authority Nonzero initial upgrade authority.
    /// @return accounts One-element proposer/executor list.
    function _authority(address authority) private pure returns (address[] memory accounts) {
        require(authority != address(0), InvalidConfiguration());
        accounts = new address[](1);
        accounts[0] = authority;
    }

    /// @notice Queues an exact allowed upgrade or self-administration call after the current delay.
    /// @dev Serializes each resource and commits the implementation runtime hash for upgrades.
    /// @param target Configured ProxyAdmin or this controller.
    /// @param value Must be zero.
    /// @param data Exact upgradeAndCall, updateDelay or updateUpgradeAuthority payload.
    /// @param predecessor Operation that must complete first, or zero.
    /// @param salt Salt distinguishing the operation identifier.
    /// @param delay Requested wait in seconds, at least the current minimum.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public override onlyRole(PROPOSER_ROLE) {
        (bytes32 resource, address implementation) = _validateCall(target, value, data);
        bytes32 previous = pendingOperation[resource];
        require(!isOperationPending(previous), OperationPending(previous));
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        pendingOperation[resource] = id;
        if (implementation != address(0)) implementationCodeHash[id] = implementation.codehash;
        super.schedule(target, value, data, predecessor, salt, delay);
    }

    /// @notice Executes a ready exact proposal under the current upgrade authority.
    /// @dev Rechecks the proxy/admin pair, ownership and committed implementation code. Rejects ETH.
    /// @param target Scheduled ProxyAdmin or this controller.
    /// @param value Must be zero.
    /// @param data Exact scheduled payload.
    /// @param predecessor Scheduled dependency, or zero.
    /// @param salt Scheduled operation salt.
    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        public
        payable
        override
        onlyRole(EXECUTOR_ROLE)
    {
        require(msg.value == 0, UnsupportedOperation());
        (, address implementation) = _validateCall(target, value, data);
        if (implementation != address(0)) {
            bytes32 id = hashOperation(target, value, data, predecessor, salt);
            require(implementation.codehash == implementationCodeHash[id], ImplementationChanged());
        }
        super.execute(target, value, data, predecessor, salt);
    }

    /// @notice Validates the fixed target/selector policy at scheduling and execution.
    /// @param target Proposed call target.
    /// @param value Proposed ETH value, required to be zero.
    /// @param data Complete proposed calldata.
    /// @return resource Key serializing upgrades or changes to one controller setting.
    /// @return implementation Proposed implementation, or zero for self-administration.
    function _validateCall(address target, uint256 value, bytes calldata data)
        private
        view
        returns (bytes32 resource, address implementation)
    {
        require(value == 0 && data.length >= 4, UnsupportedOperation());
        bytes4 selector = bytes4(data[:4]);
        if (target == address(this)) {
            require(data.length == 36, UnsupportedOperation());
            if (selector == this.updateDelay.selector) {
                require(abi.decode(data[4:], (uint256)) >= MIN_UPGRADE_DELAY, DelayBelowFloor());
            } else if (selector == this.updateUpgradeAuthority.selector) {
                address authority = abi.decode(data[4:], (address));
                require(authority != address(0) && authority != address(this), InvalidConfiguration());
            } else {
                revert UnsupportedOperation();
            }
            return (keccak256(abi.encode(target, selector)), address(0));
        }
        require(target == PROXY_ADMIN_A || target == PROXY_ADMIN_B, UnsupportedOperation());
        require(selector == ProxyAdmin.upgradeAndCall.selector, UnsupportedOperation());
        (address proxy, address impl,) = abi.decode(data[4:], (address, address, bytes));
        require(proxy == (target == PROXY_ADMIN_A ? PROXY_A : PROXY_B), UnsupportedOperation());
        require(impl.code.length != 0, InvalidConfiguration());
        require(ProxyAdmin(target).owner() == address(this), ProxyAdminNotOwned());
        return (keccak256(abi.encode(target)), impl);
    }

    /// @notice Both rights move in one delayed self-call, with no external calls between role updates.
    /// @param authority New nonzero sole proposer/executor, distinct from this controller.
    function updateUpgradeAuthority(address authority) external {
        require(msg.sender == address(this), TimelockUnauthorizedCaller(msg.sender));
        require(authority != address(0) && authority != address(this), InvalidConfiguration());
        address previous = upgradeAuthority;
        _revokeRole(PROPOSER_ROLE, previous);
        _revokeRole(EXECUTOR_ROLE, previous);
        upgradeAuthority = authority;
        _grantRole(PROPOSER_ROLE, authority);
        _grantRole(EXECUTOR_ROLE, authority);
        emit UpgradeAuthorityChanged(previous, authority);
    }

    /// @notice Applies a delayed self-call changing the upgrade delay, with a three-day hard floor.
    /// @param newDelay New minimum wait in seconds.
    function updateDelay(uint256 newDelay) public override {
        require(newDelay >= MIN_UPGRADE_DELAY, DelayBelowFloor());
        super.updateDelay(newDelay);
    }

    /// @inheritdoc AccessControl
    /// @notice Disabled; authority changes must use updateUpgradeAuthority through the delay.
    function grantRole(bytes32, address) public pure override {
        revert UnsupportedOperation();
    }

    /// @inheritdoc AccessControl
    /// @notice Disabled; authority changes must use updateUpgradeAuthority through the delay.
    function revokeRole(bytes32, address) public pure override {
        revert UnsupportedOperation();
    }

    /// @inheritdoc AccessControl
    /// @notice Disabled so scheduling and execution authority cannot diverge.
    function renounceRole(bytes32, address) public pure override {
        revert UnsupportedOperation();
    }

    /// @inheritdoc TimelockController
    /// @notice Disabled; proposals cannot be cancelled.
    function cancel(bytes32) public pure override {
        revert UnsupportedOperation();
    }

    /// @inheritdoc TimelockController
    /// @notice Disabled; each upgrade must pass individual target and resource validation.
    function scheduleBatch(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32, bytes32, uint256)
        public
        pure
        override
    {
        revert UnsupportedOperation();
    }

    /// @inheritdoc TimelockController
    /// @notice Disabled; the authority may atomically relay individually queued operations in a reverting batch.
    function executeBatch(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32, bytes32)
        public
        payable
        override
    {
        revert UnsupportedOperation();
    }
}
