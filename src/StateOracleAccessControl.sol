// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {StateOracleAdministration} from "./StateOracleAdministration.sol";
import {StateOracleTimelock} from "./StateOracleTimelock.sol";

/// @title StateOracleAccessControl
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Base contract providing role-based access control for StateOracle
/// @dev Implements a five-tier role hierarchy with owner/DEFAULT_ADMIN_ROLE invariant
/// @dev Invariant: owner() always has DEFAULT_ADMIN_ROLE exclusively (1:1 coupling)
/// @dev Named and generic role mutations schedule proposals, not effective changes. Execute the
/// emitted operation ID after D. Self-renunciation authenticates the account before scheduling.
/// Ownership acceptance additionally requires the exact nomination's matured authorization.
///
/// @dev Role Hierarchy:
/// ```
///                              owner() (Cold Multisig)
///                                       ║
///                          (1:1 coupling - INVARIANT)
///                                       ║
///                               DEFAULT_ADMIN_ROLE
///                                       │
///                ┌──────────────────────┼──────────────────────┐
///                │                      │                      │
///          GOVERNANCE_ROLE        GUARDIAN_ADMIN        OPERATOR_ADMIN
///                │                      │                      │
///                │                GUARDIAN_ROLE         OPERATOR_ROLE
///                │                      │                      │
///                ▼                      ▼                      ▼
///    ┌────────────────────┐ ┌────────────────────┐ ┌────────────────────┐
///    │  Protocol Admin    │ │  Emergency Actions │ │  Whitelist Mgmt    │
///    ├────────────────────┤ ├────────────────────┤ ├────────────────────┤
///    │ • enableWhitelist  │ │ • removeAssertion  │ │ • addToWhitelist   │
///    │ • disableWhitelist │ │   ByGuardian       │ │ • removeFrom       │
///    │ • addAdminVerifier │ │ • revokeManager    │ │   Whitelist        │
///    │ • removeAdmin      │ │                    │ │                    │
///    │   Verifier         │ │                    │ │                    │
///    │ • setMaxAssertions │ │                    │ │                    │
///    │   PerAA            │ │                    │ │                    │
///    └────────────────────┘ └────────────────────┘ └────────────────────┘
/// ```
///
/// @dev Security Features:
/// - owner() and DEFAULT_ADMIN_ROLE are permanently coupled (cannot be broken)
/// - DEFAULT_ADMIN_ROLE cannot be granted to any address except owner()
/// - DEFAULT_ADMIN_ROLE cannot be revoked from owner()
/// - Owner cannot renounce DEFAULT_ADMIN_ROLE through renounceRole()
/// - renounceOwnership() maintains invariant by granting role to address(0)
/// - All role transfers are atomic to prevent invariant violations
abstract contract StateOracleAccessControl is Ownable2Step, AccessControl, StateOracleAdministration {
    /// @notice Role for governance operations (protocol administration)
    /// @dev Managed by DEFAULT_ADMIN_ROLE (owner)
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /// @notice Role for guardian admins who can manage guardian access
    bytes32 public constant GUARDIAN_ADMIN_ROLE = keccak256("GUARDIAN_ADMIN_ROLE");

    /// @notice Role for guardians who can take emergency defensive actions
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Role for operator admins who can manage operator access
    bytes32 public constant OPERATOR_ADMIN_ROLE = keccak256("OPERATOR_ADMIN_ROLE");

    /// @notice Role for operators who can manage day-to-day operations like whitelist management
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Thrown when an unauthorized address attempts to manage assertions
    error UnauthorizedManager();

    /// @notice Thrown when attempting to grant DEFAULT_ADMIN_ROLE to non-owner
    error CannotGrantDefaultAdminRole();

    /// @notice Thrown when attempting to revoke owner's DEFAULT_ADMIN_ROLE
    error CannotRevokeOwnerDefaultAdminRole();

    /// @notice Thrown when owner attempts to renounce DEFAULT_ADMIN_ROLE
    error CannotRenounceOwnerDefaultAdminRole();

    /// @notice Modifier to restrict access to governance role
    modifier onlyGovernance() {
        _checkRole(GOVERNANCE_ROLE);
        _;
    }

    /// @notice Modifier to restrict access to guardian role
    modifier onlyGuardian() {
        _checkRole(GUARDIAN_ROLE);
        _;
    }

    /// @notice Modifier to restrict access to operator role
    modifier onlyOperator() {
        _checkRole(OPERATOR_ROLE);
        _;
    }

    /// @notice Proposes this oracle's administration delay change; only one may be pending per oracle.
    /// @dev The current delay governs execution, including a decrease; three days is the hard floor.
    /// @param newDelay Proposed delay in seconds.
    /// @return Identifier of the queued delay change.
    function scheduleDelayUpdate(uint256 newDelay) external onlyOwner returns (bytes32) {
        return _scheduleAdministration(
            keccak256("delay"), address(timelock()), abi.encodeCall(StateOracleTimelock.updateDelay, (newDelay))
        );
    }

    /// @notice Returns all roles in the system
    /// @dev DEFAULT_ADMIN_ROLE is not included as it's coupled with ownership
    /// @return roles Array of all role identifiers
    function _getAllRoles() internal pure returns (bytes32[] memory roles) {
        roles = new bytes32[](5);
        roles[0] = GOVERNANCE_ROLE;
        roles[1] = GUARDIAN_ADMIN_ROLE;
        roles[2] = OPERATOR_ADMIN_ROLE;
        roles[3] = GUARDIAN_ROLE;
        roles[4] = OPERATOR_ROLE;
        return roles;
    }

    /// @notice Initialize the role hierarchy and grant initial roles
    /// @dev Internal function called during contract initialization
    /// @dev Sets up the complete role hierarchy with proper admin relationships
    /// @dev Initially grants all admin roles to the admin address (can be delegated later)
    /// @param admin The address to set as owner and grant initial roles to
    function _initializeRoles(address admin) internal {
        // _transferOwnership grants DEFAULT_ADMIN_ROLE to admin automatically
        _transferOwnership(admin);

        // Set up role hierarchy
        // DEFAULT_ADMIN_ROLE (owner) is the admin of all other roles
        _setRoleAdmin(GOVERNANCE_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(GUARDIAN_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(OPERATOR_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(GUARDIAN_ROLE, GUARDIAN_ADMIN_ROLE);
        _setRoleAdmin(OPERATOR_ROLE, OPERATOR_ADMIN_ROLE);

        // Grant all delegatable roles to admin
        bytes32[] memory roles = _getAllRoles();
        for (uint256 i = 0; i < roles.length; i++) {
            _grantRole(roles[i], admin);
        }
    }

    /// @notice Queues a governance role grant after the administration delay.
    /// @dev Only callable by owner (who has DEFAULT_ADMIN_ROLE)
    /// @dev Governance role can manage protocol parameters (whitelist, verifiers, etc.)
    /// @param governance The address to grant the governance role to
    function grantGovernanceRole(address governance) external onlyOwner {
        _queueRoleChange(GOVERNANCE_ROLE, governance, true);
    }

    /// @notice Queues a governance role revocation after the administration delay.
    /// @dev Only callable by owner (who has DEFAULT_ADMIN_ROLE)
    /// @param governance The address to revoke the governance role from
    function revokeGovernanceRole(address governance) external onlyOwner {
        _queueRoleChange(GOVERNANCE_ROLE, governance, false);
    }

    /// @notice Queues a guardian-admin role grant after the administration delay.
    /// @dev Only callable by owner (who has DEFAULT_ADMIN_ROLE)
    /// @dev Guardian admins can manage the guardian role (grant/revoke guardians)
    /// @param guardianAdmin The address to grant the guardian admin role to
    function grantGuardianAdminRole(address guardianAdmin) external onlyOwner {
        _queueRoleChange(GUARDIAN_ADMIN_ROLE, guardianAdmin, true);
    }

    /// @notice Queues a guardian-admin role revocation after the administration delay.
    /// @dev Only callable by owner (who has DEFAULT_ADMIN_ROLE)
    /// @param guardianAdmin The address to revoke the guardian admin role from
    function revokeGuardianAdminRole(address guardianAdmin) external onlyOwner {
        _queueRoleChange(GUARDIAN_ADMIN_ROLE, guardianAdmin, false);
    }

    /// @notice Queues a guardian role grant after the administration delay.
    /// @dev Only callable by guardian admins
    /// @dev Guardians can perform emergency defensive actions (remove assertions, revoke managers)
    /// @param guardian The address to grant the guardian role to
    function grantGuardianRole(address guardian) external onlyRole(GUARDIAN_ADMIN_ROLE) {
        _queueRoleChange(GUARDIAN_ROLE, guardian, true);
    }

    /// @notice Queues a guardian role revocation after the administration delay.
    /// @dev Only callable by guardian admins
    /// @param guardian The address to revoke the guardian role from
    function revokeGuardianRole(address guardian) external onlyRole(GUARDIAN_ADMIN_ROLE) {
        _queueRoleChange(GUARDIAN_ROLE, guardian, false);
    }

    /// @notice Queues an operator-admin role grant after the administration delay.
    /// @dev Only callable by owner (who has DEFAULT_ADMIN_ROLE)
    /// @dev Operator admins can manage the operator role (grant/revoke operators)
    /// @param operatorAdmin The address to grant the operator admin role to
    function grantOperatorAdminRole(address operatorAdmin) external onlyOwner {
        _queueRoleChange(OPERATOR_ADMIN_ROLE, operatorAdmin, true);
    }

    /// @notice Queues an operator-admin role revocation after the administration delay.
    /// @dev Only callable by owner (who has DEFAULT_ADMIN_ROLE)
    /// @param operatorAdmin The address to revoke the operator admin role from
    function revokeOperatorAdminRole(address operatorAdmin) external onlyOwner {
        _queueRoleChange(OPERATOR_ADMIN_ROLE, operatorAdmin, false);
    }

    /// @notice Queues an operator role grant after the administration delay.
    /// @dev Only callable by operator admins
    /// @dev Operators can manage the whitelist (add/remove addresses)
    /// @param operator The address to grant the operator role to
    function grantOperatorRole(address operator) external onlyRole(OPERATOR_ADMIN_ROLE) {
        _queueRoleChange(OPERATOR_ROLE, operator, true);
    }

    /// @notice Queues an operator role revocation after the administration delay.
    /// @dev Only callable by operator admins
    /// @param operator The address to revoke the operator role from
    function revokeOperatorRole(address operator) external onlyRole(OPERATOR_ADMIN_ROLE) {
        _queueRoleChange(OPERATOR_ROLE, operator, false);
    }

    /// @notice Override _transferOwnership to also transfer DEFAULT_ADMIN_ROLE atomically
    /// @dev Internal function called by transferOwnership() and renounceOwnership()
    /// @dev Transfers DEFAULT_ADMIN_ROLE BEFORE changing ownership to maintain invariant
    /// @dev Also transfers any delegatable roles that the old owner had
    /// @dev Handles address(0) case for renounceOwnership() to maintain invariant
    /// @param newOwner The address of the new owner (can be address(0) when renouncing)
    function _transferOwnership(address newOwner) internal virtual override {
        address oldOwner = owner();

        // Transfer DEFAULT_ADMIN_ROLE BEFORE ownership transfer (maintain 1:1 invariant)
        // Always transfer role, even to address(0) (maintains invariant when renouncing)
        if (oldOwner != address(0)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, oldOwner);

            // Transfer any delegatable roles the old owner has to the new owner
            bytes32[] memory roles = _getAllRoles();
            for (uint256 i = 0; i < roles.length; i++) {
                if (hasRole(roles[i], oldOwner)) {
                    _revokeRole(roles[i], oldOwner);
                    if (newOwner != address(0)) {
                        _grantRole(roles[i], newOwner);
                    }
                }
            }
        }

        // Grant DEFAULT_ADMIN_ROLE to newOwner unconditionally (even if address(0))
        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);

        super._transferOwnership(newOwner);
    }

    /// @notice Queues a role grant, rejecting independent DEFAULT_ADMIN_ROLE changes.
    /// @dev Maintains invariant: only owner() can have DEFAULT_ADMIN_ROLE
    /// @dev DEFAULT_ADMIN_ROLE can only be transferred via ownership transfer
    /// @param role The role to grant
    /// @param account The account to grant the role to
    function grantRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        require(role != DEFAULT_ADMIN_ROLE, CannotGrantDefaultAdminRole());
        _queueRoleChange(role, account, true);
    }

    /// @notice Queues a role revocation, preserving the owner's coupled DEFAULT_ADMIN_ROLE.
    /// @dev Maintains invariant: owner() must always have DEFAULT_ADMIN_ROLE
    /// @dev Allows revoking DEFAULT_ADMIN_ROLE from non-owners (e.g., during ownership transfer)
    /// @param role The role to revoke
    /// @param account The account to revoke the role from
    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        require(role != DEFAULT_ADMIN_ROLE || account != owner(), CannotRevokeOwnerDefaultAdminRole());
        _queueRoleChange(role, account, false);
    }

    /// @notice Queues self-renunciation after the administration delay, except for the owner's coupled role.
    /// @dev Maintains invariant: owner() must keep DEFAULT_ADMIN_ROLE
    /// @dev Owner must use renounceOwnership() instead to give up both owner and role atomically
    /// @param role The role to renounce
    /// @param callerConfirmation Must be msg.sender (OpenZeppelin safety check)
    function renounceRole(bytes32 role, address callerConfirmation) public virtual override {
        require(role != DEFAULT_ADMIN_ROLE || callerConfirmation != owner(), CannotRenounceOwnerDefaultAdminRole());
        require(callerConfirmation == msg.sender, AccessControlBadConfirmation());
        _queueRoleChange(role, callerConfirmation, false);
    }

    /// @notice Queues an authorized role change under a per-role/account resource lock.
    /// @dev The caller must enforce proposer authority before invoking this helper.
    /// @param role Role to change.
    /// @param account Affected account.
    /// @param grant True to grant, false to revoke.
    function _queueRoleChange(bytes32 role, address account, bool grant) internal {
        _scheduleAdministration(
            keccak256(abi.encode("role", role, account)),
            address(this),
            abi.encodeCall(this.applyRoleChange, (role, account, grant))
        );
    }

    /// @notice Applies only a matured, authenticated grant, revoke or self-renunciation.
    /// @param role Role to change; ownership controls DEFAULT_ADMIN_ROLE separately.
    /// @param account Affected account.
    /// @param grant True to grant, false to revoke.
    function applyRoleChange(bytes32 role, address account, bool grant) external onlyTimelock {
        if (grant) {
            require(role != DEFAULT_ADMIN_ROLE, CannotGrantDefaultAdminRole());
            _grantRole(role, account);
        } else {
            require(role != DEFAULT_ADMIN_ROLE || account != owner(), CannotRevokeOwnerDefaultAdminRole());
            _revokeRole(role, account);
        }
    }

    /// @notice Nominates a recipient immediately, but acceptance requires this exact proposal to mature.
    /// @dev One pending ownership operation at a time; zero-address cancellation is not supported.
    /// @param newOwner Nominated successor, which must accept after the queued authorization executes.
    function transferOwnership(address newOwner) public override onlyOwner {
        require(newOwner != address(0), OwnableInvalidOwner(newOwner));
        super.transferOwnership(newOwner);
        _scheduleAdministration(
            keccak256("ownership"), address(this), abi.encodeCall(this.authorizeOwnership, (newOwner))
        );
    }

    /// @notice Lets the nominee accept only after its exact delayed authorization has executed.
    /// @dev Ownership and DEFAULT_ADMIN_ROLE move together; inherited legacy nominations need a new proposal.
    function acceptOwnership() public override {
        require(msg.sender == pendingOwner() && msg.sender != address(0), OwnableUnauthorizedAccount(msg.sender));
        StateOracleTimelock controller = timelock();
        _requireAdministrationReady();
        bytes32 id = controller.pendingAdministrationOperation(address(this), keccak256("ownership"));
        require(
            controller.isOperationDone(id)
                && keccak256(controller.administrationOperation(address(this), id).data)
                    == keccak256(abi.encodeCall(this.authorizeOwnership, (msg.sender))),
            OwnershipNotReady()
        );
        super.acceptOwnership();
    }

    /// @notice Queues ownership renunciation after the current administration delay.
    /// @dev Shares the ownership resource lock with nominations; effective execution clears both owner and role.
    function renounceOwnership() public override onlyOwner {
        _scheduleAdministration(
            keccak256("ownership"), address(this), abi.encodeCall(this.authorizeOwnership, (address(0)))
        );
    }

    /// @notice The exact pending nomination has not completed its delayed authorization.
    error OwnershipNotReady();

    /// @notice Matures a nomination, or executes a delayed ownership renunciation.
    /// @param recipient Nominated owner, or zero to renounce ownership and its coupled role.
    function authorizeOwnership(address recipient) external onlyTimelock {
        if (recipient == address(0)) {
            _transferOwnership(address(0));
        } else {
            require(pendingOwner() == recipient, OwnableUnauthorizedAccount(recipient));
        }
    }
}
