// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/// @title IStateOracleV3
/// @notice Consumer ABI for the oracle with per-oracle administration.
/// @dev Assertion lifecycle delays use blocks; administration delays use timestamps.
/// Role grants, revocations and renunciations queue changes; membership changes only after execution.
/// Ownership nomination is immediate, but acceptance requires execution of its delayed authorization.
interface IStateOracleV3 {
    /// @notice Exact queued administration payload, matching StateOracleTimelock.Operation.
    struct Operation {
        /// @notice Effective-call target.
        address target;
        /// @notice Effective-call calldata.
        bytes data;
        /// @notice Unique operation salt.
        bytes32 salt;
        /// @notice Conflicting-action key.
        bytes32 resource;
        /// @notice Earliest execution timestamp in seconds.
        uint256 readyAt;
    }

    /// @notice Role renunciation confirmation does not match the caller.
    error AccessControlBadConfirmation();
    /// @notice An account lacks the required role.
    /// @param account Unauthorized account.
    /// @param neededRole Required role identifier.
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
    /// @notice The account is absent from the caller whitelist.
    /// @param account Account being removed.
    error AccountNotWhitelisted(address account);
    /// @notice The admin verifier is already registered.
    error AdminVerifierAlreadyRegistered();
    /// @notice The admin verifier is not registered.
    error AdminVerifierNotRegistered();
    /// @notice A conflicting administration proposal remains pending.
    /// @param id Blocking operation identifier.
    error AdministrationOperationPending(bytes32 id);
    /// @notice The account is already whitelisted.
    /// @param account Account being added.
    error AlreadyWhitelisted(address account);
    /// @notice The adopter already has a manager.
    error AssertionAdopterAlreadyRegistered();
    /// @notice The adopter has no manager.
    error AssertionAdopterNotRegistered();
    /// @notice The assertion's current lifecycle has not finished.
    error AssertionAlreadyExists();
    /// @notice Assertion removal has already been scheduled.
    error AssertionAlreadyRemoved();
    /// @notice The assertion has never been added.
    error AssertionDoesNotExist();
    /// @notice A batched delegatecall reverted.
    /// @param result Revert data from the failed call.
    error BatchError(bytes result);
    /// @notice An effective administration callback did not come from this oracle's timelock.
    error CallerNotTimelock();
    /// @notice DEFAULT_ADMIN_ROLE cannot be independently granted.
    error CannotGrantDefaultAdminRole();
    /// @notice The owner cannot independently renounce DEFAULT_ADMIN_ROLE.
    error CannotRenounceOwnerDefaultAdminRole();
    /// @notice DEFAULT_ADMIN_ROLE cannot be independently revoked.
    error CannotRevokeOwnerDefaultAdminRole();
    /// @notice The DA verifier is already registered.
    error DAVerifierAlreadyRegistered();
    /// @notice The DA verifier is not registered.
    error DAVerifierNotRegistered();
    /// @notice The assertion lifecycle delay must be nonzero.
    error InvalidAssertionTimelock();
    /// @notice DA verification rejected the assertion proof.
    /// @param daVerifier Verifier that rejected the proof.
    error InvalidDAProof(address daVerifier);
    /// @notice Initialization was repeated or migration authentication failed.
    error InvalidInitialization();
    /// @notice A manager transfer request is invalid.
    error InvalidManagerTransferRequest();
    /// @notice No manager transfer is pending.
    error NoPendingManager();
    /// @notice An initialization-only operation ran outside initialization.
    error NotInitializing();
    /// @notice The caller is not whitelisted while admission is enabled.
    error NotWhitelisted();
    /// @notice The proposed ownership address is invalid.
    /// @param owner Invalid owner address.
    error OwnableInvalidOwner(address owner);
    /// @notice The caller is not authorized by ownership.
    /// @param account Unauthorized caller.
    error OwnableUnauthorizedAccount(address account);
    /// @notice The exact ownership nomination has not completed its delayed authorization.
    error OwnershipNotReady();
    /// @notice This oracle has not deployed its administration timelock.
    error TimelockNotInitialized();
    /// @notice The adopter reached its assertion capacity.
    error TooManyAssertions();
    /// @notice The caller is not the adopter's manager.
    error UnauthorizedManager();
    /// @notice Admin verification rejected registration.
    error UnauthorizedRegistrant();
    /// @notice The administration operation is not in this oracle's queue.
    error UnknownAdministrationOperation();
    /// @notice The caller whitelist is already disabled.
    error WhitelistAlreadyDisabled();
    /// @notice The caller whitelist is already enabled.
    error WhitelistAlreadyEnabled();

    /// @notice An account entered the caller whitelist.
    /// @param account Admitted account.
    event AddedToWhitelist(address indexed account);
    /// @notice An admin verifier entered the registry.
    /// @param adminVerifier Added verifier.
    event AdminVerifierAdded(address adminVerifier);
    /// @notice An admin verifier left the registry.
    /// @param adminVerifier Removed verifier.
    event AdminVerifierRemoved(address adminVerifier);
    /// @notice A queued administration action executed successfully.
    /// @param id Executed identifier.
    /// @param executedAt Execution timestamp in seconds.
    event AdministrationExecuted(bytes32 indexed id, uint256 executedAt);
    /// @notice An authorized caller scheduled an exact administration action.
    /// @param id Operation identifier.
    /// @param resource Conflicting-action key.
    /// @param proposer Authorized scheduling caller.
    /// @param readyAt Earliest execution timestamp in seconds.
    event AdministrationScheduled(
        bytes32 indexed id, bytes32 indexed resource, address indexed proposer, uint256 readyAt
    );
    /// @notice A new assertion lifecycle was scheduled.
    /// @param assertionAdopter Registered adopter.
    /// @param assertionId Assertion identifier.
    /// @param activationBlock First active block.
    /// @param daVerifier Verifier accepting the proof.
    /// @param metadata Verifier metadata.
    /// @param proof Accepted DA proof.
    event AssertionAdded(
        address indexed assertionAdopter,
        bytes32 indexed assertionId,
        uint256 activationBlock,
        address indexed daVerifier,
        bytes metadata,
        bytes proof
    );
    /// @notice An adopter registered a manager.
    /// @param contractAddress Adopter address.
    /// @param manager Registered manager.
    /// @param adminVerifier Verifier approving registration.
    event AssertionAdopterAdded(address indexed contractAddress, address indexed manager, address adminVerifier);
    /// @notice Assertion removal was scheduled with the block-based lifecycle delay.
    /// @param assertionAdopter Adopter address.
    /// @param assertionId Assertion identifier.
    /// @param deactivationBlock First inactive block.
    event AssertionRemoved(address indexed assertionAdopter, bytes32 indexed assertionId, uint256 deactivationBlock);
    /// @notice A DA verifier entered the registry.
    /// @param daVerifier Added verifier.
    event DAVerifierAdded(address daVerifier);
    /// @notice A DA verifier left the registry.
    /// @param daVerifier Removed verifier.
    event DAVerifierRemoved(address daVerifier);
    /// @notice An initialization version was consumed.
    /// @param version Consumed version number.
    event Initialized(uint64 version);
    /// @notice A manager nominated its successor.
    /// @param contractAddress Adopter address.
    /// @param manager Current manager.
    /// @param newManager Nominated successor.
    event ManagerTransferRequested(
        address indexed contractAddress, address indexed manager, address indexed newManager
    );
    /// @notice Management changed or was revoked.
    /// @param contractAddress Adopter address.
    /// @param newManager New manager, or zero on revocation.
    event ManagerTransferred(address indexed contractAddress, address indexed newManager);
    /// @notice A matured capacity change became effective.
    /// @param previousMaximum Previous assertion cap.
    /// @param newMaximum New assertion cap.
    event MaxAssertionsPerAAChanged(uint16 previousMaximum, uint16 newMaximum);
    /// @notice Ownership transfer was proposed.
    /// @param previousOwner Current owner.
    /// @param newOwner Proposed owner.
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    /// @notice Ownership changed with the coupled default-admin role.
    /// @param previousOwner Previous owner.
    /// @param newOwner New owner, or zero on renunciation.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    /// @notice An account left the caller whitelist.
    /// @param account Removed account.
    event RemovedFromWhitelist(address indexed account);
    /// @notice A role's administrator role changed.
    /// @param role Managed role.
    /// @param previousAdminRole Former administrator role.
    /// @param newAdminRole New administrator role.
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    /// @notice Role membership was granted.
    /// @param role Granted role.
    /// @param account New member.
    /// @param sender Caller applying the grant.
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    /// @notice Role membership was revoked.
    /// @param role Revoked role.
    /// @param account Former member.
    /// @param sender Caller applying the revocation.
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    /// @notice A storage reset was scheduled with the assertion lifecycle delay.
    /// @param adopter Adopter address.
    /// @param storageKey Storage key to reset.
    /// @param resetBlock Effective reset block.
    event StorageReset(address indexed adopter, bytes32 indexed storageKey, uint256 resetBlock);
    /// @notice The oracle deployed its administration timelock.
    /// @param controller Deployed controller address.
    event TimelockInitialized(address indexed controller);
    /// @notice Caller whitelist enforcement was disabled.
    event WhitelistDisabled();
    /// @notice Caller whitelist enforcement was enabled.
    event WhitelistEnabled();

    /// @notice Returns the assertion lifecycle delay, independent of administration.
    /// @return Delay in blocks.
    function ASSERTION_TIMELOCK_BLOCKS() external view returns (uint256);
    /// @notice Returns the role coupled to ownership.
    /// @return Default-admin role identifier.
    function DEFAULT_ADMIN_ROLE() external view returns (bytes32);
    /// @notice Returns the protocol-configuration role.
    /// @return Governance role identifier.
    function GOVERNANCE_ROLE() external view returns (bytes32);
    /// @notice Returns the guardian-administration role.
    /// @return Guardian-admin role identifier.
    function GUARDIAN_ADMIN_ROLE() external view returns (bytes32);
    /// @notice Returns the emergency-action role.
    /// @return Guardian role identifier.
    function GUARDIAN_ROLE() external view returns (bytes32);
    /// @notice Returns the operator-administration role.
    /// @return Operator-admin role identifier.
    function OPERATOR_ADMIN_ROLE() external view returns (bytes32);
    /// @notice Returns the caller-admission management role.
    /// @return Operator role identifier.
    function OPERATOR_ROLE() external view returns (bytes32);
    /// @notice Accepts a pending manager nomination as its nominee.
    /// @param contractAddress Adopter address.
    function acceptManagerTransfer(address contractAddress) external;
    /// @notice Accepts a pending ownership transfer as its nominee after delayed authorization executes.
    function acceptOwnership() external;
    /// @notice Queues an admin verifier addition after the administration delay under governance authorization.
    /// @param adminVerifier Verifier to add.
    function addAdminVerifier(address adminVerifier) external;
    /// @notice Schedules assertion activation after verifying authority, capacity and DA.
    /// @param contractAddress Adopter address.
    /// @param assertionId Assertion identifier.
    /// @param daVerifier Registered DA verifier.
    /// @param metadata Verifier-specific metadata.
    /// @param proof DA proof.
    function addAssertion(
        address contractAddress,
        bytes32 assertionId,
        address daVerifier,
        bytes memory metadata,
        bytes memory proof
    ) external;
    /// @notice Queues a DA verifier addition after the administration delay under governance authorization.
    /// @param daVerifier Verifier to add.
    function addDAVerifier(address daVerifier) external;
    /// @notice Queues a caller addition after the administration delay under operator authorization.
    /// @param account Account to admit.
    function addToWhitelist(address account) external;
    /// @notice Reads effective admin-verifier registry membership.
    /// @param adminVerifier Verifier address.
    /// @return isRegistered Whether the verifier is registered.
    function adminVerifiers(address adminVerifier) external view returns (bool isRegistered);
    /// @notice Reads this oracle's current administration delay.
    /// @return Delay in seconds, at least three days.
    function administrationDelay() external view returns (uint256);
    /// @notice Reads a recorded administration payload.
    /// @param id Operation identifier.
    /// @return Exact payload, or an empty record if unknown.
    function administrationOperation(bytes32 id) external view returns (Operation memory);
    /// @notice Applies a matured admin-verifier registry change, only through this oracle's timelock.
    /// @param verifier Affected verifier.
    /// @param registered True to add, false to remove.
    function applyAdminVerifierChange(address verifier, bool registered) external;
    /// @notice Applies a matured DA-verifier registry change, only through this oracle's timelock.
    /// @param verifier Affected verifier.
    /// @param registered True to add, false to remove.
    function applyDAVerifierChange(address verifier, bool registered) external;
    /// @notice Applies a matured capacity proposal, only through this oracle's timelock.
    /// @param maximum New assertion cap.
    function applyMaxAssertionsPerAA(uint16 maximum) external;
    /// @notice Applies a matured role change; callable only by this oracle's timelock.
    /// @param role Role to change.
    /// @param account Affected account.
    /// @param grant True to grant, false to revoke.
    function applyRoleChange(bytes32 role, address account, bool grant) external;
    /// @notice Applies a matured admission proposal, only through this oracle's timelock.
    /// @param account Affected caller.
    /// @param allowed True to admit, false to remove.
    function applyWhitelistAccount(address account, bool allowed) external;
    /// @notice Applies a matured enforcement toggle, only through this oracle's timelock.
    /// @param enabled New enforcement flag.
    function applyWhitelistEnabled(bool enabled) external;
    /// @notice Reads an adopter's manager state and registered assertion count.
    /// @dev The unnamed argument is the adopter address.
    /// @return manager Current manager.
    /// @return pendingManager Nominated manager.
    /// @return assertionCount Registered, not-yet-removed assertions.
    function assertionAdopters(address)
        external
        view
        returns (address manager, address pendingManager, uint16 assertionCount);
    /// @notice Matures a nomination or executes renunciation, only through the oracle's timelock.
    /// @param recipient Nominated owner, or zero to renounce.
    function authorizeOwnership(address recipient) external;
    /// @notice Executes encoded calls atomically in this oracle's context.
    /// @param calls Encoded function calls; one revert rolls back the entire batch.
    function batch(bytes[] memory calls) external;
    /// @notice Reads effective DA-verifier registry membership.
    /// @param daVerifier Verifier address.
    /// @return isRegistered Whether the verifier is registered.
    function daVerifiers(address daVerifier) external view returns (bool isRegistered);
    /// @notice Queues disabling caller admission checks after the administration delay.
    function disableWhitelist() external;
    /// @notice Queues enabling caller admission checks after the administration delay.
    function enableWhitelist() external;
    /// @notice Permissionlessly relays an exact matured administration proposal.
    /// @param id Recorded operation identifier.
    function executeAdministration(bytes32 id) external;
    /// @notice Reads an adopter's registered assertion count.
    /// @param contractAddress Adopter address.
    /// @return assertionCount Registered, not-yet-removed assertions.
    function getAssertionCount(address contractAddress) external view returns (uint16 assertionCount);
    /// @notice Reads the latest lifecycle window, not historical windows.
    /// @param contractAddress Adopter address.
    /// @param assertionId Assertion identifier.
    /// @return activationBlock First active block, or zero if never added.
    /// @return deactivationBlock First inactive block, or zero if no removal is scheduled.
    function getAssertionWindow(address contractAddress, bytes32 assertionId)
        external
        view
        returns (uint256 activationBlock, uint256 deactivationBlock);
    /// @notice Reads the effective manager.
    /// @param contractAddress Adopter address.
    /// @return manager Current manager, or zero.
    function getManager(address contractAddress) external view returns (address manager);
    /// @notice Reads the nominated manager.
    /// @param contractAddress Adopter address.
    /// @return pendingManager Nominee, or zero.
    function getPendingManager(address contractAddress) external view returns (address pendingManager);
    /// @notice Reads the role authorized to manage a role.
    /// @param role Managed role.
    /// @return Administrator role identifier.
    function getRoleAdmin(bytes32 role) external view returns (bytes32);
    /// @notice Queues governance membership after the administration delay under owner authorization.
    /// @param governance Account to grant.
    function grantGovernanceRole(address governance) external;
    /// @notice Queues guardian-admin membership after the administration delay under owner authorization.
    /// @param guardianAdmin Account to grant.
    function grantGuardianAdminRole(address guardianAdmin) external;
    /// @notice Queues guardian membership after the administration delay under guardian-admin authorization.
    /// @param guardian Account to grant.
    function grantGuardianRole(address guardian) external;
    /// @notice Queues operator-admin membership after the administration delay under owner authorization.
    /// @param operatorAdmin Account to grant.
    function grantOperatorAdminRole(address operatorAdmin) external;
    /// @notice Queues operator membership after the administration delay under operator-admin authorization.
    /// @param operator Account to grant.
    function grantOperatorRole(address operator) external;
    /// @notice Queues a non-default-admin role grant after the delay under its administrator's authorization.
    /// @param role Role to grant.
    /// @param account Account to grant.
    function grantRole(bytes32 role, address account) external;
    /// @notice Checks whether an assertion was ever added, not whether it is currently active.
    /// @param contractAddress Adopter address.
    /// @param assertionId Assertion identifier.
    /// @return isAssociated Whether the latest window has an activation block.
    function hasAssertion(address contractAddress, bytes32 assertionId) external view returns (bool isAssociated);
    /// @notice Reads effective role membership.
    /// @param role Role identifier.
    /// @param account Account to query.
    /// @return Whether the account holds the role.
    function hasRole(bytes32 role, address account) external view returns (bool);
    /// @notice Deploys a legacy proxy's timelock once through its own ProxyAdmin's upgradeAndCall.
    /// @dev Requires version 1 and an intact ERC-1967 admin slot; preserves application state.
    function initializeTimelockV2() external;
    /// @notice Initializes a fresh proxy with caller whitelisting enabled and an empty whitelist.
    /// @param admin Initial owner and role holder.
    /// @param _adminVerifiers Initial admin verifier registry.
    /// @param _daVerifiers Initial DA verifier registry.
    /// @param _maxAssertionsPerAA Initial assertion cap.
    function initialize(
        address admin,
        address[] memory _adminVerifiers,
        address[] memory _daVerifiers,
        uint16 _maxAssertionsPerAA
    ) external;
    /// @notice Initializes a fresh proxy and deploys its own three-day timelock atomically.
    /// @param admin Initial owner and role holder.
    /// @param _adminVerifiers Initial admin verifier registry.
    /// @param _daVerifiers Initial DA verifier registry.
    /// @param _maxAssertionsPerAA Initial assertion cap.
    /// @param _whitelistEnabled Initial admission-check flag.
    /// @param _initialWhitelist Initially admitted callers.
    function initializeWithWhitelist(
        address admin,
        address[] memory _adminVerifiers,
        address[] memory _daVerifiers,
        uint16 _maxAssertionsPerAA,
        bool _whitelistEnabled,
        address[] memory _initialWhitelist
    ) external;
    /// @notice Reads effective admin-verifier membership.
    /// @param adminVerifier Verifier address.
    /// @return isRegistered Whether registered.
    function isAdminVerifierRegistered(address adminVerifier) external view returns (bool isRegistered);
    /// @notice Reads effective DA-verifier membership.
    /// @param daVerifier Verifier address.
    /// @return isRegistered Whether registered.
    function isDAVerifierRegistered(address daVerifier) external view returns (bool isRegistered);
    /// @notice Checks whether admission is disabled or the account is whitelisted.
    /// @param account Caller address.
    /// @return Whether caller admission permits the account.
    function isWhitelisted(address account) external view returns (bool);
    /// @notice Returns the last scheduled proposal, regardless of its current operation state.
    /// @return Latest identifier, or zero before the first proposal.
    function latestAdministrationOperation() external view returns (bytes32);
    /// @notice Reads the effective per-adopter assertion cap.
    /// @return Maximum registered assertions per adopter.
    function maxAssertionsPerAA() external view returns (uint16);
    /// @notice Reads the owner coupled to DEFAULT_ADMIN_ROLE.
    /// @return Current owner.
    function owner() external view returns (address);
    /// @notice Reads the proposed successor owner.
    /// @return Nominee, or zero.
    function pendingOwner() external view returns (address);
    /// @notice Registers the caller as manager after admin verification.
    /// @param contractAddress Adopter address.
    /// @param adminVerifier Registered admin verifier.
    /// @param data Verifier-specific evidence.
    function registerAssertionAdopter(address contractAddress, address adminVerifier, bytes memory data) external;
    /// @notice Queues an admin verifier removal after the administration delay under governance authorization.
    /// @param adminVerifier Verifier to remove.
    function removeAdminVerifier(address adminVerifier) external;
    /// @notice Schedules assertion deactivation after the assertion lifecycle delay.
    /// @param contractAddress Adopter address.
    /// @param assertionId Assertion to remove.
    function removeAssertion(address contractAddress, bytes32 assertionId) external;
    /// @notice Lets a guardian schedule assertion deactivation without the administration delay.
    /// @param contractAddress Adopter address.
    /// @param assertionId Assertion to remove after the block-based lifecycle delay.
    function removeAssertionByGuardian(address contractAddress, bytes32 assertionId) external;
    /// @notice Queues a DA verifier removal after the administration delay under governance authorization.
    /// @param daVerifier Verifier to remove.
    function removeDAVerifier(address daVerifier) external;
    /// @notice Queues caller removal after the administration delay under operator authorization.
    /// @param account Account to remove.
    function removeFromWhitelist(address account) external;
    /// @notice Queues renunciation of ownership and its coupled default-admin role after the current delay.
    function renounceOwnership() external;
    /// @notice Queues role renunciation, except the owner's coupled default-admin role.
    /// @param role Role to renounce.
    /// @param callerConfirmation Must equal the caller.
    function renounceRole(bytes32 role, address callerConfirmation) external;
    /// @notice Schedules a manager-authorized storage reset after the assertion lifecycle delay.
    /// @param adopter Adopter address.
    /// @param storageKey Key to reset.
    function resetStorage(address adopter, bytes32 storageKey) external;
    /// @notice Queues governance revocation after the administration delay under owner authorization.
    /// @param governance Account to revoke.
    function revokeGovernanceRole(address governance) external;
    /// @notice Queues guardian-admin revocation after the administration delay under owner authorization.
    /// @param guardianAdmin Account to revoke.
    function revokeGuardianAdminRole(address guardianAdmin) external;
    /// @notice Queues guardian revocation after the administration delay under guardian-admin authorization.
    /// @param guardian Account to revoke.
    function revokeGuardianRole(address guardian) external;
    /// @notice Immediately clears a manager and any pending manager transfer under guardian authorization.
    /// @param contractAddress Adopter address.
    function revokeManager(address contractAddress) external;
    /// @notice Queues operator-admin revocation after the administration delay under owner authorization.
    /// @param operatorAdmin Account to revoke.
    function revokeOperatorAdminRole(address operatorAdmin) external;
    /// @notice Queues operator revocation after the administration delay under operator-admin authorization.
    /// @param operator Account to revoke.
    function revokeOperatorRole(address operator) external;
    /// @notice Queues role revocation after the delay without revoking the owner's coupled default-admin role.
    /// @param role Role to revoke.
    /// @param account Account to revoke.
    function revokeRole(bytes32 role, address account) external;
    /// @notice Queues this oracle's delay change; only one may be pending.
    /// @param newDelay New delay in seconds, at least three days; waits the current delay.
    /// @return Queued operation identifier.
    function scheduleDelayUpdate(uint256 newDelay) external returns (bytes32);
    /// @notice Queues an assertion-cap change after the administration delay under governance authorization.
    /// @param _maxAssertionsPerAA New cap; existing assertions are not removed.
    function setMaxAssertionsPerAA(uint16 _maxAssertionsPerAA) external;
    /// @notice Checks ERC-165 interface support.
    /// @param interfaceId Interface identifier.
    /// @return Whether the interface is supported.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    /// @notice Reads this oracle's timelock address from its ERC-7201 namespace.
    /// @return Controller address, or zero before initialization.
    function timelock() external view returns (address);
    /// @notice Nominates a new manager under current-manager authorization.
    /// @param contractAddress Adopter address.
    /// @param newManager Nominated successor.
    function transferManager(address contractAddress, address newManager) external;
    /// @notice Nominates a successor who can accept only after the exact delayed authorization executes.
    /// @param newOwner Nominated successor.
    function transferOwnership(address newOwner) external;
    /// @notice Reads raw caller-whitelist membership.
    /// @dev The unnamed argument is the account address.
    /// @return Whether the account is present, independent of the enabled flag.
    function whitelist(address) external view returns (bool);
    /// @notice Reads whether caller admission checks are enabled.
    /// @return Whether whitelist enforcement is enabled.
    function whitelistEnabled() external view returns (bool);
}
