// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IAdminVerifier} from "./IAdminVerifier.sol";
import {IDAVerifier} from "./IDAVerifier.sol";

/// @title IStateOracleV1
/// @notice Historical StateOracle consumer interface released as 0.2.0.
/// @dev This interface is immutable. It remains available for consumers of 0.2.0 deployments;
/// breaking changes introduced in 0.3.0 are represented by IStateOracleV2.
interface IStateOracleV1 {
    error AccessControlBadConfirmation();
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
    error AccountNotWhitelisted(address account);
    error AdminVerifierAlreadyRegistered();
    error AdminVerifierNotRegistered();
    error AlreadyWhitelisted(address account);
    error AssertionAdopterAlreadyRegistered();
    error AssertionAdopterNotRegistered();
    error AssertionAlreadyExists();
    error AssertionAlreadyRemoved();
    error AssertionDoesNotExist();
    error BatchError(bytes result);
    error CannotGrantDefaultAdminRole();
    error CannotRenounceOwnerDefaultAdminRole();
    error CannotRevokeOwnerDefaultAdminRole();
    error InvalidAssertionTimelock();
    error InvalidInitialization();
    error InvalidManagerTransferRequest();
    error InvalidProof();
    error NoPendingManager();
    error NotInitializing();
    error NotWhitelisted();
    error OwnableInvalidOwner(address owner);
    error OwnableUnauthorizedAccount(address account);
    error TooManyAssertions();
    error UnauthorizedManager();
    error UnauthorizedRegistrant();
    error WhitelistAlreadyDisabled();
    error WhitelistAlreadyEnabled();

    event AddedToWhitelist(address indexed account);
    event AdminVerifierAdded(IAdminVerifier adminVerifier);
    event AdminVerifierRemoved(IAdminVerifier adminVerifier);
    event AssertionAdded(address assertionAdopter, bytes32 assertionId, uint256 activationBlock);
    event AssertionAdopterAdded(address indexed contractAddress, address indexed manager, IAdminVerifier adminVerifier);
    event AssertionRemoved(address assertionAdopter, bytes32 assertionId, uint256 deactivationBlock);
    event Initialized(uint64 version);
    event ManagerTransferRequested(
        address indexed contractAddress, address indexed manager, address indexed newManager
    );
    event ManagerTransferred(address indexed contractAddress, address indexed newManager);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RemovedFromWhitelist(address indexed account);
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event WhitelistDisabled();
    event WhitelistEnabled();

    function ASSERTION_TIMELOCK_BLOCKS() external view returns (uint128);
    function DA_VERIFIER() external view returns (IDAVerifier);
    function DEFAULT_ADMIN_ROLE() external view returns (bytes32);
    function GOVERNANCE_ROLE() external view returns (bytes32);
    function GUARDIAN_ADMIN_ROLE() external view returns (bytes32);
    function GUARDIAN_ROLE() external view returns (bytes32);
    function OPERATOR_ADMIN_ROLE() external view returns (bytes32);
    function OPERATOR_ROLE() external view returns (bytes32);
    function acceptManagerTransfer(address contractAddress) external;
    function acceptOwnership() external;
    function addAdminVerifier(IAdminVerifier adminVerifier) external;
    function addAssertion(address contractAddress, bytes32 assertionId, bytes calldata metadata, bytes calldata proof)
        external;
    function addToWhitelist(address account) external;
    function adminVerifiers(IAdminVerifier adminVerifier) external view returns (bool isRegistered);
    function assertionAdopters(address)
        external
        view
        returns (address manager, address pendingManager, uint16 assertionCount);
    function batch(bytes[] calldata calls) external;
    function disableWhitelist() external;
    function enableWhitelist() external;
    function getAssertionCount(address contractAddress) external view returns (uint16 assertionCount);
    function getAssertionWindow(address contractAddress, bytes32 assertionId)
        external
        view
        returns (uint128 activationBlock, uint128 deactivationBlock);
    function getManager(address contractAddress) external view returns (address manager);
    function getPendingManager(address contractAddress) external view returns (address pendingManager);
    function getRoleAdmin(bytes32 role) external view returns (bytes32);
    function grantGovernanceRole(address governance) external;
    function grantGuardianAdminRole(address guardianAdmin) external;
    function grantGuardianRole(address guardian) external;
    function grantOperatorAdminRole(address operatorAdmin) external;
    function grantOperatorRole(address operator) external;
    function grantRole(bytes32 role, address account) external;
    function hasAssertion(address contractAddress, bytes32 assertionId) external view returns (bool isAssociated);
    function hasRole(bytes32 role, address account) external view returns (bool);
    function initialize(address admin, IAdminVerifier[] calldata _adminVerifiers, uint16 _maxAssertionsPerAA) external;
    function isAdminVerifierRegistered(IAdminVerifier adminVerifier) external view returns (bool isRegistered);
    function isWhitelisted(address account) external view returns (bool);
    function maxAssertionsPerAA() external view returns (uint16);
    function owner() external view returns (address);
    function pendingOwner() external view returns (address);
    function registerAssertionAdopter(address contractAddress, IAdminVerifier adminVerifier, bytes calldata data)
        external;
    function removeAdminVerifier(IAdminVerifier adminVerifier) external;
    function removeAssertion(address contractAddress, bytes32 assertionId) external;
    function removeAssertionByGuardian(address contractAddress, bytes32 assertionId) external;
    function removeFromWhitelist(address account) external;
    function renounceOwnership() external;
    function renounceRole(bytes32 role, address callerConfirmation) external;
    function revokeGovernanceRole(address governance) external;
    function revokeGuardianAdminRole(address guardianAdmin) external;
    function revokeGuardianRole(address guardian) external;
    function revokeManager(address contractAddress) external;
    function revokeOperatorAdminRole(address operatorAdmin) external;
    function revokeOperatorRole(address operator) external;
    function revokeRole(bytes32 role, address account) external;
    function setMaxAssertionsPerAA(uint16 _maxAssertionsPerAA) external;
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function transferManager(address contractAddress, address newManager) external;
    function transferOwnership(address newOwner) external;
    function whitelist(address) external view returns (bool);
    function whitelistEnabled() external view returns (bool);
}
