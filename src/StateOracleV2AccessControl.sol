// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @notice Role hierarchy for StateOracleV2.
abstract contract StateOracleV2AccessControl is Ownable2Step, AccessControl {
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    bytes32 public constant GUARDIAN_ADMIN_ROLE = keccak256("GUARDIAN_ADMIN_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant PROJECT_CREATOR_ROLE = keccak256("PROJECT_CREATOR_ROLE");
    bytes32 public constant PROJECT_ADMIN_ROLE = keccak256("PROJECT_ADMIN_ROLE");
    bytes32 public constant TRIGGER_LIMIT_ROLE = keccak256("TRIGGER_LIMIT_ROLE");

    error CannotGrantDefaultAdminRole();
    error CannotRevokeOwnerDefaultAdminRole();
    error CannotRenounceOwnerDefaultAdminRole();

    modifier onlyGovernance() {
        _checkRole(GOVERNANCE_ROLE);
        _;
    }

    modifier onlyGuardian() {
        _checkRole(GUARDIAN_ROLE);
        _;
    }

    modifier onlyProjectAdmin() {
        _checkRole(PROJECT_ADMIN_ROLE);
        _;
    }

    function _initializeRoles(address admin) internal {
        _transferOwnership(admin);
        _setRoleAdmin(GOVERNANCE_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(GUARDIAN_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(GUARDIAN_ROLE, GUARDIAN_ADMIN_ROLE);
        _setRoleAdmin(PROJECT_CREATOR_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(PROJECT_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(TRIGGER_LIMIT_ROLE, DEFAULT_ADMIN_ROLE);

        bytes32[] memory roles = _roles();
        for (uint256 i; i < roles.length; ++i) {
            _grantRole(roles[i], admin);
        }
    }

    function _roles() private pure returns (bytes32[] memory roles) {
        roles = new bytes32[](6);
        roles[0] = GOVERNANCE_ROLE;
        roles[1] = GUARDIAN_ADMIN_ROLE;
        roles[2] = GUARDIAN_ROLE;
        roles[3] = PROJECT_CREATOR_ROLE;
        roles[4] = PROJECT_ADMIN_ROLE;
        roles[5] = TRIGGER_LIMIT_ROLE;
    }

    function _transferOwnership(address newOwner) internal virtual override {
        address oldOwner = owner();
        if (oldOwner != address(0)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, oldOwner);
            bytes32[] memory roles = _roles();
            for (uint256 i; i < roles.length; ++i) {
                if (hasRole(roles[i], oldOwner)) {
                    _revokeRole(roles[i], oldOwner);
                    if (newOwner != address(0)) _grantRole(roles[i], newOwner);
                }
            }
        }
        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
        super._transferOwnership(newOwner);
    }

    function grantRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        require(role != DEFAULT_ADMIN_ROLE, CannotGrantDefaultAdminRole());
        super.grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        require(role != DEFAULT_ADMIN_ROLE || account != owner(), CannotRevokeOwnerDefaultAdminRole());
        super.revokeRole(role, account);
    }

    function renounceRole(bytes32 role, address callerConfirmation) public virtual override {
        require(role != DEFAULT_ADMIN_ROLE || callerConfirmation != owner(), CannotRenounceOwnerDefaultAdminRole());
        super.renounceRole(role, callerConfirmation);
    }
}
