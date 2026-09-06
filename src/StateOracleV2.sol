// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Initializable} from "solady/utils/Initializable.sol";

import {Batch} from "./Batch.sol";
import {StateOracleV2AccessControl} from "./StateOracleV2AccessControl.sol";
import {IAdminVerifier} from "./interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "./interfaces/IDAVerifier.sol";
import {ITriggerManifestValidator} from "./interfaces/ITriggerManifestValidator.sol";
import {AdminVerifierRegistry} from "./lib/AdminVerifierRegistry.sol";
import {DAVerifierRegistry} from "./lib/DAVerifierRegistry.sol";

/// @notice Project-scoped assertion registry for fresh V2 deployments.
contract StateOracleV2 is Batch, Initializable, StateOracleV2AccessControl, Pausable {
    using AdminVerifierRegistry for mapping(IAdminVerifier verifier => bool registered);
    using DAVerifierRegistry for mapping(IDAVerifier verifier => bool registered);

    uint256 public immutable ASSERTION_TIMELOCK_BLOCKS;

    enum ProjectStatus {
        None,
        Active,
        Retired
    }

    struct Project {
        address protocolManager;
        address pendingProtocolManager;
        uint64 triggerLimit;
        uint64 usedTriggerUnits;
        uint64 retiredAtBlock;
        ProjectStatus status;
    }

    struct AssertionAdopter {
        bytes32 projectId;
        bytes32 pendingProjectId;
        uint32 assertionCount;
    }

    struct AssertionInstallation {
        uint64 triggerUnits;
        bytes32 manifestSchemaId;
        bytes32 manifestHash;
        bool enabled;
    }

    error InvalidAssertionTimelock();
    error InvalidAdmin();
    error InvalidProjectId();
    error ProjectAlreadyExists();
    error ProjectNotActive();
    error ProjectHasAssertions();
    error InvalidProtocolManager();
    error UnauthorizedProtocolManager();
    error NoPendingProtocolManager();
    error ProtocolManagerAlreadyCleared();
    error ProtocolManagerNotCleared();
    error ProjectRetirementAlreadyRequested();
    error ProjectRetirementNotRequested();
    error TriggerLimitUnchanged();
    error TriggerManifestValidatorUnchanged();
    error InvalidTriggerManifestValidator();

    event ProjectCreated(bytes32 indexed projectId, address indexed protocolManager);
    event ProtocolManagerTransferRequested(
        bytes32 indexed projectId, address indexed protocolManager, address indexed pendingProtocolManager
    );
    event ProtocolManagerTransferred(bytes32 indexed projectId, address indexed protocolManager);
    event ProjectTriggerLimitUpdated(bytes32 indexed projectId, uint64 oldLimit, uint64 newLimit);
    event ProjectRetirementRequested(bytes32 indexed projectId, address indexed protocolManager);
    event ProjectRetirementCancelled(bytes32 indexed projectId, address indexed protocolManager);
    event ProjectRetired(bytes32 indexed projectId, uint64 retiredAtBlock);
    event TriggerManifestValidatorUpdated(
        bytes32 indexed schemaId, ITriggerManifestValidator oldValidator, ITriggerManifestValidator newValidator
    );

    mapping(bytes32 projectId => Project project) public projects;
    mapping(address assertionAdopter => AssertionAdopter assignment) public assertionAdopters;
    mapping(address assertionAdopter => mapping(bytes32 assertionId => AssertionInstallation installation)) public
        assertions;
    mapping(IAdminVerifier verifier => bool registered) public adminVerifiers;
    mapping(IDAVerifier verifier => bool registered) public daVerifiers;
    mapping(bytes32 schemaId => ITriggerManifestValidator validator) public triggerManifestValidators;
    mapping(bytes32 projectId => address protocolManager) public projectRetirementRequesters;

    constructor(uint256 assertionTimelockBlocks) Ownable(msg.sender) {
        require(
            assertionTimelockBlocks != 0 && assertionTimelockBlocks <= type(uint64).max - block.number,
            InvalidAssertionTimelock()
        );
        ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
        renounceOwnership();
        _disableInitializers();
    }

    function initialize(
        address admin,
        IAdminVerifier[] calldata initialAdminVerifiers,
        IDAVerifier[] calldata initialDAVerifiers,
        bytes32 initialManifestSchemaId,
        ITriggerManifestValidator initialManifestValidator
    ) external initializer {
        require(admin != address(0), InvalidAdmin());
        _initializeRoles(admin);
        for (uint256 i; i < initialAdminVerifiers.length; ++i) {
            adminVerifiers.add(initialAdminVerifiers[i]);
        }
        for (uint256 i; i < initialDAVerifiers.length; ++i) {
            daVerifiers.add(initialDAVerifiers[i]);
        }
        _setTriggerManifestValidator(initialManifestSchemaId, initialManifestValidator);
    }

    function createProject(bytes32 projectId, address protocolManager)
        external
        onlyRole(PROJECT_CREATOR_ROLE)
        whenNotPaused
    {
        _createProject(projectId, protocolManager);
    }

    function requestProtocolManagerTransfer(bytes32 projectId, address pendingProtocolManager) external whenNotPaused {
        Project storage project = _activeProject(projectId);
        require(msg.sender == project.protocolManager, UnauthorizedProtocolManager());
        require(
            pendingProtocolManager != address(0) && pendingProtocolManager != project.protocolManager
                && pendingProtocolManager != project.pendingProtocolManager,
            InvalidProtocolManager()
        );
        project.pendingProtocolManager = pendingProtocolManager;
        emit ProtocolManagerTransferRequested(projectId, msg.sender, pendingProtocolManager);
    }

    function revokeProtocolManager(bytes32 projectId) external onlyGuardian {
        Project storage project = _activeProject(projectId);
        require(
            project.protocolManager != address(0) || project.pendingProtocolManager != address(0),
            ProtocolManagerAlreadyCleared()
        );
        _clearProjectRetirementRequest(projectId);
        project.protocolManager = address(0);
        project.pendingProtocolManager = address(0);
        emit ProtocolManagerTransferred(projectId, address(0));
    }

    function proposeProtocolManagerReplacement(bytes32 projectId, address replacement) external onlyProjectAdmin {
        Project storage project = _activeProject(projectId);
        require(
            project.protocolManager == address(0) && project.pendingProtocolManager == address(0),
            ProtocolManagerNotCleared()
        );
        require(replacement != address(0), InvalidProtocolManager());
        project.pendingProtocolManager = replacement;
        emit ProtocolManagerTransferRequested(projectId, address(0), replacement);
    }

    function acceptProtocolManagerTransfer(bytes32 projectId) external {
        Project storage project = _activeProject(projectId);
        if (project.protocolManager != address(0)) _requireNotPaused();
        address pendingProtocolManager = project.pendingProtocolManager;
        require(pendingProtocolManager != address(0), NoPendingProtocolManager());
        require(msg.sender == pendingProtocolManager, UnauthorizedProtocolManager());
        _clearProjectRetirementRequest(projectId);
        project.protocolManager = pendingProtocolManager;
        project.pendingProtocolManager = address(0);
        emit ProtocolManagerTransferred(projectId, pendingProtocolManager);
    }

    function setProjectTriggerLimit(bytes32 projectId, uint64 newLimit) external onlyRole(TRIGGER_LIMIT_ROLE) {
        Project storage project = _activeProject(projectId);
        uint64 oldLimit = project.triggerLimit;
        require(oldLimit != newLimit, TriggerLimitUnchanged());
        project.triggerLimit = newLimit;
        emit ProjectTriggerLimitUpdated(projectId, oldLimit, newLimit);
    }

    function requestProjectRetirement(bytes32 projectId) external whenNotPaused {
        Project storage project = _activeProject(projectId);
        require(msg.sender == project.protocolManager, UnauthorizedProtocolManager());
        require(projectRetirementRequesters[projectId] == address(0), ProjectRetirementAlreadyRequested());
        projectRetirementRequesters[projectId] = msg.sender;
        emit ProjectRetirementRequested(projectId, msg.sender);
    }

    function cancelProjectRetirement(bytes32 projectId) external whenNotPaused {
        Project storage project = _activeProject(projectId);
        require(msg.sender == project.protocolManager, UnauthorizedProtocolManager());
        require(projectRetirementRequesters[projectId] == msg.sender, ProjectRetirementNotRequested());
        _clearProjectRetirementRequest(projectId);
    }

    function finalizeProjectRetirement(bytes32 projectId) external onlyProjectAdmin {
        Project storage project = _activeProject(projectId);
        address retirementRequester = projectRetirementRequesters[projectId];
        require(
            retirementRequester != address(0) && retirementRequester == project.protocolManager,
            ProjectRetirementNotRequested()
        );
        require(project.usedTriggerUnits == 0, ProjectHasAssertions());
        uint64 retiredAtBlock = uint64(block.number);
        project.protocolManager = address(0);
        project.pendingProtocolManager = address(0);
        delete projectRetirementRequesters[projectId];
        project.triggerLimit = 0;
        project.status = ProjectStatus.Retired;
        project.retiredAtBlock = retiredAtBlock;
        emit ProjectRetired(projectId, retiredAtBlock);
    }

    function pause() external onlyGovernance {
        _pause();
    }

    function unpause() external onlyGovernance {
        _unpause();
    }

    function addAdminVerifier(IAdminVerifier adminVerifier) external onlyGovernance {
        adminVerifiers.add(adminVerifier);
    }

    function removeAdminVerifier(IAdminVerifier adminVerifier) external onlyGovernance {
        adminVerifiers.remove(adminVerifier);
    }

    function addDAVerifier(IDAVerifier daVerifier) external onlyGovernance {
        daVerifiers.add(daVerifier);
    }

    function removeDAVerifier(IDAVerifier daVerifier) external onlyGovernance {
        daVerifiers.remove(daVerifier);
    }

    function setTriggerManifestValidator(bytes32 schemaId, ITriggerManifestValidator validator)
        external
        onlyGovernance
    {
        _setTriggerManifestValidator(schemaId, validator);
    }

    function _createProject(bytes32 projectId, address protocolManager) private {
        require(projectId != bytes32(0), InvalidProjectId());
        require(protocolManager != address(0), InvalidProtocolManager());
        Project storage project = projects[projectId];
        require(project.status == ProjectStatus.None, ProjectAlreadyExists());
        project.protocolManager = protocolManager;
        project.status = ProjectStatus.Active;
        emit ProjectCreated(projectId, protocolManager);
    }

    function _activeProject(bytes32 projectId) private view returns (Project storage project) {
        project = projects[projectId];
        require(project.status == ProjectStatus.Active, ProjectNotActive());
    }

    function _clearProjectRetirementRequest(bytes32 projectId) private {
        address requester = projectRetirementRequesters[projectId];
        if (requester == address(0)) return;
        delete projectRetirementRequesters[projectId];
        emit ProjectRetirementCancelled(projectId, requester);
    }

    function _setTriggerManifestValidator(bytes32 schemaId, ITriggerManifestValidator validator) private {
        require(schemaId != bytes32(0) && address(validator) != address(0), InvalidTriggerManifestValidator());
        ITriggerManifestValidator oldValidator = triggerManifestValidators[schemaId];
        require(oldValidator != validator, TriggerManifestValidatorUnchanged());
        triggerManifestValidators[schemaId] = validator;
        emit TriggerManifestValidatorUpdated(schemaId, oldValidator, validator);
    }
}
