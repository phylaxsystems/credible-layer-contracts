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
import {ExecutorEventGuard} from "./lib/ExecutorEventGuard.sol";

/// @notice Project-scoped assertion registry for fresh V2 deployments.
contract StateOracleV2 is Batch, Initializable, StateOracleV2AccessControl, Pausable {
    using AdminVerifierRegistry for mapping(IAdminVerifier verifier => bool registered);
    using DAVerifierRegistry for mapping(IDAVerifier verifier => bool registered);

    uint256 private constant MAX_MANIFEST_DATA_LENGTH = 65_536;
    uint256 private constant MAX_MANIFEST_PROOF_LENGTH = 4_096;
    uint256 private constant MAX_DA_PROOF_LENGTH = 65_536;
    uint256 private constant MAX_DA_METADATA_LENGTH = 4_096;
    uint256 private constant MAX_ADMIN_DATA_LENGTH = 4_096;
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

    struct TriggerManifest {
        bytes32 schemaId;
        bytes data;
        bytes proof;
    }

    struct AssertionArtifact {
        bytes32 deploymentCodeHash;
        TriggerManifest triggerManifest;
    }

    struct DAProof {
        IDAVerifier verifier;
        bytes metadata;
        bytes proof;
    }

    struct AssertionInstallation {
        uint64 triggerUnits;
        uint64 nextAddAllowedFromBlock;
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
    error TriggerLimitUnchanged();
    error TriggerLimitExceeded();
    error UnauthorizedRegistrant();
    error InvalidAssertionAdopter();
    error AssertionAdopterAlreadyAssigned();
    error AssertionAdopterNotAssigned();
    error PendingAssignmentExists();
    error NoPendingAssignment();
    error AssertionAdopterHasAssertions();
    error AssertionAlreadyExists();
    error AssertionDoesNotExist();
    error AssertionAddNotYetAllowed();
    error InvalidAssertionId();
    error EffectiveBlockOverflow();
    error DAVerifierNotRegistered();
    error InvalidDAProof(IDAVerifier verifier);
    error TriggerManifestValidatorNotRegistered();
    error TriggerManifestValidatorUnchanged();
    error InvalidTriggerManifestValidator();
    error InvalidTriggerUnits();
    error DataTooLarge();

    event ProjectCreated(bytes32 indexed projectId, address indexed protocolManager);
    event ProtocolManagerTransferRequested(
        bytes32 indexed projectId, address indexed protocolManager, address indexed pendingProtocolManager
    );
    event ProtocolManagerTransferred(bytes32 indexed projectId, address indexed protocolManager);
    event ProjectTriggerLimitUpdated(bytes32 indexed projectId, uint64 oldLimit, uint64 newLimit);
    event ProjectRetired(bytes32 indexed projectId, uint64 retiredAtBlock);
    event AssertionAdopterRegistrationRequested(
        address indexed assertionAdopter, bytes32 indexed projectId, IAdminVerifier indexed adminVerifier
    );
    event AssertionAdopterRegistrationCancelled(address indexed assertionAdopter, bytes32 indexed projectId);
    event AssertionAdopterRegistrationRejected(address indexed assertionAdopter, bytes32 indexed projectId);
    event AssertionAdopterAdded(address indexed assertionAdopter, bytes32 indexed projectId);
    event AssertionAdopterDetached(address indexed assertionAdopter, bytes32 indexed projectId);
    event AssertionAdded(
        bytes32 indexed projectId,
        address indexed assertionAdopter,
        bytes32 indexed assertionId,
        uint256 activationBlock,
        uint64 triggerUnits,
        bytes32 manifestSchemaId,
        bytes manifestData,
        IDAVerifier daVerifier,
        bytes daMetadata,
        bytes proof
    );
    event AssertionRemoved(
        bytes32 indexed projectId,
        address indexed assertionAdopter,
        bytes32 indexed assertionId,
        uint256 deactivationBlock,
        uint64 triggerUnits
    );
    event StorageReset(address indexed assertionAdopter, bytes32 indexed storageKey, uint256 resetBlock);
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
        project.protocolManager = address(0);
        project.pendingProtocolManager = address(0);
        emit ProtocolManagerTransferred(projectId, address(0));
    }

    function proposeProtocolManagerReplacement(bytes32 projectId, address replacement) external onlyGovernance {
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

    function retireProject(bytes32 projectId) external onlyGuardian {
        Project storage project = _activeProject(projectId);
        require(project.usedTriggerUnits == 0, ProjectHasAssertions());
        uint64 retiredAtBlock = uint64(block.number);
        project.protocolManager = address(0);
        project.pendingProtocolManager = address(0);
        project.triggerLimit = 0;
        project.status = ProjectStatus.Retired;
        project.retiredAtBlock = retiredAtBlock;
        emit ProjectRetired(projectId, retiredAtBlock);
    }

    function registerAssertionAdopter(
        address assertionAdopter,
        bytes32 projectId,
        IAdminVerifier adminVerifier,
        bytes calldata data
    ) external whenNotPaused {
        require(assertionAdopter != address(0), InvalidAssertionAdopter());
        require(data.length <= MAX_ADMIN_DATA_LENGTH, DataTooLarge());
        _activeProject(projectId);
        AssertionAdopter storage assignment = assertionAdopters[assertionAdopter];
        if (assignment.projectId != bytes32(0)) {
            require(projects[assignment.projectId].status == ProjectStatus.Retired, AssertionAdopterAlreadyAssigned());
        }
        require(assignment.pendingProjectId == bytes32(0), PendingAssignmentExists());
        require(adminVerifiers.isRegistered(adminVerifier), AdminVerifierRegistry.AdminVerifierNotRegistered());
        require(adminVerifier.verifyAdmin(assertionAdopter, msg.sender, data), UnauthorizedRegistrant());
        assignment.pendingProjectId = projectId;
        emit AssertionAdopterRegistrationRequested(assertionAdopter, projectId, adminVerifier);
    }

    function cancelAssertionAdopterRegistration(
        address assertionAdopter,
        IAdminVerifier adminVerifier,
        bytes calldata data
    ) external {
        require(data.length <= MAX_ADMIN_DATA_LENGTH, DataTooLarge());
        AssertionAdopter storage assignment = assertionAdopters[assertionAdopter];
        bytes32 projectId = assignment.pendingProjectId;
        require(projectId != bytes32(0), NoPendingAssignment());
        require(adminVerifiers.isRegistered(adminVerifier), AdminVerifierRegistry.AdminVerifierNotRegistered());
        require(adminVerifier.verifyAdmin(assertionAdopter, msg.sender, data), UnauthorizedRegistrant());
        assignment.pendingProjectId = bytes32(0);
        emit AssertionAdopterRegistrationCancelled(assertionAdopter, projectId);
    }

    function rejectAssertionAdopterRegistration(address assertionAdopter) external {
        AssertionAdopter storage assignment = assertionAdopters[assertionAdopter];
        bytes32 projectId = assignment.pendingProjectId;
        require(projectId != bytes32(0), NoPendingAssignment());
        Project storage project = projects[projectId];
        require(
            project.status == ProjectStatus.Retired || msg.sender == project.protocolManager,
            UnauthorizedProtocolManager()
        );
        assignment.pendingProjectId = bytes32(0);
        emit AssertionAdopterRegistrationRejected(assertionAdopter, projectId);
    }

    function acceptAssertionAdopter(address assertionAdopter) external whenNotPaused {
        AssertionAdopter storage assignment = assertionAdopters[assertionAdopter];
        bytes32 projectId = assignment.pendingProjectId;
        require(projectId != bytes32(0), NoPendingAssignment());
        Project storage project = _activeProject(projectId);
        require(msg.sender == project.protocolManager, UnauthorizedProtocolManager());
        if (assignment.projectId != bytes32(0)) {
            require(projects[assignment.projectId].status == ProjectStatus.Retired, AssertionAdopterAlreadyAssigned());
        }
        assignment.projectId = projectId;
        assignment.pendingProjectId = bytes32(0);
        emit AssertionAdopterAdded(assertionAdopter, projectId);
    }

    function detachAssertionAdopter(address assertionAdopter) external {
        AssertionAdopter storage assignment = assertionAdopters[assertionAdopter];
        bytes32 projectId = assignment.projectId;
        require(projectId != bytes32(0), AssertionAdopterNotAssigned());
        Project storage project = _activeProject(projectId);
        require(msg.sender == project.protocolManager, UnauthorizedProtocolManager());
        require(assignment.assertionCount == 0, AssertionAdopterHasAssertions());
        assignment.projectId = bytes32(0);
        emit AssertionAdopterDetached(assertionAdopter, projectId);
    }

    function addAssertion(address assertionAdopter, AssertionArtifact calldata artifact, DAProof calldata daProof)
        external
        whenNotPaused
    {
        bytes32 projectId = _projectManagedBy(assertionAdopter, msg.sender);
        _addAssertion(projectId, assertionAdopter, artifact, daProof);
    }

    function removeAssertion(address assertionAdopter, bytes32 assertionId) external {
        bytes32 projectId = _projectManagedBy(assertionAdopter, msg.sender);
        _removeAssertion(projectId, assertionAdopter, assertionId);
    }

    function removeAssertionByGuardian(address assertionAdopter, bytes32 assertionId) external onlyGuardian {
        bytes32 projectId = assertionAdopters[assertionAdopter].projectId;
        require(projectId != bytes32(0), AssertionAdopterNotAssigned());
        _removeAssertion(projectId, assertionAdopter, assertionId);
    }

    function resetStorage(address assertionAdopter, bytes32 storageKey) external whenNotPaused {
        _projectManagedBy(assertionAdopter, msg.sender);
        ExecutorEventGuard.consume(ExecutorEventGuard.StoreType.StorageReset);
        emit StorageReset(assertionAdopter, storageKey, _effectiveBlock());
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

    function hasAssertion(address assertionAdopter, bytes32 assertionId) external view returns (bool) {
        return assertions[assertionAdopter][assertionId].enabled;
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

    function _projectManagedBy(address assertionAdopter, address account) private view returns (bytes32 projectId) {
        projectId = assertionAdopters[assertionAdopter].projectId;
        require(projectId != bytes32(0), AssertionAdopterNotAssigned());
        Project storage project = _activeProject(projectId);
        require(project.protocolManager == account, UnauthorizedProtocolManager());
    }

    function _addAssertion(
        bytes32 projectId,
        address assertionAdopter,
        AssertionArtifact calldata artifact,
        DAProof calldata daProof
    ) private {
        bytes32 assertionId = artifact.deploymentCodeHash;
        require(assertionId != bytes32(0), InvalidAssertionId());
        AssertionInstallation storage installation = assertions[assertionAdopter][assertionId];
        require(!installation.enabled, AssertionAlreadyExists());
        require(block.number >= installation.nextAddAllowedFromBlock, AssertionAddNotYetAllowed());
        require(
            artifact.triggerManifest.data.length <= MAX_MANIFEST_DATA_LENGTH
                && artifact.triggerManifest.proof.length <= MAX_MANIFEST_PROOF_LENGTH
                && daProof.metadata.length <= MAX_DA_METADATA_LENGTH && daProof.proof.length <= MAX_DA_PROOF_LENGTH,
            DataTooLarge()
        );

        ITriggerManifestValidator validator = triggerManifestValidators[artifact.triggerManifest.schemaId];
        require(address(validator) != address(0), TriggerManifestValidatorNotRegistered());
        (, uint64 triggerUnits) = validator.validate(
            assertionId,
            artifact.triggerManifest.schemaId,
            artifact.triggerManifest.data,
            artifact.triggerManifest.proof
        );
        require(triggerUnits != 0, InvalidTriggerUnits());

        Project storage project = _activeProject(projectId);
        uint64 newUsage = project.usedTriggerUnits + triggerUnits;
        require(newUsage <= project.triggerLimit, TriggerLimitExceeded());
        require(daVerifiers.isRegistered(daProof.verifier), DAVerifierNotRegistered());
        require(
            daProof.verifier.verifyDA(assertionId, daProof.metadata, daProof.proof), InvalidDAProof(daProof.verifier)
        );

        ExecutorEventGuard.consume(ExecutorEventGuard.StoreType.AssertionLifecycle);
        bytes32 manifestHash = keccak256(artifact.triggerManifest.data);
        assertions[assertionAdopter][assertionId] = AssertionInstallation({
            triggerUnits: triggerUnits,
            nextAddAllowedFromBlock: 0,
            manifestSchemaId: artifact.triggerManifest.schemaId,
            manifestHash: manifestHash,
            enabled: true
        });
        assertionAdopters[assertionAdopter].assertionCount++;
        project.usedTriggerUnits = newUsage;

        _emitAssertionAdded(projectId, assertionAdopter, _effectiveBlock(), triggerUnits, artifact, daProof);
    }

    function _removeAssertion(bytes32 projectId, address assertionAdopter, bytes32 assertionId) private {
        AssertionInstallation storage installation = assertions[assertionAdopter][assertionId];
        require(installation.enabled, AssertionDoesNotExist());
        ExecutorEventGuard.consume(ExecutorEventGuard.StoreType.AssertionLifecycle);

        installation.enabled = false;
        uint64 deactivationBlock = _effectiveBlock();
        installation.nextAddAllowedFromBlock = deactivationBlock;
        assertionAdopters[assertionAdopter].assertionCount--;
        projects[projectId].usedTriggerUnits -= installation.triggerUnits;
        emit AssertionRemoved(projectId, assertionAdopter, assertionId, deactivationBlock, installation.triggerUnits);
    }

    function _effectiveBlock() private view returns (uint64 effectiveBlock) {
        uint256 effectiveBlock256 = block.number + ASSERTION_TIMELOCK_BLOCKS;
        require(effectiveBlock256 <= type(uint64).max, EffectiveBlockOverflow());
        // The explicit bound above makes this cast lossless.
        // forge-lint: disable-next-line(unsafe-typecast)
        effectiveBlock = uint64(effectiveBlock256);
    }

    function _emitAssertionAdded(
        bytes32 projectId,
        address assertionAdopter,
        uint256 activationBlock,
        uint64 triggerUnits,
        AssertionArtifact calldata artifact,
        DAProof calldata daProof
    ) private {
        emit AssertionAdded(
            projectId,
            assertionAdopter,
            artifact.deploymentCodeHash,
            activationBlock,
            triggerUnits,
            artifact.triggerManifest.schemaId,
            artifact.triggerManifest.data,
            daProof.verifier,
            daProof.metadata,
            daProof.proof
        );
    }

    function _setTriggerManifestValidator(bytes32 schemaId, ITriggerManifestValidator validator) private {
        require(schemaId != bytes32(0) && address(validator) != address(0), InvalidTriggerManifestValidator());
        ITriggerManifestValidator oldValidator = triggerManifestValidators[schemaId];
        require(oldValidator != validator, TriggerManifestValidatorUnchanged());
        triggerManifestValidators[schemaId] = validator;
        emit TriggerManifestValidatorUpdated(schemaId, oldValidator, validator);
    }
}
