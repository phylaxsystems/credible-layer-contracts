// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {Batch} from "../src/Batch.sol";
import {StateOracleV2} from "../src/StateOracleV2.sol";
import {StateOracleV2AccessControl} from "../src/StateOracleV2AccessControl.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {ITriggerManifestValidator} from "../src/interfaces/ITriggerManifestValidator.sol";
import {ExecutorEventGuard} from "../src/lib/ExecutorEventGuard.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {TriggerManifestValidatorV1} from "../src/verification/TriggerManifestValidatorV1.sol";
import {OwnableAdopter} from "./utils/Adopter.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";
import {ProxyHelper} from "./utils/ProxyHelper.t.sol";

contract ReentrantDAVerifierMock {
    StateOracleV2 private immutable ORACLE;
    address private immutable ASSERTION_ADOPTER;
    bytes32 private immutable MANIFEST_SCHEMA_ID;
    IDAVerifier private immutable INNER_DA_VERIFIER;
    bytes32 private immutable INNER_ASSERTION_ID;
    bytes private manifestData;

    constructor(
        StateOracleV2 oracle,
        address assertionAdopter,
        bytes32 manifestSchemaId,
        bytes memory manifestData_,
        IDAVerifier innerDAVerifier,
        bytes32 innerAssertionId
    ) {
        ORACLE = oracle;
        ASSERTION_ADOPTER = assertionAdopter;
        MANIFEST_SCHEMA_ID = manifestSchemaId;
        manifestData = manifestData_;
        INNER_DA_VERIFIER = innerDAVerifier;
        INNER_ASSERTION_ID = innerAssertionId;
    }

    function verifyDA(bytes32, bytes calldata, bytes calldata) external returns (bool) {
        StateOracleV2.AssertionArtifact memory artifact = StateOracleV2.AssertionArtifact({
            deploymentCodeHash: INNER_ASSERTION_ID,
            triggerManifest: StateOracleV2.TriggerManifest({schemaId: MANIFEST_SCHEMA_ID, data: manifestData})
        });
        ORACLE.addAssertion(
            ASSERTION_ADOPTER, artifact, StateOracleV2.DAProof({verifier: INNER_DA_VERIFIER, metadata: "", proof: ""})
        );
        return true;
    }
}

abstract contract StateOracleV2TestBase is Test, ProxyHelper {
    address internal constant ORACLE_ADMIN = address(0xA11CE);
    address internal constant PROTOCOL_MANAGER = address(0xB0B);
    address internal constant ADOPTER_ADMIN = address(0xCAFE);
    bytes32 internal constant PROJECT_ID = keccak256("project");
    uint256 internal constant TIMELOCK = 10;

    StateOracleV2 internal oracle;
    IAdminVerifier internal adminVerifier;
    IDAVerifier internal daVerifier;
    TriggerManifestValidatorV1 internal manifestValidator;

    function setUp() public virtual {
        StateOracleV2 implementation = new StateOracleV2(TIMELOCK);
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        daVerifier = IDAVerifier(new DAVerifierMock());
        manifestValidator = new TriggerManifestValidatorV1(ORACLE_ADMIN);

        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](1);
        adminVerifiers[0] = adminVerifier;
        IDAVerifier[] memory daVerifiers = new IDAVerifier[](1);
        daVerifiers[0] = daVerifier;
        bytes memory data = abi.encodeCall(
            StateOracleV2.initialize,
            (
                ORACLE_ADMIN,
                adminVerifiers,
                daVerifiers,
                manifestValidator.SCHEMA_ID(),
                ITriggerManifestValidator(address(manifestValidator))
            )
        );
        oracle = StateOracleV2(deployProxy(address(implementation), data));
    }

    function _createProject(bytes32 projectId, address manager) internal {
        vm.prank(ORACLE_ADMIN);
        oracle.createProject(projectId, manager);
    }

    function _setLimit(bytes32 projectId, uint64 limit) internal {
        vm.prank(ORACLE_ADMIN);
        oracle.setProjectTriggerLimit(projectId, limit);
    }

    function _assignAdopter(bytes32 projectId) internal returns (address assertionAdopter) {
        assertionAdopter = address(new OwnableAdopter(ADOPTER_ADMIN));
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(assertionAdopter, projectId, adminVerifier, "");
        vm.prank(PROTOCOL_MANAGER);
        oracle.acceptAssertionAdopter(assertionAdopter);
    }

    function _addAssertion(address assertionAdopter, bytes32 assertionId) internal {
        StateOracleV2.AssertionArtifact memory artifact = _artifact(assertionId);
        StateOracleV2.DAProof memory proof = StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""});
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(assertionAdopter, artifact, proof);
    }

    function _artifact(bytes32 assertionId) internal view returns (StateOracleV2.AssertionArtifact memory) {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = TriggerManifestValidatorV1.TriggerV1({
            kind: TriggerManifestValidatorV1.TriggerKind.AllCalls,
            assertionFunction: bytes4(keccak256("assertion()")),
            triggerSelector: bytes4(0),
            storageSlot: bytes32(0),
            target: address(0),
            thresholdBps: 0,
            windowDuration: 0
        });
        bytes memory manifestData =
            abi.encode(TriggerManifestValidatorV1.AssertionManifestV1({version: 1, triggers: triggers}));
        return StateOracleV2.AssertionArtifact({
            deploymentCodeHash: assertionId,
            triggerManifest: StateOracleV2.TriggerManifest({
                schemaId: manifestValidator.SCHEMA_ID(), data: manifestData
            })
        });
    }

    function _usage(bytes32 projectId) internal view returns (uint64 limit, uint64 used) {
        (,, limit, used,,) = oracle.projects(projectId);
    }
}

contract StateOracleV2ProjectTest is StateOracleV2TestBase {
    function test_constructorRejectsInvalidTimelock() public {
        vm.expectRevert(StateOracleV2.InvalidAssertionTimelock.selector);
        new StateOracleV2(0);

        vm.roll(1);
        vm.expectRevert(StateOracleV2.InvalidAssertionTimelock.selector);
        new StateOracleV2(type(uint64).max);
    }

    function test_projectCanBeCreatedImmediatelyAndStartsAtZeroLimit() public {
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);

        (address manager,, uint64 limit,,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(manager, PROTOCOL_MANAGER);
        assertEq(limit, 0);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Active));
    }

    function test_rolesForCreationAndLimitsAreDistinct() public {
        address projectCreator = address(0x1234);
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.PROJECT_CREATOR_ROLE(), projectCreator);
        oracle.revokeRole(oracle.PROJECT_CREATOR_ROLE(), ORACLE_ADMIN);
        vm.stopPrank();

        vm.prank(projectCreator);
        oracle.createProject(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(projectCreator);
        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        oracle.setProjectTriggerLimit(PROJECT_ID, 1);
    }

    function test_protocolManagerTransferIsTwoStep() public {
        address newManager = address(0xD00D);
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);

        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProtocolManagerTransfer(PROJECT_ID, newManager);
        vm.prank(newManager);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        (address manager,,,,,) = oracle.projects(PROJECT_ID);
        assertEq(manager, newManager);
    }

    function test_retirementKeepsTombstoneAndIdCannotBeReused() public {
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);

        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        (address manager,,,, uint64 retiredAtBlock, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(manager, address(0));
        assertEq(retiredAtBlock, block.number);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
        vm.prank(ORACLE_ADMIN);
        vm.expectRevert(StateOracleV2.ProjectAlreadyExists.selector);
        oracle.createProject(PROJECT_ID, PROTOCOL_MANAGER);
    }

    function test_governancePauseBlocksAdditiveActions() public {
        vm.prank(ORACLE_ADMIN);
        oracle.pause();
        vm.prank(ORACLE_ADMIN);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        oracle.createProject(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(ORACLE_ADMIN);
        oracle.unpause();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
    }

    function test_resetStorageIsBlockedWhilePaused() public {
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.resetStorage(assertionAdopter, bytes32(uint256(1)));
    }

    function test_effectiveBlockMustFitUint64() public {
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        vm.roll(type(uint64).max - TIMELOCK + 1);

        vm.expectRevert(StateOracleV2.EffectiveBlockOverflow.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.resetStorage(assertionAdopter, bytes32(uint256(1)));
    }

    function test_ownerAndDefaultAdminRemainCoupled() public {
        assertEq(oracle.owner(), ORACLE_ADMIN);
        bytes32 defaultAdminRole = oracle.DEFAULT_ADMIN_ROLE();
        assertTrue(oracle.hasRole(defaultAdminRole, ORACLE_ADMIN));
        vm.prank(ORACLE_ADMIN);
        vm.expectRevert(StateOracleV2AccessControl.CannotGrantDefaultAdminRole.selector);
        oracle.grantRole(defaultAdminRole, address(1));
    }

    function test_ownershipAcceptanceMovesEveryInitialRole() public {
        address newOwner = address(0xBEEF);
        vm.prank(ORACLE_ADMIN);
        oracle.transferOwnership(newOwner);
        vm.prank(newOwner);
        oracle.acceptOwnership();

        bytes32[7] memory roles = [
            oracle.DEFAULT_ADMIN_ROLE(),
            oracle.GOVERNANCE_ROLE(),
            oracle.GUARDIAN_ADMIN_ROLE(),
            oracle.GUARDIAN_ROLE(),
            oracle.PROJECT_CREATOR_ROLE(),
            oracle.PROJECT_ADMIN_ROLE(),
            oracle.TRIGGER_LIMIT_ROLE()
        ];
        assertEq(oracle.owner(), newOwner);
        for (uint256 i; i < roles.length; ++i) {
            assertFalse(oracle.hasRole(roles[i], ORACLE_ADMIN));
            assertTrue(oracle.hasRole(roles[i], newOwner));
        }
    }
}

contract StateOracleV2ProtocolManagerRecoveryTest is StateOracleV2TestBase {
    address internal constant MALICIOUS_PENDING_MANAGER = address(0xBAD);
    address internal constant REPLACEMENT_MANAGER = address(0xD00D);
    address internal constant OTHER_REPLACEMENT_MANAGER = address(0xBEEF);
    address internal constant GUARDIAN = address(0x600D);
    address internal constant PROJECT_ADMIN = address(0x600F);
    address internal constant GOVERNANCE = address(0x600E);

    function setUp() public override {
        super.setUp();
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), PROJECT_ADMIN);
        oracle.grantRole(oracle.GOVERNANCE_ROLE(), GOVERNANCE);
        vm.stopPrank();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
    }

    function test_guardianRevocationPreservesProjectStateAndProjectAdminRecoversManager() public {
        _setLimit(PROJECT_ID, 2);
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        bytes32 assertionId = bytes32(uint256(1));
        _addAssertion(assertionAdopter, assertionId);

        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProtocolManagerTransfer(PROJECT_ID, MALICIOUS_PENDING_MANAGER);

        vm.expectRevert(StateOracleV2.ProtocolManagerNotCleared.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProtocolManagerTransferred(PROJECT_ID, address(0));
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        (
            address manager,
            address pendingManager,
            uint64 limit,
            uint64 used,
            uint64 retiredAtBlock,
            StateOracleV2.ProjectStatus status
        ) = oracle.projects(PROJECT_ID);
        assertEq(manager, address(0));
        assertEq(pendingManager, address(0));
        assertEq(limit, 2);
        assertEq(used, 1);
        assertEq(retiredAtBlock, 0);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Active));

        (bytes32 assignedProject, bytes32 pendingProject, uint32 assertionCount) =
            oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, PROJECT_ID);
        assertEq(pendingProject, bytes32(0));
        assertEq(assertionCount, 1);
        assertTrue(oracle.hasAssertion(assertionAdopter, assertionId));

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.resetStorage(assertionAdopter, bytes32(uint256(1)));

        vm.expectRevert(StateOracleV2.InvalidProtocolManager.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, address(0));

        vm.expectEmit(true, true, true, true, address(oracle));
        emit StateOracleV2.ProtocolManagerTransferRequested(PROJECT_ID, address(0), REPLACEMENT_MANAGER);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectRevert(StateOracleV2.ProtocolManagerNotCleared.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, OTHER_REPLACEMENT_MANAGER);

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(OTHER_REPLACEMENT_MANAGER);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProtocolManagerTransferred(PROJECT_ID, REPLACEMENT_MANAGER);
        vm.prank(REPLACEMENT_MANAGER);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        vm.prank(REPLACEMENT_MANAGER);
        oracle.resetStorage(assertionAdopter, bytes32(uint256(1)));

        (manager, pendingManager,,,, status) = oracle.projects(PROJECT_ID);
        assertEq(manager, REPLACEMENT_MANAGER);
        assertEq(pendingManager, address(0));
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Active));
        assertTrue(oracle.hasAssertion(assertionAdopter, assertionId));
        (, used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_guardianCanClearProjectAdminNominatedReplacement() public {
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProtocolManagerTransferred(PROJECT_ID, address(0));
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        (address manager, address pendingManager,,,,) = oracle.projects(PROJECT_ID);
        assertEq(manager, address(0));
        assertEq(pendingManager, address(0));

        vm.expectRevert(StateOracleV2.ProtocolManagerAlreadyCleared.selector);
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);
    }

    function test_recoveryRejectsNonexistentAndRetiredProjects() public {
        bytes32 nonexistentProjectId = keccak256("nonexistent");

        vm.expectRevert(StateOracleV2.ProjectNotActive.selector);
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(nonexistentProjectId);
        vm.expectRevert(StateOracleV2.ProjectNotActive.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(nonexistentProjectId, REPLACEMENT_MANAGER);

        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.expectRevert(StateOracleV2.ProjectNotActive.selector);
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);
        vm.expectRevert(StateOracleV2.ProjectNotActive.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);
    }

    function test_projectCreatorCannotRecoverProtocolManager() public {
        address projectCreator = address(0xC0DE);
        bytes32 projectCreatorRole = oracle.PROJECT_CREATOR_ROLE();
        vm.prank(ORACLE_ADMIN);
        oracle.grantRole(projectCreatorRole, projectCreator);

        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(projectCreator);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(projectCreator);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);
    }

    function test_guardianProjectAdminAndGovernanceRolesAreSeparated() public {
        bytes32 guardianRole = oracle.GUARDIAN_ROLE();
        bytes32 projectAdminRole = oracle.PROJECT_ADMIN_ROLE();

        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, GUARDIAN, projectAdminRole)
        );
        vm.prank(GUARDIAN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, GOVERNANCE, projectAdminRole
            )
        );
        vm.prank(GOVERNANCE);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, GOVERNANCE, guardianRole)
        );
        vm.prank(GOVERNANCE);
        oracle.revokeProtocolManager(PROJECT_ID);
    }

    function test_recoveryWorksWhilePausedButNormalTransferAcceptanceDoesNot() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProtocolManagerTransfer(PROJECT_ID, REPLACEMENT_MANAGER);
        vm.prank(ORACLE_ADMIN);
        oracle.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(REPLACEMENT_MANAGER);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);
        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);
        vm.prank(REPLACEMENT_MANAGER);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        (address manager, address pendingManager,,,,) = oracle.projects(PROJECT_ID);
        assertEq(manager, REPLACEMENT_MANAGER);
        assertEq(pendingManager, address(0));
        assertTrue(oracle.paused());
    }
}

contract StateOracleV2ProjectRetirementTest is StateOracleV2TestBase {
    address internal constant GUARDIAN = address(0x600D);
    address internal constant PROJECT_ADMIN = address(0x600F);
    address internal constant GOVERNANCE = address(0x600E);
    address internal constant TRIGGER_LIMIT_ADMIN = address(0x6010);
    address internal constant REPLACEMENT_MANAGER = address(0xD00D);

    function setUp() public override {
        super.setUp();
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), PROJECT_ADMIN);
        oracle.grantRole(oracle.GOVERNANCE_ROLE(), GOVERNANCE);
        oracle.grantRole(oracle.TRIGGER_LIMIT_ROLE(), TRIGGER_LIMIT_ADMIN);
        vm.stopPrank();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
    }

    function test_retirementRequiresManagerRequestAndProjectAdminFinalization() public {
        vm.expectRevert(StateOracleV2.ProjectRetirementNotRequested.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProjectRetirementRequested(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(GUARDIAN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(GOVERNANCE);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.expectEmit(true, false, false, true, address(oracle));
        emit StateOracleV2.ProjectRetired(PROJECT_ID, uint64(block.number));
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        (
            address manager,
            address pendingManager,
            uint64 limit,
            uint64 used,
            uint64 retiredAtBlock,
            StateOracleV2.ProjectStatus status
        ) = oracle.projects(PROJECT_ID);
        assertEq(manager, address(0));
        assertEq(pendingManager, address(0));
        assertEq(limit, 0);
        assertEq(used, 0);
        assertEq(retiredAtBlock, block.number);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
        assertEq(oracle.projectRetirementRequesters(PROJECT_ID), address(0));
    }

    function test_requestAndCancelArePausedButFinalizationRemainsAvailable() public {
        vm.prank(GOVERNANCE);
        oracle.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.prank(GOVERNANCE);
        oracle.unpause();
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(GOVERNANCE);
        oracle.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.cancelProjectRetirement(PROJECT_ID);

        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
        (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
    }

    function test_managerCanCancelRetirementRequest() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.expectRevert(StateOracleV2.ProjectRetirementAlreadyRequested.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(REPLACEMENT_MANAGER);
        oracle.cancelProjectRetirement(PROJECT_ID);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProjectRetirementCancelled(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(PROTOCOL_MANAGER);
        oracle.cancelProjectRetirement(PROJECT_ID);

        assertEq(oracle.projectRetirementRequesters(PROJECT_ID), address(0));
        vm.expectRevert(StateOracleV2.ProjectRetirementNotRequested.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
    }

    function test_managerChangeInvalidatesStaleRetirementRequest() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProtocolManagerTransfer(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProjectRetirementCancelled(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(REPLACEMENT_MANAGER);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        assertEq(oracle.projectRetirementRequesters(PROJECT_ID), address(0));
        vm.expectRevert(StateOracleV2.ProjectRetirementNotRequested.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
    }

    function test_guardianQuarantineInvalidatesStaleRetirementRequest() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.expectEmit(true, true, false, true, address(oracle));
        emit StateOracleV2.ProjectRetirementCancelled(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        assertEq(oracle.projectRetirementRequesters(PROJECT_ID), address(0));
        vm.expectRevert(StateOracleV2.ProjectRetirementNotRequested.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
    }

    function test_projectAdminAndTriggerLimitAuthoritiesRemainSeparate() public {
        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.setProjectTriggerLimit(PROJECT_ID, 1);

        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(TRIGGER_LIMIT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);
        vm.prank(TRIGGER_LIMIT_ADMIN);
        oracle.setProjectTriggerLimit(PROJECT_ID, 1);

        (address manager, address pendingManager, uint64 limit,,,) = oracle.projects(PROJECT_ID);
        assertEq(manager, address(0));
        assertEq(pendingManager, REPLACEMENT_MANAGER);
        assertEq(limit, 1);
    }
}

contract StateOracleV2ProjectRetirementWithAssertionTest is StateOracleV2TestBase {
    address internal constant GUARDIAN = address(0x600D);
    address internal constant PROJECT_ADMIN = address(0x600F);
    address internal assertionAdopter;
    bytes32 internal constant ASSERTION_ID = bytes32(uint256(1));

    function setUp() public override {
        super.setUp();
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), PROJECT_ADMIN);
        vm.stopPrank();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 1);
        assertionAdopter = _assignAdopter(PROJECT_ID);
        _addAssertion(assertionAdopter, ASSERTION_ID);
    }

    function test_projectCannotRetireUntilEveryInstalledAssertionIsRemoved() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);

        vm.expectRevert(StateOracleV2.ProjectHasAssertions.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.prank(GUARDIAN);
        oracle.removeAssertionByGuardian(assertionAdopter, ASSERTION_ID);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        (bytes32 assignedProject,, uint32 assertionCount) = oracle.assertionAdopters(assertionAdopter);
        (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(assignedProject, PROJECT_ID);
        assertEq(assertionCount, 0);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
        assertFalse(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));
    }
}

contract StateOracleV2AssignmentTest is StateOracleV2TestBase {
    function setUp() public virtual override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
    }

    function test_registrationRequiresAdminThenManagerAcceptance() public {
        address assertionAdopter = address(new OwnableAdopter(ADOPTER_ADMIN));
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(assertionAdopter, PROJECT_ID, adminVerifier, "");
        (bytes32 assignedProject, bytes32 pendingProject,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, bytes32(0));
        assertEq(pendingProject, PROJECT_ID);

        vm.prank(PROTOCOL_MANAGER);
        oracle.acceptAssertionAdopter(assertionAdopter);
        (assignedProject, pendingProject,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, PROJECT_ID);
        assertEq(pendingProject, bytes32(0));
    }

    function test_anyoneCanRejectPendingRegistrationAfterProjectRetirement() public {
        address assertionAdopter = address(new OwnableAdopter(ADOPTER_ADMIN));
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(assertionAdopter, PROJECT_ID, adminVerifier, "");

        vm.prank(address(0xBAD));
        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        oracle.rejectAssertionAdopterRegistration(assertionAdopter);

        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        oracle.rejectAssertionAdopterRegistration(assertionAdopter);

        (, bytes32 pendingProject,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(pendingProject, bytes32(0));
    }

    function test_activeAssignmentCannotBeMovedByVerifiedAdmin() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        bytes32 otherProject = keccak256("other");
        _createProject(otherProject, PROTOCOL_MANAGER);

        vm.prank(ADOPTER_ADMIN);
        vm.expectRevert(StateOracleV2.AssertionAdopterAlreadyAssigned.selector);
        oracle.registerAssertionAdopter(assertionAdopter, otherProject, adminVerifier, "");
    }

    function test_protocolManagerCanDetachEmptyAdopter() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        vm.prank(PROTOCOL_MANAGER);
        oracle.detachAssertionAdopter(assertionAdopter);
        (bytes32 assignedProject,,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, bytes32(0));
    }

    function test_onlyProtocolManagerCanDetachEmptyAdopterFromActiveProject() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(ORACLE_ADMIN);
        oracle.detachAssertionAdopter(assertionAdopter);

        (bytes32 assignedProject,,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, PROJECT_ID);
    }

    function test_quarantinedAdopterWaitsForManagerRecoveryBeforeDetach() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        address guardian = address(0x600D);
        address projectAdmin = address(0x600F);
        address replacementManager = address(0xD00D);
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), guardian);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), projectAdmin);
        vm.stopPrank();

        vm.prank(guardian);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        oracle.detachAssertionAdopter(assertionAdopter);
        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(projectAdmin);
        oracle.detachAssertionAdopter(assertionAdopter);

        vm.prank(projectAdmin);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, replacementManager);
        vm.prank(replacementManager);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);
        vm.prank(replacementManager);
        oracle.detachAssertionAdopter(assertionAdopter);

        (bytes32 assignedProject,,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, bytes32(0));
    }

    function test_zeroTriggerLimitBlocksFirstAssertion() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        StateOracleV2.AssertionArtifact memory artifact = _artifact(bytes32(uint256(1)));

        vm.prank(PROTOCOL_MANAGER);
        vm.expectRevert(StateOracleV2.TriggerLimitExceeded.selector);
        oracle.addAssertion(
            assertionAdopter, artifact, StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""})
        );
    }

    function test_retiredAssociationMustBePermissionlesslyDetachedBeforeReassignment() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
        bytes32 otherProject = keccak256("other");
        _createProject(otherProject, PROTOCOL_MANAGER);

        vm.prank(ADOPTER_ADMIN);
        vm.expectRevert(StateOracleV2.AssertionAdopterAlreadyAssigned.selector);
        oracle.registerAssertionAdopter(assertionAdopter, otherProject, adminVerifier, "");

        vm.prank(address(0xBEEF));
        oracle.detachAssertionAdopter(assertionAdopter);
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(assertionAdopter, otherProject, adminVerifier, "");
        vm.prank(PROTOCOL_MANAGER);
        oracle.acceptAssertionAdopter(assertionAdopter);
        (bytes32 assignedProject,,) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, otherProject);
    }
}

contract StateOracleV2AssertionTest is StateOracleV2TestBase {
    address internal assertionAdopter;
    address internal secondAdopter;

    function setUp() public virtual override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 20);
        assertionAdopter = _assignAdopter(PROJECT_ID);
    }

    function beforeTestSetup(bytes4 testSelector) public view returns (bytes[] memory calls) {
        if (testSelector == this.test_sameAssertionOnTwoAdoptersConsumesUnitsTwice.selector) {
            calls = new bytes[](2);
            calls[0] = abi.encodeCall(this.setupAddAssertion, (bytes32(uint256(1))));
            calls[1] = abi.encodeCall(this.setupAssignSecondAdopterAndAddAssertion, (bytes32(uint256(1))));
        } else if (testSelector == this.test_sameManifestValidatesDifferentDeploymentCodeHashes.selector) {
            calls = new bytes[](1);
            calls[0] = abi.encodeCall(this.setupAddAssertion, (bytes32(uint256(1))));
        } else if (testSelector == this.test_noAssertionCountLimit.selector) {
            calls = new bytes[](10);
            for (uint256 i; i < calls.length; ++i) {
                calls[i] = abi.encodeCall(this.setupAddAssertion, (bytes32(i + 1)));
            }
        }
    }

    function setupAddAssertion(bytes32 assertionId) external {
        _addAssertion(assertionAdopter, assertionId);
    }

    function setupAssignSecondAdopterAndAddAssertion(bytes32 assertionId) external {
        secondAdopter = _assignAdopter(PROJECT_ID);
        _addAssertion(secondAdopter, assertionId);
    }

    function test_assertionIdIsDeploymentCodeHashAndUsageIsProjectScoped() public {
        bytes32 assertionId = keccak256("creation code");
        _addAssertion(assertionAdopter, assertionId);

        assertTrue(oracle.hasAssertion(assertionAdopter, assertionId));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_sameAssertionOnTwoAdoptersConsumesUnitsTwice() public view {
        assertTrue(oracle.hasAssertion(assertionAdopter, bytes32(uint256(1))));
        assertTrue(oracle.hasAssertion(secondAdopter, bytes32(uint256(1))));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 2);
    }

    function test_sameManifestValidatesDifferentDeploymentCodeHashes() public {
        bytes32 firstAssertionId = bytes32(uint256(1));
        bytes32 secondAssertionId = bytes32(uint256(2));

        _addAssertion(assertionAdopter, secondAssertionId);

        assertTrue(oracle.hasAssertion(assertionAdopter, firstAssertionId));
        assertTrue(oracle.hasAssertion(assertionAdopter, secondAssertionId));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 2);
    }

    function test_noAssertionCountLimit() public view {
        (,, uint32 count) = oracle.assertionAdopters(assertionAdopter);
        assertEq(count, 10);
    }

    function test_lowerLimitGrandfathersActiveAssertionsAndBlocksAdds() public {
        _addAssertion(assertionAdopter, bytes32(uint256(1)));
        _setLimit(PROJECT_ID, 0);
        assertTrue(oracle.hasAssertion(assertionAdopter, bytes32(uint256(1))));

        StateOracleV2.AssertionArtifact memory artifact = _artifact(bytes32(uint256(2)));
        vm.prank(PROTOCOL_MANAGER);
        vm.expectRevert(StateOracleV2.TriggerLimitExceeded.selector);
        oracle.addAssertion(
            assertionAdopter, artifact, StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""})
        );
    }

    function test_detachRequiresAssertionsRemoved() public {
        _addAssertion(assertionAdopter, bytes32(uint256(1)));
        vm.prank(PROTOCOL_MANAGER);
        vm.expectRevert(StateOracleV2.AssertionAdopterHasAssertions.selector);
        oracle.detachAssertionAdopter(assertionAdopter);

        (bytes32 assignedProject,, uint32 assertionCount) = oracle.assertionAdopters(assertionAdopter);
        assertEq(assignedProject, PROJECT_ID);
        assertEq(assertionCount, 1);
        assertTrue(oracle.hasAssertion(assertionAdopter, bytes32(uint256(1))));
    }
}

contract StateOracleV2TriggerAccountingInvariantTest is StateOracleV2TestBase {
    bytes32 internal constant SECOND_PROJECT_ID = keccak256("second project");
    bytes32 internal constant FIRST_ASSERTION_ID = bytes32(uint256(1));
    bytes32 internal constant SECOND_ASSERTION_ID = bytes32(uint256(2));

    address internal firstAdopter;
    address internal secondAdopter;

    function setUp() public override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _createProject(SECOND_PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 10);
        _setLimit(SECOND_PROJECT_ID, 10);
        firstAdopter = _assignAdopter(PROJECT_ID);
        secondAdopter = _assignAdopter(SECOND_PROJECT_ID);
    }

    function beforeTestSetup(bytes4 testSelector) public view returns (bytes[] memory calls) {
        if (
            testSelector == this.test_totalInstalledUnitsEqualSumOfProjectUsage.selector
                || testSelector == this.test_removalPreservesTriggerAccountingConservation.selector
        ) {
            calls = new bytes[](2);
            calls[0] = abi.encodeCall(this.setupAddAssertion, (firstAdopter, FIRST_ASSERTION_ID));
            calls[1] = abi.encodeCall(this.setupAddAssertion, (secondAdopter, SECOND_ASSERTION_ID));
        }
    }

    function setupAddAssertion(address adopter, bytes32 assertionId) external {
        _addAssertion(adopter, assertionId);
    }

    function test_totalInstalledUnitsEqualSumOfProjectUsage() public view {
        assertEq(_totalInstalledUnits(), _totalProjectUsage());
    }

    function test_removalPreservesTriggerAccountingConservation() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(firstAdopter, FIRST_ASSERTION_ID);

        assertEq(_totalInstalledUnits(), _totalProjectUsage());
        (, uint64 firstProjectUsed) = _usage(PROJECT_ID);
        (, uint64 secondProjectUsed) = _usage(SECOND_PROJECT_ID);
        assertEq(firstProjectUsed, 0);
        assertEq(secondProjectUsed, 1);
    }

    function _totalInstalledUnits() private view returns (uint256 total) {
        (uint64 firstUnits,,, bool firstEnabled) = oracle.assertions(firstAdopter, FIRST_ASSERTION_ID);
        (uint64 secondUnits,,, bool secondEnabled) = oracle.assertions(secondAdopter, SECOND_ASSERTION_ID);
        if (firstEnabled) total += firstUnits;
        if (secondEnabled) total += secondUnits;
    }

    function _totalProjectUsage() private view returns (uint256 total) {
        (, uint64 firstProjectUsed) = _usage(PROJECT_ID);
        (, uint64 secondProjectUsed) = _usage(SECOND_PROJECT_ID);
        return uint256(firstProjectUsed) + secondProjectUsed;
    }
}

contract StateOracleV2ExecutorEventGuardTest is StateOracleV2TestBase {
    bytes32 internal constant FIRST_ASSERTION_ID = bytes32(uint256(1));
    bytes32 internal constant SECOND_ASSERTION_ID = bytes32(uint256(2));
    bytes32 internal constant THIRD_ASSERTION_ID = bytes32(uint256(3));

    address internal assertionAdopter;
    uint256 internal firstSetupBlock;
    uint256 internal secondSetupBlock;

    function setUp() public override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 20);
        assertionAdopter = _assignAdopter(PROJECT_ID);
    }

    function beforeTestSetup(bytes4 testSelector) public view returns (bytes[] memory calls) {
        if (
            testSelector == this.test_batchAllowsRemovingDifferentAssertionsForSameAdopter.selector
                || testSelector == this.test_separateLifecycleTransactionsInSameBlockSucceed.selector
        ) {
            calls = new bytes[](2);
            calls[0] = abi.encodeCall(this.setupAddFirstAssertion, ());
            calls[1] = abi.encodeCall(this.setupAddSecondAssertion, ());
        } else if (
            testSelector == this.test_batchAllowsAddingAndRemovingDifferentAssertions.selector
                || testSelector == this.test_batchRejectsRemoveThenAddForSameAssertion.selector
        ) {
            calls = new bytes[](1);
            calls[0] = abi.encodeCall(this.setupAddFirstAssertion, ());
        }
    }

    function setupAddFirstAssertion() external {
        firstSetupBlock = block.number;
        _addAssertion(assertionAdopter, FIRST_ASSERTION_ID);
    }

    function setupAddSecondAssertion() external {
        secondSetupBlock = block.number;
        _addAssertion(assertionAdopter, SECOND_ASSERTION_ID);
    }

    function test_batchAllowsAddingDifferentAssertionsForSameAdopter() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(assertionAdopter, FIRST_ASSERTION_ID);
        calls[1] = _addAssertionCall(assertionAdopter, SECOND_ASSERTION_ID);

        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertTrue(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 2);
    }

    function test_batchAllowsRemovingDifferentAssertionsForSameAdopter() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, FIRST_ASSERTION_ID));
        calls[1] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, SECOND_ASSERTION_ID));

        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertFalse(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertFalse(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 0);
    }

    function test_batchAllowsAddingAndRemovingDifferentAssertions() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, FIRST_ASSERTION_ID));
        calls[1] = _addAssertionCall(assertionAdopter, SECOND_ASSERTION_ID);

        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertFalse(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertTrue(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_batchAllowsSameAssertionForDifferentAdopters() public {
        address secondAdopter = _assignAdopter(PROJECT_ID);
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(assertionAdopter, FIRST_ASSERTION_ID);
        calls[1] = _addAssertionCall(secondAdopter, FIRST_ASSERTION_ID);

        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertTrue(oracle.hasAssertion(secondAdopter, FIRST_ASSERTION_ID));
        (,, uint32 firstCount) = oracle.assertionAdopters(assertionAdopter);
        (,, uint32 secondCount) = oracle.assertionAdopters(secondAdopter);
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(firstCount, 1);
        assertEq(secondCount, 1);
        assertEq(used, 2);
    }

    function test_batchRejectsAddThenRemoveForSameAssertion() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(assertionAdopter, FIRST_ASSERTION_ID);
        calls[1] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, FIRST_ASSERTION_ID));

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.AssertionLifecycle));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertFalse(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 0);
    }

    function test_batchRejectsRemoveThenAddForSameAssertion() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, FIRST_ASSERTION_ID));
        calls[1] = _addAssertionCall(assertionAdopter, FIRST_ASSERTION_ID);

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.AssertionLifecycle));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_batchAccumulatesUsageAcrossThreeAdds() public {
        bytes[] memory calls = new bytes[](3);
        calls[0] = _addAssertionCall(assertionAdopter, FIRST_ASSERTION_ID);
        calls[1] = _addAssertionCall(assertionAdopter, SECOND_ASSERTION_ID);
        calls[2] = _addAssertionCall(assertionAdopter, THIRD_ASSERTION_ID);

        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        (,, uint32 count) = oracle.assertionAdopters(assertionAdopter);
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(count, 3);
        assertEq(used, 3);
    }

    function test_nonViewReentrantDAVerifierCannotDoubleSpendTriggerLimit() public {
        bytes32 projectId = keccak256("reentrant verifier project");
        address reentrantAdopter = address(new OwnableAdopter(ADOPTER_ADMIN));
        StateOracleV2.AssertionArtifact memory innerArtifact = _artifact(SECOND_ASSERTION_ID);
        ReentrantDAVerifierMock reentrantVerifier = new ReentrantDAVerifierMock(
            oracle,
            reentrantAdopter,
            manifestValidator.SCHEMA_ID(),
            innerArtifact.triggerManifest.data,
            daVerifier,
            SECOND_ASSERTION_ID
        );

        vm.prank(ORACLE_ADMIN);
        oracle.addDAVerifier(IDAVerifier(address(reentrantVerifier)));
        _createProject(projectId, address(reentrantVerifier));
        _setLimit(projectId, 1);
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(reentrantAdopter, projectId, adminVerifier, "");
        vm.prank(address(reentrantVerifier));
        oracle.acceptAssertionAdopter(reentrantAdopter);

        StateOracleV2.AssertionArtifact memory outerArtifact = _artifact(FIRST_ASSERTION_ID);
        StateOracleV2.DAProof memory outerProof =
            StateOracleV2.DAProof({verifier: IDAVerifier(address(reentrantVerifier)), metadata: "", proof: ""});
        bytes memory callData =
            abi.encodeCall(StateOracleV2.addAssertion, (reentrantAdopter, outerArtifact, outerProof));
        vm.prank(address(reentrantVerifier));
        (bool success,) = address(oracle).call{gas: 1_000_000}(callData);
        assertFalse(success);

        assertFalse(oracle.hasAssertion(reentrantAdopter, FIRST_ASSERTION_ID));
        assertFalse(oracle.hasAssertion(reentrantAdopter, SECOND_ASSERTION_ID));
        (,, uint32 count) = oracle.assertionAdopters(reentrantAdopter);
        (, uint64 used) = _usage(projectId);
        assertEq(count, 0);
        assertEq(used, 0);
    }

    function test_batchAllowsDifferentStorageKeysForSameAdopter() public {
        bytes32 firstKey = bytes32(uint256(1));
        bytes32 secondKey = bytes32(uint256(2));
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, firstKey));
        calls[1] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, secondKey));

        vm.recordLogs();
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(logs[0].topics[2], firstKey);
        assertEq(logs[1].topics[2], secondKey);
    }

    function test_batchAllowsSameStorageKeyForDifferentAdopters() public {
        address secondAdopter = _assignAdopter(PROJECT_ID);
        bytes32 storageKey = bytes32(uint256(1));
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, storageKey));
        calls[1] = abi.encodeCall(StateOracleV2.resetStorage, (secondAdopter, storageKey));

        vm.recordLogs();
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(address(uint160(uint256(logs[0].topics[1]))), assertionAdopter);
        assertEq(address(uint160(uint256(logs[1].topics[1]))), secondAdopter);
    }

    function test_batchRejectsDuplicateStorageReset() public {
        bytes32 storageKey = bytes32(uint256(1));
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, storageKey));
        calls[1] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, storageKey));

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.StorageReset));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);
    }

    function test_batchAllowsOneLifecycleEventAndOneStorageReset() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(assertionAdopter, FIRST_ASSERTION_ID);
        calls[1] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, bytes32(uint256(1))));

        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_separateLifecycleTransactionsInSameBlockSucceed() public view {
        assertEq(firstSetupBlock, secondSetupBlock);
        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertTrue(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 2);
    }

    function _addAssertionCall(address adopter, bytes32 assertionId) private view returns (bytes memory) {
        return abi.encodeCall(
            StateOracleV2.addAssertion,
            (adopter, _artifact(assertionId), StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""}))
        );
    }

    function _batchGuardRevert(ExecutorEventGuard.StoreType storeType) private pure returns (bytes memory) {
        bytes memory innerRevert =
            abi.encodeWithSelector(ExecutorEventGuard.ExecutorEventAlreadyEmitted.selector, storeType);
        return abi.encodeWithSelector(Batch.BatchError.selector, innerRevert);
    }
}

contract StateOracleV2InstalledAssertionTest is StateOracleV2TestBase {
    bytes32 internal constant ASSERTION_ID = bytes32(uint256(1));
    address internal assertionAdopter;
    uint256 internal removalSetupBlock;
    uint256 internal removalDeactivationBlock;

    function setUp() public override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 20);
        assertionAdopter = _assignAdopter(PROJECT_ID);
        _addAssertion(assertionAdopter, ASSERTION_ID);
    }

    function beforeTestSetup(bytes4 testSelector) public view returns (bytes[] memory calls) {
        if (testSelector == this.test_weightChangesOnlyAffectNewInstallations.selector) {
            calls = new bytes[](3);
            calls[0] = abi.encodeCall(this.setupSetAllCallsWeight, (4));
            calls[1] = abi.encodeCall(this.setupAddAssertion, (bytes32(uint256(2))));
            calls[2] = abi.encodeCall(this.setupRemoveAssertion, (ASSERTION_ID));
        } else if (testSelector == this.test_canAddSameAssertionAfterRemovalInNextTransaction.selector) {
            calls = new bytes[](1);
            calls[0] = abi.encodeCall(this.setupRemoveAssertion, (ASSERTION_ID));
        } else if (testSelector == this.test_sameBlockReaddSharesEffectiveBlockWithRemoval.selector) {
            calls = new bytes[](1);
            calls[0] = abi.encodeCall(this.setupRemoveAssertionRecordingDeactivation, ());
        }
    }

    function setupRemoveAssertionRecordingDeactivation() external {
        removalSetupBlock = block.number;
        vm.recordLogs();
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(assertionAdopter, ASSERTION_ID);
        removalDeactivationBlock = _effectiveBlockOf(vm.getRecordedLogs(), StateOracleV2.AssertionRemoved.selector);
    }

    function setupSetAllCallsWeight(uint32 weight) external {
        vm.prank(ORACLE_ADMIN);
        manifestValidator.setTriggerWeight(TriggerManifestValidatorV1.TriggerKind.AllCalls, weight);
    }

    function setupAddAssertion(bytes32 assertionId) external {
        _addAssertion(assertionAdopter, assertionId);
    }

    function setupRemoveAssertion(bytes32 assertionId) external {
        removalSetupBlock = block.number;
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(assertionAdopter, assertionId);
    }

    function test_removalReleasesStoredUnits() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(assertionAdopter, ASSERTION_ID);
        assertFalse(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 0);
    }

    function test_canAddSameAssertionAfterRemovalInNextTransaction() public {
        assertEq(block.number, removalSetupBlock);
        assertFalse(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));
        StateOracleV2.AssertionArtifact memory artifact = _artifact(ASSERTION_ID);
        StateOracleV2.DAProof memory proof = StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""});
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(assertionAdopter, artifact, proof);

        assertTrue(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_weightChangesOnlyAffectNewInstallations() public view {
        (uint64 originalTriggerUnits,,, bool originalEnabled) = oracle.assertions(assertionAdopter, ASSERTION_ID);
        (uint64 newTriggerUnits,,, bool newEnabled) = oracle.assertions(assertionAdopter, bytes32(uint256(2)));
        assertEq(originalTriggerUnits, 1);
        assertFalse(originalEnabled);
        assertEq(newTriggerUnits, 4);
        assertTrue(newEnabled);
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 4);
    }

    function test_guardianCanRemoveWhilePausedThenProjectAdminFinalizesRetirement() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.pause();
        vm.prank(ORACLE_ADMIN);
        oracle.removeAssertionByGuardian(assertionAdopter, ASSERTION_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);
        (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
    }

    /// @dev Removing and re-adding one assertion in the same block emits `AssertionRemoved` and
    /// `AssertionAdded` for the same key carrying an identical effective block, because both
    /// stamp `block.number + ASSERTION_TIMELOCK_BLOCKS`. Neither event carries an intra-block
    /// sequence number, so consumers MUST resolve the pair by log order; the on-chain state that
    /// log order reproduces is `enabled == true`. Changing this pins an executor requirement.
    function test_sameBlockReaddSharesEffectiveBlockWithRemoval() public {
        assertEq(block.number, removalSetupBlock);
        assertEq(removalDeactivationBlock, removalSetupBlock + TIMELOCK);
        assertFalse(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));

        StateOracleV2.AssertionArtifact memory artifact = _artifact(ASSERTION_ID);
        StateOracleV2.DAProof memory proof = StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""});
        vm.recordLogs();
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(assertionAdopter, artifact, proof);
        uint256 activationBlock = _effectiveBlockOf(vm.getRecordedLogs(), StateOracleV2.AssertionAdded.selector);

        assertEq(activationBlock, removalDeactivationBlock);
        assertTrue(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));
    }

    /// @dev Reads the first non-indexed field of the newest matching lifecycle event, which is
    /// `activationBlock` for `AssertionAdded` and `deactivationBlock` for `AssertionRemoved`.
    function _effectiveBlockOf(Vm.Log[] memory logs, bytes32 eventSelector) private pure returns (uint256) {
        for (uint256 i = logs.length; i != 0; --i) {
            Vm.Log memory log = logs[i - 1];
            if (log.topics.length != 0 && log.topics[0] == eventSelector) {
                return abi.decode(log.data, (uint256));
            }
        }
        revert("lifecycle event not found");
    }
}
