// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Test} from "forge-std/Test.sol";

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

abstract contract StateOracleV2TestBase is Test, ProxyHelper {
    address internal constant ORACLE_ADMIN = address(0xA11CE);
    address internal constant PROTOCOL_MANAGER = address(0xB0B);
    address internal constant ADOPTER_ADMIN = address(0xCAFE);
    bytes32 internal constant PROJECT_ID = keccak256("project");
    uint256 internal constant TIMELOCK = 10;
    uint256 internal constant MANIFEST_ATTESTOR_KEY = 0xA11E57;

    StateOracleV2 internal oracle;
    IAdminVerifier internal adminVerifier;
    IDAVerifier internal daVerifier;
    TriggerManifestValidatorV1 internal manifestValidator;

    function setUp() public virtual {
        StateOracleV2 implementation = new StateOracleV2(TIMELOCK);
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        daVerifier = IDAVerifier(new DAVerifierMock());
        manifestValidator = new TriggerManifestValidatorV1(ORACLE_ADMIN, vm.addr(MANIFEST_ATTESTOR_KEY));

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
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(MANIFEST_ATTESTOR_KEY, manifestValidator.attestationDigest(assertionId, manifestData));
        return StateOracleV2.AssertionArtifact({
            deploymentCodeHash: assertionId,
            triggerManifest: StateOracleV2.TriggerManifest({
                schemaId: manifestValidator.SCHEMA_ID(), data: manifestData, proof: abi.encodePacked(r, s, v)
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

        vm.prank(ORACLE_ADMIN);
        oracle.retireProject(PROJECT_ID);

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

        bytes32[6] memory roles = [
            oracle.DEFAULT_ADMIN_ROLE(),
            oracle.GOVERNANCE_ROLE(),
            oracle.GUARDIAN_ADMIN_ROLE(),
            oracle.GUARDIAN_ROLE(),
            oracle.PROJECT_CREATOR_ROLE(),
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
    address internal constant GOVERNANCE = address(0x600E);

    function setUp() public override {
        super.setUp();
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.GOVERNANCE_ROLE(), GOVERNANCE);
        vm.stopPrank();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
    }

    function test_guardianRevocationPreservesProjectStateAndGovernanceRecoversManager() public {
        _setLimit(PROJECT_ID, 2);
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        bytes32 assertionId = bytes32(uint256(1));
        _addAssertion(assertionAdopter, assertionId);

        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProtocolManagerTransfer(PROJECT_ID, MALICIOUS_PENDING_MANAGER);

        vm.expectRevert(StateOracleV2.ProtocolManagerNotCleared.selector);
        vm.prank(GOVERNANCE);
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
        vm.prank(GOVERNANCE);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, address(0));

        vm.expectEmit(true, true, true, true, address(oracle));
        emit StateOracleV2.ProtocolManagerTransferRequested(PROJECT_ID, address(0), REPLACEMENT_MANAGER);
        vm.prank(GOVERNANCE);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.expectRevert(StateOracleV2.ProtocolManagerNotCleared.selector);
        vm.prank(GOVERNANCE);
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

    function test_guardianCanClearGovernanceNominatedReplacement() public {
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);
        vm.prank(GOVERNANCE);
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
        vm.prank(GOVERNANCE);
        oracle.proposeProtocolManagerReplacement(nonexistentProjectId, REPLACEMENT_MANAGER);

        vm.prank(ORACLE_ADMIN);
        oracle.retireProject(PROJECT_ID);

        vm.expectRevert(StateOracleV2.ProjectNotActive.selector);
        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);
        vm.expectRevert(StateOracleV2.ProjectNotActive.selector);
        vm.prank(GOVERNANCE);
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

        vm.prank(ORACLE_ADMIN);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(projectCreator);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);
    }

    function test_guardianAndGovernanceRecoveryRolesAreSeparated() public {
        bytes32 guardianRole = oracle.GUARDIAN_ROLE();
        bytes32 governanceRole = oracle.GOVERNANCE_ROLE();

        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(PROJECT_ID);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, GUARDIAN, governanceRole)
        );
        vm.prank(GUARDIAN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);

        vm.prank(GOVERNANCE);
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
        vm.prank(GOVERNANCE);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, REPLACEMENT_MANAGER);
        vm.prank(REPLACEMENT_MANAGER);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        (address manager, address pendingManager,,,,) = oracle.projects(PROJECT_ID);
        assertEq(manager, REPLACEMENT_MANAGER);
        assertEq(pendingManager, address(0));
        assertTrue(oracle.paused());
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

        vm.prank(ORACLE_ADMIN);
        oracle.retireProject(PROJECT_ID);

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

    function test_zeroTriggerLimitBlocksFirstAssertion() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        StateOracleV2.AssertionArtifact memory artifact = _artifact(bytes32(uint256(1)));

        vm.prank(PROTOCOL_MANAGER);
        vm.expectRevert(StateOracleV2.TriggerLimitExceeded.selector);
        oracle.addAssertion(
            assertionAdopter, artifact, StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""})
        );
    }

    function test_retiredAssociationCanBeReplaced() public {
        address assertionAdopter = _assignAdopter(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.retireProject(PROJECT_ID);
        bytes32 otherProject = keccak256("other");
        _createProject(otherProject, PROTOCOL_MANAGER);

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
    }
}

contract StateOracleV2ExecutorEventGuardTest is StateOracleV2TestBase {
    bytes32 internal constant FIRST_ASSERTION_ID = bytes32(uint256(1));
    bytes32 internal constant SECOND_ASSERTION_ID = bytes32(uint256(2));

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
            testSelector == this.test_batchCannotRemoveTwoAssertions.selector
                || testSelector == this.test_separateLifecycleTransactionsInSameBlockSucceed.selector
        ) {
            calls = new bytes[](2);
            calls[0] = abi.encodeCall(this.setupAddFirstAssertion, ());
            calls[1] = abi.encodeCall(this.setupAddSecondAssertion, ());
        } else if (testSelector == this.test_batchCannotAddAndRemoveAssertions.selector) {
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

    function test_batchCannotAddTwoAssertions() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(FIRST_ASSERTION_ID);
        calls[1] = _addAssertionCall(SECOND_ASSERTION_ID);

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.AssertionLifecycle));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertFalse(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertFalse(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 0);
    }

    function test_batchCannotRemoveTwoAssertions() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, FIRST_ASSERTION_ID));
        calls[1] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, SECOND_ASSERTION_ID));

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.AssertionLifecycle));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertTrue(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 2);
    }

    function test_batchCannotAddAndRemoveAssertions() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(SECOND_ASSERTION_ID);
        calls[1] = abi.encodeCall(StateOracleV2.removeAssertion, (assertionAdopter, FIRST_ASSERTION_ID));

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.AssertionLifecycle));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);

        assertTrue(oracle.hasAssertion(assertionAdopter, FIRST_ASSERTION_ID));
        assertFalse(oracle.hasAssertion(assertionAdopter, SECOND_ASSERTION_ID));
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_batchCannotResetTwoStorageKeys() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, bytes32(uint256(1))));
        calls[1] = abi.encodeCall(StateOracleV2.resetStorage, (assertionAdopter, bytes32(uint256(2))));

        vm.expectRevert(_batchGuardRevert(ExecutorEventGuard.StoreType.StorageReset));
        vm.prank(PROTOCOL_MANAGER);
        oracle.batch(calls);
    }

    function test_batchAllowsOneLifecycleEventAndOneStorageReset() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = _addAssertionCall(FIRST_ASSERTION_ID);
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

    function _addAssertionCall(bytes32 assertionId) private view returns (bytes memory) {
        return abi.encodeCall(
            StateOracleV2.addAssertion,
            (
                assertionAdopter,
                _artifact(assertionId),
                StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""})
            )
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
        }
    }

    function setupSetAllCallsWeight(uint32 weight) external {
        vm.prank(ORACLE_ADMIN);
        manifestValidator.setTriggerWeight(TriggerManifestValidatorV1.TriggerKind.AllCalls, weight);
    }

    function setupAddAssertion(bytes32 assertionId) external {
        _addAssertion(assertionAdopter, assertionId);
    }

    function setupRemoveAssertion(bytes32 assertionId) external {
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(assertionAdopter, assertionId);
    }

    function test_removalReleasesStoredUnits() public {
        uint256 expectedNextAddAllowedFromBlock = block.number + TIMELOCK;
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(assertionAdopter, ASSERTION_ID);
        assertFalse(oracle.hasAssertion(assertionAdopter, ASSERTION_ID));
        (, uint64 nextAddAllowedFromBlock,,,) = oracle.assertions(assertionAdopter, ASSERTION_ID);
        assertEq(nextAddAllowedFromBlock, expectedNextAddAllowedFromBlock);
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 0);
    }

    function test_cannotReaddBeforePriorDeactivation() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(assertionAdopter, ASSERTION_ID);

        StateOracleV2.AssertionArtifact memory artifact = _artifact(ASSERTION_ID);
        StateOracleV2.DAProof memory proof = StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""});
        vm.prank(PROTOCOL_MANAGER);
        vm.expectRevert(StateOracleV2.AssertionAddNotYetAllowed.selector);
        oracle.addAssertion(assertionAdopter, artifact, proof);
    }

    function test_weightChangesOnlyAffectNewInstallations() public view {
        (uint64 originalTriggerUnits,,,, bool originalEnabled) = oracle.assertions(assertionAdopter, ASSERTION_ID);
        (uint64 newTriggerUnits,,,, bool newEnabled) = oracle.assertions(assertionAdopter, bytes32(uint256(2)));
        assertEq(originalTriggerUnits, 1);
        assertFalse(originalEnabled);
        assertEq(newTriggerUnits, 4);
        assertTrue(newEnabled);
        (, uint64 used) = _usage(PROJECT_ID);
        assertEq(used, 4);
    }

    function test_guardianCanRemoveWhilePausedThenRetire() public {
        vm.prank(ORACLE_ADMIN);
        oracle.pause();
        vm.prank(ORACLE_ADMIN);
        oracle.removeAssertionByGuardian(assertionAdopter, ASSERTION_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.retireProject(PROJECT_ID);
        (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
    }
}
