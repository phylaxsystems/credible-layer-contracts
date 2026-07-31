// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Test} from "forge-std/Test.sol";

import {StateOracleV2} from "../src/StateOracleV2.sol";
import {StateOracleV2AccessControl} from "../src/StateOracleV2AccessControl.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {ITriggerManifestValidator} from "../src/interfaces/ITriggerManifestValidator.sol";
import {AdminVerifierRegistry} from "../src/lib/AdminVerifierRegistry.sol";
import {DAVerifierRegistry} from "../src/lib/DAVerifierRegistry.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {OwnableAdopter} from "./utils/Adopter.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";

contract UnitManifestValidator is ITriggerManifestValidator {
    function validate(bytes32, bytes calldata data) external pure returns (uint32 triggerCount, uint64 triggerUnits) {
        triggerCount = 1;
        triggerUnits = data.length == 32 ? abi.decode(data, (uint64)) : 1;
    }
}

contract ZeroUnitManifestValidator is ITriggerManifestValidator {
    function validate(bytes32, bytes calldata) external pure returns (uint32, uint64) {
        return (1, 0);
    }
}

contract RejectingDAVerifier is IDAVerifier {
    function verifyDA(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return false;
    }
}

abstract contract StateOracleV2FuzzBase is Test {
    address internal constant ORACLE_ADMIN = address(0xA11CE);
    address internal constant PROXY_ADMIN_OWNER = address(0xA11CF);
    address internal constant PROTOCOL_MANAGER = address(0xB0B);
    address internal constant ADOPTER_ADMIN = address(0xCAFE);
    bytes32 internal constant PROJECT_ID = keccak256("fuzz-project");
    bytes32 internal constant SCHEMA_ID = keccak256("test.trigger-manifest.units");
    uint256 internal constant TIMELOCK = 10;

    StateOracleV2 internal oracle;
    IAdminVerifier internal adminVerifier;
    IDAVerifier internal daVerifier;
    ITriggerManifestValidator internal manifestValidator;
    address internal transparentProxyAdmin;

    function setUp() public virtual {
        StateOracleV2 implementation = new StateOracleV2(TIMELOCK);
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        daVerifier = IDAVerifier(new DAVerifierMock());
        manifestValidator = ITriggerManifestValidator(new UnitManifestValidator());

        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](1);
        adminVerifiers[0] = adminVerifier;
        IDAVerifier[] memory daVerifiers = new IDAVerifier[](1);
        daVerifiers[0] = daVerifier;
        bytes memory initialization = abi.encodeCall(
            StateOracleV2.initialize, (ORACLE_ADMIN, adminVerifiers, daVerifiers, SCHEMA_ID, manifestValidator)
        );
        oracle = StateOracleV2(
            address(new TransparentUpgradeableProxy(address(implementation), PROXY_ADMIN_OWNER, initialization))
        );
        transparentProxyAdmin = address(uint160(uint256(vm.load(address(oracle), ERC1967Utils.ADMIN_SLOT))));
    }

    function _createProject(bytes32 projectId, address manager) internal {
        vm.prank(ORACLE_ADMIN);
        oracle.createProject(projectId, manager);
    }

    function _setLimit(bytes32 projectId, uint64 limit) internal {
        vm.prank(ORACLE_ADMIN);
        oracle.setProjectTriggerLimit(projectId, limit);
    }

    function _newAdopter(address adopterAdmin) internal returns (address) {
        return address(new OwnableAdopter(adopterAdmin));
    }

    function _requestAssignment(address adopter, bytes32 projectId, address adopterAdmin) internal {
        vm.prank(adopterAdmin);
        oracle.registerAssertionAdopter(adopter, projectId, adminVerifier, "");
    }

    function _assign(address adopter, bytes32 projectId, address adopterAdmin, address manager) internal {
        _requestAssignment(adopter, projectId, adopterAdmin);
        vm.prank(manager);
        oracle.acceptAssertionAdopter(adopter);
    }

    function _artifact(bytes32 assertionId, bytes32 schemaId, uint64 units)
        internal
        pure
        returns (StateOracleV2.AssertionArtifact memory)
    {
        return StateOracleV2.AssertionArtifact({
            deploymentCodeHash: assertionId,
            triggerManifest: StateOracleV2.TriggerManifest({schemaId: schemaId, data: abi.encode(units)})
        });
    }

    function _proof(IDAVerifier verifier) internal pure returns (StateOracleV2.DAProof memory) {
        return StateOracleV2.DAProof({verifier: verifier, metadata: "", proof: ""});
    }

    function _add(address adopter, address manager, bytes32 assertionId, uint64 units) internal {
        vm.prank(manager);
        oracle.addAssertion(adopter, _artifact(assertionId, SCHEMA_ID, units), _proof(daVerifier));
    }

    function _projectUsage(bytes32 projectId) internal view returns (uint64 limit, uint64 used) {
        (,, limit, used,,) = oracle.projects(projectId);
    }

    function _assumeCanCallProxy(address caller) internal view {
        vm.assume(
            caller != address(0) && caller != PROXY_ADMIN_OWNER && caller != transparentProxyAdmin
                && caller != address(oracle)
        );
    }
}

contract StateOracleV2RegistrationAndRegistryCoverageTest is StateOracleV2FuzzBase {
    function testFuzz_verifiedAdminCanCancelAndReplacePendingAssignment(
        bytes32 firstProjectId,
        bytes32 secondProjectId,
        address adopterAdmin
    ) public {
        vm.assume(firstProjectId != bytes32(0));
        vm.assume(secondProjectId != bytes32(0) && secondProjectId != firstProjectId);
        _assumeCanCallProxy(adopterAdmin);
        _createProject(firstProjectId, PROTOCOL_MANAGER);
        _createProject(secondProjectId, PROTOCOL_MANAGER);
        address adopter = _newAdopter(adopterAdmin);

        _requestAssignment(adopter, firstProjectId, adopterAdmin);
        vm.prank(adopterAdmin);
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, "");

        (bytes32 assignedProject, bytes32 pendingProject, uint32 count) = oracle.assertionAdopters(adopter);
        assertEq(assignedProject, bytes32(0));
        assertEq(pendingProject, bytes32(0));
        assertEq(count, 0);

        _requestAssignment(adopter, secondProjectId, adopterAdmin);
        vm.prank(PROTOCOL_MANAGER);
        oracle.acceptAssertionAdopter(adopter);
        (assignedProject, pendingProject, count) = oracle.assertionAdopters(adopter);
        assertEq(assignedProject, secondProjectId);
        assertEq(pendingProject, bytes32(0));
        assertEq(count, 0);
    }

    function test_cancelRegistrationRejectsNoPendingUnauthorizedAndRemovedVerifier() public {
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        address adopter = _newAdopter(ADOPTER_ADMIN);

        vm.expectRevert(StateOracleV2.NoPendingAssignment.selector);
        vm.prank(ADOPTER_ADMIN);
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, "");

        _requestAssignment(adopter, PROJECT_ID, ADOPTER_ADMIN);
        vm.expectRevert(StateOracleV2.UnauthorizedRegistrant.selector);
        vm.prank(address(0xBAD));
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, "");

        vm.prank(ORACLE_ADMIN);
        oracle.removeAdminVerifier(adminVerifier);
        vm.expectRevert(AdminVerifierRegistry.AdminVerifierNotRegistered.selector);
        vm.prank(ADOPTER_ADMIN);
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, "");

        (, bytes32 pendingProject,) = oracle.assertionAdopters(adopter);
        assertEq(pendingProject, PROJECT_ID);
    }

    function test_registrationAndCancellationEnforceAdminDataBounds() public {
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        address adopter = _newAdopter(ADOPTER_ADMIN);
        bytes memory maximumData = new bytes(4_096);

        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(adopter, PROJECT_ID, adminVerifier, maximumData);
        vm.prank(ADOPTER_ADMIN);
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, maximumData);

        bytes memory oversizedData = new bytes(4_097);
        vm.expectRevert(StateOracleV2.DataTooLarge.selector);
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(adopter, PROJECT_ID, adminVerifier, oversizedData);
        vm.expectRevert(StateOracleV2.DataTooLarge.selector);
        vm.prank(ADOPTER_ADMIN);
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, oversizedData);
    }

    function test_adminVerifierRegistryLifecycleAndDuplicateGuards() public {
        IAdminVerifier verifier = IAdminVerifier(new AdminVerifierOwner());
        vm.startPrank(ORACLE_ADMIN);
        oracle.addAdminVerifier(verifier);
        assertTrue(oracle.adminVerifiers(verifier));

        vm.expectRevert(AdminVerifierRegistry.AdminVerifierAlreadyRegistered.selector);
        oracle.addAdminVerifier(verifier);

        oracle.removeAdminVerifier(verifier);
        assertFalse(oracle.adminVerifiers(verifier));
        vm.expectRevert(AdminVerifierRegistry.AdminVerifierNotRegistered.selector);
        oracle.removeAdminVerifier(verifier);
        vm.stopPrank();
    }

    function test_daVerifierRegistryLifecycleAndDuplicateGuards() public {
        IDAVerifier verifier = IDAVerifier(new DAVerifierMock());
        vm.startPrank(ORACLE_ADMIN);
        oracle.addDAVerifier(verifier);
        assertTrue(oracle.daVerifiers(verifier));

        vm.expectRevert(DAVerifierRegistry.DAVerifierAlreadyRegistered.selector);
        oracle.addDAVerifier(verifier);

        oracle.removeDAVerifier(verifier);
        assertFalse(oracle.daVerifiers(verifier));
        vm.expectRevert(DAVerifierRegistry.DAVerifierNotRegistered.selector);
        oracle.removeDAVerifier(verifier);
        vm.stopPrank();
    }

    function test_manifestValidatorCanBeAddedReplacedButNotClearedOrRepeated() public {
        bytes32 schemaId = keccak256("replacement-schema");
        ITriggerManifestValidator first = ITriggerManifestValidator(new UnitManifestValidator());
        ITriggerManifestValidator second = ITriggerManifestValidator(new UnitManifestValidator());

        vm.startPrank(ORACLE_ADMIN);
        oracle.setTriggerManifestValidator(schemaId, first);
        assertEq(address(oracle.triggerManifestValidators(schemaId)), address(first));
        oracle.setTriggerManifestValidator(schemaId, second);
        assertEq(address(oracle.triggerManifestValidators(schemaId)), address(second));

        vm.expectRevert(StateOracleV2.TriggerManifestValidatorUnchanged.selector);
        oracle.setTriggerManifestValidator(schemaId, second);
        vm.expectRevert(StateOracleV2.InvalidTriggerManifestValidator.selector);
        oracle.setTriggerManifestValidator(bytes32(0), first);
        vm.expectRevert(StateOracleV2.InvalidTriggerManifestValidator.selector);
        oracle.setTriggerManifestValidator(schemaId, ITriggerManifestValidator(address(0)));
        vm.stopPrank();
    }

    function test_governanceRoleCanBeRenouncedButOwnerDefaultAdminCannot() public {
        address governance = address(0x600D);
        bytes32 governanceRole = oracle.GOVERNANCE_ROLE();
        bytes32 defaultAdminRole = oracle.DEFAULT_ADMIN_ROLE();
        vm.prank(ORACLE_ADMIN);
        oracle.grantRole(governanceRole, governance);

        vm.prank(governance);
        oracle.renounceRole(governanceRole, governance);
        assertFalse(oracle.hasRole(governanceRole, governance));
        vm.expectPartialRevert(IAccessControl.AccessControlUnauthorizedAccount.selector);
        vm.prank(governance);
        oracle.pause();

        vm.prank(ORACLE_ADMIN);
        vm.expectRevert(StateOracleV2AccessControl.CannotRenounceOwnerDefaultAdminRole.selector);
        oracle.renounceRole(defaultAdminRole, ORACLE_ADMIN);
        vm.prank(ORACLE_ADMIN);
        vm.expectRevert(StateOracleV2AccessControl.CannotRevokeOwnerDefaultAdminRole.selector);
        oracle.revokeRole(defaultAdminRole, ORACLE_ADMIN);
    }
}

contract StateOracleV2AssertionFuzzAndBoundsTest is StateOracleV2FuzzBase {
    address internal adopter;

    function setUp() public override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        adopter = _newAdopter(ADOPTER_ADMIN);
        _assign(adopter, PROJECT_ID, ADOPTER_ADMIN, PROTOCOL_MANAGER);
    }

    function testFuzz_triggerLimitAdmissionHasAtomicAccounting(bytes32 assertionId, uint64 unitSeed, uint64 limitSeed)
        public
    {
        vm.assume(assertionId != bytes32(0));
        uint64 units = uint64(bound(unitSeed, 1, 1_000_000));
        uint64 limit = uint64(bound(limitSeed, 0, 1_000_000));
        if (limit != 0) _setLimit(PROJECT_ID, limit);

        if (units <= limit) {
            _add(adopter, PROTOCOL_MANAGER, assertionId, units);
            assertTrue(oracle.hasAssertion(adopter, assertionId));
            (, uint64 used) = _projectUsage(PROJECT_ID);
            assertEq(used, units);
            (bytes32 projectId,, uint32 count) = oracle.assertionAdopters(adopter);
            assertEq(projectId, PROJECT_ID);
            assertEq(count, 1);
        } else {
            vm.expectRevert(StateOracleV2.TriggerLimitExceeded.selector);
            vm.prank(PROTOCOL_MANAGER);
            oracle.addAssertion(adopter, _artifact(assertionId, SCHEMA_ID, units), _proof(daVerifier));
            assertFalse(oracle.hasAssertion(adopter, assertionId));
            (, uint64 used) = _projectUsage(PROJECT_ID);
            assertEq(used, 0);
            (,, uint32 count) = oracle.assertionAdopters(adopter);
            assertEq(count, 0);
        }
    }

    function testFuzz_triggerLimitUsesCumulativeProjectUsage(uint64 limitSeed, uint64 firstUnitsSeed) public {
        uint64 limit = uint64(bound(limitSeed, 2, 1_000_000));
        uint64 firstUnits = uint64(bound(firstUnitsSeed, 1, limit - 1));
        uint64 secondUnits = limit - firstUnits + 1;
        _setLimit(PROJECT_ID, limit);
        _add(adopter, PROTOCOL_MANAGER, bytes32(uint256(1)), firstUnits);

        vm.expectRevert(StateOracleV2.TriggerLimitExceeded.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, _artifact(bytes32(uint256(2)), SCHEMA_ID, secondUnits), _proof(daVerifier));

        (, uint64 used) = _projectUsage(PROJECT_ID);
        (,, uint32 count) = oracle.assertionAdopters(adopter);
        assertEq(used, firstUnits);
        assertEq(count, 1);
        assertFalse(oracle.hasAssertion(adopter, bytes32(uint256(2))));
    }

    function testFuzz_assignmentRequiresBothIdentitiesAndExplicitDetachBeforeMove(
        bytes32 firstProjectId,
        bytes32 secondProjectId,
        address adopterAdmin,
        address firstManager,
        address secondManager
    ) public {
        vm.assume(firstProjectId != bytes32(0));
        vm.assume(secondProjectId != bytes32(0) && secondProjectId != firstProjectId);
        vm.assume(firstProjectId != PROJECT_ID && secondProjectId != PROJECT_ID);
        _assumeCanCallProxy(adopterAdmin);
        _assumeCanCallProxy(firstManager);
        _assumeCanCallProxy(secondManager);
        vm.assume(secondManager != firstManager);
        _createProject(firstProjectId, firstManager);
        _createProject(secondProjectId, secondManager);
        address fuzzAdopter = _newAdopter(adopterAdmin);

        _requestAssignment(fuzzAdopter, firstProjectId, adopterAdmin);
        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(secondManager);
        oracle.acceptAssertionAdopter(fuzzAdopter);
        vm.expectRevert(StateOracleV2.PendingAssignmentExists.selector);
        vm.prank(adopterAdmin);
        oracle.registerAssertionAdopter(fuzzAdopter, secondProjectId, adminVerifier, "");

        vm.prank(firstManager);
        oracle.acceptAssertionAdopter(fuzzAdopter);
        vm.expectRevert(StateOracleV2.AssertionAdopterAlreadyAssigned.selector);
        vm.prank(adopterAdmin);
        oracle.registerAssertionAdopter(fuzzAdopter, secondProjectId, adminVerifier, "");
        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(secondManager);
        oracle.detachAssertionAdopter(fuzzAdopter);

        vm.prank(firstManager);
        oracle.detachAssertionAdopter(fuzzAdopter);
        _requestAssignment(fuzzAdopter, secondProjectId, adopterAdmin);
        vm.prank(secondManager);
        oracle.acceptAssertionAdopter(fuzzAdopter);

        (bytes32 projectId, bytes32 pendingProjectId, uint32 count) = oracle.assertionAdopters(fuzzAdopter);
        assertEq(projectId, secondProjectId);
        assertEq(pendingProjectId, bytes32(0));
        assertEq(count, 0);
    }

    function test_assertionPayloadBoundsAreInclusiveAndEachOversizeFieldIsRejected() public {
        _setLimit(PROJECT_ID, 4);
        StateOracleV2.AssertionArtifact memory maximumArtifact = StateOracleV2.AssertionArtifact({
            deploymentCodeHash: bytes32(uint256(1)),
            triggerManifest: StateOracleV2.TriggerManifest({schemaId: SCHEMA_ID, data: new bytes(65_536)})
        });
        StateOracleV2.DAProof memory maximumProof =
            StateOracleV2.DAProof({verifier: daVerifier, metadata: new bytes(4_096), proof: new bytes(65_536)});
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, maximumArtifact, maximumProof);
        assertTrue(oracle.hasAssertion(adopter, bytes32(uint256(1))));

        _expectOversizedPayload(new bytes(65_537), "", "", bytes32(uint256(2)));
        _expectOversizedPayload("", new bytes(4_097), "", bytes32(uint256(3)));
        _expectOversizedPayload("", "", new bytes(65_537), bytes32(uint256(4)));
        (, uint64 used) = _projectUsage(PROJECT_ID);
        assertEq(used, 1);
    }

    function test_addAssertionRejectsInvalidIdentityRegistriesProofAndUnits() public {
        _setLimit(PROJECT_ID, 10);

        vm.expectRevert(StateOracleV2.InvalidAssertionId.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, _artifact(bytes32(0), SCHEMA_ID, 1), _proof(daVerifier));

        vm.expectRevert(StateOracleV2.TriggerManifestValidatorNotRegistered.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, _artifact(bytes32(uint256(1)), keccak256("unknown-schema"), 1), _proof(daVerifier));

        ITriggerManifestValidator zeroValidator = ITriggerManifestValidator(new ZeroUnitManifestValidator());
        bytes32 zeroSchema = keccak256("zero-unit-schema");
        vm.prank(ORACLE_ADMIN);
        oracle.setTriggerManifestValidator(zeroSchema, zeroValidator);
        vm.expectRevert(StateOracleV2.InvalidTriggerUnits.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, _artifact(bytes32(uint256(1)), zeroSchema, 1), _proof(daVerifier));

        IDAVerifier unregisteredVerifier = IDAVerifier(new DAVerifierMock());
        vm.expectRevert(DAVerifierRegistry.DAVerifierNotRegistered.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, _artifact(bytes32(uint256(1)), SCHEMA_ID, 1), _proof(unregisteredVerifier));

        IDAVerifier rejectingVerifier = IDAVerifier(new RejectingDAVerifier());
        vm.prank(ORACLE_ADMIN);
        oracle.addDAVerifier(rejectingVerifier);
        vm.expectPartialRevert(StateOracleV2.InvalidDAProof.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, _artifact(bytes32(uint256(1)), SCHEMA_ID, 1), _proof(rejectingVerifier));

        assertFalse(oracle.hasAssertion(adopter, bytes32(uint256(1))));
        (,, uint32 count) = oracle.assertionAdopters(adopter);
        (, uint64 used) = _projectUsage(PROJECT_ID);
        assertEq(count, 0);
        assertEq(used, 0);
    }

    function _expectOversizedPayload(bytes memory manifestData, bytes memory metadata, bytes memory proof, bytes32 id)
        private
    {
        StateOracleV2.AssertionArtifact memory artifact = StateOracleV2.AssertionArtifact({
            deploymentCodeHash: id,
            triggerManifest: StateOracleV2.TriggerManifest({schemaId: SCHEMA_ID, data: manifestData})
        });
        vm.expectRevert(StateOracleV2.DataTooLarge.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(adopter, artifact, StateOracleV2.DAProof(daVerifier, metadata, proof));
    }
}

contract StateOracleV2ReaddFuzzTest is StateOracleV2FuzzBase {
    bytes32 internal constant ASSERTION_ID = keccak256("readd-assertion");
    address internal adopter;

    function setUp() public override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, type(uint64).max);
        adopter = _newAdopter(ADOPTER_ADMIN);
        _assign(adopter, PROJECT_ID, ADOPTER_ADMIN, PROTOCOL_MANAGER);
        _add(adopter, PROTOCOL_MANAGER, ASSERTION_ID, 7);
    }

    function beforeTestSetup(bytes4 testSelector) public view returns (bytes[] memory calls) {
        if (testSelector == this.testFuzz_readdReplacesInstallationAccounting.selector) {
            calls = new bytes[](1);
            calls[0] = abi.encodeCall(this.prepareRemovedAssertion, ());
        }
    }

    function prepareRemovedAssertion() external {
        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(adopter, ASSERTION_ID);
    }

    function testFuzz_readdReplacesInstallationAccounting(uint64 unitSeed) public {
        uint64 newUnits = unitSeed == 0 ? 1 : unitSeed;
        assertFalse(oracle.hasAssertion(adopter, ASSERTION_ID));
        (,, uint32 countBefore) = oracle.assertionAdopters(adopter);
        (, uint64 usedBefore) = _projectUsage(PROJECT_ID);
        assertEq(countBefore, 0);
        assertEq(usedBefore, 0);

        _add(adopter, PROTOCOL_MANAGER, ASSERTION_ID, newUnits);

        (uint64 storedUnits, bytes32 schemaId, bytes32 manifestHash, bool enabled) =
            oracle.assertions(adopter, ASSERTION_ID);
        (,, uint32 countAfter) = oracle.assertionAdopters(adopter);
        (, uint64 usedAfter) = _projectUsage(PROJECT_ID);
        assertTrue(enabled);
        assertEq(storedUnits, newUnits);
        assertEq(schemaId, SCHEMA_ID);
        assertEq(manifestHash, keccak256(abi.encode(newUnits)));
        assertEq(countAfter, 1);
        assertEq(usedAfter, newUnits);
    }
}

contract StateOracleV2GrandfatherFuzzTest is StateOracleV2FuzzBase {
    bytes32 internal constant ASSERTION_ID = keccak256("grandfathered-assertion");
    address internal adopter;

    function setUp() public override {
        super.setUp();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 200);
        adopter = _newAdopter(ADOPTER_ADMIN);
        _assign(adopter, PROJECT_ID, ADOPTER_ADMIN, PROTOCOL_MANAGER);
        _add(adopter, PROTOCOL_MANAGER, ASSERTION_ID, 100);
    }

    function testFuzz_lowerLimitGrandfathersThenRemovalRestoresConservation(uint64 limitSeed) public {
        uint64 loweredLimit = uint64(bound(limitSeed, 0, 99));
        _setLimit(PROJECT_ID, loweredLimit);
        assertTrue(oracle.hasAssertion(adopter, ASSERTION_ID));
        (uint64 limit, uint64 used) = _projectUsage(PROJECT_ID);
        assertEq(limit, loweredLimit);
        assertEq(used, 100);

        vm.expectRevert(StateOracleV2.TriggerLimitExceeded.selector);
        vm.prank(PROTOCOL_MANAGER);
        oracle.addAssertion(
            adopter, _artifact(keccak256("blocked-assertion"), SCHEMA_ID, loweredLimit + 1), _proof(daVerifier)
        );

        vm.prank(PROTOCOL_MANAGER);
        oracle.removeAssertion(adopter, ASSERTION_ID);
        (,, uint32 count) = oracle.assertionAdopters(adopter);
        (, used) = _projectUsage(PROJECT_ID);
        assertEq(count, 0);
        assertEq(used, 0);
    }
}

contract StateOracleV2RoleAndLifecycleEdgeTest is StateOracleV2FuzzBase {
    address internal constant GOVERNANCE = address(0x1001);
    address internal constant GUARDIAN = address(0x1002);
    address internal constant PROJECT_CREATOR = address(0x1003);
    address internal constant PROJECT_ADMIN = address(0x1004);
    address internal constant TRIGGER_LIMITER = address(0x1005);

    function setUp() public override {
        super.setUp();
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GOVERNANCE_ROLE(), GOVERNANCE);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.PROJECT_CREATOR_ROLE(), PROJECT_CREATOR);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), PROJECT_ADMIN);
        oracle.grantRole(oracle.TRIGGER_LIMIT_ROLE(), TRIGGER_LIMITER);
        vm.stopPrank();
    }

    function test_eachOperationalRoleIsRejectedFromEveryOtherRoleCapability() public {
        address[5] memory actors = [GOVERNANCE, GUARDIAN, PROJECT_CREATOR, PROJECT_ADMIN, TRIGGER_LIMITER];
        bytes[] memory calls = _roleProtectedCalls();

        for (uint256 actorIndex; actorIndex < actors.length; ++actorIndex) {
            for (uint256 callIndex; callIndex < calls.length; ++callIndex) {
                if (_actorIsAuthorizedForCall(actorIndex, callIndex)) continue;
                vm.prank(actors[actorIndex]);
                (bool success, bytes memory result) = address(oracle).call(calls[callIndex]);
                bytes4 revertSelector = success ? bytes4(0) : _selector(result);
                assertEq(revertSelector, IAccessControl.AccessControlUnauthorizedAccount.selector);
            }
        }
    }

    function test_roleIdsAreCanonicalAndPairwiseDistinct() public view {
        bytes32[6] memory expectedRoleIds = [
            keccak256("GOVERNANCE_ROLE"),
            keccak256("GUARDIAN_ADMIN_ROLE"),
            keccak256("GUARDIAN_ROLE"),
            keccak256("PROJECT_CREATOR_ROLE"),
            keccak256("PROJECT_ADMIN_ROLE"),
            keccak256("TRIGGER_LIMIT_ROLE")
        ];
        bytes32[6] memory actualRoleIds = [
            oracle.GOVERNANCE_ROLE(),
            oracle.GUARDIAN_ADMIN_ROLE(),
            oracle.GUARDIAN_ROLE(),
            oracle.PROJECT_CREATOR_ROLE(),
            oracle.PROJECT_ADMIN_ROLE(),
            oracle.TRIGGER_LIMIT_ROLE()
        ];

        for (uint256 i; i < actualRoleIds.length; ++i) {
            assertEq(actualRoleIds[i], expectedRoleIds[i]);
            for (uint256 j = i + 1; j < actualRoleIds.length; ++j) {
                assertNotEq(actualRoleIds[i], actualRoleIds[j]);
            }
        }
    }

    function test_roleAdministrationMatchesConfiguredHierarchy() public {
        address guardianAdmin = address(0x1006);
        address candidate = address(0x1007);
        bytes32 defaultAdminRole = oracle.DEFAULT_ADMIN_ROLE();
        bytes32 guardianAdminRole = oracle.GUARDIAN_ADMIN_ROLE();
        bytes32 guardianRole = oracle.GUARDIAN_ROLE();

        assertEq(oracle.getRoleAdmin(guardianRole), guardianAdminRole);
        vm.prank(ORACLE_ADMIN);
        oracle.grantRole(guardianAdminRole, guardianAdmin);
        vm.prank(guardianAdmin);
        oracle.grantRole(guardianRole, candidate);
        assertTrue(oracle.hasRole(guardianRole, candidate));

        bytes32[5] memory defaultAdministeredRoles = [
            oracle.GOVERNANCE_ROLE(),
            guardianAdminRole,
            oracle.PROJECT_CREATOR_ROLE(),
            oracle.PROJECT_ADMIN_ROLE(),
            oracle.TRIGGER_LIMIT_ROLE()
        ];
        for (uint256 i; i < defaultAdministeredRoles.length; ++i) {
            assertEq(oracle.getRoleAdmin(defaultAdministeredRoles[i]), defaultAdminRole);
            vm.expectRevert(
                abi.encodeWithSelector(
                    IAccessControl.AccessControlUnauthorizedAccount.selector, guardianAdmin, defaultAdminRole
                )
            );
            vm.prank(guardianAdmin);
            oracle.grantRole(defaultAdministeredRoles[i], candidate);
        }

        vm.prank(guardianAdmin);
        oracle.revokeRole(guardianRole, candidate);
        assertFalse(oracle.hasRole(guardianRole, candidate));
    }

    function testFuzz_quarantinedAdopterCanOnlyDetachAfterProjectAdminRecovery(
        bytes32 projectId,
        address manager,
        address replacement,
        address outsider
    ) public {
        vm.assume(projectId != bytes32(0));
        _assumeCanCallProxy(manager);
        _assumeCanCallProxy(replacement);
        _assumeCanCallProxy(outsider);
        vm.assume(replacement != manager);
        vm.assume(outsider != replacement && outsider != manager);
        _createProject(projectId, manager);
        address adopter = _newAdopter(ADOPTER_ADMIN);
        _assign(adopter, projectId, ADOPTER_ADMIN, manager);

        vm.prank(GUARDIAN);
        oracle.revokeProtocolManager(projectId);
        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(outsider);
        oracle.detachAssertionAdopter(adopter);

        vm.prank(PROJECT_ADMIN);
        oracle.proposeProtocolManagerReplacement(projectId, replacement);
        vm.prank(replacement);
        oracle.acceptProtocolManagerTransfer(projectId);
        vm.prank(replacement);
        oracle.detachAssertionAdopter(adopter);

        (bytes32 assignedProject,, uint32 count) = oracle.assertionAdopters(adopter);
        assertEq(assignedProject, bytes32(0));
        assertEq(count, 0);
    }

    function testFuzz_retiredEmptyAdopterCanBeDetachedByAnyAccount(bytes32 projectId, address manager, address detacher)
        public
    {
        vm.assume(projectId != bytes32(0));
        _assumeCanCallProxy(manager);
        _assumeCanCallProxy(detacher);
        _createProject(projectId, manager);
        address adopter = _newAdopter(ADOPTER_ADMIN);
        _assign(adopter, projectId, ADOPTER_ADMIN, manager);

        vm.prank(manager);
        oracle.requestProjectRetirement(projectId);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(projectId);
        vm.prank(detacher);
        oracle.detachAssertionAdopter(adopter);

        (bytes32 assignedProject,, uint32 count) = oracle.assertionAdopters(adopter);
        assertEq(assignedProject, bytes32(0));
        assertEq(count, 0);
    }

    function test_pendingManagerTransferDoesNotAuthorizeOrInvalidateRetirementRequest() public {
        address pendingManager = address(0xD00D);
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProtocolManagerTransfer(PROJECT_ID, pendingManager);

        vm.expectRevert(StateOracleV2.UnauthorizedProtocolManager.selector);
        vm.prank(pendingManager);
        oracle.cancelProjectRetirement(PROJECT_ID);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        (address manager, address pending,,,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(manager, address(0));
        assertEq(pending, address(0));
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));
    }

    function _roleProtectedCalls() private view returns (bytes[] memory calls) {
        calls = new bytes[](13);
        calls[0] = abi.encodeCall(StateOracleV2.pause, ());
        calls[1] = abi.encodeCall(StateOracleV2.unpause, ());
        calls[2] = abi.encodeCall(StateOracleV2.addAdminVerifier, (adminVerifier));
        calls[3] = abi.encodeCall(StateOracleV2.removeAdminVerifier, (IAdminVerifier(address(0xDEAD))));
        calls[4] = abi.encodeCall(StateOracleV2.addDAVerifier, (daVerifier));
        calls[5] = abi.encodeCall(StateOracleV2.removeDAVerifier, (IDAVerifier(address(0xDEAD))));
        calls[6] = abi.encodeCall(StateOracleV2.setTriggerManifestValidator, (SCHEMA_ID, manifestValidator));
        calls[7] = abi.encodeCall(StateOracleV2.revokeProtocolManager, (bytes32(0)));
        calls[8] = abi.encodeCall(StateOracleV2.removeAssertionByGuardian, (address(0), bytes32(0)));
        calls[9] = abi.encodeCall(StateOracleV2.createProject, (bytes32(0), address(0)));
        calls[10] = abi.encodeCall(StateOracleV2.proposeProtocolManagerReplacement, (bytes32(0), address(0)));
        calls[11] = abi.encodeCall(StateOracleV2.finalizeProjectRetirement, (bytes32(0)));
        calls[12] = abi.encodeCall(StateOracleV2.setProjectTriggerLimit, (bytes32(0), 0));
    }

    function _actorIsAuthorizedForCall(uint256 actorIndex, uint256 callIndex) private pure returns (bool) {
        if (actorIndex == 0) return callIndex < 7;
        if (actorIndex == 1) return callIndex == 7 || callIndex == 8;
        if (actorIndex == 2) return callIndex == 9;
        if (actorIndex == 3) return callIndex == 10 || callIndex == 11;
        return callIndex == 12;
    }

    function _selector(bytes memory revertData) private pure returns (bytes4 selector) {
        if (revertData.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(revertData, 0x20))
        }
    }
}

contract StateOracleV2RetirementWithAssertionEdgeTest is StateOracleV2FuzzBase {
    address internal constant GUARDIAN = address(0x2001);
    address internal constant PROJECT_ADMIN = address(0x2002);
    bytes32 internal constant ASSERTION_ID = keccak256("retirement-assertion");
    address internal adopter;

    function setUp() public override {
        super.setUp();
        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), PROJECT_ADMIN);
        vm.stopPrank();
        _createProject(PROJECT_ID, PROTOCOL_MANAGER);
        _setLimit(PROJECT_ID, 1);
        adopter = _newAdopter(ADOPTER_ADMIN);
        _assign(adopter, PROJECT_ID, ADOPTER_ADMIN, PROTOCOL_MANAGER);
        _add(adopter, PROTOCOL_MANAGER, ASSERTION_ID, 1);
    }

    function test_retirementWithAssertionRequiresLoadReductionBeforeFinalization() public {
        vm.prank(PROTOCOL_MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.expectRevert(StateOracleV2.ProjectHasAssertions.selector);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.prank(GUARDIAN);
        oracle.removeAssertionByGuardian(adopter, ASSERTION_ID);
        vm.prank(PROJECT_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        (bytes32 assignedProject,, uint32 count) = oracle.assertionAdopters(adopter);
        (,,,, uint64 retiredAtBlock, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(assignedProject, PROJECT_ID);
        assertEq(count, 0);
        assertEq(retiredAtBlock, block.number);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Retired));

        vm.prank(address(0xBEEF));
        oracle.detachAssertionAdopter(adopter);
        (assignedProject,,) = oracle.assertionAdopters(adopter);
        assertEq(assignedProject, bytes32(0));
    }
}
