// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";

import {StateOracleV2} from "../src/StateOracleV2.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {ITriggerManifestValidator} from "../src/interfaces/ITriggerManifestValidator.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {OwnableAdopter} from "./utils/Adopter.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";

contract InvariantTriggerManifestValidator is ITriggerManifestValidator {
    bytes32 public constant SCHEMA_ID = keccak256("state-oracle-v2.invariant-manifest");

    function validate(bytes32 schemaId, bytes calldata data)
        external
        pure
        returns (uint32 triggerCount, uint64 triggerUnits)
    {
        require(schemaId == SCHEMA_ID);
        triggerUnits = abi.decode(data, (uint64));
        require(triggerUnits != 0);
        return (1, triggerUnits);
    }
}

contract StateOracleV2InvariantHandler is Test {
    uint256 internal constant PROJECT_COUNT = 3;
    uint256 internal constant ADOPTER_COUNT = 4;
    uint256 internal constant ASSERTION_COUNT = 6;
    uint256 internal constant MANAGER_COUNT = 6;
    uint64 internal constant MAX_LIMIT = 40;

    StateOracleV2 public immutable oracle;
    IAdminVerifier public immutable adminVerifier;
    IDAVerifier public immutable daVerifier;
    bytes32 public immutable manifestSchemaId;

    address public immutable projectCreator;
    address public immutable triggerLimitAdmin;
    address public immutable guardian;
    address public immutable projectAdmin;
    address public immutable governance;

    bytes32[PROJECT_COUNT] private _projectIds;
    address[ADOPTER_COUNT] private _adopters;
    address[ADOPTER_COUNT] private _adopterAdmins;
    bytes32[ASSERTION_COUNT] private _assertionIds;
    address[MANAGER_COUNT] private _managers;

    mapping(bytes32 projectId => bool created) public ghostProjectCreated;
    mapping(bytes32 projectId => bool retired) public ghostProjectRetired;
    mapping(bytes32 projectId => address manager) public ghostProtocolManager;
    mapping(bytes32 projectId => address pendingManager) public ghostPendingProtocolManager;
    mapping(bytes32 projectId => uint64 limit) public ghostTriggerLimit;
    mapping(bytes32 projectId => uint64 usedTriggerUnits) public ghostProjectUsage;
    mapping(bytes32 projectId => address requester) public ghostRetirementRequester;
    mapping(address adopter => bytes32 projectId) public ghostAssignedProject;
    mapping(address adopter => bytes32 projectId) public ghostPendingProject;
    mapping(address adopter => uint32 count) public ghostAssertionCount;
    mapping(address adopter => mapping(bytes32 assertionId => uint64 units)) public ghostEnabledUnits;
    mapping(address adopter => mapping(bytes32 assertionId => bytes32 schemaId)) public ghostManifestSchemaId;
    mapping(address adopter => mapping(bytes32 assertionId => bytes32 manifestHash)) public ghostManifestHash;
    bool public ghostPaused;

    constructor(
        StateOracleV2 oracle_,
        IAdminVerifier adminVerifier_,
        IDAVerifier daVerifier_,
        bytes32 manifestSchemaId_,
        address projectCreator_,
        address triggerLimitAdmin_,
        address guardian_,
        address projectAdmin_,
        address governance_
    ) {
        oracle = oracle_;
        adminVerifier = adminVerifier_;
        daVerifier = daVerifier_;
        manifestSchemaId = manifestSchemaId_;
        projectCreator = projectCreator_;
        triggerLimitAdmin = triggerLimitAdmin_;
        guardian = guardian_;
        projectAdmin = projectAdmin_;
        governance = governance_;

        for (uint256 i; i < PROJECT_COUNT; ++i) {
            _projectIds[i] = keccak256(abi.encode("invariant project", i));
        }
        for (uint256 i; i < ADOPTER_COUNT; ++i) {
            // The bounded loop keeps this value far below the address width.
            // forge-lint: disable-next-line(unsafe-typecast)
            address adopterAdmin = address(uint160(0x2000 + i));
            _adopterAdmins[i] = adopterAdmin;
            _adopters[i] = address(new OwnableAdopter(adopterAdmin));
        }
        for (uint256 i; i < ASSERTION_COUNT; ++i) {
            _assertionIds[i] = bytes32(i + 1);
        }
        for (uint256 i; i < MANAGER_COUNT; ++i) {
            // The bounded loop keeps this value far below the address width.
            // forge-lint: disable-next-line(unsafe-typecast)
            _managers[i] = address(uint160(0x3000 + i));
        }
    }

    function projectIdAt(uint256 index) external view returns (bytes32) {
        return _projectIds[index];
    }

    function adopterAt(uint256 index) external view returns (address) {
        return _adopters[index];
    }

    function assertionIdAt(uint256 index) external view returns (bytes32) {
        return _assertionIds[index];
    }

    function createProject(uint256 projectSeed, uint256 managerSeed) external {
        bytes32 projectId = _project(projectSeed);
        if (ghostProjectCreated[projectId] || ghostPaused) return;

        address manager = _manager(managerSeed);
        vm.prank(projectCreator);
        oracle.createProject(projectId, manager);
        ghostProjectCreated[projectId] = true;
        ghostProtocolManager[projectId] = manager;
    }

    function setTriggerLimit(uint256 projectSeed, uint64 limitSeed) external {
        bytes32 projectId = _project(projectSeed);
        if (!ghostProjectCreated[projectId] || ghostProjectRetired[projectId]) return;

        uint64 newLimit = limitSeed % (MAX_LIMIT + 1);
        if (newLimit == ghostTriggerLimit[projectId]) newLimit = (newLimit + 1) % (MAX_LIMIT + 1);
        vm.prank(triggerLimitAdmin);
        oracle.setProjectTriggerLimit(projectId, newLimit);
        ghostTriggerLimit[projectId] = newLimit;
    }

    function requestRegistration(uint256 adopterSeed, uint256 projectSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 projectId = _project(projectSeed);
        if (ghostPaused || ghostAssignedProject[adopter] != bytes32(0) || ghostPendingProject[adopter] != bytes32(0)) {
            return;
        }
        if (!ghostProjectCreated[projectId] || ghostProjectRetired[projectId]) return;

        vm.prank(_adopterAdmin(adopterSeed));
        oracle.registerAssertionAdopter(adopter, projectId, adminVerifier, "");
        ghostPendingProject[adopter] = projectId;
    }

    function cancelRegistration(uint256 adopterSeed) external {
        address adopter = _adopter(adopterSeed);
        if (ghostPendingProject[adopter] == bytes32(0)) return;

        vm.prank(_adopterAdmin(adopterSeed));
        oracle.cancelAssertionAdopterRegistration(adopter, adminVerifier, "");
        ghostPendingProject[adopter] = bytes32(0);
    }

    function rejectRegistration(uint256 adopterSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 projectId = ghostPendingProject[adopter];
        if (projectId == bytes32(0)) return;

        address manager = ghostProtocolManager[projectId];
        if (!ghostProjectRetired[projectId] && manager == address(0)) return;
        address caller = ghostProjectRetired[projectId] ? address(0x4000) : manager;
        vm.prank(caller);
        oracle.rejectAssertionAdopterRegistration(adopter);
        ghostPendingProject[adopter] = bytes32(0);
    }

    function acceptRegistration(uint256 adopterSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 projectId = ghostPendingProject[adopter];
        if (projectId == bytes32(0) || ghostPaused) return;

        address manager = ghostProtocolManager[projectId];
        if (ghostProjectRetired[projectId] || manager == address(0)) return;
        vm.prank(manager);
        oracle.acceptAssertionAdopter(adopter);
        ghostAssignedProject[adopter] = projectId;
        ghostPendingProject[adopter] = bytes32(0);
    }

    function detachAdopter(uint256 adopterSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 projectId = ghostAssignedProject[adopter];
        if (projectId == bytes32(0) || ghostAssertionCount[adopter] != 0) return;

        address manager = ghostProtocolManager[projectId];
        if (!ghostProjectRetired[projectId] && manager == address(0)) return;
        address caller = ghostProjectRetired[projectId] ? address(0x4001) : manager;
        vm.prank(caller);
        oracle.detachAssertionAdopter(adopter);
        ghostAssignedProject[adopter] = bytes32(0);
    }

    function addAssertion(uint256 adopterSeed, uint256 assertionSeed, uint64 unitsSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 projectId = ghostAssignedProject[adopter];
        bytes32 assertionId = _assertion(assertionSeed);
        if (projectId == bytes32(0) || ghostEnabledUnits[adopter][assertionId] != 0 || ghostPaused) return;

        address manager = ghostProtocolManager[projectId];
        uint64 units = (unitsSeed % 5) + 1;
        if (
            ghostProjectRetired[projectId] || manager == address(0)
                || uint256(ghostProjectUsage[projectId]) + uint256(units) > ghostTriggerLimit[projectId]
        ) return;

        vm.prank(manager);
        oracle.addAssertion(adopter, _artifact(assertionId, units), _proof());
        ghostEnabledUnits[adopter][assertionId] = units;
        ghostManifestSchemaId[adopter][assertionId] = manifestSchemaId;
        ghostManifestHash[adopter][assertionId] = keccak256(abi.encode(units));
        ghostAssertionCount[adopter]++;
        ghostProjectUsage[projectId] += units;
    }

    function removeAssertion(uint256 adopterSeed, uint256 assertionSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 assertionId = _assertion(assertionSeed);
        bytes32 projectId = ghostAssignedProject[adopter];
        uint64 units = ghostEnabledUnits[adopter][assertionId];
        if (projectId == bytes32(0) || units == 0) return;

        address manager = ghostProtocolManager[projectId];
        if (ghostProjectRetired[projectId] || manager == address(0)) return;
        vm.prank(manager);
        oracle.removeAssertion(adopter, assertionId);
        _recordRemoval(adopter, projectId, assertionId, units);
    }

    function guardianRemoveAssertion(uint256 adopterSeed, uint256 assertionSeed) external {
        address adopter = _adopter(adopterSeed);
        bytes32 assertionId = _assertion(assertionSeed);
        bytes32 projectId = ghostAssignedProject[adopter];
        uint64 units = ghostEnabledUnits[adopter][assertionId];
        if (projectId == bytes32(0) || units == 0) return;

        vm.prank(guardian);
        oracle.removeAssertionByGuardian(adopter, assertionId);
        _recordRemoval(adopter, projectId, assertionId, units);
    }

    function requestManagerTransfer(uint256 projectSeed, uint256 managerSeed) external {
        bytes32 projectId = _project(projectSeed);
        address manager = ghostProtocolManager[projectId];
        address pendingManager = ghostPendingProtocolManager[projectId];
        if (!ghostProjectCreated[projectId] || ghostProjectRetired[projectId] || manager == address(0) || ghostPaused) {
            return;
        }

        address replacement = _replacementManager(managerSeed, manager, pendingManager);
        vm.prank(manager);
        oracle.requestProtocolManagerTransfer(projectId, replacement);
        ghostPendingProtocolManager[projectId] = replacement;
    }

    function acceptManagerTransfer(uint256 projectSeed) external {
        bytes32 projectId = _project(projectSeed);
        address manager = ghostProtocolManager[projectId];
        address pendingManager = ghostPendingProtocolManager[projectId];
        if (
            !ghostProjectCreated[projectId] || ghostProjectRetired[projectId] || pendingManager == address(0)
                || (manager != address(0) && ghostPaused)
        ) return;

        vm.prank(pendingManager);
        oracle.acceptProtocolManagerTransfer(projectId);
        ghostProtocolManager[projectId] = pendingManager;
        ghostPendingProtocolManager[projectId] = address(0);
        ghostRetirementRequester[projectId] = address(0);
    }

    function quarantineManager(uint256 projectSeed) external {
        bytes32 projectId = _project(projectSeed);
        address manager = ghostProtocolManager[projectId];
        address pendingManager = ghostPendingProtocolManager[projectId];
        if (
            !ghostProjectCreated[projectId] || ghostProjectRetired[projectId]
                || (manager == address(0) && pendingManager == address(0))
        ) {
            return;
        }

        vm.prank(guardian);
        oracle.revokeProtocolManager(projectId);
        ghostProtocolManager[projectId] = address(0);
        ghostPendingProtocolManager[projectId] = address(0);
        ghostRetirementRequester[projectId] = address(0);
    }

    function proposeManagerRecovery(uint256 projectSeed, uint256 managerSeed) external {
        bytes32 projectId = _project(projectSeed);
        if (
            !ghostProjectCreated[projectId] || ghostProjectRetired[projectId]
                || ghostProtocolManager[projectId] != address(0) || ghostPendingProtocolManager[projectId] != address(0)
        ) {
            return;
        }

        address replacement = _manager(managerSeed);
        vm.prank(projectAdmin);
        oracle.proposeProtocolManagerReplacement(projectId, replacement);
        ghostPendingProtocolManager[projectId] = replacement;
    }

    function requestRetirement(uint256 projectSeed) external {
        bytes32 projectId = _project(projectSeed);
        address manager = ghostProtocolManager[projectId];
        if (
            !ghostProjectCreated[projectId] || ghostProjectRetired[projectId] || manager == address(0) || ghostPaused
                || ghostRetirementRequester[projectId] != address(0)
        ) return;

        vm.prank(manager);
        oracle.requestProjectRetirement(projectId);
        ghostRetirementRequester[projectId] = manager;
    }

    function cancelRetirement(uint256 projectSeed) external {
        bytes32 projectId = _project(projectSeed);
        address manager = ghostProtocolManager[projectId];
        if (
            !ghostProjectCreated[projectId] || ghostProjectRetired[projectId] || manager == address(0) || ghostPaused
                || ghostRetirementRequester[projectId] != manager
        ) return;

        vm.prank(manager);
        oracle.cancelProjectRetirement(projectId);
        ghostRetirementRequester[projectId] = address(0);
    }

    function finalizeRetirement(uint256 projectSeed) external {
        bytes32 projectId = _project(projectSeed);
        address manager = ghostProtocolManager[projectId];
        if (
            !ghostProjectCreated[projectId] || ghostProjectRetired[projectId] || manager == address(0)
                || ghostProjectUsage[projectId] != 0 || ghostRetirementRequester[projectId] != manager
        ) return;

        vm.prank(projectAdmin);
        oracle.finalizeProjectRetirement(projectId);
        ghostProjectRetired[projectId] = true;
        ghostProtocolManager[projectId] = address(0);
        ghostPendingProtocolManager[projectId] = address(0);
        ghostTriggerLimit[projectId] = 0;
        ghostRetirementRequester[projectId] = address(0);
    }

    function togglePause() external {
        vm.prank(governance);
        if (ghostPaused) oracle.unpause();
        else oracle.pause();
        ghostPaused = !ghostPaused;
    }

    function resetStorage(uint256 adopterSeed, bytes32 storageKey) external {
        address adopter = _adopter(adopterSeed);
        bytes32 projectId = ghostAssignedProject[adopter];
        if (projectId == bytes32(0) || ghostPaused) return;

        address manager = ghostProtocolManager[projectId];
        if (ghostProjectRetired[projectId] || manager == address(0)) return;
        vm.prank(manager);
        oracle.resetStorage(adopter, storageKey);
    }

    function _recordRemoval(address adopter, bytes32 projectId, bytes32 assertionId, uint64 units) private {
        ghostEnabledUnits[adopter][assertionId] = 0;
        ghostAssertionCount[adopter]--;
        ghostProjectUsage[projectId] -= units;
    }

    function _artifact(bytes32 assertionId, uint64 units)
        private
        view
        returns (StateOracleV2.AssertionArtifact memory)
    {
        return StateOracleV2.AssertionArtifact({
            deploymentCodeHash: assertionId,
            triggerManifest: StateOracleV2.TriggerManifest({schemaId: manifestSchemaId, data: abi.encode(units)})
        });
    }

    function _proof() private view returns (StateOracleV2.DAProof memory) {
        return StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""});
    }

    function _project(uint256 seed) private view returns (bytes32) {
        return _projectIds[seed % PROJECT_COUNT];
    }

    function _adopter(uint256 seed) private view returns (address) {
        return _adopters[seed % ADOPTER_COUNT];
    }

    function _adopterAdmin(uint256 seed) private view returns (address) {
        return _adopterAdmins[seed % ADOPTER_COUNT];
    }

    function _assertion(uint256 seed) private view returns (bytes32) {
        return _assertionIds[seed % ASSERTION_COUNT];
    }

    function _manager(uint256 seed) private view returns (address) {
        return _managers[seed % MANAGER_COUNT];
    }

    function _replacementManager(uint256 seed, address manager, address pendingManager)
        private
        view
        returns (address replacement)
    {
        uint256 start = seed % MANAGER_COUNT;
        for (uint256 i; i < MANAGER_COUNT; ++i) {
            replacement = _managers[(start + i) % MANAGER_COUNT];
            if (replacement != manager && replacement != pendingManager) return replacement;
        }
        revert();
    }
}

contract StateOracleV2StatefulInvariantTest is StdInvariant, Test {
    uint256 internal constant PROJECT_COUNT = 3;
    uint256 internal constant ADOPTER_COUNT = 4;
    uint256 internal constant ASSERTION_COUNT = 6;
    uint256 internal constant TIMELOCK = 10;
    address internal constant ORACLE_ADMIN = address(0xA11CE);
    address internal constant PROXY_ADMIN = address(0xA0);
    address internal constant PROJECT_CREATOR = address(0xC001);
    address internal constant TRIGGER_LIMIT_ADMIN = address(0xC002);
    address internal constant GUARDIAN = address(0xC003);
    address internal constant PROJECT_ADMIN = address(0xC004);
    address internal constant GOVERNANCE = address(0xC005);

    StateOracleV2 internal oracle;
    StateOracleV2InvariantHandler internal handler;

    function setUp() public {
        StateOracleV2 implementation = new StateOracleV2(TIMELOCK);
        IAdminVerifier adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        IDAVerifier daVerifier = IDAVerifier(new DAVerifierMock());
        InvariantTriggerManifestValidator manifestValidator = new InvariantTriggerManifestValidator();

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
        oracle = StateOracleV2(address(new TransparentUpgradeableProxy(address(implementation), PROXY_ADMIN, data)));

        vm.startPrank(ORACLE_ADMIN);
        oracle.grantRole(oracle.PROJECT_CREATOR_ROLE(), PROJECT_CREATOR);
        oracle.grantRole(oracle.TRIGGER_LIMIT_ROLE(), TRIGGER_LIMIT_ADMIN);
        oracle.grantRole(oracle.GUARDIAN_ROLE(), GUARDIAN);
        oracle.grantRole(oracle.PROJECT_ADMIN_ROLE(), PROJECT_ADMIN);
        oracle.grantRole(oracle.GOVERNANCE_ROLE(), GOVERNANCE);
        vm.stopPrank();

        handler = new StateOracleV2InvariantHandler(
            oracle,
            adminVerifier,
            daVerifier,
            manifestValidator.SCHEMA_ID(),
            PROJECT_CREATOR,
            TRIGGER_LIMIT_ADMIN,
            GUARDIAN,
            PROJECT_ADMIN,
            GOVERNANCE
        );

        bytes4[] memory selectors = new bytes4[](19);
        selectors[0] = handler.createProject.selector;
        selectors[1] = handler.setTriggerLimit.selector;
        selectors[2] = handler.requestRegistration.selector;
        selectors[3] = handler.cancelRegistration.selector;
        selectors[4] = handler.rejectRegistration.selector;
        selectors[5] = handler.acceptRegistration.selector;
        selectors[6] = handler.detachAdopter.selector;
        selectors[7] = handler.addAssertion.selector;
        selectors[8] = handler.removeAssertion.selector;
        selectors[9] = handler.guardianRemoveAssertion.selector;
        selectors[10] = handler.requestManagerTransfer.selector;
        selectors[11] = handler.acceptManagerTransfer.selector;
        selectors[12] = handler.quarantineManager.selector;
        selectors[13] = handler.proposeManagerRecovery.selector;
        selectors[14] = handler.requestRetirement.selector;
        selectors[15] = handler.cancelRetirement.selector;
        selectors[16] = handler.finalizeRetirement.selector;
        selectors[17] = handler.togglePause.selector;
        selectors[18] = handler.resetStorage.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function invariant_assignmentsMatchGhostStateAndRemainExclusive() public view {
        for (uint256 i; i < ADOPTER_COUNT; ++i) {
            address adopter = handler.adopterAt(i);
            (bytes32 projectId, bytes32 pendingProjectId, uint32 assertionCount) = oracle.assertionAdopters(adopter);
            assertEq(projectId, handler.ghostAssignedProject(adopter));
            assertEq(pendingProjectId, handler.ghostPendingProject(adopter));
            assertEq(assertionCount, handler.ghostAssertionCount(adopter));
            assertTrue(projectId == bytes32(0) || pendingProjectId == bytes32(0));

            if (projectId != bytes32(0)) {
                assertTrue(_isKnownProject(projectId));
                (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(projectId);
                assertTrue(
                    status == StateOracleV2.ProjectStatus.Active || status == StateOracleV2.ProjectStatus.Retired
                );
                if (status == StateOracleV2.ProjectStatus.Retired) assertEq(assertionCount, 0);
            }
            if (pendingProjectId != bytes32(0)) {
                assertTrue(_isKnownProject(pendingProjectId));
                (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(pendingProjectId);
                assertTrue(
                    status == StateOracleV2.ProjectStatus.Active || status == StateOracleV2.ProjectStatus.Retired
                );
            }
        }
    }

    function invariant_enabledAssertionsRequireAnActiveAssignmentAndCountsConserve() public view {
        for (uint256 i; i < ADOPTER_COUNT; ++i) {
            address adopter = handler.adopterAt(i);
            (bytes32 projectId,, uint32 storedCount) = oracle.assertionAdopters(adopter);
            uint256 enumeratedCount;
            for (uint256 j; j < ASSERTION_COUNT; ++j) {
                bytes32 assertionId = handler.assertionIdAt(j);
                (uint64 units, bytes32 schemaId, bytes32 manifestHash, bool enabled) =
                    oracle.assertions(adopter, assertionId);
                uint64 ghostUnits = handler.ghostEnabledUnits(adopter, assertionId);
                assertEq(enabled, ghostUnits != 0);
                assertEq(schemaId, handler.ghostManifestSchemaId(adopter, assertionId));
                assertEq(manifestHash, handler.ghostManifestHash(adopter, assertionId));
                if (!enabled) continue;

                ++enumeratedCount;
                assertEq(units, ghostUnits);
                assertNotEq(projectId, bytes32(0));
                (,,,,, StateOracleV2.ProjectStatus status) = oracle.projects(projectId);
                assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Active));
            }
            assertEq(enumeratedCount, storedCount);
        }
    }

    function invariant_projectAndGlobalTriggerUnitsConserve() public view {
        uint256[PROJECT_COUNT] memory installedByProject;
        uint256 totalInstalled;
        for (uint256 i; i < ADOPTER_COUNT; ++i) {
            address adopter = handler.adopterAt(i);
            (bytes32 projectId,,) = oracle.assertionAdopters(adopter);
            for (uint256 j; j < ASSERTION_COUNT; ++j) {
                (uint64 units,,, bool enabled) = oracle.assertions(adopter, handler.assertionIdAt(j));
                if (!enabled) continue;
                uint256 projectIndex = _projectIndex(projectId);
                installedByProject[projectIndex] += units;
                totalInstalled += units;
            }
        }

        uint256 totalProjectUsage;
        for (uint256 i; i < PROJECT_COUNT; ++i) {
            bytes32 projectId = handler.projectIdAt(i);
            (,,, uint64 used,,) = oracle.projects(projectId);
            assertEq(used, installedByProject[i]);
            assertEq(used, handler.ghostProjectUsage(projectId));
            totalProjectUsage += used;
        }
        assertEq(totalInstalled, totalProjectUsage);
    }

    function invariant_retirementIsATerminalZeroedTombstone() public view {
        assertEq(oracle.paused(), handler.ghostPaused());
        for (uint256 i; i < PROJECT_COUNT; ++i) {
            bytes32 projectId = handler.projectIdAt(i);
            (
                address manager,
                address pendingManager,
                uint64 limit,
                uint64 used,
                uint64 retiredAtBlock,
                StateOracleV2.ProjectStatus status
            ) = oracle.projects(projectId);
            bool created = handler.ghostProjectCreated(projectId);
            bool retired = handler.ghostProjectRetired(projectId);
            StateOracleV2.ProjectStatus expectedStatus = !created
                ? StateOracleV2.ProjectStatus.None
                : retired ? StateOracleV2.ProjectStatus.Retired : StateOracleV2.ProjectStatus.Active;

            assertEq(uint8(status), uint8(expectedStatus));
            assertEq(manager, handler.ghostProtocolManager(projectId));
            assertEq(pendingManager, handler.ghostPendingProtocolManager(projectId));
            assertEq(limit, handler.ghostTriggerLimit(projectId));
            assertEq(used, handler.ghostProjectUsage(projectId));
            assertEq(oracle.projectRetirementRequesters(projectId), handler.ghostRetirementRequester(projectId));
            if (status != StateOracleV2.ProjectStatus.Retired) {
                assertEq(retiredAtBlock, 0);
                continue;
            }

            assertEq(manager, address(0));
            assertEq(pendingManager, address(0));
            assertEq(limit, 0);
            assertEq(used, 0);
            assertGt(retiredAtBlock, 0);
            assertEq(handler.ghostRetirementRequester(projectId), address(0));
        }
    }

    function invariant_ownerAndDefaultAdminRemainCoupled() public view {
        assertEq(oracle.owner(), ORACLE_ADMIN);
        assertTrue(oracle.hasRole(oracle.DEFAULT_ADMIN_ROLE(), ORACLE_ADMIN));
    }

    function _isKnownProject(bytes32 projectId) private view returns (bool) {
        for (uint256 i; i < PROJECT_COUNT; ++i) {
            if (handler.projectIdAt(i) == projectId) return true;
        }
        return false;
    }

    function _projectIndex(bytes32 projectId) private view returns (uint256) {
        for (uint256 i; i < PROJECT_COUNT; ++i) {
            if (handler.projectIdAt(i) == projectId) return i;
        }
        revert("unknown project");
    }
}

contract StateOracleV2InvariantEdgeFuzzTest is Test {
    uint256 internal constant TIMELOCK = 10;
    address internal constant ORACLE_ADMIN = address(0xA11CE);
    address internal constant PROXY_ADMIN = address(0xA0);
    address internal constant MANAGER = address(0xB0B);
    address internal constant ADOPTER_ADMIN = address(0xCAFE);
    bytes32 internal constant PROJECT_ID = keccak256("fuzz project");
    bytes32 internal constant SECOND_PROJECT_ID = keccak256("second fuzz project");
    bytes32 internal constant ASSERTION_ID = bytes32(uint256(1));
    uint64 internal constant INSTALLED_UNITS = 7;

    StateOracleV2 internal oracle;
    IAdminVerifier internal adminVerifier;
    IDAVerifier internal daVerifier;
    InvariantTriggerManifestValidator internal manifestValidator;
    address internal adopter;

    function setUp() public {
        StateOracleV2 implementation = new StateOracleV2(TIMELOCK);
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        daVerifier = IDAVerifier(new DAVerifierMock());
        manifestValidator = new InvariantTriggerManifestValidator();

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
        oracle = StateOracleV2(address(new TransparentUpgradeableProxy(address(implementation), PROXY_ADMIN, data)));
        vm.prank(ORACLE_ADMIN);
        oracle.createProject(PROJECT_ID, MANAGER);
        _setLimit(PROJECT_ID, 100);
        adopter = address(new OwnableAdopter(ADOPTER_ADMIN));
        _assign(PROJECT_ID, MANAGER);
    }

    function beforeTestSetup(bytes4 testSelector) public view returns (bytes[] memory calls) {
        if (
            testSelector == this.testFuzz_retirementCannotStrandAnAdopter.selector
                || testSelector == this.testFuzz_quarantinedManagerCanBeRecoveredEvenWhilePaused.selector
                || testSelector == this.testFuzz_adopterCanMoveOnlyAfterEveryAssertionIsRemoved.selector
        ) {
            calls = new bytes[](1);
            calls[0] = abi.encodeCall(this.setupAddAssertion, ());
        }
    }

    function setupAddAssertion() external {
        _add(MANAGER, ASSERTION_ID, INSTALLED_UNITS);
    }

    function testFuzz_retirementCannotStrandAnAdopter(address cleanupCaller) public {
        _assumeNotProxyAdmin(cleanupCaller);
        vm.prank(MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        vm.expectRevert(StateOracleV2.ProjectHasAssertions.selector);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.prank(ORACLE_ADMIN);
        oracle.removeAssertionByGuardian(adopter, ASSERTION_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.prank(cleanupCaller);
        oracle.detachAssertionAdopter(adopter);
        (bytes32 projectId,, uint32 assertionCount) = oracle.assertionAdopters(adopter);
        assertEq(projectId, bytes32(0));
        assertEq(assertionCount, 0);
    }

    function testFuzz_quarantinedManagerCanBeRecoveredEvenWhilePaused(address replacement) public {
        vm.assume(replacement != address(0) && replacement != MANAGER);
        _assumeNotProxyAdmin(replacement);

        vm.prank(ORACLE_ADMIN);
        oracle.revokeProtocolManager(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.pause();
        vm.prank(ORACLE_ADMIN);
        oracle.proposeProtocolManagerReplacement(PROJECT_ID, replacement);
        vm.prank(replacement);
        oracle.acceptProtocolManagerTransfer(PROJECT_ID);

        (address manager,, uint64 limit, uint64 used,, StateOracleV2.ProjectStatus status) = oracle.projects(PROJECT_ID);
        assertEq(manager, replacement);
        assertEq(limit, 100);
        assertEq(used, INSTALLED_UNITS);
        assertEq(uint8(status), uint8(StateOracleV2.ProjectStatus.Active));
        assertTrue(oracle.hasAssertion(adopter, ASSERTION_ID));

        vm.prank(replacement);
        oracle.removeAssertion(adopter, ASSERTION_ID);
        vm.prank(replacement);
        oracle.detachAssertionAdopter(adopter);
        (bytes32 projectId,,) = oracle.assertionAdopters(adopter);
        assertEq(projectId, bytes32(0));
    }

    function testFuzz_adopterCanMoveOnlyAfterEveryAssertionIsRemoved(address newManager) public {
        vm.assume(newManager != address(0) && newManager != MANAGER);
        _assumeNotProxyAdmin(newManager);
        vm.prank(ORACLE_ADMIN);
        oracle.createProject(SECOND_PROJECT_ID, newManager);

        vm.prank(MANAGER);
        vm.expectRevert(StateOracleV2.AssertionAdopterHasAssertions.selector);
        oracle.detachAssertionAdopter(adopter);
        vm.prank(MANAGER);
        oracle.removeAssertion(adopter, ASSERTION_ID);
        vm.prank(MANAGER);
        oracle.detachAssertionAdopter(adopter);

        _assign(SECOND_PROJECT_ID, newManager);
        (bytes32 projectId,, uint32 assertionCount) = oracle.assertionAdopters(adopter);
        assertEq(projectId, SECOND_PROJECT_ID);
        assertEq(assertionCount, 0);
    }

    function testFuzz_retiredProjectPendingRegistrationCanBeRejectedByAnyone(address cleanupCaller) public {
        _assumeNotProxyAdmin(cleanupCaller);
        address pendingAdopter = address(new OwnableAdopter(ADOPTER_ADMIN));
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(pendingAdopter, PROJECT_ID, adminVerifier, "");
        vm.prank(MANAGER);
        oracle.detachAssertionAdopter(adopter);
        vm.prank(MANAGER);
        oracle.requestProjectRetirement(PROJECT_ID);
        vm.prank(ORACLE_ADMIN);
        oracle.finalizeProjectRetirement(PROJECT_ID);

        vm.prank(cleanupCaller);
        oracle.rejectAssertionAdopterRegistration(pendingAdopter);
        (, bytes32 pendingProjectId,) = oracle.assertionAdopters(pendingAdopter);
        assertEq(pendingProjectId, bytes32(0));
    }

    function testFuzz_triggerUnitsAreConservedOnAdmission(uint64 unitsSeed) public {
        uint64 units = (unitsSeed % 100) + 1;
        _add(MANAGER, ASSERTION_ID, units);

        (,,, uint64 used,,) = oracle.projects(PROJECT_ID);
        (,, uint32 assertionCount) = oracle.assertionAdopters(adopter);
        (uint64 installedUnits,,, bool enabled) = oracle.assertions(adopter, ASSERTION_ID);
        assertEq(used, units);
        assertEq(assertionCount, 1);
        assertEq(installedUnits, units);
        assertTrue(enabled);
    }

    function _assign(bytes32 projectId, address manager) private {
        vm.prank(ADOPTER_ADMIN);
        oracle.registerAssertionAdopter(adopter, projectId, adminVerifier, "");
        vm.prank(manager);
        oracle.acceptAssertionAdopter(adopter);
    }

    function _setLimit(bytes32 projectId, uint64 limit) private {
        vm.prank(ORACLE_ADMIN);
        oracle.setProjectTriggerLimit(projectId, limit);
    }

    function _add(address manager, bytes32 assertionId, uint64 units) private {
        StateOracleV2.AssertionArtifact memory artifact = StateOracleV2.AssertionArtifact({
            deploymentCodeHash: assertionId,
            triggerManifest: StateOracleV2.TriggerManifest({
                schemaId: manifestValidator.SCHEMA_ID(), data: abi.encode(units)
            })
        });
        vm.prank(manager);
        oracle.addAssertion(adopter, artifact, StateOracleV2.DAProof({verifier: daVerifier, metadata: "", proof: ""}));
    }

    function _assumeNotProxyAdmin(address account) private view {
        // forge-lint: disable-next-line(unsafe-typecast)
        address actualProxyAdmin = address(uint160(uint256(vm.load(address(oracle), ERC1967Utils.ADMIN_SLOT))));
        vm.assume(account != PROXY_ADMIN && account != actualProxyAdmin);
    }
}
