// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {StateOracle} from "../src/StateOracle.sol";
import {Adopter, OwnableAdopter} from "./utils/Adopter.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";
import {ProxyHelper} from "./utils/ProxyHelper.t.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {AdminVerifierRegistry} from "../src/lib/AdminVerifierRegistry.sol";

contract StateOracleBase is Test, ProxyHelper {
    address constant OWNER = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.OWNER")))));
    address constant DEPLOYER = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.DEPLOYER")))));
    uint128 constant TIMEOUT = 1000;
    uint32 constant MAX_ASSERTIONS_PER_AA = 5;
    StateOracle stateOracle;
    IAdminVerifier adminVerifier;

    /// @notice Emitted when a new assertion adopter is registered
    /// @param contractAddress The address of the registered contract
    /// @param manager The address authorized to manage the contract's assertions
    /// @param adminVerifier The admin verifier used to register the assertion adopter
    event AssertionAdopterAdded(address indexed contractAddress, address indexed manager, IAdminVerifier adminVerifier);

    /// @notice Emitted when a new assertion is added
    /// @param assertionAdopter The assertion adopter the assertion is associated with
    /// @param assertionId The unique identifier of the assertion
    /// @param activationBlock The block number when the assertion becomes active
    event AssertionAdded(address assertionAdopter, bytes32 assertionId, uint256 activationBlock);

    /// @notice Emitted when an assertion is removed
    /// @param assertionAdopter The assertion adopter where the assertion is removed from
    /// @param assertionId The unique identifier of the removed assertion
    /// @param deactivationBlock The block number when the assertion is going to be inactive
    event AssertionRemoved(address assertionAdopter, bytes32 assertionId, uint256 deactivationBlock);

    /// @notice Modifier to ensure the address is not the proxy admin
    /// @param _address The address to check
    /// @dev This is needed because proxy admin calls will be processed internally
    modifier noAdmin(address _address) {
        vm.assume(_address != getProxyAdmin(address(stateOracle)));
        _;
    }

    function setUp() public virtual {
        DAVerifierMock daVerifier = new DAVerifierMock();
        StateOracle implementation = new StateOracle(TIMEOUT, address(daVerifier), MAX_ASSERTIONS_PER_AA);
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        IAdminVerifier[] memory verifiers = new IAdminVerifier[](1);
        verifiers[0] = adminVerifier;

        bytes memory data = abi.encodeWithSelector(StateOracle.initialize.selector, OWNER, verifiers);
        stateOracle = StateOracle(deployProxy(address(implementation), data));
    }

    function registerAssertionAdopter() internal returns (address, address) {
        address manager = OWNER;
        vm.assume(manager != getProxyAdmin(address(stateOracle)));

        vm.startPrank(manager);
        OwnableAdopter adopter = new OwnableAdopter(manager);
        stateOracle.registerAssertionAdopter(address(adopter), adminVerifier, new bytes(0));
        vm.stopPrank();

        assertTrue(stateOracle.getManager(address(adopter)) == manager, "Manager mismatch");
        return (address(adopter), manager);
    }

    function addAssertionAndAssert(address manager, address adopter, bytes32 assertionId) internal noAdmin(manager) {
        vm.prank(manager);
        stateOracle.addAssertion(adopter, assertionId, new bytes(0), new bytes(0));

        assertTrue(stateOracle.hasAssertion(adopter, assertionId), "Assertion not found");
        (uint128 activationBlock, uint128 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(
            activationBlock,
            uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS(),
            "Activation block mismatch"
        );
        assertEq(deactivationBlock, uint128(0), "Deactivation block mismatch");
    }
}

contract Constructor is StateOracleBase {
    function test_assertionTimelockZero() public {
        DAVerifierMock daVerifier = new DAVerifierMock();
        vm.expectRevert(StateOracle.InvalidAssertionTimelock.selector);
        new StateOracle(0, address(daVerifier), MAX_ASSERTIONS_PER_AA);
    }
}

contract Initialize is StateOracleBase {
    function test_RevertIf_alreadyInitialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        stateOracle.initialize(OWNER, new IAdminVerifier[](0));
    }

    function test_initializeNonProxy() public {
        DAVerifierMock daVerifier = new DAVerifierMock();
        stateOracle = new StateOracle(TIMEOUT, address(daVerifier), MAX_ASSERTIONS_PER_AA);
        assertEq(stateOracle.owner(), address(0), "Owner should be address(0)");
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        IAdminVerifier[] memory verifiers = new IAdminVerifier[](1);
        verifiers[0] = adminVerifier;
        stateOracle.initialize(ADMIN, verifiers);
        assertEq(stateOracle.owner(), ADMIN, "Owner should be ADMIN");
        assertEq(stateOracle.adminVerifiers(adminVerifier), true, "Admin verifier should be added");
    }
}

contract Register is StateOracleBase {
    function test_registerByOwner() public {
        OwnableAdopter adopter = new OwnableAdopter(OWNER);

        vm.prank(OWNER);
        stateOracle.registerAssertionAdopter(address(adopter), adminVerifier, new bytes(0));
        assertEq(stateOracle.getManager(address(adopter)), OWNER, "Manager mismatch");
    }

    function testFuzz_RevertIf_registerByUnauthorized(address unauthorizedRegistrant)
        public
        noAdmin(unauthorizedRegistrant)
    {
        vm.assume(unauthorizedRegistrant != OWNER);
        OwnableAdopter adopter = new OwnableAdopter(OWNER);

        vm.prank(unauthorizedRegistrant);
        vm.expectRevert(StateOracle.UnauthorizedRegistrant.selector);
        stateOracle.registerAssertionAdopter(address(adopter), adminVerifier, new bytes(0));

        vm.assertEq(stateOracle.getManager(address(adopter)), address(0), "Manager should be address(0)");
    }

    function test_RevertIf_registerAssertionAdopterTwice() public {
        (address adopter, address manager) = registerAssertionAdopter();

        vm.prank(manager);
        vm.expectRevert(StateOracle.AssertionAdopterAlreadyRegistered.selector);
        stateOracle.registerAssertionAdopter(adopter, adminVerifier, new bytes(0));
    }

    function test_expectAssertionAdopterAdded() public {
        // Doesn't check adopter, checks only topic2: manager and emitting address
        vm.expectEmit(false, true, false, false, address(stateOracle));
        emit AssertionAdopterAdded(address(1), OWNER, IAdminVerifier(adminVerifier));
        registerAssertionAdopter();
    }

    function testFuzz_RevertIf_registerAssertionAdopterAdminVerifierNotAdded() public {
        IAdminVerifier _adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        vm.prank(OWNER);
        vm.expectRevert(AdminVerifierRegistry.AdminVerifierNotRegistered.selector);
        stateOracle.registerAssertionAdopter(address(1), _adminVerifier, new bytes(0));
    }
}

contract AddAssertion is StateOracleBase {
    function testFuzz_addAssertion(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId);
    }

    function testFuzz_RevertIf_addAssertionByUnauthorized(bytes32 assertionId, address unauthorizedManager)
        public
        noAdmin(unauthorizedManager)
    {
        (address adopter, address manager) = registerAssertionAdopter();

        vm.assume(unauthorizedManager != manager);
        vm.prank(unauthorizedManager);
        vm.expectRevert(StateOracle.UnauthorizedManager.selector);
        stateOracle.addAssertion(adopter, assertionId, new bytes(0), new bytes(0));
    }

    function testFuzz_RevertIf_addDuplicateAssertion(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId);

        vm.prank(manager);
        vm.expectRevert(StateOracle.AssertionAlreadyExists.selector);
        stateOracle.addAssertion(adopter, assertionId, new bytes(0), new bytes(0));
    }

    function testFuzz_addMultipleAssertions(bytes32 assertionId1, bytes32 assertionId2) public {
        vm.assume(assertionId1 != assertionId2);
        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId1);
        addAssertionAndAssert(manager, adopter, assertionId2);
    }

    function testFuzz_RevertIf_addAssertionNotRegistered(address adopter, bytes32 assertionId) public {
        vm.prank(address(1));
        vm.expectRevert(StateOracle.AssertionAdopterNotRegistered.selector);
        stateOracle.addAssertion(adopter, assertionId, new bytes(0), new bytes(0));
    }

    function testFuzz_expectAssertionAdded(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();
        uint128 activationBlock = uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS();
        // Check topic1: adopter, topic2: assertionId, data: activationBlock and emitting address
        vm.expectEmit(true, true, false, true, address(stateOracle));
        emit AssertionAdded(adopter, assertionId, activationBlock);
        addAssertionAndAssert(manager, adopter, assertionId);
    }

    function testFuzz_addTooManyAssertions(bytes32 assertionId) public {
        vm.assume(uint256(assertionId) >= uint256(MAX_ASSERTIONS_PER_AA));
        (address adopter, address manager) = registerAssertionAdopter();
        for (uint32 i = 0; i < MAX_ASSERTIONS_PER_AA; i++) {
            addAssertionAndAssert(manager, adopter, bytes32(uint256(i)));
        }
        vm.startPrank(manager);
        vm.expectRevert(StateOracle.TooManyAssertions.selector);
        stateOracle.addAssertion(adopter, assertionId, new bytes(0), new bytes(0));
        stateOracle.removeAssertion(adopter, bytes32(uint256(MAX_ASSERTIONS_PER_AA - 1)));
        vm.stopPrank();

        addAssertionAndAssert(manager, adopter, assertionId);
    }
}

contract RemoveAssertion is StateOracleBase {
    function testFuzz_removeAssertion(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId);
        (uint128 activationBlockBefore,) = stateOracle.getAssertionWindow(adopter, assertionId);

        vm.roll(block.number + 1);

        vm.prank(manager);
        stateOracle.removeAssertion(adopter, assertionId);
        (uint128 activationBlock, uint128 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(activationBlock, activationBlockBefore, "Activation should not change");
        assertEq(
            deactivationBlock,
            uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS(),
            "Deactivation block mismatch"
        );
    }

    function testFuzz_removeAssertionByAdmin(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId);
        (uint128 activationBlockBefore,) = stateOracle.getAssertionWindow(adopter, assertionId);

        vm.roll(block.number + 1);

        vm.prank(stateOracle.owner());
        stateOracle.removeAssertionByOwner(adopter, assertionId);
        (uint128 activationBlock, uint128 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(activationBlock, activationBlockBefore, "Activation should not change");
        assertEq(
            deactivationBlock,
            uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS(),
            "Deactivation block mismatch"
        );
    }

    function testFuzz_RevertIf_removeAssertionByUnauthorizedAdmin(bytes32 assertionId, address unauthorizedAdmin)
        public
        noAdmin(unauthorizedAdmin)
    {
        vm.assume(unauthorizedAdmin != stateOracle.owner());

        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId);

        vm.prank(unauthorizedAdmin);
        vm.expectRevert(Ownable.Unauthorized.selector);
        stateOracle.removeAssertionByOwner(adopter, assertionId);
    }

    function testFuzz_RevertIf_removeAssertionByUnauthorized(bytes32 assertionId, address unauthorizedManager)
        public
        noAdmin(unauthorizedManager)
    {
        (address adopter, address manager) = registerAssertionAdopter();
        vm.assume(unauthorizedManager != manager);
        addAssertionAndAssert(manager, adopter, assertionId);

        vm.prank(unauthorizedManager);
        vm.expectRevert(StateOracle.UnauthorizedManager.selector);
        stateOracle.removeAssertion(adopter, assertionId);
    }

    function testFuzz_RevertIf_removeNonExistentAssertion(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();

        vm.prank(manager);
        vm.expectRevert(StateOracle.AssertionDoesNotExist.selector);
        stateOracle.removeAssertion(adopter, assertionId);
    }

    function test_expectAssertionRemoved(bytes32 assertionId) public {
        (address adopter, address manager) = registerAssertionAdopter();
        addAssertionAndAssert(manager, adopter, assertionId);

        vm.roll(block.number + 1);

        uint128 deactivationBlock = uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS();
        // Check topic1: adopter, topic2: assertionId, data: deactivationBlock and emitting address
        vm.expectEmit(true, true, false, true, address(stateOracle));
        emit AssertionRemoved(adopter, assertionId, deactivationBlock);

        vm.prank(manager);
        stateOracle.removeAssertion(adopter, assertionId);
    }
}

contract TransferManagementBase is StateOracleBase {
    function transferManagerAndAssert(address adopter, address manager, address newManager)
        internal
        noAdmin(newManager)
    {
        vm.prank(manager);
        stateOracle.transferManager(adopter, newManager);
        assertEq(stateOracle.getManager(adopter), manager, "Manager mismatch");
        assertEq(stateOracle.getPendingManager(adopter), newManager, "New manager should still be pending");
    }
}

contract TransferManager is TransferManagementBase {
    function testFuzz_transferManager(address newManager) public noAdmin(newManager) {
        vm.assume(newManager != address(0));
        (address adopter, address manager) = registerAssertionAdopter();
        transferManagerAndAssert(adopter, manager, newManager);
    }

    function testFuzz_RevertIf_transferManagerByUnauthorized(address newManager, address unauthorizedManager)
        public
        noAdmin(newManager)
        noAdmin(unauthorizedManager)
    {
        vm.assume(newManager != address(0));
        vm.assume(unauthorizedManager != newManager);
        (address adopter, address manager) = registerAssertionAdopter();
        vm.assume(unauthorizedManager != manager);
        vm.assume(unauthorizedManager != newManager);

        vm.startPrank(unauthorizedManager);
        // Unauthorized manager cannot accept transfer before anything was requested
        vm.expectRevert(StateOracle.NoPendingManager.selector);
        stateOracle.acceptManagerTransfer(adopter);
        // Unauthorized manager cannot transfer manager
        vm.expectRevert(StateOracle.UnauthorizedManager.selector);
        stateOracle.transferManager(adopter, newManager);
        vm.stopPrank();

        vm.startPrank(manager);
        // Even manager cannot accept transfer before anything was requested
        vm.expectRevert(StateOracle.NoPendingManager.selector);
        stateOracle.acceptManagerTransfer(adopter);
        // Request management transfer
        stateOracle.transferManager(adopter, newManager);
        vm.stopPrank();

        // Assert that new manager is pending
        assertEq(stateOracle.getManager(adopter), manager, "Manager should not have changed");
        assertEq(stateOracle.getPendingManager(adopter), newManager, "New manager should be pending");

        vm.prank(unauthorizedManager);
        // Unauthorized manager cannot accept transfer
        vm.expectRevert(StateOracle.UnauthorizedManager.selector);
        stateOracle.acceptManagerTransfer(adopter);

        vm.prank(newManager);
        // Finally new manager can still accept transfer
        stateOracle.acceptManagerTransfer(adopter);
        assertEq(stateOracle.getManager(adopter), newManager, "Manager should have been transferred to newManager");
        assertEq(stateOracle.getPendingManager(adopter), address(0), "Pending manager should be reset");
    }

    function test_RevertIf_transferManagerToZeroAddress() public {
        (address adopter, address manager) = registerAssertionAdopter();

        vm.prank(manager);
        vm.expectRevert(StateOracle.InvalidManagerTransferRequest.selector);
        stateOracle.transferManager(adopter, address(0));

        assertEq(stateOracle.getManager(adopter), manager, "Manager should not have changed");
        assertEq(stateOracle.getPendingManager(adopter), address(0), "Pending manager should still be address(0)");
    }

    function testFuzz_changePendingManager(address newManager, address newManager2)
        public
        noAdmin(newManager)
        noAdmin(newManager2)
    {
        vm.assume(newManager != address(0));
        vm.assume(newManager2 != address(0));
        vm.assume(newManager != newManager2);
        (address adopter, address manager) = registerAssertionAdopter();
        transferManagerAndAssert(adopter, manager, newManager);

        vm.prank(manager);
        stateOracle.transferManager(adopter, newManager2);
        assertEq(stateOracle.getPendingManager(adopter), newManager2, "newManager2 should be pending");

        vm.prank(newManager);
        vm.expectRevert(StateOracle.UnauthorizedManager.selector);
        stateOracle.acceptManagerTransfer(adopter);

        vm.prank(newManager2);
        stateOracle.acceptManagerTransfer(adopter);
        assertEq(stateOracle.getManager(adopter), newManager2, "Manager should have been transferred to newManager2");
        assertEq(stateOracle.getPendingManager(adopter), address(0), "Pending manager should be reset");
    }
}

contract AcceptManagerTransfer is TransferManagementBase {
    function testFuzz_acceptManagerTransfer(address newManager) public noAdmin(newManager) {
        vm.assume(newManager != address(0));
        (address adopter, address manager) = registerAssertionAdopter();
        transferManagerAndAssert(adopter, manager, newManager);

        vm.prank(newManager);
        stateOracle.acceptManagerTransfer(adopter);
        assertEq(stateOracle.getManager(adopter), newManager, "Manager should have been transferred to newManager");
        assertEq(stateOracle.getPendingManager(adopter), address(0), "Pending manager should be reset");
    }

    function test_RevertIf_NoPendingManager() public {
        (address adopter, address manager) = registerAssertionAdopter();

        vm.prank(manager);
        vm.expectRevert(StateOracle.NoPendingManager.selector);
        stateOracle.acceptManagerTransfer(adopter);

        assertEq(stateOracle.getManager(adopter), manager, "Manager should not have changed");
        assertEq(stateOracle.getPendingManager(adopter), address(0), "Pending manager should still be address(0)");
    }
}

contract RevokeManager is TransferManagementBase {
    function testFuzz_revokeManager(address newManager) public noAdmin(newManager) {
        vm.assume(newManager != address(0));
        (address adopter, address manager) = registerAssertionAdopter();
        transferManagerAndAssert(adopter, manager, newManager);
        vm.prank(stateOracle.owner());
        stateOracle.revokeManager(adopter);
        assertEq(stateOracle.getManager(adopter), address(0), "Manager should have been revoked");
        assertEq(stateOracle.getPendingManager(adopter), address(0), "Pending manager should have been reset");
    }

    function testFuzz_RevertIf_revokeManagerByUnauthorized(address unauthorizedManager)
        public
        noAdmin(unauthorizedManager)
    {
        vm.assume(unauthorizedManager != stateOracle.owner());
        (address adopter,) = registerAssertionAdopter();
        vm.prank(unauthorizedManager);
        vm.expectRevert(Ownable.Unauthorized.selector);
        stateOracle.revokeManager(adopter);
    }

    function test_RevertIf_revokeManagerOfNonExistentAdopter() public {
        OwnableAdopter adopter = new OwnableAdopter(OWNER);
        assertEq(stateOracle.getManager(address(adopter)), address(0), "Manager should be address(0)");
        vm.prank(stateOracle.owner());
        vm.expectRevert(StateOracle.AssertionAdopterNotRegistered.selector);
        stateOracle.revokeManager(address(adopter));
    }
}

contract AddAdminVerifier is StateOracleBase {
    function test_addAdminVerifier(IAdminVerifier _adminVerifier) public {
        vm.assume(_adminVerifier != adminVerifier);
        assertEq(stateOracle.adminVerifiers(_adminVerifier), false, "Admin verifier should not have been added");
        vm.prank(OWNER);
        stateOracle.addAdminVerifier(_adminVerifier);
        assertEq(stateOracle.adminVerifiers(_adminVerifier), true, "Admin verifier should be added");
    }

    function testFuzz_RevertIf_addAdminVerifierByUnauthorized(address unauthorizedAdmin)
        public
        noAdmin(unauthorizedAdmin)
    {
        vm.assume(unauthorizedAdmin != stateOracle.owner());
        IAdminVerifier _adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        vm.prank(unauthorizedAdmin);
        vm.expectRevert(Ownable.Unauthorized.selector);
        stateOracle.addAdminVerifier(_adminVerifier);
    }

    function testFuzz_RevertIf_addAdminVerifierTwice(IAdminVerifier _adminVerifier) public {
        vm.assume(_adminVerifier != adminVerifier);
        vm.startPrank(OWNER);
        stateOracle.addAdminVerifier(_adminVerifier);
        vm.expectRevert(AdminVerifierRegistry.AdminVerifierAlreadyRegistered.selector);
        stateOracle.addAdminVerifier(_adminVerifier);
        vm.stopPrank();
    }
}

contract RemoveAdminVerifier is StateOracleBase {
    function test_removeAdminVerifier() public {
        IAdminVerifier _adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        vm.startPrank(OWNER);
        stateOracle.addAdminVerifier(_adminVerifier);
        assertEq(stateOracle.adminVerifiers(_adminVerifier), true, "Admin verifier should have been added");
        stateOracle.removeAdminVerifier(_adminVerifier);
        vm.stopPrank();
        assertEq(stateOracle.adminVerifiers(_adminVerifier), false, "Admin verifier should have been removed");
    }

    function testFuzz_RevertIf_removeAdminVerifierByUnauthorized(address unauthorizedAdmin)
        public
        noAdmin(unauthorizedAdmin)
    {
        vm.assume(unauthorizedAdmin != stateOracle.owner());
        IAdminVerifier _adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        vm.prank(OWNER);
        stateOracle.addAdminVerifier(_adminVerifier);
        assertEq(stateOracle.adminVerifiers(_adminVerifier), true, "Admin verifier should have been added");
        vm.prank(unauthorizedAdmin);
        vm.expectRevert(Ownable.Unauthorized.selector);
        stateOracle.removeAdminVerifier(_adminVerifier);
    }

    function testFuzz_RevertIf_removeAdminVerifierNotRegistered(IAdminVerifier _adminVerifier) public {
        vm.assume(_adminVerifier != adminVerifier);
        vm.prank(OWNER);
        vm.expectRevert(AdminVerifierRegistry.AdminVerifierNotRegistered.selector);
        stateOracle.removeAdminVerifier(_adminVerifier);
    }
}

contract Batch is StateOracleBase {
    function test_batch(bytes32 assertionId1, bytes32 assertionId2) public {
        vm.assume(assertionId1 != assertionId2);

        address adopter = address(new OwnableAdopter(OWNER));

        bytes[] memory calls = new bytes[](3);
        calls[0] =
            abi.encodeWithSelector(StateOracle.registerAssertionAdopter.selector, adopter, adminVerifier, new bytes(0));
        calls[1] =
            abi.encodeWithSelector(StateOracle.addAssertion.selector, adopter, assertionId1, new bytes(0), new bytes(0));
        calls[2] =
            abi.encodeWithSelector(StateOracle.addAssertion.selector, adopter, assertionId2, new bytes(0), new bytes(0));

        vm.prank(OWNER);
        stateOracle.batch(calls);

        assertEq(stateOracle.hasAssertion(adopter, assertionId1), true, "Assertion 1 should have been added");
        assertEq(stateOracle.hasAssertion(adopter, assertionId2), true, "Assertion 2 should have been added");

        calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(StateOracle.removeAssertion.selector, adopter, assertionId1);
        calls[1] = abi.encodeWithSelector(StateOracle.removeAssertion.selector, adopter, assertionId2);

        vm.prank(OWNER);
        stateOracle.batch(calls);

        (, uint128 deactivationBlock1) = stateOracle.getAssertionWindow(adopter, assertionId1);
        (, uint128 deactivationBlock2) = stateOracle.getAssertionWindow(adopter, assertionId2);

        assertTrue(deactivationBlock1 != 0, "Assertion 1 should have been removed");
        assertTrue(deactivationBlock2 != 0, "Assertion 2 should have been removed");
    }
}
