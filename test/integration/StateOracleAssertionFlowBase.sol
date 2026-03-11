// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StateOracle} from "../../src/StateOracle.sol";
import {IAdminVerifier} from "../../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";
import {ProxyHelper} from "../utils/ProxyHelper.t.sol";

/// @title StateOracleAssertionFlowBase
/// @notice Abstract base contract for integration tests covering all AdminVerifier x DAVerifier combinations
/// @dev Concrete implementations override verifier deployment and proof generation functions.
///      All assertion flow tests are defined here and automatically run for each concrete contract.
abstract contract StateOracleAssertionFlowBase is Test, ProxyHelper {
    StateOracle stateOracle;
    IAdminVerifier adminVerifier;
    IDAVerifier daVerifier;
    address adopter;
    address manager;

    uint128 constant TIMEOUT = 100;
    uint16 constant MAX_ASSERTIONS_PER_AA = 5;
    address constant STATE_ORACLE_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.STATE_ORACLE_ADMIN")))));

    /// @notice Modifier to ensure the address is not the proxy admin
    modifier noAdmin(address _address) {
        vm.assume(_address != getProxyAdmin(address(stateOracle)));
        _;
    }

    // -- Abstract functions that concrete contracts implement --

    /// @notice Deploy the admin verifier for this test combination
    function _deployAdminVerifier() internal virtual returns (IAdminVerifier);

    /// @notice Deploy the DA verifier for this test combination
    function _deployDAVerifier() internal virtual returns (IDAVerifier);

    /// @notice Register an adopter with verifier-specific setup (e.g., whitelist entries)
    /// @param contractAddress The adopter contract address
    /// @param admin The admin address for the adopter
    function _registerAdopter(address contractAddress, address admin) internal virtual;

    /// @notice Generate a valid (assertionId, metadata, proof) tuple from a seed
    /// @dev For ECDSA: assertionId = seed, sign it. For OnChain: proof = abi.encode(seed), assertionId = keccak256(proof)
    function _generateValidAssertion(bytes32 seed)
        internal
        virtual
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof);

    /// @notice Generate an invalid (assertionId, metadata, proof) tuple from a seed
    function _generateInvalidAssertion(bytes32 seed)
        internal
        virtual
        returns (bytes32 assertionId, bytes memory metadata, bytes memory proof);

    function setUp() public virtual {
        adminVerifier = _deployAdminVerifier();
        daVerifier = _deployDAVerifier();

        StateOracle implementation = new StateOracle(TIMEOUT);
        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](1);
        adminVerifiers[0] = adminVerifier;
        IDAVerifier[] memory daVerifiers = new IDAVerifier[](1);
        daVerifiers[0] = daVerifier;

        bytes memory data = abi.encodeWithSelector(
            StateOracle.initialize.selector, STATE_ORACLE_ADMIN, adminVerifiers, daVerifiers, MAX_ASSERTIONS_PER_AA
        );
        stateOracle = StateOracle(deployProxy(address(implementation), data));

        // Disable whitelist for integration tests
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.disableWhitelist();

        // Deploy adopter and register via verifier-specific logic
        manager = address(uint160(uint256(keccak256(abi.encode("pcl.test.integration.MANAGER")))));
        _registerAdopter(adopter, manager);
    }

    // -- Test methods (run for ALL 4 concrete contracts) --

    function test_addAssertionWithValidProof() public {
        (bytes32 assertionId, bytes memory metadata, bytes memory proof) =
            _generateValidAssertion(bytes32(uint256(0xCAFE)));

        vm.prank(manager);
        stateOracle.addAssertion(adopter, assertionId, daVerifier, metadata, proof);

        assertTrue(stateOracle.hasAssertion(adopter, assertionId), "Assertion should be added");
        (uint256 activationBlock, uint256 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(
            activationBlock, block.number + stateOracle.ASSERTION_TIMELOCK_BLOCKS(), "Activation mismatch"
        );
        assertEq(deactivationBlock, 0, "Deactivation should be 0");
    }

    function test_RevertIf_addAssertionWithInvalidProof() public {
        (bytes32 assertionId, bytes memory metadata, bytes memory proof) =
            _generateInvalidAssertion(bytes32(uint256(0xBAD)));

        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(StateOracle.InvalidDAProof.selector, daVerifier));
        stateOracle.addAssertion(adopter, assertionId, daVerifier, metadata, proof);
    }

    function test_addAndRemoveAssertion() public {
        (bytes32 assertionId, bytes memory metadata, bytes memory proof) =
            _generateValidAssertion(bytes32(uint256(0x1111)));

        vm.prank(manager);
        stateOracle.addAssertion(adopter, assertionId, daVerifier, metadata, proof);

        assertTrue(stateOracle.hasAssertion(adopter, assertionId), "Assertion should exist after add");
        (uint256 activationBlock,) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(
            activationBlock, block.number + stateOracle.ASSERTION_TIMELOCK_BLOCKS(), "Activation mismatch"
        );

        vm.roll(block.number + 1);

        vm.prank(manager);
        stateOracle.removeAssertion(adopter, assertionId);

        (, uint256 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
        assertEq(
            deactivationBlock,
            block.number + stateOracle.ASSERTION_TIMELOCK_BLOCKS(),
            "Deactivation block mismatch"
        );
    }

    function test_addMultipleAssertions() public {
        (bytes32 id1, bytes memory meta1, bytes memory proof1) = _generateValidAssertion(bytes32(uint256(1)));
        (bytes32 id2, bytes memory meta2, bytes memory proof2) = _generateValidAssertion(bytes32(uint256(2)));

        vm.startPrank(manager);
        stateOracle.addAssertion(adopter, id1, daVerifier, meta1, proof1);
        stateOracle.addAssertion(adopter, id2, daVerifier, meta2, proof2);
        vm.stopPrank();

        assertTrue(stateOracle.hasAssertion(adopter, id1), "Assertion 1 should exist");
        assertTrue(stateOracle.hasAssertion(adopter, id2), "Assertion 2 should exist");
        assertEq(stateOracle.getAssertionCount(adopter), 2, "Should have 2 assertions");
    }

    function testFuzz_addAssertionWithValidProof(bytes32 seed) public {
        (bytes32 assertionId, bytes memory metadata, bytes memory proof) = _generateValidAssertion(seed);

        vm.prank(manager);
        stateOracle.addAssertion(adopter, assertionId, daVerifier, metadata, proof);

        assertTrue(stateOracle.hasAssertion(adopter, assertionId), "Assertion should be added");
    }

    function test_assertionAddedEventEmitted() public {
        (bytes32 assertionId, bytes memory metadata, bytes memory proof) =
            _generateValidAssertion(bytes32(uint256(0xE1E1)));

        uint256 activationBlock = uint256(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS();

        // Check topic1: adopter, topic2: assertionId, topic3: daVerifier, data: activationBlock, metadata, proof
        vm.expectEmit(true, true, true, true, address(stateOracle));
        emit StateOracle.AssertionAdded(adopter, assertionId, activationBlock, daVerifier, metadata, proof);

        vm.prank(manager);
        stateOracle.addAssertion(adopter, assertionId, daVerifier, metadata, proof);
    }
}
