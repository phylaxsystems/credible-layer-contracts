// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IDAVerifier} from "./interfaces/IDAVerifier.sol";
import {IAdminVerifier} from "./interfaces/IAdminVerifier.sol";
import {Batch} from "./Batch.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {AdminVerifierRegistry} from "./lib/AdminVerifierRegistry.sol";

/// @title StateOracle
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Manages assertion adopters and their assertions
/// @dev Provides functionality to register assertion adopters and manage their assertions

contract StateOracle is Batch, Ownable, Initializable {
    using AdminVerifierRegistry for mapping(IAdminVerifier adminVerifier => bool isRegistered);

    /// @notice Number of blocks to wait before an assertion becomes active or inactive
    uint128 public immutable ASSERTION_TIMELOCK_BLOCKS;

    /// @notice The DA verifier
    IDAVerifier public immutable DA_VERIFIER;

    /// @notice Thrown when an unauthorized address attempts to register an assertion adopter
    error UnauthorizedRegistrant();
    /// @notice Thrown when an unauthorized address attempts to manage assertions
    error UnauthorizedManager();
    /// @notice Thrown when attempting to transfer management to an invalid address
    error InvalidManagerTransferRequest();
    /// @notice Thrown when attempting to accept management when no transfer is pending
    error NoPendingManager();
    /// @notice Thrown when attempting to register an assertion adopter that is already registered
    error AssertionAdopterAlreadyRegistered();
    /// @notice Thrown when attempting to interact with an unregistered assertion adopter
    error AssertionAdopterNotRegistered();
    /// @notice Thrown when attempting to add an assertion that already exists
    error AssertionAlreadyExists();
    /// @notice Thrown when attempting to remove or modify a non-existent assertion
    error AssertionDoesNotExist();
    /// @notice Thrown when the provided proof is invalid
    error InvalidProof();
    /// @notice Thrown when attempting to set an invalid assertion timelock value
    error InvalidAssertionTimelock();
    /// @notice Thrown when attempting to add more assertions than the maximum allowed
    error TooManyAssertions();

    /// @notice Struct containing assertion adopter data
    /// @param manager Address authorized to manage assertions
    /// @param assertions Mapping of assertion IDs to assertion windows, describing the assertion's lifecycle
    struct AssertionAdopter {
        address manager;
        address pendingManager;
        uint32 assertionCount;
        mapping(bytes32 assertionId => AssertionWindow assertionWindow) assertions;
    }

    /// @notice Struct containing the assertion time window
    /// @param activationBlock Block number when the assertion becomes active
    /// @param deactivationBlock Block number when the assertion becomes inactive
    struct AssertionWindow {
        uint128 activationBlock;
        uint128 deactivationBlock;
    }

    /// @notice Emitted when a new assertion adopter is registered
    /// @param contractAddress The address of the registered contract
    /// @param manager The address authorized to manage the contract's assertions
    /// @param adminVerifier The admin verifier used to register the assertion adopter
    event AssertionAdopterAdded(address indexed contractAddress, address indexed manager, IAdminVerifier adminVerifier);

    /// @notice Emitted when a manager transfer is requested
    /// @param contractAddress The address of the contract
    /// @param manager The address requesting the transfer
    /// @param newManager The address being requested to manage the contract
    event ManagerTransferRequested(
        address indexed contractAddress, address indexed manager, address indexed newManager
    );

    /// @notice Emitted when a manager transfer is accepted
    /// @param contractAddress The address of the contract
    /// @param newManager The address accepting the transfer
    event ManagerTransferred(address indexed contractAddress, address indexed newManager);

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

    /// @notice Maximum number of assertions per assertion adopter
    uint128 public maxAssertionsPerAA;

    /// @notice Maps contract addresses to their assertion adopter data
    mapping(address => AssertionAdopter) public assertionAdopters;

    /// @notice The admin verification registry
    mapping(IAdminVerifier adminVerifier => bool isRegistered) public adminVerifiers;

    /// @notice Ensures caller is the manager of the contract
    /// @param contractAddress The address of the contract being managed
    modifier onlyManager(address contractAddress) {
        _onlyManager(contractAddress);
        _;
    }

    /// @notice Internal function to ensure caller is the manager of the contract
    /// @param contractAddress The address of the contract being managed
    function _onlyManager(address contractAddress) internal view {
        require(assertionAdopters[contractAddress].manager != address(0), AssertionAdopterNotRegistered());
        require(assertionAdopters[contractAddress].manager == msg.sender, UnauthorizedManager());
    }

    /// @notice Initializes the contract with a timelock period
    /// @param assertionTimelockBlocks Number of blocks to wait before assertions become active/inactive
    /// @param daVerifier The address of the DA verifier
    constructor(uint128 assertionTimelockBlocks, address daVerifier) {
        require(assertionTimelockBlocks > 0, InvalidAssertionTimelock());
        ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
        DA_VERIFIER = IDAVerifier(daVerifier);
    }

    /// @notice Initializes the contract
    /// @param admin The address of the admin
    /// @param _adminVerifiers The admin verifiers to add
    /// @param _maxAssertionsPerAA Maximum number of assertions per assertion adopter
    function initialize(address admin, IAdminVerifier[] calldata _adminVerifiers, uint128 _maxAssertionsPerAA)
        external
        initializer
    {
        _initializeOwner(admin);
        for (uint256 i = 0; i < _adminVerifiers.length; i++) {
            _addAdminVerifier(_adminVerifiers[i]);
        }
        _setMaxAssertionsPerAA(_maxAssertionsPerAA);
    }

    /// @notice Registers a new assertion adopter
    /// @param contractAddress The address of the contract to register
    /// @param adminVerifier The admin verifier to use
    /// @param data The data to pass to the admin verifier
    function registerAssertionAdopter(address contractAddress, IAdminVerifier adminVerifier, bytes calldata data)
        external
    {
        require(adminVerifiers.isRegistered(adminVerifier), AdminVerifierRegistry.AdminVerifierNotRegistered());
        require(adminVerifier.verifyAdmin(contractAddress, msg.sender, data), UnauthorizedRegistrant());
        require(assertionAdopters[contractAddress].manager == address(0), AssertionAdopterAlreadyRegistered());
        assertionAdopters[contractAddress].manager = msg.sender;
        emit AssertionAdopterAdded(contractAddress, msg.sender, adminVerifier);
    }

    /// @notice Adds a new assertion for an assertion adopter
    /// @dev An assertion ID can be added only once. If removed (inactive),
    /// it cannot be re-added - attempting to reuse the same ID will revert.
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier for the assertion
    /// @param proof The data availability proof for the assertion
    /// @param metadata Needed to verify the proof
    function addAssertion(address contractAddress, bytes32 assertionId, bytes calldata metadata, bytes calldata proof)
        external
        onlyManager(contractAddress)
    {
        require(!hasAssertion(contractAddress, assertionId), AssertionAlreadyExists());
        require(DA_VERIFIER.verifyDA(assertionId, metadata, proof), InvalidProof());
        require(assertionAdopters[contractAddress].assertionCount < maxAssertionsPerAA, TooManyAssertions());

        assertionAdopters[contractAddress].assertions[assertionId].activationBlock =
            uint128(block.number) + ASSERTION_TIMELOCK_BLOCKS;
        assertionAdopters[contractAddress].assertionCount++;
        emit AssertionAdded(contractAddress, assertionId, uint256(block.number + ASSERTION_TIMELOCK_BLOCKS));
    }

    /// @notice Removes an assertion from an assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion to remove
    function removeAssertion(address contractAddress, bytes32 assertionId) external onlyManager(contractAddress) {
        _removeAssertion(contractAddress, assertionId);
    }

    /// @notice Removes an assertion from an assertion adopter by the state oracle owner
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion to remove
    function removeAssertionByOwner(address contractAddress, bytes32 assertionId) external onlyOwner {
        _removeAssertion(contractAddress, assertionId);
    }

    /// @notice Internal function to remove an assertion from an assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion to remove
    function _removeAssertion(address contractAddress, bytes32 assertionId) internal {
        require(hasAssertion(contractAddress, assertionId), AssertionDoesNotExist());
        assertionAdopters[contractAddress].assertions[assertionId].deactivationBlock =
            uint128(block.number) + ASSERTION_TIMELOCK_BLOCKS;
        assertionAdopters[contractAddress].assertionCount--;
        emit AssertionRemoved(contractAddress, assertionId, uint256(block.number) + ASSERTION_TIMELOCK_BLOCKS);
    }

    /// @notice Checks if an assertion is associated with an assertion adopter
    /// @param contractAddress The address of the contract
    /// @param assertionId The unique identifier of the assertion
    /// @return isAssociated True if the assertion is associated with the adopter, false otherwise
    function hasAssertion(address contractAddress, bytes32 assertionId) public view returns (bool isAssociated) {
        return assertionAdopters[contractAddress].assertions[assertionId].activationBlock != 0;
    }

    /// @notice Gets the assertion window for a given assertion adopter and assertion
    /// @dev Returns 0 for both activationBlock and deactivationBlock if the assertion is not associated
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion
    /// @return activationBlock The block number when the assertion becomes active
    /// @return deactivationBlock The block number when the assertion becomes inactive
    function getAssertionWindow(address contractAddress, bytes32 assertionId)
        public
        view
        returns (uint128 activationBlock, uint128 deactivationBlock)
    {
        return (
            assertionAdopters[contractAddress].assertions[assertionId].activationBlock,
            assertionAdopters[contractAddress].assertions[assertionId].deactivationBlock
        );
    }

    /// @notice Gets the manager address for a given assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @return manager The manager address
    function getManager(address contractAddress) public view returns (address manager) {
        return assertionAdopters[contractAddress].manager;
    }

    /// @notice Gets the pending manager address for a given assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @return pendingManager The pending manager address
    function getPendingManager(address contractAddress) public view returns (address pendingManager) {
        return assertionAdopters[contractAddress].pendingManager;
    }

    /// @notice Transfers the manager role to a new address
    /// @param contractAddress The address of the assertion adopter
    /// @param newManager The address to transfer the manager role to
    function transferManager(address contractAddress, address newManager) external onlyManager(contractAddress) {
        require(newManager != address(0), InvalidManagerTransferRequest());
        assertionAdopters[contractAddress].pendingManager = newManager;
        emit ManagerTransferRequested(contractAddress, msg.sender, newManager);
    }

    /// @notice Accepts a manager transfer request
    /// @param contractAddress The address of the assertion adopter
    function acceptManagerTransfer(address contractAddress) external {
        require(assertionAdopters[contractAddress].pendingManager != address(0), NoPendingManager());
        require(assertionAdopters[contractAddress].pendingManager == msg.sender, UnauthorizedManager());
        _transferManager(contractAddress, msg.sender);
    }

    /// @notice Revokes the manager role from an assertion adopter by the state oracle owner
    /// @param contractAddress The address of the assertion adopter
    function revokeManager(address contractAddress) external onlyOwner {
        require(assertionAdopters[contractAddress].manager != address(0), AssertionAdopterNotRegistered());
        _transferManager(contractAddress, address(0));
    }

    /// @notice Internal function to transfer the manager role
    /// @param contractAddress The address of the assertion adopter
    /// @param newManager The address to transfer the manager role to
    function _transferManager(address contractAddress, address newManager) internal {
        assertionAdopters[contractAddress].manager = newManager;
        assertionAdopters[contractAddress].pendingManager = address(0);
        emit ManagerTransferred(contractAddress, newManager);
    }

    /// @notice Adds an authorization module to the state oracle
    /// @param adminVerifier The admin verifier to add
    function addAdminVerifier(IAdminVerifier adminVerifier) external onlyOwner {
        _addAdminVerifier(adminVerifier);
    }

    /// @notice Internal function to add an admin verifier
    /// @param adminVerifier The admin verifier to add
    function _addAdminVerifier(IAdminVerifier adminVerifier) internal {
        adminVerifiers.add(adminVerifier);
    }

    /// @notice Removes an authorization module from the state oracle
    /// @param adminVerifier The admin verifier to remove
    function removeAdminVerifier(IAdminVerifier adminVerifier) external onlyOwner {
        adminVerifiers.remove(adminVerifier);
    }

    /// @notice Checks if an admin verifier is registered
    /// @param adminVerifier The admin verifier to check
    /// @return isRegistered True if the admin verifier is registered, false otherwise
    function isAdminVerifierRegistered(IAdminVerifier adminVerifier) public view returns (bool isRegistered) {
        return adminVerifiers.isRegistered(adminVerifier);
    }

    /// @notice Sets the maximum number of assertions per assertion adopter
    /// @param _maxAssertionsPerAA The maximum number of assertions per assertion adopter
    function setMaxAssertionsPerAA(uint128 _maxAssertionsPerAA) external onlyOwner {
        _setMaxAssertionsPerAA(_maxAssertionsPerAA);
    }

    function _setMaxAssertionsPerAA(uint128 _maxAssertionsPerAA) internal {
        maxAssertionsPerAA = _maxAssertionsPerAA;
    }
}
