// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IDAVerifier} from "./interfaces/IDAVerifier.sol";
import {IAdminVerifier} from "./interfaces/IAdminVerifier.sol";
import {Batch} from "./Batch.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {AdminVerifierRegistry} from "./lib/AdminVerifierRegistry.sol";
import {DAVerifierRegistry} from "./lib/DAVerifierRegistry.sol";
import {StateOracleAccessControl} from "./StateOracleAccessControl.sol";
import {StateOracleTimelock} from "./StateOracleTimelock.sol";
import {StateOracleAdministration} from "./StateOracleAdministration.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

/// @title StateOracle
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Manages assertion adopters and their assertions
/// @dev Provides functionality to register assertion adopters and manage their assertions

contract StateOracle is Batch, Initializable, StateOracleAccessControl {
    using AdminVerifierRegistry for mapping(IAdminVerifier adminVerifier => bool isRegistered);
    using DAVerifierRegistry for mapping(IDAVerifier daVerifier => bool isRegistered);

    /// @notice Number of blocks to wait before an assertion becomes active or inactive
    uint256 public immutable ASSERTION_TIMELOCK_BLOCKS;

    /// @notice Thrown when an unauthorized address attempts to register an assertion adopter
    error UnauthorizedRegistrant();
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
    /// @notice Thrown when the DA verifier is not registered
    error DAVerifierNotRegistered();
    /// @notice Thrown when the provided DA proof is invalid
    /// @param daVerifier The DA verifier that rejected the proof
    error InvalidDAProof(IDAVerifier daVerifier);
    /// @notice Thrown when attempting to set an invalid assertion timelock value
    error InvalidAssertionTimelock();
    /// @notice Thrown when attempting to add more assertions than the maximum allowed
    error TooManyAssertions();
    /// @notice Thrown when attempting to remove or modify an already removed assertion
    error AssertionAlreadyRemoved();
    /// @notice Thrown when whitelist is enabled and caller is not whitelisted
    error NotWhitelisted();
    /// @notice Thrown when attempting to add an account that is already whitelisted
    /// @param account The account already admitted.
    error AlreadyWhitelisted(address account);
    /// @notice Thrown when attempting to remove an account that is not whitelisted
    /// @param account The account absent from the whitelist.
    error AccountNotWhitelisted(address account);
    /// @notice Thrown when attempting to enable an already enabled whitelist
    error WhitelistAlreadyEnabled();
    /// @notice Thrown when attempting to disable an already disabled whitelist
    error WhitelistAlreadyDisabled();

    /// @notice Re-registration must wait until the guardian revocation's fixed deadline
    /// @param registrationAvailableAt Earliest registration timestamp in seconds
    error ManagerRecoveryPending(uint256 registrationAvailableAt);

    /// @notice Struct containing assertion adopter data
    /// @param manager Address authorized to manage assertions
    /// @param pendingManager Nominated successor awaiting acceptance
    /// @param assertionCount Registered assertions whose removal has not been requested
    /// @param assertions Mapping of assertion IDs to assertion windows, describing the assertion's lifecycle
    struct AssertionAdopter {
        address manager;
        address pendingManager;
        uint16 assertionCount;
        mapping(bytes32 assertionId => AssertionWindow assertionWindow) assertions;
    }

    /// @notice Struct containing the assertion time window
    /// @param activationBlock Block number when the assertion becomes active
    /// @param deactivationBlock Block number when the assertion becomes inactive
    struct AssertionWindow {
        uint256 activationBlock;
        uint256 deactivationBlock;
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

    /// @notice Manager revocation is immediate; registration becomes possible at the given timestamp
    /// @param contractAddress Adopter whose manager was revoked
    /// @param registrationAvailableAt Earliest registration timestamp in seconds
    event ManagerRevoked(address indexed contractAddress, uint256 registrationAvailableAt);

    /// @notice Emitted when a new assertion is added
    /// @param assertionAdopter The assertion adopter the assertion is associated with
    /// @param assertionId The unique identifier of the assertion
    /// @param activationBlock The block number when the assertion becomes active
    /// @param daVerifier The DA verifier used to verify the proof
    /// @param metadata The metadata used for verification
    /// @param proof The proof used for verification
    event AssertionAdded(
        address indexed assertionAdopter,
        bytes32 indexed assertionId,
        uint256 activationBlock,
        IDAVerifier indexed daVerifier,
        bytes metadata,
        bytes proof
    );

    /// @notice Emitted when an assertion is removed
    /// @param assertionAdopter The assertion adopter where the assertion is removed from
    /// @param assertionId The unique identifier of the removed assertion
    /// @param deactivationBlock The block number when the assertion is going to be inactive
    event AssertionRemoved(address indexed assertionAdopter, bytes32 indexed assertionId, uint256 deactivationBlock);

    /// @notice Emitted when a storage reset is requested for an assertion adopter
    /// @param adopter The assertion adopter whose side-store state should be reset
    /// @param storageKey The side-store key identifying the state to reset
    /// @param resetBlock The block number when the reset becomes eligible
    event StorageReset(address indexed adopter, bytes32 indexed storageKey, uint256 resetBlock);

    /// @notice Emitted when the whitelist is enabled
    event WhitelistEnabled();

    /// @notice Emitted when the whitelist is disabled
    event WhitelistDisabled();

    /// @notice Emitted when an account is added to the whitelist
    /// @param account The address added to the whitelist
    event AddedToWhitelist(address indexed account);

    /// @notice Emitted when an account is removed from the whitelist
    /// @param account The address removed from the whitelist
    event RemovedFromWhitelist(address indexed account);

    /// @notice Maps contract addresses to their assertion adopter data
    mapping(address => AssertionAdopter) public assertionAdopters;

    /// @notice The admin verification registry
    mapping(IAdminVerifier adminVerifier => bool isRegistered) public adminVerifiers;

    /// @notice The DA verification registry
    mapping(IDAVerifier daVerifier => bool isRegistered) public daVerifiers;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelist;

    /// @notice Whether the whitelist is enabled
    bool public whitelistEnabled;

    /// @notice Maximum number of assertions per assertion adopter
    uint16 public maxAssertionsPerAA;

    /// @notice Earliest re-registration timestamp after revocation under this implementation; otherwise zero
    /// @dev Deadlines live in the controller; migration does not invent historical deadlines.
    /// @param contractAddress Adopter whose recovery deadline is queried
    /// @return Earliest registration timestamp, or zero without recorded revocation
    function registrationAvailableAt(address contractAddress) public view returns (uint256) {
        return timelock().registrationAvailableAt(address(this), contractAddress);
    }

    /// @notice Ensures caller is the manager of the contract
    /// @param contractAddress The address of the contract being managed
    modifier onlyManager(address contractAddress) {
        _onlyManager(contractAddress);
        _;
    }

    /// @notice Ensures caller is whitelisted when whitelist is enabled
    modifier onlyWhitelisted() {
        _onlyWhitelisted();
        _;
    }

    /// @notice Internal function to ensure caller is whitelisted when whitelist is enabled
    function _onlyWhitelisted() internal view {
        require(!whitelistEnabled || whitelist[msg.sender], NotWhitelisted());
    }

    /// @notice Internal function to ensure caller is the manager of the contract
    /// @param contractAddress The address of the contract being managed
    function _onlyManager(address contractAddress) internal view {
        address manager = assertionAdopters[contractAddress].manager;
        require(manager != address(0), AssertionAdopterNotRegistered());
        require(manager == msg.sender, UnauthorizedManager());
    }

    /// @notice Deploys implementation bytecode with a fixed assertion lifecycle delay.
    /// @dev Does not initialize proxy storage. Locks initializers on the implementation itself.
    /// @param assertionTimelockBlocks Number of blocks to wait before assertions become active/inactive
    constructor(uint256 assertionTimelockBlocks) Ownable(msg.sender) {
        require(assertionTimelockBlocks > 0, InvalidAssertionTimelock());
        ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
        _transferOwnership(address(0));
        _disableInitializers();
    }

    /// @notice Initializes a fresh proxy with caller whitelisting enabled and no initially admitted callers.
    /// @param admin The initial owner and role holder.
    /// @param _adminVerifiers The initial admin verifier registry.
    /// @param _daVerifiers The initial DA verifier registry.
    /// @param _maxAssertionsPerAA The initial per-adopter assertion cap.
    function initialize(
        address admin,
        IAdminVerifier[] calldata _adminVerifiers,
        IDAVerifier[] calldata _daVerifiers,
        uint16 _maxAssertionsPerAA
    ) external {
        _initialize(admin, _adminVerifiers, _daVerifiers, _maxAssertionsPerAA, true, new address[](0));
    }

    /// @notice Initializes a fresh proxy and deploys its own three-day administration timelock.
    /// @dev Pass this call to the proxy constructor so no uninitialized proxy is exposed.
    /// @param admin The address to set as the admin
    /// @param _adminVerifiers The admin verifiers to add
    /// @param _daVerifiers The DA verifiers to add
    /// @param _maxAssertionsPerAA Maximum number of assertions per assertion adopter
    /// @param _whitelistEnabled Whether whitelist checks are enabled initially
    /// @param _initialWhitelist Addresses to add to the initial whitelist
    function initializeWithWhitelist(
        address admin,
        IAdminVerifier[] calldata _adminVerifiers,
        IDAVerifier[] calldata _daVerifiers,
        uint16 _maxAssertionsPerAA,
        bool _whitelistEnabled,
        address[] calldata _initialWhitelist
    ) external {
        _initialize(admin, _adminVerifiers, _daVerifiers, _maxAssertionsPerAA, _whitelistEnabled, _initialWhitelist);
    }

    /// @notice Deploys the administration timelock during an existing version-1 proxy's upgradeAndCall.
    /// @dev This hook does not transfer ProxyAdmin ownership or implement delayed upgrades.
    /// Those handovers must be performed atomically by the separately reviewed migration.
    /// Preserves application state; writes the controller namespace and existing initialization-version slot.
    function initializeTimelockV2() external onlyProxyAdminMigration reinitializer(2) {
        _initializeTimelock();
    }

    /// @notice Allows migration only through the proxy's existing upgrade admin, once.
    /// @dev Relies on the existing ERC-1967 admin slot's integrity. Fresh proxies start at version 2.
    modifier onlyProxyAdminMigration() {
        require(_getInitializedVersion() == 1 && msg.sender == ERC1967Utils.getAdmin(), InvalidInitialization());
        _;
    }

    /// @notice Prevents a fresh initialization entrypoint from resetting a legacy or migrated proxy.
    modifier onlyUninitialized() {
        require(_getInitializedVersion() == 0, InvalidInitialization());
        _;
    }

    /// @notice Sets fresh application state and the timelock through the shared version-2 setup path.
    /// @dev The version-2 migration never resets these fields.
    /// @param admin The initial owner and holder of all delegatable roles.
    /// @param _adminVerifiers The initial admin verifier registry entries.
    /// @param _daVerifiers The initial DA verifier registry entries.
    /// @param _maxAssertionsPerAA The initial per-adopter assertion cap.
    /// @param _whitelistEnabled Whether caller admission is initially enforced.
    /// @param _initialWhitelist The initially admitted accounts.
    function _initialize(
        address admin,
        IAdminVerifier[] calldata _adminVerifiers,
        IDAVerifier[] calldata _daVerifiers,
        uint16 _maxAssertionsPerAA,
        bool _whitelistEnabled,
        address[] memory _initialWhitelist
    ) internal onlyUninitialized reinitializer(2) {
        _initializeRoles(admin);

        whitelistEnabled = _whitelistEnabled;
        for (uint256 i = 0; i < _adminVerifiers.length; i++) {
            _addAdminVerifier(_adminVerifiers[i]);
        }
        for (uint256 i = 0; i < _daVerifiers.length; i++) {
            _addDAVerifier(_daVerifiers[i]);
        }
        for (uint256 i = 0; i < _initialWhitelist.length; i++) {
            _addToWhitelist(_initialWhitelist[i]);
        }
        _setMaxAssertionsPerAA(_maxAssertionsPerAA);
        _initializeTimelock();
    }

    /// @notice Registers a new assertion adopter
    /// @param contractAddress The address of the contract to register
    /// @param adminVerifier The admin verifier to use
    /// @param data The data to pass to the admin verifier
    function registerAssertionAdopter(address contractAddress, IAdminVerifier adminVerifier, bytes calldata data)
        external
        onlyWhitelisted
    {
        uint256 availableAt = registrationAvailableAt(contractAddress);
        require(block.timestamp >= availableAt, ManagerRecoveryPending(availableAt));
        require(adminVerifiers.isRegistered(adminVerifier), AdminVerifierRegistry.AdminVerifierNotRegistered());
        require(adminVerifier.verifyAdmin(contractAddress, msg.sender, data), UnauthorizedRegistrant());
        require(assertionAdopters[contractAddress].manager == address(0), AssertionAdopterAlreadyRegistered());
        assertionAdopters[contractAddress].manager = msg.sender;
        emit AssertionAdopterAdded(contractAddress, msg.sender, adminVerifier);
    }

    /// @notice Adds a new assertion for an assertion adopter
    /// @dev An assertion ID can be re-added once its previous deactivation block is reached.
    /// Each addition requires a valid DA proof and starts a new activation timelock.
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier for the assertion
    /// @param daVerifier The DA verifier to use for proof verification
    /// @param metadata Needed to verify the proof
    /// @param proof The data availability proof for the assertion
    function addAssertion(
        address contractAddress,
        bytes32 assertionId,
        IDAVerifier daVerifier,
        bytes calldata metadata,
        bytes calldata proof
    ) external onlyManager(contractAddress) onlyWhitelisted {
        AssertionWindow storage window = assertionAdopters[contractAddress].assertions[assertionId];
        require(
            window.activationBlock == 0 || (window.deactivationBlock != 0 && block.number >= window.deactivationBlock),
            AssertionAlreadyExists()
        );
        require(daVerifiers.isRegistered(daVerifier), DAVerifierNotRegistered());
        require(daVerifier.verifyDA(assertionId, metadata, proof), InvalidDAProof(daVerifier));
        require(assertionAdopters[contractAddress].assertionCount < maxAssertionsPerAA, TooManyAssertions());

        uint256 activationBlock = block.number + ASSERTION_TIMELOCK_BLOCKS;
        window.activationBlock = activationBlock;
        window.deactivationBlock = 0;
        assertionAdopters[contractAddress].assertionCount++;
        emit AssertionAdded(contractAddress, assertionId, activationBlock, daVerifier, metadata, proof);
    }

    /// @notice Requests a storage reset for an assertion adopter
    /// @param adopter The assertion adopter whose side-store state should be reset
    /// @param storageKey The side-store key identifying the state to reset
    function resetStorage(address adopter, bytes32 storageKey) external onlyManager(adopter) {
        emit StorageReset(adopter, storageKey, block.number + ASSERTION_TIMELOCK_BLOCKS);
    }

    /// @notice Removes an assertion from an assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion to remove
    function removeAssertion(address contractAddress, bytes32 assertionId) external onlyManager(contractAddress) {
        _removeAssertion(contractAddress, assertionId);
    }

    /// @notice Removes an assertion from an assertion adopter by guardian
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion to remove
    function removeAssertionByGuardian(address contractAddress, bytes32 assertionId) external onlyGuardian {
        _removeAssertion(contractAddress, assertionId);
    }

    /// @notice Schedules enabling the whitelist after D
    function enableWhitelist() external onlyGovernance {
        require(!whitelistEnabled, WhitelistAlreadyEnabled());
        _queueWhitelistEnabled(true);
    }

    /// @notice Schedules disabling the whitelist after D
    function disableWhitelist() external onlyGovernance {
        require(whitelistEnabled, WhitelistAlreadyDisabled());
        _queueWhitelistEnabled(false);
    }

    /// @notice Encodes either direction of an authorized caller-whitelist toggle.
    /// @param enabled Whether caller admission checks become enabled.
    function _queueWhitelistEnabled(bool enabled) internal {
        _scheduleAdministration(
            keccak256("whitelistEnabled"), address(this), abi.encodeCall(this.applyWhitelistEnabled, (enabled))
        );
    }

    /// @notice Applies a matured caller-whitelist toggle through this oracle's timelock.
    /// @param enabled Whether caller admission checks become enabled.
    function applyWhitelistEnabled(bool enabled) external onlyTimelock {
        whitelistEnabled = enabled;
        if (enabled) emit WhitelistEnabled();
        else emit WhitelistDisabled();
    }

    /// @notice Schedules adding a caller after D, even while enforcement is disabled
    /// @param account The address to add
    function addToWhitelist(address account) external onlyOperator {
        require(!whitelist[account], AlreadyWhitelisted(account));
        _queueWhitelistAccount(account, true);
    }

    /// @notice Admits a caller during initialization or an authorized effective change.
    /// @param account The caller to admit.
    function _addToWhitelist(address account) internal {
        require(!whitelist[account], AlreadyWhitelisted(account));
        whitelist[account] = true;
        emit AddedToWhitelist(account);
    }

    /// @notice Schedules removing a caller after D, even while enforcement is disabled
    /// @param account The address to remove
    function removeFromWhitelist(address account) external onlyOperator {
        require(whitelist[account], AccountNotWhitelisted(account));
        _queueWhitelistAccount(account, false);
    }

    /// @notice Encodes either direction of an authorized caller-admission change.
    /// @param account Caller whose membership changes.
    /// @param allowed True to add, false to remove.
    function _queueWhitelistAccount(address account, bool allowed) internal {
        _scheduleAdministration(
            keccak256(abi.encode("whitelist", account)),
            address(this),
            abi.encodeCall(this.applyWhitelistAccount, (account, allowed))
        );
    }

    /// @notice Applies a matured caller-admission change through this oracle's timelock.
    /// @dev Membership remains configurable while enforcement is disabled, with the same delay.
    /// @param account Caller whose membership changes.
    /// @param allowed True to add, false to remove.
    function applyWhitelistAccount(address account, bool allowed) external onlyTimelock {
        if (allowed) {
            _addToWhitelist(account);
        } else {
            require(whitelist[account], AccountNotWhitelisted(account));
            whitelist[account] = false;
            emit RemovedFromWhitelist(account);
        }
    }

    /// @notice Checks if an account is allowed to perform whitelisted actions
    /// @param account The address to check
    /// @return True if whitelist is disabled (everyone allowed) or account is whitelisted
    function isWhitelisted(address account) external view returns (bool) {
        return !whitelistEnabled || whitelist[account];
    }

    /// @notice Internal function to remove an assertion from an assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion to remove
    function _removeAssertion(address contractAddress, bytes32 assertionId) internal {
        require(hasAssertion(contractAddress, assertionId), AssertionDoesNotExist());
        require(
            assertionAdopters[contractAddress].assertions[assertionId].deactivationBlock == 0, AssertionAlreadyRemoved()
        );
        uint256 deactivationBlock = block.number + ASSERTION_TIMELOCK_BLOCKS;
        assertionAdopters[contractAddress].assertions[assertionId].deactivationBlock = deactivationBlock;
        assertionAdopters[contractAddress].assertionCount--;
        emit AssertionRemoved(contractAddress, assertionId, deactivationBlock);
    }

    /// @notice Checks if an assertion is associated with an assertion adopter
    /// @dev Remains true after removal; it does not indicate current enforcement or re-add eligibility.
    /// @param contractAddress The address of the contract
    /// @param assertionId The unique identifier of the assertion
    /// @return isAssociated True if the assertion is associated with the adopter, false otherwise
    function hasAssertion(address contractAddress, bytes32 assertionId) public view returns (bool isAssociated) {
        return assertionAdopters[contractAddress].assertions[assertionId].activationBlock != 0;
    }

    /// @notice Gets the latest assertion window for a given assertion adopter and assertion
    /// @dev Returns 0 for both activationBlock and deactivationBlock if the assertion is not associated.
    /// A successful re-add replaces this window; earlier lifecycle history remains in events.
    /// @param contractAddress The address of the assertion adopter
    /// @param assertionId The unique identifier of the assertion
    /// @return activationBlock The block number when the assertion becomes active
    /// @return deactivationBlock The block number when the assertion becomes inactive
    function getAssertionWindow(address contractAddress, bytes32 assertionId)
        public
        view
        returns (uint256 activationBlock, uint256 deactivationBlock)
    {
        return (
            assertionAdopters[contractAddress].assertions[assertionId].activationBlock,
            assertionAdopters[contractAddress].assertions[assertionId].deactivationBlock
        );
    }

    /// @notice Gets the assertion count for a given assertion adopter
    /// @param contractAddress The address of the assertion adopter
    /// @return assertionCount The number of assertions associated with the adopter
    function getAssertionCount(address contractAddress) public view returns (uint16 assertionCount) {
        return assertionAdopters[contractAddress].assertionCount;
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
        address pendingManager = assertionAdopters[contractAddress].pendingManager;
        require(pendingManager != address(0), NoPendingManager());
        require(pendingManager == msg.sender, UnauthorizedManager());
        _transferManager(contractAddress, msg.sender);
    }

    /// @notice Revokes the manager role from an assertion adopter by guardian
    /// @param contractAddress The address of the assertion adopter
    function revokeManager(address contractAddress) external onlyGuardian {
        require(assertionAdopters[contractAddress].manager != address(0), AssertionAdopterNotRegistered());
        _requireAdministrationReady();
        uint256 availableAt = timelock().startManagerRecovery(contractAddress);
        _transferManager(contractAddress, address(0));
        emit ManagerRevoked(contractAddress, availableAt);
    }

    /// @notice Internal function to transfer the manager role
    /// @param contractAddress The address of the assertion adopter
    /// @param newManager The address to transfer the manager role to
    function _transferManager(address contractAddress, address newManager) internal {
        assertionAdopters[contractAddress].manager = newManager;
        assertionAdopters[contractAddress].pendingManager = address(0);
        emit ManagerTransferred(contractAddress, newManager);
    }

    /// @notice Schedules adding an authorization module after D
    /// @param adminVerifier The admin verifier to add
    function addAdminVerifier(IAdminVerifier adminVerifier) external onlyGovernance {
        require(!adminVerifiers.isRegistered(adminVerifier), AdminVerifierRegistry.AdminVerifierAlreadyRegistered());
        _queueAdminVerifierChange(adminVerifier, true);
    }

    /// @notice Internal function to add an admin verifier
    /// @param adminVerifier The admin verifier to add
    function _addAdminVerifier(IAdminVerifier adminVerifier) internal {
        adminVerifiers.add(adminVerifier);
    }

    /// @notice Schedules removing an authorization module after D
    /// @param adminVerifier The admin verifier to remove
    function removeAdminVerifier(IAdminVerifier adminVerifier) external onlyGovernance {
        require(adminVerifiers.isRegistered(adminVerifier), AdminVerifierRegistry.AdminVerifierNotRegistered());
        _queueAdminVerifierChange(adminVerifier, false);
    }

    /// @notice Encodes either direction of an authorized admin-verifier registry change.
    /// @param verifier Affected admin verifier.
    /// @param registered True to add, false to remove.
    function _queueAdminVerifierChange(IAdminVerifier verifier, bool registered) internal {
        _scheduleAdministration(
            keccak256(abi.encode("adminVerifier", verifier)),
            address(this),
            abi.encodeCall(this.applyAdminVerifierChange, (verifier, registered))
        );
    }

    /// @notice Applies a matured admin-verifier registry proposal through this oracle's timelock.
    /// @dev Existing managers and assertion windows are unaffected by registry removal.
    /// @param verifier Affected admin verifier.
    /// @param registered True to add, false to remove.
    function applyAdminVerifierChange(IAdminVerifier verifier, bool registered) external onlyTimelock {
        if (registered) adminVerifiers.add(verifier);
        else adminVerifiers.remove(verifier);
    }

    /// @notice Checks if an admin verifier is registered
    /// @param adminVerifier The admin verifier to check
    /// @return isRegistered True if the admin verifier is registered, false otherwise
    function isAdminVerifierRegistered(IAdminVerifier adminVerifier) public view returns (bool isRegistered) {
        return adminVerifiers.isRegistered(adminVerifier);
    }

    /// @notice Schedules adding a DA verifier after D
    /// @param daVerifier The DA verifier to add
    function addDAVerifier(IDAVerifier daVerifier) external onlyGovernance {
        require(!daVerifiers.isRegistered(daVerifier), DAVerifierRegistry.DAVerifierAlreadyRegistered());
        _queueDAVerifierChange(daVerifier, true);
    }

    /// @notice Internal function to add a DA verifier
    /// @param daVerifier The DA verifier to add
    function _addDAVerifier(IDAVerifier daVerifier) internal {
        daVerifiers.add(daVerifier);
    }

    /// @notice Schedules removing a DA verifier after D
    /// @param daVerifier The DA verifier to remove
    function removeDAVerifier(IDAVerifier daVerifier) external onlyGovernance {
        require(daVerifiers.isRegistered(daVerifier), DAVerifierRegistry.DAVerifierNotRegistered());
        _queueDAVerifierChange(daVerifier, false);
    }

    /// @notice Encodes either direction of an authorized DA-verifier registry change.
    /// @param verifier Affected DA verifier.
    /// @param registered True to add, false to remove.
    function _queueDAVerifierChange(IDAVerifier verifier, bool registered) internal {
        _scheduleAdministration(
            keccak256(abi.encode("daVerifier", verifier)),
            address(this),
            abi.encodeCall(this.applyDAVerifierChange, (verifier, registered))
        );
    }

    /// @notice Applies a matured DA-verifier registry proposal through this oracle's timelock.
    /// @dev Removal blocks future assertion additions using this verifier, not existing assertion lifecycles.
    /// @param verifier Affected DA verifier.
    /// @param registered True to add, false to remove.
    function applyDAVerifierChange(IDAVerifier verifier, bool registered) external onlyTimelock {
        if (registered) daVerifiers.add(verifier);
        else daVerifiers.remove(verifier);
    }

    /// @notice Checks if a DA verifier is registered
    /// @param daVerifier The DA verifier to check
    /// @return isRegistered True if the DA verifier is registered, false otherwise
    function isDAVerifierRegistered(IDAVerifier daVerifier) public view returns (bool isRegistered) {
        return daVerifiers.isRegistered(daVerifier);
    }

    /// @notice Schedules an assertion capacity change after D, including zero and decreases
    /// @param _maxAssertionsPerAA The maximum number of assertions per assertion adopter
    function setMaxAssertionsPerAA(uint16 _maxAssertionsPerAA) external onlyGovernance {
        _scheduleAdministration(
            keccak256("maxAssertionsPerAA"),
            address(this),
            abi.encodeCall(this.applyMaxAssertionsPerAA, (_maxAssertionsPerAA))
        );
    }

    /// @notice Applies a matured capacity change through this oracle's timelock.
    /// @dev A decrease does not remove assertions already registered above the new limit.
    /// @param maximum New per-adopter cap, including zero.
    function applyMaxAssertionsPerAA(uint16 maximum) external onlyTimelock {
        _setMaxAssertionsPerAA(maximum);
    }

    /// @notice Emitted when a capacity change becomes effective.
    /// @param previousMaximum Previous per-adopter cap.
    /// @param newMaximum New per-adopter cap.
    event MaxAssertionsPerAAChanged(uint16 previousMaximum, uint16 newMaximum);

    /// @notice Applies the cap during fresh initialization or a matured proposal and emits the effective change.
    /// @param _maxAssertionsPerAA New per-adopter assertion cap.
    function _setMaxAssertionsPerAA(uint16 _maxAssertionsPerAA) internal {
        emit MaxAssertionsPerAAChanged(maxAssertionsPerAA, _maxAssertionsPerAA);
        maxAssertionsPerAA = _maxAssertionsPerAA;
    }
}
