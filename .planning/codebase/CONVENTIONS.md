# Coding Conventions

**Analysis Date:** 2026-03-09

## Naming Patterns

**Files:**
- Contract files: CamelCase in snake_case file names (e.g., `StateOracle.sol`, `AdminVerifierOwner.sol`)
- Test files: CamelCase with `.t.sol` suffix (e.g., `StateOracle.t.sol`, `Batch.t.sol`)
- Interface files: `I` prefix followed by CamelCase (e.g., `IAdminVerifier.sol`, `IDAVerifier.sol`, `IBatch.sol`)
- Library files: CamelCase in `lib/` subdirectory (e.g., `AdminVerifierRegistry.sol`)

**Functions:**
- camelCase for all functions (both public and internal)
- Private/internal helpers: underscore prefix with camelCase (e.g., `_onlyManager()`, `_removeAssertion()`, `_onlyWhitelisted()`)
- View/pure functions use camelCase without underscore (e.g., `hasAssertion()`, `isWhitelisted()`)
- Batch-callable functions should be named consistently for both direct and batched invocation

**Variables:**
- camelCase for local variables, parameters, and state variables (e.g., `manager`, `assertionId`, `whitelistEnabled`, `adminVerifiers`)
- All-caps with underscores for constants: `ASSERTION_TIMELOCK_BLOCKS`, `GUARDIAN_ROLE`, `MAX_ASSERTIONS_PER_AA`
- Immutable state variables: `DA_VERIFIER`, `GUARDIAN_ROLE`, `ASSERTION_TIMELOCK_BLOCKS` (all-caps)
- Mapping keys in comments use arrow notation: `mapping(bytes32 assertionId => AssertionWindow assertionWindow)`

**Types:**
- Struct names: CamelCase (e.g., `AssertionAdopter`, `AssertionWindow`)
- Enum names: CamelCase (no enums in current codebase)
- Custom errors: CapitalizedError format (e.g., `UnauthorizedManager()`, `AssertionAlreadyExists()`, `InvalidAssertionTimelock()`)

## Code Style

**Formatting:**
- Tool: Forge formatter (`forge fmt`)
- Run before committing: `npm run format` or `forge fmt`
- Line length: Standard Solidity convention (no strict limit enforced, but keep readable)
- Indentation: 4 spaces

**Linting:**
- Tool: Foundry built-in lint (see `foundry.toml`)
- Excluded lints in `foundry.toml`:
  - `mixed-case-function`: Allows camelCase consistently
  - `mixed-case-variable`: Allows conventional patterns like `CONSTANT_CASE` and `camelCase`

**SPDX Identifiers:**
- Protocol core files: `CC0-1.0` (e.g., `StateOracle.sol`, `StateOracleAccessControl.sol`, `Batch.sol`)
- Admin/DA verifier files: `MIT` or `CC0-1.0` depending on file (e.g., `AdminVerifierOwner.sol` is `MIT`, `AdminVerifierWhitelist.sol` is `MIT`)
- Batch.sol (forked): `GPL-3.0-or-later`
- Keep existing SPDX choice per file family unless task explicitly requires harmonization

## Import Organization

**Order:**
1. Built-in Solidity imports (none typically needed)
2. Local imports from same repo (relative paths with `./`)
3. External library imports (OpenZeppelin, Solady)
4. Library using statements (e.g., `using AdminVerifierRegistry for mapping(...)`)

**Examples:**
```solidity
// StateOracle.sol style:
import {IDAVerifier} from "./interfaces/IDAVerifier.sol";
import {IAdminVerifier} from "./interfaces/IAdminVerifier.sol";
import {Batch} from "./Batch.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {AdminVerifierRegistry} from "./lib/AdminVerifierRegistry.sol";
import {StateOracleAccessControl} from "./StateOracleAccessControl.sol";

using AdminVerifierRegistry for mapping(IAdminVerifier adminVerifier => bool isRegistered);
```

**Path Aliases:**
- Not used in this codebase; imports use relative paths `./` for local modules and full package names for external imports

## Error Handling

**Patterns:**
- Custom errors defined at contract/library top level after events
- Errors documented with `@notice` NatSpec comments
- Errors thrown with `require()` statements using comma operator: `require(condition, ErrorType())`
- Error conditions checked early in functions (fail-fast pattern)
- Error messages use descriptive names: prefer `AssertionAlreadyExists()` over generic messages

**Error Organization:**
- Grouped by concern in contract (e.g., all assertion-related errors together)
- Library errors defined in the library itself (e.g., `AdminVerifierRegistry.AdminVerifierNotRegistered()`)

**Example from StateOracle.sol:**
```solidity
/// @notice Thrown when attempting to register an assertion adopter that is already registered
error AssertionAdopterAlreadyRegistered();

/// Usage:
require(assertionAdopters[contractAddress].manager == address(0), AssertionAdopterAlreadyRegistered());
```

## Logging

**Framework:** Not used in current codebase. Test output via Forge's `vm.log*` and assertions.

**Events:**
- Emitted for all state changes and significant operations
- Event names use past tense or descriptive names:
  - State changes: `AssertionAdded`, `AssertionRemoved`, `ManagerTransferred`
  - Actions: `WhitelistEnabled`, `WhitelistDisabled`
  - Lifecycle: `AssertionAdopterAdded`
- Indexed parameters: typically address fields for filtering (up to 3 indexed params)

**Example from StateOracle.sol:**
```solidity
/// @notice Emitted when a new assertion is added
/// @param assertionAdopter The assertion adopter the assertion is associated with
/// @param assertionId The unique identifier of the assertion
/// @param activationBlock The block number when the assertion becomes active
event AssertionAdded(address assertionAdopter, bytes32 assertionId, uint256 activationBlock);

// Usage:
emit AssertionAdded(contractAddress, assertionId, uint256(block.number + ASSERTION_TIMELOCK_BLOCKS));
```

## Comments

**When to Comment:**
- NatSpec comments on all public/external functions and events (required)
- Complex internal logic that is not self-evident
- Security-critical invariants and assumptions (especially in `StateOracleAccessControl.sol`)
- References to external documentation (e.g., "Forked from: URL")

**JSDoc/TSDoc (NatSpec for Solidity):**
- `@title`: Contract or interface name
- `@author`: Author reference (format: `@username (email)`)
- `@notice`: Human-readable description for all public functions and events
- `@dev`: Implementation details and technical notes
- `@param`: Parameter descriptions
- `@return`: Return value descriptions
- `@inheritdoc`: Reference to parent interface implementation

**Example from StateOracle.sol:**
```solidity
/// @title StateOracle
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Manages assertion adopters and their assertions
/// @dev Provides functionality to register assertion adopters and manage their assertions

/// @notice Registers a new assertion adopter
/// @param contractAddress The address of the contract to register
/// @param adminVerifier The admin verifier to use
/// @param data The data to pass to the admin verifier
function registerAssertionAdopter(address contractAddress, IAdminVerifier adminVerifier, bytes calldata data)
    external
    onlyWhitelisted
{
    // ...
}
```

## Function Design

**Size:** Keep functions focused on single responsibility. Large functions like `StateOracle.addAssertion()` (~15 lines) are typical for this codebase.

**Parameters:**
- Use types explicitly (e.g., `address`, `bytes32`, `uint128`)
- calldata for dynamic types in external functions (e.g., `bytes calldata data`, `bytes calldata proof`)
- Validate parameters early with require statements
- Use meaningful parameter names (e.g., `contractAddress` not `addr`, `assertionId` not `id`)

**Return Values:**
- Named return values for clarity (e.g., `returns (bool isAssociated)`)
- Single return values common; use struct returns for multiple related values

**Modifiers:**
- Single modifier per line
- Stacked on function signature line before `{` (e.g., `external onlyManager(contractAddress) onlyWhitelisted`)
- Custom modifiers with parameters (e.g., `onlyManager(address contractAddress)`)

**Example from StateOracle.sol:**
```solidity
function addAssertion(address contractAddress, bytes32 assertionId, bytes calldata metadata, bytes calldata proof)
    external
    onlyManager(contractAddress)
    onlyWhitelisted
{
    require(!hasAssertion(contractAddress, assertionId), AssertionAlreadyExists());
    require(DA_VERIFIER.verifyDA(assertionId, metadata, proof), InvalidProof());
    require(assertionAdopters[contractAddress].assertionCount < maxAssertionsPerAA, TooManyAssertions());

    assertionAdopters[contractAddress].assertions[assertionId].activationBlock =
        uint128(block.number) + ASSERTION_TIMELOCK_BLOCKS;
    assertionAdopters[contractAddress].assertionCount++;
    emit AssertionAdded(contractAddress, assertionId, uint256(block.number + ASSERTION_TIMELOCK_BLOCKS));
}
```

## Module Design

**Exports:**
- All public contracts, interfaces, and libraries are intended for external use
- Internal contracts (test harnesses) marked with comment `// @dev test harness` or live in `/test` directory

**Barrel Files:**
- Not used in this codebase
- Direct imports from specific contracts recommended

**Inheritance Patterns:**
- Avoid deep inheritance chains; typically 1-2 levels
- `StateOracle` inherits: `Batch`, `Initializable`, `StateOracleAccessControl`
- `StateOracleAccessControl` inherits: `Ownable2Step`, `AccessControl`
- Use `is` keyword with all parent names on same line or stacked

**Example from StateOracle.sol:**
```solidity
contract StateOracle is Batch, Initializable, StateOracleAccessControl {
    using AdminVerifierRegistry for mapping(IAdminVerifier adminVerifier => bool isRegistered);
    // ...
}
```

## Access Control

**Modifiers for Role Checks:**
- `onlyGovernance()`: Checks `GOVERNANCE_ROLE`
- `onlyGuardian()`: Checks `GUARDIAN_ROLE`
- `onlyOperator()`: Checks `OPERATOR_ROLE`
- `onlyManager(address contractAddress)`: Custom check for assertion adopter manager
- `onlyWhitelisted()`: Check whitelist status
- `onlyOwner()`: Inherited from OpenZeppelin's `Ownable2Step`

**Custom Modifiers:**
- Defined as 2-5 line inline functions
- End with `_;` to execute function body
- Should be fast and gas-efficient

**Example:**
```solidity
modifier onlyManager(address contractAddress) {
    _onlyManager(contractAddress);
    _;
}

function _onlyManager(address contractAddress) internal view {
    address manager = assertionAdopters[contractAddress].manager;
    require(manager != address(0), AssertionAdopterNotRegistered());
    require(manager == msg.sender, UnauthorizedManager());
}
```

## Pragma and Solidity Version

**Version:** `^0.8.28` for core contracts, `^0.8.0` for some verifiers
- Core protocol (StateOracle, interfaces, Batch): `^0.8.28`
- Admin verifiers: `^0.8.0` (broader compatibility) or `^0.8.28`
- DA verifiers: `^0.8.28`

**Reasoning:** Allows minor version bumps within major version (0.8.x); guards against breaking changes in 0.9+

## Type Casting

**Patterns:**
- Explicit casting: `uint128(block.number)`, `address(this)`
- Use `uint128` for block numbers that will be stored long-term (memory savings)
- Rare casting of `uint256` to `uint16` in loops (e.g., `bytes32(uint256(i))`)

**Example from StateOracle.sol:**
```solidity
assertionAdopters[contractAddress].assertions[assertionId].activationBlock =
    uint128(block.number) + ASSERTION_TIMELOCK_BLOCKS;
```

## Constants and Immutables

**Immutables:**
- Set in constructor, cannot change after deployment
- Use for core configuration: `ASSERTION_TIMELOCK_BLOCKS`, `DA_VERIFIER`
- ALL_CAPS naming convention

**Constants:**
- Role identifiers use `keccak256("ROLE_NAME")` pattern
- `bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");`

---

*Convention analysis: 2026-03-09*
