# Architecture

**Analysis Date:** 2026-03-09

## Pattern Overview

**Overall:** Proxy-based contract system with pluggable verifier modules

**Key Characteristics:**
- Upgradeable via `TransparentUpgradeableProxy` pattern
- Core orchestrator (`StateOracle`) coordinates multiple independent verifier implementations
- Role-based access control with strict owner/admin invariant enforcement
- Delegatecall-based batch execution for atomic multi-operation transactions
- Immutable configuration injected at construction time

## Layers

**Entry Point / Orchestration:**
- Purpose: Manages assertion adopter registration, assertion lifecycle, and delegation to verifiers
- Location: `src/StateOracle.sol`
- Contains: Core protocol state machine, assertion tracking, manager delegation
- Depends on: `IAdminVerifier`, `IDAVerifier`, `StateOracleAccessControl`, `Batch`, `AdminVerifierRegistry`
- Used by: Users via external contract interactions, governance via admin verifiers

**Access Control:**
- Purpose: Enforces role hierarchy and owner/DEFAULT_ADMIN_ROLE coupling invariant
- Location: `src/StateOracleAccessControl.sol`
- Contains: Five-tier role system, ownership safety constraints, role grant/revoke overrides
- Depends on: OpenZeppelin `Ownable2Step` and `AccessControl`
- Used by: `StateOracle` for modifier enforcement

**Batch Execution:**
- Purpose: Enable atomic multi-operation transactions via delegatecall
- Location: `src/Batch.sol`
- Contains: Loop over encoded function calls, delegatecall execution, error wrapping
- Depends on: `IBatch` interface
- Used by: `StateOracle` (mixins via inheritance) for composite operations

**Verification: Admin:**
- Purpose: Determine who may register new assertion adopters
- Location: `src/verification/admin/`
- Contains: Multiple implementations (`AdminVerifierOwner`, `AdminVerifierWhitelist`, `AdminVerifierSuperAdmin`)
- Depends on: `IAdminVerifier` interface
- Used by: `StateOracle.registerAssertionAdopter()` with pluggable module lookup

**Verification: Data Availability:**
- Purpose: Prove assertion bytecode is available before accepting registration
- Location: `src/verification/da/`
- Contains: ECDSA signature verification (`DAVerifierECDSA`)
- Depends on: `IDAVerifier` interface
- Used by: `StateOracle.addAssertion()` before accepting assertion window

**Registry Helper:**
- Purpose: Manage the mapping of registered verifiers and emit registration events
- Location: `src/lib/AdminVerifierRegistry.sol`
- Contains: Library functions for add/remove/isRegistered over verifier mappings
- Depends on: `IAdminVerifier` interface
- Used by: `StateOracle` to manage admin verifier registry

## Data Flow

**Assertion Adopter Registration:**

1. User calls `registerAssertionAdopter(contractAddress, adminVerifier, data)` on proxy
2. StateOracle checks `onlyWhitelisted` modifier
3. StateOracle verifies `adminVerifier` is registered in `adminVerifiers` mapping
4. StateOracle delegates to `adminVerifier.verifyAdmin(contractAddress, msg.sender, data)`
5. If verification succeeds, StateOracle creates `AssertionAdopter` entry with `msg.sender` as manager
6. Emit `AssertionAdopterAdded` event

**Assertion Registration and Activation:**

1. Manager calls `addAssertion(contractAddress, assertionId, metadata, proof)` on proxy
2. StateOracle checks `onlyManager` and `onlyWhitelisted` modifiers
3. StateOracle delegates to `DA_VERIFIER.verifyDA(assertionId, metadata, proof)` (immutable at construction)
4. If verification succeeds, StateOracle stores `AssertionWindow` with `activationBlock = block.number + ASSERTION_TIMELOCK_BLOCKS`
5. Assertion only becomes usable after timelock expires
6. Emit `AssertionAdded` event

**Assertion Removal (Deactivation):**

1. Manager or guardian calls `removeAssertion(contractAddress, assertionId)`
2. StateOracle stores `deactivationBlock = block.number + ASSERTION_TIMELOCK_BLOCKS`
3. Assertion transitions to inactive after timelock expires
4. Cannot be re-added due to non-zero `activationBlock`
5. Emit `AssertionRemoved` event

**Manager Transfer (Two-Step):**

1. Current manager calls `transferManager(contractAddress, newManager)`
2. StateOracle stores pending manager, emits `ManagerTransferRequested`
3. New manager must call `acceptManagerTransfer(contractAddress)` to finalize
4. Or guardian can call `revokeManager(contractAddress)` to force zero address

**State Management:**

- Per-adopter state: `mapping(address => AssertionAdopter)` containing manager, pending manager, assertion count, and nested assertion windows
- Global verifier registry: `mapping(IAdminVerifier => bool)` of registered admin verifiers
- Whitelist control: `whitelistEnabled` flag and `mapping(address => bool)` for whitelisted callers
- Immutable config: `ASSERTION_TIMELOCK_BLOCKS` and `DA_VERIFIER` set at construction

## Key Abstractions

**AssertionAdopter Struct:**
- Purpose: Container for adopter-specific state (manager, assertions, counts)
- Examples: `src/StateOracle.sol` lines 62-67
- Pattern: Nested mapping pattern—adopter address → adopter data → assertion ID → assertion window

**AssertionWindow Struct:**
- Purpose: Time-windowed representation of assertion state
- Examples: `src/StateOracle.sol` lines 72-75
- Pattern: Two uint128 values (activation and deactivation blocks) track lifecycle boundaries

**Verifier Interface Pattern:**
- Purpose: Pluggable implementation contracts that return true/false from a `verify*()` method
- Examples: `src/interfaces/IAdminVerifier.sol`, `src/interfaces/IDAVerifier.sol`
- Pattern: Stateless or minimally stateful view functions; verifiers can be swapped at runtime via registry

**Registry Libary:**
- Purpose: Reusable add/remove/isRegistered logic for managing verifier collections
- Examples: `src/lib/AdminVerifierRegistry.sol`
- Pattern: Internal library functions operating over storage mappings, emit events on state change

## Entry Points

**StateOracle Proxy (TransparentUpgradeableProxy):**
- Location: Deployed proxy address (from deployment script output)
- Triggers: Any transaction calling StateOracle functions
- Responsibilities: Route calls to implementation, enforce proxy admin controls

**StateOracle.initialize(admin, adminVerifiers, maxAssertionsPerAA):**
- Location: `src/StateOracle.sol` lines 178-189
- Triggers: Called once during proxy deployment via constructor encoding
- Responsibilities: Set owner, initialize role hierarchy, register admin verifiers, set assertion limit

**StateOracle.registerAssertionAdopter(...):**
- Location: `src/StateOracle.sol` lines 195-204
- Triggers: User/adopter manager initiates new protocol registration
- Responsibilities: Verify admin ownership, create adopter entry, emit event

**StateOracle.addAssertion(...):**
- Location: `src/StateOracle.sol` lines 213-226
- Triggers: Manager submits a new assertion for inclusion
- Responsibilities: Verify DA availability, create assertion window with timelock, increment counter

**Governance Entry Points:**
- Location: `src/StateOracle.sol` lines 242-406
- Triggers: Governance role holders invoke configuration changes
- Responsibilities: Enable/disable whitelist, manage admin verifiers, adjust assertion limits

**Guardian Entry Points:**
- Location: `src/StateOracle.sol` lines 238-240, 359-362
- Triggers: Guardian role holders invoke emergency actions
- Responsibilities: Remove assertions or revoke managers without manager consent

## Error Handling

**Strategy:** Custom error types with explicit revert messages for each failure condition

**Patterns:**

- **Access Control:** `UnauthorizedManager()` (line 160), `UnauthorizedRegistrant()` (line 200)
- **Constraint Violations:** `AssertionAlreadyExists()` (line 218), `TooManyAssertions()` (line 220)
- **Lifecycle Violations:** `AssertionAlreadyRemoved()` (line 285), `AssertionDoesNotExist()` (line 283)
- **Batch Failures:** `BatchError(bytes result)` (src/Batch.sol line 12) wraps delegatecall failures
- **Whitelist Errors:** `NotWhitelisted()`, `AlreadyWhitelisted()`, `AccountNotWhitelisted()` (lines 49-53)
- **Verifier Registry:** `AdminVerifierNotRegistered()` from `AdminVerifierRegistry` (line 199)

All custom errors are defined as top-level contract definitions or library definitions for Foundry error tracking.

## Cross-Cutting Concerns

**Logging:**

Events emitted for all state mutations:
- `AssertionAdopterAdded`, `ManagerTransferRequested`, `ManagerTransferred` (adoption & transfer flow)
- `AssertionAdded`, `AssertionRemoved` (assertion lifecycle)
- `WhitelistEnabled`, `WhitelistDisabled`, `AddedToWhitelist`, `RemovedFromWhitelist` (whitelist management)
- `AdminVerifierAdded`, `AdminVerifierRemoved` (via `AdminVerifierRegistry` library, line 17-21)

**Validation:**

Constraints enforced at function entry:
- `onlyManager(contractAddress)` modifier ensures caller matches adopter manager
- `onlyWhitelisted` modifier checks whitelist enabled + caller whitelisted (lines 142-153)
- `require()` statements for data integrity (assertion count < max, no double-add, valid proofs)

**Authentication:**

Role-based via `StateOracleAccessControl`:
- `onlyGovernance` for whitelist toggling and verifier registry management
- `onlyGuardian` for emergency assertion/manager removal
- `onlyOperator` for whitelist member management
- `onlyOwner` for role delegation and 2-step ownership transfer

**Upgradeability Preservation:**

- Constructor disables initializers on implementation via `_disableInitializers()` (line 171)
- Initialization deferred to proxy via `initialize()` using `initializer` modifier (line 180)
- Storage layout preserved: new fields appended at end (e.g., `maxAssertionsPerAA` line 148)
- No storage reordering or removal of existing fields

---

*Architecture analysis: 2026-03-09*
