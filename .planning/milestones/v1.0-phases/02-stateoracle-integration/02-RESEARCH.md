# Phase 2: StateOracle Integration - Research

**Researched:** 2026-03-09
**Domain:** Solidity upgradeable contract modification, storage layout safety, Foundry testing
**Confidence:** HIGH

## Summary

Phase 2 integrates the `DAVerifierRegistry` library (built in Phase 1) into `StateOracle`, transforming it from a single-immutable-DA-verifier model to a governance-managed registry where managers choose a registered DA verifier per-assertion. This is the heaviest phase (12 requirements) because registry governance, assertion flow changes, constructor changes, and storage layout safety are tightly coupled and must land together.

The core changes are: (1) add `using DAVerifierRegistry for mapping(IDAVerifier => bool)` and a new `daVerifiers` storage mapping appended after `maxAssertionsPerAA` at slot 8, (2) remove the `DA_VERIFIER` immutable from the constructor, (3) add governance functions `addDAVerifier`/`removeDAVerifier`/`isDAVerifierRegistered` mirroring the admin verifier pattern exactly, (4) extend `initialize()` to accept `IDAVerifier[]`, (5) change `addAssertion` signature to accept `IDAVerifier daVerifier`, (6) extend the `AssertionAdded` event with verifier/metadata/proof fields, and (7) validate storage layout safety.

**Primary recommendation:** Mirror the existing `AdminVerifierRegistry` integration pattern exactly -- same naming conventions, same external/internal function split, same NatDoc style. The new `daVerifiers` mapping occupies slot 8 (append-only after slot 7's `maxAssertionsPerAA`). All existing tests need signature updates but preserve their behavioral assertions.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions
- Event Indexing: AssertionAdded indexes all 3 available slots (assertionAdopter, assertionId, daVerifier); metadata and proof unindexed bytes. AssertionRemoved indexes assertionAdopter + assertionId.
- Storage Layout: No __gap array. Storage validated via automated test asserting known slots in expected order. No snapshot that breaks on intentional additions.
- addAssertion Signature: `addAssertion(address contractAddress, IDAVerifier daVerifier, bytes32 assertionId, bytes calldata metadata, bytes calldata proof)`. New custom error `DAVerifierNotRegistered()` on StateOracle. Rename `InvalidProof` to `InvalidDAProof(IDAVerifier daVerifier)`.
- initialize() Signature: `initialize(address admin, IAdminVerifier[] calldata _adminVerifiers, IDAVerifier[] calldata _daVerifiers, uint16 _maxAssertionsPerAA)`.
- Governance Functions: addDAVerifier/removeDAVerifier mirror addAdminVerifier/removeAdminVerifier exactly. Public mapping `daVerifiers` + explicit `isDAVerifierRegistered(IDAVerifier)` view function.
- Error Handling Flow: Verifier reverts bubble up (no try/catch). Check order: hasAssertion first, then DAVerifierNotRegistered, then verifyDA, then assertion count. InvalidDAProof(IDAVerifier daVerifier) includes verifier address.
- Test Organization: Unit tests in StateOracle.t.sol using DAVerifierMock. New integration test matrix: abstract base + 4 concrete (AdminVerifierOwner/Whitelist x DAVerifierECDSA/OnChain).
- Batch call compatibility testing deferred to Phase 3.

### Claude's Discretion
- Internal helper naming (_addDAVerifier, _removeDAVerifier)
- NatDoc style and comment depth on new functions
- Storage layout test implementation details (which slots to assert ordering on)
- Integration test file naming and organization within test/ directory

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| R2 | Governance can add DA verifiers | Mirror addAdminVerifier pattern: external onlyGovernance -> internal _addDAVerifier -> daVerifiers.add() |
| R3 | Governance can remove DA verifiers | Mirror removeAdminVerifier pattern: external onlyGovernance -> daVerifiers.remove() |
| R4 | Public view for verifier registration check | isDAVerifierRegistered(IDAVerifier) -> daVerifiers.isRegistered(), mirror isAdminVerifierRegistered exactly |
| R5 | Initialize with default DA verifiers | Add IDAVerifier[] parameter to initialize(), loop calling _addDAVerifier, placed between admin verifiers and maxAssertionsPerAA |
| R6 | Manager picks DA verifier per-assertion | New IDAVerifier daVerifier param in addAssertion after contractAddress |
| R7 | addAssertion validates verifier is registered | require(daVerifiers.isRegistered(daVerifier), DAVerifierNotRegistered()) after hasAssertion check |
| R8 | addAssertion calls verifyDA on chosen verifier | Replace DA_VERIFIER.verifyDA with daVerifier.verifyDA(assertionId, metadata, proof), revert with InvalidDAProof(daVerifier) |
| R9 | AssertionAdded event extended | Add indexed daVerifier + unindexed metadata + unindexed proof to event; uses all 3 index slots |
| R10 | IDAVerifier interface unchanged | verifyDA(bytes32, bytes, bytes) signature stays as-is; verified in current code |
| R13 | Storage layout preserved for proxy upgrade | New daVerifiers mapping at slot 8 (after maxAssertionsPerAA at slot 7); append-only, no reordering |
| R14 | DA_VERIFIER immutable removed from constructor | Constructor takes only assertionTimelockBlocks; no daVerifier address parameter |
| R15 | Storage layout validated with forge inspect | Test compares forge inspect output for slot ordering invariants |

</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Solidity | ^0.8.28 | Smart contract language | Project standard |
| Foundry (forge) | Latest | Build, test, format, inspect storage | Project standard |
| OpenZeppelin Contracts | 5.x (vendored in lib/) | AccessControl, TransparentUpgradeableProxy, Ownable2Step | Project standard |
| Solady | Latest (vendored in lib/) | Initializable, ECDSA | Project standard |
| forge-std | Latest (vendored in lib/) | Test utilities, vm cheatcodes | Project standard |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| DAVerifierRegistry | Phase 1 output | Library for mapping(IDAVerifier => bool) with add/remove/isRegistered | Always -- core of this integration |
| DAVerifierOnChain | Phase 1 output | keccak256(proof) == assertionId verifier | Integration tests |
| DAVerifierECDSA | Existing | ECDSA signature-based DA verifier | Integration tests |
| DAVerifierMock | Existing test util | Always-returns-true mock | Unit tests |

## Architecture Patterns

### Current Storage Layout (MUST PRESERVE slots 0-7)
```
Slot 0: _owner                (address)         -- from Ownable
Slot 1: _pendingOwner         (address)         -- from Ownable2Step
Slot 2: _roles                (mapping)         -- from AccessControl
Slot 3: assertionAdopters     (mapping)         -- StateOracle
Slot 4: adminVerifiers        (mapping)         -- StateOracle
Slot 5: whitelistEnabled      (bool)            -- StateOracle
Slot 6: whitelist             (mapping)         -- StateOracle
Slot 7: maxAssertionsPerAA    (uint16)          -- StateOracle
Slot 8: daVerifiers           (mapping)         -- NEW: append-only
```

### Pattern 1: Library-on-Mapping (Mirror AdminVerifierRegistry)
**What:** Attach library functions to a storage mapping via `using ... for mapping(...)`
**When to use:** Always for registry operations
**Example:**
```solidity
// Existing pattern in StateOracle.sol line 18
using AdminVerifierRegistry for mapping(IAdminVerifier adminVerifier => bool isRegistered);

// New addition -- identical pattern
using DAVerifierRegistry for mapping(IDAVerifier daVerifier => bool isRegistered);
```

### Pattern 2: Governance Function (External -> Internal Helper)
**What:** External onlyGovernance function delegates to internal helper; internal helper is also called from initialize()
**When to use:** For addDAVerifier/removeDAVerifier
**Example (existing pattern from admin verifiers):**
```solidity
// External with governance check
function addAdminVerifier(IAdminVerifier adminVerifier) external onlyGovernance {
    _addAdminVerifier(adminVerifier);
}

// Internal helper used by both external and initialize()
function _addAdminVerifier(IAdminVerifier adminVerifier) internal {
    adminVerifiers.add(adminVerifier);
}
```
The DA verifier functions must follow this pattern identically.

### Pattern 3: Constructor Immutables + Disabled Initializers
**What:** Constructor sets immutables, renounces ownership, disables initializers
**When to use:** StateOracle constructor
**Current:**
```solidity
constructor(uint128 assertionTimelockBlocks, address daVerifier) Ownable(msg.sender) {
    require(assertionTimelockBlocks > 0, InvalidAssertionTimelock());
    ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
    DA_VERIFIER = IDAVerifier(daVerifier);
    renounceOwnership();
    _disableInitializers();
}
```
**After change:** Remove `DA_VERIFIER` immutable and `daVerifier` parameter entirely. Constructor becomes single-parameter.

### Pattern 4: Event Emission with Index Allocation
**What:** Solidity events have 3 available indexed parameter slots (topic1, topic2, topic3; topic0 is event signature)
**Current AssertionAdded:**
```solidity
event AssertionAdded(address assertionAdopter, bytes32 assertionId, uint256 activationBlock);
// Currently: NO indexed params used
```
**New AssertionAdded:**
```solidity
event AssertionAdded(
    address indexed assertionAdopter,
    bytes32 indexed assertionId,
    IDAVerifier indexed daVerifier,
    uint256 activationBlock,
    bytes metadata,
    bytes proof
);
```
Uses all 3 index slots. metadata and proof are unindexed bytes fields (cannot be efficiently indexed).

### Pattern 5: Integration Test Matrix (Abstract Base + Concrete Implementations)
**What:** Single abstract contract defines all assertion flow tests; concrete contracts provide setUp with specific verifier combinations
**When to use:** New integration test files
**Structure:**
```
test/integration/
  StateOracleAssertionFlowBase.sol     -- abstract base with all test methods
  StateOracleOwnerECDSA.t.sol          -- AdminVerifierOwner + DAVerifierECDSA
  StateOracleOwnerOnChain.t.sol        -- AdminVerifierOwner + DAVerifierOnChain
  StateOracleWhitelistECDSA.t.sol      -- AdminVerifierWhitelist + DAVerifierECDSA
  StateOracleWhitelistOnChain.t.sol    -- AdminVerifierWhitelist + DAVerifierOnChain
```
Each concrete contract overrides setUp and provides helper functions for generating valid proofs.

### Anti-Patterns to Avoid
- **Reordering storage variables:** NEVER change the order of slots 0-7. The new `daVerifiers` mapping MUST go after `maxAssertionsPerAA` at slot 8.
- **Try/catch around verifyDA:** User decision says reverts bubble up. Do NOT wrap in try/catch.
- **Custom error on StateOracle reusing library error name:** User decided `DAVerifierNotRegistered()` is a new StateOracle error, NOT reusing `DAVerifierRegistry.DAVerifierNotRegistered`.
- **Adding __gap arrays:** User explicitly decided no gap arrays needed since StateOracle is terminal in the inheritance chain.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| DA verifier registry logic | Custom add/remove/check functions | `DAVerifierRegistry` library (Phase 1) | Already built, tested, mirrors AdminVerifierRegistry |
| Proxy deployment for tests | Manual proxy setup | `ProxyHelper.deployProxy()` | Existing utility handles TransparentUpgradeableProxy consistently |
| ECDSA proof generation in tests | Manual signature computation | `vm.sign(privateKey, assertionId)` | Foundry cheatcode, reliable |
| On-chain proof generation in tests | Manual hash computation | `keccak256(bytecode)` as assertionId with `bytecode` as proof | Direct from DAVerifierOnChain contract logic |

**Key insight:** Phase 1 outputs (DAVerifierRegistry, DAVerifierOnChain) are fully tested and ready for integration. The Phase 2 work is purely about wiring them into StateOracle.

## Common Pitfalls

### Pitfall 1: Breaking the initialize() ABI
**What goes wrong:** The `initialize` function selector changes when parameters change, breaking any existing encode calls.
**Why it happens:** `abi.encodeCall(StateOracle.initialize, (...))` in deployment scripts and tests uses compile-time type checking.
**How to avoid:** Update ALL call sites: test setUp functions, integration tests, deployment scripts (though deployment script updates are Phase 3).
**Warning signs:** Compilation errors in tests after changing initialize signature.
**Affected files:** `test/StateOracle.t.sol` (StateOracleBase.setUp), `test/integration/StateOracleWithDAVerifierECDSA.sol`, `test/integration/DeployCoreWithStaging.t.sol`.

### Pitfall 2: addAssertion Selector Change Breaks Batch Tests
**What goes wrong:** The batch test encodes `addAssertion` calls with the old 4-parameter selector. After adding the `daVerifier` parameter, encoded selectors no longer match.
**Why it happens:** `abi.encodeWithSelector(StateOracle.addAssertion.selector, ...)` uses compile-time selector lookup.
**How to avoid:** Update all batch test encode calls to include the new `daVerifier` parameter.
**Warning signs:** Batch tests fail with revert or wrong function dispatch.

### Pitfall 3: Transparent Proxy Admin Interference
**What goes wrong:** Test calls from the proxy admin address are intercepted by the proxy, not forwarded to the implementation.
**Why it happens:** TransparentUpgradeableProxy's fallback logic routes admin calls to ProxyAdmin.
**How to avoid:** Use the existing `noAdmin(address)` modifier in tests. Never use the proxy admin address as a test actor.
**Warning signs:** Unexpected reverts or missing function errors in tests.

### Pitfall 4: Event Signature Change Breaks Existing Tests
**What goes wrong:** Tests using `vm.expectEmit` with the old `AssertionAdded` signature fail because event topics changed.
**Why it happens:** Adding indexed parameters changes the event's topic count and data layout.
**How to avoid:** Update all `vm.expectEmit` calls for `AssertionAdded` to match the new 6-parameter signature with correct indexed fields.
**Warning signs:** Test failures in event assertion tests.

### Pitfall 5: Constructor Change Breaks All Test setUp
**What goes wrong:** Removing the `daVerifier` constructor parameter causes all `new StateOracle(TIMEOUT, address(daVerifier))` calls to fail.
**Why it happens:** Constructor signature changes from 2-param to 1-param.
**How to avoid:** Update ALL `new StateOracle(...)` calls across tests and scripts simultaneously.
**Warning signs:** Compilation errors everywhere.

### Pitfall 6: Storage Layout Validation Test Brittleness
**What goes wrong:** Storage layout test that relies on exact slot numbers breaks when unrelated upstream changes add storage to parent contracts.
**Why it happens:** Inheritance order and parent contract storage can shift absolute slot assignments.
**How to avoid:** Test relative ordering (assertionAdopters before adminVerifiers before whitelistEnabled before whitelist before maxAssertionsPerAA before daVerifiers) rather than absolute slot numbers.
**Warning signs:** Test passes locally but fails after dependency updates.

### Pitfall 7: DAVerifierMock Needs Registration in Unit Tests
**What goes wrong:** After the change, addAssertion requires the DA verifier to be registered. Unit tests using DAVerifierMock will fail if the mock isn't registered in the DA verifier registry.
**Why it happens:** New `require(daVerifiers.isRegistered(daVerifier), DAVerifierNotRegistered())` check.
**How to avoid:** In test setUp, register DAVerifierMock in the DA verifier registry either via initialize() or via addDAVerifier.
**Warning signs:** All addAssertion unit tests revert with DAVerifierNotRegistered.

### Pitfall 8: Integration Test ECDSA setUp Must Not stopPrank
**What goes wrong:** The existing StateOracleWithDAVerifierECDSA test setUp calls `vm.startPrank(OWNER)` without stopping in setUp, relying on tests to call stopPrank.
**Why it happens:** Legacy test structure.
**How to avoid:** In new integration tests, keep setUp self-contained. Start and stop pranks within each test method.
**Warning signs:** Prank state leaks between tests.

## Code Examples

### Change 1: StateOracle Constructor (Before/After)
```solidity
// BEFORE
constructor(uint128 assertionTimelockBlocks, address daVerifier) Ownable(msg.sender) {
    require(assertionTimelockBlocks > 0, InvalidAssertionTimelock());
    ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
    DA_VERIFIER = IDAVerifier(daVerifier);
    renounceOwnership();
    _disableInitializers();
}

// AFTER
constructor(uint128 assertionTimelockBlocks) Ownable(msg.sender) {
    require(assertionTimelockBlocks > 0, InvalidAssertionTimelock());
    ASSERTION_TIMELOCK_BLOCKS = assertionTimelockBlocks;
    renounceOwnership();
    _disableInitializers();
}
```

### Change 2: Initialize Signature (Before/After)
```solidity
// BEFORE
function initialize(address admin, IAdminVerifier[] calldata _adminVerifiers, uint16 _maxAssertionsPerAA)

// AFTER
function initialize(
    address admin,
    IAdminVerifier[] calldata _adminVerifiers,
    IDAVerifier[] calldata _daVerifiers,
    uint16 _maxAssertionsPerAA
) external initializer {
    _initializeRoles(admin);
    whitelistEnabled = true;
    for (uint256 i = 0; i < _adminVerifiers.length; i++) {
        _addAdminVerifier(_adminVerifiers[i]);
    }
    for (uint256 i = 0; i < _daVerifiers.length; i++) {
        _addDAVerifier(_daVerifiers[i]);
    }
    _setMaxAssertionsPerAA(_maxAssertionsPerAA);
}
```

### Change 3: addAssertion (Before/After)
```solidity
// BEFORE
function addAssertion(address contractAddress, bytes32 assertionId, bytes calldata metadata, bytes calldata proof)
    external onlyManager(contractAddress) onlyWhitelisted
{
    require(!hasAssertion(contractAddress, assertionId), AssertionAlreadyExists());
    require(DA_VERIFIER.verifyDA(assertionId, metadata, proof), InvalidProof());
    require(assertionAdopters[contractAddress].assertionCount < maxAssertionsPerAA, TooManyAssertions());
    // ...
    emit AssertionAdded(contractAddress, assertionId, uint256(block.number + ASSERTION_TIMELOCK_BLOCKS));
}

// AFTER
function addAssertion(
    address contractAddress,
    IDAVerifier daVerifier,
    bytes32 assertionId,
    bytes calldata metadata,
    bytes calldata proof
) external onlyManager(contractAddress) onlyWhitelisted {
    require(!hasAssertion(contractAddress, assertionId), AssertionAlreadyExists());
    require(daVerifiers.isRegistered(daVerifier), DAVerifierNotRegistered());
    require(daVerifier.verifyDA(assertionId, metadata, proof), InvalidDAProof(daVerifier));
    require(assertionAdopters[contractAddress].assertionCount < maxAssertionsPerAA, TooManyAssertions());
    // ...
    emit AssertionAdded(contractAddress, assertionId, daVerifier, activationBlock, metadata, proof);
}
```

### Change 4: New Governance Functions
```solidity
// Mirrors addAdminVerifier/removeAdminVerifier exactly
function addDAVerifier(IDAVerifier daVerifier) external onlyGovernance {
    _addDAVerifier(daVerifier);
}

function _addDAVerifier(IDAVerifier daVerifier) internal {
    daVerifiers.add(daVerifier);
}

function removeDAVerifier(IDAVerifier daVerifier) external onlyGovernance {
    daVerifiers.remove(daVerifier);
}

function isDAVerifierRegistered(IDAVerifier daVerifier) public view returns (bool isRegistered) {
    return daVerifiers.isRegistered(daVerifier);
}
```

### Change 5: New Error Declarations
```solidity
// Remove
error InvalidProof();

// Add
error DAVerifierNotRegistered();
error InvalidDAProof(IDAVerifier daVerifier);
```

### Change 6: New Event Signatures
```solidity
// BEFORE
event AssertionAdded(address assertionAdopter, bytes32 assertionId, uint256 activationBlock);
event AssertionRemoved(address assertionAdopter, bytes32 assertionId, uint256 deactivationBlock);

// AFTER
event AssertionAdded(
    address indexed assertionAdopter,
    bytes32 indexed assertionId,
    IDAVerifier indexed daVerifier,
    uint256 activationBlock,
    bytes metadata,
    bytes proof
);
event AssertionRemoved(
    address indexed assertionAdopter,
    bytes32 indexed assertionId,
    uint256 deactivationBlock
);
```

### Change 7: Test setUp Pattern Update
```solidity
// BEFORE (in StateOracleBase)
function setUp() public virtual {
    DAVerifierMock daVerifier = new DAVerifierMock();
    StateOracle implementation = new StateOracle(TIMEOUT, address(daVerifier));
    // ...
    bytes memory data = abi.encodeWithSelector(
        StateOracle.initialize.selector, STATE_ORACLE_ADMIN, verifiers, MAX_ASSERTIONS_PER_AA
    );
    // ...
}

// AFTER
function setUp() public virtual {
    DAVerifierMock daVerifierMock = new DAVerifierMock();
    StateOracle implementation = new StateOracle(TIMEOUT);
    // ...
    IDAVerifier[] memory daVerifiers = new IDAVerifier[](1);
    daVerifiers[0] = IDAVerifier(address(daVerifierMock));
    bytes memory data = abi.encodeWithSelector(
        StateOracle.initialize.selector, STATE_ORACLE_ADMIN, verifiers, daVerifiers, MAX_ASSERTIONS_PER_AA
    );
    // ...
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single immutable DA_VERIFIER | DA verifier registry (mapping) | Phase 2 | Managers choose verifier per-assertion |
| Constructor sets DA verifier | initialize() populates registry | Phase 2 | Multiple verifiers supported; governance can add/remove |
| AssertionAdded with 3 unindexed fields | AssertionAdded with 3 indexed + 3 data fields | Phase 2 | Proof data available in event logs for indexers |

**Deprecated/outdated after Phase 2:**
- `DA_VERIFIER` immutable: removed entirely
- `InvalidProof` error: renamed to `InvalidDAProof(IDAVerifier daVerifier)` with context
- Old `addAssertion` 4-param signature: replaced with 5-param including daVerifier
- Old `initialize` 3-param signature: replaced with 4-param including IDAVerifier[]
- Old unindexed `AssertionAdded` event: replaced with fully-indexed version

## Open Questions

1. **Deployment script impact from constructor change**
   - What we know: Phase 3 handles deployment script updates. Constructor signature change in Phase 2 will break deployment scripts.
   - What's unclear: Whether deployment scripts should be updated minimally in Phase 2 to keep them compilable.
   - Recommendation: Update deployment scripts minimally for compilation (change constructor call), mark full Phase 3 deployment updates as separate. OR accept compilation warnings on scripts during Phase 2 and fix fully in Phase 3.

2. **Integration test file organization**
   - What we know: User wants 4 concrete test files with abstract base.
   - What's unclear: Exact file naming convention for test/integration/ directory.
   - Recommendation: Use descriptive names like `StateOracleOwnerECDSA.t.sol` following the `{Contract}{AdminVerifier}{DAVerifier}.t.sol` pattern.

3. **Existing integration test updates**
   - What we know: `test/integration/StateOracleWithDAVerifierECDSA.sol` and `test/integration/DeployCoreWithStaging.t.sol` will break due to constructor/initialize changes.
   - What's unclear: Whether existing integration tests should be updated in Phase 2 or Phase 3.
   - Recommendation: Update `StateOracleWithDAVerifierECDSA.sol` in Phase 2 (it tests assertion flow). Defer `DeployCoreWithStaging.t.sol` to Phase 3 (it tests deployment flow). For compilation, both need minimal constructor param fixes.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Foundry (forge test) |
| Config file | foundry.toml |
| Quick run command | `forge test --match-path test/StateOracle.t.sol` |
| Full suite command | `forge test` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R2 | Governance can add DA verifiers | unit | `forge test --match-path test/StateOracle.t.sol --match-contract AddDAVerifier -vv` | Wave 0 |
| R3 | Governance can remove DA verifiers | unit | `forge test --match-path test/StateOracle.t.sol --match-contract RemoveDAVerifier -vv` | Wave 0 |
| R4 | Public view isDAVerifierRegistered | unit | `forge test --match-path test/StateOracle.t.sol --match-contract AddDAVerifier -vv` | Wave 0 |
| R5 | Initialize with DA verifier array | unit | `forge test --match-path test/StateOracle.t.sol --match-contract Initialize -vv` | Exists (needs update) |
| R6 | addAssertion accepts daVerifier param | unit | `forge test --match-path test/StateOracle.t.sol --match-contract AddAssertion -vv` | Exists (needs update) |
| R7 | addAssertion reverts on unregistered verifier | unit | `forge test --match-path test/StateOracle.t.sol --match-contract AddAssertion -vv` | Wave 0 |
| R8 | addAssertion delegates to chosen verifier | integration | `forge test --match-path test/integration/ -vv` | Wave 0 |
| R9 | AssertionAdded event extended | unit | `forge test --match-path test/StateOracle.t.sol --match-test expectAssertionAdded -vv` | Exists (needs update) |
| R10 | IDAVerifier interface unchanged | unit | Compile check -- `forge build` | Exists |
| R13 | Storage layout append-only | unit | `forge test --match-test storageLayout -vv` | Wave 0 |
| R14 | DA_VERIFIER immutable removed | unit | `forge test --match-path test/StateOracle.t.sol --match-contract Constructor -vv` | Exists (needs update) |
| R15 | Storage layout validated | unit | `forge test --match-test storageLayout -vv` | Wave 0 |

### Sampling Rate
- **Per task commit:** `forge test --match-path test/StateOracle.t.sol`
- **Per wave merge:** `forge test`
- **Phase gate:** Full suite green before /gsd:verify-work

### Wave 0 Gaps
- [ ] `AddDAVerifier` test contract in `test/StateOracle.t.sol` -- covers R2, R4
- [ ] `RemoveDAVerifier` test contract in `test/StateOracle.t.sol` -- covers R3
- [ ] Test for DAVerifierNotRegistered revert in AddAssertion -- covers R7
- [ ] Storage layout ordering test (new file or in StateOracle.t.sol) -- covers R13, R15
- [ ] Integration test base + 4 concrete implementations in `test/integration/` -- covers R8
- [ ] Update existing tests for new signatures -- covers R5, R6, R9, R14

## Sources

### Primary (HIGH confidence)
- `src/StateOracle.sol` - Current implementation, all patterns extracted directly
- `src/StateOracleAccessControl.sol` - Role hierarchy and governance modifier patterns
- `src/lib/AdminVerifierRegistry.sol` - Mirror pattern for DA verifier registry integration
- `src/lib/DAVerifierRegistry.sol` - Phase 1 output, ready for integration
- `src/verification/da/DAVerifierOnChain.sol` - Phase 1 output, ready for integration tests
- `src/verification/da/DAVerifierECDSA.sol` - Existing verifier for integration tests
- `test/StateOracle.t.sol` - Current test patterns, all test contract names and structures
- `forge inspect StateOracle storage-layout` - Verified current slot assignments (0-7)

### Secondary (MEDIUM confidence)
- `test/integration/StateOracleWithDAVerifierECDSA.sol` - Existing integration test pattern
- `test/integration/DeployCoreWithStaging.t.sol` - Deployment integration test (Phase 3 concern)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All libraries already in the project, no new dependencies needed
- Architecture: HIGH - Patterns are directly extracted from existing code; mirror approach is well-defined
- Pitfalls: HIGH - Identified from direct code analysis of all affected call sites
- Storage layout: HIGH - Verified via forge inspect; slot 8 is confirmed append-only

**Research date:** 2026-03-09
**Valid until:** 2026-04-09 (stable -- no external dependency changes expected)
