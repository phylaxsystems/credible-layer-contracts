# Phase 1: DAVerifierRegistry Library + DAVerifierOnChain - Research

**Researched:** 2026-03-09
**Domain:** Solidity library + contract development (Foundry, mirroring existing codebase patterns)
**Confidence:** HIGH

## Summary

Phase 1 creates two independent, self-contained artifacts: a `DAVerifierRegistry` library and a `DAVerifierOnChain` contract. Neither touches any existing code in the repository. Both artifacts are new files that follow patterns already established in the codebase (the `AdminVerifierRegistry` library and `DAVerifierECDSA` contract respectively), making this a low-risk, pattern-replication phase.

The `DAVerifierRegistry` library is a near-exact structural mirror of the existing `AdminVerifierRegistry` library (54 lines), replacing `IAdminVerifier` references with `IDAVerifier`. It provides `add`, `remove`, and `isRegistered` internal functions operating on a `mapping(IDAVerifier => bool)`. The `DAVerifierOnChain` contract implements the existing `IDAVerifier` interface with a single `pure` function that returns `keccak256(proof) == assertionId`. No new dependencies, no storage changes, no upgrade risk.

The primary risk in this phase is not technical but structural: ensuring the new files follow the exact naming, SPDX, NatDoc, and error/event conventions of the codebase so that Phase 2 integration is seamless.

**Primary recommendation:** Mirror `AdminVerifierRegistry.sol` line-for-line (substituting types), implement `DAVerifierOnChain.verifyDA` as a `pure` function with a single `keccak256` comparison, and write comprehensive unit tests following existing test patterns.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| R1 | DAVerifierRegistry library mirroring AdminVerifierRegistry | Direct template exists at `src/lib/AdminVerifierRegistry.sol` (54 lines). Replace `IAdminVerifier` with `IDAVerifier`, rename errors/events accordingly. Pattern is fully understood. |
| R11 | DAVerifierOnChain implements IDAVerifier | `IDAVerifier` interface at `src/interfaces/IDAVerifier.sol` defines `verifyDA(bytes32, bytes calldata, bytes calldata) returns (bool)`. Implementation: `return keccak256(proof) == assertionId`. Follow `DAVerifierECDSA.sol` structure. |
| R12 | DAVerifierOnChain is pure/view | Implementation uses only `keccak256` (a precompile opcode, not an external call) and comparison. Function can be marked `pure` -- no state reads, no external calls. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Solidity | ^0.8.28 | Smart contract language | Existing pragma across all source files |
| Foundry (forge) | latest | Build, test, format | Existing project toolchain |
| forge-std | vendored in lib/ | Test framework (Test, console) | Already used by all test files |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| IDAVerifier | existing | Interface for DA verifiers | DAVerifierOnChain implements this |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Library with internal functions | Abstract contract with virtual functions | Library is the established pattern in this codebase (AdminVerifierRegistry). Do not deviate. |
| `pure` function | `view` function | `pure` is correct since `keccak256` and comparison use no state. Use `pure`. |

**Installation:**
```bash
# No new dependencies needed. Everything is already vendored.
```

## Architecture Patterns

### Recommended Project Structure
```
src/
├── lib/
│   ├── AdminVerifierRegistry.sol   # existing (template)
│   └── DAVerifierRegistry.sol      # NEW: mirrors AdminVerifierRegistry
├── verification/
│   └── da/
│       ├── DAVerifierECDSA.sol     # existing
│       └── DAVerifierOnChain.sol   # NEW: on-chain hash verifier
├── interfaces/
│   └── IDAVerifier.sol             # existing, unchanged
test/
├── DAVerifierOnChain.t.sol         # NEW: unit tests for verifier
├── DAVerifierRegistry.t.sol        # NEW: unit tests for registry library
```

### Pattern 1: Library with Storage Mapping Parameter
**What:** Libraries that receive a `mapping(InterfaceType => bool) storage` parameter for all operations.
**When to use:** When managing a registry of typed addresses without owning storage directly.
**Example:**
```solidity
// Source: src/lib/AdminVerifierRegistry.sol (existing pattern)
library DAVerifierRegistry {
    error DAVerifierAlreadyRegistered();
    error DAVerifierNotRegistered();

    event DAVerifierAdded(IDAVerifier daVerifier);
    event DAVerifierRemoved(IDAVerifier daVerifier);

    function isRegistered(mapping(IDAVerifier => bool) storage daVerifiers, IDAVerifier daVerifier)
        internal view returns (bool)
    {
        return daVerifiers[daVerifier];
    }

    function add(mapping(IDAVerifier => bool) storage daVerifiers, IDAVerifier daVerifier) internal {
        require(!isRegistered(daVerifiers, daVerifier), DAVerifierAlreadyRegistered());
        daVerifiers[daVerifier] = true;
        emit DAVerifierAdded(daVerifier);
    }

    function remove(mapping(IDAVerifier => bool) storage daVerifiers, IDAVerifier daVerifier) internal {
        require(isRegistered(daVerifiers, daVerifier), DAVerifierNotRegistered());
        daVerifiers[daVerifier] = false;
        emit DAVerifierRemoved(daVerifier);
    }
}
```

### Pattern 2: IDAVerifier Implementation (Stateless)
**What:** A contract implementing IDAVerifier with no constructor arguments and a `pure` function.
**When to use:** When verification logic depends only on function inputs (no external state).
**Example:**
```solidity
// Source: Derived from IDAVerifier interface + project conventions
contract DAVerifierOnChain is IDAVerifier {
    /// @inheritdoc IDAVerifier
    function verifyDA(bytes32 assertionId, bytes calldata, bytes calldata proof)
        external pure returns (bool verified)
    {
        return keccak256(proof) == assertionId;
    }
}
```

### Pattern 3: Foundry Test Structure (Contract-per-Behavior)
**What:** Each test file uses a base contract with shared setup, then separate `contract` blocks for each behavior group.
**When to use:** All test files in this codebase follow this pattern.
**Example:**
```solidity
// Source: test/DAVerifierECDSA.t.sol, test/StateOracle.t.sol (existing patterns)
contract DAVerifierOnChainTest is Test {
    DAVerifierOnChain public verifier;

    function setUp() public {
        verifier = new DAVerifierOnChain();
    }

    // Tests grouped by behavior...
}
```

### Pattern 4: Library Testing via Harness Contract
**What:** Since library `internal` functions cannot be called directly from tests, wrap them in a test harness contract that exposes the internal functions as external.
**When to use:** Testing any library with internal functions.
**Example:**
```solidity
// Test harness for DAVerifierRegistry library
contract DAVerifierRegistryHarness {
    using DAVerifierRegistry for mapping(IDAVerifier => bool);

    mapping(IDAVerifier => bool) public daVerifiers;

    function add(IDAVerifier daVerifier) external {
        daVerifiers.add(daVerifier);
    }

    function remove(IDAVerifier daVerifier) external {
        daVerifiers.remove(daVerifier);
    }

    function isRegistered(IDAVerifier daVerifier) external view returns (bool) {
        return daVerifiers.isRegistered(daVerifier);
    }
}
```

### Anti-Patterns to Avoid
- **Adding storage to StateOracle in Phase 1:** This phase creates independent new files only. The `mapping(IDAVerifier => bool)` storage lives in StateOracle, but that integration happens in Phase 2.
- **Changing IDAVerifier interface:** R10 explicitly requires the interface to remain unchanged. `verifyDA(bytes32, bytes calldata, bytes calldata)` is the signature.
- **Using `view` instead of `pure` for DAVerifierOnChain:** `keccak256` is an opcode, not a state read. The function can and should be `pure`.
- **Importing libraries not already in the project:** No new dependencies needed.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Registry add/remove/check logic | Custom state management | Library pattern from AdminVerifierRegistry | Proven pattern, consistent codebase style, handles error/event emission |
| IDAVerifier compliance | Custom interface | Existing `IDAVerifier` interface | R10 mandates no interface changes |
| Test infrastructure | Custom test base | forge-std `Test` contract | Already used everywhere in the project |

**Key insight:** Phase 1 is pure pattern replication. The template (`AdminVerifierRegistry`) is 54 lines of straightforward Solidity. The verifier contract is ~15 lines of logic. There is nothing to invent.

## Common Pitfalls

### Pitfall 1: Wrong SPDX License for New Files
**What goes wrong:** New files use inconsistent SPDX identifiers, creating legal ambiguity.
**Why it happens:** The codebase mixes `CC0-1.0`, `MIT`, and `GPL-3.0-or-later` across file families.
**How to avoid:** Follow the existing pattern for each file family:
- `src/lib/DAVerifierRegistry.sol` -> `CC0-1.0` (matches `AdminVerifierRegistry.sol`)
- `src/verification/da/DAVerifierOnChain.sol` -> `CC0-1.0` (matches `DAVerifierECDSA.sol`)
- Test files -> `CC0-1.0` (matches existing test files)
**Warning signs:** SPDX mismatch during code review.

### Pitfall 2: metadata Parameter Name Suppression
**What goes wrong:** Solidity compiler warns about unused parameter names in `verifyDA`.
**Why it happens:** `DAVerifierOnChain` does not use the `metadata` parameter (just like `DAVerifierECDSA` ignores it).
**How to avoid:** Suppress the parameter name in the function signature: `bytes calldata` (unnamed) instead of `bytes calldata metadata`. This is the pattern `DAVerifierECDSA` uses.
**Warning signs:** Compiler warnings about unused variables.

### Pitfall 3: Forgetting to Test Library Error Conditions
**What goes wrong:** Tests only cover happy paths, missing the `require` revert cases.
**Why it happens:** The library has two error conditions (add duplicate, remove non-existent) that are easy to overlook.
**How to avoid:** Test matrix must include: add succeeds, add reverts on duplicate, remove succeeds, remove reverts on non-existent, isRegistered returns false by default, isRegistered returns true after add, isRegistered returns false after remove.
**Warning signs:** Incomplete test coverage.

### Pitfall 4: Event Emission Testing
**What goes wrong:** Tests verify state changes but not event emissions.
**Why it happens:** Event testing requires explicit `vm.expectEmit` setup that is easy to skip.
**How to avoid:** The library emits `DAVerifierAdded` and `DAVerifierRemoved` events. Tests must verify these with `vm.expectEmit`.
**Warning signs:** Missing event assertions in test functions.

### Pitfall 5: Using address(0) as IDAVerifier in Tests
**What goes wrong:** `address(0)` cast to `IDAVerifier` may behave unexpectedly in mapping lookups.
**Why it happens:** Test authors use zero addresses as "invalid" inputs without considering mapping semantics.
**How to avoid:** Use non-zero mock addresses for test verifiers. The harness approach (Pattern 4) with concrete mock contracts avoids this entirely.
**Warning signs:** Tests pass but don't actually exercise the intended logic.

## Code Examples

Verified patterns from the existing codebase:

### AdminVerifierRegistry (Direct Template for DAVerifierRegistry)
```solidity
// Source: src/lib/AdminVerifierRegistry.sol (lines 1-54)
// This is the EXACT template. Replace IAdminVerifier -> IDAVerifier,
// AdminVerifier -> DAVerifier in all identifiers.
library AdminVerifierRegistry {
    error AdminVerifierAlreadyRegistered();
    error AdminVerifierNotRegistered();
    event AdminVerifierAdded(IAdminVerifier adminVerifier);
    event AdminVerifierRemoved(IAdminVerifier adminVerifier);

    function isRegistered(mapping(IAdminVerifier => bool) storage, IAdminVerifier) internal view returns (bool);
    function add(mapping(IAdminVerifier => bool) storage, IAdminVerifier) internal;
    function remove(mapping(IAdminVerifier => bool) storage, IAdminVerifier) internal;
}
```

### DAVerifierECDSA (Reference for DAVerifierOnChain Structure)
```solidity
// Source: src/verification/da/DAVerifierECDSA.sol (lines 1-31)
// DAVerifierOnChain follows the same structure but:
// - No constructor (no immutable state)
// - verifyDA is `pure` not `view`
// - Logic: keccak256(proof) == assertionId
contract DAVerifierECDSA is IDAVerifier {
    address public immutable DA_PROVER;
    constructor(address daProver) { DA_PROVER = daProver; }
    function verifyDA(bytes32 assertionId, bytes calldata, bytes calldata proof)
        external view returns (bool verified)
    {
        return ECDSA.recoverCalldata(assertionId, proof) == DA_PROVER;
    }
}
```

### DAVerifierECDSA Test (Reference for DAVerifierOnChain Test Style)
```solidity
// Source: test/DAVerifierECDSA.t.sol (lines 1-47)
// DAVerifierOnChain tests follow this same structure:
// - setUp deploys the verifier
// - Fuzz tests for valid and invalid inputs
// - Edge case tests for boundary conditions
contract DAVerifierECDSATest is Test {
    DAVerifierECDSA public verifier;
    function setUp() public { verifier = new DAVerifierECDSA(vm.addr(0x123)); }
    function testFuzz_verifyDA(...) public view { ... }
    function testFuzz_RevertIf_verifyDAWithWrongProver(...) public view { ... }
}
```

### DAVerifierMock (Existing Test Utility)
```solidity
// Source: test/utils/DAVerifierMock.sol (lines 1-10)
// This mock always returns true. For registry tests, create specific
// mock verifier instances to test add/remove behavior.
contract DAVerifierMock is IDAVerifier {
    function verifyDA(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
```

### Using Library with `using ... for` (StateOracle Pattern)
```solidity
// Source: src/StateOracle.sol (line 18)
// Phase 2 will add this same pattern for DAVerifierRegistry.
// Phase 1 tests use the harness approach instead.
using AdminVerifierRegistry for mapping(IAdminVerifier adminVerifier => bool isRegistered);
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single immutable DA_VERIFIER | Registry of multiple DA verifiers | This project (Phase 1-2) | Enables per-assertion DA strategy selection |
| Off-chain only DA (ECDSA) | Off-chain (ECDSA) + on-chain (hash) DA | This project (Phase 1) | Enables fully on-chain DA verification |

**Deprecated/outdated:**
- Nothing deprecated in Phase 1. All existing code remains untouched.

## Open Questions

1. **NatDoc Author Tag**
   - What we know: Existing files use `@author @fredo (luehrs.fred@gmail.com)`
   - What's unclear: Whether new files by an agent should use the same author tag
   - Recommendation: Use the same author tag as existing files for consistency. The user can change it during review.

2. **Test File Naming Convention**
   - What we know: Existing tests use `{ContractName}.t.sol` directly in `test/` (e.g., `DAVerifierECDSA.t.sol`)
   - What's unclear: Whether the registry library test should be `DAVerifierRegistry.t.sol` or if there's a preference
   - Recommendation: Use `DAVerifierRegistry.t.sol` and `DAVerifierOnChain.t.sol` in `test/`, matching the existing flat structure

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Foundry (forge-std Test) |
| Config file | `foundry.toml` (minimal config, defaults) |
| Quick run command | `forge test --match-path test/DAVerifierOnChain.t.sol && forge test --match-path test/DAVerifierRegistry.t.sol` |
| Full suite command | `forge test` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R1-a | DAVerifierRegistry.add succeeds for unregistered verifier | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_add` | Wave 0 |
| R1-b | DAVerifierRegistry.add reverts for already-registered verifier | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_add_AlreadyRegistered` | Wave 0 |
| R1-c | DAVerifierRegistry.remove succeeds for registered verifier | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_remove` | Wave 0 |
| R1-d | DAVerifierRegistry.remove reverts for unregistered verifier | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_remove_NotRegistered` | Wave 0 |
| R1-e | DAVerifierRegistry.isRegistered returns correct status | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_isRegistered` | Wave 0 |
| R1-f | DAVerifierRegistry emits DAVerifierAdded event | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_add_emitsEvent` | Wave 0 |
| R1-g | DAVerifierRegistry emits DAVerifierRemoved event | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_remove_emitsEvent` | Wave 0 |
| R11-a | DAVerifierOnChain returns true when keccak256(proof) == assertionId | unit | `forge test --match-path test/DAVerifierOnChain.t.sol --match-test test_verifyDA_validProof` | Wave 0 |
| R11-b | DAVerifierOnChain returns false when keccak256(proof) != assertionId | unit | `forge test --match-path test/DAVerifierOnChain.t.sol --match-test test_verifyDA_invalidProof` | Wave 0 |
| R11-c | DAVerifierOnChain handles empty proof correctly | unit | `forge test --match-path test/DAVerifierOnChain.t.sol --match-test test_verifyDA_emptyProof` | Wave 0 |
| R12 | DAVerifierOnChain.verifyDA is pure (no state, no external calls) | unit | Compile-time guarantee via `pure` modifier; fuzz test confirms determinism | Wave 0 |

### Sampling Rate
- **Per task commit:** `forge test --match-path test/DAVerifierOnChain.t.sol && forge test --match-path test/DAVerifierRegistry.t.sol`
- **Per wave merge:** `forge test`
- **Phase gate:** Full suite green (`forge test`) before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `test/DAVerifierRegistry.t.sol` -- covers R1 (all registry library behaviors)
- [ ] `test/DAVerifierOnChain.t.sol` -- covers R11, R12 (verifier accept/reject/purity)
- [ ] No framework install needed -- Foundry is already configured
- [ ] No shared fixtures needed -- each test file is self-contained (follows existing pattern)

## Sources

### Primary (HIGH confidence)
- `src/lib/AdminVerifierRegistry.sol` -- Direct template for DAVerifierRegistry (54 lines, fully read)
- `src/verification/da/DAVerifierECDSA.sol` -- Reference IDAVerifier implementation (31 lines, fully read)
- `src/interfaces/IDAVerifier.sol` -- Interface contract (17 lines, fully read)
- `src/StateOracle.sol` -- Consumer of AdminVerifierRegistry pattern, shows `using` syntax (407 lines, fully read)
- `test/DAVerifierECDSA.t.sol` -- Reference test pattern for DA verifier (47 lines, fully read)
- `test/StateOracle.t.sol` -- Reference test pattern for library usage and base contract setup (80 lines read)
- `test/utils/DAVerifierMock.sol` -- Existing mock for IDAVerifier (10 lines, fully read)
- `foundry.toml` -- Build configuration (11 lines, fully read)

### Secondary (MEDIUM confidence)
- Solidity documentation -- `pure` vs `view` semantics, library `using for` syntax, `keccak256` as opcode (not external call)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- no new dependencies, exact pattern replication from codebase
- Architecture: HIGH -- both file locations and code structure are dictated by existing conventions
- Pitfalls: HIGH -- all pitfalls are minor stylistic/testing concerns; no upgrade or security risk in Phase 1

**Research date:** 2026-03-09
**Valid until:** 2026-04-09 (stable -- no external dependencies, pattern is internal to this codebase)
