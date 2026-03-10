# Phase 3: Deployment Scripts + Integration Tests - Research

**Researched:** 2026-03-10
**Domain:** Foundry deployment scripts, Solidity integration testing, proxy deployment patterns
**Confidence:** HIGH

## Summary

Phase 3 updates three deployment scripts (DeployCore, DeployCoreWithCreateX, DeployCoreWithStaging) to deploy DAVerifierOnChain alongside DAVerifierECDSA and register both in the DA verifier registry during initialization. It also updates the existing integration test (DeployCoreWithStaging.t.sol) to validate DA verifier registry state across both oracles.

The codebase is well-structured for this change. The existing deployment scripts use a virtual method pattern (`_deploy*` methods in DeployCore, overridden in DeployCoreWithCreateX) that makes adding a new `_deployDAVerifierOnChain()` method straightforward. The `initialize()` function already accepts `IDAVerifier[] calldata _daVerifiers` (Phase 2 added this), so scripts just need to build a 2-element array instead of a 1-element array. The existing integration test infrastructure (StateOracleAssertionFlowBase with 4 concrete implementations) already covers end-to-end assertion flows with both ECDSA and OnChain verifiers through deployed proxies.

**Primary recommendation:** Add `_deployDAVerifierOnChain()` to DeployCore, override it in DeployCoreWithCreateX, update `_deployStateOracleProxy` to accept an array of DA verifier addresses (instead of a single address), update DeployCoreWithStaging to deploy per-oracle OnChain verifiers while sharing ECDSA verifier, and extend the staging integration test to verify both DA verifiers are registered on both oracles.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- DAVerifierOnChain is deployed per-oracle (not shared), even though it's stateless -- each oracle gets its own instance
- DAVerifierOnChain is always deployed -- no env var toggle needed (unlike admin verifiers which have DEPLOY_* toggles)
- CreateX salt follows existing pattern: `credible-layer-da-verifier-onchain`
- Separate _deployDAVerifierOnChain() method added alongside existing _deployDAVerifier() (which stays for ECDSA)
- run() orchestrates both deployment methods
- DeployCoreWithCreateX overrides _deployDAVerifierOnChain() with CreateX deployment
- Both ECDSA and OnChain verifiers passed via initialize() in the IDAVerifier[] array -- atomic with proxy deployment
- No post-deploy addDAVerifier calls needed -- registry is populated the moment the proxy is created
- _deployStateOracleProxy updated to accept multiple DA verifier addresses (not just one)
- DeployCoreWithStaging deploys DAVerifierOnChain per-oracle (one for prod, one for staging)
- Both oracles get both DA verifiers registered via initialize()
- Verify batch(addAssertion(...)) works with new 5-param signature in integration tests

### Claude's Discretion
- Integration test coverage scope (which deployment flows to test end-to-end)
- Console log messages for new deployments
- Method parameter naming and NatDoc on new deploy methods

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| R16 | Deployment scripts deploy DAVerifierOnChain | Add `_deployDAVerifierOnChain()` virtual method to DeployCore; override in DeployCoreWithCreateX with CreateX salt `credible-layer-da-verifier-onchain`; call from `run()` |
| R17 | Deployment scripts populate DA verifier registry | Update `_deployStateOracleProxy` to accept `address[] memory daVerifierAddresses` (array), build 2-element `IDAVerifier[]` from both ECDSA + OnChain addresses, pass to `initialize()` |
| R18 | Staging deployment handles DA verifier registry | DeployCoreWithStaging deploys DAVerifierOnChain per-oracle (separate from shared DAVerifierECDSA), passes both to each proxy's `initialize()` |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Foundry (forge) | Current | Build, test, deploy | Already project toolchain |
| Solidity | ^0.8.28 | Smart contract language | Already project standard |
| OpenZeppelin | Vendored in lib/ | TransparentUpgradeableProxy | Already used by all deploy scripts |
| CreateX | 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed | Deterministic deployment | Already used by DeployCoreWithCreateX |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| forge-std | Vendored | Script, Test, console2 | Already used in all scripts and tests |
| DAVerifierOnChain | Phase 1 | On-chain DA verification | Deployed alongside ECDSA verifier |
| DAVerifierECDSA | Existing | ECDSA DA verification | Existing deployment, unchanged |

## Architecture Patterns

### Deployment Script Virtual Method Pattern

The codebase uses a clean inheritance pattern for deployment scripts:

```
DeployCore (base)
  |-- virtual _deployDAVerifier() -> ECDSA
  |-- virtual _deployDAVerifierOnChain() -> OnChain  (NEW)
  |-- virtual _deployAdminVerifiers() -> Owner/Whitelist
  |-- virtual _deployStateOracle() -> Implementation
  |-- virtual _deployStateOracleProxy() -> Proxy + initialize
  |
  +-- DeployCoreWithCreateX (override deploy methods with CreateX)
  |
  +-- DeployCoreWithStaging (override run() for dual-oracle)
```

**Key insight:** DeployCoreWithCreateX only overrides individual `_deploy*` methods, NOT `run()`. DeployCoreWithStaging overrides `run()` but reuses inherited `_deploy*` methods. This means:
- Adding `_deployDAVerifierOnChain()` to DeployCore gives it to all three scripts.
- DeployCoreWithCreateX must override `_deployDAVerifierOnChain()` with a CreateX variant.
- DeployCoreWithStaging can call `_deployDAVerifierOnChain()` in its overridden `run()`.

### Current _deployStateOracleProxy Signature (MUST CHANGE)

Currently accepts a single `address daVerifierAddress`:
```solidity
function _deployStateOracleProxy(
    address stateOracle,
    address[] memory adminVerifierDeployments,
    address daVerifierAddress,      // <-- single address
    uint16 maxAssertions
) internal virtual returns (address)
```

Must change to accept an array:
```solidity
function _deployStateOracleProxy(
    address stateOracle,
    address[] memory adminVerifierDeployments,
    address[] memory daVerifierAddresses,    // <-- array
    uint16 maxAssertions
) internal virtual returns (address)
```

**Critical:** Both DeployCore AND DeployCoreWithCreateX override `_deployStateOracleProxy`. Both must be updated to match the new signature.

### Public Wrapper Method

DeployCore has a public wrapper `deployStateOracleProxy(...)` on line 82-89 that also needs its signature updated to match the internal method change.

### run() Orchestration Pattern

```solidity
// DeployCore.run() current:
address daVerifier = _deployDAVerifier();
address stateOracle = _deployStateOracle(...);
_deployStateOracleProxy(stateOracle, adminVerifiers, daVerifier, maxAssertions);

// DeployCore.run() after change:
address daVerifierECDSA = _deployDAVerifier();
address daVerifierOnChain = _deployDAVerifierOnChain();
address[] memory daVerifiers = new address[](2);
daVerifiers[0] = daVerifierECDSA;
daVerifiers[1] = daVerifierOnChain;
address stateOracle = _deployStateOracle(...);
_deployStateOracleProxy(stateOracle, adminVerifiers, daVerifiers, maxAssertions);
```

### Staging Dual-Oracle Pattern

DeployCoreWithStaging stores deployed addresses in public state variables for test access. Current pattern:
- `deployedDAVerifier` (single address, shared between oracles)
- `deployedAdminVerifiers` (array, shared)
- `deployedProductionOracle` and `deployedStagingOracle`

After change, since DAVerifierOnChain is per-oracle (not shared), the staging script needs:
- `deployedDAVerifier` remains for shared ECDSA verifier
- Two OnChain verifiers deployed (one per oracle), not stored at contract level since they are consumed immediately when building the DA verifier array for each `_deployStateOracleProxy` call

### Integration Test Patterns

The codebase has two integration test patterns:

1. **Deployment flow tests** (`DeployCoreWithStaging.t.sol`): Test that deployment produces correct state. These mirror the deployment script's structure but use direct contract creation instead of scripts. They verify:
   - Persistent accounts funded
   - Both oracles deployed at different addresses
   - Shared verifiers registered on both oracles
   - Different configs per oracle
   - Full workflow (whitelist, register, add assertion)

2. **Assertion flow matrix tests** (`StateOracleAssertionFlowBase.sol` + 4 concrete contracts): Test AdminVerifier x DAVerifier combinations end-to-end. These already cover:
   - `AdminVerifierOwner + DAVerifierECDSA` (StateOracleOwnerECDSA.t.sol)
   - `AdminVerifierOwner + DAVerifierOnChain` (StateOracleOwnerOnChain.t.sol)
   - `AdminVerifierWhitelist + DAVerifierECDSA` (StateOracleWhitelistECDSA.t.sol)
   - `AdminVerifierWhitelist + DAVerifierOnChain` (StateOracleWhitelistOnChain.t.sol)

**Key finding:** The assertion flow matrix tests (pattern 2) already fully cover "addAssertion works end-to-end with both ECDSA and on-chain DA verifiers through the deployed proxy" (success criterion 3). The batch test in `StateOracle.t.sol::Batch` already tests batch(addAssertion(...)) with the 5-param signature. What Phase 3 needs to add is DA verifier registry validation in the deployment flow tests (pattern 1).

### Anti-Patterns to Avoid
- **Duplicating assertion flow tests in deployment tests:** The assertion flow is already covered by the matrix tests. Deployment tests should verify deployment state, not re-test assertion logic.
- **Forgetting to update DeployCoreWithCreateX._deployStateOracleProxy:** Both overrides must match the new signature or compilation fails.
- **Storing per-oracle OnChain verifier addresses as contract state in staging script when they are only needed during `run()`:** Keep them local to `run()`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| DA verifier array construction | Custom array builder | Inline `new address[](2)` pattern | Already used for adminVerifiers array |
| CreateX deterministic deploy | Custom CREATE2 logic | Existing `deployCreate3()` helper in DeployCoreWithCreateX | Salt generation helper already exists |
| Proxy initialization data | Manual abi.encodePacked | `abi.encodeWithSelector(StateOracle.initialize.selector, ...)` | Already used in all scripts |

## Common Pitfalls

### Pitfall 1: Signature Mismatch Between DeployCore and DeployCoreWithCreateX
**What goes wrong:** DeployCoreWithCreateX overrides `_deployStateOracleProxy`. If the base signature changes but the override doesn't, compilation fails with a confusing "override specifier" error.
**Why it happens:** The two contracts define identical override methods independently.
**How to avoid:** Update both `_deployStateOracleProxy` implementations simultaneously. Verify compilation after the change.
**Warning signs:** `TypeError: Trying to override non-virtual function.` or `DeclarationError: Function has override specified but does not override anything.`

### Pitfall 2: Public Wrapper Functions Out of Sync
**What goes wrong:** DeployCore has public wrapper functions (e.g., `deployStateOracleProxy`) that expose internal methods. These wrappers must also be updated.
**Why it happens:** The wrappers are rarely tested directly but must compile.
**How to avoid:** Grep for all callers of the changed internal method and update them.
**Warning signs:** Compilation errors on public functions.

### Pitfall 3: DeployCoreWithStaging State Variable Naming Confusion
**What goes wrong:** `deployedDAVerifier` (singular) currently stores the shared ECDSA verifier address. Adding OnChain verifiers could create confusion about what's shared vs per-oracle.
**Why it happens:** The naming convention assumes a single DA verifier.
**How to avoid:** Keep `deployedDAVerifier` for the shared ECDSA verifier (since that's what tests reference). OnChain verifiers are per-oracle and can be local variables in `run()`.
**Warning signs:** Tests that relied on `deployedDAVerifier` break unexpectedly.

### Pitfall 4: Transparent Proxy Admin Interference in Tests
**What goes wrong:** If the test caller happens to be the proxy admin, function calls get routed to the ProxyAdmin contract instead of the implementation.
**Why it happens:** TransparentUpgradeableProxy routes admin calls differently.
**How to avoid:** Use `noAdmin(address)` modifier in tests, or ensure test addresses are not the proxy admin. The existing test patterns already handle this.
**Warning signs:** Unexpected reverts or empty return data in tests.

### Pitfall 5: Forgetting initialize() Already Handles Arrays
**What goes wrong:** Adding a post-deploy `addDAVerifier()` governance call when it's not needed.
**Why it happens:** Misunderstanding that `initialize()` already populates the registry from the `IDAVerifier[]` array.
**How to avoid:** Pass both verifiers in the `IDAVerifier[]` array during `initialize()`. No separate governance transaction needed.
**Warning signs:** Extra governance calls in deployment script `run()`.

## Code Examples

### Pattern 1: New _deployDAVerifierOnChain in DeployCore
```solidity
// Source: Mirrors existing _deployDAVerifier() pattern
function _deployDAVerifierOnChain() internal virtual returns (address) {
    address daVerifierOnChain = address(new DAVerifierOnChain());
    console2.log("DA Verifier (OnChain) deployed at", daVerifierOnChain);
    return daVerifierOnChain;
}
```

### Pattern 2: CreateX Override in DeployCoreWithCreateX
```solidity
// Source: Mirrors existing ECDSA CreateX pattern
string public constant SALT_DA_VERIFIER_ONCHAIN_NAME = "credible-layer-da-verifier-onchain";

function _deployDAVerifierOnChain() internal override returns (address) {
    address daVerifierOnChain = deployCreate3(
        SALT_DA_VERIFIER_ONCHAIN_NAME,
        type(DAVerifierOnChain).creationCode
    );
    console2.log("DA Verifier (OnChain) deployed at", daVerifierOnChain);
    return daVerifierOnChain;
}
```

### Pattern 3: Updated _deployStateOracleProxy with DA Verifier Array
```solidity
// Source: Modified from existing DeployCore._deployStateOracleProxy
function _deployStateOracleProxy(
    address stateOracle,
    address[] memory adminVerifierDeployments,
    address[] memory daVerifierAddresses,
    uint16 maxAssertions
) internal virtual returns (address) {
    IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](adminVerifierDeployments.length);
    for (uint256 i = 0; i < adminVerifierDeployments.length; i++) {
        adminVerifiers[i] = IAdminVerifier(adminVerifierDeployments[i]);
    }
    IDAVerifier[] memory daVfrs = new IDAVerifier[](daVerifierAddresses.length);
    for (uint256 i = 0; i < daVerifierAddresses.length; i++) {
        daVfrs[i] = IDAVerifier(daVerifierAddresses[i]);
    }
    bytes memory initCallData =
        abi.encodeWithSelector(StateOracle.initialize.selector, admin, adminVerifiers, daVfrs, maxAssertions);
    address proxyAddress = address(new TransparentUpgradeableProxy(address(stateOracle), admin, initCallData));
    console2.log("State Oracle Proxy deployed at", proxyAddress);
    return proxyAddress;
}
```

### Pattern 4: Updated run() in DeployCore
```solidity
// Source: Modified from existing DeployCore.run()
function run() public virtual broadcast {
    _fundPersistentAccounts();

    address daVerifier = _deployDAVerifier();
    address daVerifierOnChain = _deployDAVerifierOnChain();
    address[] memory adminVerifierDeployments = _deployAdminVerifiers();

    address stateOracle = _deployStateOracle(assertionTimelockBlocks, "State Oracle");

    address[] memory daVerifierAddresses = new address[](2);
    daVerifierAddresses[0] = daVerifier;
    daVerifierAddresses[1] = daVerifierOnChain;

    _deployStateOracleProxy(stateOracle, adminVerifierDeployments, daVerifierAddresses, maxAssertionsPerAA);
}
```

### Pattern 5: Updated DeployCoreWithStaging.run() (Per-Oracle OnChain)
```solidity
// Source: Modified from existing DeployCoreWithStaging.run()
function run() public override broadcast {
    _fundPersistentAccounts();

    // Shared: ECDSA verifier + admin verifiers
    deployedDAVerifier = _deployDAVerifier();
    deployedAdminVerifiers = _deployAdminVerifiers();

    // Production oracle
    address prodOnChain = _deployDAVerifierOnChain();
    address stateOracle = _deployStateOracle(assertionTimelockBlocks, "State Oracle");
    address[] memory prodDAVerifiers = new address[](2);
    prodDAVerifiers[0] = deployedDAVerifier;
    prodDAVerifiers[1] = prodOnChain;
    deployedProductionOracle = _deployStateOracleProxy(stateOracle, deployedAdminVerifiers, prodDAVerifiers, maxAssertionsPerAA);

    // Staging oracle
    address stagingOnChain = _deployDAVerifierOnChain();
    address stagingOracle = _deployStateOracle(stagingAssertionTimelockBlocks, "Staging State Oracle");
    address[] memory stagingDAVerifiers = new address[](2);
    stagingDAVerifiers[0] = deployedDAVerifier;
    stagingDAVerifiers[1] = stagingOnChain;
    deployedStagingOracle = _deployStateOracleProxy(stagingOracle, deployedAdminVerifiers, stagingDAVerifiers, stagingMaxAssertionsPerAA);
}
```

### Pattern 6: Integration Test - Verify DA Verifier Registry State
```solidity
// Source: Extension of existing DeployCoreWithStaging.t.sol pattern
function test_BothOraclesHaveBothDAVerifiers() public view {
    assertTrue(productionOracle.isDAVerifierRegistered(IDAVerifier(address(ecdsaVerifier))));
    assertTrue(productionOracle.isDAVerifierRegistered(IDAVerifier(address(prodOnChainVerifier))));
    assertTrue(stagingOracle.isDAVerifierRegistered(IDAVerifier(address(ecdsaVerifier))));
    assertTrue(stagingOracle.isDAVerifierRegistered(IDAVerifier(address(stagingOnChainVerifier))));
}

function test_OnChainVerifiersArePerOracle() public view {
    // Each oracle has its own OnChain verifier
    assertTrue(address(prodOnChainVerifier) != address(stagingOnChainVerifier));
    // But the ECDSA verifier is shared
    assertTrue(productionOracle.isDAVerifierRegistered(IDAVerifier(address(ecdsaVerifier))));
    assertTrue(stagingOracle.isDAVerifierRegistered(IDAVerifier(address(ecdsaVerifier))));
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single DA_VERIFIER immutable | DA verifier registry (mapping) | Phase 2 | Multiple DA verifiers per oracle |
| Single daVerifierAddress param in deploy | Array of DA verifier addresses | Phase 3 (this phase) | Scripts deploy and register both verifiers |
| Post-deploy governance calls for registry | Atomic via initialize() | Phase 2 design | No DoS window after deployment |

**Important:** The `initialize()` function added in Phase 2 already iterates over the `IDAVerifier[]` array and calls `_addDAVerifier` for each entry. The deployment scripts just need to pass a 2-element array instead of a 1-element array.

## Open Questions

1. **Public wrapper functions**
   - What we know: DeployCore has public wrappers like `deployStateOracleProxy()`, `deployDAVerifier()`. The proxy wrapper must change signature.
   - What's unclear: Whether anyone uses these public wrappers externally.
   - Recommendation: Update the signature. Add a new `deployDAVerifierOnChain()` public wrapper. These are low-risk since they are standalone callable functions for manual deployment steps.

2. **DeployCoreWithStaging state variable for OnChain verifier addresses**
   - What we know: Per-oracle OnChain verifiers are consumed immediately in `run()`. The ECDSA verifier is stored in `deployedDAVerifier` for test access.
   - What's unclear: Whether integration tests need access to individual OnChain verifier addresses.
   - Recommendation: Store them as local variables in `run()` since they're only needed for the `_deployStateOracleProxy` call. If tests need them, the test can query `isDAVerifierRegistered` directly. If individual addresses are needed in tests, add public state vars like `deployedProductionDAVerifierOnChain` and `deployedStagingDAVerifierOnChain`.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Foundry (forge test) |
| Config file | `foundry.toml` |
| Quick run command | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol` |
| Full suite command | `forge test` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R16 | Deployment scripts deploy DAVerifierOnChain | integration | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol -x` | Exists (needs update) |
| R17 | Deployment scripts populate DA verifier registry | integration | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol -x` | Exists (needs update) |
| R18 | Staging deployment handles DA verifier registry | integration | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol -x` | Exists (needs update) |

### Sampling Rate
- **Per task commit:** `forge test --match-path test/integration/DeployCoreWithStaging.t.sol`
- **Per wave merge:** `forge test`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
None -- existing test infrastructure covers all phase requirements. The `DeployCoreWithStaging.t.sol` test file exists and needs to be updated (not created from scratch). The assertion flow matrix tests already exist and cover end-to-end assertion flows with both DA verifiers.

## Sources

### Primary (HIGH confidence)
- Codebase analysis: `script/DeployCore.s.sol`, `script/DeployCoreWithCreateX.s.sol`, `script/DeployCoreWithStaging.s.sol` -- deployment script patterns
- Codebase analysis: `test/integration/DeployCoreWithStaging.t.sol` -- existing deployment integration test
- Codebase analysis: `test/integration/StateOracleAssertionFlowBase.sol` + 4 concrete contracts -- assertion flow matrix tests
- Codebase analysis: `src/StateOracle.sol` lines 192-208 -- `initialize()` accepts `IDAVerifier[]` array
- Codebase analysis: `src/verification/da/DAVerifierOnChain.sol` -- stateless, no constructor, no state
- Codebase analysis: `test/StateOracle.t.sol::Batch` -- batch test with 5-param addAssertion already exists

### Secondary (MEDIUM confidence)
- Phase context: `.planning/phases/03-deployment-scripts-integration-tests/03-CONTEXT.md` -- locked implementation decisions

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All tools and libraries already in the project
- Architecture: HIGH - Direct codebase analysis, patterns are visible and well-established
- Pitfalls: HIGH - Identified from actual code structure (overrides, public wrappers, naming)

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (stable codebase, no external dependencies changing)
