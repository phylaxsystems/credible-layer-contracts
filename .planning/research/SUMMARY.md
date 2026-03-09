# Project Research Summary

**Project:** Credible Layer Contracts -- DA Verifier Registry & On-Chain Bytecode DA
**Domain:** Upgradeable Solidity protocol (security-sensitive, proxy-based)
**Researched:** 2026-03-09
**Confidence:** HIGH

## Executive Summary

This project extends the Credible Layer StateOracle to support multiple data availability verification strategies. The current system hardcodes a single immutable `DA_VERIFIER`; the upgrade replaces it with a governance-managed registry of DA verifiers (mirroring the existing `AdminVerifierRegistry` pattern) and introduces a new `DAVerifierOnChain` contract that validates bytecode availability by checking `keccak256(proof) == assertionId`. The `AssertionAdded` event is extended with `daVerifier`, `metadata`, and `proof` fields so that on-chain DA users can retrieve full assertion bytecode directly from chain events.

The recommended approach is a direct mirror of the existing admin verifier registry pattern: a `DAVerifierRegistry` library with `mapping(IDAVerifier => bool)`, governance-gated add/remove functions, and initialization via an array parameter in `initialize()`. The `addAssertion` function gains a `daVerifier` parameter so managers choose the DA strategy per-assertion. This is a well-understood pattern within this codebase -- the implementation template already exists in `AdminVerifierRegistry.sol`. The `IDAVerifier` interface does not change; the on-chain verifier simply implements `verifyDA` as a hash check.

The primary risks are upgrade-related: storage layout must be append-only (the new mapping goes after `maxAssertionsPerAA`), the `addAssertion` function signature changes (breaking all existing callers), and the `AssertionAdded` event signature changes (breaking off-chain indexers). All three are manageable with coordinated deployment. The immutable `DA_VERIFIER` removal is safe because immutables live in implementation bytecode, not proxy storage. Post-upgrade, governance must immediately populate the DA verifier registry or `addAssertion` will revert for all callers.

## Key Findings

### Recommended Stack

No new dependencies or tooling changes are required. The existing Foundry + Solidity 0.8.28 stack is sufficient.

**Core technologies:**
- **Solidity 0.8.28**: Current compiler, no version bump needed
- **Foundry**: Build, test, deployment -- all existing tooling applies
- **OpenZeppelin/Solady**: Existing dependencies cover all patterns needed
- **AdminVerifierRegistry pattern**: Direct template for the new DAVerifierRegistry library

**Gas impact of event extension:**
- ECDSA proof in event: ~520 gas overhead (65 bytes) -- negligible
- On-chain bytecode in event: ~82K gas for 10KB, ~400K for 50KB -- acceptable since opt-in

### Expected Features

**Must have (table stakes):**
- Governance-gated add/remove DA verifier functions
- Public view for verifier registration status (`isDAVerifierRegistered`)
- Registry events (`DAVerifierAdded` / `DAVerifierRemoved`)
- Manager picks verifier per-assertion via new `addAssertion` parameter
- Validation that chosen verifier is registered before assertion proceeds
- Initialize with default verifiers via `IDAVerifier[]` array in `initialize()`
- Storage-safe implementation (append-only mapping)
- Extended `AssertionAdded` event including chosen verifier, metadata, and proof

**Should have (differentiators):**
- `DAVerifierOnChain` contract (`keccak256(proof) == assertionId` hash check)
- Proof data emitted in event for all DA methods (uniform behavior)
- Coexistence of ECDSA and on-chain DA methods simultaneously

**Defer (do NOT build):**
- Per-adopter verifier defaults -- manager picks explicitly each time
- Automatic verifier selection -- loses transparency
- Separate event types per DA method -- single `AssertionAdded` with verifier field
- IDAVerifier interface changes -- existing `verifyDA(bytes32, bytes, bytes)` signature is sufficient
- On-chain bytecode storage in contract state -- events only
- Migration of existing assertions -- forward-only change

### Architecture Approach

The architecture follows the established registry pattern in this codebase. A new `DAVerifierRegistry` library (structurally identical to `AdminVerifierRegistry`) manages a `mapping(IDAVerifier => bool)`. The StateOracle constructor drops the `daVerifier` param; `initialize()` gains an `IDAVerifier[]` array. `addAssertion()` gains an `IDAVerifier daVerifier` param, checks registration, calls `verifyDA`, and emits the extended event. Governance functions mirror the admin verifier management (`addDAVerifier` / `removeDAVerifier`).

**Major components:**
1. **DAVerifierRegistry library** -- manages DA verifier registration (add/remove/isRegistered), mirrors AdminVerifierRegistry exactly
2. **DAVerifierOnChain contract** -- implements IDAVerifier, verifies `keccak256(proof) == assertionId`
3. **StateOracle changes** -- registry storage, updated constructor/initialize/addAssertion, governance functions, extended event
4. **Deployment scripts** -- updated for registry initialization and new verifier deployment

### Critical Pitfalls

1. **Storage variable ordering** -- The new `mapping(IDAVerifier => bool) daVerifiers` must be appended after `maxAssertionsPerAA`. Never insert or reorder. Validate with `forge inspect StateOracle storage-layout` before and after.
2. **Function signature breaking change** -- `addAssertion` selector changes with the new `IDAVerifier` parameter. All callers (scripts, tests, off-chain systems, batch calls) must update simultaneously.
3. **Event signature breaking change** -- `AssertionAdded` topic[0] changes. Off-chain indexers silently stop matching if not updated. Coordinate indexer updates before deployment.
4. **Post-upgrade registry population** -- After proxy upgrade, governance must call `addDAVerifier()` for each verifier. Until then, all `addAssertion` calls revert. This must be scripted, not manual.
5. **Proxy admin in tests** -- New DA verifier tests must use the existing `noAdmin()` pattern to avoid TransparentUpgradeableProxy admin routing issues.

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: DAVerifierRegistry Library + DAVerifierOnChain

**Rationale:** Both are independent, self-contained units with no breaking changes to existing code. They can be built and fully tested in isolation before touching StateOracle.
**Delivers:** `src/lib/DAVerifierRegistry.sol` and `src/verification/da/DAVerifierOnChain.sol` with comprehensive unit tests.
**Addresses:** Registry library (table stakes), on-chain hash verification (differentiator).
**Avoids:** No upgrade risk -- these are new files with no impact on deployed contracts.

### Phase 2: StateOracle Integration

**Rationale:** Depends on Phase 1 components. This is the core breaking change -- constructor, initialize, addAssertion signature, event, governance functions. Needs careful storage layout validation.
**Delivers:** Updated StateOracle with DA verifier registry, new addAssertion signature, extended AssertionAdded event, governance add/remove functions.
**Addresses:** Manager picks verifier per-assertion, registry validation, event extension, storage safety (all table stakes).
**Avoids:** Storage reordering pitfall (validate with forge inspect), post-upgrade initialization gap (test that addAssertion reverts with empty registry).

### Phase 3: Deployment Scripts + Integration Tests

**Rationale:** Depends on Phase 2 being stable. Scripts must deploy new components, handle upgrade path, and populate registry post-upgrade. Integration tests must cover the full lifecycle including upgrade scenario.
**Delivers:** Updated deployment scripts (`DeployCore.s.sol`, `DeployCoreWithCreateX.s.sol`, `DeployCoreWithStaging.s.sol`), integration tests covering upgrade path, post-upgrade governance calls.
**Addresses:** Deployment coordination, post-upgrade registry population (critical pitfall).
**Avoids:** Post-upgrade initialization gap by scripting `addDAVerifier` calls as part of deployment flow.

### Phase 4: Documentation + ABI Artifacts

**Rationale:** Depends on all code being finalized. ABI artifacts must reflect final function signatures and events. README must document new deployment parameters and DA verifier management.
**Delivers:** Updated README, regenerated `artifacts/` via `npm run prepare`, updated deployment documentation.
**Addresses:** Off-chain consumer coordination (event signature change), operational documentation.

### Phase Ordering Rationale

- **Phase 1 before Phase 2** because the library and verifier contract are dependencies of StateOracle changes. Building them first allows isolated unit testing.
- **Phase 2 before Phase 3** because deployment scripts need the final StateOracle implementation. Integration tests need both the new components and the updated StateOracle.
- **Phase 4 last** because ABI artifacts and documentation must reflect the final state of all code changes.
- **This ordering isolates risk**: Phase 1 has zero upgrade risk, Phase 2 concentrates all storage and signature breaking changes, Phase 3 validates the full upgrade path, Phase 4 is purely documentation.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 2:** Storage layout validation requires careful comparison of V1 vs V2 layouts. The `forge inspect` diff should be part of the phase definition. Also needs careful thought about event indexing (which fields to mark `indexed`).
- **Phase 3:** Upgrade script sequencing (deploy new impl, upgrade proxy, populate registry) may need research into existing deployment patterns in `script/` to maintain consistency.

Phases with standard patterns (skip research-phase):
- **Phase 1:** Direct mirror of `AdminVerifierRegistry.sol` -- the template is 54 lines and fully understood. `DAVerifierOnChain` is a trivial hash check.
- **Phase 4:** Standard artifact generation and documentation update.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | No new dependencies. Existing tooling is sufficient. Solidity 0.8.28 confirmed. |
| Features | MEDIUM | Feature list is clear but event field indexing choices (which of daVerifier/metadata/proof to index) need validation during implementation. |
| Architecture | HIGH | Direct mirror of existing AdminVerifierRegistry pattern. Storage layout change is straightforward append. |
| Pitfalls | HIGH | All critical pitfalls are well-understood upgrade hazards with known mitigations. Pre-upgrade checklist is concrete. |

**Overall confidence:** HIGH

### Gaps to Address

- **Event indexing strategy**: Which fields of the extended `AssertionAdded` event should be `indexed`? Architecture research suggests `adopter`, `assertionId`, and `daVerifier` -- but this consumes all 3 indexed slots (EVM limit for non-anonymous events). Validate during Phase 2 implementation whether `metadata` or `proof` indexing is needed.
- **Storage gap consideration**: PITFALLS.md flags missing `__gap` as a moderate concern for future inheritance changes. Decide during Phase 2 whether to add a storage gap to StateOracle while making this change.
- **Batch call compatibility**: The new `addAssertion` signature affects `Batch.batch()` callers. Verify during Phase 2 that batch-encoded calls work correctly with the new parameter.
- **Post-upgrade governance timing**: The window between proxy upgrade and registry population is a denial-of-service window for `addAssertion`. Phase 3 must ensure these happen atomically or in the same transaction/script.

## Sources

### Primary (HIGH confidence)
- Existing codebase: `src/lib/AdminVerifierRegistry.sol` -- direct template for DAVerifierRegistry
- Existing codebase: `src/StateOracle.sol` -- storage layout, constructor, initialize patterns
- Existing codebase: `src/verification/da/DAVerifierECDSA.sol` -- IDAVerifier implementation pattern
- Solidity documentation -- storage layout rules for upgradeable proxies
- EVM specification -- LOG opcode gas costs (375 base + 375/topic + 8/byte)

### Secondary (MEDIUM confidence)
- OpenZeppelin upgrade safety guidelines -- storage append-only rules
- Foundry documentation -- `forge inspect` for storage layout verification

---
*Research completed: 2026-03-09*
*Ready for roadmap: yes*
