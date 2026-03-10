# Roadmap: DA Verifier Registry & On-Chain Bytecode DA

## Overview

This milestone replaces the single immutable DA_VERIFIER in StateOracle with a governance-managed registry of DA verifiers and introduces an on-chain DA verifier that validates bytecode by hash. The work progresses from isolated library/contract creation (zero risk), through the core StateOracle integration (breaking changes, storage layout), to deployment script updates and documentation. Each phase delivers a coherent, testable capability before the next phase builds on it.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: DAVerifierRegistry Library + DAVerifierOnChain** - Build independent library and on-chain verifier with full unit tests
- [x] **Phase 2: StateOracle Integration** - Integrate DA verifier registry, update addAssertion, extend event, add governance functions
- [x] **Phase 3: Deployment Scripts + Integration Tests** - Update all deployment scripts and validate full upgrade path
- [ ] **Phase 4: Documentation + ABI Artifacts** - Update README and regenerate published ABI artifacts

## Phase Details

### Phase 1: DAVerifierRegistry Library + DAVerifierOnChain
**Goal**: Developers have a tested DA verifier registry library and a working on-chain DA verifier contract, both ready for StateOracle integration
**Depends on**: Nothing (first phase)
**Requirements**: R1, R11, R12
**Success Criteria** (what must be TRUE):
  1. DAVerifierRegistry library exposes add, remove, and isRegistered internal functions operating on a mapping(IDAVerifier => bool), mirroring AdminVerifierRegistry
  2. DAVerifierOnChain contract implements IDAVerifier and returns true when keccak256(proof) == assertionId, false otherwise
  3. DAVerifierOnChain.verifyDA is pure or view with no state changes and no external calls
  4. Unit tests cover registry add/remove/isRegistered and verifier accept/reject cases, all passing via forge test
**Plans**: 2 plans

Plans:
- [x] 01-01-PLAN.md — DAVerifierRegistry library with unit tests (R1)
- [x] 01-02-PLAN.md — DAVerifierOnChain contract with unit tests (R11, R12)

### Phase 2: StateOracle Integration
**Goal**: StateOracle supports a governance-managed DA verifier registry where managers choose a registered DA verifier per-assertion, with the extended AssertionAdded event emitting proof data
**Depends on**: Phase 1
**Requirements**: R2, R3, R4, R5, R6, R7, R8, R9, R10, R13, R14, R15
**Success Criteria** (what must be TRUE):
  1. Governance can add and remove DA verifiers via addDAVerifier/removeDAVerifier, with corresponding DAVerifierAdded/DAVerifierRemoved events emitted
  2. isDAVerifierRegistered(IDAVerifier) public view returns correct registration status
  3. initialize() accepts an IDAVerifier[] array and populates the DA verifier registry on first call
  4. addAssertion accepts a daVerifier parameter, reverts if the verifier is not registered, and delegates to daVerifier.verifyDA for proof validation
  5. AssertionAdded event includes daVerifier, metadata, and proof fields so readers can retrieve assertion data from chain events
  6. IDAVerifier interface (verifyDA signature) is unchanged from existing code
  7. Storage layout is append-only (new mapping after maxAssertionsPerAA), validated by forge inspect comparison showing no reordering
  8. DA_VERIFIER immutable is removed from constructor; constructor takes only assertionTimelockBlocks
**Plans**: 2 plans

Plans:
- [x] 02-01-PLAN.md — StateOracle contract changes + unit tests + compilation fixes (R2, R3, R4, R5, R6, R7, R8, R9, R10, R14)
- [x] 02-02-PLAN.md — Storage layout validation + integration test matrix (R8, R13, R15)

### Phase 3: Deployment Scripts + Integration Tests
**Goal**: All deployment scripts deploy and configure the DA verifier registry, and integration tests validate the full upgrade path including post-upgrade registry population
**Depends on**: Phase 2
**Requirements**: R16, R17, R18
**Success Criteria** (what must be TRUE):
  1. DeployCore.s.sol, DeployCoreWithCreateX.s.sol, and DeployCoreWithStaging.s.sol all deploy DAVerifierOnChain and register it (plus DAVerifierECDSA) in the DA verifier registry during deployment
  2. DeployCoreWithStaging shares DA verifiers across production and staging oracle instances
  3. Integration tests demonstrate addAssertion works end-to-end with both ECDSA and on-chain DA verifiers through the deployed proxy
  4. Post-upgrade registry population is scripted (not manual) so there is no denial-of-service window where addAssertion reverts due to empty registry
**Plans**: 2 plans

Plans:
- [x] 03-01-PLAN.md — Update deployment scripts to deploy DAVerifierOnChain and register both DA verifiers (R16, R17, R18)
- [x] 03-02-PLAN.md — Update integration tests to validate DA verifier registry across both oracles (R16, R17, R18)

### Phase 4: Documentation + ABI Artifacts
**Goal**: README documents the DA verifier registry and new deployment parameters, and published ABI artifacts reflect all interface changes
**Depends on**: Phase 3
**Requirements**: R19, R20
**Success Criteria** (what must be TRUE):
  1. npm run prepare produces updated artifacts reflecting the new addAssertion signature, new governance functions, new events, and DAVerifierOnChain ABI
  2. README documents DA verifier registry governance functions, new addAssertion parameter, DAVerifierOnChain usage, and any new environment variables for deployment scripts
**Plans**: 1 plan

Plans:
- [ ] 04-01-PLAN.md — Regenerate ABI artifacts and update README documentation (R19, R20)

## Coverage

| Requirement | Phase | Description |
|-------------|-------|-------------|
| R1 | Phase 1 | DAVerifierRegistry library mirroring AdminVerifierRegistry |
| R2 | Phase 2 | Governance can add DA verifiers |
| R3 | Phase 2 | Governance can remove DA verifiers |
| R4 | Phase 2 | Public view for verifier registration check |
| R5 | Phase 2 | Initialize with default DA verifiers |
| R6 | Phase 2 | Manager picks DA verifier per-assertion |
| R7 | Phase 2 | addAssertion validates verifier is registered |
| R8 | Phase 2 | addAssertion calls verifyDA on chosen verifier |
| R9 | Phase 2 | AssertionAdded event extended |
| R10 | Phase 2 | IDAVerifier interface unchanged |
| R11 | Phase 1 | DAVerifierOnChain implements IDAVerifier |
| R12 | Phase 1 | DAVerifierOnChain is pure/view |
| R13 | Phase 2 | Storage layout preserved for proxy upgrade |
| R14 | Phase 2 | DA_VERIFIER immutable removed from constructor |
| R15 | Phase 2 | Storage layout validated with forge inspect |
| R16 | Phase 3 | Deployment scripts deploy DAVerifierOnChain |
| R17 | Phase 3 | Deployment scripts populate DA verifier registry |
| R18 | Phase 3 | Staging deployment handles DA verifier registry |
| R19 | Phase 4 | ABI artifacts regenerated |
| R20 | Phase 4 | README updated with DA verifier registry docs |

**Coverage: 20/20 requirements mapped. No orphans.**

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. DAVerifierRegistry Library + DAVerifierOnChain | 2/2 | Complete | 2026-03-09 |
| 2. StateOracle Integration | 2/2 | Complete | 2026-03-10 |
| 3. Deployment Scripts + Integration Tests | 2/2 | Complete | 2026-03-10 |
| 4. Documentation + ABI Artifacts | 0/1 | Not started | - |
