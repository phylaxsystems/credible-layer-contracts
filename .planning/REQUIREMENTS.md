# Requirements: DA Verifier Registry & On-Chain Bytecode DA

**Version:** 0.3.0
**Last updated:** 2026-03-09
**Derived from:** PROJECT.md, research/SUMMARY.md

## Validated Requirements (Existing -- No Changes Needed)

| ID | Requirement | Source |
|----|-------------|--------|
| V1 | Assertion adopter registration with pluggable admin verifiers | Existing code |
| V2 | Assertion lifecycle (add, remove, timelock, one-time registration) | Existing code |
| V3 | ECDSA-based DA verification for off-chain bytecode storage | Existing code |
| V4 | Admin verifier registry with governance add/remove | Existing code |
| V5 | Role-based access control with owner/DEFAULT_ADMIN_ROLE invariant | Existing code |
| V6 | Whitelist-gated operations | Existing code |
| V7 | Batch execution via delegatecall | Existing code |
| V8 | TransparentUpgradeableProxy deployment | Existing code |

## Active Requirements

### Registry

| ID | Requirement | Priority | Success Criteria |
|----|-------------|----------|------------------|
| R1 | DAVerifierRegistry library mirroring AdminVerifierRegistry | Must | Library with mapping(IDAVerifier => bool), add/remove/isRegistered internal functions |
| R2 | Governance can add DA verifiers | Must | Only GOVERNANCE_ROLE can call addDAVerifier; emits DAVerifierAdded event |
| R3 | Governance can remove DA verifiers | Must | Only GOVERNANCE_ROLE can call removeDAVerifier; emits DAVerifierRemoved event |
| R4 | Public view for verifier registration check | Must | isDAVerifierRegistered(IDAVerifier) returns bool |
| R5 | Initialize with default DA verifiers | Must | initialize() accepts IDAVerifier[] calldata; populates registry |

### Assertion Flow

| ID | Requirement | Priority | Success Criteria |
|----|-------------|----------|------------------|
| R6 | Manager picks DA verifier per-assertion | Must | addAssertion gains IDAVerifier daVerifier parameter |
| R7 | addAssertion validates verifier is registered | Must | Reverts if daVerifier not in registry |
| R8 | addAssertion calls verifyDA on chosen verifier | Must | Delegates to daVerifier.verifyDA(assertionId, metadata, proof) |
| R9 | AssertionAdded event extended | Must | Event includes daVerifier, metadata, proof fields |
| R10 | IDAVerifier interface unchanged | Must | verifyDA(bytes32, bytes, bytes) signature preserved |

### On-Chain DA Verifier

| ID | Requirement | Priority | Success Criteria |
|----|-------------|----------|------------------|
| R11 | DAVerifierOnChain implements IDAVerifier | Must | Contract verifies keccak256(proof) == assertionId |
| R12 | DAVerifierOnChain is pure/view | Should | No state changes, no external calls |

### Storage & Upgrade Safety

| ID | Requirement | Priority | Success Criteria |
|----|-------------|----------|------------------|
| R13 | Storage layout preserved for proxy upgrade | Must | mapping appended after maxAssertionsPerAA; no reordering |
| R14 | DA_VERIFIER immutable removed from constructor | Must | Constructor takes only assertionTimelockBlocks |
| R15 | Storage layout validated with forge inspect | Must | Pre/post layout comparison shows append-only change |

### Deployment & Scripts

| ID | Requirement | Priority | Success Criteria |
|----|-------------|----------|------------------|
| R16 | Deployment scripts deploy DAVerifierOnChain | Must | All deploy scripts create and configure on-chain verifier |
| R17 | Deployment scripts populate DA verifier registry | Must | Post-deploy scripts call addDAVerifier for each verifier |
| R18 | Staging deployment handles DA verifier registry | Must | DeployCoreWithStaging shares DA verifiers across oracles |

### Documentation & Artifacts

| ID | Requirement | Priority | Success Criteria |
|----|-------------|----------|------------------|
| R19 | ABI artifacts regenerated | Must | npm run prepare produces updated artifacts |
| R20 | README updated with DA verifier registry docs | Must | New env vars, governance functions, DA verifier management documented |

## Out of Scope

- Changing assertion lifecycle semantics
- Migrating existing assertions
- Removing ECDSA verifier
- On-chain bytecode storage in contract state
- Changing IDAVerifier interface
- Per-adopter verifier defaults
- Automatic verifier selection

## Requirement-Phase Mapping

| Phase | Requirements |
|-------|-------------|
| Phase 1: DAVerifierRegistry + DAVerifierOnChain | R1, R11, R12 |
| Phase 2: StateOracle Integration | R2, R3, R4, R5, R6, R7, R8, R9, R10, R13, R14, R15 |
| Phase 3: Deployment Scripts + Integration Tests | R16, R17, R18 |
| Phase 4: Documentation + ABI Artifacts | R19, R20 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| R1 | Phase 1 | Complete |
| R2 | Phase 2 | Complete |
| R3 | Phase 2 | Complete |
| R4 | Phase 2 | Complete |
| R5 | Phase 2 | Complete |
| R6 | Phase 2 | Complete |
| R7 | Phase 2 | Complete |
| R8 | Phase 2 | Complete |
| R9 | Phase 2 | Complete |
| R10 | Phase 2 | Complete |
| R11 | Phase 1 | Complete |
| R12 | Phase 1 | Complete |
| R13 | Phase 2 | Complete |
| R14 | Phase 2 | Complete |
| R15 | Phase 2 | Complete |
| R16 | Phase 3 | Complete |
| R17 | Phase 3 | Complete |
| R18 | Phase 3 | Complete |
| R19 | Phase 4 | Pending |
| R20 | Phase 4 | Pending |

Coverage: 20/20 requirements assigned to phases. No orphans.
