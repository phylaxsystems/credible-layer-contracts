# Credible Layer Contracts — DA Verifier Registry & On-Chain Bytecode DA

## What This Is

The Credible Layer protocol manages assertion adopters and their assertions through an upgradeable StateOracle. This milestone adds a DA verifier registry (replacing the single immutable DA verifier) and introduces an on-chain DA verifier that validates bytecode by hash. The `AssertionAdded` event is extended to include proof data, so readers can retrieve assertion bytecode directly from chain events instead of relying on a centralized database.

## Core Value

Assertion bytecode must be verifiably available — whether through off-chain ECDSA proofs or on-chain event emission — and the system must remain flexible about which DA mechanism each assertion uses.

## Requirements

### Validated

- ✓ Assertion adopter registration with pluggable admin verifiers — existing
- ✓ Assertion lifecycle (add, remove, timelock, one-time registration) — existing
- ✓ ECDSA-based DA verification for off-chain bytecode storage — existing
- ✓ Admin verifier registry with governance add/remove — existing
- ✓ Role-based access control with owner/DEFAULT_ADMIN_ROLE invariant — existing
- ✓ Whitelist-gated operations — existing
- ✓ Batch execution via delegatecall — existing
- ✓ TransparentUpgradeableProxy deployment — existing

### Active

- [ ] DA verifier registry replacing single immutable DA_VERIFIER
- [ ] DAVerifierRegistry library mirroring AdminVerifierRegistry
- [ ] Manager picks DA verifier per-assertion when calling addAssertion
- [ ] Governance can add/remove DA verifiers (mirroring admin verifier management)
- [ ] DA verifiers initialized during `initialize()` (like admin verifiers)
- [ ] On-chain DA verifier (`DAVerifierOnChain`) that verifies `keccak256(proof) == assertionId`
- [ ] `AssertionAdded` event extended with `daVerifier`, `metadata`, and `proof` fields
- [ ] Readers can retrieve bytecode from AssertionAdded event when on-chain DA is used
- [ ] AssertionAdded event links bytecode to adopter+assertionId unambiguously
- [ ] IDAVerifier interface unchanged (verifyDA remains view)
- [ ] Deployment scripts updated for DA verifier registry
- [ ] Storage layout safe for proxy upgrade (registry mapping appended, immutable removed)

### Out of Scope

- Changing assertion lifecycle semantics (one-time registration, timelock) — not part of this work
- Migrating existing assertions — forward-looking change only
- Removing ECDSA verifier — both DA methods coexist
- On-chain storage of bytecode in contract state (event emission only)
- Changing IDAVerifier interface — stays as-is with view-only verifyDA

## Context

**Assertion IDs** are `keccak256(deployable bytecode)` where deployable bytecode = creation bytecode + ABI-encoded constructor args. Previously, bytecode was stored in a centralized database and DA was proven via ECDSA signature from a trusted prover. This change makes on-chain bytecode availability optional — the manager chooses at assertion-add time whether to use ECDSA (off-chain) or on-chain emission.

**Proof field semantics:** The `proof` parameter in `addAssertion` / `verifyDA` carries:
- For ECDSA: the signature (65 bytes) — proof that a trusted party attests data exists elsewhere
- For on-chain: the deployable bytecode itself — the most direct proof of availability (the data is right there)

`metadata` remains available for additional context and is currently unused by both verifiers.

**Event design:** `AssertionAdded` is extended to include `daVerifier`, `metadata`, and `proof`. When on-chain DA is used, the reader gets the full bytecode directly from the event. When ECDSA is used, the proof field contains just a 65-byte signature (negligible gas overhead). The reader matches events by `assertionId` + `assertionAdopter` — both are unique (assertions can never be re-added).

**Storage safety:** `DA_VERIFIER` is currently an immutable (lives in implementation bytecode, not proxy storage). Removing it from the new implementation is safe. The new `mapping(IDAVerifier => bool)` is appended after `maxAssertionsPerAA` in storage layout.

**Files to change:**
- `src/StateOracle.sol` — remove DA_VERIFIER immutable, add DA verifier registry, update addAssertion signature and event, add governance functions, update constructor/initialize
- `src/verification/da/DAVerifierECDSA.sol` — no change (interface unchanged)
- New: `src/verification/da/DAVerifierOnChain.sol` — hash verification
- New: `src/lib/DAVerifierRegistry.sol` — registry library mirroring AdminVerifierRegistry
- `script/` — deployment scripts updated for DA verifier registry
- `test/` — new and updated tests

## Constraints

- **Upgradeability**: Storage layout must be preserved — append-only changes to StateOracle storage
- **ABI change**: addAssertion signature changes (new daVerifier param) and AssertionAdded event changes — breaking for existing callers
- **Gas**: On-chain bytecode emission costs more gas than ECDSA — expected and acceptable since it's opt-in per assertion
- **No interface change**: IDAVerifier stays as-is with view-only verifyDA

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| DA verifier registry instead of single immutable | Mirrors admin verifier pattern, allows multiple DA mechanisms | — Pending |
| Manager picks DA verifier per-assertion | Maximum flexibility, different assertions can use different DA | — Pending |
| No IDAVerifier interface change | On-chain verifier just does hash check in existing verifyDA; no callback needed | — Pending |
| Bytecode in proof field (not metadata) | Presenting the data IS the proof of availability; metadata stays for additional context | — Pending |
| Extend AssertionAdded event (not separate event) | Single event with daVerifier+metadata+proof; reader interprets based on verifier type | — Pending |
| Always emit proof in event | Uniform behavior; 65-byte ECDSA overhead is negligible | — Pending |

---
*Last updated: 2026-03-09 after initialization*
