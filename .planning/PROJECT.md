# Credible Layer Contracts — DA Verifier Registry & On-Chain Bytecode DA

## What This Is

The Credible Layer protocol manages assertion adopters and their assertions through an upgradeable StateOracle. The v1.0 milestone added a governance-managed DA verifier registry (replacing the single immutable DA verifier) and an on-chain DA verifier that validates bytecode by hash. Managers choose a registered DA verifier per-assertion at add time, and the `AssertionAdded` event emits proof data so readers can retrieve assertion bytecode directly from chain events.

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
- ✓ DA verifier registry replacing single immutable DA_VERIFIER — v1.0
- ✓ DAVerifierRegistry library mirroring AdminVerifierRegistry — v1.0
- ✓ Manager picks DA verifier per-assertion when calling addAssertion — v1.0
- ✓ Governance can add/remove DA verifiers — v1.0
- ✓ DA verifiers initialized during initialize() — v1.0
- ✓ DAVerifierOnChain verifies keccak256(proof) == assertionId — v1.0
- ✓ AssertionAdded event extended with daVerifier, metadata, proof fields — v1.0
- ✓ IDAVerifier interface unchanged (verifyDA remains view) — v1.0
- ✓ Deployment scripts updated for DA verifier registry — v1.0
- ✓ Storage layout safe for proxy upgrade (append-only) — v1.0
- ✓ ABI artifacts regenerated — v1.0
- ✓ README updated with DA verifier registry docs — v1.0

### Active

(None — planning next milestone)

### Out of Scope

- Changing assertion lifecycle semantics (one-time registration, timelock) — not part of this work
- Migrating existing assertions — forward-looking change only
- Removing ECDSA verifier — both DA methods coexist
- On-chain storage of bytecode in contract state (event emission only)
- Changing IDAVerifier interface — stays as-is with view-only verifyDA

## Context

Shipped v1.0 with 5,109 LOC Solidity across 18 modified files.
Tech stack: Foundry, OpenZeppelin, Solady, forge-std.
263 tests passing (unit, fuzz, integration, storage layout).

**Assertion IDs** are `keccak256(deployable bytecode)` where deployable bytecode = creation bytecode + ABI-encoded constructor args. The DA verifier registry allows managers to choose at assertion-add time whether to use ECDSA (off-chain) or on-chain emission for data availability proof.

**Proof field semantics:**
- For ECDSA: the signature (65 bytes) — proof that a trusted party attests data exists elsewhere
- For on-chain: the deployable bytecode itself — the most direct proof of availability

**Storage layout:** `DA_VERIFIER` immutable was removed. The new `mapping(IDAVerifier => bool)` is appended after `maxAssertionsPerAA` at storage slot 8.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| DA verifier registry instead of single immutable | Mirrors admin verifier pattern, allows multiple DA mechanisms | ✓ Good |
| Manager picks DA verifier per-assertion | Maximum flexibility, different assertions can use different DA | ✓ Good |
| No IDAVerifier interface change | On-chain verifier does hash check in existing verifyDA; no callback needed | ✓ Good |
| Bytecode in proof field (not metadata) | Presenting the data IS the proof of availability; metadata stays for context | ✓ Good |
| Extend AssertionAdded event (not separate event) | Single event with daVerifier+metadata+proof; reader interprets based on verifier type | ✓ Good |
| Always emit proof in event | Uniform behavior; 65-byte ECDSA overhead is negligible | ✓ Good |
| DAVerifierOnChain.verifyDA is pure (not view) | No state reads or external calls needed; stricter than interface requires | ✓ Good |
| DAVerifierNotRegistered as StateOracle error | Contract-level error, not reusing library error | ✓ Good |
| daVerifiers mapping at slot 8 after maxAssertionsPerAA | Append-only storage layout preserves proxy upgrade safety | ✓ Good |
| DAVerifierOnChain deployed per-oracle in staging | Isolation between production and staging environments | ✓ Good |

## Constraints

- **Upgradeability**: Storage layout must be preserved — append-only changes to StateOracle storage
- **ABI change**: addAssertion signature changed (new daVerifier param) and AssertionAdded event changed — breaking for existing callers
- **Gas**: On-chain bytecode emission costs more gas than ECDSA — expected and acceptable since it's opt-in per assertion
- **No interface change**: IDAVerifier stays as-is with view-only verifyDA

---
*Last updated: 2026-03-11 after v1.0 milestone*
