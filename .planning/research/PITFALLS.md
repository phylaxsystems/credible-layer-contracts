# Pitfalls Research: DA Verifier Registry Migration

**Researched:** 2026-03-09 | **Confidence:** HIGH

## Critical Pitfalls

1. **Storage Variable Reordering** — Never insert/reorder/remove existing storage vars. Only append. Validate with `forge inspect StateOracle storage-layout`.

2. **Immutable Removal Misunderstanding** — Removing DA_VERIFIER immutable is SAFE (lives in bytecode, not proxy storage). Don't add unnecessary workarounds.

3. **Function Signature Breaking Change** — addAssertion selector changes. All clients must update simultaneously. Coordinate deployment.

4. **Event Signature Breaking Change** — AssertionAdded topic[0] changes. Off-chain indexers must update filters before deployment. Silent failure if missed.

5. **Post-Upgrade Initialization** — Governance must call addDAVerifier() after upgrade to populate registry. Until then, addAssertion reverts.

6. **Proxy Admin in Tests** — Use existing noAdmin() pattern for new DA verifier tests.

## Moderate Pitfalls
- Missing storage gaps constrain future inheritance changes (consider adding __gap)
- Registry must be populated before addAssertion can succeed
- Batch calls must use new addAssertion signature

## Pre-Upgrade Checklist
- [ ] forge inspect storage-layout comparison (V1 vs V2)
- [ ] All scripts/tests use new addAssertion signature
- [ ] Off-chain indexers updated for new event
- [ ] Post-upgrade governance calls planned
- [ ] Integration test covers upgrade scenario
