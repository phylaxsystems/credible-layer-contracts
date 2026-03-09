# Feature Research: DA Verifier Registry

**Researched:** 2026-03-09 | **Confidence:** MEDIUM

## Table Stakes
- Add/remove DA verifier (governance-gated)
- Check verifier registration (public view)
- Registry events (DAVerifierAdded/Removed)
- Manager picks verifier per-assertion (new addAssertion param)
- Validation in addAssertion (require registered)
- Initialize with default verifiers (array in initialize())
- Storage-safe implementation (append-only)
- Event includes chosen verifier

## Differentiators
- Event includes proof data (on-chain bytecode retrieval)
- On-chain DA verifier (keccak256 hash check)
- Coexistence of multiple DA methods
- Per-assertion DA choice

## Anti-Features (Do NOT Build)
- Per-adopter verifier defaults — manager picks explicitly
- Automatic verifier selection — loses transparency
- Separate event types per DA method — use single AssertionAdded
- IDAVerifier interface changes — keep existing verifyDA signature
- On-chain bytecode storage in state — events only
- Migration of existing assertions — forward-only
