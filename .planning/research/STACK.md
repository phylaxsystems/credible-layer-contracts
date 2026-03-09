# Stack Research: DA Verifier Registry

**Researched:** 2026-03-09 | **Confidence:** HIGH

## Key Findings

**Registry Pattern:** Mirror `AdminVerifierRegistry` exactly — library with `mapping(IDAVerifier => bool)`, internal functions for add/remove/isRegistered.

**Storage Safety:** Append `mapping(IDAVerifier => bool) daVerifiers` after `maxAssertionsPerAA`. Remove `DA_VERIFIER` immutable (lives in bytecode, not proxy storage — safe). No reordering needed.

**Event Gas Costs (LOG opcodes):**
- Base: 375 gas + 375/topic
- Per byte: 8 gas/byte of data
- ECDSA proof (65 bytes): ~520 gas overhead — negligible
- 10KB bytecode: ~82K gas — acceptable for opt-in
- 50KB bytecode: ~400K gas — expensive but expected

**No version change needed** — Solidity 0.8.28 is current and sufficient.

**Constructor change:** Remove `daVerifier` param, keep only `assertionTimelockBlocks`.
**Initialize change:** Add `IDAVerifier[] calldata _daVerifiers` parameter.
**addAssertion change:** Add `IDAVerifier daVerifier` parameter, check registry, use provided verifier.
