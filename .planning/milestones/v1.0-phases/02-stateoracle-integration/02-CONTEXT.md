# Phase 2: StateOracle Integration - Context

**Gathered:** 2026-03-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Integrate the DAVerifierRegistry library into StateOracle. Add governance functions for DA verifier management (add/remove/isRegistered), update addAssertion to accept a caller-chosen DA verifier, extend the AssertionAdded event with proof data, update initialize() to accept DA verifiers, remove the DA_VERIFIER immutable, and validate storage layout safety. This phase does NOT update deployment scripts (Phase 3) or documentation/artifacts (Phase 4).

</domain>

<decisions>
## Implementation Decisions

### Event Indexing
- AssertionAdded: index all 3 available slots — assertionAdopter (indexed), assertionId (indexed), daVerifier (indexed). metadata and proof remain unindexed (bytes fields)
- AssertionRemoved: index assertionAdopter (indexed) + assertionId (indexed) for consistency with AssertionAdded pattern
- Claude's discretion on daVerifier indexing: use all 3 slots on AssertionAdded

### Storage Layout
- No __gap storage array needed — StateOracle is terminal in inheritance, new variables appended at end
- Storage layout validated via automated test using ordering invariants (not full snapshot comparison)
- Test asserts known slots appear in expected order; new variables at end are acceptable
- No snapshot that breaks on intentional additions

### addAssertion Signature
- New IDAVerifier daVerifier parameter goes after contractAddress: `addAssertion(address contractAddress, IDAVerifier daVerifier, bytes32 assertionId, bytes calldata metadata, bytes calldata proof)`
- New custom error on StateOracle: `error DAVerifierNotRegistered()` — NOT reusing library error
- Rename existing `InvalidProof` to `InvalidDAProof(IDAVerifier daVerifier)` — includes verifier address for debugging context
- Batch call compatibility testing deferred to Phase 3

### initialize() Signature
- DA verifiers array placed after admin verifiers: `initialize(address admin, IAdminVerifier[] calldata _adminVerifiers, IDAVerifier[] calldata _daVerifiers, uint16 _maxAssertionsPerAA)`
- Groups both verifier arrays together before the scalar config

### Governance Functions
- addDAVerifier/removeDAVerifier mirror addAdminVerifier/removeAdminVerifier exactly
- Internal helpers follow _addDAVerifier/_removeDAVerifier pattern (Claude's discretion, matching existing convention)
- Public mapping `daVerifiers` + explicit `isDAVerifierRegistered(IDAVerifier)` view function — mirrors admin verifier pattern exactly (both public mapping and view function)

### Error Handling Flow
- Verifier reverts bubble up (no try/catch) — matches current direct call pattern
- Check order in addAssertion: hasAssertion check first (existing), then DAVerifierNotRegistered check, then verifyDA call, then assertion count check
- InvalidDAProof(IDAVerifier daVerifier) includes verifier address parameter for debugging

### Test Organization
- Unit tests (StateOracle.t.sol): keep using DAVerifierMock, update for new signatures/events/errors
- New integration tests: parameterized matrix with real verifier combinations
  - Abstract base test contract with all assertion flow test methods
  - 4 concrete implementations (full cross-product):
    - AdminVerifierOwner + DAVerifierECDSA
    - AdminVerifierOwner + DAVerifierOnChain
    - AdminVerifierWhitelist + DAVerifierECDSA
    - AdminVerifierWhitelist + DAVerifierOnChain
  - Each concrete contract overrides setUp with appropriate verifier setup (signer keys for ECDSA, whitelist addresses for whitelist verifier, valid proof computation for on-chain verifier)
  - Foundry runs all tests for each concrete contract automatically

### Claude's Discretion
- Internal helper naming (_addDAVerifier, _removeDAVerifier)
- NatDoc style and comment depth on new functions
- Storage layout test implementation details (which slots to assert ordering on)
- Integration test file naming and organization within test/ directory

</decisions>

<specifics>
## Specific Ideas

- Mirror AdminVerifierRegistry integration pattern exactly — same naming, same structure, same NatDoc conventions
- The test matrix ensures StateOracle behavior is verified against all real verifier combinations, not just mocks
- Storage ordering test should be non-brittle: assert relative ordering, not absolute slot numbers

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DAVerifierRegistry` library (src/lib/DAVerifierRegistry.sol): Built in Phase 1, mirrors AdminVerifierRegistry exactly. Ready for `using DAVerifierRegistry for mapping(IDAVerifier => bool)`
- `DAVerifierOnChain` (src/verification/da/DAVerifierOnChain.sol): Built in Phase 1, pure function, ready for integration tests
- `AdminVerifierRegistry` library (src/lib/AdminVerifierRegistry.sol): The pattern to mirror for all DA verifier governance integration
- `DAVerifierMock` (test/utils/DAVerifierMock.sol): Always-true mock, stays for unit tests
- `ProxyHelper` (test/utils/ProxyHelper.t.sol): Proxy deployment helper, used by all test bases

### Established Patterns
- Library-on-mapping pattern: `using AdminVerifierRegistry for mapping(IAdminVerifier => bool)` — DA verifier registry will use identical pattern
- Governance function pattern: external onlyGovernance -> internal helper (_addAdminVerifier -> adminVerifiers.add)
- Constructor: immutables + renounceOwnership + _disableInitializers
- Initialize: _initializeRoles + feature setup loop + config

### Integration Points
- StateOracle.sol line 18: add `using DAVerifierRegistry for mapping(IDAVerifier => bool)` alongside AdminVerifierRegistry
- StateOracle.sol line 24: remove `DA_VERIFIER` immutable
- StateOracle.sol line 126: add `mapping(IDAVerifier daVerifier => bool isRegistered) public daVerifiers` after `maxAssertionsPerAA` (storage append-only)
- StateOracle.sol constructor: remove daVerifier parameter
- StateOracle.sol initialize(): add IDAVerifier[] parameter, add DA verifier population loop
- StateOracle.sol addAssertion(): add IDAVerifier parameter, replace DA_VERIFIER.verifyDA with daVerifier.verifyDA

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-stateoracle-integration*
*Context gathered: 2026-03-09*
