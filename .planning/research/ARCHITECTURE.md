# Architecture Research: DA Verifier Registry Integration

**Researched:** 2026-03-09 | **Confidence:** HIGH

## Storage Layout (Safe)
- Remove DA_VERIFIER immutable (bytecode, not storage — safe)
- Append `mapping(IDAVerifier => bool) daVerifiers` after maxAssertionsPerAA
- No existing slots change

## Build Order
1. **Phase 1:** DAVerifierRegistry library + DAVerifierOnChain (independent, non-breaking)
2. **Phase 2:** StateOracle changes (registry, addAssertion, event, governance functions)
3. **Phase 3:** Deployment scripts + integration tests
4. **Phase 4:** Documentation + ABI artifacts

## Integration Points
- Constructor: remove daVerifier param
- initialize(): add IDAVerifier[] param
- addAssertion(): add IDAVerifier param, check registry, extend event
- New governance: addDAVerifier/removeDAVerifier/isDAVerifierRegistered
- AssertionAdded event: add daVerifier, metadata, proof fields (indexed: adopter, assertionId, daVerifier)

## Migration Path (Existing Deployments)
1. Deploy new components (DAVerifierOnChain, new StateOracle impl)
2. Upgrade proxy (upgradeTo)
3. Governance calls addDAVerifier for each verifier
4. Update off-chain systems for new ABI
