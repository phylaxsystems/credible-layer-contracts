# Phase 3: Deployment Scripts + Integration Tests - Context

**Gathered:** 2026-03-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Update all deployment scripts (DeployCore, DeployCoreWithCreateX, DeployCoreWithStaging) to deploy DAVerifierOnChain alongside DAVerifierECDSA, register both DA verifiers in the registry during initialize(), and validate the full deployment flow with integration tests. This phase does NOT update documentation or ABI artifacts (Phase 4).

</domain>

<decisions>
## Implementation Decisions

### DAVerifierOnChain Deployment
- DAVerifierOnChain is deployed per-oracle (not shared), even though it's stateless — each oracle gets its own instance
- DAVerifierOnChain is always deployed — no env var toggle needed (unlike admin verifiers which have DEPLOY_* toggles)
- CreateX salt follows existing pattern: `credible-layer-da-verifier-onchain`

### Deploy Method Organization
- Separate _deployDAVerifierOnChain() method added alongside existing _deployDAVerifier() (which stays for ECDSA)
- run() orchestrates both deployment methods
- DeployCoreWithCreateX overrides _deployDAVerifierOnChain() with CreateX deployment

### Registry Population
- Both ECDSA and OnChain verifiers passed via initialize() in the IDAVerifier[] array — atomic with proxy deployment
- No post-deploy addDAVerifier calls needed — registry is populated the moment the proxy is created
- _deployStateOracleProxy updated to accept multiple DA verifier addresses (not just one)
- This resolves the STATE.md concern about "post-upgrade governance timing (registry population must be atomic with upgrade)"

### Staging Deployment (R18)
- DeployCoreWithStaging deploys DAVerifierOnChain per-oracle (one for prod, one for staging)
- Both oracles get both DA verifiers registered via initialize()

### Batch Call Compatibility
- Deferred from Phase 2 — verify batch(addAssertion(...)) works with new 5-param signature in integration tests

### Claude's Discretion
- Integration test coverage scope (which deployment flows to test end-to-end)
- Console log messages for new deployments
- Method parameter naming and NatDoc on new deploy methods

</decisions>

<specifics>
## Specific Ideas

- Mirror the existing _deployDAVerifier/_deployAdminVerifiers pattern — separate deploy methods, orchestrated by run()
- The IDAVerifier[] array in initialize() already supports multiple verifiers (Phase 2 added this) — scripts just need to build a 2-element array

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- DeployCore.s.sol: Base script with virtual _deploy* methods, already has _deployDAVerifier for ECDSA
- DeployCoreWithCreateX.s.sol: Overrides _deploy* with CreateX deterministic deployment, salt generation helper exists
- DeployCoreWithStaging.s.sol: Inherits DeployCore, deploys prod + staging oracles sharing verifiers
- test/integration/DeployCoreWithStaging.t.sol: Existing deployment integration test — needs DA verifier registry assertions

### Established Patterns
- Virtual _deploy* methods in DeployCore, overridden in CreateX variant
- Console2.log for each deployment with descriptive labels
- Env var assertions in setUp()
- _deployStateOracleProxy builds IDAVerifier[] array from address parameters

### Integration Points
- DeployCore.run(): Add _deployDAVerifierOnChain() call, pass both addresses to _deployStateOracleProxy
- _deployStateOracleProxy: Update to accept array of DA verifier addresses (not single address)
- DeployCoreWithCreateX: Override _deployDAVerifierOnChain with CreateX variant
- DeployCoreWithStaging.run(): Deploy OnChain verifier, pass to both proxy deployments

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-deployment-scripts-integration-tests*
*Context gathered: 2026-03-09*
