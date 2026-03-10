# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — DA Verifier Registry & On-Chain Bytecode DA

**Shipped:** 2026-03-11
**Phases:** 4 | **Plans:** 7 | **Tasks:** 13

### What Was Built
- DAVerifierRegistry library mirroring AdminVerifierRegistry pattern
- DAVerifierOnChain contract (stateless, pure keccak256 hash verification)
- StateOracle DA verifier registry with governance add/remove/isRegistered
- Per-assertion DA verifier selection in addAssertion
- Extended AssertionAdded event with daVerifier, metadata, proof fields
- All deployment scripts (DeployCore, CreateX, Staging) updated for dual DA verifier support
- 263 tests (unit, fuzz, integration, storage layout) all passing

### What Worked
- Isolated library/contract first (Phase 1) with zero risk — both components ready before integration
- Mirroring AdminVerifierRegistry pattern exactly made Phase 2 integration predictable
- TDD approach for DAVerifierOnChain (RED -> GREEN commits) caught edge cases early
- Abstract base test with virtual proof generation enabled 4 integration test variants from one base
- Seed-based assertion generation pattern made verifier-agnostic testing natural
- Phase execution velocity was fast: 2min average for Phase 1 plans, total milestone in ~36min execution time

### What Was Inefficient
- Phase 4 roadmap checkbox was never updated to [x] despite plan completion — minor bookkeeping gap
- Some deployment script test deviations (parameter order mismatch in plan code snippets vs actual signatures) — plans could be more precise about parameter ordering
- Duplicate decision entries in STATE.md (same decisions logged under both plan-level and phase-level prefixes)

### Patterns Established
- Library-on-mapping pattern: internal library with add/remove/isRegistered operating on a mapping type, mirroring AdminVerifierRegistry
- Test harness contract with `using Library for mapping` to expose internal library functions
- Abstract base test with virtual proof generation for verifier matrix testing (AdminVerifier x DAVerifier cross-product)
- Array-based DA verifier deployment: all scripts pass address[] to _deployStateOracleProxy
- Per-oracle OnChain verifier in staging for isolation between environments

### Key Lessons
1. When adding a new registry pattern, mirror the existing one exactly (naming, NatDoc, error conventions) — integration becomes predictable
2. Storage layout validation via functional tests (exercise each slot) is more robust than raw slot reads
3. Virtual deployment methods (_deployDAVerifierOnChain) enable deterministic-salt overrides in CreateX without code duplication
4. Per-assertion verifier selection gives maximum flexibility with minimal gas overhead

### Cost Observations
- Model mix: quality profile (opus-dominant)
- Total execution time: ~36 minutes across 7 plans
- Average plan duration: ~5 minutes
- Notable: Phase 1 plans executed in 2min each — isolated library work is very fast

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Execution Time | Phases | Key Change |
|-----------|---------------|--------|------------|
| v1.0 | ~36min | 4 | First milestone — established patterns for registry, testing, deployment |

### Cumulative Quality

| Milestone | Tests | Deviations | Auto-Fixed |
|-----------|-------|------------|------------|
| v1.0 | 263 | 4 | 4 (all blocking, all trivial) |

### Top Lessons (Verified Across Milestones)

1. Mirror existing patterns exactly when adding parallel functionality — consistency reduces integration surprises
2. Abstract base test contracts with virtual proof generation enable comprehensive matrix testing with minimal code
