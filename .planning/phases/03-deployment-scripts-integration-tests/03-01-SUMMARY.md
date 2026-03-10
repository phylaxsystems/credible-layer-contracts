---
phase: 03-deployment-scripts-integration-tests
plan: 01
subsystem: deployment
tags: [foundry, solidity, deploy-scripts, da-verifier, createx, proxy]

# Dependency graph
requires:
  - phase: 01-da-verifier-library-contracts
    provides: DAVerifierOnChain contract and DAVerifierRegistry library
  - phase: 02-stateoracle-integration
    provides: StateOracle.initialize() with IDAVerifier[] array parameter
provides:
  - DeployCore deploys both DAVerifierECDSA and DAVerifierOnChain in run()
  - _deployStateOracleProxy accepts address[] for DA verifiers across all script overrides
  - DeployCoreWithCreateX uses deterministic salt for DAVerifierOnChain
  - DeployCoreWithStaging deploys per-oracle OnChain verifiers while sharing ECDSA verifier
affects: [03-02, integration-tests, deployment-docs]

# Tech tracking
tech-stack:
  added: []
  patterns: [per-oracle-onchain-verifier, array-based-da-verifier-deployment]

key-files:
  created: []
  modified:
    - script/DeployCore.s.sol
    - script/DeployCoreWithCreateX.s.sol
    - script/DeployCoreWithStaging.s.sol
    - test/integration/DeployCoreWithStaging.t.sol

key-decisions:
  - "DAVerifierOnChain deployed per-oracle in staging script (not shared) for isolation"
  - "OnChain verifier addresses kept as local variables in staging run() since consumed immediately"
  - "_deployDAVerifierOnChain() is virtual to allow CreateX override with deterministic salt"

patterns-established:
  - "Array-based DA verifier deployment: all scripts pass address[] to _deployStateOracleProxy"
  - "Per-oracle OnChain verifier: staging deploys separate DAVerifierOnChain instances per oracle"

requirements-completed: [R16, R17, R18]

# Metrics
duration: 13min
completed: 2026-03-10
---

# Phase 3 Plan 1: Deployment Script DA Verifier Updates Summary

**All three deployment scripts updated to deploy DAVerifierOnChain alongside DAVerifierECDSA and register both atomically via initialize() IDAVerifier[] array**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-10T13:07:22Z
- **Completed:** 2026-03-10T13:20:30Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- DeployCore.s.sol deploys both ECDSA and OnChain DA verifiers and passes 2-element array to proxy initialization
- DeployCoreWithCreateX.s.sol uses deterministic CreateX deployment with salt "credible-layer-da-verifier-onchain"
- DeployCoreWithStaging.s.sol deploys per-oracle DAVerifierOnChain instances while sharing ECDSA verifier
- Integration test updated to mirror per-oracle OnChain verifier pattern
- All 259 tests pass with zero failures

## Task Commits

Each task was committed atomically:

1. **Task 1: Add _deployDAVerifierOnChain and update _deployStateOracleProxy in DeployCore and DeployCoreWithCreateX** - `059398d` (feat)
2. **Task 2: Update DeployCoreWithStaging for per-oracle OnChain verifier deployment** - `b5e6c4c` (feat)

## Files Created/Modified
- `script/DeployCore.s.sol` - Added _deployDAVerifierOnChain() virtual method, updated _deployStateOracleProxy to accept address[], updated run() to deploy both DA verifiers
- `script/DeployCoreWithCreateX.s.sol` - Added SALT_DA_VERIFIER_ONCHAIN_NAME constant, _deployDAVerifierOnChain() override with CreateX, updated _deployStateOracleProxy signature
- `script/DeployCoreWithStaging.s.sol` - Updated run() to deploy per-oracle OnChain verifiers while sharing ECDSA verifier, both oracles receive 2-element DA verifier array
- `test/integration/DeployCoreWithStaging.t.sol` - Updated setUp to deploy both ECDSA and OnChain DA verifiers per oracle

## Decisions Made
- DAVerifierOnChain is deployed per-oracle in the staging script (not shared) for isolation between production and staging
- OnChain verifier addresses are local variables in staging run() since they are consumed immediately by _deployStateOracleProxy
- _deployDAVerifierOnChain() is virtual to allow CreateX deterministic deployment override

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated integration test to match new deployment script interface**
- **Found during:** Task 2 (DeployCoreWithStaging update)
- **Issue:** Integration test DeployCoreWithStaging.t.sol still used single DA verifier pattern, which would fail with updated scripts
- **Fix:** Updated test setUp to deploy both ECDSA and OnChain DA verifiers per oracle, matching new deployment pattern
- **Files modified:** test/integration/DeployCoreWithStaging.t.sol
- **Verification:** All 7 integration tests pass
- **Committed in:** b5e6c4c (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Auto-fix was necessary to maintain test consistency with updated deployment scripts. No scope creep.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All deployment scripts compile and deploy complete DA verifier set atomically
- Integration tests verify dual-oracle deployment with shared ECDSA and per-oracle OnChain verifiers
- Ready for Plan 03-02 (deployment integration testing or remaining Phase 3 tasks)

## Self-Check: PASSED

All files verified present. All commit hashes verified in git log.

---
*Phase: 03-deployment-scripts-integration-tests*
*Completed: 2026-03-10*
