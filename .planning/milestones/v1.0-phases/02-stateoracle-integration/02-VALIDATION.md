---
phase: 2
slug: stateoracle-integration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-09
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Foundry (forge test) |
| **Config file** | foundry.toml |
| **Quick run command** | `forge test --match-path test/StateOracle.t.sol` |
| **Full suite command** | `forge test` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `forge test --match-path test/StateOracle.t.sol`
- **After every plan wave:** Run `forge test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | R13, R14 | unit | `forge test --match-path test/StateOracle.t.sol --match-contract Constructor -vv` | Exists (needs update) | ⬜ pending |
| 02-01-02 | 01 | 1 | R2, R4 | unit | `forge test --match-path test/StateOracle.t.sol --match-contract AddDAVerifier -vv` | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 1 | R3 | unit | `forge test --match-path test/StateOracle.t.sol --match-contract RemoveDAVerifier -vv` | ❌ W0 | ⬜ pending |
| 02-01-04 | 01 | 1 | R5 | unit | `forge test --match-path test/StateOracle.t.sol --match-contract Initialize -vv` | Exists (needs update) | ⬜ pending |
| 02-02-01 | 02 | 1 | R6, R7, R9 | unit | `forge test --match-path test/StateOracle.t.sol --match-contract AddAssertion -vv` | Exists (needs update) | ⬜ pending |
| 02-02-02 | 02 | 1 | R10 | unit | `forge build` | ✅ | ⬜ pending |
| 02-02-03 | 02 | 1 | R13, R15 | unit | `forge test --match-test storageLayout -vv` | ❌ W0 | ⬜ pending |
| 02-03-01 | 03 | 2 | R8 | integration | `forge test --match-path test/integration/ -vv` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `AddDAVerifier` test contract in `test/StateOracle.t.sol` — stubs for R2, R4
- [ ] `RemoveDAVerifier` test contract in `test/StateOracle.t.sol` — stubs for R3
- [ ] DAVerifierNotRegistered revert test in AddAssertion — covers R7
- [ ] Storage layout ordering test — covers R13, R15
- [ ] Integration test base + 4 concrete implementations in `test/integration/` — covers R8
- [ ] Update existing Constructor, Initialize, AddAssertion tests for new signatures — covers R5, R6, R9, R14

*Existing infrastructure covers test framework. Wave 0 is about new test contracts and signature updates.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
