---
phase: 1
slug: daverifierregistry-library-daverifieronchain
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-09
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Foundry (forge-std Test) |
| **Config file** | `foundry.toml` |
| **Quick run command** | `forge test --match-path test/DAVerifierOnChain.t.sol && forge test --match-path test/DAVerifierRegistry.t.sol` |
| **Full suite command** | `forge test` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `forge test --match-path test/DAVerifierOnChain.t.sol && forge test --match-path test/DAVerifierRegistry.t.sol`
- **After every plan wave:** Run `forge test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | R1 | unit | `forge test --match-path test/DAVerifierRegistry.t.sol` | W0 | pending |
| 01-01-02 | 01 | 1 | R1 | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_add` | W0 | pending |
| 01-01-03 | 01 | 1 | R1 | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_remove` | W0 | pending |
| 01-01-04 | 01 | 1 | R1 | unit | `forge test --match-path test/DAVerifierRegistry.t.sol --match-test test_isRegistered` | W0 | pending |
| 01-02-01 | 02 | 1 | R11 | unit | `forge test --match-path test/DAVerifierOnChain.t.sol` | W0 | pending |
| 01-02-02 | 02 | 1 | R11 | unit | `forge test --match-path test/DAVerifierOnChain.t.sol --match-test test_verifyDA_validProof` | W0 | pending |
| 01-02-03 | 02 | 1 | R12 | unit | `forge test --match-path test/DAVerifierOnChain.t.sol --match-test test_verifyDA` | W0 | pending |

*Status: pending / green / red / flaky*

---

## Wave 0 Requirements

- [ ] `test/DAVerifierRegistry.t.sol` — stubs for R1 (registry add/remove/isRegistered + events)
- [ ] `test/DAVerifierOnChain.t.sol` — stubs for R11, R12 (hash verification + purity)

*Existing infrastructure covers framework needs. No new dependencies.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
