---
phase: 3
slug: deployment-scripts-integration-tests
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Foundry (forge test) |
| **Config file** | `foundry.toml` |
| **Quick run command** | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol` |
| **Full suite command** | `forge test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `forge test --match-path test/integration/DeployCoreWithStaging.t.sol`
- **After every plan wave:** Run `forge test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | R16 | integration | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol` | Exists (needs update) | ⬜ pending |
| 03-01-02 | 01 | 1 | R17 | integration | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol` | Exists (needs update) | ⬜ pending |
| 03-01-03 | 01 | 1 | R18 | integration | `forge test --match-path test/integration/DeployCoreWithStaging.t.sol` | Exists (needs update) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements.

- `test/integration/DeployCoreWithStaging.t.sol` — exists, needs DA verifier registry assertions added
- `test/integration/StateOracleAssertionFlowBase.sol` + 4 concrete contracts — assertion flow matrix already covers E2E with both DA verifiers
- `test/StateOracle.t.sol::Batch` — batch test with 5-param addAssertion already passing

*No new test files need to be created from scratch.*

---

## Manual-Only Verifications

All phase behaviors have automated verification.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
