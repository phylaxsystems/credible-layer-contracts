---
phase: 4
slug: documentation-abi-artifacts
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Foundry (forge test) + npm scripts |
| **Config file** | `foundry.toml`, `package.json` |
| **Quick run command** | `npm run prepare` |
| **Full suite command** | `forge test && npm run prepare` |
| **Estimated runtime** | ~20 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm run prepare` (verify artifacts regenerate cleanly)
- **After every plan wave:** Run `forge test` (ensure no accidental contract changes)
- **Before `/gsd:verify-work`:** Full suite must be green + README content review
- **Max feedback latency:** 20 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | R19 | smoke | `npm run prepare && git diff --stat artifacts/` | N/A | ⬜ pending |
| 04-01-02 | 01 | 1 | R20 | manual | N/A — human review of README content | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements.

This phase is documentation and artifact regeneration only — no new test files needed.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| README content accuracy | R20 | Documentation correctness requires human review | Read updated README sections, verify DA verifier registry, governance functions, deployment steps, and console output are accurate |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 20s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
