# Phase 4: Documentation + ABI Artifacts - Research

**Researched:** 2026-03-10
**Domain:** README documentation updates and npm ABI artifact regeneration
**Confidence:** HIGH

## Summary

Phase 4 is a documentation-only phase with no contract or test changes. It requires two deliverables: (1) regenerating ABI artifacts via `npm run prepare`, and (2) updating README.md to document the DA verifier registry, new governance functions, updated `addAssertion` signature, `DAVerifierOnChain` usage, the staging deployment script, and any new environment variables.

The ABI artifacts are already reflecting the new code because `npm run prepare` re-extracts from forge build output. The `shell/create_artifacts.sh` script does not need modification -- it already extracts StateOracle, DAVerifierECDSA, AdminVerifierOwner, interfaces, and libraries. The user decision explicitly states DAVerifierOnChain and DAVerifierRegistry should NOT be added to the artifact script.

The README requires targeted expansions to six sections. The existing documentation tone is mid-detail: short paragraphs with bullet lists, no inline code snippets beyond deployment commands and console output.

**Primary recommendation:** Run `npm run prepare` to regenerate artifacts first, then update README.md sections in the order listed in CONTEXT.md. No script changes needed.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- No changes to `shell/create_artifacts.sh` -- the script already covers StateOracle, IDAVerifier interface, and other published contracts
- Just run `npm run prepare` to regenerate -- StateOracle ABI auto-updates with new functions/events/signatures from Phases 1-3
- Do NOT add DAVerifierOnChain, DAVerifierRegistry library, or AdminVerifierWhitelist to the artifact script -- interfaces are sufficient
- IDAVerifier interface is already published in `artifacts/interfaces/`
- Expand existing sections rather than adding new top-level sections
- Update "Data Availability Verification" section to cover the registry concept + OnChain verifier alongside ECDSA
- Add "Add or remove DA verifiers" bullet to "State Oracle Administration" section (alongside existing admin verifier governance)
- Update "Deployment Overview" numbered steps AND example console output to show both DA verifiers deployed
- Update "Testing with Anvil" section console output only (env vars and command are still valid)
- Leave ASCII architecture diagram as-is -- still accurate at the high level
- Mid-detail matching current README tone (1-2 paragraphs + bullet lists, not code snippets)
- Document assertion lifecycle change in "State Oracle Behavior" section: managers now select a registered DA verifier when adding assertions
- Brief explanation of DAVerifierOnChain proof mechanism: "keccak256(proof) == assertionId" -- one sentence matching how ECDSA verifier is documented
- List available DA verifiers (ECDSA for off-chain DA, OnChain for on-chain bytecode availability)
- Mention per-assertion verifier selection
- Match the documentation style of the existing ECDSA verifier description when adding DAVerifierOnChain
- The deployment description currently says "provision the core protocol with the DAVerifierECDSA implementation" -- update to mention both verifiers
- The deployment steps should reflect the actual order: ECDSA verifier, OnChain verifier, admin verifiers, implementation, proxy

### Claude's Discretion
- Exact wording and paragraph structure within updated sections
- Whether to add a brief "Available DA Verifiers" sub-list or inline descriptions
- Console output example addresses (can be placeholder or regenerated)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| R19 | ABI artifacts regenerated: `npm run prepare` produces updated artifacts | Verified: `npm run prepare` already produces correct output. StateOracle ABI already includes `addDAVerifier`, `removeDAVerifier`, `isDAVerifierRegistered`, `daVerifiers` mapping, `DAVerifierAdded`/`DAVerifierRemoved` events, updated 5-param `addAssertion`, and extended `AssertionAdded` event. No script changes needed. |
| R20 | README updated with DA verifier registry docs: new env vars, governance functions, DA verifier management documented | Six README sections need updates. New env vars from staging script: `STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA`, `STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS`. New governance functions: `addDAVerifier`, `removeDAVerifier`. New assertion flow: per-assertion DA verifier selection. |
</phase_requirements>

## Standard Stack

This phase does not introduce new libraries or tools. It uses only existing project tooling.

### Core
| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| `npm run prepare` | N/A | Regenerates ABI artifacts from forge build output | Existing project script, documented in CLAUDE.md |
| `forge build` | latest | Compiles contracts (called internally by create_artifacts.sh) | Standard Foundry toolchain |
| Markdown | N/A | README.md format | Existing documentation format |

### Installation
No new packages required.

## Architecture Patterns

### Existing README Structure (Line References)
```
README.md
  L1-9:     Title + Overview
  L12-29:   Components (ASCII diagram)
  L31-43:   The State Oracle + Behavior
  L45-64:   Protocol Admin Verification + Data Availability Verification
  L66-74:   State Oracle Administration
  L76-78:   Deployment (description paragraph)
  L80-91:   Environment Variables
  L93-110:  Deployment Overview (numbered steps + console output)
  L112-145: Installation + CreateX
  L147-191: Testing with Anvil
```

### Pattern 1: Section Expansion Strategy
**What:** Each README section update expands existing content in-place rather than adding new sections.
**When to use:** All six section updates.
**Key principle:** Maintain the existing README organizational structure. The user explicitly said "expand existing sections rather than adding new top-level sections."

### Pattern 2: DA Verifier Documentation Pattern
**What:** Follow the existing pattern used for ECDSA verifier documentation.
**Current pattern (README L62-64):**
> For example, the `DAVerifierECDSA` requires a signature over the assertion id from a configured `DA_PROVER_ADDRESS`. When storing the assertion at the Assertion DA, the user will receive the signature in return.

**New content should follow the same style:** one-sentence mechanism description per verifier.

### Pattern 3: Console Output Pattern
**What:** Deployment console output uses `<label> deployed at <address>` format.
**Current pattern (README L104-110):** Labels match `console2.log` strings from deployment scripts.
**New labels from DeployCore.s.sol:**
- `"DA Verifier deployed at"` (ECDSA, existing)
- `"DA Verifier (OnChain) deployed at"` (new)
- `"Admin Verifier (Owner) deployed at"` (existing)
- `"Admin Verifier (Whitelist) deployed at"` (existing)
- `"State Oracle Implementation deployed at"` (existing, label changed from "State Oracle")
- `"State Oracle Proxy deployed at"` (existing)

### Anti-Patterns to Avoid
- **Adding new top-level sections:** User explicitly said to expand existing sections.
- **Adding code snippets:** User said mid-detail, matching existing tone; existing README uses no Solidity code blocks.
- **Documenting DAVerifierOnChain ABI in artifacts section:** User explicitly said NOT to add DAVerifierOnChain to artifact script.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ABI extraction | Manual JSON editing | `npm run prepare` (shell/create_artifacts.sh) | Script already handles forge build + jq extraction for all published contracts |

**Key insight:** The artifact regeneration is purely mechanical -- run the existing script. The documentation work is the actual substance of this phase.

## Common Pitfalls

### Pitfall 1: Forgetting Staging Environment Variables
**What goes wrong:** README documents only the base deployment env vars but misses the two new staging-specific variables.
**Why it happens:** `DeployCoreWithStaging` extends `DeployCore.setUp()` and adds its own `vm.envUint` calls that are easy to overlook.
**How to avoid:** Document `STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA` and `STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS` in the Environment Variables section, clearly noting they are only needed for the staging deployment script.
**Warning signs:** `DeployCoreWithStaging.setUp()` requires these env vars; deployment would fail without them.

### Pitfall 2: Console Output Mismatch
**What goes wrong:** Example console output in README does not match actual `console2.log` strings in deployment scripts.
**Why it happens:** The deployment script log labels changed when DAVerifierOnChain was added (e.g., the implementation label changed to include "Implementation").
**How to avoid:** Cross-reference exact console2.log strings from `DeployCore.s.sol` lines 116, 121, 141, 162, 168, 174 when writing console output examples.
**Warning signs:** Console output labels in README do not match what running the script actually produces.

### Pitfall 3: Deployment Step Order Wrong
**What goes wrong:** Numbered deployment steps do not match actual execution order in `DeployCore.run()`.
**Why it happens:** The run() function deploys in a specific order: ECDSA DA verifier, OnChain DA verifier, admin verifiers, state oracle implementation, proxy with initialization.
**How to avoid:** Follow the actual `run()` method order (lines 57-73 of DeployCore.s.sol).
**Warning signs:** Steps do not match the order in which console2.log lines appear.

### Pitfall 4: Overstating Changes
**What goes wrong:** Documentation implies larger architectural changes than what actually happened.
**Why it happens:** The DA verifier registry is a significant internal change, but from a user perspective the main visible changes are: (1) managers pick a DA verifier per-assertion, (2) governance can manage DA verifiers, (3) the OnChain verifier is a new option.
**How to avoid:** Keep the description focused on user-facing behavior changes, matching the existing README's practical tone.

### Pitfall 5: Not Running npm run prepare Before Committing
**What goes wrong:** Artifacts directory contains stale ABIs from before Phase 1-3 changes.
**Why it happens:** Artifacts are not auto-regenerated on forge build; they require explicit `npm run prepare`.
**How to avoid:** Run `npm run prepare` as the first task action and verify the output includes updated files.
**Warning signs:** `git diff` shows no changes to artifacts/ after running `npm run prepare` (this actually means they were already current, which is fine, but should be verified).

## Code Examples

### Verified: Current Deployment Script Order (DeployCore.run())
Source: `script/DeployCore.s.sol` lines 57-73
```
1. _deployDAVerifier()           -- DAVerifierECDSA
2. _deployDAVerifierOnChain()    -- DAVerifierOnChain
3. _deployAdminVerifiers()       -- AdminVerifierOwner and/or AdminVerifierWhitelist
4. _deployStateOracle()          -- StateOracle implementation
5. _deployStateOracleProxy()     -- Proxy with initialize(admin, adminVerifiers, daVerifiers, maxAssertions)
```

### Verified: Console Log Labels (From Deployment Scripts)
Source: `script/DeployCore.s.sol`
```
"DA Verifier deployed at"                    (line 116)
"DA Verifier (OnChain) deployed at"          (line 121)
"Admin Verifier (Owner) deployed at"         (line 168)
"Admin Verifier (Whitelist) deployed at"     (line 174)
"State Oracle Implementation deployed at"    (line 141, via string.concat)
"State Oracle Proxy deployed at"             (line 162)
```

### Verified: New StateOracle Functions (For Documentation)
Source: `src/StateOracle.sol`
```
addDAVerifier(IDAVerifier daVerifier)        -- onlyGovernance (line 423)
removeDAVerifier(IDAVerifier daVerifier)     -- onlyGovernance (line 436)
isDAVerifierRegistered(IDAVerifier)          -- public view (line 442)
addAssertion(address, IDAVerifier, bytes32, bytes, bytes)  -- updated signature (line 233)
```

### Verified: New Events
Source: `src/lib/DAVerifierRegistry.sol`
```
event DAVerifierAdded(IDAVerifier daVerifier)    (line 17)
event DAVerifierRemoved(IDAVerifier daVerifier)  (line 21)
```

### Verified: New Errors
Source: `src/StateOracle.sol`
```
error DAVerifierNotRegistered()              (line 40)
error InvalidDAProof(IDAVerifier daVerifier) (line 43)
```

### Verified: Environment Variables (All Deploy Scripts)
Source: `script/DeployCore.s.sol` setUp() + `script/DeployCoreWithStaging.s.sol` setUp()
```
Existing (DeployCore):
  STATE_ORACLE_MAX_ASSERTIONS_PER_AA
  STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS
  STATE_ORACLE_ADMIN_ADDRESS
  DA_PROVER_ADDRESS
  DEPLOY_ADMIN_VERIFIER_OWNER (true/false)
  DEPLOY_ADMIN_VERIFIER_WHITELIST (true/false)
  ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS

New (DeployCoreWithStaging only):
  STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA
  STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS
```

### Verified: Artifact Script Does Not Need Changes
Source: `shell/create_artifacts.sh`
```
Already extracts:
  - StateOracle.json           (includes new DA verifier functions/events/errors)
  - AdminVerifierOwner.json
  - DAVerifierECDSA.json
  - interfaces/IBatch.json
  - interfaces/IDAVerifier.json (unchanged interface)
  - interfaces/IAdminVerifier.json
  - libraries/AdminVerifierRegistry.json

NOT included (per user decision):
  - DAVerifierOnChain (not published as artifact)
  - DAVerifierRegistry library (not published as artifact)
```

## Specific README Section Changes

### Section 1: "State Oracle Behavior" (Current Lines 39-43)
**Current content:** Describes assertion lifecycle, one-time registration, timelock, admin verifiers.
**Change needed:** Add a bullet about managers selecting a registered DA verifier when adding assertions. This is a behavior change: previously there was a single hardcoded DA verifier, now it is per-assertion.

### Section 2: "Data Availability Verification" (Current Lines 51-64)
**Current content:** Describes DA concept generally, then specifically mentions DAVerifierECDSA and DA_PROVER_ADDRESS.
**Change needed:** Expand to explain the registry concept (multiple DA verifiers can be registered), introduce DAVerifierOnChain alongside ECDSA. Keep the Assertion DA link for ECDSA. Add one-sentence description of OnChain verifier: `keccak256(proof) == assertionId`.

### Section 3: "State Oracle Administration" (Current Lines 66-74)
**Current content:** Three bullets: admin verifiers, manager management, assertion removal.
**Change needed:** Add a fourth bullet for DA verifier management: "Add or remove DA verifiers" matching the style of the existing admin verifier bullet.

### Section 4: "Deployment" paragraph (Current Lines 76-78)
**Current content:** References only DAVerifierECDSA and DA_PROVER_ADDRESS requirement.
**Change needed:** Update to mention both verifiers. Reference DeployCoreWithStaging as well. Note that both ECDSA and OnChain DA verifiers are deployed and registered during initialization.

### Section 5: "Environment Variables" (Current Lines 80-91)
**Current content:** Lists 7 env vars for DeployCore/DeployCoreWithCreateX.
**Change needed:** Add the two staging-specific env vars with a note that they apply only to DeployCoreWithStaging.

### Section 6: "Deployment Overview" (Current Lines 93-110)
**Current content:** 5 numbered steps + console output. Step 1 says "Deploy the DA verifier (ECDSA)".
**Change needed:**
- Add step for OnChain DA verifier (step 2, shifting others down)
- Update proxy step to mention DA verifier registry population
- Update console output to include `DA Verifier (OnChain) deployed at <address>`
- Update label from "State Oracle" to "State Oracle Implementation" to match console2.log

### Section 7: "Testing with Anvil" Console Output (Current Lines 170-179)
**Current content:** Shows 5 deployed addresses.
**Change needed:** Add `DA Verifier (OnChain) deployed at <address>` line. Update implementation label. Addresses can remain placeholder or be regenerated.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single immutable DA_VERIFIER | DA verifier registry with per-assertion selection | Phase 2 (this project) | Documentation must reflect registry concept, not single verifier |
| `addAssertion(address, bytes32, bytes, bytes)` | `addAssertion(address, IDAVerifier, bytes32, bytes, bytes)` | Phase 2 (this project) | ABI change reflected in artifacts; README behavior section needs update |
| Constructor takes `assertionTimelockBlocks` + `daVerifier` | Constructor takes only `assertionTimelockBlocks` | Phase 2 (this project) | No README impact (constructor params not documented in README) |

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Foundry (forge test) |
| Config file | foundry.toml |
| Quick run command | `forge test` |
| Full suite command | `forge test` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R19 | ABI artifacts regenerated correctly | smoke | `npm run prepare && git diff --stat artifacts/` | N/A -- manual verification that output matches expected |
| R20 | README correctly documents new features | manual-only | N/A -- human review of README content | N/A |

**Justification for manual-only:** Both requirements are documentation-only. R19 can be smoke-tested by running `npm run prepare` and confirming it succeeds without errors. R20 is inherently a human-review task (correctness of prose). No new automated tests are needed for this phase.

### Sampling Rate
- **Per task commit:** `npm run prepare` (verify artifacts regenerate cleanly)
- **Per wave merge:** `forge test` (ensure no accidental contract changes)
- **Phase gate:** `npm run prepare` succeeds + README content review

### Wave 0 Gaps
None -- this phase does not require test infrastructure. It is documentation and artifact regeneration only.

## Open Questions

1. **Console output addresses for Testing with Anvil section**
   - What we know: The existing console output shows deterministic addresses from CreateX deployment with a specific private key. Phase 1-3 changes (adding DAVerifierOnChain) will change the nonce-derived addresses.
   - What's unclear: Whether to regenerate exact addresses by running anvil locally, or use placeholder addresses.
   - Recommendation: Use placeholder `<address>` format for new entries, keeping existing addresses for unchanged contracts since they come from deterministic CreateX deployment. The user decision said "Console output example addresses (can be placeholder or regenerated)" -- placeholders are simpler and less error-prone.

2. **DeployCoreWithStaging documentation depth**
   - What we know: The staging script is a new deployment flow from Phase 3. The README currently only mentions DeployCore and DeployCoreWithCreateX.
   - What's unclear: How prominently to document the staging deployment script.
   - Recommendation: Mention it in the Deployment paragraph alongside the other scripts. Add its env vars to the Environment Variables section. Keep it brief since the CONTEXT.md decisions focus on updating existing sections, not adding staging-specific sections.

## Sources

### Primary (HIGH confidence)
- `src/StateOracle.sol` -- verified new functions, events, errors, and addAssertion signature
- `src/verification/da/DAVerifierOnChain.sol` -- verified keccak256(proof) == assertionId mechanism
- `src/lib/DAVerifierRegistry.sol` -- verified DAVerifierAdded/DAVerifierRemoved events
- `script/DeployCore.s.sol` -- verified deployment order and console2.log labels
- `script/DeployCoreWithStaging.s.sol` -- verified new env vars
- `shell/create_artifacts.sh` -- verified artifact extraction scope
- `artifacts/StateOracle.json` -- verified ABI already includes new functions/events
- `README.md` -- verified current section structure and content
- `package.json` -- verified `npm run prepare` script

### Secondary (MEDIUM confidence)
- None needed -- all findings are from direct codebase inspection

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- no new tools, just existing `npm run prepare` and README editing
- Architecture: HIGH -- direct inspection of all source files, deployment scripts, and current README
- Pitfalls: HIGH -- identified from concrete codebase inspection (deployment order, console labels, env vars)

**Research date:** 2026-03-10
**Valid until:** Indefinite (phase is documentation-only, locked to current codebase state)
