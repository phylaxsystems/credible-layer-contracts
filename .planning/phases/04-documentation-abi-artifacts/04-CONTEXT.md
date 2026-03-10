# Phase 4: Documentation + ABI Artifacts - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Update README.md to document the DA verifier registry, new governance functions, updated addAssertion signature, DAVerifierOnChain usage, and revised deployment flow. Regenerate published ABI artifacts via `npm run prepare`. This phase does NOT add new features or change contracts.

</domain>

<decisions>
## Implementation Decisions

### Artifact Scope
- No changes to `shell/create_artifacts.sh` — the script already covers StateOracle, IDAVerifier interface, and other published contracts
- Just run `npm run prepare` to regenerate — StateOracle ABI auto-updates with new functions/events/signatures from Phases 1-3
- Do NOT add DAVerifierOnChain, DAVerifierRegistry library, or AdminVerifierWhitelist to the artifact script — interfaces are sufficient
- IDAVerifier interface is already published in `artifacts/interfaces/`

### README Structure
- Expand existing sections rather than adding new top-level sections
- Update "Data Availability Verification" section to cover the registry concept + OnChain verifier alongside ECDSA
- Add "Add or remove DA verifiers" bullet to "State Oracle Administration" section (alongside existing admin verifier governance)
- Update "Deployment Overview" numbered steps AND example console output to show both DA verifiers deployed
- Update "Testing with Anvil" section console output only (env vars and command are still valid)
- Leave ASCII architecture diagram as-is — still accurate at the high level

### Documentation Depth
- Mid-detail matching current README tone (1-2 paragraphs + bullet lists, not code snippets)
- Document assertion lifecycle change in "State Oracle Behavior" section: managers now select a registered DA verifier when adding assertions
- Brief explanation of DAVerifierOnChain proof mechanism: "keccak256(proof) == assertionId" — one sentence matching how ECDSA verifier is documented
- List available DA verifiers (ECDSA for off-chain DA, OnChain for on-chain bytecode availability)
- Mention per-assertion verifier selection

### Claude's Discretion
- Exact wording and paragraph structure within updated sections
- Whether to add a brief "Available DA Verifiers" sub-list or inline descriptions
- Console output example addresses (can be placeholder or regenerated)

</decisions>

<specifics>
## Specific Ideas

- Match the documentation style of the existing ECDSA verifier description when adding DAVerifierOnChain
- The deployment description currently says "provision the core protocol with the `DAVerifierECDSA` implementation" — update to mention both verifiers
- The deployment steps should reflect the actual order: ECDSA verifier, OnChain verifier, admin verifiers, implementation, proxy

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `shell/create_artifacts.sh`: Extracts ABIs from forge build output. Already handles StateOracle, interfaces, and libraries. No changes needed.
- `README.md`: Well-structured with Components, State Oracle, Admin Verification, DA Verification, Administration, Deployment, Environment Variables, Installation sections.

### Established Patterns
- DA verifier documentation follows the pattern: explain the concept, then describe the specific implementation (ECDSA with DA_PROVER_ADDRESS)
- Deployment overview: numbered steps with console output example
- Environment variables listed as bullet points before deployment overview

### Integration Points
- README "Data Availability Verification" section (lines 51-64): expand with registry + OnChain verifier
- README "State Oracle Administration" section (lines 68-74): add DA verifier governance bullet
- README "State Oracle Behavior" section (lines 39-43): add per-assertion DA verifier selection
- README "Deployment" section (lines 77-78): update deployment description
- README "Deployment Overview" (lines 93-110): update steps and console output
- README "Testing with Anvil" (lines 147-179): update console output

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 04-documentation-abi-artifacts*
*Context gathered: 2026-03-10*
