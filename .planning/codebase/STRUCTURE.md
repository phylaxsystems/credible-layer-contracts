# Codebase Structure

**Analysis Date:** 2026-03-09

## Directory Layout

```
credible-layer-contracts/
├── src/                                # Core smart contract implementations
│   ├── StateOracle.sol                 # Main orchestrator contract
│   ├── StateOracleAccessControl.sol    # Role-based access control base
│   ├── Batch.sol                       # Delegatecall batch execution helper
│   ├── interfaces/                     # Protocol interface definitions
│   │   ├── IAdminVerifier.sol          # Admin verification interface
│   │   ├── IDAVerifier.sol             # Data availability verification interface
│   │   └── IBatch.sol                  # Batch execution interface
│   ├── lib/                            # Library contracts and helpers
│   │   └── AdminVerifierRegistry.sol   # Verifier registry management library
│   └── verification/                   # Pluggable verifier implementations
│       ├── admin/                      # Admin verification implementations
│       │   ├── AdminVerifierOwner.sol  # Verify admin via owner() method
│       │   ├── AdminVerifierWhitelist.sol # Verify admin via whitelist mapping
│       │   └── AdminVerifierSuperAdmin.sol # Test-only super admin verifier
│       └── da/                         # Data availability verification
│           └── DAVerifierECDSA.sol     # ECDSA signature verification
├── test/                               # Foundry test suite
│   ├── StateOracle.t.sol               # StateOracle unit and integration tests
│   ├── StateOracleAccessControl.t.sol  # Access control invariant tests
│   ├── AdminVerifierWhitelist.t.sol    # Whitelist verifier tests
│   ├── AdminVerifierSuperAdmin.t.sol   # Super admin verifier tests
│   ├── DAVerifierECDSA.t.sol           # ECDSA verifier tests
│   ├── Batch.t.sol                     # Batch execution tests
│   ├── integration/                    # Integration test scenarios
│   │   ├── StateOracleWithDAVerifierECDSA.sol # E2E adoption + assertion flow
│   │   └── DeployCoreWithStaging.t.sol # Dual oracle deployment scenario
│   └── utils/                          # Shared test utilities
│       ├── Adopter.sol                 # Mock adopter contracts for tests
│       ├── DAVerifierMock.sol          # Mock DA verifier for tests
│       └── ProxyHelper.t.sol           # Proxy deployment helper functions
├── script/                             # Foundry deployment scripts
│   ├── DeployCore.s.sol                # Standard deployment flow
│   ├── DeployCoreWithCreateX.s.sol     # Deterministic CreateX deployment
│   ├── DeployCoreWithStaging.s.sol     # Dual oracle + shared verifier deployment
│   └── ICreateX.sol                    # CreateX interface for deterministic deploys
├── shell/                              # Bash helper scripts
│   ├── create_artifacts.sh             # Generate ABI artifacts from compiled contracts
│   ├── deploy_create_x.sh              # Deploy CreateX factory (if needed)
│   ├── deploy_with_anvil.sh            # Deploy to local Anvil instance
│   └── presigned-transactions/         # Pre-signed transaction templates
├── artifacts/                          # Generated ABI outputs (do not edit)
│   ├── StateOracle.json                # StateOracle ABI
│   └── interfaces/                     # Interface ABIs
├── out/                                # Foundry compiler output (do not edit)
├── cache/                              # Foundry build cache (do not edit)
├── broadcast/                          # Foundry deployment broadcast logs (do not edit)
├── lib/                                # Vendored dependencies (do not modify)
│   ├── openzeppelin-contracts/         # OpenZeppelin ERC standards
│   ├── solady/                         # Solady utility library
│   └── forge-std/                      # Foundry test framework
├── .github/                            # GitHub configuration
│   └── workflows/                      # CI/CD workflows
├── .planning/                          # GSD planning documents (this project uses GSD)
│   └── codebase/                       # Codebase analysis documents (ARCHITECTURE.md, etc.)
├── foundry.toml                        # Foundry configuration
├── package.json                        # NPM manifest for artifact publishing
├── README.md                           # Project overview and deployment guide
├── CLAUDE.md                           # Agent-specific guidance (repo conventions)
└── .gitignore                          # Git ignore patterns
```

## Directory Purposes

**src/**
- Purpose: Production smart contract implementations
- Contains: Core protocol (`StateOracle`), access control base (`StateOracleAccessControl`), utility contract (`Batch`), and all verifier implementations
- Key files: `StateOracle.sol` (main orchestrator), `StateOracleAccessControl.sol` (role enforcement)

**src/interfaces/**
- Purpose: Protocol-facing interface definitions for pluggability
- Contains: `IAdminVerifier`, `IDAVerifier`, `IBatch` interfaces
- Pattern: Minimal interface contracts; implementations may differ

**src/lib/**
- Purpose: Reusable library logic for state management helpers
- Contains: `AdminVerifierRegistry` library for managing verifier registration
- Pattern: Library with internal functions operating over storage mappings

**src/verification/admin/**
- Purpose: Pluggable implementations of admin verification
- Contains: Three verifiers - `AdminVerifierOwner` (checks owner()), `AdminVerifierWhitelist` (owner-controlled mapping), `AdminVerifierSuperAdmin` (test-only)
- Key behavior: All return bool; silent false on incompatibility (see `AdminVerifierOwner` line 8-10)

**src/verification/da/**
- Purpose: Pluggable implementations of data availability verification
- Contains: `DAVerifierECDSA` (ECDSA signature recovery)
- Pattern: Receives assertion ID and proof; returns bool on verification success

**test/**
- Purpose: Comprehensive Foundry test suite covering all contract behaviors
- Contains: Unit tests per contract, integration tests, test utilities
- Test Organization: Co-located near implementation; `StateOracle.t.sol` tests `src/StateOracle.sol`

**test/integration/**
- Purpose: End-to-end test scenarios that span multiple contracts
- Contains: Full adoption + assertion flow tests, dual-oracle deployment tests
- Pattern: Tests validate complete user journeys from registration through assertion activation

**test/utils/**
- Purpose: Shared test doubles and helpers
- Contains: Mock adopters (`Adopter.sol`), mock DA verifier (`DAVerifierMock.sol`), proxy deployment helpers (`ProxyHelper.t.sol`)
- Usage: Imported by test files to reduce duplication

**script/**
- Purpose: Foundry deployment scripts for various chain/deployment scenarios
- Contains: Standard deploy (`DeployCore.s.sol`), deterministic CreateX deploy, staging dual-oracle deploy
- Pattern: Scripts read environment variables; output labeled addresses to console

**shell/**
- Purpose: Post-build and deployment helper scripts
- Contains: ABI generation (`create_artifacts.sh`), CreateX deployment, Anvil integration
- Automation: `npm run prepare` invokes `create_artifacts.sh`

**artifacts/** (generated, do not edit)
- Purpose: Published ABI JSON output for npm package consumers
- Generated by: `shell/create_artifacts.sh` after `forge build`
- Usage: Consumed by downstream clients (JavaScript/TypeScript integrations)

**out/**, **cache/**, **broadcast/** (generated, do not edit)
- Purpose: Build artifacts, compilation cache, deployment broadcast records
- Lifecycle: Regenerated by Foundry build/deploy commands
- Cleanup: Safe to delete; will be regenerated on next build

**lib/** (vendored, do not modify unless required)
- Purpose: Dependency contracts from external projects
- Contains: OpenZeppelin contracts, Solady utilities, forge-std test framework
- Pattern: Use `forge update` to upgrade; avoid hand-edits

## Key File Locations

**Entry Points:**

- `src/StateOracle.sol` (implementation) → deployed behind `TransparentUpgradeableProxy`
- `script/DeployCore.s.sol` (main deployment) → runs via `forge script`
- `test/StateOracle.t.sol` (primary test entry) → runs via `forge test`

**Configuration:**

- `foundry.toml` → Forge compilation settings, test defaults
- `.github/workflows/` → CI/CD pipeline definitions
- `CLAUDE.md` → Agent guidance for safe repo navigation

**Core Logic:**

- `src/StateOracle.sol` → Assertion adoption, registration, lifecycle management
- `src/StateOracleAccessControl.sol` → Role hierarchy and owner invariant
- `src/Batch.sol` → Multi-call delegation execution

**Testing:**

- `test/StateOracle.t.sol` → Primary unit test suite (66KB, comprehensive)
- `test/StateOracleAccessControl.t.sol` → Access control invariant tests
- `test/integration/StateOracleWithDAVerifierECDSA.sol` → E2E scenario validation

## Naming Conventions

**Files:**

- Implementation contracts: `PascalCase.sol` (e.g., `StateOracle.sol`, `AdminVerifierOwner.sol`)
- Test files: `PascalCase.t.sol` (e.g., `StateOracle.t.sol`)
- Scripts: `PascalCase.s.sol` (e.g., `DeployCore.s.sol`)
- Interfaces: `I` prefix + `PascalCase.sol` (e.g., `IAdminVerifier.sol`)
- Libraries: Direct `PascalCase.sol` without prefix (e.g., `AdminVerifierRegistry.sol`)

**Directories:**

- Camel case for logical grouping: `verification/admin/`, `verification/da/`, `test/utils/`, `test/integration/`

**Contracts & Identifiers:**

- Contract names: `PascalCase` (e.g., `StateOracle`, `AdminVerifierWhitelist`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `ASSERTION_TIMELOCK_BLOCKS`, `DA_VERIFIER`)
- Functions: `camelCase` (e.g., `registerAssertionAdopter`, `addAssertion`)
- Events: `PascalCase` (e.g., `AssertionAdded`, `ManagerTransferred`)
- Custom errors: `PascalCase` (e.g., `UnauthorizedManager()`, `AssertionAlreadyExists()`)
- Role identifiers: `SCREAMING_SNAKE_CASE` computed via keccak256 (e.g., `GOVERNANCE_ROLE`, `GUARDIAN_ROLE`)

## Where to Add New Code

**New Feature (e.g., new assertion constraint):**
- Primary code: `src/StateOracle.sol` → add method to public interface, add internal helper, extend `AssertionWindow` struct if needed
- Tests: `test/StateOracle.t.sol` → add new test contract inheriting `StateOracleBase`, add test cases
- Integration: `test/integration/StateOracleWithDAVerifierECDSA.sol` → add E2E scenario if feature affects user flow

**New Verifier Implementation (e.g., alternative admin verification):**
- Implementation: `src/verification/admin/AdminVerifierNewMethod.sol` → implement `IAdminVerifier.verifyAdmin()`
- Tests: `test/AdminVerifierNewMethod.t.sol` → unit tests for verifier logic
- Integration: `test/integration/` → add adoption test using new verifier if needed
- Deployment: `script/DeployCore.s.sol` → add optional deployment branch for new verifier

**New Utility Library (e.g., helper for assertion ID generation):**
- Implementation: `src/lib/AssertionIdHelper.sol` → library functions
- Tests: `test/AssertionIdHelper.t.sol` → unit test coverage
- Usage: Import in `StateOracle.sol` or `test/` as needed

**Test Utilities (e.g., new mock contract):**
- Implementation: `test/utils/NewMock.sol` → minimal mock implementing needed interface
- Usage: Import in test files that need the mock
- Pattern: Keep test utilities simple; avoid business logic

## Special Directories

**out/, cache/, broadcast/**
- Purpose: Foundry-generated outputs
- Generated: Yes (automatically by `forge build`, `forge test`, `forge script`)
- Committed: No (listed in .gitignore)
- Management: Safe to delete; will be regenerated on next Foundry command

**artifacts/**
- Purpose: Generated ABI JSON for npm package publishing
- Generated: Yes (by `shell/create_artifacts.sh` after `forge build`)
- Committed: Yes (intentional; distributed via npm package)
- Management: Do not hand-edit; regenerate via `npm run prepare` if contracts change

**lib/**
- Purpose: Vendored dependencies from external packages
- Generated: No (checked in via git submodules)
- Committed: Yes
- Management: Use `forge update openzeppelin-contracts` to upgrade; avoid direct edits

**.github/workflows/**
- Purpose: Automated CI/CD pipeline definitions
- Generated: No
- Committed: Yes
- Management: Edit to adjust test/build triggers

## Proxy Pattern Notes

**TransparentUpgradeableProxy Structure:**

- Implementation contract: `StateOracle` (deployed separately)
- Proxy contract: `TransparentUpgradeableProxy` (deployment script creates and initializes)
- Proxy admin: Separate address (configurable, often governance multisig)
- Initialization: Happens via `initialize()` called through proxy constructor argument

**Implications for File Organization:**

- `src/StateOracle.sol` is the *implementation*; tests use `TransparentUpgradeableProxy` wrapper
- `test/utils/ProxyHelper.t.sol` provides `deployProxy()` helper to avoid repetition
- Test setup uses `noAdmin()` modifier to exclude proxy admin from assertions (transparent proxy limitation)
- Deployment scripts emit both implementation and proxy addresses

---

*Structure analysis: 2026-03-09*
