# Technology Stack

**Analysis Date:** 2026-03-09

## Languages

**Primary:**
- Solidity 0.8.28 - Core smart contracts for the Credible Layer protocol
- Solidity 0.8.22+ - Secondary contracts (e.g., `src/Batch.sol` uses `^0.8.22`)

**Secondary:**
- Shell - Build and deployment helper scripts
- Bash - CI/CD automation

## Runtime

**Environment:**
- Ethereum Virtual Machine (EVM) - All contracts compile to EVM bytecode
- Foundry (Forge) - Test and execution environment

**Package Manager:**
- npm - JavaScript package management for npm publishing
- Foundry (`forge`) - Solidity dependency and build management

## Frameworks

**Core:**
- OpenZeppelin Contracts 4.x - Access control, proxy patterns, upgradeable contracts
  - Location: `lib/openzeppelin-contracts`
  - Used for: `Ownable2Step`, `AccessControl`, `TransparentUpgradeableProxy`
- Solady - Optimized EVM utility library for cryptographic operations
  - Location: `lib/solady`
  - Used for: `Initializable`, `ECDSA` signature recovery

**Testing:**
- Foundry (Forge) - Smart contract testing framework
  - Config: `foundry.toml`
  - Test framework: `forge-std/Test.sol`

**Build/Dev:**
- Foundry (Forge) - Build, compile, and deployment tool
  - Config: `foundry.toml` defines source (`src`), output (`out`), and library paths (`lib`)
- jq - JSON processor for ABI extraction in build scripts

## Key Dependencies

**Critical:**
- openzeppelin-contracts - Provides proxy infrastructure (`TransparentUpgradeableProxy`), role-based access control (`AccessControl`), and ownership patterns (`Ownable2Step`)
  - Location: `lib/openzeppelin-contracts`
  - Why it matters: Core to upgradeable protocol design and security model
- solady - Provides optimized ECDSA signature recovery (`ECDSA.recoverCalldata`)
  - Location: `lib/solady`
  - Why it matters: Data availability proof verification relies on signature recovery

**Infrastructure:**
- forge-std - Standard library and utilities for Foundry tests
  - Location: `lib/forge-std`
  - Used for: `Test` base class, `console2` logging, `Script` base for deployment scripts

## Configuration

**Environment:**
- Environment variables configured in deployment scripts and test suites
- Key runtime config vars (from README.md):
  - `STATE_ORACLE_MAX_ASSERTIONS_PER_AA` - Per-adopter assertion limit
  - `STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS` - Timelock duration
  - `STATE_ORACLE_ADMIN_ADDRESS` - Initial admin/owner
  - `DA_PROVER_ADDRESS` - Data availability signer address
  - `DEPLOY_ADMIN_VERIFIER_OWNER` - Boolean flag for owner verifier deployment
  - `DEPLOY_ADMIN_VERIFIER_WHITELIST` - Boolean flag for whitelist verifier deployment
  - `ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS` - Whitelist verifier admin

**Build:**
- `foundry.toml` - Primary build configuration
  - Defines source directory: `src/`
  - Defines output directory: `out/`
  - Defines library paths: `lib/`
  - Lint exclusions: mixed-case-function, mixed-case-variable

**Compilation:**
- Solidity ^0.8.28 required for primary contracts
- Contracts compile to EVM bytecode deployable on Ethereum and EVM-compatible chains

## Platform Requirements

**Development:**
- Foundry installed (`forge` CLI)
- npm (Node.js) for package management and npm publishing
- jq for shell script JSON processing
- Bash shell environment

**Production:**
- Ethereum or EVM-compatible blockchain network
- Deployment via deployment scripts: `DeployCore.s.sol`, `DeployCoreWithCreateX.s.sol`, `DeployCoreWithStaging.s.sol`
- Optional: CreateX contract factory (deterministic deployment) at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`

---

*Stack analysis: 2026-03-09*
