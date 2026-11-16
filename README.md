# Credible Layer Contracts

Smart contracts for the Credible Layer protocol, built with Foundry.

## Overview

The Credible Layer is a protocol that enables trustless and verifiable assertion execution
on smart contracts. This repository contains the core smart contracts that power the protocol.

### Components

```
                           +------------+------------+            +-------------------------+
###############            |                         |            |                         |
#             #            |                         |            |  Protocol               |
#    User     #----------->+      State Oracle       +----------->|  Admin                  |
#             #            |                         |            |  Verification           |
###############            |                         |            |                         |
                           +------------+------------+            +-------------------------+
                                        |
                                        |
                                        v
                           +------------+------------+
                           |                         |
                           |  Data Availability      |
                           |  Verification           |
                           |                         |
                           +-------------------------+
```

### The State Oracle

The state oracle coordinates protocol admins/managers and network operators.
Protocol admins attach assertions to their protocol by adding entries in the state oracle contract.
Network operators and/or block builders operate the assertion executor who adhere to the entries of
the contracts and enforce the validation of assertions.

#### State Oracle Behavior

- Each assertion adopter maintains a manager and a set of assertion windows, preserving the existing window storage layout and `getAssertionWindow` getter.
- A removed assertion ID can be added again at or after its previous deactivation block. There is no additional cooldown; re-add still requires the normal authorization, whitelist, DA verification, and capacity checks, followed by a new activation timelock.
- Activation and deactivation blocks are stored in the latest window and emitted in events for enforcement off-chain. Re-add replaces the window with a new activation block and zero deactivation; earlier lifecycle history remains in events.
- `hasAssertion` reports whether an ID has ever been associated with the adopter, including after removal. The assertion count increases on add and decreases on a removal request, rather than at the effective deactivation block.
- External admin verifiers (owner-based, whitelist) govern who may register new adopters.
- Managers select a registered DA verifier when adding each assertion, enabling per-assertion choice of data availability mechanism from a governance-managed registry.

### Protocol Admin Verification

The Protocol Admin Verification interface allows for methods to verify who the rightful admin
of a protocol is. This adapter acts as an oracle which verifies who has the administrative authority
over the protocol. It is needed for initial registration.

### Data Availability Verification

The Data Availability Verification interface ensures that the assertion bytecode is available.
Governance can register multiple DA verifiers in the DA verifier registry, and managers select
which registered verifier to use when adding each assertion. Two DA verifier implementations
are available:

- **`DAVerifierECDSA`**: Requires a signature over the assertion ID from a configured `DA_PROVER_ADDRESS`. When storing the assertion at the [Assertion DA](https://github.com/phylaxsystems/assertion-da), the user will receive the signature in return.
- **`DAVerifierOnChain`**: Validates that `keccak256(proof) == assertionId`, proving that the assertion bytecode is available on-chain through the proof data itself.

Typical data availability layers include network-hosted DA servers, decentralized DA networks, and the underlying network itself.

### State Oracle Administration

Administrative entrypoints now **schedule proposals**, rather than changing effective state immediately.
Each oracle's `StateOracleTimelock` starts with D = 3 days (259,200 seconds), with a hard 3-day floor.
Only that oracle proxy proposes/executes through it; it has no external administrator.

- Role grants, revocations and self-renunciation, ownership transfer/renunciation, admin/DA verifier registry changes, caller whitelist changes (including while disabled), and all assertion-cap changes wait D.
- Read the operation ID from `AdministrationScheduled`, then inspect its exact payload and `readyAt` with `administrationOperation(id)`. Anyone can relay `executeAdministration(id)` once ready. `isOperationReady` on the controller is not the same as `isOperationDone`; effective changes happen only on execution.
- Only one pending proposal per resource is allowed (for example, a role/account or whitelist account). Conflicting changes must wait for execution and then schedule a fresh delay. Cancellation is unavailable.
- Ownership nomination is visible immediately, but acceptance requires both execution of that nomination's delayed authorization and consent from the nominated account. Renouncing ownership is delayed too.
- `scheduleDelayUpdate` waits the current D. Only one D change may be pending per oracle, so queued increases/decreases cannot execute back-to-back under the old delay. Existing proposals keep their original deadlines.
- Guardian `revokeManager` is immediate and clears pending handovers. Re-registration waits until `registrationAvailableAt(adopter)`, which snapshots current D at revocation. Later D changes do not alter that deadline. Expiry does not install a manager; the caller must still pass whitelist and admin-verifier checks. Existing valid approvals remain usable without an extra serial wait.
- Assertion add/remove and `resetStorage` retain `ASSERTION_TIMELOCK_BLOCKS`, independently of D. Guardian assertion removal also retains this block delay. Revocation and re-registration preserve assertion windows and counts.
- Caller whitelist removal only blocks registration and additions; it does not prevent a manager removing assertions, transferring management or resetting storage. Lowering the cap, even to zero, preserves existing assertions and affects subsequent additions.

Existing proxies deploy their own controller through `initializeTimelockV2()` using Solady
`reinitializer(2)` in a ProxyAdmin `upgradeAndCall`. Only the actual proxy admin can invoke that migration.
Fresh deployments use the normal initializer to deploy their controller in the same transaction.
ProxyAdmin ownership handover and delayed upgrade wrappers are deferred to ENG-6421 at this layer.
Admin-verifier internal approval/ownership policy is unchanged (ENG-6426 is separate).
Legacy revocations have no stored timestamp, so migration does not invent a retroactive recovery
deadline for adopters that already had no manager.

Existing oracle proxy addresses, bytecode and ProxyAdmin remain unchanged: the upgrade replaces only
the implementation and runs the version-2 initializer through the existing ProxyAdmin. Deploy the new
implementation with the existing assertion block delay; it has no proxy-specific constructor bindings.
All nine existing storage fields (slots 0–7) and assertion structs remain exactly unchanged. The only
new oracle storage is its controller address in the ERC-7201 namespace
`phylax.storage.StateOracleAdministration`. Queue records and recovery deadlines stay in the controller;
ownership eligibility derives from its completed nomination operation. Setup also updates the existing
Solady initialization-version slot. Later implementation upgrades must retain the namespace and controller
history; rotating controllers is not part of this stack.

### Deployment

The deployment scripts (`script/DeployCore.s.sol`, `script/DeployCoreWithCreateX.s.sol`, and `script/DeployCoreWithStaging.s.sol`) provision the core protocol with both `DAVerifierECDSA` and `DAVerifierOnChain` implementations. Both DA verifiers are deployed and registered in the DA verifier registry during initialization, allowing managers to select either mechanism when adding assertions.

Fresh proxies call `initializeWithWhitelist(admin, adminVerifiers, daVerifiers, maxAssertions, whitelistEnabled, initialWhitelist)`
in their constructor, or the original four-argument `initialize` for an enabled, empty caller whitelist.
Both entrypoints use one setup path to initialize application state at version 2 and deploy the oracle's three-day administration
timelock. Existing version-1 proxies instead call `initializeTimelockV2()` through their existing ProxyAdmin's
`upgradeAndCall`; this preserves application state and rejects callers other than the upgrade admin and replay.
Both paths share the same timelock setup. No address prediction or legacy bootstrap deployment is needed.

The oracle deploys its controller with plain `new StateOracleTimelock(address(this))` and stores the address
in the ERC-7201 namespace `phylax.storage.StateOracleAdministration`. `timelock()` reads that reference;
future implementations must preserve the namespace. Existing sequential storage is unchanged.
Each oracle is its own controller's only proposer/executor. The 75/25-block assertion
lifecycle configuration remains independent of the timestamp-based administration delay.

Both original initializer signatures are preserved. Already initialized proxies cannot run either fresh
initializer; historical V1/V2 consumer interfaces are unchanged. The ABI check has no initializer exceptions.

### Environment Variables

Set the following environment variables before running the deployment scripts:

- `STATE_ORACLE_MAX_ASSERTIONS_PER_AA`
- `STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS`
- `STATE_ORACLE_ADMIN_ADDRESS`
- `DA_PROVER_ADDRESS`
- `DEPLOY_ADMIN_VERIFIER_OWNER` (true/false)
- `DEPLOY_ADMIN_VERIFIER_WHITELIST` (true/false)
- `ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS` (required when whitelist verifier is enabled)
- `STATE_ORACLE_WHITELIST_ENABLED` (optional, defaults to true)
- `DEPLOY_ADMIN_VERIFIER_ALWAYS_APPROVE` (optional, defaults to false; testing only)
- `DEPLOYMENT_IS_TESTING` (must be true when the Always Approve verifier is enabled)

The following additional variables apply only to `DeployCoreWithStaging.s.sol`:

- `STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA`
- `STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS`

### Deployment Overview

Running `DeployCore`, `DeployCoreWithCreateX`, or `DeployCoreWithStaging` will:

1. Deploy the DA verifier (ECDSA) and log its address.
2. Deploy the DA verifier (OnChain) and log its address.
3. Deploy `AdminVerifierOwner` if `DEPLOY_ADMIN_VERIFIER_OWNER=true` and log its address.
4. Deploy `AdminVerifierWhitelist` if `DEPLOY_ADMIN_VERIFIER_WHITELIST=true` (using `ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS` as constructor default admin and initial whitelist admin) and log its address.
5. Deploy `AdminVerifierAlwaysApprove` if `DEPLOY_ADMIN_VERIFIER_ALWAYS_APPROVE=true` and `DEPLOYMENT_IS_TESTING=true`, and log its address.
6. Deploy the `StateOracle` implementation and log its address.
7. Deploy the proxy, initialize it with the configured admin verifiers, DA verifiers, and initial whitelist state, and log the proxy address.

`DeployCoreWithStaging` repeats the last two steps for the staging oracle. It inherits the CreateX deployment path, so both State Oracle implementations, both proxies, both DA verifiers, and every selected admin verifier use named CREATE3 salts.

For a local testing deployment with registration whitelisting disabled and the Always Approve verifier enabled, combine the required values above with:

```sh
DEPLOYMENT_IS_TESTING=true \
STATE_ORACLE_WHITELIST_ENABLED=false \
DEPLOY_ADMIN_VERIFIER_OWNER=false \
DEPLOY_ADMIN_VERIFIER_WHITELIST=false \
DEPLOY_ADMIN_VERIFIER_ALWAYS_APPROVE=true \
forge script script/DeployCoreWithStaging.s.sol --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast
```

Console output will include labeled addresses for each deployed contract, e.g.:

```
DA Verifier (ECDSA) deployed at <address>
DA Verifier (OnChain) deployed at <address>
Admin Verifier (Owner) deployed at <address>
Admin Verifier (Whitelist) deployed at <address>
State Oracle Implementation deployed at <address>
State Oracle Proxy deployed at <address>
```

### Interactive deployment wizard

Run the terminal wizard from the repository root:

```sh
make deploy
```

The wizard uses the deterministic CreateX deployment backend and guides you through:

- production or testing mode, plus an optional staging State Oracle;
- admin verifier selection and assignment to the production and/or staging oracle;
- ECDSA and/or on-chain DA verification, independently assigned to each State Oracle;
- initial State Oracle whitelist state and addresses;
- optional explorer verification using `ETHERSCAN_API_KEY`;
- all State Oracle limits, timelocks, admins, and verifier-specific addresses; and
- a Foundry keystore account selected from `cast wallet list`.

The wallet password and explorer API key are read without echoing. The password is checked before
deployment and stored only in a temporary mode-`600` file that is removed when the wizard exits.
Before broadcasting, the wizard prints a redacted Forge command and a complete configuration
summary. After broadcasting, it reads Foundry's receipt file and prints every deployment address,
block number, transaction hash, and proxy admin address.

Testing mode also exposes the `Super Admin` and `Always Approve` admin verifiers. These options are
rejected by the Solidity deployment backend unless testing mode is explicitly enabled. Both testing
verifiers use named CREATE3 salts, as do every production and staging contract deployed by the wizard.
Every broadcast entrypoint in `DeployTestingAdminVerifiers.s.sol` likewise requires
`DEPLOYMENT_IS_TESTING=true`.

## Installation

See the [changelog](CHANGELOG.md) for release behavior and compatibility notes.

### Rust bindings

Versioned Alloy bindings for the StateOracle interfaces are maintained under
[`bindings/rust`](bindings/rust). They expose the historical `0.2.0` interface as
`credible_layer_contracts::state_oracle::v1::IStateOracleV1` and the interface
introduced in `0.3.0` as `credible_layer_contracts::state_oracle::v2::IStateOracleV2`.
The unreleased delayed-administration interface is `state_oracle::v3::IStateOracleV3`;
V1 and V2 remain unchanged for existing deployments.
Future breaking changes add another interface generation rather than replacing
an existing one. The committed ABI snapshots allow the Rust crate to compile
without installing Foundry.

### Solidity development

1. Clone the repository:

```bash
git clone https://github.com/phylax/credible-layer-contracts
cd credible-layer-contracts
```

2. Install dependencies:

```bash
forge install
```

### CreateX

The forge scripts `script/DeployCoreWithCreateX.s.sol`, `script/DeployCoreWithStaging.s.sol`, `script/DeployWizard.s.sol`, and `script/DeployTestingAdminVerifiers.s.sol` use the CreateX contract factory to maintain stable protocol contract addresses. CREATE3 derives each address from the deployer and a contract-specific salt, so transaction order, deployer nonce, and contract init code do not change it. Production and staging State Oracles use different salts; the testing-only SuperAdmin and AlwaysApprove verifiers also have distinct salts shared by the wizard and standalone testing script.

The fixed address must be empty when first deployed. On a retained chain, rerunning a salt whose contract already exists will revert; preserve the existing proxy and upgrade it for code changes, or reset the chain before performing a clean redeployment.
The deployment address of CreateX is `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`.
If CreateX is not deployed on your chain, you will find a helper script to deploy CreateX at
`shell/deploy_create_x.sh`.

Run

```sh
FUNDER_PRIVATE_KEY="0x..." \
RPC_URL="" \
./shell/deploy_create_x.sh
```

`Note: The funder account will send 0.5 ether to the deployer account of CreateX.`

For more information about CreateX see https://github.com/pcaversaccio/createx.

### Testing with Anvil

To deploy the protocol on an anvil instance run

````sh
anvil
cast rpc anvil_setBalance "0x8d63e0FE87CA36E06a076584fCA651A684D4c97d" "0xDE0B6B3A7640000" --rpc-url http://localhost:8545

FUNDER_PRIVATE_KEY="0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2" \

RPC_URL="http://localhost:8545" \
./shell/deploy_create_x.sh

STATE_ORACLE_MAX_ASSERTIONS_PER_AA=5 \
STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS=10 \
STATE_ORACLE_ADMIN_ADDRESS=0xD2EfB83dd46094775188d927323b2523EaE3d087 \
DA_PROVER_ADDRESS=0x670cFA8781BF365Aefb6c048CDc522B857946C71 \
DEPLOY_ADMIN_VERIFIER_OWNER=true \
DEPLOY_ADMIN_VERIFIER_WHITELIST=true \
STATE_ORACLE_WHITELIST_ENABLED=true \
ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS=0xD2EfB83dd46094775188d927323b2523EaE3d087 \
forge script script/DeployCoreWithCreateX.s.sol --rpc-url http://localhost:8545 --private-key 0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2 --broadcast
```

The contracts will be deployed at

```txt
== Logs ==
  DA Verifier (ECDSA) deployed at 0xE5b59c5AF181D522be5e721D83F8b0F69592A6b0
  DA Verifier (OnChain) deployed at 0x1234567890abcdef1234567890abcdef12345678
  Admin Verifier (Owner) deployed at 0x3e06372d794a48552203069915eA91b223297736
  Admin Verifier (Whitelist) deployed at 0xcaaC06Fc3826D47950aD28fA58bA8D986BBae0A4
  State Oracle Implementation deployed at 0x080f6B740F9CAC60BA17Adab3d763997EEdce1e7
  State Oracle Proxy deployed at 0x6dD3f12ce435f69DCeDA7e31605C02Bb5422597b
````

In this example the contracts are deployed by

```
// keccak256("credible-layer-sandbox-deployer")
Private Key: 0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2
Account: (0x8d63e0FE87CA36E06a076584fCA651A684D4c97d)
```

When broadcasting `script/DeployCoreWithCreateX.s.sol` with the above key, the contracts will always be
deployed at the same addresses on a clean chain. Neither init code nor nonce influences address generation.

## Compatibility Checks

Two snapshots guard the surfaces that break consumers silently. Both run on every pull request and
are reproducible locally.

| Check | Baseline | Verify | Refresh |
| --- | --- | --- | --- |
| Published ABI | base branch | `make check-abi` | not applicable |
| Storage layout | `.storage-layout` | `make check-storage-layout` | `make update-storage-layout` |

The ABI check compares the working tree against the same contracts at a base revision. Nothing is
committed for it: the published ABI is a release artifact, generated by `shell/create_artifacts.sh`
into a gitignored `artifacts/` and published on tag, so a second copy in the repository would only
duplicate it. The baseline is built in a temporary worktree and thrown away.

```sh
make check-abi                          # against origin/main
make check-abi ABI_BASE_REF=<ref>       # against any revision
```

It covers the contracts published by `shell/create_artifacts.sh`, plus `AdminVerifierWhitelist`,
whose signatures the dapp seed script calls by literal string. Entries are keyed by function
selector and event topic0, so reordering by the toolchain never causes a failure. A removed entry,
a changed parameter or return type, a changed `indexed` layout, or tightened state mutability fails
the check; new functions and events are reported as additive rather than breaking.

`make` reports any failed recipe as `Error 2`, so a purely additive change shows `Error 2` locally.
CI treats that case as a warning and lets the build pass. The script's own exit codes are
`0` unchanged, `1` additive, `2` breaking, `3` could not run.

One change is invisible to this check by construction: swapping two parameters of the same type, such
as the two `address` arguments of `addToWhitelist(address,address)`, leaves the canonical signature
and therefore the selector untouched. No selector-based comparison can detect it, so review argument
order by hand.
