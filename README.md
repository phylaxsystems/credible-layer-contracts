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

- Each assertion adopter maintains a manager and a set of assertion windows.
- An assertion ID can be registered only once. If removed (inactive), it cannot be re-added—attempting to reuse the same ID will revert.
- Activation and deactivation blocks are enforced via the configured timelock.
- External admin verifiers (owner-based, whitelist) govern who may register new adopters.

### Protocol Admin Verification

The Protocol Admin Verification interface allows for methods to verify who the rightful admin
of a protocol is. This adapter acts as an oracle which verifies who has the administrative authority
over the protocol. It is needed for initial registration.

### Data Availability Verification

The Data Availability Verification interface ensures that the assertion bytecode is available.
Typical data availability layers are:

- Network hosted DA server
- Decentralized DA networks
- The underlying network itself

When adding assertions to a protocol, some form of proof might be needed to be passed with the call
to verify the availability of the assertion bytecode.
For example, the `DAVerifierECDSA` requires a signature over the assertion id from a configured
`DA_PROVER_ADDRESS`. When storing the assertion at the [Assertion DA](https://github.com/phylaxsystems/assertion-da),
the user will receive the signature in return.

### State Oracle Administration

The State Oracle owner retains privileged controls as a safety net for protocol operations:

- **Add or remove admin verifiers:** Adjust which verification modules are authorized to verify ownership of new assertion adopters.
- **Register or revoke managers:** Directly assign, revoke, or reset managers for assertion adopters when necessary.
- **Remove assertions:** Forcefully deactivate assertions if malicious or unwanted logic is introduced, or if a project requests emergency removal.

These controls are intended strictly for emergency response scenarios—such as attacks or lost manager keys—and should be exercised with operational safeguards to avoid disrupting legitimate protocol activity.

### Deployment

The deployment scripts (`script/DeployCore.s.sol` and `script/DeployCoreWithCreateX.s.sol`) provision the core protocol with the `DAVerifierECDSA` implementation. Any assertion onboarding performed against the resulting `StateOracle` will require a signature from `DA_PROVER_ADDRESS`.

### Environment Variables

Set the following environment variables before running the deployment scripts:

- `STATE_ORACLE_MAX_ASSERTIONS_PER_AA`
- `STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS`
- `STATE_ORACLE_ADMIN_ADDRESS`
- `DA_PROVER_ADDRESS`
- `DEPLOY_ADMIN_VERIFIER_OWNER` (true/false)
- `DEPLOY_ADMIN_VERIFIER_WHITELIST` (true/false)
- `ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS` (required when whitelist verifier is enabled)

### Deployment Overview

Running `DeployCore` or `DeployCoreWithCreateX` will:

1. Deploy the DA verifier (ECDSA) and log its address.
2. Deploy `AdminVerifierOwner` if `STATE_ORACLE_ADMIN_VERIFIER_OWNER=true` and log its address.
3. Deploy `AdminVerifierWhitelist` if `STATE_ORACLE_ADMIN_VERIFIER_WHITELIST=true` (using `ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS` as constructor owner) and log its address.
4. Deploy the `StateOracle` implementation and log its address.
5. Deploy the proxy, initialize it with the configured admin verifiers, and log the proxy address.

Console output will include labeled addresses for each deployed contract, e.g.:

```
DA Verifier deployed at <address>
Admin Verifier (Owner) deployed at <address>
Admin Verifier (Whitelist) deployed at <address>
State Oracle Implementation deployed at <address>
State Oracle Proxy deployed at <address>
```

## Installation

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

The forge script `script/DeployCoreWithCreateX` uses the CreateX contract factory for maintaining and controlling contract addresses
of the protocol.
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
ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS=0xD2EfB83dd46094775188d927323b2523EaE3d087 \
forge script script/DeployCoreWithCreateX.s.sol --rpc-url http://localhost:8545 --private-key 0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2 --broadcast
```

The contracts will be deployed at

```txt
== Logs ==
  DA Verifier deployed at 0xE5b59c5AF181D522be5e721D83F8b0F69592A6b0
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

When broadcasting `script/DeployCore.s.sol ` with the above key, the contracts will always be deployed
at the same address. Neither the initCode of the contracts nor the nonce influence the address generation.
