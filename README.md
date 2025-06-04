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

## Deployment

The current deployment script [scripts/DeployCore.s.sol](./scripts/DeployCore.s.sol) deploys the
core contracts with a DAVerifierECDSA implementation. This means adding assertions require the
signature of the `DA_PROVER_ADDRESS`.

1. Set up environment variables in `.env`:

```bash
# Required for deployment
DA_PROVER_ADDRESS="0x..."                       # Address of the DA prover
STATE_ORACLE_MAX_ASSERTIONS_PER_AA="100"        # Maximum number of assertions per Assertion Adopter
STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS="100"    # Delay in number of blocks until the assertion becomes enforced/will not be enforced anymore
STATE_ORACLE_PROXY_ADMIN_ADDRESS="0x..."        # Required if DEPLOY_PROXY is true
```

2. Deploy the contracts:

```bash
# Deploy to testnet
forge script script/DeployCore.s.sol --broadcast # Add flags for rpc url and wallet options

```

The deployment script will:

1. Deploy the `DAVerifierECDSA` contract with the specified prover address
2. Deploy the `AdminVerifierOwner` contract
3. Deploy the `StateOracle` contract implementation with the configured timelock and max assertions
4. Deploy a `TransparentUpgradableProxy` and initialize it with the necessary values

### CreateX

The forge script uses the CreateX contract factory for maintaining and controlling contract addresses
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

```sh
anvil
cast rpc anvil_setBalance "0x8d63e0FE87CA36E06a076584fCA651A684D4c97d" "0xDE0B6B3A7640000" --rpc-url http://localhost:8545
FUNDER_PRIVATE_KEY="0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2" \
RPC_URL="http://localhost:8545" \
./shell/deploy_create_x.sh

forge script script/DeployCore.s.sol --private-key 0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2 --rpc-url http://localhost:8545 --broadcast
```

The contracts will be deployed at

```txt
== Logs ==
  DA Verifier:          0xE5b59c5AF181D522be5e721D83F8b0F69592A6b0
  Admin Verifier:       0x3e06372d794a48552203069915eA91b223297736
  State Oracle:         0x080f6B740F9CAC60BA17Adab3d763997EEdce1e7
  State Oracle Proxy:   0x6dD3f12ce435f69DCeDA7e31605C02Bb5422597b
```

In this example the contracts are deployed by

```
// keccak256("credible-layer-sandbox-deployer")
Private Key: 0xac431098061ca49f5b36121d01a17d30e1d0624227d08b583ff328f1efe0d4a2
Account: (0x8d63e0FE87CA36E06a076584fCA651A684D4c97d)
```

When broadcasting `script/DeployCore.s.sol ` with the above key, the contracts will always be deployed
at the same address. Neither the initCode of the contracts nor the nonce influence the address generation.
