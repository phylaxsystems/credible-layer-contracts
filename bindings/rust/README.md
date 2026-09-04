# Credible Layer contract bindings

Alloy Rust bindings for the versioned consumer interfaces maintained in
[`credible-layer-contracts`](https://github.com/phylaxsystems/credible-layer-contracts).

The crate version follows the repository's contract release version. Its ABI
snapshots are generated from the same canonical Solidity interfaces published
in the `@phylax-systems/credible-layer-contracts` npm package. Consume it
directly from this repository and pin an exact commit:

```toml
[dependencies]
credible-layer-contracts = { git = "https://github.com/phylaxsystems/credible-layer-contracts.git", rev = "<commit>" }
```

```rust
use credible_layer_contracts::state_oracle::v2::IStateOracleV2;
```

## Interface compatibility

Interface generations are independent from repository release versions. The
active generation may grow additively, but a breaking ABI change introduces a
new Solidity interface and Rust module. Superseded generations are frozen and
remain available so consumers can select the interface used by their deployment.

| Contract release | Solidity interface | Rust module |
| --- | --- | --- |
| `0.2.0` | `IStateOracleV1` | `state_oracle::v1` |
| `0.3.0` | `IStateOracleV2` | `state_oracle::v2` |

Do not edit files under `abi/` by hand. Run `./shell/create_artifacts.sh` from
the repository root and review the resulting ABI changes.
