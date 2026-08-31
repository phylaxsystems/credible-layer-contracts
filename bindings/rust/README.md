# Credible Layer contract bindings

Alloy Rust bindings for the versioned consumer interfaces maintained in
[`credible-layer-contracts`](https://github.com/phylaxsystems/credible-layer-contracts).

The crate version follows the repository's contract release version. Its ABI
snapshots are generated from the same canonical Solidity interfaces published
in the `@phylax-systems/credible-layer-contracts` npm package.

```bash
cargo add credible-layer-contracts
```

```rust
use credible_layer_contracts::state_oracle::v1::IStateOracleV1;
```

## Interface compatibility

Interface generations are independent from repository release versions. An
existing generation may grow additively, but a breaking ABI change introduces
a new Solidity interface and Rust module. Published generations remain
available so consumers can select the interface used by their deployment.

| First release | Solidity interface | Rust module |
| --- | --- | --- |
| `0.3.0` | `IStateOracleV1` | `state_oracle::v1` |

Do not edit files under `abi/` by hand. Run `./shell/create_artifacts.sh` from
the repository root and review the resulting ABI changes.

Maintainers should follow [`RELEASING.md`](RELEASING.md) for the one-time
crates.io bootstrap and subsequent tagged releases.
