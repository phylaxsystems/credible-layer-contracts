# Credible Layer contract bindings

Alloy Rust bindings for the production contracts maintained in
[`credible-layer-contracts`](https://github.com/phylaxsystems/credible-layer-contracts).

The crate version follows the repository's contract release version. Its ABI
snapshot is generated from the same Foundry artifact that is published in the
`@phylax-systems/credible-layer-contracts` npm package.

```bash
cargo add credible-layer-contracts
```

```rust
use credible_layer_contracts::StateOracle;
```

Do not edit `abi/StateOracle.json` by hand. Run `./shell/create_artifacts.sh`
from the repository root and review the resulting ABI change.

Maintainers should follow [`RELEASING.md`](RELEASING.md) for the one-time
crates.io bootstrap and subsequent tagged releases.
