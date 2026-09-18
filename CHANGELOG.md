# Changelog

## 0.4.0

### Assertion resubmission

Previously, an assertion ID could only be added once for a given adopter.
Removed assertions can now be submitted again through `addAssertion` once
their previous deactivation block is reached
([#39](https://github.com/phylaxsystems/credible-layer-contracts/pull/39)).

- Re-add is allowed when `deactivationBlock != 0` and
  `block.number >= deactivationBlock`. Requesting removal alone is insufficient;
  re-add before that block still reverts with `AssertionAlreadyExists`.
- There is no additional cooldown after deactivation. Each re-add starts the
  normal activation timelock, so the assertion becomes active at the re-add
  block plus `ASSERTION_TIMELOCK_BLOCKS`.
- Every re-add checks manager authorization, the caller whitelist when enabled,
  the registered DA verifier, a valid DA proof, and the assertion limit again.
  An existing proof may be reused if the verifier still accepts it.
- Manager and guardian removals follow the same re-add rule. Re-add replaces
  the stored activation block, clears the old deactivation block to zero, and
  emits a new `AssertionAdded` event.

For example, with a 100-block timelock, removal at block 1,000 takes effect at
block 1,100. Re-add at block 1,099 fails; re-add at block 1,100 is allowed and
schedules activation for block 1,200.

### Compatibility and event consumers

- Resubmission preserves the existing assertion-window storage layout and
  public ABI; release `0.4.0` continues to use `IStateOracleV2`.
- `getAssertionWindow` returns only the latest lifecycle. Consumers needing
  earlier activation and removal history must retain or replay events.
- Indexers must handle repeated `AssertionAdded` events for the same adopter
  and assertion ID, clearing the previous deactivation when recording the new
  lifecycle.
- `hasAssertion` still reports whether an ID has ever been associated with an
  adopter, including after removal. Use the latest window and current block
  to determine lifecycle eligibility.

### Rust bindings

The first release containing the Alloy Rust bindings supports both the
historical `IStateOracleV1` interface and `IStateOracleV2`
([#38](https://github.com/phylaxsystems/credible-layer-contracts/pull/38)).
The Rust crate and npm package share version `0.4.0`; interface generations
remain independent of release versions.

### Deployment and compatibility tooling

- Added deterministic deployment workflows and an interactive deployment wizard
  ([#33](https://github.com/phylaxsystems/credible-layer-contracts/pull/33)).
- Added CI checks for published ABI compatibility and proxy storage layout
  ([#50](https://github.com/phylaxsystems/credible-layer-contracts/pull/50)).
