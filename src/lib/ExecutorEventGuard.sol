// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/// @notice Limits executor-consumed events to one event per `(storeType, adopter, key)` tuple and transaction.
library ExecutorEventGuard {
    bytes32 private constant GUARD_SLOT = keccak256("credible-layer.executor-event-guard.v1");

    enum StoreType {
        AssertionLifecycle,
        StorageReset
    }

    error ExecutorEventAlreadyEmitted(StoreType storeType);

    function consume(StoreType storeType, address assertionAdopter, bytes32 key) internal {
        bytes32 slot = keccak256(abi.encode(GUARD_SLOT, storeType, assertionAdopter, key));
        uint256 consumed;
        assembly ("memory-safe") {
            consumed := tload(slot)
        }

        require(consumed == 0, ExecutorEventAlreadyEmitted(storeType));

        assembly ("memory-safe") {
            tstore(slot, 1)
        }
    }
}
