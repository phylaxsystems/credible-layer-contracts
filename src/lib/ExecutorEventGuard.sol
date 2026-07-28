// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/// @notice Limits executor-consumed events to one event per store type and transaction.
library ExecutorEventGuard {
    bytes32 private constant GUARD_SLOT = keccak256("credible-layer.executor-event-guard.v1");

    enum StoreType {
        AssertionLifecycle,
        StorageReset
    }

    error ExecutorEventAlreadyEmitted(StoreType storeType);

    function consume(StoreType storeType) internal {
        bytes32 slot = GUARD_SLOT;
        uint256 consumedStoreTypes;
        assembly ("memory-safe") {
            consumedStoreTypes := tload(slot)
        }

        uint256 storeTypeBit = 2 ** uint256(storeType);
        require(consumedStoreTypes & storeTypeBit == 0, ExecutorEventAlreadyEmitted(storeType));

        assembly ("memory-safe") {
            tstore(slot, or(consumedStoreTypes, storeTypeBit))
        }
    }
}
