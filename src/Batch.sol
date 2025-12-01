// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.8.22;

import {IBatch} from "./interfaces/IBatch.sol";

/// @title Batch
/// @notice See the documentation in {IBatch}.
/// @dev Forked from: https://github.com/sablier-labs/v2-core/blob/b88ead3d7dd483f7107d56320ca01e4122e00d92/src/abstracts/Batch.sol
abstract contract Batch is IBatch {
    /// @notice Thrown when an unexpected error occurs during a batch call.
    /// @param result The result of the failed batch call.
    error BatchError(bytes result);

    /// @inheritdoc IBatch
    /// @dev The `msg.value` should not be used on any method called in the batch.
    function batch(bytes[] calldata calls) external override {
        uint256 count = calls.length;

        for (uint256 i = 0; i < count; ++i) {
            (bool success, bytes memory result) = address(this).delegatecall(calls[i]);
            if (!success) {
                revert BatchError(result);
            }
        }
    }
}
