// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCoreV2} from "../script/DeployCoreV2.s.sol";

contract DeployCoreV2Harness is DeployCoreV2 {
    function validEventTiming(uint256 timelockBlocks, uint256 confirmationDepth) external pure returns (bool) {
        return _validEventTiming(timelockBlocks, confirmationDepth);
    }
}

contract DeployCoreV2Test {
    function test_confirmationDepthLeavesProcessingBlock() public {
        assert(new DeployCoreV2Harness().validEventTiming(66, 64));
    }

    function test_rejectsConfirmationDepthWithoutProcessingBlock() public {
        assert(!new DeployCoreV2Harness().validEventTiming(65, 64));
    }
}
