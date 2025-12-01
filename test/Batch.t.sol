// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Batch} from "../src/Batch.sol";

contract BatchHarness is Batch {
    uint256 private _value;

    error HarnessError();

    function increment(uint256 amount) external {
        _value += amount;
    }

    function value() external view returns (uint256) {
        return _value;
    }

    function revertWithError() external pure {
        revert HarnessError();
    }
}

contract BatchTest is Test {
    BatchHarness internal harness;

    function setUp() public {
        harness = new BatchHarness();
    }

    function test_batchExecutesAllCalls() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(BatchHarness.increment, 2);
        calls[1] = abi.encodeCall(BatchHarness.increment, 3);

        harness.batch(calls);

        assertEq(harness.value(), 5);
    }

    function test_batchRevertsWhenInnerCallFails() public {
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(BatchHarness.revertWithError, ());

        bytes memory innerRevert = abi.encodeWithSelector(BatchHarness.HarnessError.selector);
        bytes memory expectedRevert = abi.encodeWithSelector(Batch.BatchError.selector, innerRevert);

        vm.expectRevert(expectedRevert);
        harness.batch(calls);
    }

    function test_batchIsNotPayable() public {
        bytes[] memory calls = new bytes[](0);

        vm.deal(address(this), 1 ether);
        (bool success, bytes memory returndata) =
            address(harness).call{value: 1}(abi.encodeWithSelector(Batch.batch.selector, calls));

        assertFalse(success, "call should fail when sending value");
        assertEq(returndata.length, 0, "non-payable call should not return data");
    }
}

