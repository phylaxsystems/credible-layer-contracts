// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IDAVerifier} from "../../src/interfaces/IDAVerifier.sol";

contract DAVerifierMock is IDAVerifier {
    function verifyDA(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
