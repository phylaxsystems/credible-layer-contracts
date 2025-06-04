// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAdminVerifier} from "../../interfaces/IAdminVerifier.sol";

contract AdminVerifierOwner is IAdminVerifier {
    function verifyAdmin(address contractAddress, address requester, bytes calldata) external view returns (bool) {
        (bool success, bytes memory returnValue) = contractAddress.staticcall(abi.encodeWithSignature("owner()"));
        if (!success || returnValue.length != 32) return false;
        return abi.decode(returnValue, (address)) == requester;
    }
}
