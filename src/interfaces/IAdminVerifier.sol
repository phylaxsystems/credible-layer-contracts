// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

interface IAdminVerifier {
    function verifyAdmin(address contractAddress, address requester, bytes calldata data)
        external
        view
        returns (bool);
}
