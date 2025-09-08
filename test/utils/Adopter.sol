// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

contract Adopter {}

contract OwnableAdopter {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }
}
