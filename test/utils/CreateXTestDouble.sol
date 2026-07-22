// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

contract CreateXTestDouble {
    bytes internal constant CREATE3_PROXY_INITCODE = hex"67363d3d37363d34f03d5260086018f3";

    address[] public deployments;

    function deploymentCount() external view returns (uint256) {
        return deployments.length;
    }

    function deployCreate3(bytes32 salt, bytes memory initCode) external returns (address deployed) {
        require(salt[20] == bytes1(0), "cross-chain protection must be disabled");

        // The CreateX salt format intentionally stores an address in its first 20 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 guardedSalt = address(bytes20(salt)) == msg.sender
            ? keccak256(abi.encode(bytes32(uint256(uint160(msg.sender))), salt))
            : keccak256(abi.encode(salt));
        bytes memory proxyInitCode = CREATE3_PROXY_INITCODE;
        address proxy;
        assembly ("memory-safe") {
            proxy := create2(0, add(proxyInitCode, 32), mload(proxyInitCode), guardedSalt)
        }
        require(proxy != address(0), "CREATE3 proxy deployment failed");

        deployed = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
        (bool success,) = proxy.call(initCode);
        require(success && deployed.code.length != 0, "CREATE3 deployment failed");
        deployments.push(deployed);
    }
}
