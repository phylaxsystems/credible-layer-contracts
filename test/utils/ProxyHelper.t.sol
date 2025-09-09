// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {ProxyAdmin} from "lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Upgrade} from "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Upgrade.sol";

import {Adopter} from "./Adopter.sol";

contract ProxyHelper is Test {
    address constant ADMIN = address(uint160(uint256(keccak256(abi.encode("pcl.test.PHYLAX_WINS")))));

    function deployProxy(address implementation, bytes memory data) internal returns (address proxy) {
        proxy = address(new TransparentUpgradeableProxy(implementation, ADMIN, data));
    }

    function getProxyAdmin(address proxy) internal view returns (address admin) {
        // Read admin slot from proxy storage
        // Use the actual storage slot value directly since _ADMIN_SLOT is internal
        bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        admin = address(uint160(uint256(vm.load(proxy, adminSlot))));
    }

    function test_isAdmin() public {
        address adopter = address(new Adopter());
        address proxy = address(new TransparentUpgradeableProxy(adopter, ADMIN, ""));

        assertEq(getProxyAdmin(proxy), ADMIN, "Should be ADMIN");
    }
}
