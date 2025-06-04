// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {Adopter} from "./Adopter.sol";

contract ProxyHelper is Test {
    address constant ADMIN = address(uint160(uint256(keccak256(abi.encode("pcl.test.PHYLAX_WINS")))));

    function deployProxy(address implementation, bytes memory data) internal returns (address proxy) {
        proxy = address(new TransparentUpgradeableProxy(implementation, ADMIN, data));
    }

    function getProxyAdmin(address proxy) internal view returns (address admin) {
        // Read admin slot from proxy storage
        admin = address(uint160(uint256(vm.load(proxy, ERC1967Utils.ADMIN_SLOT))));
    }

    function test_isAdmin() public {
        address adopter = address(new Adopter());
        address proxy = address(new TransparentUpgradeableProxy(adopter, ADMIN, ""));

        assertEq(ProxyAdmin(getProxyAdmin(proxy)).owner(), ADMIN, "Should be ADMIN");
    }
}
