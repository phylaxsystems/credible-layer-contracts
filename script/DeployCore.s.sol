// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {console2} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";
import {AdminVerifierWhitelist} from "../src/verification/admin/AdminVerifierWhitelist.sol";
import {AdminVerifierSuperAdmin} from "../src/verification/admin/AdminVerifierSuperAdmin.sol";

contract DeployCore is Script {
    address admin;
    uint128 assertionTimelockBlocks;
    uint16 maxAssertionsPerAA;
    address daProver;
    bool deployOwnerVerifier;
    bool deployWhitelistVerifier;
    bool deploySuperAdminVerifier;
    address whitelistAdmin;
    address superAdmin;

    function setUp() public {
        maxAssertionsPerAA = uint16(vm.envUint("STATE_ORACLE_MAX_ASSERTIONS_PER_AA"));
        assertionTimelockBlocks = uint128(vm.envUint("STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS"));
        admin = vm.envAddress("STATE_ORACLE_ADMIN_ADDRESS");
        daProver = vm.envAddress("DA_PROVER_ADDRESS");
        deployOwnerVerifier = vm.envOr("DEPLOY_ADMIN_VERIFIER_OWNER", false);
        deployWhitelistVerifier = vm.envOr("DEPLOY_ADMIN_VERIFIER_WHITELIST", false);
        whitelistAdmin = vm.envOr("ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS", address(0));
        deploySuperAdminVerifier = vm.envOr("DEPLOY_ADMIN_VERIFIER_SUPER_ADMIN", false);
        superAdmin = vm.envOr("ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS", address(0));

        assert(daProver != address(0));
        assert(assertionTimelockBlocks > 0);
        assert(admin != address(0));
        assert(deployWhitelistVerifier && whitelistAdmin != address(0) || !deployWhitelistVerifier);
        assert(deploySuperAdminVerifier && superAdmin != address(0) || !deploySuperAdminVerifier);
    }

    modifier broadcast() {
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() public broadcast {
        // Deploy DA Verifier (ECDSA)
        address daVerifier = _deployDAVerifier();
        // Deploy Admin Verifier (Owner)
        address[] memory adminVerifierDeployments = _deployAdminVerifiers();
        // Deploy State Oracle
        address stateOracle = _deployStateOracle(daVerifier);
        // Deploy State Oracle Proxy
        _deployStateOracleProxy(stateOracle, adminVerifierDeployments);
    }

    function deployDAVerifier() public broadcast {
        _deployDAVerifier();
    }

    function deployAdminVerifiers() public broadcast {
        _deployAdminVerifiers();
    }

    function deployStateOracle(address daVerifier) public broadcast {
        _deployStateOracle(daVerifier);
    }

    function deployStateOracleProxy(address stateOracle, address[] memory adminVerifierDeployments) public broadcast {
        _deployStateOracleProxy(stateOracle, adminVerifierDeployments);
    }

    function deployOwnerAdminVerifier() public broadcast {
        _deployOwnerAdminVerifier();
    }

    function deployWhitelistAdminVerifier() public broadcast {
        _deployWhitelistAdminVerifier();
    }

    function deploySuperAdminAdminVerifier() public broadcast {
        _deploySuperAdminAdminVerifier();
    }

    function _deployDAVerifier() internal virtual returns (address) {
        address daVerifier = address(new DAVerifierECDSA(daProver));
        console2.log("DA Verifier deployed at", daVerifier);
        return daVerifier;
    }

    function _deployAdminVerifiers() internal virtual returns (address[] memory deployments) {
        uint256 count;
        if (deployOwnerVerifier) count++;
        if (deployWhitelistVerifier) count++;
        deployments = new address[](count);
        uint256 index;
        if (deployOwnerVerifier) {
            deployments[index++] = _deployOwnerAdminVerifier();
        }
        if (deployWhitelistVerifier) {
            deployments[index] = _deployWhitelistAdminVerifier();
        }
    }

    function _deployStateOracle(address daVerifier) public virtual returns (address) {
        address stateOracle = address(new StateOracle(assertionTimelockBlocks, daVerifier));
        console2.log("State Oracle Implementation deployed at", stateOracle);
        return stateOracle;
    }

    function _deployStateOracleProxy(address stateOracle, address[] memory adminVerifierDeployments)
        public
        virtual
        returns (address)
    {
        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](adminVerifierDeployments.length);
        for (uint256 i = 0; i < adminVerifierDeployments.length; i++) {
            adminVerifiers[i] = IAdminVerifier(adminVerifierDeployments[i]);
        }
        bytes memory initCallData =
            abi.encodeWithSelector(StateOracle.initialize.selector, admin, adminVerifiers, maxAssertionsPerAA);
        address proxyAddress = address(new TransparentUpgradeableProxy(address(stateOracle), admin, initCallData));
        console2.log("State Oracle Proxy deployed at", proxyAddress);
        return proxyAddress;
    }

    function _deployOwnerAdminVerifier() internal virtual returns (address verifier) {
        verifier = address(new AdminVerifierOwner());
        console2.log("Admin Verifier (Owner) deployed at", verifier);
        return verifier;
    }

    function _deployWhitelistAdminVerifier() internal virtual returns (address verifier) {
        verifier = address(new AdminVerifierWhitelist(whitelistAdmin));
        console2.log("Admin Verifier (Whitelist) deployed at", verifier);
        return verifier;
    }

    function _deploySuperAdminAdminVerifier() internal virtual returns (address verifier) {
        verifier = address(new AdminVerifierSuperAdmin(superAdmin));
        console2.log("Admin Verifier (Super Admin) deployed at", verifier);
        return verifier;
    }
}
