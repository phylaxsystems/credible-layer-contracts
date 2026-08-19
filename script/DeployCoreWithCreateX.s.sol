// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {AdminVerifierAlwaysApprove} from "../src/verification/admin/AdminVerifierAlwaysApprove.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {AdminVerifierWhitelist} from "../src/verification/admin/AdminVerifierWhitelist.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {DAVerifierOnChain} from "../src/verification/da/DAVerifierOnChain.sol";
import {CreateXDeployer} from "./CreateXDeployer.s.sol";
import {DeployCore} from "./DeployCore.s.sol";
import {console2} from "forge-std/console2.sol";

contract DeployCoreWithCreateX is DeployCore, CreateXDeployer {
    function _deployDAVerifierECDSA() internal override returns (address) {
        address daVerifier = _deployCreate3(
            SALT_DA_VERIFIER_ECDSA_NAME, abi.encodePacked(type(DAVerifierECDSA).creationCode, abi.encode(daProver))
        );
        console2.log("DA Verifier (ECDSA) deployed at", daVerifier);
        return daVerifier;
    }

    function _deployDAVerifierOnChain() internal override returns (address) {
        address daVerifierOnChain = _deployCreate3(SALT_DA_VERIFIER_ONCHAIN_NAME, type(DAVerifierOnChain).creationCode);
        console2.log("DA Verifier (OnChain) deployed at", daVerifierOnChain);
        return daVerifierOnChain;
    }

    function _deployOwnerAdminVerifier() internal override returns (address verifier) {
        verifier = _deployCreate3(SALT_ADMIN_VERIFIER_OWNER_NAME, type(AdminVerifierOwner).creationCode);
        console2.log("Admin Verifier (Owner) deployed at", verifier);
        return verifier;
    }

    function _deployWhitelistAdminVerifier() internal override returns (address verifier) {
        verifier = _deployCreate3(
            SALT_ADMIN_VERIFIER_WHITELIST_NAME,
            abi.encodePacked(type(AdminVerifierWhitelist).creationCode, abi.encode(whitelistAdmin))
        );
        console2.log("Admin Verifier (Whitelist) deployed at", verifier);
        return verifier;
    }

    function _deployAlwaysApproveAdminVerifier() internal override returns (address verifier) {
        verifier =
            _deployCreate3(SALT_ADMIN_VERIFIER_ALWAYS_APPROVE_NAME, type(AdminVerifierAlwaysApprove).creationCode);
        console2.log("Testing Admin Verifier (Always Approve) deployed at", verifier);
        return verifier;
    }

    function _deployStateOracle(uint256 assertionTimelockBlocks, string memory contractName)
        internal
        override
        returns (address)
    {
        address stateOracle = _deployStateOracleWithSalt(assertionTimelockBlocks, contractName, SALT_STATE_ORACLE_NAME);
        return stateOracle;
    }

    function _deployStateOracleWithSalt(
        uint256 assertionTimelockBlocks,
        string memory contractName,
        string memory saltName
    ) internal returns (address stateOracle) {
        stateOracle = _deployCreate3(
            saltName, abi.encodePacked(type(StateOracle).creationCode, abi.encode(assertionTimelockBlocks))
        );
        console2.log(string.concat(contractName, " Implementation deployed at"), stateOracle);
    }

    function _deployStateOracleProxy(
        address stateOracle,
        address[] memory adminVerifierDeployments,
        address[] memory daVerifierAddresses,
        uint16 maxAssertions
    ) internal override returns (address) {
        return _deployStateOracleProxyWithSalt(
            stateOracle,
            adminVerifierDeployments,
            daVerifierAddresses,
            maxAssertions,
            SALT_STATE_ORACLE_PROXY_NAME,
            "State Oracle"
        );
    }

    function _deployStateOracleProxyWithSalt(
        address stateOracle,
        address[] memory adminVerifierDeployments,
        address[] memory daVerifierAddresses,
        uint16 maxAssertions,
        string memory saltName,
        string memory contractName
    ) internal returns (address proxyAddress) {
        return _deployStateOracleProxyWithConfig(
            stateOracle,
            adminVerifierDeployments,
            daVerifierAddresses,
            maxAssertions,
            stateOracleWhitelistEnabled,
            new address[](0),
            saltName,
            contractName
        );
    }

    function _deployStateOracleProxyWithConfig(
        address stateOracle,
        address[] memory adminVerifierDeployments,
        address[] memory daVerifierAddresses,
        uint16 maxAssertions,
        bool whitelistEnabled,
        address[] memory initialWhitelist,
        string memory saltName,
        string memory contractName
    ) internal returns (address proxyAddress) {
        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](adminVerifierDeployments.length);
        for (uint256 i = 0; i < adminVerifierDeployments.length; i++) {
            adminVerifiers[i] = IAdminVerifier(adminVerifierDeployments[i]);
        }
        IDAVerifier[] memory daVfrs = new IDAVerifier[](daVerifierAddresses.length);
        for (uint256 i = 0; i < daVerifierAddresses.length; i++) {
            daVfrs[i] = IDAVerifier(daVerifierAddresses[i]);
        }
        bytes memory initCallData = abi.encodeCall(
            StateOracle.initializeWithWhitelist,
            (admin, adminVerifiers, daVfrs, maxAssertions, whitelistEnabled, initialWhitelist)
        );
        proxyAddress = _deployCreate3(
            saltName,
            abi.encodePacked(
                type(TransparentUpgradeableProxy).creationCode, abi.encode(address(stateOracle), admin, initCallData)
            )
        );
        console2.log(string.concat(contractName, " Proxy deployed at"), proxyAddress);
    }
}
