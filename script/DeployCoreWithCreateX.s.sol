// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";
import {AdminVerifierWhitelist} from "../src/verification/admin/AdminVerifierWhitelist.sol";
import {DAVerifierECDSA} from "../src/verification/da/DAVerifierECDSA.sol";
import {ICreateX, CREATE_X_ADDRESS} from "./ICreateX.sol";
import {DeployCore} from "./DeployCore.s.sol";
import {console2} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";
import {CREATE3} from "solady/utils/CREATE3.sol";

contract DeployCoreWithCreateX is DeployCore {
    string public constant SALT_DA_VERIFIER_NAME = "credible-layer-da-verifier-ecdsa";
    string public constant SALT_ADMIN_VERIFIER_OWNER_NAME = "credible-layer-admin-verifier-owner";
    string public constant SALT_ADMIN_VERIFIER_WHITELIST_NAME = "credible-layer-admin-verifier-whitelist";
    string public constant SALT_STATE_ORACLE_NAME = "credible-layer-state-oracle-implementation";
    string public constant SALT_STATE_ORACLE_PROXY_NAME = "credible-layer-state-oracle-proxy";

    ICreateX internal constant CREATE_X = ICreateX(CREATE_X_ADDRESS);

    function _deployDAVerifier() internal override returns (address) {
        address daVerifier = deployCreate3(
            SALT_DA_VERIFIER_NAME, abi.encodePacked(type(DAVerifierECDSA).creationCode, abi.encode(daProver))
        );
        console2.log("DA Verifier deployed at", daVerifier);
        return daVerifier;
    }

    function _deployOwnerAdminVerifier() internal override returns (address verifier) {
        verifier = deployCreate3(SALT_ADMIN_VERIFIER_OWNER_NAME, type(AdminVerifierOwner).creationCode);
        console2.log("Admin Verifier (Owner) deployed at", verifier);
        return verifier;
    }

    function _deployWhitelistAdminVerifier() internal override returns (address verifier) {
        verifier = deployCreate3(
            SALT_ADMIN_VERIFIER_WHITELIST_NAME,
            abi.encodePacked(type(AdminVerifierWhitelist).creationCode, abi.encode(whitelistAdmin))
        );
        console2.log("Admin Verifier (Whitelist) deployed at", verifier);
        return verifier;
    }

    function _deployStateOracle(address daVerifier) public override returns (address) {
        address stateOracle = deployCreate3(
            SALT_STATE_ORACLE_NAME,
            abi.encodePacked(
                type(StateOracle).creationCode, abi.encode(assertionTimelockBlocks, daVerifier, maxAssertionsPerAA)
            )
        );
        console2.log("State Oracle Implementation deployed at", stateOracle);
        return stateOracle;
    }

    function _deployStateOracleProxy(address stateOracle, address[] memory adminVerifierDeployments)
        public
        virtual
        override
        returns (address)
    {
        IAdminVerifier[] memory adminVerifiers = new IAdminVerifier[](adminVerifierDeployments.length);
        for (uint256 i = 0; i < adminVerifierDeployments.length; i++) {
            adminVerifiers[i] = IAdminVerifier(adminVerifierDeployments[i]);
        }
        bytes memory initCallData = abi.encodeWithSelector(StateOracle.initialize.selector, admin, adminVerifiers);
        address proxyAddress = deployCreate3(
            SALT_STATE_ORACLE_PROXY_NAME,
            abi.encodePacked(
                type(TransparentUpgradeableProxy).creationCode, abi.encode(address(stateOracle), admin, initCallData)
            )
        );
        console2.log("State Oracle Proxy deployed at", proxyAddress);
        return proxyAddress;
    }

    function deployCreate3(string memory name, bytes memory initCode) private returns (address) {
        bytes32 salt = generateCreateXSalt(msg.sender, name);
        return CREATE_X.deployCreate3(salt, initCode);
    }

    // Set salt with frontrunning protection, i.e. first 20 bytes = deployer;
    // 0 byte to switch off cross-chain redeploy protection; 11 bytes salt
    // Details: https://github.com/pcaversaccio/createx#permissioned-deploy-protection-and-cross-chain-redeploy-protection
    function generateCreateXSalt(address sender, string memory name) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(sender, hex"00", bytes11(keccak256(bytes(name)))));
    }
}
