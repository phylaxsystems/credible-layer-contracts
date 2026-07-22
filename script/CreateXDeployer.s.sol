// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ICreateX, CREATE_X_ADDRESS} from "./ICreateX.sol";

abstract contract CreateXDeployer {
    string public constant SALT_DA_VERIFIER_ECDSA_NAME = "credible-layer-da-verifier-ecdsa";
    string public constant SALT_DA_VERIFIER_ONCHAIN_NAME = "credible-layer-da-verifier-onchain";
    string public constant SALT_ADMIN_VERIFIER_OWNER_NAME = "credible-layer-admin-verifier-owner";
    string public constant SALT_ADMIN_VERIFIER_WHITELIST_NAME = "credible-layer-admin-verifier-whitelist";
    string public constant SALT_ADMIN_VERIFIER_SUPER_ADMIN_NAME = "credible-layer-admin-verifier-super-admin";
    string public constant SALT_ADMIN_VERIFIER_ALWAYS_APPROVE_NAME = "credible-layer-admin-verifier-always-approve";
    string public constant SALT_STATE_ORACLE_NAME = "credible-layer-state-oracle-implementation";
    string public constant SALT_STATE_ORACLE_PROXY_NAME = "credible-layer-state-oracle-proxy";
    string public constant SALT_STAGING_STATE_ORACLE_NAME = "credible-layer-staging-state-oracle-implementation";
    string public constant SALT_STAGING_STATE_ORACLE_PROXY_NAME = "credible-layer-staging-state-oracle-proxy";

    ICreateX internal constant CREATE_X = ICreateX(CREATE_X_ADDRESS);

    function _deployCreate3(string memory name, bytes memory initCode) internal returns (address) {
        bytes32 salt = _generateCreateXSalt(msg.sender, name);
        return CREATE_X.deployCreate3(salt, initCode);
    }

    // Set salt with frontrunning protection, i.e. first 20 bytes = deployer;
    // 0 byte to switch off cross-chain redeploy protection; 11 bytes salt
    // Details: https://github.com/pcaversaccio/createx#permissioned-deploy-protection-and-cross-chain-redeploy-protection
    function _generateCreateXSalt(address sender, string memory name) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(sender, hex"00", bytes11(keccak256(bytes(name)))));
    }
}
