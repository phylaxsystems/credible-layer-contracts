// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {console2} from "forge-std/console2.sol";

import {StateOracleV2} from "../src/StateOracleV2.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {ITriggerManifestValidator} from "../src/interfaces/ITriggerManifestValidator.sol";
import {TriggerManifestValidatorV1} from "../src/verification/TriggerManifestValidatorV1.sol";
import {DeployCore} from "./DeployCore.s.sol";

/// @notice Production-only fresh deployment for StateOracleV2.
contract DeployCoreV2 is DeployCore {
    uint256 internal eventConfirmationDepth;
    address internal manifestAttestor;

    function setUp() public override {
        assertionTimelockBlocks = vm.envUint("STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS");
        eventConfirmationDepth = vm.envUint("STATE_ORACLE_EVENT_CONFIRMATION_DEPTH");
        admin = vm.envAddress("STATE_ORACLE_ADMIN_ADDRESS");
        daProver = vm.envAddress("DA_PROVER_ADDRESS");
        deployOwnerVerifier = vm.envBool("DEPLOY_ADMIN_VERIFIER_OWNER");
        deployWhitelistVerifier = vm.envBool("DEPLOY_ADMIN_VERIFIER_WHITELIST");
        whitelistAdmin = vm.envOr("ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS", address(0));
        manifestAttestor = vm.envAddress("TRIGGER_MANIFEST_ATTESTOR_ADDRESS");

        assert(daProver != address(0));
        assert(admin != address(0));
        assert(manifestAttestor != address(0));
        assert(assertionTimelockBlocks > 0);
        assert(_validEventTiming(assertionTimelockBlocks, eventConfirmationDepth));
        assert(deployWhitelistVerifier && whitelistAdmin != address(0) || !deployWhitelistVerifier);
    }

    function _validEventTiming(uint256 timelockBlocks, uint256 confirmationDepth) internal pure returns (bool) {
        return confirmationDepth != 0 && confirmationDepth < type(uint256).max && confirmationDepth + 1 < timelockBlocks;
    }

    function run() public override broadcast {
        _fundPersistentAccounts();
        address[] memory adminVerifierAddresses = _deployAdminVerifiers();
        address[] memory daVerifierAddresses = new address[](2);
        daVerifierAddresses[0] = _deployDAVerifierECDSA();
        daVerifierAddresses[1] = _deployDAVerifierOnChain();

        TriggerManifestValidatorV1 validator = new TriggerManifestValidatorV1(admin, manifestAttestor);
        StateOracleV2 implementation = new StateOracleV2(assertionTimelockBlocks);

        IAdminVerifier[] memory adminVfrs = new IAdminVerifier[](adminVerifierAddresses.length);
        for (uint256 i; i < adminVerifierAddresses.length; ++i) {
            adminVfrs[i] = IAdminVerifier(adminVerifierAddresses[i]);
        }
        IDAVerifier[] memory daVfrs = new IDAVerifier[](daVerifierAddresses.length);
        for (uint256 i; i < daVerifierAddresses.length; ++i) {
            daVfrs[i] = IDAVerifier(daVerifierAddresses[i]);
        }

        bytes memory initData = abi.encodeCall(
            StateOracleV2.initialize,
            (admin, adminVfrs, daVfrs, validator.SCHEMA_ID(), ITriggerManifestValidator(address(validator)))
        );
        address proxy = address(new TransparentUpgradeableProxy(address(implementation), admin, initData));

        console2.log("Trigger Manifest Validator V1 deployed at", address(validator));
        console2.log("State Oracle V2 Implementation deployed at", address(implementation));
        console2.log("State Oracle V2 Proxy deployed at", proxy);
    }
}
