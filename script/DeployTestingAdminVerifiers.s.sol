// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {StateOracle} from "../src/StateOracle.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {AdminVerifierAlwaysApprove} from "../src/verification/admin/AdminVerifierAlwaysApprove.sol";
import {AdminVerifierSuperAdmin} from "../src/verification/admin/AdminVerifierSuperAdmin.sol";
import {console2} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";
import {CreateXDeployer} from "./CreateXDeployer.s.sol";

contract DeployTestingAdminVerifiers is Script, CreateXDeployer {
    address stateOracle;
    address superAdmin;
    bool deploySuperAdminVerifierEnabled;
    bool deployAlwaysApproveVerifierEnabled;
    bool addToStateOracle;

    function setUp() public virtual {
        stateOracle = vm.envOr("TEST_STATE_ORACLE_ADDRESS", address(0));
        superAdmin = vm.envOr("TEST_ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS", address(0));
        deploySuperAdminVerifierEnabled = vm.envOr("DEPLOY_TEST_ADMIN_VERIFIER_SUPER_ADMIN", false);
        deployAlwaysApproveVerifierEnabled = vm.envOr("DEPLOY_TEST_ADMIN_VERIFIER_ALWAYS_APPROVE", false);
        addToStateOracle = vm.envOr("ADD_TEST_ADMIN_VERIFIERS_TO_STATE_ORACLE", false);
    }

    modifier broadcast() {
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() public broadcast {
        _run();
    }

    function deploySuperAdminVerifier(address _superAdmin) public broadcast returns (address) {
        return _deploySuperAdminVerifier(_superAdmin);
    }

    function deployAlwaysApproveAdminVerifier() public broadcast returns (address) {
        return _deployAlwaysApproveAdminVerifier();
    }

    function deployAndAddSuperAdminVerifier(address _stateOracle, address _superAdmin)
        public
        broadcast
        returns (address verifier)
    {
        verifier = _deploySuperAdminVerifier(_superAdmin);
        _addAdminVerifier(_stateOracle, verifier);
    }

    function deployAndAddAlwaysApproveAdminVerifier(address _stateOracle) public broadcast returns (address verifier) {
        verifier = _deployAlwaysApproveAdminVerifier();
        _addAdminVerifier(_stateOracle, verifier);
    }

    function addAdminVerifier(address _stateOracle, address verifier) public broadcast {
        _addAdminVerifier(_stateOracle, verifier);
    }

    function _run() internal returns (address[] memory deployments) {
        deployments = _deployEnabledAdminVerifiers();
        if (addToStateOracle) {
            _addAdminVerifiers(stateOracle, deployments);
        }
    }

    function _deployEnabledAdminVerifiers() internal returns (address[] memory deployments) {
        uint256 count;
        if (deploySuperAdminVerifierEnabled) count++;
        if (deployAlwaysApproveVerifierEnabled) count++;
        require(count > 0, "No test verifiers enabled");

        deployments = new address[](count);
        uint256 index;
        if (deploySuperAdminVerifierEnabled) {
            deployments[index++] = _deploySuperAdminVerifier(superAdmin);
        }
        if (deployAlwaysApproveVerifierEnabled) {
            deployments[index++] = _deployAlwaysApproveAdminVerifier();
        }
    }

    function _deploySuperAdminVerifier(address _superAdmin) internal virtual returns (address verifier) {
        require(_superAdmin != address(0), "Invalid super admin");
        verifier = _deployCreate3(
            SALT_ADMIN_VERIFIER_SUPER_ADMIN_NAME,
            abi.encodePacked(type(AdminVerifierSuperAdmin).creationCode, abi.encode(_superAdmin))
        );
        console2.log("Testing Admin Verifier (Super Admin) deployed at", verifier);
    }

    function _deployAlwaysApproveAdminVerifier() internal virtual returns (address verifier) {
        verifier =
            _deployCreate3(SALT_ADMIN_VERIFIER_ALWAYS_APPROVE_NAME, type(AdminVerifierAlwaysApprove).creationCode);
        console2.log("Testing Admin Verifier (Always Approve) deployed at", verifier);
    }

    function _addAdminVerifiers(address _stateOracle, address[] memory verifiers) internal {
        require(_stateOracle != address(0), "Invalid state oracle");
        for (uint256 i = 0; i < verifiers.length; i++) {
            _addAdminVerifier(_stateOracle, verifiers[i]);
        }
    }

    function _addAdminVerifier(address _stateOracle, address verifier) internal {
        require(_stateOracle != address(0), "Invalid state oracle");
        require(verifier != address(0), "Invalid admin verifier");
        StateOracle(_stateOracle).addAdminVerifier(IAdminVerifier(verifier));
        console2.log("Testing admin verifier added to StateOracle", verifier);
    }
}
