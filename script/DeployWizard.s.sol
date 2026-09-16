// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {DeployCoreWithCreateX} from "./DeployCoreWithCreateX.s.sol";
import {AdminVerifierSuperAdmin} from "../src/verification/admin/AdminVerifierSuperAdmin.sol";
import {console2} from "forge-std/console2.sol";

/// @notice Deployment backend for shell/deploy_wizard.sh.
/// @dev The wizard adds per-oracle verifier selection and initial whitelist
/// configuration to the deterministic CreateX deployment primitives.
contract DeployWizard is DeployCoreWithCreateX {
    struct VerifierDeployments {
        address daECDSA;
        address daOnChain;
        address adminOwner;
        address adminWhitelist;
        address adminSuperAdmin;
        address adminAlwaysApprove;
    }

    bool internal deployStaging;

    bool internal daECDSAProduction;
    bool internal daECDSAStaging;
    bool internal daOnChainProduction;
    bool internal daOnChainStaging;

    bool internal adminOwnerProduction;
    bool internal adminOwnerStaging;
    bool internal adminWhitelistProduction;
    bool internal adminWhitelistStaging;
    bool internal adminSuperAdminProduction;
    bool internal adminSuperAdminStaging;
    bool internal adminAlwaysApproveProduction;
    bool internal adminAlwaysApproveStaging;

    uint256 internal stagingAssertionTimelockBlocks;
    uint16 internal stagingMaxAssertionsPerAA;
    address internal testSuperAdmin;
    address[] internal initialWhitelist;

    function setUp() public override {
        testingDeployment = vm.envOr("DEPLOYMENT_IS_TESTING", false);
        deployStaging = vm.envOr("DEPLOY_STAGING_STATE_ORACLE", false);
        stateOracleWhitelistEnabled = vm.envOr("STATE_ORACLE_WHITELIST_ENABLED", true);

        admin = vm.envAddress("STATE_ORACLE_ADMIN_ADDRESS");
        require(admin != address(0), "Invalid State Oracle admin");

        uint256 rawMaxAssertions = vm.envUint("STATE_ORACLE_MAX_ASSERTIONS_PER_AA");
        require(rawMaxAssertions > 0 && rawMaxAssertions <= type(uint16).max, "Invalid max assertions");
        // The bounds check above makes this narrowing conversion safe.
        // forge-lint: disable-next-line(unsafe-typecast)
        maxAssertionsPerAA = uint16(rawMaxAssertions);

        uint256 rawTimelock = vm.envUint("STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS");
        require(rawTimelock > 0, "Invalid assertion timelock");
        assertionTimelockBlocks = rawTimelock;

        if (deployStaging) {
            uint256 rawStagingMaxAssertions = vm.envUint("STAGING_STATE_ORACLE_MAX_ASSERTIONS_PER_AA");
            require(
                rawStagingMaxAssertions > 0 && rawStagingMaxAssertions <= type(uint16).max,
                "Invalid staging max assertions"
            );
            // The bounds check above makes this narrowing conversion safe.
            // forge-lint: disable-next-line(unsafe-typecast)
            stagingMaxAssertionsPerAA = uint16(rawStagingMaxAssertions);

            uint256 rawStagingTimelock = vm.envUint("STAGING_STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS");
            require(rawStagingTimelock > 0, "Invalid staging assertion timelock");
            stagingAssertionTimelockBlocks = rawStagingTimelock;
        }

        _loadVerifierConfiguration();

        initialWhitelist = vm.envOr("STATE_ORACLE_INITIAL_WHITELIST", ",", new address[](0));
    }

    function run() public override broadcast {
        _fundPersistentAccounts();

        VerifierDeployments memory deployed = _deploySelectedVerifiers();

        _deployConfiguredOracle(
            true,
            "Production",
            _selectedAdminVerifiers(true, deployed),
            _selectedDAVerifiers(true, deployed),
            assertionTimelockBlocks,
            maxAssertionsPerAA
        );

        if (deployStaging) {
            _deployConfiguredOracle(
                false,
                "Staging",
                _selectedAdminVerifiers(false, deployed),
                _selectedDAVerifiers(false, deployed),
                stagingAssertionTimelockBlocks,
                stagingMaxAssertionsPerAA
            );
        }
    }

    function _loadVerifierConfiguration() internal {
        daECDSAProduction = vm.envOr("DA_VERIFIER_ECDSA_PRODUCTION", false);
        daECDSAStaging = vm.envOr("DA_VERIFIER_ECDSA_STAGING", false);
        daOnChainProduction = vm.envOr("DA_VERIFIER_ONCHAIN_PRODUCTION", false);
        daOnChainStaging = vm.envOr("DA_VERIFIER_ONCHAIN_STAGING", false);

        require(_selectedDAVerifierCount(true) > 0, "Production requires a DA verifier");
        require(!deployStaging || _selectedDAVerifierCount(false) > 0, "Staging requires a DA verifier");
        require(deployStaging || !(daECDSAStaging || daOnChainStaging), "Staging DA verifier selected without staging");

        if (daECDSAProduction || daECDSAStaging) {
            daProver = vm.envAddress("DA_PROVER_ADDRESS");
            require(daProver != address(0), "Invalid DA prover");
        }

        adminOwnerProduction = vm.envOr("ADMIN_VERIFIER_OWNER_PRODUCTION", false);
        adminOwnerStaging = vm.envOr("ADMIN_VERIFIER_OWNER_STAGING", false);
        adminWhitelistProduction = vm.envOr("ADMIN_VERIFIER_WHITELIST_PRODUCTION", false);
        adminWhitelistStaging = vm.envOr("ADMIN_VERIFIER_WHITELIST_STAGING", false);
        adminSuperAdminProduction = vm.envOr("ADMIN_VERIFIER_SUPER_ADMIN_PRODUCTION", false);
        adminSuperAdminStaging = vm.envOr("ADMIN_VERIFIER_SUPER_ADMIN_STAGING", false);
        adminAlwaysApproveProduction = vm.envOr("ADMIN_VERIFIER_ALWAYS_APPROVE_PRODUCTION", false);
        adminAlwaysApproveStaging = vm.envOr("ADMIN_VERIFIER_ALWAYS_APPROVE_STAGING", false);

        require(_selectedAdminVerifierCount(true) > 0, "Production requires an admin verifier");
        require(!deployStaging || _selectedAdminVerifierCount(false) > 0, "Staging requires an admin verifier");
        require(
            deployStaging
                || !(adminOwnerStaging || adminWhitelistStaging || adminSuperAdminStaging || adminAlwaysApproveStaging),
            "Staging admin verifier selected without staging"
        );

        if (adminWhitelistProduction || adminWhitelistStaging) {
            whitelistAdmin = vm.envAddress("ADMIN_VERIFIER_WHITELIST_ADMIN_ADDRESS");
            require(whitelistAdmin != address(0), "Invalid admin verifier whitelist owner");
        }

        if (adminSuperAdminProduction || adminSuperAdminStaging) {
            require(testingDeployment, "Super Admin verifier is test-only");
            testSuperAdmin = vm.envAddress("TEST_ADMIN_VERIFIER_SUPER_ADMIN_ADDRESS");
            require(testSuperAdmin != address(0), "Invalid test super admin");
        }
        require(
            testingDeployment || !(adminAlwaysApproveProduction || adminAlwaysApproveStaging),
            "Always Approve verifier is test-only"
        );
    }

    function _deploySelectedVerifiers() internal returns (VerifierDeployments memory deployed) {
        if (daECDSAProduction || daECDSAStaging) {
            deployed.daECDSA = _deployDAVerifierECDSA();
            _logDeployment("DA Verifier (ECDSA)", deployed.daECDSA);
        }
        if (daOnChainProduction || daOnChainStaging) {
            deployed.daOnChain = _deployDAVerifierOnChain();
            _logDeployment("DA Verifier (On-chain)", deployed.daOnChain);
        }
        if (adminOwnerProduction || adminOwnerStaging) {
            deployed.adminOwner = _deployOwnerAdminVerifier();
            _logDeployment("Admin Verifier (Owner)", deployed.adminOwner);
        }
        if (adminWhitelistProduction || adminWhitelistStaging) {
            deployed.adminWhitelist = _deployWhitelistAdminVerifier();
            _logDeployment("Admin Verifier (Whitelist)", deployed.adminWhitelist);
        }
        if (adminSuperAdminProduction || adminSuperAdminStaging) {
            deployed.adminSuperAdmin = _deployCreate3(
                SALT_ADMIN_VERIFIER_SUPER_ADMIN_NAME,
                abi.encodePacked(type(AdminVerifierSuperAdmin).creationCode, abi.encode(testSuperAdmin))
            );
            console2.log("Testing Admin Verifier (Super Admin) deployed at", deployed.adminSuperAdmin);
            _logDeployment("Testing Admin Verifier (Super Admin)", deployed.adminSuperAdmin);
        }
        if (adminAlwaysApproveProduction || adminAlwaysApproveStaging) {
            deployed.adminAlwaysApprove = _deployAlwaysApproveAdminVerifier();
            _logDeployment("Testing Admin Verifier (Always Approve)", deployed.adminAlwaysApprove);
        }
    }

    function _selectedDAVerifiers(bool production, VerifierDeployments memory deployed)
        internal
        view
        returns (address[] memory verifiers)
    {
        verifiers = new address[](_selectedDAVerifierCount(production));
        uint256 index;
        if (production ? daECDSAProduction : daECDSAStaging) verifiers[index++] = deployed.daECDSA;
        if (production ? daOnChainProduction : daOnChainStaging) verifiers[index] = deployed.daOnChain;
    }

    function _selectedDAVerifierCount(bool production) internal view returns (uint256 count) {
        if (production ? daECDSAProduction : daECDSAStaging) count++;
        if (production ? daOnChainProduction : daOnChainStaging) count++;
    }

    function _selectedAdminVerifiers(bool production, VerifierDeployments memory deployed)
        internal
        view
        returns (address[] memory verifiers)
    {
        verifiers = new address[](_selectedAdminVerifierCount(production));
        uint256 index;
        if (production ? adminOwnerProduction : adminOwnerStaging) verifiers[index++] = deployed.adminOwner;
        if (production ? adminWhitelistProduction : adminWhitelistStaging) {
            verifiers[index++] = deployed.adminWhitelist;
        }
        if (production ? adminSuperAdminProduction : adminSuperAdminStaging) {
            verifiers[index++] = deployed.adminSuperAdmin;
        }
        if (production ? adminAlwaysApproveProduction : adminAlwaysApproveStaging) {
            verifiers[index] = deployed.adminAlwaysApprove;
        }
    }

    function _selectedAdminVerifierCount(bool production) internal view returns (uint256 count) {
        if (production ? adminOwnerProduction : adminOwnerStaging) count++;
        if (production ? adminWhitelistProduction : adminWhitelistStaging) count++;
        if (production ? adminSuperAdminProduction : adminSuperAdminStaging) count++;
        if (production ? adminAlwaysApproveProduction : adminAlwaysApproveStaging) count++;
    }

    function _deployConfiguredOracle(
        bool production,
        string memory environment,
        address[] memory adminVerifierDeployments,
        address[] memory daVerifierDeployments,
        uint256 timelockBlocks,
        uint16 maxAssertions
    ) internal returns (address proxyAddress) {
        string memory contractName = string.concat(environment, " State Oracle");
        string memory implementationSalt = production ? SALT_STATE_ORACLE_NAME : SALT_STAGING_STATE_ORACLE_NAME;
        string memory proxySalt = production ? SALT_STATE_ORACLE_PROXY_NAME : SALT_STAGING_STATE_ORACLE_PROXY_NAME;
        address implementation = _deployStateOracleWithSalt(timelockBlocks, contractName, implementationSalt);
        _logDeployment(string.concat(environment, " State Oracle Implementation"), implementation);

        proxyAddress = _deployStateOracleProxyWithConfig(
            implementation,
            adminVerifierDeployments,
            daVerifierDeployments,
            maxAssertions,
            stateOracleWhitelistEnabled,
            initialWhitelist,
            proxySalt,
            contractName
        );
        _logDeployment(string.concat(environment, " State Oracle Proxy"), proxyAddress);
    }

    function _logDeployment(string memory name, address deployedAddress) internal pure {
        console2.log(string.concat("WIZARD_DEPLOYMENT|", name, "|"), deployedAddress);
    }
}
