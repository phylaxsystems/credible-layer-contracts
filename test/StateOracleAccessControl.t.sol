// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StateOracle} from "../src/StateOracle.sol";
import {DAVerifierMock} from "./utils/DAVerifierMock.sol";
import {ProxyHelper} from "./utils/ProxyHelper.t.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IAdminVerifier} from "../src/interfaces/IAdminVerifier.sol";
import {IDAVerifier} from "../src/interfaces/IDAVerifier.sol";
import {AdminVerifierOwner} from "../src/verification/admin/AdminVerifierOwner.sol";

/// @title StateOracleAccessControl Tests
/// @notice Tests for role-based access control, ownership, and role management
contract StateOracleAccessControlBase is Test, ProxyHelper {
    address constant STATE_ORACLE_ADMIN =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.STATE_ORACLE_ADMIN")))));
    uint128 constant TIMEOUT = 1000;
    uint16 constant MAX_ASSERTIONS_PER_AA = 5;
    StateOracle stateOracle;
    IAdminVerifier adminVerifier;

    /// @notice Modifier to ensure the address is not the proxy admin
    /// @param _address The address to check
    /// @dev This is needed because proxy admin calls will be processed internally
    modifier noAdmin(address _address) {
        vm.assume(_address != getProxyAdmin(address(stateOracle)));
        _;
    }

    /// @notice Deploys and initializes the oracle used by role and ownership tests.
    function setUp() public virtual {
        DAVerifierMock daVerifier = new DAVerifierMock();
        StateOracle implementation = new StateOracle(TIMEOUT);
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        IAdminVerifier[] memory verifiers = new IAdminVerifier[](1);
        verifiers[0] = adminVerifier;
        IDAVerifier[] memory daVerifiers = new IDAVerifier[](1);
        daVerifiers[0] = IDAVerifier(address(daVerifier));

        bytes memory data = abi.encodeWithSelector(
            StateOracle.initializeWithWhitelist.selector,
            STATE_ORACLE_ADMIN,
            verifiers,
            daVerifiers,
            MAX_ASSERTIONS_PER_AA,
            true,
            new address[](0)
        );
        stateOracle = StateOracle(deployProxy(address(implementation), data));

        // Disable whitelist for tests
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.disableWhitelist();
    }
}

/// @notice Tests ownership and its coupled default-admin role.
contract OwnableTest is StateOracleAccessControlBase {
    function test_ownerIsZeroOnImplementation() public {
        StateOracle implementation = new StateOracle(TIMEOUT);
        assertEq(implementation.owner(), address(0), "implementation owner should be zero");
    }

    function test_ownerIsInitializerOnProxy() public view {
        assertEq(stateOracle.owner(), STATE_ORACLE_ADMIN, "proxy owner should match initializer");
    }

    /// @notice Ownership changes only after delayed authorization and acceptance.
    function test_transferOwnership() public {
        address newOwner = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OWNER")))));

        // owner has DEFAULT_ADMIN_ROLE (1:1 coupling invariant)
        assertTrue(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), STATE_ORACLE_ADMIN),
            "Old owner should have DEFAULT_ADMIN_ROLE"
        );
        assertFalse(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), newOwner),
            "New owner should not have DEFAULT_ADMIN_ROLE yet"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.transferOwnership(newOwner);
        executeLast(stateOracle);
        assertEq(stateOracle.owner(), STATE_ORACLE_ADMIN, "ownership transfer should be pending");

        // DEFAULT_ADMIN_ROLE should not transfer until ownership is accepted
        assertTrue(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), STATE_ORACLE_ADMIN),
            "Old owner should still have DEFAULT_ADMIN_ROLE"
        );
        assertFalse(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), newOwner),
            "New owner should not have DEFAULT_ADMIN_ROLE yet"
        );

        vm.prank(newOwner);
        stateOracle.acceptOwnership();

        assertEq(stateOracle.owner(), newOwner, "ownership transfer should be completed");

        // DEFAULT_ADMIN_ROLE transfers with ownership (maintains 1:1 coupling)
        assertFalse(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), STATE_ORACLE_ADMIN),
            "Old owner should not have DEFAULT_ADMIN_ROLE anymore"
        );
        assertTrue(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), newOwner), "New owner should have DEFAULT_ADMIN_ROLE"
        );
    }

    /// @notice An accepted successor can schedule and execute governance grants.
    function test_newOwnerCanGrantRolesAsOwner() public {
        address newOwner = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OWNER")))));
        address governance = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.GOVERNANCE")))));

        // Transfer ownership (which includes DEFAULT_ADMIN_ROLE)
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.transferOwnership(newOwner);
        executeLast(stateOracle);

        vm.prank(newOwner);
        stateOracle.acceptOwnership();

        // New owner (with DEFAULT_ADMIN_ROLE) can grant GOVERNANCE_ROLE via onlyOwner functions
        vm.prank(newOwner);
        stateOracle.grantGovernanceRole(governance);
        executeLast(stateOracle);

        assertTrue(
            stateOracle.hasRole(stateOracle.GOVERNANCE_ROLE(), governance), "New owner can grant governance role"
        );
    }
}

/// @notice Tests delayed ownership renunciation.
contract RenounceOwnershipTest is StateOracleAccessControlBase {
    /// @notice Renunciation preserves the one-to-one owner/default-admin invariant.
    function test_renounceOwnershipMaintainsInvariant() public {
        // Before: owner has DEFAULT_ADMIN_ROLE
        assertEq(stateOracle.owner(), STATE_ORACLE_ADMIN);
        assertTrue(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), STATE_ORACLE_ADMIN));

        // Renounce
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.renounceOwnership();
        executeLast(stateOracle);

        // After: address(0) is owner and has DEFAULT_ADMIN_ROLE (invariant maintained!)
        assertEq(stateOracle.owner(), address(0));
        assertTrue(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), address(0)));
        assertFalse(stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), STATE_ORACLE_ADMIN));
        assertFalse(stateOracle.hasRole(stateOracle.GOVERNANCE_ROLE(), STATE_ORACLE_ADMIN));
        assertFalse(stateOracle.hasRole(stateOracle.GUARDIAN_ADMIN_ROLE(), STATE_ORACLE_ADMIN));
        assertFalse(stateOracle.hasRole(stateOracle.OPERATOR_ADMIN_ROLE(), STATE_ORACLE_ADMIN));
        assertFalse(stateOracle.hasRole(stateOracle.GUARDIAN_ROLE(), STATE_ORACLE_ADMIN));
        assertFalse(stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), STATE_ORACLE_ADMIN));
    }
}

/// @notice Tests authorized operator grants through generic and typed entrypoints.
contract GrantOperatorRole is StateOracleAccessControlBase {
    function test_stateOracleAdminHasDefaultAdminRole() public view {
        assertTrue(
            stateOracle.hasRole(stateOracle.DEFAULT_ADMIN_ROLE(), STATE_ORACLE_ADMIN),
            "STATE_ORACLE_ADMIN should have DEFAULT_ADMIN_ROLE"
        );
    }

    /// @notice The owner's generic operator grant takes effect after execution.
    function test_ownerCanGrantOperatorRole() public {
        address newOperator = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OPERATOR")))));

        assertFalse(
            stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), newOperator), "Operator should not have role initially"
        );

        vm.startPrank(STATE_ORACLE_ADMIN);
        stateOracle.grantRole(stateOracle.OPERATOR_ROLE(), newOperator);
        vm.stopPrank();
        executeLast(stateOracle);

        assertTrue(
            stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), newOperator), "Operator should have role after grant"
        );
    }

    /// @notice The typed operator grant follows the same delayed policy.
    function test_ownerCanGrantOperatorRoleUsingHelper() public {
        address newOperator = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OPERATOR")))));

        assertFalse(
            stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), newOperator), "Operator should not have role initially"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantOperatorRole(newOperator);
        executeLast(stateOracle);

        assertTrue(
            stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), newOperator), "Operator should have role after grant"
        );
    }

    function testFuzz_RevertIf_nonOperatorAdminGrantsOperatorRoleUsingHelper(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));
        bytes32 operatorAdminRole = stateOracle.OPERATOR_ADMIN_ROLE();
        vm.assume(!stateOracle.hasRole(operatorAdminRole, unauthorizedCaller));
        address newOperator = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OPERATOR")))));

        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                unauthorizedCaller,
                operatorAdminRole
            )
        );
        vm.prank(unauthorizedCaller);
        stateOracle.grantOperatorRole(newOperator);
    }

    function testFuzz_RevertIf_nonOperatorAdminGrantsOperatorRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));
        bytes32 operatorAdminRole = stateOracle.OPERATOR_ADMIN_ROLE();
        bytes32 operatorRole = stateOracle.OPERATOR_ROLE();
        vm.assume(!stateOracle.hasRole(operatorAdminRole, unauthorizedCaller));
        address newOperator = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OPERATOR")))));

        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                unauthorizedCaller,
                operatorAdminRole
            )
        );
        vm.prank(unauthorizedCaller);
        stateOracle.grantRole(operatorRole, newOperator);
    }
}

/// @notice Fixture with an effective operator grant.
contract RevokeOperatorRoleBase is StateOracleAccessControlBase {
    address constant OPERATOR = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.OPERATOR")))));

    /// @notice Executes the operator grant before testing revocation.
    function setUp() public virtual override {
        super.setUp();
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantOperatorRole(OPERATOR);
        executeLast(stateOracle);
    }
}

/// @notice Tests operator revocation through both authorized entrypoints.
contract RevokeOperatorRole is RevokeOperatorRoleBase {
    /// @notice Generic revocation removes the operator after execution.
    function test_ownerCanRevokeOperatorRole() public {
        assertTrue(stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), OPERATOR), "Operator should have role initially");

        vm.startPrank(STATE_ORACLE_ADMIN);
        stateOracle.revokeRole(stateOracle.OPERATOR_ROLE(), OPERATOR);
        vm.stopPrank();
        executeLast(stateOracle);

        assertFalse(
            stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), OPERATOR), "Operator should not have role after revoke"
        );
    }

    /// @notice Typed revocation removes the operator after execution.
    function test_ownerCanRevokeOperatorRoleUsingHelper() public {
        assertTrue(stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), OPERATOR), "Operator should have role initially");

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.revokeOperatorRole(OPERATOR);
        executeLast(stateOracle);

        assertFalse(
            stateOracle.hasRole(stateOracle.OPERATOR_ROLE(), OPERATOR), "Operator should not have role after revoke"
        );
    }

    function testFuzz_RevertIf_nonOperatorAdminRevokesOperatorRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));
        bytes32 operatorAdminRole = stateOracle.OPERATOR_ADMIN_ROLE();
        bytes32 operatorRole = stateOracle.OPERATOR_ROLE();
        vm.assume(!stateOracle.hasRole(operatorAdminRole, unauthorizedCaller));

        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                unauthorizedCaller,
                operatorAdminRole
            )
        );
        vm.prank(unauthorizedCaller);
        stateOracle.revokeRole(operatorRole, OPERATOR);
    }

    function testFuzz_RevertIf_nonOperatorAdminRevokesOperatorRoleUsingHelper(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));
        bytes32 operatorAdminRole = stateOracle.OPERATOR_ADMIN_ROLE();
        vm.assume(!stateOracle.hasRole(operatorAdminRole, unauthorizedCaller));

        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                unauthorizedCaller,
                operatorAdminRole
            )
        );
        vm.prank(unauthorizedCaller);
        stateOracle.revokeOperatorRole(OPERATOR);
    }
}

/// @notice Tests guardian-admin grants.
contract GrantGuardianAdminRole is StateOracleAccessControlBase {
    /// @notice The owner can execute a delayed guardian-admin grant.
    function test_ownerCanGrantGuardianAdminRole() public {
        address newGuardianAdmin =
            address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_GUARDIAN_ADMIN")))));
        assertFalse(
            stateOracle.hasRole(stateOracle.GUARDIAN_ADMIN_ROLE(), newGuardianAdmin),
            "GuardianAdmin should not have role initially"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantGuardianAdminRole(newGuardianAdmin);
        executeLast(stateOracle);

        assertTrue(
            stateOracle.hasRole(stateOracle.GUARDIAN_ADMIN_ROLE(), newGuardianAdmin),
            "GuardianAdmin should have role after grant"
        );
    }

    function testFuzz_RevertIf_nonOwnerGrantsGuardianAdminRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));

        address newGuardianAdmin =
            address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_GUARDIAN_ADMIN")))));

        vm.prank(unauthorizedCaller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorizedCaller));
        stateOracle.grantGuardianAdminRole(newGuardianAdmin);
    }
}

/// @notice Tests guardian-admin revocation.
contract RevokeGuardianAdminRole is StateOracleAccessControlBase {
    address constant GUARDIAN_ADMIN_TO_REVOKE =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.GUARDIAN_ADMIN_TO_REVOKE")))));

    /// @notice Executes the grant used by revocation tests.
    function setUp() public virtual override {
        super.setUp();
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantGuardianAdminRole(GUARDIAN_ADMIN_TO_REVOKE);
        executeLast(stateOracle);
    }

    /// @notice The owner can execute a delayed guardian-admin revocation.
    function test_ownerCanRevokeGuardianAdminRole() public {
        assertTrue(
            stateOracle.hasRole(stateOracle.GUARDIAN_ADMIN_ROLE(), GUARDIAN_ADMIN_TO_REVOKE),
            "GuardianAdmin should have role initially"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.revokeGuardianAdminRole(GUARDIAN_ADMIN_TO_REVOKE);
        executeLast(stateOracle);

        assertFalse(
            stateOracle.hasRole(stateOracle.GUARDIAN_ADMIN_ROLE(), GUARDIAN_ADMIN_TO_REVOKE),
            "GuardianAdmin should not have role after revoke"
        );
    }

    function testFuzz_RevertIf_nonOwnerRevokesGuardianAdminRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));

        vm.prank(unauthorizedCaller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorizedCaller));
        stateOracle.revokeGuardianAdminRole(GUARDIAN_ADMIN_TO_REVOKE);
    }
}

/// @notice Tests guardian grants under guardian-admin authorization.
contract GrantGuardianRole is StateOracleAccessControlBase {
    /// @notice A guardian admin can execute a delayed guardian grant.
    function test_guardianAdminCanGrantGuardianRole() public {
        address newGuardian = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_GUARDIAN")))));
        assertFalse(
            stateOracle.hasRole(stateOracle.GUARDIAN_ROLE(), newGuardian), "Guardian should not have role initially"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantGuardianRole(newGuardian);
        executeLast(stateOracle);

        assertTrue(
            stateOracle.hasRole(stateOracle.GUARDIAN_ROLE(), newGuardian), "Guardian should have role after grant"
        );
    }

    function testFuzz_RevertIf_nonGuardianAdminGrantsGuardianRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));

        address newGuardian = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_GUARDIAN")))));

        bytes32 guardianAdminRole = stateOracle.GUARDIAN_ADMIN_ROLE();
        vm.prank(unauthorizedCaller);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                unauthorizedCaller,
                guardianAdminRole
            )
        );
        stateOracle.grantGuardianRole(newGuardian);
    }
}

/// @notice Fixture with an effective guardian grant.
contract GuardianRoleBase is StateOracleAccessControlBase {
    address constant GUARDIAN = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.GUARDIAN")))));

    /// @notice Executes the guardian grant before revocation tests.
    function setUp() public virtual override {
        super.setUp();
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantGuardianRole(GUARDIAN);
        executeLast(stateOracle);
    }
}

/// @notice Tests guardian revocation under guardian-admin authorization.
contract RevokeGuardianRole is GuardianRoleBase {
    /// @notice A guardian admin can execute a delayed guardian revocation.
    function test_guardianAdminCanRevokeGuardianRole() public {
        assertTrue(stateOracle.hasRole(stateOracle.GUARDIAN_ROLE(), GUARDIAN), "Guardian should have role initially");

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.revokeGuardianRole(GUARDIAN);
        executeLast(stateOracle);

        assertFalse(
            stateOracle.hasRole(stateOracle.GUARDIAN_ROLE(), GUARDIAN), "Guardian should not have role after revoke"
        );
    }

    function testFuzz_RevertIf_nonGuardianAdminRevokesGuardianRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));

        bytes32 guardianAdminRole = stateOracle.GUARDIAN_ADMIN_ROLE();
        vm.prank(unauthorizedCaller);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                unauthorizedCaller,
                guardianAdminRole
            )
        );
        stateOracle.revokeGuardianRole(GUARDIAN);
    }
}

/// @notice Tests operator-admin grants.
contract GrantOperatorAdminRole is StateOracleAccessControlBase {
    /// @notice The owner can execute a delayed operator-admin grant.
    function test_ownerCanGrantOperatorAdminRole() public {
        address newOperatorAdmin =
            address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OPERATOR_ADMIN")))));
        assertFalse(
            stateOracle.hasRole(stateOracle.OPERATOR_ADMIN_ROLE(), newOperatorAdmin),
            "OperatorAdmin should not have role initially"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantOperatorAdminRole(newOperatorAdmin);
        executeLast(stateOracle);

        assertTrue(
            stateOracle.hasRole(stateOracle.OPERATOR_ADMIN_ROLE(), newOperatorAdmin),
            "OperatorAdmin should have role after grant"
        );
    }

    function testFuzz_RevertIf_nonOwnerGrantsOperatorAdminRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));

        address newOperatorAdmin =
            address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.NEW_OPERATOR_ADMIN")))));

        vm.prank(unauthorizedCaller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorizedCaller));
        stateOracle.grantOperatorAdminRole(newOperatorAdmin);
    }
}

/// @notice Tests operator-admin revocation.
contract RevokeOperatorAdminRole is StateOracleAccessControlBase {
    address constant OPERATOR_ADMIN_TO_REVOKE =
        address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.OPERATOR_ADMIN_TO_REVOKE")))));

    /// @notice Executes the operator-admin grant before revocation tests.
    function setUp() public virtual override {
        super.setUp();
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.grantOperatorAdminRole(OPERATOR_ADMIN_TO_REVOKE);
        executeLast(stateOracle);
    }

    /// @notice The owner can execute a delayed operator-admin revocation.
    function test_ownerCanRevokeOperatorAdminRole() public {
        assertTrue(
            stateOracle.hasRole(stateOracle.OPERATOR_ADMIN_ROLE(), OPERATOR_ADMIN_TO_REVOKE),
            "OperatorAdmin should have role initially"
        );

        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.revokeOperatorAdminRole(OPERATOR_ADMIN_TO_REVOKE);
        executeLast(stateOracle);

        assertFalse(
            stateOracle.hasRole(stateOracle.OPERATOR_ADMIN_ROLE(), OPERATOR_ADMIN_TO_REVOKE),
            "OperatorAdmin should not have role after revoke"
        );
    }

    function testFuzz_RevertIf_nonOwnerRevokesOperatorAdminRole(address unauthorizedCaller)
        public
        noAdmin(unauthorizedCaller)
    {
        vm.assume(unauthorizedCaller != STATE_ORACLE_ADMIN);
        vm.assume(unauthorizedCaller != address(this));

        vm.prank(unauthorizedCaller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, unauthorizedCaller));
        stateOracle.revokeOperatorAdminRole(OPERATOR_ADMIN_TO_REVOKE);
    }
}
