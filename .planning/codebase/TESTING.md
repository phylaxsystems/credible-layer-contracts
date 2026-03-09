# Testing Patterns

**Analysis Date:** 2026-03-09

## Test Framework

**Runner:**
- Foundry Test Framework (Forge)
- Config: `foundry.toml` (minimal configuration)

**Version:**
- Solidity: `^0.8.28` for test contracts

**Run Commands:**
```bash
npm test                    # Run all tests
forge test                  # Run all tests (equivalent)
forge test --match-path test/StateOracle.t.sol          # Run specific test file
forge test --match-contract AddAssertion                 # Run specific contract
forge test --match-path test/StateOracle.t.sol --via-ir # Use IR optimizer
npm run format             # Format test files with forge fmt
```

**Assertion Library:**
- Forge's built-in assertions (see `forge-std/Test.sol`)
- Common assertions: `assertTrue()`, `assertFalse()`, `assertEq()`, `assertNotEq()`
- For testing revert: `vm.expectRevert(ErrorSelector)`
- For testing emit: `vm.expectEmit(indexed1, indexed2, indexed3, checkData, contractAddress)`

## Test File Organization

**Location:**
- Co-located with source: Test files live in `test/` directory alongside main `src/` directory
- Structure mirrors source structure: `test/StateOracle.t.sol` tests `src/StateOracle.sol`

**Naming:**
- Suffix: `.t.sol` (e.g., `StateOracle.t.sol`, `Batch.t.sol`)
- Contract names in test: suffix with test type or group (e.g., `StateOracleBase`, `Constructor`, `Register`, `AddAssertion`)

**Structure:**
```
test/
├── StateOracle.t.sol              # Main contract tests
├── StateOracleAccessControl.t.sol  # Role/ownership tests
├── Batch.t.sol                     # Batch functionality tests
├── AdminVerifierWhitelist.t.sol    # Whitelist verifier tests
├── AdminVerifierSuperAdmin.t.sol   # Super admin verifier tests
├── DAVerifierECDSA.t.sol           # ECDSA verification tests
├── integration/                    # Integration tests
│   └── StateOracleWithDAVerifierECDSA.sol
│   └── DeployCoreWithStaging.t.sol
└── utils/                          # Test helpers and mocks
    ├── ProxyHelper.t.sol           # Proxy deployment helpers
    ├── Adopter.sol                 # Mock adopter contracts
    └── DAVerifierMock.sol          # Mock DA verifier
```

## Test Structure

**Base Contract Pattern:**
Tests use base contract pattern to share setUp and helper methods across test groups:

```solidity
contract StateOracleBase is Test, ProxyHelper {
    address constant OWNER = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.OWNER")))));
    address constant DEPLOYER = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.DEPLOYER")))));
    address constant STATE_ORACLE_ADMIN = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.STATE_ORACLE_ADMIN")))));
    uint128 constant TIMEOUT = 1000;
    uint16 constant MAX_ASSERTIONS_PER_AA = 5;
    StateOracle stateOracle;
    IAdminVerifier adminVerifier;

    function setUp() public virtual {
        DAVerifierMock daVerifier = new DAVerifierMock();
        StateOracle implementation = new StateOracle(TIMEOUT, address(daVerifier));
        adminVerifier = IAdminVerifier(new AdminVerifierOwner());
        IAdminVerifier[] memory verifiers = new IAdminVerifier[](1);
        verifiers[0] = adminVerifier;

        bytes memory data = abi.encodeWithSelector(
            StateOracle.initialize.selector, STATE_ORACLE_ADMIN, verifiers, MAX_ASSERTIONS_PER_AA
        );
        stateOracle = StateOracle(deployProxy(address(implementation), data));

        // Disable whitelist for existing tests
        vm.prank(STATE_ORACLE_ADMIN);
        stateOracle.disableWhitelist();
    }
}
```

**Test Contract Organization:**
- Base contract: `StateOracleBase is Test, ProxyHelper`
- Group contracts by functionality: `contract Constructor is StateOracleBase`, `contract Register is StateOracleBase`
- Each group inherits base and adds specific tests

**Setup Pattern:**
- `setUp()` runs before each test
- `setUp()` is `public virtual` to allow overrides in derived test contracts
- Initialize contract once in base, allow customization in specific tests
- Use `vm.prank()` to call functions as specific addresses

## Test Structure Examples

**Positive Test (Happy Path):**
```solidity
function test_registerByOwner() public {
    OwnableAdopter adopter = new OwnableAdopter(OWNER);

    vm.prank(OWNER);
    stateOracle.registerAssertionAdopter(address(adopter), adminVerifier, new bytes(0));
    assertEq(stateOracle.getManager(address(adopter)), OWNER, "Manager mismatch");
}
```

**Fuzz Test:**
```solidity
function testFuzz_addAssertion(bytes32 assertionId) public {
    (address adopter, address manager) = registerAssertionAdopter();
    addAssertionAndAssert(manager, adopter, assertionId);
}
```

**Revert Test:**
```solidity
function testFuzz_RevertIf_registerByUnauthorized(address unauthorizedRegistrant)
    public
    noAdmin(unauthorizedRegistrant)
{
    vm.assume(unauthorizedRegistrant != OWNER);
    OwnableAdopter adopter = new OwnableAdopter(OWNER);

    vm.prank(unauthorizedRegistrant);
    vm.expectRevert(StateOracle.UnauthorizedRegistrant.selector);
    stateOracle.registerAssertionAdopter(address(adopter), adminVerifier, new bytes(0));

    vm.assertEq(stateOracle.getManager(address(adopter)), address(0), "Manager should be address(0)");
}
```

**Event Test:**
```solidity
function test_expectAssertionAdded(bytes32 assertionId) public {
    (address adopter, address manager) = registerAssertionAdopter();
    uint128 activationBlock = uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS();
    // Check topic1: adopter, topic2: assertionId, data: activationBlock and emitting address
    vm.expectEmit(true, true, false, true, address(stateOracle));
    emit StateOracle.AssertionAdded(adopter, assertionId, activationBlock);
    addAssertionAndAssert(manager, adopter, assertionId);
}
```

## Mocking

**Framework:** Forge's `vm` (cheatcodes)

**Patterns:**

**Address Spoofing:**
```solidity
vm.prank(address);        // Single call as address
vm.startPrank(address);   // Multiple calls as address
vm.stopPrank();           // Stop pranking
```

**Block Manipulation:**
```solidity
vm.roll(blockNumber);     // Set block number
vm.warp(timestamp);       // Set block timestamp
```

**Storage/Bytecode:**
```solidity
vm.load(address, slot);   // Read storage at slot
vm.store(address, slot, value);  // Write storage
```

**Signature Generation:**
```solidity
(uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
bytes memory signature = abi.encodePacked(r, s, v);
```

**What to Mock:**
- External verifier implementations (use `DAVerifierMock`)
- Time/block dependencies (use `vm.roll`, `vm.warp`)
- Cross-contract calls where appropriate

**What NOT to Mock:**
- Core contract logic (test actual implementation)
- Access control checks (test actual role enforcement)
- Storage state (test actual state changes)
- Events (use `vm.expectEmit()` to verify)

## Fixtures and Factories

**Test Data Helpers:**

Helper methods in base contracts create test data consistently:

```solidity
function registerAssertionAdopter() internal returns (address, address) {
    address manager = OWNER;
    vm.assume(manager != getProxyAdmin(address(stateOracle)));

    vm.startPrank(manager);
    OwnableAdopter adopter = new OwnableAdopter(manager);
    stateOracle.registerAssertionAdopter(address(adopter), adminVerifier, new bytes(0));
    vm.stopPrank();

    assertTrue(stateOracle.getManager(address(adopter)) == manager, "Manager mismatch");
    return (address(adopter), manager);
}

function addAssertionAndAssert(address manager, address adopter, bytes32 assertionId) internal noAdmin(manager) {
    vm.prank(manager);
    stateOracle.addAssertion(adopter, assertionId, new bytes(0), new bytes(0));

    assertTrue(stateOracle.hasAssertion(adopter, assertionId), "Assertion not found");
    (uint128 activationBlock, uint128 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
    assertEq(
        activationBlock,
        uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS(),
        "Activation block mismatch"
    );
    assertEq(deactivationBlock, uint128(0), "Deactivation block mismatch");
}
```

**Location:**
- In base test contracts (e.g., `StateOracleBase`)
- Reused across multiple test groups

## Coverage

**Requirements:** No explicit target enforced in config, but tests aim for comprehensive coverage.

**View Coverage:**
```bash
forge coverage                    # Generate coverage report
forge coverage --report lcov      # Generate LCOV format
```

**Current State:**
- Critical paths heavily tested (registration, assertion lifecycle, access control)
- Edge cases covered via fuzz tests
- Integration tests verify end-to-end flows

## Test Types

**Unit Tests:**
- Scope: Single function or tightly-related group
- Approach: Test inputs, outputs, and side effects
- Example: `test_registerByOwner()` in `StateOracle.t.sol`
- State isolation: Each test should be independent

**Integration Tests:**
- Scope: Multiple components working together
- Location: `test/integration/` subdirectory
- Example: `StateOracleWithDAVerifierECDSA.sol` tests oracle with actual ECDSA verifier
- Approach: Minimal mocking, test realistic sequences

**Access Control Tests:**
- Location: `StateOracleAccessControl.t.sol`
- Scope: Role-based access, ownership transfer, invariants
- Approach: Test all role paths and denial cases

**Proxy/Upgrade Tests:**
- Helpers: `ProxyHelper.t.sol` provides `deployProxy()` and `getProxyAdmin()`
- Pattern: Deploy implementation, wrap with proxy, call `initialize()`
- Invariant: Test that initialization is disabled on implementation

## Common Patterns

**Async Testing (Block Progression):**
```solidity
function testFuzz_removeAssertion(bytes32 assertionId) public {
    (address adopter, address manager) = registerAssertionAdopter();
    addAssertionAndAssert(manager, adopter, assertionId);
    (uint128 activationBlockBefore,) = stateOracle.getAssertionWindow(adopter, assertionId);

    vm.roll(block.number + 1);  // Advance block

    vm.prank(manager);
    stateOracle.removeAssertion(adopter, assertionId);
    (uint128 activationBlock, uint128 deactivationBlock) = stateOracle.getAssertionWindow(adopter, assertionId);
    assertEq(activationBlock, activationBlockBefore, "Activation should not change");
    assertEq(
        deactivationBlock,
        uint128(block.number) + stateOracle.ASSERTION_TIMELOCK_BLOCKS(),
        "Deactivation block mismatch"
    );
}
```

**Error Testing with Custom Errors:**
```solidity
function testFuzz_RevertIf_verifyDAwithInvalidSignature(
    bytes32 assertionId,
    bytes calldata metadata,
    bytes calldata signature
) public {
    vm.assume(signature.length != 64 && signature.length != 65);
    vm.expectRevert(ECDSA.InvalidSignature.selector);
    verifier.verifyDA(assertionId, metadata, signature);
}
```

**Batch Call Testing:**
```solidity
function test_batchExecutesAllCalls() public {
    bytes[] memory calls = new bytes[](2);
    calls[0] = abi.encodeCall(BatchHarness.increment, 2);
    calls[1] = abi.encodeCall(BatchHarness.increment, 3);

    harness.batch(calls);

    assertEq(harness.value(), 5);
}
```

**Expectation for BatchError:**
```solidity
function test_batchRevertsWhenInnerCallFails() public {
    bytes[] memory calls = new bytes[](1);
    calls[0] = abi.encodeCall(BatchHarness.revertWithError, ());

    bytes memory innerRevert = abi.encodeWithSelector(BatchHarness.HarnessError.selector);
    bytes memory expectedRevert = abi.encodeWithSelector(Batch.BatchError.selector, innerRevert);

    vm.expectRevert(expectedRevert);
    harness.batch(calls);
}
```

## Test Naming Conventions

**Positive Tests:**
- `test_<functionName>` - Basic happy path
- `testFuzz_<functionName>` - Parameterized happy path

**Negative Tests:**
- `test_RevertIf_<condition>` - Single condition, specific revert
- `testFuzz_RevertIf_<condition>` - Fuzzy parameters, specific revert

**Event Tests:**
- `test_expect<EventName>` - Verify specific event emission
- `testFuzz_expect<EventName>` - Event with fuzzy parameters

**Examples from codebase:**
- `test_registerByOwner` - Positive: owner registration
- `testFuzz_RevertIf_registerByUnauthorized` - Negative: unauthorized caller
- `test_expectAssertionAdded` - Event: assertion added
- `testFuzz_addMultipleAssertions` - Positive: multiple assertions with fuzz
- `testFuzz_RevertIf_addDuplicateAssertion` - Negative: duplicate with fuzz

## Proxy Testing Specifics

**Pattern (ProxyHelper.t.sol):**
```solidity
bytes memory data = abi.encodeWithSelector(
    StateOracle.initialize.selector, STATE_ORACLE_ADMIN, verifiers, MAX_ASSERTIONS_PER_AA
);
stateOracle = StateOracle(deployProxy(address(implementation), data));
```

**Gotcha - Transparent Proxy Admin:**
- Proxy admin cannot call implementation functions directly through proxy
- Helper modifier `noAdmin()` excludes proxy admin from fuzz tests
- Test uses `getProxyAdmin()` to read admin from storage slot

**Example Constraint:**
```solidity
modifier noAdmin(address _address) {
    vm.assume(_address != getProxyAdmin(address(stateOracle)));
    _;
}

function testFuzz_RevertIf_registerByUnauthorized(address unauthorizedRegistrant)
    public
    noAdmin(unauthorizedRegistrant)
{
    // Now unauthorizedRegistrant is guaranteed not to be the proxy admin
}
```

## Test Configuration

**foundry.toml Settings:**
```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]

[lint]
exclude_lints = ["mixed-case-function", "mixed-case-variable"]
```

## Test Execution Safety

**Deterministic Addresses:**
- Constant test addresses derived from `keccak256(abi.encode("string"))` for determinism
- Example: `address constant OWNER = address(uint160(uint256(keccak256(abi.encode("pcl.test.StateOracle.OWNER")))));`

**Block State:**
- Tests start at block 0
- Use `vm.roll()` to advance blocks for timelock tests
- Use `vm.warp()` for timestamp-dependent tests (none currently in use)

**Assumptions in Fuzz Tests:**
- Filter invalid inputs with `vm.assume()`
- Typical filters: exclude zero addresses, exclude self, exclude proxy admin

---

*Testing analysis: 2026-03-09*
