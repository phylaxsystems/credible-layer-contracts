// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {TriggerManifestValidatorV1} from "../src/verification/TriggerManifestValidatorV1.sol";

contract TriggerManifestValidatorV1Test is Test {
    uint256 private constant ATTESTOR_KEY = 0xA11E57;
    bytes32 private constant DEPLOYMENT_CODE_HASH = keccak256("deployment code");

    TriggerManifestValidatorV1 internal validator;
    bytes32 internal schemaId;

    function setUp() public {
        validator = new TriggerManifestValidatorV1(address(this), vm.addr(ATTESTOR_KEY));
        schemaId = validator.SCHEMA_ID();
    }

    function test_countsTriggersWithDefaultWeights() public view {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);

        bytes memory data = _encode(triggers);
        (uint32 count, uint64 units) = validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, _proof(data));

        assertEq(count, 1);
        assertEq(units, 1);
    }

    function test_acceptsMaximumTriggerCount() public view {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = _allCalls(validator.MAX_TRIGGERS());
        _sort(triggers);

        bytes memory data = _encode(triggers);
        (uint32 count, uint64 units) = validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, _proof(data));

        assertEq(count, 256);
        assertEq(units, 256);
    }

    function test_rejectsMoreThanMaximumTriggerCount() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = _allCalls(validator.MAX_TRIGGERS() + 1);
        bytes memory data = _encode(triggers);
        bytes memory proof = _proof(data);

        vm.expectRevert(TriggerManifestValidatorV1.InvalidTriggerCount.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_acceptsEveryTriggerKindWithCanonicalFields() public view {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers =
            new TriggerManifestValidatorV1.TriggerV1[](uint256(TriggerManifestValidatorV1.TriggerKind.Anomaly) + 1);
        for (uint256 i; i < triggers.length; ++i) {
            triggers[i] = _trigger(TriggerManifestValidatorV1.TriggerKind(i));
        }
        _sort(triggers);

        bytes memory data = _encode(triggers);
        (uint32 count, uint64 units) = validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, _proof(data));

        assertEq(count, 11);
        assertEq(units, 11);
    }

    function test_usesAdjustedWeight() public {
        validator.setTriggerWeight(TriggerManifestValidatorV1.TriggerKind.FnCall, 4);
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.FnCall);
        triggers[0].triggerSelector = bytes4(keccak256("deposit()"));

        bytes memory data = _encode(triggers);
        (, uint64 units) = validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, _proof(data));

        assertEq(units, 4);
    }

    function test_rejectsNonCanonicalOrderAndDuplicates() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](2);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);
        triggers[1] = _trigger(TriggerManifestValidatorV1.TriggerKind.TxEnd);
        bytes32 firstHash = keccak256(abi.encode(triggers[0]));
        bytes32 secondHash = keccak256(abi.encode(triggers[1]));
        if (uint256(firstHash) < uint256(secondHash)) (triggers[0], triggers[1]) = (triggers[1], triggers[0]);

        bytes memory data = _encode(triggers);
        bytes memory proof = _proof(data);
        vm.expectRevert(TriggerManifestValidatorV1.NonCanonicalTriggerOrder.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);

        triggers[1] = triggers[0];
        data = _encode(triggers);
        proof = _proof(data);
        vm.expectRevert(TriggerManifestValidatorV1.NonCanonicalTriggerOrder.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_rejectsInvalidFields() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);
        triggers[0].target = address(1);
        bytes memory data = _encode(triggers);
        bytes memory proof = _proof(data);
        vm.expectRevert(TriggerManifestValidatorV1.InvalidTrigger.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);

        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.CumulativeOutflow);
        triggers[0].target = address(1);
        triggers[0].windowDuration = 9;
        data = _encode(triggers);
        proof = _proof(data);
        vm.expectRevert(TriggerManifestValidatorV1.InvalidTrigger.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_rejectsNonCanonicalEncoding() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);

        bytes memory data = bytes.concat(_encode(triggers), bytes32(uint256(1)));
        bytes memory proof = _proof(data);
        vm.expectRevert(TriggerManifestValidatorV1.InvalidManifestEncoding.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_rejectsZeroTriggers() public {
        bytes memory data = _encode(new TriggerManifestValidatorV1.TriggerV1[](0));
        bytes memory proof = _proof(data);
        vm.expectRevert(TriggerManifestValidatorV1.InvalidTriggerCount.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_rejectsTamperedManifestProof() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);
        bytes memory data = _encode(triggers);
        triggers[0].assertionFunction = bytes4(keccak256("differentAssertion()"));
        bytes memory proof = _proof(_encode(triggers));

        vm.expectRevert(TriggerManifestValidatorV1.InvalidManifestAttestation.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_attestationBindsDeploymentChainAndValidatorDomains() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);
        bytes memory data = _encode(triggers);
        bytes memory proof = _proof(data);

        vm.expectRevert(TriggerManifestValidatorV1.InvalidManifestAttestation.selector);
        validator.validate(keccak256("different code"), schemaId, data, proof);

        TriggerManifestValidatorV1 otherValidator = new TriggerManifestValidatorV1(address(this), vm.addr(ATTESTOR_KEY));
        bytes32 otherSchemaId = otherValidator.SCHEMA_ID();
        vm.expectRevert(TriggerManifestValidatorV1.InvalidManifestAttestation.selector);
        otherValidator.validate(DEPLOYMENT_CODE_HASH, otherSchemaId, data, proof);

        vm.chainId(block.chainid + 1);
        vm.expectRevert(TriggerManifestValidatorV1.InvalidManifestAttestation.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, schemaId, data, proof);
    }

    function test_rejectsWrongSchemaDomain() public {
        TriggerManifestValidatorV1.TriggerV1[] memory triggers = new TriggerManifestValidatorV1.TriggerV1[](1);
        triggers[0] = _trigger(TriggerManifestValidatorV1.TriggerKind.AllCalls);
        bytes memory data = _encode(triggers);
        bytes memory proof = _proof(data);

        vm.expectRevert(TriggerManifestValidatorV1.InvalidManifestSchema.selector);
        validator.validate(DEPLOYMENT_CODE_HASH, keccak256("different schema"), data, proof);
    }

    function _trigger(TriggerManifestValidatorV1.TriggerKind kind)
        private
        pure
        returns (TriggerManifestValidatorV1.TriggerV1 memory)
    {
        TriggerManifestValidatorV1.TriggerV1 memory trigger = TriggerManifestValidatorV1.TriggerV1({
            kind: kind,
            assertionFunction: bytes4(keccak256("assertion()")),
            triggerSelector: bytes4(0),
            storageSlot: bytes32(0),
            target: address(0),
            thresholdBps: 0,
            windowDuration: 0
        });
        if (
            kind == TriggerManifestValidatorV1.TriggerKind.Call || kind == TriggerManifestValidatorV1.TriggerKind.FnCall
        ) {
            trigger.triggerSelector = bytes4(keccak256("deposit()"));
        } else if (kind == TriggerManifestValidatorV1.TriggerKind.StorageChange) {
            trigger.storageSlot = bytes32(uint256(1));
        } else if (
            kind == TriggerManifestValidatorV1.TriggerKind.Erc20Change
                || kind == TriggerManifestValidatorV1.TriggerKind.Anomaly
        ) {
            trigger.target = address(1);
        } else if (
            kind == TriggerManifestValidatorV1.TriggerKind.CumulativeOutflow
                || kind == TriggerManifestValidatorV1.TriggerKind.CumulativeInflow
        ) {
            trigger.target = address(1);
            trigger.thresholdBps = 100;
            trigger.windowDuration = 10;
        }
        return trigger;
    }

    function _allCalls(uint256 count) private pure returns (TriggerManifestValidatorV1.TriggerV1[] memory triggers) {
        triggers = new TriggerManifestValidatorV1.TriggerV1[](count);
        for (uint256 i; i < count; ++i) {
            triggers[i] = TriggerManifestValidatorV1.TriggerV1({
                kind: TriggerManifestValidatorV1.TriggerKind.AllCalls,
                assertionFunction: bytes4(keccak256(abi.encode(i))),
                triggerSelector: bytes4(0),
                storageSlot: bytes32(0),
                target: address(0),
                thresholdBps: 0,
                windowDuration: 0
            });
        }
    }

    function _sort(TriggerManifestValidatorV1.TriggerV1[] memory triggers) private pure {
        for (uint256 i = 1; i < triggers.length; ++i) {
            TriggerManifestValidatorV1.TriggerV1 memory current = triggers[i];
            bytes32 currentHash = keccak256(abi.encode(current));
            uint256 j = i;
            while (j != 0 && uint256(keccak256(abi.encode(triggers[j - 1]))) > uint256(currentHash)) {
                triggers[j] = triggers[j - 1];
                --j;
            }
            triggers[j] = current;
        }
    }

    function _encode(TriggerManifestValidatorV1.TriggerV1[] memory triggers) private pure returns (bytes memory) {
        return abi.encode(TriggerManifestValidatorV1.AssertionManifestV1({version: 1, triggers: triggers}));
    }

    function _proof(bytes memory data) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_KEY, validator.attestationDigest(DEPLOYMENT_CODE_HASH, data));
        return abi.encodePacked(r, s, v);
    }
}
