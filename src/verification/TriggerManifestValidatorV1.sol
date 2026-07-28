// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {ITriggerManifestValidator} from "../interfaces/ITriggerManifestValidator.sol";

/// @notice Validates the canonical V1 trigger manifest and prices its triggers.
contract TriggerManifestValidatorV1 is ITriggerManifestValidator, Ownable2Step {
    bytes32 public constant SCHEMA_ID = keccak256("credible-layer.trigger-manifest.v1");
    bytes32 public constant ATTESTATION_DOMAIN = keccak256("credible-layer.trigger-manifest.attestation.v1");
    uint256 public constant MAX_TRIGGERS = 256;
    uint64 public constant MIN_CUMULATIVE_WINDOW = 10;

    enum TriggerKind {
        AllCalls,
        Call,
        FnCall,
        TxEnd,
        AllStorageChanges,
        StorageChange,
        BalanceChange,
        Erc20Change,
        CumulativeOutflow,
        CumulativeInflow,
        Anomaly
    }

    struct TriggerV1 {
        TriggerKind kind;
        bytes4 assertionFunction;
        bytes4 triggerSelector;
        bytes32 storageSlot;
        address target;
        uint32 thresholdBps;
        uint64 windowDuration;
    }

    struct AssertionManifestV1 {
        uint8 version;
        TriggerV1[] triggers;
    }

    error InvalidManifestEncoding();
    error InvalidManifestVersion();
    error InvalidManifestSchema();
    error InvalidTriggerCount();
    error InvalidTrigger();
    error NonCanonicalTriggerOrder();
    error InvalidTriggerWeight();
    error TriggerWeightUnchanged();
    error InvalidManifestAttestor();
    error InvalidManifestAttestation();

    event TriggerWeightUpdated(TriggerKind indexed kind, uint32 oldWeight, uint32 newWeight);
    event ManifestAttestorUpdated(address indexed oldAttestor, address indexed newAttestor);

    mapping(TriggerKind kind => uint32 weight) public triggerWeights;
    address public manifestAttestor;

    constructor(address initialOwner, address initialManifestAttestor) Ownable(initialOwner) {
        require(initialManifestAttestor != address(0), InvalidManifestAttestor());
        manifestAttestor = initialManifestAttestor;
        for (uint256 i; i <= uint256(TriggerKind.Anomaly); ++i) {
            triggerWeights[TriggerKind(i)] = 1;
        }
    }

    function setManifestAttestor(address newAttestor) external onlyOwner {
        require(newAttestor != address(0), InvalidManifestAttestor());
        address oldAttestor = manifestAttestor;
        require(oldAttestor != newAttestor, InvalidManifestAttestor());
        manifestAttestor = newAttestor;
        emit ManifestAttestorUpdated(oldAttestor, newAttestor);
    }

    function setTriggerWeight(TriggerKind kind, uint32 newWeight) external onlyOwner {
        require(newWeight != 0, InvalidTriggerWeight());
        uint32 oldWeight = triggerWeights[kind];
        require(oldWeight != newWeight, TriggerWeightUnchanged());
        triggerWeights[kind] = newWeight;
        emit TriggerWeightUpdated(kind, oldWeight, newWeight);
    }

    function validate(bytes32 deploymentCodeHash, bytes32 schemaId, bytes calldata data, bytes calldata proof)
        external
        view
        returns (uint32 triggerCount, uint64 triggerUnits)
    {
        require(schemaId == SCHEMA_ID, InvalidManifestSchema());
        AssertionManifestV1 memory manifest = abi.decode(data, (AssertionManifestV1));
        require(keccak256(data) == keccak256(abi.encode(manifest)), InvalidManifestEncoding());
        require(manifest.version == 1, InvalidManifestVersion());
        require(
            ECDSA.recoverCalldata(attestationDigest(deploymentCodeHash, data), proof) == manifestAttestor,
            InvalidManifestAttestation()
        );

        uint256 length = manifest.triggers.length;
        require(length != 0 && length <= MAX_TRIGGERS, InvalidTriggerCount());

        bytes32 previousHash;
        for (uint256 i; i < length; ++i) {
            TriggerV1 memory trigger = manifest.triggers[i];
            _validateTrigger(trigger);

            bytes32 triggerHash = keccak256(abi.encode(trigger));
            require(i == 0 || uint256(triggerHash) > uint256(previousHash), NonCanonicalTriggerOrder());
            previousHash = triggerHash;
            triggerUnits += triggerWeights[trigger.kind];
            ++triggerCount;
        }
    }

    function attestationDigest(bytes32 deploymentCodeHash, bytes calldata data) public view returns (bytes32) {
        return keccak256(
            abi.encode(ATTESTATION_DOMAIN, block.chainid, address(this), deploymentCodeHash, SCHEMA_ID, keccak256(data))
        );
    }

    function _validateTrigger(TriggerV1 memory trigger) private pure {
        require(trigger.assertionFunction != bytes4(0), InvalidTrigger());

        TriggerKind kind = trigger.kind;
        if (kind == TriggerKind.Call || kind == TriggerKind.FnCall) {
            require(trigger.triggerSelector != bytes4(0), InvalidTrigger());
            require(
                trigger.storageSlot == bytes32(0) && trigger.target == address(0) && trigger.thresholdBps == 0
                    && trigger.windowDuration == 0,
                InvalidTrigger()
            );
            return;
        }

        if (kind == TriggerKind.StorageChange) {
            require(
                trigger.triggerSelector == bytes4(0) && trigger.target == address(0) && trigger.thresholdBps == 0
                    && trigger.windowDuration == 0,
                InvalidTrigger()
            );
            return;
        }

        if (kind == TriggerKind.Erc20Change || kind == TriggerKind.Anomaly) {
            require(trigger.target != address(0), InvalidTrigger());
            require(
                trigger.triggerSelector == bytes4(0) && trigger.storageSlot == bytes32(0) && trigger.thresholdBps == 0
                    && trigger.windowDuration == 0,
                InvalidTrigger()
            );
            return;
        }

        if (kind == TriggerKind.CumulativeOutflow || kind == TriggerKind.CumulativeInflow) {
            require(trigger.target != address(0) && trigger.windowDuration >= MIN_CUMULATIVE_WINDOW, InvalidTrigger());
            require(trigger.triggerSelector == bytes4(0) && trigger.storageSlot == bytes32(0), InvalidTrigger());
            return;
        }

        require(
            trigger.triggerSelector == bytes4(0) && trigger.storageSlot == bytes32(0) && trigger.target == address(0)
                && trigger.thresholdBps == 0 && trigger.windowDuration == 0,
            InvalidTrigger()
        );
    }
}
