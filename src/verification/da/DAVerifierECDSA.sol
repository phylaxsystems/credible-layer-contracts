// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ECDSA} from "solady/utils/ECDSA.sol";

import {IDAVerifier} from "../../interfaces/IDAVerifier.sol";

/// @title DAVerifierECDSA
/// @author @fredo (luehrs.fred@gmail.com)
/// @notice Verifies data availability proofs for assertions by ECDSA recovery
/// @dev Implements signature verification for data availability of assertions
/// @dev Uses vectorized's ECDSA.recover to verify signatures
contract DAVerifierECDSA is IDAVerifier {
    /// @notice The address of the DA prover
    address public immutable DA_PROVER;

    /// @notice Initializes the contract with a DA prover address
    /// @param daProver The address authorized to sign DA proofs
    constructor(address daProver) {
        DA_PROVER = daProver;
    }

    /// @notice Verifies a data availability proof for an assertion
    /// @dev Recovers signer from signature and compares with DA_PROVER
    /// @dev Uses solady's ECDSA.recoverCalldata to verify signatures
    /// @dev metadata is not used for verification, but is included for compatibility with other DA verifiers
    /// @inheritdoc IDAVerifier
    function verifyDA(bytes32 assertionId, bytes calldata, bytes calldata proof) external view returns (bool verified) {
        return ECDSA.recoverCalldata(assertionId, proof) == DA_PROVER;
    }
}
