//! Alloy bindings for the Credible Layer protocol contracts.
//!
//! Versioned ABI snapshots are generated from canonical Solidity interfaces by
//! the repository's artifact pipeline. They are committed so compiling this
//! crate does not require Foundry.

/// `StateOracle` bindings grouped by interface generation.
pub mod state_oracle {
    /// `StateOracle` interface used by contract release 0.2.0.
    pub mod v1 {
        alloy_sol_types::sol!(IStateOracleV1, "abi/IStateOracleV1.json");
    }

    /// `StateOracle` interface introduced by contract release 0.3.0.
    pub mod v2 {
        alloy_sol_types::sol!(IStateOracleV2, "abi/IStateOracleV2.json");
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::{SolCall, SolError, SolEvent, TopicList};

    use super::state_oracle::{v1::IStateOracleV1, v2::IStateOracleV2};

    #[test]
    fn state_oracle_v1_matches_release_0_2_0() {
        assert_eq!(
            IStateOracleV1::registerAssertionAdopterCall::SIGNATURE,
            "registerAssertionAdopter(address,address,bytes)"
        );
        assert_eq!(
            IStateOracleV1::getAssertionWindowCall::SIGNATURE,
            "getAssertionWindow(address,bytes32)"
        );
        assert_eq!(
            IStateOracleV1::addAssertionCall::SIGNATURE,
            "addAssertion(address,bytes32,bytes,bytes)"
        );
        assert_eq!(
            IStateOracleV1::AssertionAdded::SIGNATURE,
            "AssertionAdded(address,bytes32,uint256)"
        );
        assert_eq!(IStateOracleV1::InvalidProof::SIGNATURE, "InvalidProof()");
        assert_eq!(
            <<IStateOracleV1::AssertionAdded as SolEvent>::TopicList as TopicList>::COUNT,
            1
        );
    }

    #[test]
    fn state_oracle_v2_matches_release_0_3_0() {
        assert_eq!(
            IStateOracleV2::registerAssertionAdopterCall::SIGNATURE,
            "registerAssertionAdopter(address,address,bytes)"
        );
        assert_eq!(
            IStateOracleV2::addAssertionCall::SIGNATURE,
            "addAssertion(address,bytes32,address,bytes,bytes)"
        );
        assert_eq!(
            IStateOracleV2::AssertionAdded::SIGNATURE,
            "AssertionAdded(address,bytes32,uint256,address,bytes,bytes)"
        );
        assert_eq!(
            IStateOracleV2::InvalidDAProof::SIGNATURE,
            "InvalidDAProof(address)"
        );
        assert_eq!(
            <<IStateOracleV2::AssertionAdded as SolEvent>::TopicList as TopicList>::COUNT,
            4
        );
    }
}
