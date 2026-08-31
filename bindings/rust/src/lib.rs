//! Alloy bindings for the Credible Layer protocol contracts.
//!
//! Versioned ABI snapshots are generated from canonical Solidity interfaces by
//! the repository's artifact pipeline. They are committed so registry and git
//! consumers do not need Foundry or submodules.

/// `StateOracle` bindings grouped by interface generation.
pub mod state_oracle {
    /// First published `StateOracle` interface generation.
    pub mod v1 {
        alloy_sol_types::sol!(IStateOracleV1, "abi/IStateOracleV1.json");
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::{SolCall, SolError, SolEvent, TopicList};

    use super::state_oracle::v1::IStateOracleV1;

    #[test]
    fn state_oracle_boundary_matches_representative_canonical_entries() {
        assert_eq!(
            IStateOracleV1::registerAssertionAdopterCall::SIGNATURE,
            "registerAssertionAdopter(address,address,bytes)"
        );
        assert_eq!(
            IStateOracleV1::getAssertionWindowCall::SIGNATURE,
            "getAssertionWindow(address,bytes32)"
        );
        assert_eq!(
            IStateOracleV1::AssertionAdded::SIGNATURE,
            "AssertionAdded(address,bytes32,uint256,address,bytes,bytes)"
        );
        assert_eq!(
            IStateOracleV1::InvalidDAProof::SIGNATURE,
            "InvalidDAProof(address)"
        );
        assert_eq!(
            <<IStateOracleV1::AssertionAdded as SolEvent>::TopicList as TopicList>::COUNT,
            4
        );
    }
}
