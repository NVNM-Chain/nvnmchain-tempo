use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use tempo_primitives::{TempoTxEnvelope, TempoTxType};

pub type Transaction = alloy_rpc_types_eth::Transaction<TempoTxEnvelope>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsFilter {
    /// Filter by sender address (from)
    from: Option<Address>,
    /// Filter by recipient address (to)
    to: Option<Address>,
    /// Transaction type
    #[serde(rename = "type")]
    type_: Option<TempoTxType>,
}

/// Read accessors, so a backend in another crate can apply the filter without the
/// fields becoming part of the wire type's public shape.
impl TransactionsFilter {
    pub const fn from(&self) -> Option<Address> {
        self.from
    }

    pub const fn to(&self) -> Option<Address> {
        self.to
    }

    pub const fn tx_type(&self) -> Option<TempoTxType> {
        self.type_
    }
}
