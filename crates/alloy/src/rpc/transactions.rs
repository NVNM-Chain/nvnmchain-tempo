//! `eth_getTransactions` types.
//!
//! Beside [`super::pagination`] rather than in the node, because they are schema: a
//! backend serving this method has to build the response, and it should not have to
//! reach into the node crate that happens to declare the trait.

use alloy_primitives::{Address, BlockNumber};
use serde::{Deserialize, Serialize};
use tempo_primitives::{TempoTxEnvelope, TempoTxType};

use super::pagination::FilterRange;

pub type Transaction = alloy_rpc_types_eth::Transaction<TempoTxEnvelope>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// How many transactions match, across every page.
    ///
    /// Null when the index keeps no count for this combination of filters — counts are
    /// maintained per filter value as transactions are indexed, so an intersection of
    /// two of them, or a block range, has no stored answer. Null means "not counted",
    /// never "none".
    pub total: Option<u64>,
    /// Array of items matching the input query
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsFilter {
    /// Filter by sender address (from)
    pub from: Option<Address>,
    /// Filter by an address the transaction calls (to)
    ///
    /// A tempo transaction is a batch of calls, and this matches *any* of their
    /// targets rather than only the first.
    pub to: Option<Address>,
    /// Filter by an address on either side: transactions it sent or transactions it
    /// was called by. What an address page asks, in one request rather than two.
    pub address: Option<Address>,
    /// Block height in range, inclusive at both ends
    pub block_number: Option<FilterRange<BlockNumber>>,
    /// Filter by the token gas was paid in; absent for the native currency
    pub fee_token: Option<Address>,
    /// Filter by who paid for the transaction — the sponsor where one paid, and the
    /// sender otherwise
    pub fee_payer: Option<Address>,
    /// Transaction type
    #[serde(rename = "type")]
    pub type_: Option<TempoTxType>,
}
