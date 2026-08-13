//! `eth_getTransactions`, served from the ExEx-maintained index.
//!
//! This fills in the trait tempo already declares (`crates/node/src/rpc/eth_ext`)
//! rather than restating its schema. allegro, which cannot depend on tempo, mirrors
//! `PaginationParams` and the response envelope by hand and carries a comment about
//! keeping them in step; inside tempo that copy would be the second definition of a
//! wire contract that has one, so there is none here.
//!
//! The split of work is the same on both: the index answers *which* transactions
//! match, reth answers what each one is. Bodies are never stored.

use futures::future::try_join_all;
use jsonrpsee::core::RpcResult;
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::helpers::EthTransactions;
use reth_rpc_eth_api::{EthApiTypes, RpcTransaction};
use tempo_alloy::rpc::pagination::{PaginationParams, SortOrder};

use crate::store::{Filter, Order, Position, Reader};

/// Page size when the caller does not ask for one, and the ceiling on one that does.
///
/// Both are the schema's: `PaginationParams::limit` documents "Defaults to 10.
/// Maximum is 100". The ceiling is also what stops one request asking the node to
/// serialize the world.
const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 100;

fn order_of(sort: SortOrder) -> Order {
    match sort {
        SortOrder::Asc => Order::Ascending,
        SortOrder::Desc => Order::Descending,
    }
}

/// The `eth_getTransactions` handler: index for selection, reth for the bodies.
#[derive(Debug, Clone)]
pub struct IndexerRpc<EthApi> {
    eth_api: EthApi,
    store: Reader,
}

impl<EthApi> IndexerRpc<EthApi> {
    pub const fn new(eth_api: EthApi, store: Reader) -> Self {
        Self { eth_api, store }
    }
}

impl<EthApi> IndexerRpc<EthApi>
where
    EthApi: EthTransactions + EthApiTypes + 'static,
{
    /// One page: the rows the index selects, hydrated through reth.
    ///
    /// Returns the transactions and the cursor to resume from, so the caller builds
    /// whichever response envelope it declares.
    pub async fn page<F>(
        &self,
        params: PaginationParams<F>,
        filter_of: impl FnOnce(F) -> Filter,
    ) -> RpcResult<(Vec<RpcTransaction<EthApi::NetworkTypes>>, Option<String>)>
    where
        F: Default,
    {
        let filter = filter_of(params.filters.unwrap_or_default());
        let order = order_of(params.sort.map(|sort| sort.order).unwrap_or_default());
        // Floor of 1, not just a ceiling: a zero limit returns no rows, so it has no
        // last row to cut a cursor from, and the caller is told the page is final
        // while a further page exists -- a walk that ends one page in.
        let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

        let after = params
            .cursor
            .as_deref()
            .map(|cursor| {
                Position::decode(cursor)
                    .ok_or_else(|| internal_rpc_err(format!("malformed cursor: {cursor}")))
            })
            .transpose()?;

        // One extra row tells us whether a further page exists. Counting instead would
        // promise a next page that turns out empty at an exact multiple of the limit.
        let mut found = self
            .store
            .query(&filter, after, order, limit.saturating_add(1))
            .map_err(|e| internal_rpc_err(format!("index query failed: {e}")))?;

        let has_more = found.len() > limit;
        found.truncate(limit);
        // The cursor names the last row returned, not the extra one peeked at.
        let next_cursor = found
            .last()
            .filter(|_| has_more)
            .map(|entry| entry.position.encode());

        // The lookups are independent, so overlap them instead of awaiting one at a
        // time -- a full page is up to 100. `try_join_all` keeps the rows in order.
        let sources = try_join_all(
            found
                .iter()
                .map(|entry| EthTransactions::transaction_by_hash(&self.eth_api, entry.hash)),
        )
        .await
        .map_err(|e| internal_rpc_err(format!("failed to load transaction: {e}")))?;

        let mut transactions = Vec::with_capacity(found.len());
        // The index can name a transaction reth has since pruned; skip it rather than
        // failing the whole page.
        for source in sources.into_iter().flatten() {
            let tx = source
                .into_transaction(self.eth_api.converter())
                .map_err(|e| internal_rpc_err(format!("failed to convert transaction: {e}")))?;
            transactions.push(tx);
        }

        Ok((transactions, next_cursor))
    }
}
