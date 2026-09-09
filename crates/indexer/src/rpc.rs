//! `eth_getTransactions`, served from the ExEx-maintained index.
//!
//! This fills in the trait the node already declares (`crates/node/src/rpc/eth_ext`)
//! rather than restating its schema. The trait itself has to stay there — it is what
//! the node merges into reth's RPC server — but everything under it is here, so the
//! node's handler is a flag check and one call.
//!
//! The split of work: the index answers *which* transactions match, reth answers what
//! each one is. Bodies are never stored. Paging is the index's too — clamping, the
//! look-ahead and the cursor live in `tx-index` beside the tests that pin them.

use futures::future::try_join_all;
use jsonrpsee::core::RpcResult;
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::helpers::EthTransactions;
use reth_rpc_eth_api::{EthApiTypes, RpcTypes};
use tempo_alloy::rpc::pagination::{PaginationParams, SortOrder};
use tempo_alloy::rpc::transactions::{Transaction, TransactionsFilter, TransactionsResponse};

use crate::store::{BlockRange, Filter, Order, Reader};

/// A free function rather than `From`: both types are foreign here, so the orphan
/// rule forbids the impl. allegro can write one only because it declares its own
/// `SortOrder` locally.
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
    // The index hands back whatever this node's eth API calls a transaction; the bound
    // says that is the one the method declares, rather than converting between two
    // spellings of the same type.
    EthApi: EthTransactions
        + EthApiTypes<NetworkTypes: RpcTypes<TransactionResponse = Transaction>>
        + 'static,
{
    pub async fn transactions(
        &self,
        params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse> {
        let filters = params.filters.unwrap_or_default();
        let blocks = filters.block_number.unwrap_or_default();
        let filter = Filter {
            from: filters.from,
            to: filters.to,
            address: filters.address,
            tx_type: filters.type_.map(|ty| ty as u8),
            fee_token: filters.fee_token,
            fee_payer: filters.fee_payer,
            blocks: BlockRange::new(blocks.min, blocks.max),
        };
        let order = order_of(params.sort.unwrap_or_default().order);

        let page = self
            .store
            .page(&filter, params.cursor.as_deref(), order, params.limit)
            .map_err(|e| internal_rpc_err(e.to_string()))?;
        // Whether the index counts this combination at all, not how many it found:
        // `None` here becomes a null `total` rather than a zero.
        let total = self
            .store
            .count(&filter)
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        // The lookups are independent, so overlap them instead of awaiting one at a
        // time -- a full page is up to 100. `try_join_all` keeps the rows in order.
        let sources = try_join_all(
            page.rows
                .iter()
                .map(|row| EthTransactions::transaction_by_hash(&self.eth_api, row.hash)),
        )
        .await
        .map_err(|e| internal_rpc_err(format!("failed to load transaction: {e}")))?;

        let mut transactions = Vec::with_capacity(page.rows.len());
        // The index can name a transaction reth has since pruned; skip it rather than
        // failing the whole page.
        for source in sources.into_iter().flatten() {
            let tx = source
                .into_transaction(self.eth_api.converter())
                .map_err(|e| internal_rpc_err(format!("failed to convert transaction: {e}")))?;
            transactions.push(tx);
        }

        Ok(TransactionsResponse {
            next_cursor: page.next_cursor,
            total,
            transactions,
        })
    }
}
