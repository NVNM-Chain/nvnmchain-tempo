use crate::rpc::eth_ext::transactions::TransactionsResponse;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::{EthApiTypes, RpcNodeCore, RpcTypes, helpers::EthTransactions};
use tempo_alloy::rpc::pagination::PaginationParams;
use tempo_indexer::{IndexerRpc, Reader, store::Filter};

pub mod transactions;
pub use transactions::TransactionsFilter;

#[rpc(server, namespace = "eth")]
pub trait TempoEthExtApi {
    /// Gets paginated transactions on Tempo with flexible filtering and sorting.
    ///
    /// Uses cursor-based pagination for stable iteration through transactions.
    #[method(name = "getTransactions")]
    async fn transactions(
        &self,
        params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse>;
}

/// The JSON-RPC handlers for the `dex_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoEthExt<EthApi> {
    eth_api: EthApi,
    /// The transaction index, when the node is running one.
    ///
    /// Optional rather than always-on so the index stays opt-in, and so the method
    /// keeps answering exactly what it answered before when it is off: one handler,
    /// one merge, and no second `eth_getTransactions` to collide with this one.
    index: Option<IndexerRpc<EthApi>>,
}

impl<EthApi: Clone> TempoEthExt<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self {
            eth_api,
            index: None,
        }
    }

    /// Serve `eth_getTransactions` from `index` instead of reporting it unimplemented.
    pub fn with_index(eth_api: EthApi, index: Reader) -> Self {
        Self {
            index: Some(IndexerRpc::new(eth_api.clone(), index)),
            eth_api,
        }
    }
}

#[async_trait::async_trait]
impl<EthApi> TempoEthExtApiServer for TempoEthExt<EthApi>
where
    // The index hands back whatever the eth API's network calls a transaction; this
    // says that is the one this method declares, rather than converting between two
    // spellings of the same type.
    EthApi: RpcNodeCore
        + EthTransactions
        + EthApiTypes<NetworkTypes: RpcTypes<TransactionResponse = transactions::Transaction>>
        + Clone
        + 'static,
{
    async fn transactions(
        &self,
        params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse> {
        // Naming the flag, because the alternative is indistinguishable from the
        // stub this replaced: an operator who did not know the index is opt-in reads
        // "unimplemented" as "this node cannot do it" rather than "switch it on".
        let Some(index) = self.index.as_ref() else {
            return Err(internal_rpc_err(
                "eth_getTransactions needs the transaction index, which is off by default; restart the node with --indexer",
            ));
        };
        let (transactions, next_cursor) = index
            .page(params, |filters| Filter {
                from: filters.from(),
                to: filters.to(),
                tx_type: filters.tx_type().map(|ty| ty as u8),
            })
            .await?;
        Ok(TransactionsResponse {
            next_cursor,
            transactions,
        })
    }
}

impl<EthApi: RpcNodeCore> TempoEthExt<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
