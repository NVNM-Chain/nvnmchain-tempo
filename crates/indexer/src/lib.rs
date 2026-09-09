//! A transaction index for tempo, maintained by a reth Execution Extension.
//!
//! The node stores every transaction but cannot cheaply answer "which ones did this
//! address send". This crate adds that secondary index ([`store`]), keeps it in step
//! with the chain ([`exex`]), and serves it as `eth_getTransactions` ([`rpc`]) — the
//! method `crates/node/src/rpc/eth_ext` declares and answers `unimplemented`.
//!
//! It holds positions and filter keys only, resolving hashes back through reth, so disk
//! grows with transaction *count* rather than size and the index can be deleted and
//! rebuilt without touching consensus state.
//!
//! Ported from allegro's `crates/indexer`, which serves the same schema from the same
//! shape. What is tempo's own is the primitives it indexes and the trait it implements:
//! the RPC here fills in `TempoEthExtApiServer` rather than declaring a parallel
//! schema, so there is one definition of the wire contract and it is tempo's.

pub mod exex;
pub mod rpc;

/// The index itself, shared with allegro through the `tx-index` crate.
///
/// It deals only in addresses, hashes and a type byte — no reth, which is what lets
/// two nodes on different reth revisions use the same one. What stays here is what
/// cannot be shared: the ExEx is concrete in this node's primitives, and the RPC
/// fills in this node's declared schema.
pub use tx_index as store;

pub use rpc::IndexerRpc;
pub use tx_index::{Reader, Store};

/// Directory name of the index inside the node's datadir.
pub const INDEX_DIR: &str = "indexer";

/// Open the index under `datadir`: a writing handle the ExEx owns outright, and a
/// lock-free read handle the RPC handlers share.
pub fn open_store(datadir: &std::path::Path) -> eyre::Result<(Store, Reader)> {
    // reth creates the datadir before either launch path reaches here; this is one
    // syscall to not depend on that.
    std::fs::create_dir_all(datadir)?;
    let store = Store::open(datadir.join(INDEX_DIR))?;
    let reader = store.reader();
    Ok((store, reader))
}
