//! A registry name index for the anchoring contract, kept by a reth Execution Extension.
//!
//! The contract answers `registriesByName` for an exact name only. This holds ids and
//! names in RocksDB ([`store`]), level with state ([`exex`]), and serves prefix, suffix and
//! contains over RPC ([`rpc`]). Rows are read back out of the contract, so the index can be
//! deleted and rebuilt without touching consensus state.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod args;
pub mod exex;
pub mod rpc;
pub mod state;
pub mod store;

use std::path::{Path, PathBuf};

use alloy_primitives::Address;

pub use args::AnchoringIndexArgs;
pub use rpc::{AnchoringApiServer, AnchoringRpc};
pub use state::Registry;
pub use store::{Mode, Reader, Store};

/// Directory name of the index inside the node's datadir.
pub const INDEX_DIR: &str = "anchoring-name-index";

/// Open the index under `datadir`: the writing handle for the ExEx and a read handle for the
/// RPC, from one open so they cannot point at different directories.
pub fn open_store(
    datadir: &Path,
    path: Option<PathBuf>,
    chain_id: u64,
    contract: Address,
) -> eyre::Result<(Store, Reader)> {
    let path = match path {
        Some(path) if path.is_absolute() => path,
        Some(path) => datadir.join(path),
        None => datadir.join(INDEX_DIR),
    };
    std::fs::create_dir_all(datadir)?;
    let store = Store::open(path)?;
    store.bind(chain_id, contract)?;
    let reader = store.reader();
    Ok((store, reader))
}
