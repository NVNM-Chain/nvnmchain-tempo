//! Tempo chainspec implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(all(not(test), feature = "reth"), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "reth")]
extern crate alloc;

#[cfg(feature = "reth")]
mod bootnodes;
#[cfg(feature = "reth")]
mod network_identity;
#[cfg(feature = "reth")]
pub mod spec;
#[cfg(feature = "reth")]
pub use network_identity::NetworkIdentity;
#[cfg(feature = "reth")]
pub use spec::{
    NvnmHardforks, TempoChainSpec, TempoConsensusSpec, TempoGenesisError, TempoHardforks,
};

pub use tempo_hardfork::{TempoHardfork, constants};
pub use tempo_nvnm_hardfork::{Forks, NvnmHardfork};

/// Backwards-compatible hardfork import path.
pub mod hardfork {
    pub use tempo_hardfork::TempoHardfork;
    pub use tempo_nvnm_hardfork::{Forks, NvnmHardfork};

    #[cfg(feature = "reth")]
    pub use crate::spec::{NvnmHardforks, TempoHardforks};
}
