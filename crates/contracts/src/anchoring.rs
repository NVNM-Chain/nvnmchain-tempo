//! The anchoring contract, as the genesis alloc places it. The runtime is copied in from the
//! contracts repo's `layout/` by `cargo xtask anchoring-runtime`; the corpus arrives separately,
//! from the dump loader.

use alloy_primitives::{Address, Bytes, address};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// `layout/anchoring.bin` decoded. `layout/anchoring.json` pins its slots, which the dump writer
/// and the explorer read too, so a new build cannot move one. T12 installs it over an earlier
/// build, so no release after that fork may change it.
pub const ANCHORING_RUNTIME: Bytes = Bytes::from_static(include_bytes!("anchoring_runtime.bin"));

/// `owner` in `layout/anchoring.json`, past every slot the dump writes.
pub const ANCHORING_OWNER_SLOT: u64 = 11;

/// The owner a chain's contract gets in the block where T12 installs the runtime. A chain not
/// named here gets none from the fork, and only genesis can name one.
pub const fn t12_anchoring_owner(chain_id: u64) -> Option<Address> {
    match chain_id {
        // NVNM testnet: its validator admin.
        787223 => Some(address!("0xd5fCEca17cE41Ebd2e88Ce730291a341864150eb")),
        _ => None,
    }
}
