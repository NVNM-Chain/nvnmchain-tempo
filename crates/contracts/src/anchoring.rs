//! The anchoring contract, as the genesis alloc places it. The T12 runtime is copied in from the
//! contracts repo's `layout/` by `cargo xtask anchoring-runtime`; the corpus arrives separately,
//! from the dump loader.

use alloy_primitives::{Address, B256, Bytes, U256, address, b256};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// The launch build: what chains ran before T12, with no owner.
pub const ANCHORING_RUNTIME: Bytes = Bytes::from_static(include_bytes!("anchoring_runtime.bin"));

/// `keccak256` of the launch build, pinned: T12 replaces this code and no other.
pub const ANCHORING_RUNTIME_HASH: B256 =
    b256!("893a2f955868c80ae17905aa36cc4f71a771731b530e72ff6cfb063f559a7c0e");

/// The T12 build, with an owner. `layout/anchoring.json` pins its slots, which the dump writer and
/// the explorer read too.
pub const T12_ANCHORING_RUNTIME: Bytes =
    Bytes::from_static(include_bytes!("t12_anchoring_runtime.bin"));

/// `keccak256` of the T12 runtime, pinned: another build gives the fork block another state root.
pub const T12_ANCHORING_RUNTIME_HASH: B256 =
    b256!("e62467174968b4f032799177c53e6086b408d0176e8560a26e1c5a9660a29a26");

/// `owner` in `layout/anchoring.json`, past every slot the dump writes.
pub const ANCHORING_OWNER_SLOT: U256 = U256::from_limbs([11, 0, 0, 0]);

crate::sol! {
    /// What this crate asks the T12 build; the launch build has no `owner()`.
    interface IAnchoring {
        function owner() external view returns (address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn the_runtimes_are_the_pinned_ones() {
        assert_eq!(keccak256(&ANCHORING_RUNTIME), ANCHORING_RUNTIME_HASH);
        assert_eq!(
            keccak256(&T12_ANCHORING_RUNTIME),
            T12_ANCHORING_RUNTIME_HASH
        );
    }
}
