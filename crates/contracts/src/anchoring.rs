//! The anchoring contract, as the genesis alloc places it. `cargo xtask anchoring-runtime` copies
//! the proxy in from the contracts repo's `layout/` and checks the implementation there; the corpus
//! arrives separately, from the dump loader.

use alloy_primitives::{Address, B256, Bytes, U256, address, b256};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// The launch build: what chains ran before T12, with no owner.
pub const T11_ANCHORING_RUNTIME: Bytes =
    Bytes::from_static(include_bytes!("t11_anchoring_runtime.bin"));

/// `keccak256` of the launch build, pinned: T12 replaces this code and no other.
pub const T11_ANCHORING_RUNTIME_HASH: B256 =
    b256!("893a2f955868c80ae17905aa36cc4f71a771731b530e72ff6cfb063f559a7c0e");

/// `owner` in `layout/anchoring.json`, past every slot the dump writes.
pub const ANCHORING_OWNER_SLOT: U256 = U256::from_limbs([11, 0, 0, 0]);

/// The ERC-1967 proxy T12 puts over the launch build once the implementation is deployed: solady's,
/// `layout/proxy.bin`.
pub const T12_ANCHORING_PROXY_RUNTIME: Bytes =
    Bytes::from_static(include_bytes!("t12_anchoring_proxy.bin"));

/// `keccak256` of the proxy, pinned.
pub const T12_ANCHORING_PROXY_RUNTIME_HASH: B256 =
    b256!("aaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d");

/// Where an ordinary deployment of `layout/anchoring.init.bin` through Arachnid's factory, salt
/// zero, puts the implementation the proxy points to.
pub const T12_ANCHORING_IMPLEMENTATION: Address =
    address!("0x4d84d0E553B1BEad40dA5E6D7818B72EeE93cF01");

/// `keccak256` of `layout/anchoring.bin`, the code that deployment leaves: the proxy points at no
/// other. `layout/anchoring.json` pins its slots, which the dump writer and the explorer read too.
pub const T12_ANCHORING_IMPLEMENTATION_HASH: B256 =
    b256!("c3b62e631f3fc2d8ecb55f9caaa5c11417e5cfb62b2e1092e959d2f2ab11e12b");

/// ERC-1967's implementation slot, which the proxy reads.
pub const ERC1967_IMPLEMENTATION_SLOT: U256 = U256::from_be_bytes(
    b256!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").0,
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn the_runtimes_are_the_pinned_ones() {
        assert_eq!(
            keccak256(&T11_ANCHORING_RUNTIME),
            T11_ANCHORING_RUNTIME_HASH
        );
        assert_eq!(
            keccak256(&T12_ANCHORING_PROXY_RUNTIME),
            T12_ANCHORING_PROXY_RUNTIME_HASH
        );
    }
}
