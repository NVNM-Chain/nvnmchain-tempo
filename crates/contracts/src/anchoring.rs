//! The anchoring contract and its module admin, as the genesis alloc places them. The anchoring
//! runtime is copied in from the contracts repo's `layout/` by `cargo xtask anchoring-runtime` and
//! the NVNM1 boundary installs it; the corpus arrives separately, from the dump loader. The module
//! admin is a Safe, whose runtimes are Safe's own and move only with Safe's own releases.

use alloy_primitives::{Address, Bytes, address};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// `params.Admin` on the old chain: a 2-of-3 amino multisig whose address no single key derives,
/// so genesis gives it a Safe instead, owned by the member keys' own addresses.
pub const MODULE_ADMIN_ADDRESS: Address = address!("0x0582bFB2e8561D48636E78f0e6b139d5a842be8f");

/// `layout/anchoring.bin` decoded. `layout/anchoring.json` pins its slots, which the dump writer
/// and the explorer read too, so a new build cannot move one.
pub const ANCHORING_RUNTIME: Bytes = Bytes::from_static(include_bytes!("anchoring_runtime.bin"));

/// Safe v1.4.1's singleton, at the address its proxies point to on every chain.
pub const SAFE_SINGLETON_ADDRESS: Address = address!("0x41675C099F32341bf84BFc5382aF534df5C7461a");

/// The bytes deployed at [`SAFE_SINGLETON_ADDRESS`] on mainnet.
pub const SAFE_SINGLETON_RUNTIME: Bytes =
    Bytes::from_static(include_bytes!("safe_singleton_runtime.bin"));

/// What `SafeProxyFactory.proxyCreationCode()` leaves behind: it delegates everything to the
/// singleton its first storage slot names.
pub const SAFE_PROXY_RUNTIME: Bytes = Bytes::from_static(include_bytes!("safe_proxy_runtime.bin"));
