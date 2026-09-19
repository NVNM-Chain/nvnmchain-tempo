//! The anchoring contract, as the genesis alloc places it and the NVNM1 boundary installs it. The
//! runtime is copied in from the contracts repo's `layout/` by `cargo xtask anchoring-runtime`;
//! the corpus arrives separately, from the dump loader.

use alloy_primitives::{Address, Bytes, address};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// `layout/anchoring.bin` decoded. `layout/anchoring.json` pins its slots, which the dump writer
/// and the explorer read too, so a new build cannot move one.
pub const ANCHORING_RUNTIME: Bytes = Bytes::from_static(include_bytes!("anchoring_runtime.bin"));
