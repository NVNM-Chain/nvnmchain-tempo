//! The anchoring contract: code from the genesis alloc and the corpus from the dump loader, both
//! built by the `nvnmchain-contracts` repo. The NVNM1 fork installs the runtime here over the
//! alloc's.

use alloy_primitives::{Address, Bytes, address};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// `layout/anchoring.bin` decoded. The swap leaves storage alone, so this has to keep the layout
/// `layout/anchoring.json` pins.
pub const NVNM1_ANCHORING_RUNTIME: Bytes =
    Bytes::from_static(include_bytes!("anchoring_runtime.bin"));
