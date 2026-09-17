//! The anchoring contract and its module admin, as the genesis alloc places them and the NVNM1
//! boundary installs them. Both runtimes are copied in from the contracts repo's `layout/` by
//! `cargo xtask anchoring-runtime`; the corpus arrives separately, from the dump loader.

use alloy_primitives::{Address, Bytes, address};

/// Where the old chain's precompile answered, so a caller changes chains and nothing else.
pub const ANCHORING_ADDRESS: Address = address!("0x0000000000000000000000000000000000000A00");

/// `params.Admin` on the old chain: a 2-of-3 amino multisig whose address no single key derives,
/// so genesis gives it code instead, owned by the member keys' own addresses.
pub const MODULE_ADMIN_ADDRESS: Address = address!("0x0582bFB2e8561D48636E78f0e6b139d5a842be8f");

/// `layout/anchoring.bin` decoded. `layout/anchoring.json` pins its slots, which the dump writer
/// and the explorer read too, so a new build cannot move one.
pub const ANCHORING_RUNTIME: Bytes = Bytes::from_static(include_bytes!("anchoring_runtime.bin"));

/// `layout/module-admin-multisig.bin` decoded. Nothing sets its owners after genesis.
pub const MODULE_ADMIN_RUNTIME: Bytes =
    Bytes::from_static(include_bytes!("module_admin_runtime.bin"));

/// The multisig's `address[3] _owners`, at slots 0..2.
pub const MODULE_ADMIN_OWNERS: usize = 3;
