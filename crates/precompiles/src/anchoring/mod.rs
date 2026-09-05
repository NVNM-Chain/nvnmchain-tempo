//! Caller-partitioned MMR precompile. Enabled at `TempoHardfork::T10`; see [`IAnchoring`] for
//! what it serves and how it hashes.
//!
//! State per namespace is the leaf count and one slot per peak height. A peak that merges away
//! is left in its slot rather than cleared — the count's bits say which are live — so a height
//! pays state creation once, when it is first reached, and every append after that only
//! overwrites. That is what makes an append need no witness: `log n` slots hold a tree of any
//! size, where a slot per key made every key cost a fresh one.
//!
//! Inherited from the `x/anchoring` precompile at the same address but not ABI-compatible with
//! it. Its records and registries become leaves a wrapper contract shapes and an indexer reads
//! back out of the log; its roles have no successor here at all.
//!
//! The append algorithm itself lives in [`mmr`] and is pure: no storage, ABI structs, events,
//! or gas. This module is the EVM/ABI boundary — it loads a [`Mmr`] from EVM slots, runs the
//! pure operations, persists the result, and maps ABI calls/events.

pub mod dispatch;
pub mod mmr;

pub use mmr::{Mmr, MmrError, bag, hash_leaf, hash_merge};

use crate::{
    ANCHORING_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Slot},
};
use alloy::primitives::{Address, B256, U256, keccak256};
pub use tempo_contracts::precompiles::{AnchoringError, AnchoringEvent, IAnchoring};
use tempo_precompiles_macros::contract;

/// Domain tag for the slot derivation. Prefixing the preimage leaves the rest of the space
/// free for future domains, so a later addition never collides with a namespace's MMR.
const DOMAIN_MMR: u8 = 0x01;

/// Gas per hash of the tree, mirroring `KECCAK256` on a three-word input (30 + 6 per word),
/// so a merge is never cheaper here than the same hash in a contract. Charged for the work
/// that grows with the tree — each merge, and each step of bagging the peaks; the one leaf
/// hash a call makes rides with the calldata it came in on.
const HASH_COST: u64 = 48;

/// Where `namespace`'s MMR lives:
///
/// ```text
/// base(ns)          = keccak256(0x01 ‖ pad32(ns))    the leaf count
/// base(ns) + 1 + h                                    the peak of height h
/// ```
///
/// Derived once per call and passed down, rather than per slot: it is a keccak, and a call
/// touching eight peaks would otherwise take it eight times over.
fn base(namespace: Address) -> U256 {
    let mut preimage = [0u8; 33];
    preimage[0] = DOMAIN_MMR;
    preimage[1..].copy_from_slice(namespace.into_word().as_slice());
    U256::from_be_bytes(keccak256(preimage).0)
}

fn count_slot(base: U256) -> Slot<U256> {
    Slot::new(base, ANCHORING_ADDRESS)
}

/// Wrapping, so a base near the top of the space still addresses 256 peaks. Two namespaces
/// colliding there needs a keccak collision.
fn peak_slot(base: U256, height: usize) -> Slot<B256> {
    Slot::new(base.wrapping_add(U256::from(1 + height)), ANCHORING_ADDRESS)
}

/// Caller-partitioned MMR. Its storage is derived rather than declared, so it has no fields
/// of its own — see [`base`] for the layout.
#[contract(addr = ANCHORING_ADDRESS)]
pub struct Anchoring {}

impl Anchoring {
    /// Initializes the anchoring contract by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Reads `base`'s MMR. Reads go through [`Slot`], so they are metered and journalled like
    /// any other precompile storage.
    fn open(&self, base: U256) -> Result<Mmr> {
        let count = count_slot(base).read()?;
        // The pure accumulator stores peaks by increasing height, matching the Lean spec.
        // The EVM slot layout already stores each live peak at its own height; walking the
        // count's set bits in ascending order gives the spec's ordering for free.
        let peaks = (0..256)
            .filter(|height| count.bit(*height))
            .map(|height| peak_slot(base, height).read())
            .collect::<Result<Vec<_>>>()?;
        Ok(Mmr::from_parts(count, peaks))
    }

    /// The root over `peaks`, charged for the merges bagging them takes: one per peak after
    /// the first, and none at all for an empty MMR.
    fn bagged(&mut self, peaks: &[B256]) -> Result<B256> {
        let merges = peaks.len().saturating_sub(1) as u64;
        self.storage.deduct_gas(HASH_COST * merges)?;
        Ok(bag(peaks.iter()))
    }

    /// Returns the root of `namespace`'s MMR, or zero if nothing was ever appended.
    pub fn root(&mut self, call: IAnchoring::rootCall) -> Result<B256> {
        let mmr = self.open(base(call.namespace))?;
        let merges = mmr.peaks_newest_first().len().saturating_sub(1) as u64;
        self.storage.deduct_gas(HASH_COST * merges)?;
        Ok(mmr.root())
    }

    /// Returns the leaf count and the peaks of `namespace`'s MMR.
    pub fn state(&self, call: IAnchoring::stateCall) -> Result<IAnchoring::stateReturn> {
        let mmr = self.open(base(call.namespace))?;
        let count = mmr.leaf_count();
        Ok(IAnchoring::stateReturn {
            count,
            peaks: mmr.into_peaks_highest_first(),
        })
    }

    /// Appends one leaf to `msg_sender`'s MMR.
    pub fn append_leaf(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::appendLeafCall,
    ) -> Result<B256> {
        let base = base(msg_sender);
        let mut mmr = self.open(base)?;
        let first = mmr.leaf_count();

        let outcome = mmr
            .append_leaf_tracked(hash_leaf(call.commitment))
            .map_err(mmr_error)?;
        self.storage.deduct_gas(HASH_COST * outcome.merges as u64)?;
        peak_slot(base, outcome.height).write(outcome.peak)?;

        let count = mmr.leaf_count();
        let peaks = mmr.into_peaks_highest_first();
        let root = self.bagged(&peaks)?;
        count_slot(base).write(count)?;

        self.emit_event(AnchoringEvent::leaf_appended(
            msg_sender,
            first,
            call.commitment,
            root,
            peaks,
            call.metadata,
        ))?;
        Ok(root)
    }

    /// Appends a batch of aligned perfect subtrees to `msg_sender`'s MMR.
    ///
    /// # Errors
    /// - `ChunksMismatch` — the roots and heights differ in length
    /// - `EmptyBatch` — no chunks
    /// - `ZeroChunkRoot` — a zero chunk root, which nothing hashes to
    /// - `ChunkNotAligned` — a chunk would land at a count that is not a multiple of its size
    pub fn append_leaves(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::appendLeavesCall,
    ) -> Result<B256> {
        if call.chunkRoots.len() != call.chunkHeights.len() {
            return Err(AnchoringError::chunks_mismatch().into());
        }
        if call.chunkRoots.is_empty() {
            return Err(AnchoringError::empty_batch().into());
        }
        if call.chunkRoots.contains(&B256::ZERO) {
            return Err(AnchoringError::zero_chunk_root().into());
        }

        let base = base(msg_sender);
        let mut mmr = self.open(base)?;
        let first = mmr.leaf_count();

        // Each push reports exactly the slot it lands in. A peak merged away by a later
        // push is left stale in its slot; the count's bits no longer name it.
        //
        // If a later chunk turns out to be misaligned, earlier peak slots may already be
        // written; the EVM journal reverts the whole precompile frame on the returned error.
        for (root, height) in call.chunkRoots.iter().zip(&call.chunkHeights) {
            let outcome = mmr.append_peak_tracked(*height, *root).map_err(mmr_error)?;
            self.storage.deduct_gas(HASH_COST * outcome.merges as u64)?;
            peak_slot(base, outcome.height).write(outcome.peak)?;
        }

        let count = mmr.leaf_count();
        let peaks = mmr.into_peaks_highest_first();
        let root = self.bagged(&peaks)?;
        count_slot(base).write(count)?;

        self.emit_event(AnchoringEvent::leaves_appended(
            msg_sender,
            first,
            count,
            call.chunkRoots,
            call.chunkHeights,
            root,
            peaks,
            call.metadata,
        ))?;
        Ok(root)
    }
}

/// Maps a pure accumulator error to the precompile's top-level error type.
fn mmr_error(err: MmrError) -> TempoPrecompileError {
    match err {
        MmrError::ChunkNotAligned { leaf_count, height } => {
            AnchoringError::chunk_not_aligned(leaf_count, U256::from(height)).into()
        }
        MmrError::CountOverflow => TempoPrecompileError::under_overflow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::{
        primitives::{Bytes, U256, address, b256},
        sol_types::{SolCall, SolEvent},
    };
    use tempo_chainspec::hardfork::TempoHardfork;

    /// The namespace pinned by the reference vectors.
    const PINNED_NS: Address = address!("0x1111111111111111111111111111111111111111");

    /// Roots computed independently, in Python with keccak, over the commitments
    /// `bytes32(1)`, `bytes32(2)`, … appended in that order. The Solidity verifier's suite
    /// pins the same sixteen, which is what keeps the two implementations agreeing.
    const ROOTS: [B256; 16] = [
        b256!("0x5786039c2502cb1b5ff9a9f0b0b6957bb8b3f6489d20080f677236b2dd590dcd"),
        b256!("0x9950fe45570c3e4c9c0241de506d53ba63bb5b4ceb7b3c0032148e32f1ab3d9d"),
        b256!("0x036e11a04c28d071bc9b3961be683ff7eac4aad9234b6a21904de44b952cb3c9"),
        b256!("0x9a444d98cfab773b89efcfe3749342cd1b072e8f2276f9f822fb1e19edabb77b"),
        b256!("0xbbd0ad9fcc22a20f7adc962f214aba7710aed4d06063e7d722d65d07920a269d"),
        b256!("0x950d9243a18618ebce2f7906ead2e5c9cfe719359d7b8635cf52ee4995c53631"),
        b256!("0x237757481f6015968d2dd6b7784aa544f822d29f6a520bfae222c79c16051c14"),
        b256!("0x2a43055cc8a7bb9202beebc4603c13e920c9c7f7e3bf26ca5178aad751d5b29e"),
        b256!("0x8948ab91036932c2798daf8808b183438f08a6acb56cae4fe3d0db2ff999fd11"),
        b256!("0x0dcc0e544f9c3d0d78a0b030257eb964bc1756e786ede2c565c24817885bee6c"),
        b256!("0xbbe8d27929385c3988405fe38bf7a82136581ef7ea7a2f71634d9785eddaf1d7"),
        b256!("0xd3ebf5629b714dde40059d9dd0bb940d3748ead5953aa63d5d7cc867354b28fa"),
        b256!("0xbc438a6c52d1d3f2abea81fdd299bdfb9c8961b03e2adbeeff075db74971b2ae"),
        b256!("0xd41583f4d63289dafc25e7b5beaefe0f1e453fe2b9f0ba50cdfa96e27689c9fe"),
        b256!("0x7d75dea0b9798ddaa25f8a0d0e6222784f6ad299617a9128e7d75af3bf5eb81e"),
        b256!("0xc60e652673b4bff570b066c5513bf939b9a69b21c5ad6802f3579166b660c2c2"),
    ];

    fn with_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
    }

    fn c(i: u64) -> B256 {
        B256::from(U256::from(i))
    }

    fn root_of(anchoring: &mut Anchoring, namespace: Address) -> Result<B256> {
        anchoring.root(IAnchoring::rootCall { namespace })
    }

    fn state_of(anchoring: &Anchoring, namespace: Address) -> Result<(U256, Vec<B256>)> {
        let state = anchoring.state(IAnchoring::stateCall { namespace })?;
        Ok((state.count, state.peaks))
    }

    /// Appends `c(from)..=c(to)` one by one.
    fn append_all(anchoring: &mut Anchoring, ns: Address, from: u64, to: u64) -> eyre::Result<()> {
        for i in from..=to {
            anchoring.append_leaf(
                ns,
                IAnchoring::appendLeafCall {
                    commitment: c(i),
                    metadata: Bytes::new(),
                },
            )?;
        }
        Ok(())
    }

    /// The root of a perfect tree over commitments `from .. from+size`, as a caller cuts a batch.
    fn perfect(from: u64, size: u64) -> B256 {
        let mut nodes: Vec<B256> = (0..size).map(|i| hash_leaf(c(from + i))).collect();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|pair| hash_merge(pair[0], pair[1]))
                .collect();
        }
        nodes[0]
    }

    fn leaves_call(chunks: &[(u64, u64, u8)]) -> IAnchoring::appendLeavesCall {
        IAnchoring::appendLeavesCall {
            chunkRoots: chunks
                .iter()
                .map(|(from, size, _)| perfect(*from, *size))
                .collect(),
            chunkHeights: chunks.iter().map(|(_, _, h)| *h).collect(),
            metadata: Bytes::new(),
        }
    }

    /// Reference vectors. A change here is an ABI break for every indexer.
    #[test]
    fn abi_constants_are_pinned() {
        assert_eq!(
            IAnchoring::appendLeafCall::SELECTOR,
            alloy::hex!("0xe5435d9a"),
            "appendLeaf(bytes32,bytes)"
        );
        assert_eq!(
            IAnchoring::appendLeavesCall::SELECTOR,
            alloy::hex!("0x1afcfa4f"),
            "appendLeaves(bytes32[],uint8[],bytes)"
        );
        assert_eq!(
            IAnchoring::rootCall::SELECTOR,
            alloy::hex!("0x6e5ac882"),
            "root(address)"
        );
        assert_eq!(
            IAnchoring::stateCall::SELECTOR,
            alloy::hex!("0x31e658a5"),
            "state(address)"
        );
        assert_eq!(
            IAnchoring::LeafAppended::SIGNATURE_HASH,
            b256!("0x299ee3fc8eecbb10ce273b5329c6e4f095c550dc1bc7e1756bd6303da53cf12a"),
            "LeafAppended(address,uint256,bytes32,bytes32,bytes32[],bytes)"
        );
        assert_eq!(
            IAnchoring::LeavesAppended::SIGNATURE_HASH,
            b256!("0x07d3a61ef7a792265f84d9a96ef8168c654dd0d610d83034971ce6c68c30a378"),
            "LeavesAppended(address,uint256,uint256,bytes32[],uint8[],bytes32,bytes32[],bytes)"
        );
        assert_eq!(
            ANCHORING_ADDRESS,
            address!("0x0000000000000000000000000000000000000a00")
        );
    }

    /// Pins the slot layout. Off-chain tooling reconstructs slots from this rule, so a
    /// change here breaks every such consumer.
    #[test]
    fn slot_layout_is_pinned() -> eyre::Result<()> {
        let preimage = [&[DOMAIN_MMR][..], PINNED_NS.into_word().as_slice()].concat();
        let base = keccak256(preimage);
        assert_eq!(
            base,
            b256!("0xb33ae4174b6ee0d698ac7fb0b98c2e8dd60d6062831f17c8355acb09a12e0c4f")
        );

        // Three leaves: count 3 = peaks at heights 1 and 0, the height-0 slot written twice.
        let base = U256::from_be_bytes(base.0);
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 3)?;

            assert_eq!(
                StorageCtx.sload(ANCHORING_ADDRESS, base)?,
                U256::from(3),
                "count"
            );
            let peak = |h: u64| StorageCtx.sload(ANCHORING_ADDRESS, base + U256::from(1 + h));
            assert_eq!(B256::from(peak(0)?.to_be_bytes()), hash_leaf(c(3)));
            assert_eq!(
                B256::from(peak(1)?.to_be_bytes()),
                hash_merge(hash_leaf(c(1)), hash_leaf(c(2)))
            );
            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, ROOTS[2]);
            Ok(())
        })
    }

    #[test]
    fn untouched_namespace_reads_empty() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            assert_eq!(root_of(&mut anchoring, ns)?, B256::ZERO);
            assert_eq!(state_of(&anchoring, ns)?, (U256::ZERO, vec![]));
            Ok(())
        })
    }

    #[test]
    fn sequential_appends_reach_the_reference_roots() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            for i in 1..=16u64 {
                let root = anchoring.append_leaf(
                    PINNED_NS,
                    IAnchoring::appendLeafCall {
                        commitment: c(i),
                        metadata: Bytes::new(),
                    },
                )?;
                assert_eq!(
                    root,
                    ROOTS[i as usize - 1],
                    "root after leaf {i}, as returned"
                );
                assert_eq!(root_of(&mut anchoring, PINNED_NS)?, root, "as read");
                let (count, peaks) = state_of(&anchoring, PINNED_NS)?;
                assert_eq!(count, U256::from(i));
                assert_eq!(peaks.len(), i.count_ones() as usize);
                assert_eq!(bag(peaks.iter()), root, "the peaks bag to the root");
            }
            Ok(())
        })
    }

    /// A peak that merged away stays in its slot, and the count is what says it is stale:
    /// the fourth leaf leaves heights 0 and 1 holding old values that no read returns.
    #[test]
    fn stale_peaks_are_left_in_place_and_never_read() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 4)?;
            let (count, peaks) = state_of(&anchoring, PINNED_NS)?;
            assert_eq!(count, U256::from(4));
            assert_eq!(peaks, vec![perfect(1, 4)], "one live peak");

            let base = base(PINNED_NS);
            let stale = StorageCtx.sload(ANCHORING_ADDRESS, base + U256::ONE)?;
            assert_eq!(
                B256::from(stale.to_be_bytes()),
                hash_leaf(c(3)),
                "left behind"
            );

            // The next leaf overwrites height 0 rather than creating it.
            append_all(&mut anchoring, PINNED_NS, 5, 5)?;
            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, ROOTS[4]);
            Ok(())
        })
    }

    #[test]
    fn a_batch_from_empty_reaches_the_sequential_root() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            // 13 leaves cut aligned from zero: sizes 8, 4, 1.
            let root = anchoring
                .append_leaves(PINNED_NS, leaves_call(&[(1, 8, 3), (9, 4, 2), (13, 1, 0)]))?;
            assert_eq!(root, ROOTS[12], "one call, thirteen leaves");
            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, ROOTS[12]);
            assert_eq!(state_of(&anchoring, PINNED_NS)?.0, U256::from(13));
            Ok(())
        })
    }

    #[test]
    fn a_batch_after_a_prefix_is_cut_to_the_alignment() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            // Five leaves one by one, then eight more: [5,6) h0, [6,8) h1, [8,12) h2, [12,13) h0.
            append_all(&mut anchoring, PINNED_NS, 1, 5)?;
            anchoring.append_leaves(
                PINNED_NS,
                leaves_call(&[(6, 1, 0), (7, 2, 1), (9, 4, 2), (13, 1, 0)]),
            )?;
            assert_eq!(
                root_of(&mut anchoring, PINNED_NS)?,
                ROOTS[12],
                "sizes rise to the boundary and fall after it"
            );
            Ok(())
        })
    }

    #[test]
    fn a_chunk_off_the_alignment_is_refused() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 5)?;
            anchoring.clear_emitted_events();
            let before = root_of(&mut anchoring, PINNED_NS)?;

            // A pair at count 5: 5 % 2 != 0.
            let err = anchoring
                .append_leaves(PINNED_NS, leaves_call(&[(6, 2, 1)]))
                .unwrap_err();
            assert_eq!(
                err,
                AnchoringError::chunk_not_aligned(U256::from(5), U256::from(1)).into()
            );
            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, before);
            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }

    /// A later chunk failing alignment leaves partial writes when calling the in-memory API
    /// directly, but an outer EVM journal snapshot reverts the whole frame.  Simulate that
    /// snapshot here with an explicit checkpoint.
    #[test]
    fn a_later_misaligned_chunk_is_reverted_by_a_snapshot() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 5)?;
            anchoring.clear_emitted_events();
            let before = root_of(&mut anchoring, PINNED_NS)?;
            let (before_count, before_peaks) = state_of(&anchoring, PINNED_NS)?;

            let err = {
                let mut ctx = StorageCtx;
                let _guard = ctx.checkpoint();
                anchoring
                    .append_leaves(
                        PINNED_NS,
                        leaves_call(&[(6, 1, 0), (7, 2, 1), (9, 2, 1), (11, 4, 2)]),
                    )
                    .unwrap_err()
            };
            assert_eq!(
                err,
                AnchoringError::chunk_not_aligned(U256::from(10), U256::from(2)).into()
            );

            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, before);
            assert_eq!(
                state_of(&anchoring, PINNED_NS)?,
                (before_count, before_peaks)
            );
            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }

    #[test]
    fn mismatched_chunk_lists_are_refused() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let mut call = leaves_call(&[(1, 1, 0)]);
            call.chunkHeights.clear();
            let err = anchoring.append_leaves(PINNED_NS, call).unwrap_err();
            assert_eq!(err, AnchoringError::chunks_mismatch().into());
            Ok(())
        })
    }

    /// The two shapes that pass the length check and still say nothing: no chunks would
    /// change nothing but the log, and a zero chunk root would read back as an empty tree's.
    #[test]
    fn an_empty_batch_and_a_zero_chunk_root_are_refused() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 2)?;
            anchoring.clear_emitted_events();

            let err = anchoring
                .append_leaves(PINNED_NS, leaves_call(&[]))
                .unwrap_err();
            assert_eq!(err, AnchoringError::empty_batch().into());

            let mut call = leaves_call(&[(3, 1, 0)]);
            call.chunkRoots[0] = B256::ZERO;
            let err = anchoring.append_leaves(PINNED_NS, call).unwrap_err();
            assert_eq!(err, AnchoringError::zero_chunk_root().into());

            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, ROOTS[1], "untouched");
            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }

    /// Both events carry the peaks and where the leaves landed, so a proof needs the log
    /// and nothing else.
    #[test]
    fn events_carry_the_mmr_state() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 5)?;
            anchoring.clear_emitted_events();

            let root = anchoring.append_leaf(
                PINNED_NS,
                IAnchoring::appendLeafCall {
                    commitment: c(6),
                    metadata: Bytes::from_static(b"provenance"),
                },
            )?;
            assert_eq!(root, ROOTS[5]);
            let (_, peaks) = state_of(&anchoring, PINNED_NS)?;
            anchoring.assert_emitted_events(vec![AnchoringEvent::leaf_appended(
                PINNED_NS,
                U256::from(5),
                c(6),
                ROOTS[5],
                peaks,
                Bytes::from_static(b"provenance"),
            )]);
            anchoring.clear_emitted_events();

            // Seven more, as [6,8) h1, [8,12) h2, [12,13) h0, to thirteen.
            let call = leaves_call(&[(7, 2, 1), (9, 4, 2), (13, 1, 0)]);
            let (chunk_roots, chunk_heights) = (call.chunkRoots.clone(), call.chunkHeights.clone());
            anchoring.append_leaves(PINNED_NS, call)?;
            let (count, peaks) = state_of(&anchoring, PINNED_NS)?;
            assert_eq!(count, U256::from(13));
            anchoring.assert_emitted_events(vec![AnchoringEvent::leaves_appended(
                PINNED_NS,
                U256::from(6),
                U256::from(13),
                chunk_roots,
                chunk_heights,
                ROOTS[12],
                peaks,
                Bytes::new(),
            )]);
            Ok(())
        })
    }

    /// Namespaces are partitioned by `msg_sender`: one account's appends never reach another's,
    /// and each starts from empty.
    #[test]
    fn namespaces_are_isolated() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let (alice, bob) = (Address::random(), Address::random());
            append_all(&mut anchoring, alice, 1, 3)?;
            append_all(&mut anchoring, bob, 1, 1)?;

            assert_eq!(root_of(&mut anchoring, alice)?, ROOTS[2]);
            assert_eq!(root_of(&mut anchoring, bob)?, ROOTS[0]);
            assert_eq!(anchoring.emitted_events().len(), 4);
            Ok(())
        })
    }
}
