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
//! The arithmetic lives in [`mmr`], which knows nothing of storage, ABI, events or gas. This
//! module is the boundary: it loads an [`Mmr`] from the slots, pushes, writes the one slot each
//! push lands in, and maps calls and events.

pub mod dispatch;
pub mod mmr;

use mmr::{Mmr, MmrError};
pub use mmr::{bag, hash_leaf, hash_merge};

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
        // Highest first, one per set bit of the count: the ABI's order, and the order a
        // carry pops from.
        let peaks = (0..256)
            .rev()
            .filter(|height| count.bit(*height))
            .map(|height| peak_slot(base, height).read())
            .collect::<Result<Vec<_>>>()?;
        debug_assert_eq!(peaks.len(), count.count_ones(), "a peak per set bit");
        Ok(Mmr {
            leaf_count: count,
            peaks,
        })
    }

    /// Pushes `node`, a perfect subtree of `height`, charging its merges and writing the one
    /// slot it lands in. The peaks it merged stay in their slots, stale — the count no longer
    /// names them — which is what keeps a height from paying state creation more than once.
    fn push(&mut self, base: U256, mmr: &mut Mmr, height: u8, node: B256) -> Result<()> {
        let pushed = mmr.push(height, node).map_err(mmr_error)?;
        self.storage.deduct_gas(HASH_COST * pushed.merges as u64)?;
        peak_slot(base, pushed.height).write(pushed.peak)
    }

    /// Stores the count and bags the live peaks into the root.
    fn close(&mut self, base: U256, mmr: &Mmr) -> Result<B256> {
        count_slot(base).write(mmr.leaf_count)?;
        self.bagged(&mmr.peaks)
    }

    /// The root over `peaks`, charged for the merges bagging them takes: one per peak after
    /// the first, and none at all for an empty MMR.
    fn bagged(&mut self, peaks: &[B256]) -> Result<B256> {
        let merges = peaks.len().saturating_sub(1) as u64;
        self.storage.deduct_gas(HASH_COST * merges)?;
        Ok(bag(peaks))
    }

    /// Returns the root of `namespace`'s MMR, or zero if nothing was ever appended.
    pub fn root(&mut self, call: IAnchoring::rootCall) -> Result<B256> {
        let mmr = self.open(base(call.namespace))?;
        self.bagged(&mmr.peaks)
    }

    /// Returns the leaf count and the peaks of `namespace`'s MMR.
    pub fn state(&self, call: IAnchoring::stateCall) -> Result<IAnchoring::stateReturn> {
        let mmr = self.open(base(call.namespace))?;
        Ok(IAnchoring::stateReturn {
            count: mmr.leaf_count,
            peaks: mmr.peaks,
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
        let first = mmr.leaf_count;

        self.push(base, &mut mmr, 0, hash_leaf(call.commitment))?;
        let root = self.close(base, &mmr)?;

        self.emit_event(AnchoringEvent::leaf_appended(
            msg_sender,
            first,
            call.commitment,
            mmr.peaks,
            call.metadata,
        ))?;
        Ok(root)
    }

    /// Appends a batch of aligned perfect subtrees to `msg_sender`'s MMR.
    ///
    /// # Errors
    /// - `ZeroChunkRoot` — a zero chunk root, which nothing hashes to
    /// - `ChunkNotAligned` — a chunk would land at a count that is not a multiple of its size
    pub fn append_leaves(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::appendLeavesCall,
    ) -> Result<B256> {
        if call.chunks.is_empty() {
            let mmr = self.open(base(msg_sender))?;
            return self.bagged(&mmr.peaks);
        }
        if call.chunks.iter().any(|chunk| chunk.root.is_zero()) {
            return Err(AnchoringError::zero_chunk_root().into());
        }

        let base = base(msg_sender);
        let mut mmr = self.open(base)?;
        let first = mmr.leaf_count;

        // Checked before anything is written, so a refused batch touches no slot.
        let heights: Vec<u8> = call.chunks.iter().map(|chunk| chunk.height).collect();
        mmr.validate(&heights).map_err(mmr_error)?;
        for chunk in &call.chunks {
            self.push(base, &mut mmr, chunk.height, chunk.root)?;
        }
        let root = self.close(base, &mmr)?;

        self.emit_event(AnchoringEvent::leaves_appended(
            msg_sender,
            first,
            mmr.leaf_count,
            call.chunks,
            mmr.peaks,
            call.metadata,
        ))?;
        Ok(root)
    }
}

/// The pure module's refusals as the precompile's errors.
fn mmr_error(err: MmrError) -> TempoPrecompileError {
    match err {
        MmrError::ChunkNotAligned { leaf_count, height } => {
            AnchoringError::chunk_not_aligned(leaf_count, U256::from(height)).into()
        }
        // `open` builds a peak per set bit, so a missing one cannot happen; the count
        // overflowing can, at 2^256 leaves.
        MmrError::CountOverflow | MmrError::PeakMissing => TempoPrecompileError::under_overflow(),
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
    use mmr::vectors::{ROOTS, c, perfect};
    use tempo_chainspec::hardfork::TempoHardfork;

    /// The namespace pinned by the reference vectors.
    const PINNED_NS: Address = address!("0x1111111111111111111111111111111111111111");

    fn with_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
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

    fn leaves_call(chunks: &[(u64, u64, u8)]) -> IAnchoring::appendLeavesCall {
        IAnchoring::appendLeavesCall {
            chunks: chunks
                .iter()
                .map(|(from, size, height)| IAnchoring::Chunk {
                    root: perfect(*from, *size),
                    height: *height,
                })
                .collect(),
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
            alloy::hex!("0x7150c2c6"),
            "appendLeaves((bytes32,uint8)[],bytes)"
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
            b256!("0x43a24f34ff55c61c25ca8f226ce1e940c9bc4ca4ef98253d9780a3cf29aa2262"),
            "LeafAppended(address,uint256,bytes32,bytes32[],bytes)"
        );
        assert_eq!(
            IAnchoring::LeavesAppended::SIGNATURE_HASH,
            b256!("0xa643a7916be4114a8d4f887b0606856c1f49b02a0a4374c775283987c1e12c2c"),
            "LeavesAppended(address,uint256,uint256,(bytes32,uint8)[],bytes32[],bytes)"
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
                assert_eq!(bag(&peaks), root, "the peaks bag to the root");
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

            // A fourth chunk off the alignment refuses the batch before the first is
            // written: the height-0 slot still holds the fifth leaf, not the sixth.
            let err = anchoring
                .append_leaves(
                    PINNED_NS,
                    leaves_call(&[(6, 1, 0), (7, 2, 1), (9, 2, 1), (11, 4, 2)]),
                )
                .unwrap_err();
            assert_eq!(
                err,
                AnchoringError::chunk_not_aligned(U256::from(10), U256::from(2)).into()
            );
            let lowest = StorageCtx.sload(ANCHORING_ADDRESS, base(PINNED_NS) + U256::ONE)?;
            assert_eq!(B256::from(lowest.to_be_bytes()), hash_leaf(c(5)));

            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, before);
            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }

    /// An empty batch is a no-op returning the current root; a zero chunk root is still
    /// refused because nothing hashes to it.
    #[test]
    fn empty_batch_is_a_noop_and_zero_chunk_root_is_refused() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            append_all(&mut anchoring, PINNED_NS, 1, 2)?;
            anchoring.clear_emitted_events();

            let root = anchoring.append_leaves(PINNED_NS, leaves_call(&[]))?;
            assert_eq!(root, ROOTS[1], "empty batch returns current root");
            assert_eq!(root_of(&mut anchoring, PINNED_NS)?, ROOTS[1], "unchanged");
            assert_eq!(state_of(&anchoring, PINNED_NS)?.0, U256::from(2));
            assert!(anchoring.emitted_events().is_empty());

            let mut call = leaves_call(&[(3, 1, 0)]);
            call.chunks[0].root = B256::ZERO;
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
                peaks,
                Bytes::from_static(b"provenance"),
            )]);
            anchoring.clear_emitted_events();

            // Seven more, as [6,8) h1, [8,12) h2, [12,13) h0, to thirteen.
            let call = leaves_call(&[(7, 2, 1), (9, 4, 2), (13, 1, 0)]);
            let chunks = call.chunks.clone();
            anchoring.append_leaves(PINNED_NS, call)?;
            let (count, peaks) = state_of(&anchoring, PINNED_NS)?;
            assert_eq!(count, U256::from(13));
            anchoring.assert_emitted_events(vec![AnchoringEvent::leaves_appended(
                PINNED_NS,
                U256::from(6),
                U256::from(13),
                chunks,
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
