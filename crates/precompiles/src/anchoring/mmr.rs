//! Pure in-memory MMR accumulator.
//!
//! This module mirrors the minimal MMR from [lean-mmr](https://github.com/yihuang/lean-mmr):
//!
//! * an accumulator stores only `leaf_count` and `peaks`;
//! * `peaks` are stored highest-first (oldest/leftmost first) so a `Vec` can use O(1)
//!   `push`/`pop` on the end where appends and carries happen; this is the reverse of
//!   Lean's `Acc.peaks` ordering but the same carry-merge algorithm;
//! * appending a subtree of `height` is the binary carry-merge
//!   `mergeCarry (trailingOnes (leaf_count / 2^height))`;
//! * the aligned precondition (`leaf_count % 2^height = 0`) is what makes a push the
//!   canonical extension of the leaf history.  It is enforced here because the EVM
//!   precompile must never produce a non-append-only MMR.
//!
//! The module intentionally has no dependency on EVM storage, ABI structs, events, or
//! gas accounting.  The EVM layer loads a [`Mmr`] from storage, applies these pure
//! operations, and then persists the resulting accumulator.

use alloy::primitives::{B256, U256, keccak256};

/// `keccak256("leaf" ‖ commitment)`.
pub fn hash_leaf(commitment: B256) -> B256 {
    keccak256([b"leaf" as &[u8], commitment.as_slice()].concat())
}

/// `keccak256("merge" ‖ left ‖ right)`.
pub fn hash_merge(left: B256, right: B256) -> B256 {
    keccak256([b"merge" as &[u8], left.as_slice(), right.as_slice()].concat())
}

/// The peaks bagged from the highest down; zero when there are none.
pub fn bag(peaks: &[B256]) -> B256 {
    let Some((first, rest)) = peaks.split_first() else {
        return B256::ZERO;
    };
    rest.iter().fold(*first, |acc, peak| {
        keccak256([b"bag" as &[u8], acc.as_slice(), peak.as_slice()].concat())
    })
}

/// Returns whether `leaf_count` is a multiple of subtree `size` (`2^height`).
///
/// This is the aligned condition from the Lean spec, `leaf_count % 2^height = 0`.  The
/// bitmask form is equivalent because `size` is a power of two.
#[inline]
pub fn aligned_at(leaf_count: U256, size: U256) -> bool {
    leaf_count & (size - U256::ONE) == U256::ZERO
}

/// Pure algorithm error.  These are deliberately separate from the ABI's `AnchoringError`
/// so the core can be reasoned about and tested without generated Solidity interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmrError {
    /// A chunk of `height` cannot be appended at `leaf_count` because the count is not
    /// a multiple of `2^height`.
    ChunkNotAligned { leaf_count: U256, height: u8 },
    /// Adding the chunk would make the leaf count overflow `U256`.
    CountOverflow,
    /// Internal invariant violation: the peak list did not contain a live peak.
    InvalidState,
}

/// The slot write produced by one append: the peak that must be persisted at `height`.
///
/// Returning this from the pure operation lets the EVM layer write exactly the touched
/// peak slot without cloning the whole old MMR or diffing every live peak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendPeakOutcome {
    /// Number of merge hashes performed by this append.
    pub merges: usize,
    /// Height of the peak slot to persist.
    pub height: usize,
    /// Peak hash to persist at `height`.
    pub peak: B256,
}

/// A minimal MMR accumulator.
///
/// `peaks` are ordered highest-first to match the ABI/event ordering and to let `Vec`
/// append/carry with O(1) `push`/`pop`.  The Lean `MMR.Acc` uses the reverse order; the
/// algorithm is otherwise identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mmr {
    /// The number of leaves appended so far.
    pub leaf_count: U256,
    /// Live peaks ordered highest-first.
    pub peaks: Vec<B256>,
}

impl Default for Mmr {
    fn default() -> Self {
        Self {
            leaf_count: U256::ZERO,
            peaks: Vec::new(),
        }
    }
}

impl Mmr {
    /// Creates an empty MMR.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The canonical root: the live peaks bagged highest first; zero when empty.
    pub fn root(&self) -> B256 {
        bag(&self.peaks)
    }

    /// Whether a subtree of `height` is aligned with this accumulator.
    pub fn is_aligned(&self, height: u8) -> bool {
        aligned_at(self.leaf_count, U256::ONE << usize::from(height))
    }

    /// The `ValidChunk` predicate from the Lean spec: every chunk must be aligned at the
    /// count it would see when pushed.  Roots are ignored; only heights and the count
    /// matter for alignment.
    pub fn valid_chunk(&self, chunks: &[(u8, B256)]) -> bool {
        self.validate_chunks(chunks).is_ok()
    }

    /// Count-only validation of an ordered batch.  It returns the first alignment or
    /// overflow error without mutating `self`, so an invalid batch can be rejected
    /// before any storage write.
    pub fn validate_chunks(&self, chunks: &[(u8, B256)]) -> Result<(), MmrError> {
        let mut count = self.leaf_count;
        for &(height, _) in chunks {
            let size = U256::ONE << usize::from(height);
            if !aligned_at(count, size) {
                return Err(MmrError::ChunkNotAligned {
                    leaf_count: count,
                    height,
                });
            }
            count = count.checked_add(size).ok_or(MmrError::CountOverflow)?;
        }
        Ok(())
    }

    /// Appends one leaf (height 0).
    ///
    /// Returns the number of merge hashes performed.
    pub fn append_leaf(&mut self, leaf: B256) -> Result<usize, MmrError> {
        Ok(self.append_leaf_tracked(leaf)?.merges)
    }

    /// Appends one leaf and reports the peak slot that must be persisted.
    pub fn append_leaf_tracked(&mut self, leaf: B256) -> Result<AppendPeakOutcome, MmrError> {
        self.append_peak_tracked(0, leaf)
    }

    /// Appends a perfect subtree of `2^height` leaves whose root is `peak`.
    ///
    /// This is the `appendPeak` from the Lean formalization.  Alignment is required:
    /// without it the resulting state is not the canonical MMR of any leaf history and
    /// append-only semantics are lost.
    ///
    /// Returns the number of merge hashes performed.
    pub fn append_peak(&mut self, height: u8, peak: B256) -> Result<usize, MmrError> {
        Ok(self.append_peak_tracked(height, peak)?.merges)
    }

    /// Appends a perfect subtree and reports the peak slot that must be persisted.
    pub fn append_peak_tracked(
        &mut self,
        height: u8,
        peak: B256,
    ) -> Result<AppendPeakOutcome, MmrError> {
        let height = usize::from(height);
        let size = U256::ONE << height;

        if !aligned_at(self.leaf_count, size) {
            return Err(MmrError::ChunkNotAligned {
                leaf_count: self.leaf_count,
                height: height as u8,
            });
        }

        let new_leaf_count = self
            .leaf_count
            .checked_add(size)
            .ok_or(MmrError::CountOverflow)?;

        let mut node = peak;
        let mut merges = 0;
        let mut carry_height = height;
        while self.leaf_count.bit(carry_height) {
            // `peaks` is highest-first, so the low peak being absorbed is at the end.
            let left = self.peaks.pop().ok_or(MmrError::InvalidState)?;
            node = hash_merge(left, node);
            merges += 1;
            carry_height += 1;
        }

        self.peaks.push(node);
        self.leaf_count = new_leaf_count;
        Ok(AppendPeakOutcome {
            merges,
            height: carry_height,
            peak: node,
        })
    }

    /// Appends an ordered batch of aligned perfect subtrees.
    ///
    /// Chunks are applied in order and each chunk is individually alignment-checked.
    /// This is intentionally not atomic: if a later chunk is invalid, earlier chunks have
    /// already been applied.  Callers that need all-or-nothing semantics should clone first
    /// or rely on an outer snapshot such as the EVM journal.
    ///
    /// Returns the total number of merge hashes performed.
    pub fn append_peaks(&mut self, chunks: &[(u8, B256)]) -> Result<usize, MmrError> {
        let mut merges = 0;
        for &(height, peak) in chunks {
            merges += self.append_peak(height, peak)?;
        }
        Ok(merges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::b256;
    use proptest::prelude::*;

    fn c(i: u64) -> B256 {
        B256::from(U256::from(i))
    }

    /// Roots for sequential leaves 1..=16, from the EVM reference vectors.
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

    /// Root of a perfect tree over the given leaf hashes.
    fn root_of_leaves(leaves: &[B256]) -> B256 {
        let mut nodes = leaves.to_vec();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|pair| hash_merge(pair[0], pair[1]))
                .collect();
        }
        nodes[0]
    }

    /// Root of a perfect tree over commitments `from..from+size`.
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

    #[test]
    fn aligned_at_matches_the_lean_modulo_spec() {
        let counts = [
            U256::ZERO,
            U256::from(1u64),
            U256::from(2u64),
            U256::from(3u64),
            U256::from(4u64),
            U256::from(5u64),
            U256::from(7u64),
            U256::from(8u64),
            U256::from(13u64),
            U256::from(255u64),
            U256::from(256u64),
        ];
        for count in counts {
            for height in 0..=8u8 {
                let size = U256::ONE << usize::from(height);
                assert_eq!(
                    aligned_at(count, size),
                    count % size == U256::ZERO,
                    "aligned_at({count}, {size}) must match `leafCount % 2^height = 0`"
                );
            }
        }
    }

    proptest! {
        #[test]
        fn sequential_appends_preserve_invariants(
            leaves in prop::collection::vec(any::<[u8; 32]>().prop_map(B256::from), 0..64),
        ) {
            let mut mmr = Mmr::empty();
            for leaf in leaves {
                mmr.append_leaf(leaf).unwrap();
                prop_assert_eq!(mmr.peaks.len(), mmr.leaf_count.count_ones());
                prop_assert_eq!(mmr.root(), bag(&mmr.peaks));
            }
        }

        #[test]
        fn aligned_batch_matches_sequential_appends(
            leaves in prop::collection::vec(any::<[u8; 32]>().prop_map(B256::from), 0..128),
        ) {
            let mut sequential = Mmr::empty();
            for &leaf in &leaves {
                sequential.append_leaf(leaf).unwrap();
            }

            let mut chunks = Vec::new();
            let mut offset = 0usize;
            let mut remaining = leaves.len();
            while remaining > 0 {
                let height = remaining.ilog2() as usize;
                let size = 1usize << height;
                chunks.push((height as u8, root_of_leaves(&leaves[offset..offset + size])));
                offset += size;
                remaining -= size;
            }

            let mut batched = Mmr::empty();
            batched.append_peaks(&chunks).unwrap();
            prop_assert_eq!(batched.clone(), sequential.clone());
            prop_assert_eq!(batched.root(), sequential.root());
        }
    }

    #[test]
    fn empty_mmr_has_zero_root_and_accepts_any_alignment() {
        let mmr = Mmr::empty();
        assert_eq!(mmr.leaf_count, U256::ZERO);
        assert!(mmr.peaks.is_empty());
        assert_eq!(mmr.root(), B256::ZERO);
        assert!(mmr.is_aligned(0));
        assert!(mmr.is_aligned(1));
        assert!(mmr.is_aligned(255));
    }

    #[test]
    fn sequential_appends_reach_reference_roots() {
        let mut mmr = Mmr::empty();
        for i in 1..=16u64 {
            mmr.append_leaf(hash_leaf(c(i))).unwrap();
            assert_eq!(mmr.root(), ROOTS[i as usize - 1]);
        }
        assert_eq!(mmr.leaf_count, U256::from(16));
    }

    #[test]
    fn peaks_are_kept_in_highest_first_order() {
        let mut mmr = Mmr::empty();
        for i in 1..=5u64 {
            mmr.append_leaf(hash_leaf(c(i))).unwrap();
        }

        // count 5 (0b101): live peaks are heights 2 and 0, highest first.
        assert_eq!(mmr.leaf_count, U256::from(5));
        assert_eq!(mmr.peaks.len(), 2);
        assert_eq!(mmr.peaks[0], perfect(1, 4));
        assert_eq!(mmr.peaks[1], hash_leaf(c(5)));
    }

    #[test]
    fn a_batch_from_empty_reaches_sequential_root() {
        let mut mmr = Mmr::empty();
        let chunks = [
            (3, perfect(1, 8)),
            (2, perfect(9, 4)),
            (0, hash_leaf(c(13))),
        ];
        let merges = mmr.append_peaks(&chunks).unwrap();
        assert_eq!(
            merges, 0,
            "these aligned chunks are already perfect boundaries"
        );
        assert_eq!(mmr.leaf_count, U256::from(13));
        assert_eq!(mmr.root(), ROOTS[12]);
    }

    #[test]
    fn valid_chunk_matches_append_only_alignment() {
        let mmr = Mmr::empty();
        let valid = [
            (3, perfect(1, 8)),
            (2, perfect(9, 4)),
            (0, hash_leaf(c(13))),
        ];
        assert!(mmr.valid_chunk(&valid));

        let mut one_leaf = Mmr::empty();
        one_leaf.append_leaf(hash_leaf(c(1))).unwrap();
        assert!(!one_leaf.valid_chunk(&[(1, hash_leaf(c(2)))]));
    }

    #[test]
    fn misaligned_batch_is_rejected_without_mutation() {
        let mut mmr = Mmr::empty();
        mmr.append_leaf(hash_leaf(c(1))).unwrap();
        let before = mmr.clone();

        let err = mmr.append_peaks(&[(1, hash_leaf(c(2)))]).unwrap_err();
        assert_eq!(
            err,
            MmrError::ChunkNotAligned {
                leaf_count: U256::ONE,
                height: 1
            }
        );
        assert_eq!(mmr, before);
    }

    #[test]
    fn later_misalignment_is_reported_after_applying_the_valid_prefix() {
        let mut mmr = Mmr::empty();
        let chunks = [
            (0, hash_leaf(c(1))),
            (0, hash_leaf(c(2))),
            (1, perfect(3, 2)),
            (0, hash_leaf(c(5))),
            (1, perfect(6, 2)), // count 5 is not a multiple of 2
        ];
        let err = mmr.append_peaks(&chunks).unwrap_err();
        assert_eq!(
            err,
            MmrError::ChunkNotAligned {
                leaf_count: U256::from(5),
                height: 1
            }
        );
        // Non-atomic by design: callers clone first for all-or-nothing semantics.
        assert_eq!(mmr.leaf_count, U256::from(5));
    }

    #[test]
    fn clone_in_advance_gives_atomic_batch_semantics() {
        let mmr = Mmr::empty();
        let chunks = [
            (0, hash_leaf(c(1))),
            (0, hash_leaf(c(2))),
            (1, perfect(3, 2)),
            (0, hash_leaf(c(5))),
            (1, perfect(6, 2)), // count 5 is not a multiple of 2
        ];
        let mut candidate = mmr.clone();
        let err = candidate.append_peaks(&chunks).unwrap_err();
        assert_eq!(
            err,
            MmrError::ChunkNotAligned {
                leaf_count: U256::from(5),
                height: 1
            }
        );
        assert_eq!(mmr, Mmr::empty());
    }
}
