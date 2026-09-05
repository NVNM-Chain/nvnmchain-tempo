//! Pure in-memory MMR accumulator.
//!
//! Mirrors the accumulator of [lean-mmr](https://github.com/yihuang/lean-mmr): only a leaf
//! count and the live peaks, one per set bit of the count; a push of a subtree of `height` is
//! the binary carry-merge over the count's trailing ones; and a chunk may be pushed only when
//! the count is a multiple of `2^height`, which is what makes the result the MMR of a leaf
//! history and nothing else. Peaks are kept highest first, the ABI's order, so a `Vec` carries
//! with `push` and `pop`; that is the reverse of the Lean `Acc.peaks`, and nothing here checks
//! the correspondence beyond the sixteen roots the tests pin.
//!
//! No storage, ABI, events or gas: the precompile loads an [`Mmr`] from its slots, pushes, and
//! writes the one slot each push lands in.

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

/// Whether `leaf_count` is a multiple of `size`, a power of two: the Lean spec's
/// `leafCount % 2^height = 0`.
fn aligned(leaf_count: U256, size: U256) -> bool {
    leaf_count & (size - U256::ONE) == U256::ZERO
}

/// The count after a chunk of `height` at `leaf_count`, or why there is none.
fn advanced(leaf_count: U256, height: u8) -> Result<U256, MmrError> {
    let size = U256::ONE << usize::from(height);
    if !aligned(leaf_count, size) {
        return Err(MmrError::ChunkNotAligned { leaf_count, height });
    }
    leaf_count.checked_add(size).ok_or(MmrError::CountOverflow)
}

/// Why a chunk cannot be pushed. Separate from the ABI's errors, so the core is tested
/// without the generated interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmrError {
    /// The count is not a multiple of `2^height`.
    ChunkNotAligned { leaf_count: U256, height: u8 },
    /// The count would overflow `U256`.
    CountOverflow,
    /// The count names a peak the list does not hold.
    PeakMissing,
}

/// What one push did: the peak it landed at `height`, and the merges on the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pushed {
    pub merges: usize,
    pub height: usize,
    pub peak: B256,
}

/// The accumulator: the leaf count, and the live peaks highest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mmr {
    pub leaf_count: U256,
    pub peaks: Vec<B256>,
}

impl Mmr {
    /// The root: the peaks bagged highest first; zero when empty.
    pub fn root(&self) -> B256 {
        bag(&self.peaks)
    }

    /// Whether every chunk of `heights`, in order, is aligned at the count it would see,
    /// reporting the first that is not — so a batch is refused before anything is written.
    pub fn validate(&self, heights: &[u8]) -> Result<(), MmrError> {
        heights
            .iter()
            .try_fold(self.leaf_count, |count, height| advanced(count, *height))
            .map(|_| ())
    }

    /// Merges `node`, a perfect subtree of `height`, at the low end, carrying through every
    /// peak of consecutive height. A refused push changes nothing.
    pub fn push(&mut self, height: u8, node: B256) -> Result<Pushed, MmrError> {
        let leaf_count = advanced(self.leaf_count, height)?;
        let (mut peak, mut merges, mut height) = (node, 0, usize::from(height));
        // No live peak sits below `height`, so each one the count names from there up is
        // the lowest live peak: the tail.
        while self.leaf_count.bit(height) {
            let left = self.peaks.pop().ok_or(MmrError::PeakMissing)?;
            peak = hash_merge(left, peak);
            merges += 1;
            height += 1;
        }
        self.peaks.push(peak);
        self.leaf_count = leaf_count;
        Ok(Pushed {
            merges,
            height,
            peak,
        })
    }
}

/// The reference vectors every suite pins: the roots over the commitments `bytes32(1)`,
/// `bytes32(2)`, … appended in that order, computed independently in Python with keccak.
/// The Solidity verifier's suite and the indexer pin the same sixteen.
#[cfg(test)]
pub(crate) mod vectors {
    use super::{hash_leaf, hash_merge};
    use alloy::primitives::{B256, U256, b256};

    pub(crate) const ROOTS: [B256; 16] = [
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

    /// The commitment the reference roots are over.
    pub(crate) fn c(i: u64) -> B256 {
        B256::from(U256::from(i))
    }

    /// The root of a perfect tree over `leaves`, already hashed.
    pub(crate) fn tree(leaves: &[B256]) -> B256 {
        let mut nodes = leaves.to_vec();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|pair| hash_merge(pair[0], pair[1]))
                .collect();
        }
        nodes[0]
    }

    /// The root of a perfect tree over commitments `from .. from+size`, as a caller cuts a
    /// batch.
    pub(crate) fn perfect(from: u64, size: u64) -> B256 {
        let leaves: Vec<B256> = (0..size).map(|i| hash_leaf(c(from + i))).collect();
        tree(&leaves)
    }

    /// `leaves` cut into aligned chunks from an empty tree: the binary decomposition of
    /// their number, largest first, as `(height, root)`.
    pub(crate) fn cut(leaves: &[B256]) -> Vec<(u8, B256)> {
        let mut chunks = Vec::new();
        let mut at = 0;
        while at < leaves.len() {
            let size = 1usize << (leaves.len() - at).ilog2();
            chunks.push((size.ilog2() as u8, tree(&leaves[at..at + size])));
            at += size;
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::{vectors::*, *};
    use proptest::prelude::*;

    #[test]
    fn aligned_matches_the_lean_modulo_spec() {
        for count in [0u64, 1, 2, 3, 4, 5, 7, 8, 13, 255, 256].map(U256::from) {
            for height in 0..=8u8 {
                let size = U256::ONE << usize::from(height);
                assert_eq!(
                    aligned(count, size),
                    count % size == U256::ZERO,
                    "{count} at {size}"
                );
            }
        }
    }

    #[test]
    fn an_empty_mmr_has_a_zero_root_and_takes_any_height() {
        let mmr = Mmr::default();
        assert_eq!(mmr.root(), B256::ZERO);
        assert!(mmr.validate(&[255]).is_ok());
        assert!(mmr.validate(&[3, 2, 0]).is_ok());
    }

    #[test]
    fn sequential_pushes_reach_the_reference_roots() {
        let mut mmr = Mmr::default();
        for i in 1..=16u64 {
            mmr.push(0, hash_leaf(c(i))).unwrap();
            assert_eq!(mmr.root(), ROOTS[i as usize - 1], "after leaf {i}");
            assert_eq!(mmr.peaks.len(), i.count_ones() as usize);
        }
    }

    /// Count 5 is `101`: a peak of height 2, then one of height 0.
    #[test]
    fn peaks_are_kept_highest_first() {
        let mut mmr = Mmr::default();
        for i in 1..=5u64 {
            mmr.push(0, hash_leaf(c(i))).unwrap();
        }
        assert_eq!(mmr.peaks, [perfect(1, 4), hash_leaf(c(5))]);
    }

    /// Three leaves hold peaks at heights 1 and 0; a fourth carries through both and lands
    /// at height 2, which is the slot the precompile writes.
    #[test]
    fn a_push_reports_where_it_landed() {
        let mut mmr = Mmr::default();
        for i in 1..=3u64 {
            mmr.push(0, hash_leaf(c(i))).unwrap();
        }
        let pushed = mmr.push(0, hash_leaf(c(4))).unwrap();
        assert_eq!(
            pushed,
            Pushed {
                merges: 2,
                height: 2,
                peak: perfect(1, 4)
            }
        );
        assert_eq!(mmr.root(), ROOTS[3]);
    }

    #[test]
    fn a_batch_from_empty_reaches_the_sequential_root() {
        let mut mmr = Mmr::default();
        let chunks = [
            (3, perfect(1, 8)),
            (2, perfect(9, 4)),
            (0, hash_leaf(c(13))),
        ];
        assert!(mmr.validate(&[3, 2, 0]).is_ok());
        for (height, root) in chunks {
            assert_eq!(
                mmr.push(height, root).unwrap().merges,
                0,
                "already at a boundary"
            );
        }
        assert_eq!(mmr.leaf_count, U256::from(13));
        assert_eq!(mmr.root(), ROOTS[12]);
    }

    /// A pair at count 1 is off the alignment: refused by `validate` before anything is
    /// pushed, and by `push` itself without moving the tree. In a batch, the first chunk
    /// off it is the one reported, at the count it would have met.
    #[test]
    fn a_misaligned_chunk_is_refused_and_nothing_moves() {
        let mut mmr = Mmr::default();
        mmr.push(0, hash_leaf(c(1))).unwrap();
        let before = mmr.clone();
        let refused = MmrError::ChunkNotAligned {
            leaf_count: U256::ONE,
            height: 1,
        };

        assert_eq!(mmr.validate(&[1]), Err(refused));
        assert_eq!(mmr.push(1, perfect(2, 2)).unwrap_err(), refused);
        assert_eq!(mmr, before);

        assert_eq!(
            mmr.validate(&[0, 1, 1, 2]),
            Err(MmrError::ChunkNotAligned {
                leaf_count: U256::from(6),
                height: 2
            }),
            "counts 1, 2, 4, 6: the height-2 chunk meets 6"
        );
    }

    proptest! {
        #[test]
        fn sequential_pushes_keep_a_peak_per_set_bit(
            leaves in prop::collection::vec(any::<[u8; 32]>().prop_map(B256::from), 0..64),
        ) {
            let mut mmr = Mmr::default();
            for leaf in leaves {
                mmr.push(0, leaf).unwrap();
                prop_assert_eq!(mmr.peaks.len(), mmr.leaf_count.count_ones());
                prop_assert_eq!(mmr.root(), bag(&mmr.peaks));
            }
        }

        #[test]
        fn an_aligned_batch_matches_sequential_pushes(
            leaves in prop::collection::vec(any::<[u8; 32]>().prop_map(B256::from), 0..128),
        ) {
            let mut sequential = Mmr::default();
            for &leaf in &leaves {
                sequential.push(0, leaf).unwrap();
            }

            let mut batched = Mmr::default();
            for (height, root) in cut(&leaves) {
                batched.push(height, root).unwrap();
            }
            prop_assert_eq!(batched, sequential);
        }
    }
}
