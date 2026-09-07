//! ABI dispatch for the [`Anchoring`] precompile.

use crate::{Precompile, anchoring::Anchoring, charge_input_cost, dispatch, mutate_void, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IAnchoring;

impl Precompile for Anchoring {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IAnchoring::IAnchoringCalls {
                    // Writes: the caller is the namespace, so no authorization check exists.
                    appendLeaf(call) => mutate_void(call, msg_sender, |s, c| self.append_leaf(s, c)),
                    appendLeaves(call) => mutate_void(call, msg_sender, |s, c| {
                        self.append_leaves(s, c)
                    }),
                    // Views
                    root(call) => view(call, |c| self.root(c)),
                    state(call) => view(call, |c| self.state(c))
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        anchoring::{bag, hash_leaf, mmr::vectors::cut},
        dispatch::StaticCallNotAllowed,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{B256, Bytes, U256},
        sol_types::{SolCall, SolError, SolInterface, SolValue},
    };
    use proptest::prelude::*;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        AnchoringError, IAnchoring::IAnchoringCalls, UnknownFunctionSelector,
    };

    /// `records(uint64,string,uint64,uint64,(bytes,uint64,uint64,bool,bool))` — the paginated
    /// record query the `x/anchoring` precompile served at this address; the tuple is its
    /// `PageRequest`. Any retired selector would do; this one is calldata a stale integration
    /// might genuinely still send.
    const LEGACY_SELECTOR: [u8; 4] = alloy::hex!("0xc7be5e37");

    fn with_spec<T>(
        spec: TempoHardfork,
        f: impl FnOnce(Anchoring) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
    }

    fn with_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        with_spec(TempoHardfork::T10, f)
    }

    /// A read-only context, as a `STATICCALL` would run in.
    fn with_static_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        let mut storage =
            HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10).with_static(true);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
    }

    fn leaf(commitment: B256) -> Vec<u8> {
        IAnchoring::appendLeafCall {
            commitment,
            metadata: Bytes::from_static(b"payload"),
        }
        .abi_encode()
    }

    fn leaves(chunks: Vec<IAnchoring::Chunk>) -> Vec<u8> {
        IAnchoring::appendLeavesCall {
            chunks,
            metadata: Bytes::new(),
        }
        .abi_encode()
    }

    fn root_call(namespace: Address) -> Vec<u8> {
        IAnchoring::rootCall { namespace }.abi_encode()
    }

    /// The aligned chunks for appending `commitments` from an empty MMR.
    fn chunks_from_commitments(commitments: &[B256]) -> Vec<IAnchoring::Chunk> {
        let leaves: Vec<_> = commitments.iter().copied().map(hash_leaf).collect();
        cut(&leaves)
            .into_iter()
            .map(|(height, root)| IAnchoring::Chunk { root, height })
            .collect()
    }

    proptest! {
        #[test]
        fn append_leaves_calldata_roundtrips(
            chunks in prop::collection::vec((any::<[u8; 32]>(), 0u8..=8), 0..32),
            metadata in prop::collection::vec(any::<u8>(), 0..32),
        ) {
            let chunks: Vec<_> = chunks
                .into_iter()
                .map(|(root, height)| IAnchoring::Chunk {
                    root: B256::from(root),
                    height,
                })
                .collect();
            let call = IAnchoring::appendLeavesCall {
                chunks: chunks.clone(),
                metadata: Bytes::from(metadata),
            };
            let decoded = IAnchoring::appendLeavesCall::abi_decode(&call.abi_encode()).unwrap();
            prop_assert_eq!(decoded.chunks, chunks);
            prop_assert_eq!(decoded.metadata, call.metadata);
        }

        #[test]
        fn append_leaves_via_abi_matches_sequential_appends(
            commitments in prop::collection::vec(any::<[u8; 32]>(), 1..32),
        ) {
            let commitments: Vec<_> = commitments.into_iter().map(B256::from).collect();
            let chunks = chunks_from_commitments(&commitments);

            let sequential_root = with_anchoring(|mut anchoring| {
                let sender = Address::random();
                for commitment in &commitments {
                    let output = anchoring.call(&leaf(*commitment), sender)?;
                    assert!(output.is_success());
                }
                let output = anchoring.call(&root_call(sender), sender)?;
                Ok(IAnchoring::rootCall::abi_decode_returns(&output.bytes)?)
            })
            .unwrap();

            let batch_root = with_anchoring(|mut anchoring| {
                let sender = Address::random();
                let output = anchoring.call(&leaves(chunks), sender)?;
                assert!(output.is_success());
                let output = anchoring.call(&root_call(sender), sender)?;
                Ok(IAnchoring::rootCall::abi_decode_returns(&output.bytes)?)
            })
            .unwrap();

            prop_assert_eq!(sequential_root, batch_root);
        }
    }

    #[test]
    fn selector_coverage() {
        with_anchoring(|mut anchoring| {
            assert_full_coverage([check_selector_coverage(
                &mut anchoring,
                IAnchoringCalls::SELECTORS,
                "IAnchoring",
                IAnchoringCalls::name_by_selector,
            )]);
            Ok(())
        })
        .unwrap()
    }

    /// Both writes go in as calldata, return nothing, and what they did comes back out
    /// through `root` and `state`, which is the only path a real caller has. `msg_sender`
    /// becomes the namespace, so the reads use a different caller to prove the MMR is keyed
    /// on the writer rather than the reader.
    #[test]
    fn writes_round_trip_through_calldata() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let sender = Address::random();
            let first = hash_leaf(B256::repeat_byte(0xab));

            let output = anchoring.call(&leaf(B256::repeat_byte(0xab)), sender)?;
            assert!(output.is_success());
            assert!(output.bytes.is_empty(), "a write returns nothing");

            let output = anchoring.call(&root_call(sender), Address::random())?;
            assert!(output.is_success());
            assert_eq!(
                IAnchoring::rootCall::abi_decode_returns(&output.bytes)?,
                bag(&[first]),
                "one leaf is its own root"
            );

            // A batch on top of it: a second leaf, which merges with the first.
            let output = anchoring.call(
                &leaves(vec![IAnchoring::Chunk {
                    root: hash_leaf(B256::repeat_byte(0xcd)),
                    height: 0,
                }]),
                sender,
            )?;
            assert!(output.is_success());
            assert!(output.bytes.is_empty(), "a batch returns nothing either");
            let output = anchoring.call(&root_call(sender), Address::random())?;
            let root = IAnchoring::rootCall::abi_decode_returns(&output.bytes)?;
            assert_ne!(root, bag(&[first]));

            let output = anchoring.call(
                &IAnchoring::stateCall { namespace: sender }.abi_encode(),
                Address::random(),
            )?;
            assert!(output.is_success());
            let state = IAnchoring::stateCall::abi_decode_returns(&output.bytes)?;
            assert_eq!(state.count, U256::from(2));
            assert_eq!(state.peaks.len(), 1);
            assert_eq!(bag(&state.peaks), root);
            assert_eq!(anchoring.emitted_events().len(), 2);
            Ok(())
        })
    }

    #[test]
    fn a_misaligned_chunk_reverts_with_the_typed_error() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let sender = Address::random();
            assert!(
                anchoring
                    .call(&leaf(B256::repeat_byte(0xcd)), sender)?
                    .is_success()
            );

            // A pair at count 1.
            let output = anchoring.call(
                &leaves(vec![IAnchoring::Chunk {
                    root: B256::repeat_byte(0xef),
                    height: 1,
                }]),
                sender,
            )?;
            assert!(output.is_revert());
            assert_eq!(
                output.bytes,
                AnchoringError::chunk_not_aligned(U256::ONE, U256::ONE).abi_encode()
            );
            Ok(())
        })
    }

    /// Writes must reject `STATICCALL`; the views must still serve reads.
    #[test]
    fn static_context_rejects_writes_but_serves_reads() -> eyre::Result<()> {
        with_static_anchoring(|mut anchoring| {
            let sender = Address::random();

            for calldata in [
                leaf(B256::repeat_byte(0xef)),
                leaves(vec![IAnchoring::Chunk {
                    root: B256::repeat_byte(0xef),
                    height: 0,
                }]),
            ] {
                let output = anchoring.call(&calldata, sender)?;
                assert!(output.is_revert());
                assert!(StaticCallNotAllowed::abi_decode(&output.bytes).is_ok());
            }

            assert!(anchoring.emitted_events().is_empty());

            let output = anchoring.call(&root_call(sender), sender)?;
            assert!(output.is_success());
            assert_eq!(
                IAnchoring::rootCall::abi_decode_returns(&output.bytes)?,
                B256::ZERO
            );
            let output = anchoring.call(
                &IAnchoring::stateCall { namespace: sender }.abi_encode(),
                sender,
            )?;
            assert!(output.is_success());
            Ok(())
        })
    }

    /// The address is reused, the ABI is not: legacy calldata must fail loudly.
    #[test]
    fn legacy_selector_reverts_unknown_function_selector() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let mut calldata = LEGACY_SELECTOR.to_vec();
            calldata.extend_from_slice(&(0u64, 10u64).abi_encode());

            let output = anchoring.call(&calldata, Address::random())?;
            assert!(output.is_revert());
            assert_eq!(
                UnknownFunctionSelector::abi_decode(&output.bytes)?.selector,
                LEGACY_SELECTOR
            );
            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }

    #[test]
    fn malformed_calldata_reverts_without_side_effects() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            // A known selector with truncated arguments.
            let mut truncated = IAnchoring::appendLeafCall::SELECTOR.to_vec();
            truncated.extend_from_slice(&[0u8; 31]);
            let output = anchoring.call(&truncated, Address::random())?;
            assert!(output.is_revert());
            assert!(output.bytes.is_empty(), "ABI-decode failure reverts empty");

            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }
}
