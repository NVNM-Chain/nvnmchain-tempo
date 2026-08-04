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
                    anchor(call) => mutate_void(call, msg_sender, |s, c| self.anchor(s, c)),
                    anchorAndHash(call) => mutate_void(call, msg_sender, |s, c| {
                        self.anchor_and_hash(s, c)
                    }),
                    // View
                    latest(call) => view(call, |c| self.latest(c))
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dispatch::StaticCallNotAllowed,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{B256, Bytes, keccak256},
        sol_types::{SolCall, SolError, SolInterface, SolValue},
    };
    use revm::precompile::{PrecompileHalt, PrecompileStatus};
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
        with_spec(TempoHardfork::T9, f)
    }

    /// A read-only context, as a `STATICCALL` would run in.
    fn with_static_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        let mut storage =
            HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9).with_static(true);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
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

    /// Both writes go in as calldata and come back out through `latest`, which is the only
    /// path a real caller has. `msg_sender` becomes the namespace, so the read uses a
    /// different caller to prove the head is keyed on the writer rather than the reader.
    #[test]
    fn writes_round_trip_through_calldata() -> eyre::Result<()> {
        let metadata = Bytes::from_static(b"self-verifying payload");
        let commitment = B256::repeat_byte(0xab);

        for (write, expected) in [
            (
                IAnchoring::anchorCall {
                    key: B256::ZERO,
                    commitment,
                    metadata: metadata.clone(),
                }
                .abi_encode(),
                commitment,
            ),
            (
                IAnchoring::anchorAndHashCall {
                    key: B256::ZERO,
                    metadata: metadata.clone(),
                }
                .abi_encode(),
                keccak256(&metadata),
            ),
        ] {
            with_anchoring(|mut anchoring| {
                let sender = Address::random();

                let output = anchoring.call(&write, sender)?;
                assert!(output.is_success());
                assert!(output.bytes.is_empty(), "writes return no data");

                let output = anchoring.call(
                    &IAnchoring::latestCall {
                        namespace: sender,
                        key: B256::ZERO,
                    }
                    .abi_encode(),
                    Address::random(),
                )?;
                assert!(output.is_success());
                assert_eq!(
                    IAnchoring::latestCall::abi_decode_returns(&output.bytes)?,
                    expected
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn commitment_unchanged_reverts_with_the_typed_error() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let sender = Address::random();
            let calldata = IAnchoring::anchorCall {
                key: B256::random(),
                commitment: B256::repeat_byte(0xcd),
                metadata: Bytes::new(),
            }
            .abi_encode();

            assert!(anchoring.call(&calldata, sender)?.is_success());

            let output = anchoring.call(&calldata, sender)?;
            assert!(output.is_revert());
            assert_eq!(
                output.bytes,
                AnchoringError::commitment_unchanged().abi_encode()
            );
            Ok(())
        })
    }

    /// Writes must reject `STATICCALL`; `latest` must still serve reads.
    #[test]
    fn static_context_rejects_writes_but_serves_latest() -> eyre::Result<()> {
        with_static_anchoring(|mut anchoring| {
            let sender = Address::random();
            let key = B256::random();

            for calldata in [
                IAnchoring::anchorCall {
                    key,
                    commitment: B256::repeat_byte(0xef),
                    metadata: Bytes::new(),
                }
                .abi_encode(),
                IAnchoring::anchorAndHashCall {
                    key,
                    metadata: Bytes::from_static(b"nope"),
                }
                .abi_encode(),
            ] {
                let output = anchoring.call(&calldata, sender)?;
                assert!(output.is_revert());
                assert!(StaticCallNotAllowed::abi_decode(&output.bytes).is_ok());
            }

            assert!(anchoring.emitted_events().is_empty());

            let output = anchoring.call(
                &IAnchoring::latestCall {
                    namespace: sender,
                    key,
                }
                .abi_encode(),
                sender,
            )?;
            assert!(output.is_success());
            assert_eq!(
                IAnchoring::latestCall::abi_decode_returns(&output.bytes)?,
                B256::ZERO
            );
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
            let mut truncated = IAnchoring::anchorCall::SELECTOR.to_vec();
            truncated.extend_from_slice(&[0u8; 31]);
            let output = anchoring.call(&truncated, Address::random())?;
            assert!(output.is_revert());
            assert!(output.bytes.is_empty(), "ABI-decode failure reverts empty");

            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }
}
