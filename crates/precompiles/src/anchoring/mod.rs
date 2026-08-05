//! Caller-partitioned commitment log precompile. Enabled at `TempoHardfork::T10`.
//!
//! The caller *is* the namespace, so there is no authorization logic: permissionless by
//! construction, and permissioned on demand by routing writes through a wrapper contract whose
//! own address then becomes the namespace.
//!
//! State is one word per `(namespace, key)` — the latest commitment; history, payloads, and
//! version order live in the `Anchored` log for indexers to derive. Re-writing the stored
//! commitment reverts with `CommitmentUnchanged`, the single protocol invariant: every
//! successful anchor changes state, so every event is a distinct change.
//!
//! Inherited from the `x/anchoring` precompile at the same address but not
//! ABI-compatible with it. Its record and registry reads become indexer queries over the log;
//! its roles have no successor here at all — there is no `grantRole`/`hasRole` and no role
//! state, so any permissioning is an application concern in a calling contract.

pub mod dispatch;

use crate::{
    ANCHORING_ADDRESS,
    error::Result,
    storage::{Handler, Slot},
};
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
pub use tempo_contracts::precompiles::{AnchoringError, AnchoringEvent, IAnchoring};
use tempo_precompiles_macros::contract;

/// Domain tag for the head-slot derivation. Prefixing the preimage leaves the rest of the
/// space free for future domains, so a later addition never collides with an existing head.
const DOMAIN_HEAD: u8 = 0x01;

/// Caller-partitioned commitment log.
///
/// Storage is a single derived word per `(namespace, key)` rather than a declared mapping
/// field, so it takes one keccak instead of the two a nested `Mapping` would — see
/// [`Anchoring::head`].
#[contract(addr = ANCHORING_ADDRESS)]
pub struct Anchoring {}

impl Anchoring {
    /// Initializes the anchoring contract by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// The slot holding the latest commitment for `(namespace, key)`:
    ///
    /// ```text
    /// headSlot(ns, key) = keccak256(0x01 ‖ pad32(ns) ‖ key)
    /// ```
    ///
    /// One hash over a domain-tagged preimage, rather than the two a nested `Mapping` would
    /// take. Reads and writes still go through [`Slot`], so they are metered and journalled
    /// like any other precompile storage.
    fn head(&self, namespace: Address, key: B256) -> Slot<B256> {
        let mut preimage = [0u8; 65];
        preimage[0] = DOMAIN_HEAD;
        preimage[1..33].copy_from_slice(namespace.into_word().as_slice());
        preimage[33..].copy_from_slice(key.as_slice());
        Slot::new(
            U256::from_be_bytes(keccak256(preimage).0),
            ANCHORING_ADDRESS,
        )
    }

    /// Returns the latest commitment for `(namespace, key)`, or zero if never anchored.
    pub fn latest(&self, call: IAnchoring::latestCall) -> Result<B256> {
        self.head(call.namespace, call.key).read()
    }

    /// Anchors `commitment` under `msg_sender`'s namespace at `key`.
    ///
    /// # Errors
    /// - `CommitmentUnchanged` — `commitment` already is the head for `(msg_sender, key)`
    pub fn anchor(&mut self, msg_sender: Address, call: IAnchoring::anchorCall) -> Result<()> {
        self.write_head(msg_sender, call.key, call.commitment, call.metadata)
    }

    /// Anchors `keccak256(metadata)`, which makes the emitted event self-verifying.
    ///
    /// # Errors
    /// - `CommitmentUnchanged` — the metadata digest already is the head for `(msg_sender, key)`
    pub fn anchor_and_hash(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::anchorAndHashCall,
    ) -> Result<()> {
        let commitment = keccak256(&call.metadata);
        self.write_head(msg_sender, call.key, commitment, call.metadata)
    }

    /// Writes the head for `(namespace, key)` and emits `Anchored`.
    ///
    /// Rejects no-op writes so that every emitted event corresponds to a real state change.
    /// Zero is a legal commitment — it resets the head — and is rejected only when the head is
    /// already zero.
    fn write_head(
        &mut self,
        namespace: Address,
        key: B256,
        commitment: B256,
        metadata: Bytes,
    ) -> Result<()> {
        if self.head(namespace, key).read()? == commitment {
            return Err(AnchoringError::commitment_unchanged().into());
        }

        self.head(namespace, key).write(commitment)?;
        self.emit_event(AnchoringEvent::anchored(
            namespace, key, commitment, metadata,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::{
        primitives::{U256, address, b256},
        sol_types::{SolCall, SolEvent},
    };
    use tempo_chainspec::hardfork::TempoHardfork;

    /// `keccak256("sha256:aa11bb22cc33")` — the key pinned by the anchoring spec.
    const PINNED_KEY: B256 =
        b256!("0x67f62d0f6aeb3832ec7bddf22daf97ee7538761d2fdb89e6e5ba36bd5ed0c213");
    /// The namespace pinned by the anchoring spec.
    const PINNED_NS: Address = address!("0x1111111111111111111111111111111111111111");

    fn with_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
    }

    fn anchor_call(key: B256, commitment: B256, metadata: &[u8]) -> IAnchoring::anchorCall {
        IAnchoring::anchorCall {
            key,
            commitment,
            metadata: Bytes::copy_from_slice(metadata),
        }
    }

    fn latest_of(anchoring: &Anchoring, namespace: Address, key: B256) -> Result<B256> {
        anchoring.latest(IAnchoring::latestCall { namespace, key })
    }

    /// Reference vectors from the spec. A change here is an ABI break for every indexer.
    #[test]
    fn abi_constants_are_pinned() {
        assert_eq!(
            IAnchoring::anchorCall::SELECTOR,
            alloy::hex!("0x0a3bd8ec"),
            "anchor(bytes32,bytes32,bytes)"
        );
        assert_eq!(
            IAnchoring::anchorAndHashCall::SELECTOR,
            alloy::hex!("0x875d07f6"),
            "anchorAndHash(bytes32,bytes)"
        );
        assert_eq!(
            IAnchoring::latestCall::SELECTOR,
            alloy::hex!("0x68205bc3"),
            "latest(address,bytes32)"
        );
        assert_eq!(
            IAnchoring::Anchored::SIGNATURE_HASH,
            b256!("0x778db4d46fc7a84c4e5105dcb250cb47092b78648868d3efaf18e1205b25801d"),
            "Anchored(address,bytes32,bytes32,bytes)"
        );
        assert_eq!(
            ANCHORING_ADDRESS,
            address!("0x0000000000000000000000000000000000000a00")
        );
    }

    /// Pins the head slot derivation against the spec's reference vector. Off-chain tooling
    /// reconstructs slots from this rule, so a change here breaks every such consumer.
    #[test]
    fn head_slot_derivation_is_pinned() -> eyre::Result<()> {
        let preimage = [
            &[DOMAIN_HEAD][..],
            PINNED_NS.into_word().as_slice(),
            PINNED_KEY.as_slice(),
        ]
        .concat();
        let expected = keccak256(preimage);
        assert_eq!(
            expected,
            b256!("0x68945f381cbccb13ba2b13540e8ac2e28d1e9d3ca33aecf37861f5ef565fd489")
        );

        // The accessor must resolve to the same slot, and an anchor must land in it.
        let slot = U256::from_be_bytes(expected.0);
        with_anchoring(|mut anchoring| {
            let commitment = B256::repeat_byte(0xaa);
            anchoring.anchor(PINNED_NS, anchor_call(PINNED_KEY, commitment, b""))?;

            let raw = StorageCtx.sload(ANCHORING_ADDRESS, slot)?;
            assert_eq!(B256::from(raw.to_be_bytes()), commitment);
            Ok(())
        })
    }

    #[test]
    fn untouched_key_reads_zero() -> eyre::Result<()> {
        with_anchoring(|anchoring| {
            assert_eq!(
                latest_of(&anchoring, Address::random(), B256::random())?,
                B256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn successive_anchors_update_head_and_emit_one_event_each() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            let key = B256::random();
            let (first, second) = (B256::repeat_byte(0x11), B256::repeat_byte(0x22));

            anchoring.anchor(ns, anchor_call(key, first, b"v1"))?;
            assert_eq!(latest_of(&anchoring, ns, key)?, first);

            anchoring.anchor(ns, anchor_call(key, second, b"v2"))?;
            assert_eq!(latest_of(&anchoring, ns, key)?, second);

            // One event per anchor, in order — the exact list, so a stray event fails here too.
            anchoring.assert_emitted_events(vec![
                AnchoringEvent::anchored(ns, key, first, Bytes::from_static(b"v1")),
                AnchoringEvent::anchored(ns, key, second, Bytes::from_static(b"v2")),
            ]);
            Ok(())
        })
    }

    /// The single protocol invariant: an anchor must change the commitment.
    #[test]
    fn re_anchoring_the_current_commitment_reverts_without_side_effects() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            let key = B256::random();
            let commitment = B256::repeat_byte(0x33);

            anchoring.anchor(ns, anchor_call(key, commitment, b"first"))?;
            anchoring.clear_emitted_events();

            // Different metadata must not rescue an unchanged commitment.
            let err = anchoring
                .anchor(ns, anchor_call(key, commitment, b"different metadata"))
                .unwrap_err();
            assert_eq!(err, AnchoringError::commitment_unchanged().into());

            assert_eq!(latest_of(&anchoring, ns, key)?, commitment);
            assert!(anchoring.emitted_events().is_empty());
            Ok(())
        })
    }

    /// Only the *current* head is rejected — an older commitment is a real state change.
    #[test]
    fn an_older_commitment_can_be_anchored_again() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            let key = B256::random();
            let (first, second) = (B256::repeat_byte(0x44), B256::repeat_byte(0x55));

            anchoring.anchor(ns, anchor_call(key, first, b""))?;
            anchoring.anchor(ns, anchor_call(key, second, b""))?;
            anchoring.anchor(ns, anchor_call(key, first, b""))?;

            assert_eq!(latest_of(&anchoring, ns, key)?, first);
            assert_eq!(anchoring.emitted_events().len(), 3);
            Ok(())
        })
    }

    /// Zero is a legal commitment; it resets a head and is rejected only when already zero.
    #[test]
    fn zero_commitment_is_a_reset_not_a_special_case() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            let key = B256::random();

            let err = anchoring
                .anchor(ns, anchor_call(key, B256::ZERO, b""))
                .unwrap_err();
            assert_eq!(err, AnchoringError::commitment_unchanged().into());
            assert!(anchoring.emitted_events().is_empty());

            anchoring.anchor(ns, anchor_call(key, B256::repeat_byte(0x66), b""))?;
            anchoring.anchor(ns, anchor_call(key, B256::ZERO, b""))?;

            assert_eq!(latest_of(&anchoring, ns, key)?, B256::ZERO);
            assert_eq!(anchoring.emitted_events().len(), 2);
            Ok(())
        })
    }

    #[test]
    fn anchor_and_hash_commits_the_metadata_digest() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            let key = B256::random();
            let metadata = Bytes::from_static(br#"{"v":1,"kind":"content"}"#);

            anchoring.anchor_and_hash(
                ns,
                IAnchoring::anchorAndHashCall {
                    key,
                    metadata: metadata.clone(),
                },
            )?;

            let digest = keccak256(&metadata);
            assert_eq!(latest_of(&anchoring, ns, key)?, digest);
            anchoring
                .assert_emitted_events(vec![AnchoringEvent::anchored(ns, key, digest, metadata)]);
            Ok(())
        })
    }

    /// Two legacy rows differing only in an envelope discriminator must both replay.
    #[test]
    fn anchor_and_hash_distinguishes_metadata_that_differs_only_in_seq() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let ns = Address::random();
            let key = B256::random();

            for seq in [1, 2] {
                anchoring.anchor_and_hash(
                    ns,
                    IAnchoring::anchorAndHashCall {
                        key,
                        metadata: format!(r#"{{"seq":{seq},"checksum":"0xabc"}}"#)
                            .into_bytes()
                            .into(),
                    },
                )?;
            }

            assert_eq!(anchoring.emitted_events().len(), 2);
            Ok(())
        })
    }

    /// Heads are partitioned on both axes: the namespace (`msg_sender`, so one account cannot
    /// reach another's) and the key. The no-op rule applies per partition, so the *same*
    /// commitment written into a different one is a real state change rather than a revert.
    #[test]
    fn heads_are_isolated_per_namespace_and_key() -> eyre::Result<()> {
        with_anchoring(|mut anchoring| {
            let (alice, bob) = (Address::random(), Address::random());
            let (key_a, key_b) = (B256::random(), B256::random());
            let commitment = B256::repeat_byte(0x77);

            anchoring.anchor(alice, anchor_call(key_a, commitment, b""))?;
            // Neither a different namespace nor a different key collides with Alice's head.
            anchoring.anchor(bob, anchor_call(key_a, commitment, b""))?;
            anchoring.anchor(alice, anchor_call(key_b, commitment, b""))?;

            for (ns, key) in [(alice, key_a), (bob, key_a), (alice, key_b)] {
                assert_eq!(latest_of(&anchoring, ns, key)?, commitment);
            }
            assert_eq!(latest_of(&anchoring, bob, key_b)?, B256::ZERO);
            assert_eq!(anchoring.emitted_events().len(), 3);
            Ok(())
        })
    }
}
