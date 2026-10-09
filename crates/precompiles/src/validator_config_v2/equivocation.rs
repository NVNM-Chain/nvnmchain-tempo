//! Evidence that a validator's consensus key signed conflicting votes in one round, as the node
//! encodes it:
//!
//! ```text
//! evidence = signer (32) | ballot | ballot
//! ballot   = kind (1) | body | ed25519 signature (64)
//! body     = epoch | view                            for a nullify (1)
//!          = epoch | view | parent | payload (32)    for a notarize (0) or a finalize (2)
//! ```
//!
//! The integers are varints. A signature is over its ballot's body, under this chain's namespace
//! for the kind. The votes conflict as the consensus crate has it: two proposals notarized, two
//! finalized, or one finalized in a round the key nullified.

use super::{IEquivocation, ValidatorConfigV2, ValidatorConfigV2Error};
use crate::error::Result;
use alloy::primitives::B256;
use commonware_codec::{DecodeExt as _, ReadExt as _, varint::UInt};
use commonware_cryptography::{
    Verifier as _,
    ed25519::{PublicKey, Signature},
};

const NOTARIZE: u8 = 0;
const NULLIFY: u8 = 1;
const FINALIZE: u8 = 2;

/// Charged for each of the two signatures checked.
const ED25519_VERIFY_GAS: u64 = 3_000;

struct Ballot<'a> {
    kind: u8,
    epoch: u64,
    view: u64,
    /// What the signature is over.
    body: &'a [u8],
    signature: Signature,
}

impl<'a> Ballot<'a> {
    fn read(reader: &mut &'a [u8]) -> Option<Self> {
        let kind = u8::read(reader).ok()?;
        let start = *reader;
        let epoch = UInt::<u64>::read(reader).ok()?.into();
        let view = UInt::<u64>::read(reader).ok()?.into();
        match kind {
            NULLIFY => {}
            NOTARIZE | FINALIZE => {
                UInt::<u64>::read(reader).ok()?;
                *reader = reader.get(B256::len_bytes()..)?;
            }
            _ => return None,
        }
        let body = &start[..start.len() - reader.len()];
        let signature = Signature::read(reader).ok()?;
        Some(Self {
            kind,
            epoch,
            view,
            body,
            signature,
        })
    }

    fn conflicts_with(&self, other: &Self) -> bool {
        (self.epoch, self.view) == (other.epoch, other.view)
            && match (self.kind, other.kind) {
                (NOTARIZE, NOTARIZE) | (FINALIZE, FINALIZE) => self.body != other.body,
                (NULLIFY, FINALIZE) | (FINALIZE, NULLIFY) => true,
                _ => false,
            }
    }
}

/// The namespace the consensus crate signs a vote of `kind` under on this chain.
fn namespace(kind: u8, chain_id: u64, genesis: B256) -> Vec<u8> {
    let kind: &[u8] = match kind {
        NOTARIZE => b"_NOTARIZE",
        NULLIFY => b"_NULLIFY",
        _ => b"_FINALIZE",
    };
    [
        b"TEMPO_ATTRIBUTABLE_",
        chain_id.to_be_bytes().as_slice(),
        genesis.as_slice(),
        kind,
    ]
    .concat()
}

impl ValidatorConfigV2 {
    /// Whether consensus votes carry their signer's signature by this block.
    pub(super) fn votes_are_attributable(&self) -> bool {
        self.storage.spec().is_t12()
            && self
                .storage
                .attributable_votes_time()
                .is_some_and(|from| self.storage.timestamp() >= alloy::primitives::U256::from(from))
    }

    /// The validator whose key signed both votes in the evidence, and their round.
    ///
    /// # Errors
    /// - `InvalidSignature` — the evidence does not decode, its votes do not conflict, they are
    ///   for an epoch yet to come, or the key did not sign both on this chain
    /// - `ValidatorNotFound` — the registry does not hold the key, or did not yet in that epoch
    pub fn equivocator(
        &self,
        call: IEquivocation::equivocatorCall,
    ) -> Result<IEquivocation::equivocatorReturn> {
        let invalid = ValidatorConfigV2Error::invalid_signature;
        let mut reader = call.evidence.as_ref();
        let key = reader.split_off(..B256::len_bytes()).ok_or_else(invalid)?;
        let signer = PublicKey::decode(key).map_err(|_| invalid())?;
        let (Some(first), Some(second)) = (Ballot::read(&mut reader), Ballot::read(&mut reader))
        else {
            Err(invalid())?
        };
        if !reader.is_empty() || !first.conflicts_with(&second) {
            Err(invalid())?
        }

        let (chain_id, genesis) = (self.storage.chain_id(), self.storage.genesis_hash());
        self.storage.deduct_gas(2 * ED25519_VERIFY_GAS)?;
        for ballot in [&first, &second] {
            let namespace = namespace(ballot.kind, chain_id, genesis);
            if !signer.verify(&namespace, ballot.body, &ballot.signature) {
                Err(invalid())?
            }
        }

        // The record of this key, live or left by a rotation, names the address its bond is
        // under. A key cannot have signed before that record held a seat. After it left one it
        // still answers: failed key ceremonies carry an old set on for any number of epochs, and
        // only the key itself can make the two signatures.
        let record = self.validator_by_public_key(B256::from_slice(key))?;
        let epoch_length = self
            .storage
            .with_block_env(|block_env| block_env.epoch_length.get());
        let epochs_ago = (self.storage.block_number() / epoch_length)
            .checked_sub(first.epoch)
            .ok_or_else(invalid)?;
        if first.epoch < record.addedAtHeight / epoch_length {
            Err(ValidatorConfigV2Error::validator_not_found())?
        }

        Ok(IEquivocation::equivocatorReturn {
            validator: record.validatorAddress,
            epoch: first.epoch,
            viewNumber: first.view,
            epochsAgo: epochs_ago,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, Bytes, Keccak256},
        sol_types::{SolCall as _, SolValue as _},
    };
    use commonware_codec::{Encode as _, Write as _};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{IValidatorConfigV2, VALIDATOR_CONFIG_V2_ADDRESS};

    use super::*;
    use crate::{
        Precompile as _,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        validator_config_v2::{VALIDATOR_NS_ADD, VALIDATOR_NS_ROTATE},
    };

    const CHAIN_ID: u64 = 1;
    const GENESIS: B256 = B256::repeat_byte(7);
    /// The epoch is one block long in these tests, so a height is its epoch.
    const ENROLLED: u64 = 200;
    const NOW: u64 = 210;
    const EPOCH: u64 = 205;

    /// A ballot of `kind` for view 3 of `epoch`, for the proposal `payload` names, signed by
    /// `key` for the chain of `chain_id` and `genesis`.
    fn ballot(key: &PrivateKey, kind: u8, epoch: u64, payload: u8, chain: (u64, B256)) -> Vec<u8> {
        let mut body = Vec::new();
        UInt(epoch).write(&mut body);
        UInt(3u64).write(&mut body);
        if kind != NULLIFY {
            UInt(2u64).write(&mut body);
            body.extend([payload; 32]);
        }
        let signature = key.sign(&namespace(kind, chain.0, chain.1), &body);
        [&[kind], body.as_slice(), signature.encode().as_ref()].concat()
    }

    fn evidence(key: &PrivateKey, first: &[u8], second: &[u8]) -> IEquivocation::equivocatorCall {
        let evidence = [key.public_key().encode().as_ref(), first, second].concat();
        IEquivocation::equivocatorCall {
            evidence: evidence.into(),
        }
    }

    /// Two notarizes for different proposals in `epoch`, on this chain.
    fn double_notarize(key: &PrivateKey, epoch: u64) -> IEquivocation::equivocatorCall {
        let here = (CHAIN_ID, GENESIS);
        evidence(
            key,
            &ballot(key, NOTARIZE, epoch, 1, here),
            &ballot(key, NOTARIZE, epoch, 2, here),
        )
    }

    /// `key`'s signature over what the registry asks of a validator at `address`.
    fn enrolment(
        key: &PrivateKey,
        namespace: &[u8],
        address: Address,
        ip: &str,
        recipient: Option<Address>,
    ) -> Bytes {
        let ingress = format!("{ip}:8000");
        let mut hasher = Keccak256::new();
        hasher.update(CHAIN_ID.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(address.as_slice());
        for part in [ingress.as_str(), ip] {
            hasher.update([u8::try_from(part.len()).unwrap()]);
            hasher.update(part.as_bytes());
        }
        if let Some(recipient) = recipient {
            hasher.update(recipient.as_slice());
        }
        key.sign(namespace, hasher.finalize().as_slice())
            .encode()
            .to_vec()
            .into()
    }

    /// A registry in which `key` was enrolled for `validator` at [`ENROLLED`], by [`NOW`], in a
    /// chain whose votes are attributable.
    fn with_registry<T>(
        key: &PrivateKey,
        validator: Address,
        owner: Address,
        test: impl FnOnce(&mut ValidatorConfigV2) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(CHAIN_ID, TempoHardfork::T12);
        storage.set_attributable_votes_time(Some(0));
        storage.set_genesis_hash(GENESIS);
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;
            vc.storage.set_block_number(ENROLLED);
            vc.add_validator(
                owner,
                IValidatorConfigV2::addValidatorCall {
                    validatorAddress: validator,
                    publicKey: B256::from_slice(&key.public_key().encode()),
                    ingress: "192.168.1.1:8000".to_string(),
                    egress: "192.168.1.1".to_string(),
                    feeRecipient: validator,
                    signature: enrolment(
                        key,
                        VALIDATOR_NS_ADD,
                        validator,
                        "192.168.1.1",
                        Some(validator),
                    ),
                },
            )?;
            vc.storage.set_block_number(NOW);
            test(&mut vc)
        })
    }

    #[test]
    fn each_conflict_names_the_validator_and_the_round() -> eyre::Result<()> {
        let (key, validator) = (PrivateKey::from_seed(1), Address::random());
        let here = (CHAIN_ID, GENESIS);
        let vote = |kind, payload| ballot(&key, kind, EPOCH, payload, here);
        with_registry(&key, validator, Address::random(), |vc| {
            for (first, second) in [
                (vote(NOTARIZE, 1), vote(NOTARIZE, 2)),
                (vote(FINALIZE, 1), vote(FINALIZE, 2)),
                (vote(NULLIFY, 0), vote(FINALIZE, 1)),
                (vote(FINALIZE, 1), vote(NULLIFY, 0)),
            ] {
                let found = vc.equivocator(evidence(&key, &first, &second))?;
                assert_eq!(found.validator, validator);
                assert_eq!((found.epoch, found.viewNumber), (EPOCH, 3));
                assert_eq!(found.epochsAgo, NOW - EPOCH);
            }
            Ok(())
        })
    }

    #[test]
    fn votes_an_honest_signer_casts_together_prove_nothing() -> eyre::Result<()> {
        let (key, validator) = (PrivateKey::from_seed(1), Address::random());
        let here = (CHAIN_ID, GENESIS);
        let vote = |kind, epoch, payload| ballot(&key, kind, epoch, payload, here);
        with_registry(&key, validator, Address::random(), |vc| {
            let invalid = Err(ValidatorConfigV2Error::invalid_signature().into());
            for (first, second) in [
                (vote(NOTARIZE, EPOCH, 1), vote(NOTARIZE, EPOCH, 1)),
                (vote(NOTARIZE, EPOCH, 1), vote(FINALIZE, EPOCH, 1)),
                (vote(NOTARIZE, EPOCH, 1), vote(NULLIFY, EPOCH, 0)),
                // Another round is another matter.
                (vote(NOTARIZE, EPOCH, 1), vote(NOTARIZE, EPOCH + 1, 2)),
                (vote(NULLIFY, EPOCH, 0), vote(FINALIZE, EPOCH + 1, 1)),
            ] {
                assert_eq!(vc.equivocator(evidence(&key, &first, &second)), invalid);
            }

            // Nor does anything but exactly two ballots.
            let mut long = double_notarize(&key, EPOCH).evidence.to_vec();
            long.push(0);
            let short = long[..long.len() - 2].to_vec();
            for evidence in [long, short, Vec::new()] {
                let call = IEquivocation::equivocatorCall {
                    evidence: evidence.into(),
                };
                assert_eq!(vc.equivocator(call), invalid);
            }
            Ok(())
        })
    }

    #[test]
    fn votes_signed_elsewhere_or_by_another_key_prove_nothing() -> eyre::Result<()> {
        let (key, other, validator) = (
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            Address::random(),
        );
        let here = (CHAIN_ID, GENESIS);
        with_registry(&key, validator, Address::random(), |vc| {
            let invalid = Err(ValidatorConfigV2Error::invalid_signature().into());
            // The same key and votes on another chain, by its id or by its genesis.
            for chain in [(CHAIN_ID + 1, GENESIS), (CHAIN_ID, B256::repeat_byte(8))] {
                let pair = evidence(
                    &key,
                    &ballot(&key, NOTARIZE, EPOCH, 1, chain),
                    &ballot(&key, NOTARIZE, EPOCH, 2, chain),
                );
                assert_eq!(vc.equivocator(pair), invalid);
            }
            // One vote of the pair signed by another key.
            let pair = evidence(
                &key,
                &ballot(&key, NOTARIZE, EPOCH, 1, here),
                &ballot(&other, NOTARIZE, EPOCH, 2, here),
            );
            assert_eq!(vc.equivocator(pair), invalid);
            // A key the registry never held.
            assert_eq!(
                vc.equivocator(double_notarize(&other, EPOCH)),
                Err(ValidatorConfigV2Error::validator_not_found().into())
            );
            Ok(())
        })
    }

    #[test]
    fn a_key_answers_for_the_epochs_it_held_a_seat_in() -> eyre::Result<()> {
        let (key, successor, validator, owner) = (
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            Address::random(),
            Address::random(),
        );
        with_registry(&key, validator, owner, |vc| {
            let not_found = Err(ValidatorConfigV2Error::validator_not_found().into());
            assert_eq!(
                vc.equivocator(double_notarize(&key, ENROLLED - 1)),
                not_found
            );
            assert_eq!(
                vc.equivocator(double_notarize(&key, NOW + 1)),
                Err(ValidatorConfigV2Error::invalid_signature().into())
            );

            // Rotated out at NOW, the old key still answers, under the same address, for every
            // epoch after: a failed key ceremony may keep it signing.
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: B256::from_slice(&successor.public_key().encode()),
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    signature: enrolment(
                        &successor,
                        VALIDATOR_NS_ROTATE,
                        validator,
                        "10.0.0.1",
                        None,
                    ),
                },
            )?;
            vc.storage.set_block_number(NOW + 10);
            for epoch in [EPOCH, NOW + 10] {
                assert_eq!(
                    vc.equivocator(double_notarize(&key, epoch))?.validator,
                    validator
                );
            }
            // Its successor answers from the rotation on.
            assert_eq!(
                vc.equivocator(double_notarize(&successor, NOW - 1)),
                not_found
            );
            assert_eq!(
                vc.equivocator(double_notarize(&successor, NOW))?.validator,
                validator
            );

            Ok(())
        })
    }

    #[test]
    fn the_check_exists_only_where_votes_are_attributable() -> eyre::Result<()> {
        let (key, validator) = (PrivateKey::from_seed(1), Address::random());
        with_registry(&key, validator, Address::random(), |vc| {
            let call = double_notarize(&key, EPOCH).abi_encode();

            let answer = vc.call(&call, Address::random())?;
            assert!(!answer.is_revert());
            let (found, ..) = <(Address, u64, u64, u64)>::abi_decode_params(&answer.bytes)?;
            assert_eq!(found, validator);

            // Before T12 the registry is upstream's and does not know the selector.
            vc.storage.set_spec(TempoHardfork::T11);
            let unknown = vc.call(&call, Address::random())?;
            assert!(unknown.is_revert());
            Ok(())
        })?;

        // The same with no time set at all.
        let mut storage = HashMapStorageProvider::new_with_spec(CHAIN_ID, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            let call = double_notarize(&key, EPOCH).abi_encode();
            let unknown = vc.call(&call, Address::random()).unwrap();
            assert!(unknown.is_revert());
            let upstream = crate::dispatch::unknown_selector_result(&call).unwrap();
            assert_eq!(unknown.bytes, upstream.bytes);
        });
        Ok(())
    }
}
