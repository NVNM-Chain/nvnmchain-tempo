//! Evidence that a validator signed conflicting votes in one round, as the node keeps and encodes
//! it:
//!
//! ```text
//! evidence = validator key (32) | ballot | ballot
//! ballot   = kind (1) | body | BLS signature (48)
//! body     = epoch | view                            for a nullify (1)
//!          = epoch | view | parent | payload (32)    for a notarize (0) or a finalize (2)
//! ```
//!
//! The integers are varints. A signature is the validator's vote key's, over its ballot's body,
//! under this chain's namespace for the kind.

use super::{
    IEquivocation, ValidatorConfigV2, ValidatorConfigV2Error,
    vote_key::{BLS_VERIFY_GAS, VoteKey, VoteSignature},
};
use crate::error::Result;
use alloy::primitives::B256;
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt as _, EncodeSize, Error, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};

const NOTARIZE: u8 = 0;
const NULLIFY: u8 = 1;
const FINALIZE: u8 = 2;

/// A round of consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Round {
    pub epoch: u64,
    pub view: u64,
}

/// A proposal as the votes for it name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub round: Round,
    pub parent: u64,
    pub payload: B256,
}

/// What one signer says about one round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ballot {
    Notarize(Proposal),
    Nullify(Round),
    Finalize(Proposal),
}

impl Ballot {
    pub fn round(&self) -> Round {
        match self {
            Self::Notarize(proposal) | Self::Finalize(proposal) => proposal.round,
            Self::Nullify(round) => *round,
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Self::Notarize(_) => NOTARIZE,
            Self::Nullify(_) => NULLIFY,
            Self::Finalize(_) => FINALIZE,
        }
    }

    /// What a vote key signs for the ballot: its encoding past the kind.
    pub fn body(&self) -> Vec<u8> {
        let Round { epoch, view } = self.round();
        let mut body = Vec::new();
        UInt(epoch).write(&mut body);
        UInt(view).write(&mut body);
        if let Self::Notarize(proposal) | Self::Finalize(proposal) = self {
            UInt(proposal.parent).write(&mut body);
            body.extend(proposal.payload);
        }
        body
    }

    /// The three pairs no honest signer casts in one round: two proposals notarized, two
    /// finalized, or one finalized in a round it nullified.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.round() == other.round()
            && match (self, other) {
                (Self::Notarize(a), Self::Notarize(b)) | (Self::Finalize(a), Self::Finalize(b)) => {
                    a != b
                }
                (Self::Nullify(_), Self::Finalize(_)) | (Self::Finalize(_), Self::Nullify(_)) => {
                    true
                }
                _ => false,
            }
    }
}

impl Write for Ballot {
    fn write(&self, writer: &mut impl BufMut) {
        self.kind().write(writer);
        writer.put_slice(&self.body());
    }
}

impl EncodeSize for Ballot {
    fn encode_size(&self) -> usize {
        1 + self.body().len()
    }
}

impl Read for Ballot {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> core::result::Result<Self, Error> {
        let kind = u8::read(reader)?;
        let round = Round {
            epoch: UInt::<u64>::read(reader)?.into(),
            view: UInt::<u64>::read(reader)?.into(),
        };
        if kind == NULLIFY {
            return Ok(Self::Nullify(round));
        }
        let proposal = Proposal {
            round,
            parent: UInt::<u64>::read(reader)?.into(),
            payload: <[u8; 32]>::read(reader)?.into(),
        };
        match kind {
            NOTARIZE => Ok(Self::Notarize(proposal)),
            FINALIZE => Ok(Self::Finalize(proposal)),
            kind => Err(Error::InvalidEnum(kind)),
        }
    }
}

/// What a chain's vote keys sign each kind of vote under. The threshold scheme's namespace is the
/// same on every chain, and a key that signs on two chains, or on one restarted from a new
/// genesis, has not signed twice.
#[derive(Clone, Debug)]
pub struct VoteNamespace([Vec<u8>; 3]);

impl VoteNamespace {
    pub fn new(chain_id: u64, genesis: B256) -> Self {
        let chain_id = chain_id.to_be_bytes();
        let kinds = [b"_NOTARIZE".as_slice(), b"_NULLIFY", b"_FINALIZE"];
        Self(kinds.map(|kind| [b"TEMPO_ATTRIBUTABLE_", &chain_id[..], &genesis[..], kind].concat()))
    }

    /// The one `ballot` is signed under.
    pub fn of(&self, ballot: &Ballot) -> &[u8] {
        &self.0[usize::from(ballot.kind())]
    }
}

/// A ballot under its signer's vote key's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed {
    pub ballot: Ballot,
    pub signature: VoteSignature,
}

impl Signed {
    /// Whether the vote key `key` signed the ballot on the chain of `namespace`.
    pub fn verify(&self, namespace: &VoteNamespace, key: &VoteKey) -> bool {
        let (namespace, body) = (namespace.of(&self.ballot), self.ballot.body());
        ops::verify_message::<MinSig>(key, namespace, &body, &self.signature).is_ok()
    }
}

impl Write for Signed {
    fn write(&self, writer: &mut impl BufMut) {
        self.ballot.write(writer);
        self.signature.write(writer);
    }
}

impl EncodeSize for Signed {
    fn encode_size(&self) -> usize {
        self.ballot.encode_size() + self.signature.encode_size()
    }
}

impl Read for Signed {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> core::result::Result<Self, Error> {
        Ok(Self {
            ballot: Ballot::read(reader)?,
            signature: VoteSignature::read(reader)?,
        })
    }
}

/// Two ballots held against the validator key `signer`, whose vote key signed both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub signer: B256,
    pub first: Signed,
    pub second: Signed,
}

impl Evidence {
    /// Whether the ballots conflict and `key`, the signer's vote key as the registry holds it,
    /// signed both on the chain of `namespace`.
    pub fn verify(&self, namespace: &VoteNamespace, key: &VoteKey) -> bool {
        self.first.ballot.conflicts_with(&self.second.ballot)
            && self.first.verify(namespace, key)
            && self.second.verify(namespace, key)
    }
}

impl Write for Evidence {
    fn write(&self, writer: &mut impl BufMut) {
        writer.put_slice(self.signer.as_slice());
        self.first.write(writer);
        self.second.write(writer);
    }
}

impl EncodeSize for Evidence {
    fn encode_size(&self) -> usize {
        B256::len_bytes() + self.first.encode_size() + self.second.encode_size()
    }
}

impl Read for Evidence {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> core::result::Result<Self, Error> {
        Ok(Self {
            signer: <[u8; 32]>::read(reader)?.into(),
            first: Signed::read(reader)?,
            second: Signed::read(reader)?,
        })
    }
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

    /// The validator whose vote key signed both votes in the evidence, and their round.
    ///
    /// # Errors
    /// - `InvalidSignature` — the evidence does not decode, its votes do not conflict, they are
    ///   for an epoch yet to come, or the validator's vote key did not sign both on this chain
    /// - `ValidatorNotFound` — the registry does not hold the key, did not yet in that epoch, or
    ///   holds no vote key for it
    pub fn equivocator(
        &self,
        call: IEquivocation::equivocatorCall,
    ) -> Result<IEquivocation::equivocatorReturn> {
        let invalid = ValidatorConfigV2Error::invalid_signature;
        // Paid before any point is decoded.
        self.storage.deduct_gas(2 * BLS_VERIFY_GAS)?;
        let evidence = Evidence::decode(call.evidence.as_ref()).map_err(|_| invalid())?;
        let (round, key) = (evidence.first.ballot.round(), evidence.signer);

        // A validator's votes count only under the vote key registered for it.
        let vote_key = self
            .vote_key_of(key)?
            .ok_or_else(ValidatorConfigV2Error::validator_not_found)?;
        let namespace = VoteNamespace::new(self.storage.chain_id(), self.storage.genesis_hash());
        if !evidence.verify(&namespace, &vote_key) {
            Err(invalid())?
        }

        // The record of this key, live or left by a rotation, names the address its bond is
        // under. A key cannot have signed before that record held a seat. After it left one it
        // still answers: failed key ceremonies carry an old set on for any number of epochs, and
        // only the key itself can make the two signatures.
        let record = self.validator_by_public_key(key)?;
        let epoch_length = self
            .storage
            .with_block_env(|block_env| block_env.epoch_length.get());
        let epochs_ago = (self.storage.block_number() / epoch_length)
            .checked_sub(round.epoch)
            .ok_or_else(invalid)?;
        if round.epoch < record.addedAtHeight / epoch_length {
            Err(ValidatorConfigV2Error::validator_not_found())?
        }

        Ok(IEquivocation::equivocatorReturn {
            validator: record.validatorAddress,
            epoch: round.epoch,
            viewNumber: round.view,
            epochsAgo: epochs_ago,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::Address,
        sol_types::{SolCall as _, SolValue as _},
    };
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::IValidatorConfigV2;

    use super::{
        super::vote_key::tests::{
            CHAIN_ID, ENROLLED, GENESIS, NOW, enrolled, enrolment, register, vote_key,
        },
        *,
    };
    use crate::{
        Precompile as _,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        validator_config_v2::VALIDATOR_NS_ROTATE,
    };

    /// A round in the epoch between the validator's enrolment and now.
    const EPOCH: u64 = 205;

    /// A ballot of `kind` for view 3 of `epoch`, for the proposal `payload` names, signed by
    /// `key`'s vote key for `chain`, an id and a genesis hash.
    fn ballot(key: &PrivateKey, kind: u8, epoch: u64, payload: u8, chain: (u64, B256)) -> Vec<u8> {
        let mut body = Vec::new();
        UInt(epoch).write(&mut body);
        UInt(3u64).write(&mut body);
        if kind != NULLIFY {
            UInt(2u64).write(&mut body);
            body.extend([payload; 32]);
        }
        let namespace = &VoteNamespace::new(chain.0, chain.1).0[usize::from(kind)];
        let signature = ops::sign_message::<MinSig>(&vote_key(key), namespace, &body);
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

    /// A registry in which `key` was enrolled for `validator` at [`ENROLLED`] with its vote key,
    /// by [`NOW`], in a chain whose votes are attributable.
    fn with_registry<T>(
        key: &PrivateKey,
        validator: Address,
        owner: Address,
        test: impl FnOnce(&mut ValidatorConfigV2) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        enrolled(0, key, validator, owner, |vc| {
            register(vc, validator, 0, key)?;
            test(vc)
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
                let call = evidence(&key, &first, &second);
                // The codec writes what it read, which these tests spell out by hand.
                let decoded = Evidence::decode(call.evidence.as_ref()).unwrap();
                assert_eq!(decoded.encode().as_ref(), call.evidence.as_ref());

                let found = vc.equivocator(call)?;
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
            // One vote of the pair signed by another's vote key.
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
            // Its successor answers from the rotation on, once it has a vote key of its own.
            let unregistered = vc.equivocator(double_notarize(&successor, NOW));
            assert_eq!(unregistered, not_found);
            register(vc, validator, 0, &successor)?;
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
