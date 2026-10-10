//! Votes a third party can hold their signer to.
//!
//! A threshold partial signature is no evidence against its signer: a quorum of them forges
//! anyone's. So each vote also carries the signature of its signer's vote key, the BLS key the
//! registry holds for it. Without it the vote does not count; [`crate::equivocation`] is what two
//! of them prove. Certificates stay the threshold scheme's, byte for byte.

use std::{collections::BTreeSet, sync::Arc};

use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use commonware_actor::Feedback;
use commonware_codec::{Encode, Error, FixedSize, Read, ReadExt as _, Write};
use commonware_consensus::{
    Reporter,
    simplex::{
        scheme::bls12381_threshold::vrf,
        types::{Activity, Finalization, Finalize, Notarization, Notarize, Nullify, Subject},
    },
    types::Participant,
};
use commonware_cryptography::{
    Digest,
    bls12381::primitives::{
        group::Private,
        ops::{self, batch},
        variant::MinSig,
    },
    certificate::{self, AssemblyError, Attestation, Verification},
    ed25519::PublicKey,
};
use commonware_parallel::Strategy;
use commonware_utils::{Faults as _, N3f1, iter::NonEmpty, ordered};
use rand_core::CryptoRng;
use tempo_precompiles::validator_config_v2::{Signed, VoteKey, VoteNamespace, VoteSignature};
use tracing::error;

use crate::{
    equivocation::{Votes, ballot},
    utils::public_key_to_b256,
};

type Threshold = vrf::Scheme<PublicKey, MinSig>;

/// The threshold scheme, with every vote also signed by its signer's vote key.
#[derive(Clone, Debug)]
pub(crate) struct Scheme {
    threshold: Threshold,
    /// What vote keys sign this chain's votes under.
    namespace: Arc<VoteNamespace>,
    /// Each participant's vote key, at its place, if the registry holds one.
    keys: Arc<[Option<VoteKey>]>,
    /// Our vote key, if it is the one at our share's place.
    signer: Option<Private>,
}

impl Scheme {
    /// `keys` are the participants' vote keys in their order, `signer` ours. A participant
    /// without one is mute, and with too few keyed to certify so is the epoch.
    pub(crate) fn new(
        threshold: Threshold,
        keys: &[Option<VoteKey>],
        signer: Private,
        chain_id: u64,
        genesis: B256,
    ) -> Self {
        let keyed = keys.iter().flatten().count();
        let quorum = N3f1::quorum(threshold.participants().len()) as usize;
        if keyed < quorum {
            error!(
                keyed,
                quorum, "too few of this epoch's participants have a vote key to certify anything"
            );
        }
        let mut scheme = Self {
            threshold,
            namespace: Arc::new(VoteNamespace::new(chain_id, genesis)),
            keys: keys.into(),
            signer: None,
        };
        if let Some(me) = certificate::Scheme::me(&scheme.threshold) {
            if scheme.key(me) == Some(ops::compute_public::<MinSig>(&signer)) {
                scheme.signer = Some(signer);
            } else {
                error!("the registry does not hold our vote key for our share; verifying only");
            }
        }
        scheme
    }

    /// The vote key of `signer`, if the registry holds one.
    fn key(&self, signer: Participant) -> Option<VoteKey> {
        *self.keys.get(usize::from(signer))?
    }

    /// A vote's threshold half as that scheme takes it, and its signer's vote key with the
    /// signature it is to have made.
    fn split(
        &self,
        attestation: &Attestation<Self>,
    ) -> Option<(Attestation<Threshold>, (VoteKey, VoteSignature))> {
        let signature = attestation.signature.get()?;
        let partial = Attestation {
            signer: attestation.signer,
            signature: signature.threshold.clone().into(),
        };
        Some((partial, (self.key(attestation.signer)?, signature.identity)))
    }
}

/// A vote's signatures: the threshold scheme's partials and its signer's vote key's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Signature {
    threshold: vrf::Signature<MinSig>,
    identity: VoteSignature,
}

impl Write for Signature {
    fn write(&self, writer: &mut impl BufMut) {
        self.threshold.write(writer);
        self.identity.write(writer);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            threshold: vrf::Signature::read(reader)?,
            identity: VoteSignature::read(reader)?,
        })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = vrf::Signature::<MinSig>::SIZE + VoteSignature::SIZE;
}

impl certificate::Verifier for Scheme {
    type Subject<'a, D: Digest> = Subject<'a, D>;
    type Faults = N3f1;
    type PublicKey = PublicKey;
    type Certificate = vrf::Certificate<MinSig>;

    fn verify_certificate<R, D>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        self.threshold
            .verify_certificate(rng, subject, certificate, strategy)
    }

    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        certificates: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        I: Iterator<Item = (Subject<'a, D>, &'a Self::Certificate)>,
    {
        self.threshold
            .verify_certificates(rng, certificates, strategy)
    }

    fn is_batchable() -> bool {
        Threshold::is_batchable()
    }

    fn certificate_codec_config(&self) {}

    fn certificate_codec_config_unbounded() {}
}

impl certificate::Scheme for Scheme {
    type Signature = Signature;

    /// Our place, if both halves of a vote are ours to sign from it.
    fn me(&self) -> Option<Participant> {
        self.signer.as_ref()?;
        certificate::Scheme::me(&self.threshold)
    }

    fn participants(&self) -> &ordered::Set<PublicKey> {
        self.threshold.participants()
    }

    fn sign<D: Digest>(&self, subject: Subject<'_, D>) -> Option<Attestation<Self>> {
        let ballot = ballot(subject)?;
        let namespace = self.namespace.of(&ballot);
        let identity =
            ops::sign_message::<MinSig>(self.signer.as_ref()?, namespace, &ballot.body());
        let partial = self.threshold.sign(subject)?;
        let signature = Signature {
            threshold: partial.signature.get()?.clone(),
            identity,
        };
        Some(Attestation {
            signer: partial.signer,
            signature: signature.into(),
        })
    }

    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        let (Some(ballot), Some((partial, (key, signature)))) =
            (ballot(subject), self.split(attestation))
        else {
            return false;
        };
        Signed { ballot, signature }.verify(&self.namespace, &key)
            && self
                .threshold
                .verify_attestation(rng, subject, &partial, strategy)
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let ballot = ballot(subject);
        let mut invalid = BTreeSet::new();
        let (mut votes, mut partials, mut signed) = (Vec::new(), Vec::new(), Vec::new());
        for attestation in attestations {
            let Some((partial, vote)) = ballot.and_then(|_| self.split(&attestation)) else {
                invalid.insert(attestation.signer);
                continue;
            };
            votes.push(attestation);
            partials.push(partial);
            signed.push(vote);
        }

        // The vote keys sign one message, so their signatures verify as one batch, and the
        // partials of those that hold as another.
        if let (Some(ballot), Some(signed)) = (ballot, NonEmpty::try_new(signed.into_iter())) {
            let (namespace, body) = (self.namespace.of(&ballot), ballot.body());
            let failed =
                batch::verify_same_message::<_, MinSig, _>(rng, namespace, &body, signed, strategy);
            invalid.extend(failed.into_iter().map(|place| votes[place].signer));
            partials.retain(|partial| !invalid.contains(&partial.signer));
        }
        let partials = self
            .threshold
            .verify_attestations(rng, subject, partials, strategy);
        invalid.extend(partials.invalid);
        votes.retain(|vote| !invalid.contains(&vote.signer));
        Verification::new(votes, invalid.into_iter().collect())
    }

    fn assemble<I>(
        &self,
        attestations: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, AssemblyError>
    where
        I: Iterator<Item = Attestation<Self>> + Send,
    {
        let partials = attestations
            .into_iter()
            .map(|attestation| {
                let halves = self.split(&attestation);
                let (partial, _) =
                    halves.ok_or(AssemblyError::MalformedSignature(attestation.signer))?;
                Ok(partial)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let partials =
            NonEmpty::try_new(partials.into_iter()).expect("made from as many attestations");
        self.threshold.assemble(partials, strategy)
    }

    fn is_attributable() -> bool {
        true
    }
}

/// Hands a reporter of the threshold scheme the certificates an engine reports under [`Scheme`],
/// and keeps the votes it reports.
#[derive(Clone)]
pub(crate) struct Recorder<R> {
    pub(crate) scheme: Scheme,
    pub(crate) votes: Votes,
    pub(crate) certificates: R,
}

impl<R> Recorder<R> {
    /// Keeps the vote on `subject` under its signer's vote key's signature.
    fn keep<D: Digest>(&self, subject: Subject<'_, D>, attestation: &Attestation<Scheme>) {
        let threshold = &self.scheme.threshold;
        if let Some(ballot) = ballot(subject)
            && let Some(signature) = attestation.signature.get()
            && let Some(signer) = threshold.participants().get(attestation.signer.into())
            && let Some(key) = self.scheme.key(attestation.signer)
        {
            let signed = Signed {
                ballot,
                signature: signature.identity,
            };
            self.votes.record(public_key_to_b256(signer), key, signed);
        }
    }
}

/// The two votes of a conflict the engine reports. It exposes neither, but encodes one after the
/// other.
fn halves<A: Read<Cfg = ()>, B: Read<Cfg = ()>>(conflict: &impl Encode) -> Option<(A, B)> {
    let mut encoded = conflict.encode();
    Some((A::read(&mut encoded).ok()?, B::read(&mut encoded).ok()?))
}

impl<R, D> Reporter for Recorder<R>
where
    R: Reporter<Activity = Activity<Threshold, D>>,
    D: Digest,
{
    type Activity = Activity<Scheme, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let notarize = |vote: &Notarize<Scheme, D>| {
            let proposal = &vote.proposal;
            self.keep(Subject::Notarize { proposal }, &vote.attestation)
        };
        let nullify = |vote: &Nullify<Scheme>| {
            let round = vote.round;
            self.keep(Subject::<D>::Nullify { round }, &vote.attestation)
        };
        let finalize = |vote: &Finalize<Scheme, D>| {
            let proposal = &vote.proposal;
            self.keep(Subject::Finalize { proposal }, &vote.attestation)
        };
        match activity {
            // Marshal reads no other activity.
            Activity::Notarization(Notarization {
                proposal,
                certificate,
            }) => {
                return self
                    .certificates
                    .report(Activity::Notarization(Notarization {
                        proposal,
                        certificate,
                    }));
            }
            Activity::Finalization(Finalization {
                proposal,
                certificate,
            }) => {
                return self
                    .certificates
                    .report(Activity::Finalization(Finalization {
                        proposal,
                        certificate,
                    }));
            }
            Activity::Certification(_) | Activity::Nullification(_) => {}
            Activity::Notarize(vote) => notarize(&vote),
            Activity::Nullify(vote) => nullify(&vote),
            Activity::Finalize(vote) => finalize(&vote),
            Activity::ConflictingNotarize(conflict) => {
                if let Some((first, second)) = halves(&conflict) {
                    notarize(&first);
                    notarize(&second);
                }
            }
            Activity::ConflictingFinalize(conflict) => {
                if let Some((first, second)) = halves(&conflict) {
                    finalize(&first);
                    finalize(&second);
                }
            }
            Activity::NullifyFinalize(conflict) => {
                if let Some((first, second)) = halves(&conflict) {
                    nullify(&first);
                    finalize(&second);
                }
            }
        }
        Feedback::Ok
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use commonware_consensus::{
        simplex::types::{ConflictingFinalize, ConflictingNotarize, NullifyFinalize, Proposal},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        Signer as _,
        bls12381::{dkg::feldman_desmedt as dkg, primitives::sharing::Mode},
        certificate::{Scheme as _, Verifier as _},
        ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_utils::TryFromIterator as _;
    use rand::{SeedableRng as _, rngs::StdRng};
    use tempo_validator_config::VoteKeypair;

    use super::*;
    use crate::consensus::Digest;

    pub(crate) const CHAIN_ID: u64 = 787_222;
    pub(crate) const GENESIS: B256 = B256::repeat_byte(1);

    /// Four participants over one dealt output: each one's key and threshold scheme, in the
    /// participants' order. The same `seed` deals the same.
    pub(crate) fn dealt(seed: u64) -> Vec<(PrivateKey, Threshold)> {
        let mut rng = StdRng::seed_from_u64(seed);
        let keys: Vec<_> = (0..4).map(|_| PrivateKey::random(&mut rng)).collect();
        let players = ordered::Set::try_from_iter(keys.iter().map(|key| key.public_key())).unwrap();
        let (output, shares) =
            dkg::deal::<_, _, N3f1>(&mut rng, Mode::NonZeroCounter, players).unwrap();
        shares
            .into_iter()
            .map(|(player, share)| {
                let threshold = Threshold::signer(
                    crate::config::NAMESPACE,
                    output.players().clone(),
                    output.public().clone(),
                    share,
                )
                .unwrap();
                let key = keys.iter().find(|key| key.public_key() == player).unwrap();
                (key.clone(), threshold)
            })
            .collect()
    }

    /// Those four under the threshold scheme and under [`Scheme`], the registry holding each
    /// one's vote key but those of `keyless`.
    pub(crate) fn signers(
        keyless: &[usize],
        seed: u64,
        chain_id: u64,
        genesis: B256,
    ) -> Vec<(Threshold, Scheme)> {
        let dealt = dealt(seed);
        let keys: Vec<_> = dealt
            .iter()
            .enumerate()
            .map(|(place, (key, _))| {
                (!keyless.contains(&place)).then(|| VoteKeypair::derive(key).public())
            })
            .collect();
        dealt
            .into_iter()
            .map(|(key, threshold)| {
                let signer = VoteKeypair::derive(&key).private();
                let scheme = Scheme::new(threshold.clone(), &keys, signer, chain_id, genesis);
                (threshold, scheme)
            })
            .collect()
    }

    fn proposal() -> Proposal<Digest> {
        Proposal::new(
            Round::new(Epoch::zero(), View::new(2)),
            View::new(1),
            Digest(B256::repeat_byte(1)),
        )
    }

    #[test]
    fn votes_assemble_the_threshold_schemes_certificate() {
        let mut rng = StdRng::seed_from_u64(0);
        let signers = signers(&[], 1, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let (threshold, scheme) = &signers[0];

        let votes: Vec<_> = signers
            .iter()
            .map(|(_, scheme)| scheme.sign(subject).unwrap())
            .collect();
        let checked = scheme.verify_attestations(&mut rng, subject, votes.clone(), &Sequential);
        assert_eq!(checked.verified.len(), signers.len());
        assert!(checked.invalid.is_empty());

        let partials = signers
            .iter()
            .map(|(threshold, _)| threshold.sign(subject).unwrap());
        let expected = threshold
            .assemble(NonEmpty::try_new(partials).unwrap(), &Sequential)
            .unwrap();
        let certificate = scheme
            .assemble(NonEmpty::try_new(votes.into_iter()).unwrap(), &Sequential)
            .unwrap();
        assert_eq!(certificate.encode(), expected.encode());
        assert!(threshold.verify_certificate(&mut rng, subject, &certificate, &Sequential));
    }

    #[test]
    fn a_vote_counts_only_under_its_signers_vote_key() {
        let mut rng = StdRng::seed_from_u64(0);
        let signers = signers(&[], 2, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let scheme = &signers[0].1;

        let mut votes: Vec<_> = signers
            .iter()
            .map(|(_, scheme)| scheme.sign(subject).unwrap())
            .collect();
        // The second signer's valid partials, under the third's valid signature.
        let borrowed = Signature {
            threshold: votes[1].signature.get().unwrap().threshold.clone(),
            identity: votes[2].signature.get().unwrap().identity,
        };
        votes[1].signature = borrowed.into();
        assert!(!scheme.verify_attestation(&mut rng, subject, &votes[1], &Sequential));
        assert!(scheme.verify_attestation(&mut rng, subject, &votes[2], &Sequential));

        let checked = scheme.verify_attestations(&mut rng, subject, votes.clone(), &Sequential);
        assert_eq!(checked.invalid, vec![votes[1].signer]);
        assert_eq!(checked.verified.len(), signers.len() - 1);
    }

    /// The other three of four, a quorum, vote and certify between them.
    #[test]
    fn a_participant_without_a_vote_key_is_mute() {
        let mut rng = StdRng::seed_from_u64(0);
        let signers = signers(&[1], 8, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let (threshold, scheme) = &signers[0];

        let keyless = &signers[1].1;
        assert_eq!(keyless.me(), None);
        assert!(keyless.sign(subject).is_none());

        let mut votes: Vec<_> = [0, 2, 3]
            .map(|place| signers[place].1.sign(subject).unwrap())
            .into();
        let checked = keyless.verify_attestations(&mut rng, subject, votes.clone(), &Sequential);
        let verified: Vec<_> = checked.verified.iter().map(|vote| vote.signer).collect();
        assert_eq!(verified, [0, 2, 3].map(Participant::new));
        let certificate = scheme
            .assemble(
                NonEmpty::try_new(votes.clone().into_iter()).unwrap(),
                &Sequential,
            )
            .unwrap();
        assert!(threshold.verify_certificate(&mut rng, subject, &certificate, &Sequential));

        // Its share alone signs nothing that counts, under whoever's signature.
        let partial = signers[1].0.sign(subject).unwrap();
        votes[0] = Attestation {
            signer: partial.signer,
            signature: Signature {
                threshold: partial.signature.get().unwrap().clone(),
                identity: votes[1].signature.get().unwrap().identity,
            }
            .into(),
        };
        assert!(!scheme.verify_attestation(&mut rng, subject, &votes[0], &Sequential));
        let checked = scheme.verify_attestations(&mut rng, subject, votes, &Sequential);
        assert_eq!(checked.invalid, [Participant::new(1)]);
        assert_eq!(checked.verified.len(), 2);
    }

    #[test]
    fn a_scheme_stands_on_fewer_vote_keys_than_a_quorum() {
        let mut rng = StdRng::seed_from_u64(0);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        for keyless in [&[2, 3][..], &[0, 1, 2, 3]] {
            let signers = signers(keyless, 9, CHAIN_ID, GENESIS);
            let votes: Vec<_> = signers
                .iter()
                .filter_map(|(_, scheme)| scheme.sign(subject))
                .collect();
            let checked = signers[3]
                .1
                .verify_attestations(&mut rng, subject, votes, &Sequential);
            assert_eq!(checked.verified.len(), 4 - keyless.len());
        }
    }

    /// A node whose vote key the registry does not hold for its share would sign votes that fail
    /// their own check: it verifies instead of stopping.
    #[test]
    fn a_vote_key_that_is_not_its_shares_makes_a_verifier() {
        let mut rng = StdRng::seed_from_u64(0);
        let dealt = dealt(6);
        let signers = signers(&[], 6, CHAIN_ID, GENESIS);
        let keys: Vec<_> = dealt
            .iter()
            .map(|(key, _)| Some(VoteKeypair::derive(key).public()))
            .collect();
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let vote = signers[2].1.sign(subject).unwrap();

        // Another participant's key, and one that is nobody's.
        for key in [dealt[1].0.clone(), PrivateKey::random(&mut rng)] {
            let signer = VoteKeypair::derive(&key).private();
            let mismatched = Scheme::new(dealt[0].1.clone(), &keys, signer, CHAIN_ID, GENESIS);
            assert_eq!(mismatched.me(), None);
            assert!(mismatched.sign(subject).is_none());
            assert!(mismatched.verify_attestation(&mut rng, subject, &vote, &Sequential));
        }
    }

    #[test]
    fn a_vote_signed_for_another_chain_does_not_count() {
        let mut rng = StdRng::seed_from_u64(0);
        let here = signers(&[], 3, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        // Same keys, same shares, same vote: only the chain differs, by its id or by its genesis.
        for elsewhere in [
            signers(&[], 3, CHAIN_ID + 1, GENESIS),
            signers(&[], 3, CHAIN_ID, B256::repeat_byte(2)),
        ] {
            let vote = elsewhere[1].1.sign(subject).unwrap();
            assert!(
                elsewhere[0]
                    .1
                    .verify_attestation(&mut rng, subject, &vote, &Sequential)
            );
            assert!(
                !here[0]
                    .1
                    .verify_attestation(&mut rng, subject, &vote, &Sequential)
            );
        }
    }

    /// Takes the certificates a [`Recorder`] under test hands on.
    #[derive(Clone)]
    struct Nowhere;

    impl Reporter for Nowhere {
        type Activity = Activity<Threshold, Digest>;

        fn report(&mut self, _: Self::Activity) -> Feedback {
            Feedback::Ok
        }
    }

    #[test]
    fn a_conflict_the_engine_reports_is_kept_as_evidence() {
        let mut rng = StdRng::seed_from_u64(0);
        let signers = signers(&[], 5, CHAIN_ID, GENESIS);
        let key = VoteKeypair::derive(&dealt(5)[1].0).public();
        let double = &signers[1].1;
        let (first, round) = (proposal(), proposal().round);
        let second = Proposal::new(round, View::new(1), Digest(B256::repeat_byte(2)));
        let notarize = |proposal: &Proposal<Digest>| Notarize::sign(double, proposal.clone());
        let finalize = |proposal: &Proposal<Digest>| Finalize::sign(double, proposal.clone());

        // The library's own conflict holds against the keys the scheme knows.
        let conflict =
            ConflictingNotarize::new(notarize(&first).unwrap(), notarize(&second).unwrap());
        assert!(conflict.verify(&mut rng, &signers[0].1, &Sequential));

        for conflict in [
            Activity::ConflictingNotarize(conflict),
            Activity::ConflictingFinalize(ConflictingFinalize::new(
                finalize(&first).unwrap(),
                finalize(&second).unwrap(),
            )),
            Activity::NullifyFinalize(NullifyFinalize::new(
                Nullify::sign::<Digest>(double, round).unwrap(),
                finalize(&first).unwrap(),
            )),
        ] {
            let votes = Votes::new(VoteNamespace::new(CHAIN_ID, GENESIS));
            let mut recorder = Recorder {
                scheme: signers[0].1.clone(),
                votes: votes.clone(),
                certificates: Nowhere,
            };
            recorder.report(conflict);

            let evidence = votes.evidence();
            assert_eq!(evidence.len(), 1);
            assert!(evidence[0].verify(&VoteNamespace::new(CHAIN_ID, GENESIS), &key));
        }
    }

    /// A vote grows by one BLS signature in the threshold scheme's group.
    #[test]
    fn a_signature_round_trips() {
        let signers = signers(&[], 4, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let vote = signers[0]
            .1
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();
        let signature = vote.signature.get().unwrap();
        let encoded = signature.encode();
        assert_eq!(encoded.len(), vrf::Signature::<MinSig>::SIZE + 48);
        assert_eq!(&Signature::read(&mut encoded.as_ref()).unwrap(), signature);
    }
}
