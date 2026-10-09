//! Votes a third party can hold their signer to.
//!
//! A threshold partial signature is no evidence against its signer: a quorum of them forges
//! anyone's. So each vote also carries its signer's ed25519 signature, without which it does not
//! count; [`crate::equivocation`] is what two of those prove. Certificates stay the threshold
//! scheme's, byte for byte.

use std::collections::BTreeMap;

use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use commonware_actor::Feedback;
use commonware_codec::{Encode, Error, FixedSize, Read, ReadExt as _, Write};
use commonware_consensus::{
    Reporter,
    simplex::{
        scheme::{Namespace, bls12381_threshold::vrf},
        types::{Activity, Finalization, Finalize, Notarization, Notarize, Nullify, Subject},
    },
    types::Participant,
};
use commonware_cryptography::{
    Digest, Signer as _, Verifier as _,
    bls12381::primitives::variant::MinSig,
    certificate::{self, AssemblyError, Attestation, Subject as _, Verification},
    ed25519::{self, PrivateKey, PublicKey},
};
use commonware_parallel::Strategy;
use commonware_utils::{N3f1, iter::NonEmpty, ordered::Set};
use rand_core::CryptoRng;
use tracing::error;

use crate::equivocation::{Ballot, Signed, Votes, namespace};

type Threshold = vrf::Scheme<PublicKey, MinSig>;

/// The threshold scheme, with every vote also signed by its signer's ed25519 key.
#[derive(Clone, Debug)]
pub(crate) struct Scheme {
    threshold: Threshold,
    signer: PrivateKey,
    /// Whether our share sits at our key's place among the participants. Where it does not, a
    /// vote of ours would fail its own check, so we verify and do not sign.
    signs: bool,
    /// This chain's [`namespace`], which the signers' own signatures are made under.
    namespace: Namespace,
}

impl Scheme {
    pub(crate) fn new(
        threshold: Threshold,
        signer: PrivateKey,
        chain_id: u64,
        genesis: B256,
    ) -> Self {
        let signs = certificate::Scheme::me(&threshold)
            .is_none_or(|me| threshold.participants().get(me.into()) == Some(&signer.public_key()));
        if !signs {
            error!(
                "our share does not sit at our key's place among the participants; verifying only"
            );
        }
        Self {
            threshold,
            signer,
            signs,
            namespace: namespace(chain_id, genesis),
        }
    }

    fn signed_by<D: Digest>(
        &self,
        subject: &Subject<'_, D>,
        signer: Participant,
        signature: &ed25519::Signature,
    ) -> bool {
        self.threshold
            .participants()
            .get(signer.into())
            .is_some_and(|key| {
                key.verify(
                    subject.namespace(&self.namespace),
                    &subject.message(),
                    signature,
                )
            })
    }
}

/// A vote's threshold partial signatures and its signer's own signature over the same vote.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Signature {
    threshold: vrf::Signature<MinSig>,
    identity: ed25519::Signature,
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
            identity: ed25519::Signature::read(reader)?,
        })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = vrf::Signature::<MinSig>::SIZE + ed25519::Signature::SIZE;
}

/// The vote as the threshold scheme takes it.
fn partial(attestation: &Attestation<Scheme>) -> Option<Attestation<Threshold>> {
    Some(Attestation {
        signer: attestation.signer,
        signature: attestation.signature.get()?.threshold.clone().into(),
    })
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

    fn me(&self) -> Option<Participant> {
        self.signs
            .then(|| certificate::Scheme::me(&self.threshold))
            .flatten()
    }

    fn participants(&self) -> &Set<PublicKey> {
        self.threshold.participants()
    }

    fn sign<D: Digest>(&self, subject: Subject<'_, D>) -> Option<Attestation<Self>> {
        if !self.signs {
            return None;
        }
        let Attestation { signer, signature } = self.threshold.sign(subject)?;
        let signature = Signature {
            threshold: signature.get()?.clone(),
            identity: self
                .signer
                .sign(subject.namespace(&self.namespace), &subject.message()),
        };
        Some(Attestation {
            signer,
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
        let (Some(signature), Some(partial)) = (attestation.signature.get(), partial(attestation))
        else {
            return false;
        };
        self.signed_by(&subject, attestation.signer, &signature.identity)
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
        // The partials go to the threshold scheme together, so it still verifies them as a batch.
        let mut invalid = Vec::new();
        let mut signed = BTreeMap::new();
        let mut partials = Vec::new();
        for attestation in attestations {
            match (attestation.signature.get(), partial(&attestation)) {
                (Some(signature), Some(partial))
                    if self.signed_by(&subject, attestation.signer, &signature.identity) =>
                {
                    partials.push(partial);
                    signed.insert(attestation.signer, attestation);
                }
                _ => invalid.push(attestation.signer),
            }
        }

        let partials = self
            .threshold
            .verify_attestations(rng, subject, partials, strategy);
        invalid.extend(partials.invalid);
        let verified = partials
            .verified
            .iter()
            .filter_map(|partial| signed.remove(&partial.signer))
            .collect();
        Verification::new(verified, invalid)
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
                partial(&attestation).ok_or(AssemblyError::MalformedSignature(attestation.signer))
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
pub(crate) struct Recorder<R, D: Digest> {
    pub(crate) scheme: Scheme,
    pub(crate) votes: Votes<D>,
    pub(crate) certificates: R,
}

impl<R, D: Digest> Recorder<R, D> {
    fn keep(&self, ballot: Ballot<D>, attestation: &Attestation<Scheme>) {
        if let Some(signature) = attestation.signature.get()
            && let Some(signer) = self
                .scheme
                .threshold
                .participants()
                .get(attestation.signer.into())
        {
            let signed = Signed {
                ballot,
                signature: signature.identity.clone(),
            };
            self.votes.record(signer.clone(), signed);
        }
    }
}

/// The two votes of a conflict the engine reports. It exposes neither, but encodes one after the
/// other.
fn halves<A: Read<Cfg = ()>, B: Read<Cfg = ()>>(conflict: &impl Encode) -> Option<(A, B)> {
    let mut encoded = conflict.encode();
    Some((A::read(&mut encoded).ok()?, B::read(&mut encoded).ok()?))
}

impl<R, D> Reporter for Recorder<R, D>
where
    R: Reporter<Activity = Activity<Threshold, D>>,
    D: Digest,
{
    type Activity = Activity<Scheme, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let notarize =
            |vote: Notarize<Scheme, D>| (Ballot::Notarize(vote.proposal), vote.attestation);
        let nullify = |vote: Nullify<Scheme>| (Ballot::Nullify(vote.round), vote.attestation);
        let finalize =
            |vote: Finalize<Scheme, D>| (Ballot::Finalize(vote.proposal), vote.attestation);
        let votes = match activity {
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
            Activity::Certification(_) | Activity::Nullification(_) => return Feedback::Ok,
            Activity::Notarize(vote) => vec![notarize(vote)],
            Activity::Nullify(vote) => vec![nullify(vote)],
            Activity::Finalize(vote) => vec![finalize(vote)],
            Activity::ConflictingNotarize(conflict) => halves(&conflict)
                .map(|(first, second)| vec![notarize(first), notarize(second)])
                .unwrap_or_default(),
            Activity::ConflictingFinalize(conflict) => halves(&conflict)
                .map(|(first, second)| vec![finalize(first), finalize(second)])
                .unwrap_or_default(),
            Activity::NullifyFinalize(conflict) => halves(&conflict)
                .map(|(first, second)| vec![nullify(first), finalize(second)])
                .unwrap_or_default(),
        };
        for (ballot, attestation) in votes {
            self.keep(ballot, &attestation);
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
        bls12381::{dkg::feldman_desmedt as dkg, primitives::sharing::Mode},
        certificate::{Scheme as _, Verifier as _},
    };
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_utils::{TryFromIterator as _, ordered};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::consensus::Digest;

    pub(crate) const CHAIN_ID: u64 = 787_222;
    pub(crate) const GENESIS: B256 = B256::repeat_byte(1);

    /// Four signers over one dealt output, each under the threshold scheme and under [`Scheme`].
    /// The same `seed` deals the same keys and shares.
    pub(crate) fn signers(seed: u64, chain_id: u64, genesis: B256) -> Vec<(Threshold, Scheme)> {
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
                (
                    threshold.clone(),
                    Scheme::new(threshold, key.clone(), chain_id, genesis),
                )
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
        let signers = signers(1, CHAIN_ID, GENESIS);
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
    fn a_vote_counts_only_under_its_signers_own_signature() {
        let mut rng = StdRng::seed_from_u64(0);
        let signers = signers(2, CHAIN_ID, GENESIS);
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
            identity: votes[2].signature.get().unwrap().identity.clone(),
        };
        votes[1].signature = borrowed.into();
        assert!(!scheme.verify_attestation(&mut rng, subject, &votes[1], &Sequential));
        assert!(scheme.verify_attestation(&mut rng, subject, &votes[2], &Sequential));

        let checked = scheme.verify_attestations(&mut rng, subject, votes.clone(), &Sequential);
        assert_eq!(checked.invalid, vec![votes[1].signer]);
        assert_eq!(checked.verified.len(), signers.len() - 1);
    }

    /// A node whose share is not its key's would sign votes that fail their own check: it
    /// verifies instead of stopping.
    #[test]
    fn a_share_at_another_keys_place_makes_a_verifier() {
        let mut rng = StdRng::seed_from_u64(0);
        let signers = signers(6, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let mismatched = Scheme::new(
            signers[0].0.clone(),
            signers[1].1.signer.clone(),
            CHAIN_ID,
            GENESIS,
        );
        assert_eq!(certificate::Scheme::me(&mismatched), None);
        assert!(mismatched.sign(subject).is_none());

        let vote = signers[2].1.sign(subject).unwrap();
        assert!(mismatched.verify_attestation(&mut rng, subject, &vote, &Sequential));
    }

    #[test]
    fn a_vote_signed_for_another_chain_does_not_count() {
        let mut rng = StdRng::seed_from_u64(0);
        let here = signers(3, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        // Same keys, same shares, same vote: only the chain differs, by its id or by its genesis.
        for elsewhere in [
            signers(3, CHAIN_ID + 1, GENESIS),
            signers(3, CHAIN_ID, B256::repeat_byte(2)),
        ] {
            let vote = elsewhere[1].1.sign(subject).unwrap();
            assert!(
                elsewhere[0]
                    .1
                    .verify_attestation(&mut rng, subject, &vote, &Sequential)
            );
            let moved = Attestation {
                signer: vote.signer,
                signature: vote.signature.get().unwrap().clone().into(),
            };
            assert!(
                !here[0]
                    .1
                    .verify_attestation(&mut rng, subject, &moved, &Sequential)
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
        let signers = signers(5, CHAIN_ID, GENESIS);
        let double = &signers[1].1;
        let (first, round) = (proposal(), proposal().round);
        let second = Proposal::new(round, View::new(1), Digest(B256::repeat_byte(2)));
        let notarize = |proposal: &Proposal<Digest>| Notarize::sign(double, proposal.clone());
        let finalize = |proposal: &Proposal<Digest>| Finalize::sign(double, proposal.clone());

        for conflict in [
            Activity::ConflictingNotarize(ConflictingNotarize::new(
                notarize(&first).unwrap(),
                notarize(&second).unwrap(),
            )),
            Activity::ConflictingFinalize(ConflictingFinalize::new(
                finalize(&first).unwrap(),
                finalize(&second).unwrap(),
            )),
            Activity::NullifyFinalize(NullifyFinalize::new(
                Nullify::sign::<Digest>(double, round).unwrap(),
                finalize(&first).unwrap(),
            )),
        ] {
            let votes = Votes::new(namespace(CHAIN_ID, GENESIS));
            let mut recorder = Recorder {
                scheme: signers[0].1.clone(),
                votes: votes.clone(),
                certificates: Nowhere,
            };
            recorder.report(conflict);

            let evidence = votes.evidence();
            assert_eq!(evidence.len(), 1);
            assert!(evidence[0].verify(&namespace(CHAIN_ID, GENESIS)));
        }
    }

    #[test]
    fn a_signature_round_trips() {
        let signers = signers(4, CHAIN_ID, GENESIS);
        let proposal = proposal();
        let vote = signers[0]
            .1
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();
        let signature = vote.signature.get().unwrap();
        let encoded = signature.encode();
        assert_eq!(encoded.len(), Signature::SIZE);
        assert_eq!(&Signature::read(&mut encoded.as_ref()).unwrap(), signature);
    }
}
