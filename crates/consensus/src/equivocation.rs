//! Evidence that a validator signed conflicting votes.
//!
//! Once votes carry their signer's ed25519 signature, two of them over conflicting votes in one
//! round convict the key that signed both, with nothing but those signatures and the chain's
//! namespace. A signer that splits the pair between its peers shows each node only one, so a node
//! keeps what it saw for whoever compares several nodes.

use std::{collections::BTreeMap, sync::Arc};

use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_consensus::{
    simplex::{
        scheme::Namespace,
        types::{Proposal, Subject},
    },
    types::Round,
};
use commonware_cryptography::{
    Digest, Verifier as _,
    certificate::Subject as _,
    ed25519::{PublicKey, Signature},
};
use parking_lot::Mutex;

/// How many rounds a node keeps the votes of.
const RETAINED_ROUNDS: usize = 4_096;

/// How many pieces of evidence a node keeps.
const RETAINED_EVIDENCE: usize = 1_024;

/// What a node keeps of one signer in one round: its three votes and one that conflicts.
const BALLOTS_PER_SIGNER: usize = 4;

/// What signers' own signatures are made under on the chain of `chain_id` and `genesis`. The
/// threshold scheme's namespace is the same on every chain, and a key that signs on two chains,
/// or on one restarted from a new genesis, has not signed twice.
pub fn namespace(chain_id: u64, genesis: B256) -> Namespace {
    Namespace::new(
        &[
            crate::config::NAMESPACE,
            b"_ATTRIBUTABLE_",
            &chain_id.to_be_bytes(),
            genesis.as_slice(),
        ]
        .concat(),
    )
}

/// What one signer says about one round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ballot<D: Digest> {
    Notarize(Proposal<D>),
    Nullify(Round),
    Finalize(Proposal<D>),
}

impl<D: Digest> Ballot<D> {
    pub fn round(&self) -> Round {
        match self {
            Self::Notarize(proposal) | Self::Finalize(proposal) => proposal.round,
            Self::Nullify(round) => *round,
        }
    }

    fn subject(&self) -> Subject<'_, D> {
        match self {
            Self::Notarize(proposal) => Subject::Notarize { proposal },
            Self::Nullify(round) => Subject::Nullify { round: *round },
            Self::Finalize(proposal) => Subject::Finalize { proposal },
        }
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

impl<D: Digest> Write for Ballot<D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(proposal) => {
                0u8.write(writer);
                proposal.write(writer);
            }
            Self::Nullify(round) => {
                1u8.write(writer);
                round.write(writer);
            }
            Self::Finalize(proposal) => {
                2u8.write(writer);
                proposal.write(writer);
            }
        }
    }
}

impl<D: Digest> EncodeSize for Ballot<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(proposal) | Self::Finalize(proposal) => proposal.encode_size(),
            Self::Nullify(round) => round.encode_size(),
        }
    }
}

impl<D: Digest> Read for Ballot<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::Notarize(Proposal::read(reader)?)),
            1 => Ok(Self::Nullify(Round::read(reader)?)),
            2 => Ok(Self::Finalize(Proposal::read(reader)?)),
            kind => Err(Error::InvalidEnum(kind)),
        }
    }
}

/// A ballot under its signer's own signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<D: Digest> {
    pub ballot: Ballot<D>,
    pub signature: Signature,
}

impl<D: Digest> Signed<D> {
    /// Whether `signer` signed the ballot on the chain `namespace` names.
    pub fn verify(&self, namespace: &Namespace, signer: &PublicKey) -> bool {
        let subject = self.ballot.subject();
        signer.verify(
            subject.namespace(namespace),
            &subject.message(),
            &self.signature,
        )
    }
}

impl<D: Digest> Write for Signed<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.ballot.write(writer);
        self.signature.write(writer);
    }
}

impl<D: Digest> EncodeSize for Signed<D> {
    fn encode_size(&self) -> usize {
        self.ballot.encode_size() + self.signature.encode_size()
    }
}

impl<D: Digest> Read for Signed<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            ballot: Ballot::read(reader)?,
            signature: Signature::read(reader)?,
        })
    }
}

/// Two ballots held against the key that signed both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence<D: Digest> {
    pub signer: PublicKey,
    pub first: Signed<D>,
    pub second: Signed<D>,
}

impl<D: Digest> Evidence<D> {
    /// Whether the ballots conflict and `signer` signed both on the chain `namespace` names.
    pub fn verify(&self, namespace: &Namespace) -> bool {
        self.first.ballot.conflicts_with(&self.second.ballot)
            && self.first.verify(namespace, &self.signer)
            && self.second.verify(namespace, &self.signer)
    }
}

impl<D: Digest> Write for Evidence<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.first.write(writer);
        self.second.write(writer);
    }
}

impl<D: Digest> EncodeSize for Evidence<D> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.first.encode_size() + self.second.encode_size()
    }
}

impl<D: Digest> Read for Evidence<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            signer: PublicKey::read(reader)?,
            first: Signed::read(reader)?,
            second: Signed::read(reader)?,
        })
    }
}

/// The evidence in `votes` gathered from several nodes: for each signer and round, the first two
/// that conflict and that the signer did sign.
pub fn pair<D: Digest>(
    namespace: &Namespace,
    votes: impl IntoIterator<Item = (PublicKey, Signed<D>)>,
) -> Vec<Evidence<D>> {
    let mut held = Held::default();
    votes
        .into_iter()
        .filter_map(|(signer, signed)| held.keep(namespace, signer, signed, usize::MAX))
        .collect()
}

/// A round's ballots by signer. A signer convicted in the round keeps `None`: nothing more it
/// says there proves anything new.
type Ballots<D> = BTreeMap<PublicKey, Option<Vec<Signed<D>>>>;

struct Held<D: Digest>(BTreeMap<Round, Ballots<D>>);

impl<D: Digest> Default for Held<D> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<D: Digest> Held<D> {
    /// Keeps `signed` unless `signer` already holds `limit` ballots in its round, and returns the
    /// evidence it completes. Signatures are checked only for ballots that conflict: the engine
    /// reports a vote before verifying it, and nearly none conflict.
    fn keep(
        &mut self,
        namespace: &Namespace,
        signer: PublicKey,
        signed: Signed<D>,
        limit: usize,
    ) -> Option<Evidence<D>> {
        let slot = self
            .0
            .entry(signed.ballot.round())
            .or_default()
            .entry(signer.clone())
            .or_insert_with(|| Some(Vec::new()));
        let ballots = slot.as_mut()?;
        if ballots.contains(&signed) {
            return None;
        }
        let conflicts = |held: &Signed<D>| held.ballot.conflicts_with(&signed.ballot);
        if ballots.iter().any(conflicts) {
            if !signed.verify(namespace, &signer) {
                return None;
            }
            ballots.retain(|held| !conflicts(held) || held.verify(namespace, &signer));
            if let Some(first) = ballots.iter().find(|held| conflicts(held)).cloned() {
                *slot = None;
                return Some(Evidence {
                    signer,
                    first,
                    second: signed,
                });
            }
        }
        if ballots.len() < limit {
            ballots.push(signed);
        }
        None
    }
}

/// The signed votes a node saw in its latest rounds, and the evidence they make on their own.
#[derive(Clone)]
pub struct Votes<D: Digest> {
    namespace: Namespace,
    inner: Arc<Mutex<Inner<D>>>,
}

struct Inner<D: Digest> {
    held: Held<D>,
    evidence: Vec<Evidence<D>>,
}

impl<D: Digest> Votes<D> {
    pub fn new(namespace: Namespace) -> Self {
        Self {
            namespace,
            inner: Arc::new(Mutex::new(Inner {
                held: Held::default(),
                evidence: Vec::new(),
            })),
        }
    }

    /// Keeps a vote the engine reported, not yet verified.
    pub(crate) fn record(&self, signer: PublicKey, signed: Signed<D>) {
        let mut inner = self.inner.lock();
        let evidence = inner
            .held
            .keep(&self.namespace, signer, signed, BALLOTS_PER_SIGNER);
        if let Some(evidence) = evidence
            && inner.evidence.len() < RETAINED_EVIDENCE
        {
            inner.evidence.push(evidence);
        }
        while inner.held.0.len() > RETAINED_ROUNDS {
            inner.held.0.pop_first();
        }
    }

    /// The votes held for `round` that their signers did sign.
    pub fn in_round(&self, round: Round) -> Vec<(PublicKey, Signed<D>)> {
        let inner = self.inner.lock();
        inner
            .held
            .0
            .get(&round)
            .into_iter()
            .flatten()
            .flat_map(|(signer, ballots)| {
                ballots
                    .iter()
                    .flatten()
                    .filter(|signed| signed.verify(&self.namespace, signer))
                    .map(|signed| (signer.clone(), signed.clone()))
            })
            .collect()
    }

    /// Rounds whose votes disagree, so that another node may hold the other half of a pair: two
    /// proposals voted for, or a nullify beside a finalize.
    pub fn disputed(&self) -> Vec<Round> {
        let inner = self.inner.lock();
        inner
            .held
            .0
            .iter()
            .filter(|(_, signers)| {
                let ballots = || {
                    signers
                        .values()
                        .flatten()
                        .flatten()
                        .map(|signed| &signed.ballot)
                };
                let mut proposals = ballots().filter_map(|ballot| match ballot {
                    Ballot::Notarize(proposal) | Ballot::Finalize(proposal) => Some(proposal),
                    Ballot::Nullify(_) => None,
                });
                let split = proposals
                    .next()
                    .is_some_and(|first| proposals.any(|other| other != first));
                split
                    || (ballots().any(|ballot| matches!(ballot, Ballot::Nullify(_)))
                        && ballots().any(|ballot| matches!(ballot, Ballot::Finalize(_))))
            })
            .map(|(round, _)| *round)
            .collect()
    }

    /// Evidence this node's own votes make.
    pub fn evidence(&self) -> Vec<Evidence<D>> {
        self.inner.lock().evidence.clone()
    }
}

#[cfg(test)]
mod double_signer;

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::*;
    use crate::consensus::Digest;

    fn chain() -> Namespace {
        namespace(787_222, B256::repeat_byte(1))
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn proposal(view: u64, payload: u8) -> Proposal<Digest> {
        Proposal::new(
            round(view),
            View::new(view - 1),
            Digest(B256::repeat_byte(payload)),
        )
    }

    fn sign(namespace: &Namespace, key: &PrivateKey, ballot: Ballot<Digest>) -> Signed<Digest> {
        let subject = ballot.subject();
        let signature = key.sign(subject.namespace(namespace), &subject.message());
        Signed { ballot, signature }
    }

    #[test]
    fn only_the_three_faults_conflict() {
        let (a, b) = (proposal(2, 1), proposal(2, 2));
        let conflicting = [
            (Ballot::Notarize(a.clone()), Ballot::Notarize(b.clone())),
            (Ballot::Finalize(a.clone()), Ballot::Finalize(b)),
            (Ballot::Nullify(round(2)), Ballot::Finalize(a.clone())),
        ];
        for (first, second) in conflicting {
            assert!(first.conflicts_with(&second) && second.conflicts_with(&first));
        }

        let honest = [
            // A signer may give up on a round it notarized, and finalizes what it notarized.
            (Ballot::Notarize(a.clone()), Ballot::Nullify(round(2))),
            (Ballot::Notarize(a.clone()), Ballot::Finalize(a.clone())),
            (Ballot::Notarize(a.clone()), Ballot::Notarize(a.clone())),
            // Another round is another matter.
            (
                Ballot::Notarize(a.clone()),
                Ballot::Notarize(proposal(3, 2)),
            ),
            (Ballot::Nullify(round(3)), Ballot::Finalize(a)),
        ];
        for (first, second) in honest {
            assert!(!first.conflicts_with(&second) && !second.conflicts_with(&first));
        }
    }

    #[test]
    fn two_nodes_hold_between_them_what_neither_holds_alone() {
        let chain = chain();
        let (double, honest) = (PrivateKey::from_seed(1), PrivateKey::from_seed(2));
        let (a, b) = (proposal(2, 1), proposal(2, 2));

        // The double signer shows each node a different notarize. The honest signer voted with
        // the second node's half.
        let (first, second) = (Votes::new(chain.clone()), Votes::new(chain.clone()));
        first.record(
            double.public_key(),
            sign(&chain, &double, Ballot::Notarize(a)),
        );
        second.record(
            double.public_key(),
            sign(&chain, &double, Ballot::Notarize(b.clone())),
        );
        for node in [&first, &second] {
            node.record(
                honest.public_key(),
                sign(&chain, &honest, Ballot::Notarize(b.clone())),
            );
            assert!(node.evidence().is_empty());
        }
        // Only the first node sees two proposals, and that is what sends a watcher to the others.
        assert_eq!(first.disputed(), [round(2)]);
        assert!(second.disputed().is_empty());

        let votes = [&first, &second]
            .into_iter()
            .flat_map(|node| node.in_round(round(2)));
        let evidence = pair(&chain, votes);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].signer, double.public_key());
        assert!(evidence[0].verify(&chain));

        let decoded = Evidence::<Digest>::decode(evidence[0].encode()).unwrap();
        assert_eq!(decoded, evidence[0]);
        // On another chain the same bytes prove nothing.
        assert!(!decoded.verify(&namespace(787_223, B256::repeat_byte(1))));
    }

    #[test]
    fn a_node_that_sees_both_votes_holds_the_evidence_itself() {
        let chain = chain();
        let double = PrivateKey::from_seed(1);
        let node = Votes::new(chain.clone());
        let nullify = sign(&chain, &double, Ballot::Nullify(round(2)));
        let finalize = sign(&chain, &double, Ballot::Finalize(proposal(2, 1)));
        node.record(double.public_key(), nullify);
        node.record(double.public_key(), finalize);

        let evidence = node.evidence();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].verify(&chain));
        // What it said after is no second conviction.
        node.record(
            double.public_key(),
            sign(&chain, &double, Ballot::Finalize(proposal(2, 2))),
        );
        assert_eq!(node.evidence().len(), 1);
    }

    #[test]
    fn a_vote_nobody_signed_convicts_nobody() {
        let chain = chain();
        let (honest, forger) = (PrivateKey::from_seed(1), PrivateKey::from_seed(2));
        let vote = sign(&chain, &honest, Ballot::Notarize(proposal(2, 1)));
        // Signed by another key, and put under the honest signer's name.
        let forged = sign(&chain, &forger, Ballot::Notarize(proposal(2, 2)));

        for votes in [[vote.clone(), forged.clone()], [forged, vote.clone()]] {
            let node = Votes::new(chain.clone());
            for signed in votes.clone() {
                node.record(honest.public_key(), signed);
            }
            assert!(node.evidence().is_empty());
            assert_eq!(
                node.in_round(round(2)),
                [(honest.public_key(), vote.clone())]
            );
            let gathered = votes
                .into_iter()
                .map(|signed| (honest.public_key(), signed));
            assert!(pair(&chain, gathered).is_empty());
        }
    }
}
