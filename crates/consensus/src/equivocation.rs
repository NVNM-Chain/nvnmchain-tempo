//! Evidence that a validator signed conflicting votes.
//!
//! Once votes carry the signature of their signer's vote key, two of them over conflicting votes
//! in one round convict the validator whose key signed both, with nothing but those signatures,
//! that key and the chain's namespace. A signer that splits the pair between its peers shows each
//! node only one, so a node keeps what it saw for whoever compares several nodes.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use alloy_primitives::B256;
use commonware_consensus::simplex::types::Subject;
use commonware_cryptography::Digest;
use parking_lot::Mutex;
use tempo_precompiles::validator_config_v2::{
    Ballot, Evidence, Proposal, Round, Signed, VoteKey, VoteNamespace,
};
use tracing::warn;

/// How many rounds a node keeps the votes of.
const RETAINED_ROUNDS: usize = 4_096;

/// How many disputed rounds a node keeps beyond that, for whoever pairs their votes with other
/// nodes': a split pair is evidence only once both halves meet.
const RETAINED_DISPUTED: usize = 1_024;

/// How many pieces of evidence a node keeps.
const RETAINED_EVIDENCE: usize = 1_024;

/// What a node keeps of one signer in one round: its three votes and one that conflicts.
const BALLOTS_PER_SIGNER: usize = 4;

/// The ballot a vote on `subject` casts, in the registry's terms. `None` unless its proposal
/// names a block.
pub(crate) fn ballot<D: Digest>(subject: Subject<'_, D>) -> Option<Ballot> {
    let round = |round: commonware_consensus::types::Round| Round {
        epoch: round.epoch().get(),
        view: round.view().get(),
    };
    let proposal = |proposal: &commonware_consensus::simplex::types::Proposal<D>| {
        Some(Proposal {
            round: round(proposal.round),
            parent: proposal.parent.get(),
            payload: B256::try_from(proposal.payload.as_ref()).ok()?,
        })
    };
    Some(match subject {
        Subject::Notarize { proposal: named } => Ballot::Notarize(proposal(named)?),
        Subject::Nullify { round: nullified } => Ballot::Nullify(round(nullified)),
        Subject::Finalize { proposal: named } => Ballot::Finalize(proposal(named)?),
    })
}

/// The evidence in `votes` gathered from several nodes, each with its signer's vote key: for each
/// signer and round, the first two that conflict and that the key did sign.
pub fn pair(
    namespace: &VoteNamespace,
    votes: impl IntoIterator<Item = (B256, VoteKey, Signed)>,
) -> Vec<Evidence> {
    let mut held = Held::default();
    votes
        .into_iter()
        .filter_map(|(signer, key, signed)| held.keep(namespace, signer, key, signed, usize::MAX))
        .collect()
}

/// A round's ballots by signer, under the vote key it first voted with there. A signer convicted
/// in the round keeps `None`: nothing more it says there proves anything new.
type Ballots = BTreeMap<B256, Option<(VoteKey, Vec<Signed>)>>;

#[derive(Default)]
struct Held(BTreeMap<Round, Ballots>);

impl Held {
    /// Keeps `signed` unless `signer` already holds `limit` ballots in its round, and returns the
    /// evidence it completes. Signatures are checked only for ballots that conflict: the engine
    /// reports a vote before verifying it, and nearly none conflict.
    fn keep(
        &mut self,
        namespace: &VoteNamespace,
        signer: B256,
        key: VoteKey,
        signed: Signed,
        limit: usize,
    ) -> Option<Evidence> {
        let slot = self
            .0
            .entry(signed.ballot.round())
            .or_default()
            .entry(signer)
            .or_insert_with(|| Some((key, Vec::new())));
        let (key, ballots) = slot.as_mut()?;
        if ballots.contains(&signed) {
            return None;
        }
        let conflicts = |held: &Signed| held.ballot.conflicts_with(&signed.ballot);
        if ballots.iter().any(conflicts) {
            if !signed.verify(namespace, key) {
                return None;
            }
            ballots.retain(|held| !conflicts(held) || held.verify(namespace, key));
            if let Some(first) = ballots.iter().find(|held| conflicts(held)).copied() {
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

/// Whether a round's ballots disagree: two proposals voted for, or a nullify beside a finalize.
/// Another node may then hold the vote that conflicts with one held here.
fn is_disputed(signers: &Ballots) -> bool {
    let ballots = || {
        signers
            .values()
            .flatten()
            .flat_map(|(_, ballots)| ballots)
            .map(|signed| &signed.ballot)
    };
    let mut proposals = ballots().filter_map(|ballot| match ballot {
        Ballot::Notarize(proposal) | Ballot::Finalize(proposal) => Some(proposal),
        Ballot::Nullify(_) => None,
    });
    proposals
        .next()
        .is_some_and(|first| proposals.any(|other| other != first))
        || (ballots().any(|ballot| matches!(ballot, Ballot::Nullify(_)))
            && ballots().any(|ballot| matches!(ballot, Ballot::Finalize(_))))
}

/// The signed votes a node saw in its latest rounds, and the evidence they make on their own.
/// All of it in memory: a restart drops it, so it is read off a node as it appears.
#[derive(Clone)]
pub struct Votes {
    namespace: Arc<VoteNamespace>,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    held: Held,
    disputed: BTreeSet<Round>,
    evidence: Vec<Evidence>,
}

impl Votes {
    pub fn new(namespace: VoteNamespace) -> Self {
        Self {
            namespace: Arc::new(namespace),
            inner: Arc::new(Mutex::new(Inner {
                held: Held::default(),
                disputed: BTreeSet::new(),
                evidence: Vec::new(),
            })),
        }
    }

    /// Keeps a vote the engine reported, not yet verified, of `signer` whose vote key is `key`.
    pub(crate) fn record(&self, signer: B256, key: VoteKey, signed: Signed) {
        let round = signed.ballot.round();
        let mut inner = self.inner.lock();
        let evidence = inner
            .held
            .keep(&self.namespace, signer, key, signed, BALLOTS_PER_SIGNER);
        if let Some(evidence) = evidence
            && inner.evidence.len() < RETAINED_EVIDENCE
        {
            warn!(signer = %evidence.signer, ?round, "a validator signed conflicting votes");
            inner.evidence.push(evidence);
        }
        if inner.held.0.get(&round).is_some_and(is_disputed) {
            inner.disputed.insert(round);
        }
        // The oldest rounds go, but a disputed one outlives them: its other half may be held
        // elsewhere, and the pairing waits on whoever compares nodes.
        while inner.held.0.len() > RETAINED_ROUNDS + inner.disputed.len() {
            let oldest = inner
                .held
                .0
                .keys()
                .find(|round| !inner.disputed.contains(round));
            let Some(oldest) = oldest.copied() else { break };
            inner.held.0.remove(&oldest);
        }
        while inner.disputed.len() > RETAINED_DISPUTED {
            if let Some(oldest) = inner.disputed.pop_first() {
                inner.held.0.remove(&oldest);
            }
        }
    }

    /// The votes held for `round` that their signers' vote keys did sign.
    pub fn in_round(&self, round: Round) -> Vec<(B256, Signed)> {
        // Checked outside the lock, which the engine's reports wait on.
        let held = self.inner.lock().held.0.get(&round).cloned();
        held.into_iter()
            .flatten()
            .flat_map(|(signer, held)| held.map(|held| (signer, held)))
            .flat_map(|(signer, (key, ballots))| {
                ballots
                    .into_iter()
                    .filter(move |signed| signed.verify(&self.namespace, &key))
                    .map(move |signed| (signer, signed))
            })
            .collect()
    }

    /// Rounds whose votes disagree, so that another node may hold the other half of a pair.
    pub fn disputed(&self) -> Vec<Round> {
        self.inner.lock().disputed.iter().copied().collect()
    }

    /// Evidence this node's own votes make.
    pub fn evidence(&self) -> Vec<Evidence> {
        self.inner.lock().evidence.clone()
    }
}

#[cfg(test)]
mod double_signer;

#[cfg(test)]
mod tests {
    use commonware_consensus::{
        simplex::types,
        types::{Epoch, View},
    };
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::{ops, variant::MinSig},
        certificate::Subject as _,
        ed25519::PrivateKey,
    };

    use super::*;
    use crate::{consensus::Digest, utils::public_key_to_b256};

    fn chain() -> VoteNamespace {
        VoteNamespace::new(787_222, B256::repeat_byte(1))
    }

    fn round(view: u64) -> Round {
        Round { epoch: 0, view }
    }

    fn proposal(view: u64, payload: u8) -> Proposal {
        Proposal {
            round: round(view),
            parent: view - 1,
            payload: B256::repeat_byte(payload),
        }
    }

    /// The validator `key` as the registry names it, and the vote key it would hold for it.
    fn signer(key: &PrivateKey) -> (B256, VoteKey) {
        let vote_key = tempo_validator_config::VoteKeypair::derive(key).public();
        (public_key_to_b256(&key.public_key()), vote_key)
    }

    /// `ballot` under the signature of `key`'s vote key.
    fn sign(namespace: &VoteNamespace, key: &PrivateKey, ballot: Ballot) -> Signed {
        let vote_key = tempo_validator_config::VoteKeypair::derive(key).private();
        let signature =
            ops::sign_message::<MinSig>(&vote_key, namespace.of(&ballot), &ballot.body());
        Signed { ballot, signature }
    }

    /// `node` receives `ballot` from the validator `key`.
    fn cast(node: &Votes, namespace: &VoteNamespace, key: &PrivateKey, ballot: Ballot) {
        let (signer, vote_key) = signer(key);
        node.record(signer, vote_key, sign(namespace, key, ballot));
    }

    /// A vote key signs what the consensus library says a vote is, so two votes that differ there
    /// differ here.
    #[test]
    fn a_ballots_body_is_the_librarys_vote() {
        let named = types::Proposal::new(
            commonware_consensus::types::Round::new(Epoch::new(7), View::new(9)),
            View::new(8),
            Digest(B256::repeat_byte(3)),
        );
        for subject in [
            Subject::Notarize { proposal: &named },
            Subject::Nullify { round: named.round },
            Subject::Finalize { proposal: &named },
        ] {
            assert_eq!(ballot(subject).unwrap().body(), subject.message());
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
        cast(&first, &chain, &double, Ballot::Notarize(a));
        cast(&second, &chain, &double, Ballot::Notarize(b));
        for node in [&first, &second] {
            cast(node, &chain, &honest, Ballot::Notarize(b));
            assert!(node.evidence().is_empty());
        }
        // Only the first node sees two proposals, and that is what sends a watcher to the others.
        assert_eq!(first.disputed(), [round(2)]);
        assert!(second.disputed().is_empty());

        // Whoever compares the nodes takes each signer's vote key from the registry.
        let keys = BTreeMap::from([&double, &honest].map(signer));
        let votes = [&first, &second]
            .into_iter()
            .flat_map(|node| node.in_round(round(2)))
            .map(|(signer, signed)| (signer, keys[&signer], signed));
        let evidence = pair(&chain, votes);
        let (double, vote_key) = signer(&double);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].signer, double);
        assert!(evidence[0].verify(&chain, &vote_key));
    }

    #[test]
    fn a_node_that_sees_both_votes_holds_the_evidence_itself() {
        let chain = chain();
        let double = PrivateKey::from_seed(1);
        let node = Votes::new(chain.clone());
        cast(&node, &chain, &double, Ballot::Nullify(round(2)));
        cast(&node, &chain, &double, Ballot::Finalize(proposal(2, 1)));

        let evidence = node.evidence();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].verify(&chain, &signer(&double).1));
        // What it said after is no second conviction.
        cast(&node, &chain, &double, Ballot::Finalize(proposal(2, 2)));
        assert_eq!(node.evidence().len(), 1);
    }

    #[test]
    fn a_vote_nobody_signed_convicts_nobody() {
        let chain = chain();
        let (honest, forger) = (PrivateKey::from_seed(1), PrivateKey::from_seed(2));
        let vote = sign(&chain, &honest, Ballot::Notarize(proposal(2, 1)));
        // Signed by another's vote key, and put under the honest signer's name.
        let forged = sign(&chain, &forger, Ballot::Notarize(proposal(2, 2)));
        let (honest, key) = signer(&honest);

        for votes in [[vote, forged], [forged, vote]] {
            let node = Votes::new(chain.clone());
            for signed in votes {
                node.record(honest, key, signed);
            }
            assert!(node.evidence().is_empty());
            assert_eq!(node.in_round(round(2)), [(honest, vote)]);
            let gathered = votes.into_iter().map(|signed| (honest, key, signed));
            assert!(pair(&chain, gathered).is_empty());
        }
    }

    /// A split seen in one round must still be there when someone compares nodes, however many
    /// rounds have passed since.
    #[test]
    fn a_disputed_round_outlives_the_retained_rounds() {
        let chain = chain();
        let (one, other) = (PrivateKey::from_seed(1), PrivateKey::from_seed(2));
        let node = Votes::new(chain.clone());
        cast(&node, &chain, &one, Ballot::Notarize(proposal(2, 1)));
        cast(&node, &chain, &other, Ballot::Notarize(proposal(2, 2)));
        // Signed once: the store checks a signature only when votes conflict.
        let nullify = sign(&chain, &one, Ballot::Nullify(round(3))).signature;
        let (one, key) = signer(&one);
        for view in 3..3 + RETAINED_ROUNDS as u64 + 1 {
            let signed = Signed {
                ballot: Ballot::Nullify(round(view)),
                signature: nullify,
            };
            node.record(one, key, signed);
        }

        assert_eq!(node.disputed(), [round(2)]);
        assert_eq!(node.in_round(round(2)).len(), 2);
        assert!(
            node.in_round(round(3)).is_empty(),
            "the oldest undisputed round went"
        );
    }
}
