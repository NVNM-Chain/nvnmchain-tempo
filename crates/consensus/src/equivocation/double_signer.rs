//! Honest engines beside a participant that shows one of them a different vote.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use commonware_actor::Feedback;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Reporter,
    simplex::{
        self, Engine,
        config::{Floor, ForwardPolicy, SkipBudget, SkipPolicy},
        elector::RoundRobin,
        mocks,
        scheme::bls12381_threshold::vrf,
        types::{Activity, Notarize, Proposal, Vote},
    },
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{
    Sha256, Signer as _, bls12381::primitives::variant::MinSig, certificate, ed25519::PublicKey,
    sha256::Digest,
};
use commonware_math::algebra::Random as _;
use commonware_p2p::{
    Receiver as _, Recipients, Sender as _,
    simulated::{Config, Link, Network},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Quota, Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{NZU16, NZUsize, probability};
use futures::{StreamExt as _, channel::mpsc};
use tempo_precompiles::validator_config_v2::VoteNamespace;
use tempo_validator_config::VoteKeypair;

use super::{Votes, pair};
use crate::{
    attributable::{
        Recorder, Scheme,
        tests::{CHAIN_ID, GENESIS, dealt, signers},
    },
    utils::public_key_to_b256,
};

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const FINALIZED: usize = 10;

/// Tells the test of each round an honest engine finalizes.
#[derive(Clone)]
struct Finalized(mpsc::UnboundedSender<()>);

impl Reporter for Finalized {
    type Activity = Activity<vrf::Scheme<PublicKey, MinSig>, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if matches!(activity, Activity::Finalization(_)) {
            let _ = self.0.unbounded_send(());
        }
        Feedback::Ok
    }
}

#[test]
fn votes_split_between_nodes_convict_their_signer() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|context| async move {
        let chain = VoteNamespace::new(CHAIN_ID, GENESIS);
        let schemes: Vec<_> = signers(&[], 0, CHAIN_ID, GENESIS)
            .into_iter()
            .map(|(_, scheme)| scheme)
            .collect();
        let players = certificate::Scheme::participants(&schemes[0]).clone();
        // What whoever compares the nodes reads from the registry.
        let keys: BTreeMap<_, _> = dealt(0)
            .iter()
            .map(|(key, _)| {
                let vote_key = VoteKeypair::derive(key).public();
                (public_key_to_b256(&key.public_key()), vote_key)
            })
            .collect();

        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(players.len()),
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(1),
            },
            players.clone(),
        )
        .await;
        network.start();
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: probability!(1.0),
        };
        for from in players.iter() {
            for to in players.iter().filter(|to| *to != from) {
                oracle
                    .add_link(from.clone(), to.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }

        // The first player signs twice. The others run honest engines.
        let double = players.get(0).unwrap().clone();
        let honest: Vec<_> = players.iter().skip(1).cloned().collect();
        let relay = Arc::new(mocks::relay::Relay::<Digest, _>::new());
        let (finalized, mut finalizations) = mpsc::unbounded();
        let mut nodes = Vec::new();
        for (player, scheme) in players.iter().zip(schemes) {
            let context = context
                .child("validator")
                .with_attribute("public_key", player);
            let control = oracle.control(player.clone());
            let votes = control.register(0, QUOTA).await.unwrap();
            let certificates = control.register(1, QUOTA).await.unwrap();
            let resolver = control.register(2, QUOTA).await.unwrap();

            if player == &double {
                let (mut sender, mut receiver) = votes;
                let (most, one) = (honest[..2].to_vec(), honest[2..].to_vec());
                context
                    .child("double_signer")
                    .spawn(move |mut context| async move {
                        let mut signed = BTreeSet::new();
                        while let Ok((_, message)) = receiver.recv().await {
                            let Ok(Vote::Notarize(seen)) = Vote::<Scheme, Digest>::decode(message)
                            else {
                                continue;
                            };
                            if !signed.insert(seen.round()) {
                                continue;
                            }
                            // What the others notarize goes to two of them, and something else to
                            // the third, so that no node receives both.
                            let other = Proposal::new(
                                seen.round(),
                                seen.proposal.parent,
                                Digest::random(&mut context),
                            );
                            for (proposal, to) in [(seen.proposal, &most), (other, &one)] {
                                let vote = Notarize::sign(&scheme, proposal).unwrap();
                                sender.send(
                                    Recipients::Some(to.clone()),
                                    Vote::Notarize(vote).encode(),
                                    true,
                                );
                            }
                        }
                    });
                continue;
            }

            let node = Votes::new(chain.clone());
            nodes.push(node.clone());
            let (actor, application) = mocks::application::Application::new(
                context.child("application"),
                mocks::application::Config::<Sha256, _> {
                    relay: relay.clone(),
                    me: player.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                },
            );
            actor.start();
            Engine::new(
                context.child("engine"),
                simplex::Config {
                    scheme: scheme.clone(),
                    elector: RoundRobin::<Sha256>::default(),
                    blocker: control,
                    automaton: application.clone(),
                    relay: application,
                    reporter: Recorder {
                        scheme,
                        votes: node,
                        certificates: Finalized(finalized.clone()),
                    },
                    strategy: Sequential,
                    partition: player.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::zero(),
                    floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::zero())),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    view_retention: ViewDelta::new(10),
                    skip: SkipPolicy::Enabled {
                        timeout: Duration::from_secs(11),
                        budget: SkipBudget::Participants,
                    },
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forward: ForwardPolicy::Disabled,
                    track_historical_votes: true,
                },
            )
            .start(votes, certificates, resolver);
        }

        for _ in 0..FINALIZED * honest.len() {
            finalizations.next().await.unwrap();
        }

        // No node received both halves of a pair, so none holds evidence. Each that received the
        // odd half saw two proposals in the round, which is what points at it.
        let mut disputed = BTreeSet::new();
        for node in &nodes {
            assert!(node.evidence().is_empty());
            disputed.extend(node.disputed());
        }
        assert!(!disputed.is_empty());

        let mut convicted = 0;
        for round in disputed {
            let votes = nodes
                .iter()
                .flat_map(|node| node.in_round(round))
                .map(|(signer, signed)| (signer, keys[&signer], signed));
            for evidence in pair(&chain, votes) {
                assert_eq!(evidence.signer, public_key_to_b256(&double));
                assert!(evidence.verify(&chain, &keys[&evidence.signer]));
                convicted += 1;
            }
        }
        assert!(convicted > 0);
    });
}
