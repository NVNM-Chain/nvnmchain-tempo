//! Validators keep finalizing across the epoch whose votes first carry their vote keys'
//! signatures.

use std::{
    net::SocketAddr,
    time::{Duration, UNIX_EPOCH},
};

use alloy::providers::ProviderBuilder;
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::NZU64;
use futures::{channel::oneshot, future::join_all};
use jsonrpsee::http_client::HttpClientBuilder;
use reth_ethereum::chainspec::EthChainSpec as _;
use tempo_node::rpc::consensus::{RoundId, TempoConsensusApiClient as _};
use tempo_precompiles::{
    VALIDATOR_CONFIG_V2_ADDRESS,
    validator_config_v2::{IEquivocation, Signed, VoteKey, VoteNamespace},
};

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    metrics::{MetricsExt as _, wait_for_metrics},
    setup_validators,
};

const ATTRIBUTABLE_VOTES: &str = "epoch_manager_attributable_votes";

#[test_traced]
fn validators_switch_to_attributable_votes_at_an_epoch_boundary() {
    let _ = tempo_eyre::install();
    const EPOCH_LENGTH: u64 = 20;
    const ACTIVATION: u64 = 1;

    // Genesis is stamped zero, so epoch zero keeps the threshold scheme's votes. The boundary
    // before epoch one is stamped later, so that epoch is the first to sign them.
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(EPOCH_LENGTH)
        .attributable_votes_time(ACTIVATION);
    let cfg = Config::default()
        .with_seed(setup.seed)
        .with_start_time(UNIX_EPOCH + Duration::from_secs(ACTIVATION));

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        for (epoch, attributable) in [(0, 0), (1, 1)] {
            wait_for_metrics(&context, |metrics| {
                metrics.consensus_at_epoch(epoch) == validators.len()
            })
            .await;

            let metrics = context.to_metrics();
            for validator in &validators {
                let metrics = metrics.for_scope(validator);
                assert_eq!(metrics.latest_consensus_epoch(), Some(epoch));
                assert_eq!(metrics.value::<u64>(ATTRIBUTABLE_VOTES), Some(attributable));
            }
        }

        // Every validator reaching epoch two has finalized all of epoch one under the new votes,
        // its key ceremony included.
        let epoch_strategy = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let target = epoch_strategy.first(Epoch::new(2)).unwrap();
        wait_for_metrics(&context, |metrics| {
            metrics.consensus_at_height(target.get()) == validators.len()
        })
        .await;
    });
}

/// The registry holds no vote key for one validator of five. Its votes do not count, so the other
/// four, a quorum, finalize without it. A ceremony then seats only them, and it follows.
#[test_traced]
fn validators_finalize_without_the_one_that_has_no_vote_key() {
    let _ = tempo_eyre::install();
    const EPOCH_LENGTH: u64 = 20;

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(5)
        .epoch_length(EPOCH_LENGTH)
        .attributable_votes_time(0)
        .signers_without_vote_key(1);
    let cfg = Config::default().with_seed(setup.seed);

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        // The genesis seats all five for epoch one's ceremony too. The four run the epoch after a
        // ceremony for them succeeds: with one dealer mute, it needs a block from each other one.
        wait_for_metrics(&context, |metrics| {
            validators.iter().all(|validator| {
                let metrics = metrics.for_scope(validator);
                metrics.value::<u64>(ATTRIBUTABLE_VOTES) == Some(1)
                    && metrics.has_consensus_participants(4)
            })
        })
        .await;
    });
}

/// Two vote keys of four are no quorum: the votes stay attributable and nothing is certified.
#[test_traced]
fn too_few_vote_keys_stop_the_chain() {
    let _ = tempo_eyre::install();

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(100)
        .attributable_votes_time(0)
        .signers_without_vote_key(2);
    let cfg = Config::default().with_seed(setup.seed);

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        wait_for_metrics(&context, |metrics| {
            validators.iter().all(|validator| {
                metrics
                    .for_scope(validator)
                    .value::<u64>(ATTRIBUTABLE_VOTES)
                    == Some(1)
            })
        })
        .await;

        // Long enough for four keyed validators to finalize many times over.
        context.sleep(Duration::from_secs(30)).await;
        assert_eq!(context.to_metrics().consensus_at_height(1), 0);
    });
}

/// A validator stopped inside an epoch comes back to the signed votes it journaled, in that same
/// epoch, and rejoins.
#[test_traced]
fn a_validator_restarts_within_an_epoch_of_attributable_votes() {
    let _ = tempo_eyre::install();

    // From genesis, which is stamped zero, in an epoch that outlasts the test.
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(100)
        .attributable_votes_time(0);
    let cfg = Config::default().with_seed(setup.seed);

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        let reach = |height, nodes| {
            wait_for_metrics(&context, move |metrics| {
                metrics.consensus_at_height(height) == nodes
            })
        };
        reach(5, 4).await;
        validators[0].stop().await;
        reach(10, 3).await;
        validators[0].start(&context).await;
        connect_execution_to_peers(&validators[0], &validators).await;
        reach(20, 4).await;

        let metrics = context.to_metrics();
        assert_eq!(
            metrics
                .for_scope(&validators[0])
                .value::<u64>(ATTRIBUTABLE_VOTES),
            Some(1)
        );
    });
}

/// A node serves the votes it received under their signers' signatures, and among honest
/// validators holds no evidence.
#[tokio::test]
#[test_traced]
async fn a_node_serves_the_signed_votes_it_received() {
    let _ = tempo_eyre::install();

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(100)
        .attributable_votes_time(0);
    let cfg = Config::default().with_seed(setup.seed);

    let (node_tx, node_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let executor = std::thread::spawn(move || {
        Runner::from(cfg).start(|mut context| async move {
            let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
            join_all(validators.iter_mut().map(|node| node.start(&context))).await;
            connect_execution_peers(&validators).await;
            wait_for_metrics(&context, |metrics| {
                metrics.consensus_at_height(5) == validators.len()
            })
            .await;

            let execution = validators[0].execution();
            let rpc: SocketAddr = execution.rpc_server_handles.rpc.http_local_addr().unwrap();
            let chain = execution.chain_spec();
            node_tx
                .send((rpc, chain.chain_id(), chain.genesis_hash()))
                .unwrap();
            let _ = done_rx.await;
        });
    });

    let (rpc, chain_id, genesis) = node_rx.await.unwrap();
    let client = HttpClientBuilder::default()
        .build(format!("http://{rpc}"))
        .unwrap();
    let chain = VoteNamespace::new(chain_id, genesis);
    let provider = ProviderBuilder::new().connect_http(format!("http://{rpc}").parse().unwrap());
    let registry = IEquivocation::new(VALIDATOR_CONFIG_V2_ADDRESS, provider);

    // By height five, a quorum signed in some early view of the first epoch, each under the vote
    // key the registry holds for it.
    let mut most = 0;
    for view in 1..=5 {
        let votes = client.get_votes(RoundId { epoch: 0, view }).await.unwrap();
        let mut signers = std::collections::BTreeSet::new();
        for vote in votes {
            let signed = Signed::decode(vote.vote.as_ref()).unwrap();
            let key = registry.voteKey(vote.signer).call().await.unwrap();
            assert!(signed.verify(&chain, &VoteKey::decode(key.as_ref()).unwrap()));
            signers.insert(vote.signer);
        }
        most = most.max(signers.len());
    }
    assert!(most >= 3, "votes of {most} signers");
    assert!(client.get_equivocations().await.unwrap().is_empty());

    drop(done_tx);
    executor.join().unwrap();
}
