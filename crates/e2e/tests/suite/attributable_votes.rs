//! Validators keep finalizing across the epoch whose votes first carry their signer's signature.

use std::time::{Duration, UNIX_EPOCH};

use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;

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
