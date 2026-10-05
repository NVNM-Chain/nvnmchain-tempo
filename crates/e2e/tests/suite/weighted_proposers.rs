//! Stake-weighted block proposers.

use std::collections::BTreeMap;

use commonware_cryptography::ed25519::PublicKey;
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockReader as _;

use crate::{Setup, metrics::wait_for_height, setup_validators};

const EPOCH_LENGTH: u64 = 30;

/// Six signers, the last weighed at zero by the election, run for four epochs. Returns how many
/// blocks each proposed in epoch 0 and, outside each epoch's round-robin first view, after it,
/// with the key weighed at zero.
fn proposals(
    setup: Setup,
) -> (
    BTreeMap<PublicKey, u64>,
    BTreeMap<PublicKey, u64>,
    PublicKey,
) {
    let setup = setup
        .how_many_signers(6)
        .epoch_length(EPOCH_LENGTH)
        .proposer_weights(vec![1, 1, 1, 1, 1, 0])
        .seed(0);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    Runner::from(cfg).start(|mut context| async move {
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let last = 4 * EPOCH_LENGTH;
        wait_for_height(&context, &nodes[0], last).await;

        let mut first_epoch = BTreeMap::new();
        let mut later = BTreeMap::new();
        let provider = nodes[0].execution_provider();
        for height in 1..=last {
            let block = provider.block_by_number(height).unwrap().unwrap();
            let ctx = block.header.consensus_context.unwrap();
            let proposed = match (ctx.epoch, ctx.view) {
                (0, _) => &mut first_epoch,
                (_, 1) => continue,
                _ => &mut later,
            };
            *proposed.entry(ctx.proposer.to_inner()).or_insert(0u64) += 1;
        }

        // Nodes are in key order, as the weights are.
        (first_epoch, later, nodes.last().unwrap().public_key())
    })
}

/// A signer the election weighs at zero keeps its vote but stops proposing from epoch 1, the
/// first whose DKG outcome carries proposer units. View 1 of every epoch is round robin.
#[test_traced]
fn a_signer_weighed_at_zero_stops_proposing() {
    let _ = tempo_eyre::install();

    let (uniform, weighted, zero) = proposals(Setup::new(crate::VERIFICATION_MODE));
    assert!(uniform.contains_key(&zero), "{uniform:?}");
    assert!(!weighted.contains_key(&zero), "{weighted:?}");
    assert_eq!(weighted.len(), 5, "{weighted:?}");
}

/// Before T12 no outcome carries units, so the same signer goes on proposing.
#[test_traced]
fn before_t12_a_signer_weighed_at_zero_still_proposes() {
    let _ = tempo_eyre::install();

    let (_, later, zero) = proposals(Setup::new(crate::VERIFICATION_MODE).t12_time(u64::MAX));
    assert!(later.contains_key(&zero), "{later:?}");
}
