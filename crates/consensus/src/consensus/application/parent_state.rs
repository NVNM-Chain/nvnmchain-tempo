//! The part of a boundary block's DKG outcome that comes from the post-state
//! of its parent.

use std::{collections::BTreeMap, sync::Arc};

use alloy_consensus::BlockHeader as _;
use alloy_primitives::U256;
use commonware_consensus::{
    Heightable as _,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::{Faults as _, N3f1, ordered};
use eyre::{Report, WrapErr as _};
use reth_provider::{EvmStateProviderBox, StateProvider as _};
use tempo_chainspec::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{ExecutedState, TempoFullNode};
use tempo_precompiles::validator_config_v2::{ValidatorConfigV2, VoteKey};
use tracing::{Level, debug, info, instrument, warn};

use crate::{
    consensus::block::Block,
    utils::public_key_to_b256,
    validators::{
        NextPlayers, read_elected_players, read_seatable_players, read_validator_config_with_state,
    },
    weighted_elector,
};

/// Reads the post-state of a boundary block's parent through
/// [`ExecutedState`], so a parent on a fork that is not canonical has its
/// state too. The reads fail until the engine has executed the parent.
#[derive(Clone)]
pub(crate) struct TempoParentState {
    pub(crate) node: Arc<TempoFullNode>,
    pub(crate) executed_state: ExecutedState,
}

impl TempoParentState {
    /// Returns the DKG outcome of a boundary block on top of `parent`, made
    /// from the ceremony `output` and the post-state of `parent`.
    ///
    /// Call this only after the engine has executed `parent`. Before that, the
    /// state reads fail.
    pub(super) fn boundary_outcome(
        &self,
        epoch_strategy: &FixedEpocher,
        parent: &Block,
        output: Output<MinSig, PublicKey>,
    ) -> eyre::Result<OnchainDkgOutcome> {
        let next_full_dkg_epoch = self
            .next_full_dkg_epoch(parent)
            .wrap_err("could not determine the next full DKG epoch")?;
        // Whoever holds the output runs the next epoch: the players if the ceremony succeeded,
        // the dealers it carried forward if not.
        let next = self
            .next_players(parent, output.players())
            .wrap_err("could not determine who the next players are supposed to be")?;
        let proposer_units = next
            .weights
            .map(|weights| proposer_units(output.players(), &weights));
        let vote_keys = self
            .vote_keys(parent, output.players())
            .wrap_err("could not read the vote keys of those who run the next epoch")?;

        let outcome = assemble_boundary_outcome(
            epoch_strategy,
            parent.height(),
            output,
            next.players,
            next_full_dkg_epoch,
            proposer_units,
            vote_keys,
        );
        info!(
            outcome.is_next_full_dkg,
            next_epoch = %outcome.epoch(),
            "determined if the next epoch will be a reshare or full re-dkg process",
        );
        Ok(outcome)
    }

    /// Returns the validators that are active in the validator config at
    /// `parent`, and from attributable votes on have a vote key there. They
    /// are the players of the ceremony in the next epoch.
    ///
    /// Where the genesis names a staking election, that contract picks them
    /// among the active validators; `current_players` stay if it cannot. From
    /// T12 its weights for `current_players` come with them.
    #[instrument(
        skip_all,
        fields(parent.height = %parent.height()),
        err(level = Level::WARN),
    )]
    fn next_players(
        &self,
        parent: &Block,
        current_players: &ordered::Set<PublicKey>,
    ) -> eyre::Result<NextPlayers> {
        let chain_spec = self.node.chain_spec();
        let next_players = match chain_spec.info.staking_election() {
            Some(staking_election) => read_elected_players(
                self.node.as_ref(),
                self.parent_post_state(parent)?,
                parent.header(),
                staking_election,
                chain_spec.info.staking_election_time(),
                chain_spec
                    .tempo_hardfork_at(parent.header().timestamp())
                    .is_t12(),
                current_players,
            )
            .wrap_err("failed determining the elected players")?,
            None => NextPlayers {
                players: self
                    .read_validator_config(parent, read_seatable_players)
                    .wrap_err("failed reading peers from validator config v2")?,
                weights: None,
            },
        };

        debug!(?next_players, "determined next players");
        Ok(next_players)
    }

    /// Returns each of `players`' vote key as the registry holds it at `parent`, in their order,
    /// once votes are attributable there. Before that the next epoch keeps the threshold scheme's
    /// votes, and from T12 a warning tells when the players' keys are short of a quorum.
    #[instrument(
        skip_all,
        fields(parent.height = %parent.height()),
        err(level = Level::WARN),
    )]
    fn vote_keys(
        &self,
        parent: &Block,
        players: &ordered::Set<PublicKey>,
    ) -> eyre::Result<Option<Vec<Option<VoteKey>>>> {
        let chain_spec = self.node.chain_spec();
        let timestamp = parent.header().timestamp();
        // No vote key is registered before T12.
        let scheduled = chain_spec
            .info
            .attributable_votes_time()
            .filter(|_| chain_spec.tempo_hardfork_at(timestamp).is_t12());
        let Some(from) = scheduled else {
            return Ok(None);
        };
        let keys: eyre::Result<Vec<_>> = self.read_validator_config(parent, |config| {
            players
                .iter()
                .map(|player| {
                    config
                        .vote_key_of(public_key_to_b256(player))
                        .map_err(Report::new)
                })
                .collect()
        });
        if timestamp >= from {
            return keys.map(Some);
        }
        // Not in force yet, so a failed read costs only the warning.
        if let Ok(keys) = keys {
            let keyed = keys.iter().flatten().count();
            let quorum = N3f1::quorum(players.len()) as usize;
            if keyed < quorum {
                warn!(
                    keyed,
                    quorum,
                    attributable_votes_time = from,
                    "too few of the next epoch's participants have a vote key for the chain to \
                    go on once votes are attributable"
                );
            }
        }
        Ok(None)
    }

    /// Returns the epoch of the next full DKG ceremony, as the validator
    /// config at `parent` schedules it. In all other epochs, the ceremony
    /// reshares the current polynomial.
    #[instrument(
        skip_all,
        fields(parent.height = %parent.height()),
        err(level = Level::WARN),
        ret
    )]
    fn next_full_dkg_epoch(&self, parent: &Block) -> eyre::Result<u64> {
        self.read_validator_config(parent, |config| {
            config
                .get_next_network_identity_rotation_epoch()
                .map_err(Report::new)
        })
    }

    fn read_validator_config<T>(
        &self,
        parent: &Block,
        read_fn: impl FnOnce(&ValidatorConfigV2) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        read_validator_config_with_state(
            self.node.as_ref(),
            self.parent_post_state(parent)?,
            parent.header(),
            read_fn,
        )
    }

    fn parent_post_state(&self, parent: &Block) -> eyre::Result<EvmStateProviderBox> {
        let state = self
            .executed_state
            .state_by_block_hash(self.node.provider.clone(), parent.digest().0)?;
        Ok(Box::new(state.into_evm_state_provider()))
    }
}

/// Each of `players`' proposer units, in their order, as the election weighs them at the parent,
/// elected for the epoch after or not; one it does not rank gets a unit.
fn proposer_units(
    players: &ordered::Set<PublicKey>,
    weights: &BTreeMap<PublicKey, U256>,
) -> Vec<u16> {
    let weights: Vec<U256> = players
        .iter()
        .map(|player| weights.get(player).copied().unwrap_or_default())
        .collect();
    weighted_elector::units(&weights, weighted_elector::CAP_BPS)
}

/// Returns the DKG outcome of a boundary block whose parent is at
/// `parent_height`. The outcome is for the epoch after the parent's epoch.
fn assemble_boundary_outcome(
    epoch_strategy: &FixedEpocher,
    parent_height: Height,
    output: Output<MinSig, PublicKey>,
    next_players: ordered::Set<PublicKey>,
    next_full_dkg_epoch: u64,
    proposer_units: Option<Vec<u16>>,
    vote_keys: Option<Vec<Option<VoteKey>>>,
) -> OnchainDkgOutcome {
    let next_epoch = epoch_strategy
        .containing(parent_height)
        .expect("epoch strategy is for all heights")
        .epoch()
        .next();

    OnchainDkgOutcome {
        epoch: next_epoch.get(),
        output,
        next_players,
        is_next_full_dkg: next_full_dkg_epoch == next_epoch.get(),
        proposer_units,
        vote_keys,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_utils::TryFromIterator as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::test_utils::dkg_fixture;

    #[test]
    fn boundary_outcome_is_for_the_next_epoch_and_uses_the_parent_state() {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let output = dkg_fixture(&mut StdRng::seed_from_u64(0), Epoch::new(2))
            .outcome
            .output;
        let next_players = ordered::Set::try_from_iter(
            (10..13).map(|seed| PrivateKey::from_seed(seed).public_key()),
        )
        .unwrap();

        // With an epoch length of 10, height 18 is the parent of the boundary
        // block of epoch 1.
        for (next_full_dkg_epoch, is_next_full_dkg) in [(2, true), (1, false), (3, false)] {
            assert_eq!(
                assemble_boundary_outcome(
                    &epoch_strategy,
                    Height::new(18),
                    output.clone(),
                    next_players.clone(),
                    next_full_dkg_epoch,
                    None,
                    None,
                ),
                OnchainDkgOutcome {
                    epoch: 2,
                    output: output.clone(),
                    next_players: next_players.clone(),
                    is_next_full_dkg,
                    proposer_units: None,
                    vote_keys: None,
                },
                "full DKG scheduled for epoch {next_full_dkg_epoch}",
            );
        }
    }
    #[test]
    fn proposer_units_follow_the_players_in_their_order() {
        // Seven seats, so the 20% cap leaves room for unequal odds; the last is not ranked.
        let players = ordered::Set::try_from_iter(
            (0..7).map(|seed| PrivateKey::from_seed(seed).public_key()),
        )
        .unwrap();
        let weights = players
            .iter()
            .cloned()
            .zip([40u64, 10, 10, 10, 10, 10].map(U256::from))
            .collect();
        assert_eq!(
            proposer_units(&players, &weights),
            [1_389, 1_111, 1_111, 1_111, 1_111, 1_111, 1]
        );
    }
}
