//! Stake-weighted leader election.
//!
//! Once an epoch's DKG outcome carries proposer units, a seat proposes in proportion to its
//! election weight, quantized to [`UNITS`] and capped at [`CAP_BPS`]. Voting stays one vote per
//! seat. Units come only from T12, where upstream's schedule is [`RandomVersion::V1`], which
//! equal units reproduce.

use std::{collections::BTreeMap, marker::PhantomData};

use alloy_primitives::{U256, U512};
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::{
        elector::{Config, Elector, Random, RandomVersion, Terms},
        scheme::bls12381_threshold::vrf,
    },
    types::{Participant, Round, View},
};
use commonware_cryptography::{
    Hasher as _, PublicKey, Sha256, bls12381::primitives::variant::Variant,
};
use commonware_utils::{modulo, ordered::Set};

/// An epoch's proposer odds are quantized to this many units across its seats.
pub(crate) const UNITS: u16 = 10_000;

/// No seat proposes more than this share of an epoch's rounds, in basis points: it bounds how
/// much of the block space one validator orders, and how far the chain slows when it is offline.
pub(crate) const CAP_BPS: u64 = 2_000;

const BPS: u64 = 10_000;

/// Each weight's share of [`UNITS`], at least one unit, then capped so that no seat holds more
/// than `cap_bps` of the total. A cap under `1 / weights.len()` is raised to it, which makes
/// selection uniform.
pub(crate) fn units(weights: &[U256], cap_bps: u64) -> Vec<u16> {
    let total = weights
        .iter()
        .fold(U512::ZERO, |sum, weight| sum + U512::from(*weight));
    let mut units: Vec<u64> = weights
        .iter()
        .map(|weight| {
            if total.is_zero() {
                return 1;
            }
            (U512::from(*weight) * U512::from(UNITS) / total)
                .to::<u64>()
                .max(1)
        })
        .collect();
    cap(&mut units, cap_bps);
    units
        .into_iter()
        .map(|units| u16::try_from(units).expect("a seat never holds more than UNITS"))
        .collect()
}

/// Sets the `k` largest seats to `cap_bps` of the resulting total, for the smallest `k` at which
/// the next largest already fits under it.
fn cap(units: &mut [u64], cap_bps: u64) {
    let n = units.len() as u64;
    if n == 0 {
        return;
    }
    let cap_bps = cap_bps.clamp(BPS.div_ceil(n), BPS);
    let mut order: Vec<usize> = (0..units.len()).collect();
    order.sort_by(|&a, &b| units[b].cmp(&units[a]).then(a.cmp(&b)));

    // With `k` seats at the cap the total is `rest / (1 - k × cap)`, where `rest` is what the
    // other seats hold. The loop stops by the first `k` with `(k + 1) × cap >= 1`, so the
    // denominator stays positive.
    let mut rest: u64 = units.iter().sum();
    for (k, &seat) in order.iter().enumerate() {
        let room = BPS - k as u64 * cap_bps;
        if units[seat] * room <= cap_bps * rest {
            let capped = (cap_bps * rest / room).max(1);
            for &top in &order[..k] {
                units[top] = capped;
            }
            return;
        }
        rest -= units[seat];
    }
}

/// [`Config`] for leader election: [`Random`]'s schedule, in `version`, until an epoch's DKG
/// outcome carries proposer units, then weighted by them. A participant without units gets one.
#[derive(Clone, Debug)]
pub(crate) struct WeightedRandom<P> {
    version: RandomVersion,
    units: Option<BTreeMap<P, u16>>,
}

impl<P> WeightedRandom<P> {
    pub(crate) fn new(version: RandomVersion, units: Option<BTreeMap<P, u16>>) -> Self {
        Self { version, units }
    }
}

impl<P: PublicKey, V: Variant> Config<vrf::Scheme<P, V>> for WeightedRandom<P> {
    type Elector = WeightedRandomElector<vrf::Scheme<P, V>>;

    fn build(self, participants: &Set<P>) -> Self::Elector {
        assert!(!participants.is_empty(), "no participants");
        let draw = match self.units {
            None => Draw::Uniform {
                version: self.version,
                n: u32::try_from(participants.len()).expect("fits u32"),
            },
            Some(units) => Draw::Weighted(ends(
                participants
                    .iter()
                    .map(|participant| units.get(participant).copied().unwrap_or(1)),
            )),
        };
        WeightedRandomElector {
            draw,
            _scheme: PhantomData,
        }
    }
}

/// Initialized by [`WeightedRandom`].
#[derive(Clone, Debug)]
pub(crate) struct WeightedRandomElector<S> {
    draw: Draw,
    _scheme: PhantomData<S>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Draw {
    /// [`Random`] in `version` over `n` participants.
    Uniform { version: RandomVersion, n: u32 },
    /// Each participant's range of units, by its upper end.
    Weighted(Vec<u64>),
}

/// Running totals of `units`, a participant without any counting one.
fn ends(units: impl IntoIterator<Item = u16>) -> Vec<u64> {
    units
        .into_iter()
        .scan(0u64, |end, units| {
            *end += u64::from(units.max(1));
            Some(*end)
        })
        .collect()
}

/// Round robin for view 1, as [`Random`] does. After it, the SHA-256 of the seed signature,
/// taken modulo the units, lands in one participant's range, as [`RandomVersion::V1`] takes it
/// modulo the participants.
fn weighted(ends: &[u64], round: Round, seed: Option<&[u8]>) -> Participant {
    let Some(seed) = seed else {
        assert_eq!(round.view(), View::new(1), "no seed after view 1");
        let n = ends.len() as u64;
        let index = round.epoch().get().wrapping_add(round.view().get()) % n;
        return Participant::new(u32::try_from(index).expect("participant index fits u32"));
    };
    let total = *ends.last().expect("built with participants");
    let draw = modulo(Sha256::hash(&[seed]).as_ref(), total);
    Participant::from_usize(ends.partition_point(|&end| end <= draw))
}

impl<P: PublicKey, V: Variant> Elector<vrf::Scheme<P, V>>
    for WeightedRandomElector<vrf::Scheme<P, V>>
{
    fn terms(&self) -> Terms {
        Terms::rotating()
    }

    fn elect(&self, round: Round, certificate: Option<&vrf::Certificate<V>>) -> Participant {
        let seed = certificate.map(|certificate| {
            certificate
                .get()
                .expect("verified certificate must decode")
                .seed_signature
        });
        match &self.draw {
            Draw::Uniform { version, n } => {
                Random::<Sha256>::new(*version).select_leader::<V>(round, *n, seed)
            }
            Draw::Weighted(ends) => weighted(ends, round, seed.map(|s| s.encode()).as_deref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::variant::MinSig,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::TryFromIterator as _;

    use super::*;

    fn weights(weights: &[u64]) -> Vec<U256> {
        weights.iter().copied().map(U256::from).collect()
    }

    /// The weighted draw over `units`.
    fn draw(units: &[u16], round: Round, seed: Option<&[u8]>) -> Participant {
        weighted(&ends(units.iter().copied()), round, seed)
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::new(2), View::new(view))
    }

    #[test]
    fn units_are_proportional_with_at_least_one() {
        assert_eq!(
            units(&weights(&[6, 3, 1, 0]), BPS),
            [6_000, 3_000, 1_000, 1]
        );
    }

    #[test]
    fn zero_weights_are_uniform() {
        assert_eq!(units(&weights(&[0, 0, 0]), BPS), [1, 1, 1]);
    }

    #[test]
    fn weights_at_the_top_of_u256_do_not_overflow() {
        assert_eq!(units(&[U256::MAX, U256::MAX], BPS), [5_000, 5_000]);
    }

    /// Clamping the 9,100 units to 20% of 10,000 would leave it 2,000 of 2,900, about 69%.
    #[test]
    fn the_cap_holds_a_seat_at_its_share_of_the_new_total() {
        let capped = units(&weights(&[91, 1, 1, 1, 1, 1, 1, 1, 1, 1]), 2_000);
        assert_eq!(capped, [225, 100, 100, 100, 100, 100, 100, 100, 100, 100]);
    }

    /// Capping the largest seat alone pushes the second over the cap, so both are capped.
    #[test]
    fn the_cap_reaches_every_seat_over_it() {
        assert_eq!(
            units(&weights(&[45, 45, 5, 5]), 3_000),
            [750, 750, 500, 500]
        );
    }

    #[test]
    fn a_cap_under_one_over_n_is_uniform() {
        assert_eq!(units(&weights(&[9, 1]), 2_000), [1_000, 1_000]);
    }

    #[test]
    fn view_one_is_round_robin() {
        assert_eq!(draw(&[3, 1, 1], round(1), None), Participant::new(0));
        assert_eq!(
            draw(&[3, 1, 1], Round::new(Epoch::new(3), View::new(1)), None),
            Participant::new(1)
        );
    }

    #[test]
    fn equal_units_pick_by_the_hashed_seed() {
        for seed in 0u64..64 {
            let seed = seed.to_be_bytes();
            let expected = modulo(Sha256::hash(&[&seed]).as_ref(), 5);
            assert_eq!(
                draw(&[1; 5], round(2), Some(&seed)),
                Participant::from_usize(expected as usize)
            );
        }
    }

    #[test]
    fn leaders_follow_units() {
        let units = [6_000, 3_000, 1_000];
        let draws = 30_000u64;
        let mut counts = [0u64; 3];
        for seed in 0..draws {
            let leader = draw(&units, round(2), Some(&seed.to_be_bytes()));
            counts[leader.get() as usize] += 1;
        }
        for (count, units) in counts.into_iter().zip(units) {
            let expected = draws * u64::from(units) / u64::from(UNITS);
            assert!(
                count.abs_diff(expected) < draws / 50,
                "{count} draws against {expected} expected"
            );
        }
    }

    fn participants() -> (Vec<PublicKey>, Set<PublicKey>) {
        let keys: Vec<PublicKey> = (0..3)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        let participants = Set::try_from_iter(keys.clone()).unwrap();
        (keys, participants)
    }

    fn build(units: Option<BTreeMap<PublicKey, u16>>, participants: &Set<PublicKey>) -> Draw {
        let elector: WeightedRandomElector<vrf::Scheme<PublicKey, MinSig>> =
            WeightedRandom::new(RandomVersion::V1, units).build(participants);
        elector.draw
    }

    /// Before an outcome carries units, the schedule is `elector::Random`'s.
    #[test]
    fn without_units_the_draw_is_random() {
        let (_, participants) = participants();
        assert_eq!(
            build(None, &participants),
            Draw::Uniform {
                version: RandomVersion::V1,
                n: 3
            }
        );
    }

    /// Units follow each participant's key, in the order consensus passes them.
    #[test]
    fn build_aligns_units_with_the_participant_order() {
        let (keys, participants) = participants();
        let units = BTreeMap::from([(keys[1].clone(), 5)]);
        let expected: Vec<u64> = participants
            .iter()
            .scan(0, |end, key| {
                *end += if *key == keys[1] { 5 } else { 1 };
                Some(*end)
            })
            .collect();
        assert_eq!(build(Some(units), &participants), Draw::Weighted(expected));
    }
}
