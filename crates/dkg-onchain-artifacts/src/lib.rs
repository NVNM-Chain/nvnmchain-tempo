//! Items that are written to chain.

use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt, Write, varint::UInt};
#[cfg(feature = "commonware-consensus")]
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{
            sharing::{ModeVersion, Sharing},
            variant::{MinSig, Variant},
        },
    },
    ed25519::PublicKey,
};
use commonware_utils::{NZU32, ordered};

const MAX_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

/// Takes `is_next_full_dkg`'s byte when the outcome carries proposer units. A decoder that
/// predates the units reads it as an invalid bool and stops, rather than drawing leaders the
/// upgraded nodes do not.
const WITH_PROPOSER_UNITS: u8 = 2;

/// Takes that byte when the outcome carries vote keys, with or without units: a decoder that
/// predates them would take the epoch's votes for garbage.
const WITH_VOTE_KEYS: u8 = 3;

/// A validator's vote key, as the registry holds it.
type VoteKey = <MinSig as Variant>::Public;

/// The outcome of a DKG ceremony as it is written to the chain.
///
/// This DKG outcome can encode up to [`u16::MAX`] validators. Note that in
/// practice this far exceeds the maximum size permitted header size and so
/// is likely out of reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainDkgOutcome {
    /// The epoch for which this outcome is used, encoded as an unsigned varint.
    pub epoch: u64,

    /// The output of the DKG ceremony. Contains the shared public polynomial,
    /// and the players in the ceremony (which will be the dealers for the
    /// epoch encoded with this output).
    pub output: Output<MinSig, PublicKey>,

    /// The next players. These will be the players in the DKG ceremony running
    /// during `epoch`.
    pub next_players: ordered::Set<PublicKey>,

    /// Whether the next DKG ceremony should be a full ceremony (new polynomial)
    /// instead of a reshare. Set when `nextFullDkgCeremony == epoch`.
    pub is_next_full_dkg: bool,

    /// Each player's odds of proposing during `epoch`, in [`Self::players`] order, once proposers
    /// are weighted by stake. `None` keeps the uniform elector.
    pub proposer_units: Option<Vec<u16>>,

    /// Each player's vote key during `epoch`, in [`Self::players`] order, where the registry
    /// holds one. `None` keeps the threshold scheme's votes.
    pub vote_keys: Option<Vec<Option<VoteKey>>>,
}

impl OnchainDkgOutcome {
    /// Returns the epoch for which this outcome is used.
    #[cfg(feature = "commonware-consensus")]
    pub fn epoch(&self) -> Epoch {
        Epoch::new(self.epoch)
    }

    pub fn dealers(&self) -> &ordered::Set<PublicKey> {
        self.output.dealers()
    }

    pub fn players(&self) -> &ordered::Set<PublicKey> {
        self.output.players()
    }

    pub fn next_players(&self) -> &ordered::Set<PublicKey> {
        &self.next_players
    }

    pub fn sharing(&self) -> &Sharing<MinSig> {
        self.output.public()
    }

    pub fn network_identity(&self) -> &<MinSig as Variant>::Public {
        self.sharing().public()
    }
}

impl Write for OnchainDkgOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.output.write(buf);
        self.next_players.write(buf);
        match (&self.proposer_units, &self.vote_keys) {
            (units, Some(keys)) => {
                WITH_VOTE_KEYS.write(buf);
                self.is_next_full_dkg.write(buf);
                units.write(buf);
                keys.write(buf);
            }
            (Some(units), None) => {
                WITH_PROPOSER_UNITS.write(buf);
                self.is_next_full_dkg.write(buf);
                units.write(buf);
            }
            (None, None) => self.is_next_full_dkg.write(buf),
        }
    }
}

impl Read for OnchainDkgOutcome {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::<u64>::read(buf)?.into();
        let output: Output<MinSig, PublicKey> =
            Read::read_cfg(buf, &(MAX_VALIDATORS, ModeVersion::v0()))?;
        let next_players = Read::read_cfg(
            buf,
            &(RangeCfg::from(1..=(MAX_VALIDATORS.get() as usize)), ()),
        )?;
        // One entry for each player, whichever it is of.
        let each_player = (RangeCfg::exact(output.players().len()), ());
        let (is_next_full_dkg, proposer_units, vote_keys) = match u8::read(buf)? {
            0 => (false, None, None),
            1 => (true, None, None),
            WITH_PROPOSER_UNITS => {
                let is_next_full_dkg = ReadExt::read(buf)?;
                let units: Vec<u16> = Read::read_cfg(buf, &each_player)?;
                (is_next_full_dkg, Some(units), None)
            }
            WITH_VOTE_KEYS => {
                let is_next_full_dkg = ReadExt::read(buf)?;
                let units: Option<Vec<u16>> = Read::read_cfg(buf, &each_player)?;
                let keys: Vec<Option<VoteKey>> = Read::read_cfg(buf, &each_player)?;
                (is_next_full_dkg, units, Some(keys))
            }
            other => return Err(commonware_codec::Error::InvalidEnum(other)),
        };
        Ok(Self {
            epoch,
            output,
            next_players,
            is_next_full_dkg,
            proposer_units,
            vote_keys,
        })
    }
}

impl EncodeSize for OnchainDkgOutcome {
    fn encode_size(&self) -> usize {
        let marked = WITH_VOTE_KEYS.encode_size();
        UInt(self.epoch).encode_size()
            + self.output.encode_size()
            + self.next_players.encode_size()
            + self.is_next_full_dkg.encode_size()
            + match (&self.proposer_units, &self.vote_keys) {
                (units, Some(keys)) => marked + units.encode_size() + keys.encode_size(),
                (Some(units), None) => marked + units.encode_size(),
                (None, None) => 0,
            }
    }
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use commonware_codec::{Encode as _, EncodeSize as _, Error, ReadExt as _};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt as dkg,
            primitives::{ops::keypair, sharing::Mode, variant::MinSig},
        },
        ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random as _;
    use commonware_utils::{N3f1, TryFromIterator as _, ordered};
    use rand::SeedableRng as _;

    use super::{OnchainDkgOutcome, VoteKey};

    /// A vote key for each of ten players but the third, which the registry holds none for.
    fn vote_keys() -> Vec<Option<VoteKey>> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        (0..10)
            .map(|player| (player != 2).then(|| keypair::<_, MinSig>(&mut rng).1))
            .collect()
    }

    fn outcome(
        proposer_units: Option<Vec<u16>>,
        vote_keys: Option<Vec<Option<VoteKey>>>,
    ) -> OnchainDkgOutcome {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let mut player_keys = repeat_with(|| PrivateKey::random(&mut rng))
            .take(10)
            .collect::<Vec<_>>();
        player_keys.sort_by_key(|key| key.public_key());
        let (output, _shares) = dkg::deal::<_, _, N3f1>(
            &mut rng,
            Mode::NonZeroCounter,
            ordered::Set::try_from_iter(player_keys.iter().map(|key| key.public_key())).unwrap(),
        )
        .unwrap();

        OnchainDkgOutcome {
            epoch: 42,
            output,
            next_players: ordered::Set::try_from_iter(
                player_keys.iter().map(|key| key.public_key()),
            )
            .unwrap(),
            is_next_full_dkg: true,
            proposer_units,
            vote_keys,
        }
    }

    #[test]
    fn onchain_dkg_outcome_roundtrip() {
        let units: Option<Vec<u16>> = Some((1..=10).collect());
        for (units, keys) in [
            (None, None),
            (units.clone(), None),
            (None, Some(vote_keys())),
            (units, Some(vote_keys())),
        ] {
            let mut on_chain = outcome(units, keys);
            // Preserve Commonware Epoch's wire encoding, including varint boundaries.
            let payload = on_chain.encode()[Epoch::new(on_chain.epoch).encode_size()..].to_vec();
            for epoch in [0, 127, 128, 16383, 16384, u64::MAX] {
                let prefix = Epoch::new(epoch).encode();
                on_chain.epoch = epoch;
                #[cfg(feature = "commonware-consensus")]
                assert_eq!(on_chain.epoch(), Epoch::new(epoch));
                let bytes = on_chain.encode();
                assert_eq!(&bytes[..prefix.len()], prefix.as_ref());
                assert_eq!(&bytes[prefix.len()..], payload);
                assert_eq!(bytes.len(), on_chain.encode_size());
                assert_eq!(
                    OnchainDkgOutcome::read(&mut bytes.as_ref()).unwrap(),
                    on_chain
                );
            }
        }
    }

    /// The marker of units or vote keys sits where a decoder without them expects
    /// `is_next_full_dkg`, which it refuses.
    #[test]
    fn a_decoder_without_units_or_vote_keys_refuses_an_outcome_with_them() {
        let legacy = outcome(None, None).encode();
        let flag = legacy.len() - 1;
        for marked in [
            outcome(Some(vec![1; 10]), None),
            outcome(None, Some(vote_keys())),
        ] {
            let marked = marked.encode();
            assert_eq!(legacy[..flag], marked[..flag]);
            assert!(matches!(
                bool::read(&mut &marked[flag..]),
                Err(Error::InvalidBool)
            ));
        }
    }

    #[test]
    fn units_must_cover_every_player() {
        let mut bytes = outcome(Some(vec![1; 10]), None).encode().to_vec();
        let flag = outcome(None, None).encode().len() - 1;
        bytes[flag + 2] = 9; // the units' length prefix
        bytes.pop();
        assert!(OnchainDkgOutcome::read(&mut bytes.as_slice()).is_err());
    }

    #[test]
    fn vote_keys_must_cover_every_player() {
        let mut keys = vote_keys();
        keys.pop();
        let bytes = outcome(None, Some(keys)).encode();
        assert!(OnchainDkgOutcome::read(&mut bytes.as_ref()).is_err());
    }
}
