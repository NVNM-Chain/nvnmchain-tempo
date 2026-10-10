//! The BLS key a validator signs its consensus votes with once they are attributable.
//!
//! Kept beside the registry's storage, at slots hashed from a name, so the layout upstream defines
//! stays upstream's.

use super::{IEquivocation, ValidatorConfigV2, ValidatorConfigV2Error};
use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::bls12381::primitives::{
    ops,
    variant::{MinSig, Variant},
};

/// Namespace of the proof of possession a vote key is registered with.
const VALIDATOR_NS_VOTE_KEY: &[u8] = b"TEMPO_VALIDATOR_CONFIG_V2_VOTE_KEY";

/// A BLS signature check at EIP-2537's prices: a pairing check of two pairs and a hash to G1.
pub(super) const BLS_VERIFY_GAS: u64 = 115_000;

/// A vote key, in the group the threshold scheme keeps its public keys in.
pub type VoteKey = <MinSig as Variant>::Public;

/// What a vote key signs.
pub type VoteSignature = <MinSig as Variant>::Signature;

/// What a vote key's proof of possession is made under, for the validator key `public_key` on the
/// chain of `chain_id`: a proof made for one validator registers the key for no other.
pub fn vote_key_proof_namespace(chain_id: u64, public_key: B256) -> Vec<u8> {
    [
        VALIDATOR_NS_VOTE_KEY,
        &chain_id.to_be_bytes(),
        public_key.as_slice(),
    ]
    .concat()
}

/// A mapping of this registry's at the slot `name` hashes to.
fn named<K, V: crate::storage::StorableType>(name: &str, address: Address) -> Mapping<K, V> {
    Mapping::new(U256::from_be_bytes(keccak256(name).0), address)
}

impl ValidatorConfigV2 {
    /// Validator key to the vote key registered for it.
    fn vote_keys(&self) -> Mapping<B256, Bytes> {
        named("tempo.validator_config_v2.vote_keys", self.address)
    }

    /// Hash of a vote key to the validator key it is registered for: no two share one.
    fn vote_key_holders(&self) -> Mapping<B256, B256> {
        named("tempo.validator_config_v2.vote_key_holders", self.address)
    }

    /// Whether this chain's votes are, or are scheduled to be, attributable. Vote keys are taken
    /// from then on, ahead of the first such vote.
    pub(super) fn takes_vote_keys(&self) -> bool {
        self.storage.spec().is_t12() && self.storage.attributable_votes_time().is_some()
    }

    /// Whether the validator key `public_key` has a vote key.
    pub(super) fn has_vote_key(&self, public_key: B256) -> Result<bool> {
        Ok(!self.vote_keys().at(&public_key).read()?.is_empty())
    }

    /// The vote key registered for the validator key `public_key`, if any.
    pub fn vote_key_of(&self, public_key: B256) -> Result<Option<VoteKey>> {
        let key = self.vote_keys().at(&public_key).read()?;
        // Only what `set_vote_key` decoded is ever stored.
        Ok(VoteKey::decode(key.as_ref()).ok())
    }

    pub fn vote_key(&self, call: IEquivocation::voteKeyCall) -> Result<Bytes> {
        self.vote_keys().at(&call.publicKey).read()
    }

    /// Registers the vote key of the validator at `idx`, once and from its own address: evidence
    /// is checked against it, and whoever chose a validator's vote key could sign conflicting
    /// votes in its name.
    ///
    /// # Errors
    /// - `NotInitialized` — the contract has not been initialized
    /// - `ValidatorNotFound` / `ValidatorAlreadyDeleted` — `idx` is invalid
    /// - `Unauthorized` — `sender` is not the validator
    /// - `PublicKeyAlreadyExists` — the validator has a vote key, or the key is another's
    /// - `InvalidPublicKey` — `key` is not a BLS public key
    /// - `InvalidSignature` — `proof` is not the key's proof of possession for this validator
    pub fn set_vote_key(
        &mut self,
        sender: Address,
        call: IEquivocation::setVoteKeyCall,
    ) -> Result<()> {
        let v = self.get_active_validator(call.idx)?;
        self.config.read()?.require_init()?;
        if sender != v.validator_address {
            Err(ValidatorConfigV2Error::unauthorized())?
        }
        if self.has_vote_key(v.public_key)? {
            Err(ValidatorConfigV2Error::public_key_already_exists())?
        }

        self.storage.deduct_gas(BLS_VERIFY_GAS)?;
        let key = VoteKey::decode(call.key.as_ref())
            .map_err(|_| ValidatorConfigV2Error::invalid_public_key())?;
        let proof = VoteSignature::decode(call.proof.as_ref())
            .map_err(|_| ValidatorConfigV2Error::invalid_signature())?;
        let namespace = vote_key_proof_namespace(self.storage.chain_id(), v.public_key);
        ops::verify_proof_of_possession::<MinSig>(&key, &namespace, &proof)
            .map_err(|_| ValidatorConfigV2Error::invalid_signature())?;

        let holder = keccak256(&call.key);
        if !self.vote_key_holders().at(&holder).read()?.is_zero() {
            Err(ValidatorConfigV2Error::public_key_already_exists())?
        }
        self.vote_key_holders()
            .at_mut(&holder)
            .write(v.public_key)?;
        self.vote_keys()
            .at_mut(&v.public_key)
            .write(call.key.clone())?;

        self.emit_event(IEquivocation::VoteKeySet {
            index: call.idx,
            publicKey: v.public_key,
            key: call.key,
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use alloy::{
        primitives::{Address, Keccak256},
        sol_types::SolCall as _,
    };
    use commonware_codec::Encode as _;
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::group::{Private, Scalar},
        ed25519::PrivateKey,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{IValidatorConfigV2, VALIDATOR_CONFIG_V2_ADDRESS};

    use super::{super::VALIDATOR_NS_ADD, *};
    use crate::{
        Precompile as _,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };

    pub(in super::super) const CHAIN_ID: u64 = 1;
    pub(in super::super) const GENESIS: B256 = B256::repeat_byte(7);
    /// The epoch is one block long in these tests, so a height is its epoch.
    pub(in super::super) const ENROLLED: u64 = 200;
    pub(in super::super) const NOW: u64 = 210;

    /// The vote key these tests give the validator key `key`.
    pub(in super::super) fn vote_key(key: &PrivateKey) -> Private {
        Private::new(Scalar::map(b"TEST_VOTE_KEY", &key.public_key().encode()))
    }

    /// Registers that vote key for the validator at `idx`, as `sender`.
    pub(in super::super) fn register(
        vc: &mut ValidatorConfigV2,
        sender: Address,
        idx: u64,
        key: &PrivateKey,
    ) -> Result<()> {
        vc.set_vote_key(sender, registration(idx, key, key, CHAIN_ID))
    }

    /// `key`'s signature over what the registry asks of a validator at `address`.
    pub(in super::super) fn enrolment(
        key: &PrivateKey,
        namespace: &[u8],
        address: Address,
        ip: &str,
        recipient: Option<Address>,
    ) -> Bytes {
        let ingress = format!("{ip}:8000");
        let mut hasher = Keccak256::new();
        hasher.update(CHAIN_ID.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(address.as_slice());
        for part in [ingress.as_str(), ip] {
            hasher.update([u8::try_from(part.len()).unwrap()]);
            hasher.update(part.as_bytes());
        }
        if let Some(recipient) = recipient {
            hasher.update(recipient.as_slice());
        }
        key.sign(namespace, hasher.finalize().as_slice())
            .encode()
            .to_vec()
            .into()
    }

    /// A registry in which `key` was enrolled for `validator` at [`ENROLLED`], by [`NOW`], on a
    /// chain whose votes are attributable from `from`.
    pub(in super::super) fn enrolled<T>(
        from: u64,
        key: &PrivateKey,
        validator: Address,
        owner: Address,
        test: impl FnOnce(&mut ValidatorConfigV2) -> eyre::Result<T>,
    ) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(CHAIN_ID, TempoHardfork::T12);
        storage.set_attributable_votes_time(Some(from));
        storage.set_genesis_hash(GENESIS);
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;
            vc.storage.set_block_number(ENROLLED);
            vc.add_validator(
                owner,
                IValidatorConfigV2::addValidatorCall {
                    validatorAddress: validator,
                    publicKey: validator_key(key),
                    ingress: "192.168.1.1:8000".to_string(),
                    egress: "192.168.1.1".to_string(),
                    feeRecipient: validator,
                    signature: enrolment(
                        key,
                        VALIDATOR_NS_ADD,
                        validator,
                        "192.168.1.1",
                        Some(validator),
                    ),
                },
            )?;
            vc.storage.set_block_number(NOW);
            test(&mut vc)
        })
    }

    fn validator_key(key: &PrivateKey) -> B256 {
        B256::from_slice(&key.public_key().encode())
    }

    /// A call registering `vote` for the validator at `idx`, proven for `proven_for` on `chain_id`.
    fn registration(
        idx: u64,
        vote: &PrivateKey,
        proven_for: &PrivateKey,
        chain_id: u64,
    ) -> IEquivocation::setVoteKeyCall {
        let vote = vote_key(vote);
        let namespace = vote_key_proof_namespace(chain_id, validator_key(proven_for));
        let proof = ops::sign_proof_of_possession::<MinSig>(&vote, &namespace);
        IEquivocation::setVoteKeyCall {
            idx,
            key: ops::compute_public::<MinSig>(&vote)
                .encode()
                .to_vec()
                .into(),
            proof: proof.encode().to_vec().into(),
        }
    }

    #[test]
    fn the_validator_registers_its_vote_key_once() -> eyre::Result<()> {
        let (key, validator, owner) = (
            PrivateKey::from_seed(1),
            Address::random(),
            Address::random(),
        );
        enrolled(0, &key, validator, owner, |vc| {
            assert_eq!(vc.vote_key_of(validator_key(&key))?, None);
            // Not the owner either: it can rewrite the entry's key, and would sign in its name.
            for sender in [owner, Address::random()] {
                assert_eq!(
                    register(vc, sender, 0, &key),
                    Err(ValidatorConfigV2Error::unauthorized().into())
                );
            }

            register(vc, validator, 0, &key)?;
            let registered = ops::compute_public::<MinSig>(&vote_key(&key));
            assert_eq!(vc.vote_key_of(validator_key(&key))?, Some(registered));
            let served = vc.vote_key(IEquivocation::voteKeyCall {
                publicKey: validator_key(&key),
            })?;
            assert_eq!(served.as_ref(), registered.encode().as_ref());

            // Final, with another key as much as with the same.
            let exists = Err(ValidatorConfigV2Error::public_key_already_exists().into());
            assert_eq!(register(vc, validator, 0, &key), exists);
            let other = registration(0, &PrivateKey::from_seed(9), &key, CHAIN_ID);
            assert_eq!(vc.set_vote_key(validator, other), exists);
            Ok(())
        })
    }

    #[test]
    fn a_vote_key_comes_with_its_proof_for_this_validator() -> eyre::Result<()> {
        let (key, other, validator, owner) = (
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            Address::random(),
            Address::random(),
        );
        enrolled(0, &key, validator, owner, |vc| {
            let invalid = Err(ValidatorConfigV2Error::invalid_signature().into());
            // Proven for another validator, or for this one on another chain.
            for proof in [
                registration(0, &key, &other, CHAIN_ID),
                registration(0, &key, &key, CHAIN_ID + 1),
            ] {
                assert_eq!(vc.set_vote_key(validator, proof), invalid);
            }
            // Another key's proof under this key.
            let mut borrowed = registration(0, &key, &key, CHAIN_ID);
            borrowed.proof = registration(0, &other, &key, CHAIN_ID).proof;
            assert_eq!(vc.set_vote_key(validator, borrowed), invalid);
            // Not a key at all.
            let mut garbage = registration(0, &key, &key, CHAIN_ID);
            garbage.key = vec![0xff; 96].into();
            assert_eq!(
                vc.set_vote_key(validator, garbage),
                Err(ValidatorConfigV2Error::invalid_public_key().into())
            );

            assert_eq!(vc.vote_key_of(validator_key(&key))?, None);
            vc.set_vote_key(validator, registration(0, &key, &key, CHAIN_ID))?;
            Ok(())
        })
    }

    /// The owner may move an entry to an address of its own and register there, but not bring
    /// the entry back under the validator's bond.
    #[test]
    fn an_entry_with_a_vote_key_keeps_its_address() -> eyre::Result<()> {
        let (key, validator, moved, owner) = (
            PrivateKey::from_seed(1),
            Address::random(),
            Address::random(),
            Address::random(),
        );
        let transfer = |to| IValidatorConfigV2::transferValidatorOwnershipCall {
            idx: 0,
            newAddress: to,
        };
        enrolled(u64::MAX, &key, validator, owner, |vc| {
            vc.transfer_validator_ownership(owner, transfer(moved))?;
            register(vc, moved, 0, &key)?;
            for sender in [moved, owner] {
                assert_eq!(
                    vc.transfer_validator_ownership(sender, transfer(validator)),
                    Err(ValidatorConfigV2Error::unauthorized().into())
                );
            }
            Ok(())
        })
    }

    #[test]
    fn no_two_validators_share_a_vote_key() -> eyre::Result<()> {
        let (key, second, validator, other, owner) = (
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            Address::random(),
            Address::random(),
            Address::random(),
        );
        enrolled(0, &key, validator, owner, |vc| {
            register(vc, validator, 0, &key)?;
            vc.add_validator(
                owner,
                IValidatorConfigV2::addValidatorCall {
                    validatorAddress: other,
                    publicKey: validator_key(&second),
                    ingress: "192.168.1.2:8000".to_string(),
                    egress: "192.168.1.2".to_string(),
                    feeRecipient: other,
                    signature: enrolment(
                        &second,
                        VALIDATOR_NS_ADD,
                        other,
                        "192.168.1.2",
                        Some(other),
                    ),
                },
            )?;

            // The first one's vote key, with a proof of it made for the second.
            assert_eq!(
                vc.set_vote_key(other, registration(1, &key, &second, CHAIN_ID)),
                Err(ValidatorConfigV2Error::public_key_already_exists().into())
            );
            register(vc, other, 1, &second)?;
            Ok(())
        })
    }

    #[test]
    fn vote_keys_are_taken_from_t12_where_such_votes_are_scheduled() -> eyre::Result<()> {
        let (key, validator, owner) = (
            PrivateKey::from_seed(1),
            Address::random(),
            Address::random(),
        );
        let read = IEquivocation::voteKeyCall {
            publicKey: validator_key(&key),
        }
        .abi_encode();
        let write = registration(0, &key, &key, CHAIN_ID).abi_encode();

        let unknown_to = |vc: &mut ValidatorConfigV2| {
            for call in [&write, &read] {
                let answer = vc.call(call, validator).unwrap();
                let upstream = crate::dispatch::unknown_selector_result(call).unwrap();
                assert_eq!(answer.bytes, upstream.bytes);
            }
        };

        // Ahead of the first such vote, so that it finds the keys there.
        enrolled(u64::MAX, &key, validator, owner, |vc| {
            assert!(!vc.call(&write, validator)?.is_revert());
            assert!(!vc.call(&read, validator)?.is_revert());

            // Before T12 the registry is upstream's and knows neither selector.
            vc.storage.set_spec(TempoHardfork::T11);
            unknown_to(vc);
            Ok(())
        })?;

        // Nor does it on a chain that schedules no such votes.
        let mut storage = HashMapStorageProvider::new_with_spec(CHAIN_ID, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || unknown_to(&mut ValidatorConfigV2::new()));
        Ok(())
    }
}
