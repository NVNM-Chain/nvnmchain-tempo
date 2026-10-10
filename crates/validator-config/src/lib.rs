//! Provides [`ValidatorConfig`] which builds the keccak256 message preimages expected by
//! `addValidator` and `rotateValidator`, and verifies ed25519 signatures over them, and
//! [`VoteKeypair`], the BLS key a validator signs its consensus votes with.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::net::{IpAddr, SocketAddr};

use alloy_primitives::{Address, B256, Keccak256};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Signer as _, Verifier as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops,
        variant::MinSig,
    },
    ed25519,
};
use tempo_contracts::precompiles::{IEquivocation, VALIDATOR_CONFIG_V2_ADDRESS};
use tempo_precompiles::validator_config_v2::{
    VALIDATOR_NS_ADD, VALIDATOR_NS_ROTATE, vote_key_proof_namespace,
};

/// What a vote key is derived under.
const VOTE_KEY_DST: &[u8] = b"TEMPO_VOTE_KEY";

/// The BLS key a validator signs its consensus votes with once they are attributable, derived
/// from its ed25519 signing key so that an operator keeps one secret. A signing key rotated out
/// stays one: the registry keeps its vote key, and evidence under it still names the validator.
#[derive(Clone, Debug)]
pub struct VoteKeypair {
    private: Private,
    /// The validator key it is derived from, which the registry holds it under.
    public_key: B256,
}

impl VoteKeypair {
    pub fn derive(signing_key: &ed25519::PrivateKey) -> Self {
        Self {
            private: Private::new(Scalar::map(VOTE_KEY_DST, signing_key.encode().as_ref())),
            public_key: B256::from_slice(signing_key.public_key().as_ref()),
        }
    }

    pub fn private(&self) -> Private {
        self.private.clone()
    }

    pub fn public(&self) -> tempo_precompiles::validator_config_v2::VoteKey {
        ops::compute_public::<MinSig>(&self.private)
    }

    /// The registry call that registers this key for the validator at `idx` on the chain of
    /// `chain_id`, with the proof of possession it asks for.
    pub fn registration(&self, chain_id: u64, idx: u64) -> IEquivocation::setVoteKeyCall {
        let namespace = vote_key_proof_namespace(chain_id, self.public_key);
        let proof = ops::sign_proof_of_possession::<MinSig>(&self.private, &namespace);
        IEquivocation::setVoteKeyCall {
            idx,
            key: self.public().encode().to_vec().into(),
            proof: proof.encode().to_vec().into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidatorConfigError {
    #[error("invalid ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid ed25519 signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}
pub struct ValidatorConfig {
    pub chain_id: u64,
    pub validator_address: Address,
    pub public_key: B256,
    pub ingress: SocketAddr,
    pub egress: IpAddr,
}

impl ValidatorConfig {
    /// Returns the base hasher with the common preimage fields:
    /// `chainId || contractAddr || validatorAddr || len(ingress) || ingress || len(egress) || egress`.
    fn base_hasher(&self) -> Keccak256 {
        let ingress = self.ingress.to_string();
        let ingress_length = u8::try_from(ingress.len()).expect("ingress length must fit u8");

        let egress = self.egress.to_string();
        let egress_length = u8::try_from(egress.len()).expect("egress length must fit u8");

        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(self.validator_address.as_slice());
        hasher.update([ingress_length]);
        hasher.update(ingress.as_bytes());
        hasher.update([egress_length]);
        hasher.update(egress.as_bytes());
        hasher
    }

    /// Returns the message hash for `addValidator`
    pub fn add_validator_message_hash(&self, fee_recipient: Address) -> B256 {
        let mut hasher = self.base_hasher();
        hasher.update(fee_recipient.as_slice());
        hasher.finalize()
    }

    /// Returns the message hash for `rotateValidator`
    pub fn rotate_validator_message_hash(&self) -> B256 {
        self.base_hasher().finalize()
    }

    /// Verifies that `signature` is a valid `addValidator` ed25519 signature.
    pub fn check_add_validator_signature(
        &self,
        fee_recipient: Address,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        let message = self.add_validator_message_hash(fee_recipient);
        self.check_signature(VALIDATOR_NS_ADD, &message, signature)
    }

    /// Verifies that `signature` is a valid `rotateValidator` ed25519 signature.
    pub fn check_rotate_validator_signature(
        &self,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        let message = self.rotate_validator_message_hash();
        self.check_signature(VALIDATOR_NS_ROTATE, &message, signature)
    }

    fn check_signature(
        &self,
        namespace: &[u8],
        message: &B256,
        signature: &[u8],
    ) -> Result<(), ValidatorConfigError> {
        let public_key = ed25519::PublicKey::decode(self.public_key.as_slice())
            .map_err(|_| ValidatorConfigError::InvalidPublicKey)?;
        let sig = ed25519::Signature::decode(signature)
            .map_err(|_| ValidatorConfigError::InvalidSignature)?;
        if !public_key.verify(namespace, message.as_slice(), &sig) {
            return Err(ValidatorConfigError::SignatureVerificationFailed);
        }
        Ok(())
    }
}
