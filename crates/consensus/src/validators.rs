use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, B256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Ingress;
use commonware_utils::{TryFromIterator, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use reth_ethereum::evm::revm::{State, database::StateProviderDatabase};
use reth_node_builder::ConfigureEvm as _;
use reth_provider::{HeaderProvider as _, StateProviderBox, StateProviderFactory as _};
use tempo_node::{TempoFullNode, evm::evm::TempoEvm};
use tempo_precompiles::{
    storage::{StorageActions, StorageCtx},
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2},
};
use tempo_primitives::TempoHeader;

use tracing::{Level, debug, instrument, warn};

use crate::utils::public_key_to_b256;

/// Minimal execution-node interface needed to read validator config state.
///
/// Production code uses [`TempoFullNode`]. This trait exists so unit tests can
/// use a mock that only provides a historical state provider and an EVM
/// configured for the corresponding block, while still exercising the same
/// validator config reader used in production.
pub(crate) trait ExecutionNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader>;

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox>;

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<StateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>>;
}

impl ExecutionNode for TempoFullNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        self.provider
            .header(block_hash)
            .map_err(eyre::Report::new)
            .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty header"))
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
        self.provider
            .state_by_block_hash(block_hash)
            .map_err(eyre::Report::new)
    }

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<StateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>> {
        self.evm_config
            .evm_for_block(db, header)
            .map_err(eyre::Report::new)
    }
}

impl<N> ExecutionNode for &N
where
    N: ExecutionNode,
{
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        (*self).header(block_hash)
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
        (*self).state_by_block_hash(block_hash)
    }

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<StateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>> {
        (*self).evm_for_block(db, header)
    }
}

/// Returns active validator config v2 entries at block `hash`.
///
/// This returns both the validators that are `active` as per the contract, and
/// those that are `known`.
pub(crate) fn read_active_and_known_peers_at_block_hash(
    node: impl ExecutionNode,
    known: &ordered::Set<PublicKey>,
    hash: B256,
) -> eyre::Result<ordered::Map<PublicKey, commonware_p2p::Address>> {
    read_validator_config_at_block_hash(node, hash, |config: &ValidatorConfigV2| {
        let mut all = HashMap::new();
        for raw in config
            .get_active_validators()
            .wrap_err("failed getting active validator set")?
        {
            if let Ok(decoded) = DecodedValidatorV2::decode_from_contract(raw)
                && all
                    .insert(decoded.public_key.clone(), decoded.to_p2p_address())
                    .is_some()
            {
                warn!(
                    duplicate = %decoded.public_key,
                    "found duplicate public keys",
                );
            }
        }
        debug!(
            active_validators = ?all,
            "read active validators from contract, now extending with historic \
            peers that are still in the peer set but no longer marked active",
        );
        for member in known {
            if !all.contains_key(member) {
                let decoded = config
                    .validator_by_public_key(public_key_to_b256(member))
                    .map_err(eyre::Report::new)
                    .and_then(DecodedValidatorV2::decode_from_contract)
                    .wrap_err_with(|| format!("failed to read peer `{member}` from contract"))
                    .expect(
                        "invariant: known peers must have an entry in the \
                        smart contract and be well formed",
                    );
                all.insert(decoded.public_key.clone(), decoded.to_p2p_address());
            }
        }
        Ok(ordered::Map::try_from_iter(all).expect("hashmaps don't contain duplicates"))
    })
    .map(|(_height, _hash, value)| value)
}

/// Reads the validator state at the given block hash.
#[instrument(skip_all, fields(%block_hash), err(Display))]
pub(crate) fn read_validator_config_at_block_hash<C, T>(
    node: impl ExecutionNode,
    block_hash: B256,
    read_fn: impl FnOnce(&C) -> eyre::Result<T>,
) -> eyre::Result<(u64, B256, T)>
where
    C: Default,
{
    let header = node
        .header(block_hash)
        .wrap_err_with(|| format!("failed reading block with hash `{block_hash}`"))?;

    debug!(height = header.number(), "header found");

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.state_by_block_hash(block_hash).wrap_err_with(|| {
                format!("failed to get state from node provider for hash `{block_hash}`")
            })?,
        ))
        .build();

    let mut evm = node
        .evm_for_block(db, &header)
        .wrap_err("failed instantiating evm for block")?;

    let ctx = evm.ctx_mut();
    let res = StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || read_fn(&C::default()),
    )?;
    Ok((header.number(), block_hash, res))
}

/// Reads the active validator set at `block_hash` as `(consensus key, validator address)` pairs.
pub(crate) fn read_active_validator_keys_at_block_hash(
    node: impl ExecutionNode,
    block_hash: B256,
) -> eyre::Result<Vec<(PublicKey, Address)>> {
    read_validator_config_at_block_hash(node, block_hash, |config: &ValidatorConfigV2| {
        let mut out = Vec::new();
        for raw in config
            .get_active_validators()
            .wrap_err("failed getting active validator set")?
        {
            if let Ok(decoded) = DecodedValidatorV2::decode_from_contract(raw) {
                out.push((decoded.public_key().clone(), decoded.address()));
            }
        }
        Ok(out)
    })
    .map(|(_, _, out)| out)
}

alloy_sol_types::sol! {
    /// The committee-election surface of the staking contract (`NVNMStaking.computeCommittee`).
    interface IStakingElection {
        function computeCommittee() external view returns (address[] vals, uint256[] seats);
    }
}

/// Nominal gas limit for the election read. NOTE: this is a read-only *system* call
/// (`is_system_tx: true`), and revm's system-call path rebuilds the tx with its own
/// `SYSTEM_CALL_GAS_LIMIT` — the value set here is not the one enforced. Determinism does not
/// rely on this cap: `NVNMStaking` bounds the candidate list (`MAX_CANDIDATES`), so
/// `computeCommittee()`'s gas is bounded far below any revm system-call limit on every node,
/// and a homogeneous fleet enforces an identical limit regardless. Kept for intent/documentation
/// and in case the call is ever moved off the system-tx path.
const ELECTION_CALL_GAS: u64 = 30_000_000;

/// Minimum elected committee size before falling back to the full registry (3f+1, f=1).
pub(crate) const MIN_ELECTED_COMMITTEE: usize = 4;

/// Reads the elected committee (validator addresses, election order) from the
/// staking-election contract at `block_hash` via a read-only call.
///
/// Deterministic across nodes: same block hash => same state => same result.
pub(crate) fn read_elected_committee_at_block_hash(
    node: impl ExecutionNode,
    block_hash: B256,
    contract: Address,
) -> eyre::Result<Vec<Address>> {
    use alloy_evm::Evm as _;
    use alloy_sol_types::SolCall as _;

    let header = node
        .header(block_hash)
        .wrap_err_with(|| format!("failed reading block with hash `{block_hash}`"))?;
    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.state_by_block_hash(block_hash).wrap_err_with(|| {
                format!("failed to get state from node provider for hash `{block_hash}`")
            })?,
        ))
        .build();
    let mut evm = node
        .evm_for_block(db, &header)
        .wrap_err("failed instantiating evm for block")?;

    let result = evm
        .transact(tempo_revm::TempoTxEnv {
            inner: reth_ethereum::evm::revm::context::TxEnv {
                caller: Address::ZERO,
                kind: alloy_primitives::TxKind::Call(contract),
                data: IStakingElection::computeCommitteeCall {}
                    .abi_encode()
                    .into(),
                gas_limit: ELECTION_CALL_GAS,
                gas_price: 0,
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        })
        .map_err(|e| eyre::eyre!("election call failed to execute: {e:?}"))?;

    let reth_ethereum::evm::revm::context::result::ExecutionResult::Success { output, .. } =
        result.result
    else {
        eyre::bail!("election call did not succeed: {:?}", result.result);
    };
    let ret = IStakingElection::computeCommitteeCall::abi_decode_returns(output.data())
        .wrap_err("failed decoding computeCommittee() return")?;
    Ok(ret.vals)
}

/// Filters the registry down to the elected committee.
///
/// Returns `None` when the intersection is smaller than
/// `min(MIN_ELECTED_COMMITTEE, registry size)` — the caller must then fall back
/// to the full registry so a mis-configured election cannot halt the chain.
pub(crate) fn filter_elected_players(
    registry: &[(PublicKey, Address)],
    elected: &[Address],
) -> Option<Vec<PublicKey>> {
    let filtered: Vec<PublicKey> = registry
        .iter()
        .filter(|(_, addr)| elected.contains(addr))
        .map(|(pk, _)| pk.clone())
        .collect();
    let required = MIN_ELECTED_COMMITTEE.min(registry.len());
    (filtered.len() >= required && required > 0).then_some(filtered)
}

/// An entry in the validator config v2 contract with all its fields decoded
/// into Rust types.
pub(crate) struct DecodedValidatorV2 {
    public_key: PublicKey,
    ingress: SocketAddr,
    egress: IpAddr,
    added_at_height: u64,
    deleted_at_height: u64,
    index: u64,
    address: Address,
}

impl DecodedValidatorV2 {
    #[instrument(ret(Display, level = Level::DEBUG), err(level = Level::WARN))]
    pub(crate) fn decode_from_contract(
        IValidatorConfigV2::Validator {
            publicKey,
            validatorAddress: address,
            ingress,
            egress,
            index,
            addedAtHeight: added_at_height,
            deactivatedAtHeight: deleted_at_height,
            ..
        }: IValidatorConfigV2::Validator,
    ) -> eyre::Result<Self> {
        let public_key = PublicKey::decode(publicKey.as_ref())
            .wrap_err("failed decoding publicKey field as ed25519 public key")?;
        let ingress = ingress.parse().wrap_err("ingress was not valid")?;
        let egress = egress.parse().wrap_err("egress was not valid")?;
        Ok(Self {
            public_key,
            ingress,
            egress,
            added_at_height,
            deleted_at_height,
            index,
            address,
        })
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) fn address(&self) -> Address {
        self.address
    }

    pub(crate) fn to_p2p_address(&self) -> commonware_p2p::Address {
        // NOTE: commonware takes egress as socket address but only uses the IP part.
        // So setting port to 0 is ok.
        commonware_p2p::Address::Asymmetric {
            ingress: Ingress::Socket(self.ingress),
            egress: SocketAddr::from((self.egress, 0)),
        }
    }
}
impl std::fmt::Display for DecodedValidatorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, ingress = `{}`, egress = `{}`, added_at_height: `{}`, deleted_at_height = `{}`, index = `{}`, address = `{}`",
            self.public_key,
            self.ingress,
            self.egress,
            self.added_at_height,
            self.deleted_at_height,
            self.index,
            self.address
        ))
    }
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::*;

    fn registry(n: u8) -> Vec<(PublicKey, Address)> {
        (0..n)
            .map(|i| {
                (
                    PrivateKey::from_seed(u64::from(i)).public_key(),
                    Address::repeat_byte(i + 1),
                )
            })
            .collect()
    }

    #[test]
    fn elected_subset_above_minimum_is_used() {
        let reg = registry(6);
        let elected: Vec<Address> = reg[..4].iter().map(|(_, a)| *a).collect();
        let players = filter_elected_players(&reg, &elected).expect("meets minimum");
        assert_eq!(players.len(), 4);
        assert!(players.iter().eq(reg[..4].iter().map(|(pk, _)| pk)));
    }

    #[test]
    fn committee_below_minimum_falls_back() {
        let reg = registry(6);
        let elected: Vec<Address> = reg[..3].iter().map(|(_, a)| *a).collect();
        assert!(filter_elected_players(&reg, &elected).is_none());
    }

    #[test]
    fn small_registry_lowers_the_minimum() {
        // A 2-validator devnet: electing both is enough; electing one is not.
        let reg = registry(2);
        let both: Vec<Address> = reg.iter().map(|(_, a)| *a).collect();
        assert_eq!(filter_elected_players(&reg, &both).unwrap().len(), 2);
        assert!(filter_elected_players(&reg, &both[..1].to_vec()).is_none());
    }

    #[test]
    fn unknown_elected_addresses_are_ignored() {
        let reg = registry(5);
        let mut elected: Vec<Address> = reg[..4].iter().map(|(_, a)| *a).collect();
        elected.push(Address::repeat_byte(0xEE)); // not in the registry
        assert_eq!(filter_elected_players(&reg, &elected).unwrap().len(), 4);
    }

    #[test]
    fn empty_registry_falls_back() {
        assert!(filter_elected_players(&[], &[Address::repeat_byte(1)]).is_none());
    }
}
