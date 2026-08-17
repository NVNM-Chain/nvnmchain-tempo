use std::{
    collections::HashSet,
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

/// Builds an EVM over the state at `block_hash`, with that block's header.
fn evm_at_block_hash(
    node: impl ExecutionNode,
    block_hash: B256,
) -> eyre::Result<(
    TempoHeader,
    TempoEvm<State<StateProviderDatabase<StateProviderBox>>>,
)> {
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

    let evm = node
        .evm_for_block(db, &header)
        .wrap_err("failed instantiating evm for block")?;

    Ok((header, evm))
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
    let (header, mut evm) = evm_at_block_hash(node, block_hash)?;
    debug!(height = header.number(), "header found");
    let res = read_config_on_evm(&mut evm, read_fn)?;
    Ok((header.number(), block_hash, res))
}

/// Runs a precompile-storage read against an already-built EVM.
fn read_config_on_evm<C, T>(
    evm: &mut TempoEvm<State<StateProviderDatabase<StateProviderBox>>>,
    read_fn: impl FnOnce(&C) -> eyre::Result<T>,
) -> eyre::Result<T>
where
    C: Default,
{
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || read_fn(&C::default()),
    )
}

/// Decodes the active validator set from the config contract, in contract order.
///
/// Entries that fail to decode are skipped with a warning. Duplicate consensus keys are
/// kept: each caller owns its duplicate policy — the p2p map dedups with a warning, the
/// election treats them as a fallback trigger.
pub(crate) fn decoded_active_validators(
    config: &ValidatorConfigV2,
) -> eyre::Result<Vec<DecodedValidatorV2>> {
    let mut out = Vec::new();
    for (position, raw) in config
        .get_active_validators()
        .wrap_err("failed getting active validator set")?
        .into_iter()
        .enumerate()
    {
        if let Ok(decoded) = DecodedValidatorV2::decode_from_contract(raw).inspect_err(|error| {
            warn!(%error, position, "failed decoding active validator in contract");
        }) {
            out.push(decoded);
        }
    }
    Ok(out)
}

alloy_sol_types::sol! {
    /// The committee-election surface of the staking contract (`NVNMStaking.computeCommittee`).
    /// The engine is unit-weighted, so the committee is just the address list.
    interface IStakingElection {
        function computeCommittee() external view returns (address[] vals);
    }
}

/// Minimum elected committee size before falling back to the full registry (3f+1, f=1).
const MIN_ELECTED_COMMITTEE: usize = 4;

/// The next epoch's players at `block_hash`: the committee elected by `staking_election` when
/// one is configured, intersected with the registry that holds the consensus keys — and the
/// full active registry otherwise, or whenever the election cannot seat a committee.
///
/// Deterministic across nodes: same block hash => same state => same result. Every fallback is
/// a function of that state — nothing configured, no code at the address, a reverting or
/// undecodable call, a committee below the viability floor, a duplicate key — so all nodes take
/// it together. An `Err` is node-local (missing state, provider failure) and propagates instead:
/// a fallback one node takes and its peers do not splits the validator set, with no genesis-hash
/// mismatch to catch it.
#[instrument(skip_all, fields(%block_hash), err(Display))]
pub(crate) fn next_players_at_block_hash(
    node: impl ExecutionNode,
    block_hash: B256,
    staking_election: Option<Address>,
    staking_election_time: Option<u64>,
) -> eyre::Result<ordered::Set<PublicKey>> {
    let (header, mut evm) = evm_at_block_hash(node, block_hash)?;

    // One registry read serves the election intersection and the fallback alike.
    let registry = read_config_on_evm(&mut evm, decoded_active_validators)
        .wrap_err("failed reading validator config v2")?;

    // The activation timestamp is judged against the read block, so every node flips to the
    // election at the same boundary regardless of when it restarted onto the new config.
    let election_active = staking_election_time.is_none_or(|from| header.timestamp() >= from);
    if let Some(contract) = staking_election
        && election_active
        && let Some(players) = elected_players(&mut evm, contract, &registry)?
    {
        debug!(?players, "determined next players from staking election");
        return Ok(players);
    }

    // Full registry: the active validators, deduplicated by consensus key.
    let mut keys = HashSet::new();
    for validator in &registry {
        if !keys.insert(validator.public_key().clone()) {
            warn!(duplicate = %validator.public_key(), "found duplicate public keys");
        }
    }
    let next_players =
        ordered::Set::try_from_iter(keys).expect("a hash set does not contain duplicates");
    debug!(?next_players, "determined next players from full registry");
    Ok(next_players)
}

/// The elected committee's consensus keys at the EVM's block, or `None` when the election
/// cannot seat one and the caller must fall back to the full registry.
///
/// Every `None` is a function of the state the EVM was built over, so all nodes take the
/// fallback together; only node-local failures (provider errors) surface as `Err`.
fn elected_players(
    evm: &mut TempoEvm<State<StateProviderDatabase<StateProviderBox>>>,
    contract: Address,
    registry: &[DecodedValidatorV2],
) -> eyre::Result<Option<ordered::Set<PublicKey>>> {
    use alloy_evm::Evm as _;
    use alloy_sol_types::SolCall as _;
    use reth_ethereum::evm::revm::{Database as _, context::result::ExecutionResult};

    // A codeless address (typo'd genesis, or a contract deployed after this block) makes the
    // call below succeed with empty, undecodable returndata. That is state, not a node-local
    // fault, and must land in the fallback rather than an error.
    let account = evm
        .db_mut()
        .basic(contract)
        .map_err(|e| eyre::eyre!("failed reading election contract account: {e:?}"))?;
    if account.is_none_or(|account| account.is_empty_code_hash()) {
        warn!(%contract, "staking election contract has no code; falling back to full registry");
        return Ok(None);
    }

    // The system-call path pins its own gas limit, so a revert or out-of-gas here is also a
    // function of state and hits every node together — fallback, not failure.
    let result = evm
        .transact_system_call(
            Address::ZERO,
            contract,
            IStakingElection::computeCommitteeCall {}
                .abi_encode()
                .into(),
        )
        .map_err(|e| eyre::eyre!("election call failed to execute: {e:?}"))?;
    let ExecutionResult::Success { output, .. } = result.result else {
        warn!(
            %contract,
            result = ?result.result,
            "election call did not succeed; falling back to full registry"
        );
        return Ok(None);
    };
    let Ok(elected) = IStakingElection::computeCommitteeCall::abi_decode_returns(output.data())
    else {
        warn!(%contract, "failed decoding computeCommittee() return; falling back to full registry");
        return Ok(None);
    };

    let Some(players) = filter_elected_players(registry, &elected) else {
        warn!(
            elected = elected.len(),
            registry = registry.len(),
            "elected committee below minimum; falling back to full registry"
        );
        return Ok(None);
    };

    // Unreachable while the ValidatorConfigV2 precompile enforces key uniqueness, but
    // deterministic if it ever is reached — every node reads the same registry.
    match ordered::Set::try_from_iter(players) {
        Ok(set) => Ok(Some(set)),
        Err(error) => {
            warn!(%error, "elected committee has duplicate keys; falling back to full registry");
            Ok(None)
        }
    }
}

/// Filters the registry down to the elected committee.
///
/// Returns `None` when the registry is empty or the intersection is smaller than
/// `min(MIN_ELECTED_COMMITTEE, registry size)` — the caller must then fall back
/// to the full registry so a mis-configured election cannot halt the chain.
fn filter_elected_players(
    registry: &[DecodedValidatorV2],
    elected: &[Address],
) -> Option<Vec<PublicKey>> {
    if registry.is_empty() {
        return None;
    }
    let elected: HashSet<&Address> = elected.iter().collect();
    let filtered: Vec<PublicKey> = registry
        .iter()
        .filter(|validator| elected.contains(&validator.address()))
        .map(|validator| validator.public_key().clone())
        .collect();
    (filtered.len() >= MIN_ELECTED_COMMITTEE.min(registry.len())).then_some(filtered)
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

    fn registry(n: u8) -> Vec<DecodedValidatorV2> {
        (0..n)
            .map(|i| DecodedValidatorV2 {
                public_key: PrivateKey::from_seed(u64::from(i)).public_key(),
                ingress: SocketAddr::from(([127, 0, 0, 1], 8000)),
                egress: IpAddr::from([127, 0, 0, 1]),
                added_at_height: 0,
                deleted_at_height: 0,
                index: u64::from(i),
                address: Address::repeat_byte(i + 1),
            })
            .collect()
    }

    #[test]
    fn elected_subset_above_minimum_is_used() {
        let reg = registry(6);
        let elected: Vec<Address> = reg[..4].iter().map(|v| v.address()).collect();
        let players = filter_elected_players(&reg, &elected).expect("meets minimum");
        assert_eq!(players.len(), 4);
        assert!(players.iter().eq(reg[..4].iter().map(|v| v.public_key())));
    }

    #[test]
    fn committee_below_minimum_falls_back() {
        let reg = registry(6);
        let elected: Vec<Address> = reg[..3].iter().map(|v| v.address()).collect();
        assert!(filter_elected_players(&reg, &elected).is_none());
    }

    #[test]
    fn small_registry_lowers_the_minimum() {
        // A 2-validator devnet: electing both is enough; electing one is not.
        let reg = registry(2);
        let both: Vec<Address> = reg.iter().map(|v| v.address()).collect();
        assert_eq!(filter_elected_players(&reg, &both).unwrap().len(), 2);
        assert!(filter_elected_players(&reg, &both[..1].to_vec()).is_none());
    }

    #[test]
    fn unknown_elected_addresses_are_ignored() {
        let reg = registry(5);
        let mut elected: Vec<Address> = reg[..4].iter().map(|v| v.address()).collect();
        elected.push(Address::repeat_byte(0xEE)); // not in the registry
        assert_eq!(filter_elected_players(&reg, &elected).unwrap().len(), 4);
    }

    #[test]
    fn empty_registry_falls_back() {
        assert!(filter_elected_players(&[], &[Address::repeat_byte(1)]).is_none());
    }
}
