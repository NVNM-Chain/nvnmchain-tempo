use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use alloy_consensus::BlockHeader;
use alloy_evm::Evm as _;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall as _;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Ingress;
use commonware_utils::{TryFromIterator, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use reth_ethereum::evm::revm::{
    Database as _, State,
    context::result::{EVMError, ExecutionResult},
    database::StateProviderDatabase,
};
use reth_node_builder::ConfigureEvm as _;
use reth_provider::{
    EvmStateProviderBox, HeaderProvider as _, StateProvider as _, StateProviderFactory as _,
};
use tempo_node::{TempoFullNode, evm::evm::TempoEvm};
use tempo_precompiles::{
    storage::{StorageActions, StorageCtx},
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2, ValidatorConfigV2Error},
};
use tempo_primitives::TempoHeader;

use tracing::{Level, debug, info, instrument, warn};

use crate::utils::public_key_to_b256;

/// Minimal execution-node interface needed to read validator config state.
///
/// Production code uses [`TempoFullNode`]. This trait exists so unit tests can
/// use a mock that only provides a historical state provider and an EVM
/// configured for the corresponding block, while still exercising the same
/// validator config reader used in production.
pub(crate) trait ExecutionNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader>;

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox>;

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<EvmStateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<EvmStateProviderBox>>>>;
}

impl ExecutionNode for TempoFullNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        self.provider
            .header(block_hash)
            .map_err(eyre::Report::new)
            .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty header"))
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox> {
        let provider = self
            .provider
            .state_by_block_hash(block_hash)
            .map_err(eyre::Report::new)?;
        Ok(Box::new(provider.into_evm_state_provider()))
    }

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<EvmStateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<EvmStateProviderBox>>>> {
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

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox> {
        (*self).state_by_block_hash(block_hash)
    }

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<EvmStateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<EvmStateProviderBox>>>> {
        (*self).evm_for_block(db, header)
    }
}

/// Returns the validators that are `active` in the validator config v2
/// contract, with their p2p addresses. Entries that fail to decode are
/// skipped.
pub(crate) fn read_active_peers(
    config: &ValidatorConfigV2,
) -> eyre::Result<ordered::Map<PublicKey, commonware_p2p::Address>> {
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
    debug!(active_validators = ?all, "read active validators from contract");
    Ok(ordered::Map::try_from_iter(all).expect("hashmaps don't contain duplicates"))
}

/// Reads the validator state at the given block hash.
///
/// Note that `block_hash` must be a block hash of a canonical block.
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

    let state = node.state_by_block_hash(block_hash).wrap_err_with(|| {
        format!("failed to get state from node provider for hash `{block_hash}`")
    })?;
    let res = read_validator_config_with_state(node, state, &header, read_fn)?;
    Ok((header.number(), block_hash, res))
}

/// Reads the validator state from `state`, which must be the post-state of
/// the block with `header`.
pub(crate) fn read_validator_config_with_state<C, T>(
    node: impl ExecutionNode,
    state: EvmStateProviderBox,
    header: &TempoHeader,
    read_fn: impl FnOnce(&C) -> eyre::Result<T>,
) -> eyre::Result<T>
where
    C: Default,
{
    let db = State::builder()
        .with_database(StateProviderDatabase::new(state))
        .build();

    let mut evm = node
        .evm_for_block(db, header)
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
    Ok(res)
}

/// An EVM over a block's post-state, which the election call runs on.
type ConfigEvm = TempoEvm<State<StateProviderDatabase<EvmStateProviderBox>>>;

alloy_sol_types::sol! {
    /// `NVNMStaking.computeCommittee`: the committee as addresses, drawn only from `eligible`, the
    /// registry's addresses. `electionWeight` scores any address as the election ranks it.
    interface IStakingElection {
        function computeCommittee(address[] eligible) external view returns (address[] vals);
        function electionWeight(address[] who) external view returns (uint256[] weights);
    }
}

/// The next epoch's players, read with the election weights proposers are drawn by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NextPlayers {
    pub(crate) players: ordered::Set<PublicKey>,
    /// `Some` once proposers are weighted: the election weight of each `current_players` key the
    /// registry knows, empty when the election is inactive or cannot answer.
    pub(crate) weights: Option<BTreeMap<PublicKey, U256>>,
}

/// The smallest committee the election, or its fallback, may seat (3f+1, f=1).
const MIN_ELECTED_COMMITTEE: usize = 4;

/// The next epoch's players where the genesis names a staking election, read from `state`, the
/// post-state of the block with `header`. Once the election is active: the elected committee,
/// else the `current_players` still registered, else the whole registry; before that, the
/// registry. If `weighted`, the election weights come with them. Each choice is a function of
/// state, so every node makes it; an `Err` is node-local.
#[instrument(skip_all, fields(%staking_election), err(Display))]
pub(crate) fn read_elected_players(
    node: impl ExecutionNode,
    state: EvmStateProviderBox,
    header: &TempoHeader,
    staking_election: Address,
    staking_election_time: Option<u64>,
    weighted: bool,
    current_players: &ordered::Set<PublicKey>,
) -> eyre::Result<NextPlayers> {
    let mut evm = evm_with_state(node, state, header)?;
    let registry = read_registry(&mut evm).wrap_err("failed reading validator config v2")?;

    // The block's time, not the wall clock, so every node flips at the same boundary.
    let active = staking_election_time.is_none_or(|from| header.timestamp() >= from);
    // The players weighed are the ones the output hands the next epoch's shares, whichever
    // committee the election seats for the epoch after.
    let weights = if !weighted {
        None
    } else if active {
        Some(proposer_weights(
            &mut evm,
            staking_election,
            current_players,
        )?)
    } else {
        Some(BTreeMap::new())
    };
    if active {
        if let Some(players) = elected_players(&mut evm, staking_election, &registry)? {
            info!(
                players = players.len(),
                "next committee elected by staking contract"
            );
            return Ok(NextPlayers { players, weights });
        }
        // Not the registry: after a long run, entries outside the committee may be offline.
        if let Some(players) = seated_players(&registry, |validator| {
            current_players.position(validator.public_key()).is_some()
        }) {
            info!(
                players = players.len(),
                "election fell back to the current players"
            );
            return Ok(NextPlayers { players, weights });
        }
    }

    let mut keys = HashSet::new();
    for validator in &registry {
        if !keys.insert(validator.public_key().clone()) {
            warn!(duplicate = %validator.public_key(), "found duplicate public keys");
        }
    }
    info!(
        players = keys.len(),
        active, "next committee is the full registry"
    );
    let players =
        ordered::Set::try_from_iter(keys).expect("a hash set does not contain duplicates");
    Ok(NextPlayers { players, weights })
}

fn evm_with_state(
    node: impl ExecutionNode,
    state: EvmStateProviderBox,
    header: &TempoHeader,
) -> eyre::Result<ConfigEvm> {
    let db = State::builder()
        .with_database(StateProviderDatabase::new(state))
        .build();
    node.evm_for_block(db, header)
        .wrap_err("failed instantiating evm for block")
}

/// Runs a registry read against an already-built EVM.
fn read_config_on_evm<T>(
    evm: &mut ConfigEvm,
    read_fn: impl FnOnce(&ValidatorConfigV2) -> eyre::Result<T>,
) -> eyre::Result<T> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || read_fn(&ValidatorConfigV2::default()),
    )
}

/// The active validator set in contract order, skipping entries that do not decode. Duplicate
/// keys are kept: the election falls back on them.
fn read_registry(evm: &mut ConfigEvm) -> eyre::Result<Vec<DecodedValidatorV2>> {
    read_config_on_evm(evm, |config| {
        let mut registry = Vec::new();
        for (position, raw) in config
            .get_active_validators()
            .wrap_err("failed getting active validator set")?
            .into_iter()
            .enumerate()
        {
            if let Ok(decoded) =
                DecodedValidatorV2::decode_from_contract(raw).inspect_err(|error| {
                    warn!(%error, position, "failed decoding active validator in contract");
                })
            {
                registry.push(decoded);
            }
        }
        Ok(registry)
    })
}

/// The elected committee's consensus keys, or `None` (a function of state) to fall back.
fn elected_players(
    evm: &mut ConfigEvm,
    contract: Address,
    registry: &[DecodedValidatorV2],
) -> eyre::Result<Option<ordered::Set<PublicKey>>> {
    // A codeless address would "succeed" with empty returndata.
    let account = evm
        .db_mut()
        .basic(contract)
        .map_err(|e| eyre::eyre!("failed reading election contract account: {e:?}"))?;
    if account.is_none_or(|account| account.is_empty_code_hash()) {
        warn!(%contract, "election contract has no code; falling back");
        return Ok(None);
    }

    let call = IStakingElection::computeCommitteeCall {
        eligible: registry.iter().map(|v| v.address).collect(),
    };
    let Some(output) = election_call(evm, contract, call.abi_encode())? else {
        return Ok(None);
    };
    let Ok(elected) = IStakingElection::computeCommitteeCall::abi_decode_returns(&output) else {
        warn!(%contract, "failed decoding computeCommittee's return; falling back");
        return Ok(None);
    };
    let named: HashSet<Address> = elected.into_iter().collect();
    let players = seated_players(registry, |validator| named.contains(&validator.address));
    if players.is_none() {
        warn!(%contract, "elected committee below minimum; falling back");
    }
    Ok(players)
}

/// `None` where the registry holds no such validator.
fn registered<T>(looked_up: tempo_precompiles::Result<T>) -> eyre::Result<Option<T>> {
    match looked_up {
        Ok(found) => Ok(Some(found)),
        Err(error) if error == ValidatorConfigV2Error::validator_not_found().into() => Ok(None),
        Err(error) => Err(eyre::Report::new(error)),
    }
}

/// Each of `proposers`' election weight, by key, at the staking address the registry holds for
/// it, deactivated entries included: a rotated key proposes until its successor holds a share,
/// while a key whose address a later entry took, or that lost it, is not weighed.
/// Empty when the contract cannot answer, as one without `electionWeight`; all then draw alike.
fn proposer_weights(
    evm: &mut ConfigEvm,
    contract: Address,
    proposers: &ordered::Set<PublicKey>,
) -> eyre::Result<BTreeMap<PublicKey, U256>> {
    let staked: Vec<(PublicKey, Address)> = read_config_on_evm(evm, |config| {
        let mut staked = Vec::new();
        for key in proposers.iter() {
            let found = config.validator_by_public_key(public_key_to_b256(key));
            let Some(entry) = registered(found)? else {
                continue;
            };
            // A rotation parks the old key on a later snapshot and leaves the address on the
            // original slot; a newcomer taking a deactivated entry's address holds it on a
            // later one. A transfer drops the address, so a snapshot naming it has no holder.
            let Some(holder) = registered(config.validator_by_address(entry.validatorAddress))?
            else {
                continue;
            };
            if holder.index <= entry.index {
                staked.push((key.clone(), entry.validatorAddress));
            }
        }
        Ok(staked)
    })
    .wrap_err("failed reading the proposers' registry entries")?;
    if staked.is_empty() {
        return Ok(BTreeMap::new());
    }

    let call = IStakingElection::electionWeightCall {
        who: staked.iter().map(|(_, address)| *address).collect(),
    };
    let Some(output) = election_call(evm, contract, call.abi_encode())? else {
        return Ok(BTreeMap::new());
    };
    match IStakingElection::electionWeightCall::abi_decode_returns(&output) {
        Ok(weights) if weights.len() == staked.len() => Ok(staked
            .into_iter()
            .map(|(key, _)| key)
            .zip(weights)
            .collect()),
        _ => {
            warn!(%contract, "electionWeight answered badly; every proposer draws alike");
            Ok(BTreeMap::new())
        }
    }
}

/// The election contract's answer to `input`, or `None` when the call fails as every node sees
/// it. A failure this node's alone is an `Err`.
fn election_call(
    evm: &mut ConfigEvm,
    contract: Address,
    input: Vec<u8>,
) -> eyre::Result<Option<Bytes>> {
    // Running out of the system call's 250M gas is a revert too; nvnm-contracts' CommitteeGas
    // puts the worst case at 33M.
    let result = match evm.transact_system_call(Address::ZERO, contract, input.into()) {
        Ok(result) => result,
        // Validation fails alike on every node.
        Err(error @ (EVMError::Transaction(_) | EVMError::Header(_))) => {
            warn!(%contract, ?error, "election call failed validation; falling back");
            return Ok(None);
        }
        // A precompile reports a failed state read, which is this node's alone, as a fatal custom
        // error like any other: stop rather than seat a committee the other nodes don't.
        Err(error) => return Err(eyre::eyre!("election call failed to execute: {error:?}")),
    };
    let ExecutionResult::Success { output, .. } = result.result else {
        warn!(%contract, result = ?result.result, "election call did not succeed; falling back");
        return Ok(None);
    };
    Ok(Some(output.into_data()))
}

/// The registry entries `seat` picks, or `None` below `MIN_ELECTED_COMMITTEE` (capped at the
/// registry's size, so a small chain cannot halt). The set sorts by key: the pick decides who
/// makes the cut, not leader order.
fn seated_players(
    registry: &[DecodedValidatorV2],
    seat: impl Fn(&DecodedValidatorV2) -> bool,
) -> Option<ordered::Set<PublicKey>> {
    let seated: Vec<PublicKey> = registry
        .iter()
        .filter(|validator| seat(validator))
        .map(|validator| validator.public_key().clone())
        .collect();
    let floor = MIN_ELECTED_COMMITTEE.min(registry.len());
    if floor == 0 || seated.len() < floor {
        return None;
    }
    // ValidatorConfigV2 keeps keys unique; if two ever match, falling back is still deterministic.
    ordered::Set::try_from_iter(seated)
        .inspect_err(|error| warn!(%error, "duplicate keys; falling back"))
        .ok()
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
    use alloy_consensus::Header;
    use alloy_primitives::{Bytes, U256};
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use tempo_node::evm::TempoEvmConfig;
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        storage::hashmap::HashMapStorageProvider,
        tip20::tip20_slots,
        validator_config_v2::{VALIDATOR_NS_ADD, VALIDATOR_NS_ROTATE},
    };

    use super::*;
    use crate::utils::public_key_to_b256;

    const ELECTION: Address = Address::repeat_byte(0xE1);

    /// A node whose one block, at timestamp 1, has `provider` as its post-state.
    struct TestExecutionNode {
        provider: MockEthProvider,
    }

    impl TestExecutionNode {
        fn header() -> TempoHeader {
            TempoHeader {
                general_gas_limit: 30_000_000,
                inner: Header {
                    number: 7,
                    timestamp: 1,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            }
        }

        fn state(&self) -> EvmStateProviderBox {
            Box::new(self.provider.clone().into_evm_state_provider())
        }
    }

    impl ExecutionNode for TestExecutionNode {
        fn header(&self, _block_hash: B256) -> eyre::Result<TempoHeader> {
            Ok(Self::header())
        }

        fn state_by_block_hash(&self, _block_hash: B256) -> eyre::Result<EvmStateProviderBox> {
            Ok(self.state())
        }

        fn evm_for_block(
            &self,
            db: State<StateProviderDatabase<EvmStateProviderBox>>,
            header: &TempoHeader,
        ) -> eyre::Result<ConfigEvm> {
            TempoEvmConfig::moderato()
                .evm_for_block(db, header)
                .map_err(eyre::Report::new)
        }
    }

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::from_seed(u64::from(seed))
    }

    /// The registry address of the validator whose key and endpoints derive from `seed`.
    fn address(seed: u8) -> Address {
        Address::repeat_byte(seed)
    }

    fn endpoints(seed: u8) -> (String, String) {
        (
            format!("192.168.1.{seed}:{}", 8000 + u16::from(seed)),
            format!("192.168.1.{seed}"),
        )
    }

    /// What the validator of `seed` signs to enter the registry at `validator_address`.
    fn config(seed: u8, validator_address: Address) -> tempo_validator_config::ValidatorConfig {
        let (ingress, egress) = endpoints(seed);
        tempo_validator_config::ValidatorConfig {
            chain_id: 1,
            validator_address,
            public_key: public_key_to_b256(&key(seed).public_key()),
            ingress: ingress.parse().unwrap(),
            egress: egress.parse().unwrap(),
        }
    }

    fn sign(seed: u8, namespace: &[u8], message: B256) -> Bytes {
        key(seed)
            .sign(namespace, message.as_slice())
            .encode()
            .to_vec()
            .into()
    }

    /// Adds the validator of `seed` at `validator_address`.
    fn add_validator_call(
        seed: u8,
        validator_address: Address,
    ) -> IValidatorConfigV2::addValidatorCall {
        let (ingress, egress) = endpoints(seed);
        let message = config(seed, validator_address).add_validator_message_hash(validator_address);
        IValidatorConfigV2::addValidatorCall {
            validatorAddress: validator_address,
            publicKey: public_key_to_b256(&key(seed).public_key()),
            ingress,
            egress,
            feeRecipient: validator_address,
            signature: sign(seed, VALIDATOR_NS_ADD, message),
        }
    }

    /// Rotates entry `idx` onto the key of `seed`. The signature covers `validator_address`, the
    /// staking address that stays put.
    fn rotate_validator_call(
        seed: u8,
        idx: u64,
        validator_address: Address,
    ) -> IValidatorConfigV2::rotateValidatorCall {
        let (ingress, egress) = endpoints(seed);
        let message = config(seed, validator_address).rotate_validator_message_hash();
        IValidatorConfigV2::rotateValidatorCall {
            idx,
            publicKey: public_key_to_b256(&key(seed).public_key()),
            ingress,
            egress,
            signature: sign(seed, VALIDATOR_NS_ROTATE, message),
        }
    }

    /// The registry's owner on a seeded node.
    const OWNER: Address = Address::repeat_byte(0xAA);

    /// A node whose registry `seed` fills, as [`OWNER`], and whose election contract runs `code`,
    /// if any.
    fn seeded(
        seed: impl FnOnce(&mut ValidatorConfigV2) -> eyre::Result<()>,
        code: Option<Bytes>,
    ) -> TestExecutionNode {
        let mut storage = HashMapStorageProvider::new(1);
        // A deactivation stamps the block number, and at 0 it would read as never.
        storage.set_block_number(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut config = ValidatorConfigV2::new();
            config.initialize(OWNER)?;
            seed(&mut config)
        })
        .expect("seeded registry");

        let mut storage_by_account = HashMap::<Address, Vec<(B256, U256)>>::new();
        for (address, slot, value) in storage.into_storage() {
            storage_by_account
                .entry(address)
                .or_default()
                .push((B256::from(slot), value));
        }
        let provider = MockEthProvider::new();
        for (address, storage) in storage_by_account {
            provider.add_account(
                address,
                ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
            );
        }
        if let Some(code) = code {
            provider.add_account(
                ELECTION,
                ExtendedAccount::new(0, U256::ZERO).with_bytecode(code),
            );
        }
        TestExecutionNode { provider }
    }

    /// A node whose registry holds the validators of `seeds`, in that order, the entries at
    /// `deactivated` deactivated after, and whose election contract runs `code`, if any.
    fn election_among(
        seeds: impl IntoIterator<Item = u8>,
        deactivated: &[u64],
        code: Option<Bytes>,
    ) -> TestExecutionNode {
        seeded(
            |config| {
                for seed in seeds {
                    config.add_validator(OWNER, add_validator_call(seed, address(seed)))?;
                }
                for &idx in deactivated {
                    let call = IValidatorConfigV2::deactivateValidatorCall { idx };
                    config.deactivate_validator(OWNER, call)?;
                }
                Ok(())
            },
            code,
        )
    }

    /// Validators 1 through 6 in the registry.
    fn election(code: Option<Bytes>) -> TestExecutionNode {
        election_among(1..=6, &[], code)
    }

    /// How a mock contract answers a selector.
    enum Answer {
        /// Return these bytes.
        With(Vec<u8>),
        /// Return the call's arguments: an `address[]` argument reads back as the `uint256[]` of
        /// the addresses.
        Echo,
    }

    /// Runtime code answering each selector as given and reverting every other.
    fn answering(answers: &[([u8; 4], Answer)]) -> Bytes {
        // Each dispatch is 16 bytes and the revert 5; the answers' bodies follow.
        let mut start = 16 * answers.len() + 5;
        let (mut code, mut bodies) = (Vec::new(), Vec::new());
        for (selector, answer) in answers {
            code.extend([0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c, 0x63]); // CALLDATALOAD(0) >> 224, PUSH4
            code.extend_from_slice(selector);
            code.extend([0x14, 0x61]); // EQ, PUSH2 the body
            code.extend_from_slice(&(start as u16).to_be_bytes());
            code.push(0x57); // JUMPI
            let body = match answer {
                Answer::Echo => vec![
                    0x5b, // JUMPDEST
                    0x60, 0x04, 0x36, 0x03, 0x80, // size = CALLDATASIZE - 4, twice
                    0x60, 0x04, 0x60, 0x00, 0x37, // CALLDATACOPY(0, 4, size)
                    0x60, 0x00, 0xf3, // RETURN(0, size)
                ],
                Answer::With(blob) => {
                    // CODECOPY the blob from right after this 16-byte stub, then RETURN it.
                    let len = (blob.len() as u16).to_be_bytes();
                    let offset = ((start + 16) as u16).to_be_bytes();
                    let mut body = vec![
                        0x5b, // JUMPDEST
                        0x61, len[0], len[1], // PUSH2 size
                        0x61, offset[0], offset[1], // PUSH2 offset
                        0x60, 0x00, // PUSH1 0
                        0x39, // CODECOPY
                        0x61, len[0], len[1], // PUSH2 size
                        0x60, 0x00, // PUSH1 0
                        0xf3, // RETURN
                    ];
                    body.extend_from_slice(blob);
                    body
                }
            };
            start += body.len();
            bodies.push(body);
        }
        code.extend([0x60, 0x00, 0x60, 0x00, 0xfd]); // REVERT(0, 0)
        code.extend(bodies.concat());
        code.into()
    }

    /// Runtime code that reverts with no data.
    fn reverting() -> Bytes {
        Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd])
    }

    /// `computeCommittee`'s answer: these validators, whoever is eligible.
    fn committee(seeds: &[u8]) -> ([u8; 4], Answer) {
        let elected: Vec<Address> = seeds.iter().map(|&seed| address(seed)).collect();
        (
            IStakingElection::computeCommitteeCall::SELECTOR,
            Answer::With(IStakingElection::computeCommitteeCall::abi_encode_returns(
                &elected,
            )),
        )
    }

    /// Each validator's key, weighed at its staking address read as a number, as the echoing
    /// mock answers.
    fn weighed_at_address(seeds: &[u8]) -> BTreeMap<PublicKey, U256> {
        seeds
            .iter()
            .map(|&seed| {
                (
                    key(seed).public_key(),
                    U256::from_be_slice(address(seed).as_slice()),
                )
            })
            .collect()
    }

    /// The keys of these validators.
    fn keys(seeds: &[u8]) -> ordered::Set<PublicKey> {
        ordered::Set::try_from_iter(seeds.iter().map(|&seed| key(seed).public_key())).unwrap()
    }

    fn elected_at(node: &TestExecutionNode) -> eyre::Result<Option<ordered::Set<PublicKey>>> {
        let mut evm = evm_with_state(node, node.state(), &TestExecutionNode::header())?;
        let registry = read_registry(&mut evm)?;
        elected_players(&mut evm, ELECTION, &registry)
    }

    fn read_next_players(
        node: &TestExecutionNode,
        from: Option<u64>,
        weighted: bool,
        current: &[u8],
    ) -> NextPlayers {
        read_elected_players(
            node,
            node.state(),
            &TestExecutionNode::header(),
            ELECTION,
            from,
            weighted,
            &keys(current),
        )
        .unwrap()
    }

    fn next_players(
        node: &TestExecutionNode,
        from: Option<u64>,
        current: &[u8],
    ) -> ordered::Set<PublicKey> {
        let next = read_next_players(node, from, false, current);
        assert_eq!(next.weights, None);
        next.players
    }

    fn registry(n: u8) -> Vec<DecodedValidatorV2> {
        (0..n)
            .map(|i| DecodedValidatorV2 {
                public_key: key(i).public_key(),
                ingress: SocketAddr::from(([127, 0, 0, 1], 8000)),
                egress: IpAddr::from([127, 0, 0, 1]),
                added_at_height: 0,
                deleted_at_height: 0,
                index: u64::from(i),
                address: address(i + 1),
            })
            .collect()
    }

    /// Picks the registry entries at `addresses`, as the election does.
    fn at(addresses: &[Address]) -> impl Fn(&DecodedValidatorV2) -> bool + '_ {
        move |validator| addresses.contains(&validator.address)
    }

    #[test]
    fn small_registry_lowers_the_minimum() {
        // A 2-validator devnet: electing both is enough; electing one is not.
        let reg = registry(2);
        let both: Vec<Address> = reg.iter().map(|v| v.address).collect();
        assert_eq!(seated_players(&reg, at(&both)).unwrap().len(), 2);
        assert!(seated_players(&reg, at(&both[..1])).is_none());
    }

    #[test]
    fn unknown_elected_addresses_are_ignored() {
        let reg = registry(5);
        let mut elected: Vec<Address> = reg[..4].iter().map(|v| v.address).collect();
        elected.push(Address::repeat_byte(0xEE)); // not in the registry
        assert_eq!(seated_players(&reg, at(&elected)).unwrap().len(), 4);
    }

    #[test]
    fn empty_registry_falls_back() {
        assert!(seated_players(&[], at(&[Address::repeat_byte(1)])).is_none());
    }

    #[test]
    fn an_election_that_cannot_answer_falls_back() {
        let garbage = answering(&[(
            IStakingElection::computeCommitteeCall::SELECTOR,
            Answer::With(vec![0x01]),
        )]);
        for code in [None, Some(reverting()), Some(garbage)] {
            assert_eq!(elected_at(&election(code)).unwrap(), None);
        }
    }

    #[test]
    fn an_elected_committee_is_seated_from_the_floor_up() {
        let seated = elected_at(&election(Some(answering(&[committee(&[1, 2, 3, 4])])))).unwrap();
        assert_eq!(seated, Some(keys(&[1, 2, 3, 4])));
        assert_eq!(
            elected_at(&election(Some(answering(&[committee(&[1, 2, 3])])))).unwrap(),
            None
        );
    }

    #[test]
    fn the_election_is_passed_the_registry_in_order() {
        // Seats the first four of `eligible`: echoes the calldata's array, its length cut to 4.
        let code = Bytes::from_static(&[
            0x60, 0x04, 0x36, 0x03, // CALLDATASIZE - 4
            0x60, 0x04, 0x60, 0x00, 0x37, // CALLDATACOPY(0, 4, size)
            0x60, 0x04, 0x60, 0x20, 0x52, // MSTORE(0x20, 4)
            0x60, 0xc0, 0x60, 0x00, 0xf3, // RETURN(0, 0xc0)
        ]);
        // Registered in reverse, so registry order differs from address order.
        let node = election_among((1..=6).rev(), &[], Some(code));
        assert_eq!(elected_at(&node).unwrap(), Some(keys(&[6, 5, 4, 3])));
    }

    #[test]
    fn a_fatal_precompile_error_in_the_election_stops_the_node() {
        // STATICCALL name() on a token whose stored name claims 32 bytes in short form.
        let mut code = vec![0x63, 0x06, 0xfd, 0xde, 0x03, 0x60, 0x00, 0x52]; // MSTORE selector
        code.extend([0x60, 0x00, 0x60, 0x00, 0x60, 0x04, 0x60, 0x1c, 0x73]); // sizes, PUSH20
        code.extend_from_slice(PATH_USD_ADDRESS.as_slice());
        code.extend([0x5a, 0xfa, 0x00]); // GAS, STATICCALL, STOP
        let node = election(Some(code.into()));
        node.provider.add_account(
            PATH_USD_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO)
                .with_bytecode(Bytes::from_static(&[0xef]))
                .extend_storage([(B256::from(tip20_slots::NAME), U256::from(64))]),
        );

        let mut evm = evm_with_state(&node, node.state(), &TestExecutionNode::header()).unwrap();
        let call = evm.transact_system_call(Address::ZERO, ELECTION, Bytes::new());
        assert!(matches!(call, Err(EVMError::Custom(_))), "{call:?}");
        assert!(elected_at(&node).is_err());
    }

    #[test]
    fn the_election_takes_effect_at_its_activation_time() {
        let node = election(Some(answering(&[committee(&[1, 2, 3, 4])])));
        // The mock header sits at timestamp 1.
        for from in [None, Some(1)] {
            assert_eq!(next_players(&node, from, &[]), keys(&[1, 2, 3, 4]));
        }
        assert_eq!(next_players(&node, Some(2), &[]), keys(&[1, 2, 3, 4, 5, 6]));
    }

    /// The weighed are the keys holding the next epoch's shares, not the committee seated for the
    /// epoch after: one the election has dropped keeps its score, and a deactivated entry, as a
    /// rotated key leaves behind, still names its staking address. A key the registry never
    /// held is not weighed.
    #[test]
    fn weighted_proposers_are_weighed_at_their_staking_addresses() {
        let code = answering(&[
            committee(&[1, 2, 3, 4]),
            (IStakingElection::electionWeightCall::SELECTOR, Answer::Echo),
        ]);
        // Entry 5, validator 6, is deactivated.
        let node = election_among(1..=6, &[5], Some(code));
        let next = read_next_players(&node, None, true, &[1, 2, 5, 6, 9]);
        assert_eq!(next.players, keys(&[1, 2, 3, 4]));
        assert_eq!(next.weights, Some(weighed_at_address(&[1, 2, 5, 6])));
    }

    /// Validators 1 through 6 in the registry, `then` applied to it, and an election echoing
    /// each address.
    fn after_six_validators(
        then: impl FnOnce(&mut ValidatorConfigV2) -> eyre::Result<()>,
    ) -> TestExecutionNode {
        let code = answering(&[
            committee(&[1, 2, 3, 4]),
            (IStakingElection::electionWeightCall::SELECTOR, Answer::Echo),
        ]);
        seeded(
            |config| {
                for seed in 1..=6 {
                    config.add_validator(OWNER, add_validator_call(seed, address(seed)))?;
                }
                then(config)
            },
            Some(code),
        )
    }

    /// A deactivated entry keeps its staking address, which the registry lets a newcomer take:
    /// the old key, a player until the epoch ends, must not draw by the newcomer's score.
    #[test]
    fn a_key_whose_address_was_taken_over_is_not_weighed() {
        // Validator 7's key at validator 6's address, once entry 5, validator 6, is deactivated.
        let node = after_six_validators(|config| {
            let deactivate = IValidatorConfigV2::deactivateValidatorCall { idx: 5 };
            config.deactivate_validator(OWNER, deactivate)?;
            config.add_validator(OWNER, add_validator_call(7, address(6)))?;
            Ok(())
        });

        let next = read_next_players(&node, None, true, &[1, 6, 7]);
        let mut expected = weighed_at_address(&[1]);
        expected.insert(
            key(7).public_key(),
            U256::from_be_slice(address(6).as_slice()),
        );
        assert_eq!(
            next.weights,
            Some(expected),
            "validator 6 draws alike, validator 7 by that address"
        );
    }

    /// Rotation keeps the staking address on the original slot and parks the old key on a later
    /// snapshot. That key still proposes this epoch, so it keeps the address's score.
    #[test]
    fn a_rotated_key_keeps_its_address_score() {
        let node = after_six_validators(|config| {
            config.rotate_validator(OWNER, rotate_validator_call(7, 5, address(6)))?;
            Ok(())
        });

        // The successor's key holds no share yet, so only the old key is weighed.
        let next = read_next_players(&node, None, true, &[1, 6]);
        assert_eq!(next.weights, Some(weighed_at_address(&[1, 6])));
    }

    /// An ownership transfer deletes the old address's lookup, while a snapshot a rotation left
    /// behind still names it: that key draws alike, and the boundary goes on.
    #[test]
    fn a_key_whose_address_was_transferred_away_is_not_weighed() {
        let moved_to = Address::repeat_byte(0xAB);
        let node = after_six_validators(|config| {
            config.rotate_validator(OWNER, rotate_validator_call(7, 5, address(6)))?;
            let transfer = IValidatorConfigV2::transferValidatorOwnershipCall {
                idx: 5,
                newAddress: moved_to,
            };
            config.transfer_validator_ownership(OWNER, transfer)?;
            Ok(())
        });

        let next = read_next_players(&node, None, true, &[1, 6, 7]);
        let mut expected = weighed_at_address(&[1]);
        expected.insert(
            key(7).public_key(),
            U256::from_be_slice(moved_to.as_slice()),
        );
        assert_eq!(
            next.weights,
            Some(expected),
            "validator 6 draws alike, validator 7 at the new address"
        );
    }

    #[test]
    fn weighted_proposers_fall_back_to_no_weights() {
        // Fewer weights than proposers: every proposer alike.
        let short = answering(&[(
            IStakingElection::electionWeightCall::SELECTOR,
            Answer::With(IStakingElection::electionWeightCall::abi_encode_returns(
                &vec![U256::from(1)],
            )),
        )]);
        // A reverting contract, then an election not yet active.
        for (code, from) in [
            (Some(short), None),
            (Some(reverting()), None),
            (None, Some(2)),
        ] {
            let next = read_next_players(&election(code), from, true, &[1, 2, 3, 4]);
            assert_eq!(next.weights, Some(BTreeMap::new()));
        }
    }

    /// An older staking contract has only `computeCommittee`: it still seats its committee, and
    /// every proposer draws alike.
    #[test]
    fn a_contract_without_election_weight_still_elects() {
        let node = election(Some(answering(&[committee(&[1, 2, 3, 4])])));
        let next = read_next_players(&node, None, true, &[1, 2, 3, 4]);
        assert_eq!(next.players, keys(&[1, 2, 3, 4]));
        assert_eq!(next.weights, Some(BTreeMap::new()));
    }

    #[test]
    fn a_fallback_keeps_the_current_players_still_registered() {
        let node = election(Some(reverting()));
        let kept = next_players(&node, None, &[1, 2, 3, 4, 5, 9]);
        assert_eq!(kept, keys(&[1, 2, 3, 4, 5]));
        // Below the floor, the whole registry.
        let all = next_players(&node, None, &[1, 2, 3, 9]);
        assert_eq!(all, keys(&[1, 2, 3, 4, 5, 6]));
    }
}
