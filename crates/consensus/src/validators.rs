use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use alloy_consensus::BlockHeader;
use alloy_evm::Evm as _;
use alloy_primitives::{Address, B256};
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
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2},
};
use tempo_primitives::TempoHeader;

use tracing::{Level, debug, info, instrument, warn};

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
    /// `NVNMStaking.computeCommittee`: the committee as addresses (the engine is unit-weighted),
    /// drawn only from `eligible`, the registry's addresses.
    interface IStakingElection {
        function computeCommittee(address[] eligible) external view returns (address[] vals);
    }
}

/// The smallest committee the election, or its fallback, may seat (3f+1, f=1).
const MIN_ELECTED_COMMITTEE: usize = 4;

/// The next epoch's players where the genesis names a staking election, read from `state`, the
/// post-state of the block with `header`. Once the election is active: the elected committee,
/// else the `current_players` still registered, else the whole registry; before that, the
/// registry. Each choice is a function of state, so every node makes it; an `Err` is node-local.
#[instrument(skip_all, fields(%staking_election), err(Display))]
pub(crate) fn read_elected_players(
    node: impl ExecutionNode,
    state: EvmStateProviderBox,
    header: &TempoHeader,
    staking_election: Address,
    staking_election_time: Option<u64>,
    current_players: &ordered::Set<PublicKey>,
) -> eyre::Result<ordered::Set<PublicKey>> {
    let mut evm = evm_with_state(node, state, header)?;
    let registry = read_registry(&mut evm).wrap_err("failed reading validator config v2")?;

    // The block's time, not the wall clock, so every node flips at the same boundary.
    let active = staking_election_time.is_none_or(|from| header.timestamp() >= from);
    if active {
        if let Some(players) = elected_players(&mut evm, staking_election, &registry)? {
            info!(
                players = players.len(),
                "next committee elected by staking contract"
            );
            return Ok(players);
        }
        // Not the registry: after a long run, entries outside the committee may be offline.
        if let Some(players) = seated_players(&registry, |validator| {
            current_players.position(validator.public_key()).is_some()
        }) {
            info!(
                players = players.len(),
                "election fell back to the current players"
            );
            return Ok(players);
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
    Ok(ordered::Set::try_from_iter(keys).expect("a hash set does not contain duplicates"))
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

/// The active validator set in contract order, skipping entries that do not decode. Duplicate
/// keys are kept: the election falls back on them.
fn read_registry(evm: &mut ConfigEvm) -> eyre::Result<Vec<DecodedValidatorV2>> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || {
            let mut registry = Vec::new();
            for raw in ValidatorConfigV2::default()
                .get_active_validators()
                .wrap_err("failed getting active validator set")?
            {
                if let Ok(decoded) = DecodedValidatorV2::decode_from_contract(raw) {
                    registry.push(decoded);
                }
            }
            Ok(registry)
        },
    )
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

    // Running out of the system call's 250M gas is a revert too; nvnm-contracts' CommitteeGas
    // puts the worst case at 33M.
    let call = IStakingElection::computeCommitteeCall {
        eligible: registry.iter().map(|v| v.address).collect(),
    };
    let result = match evm.transact_system_call(Address::ZERO, contract, call.abi_encode().into()) {
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
    let Ok(elected) = IStakingElection::computeCommitteeCall::abi_decode_returns(output.data())
    else {
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
        PATH_USD_ADDRESS, storage::hashmap::HashMapStorageProvider, tip20::tip20_slots,
        validator_config_v2::VALIDATOR_NS_ADD,
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

    fn add_validator_call(seed: u8) -> IValidatorConfigV2::addValidatorCall {
        let ingress = format!("192.168.1.{seed}:{}", 8000 + u16::from(seed));
        let egress = format!("192.168.1.{seed}");
        let public_key = public_key_to_b256(&key(seed).public_key());
        let message = tempo_validator_config::ValidatorConfig {
            chain_id: 1,
            validator_address: address(seed),
            public_key,
            ingress: ingress.parse().unwrap(),
            egress: egress.parse().unwrap(),
        }
        .add_validator_message_hash(address(seed));
        IValidatorConfigV2::addValidatorCall {
            validatorAddress: address(seed),
            publicKey: public_key,
            ingress,
            egress,
            feeRecipient: address(seed),
            signature: key(seed)
                .sign(VALIDATOR_NS_ADD, message.as_slice())
                .encode()
                .to_vec()
                .into(),
        }
    }

    /// A node whose registry holds the validators of `seeds`, in that order, and whose election
    /// contract runs `code`, if any.
    fn election_among(
        seeds: impl IntoIterator<Item = u8>,
        code: Option<Bytes>,
    ) -> TestExecutionNode {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xAA);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut config = ValidatorConfigV2::new();
            config.initialize(owner)?;
            for seed in seeds {
                config.add_validator(owner, add_validator_call(seed))?;
            }
            Ok(())
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

    /// Validators 1 through 6 in the registry.
    fn election(code: Option<Bytes>) -> TestExecutionNode {
        election_among(1..=6, code)
    }

    /// Runtime code that returns `blob` verbatim: CODECOPY it from the code's tail, then RETURN.
    fn returning(blob: &[u8]) -> Bytes {
        let len = (blob.len() as u16).to_be_bytes();
        let mut code = vec![
            0x61, len[0], len[1], // PUSH2 size
            0x80,   // DUP1
            0x38,   // CODESIZE
            0x03,   // SUB: the tail's offset
            0x60, 0x00, // PUSH1 0 (destOffset)
            0x39, // CODECOPY
            0x61, len[0], len[1], // PUSH2 size
            0x60, 0x00, // PUSH1 0 (offset)
            0xf3, // RETURN
        ];
        code.extend_from_slice(blob);
        code.into()
    }

    /// Runtime code that reverts with no data.
    fn reverting() -> Bytes {
        Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd])
    }

    /// Runtime code whose `computeCommittee` returns these validators, whoever is eligible.
    fn electing(seeds: &[u8]) -> Bytes {
        let addresses: Vec<Address> = seeds.iter().map(|&seed| address(seed)).collect();
        returning(&IStakingElection::computeCommitteeCall::abi_encode_returns(
            &addresses,
        ))
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

    fn next_players(
        node: &TestExecutionNode,
        from: Option<u64>,
        current: &[u8],
    ) -> ordered::Set<PublicKey> {
        read_elected_players(
            node,
            node.state(),
            &TestExecutionNode::header(),
            ELECTION,
            from,
            &keys(current),
        )
        .unwrap()
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
        for code in [None, Some(reverting()), Some(returning(&[0x01]))] {
            assert_eq!(elected_at(&election(code)).unwrap(), None);
        }
    }

    #[test]
    fn an_elected_committee_is_seated_from_the_floor_up() {
        let seated = elected_at(&election(Some(electing(&[1, 2, 3, 4])))).unwrap();
        assert_eq!(seated, Some(keys(&[1, 2, 3, 4])));
        assert_eq!(
            elected_at(&election(Some(electing(&[1, 2, 3])))).unwrap(),
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
        let node = election_among((1..=6).rev(), Some(code));
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
        let node = election(Some(electing(&[1, 2, 3, 4])));
        // The mock header sits at timestamp 1.
        for from in [None, Some(1)] {
            assert_eq!(next_players(&node, from, &[]), keys(&[1, 2, 3, 4]));
        }
        assert_eq!(next_players(&node, Some(2), &[]), keys(&[1, 2, 3, 4, 5, 6]));
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
