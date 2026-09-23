use std::{
    collections::HashSet,
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
    Database as _, State, context::result::ExecutionResult, database::StateProviderDatabase,
};
use reth_node_builder::ConfigureEvm as _;
use reth_provider::{BlockReader as _, BlockSource, StateProviderBox, StateProviderFactory as _};
use tempo_node::{TempoFullNode, evm::evm::TempoEvm};
use tempo_precompiles::{
    storage::{StorageActions, StorageCtx},
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2},
};
use tempo_primitives::TempoHeader;

use tracing::{Level, debug, info, instrument, warn};

/// Historical state, as the reads below query it.
type ConfigDb = State<StateProviderDatabase<StateProviderBox>>;

/// An EVM built over [`ConfigDb`], which both the config reads and the election call run on.
type ConfigEvm = TempoEvm<ConfigDb>;

/// Minimal execution-node interface needed to read validator config state.
///
/// Production code uses [`TempoFullNode`]. This trait exists so unit tests can
/// use a mock that only provides a historical state provider and an EVM
/// configured for the corresponding block, while still exercising the same
/// validator config reader used in production.
pub(crate) trait ExecutionNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader>;

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox>;

    fn evm_for_block(&self, db: ConfigDb, header: &TempoHeader) -> eyre::Result<ConfigEvm>;
}

impl ExecutionNode for TempoFullNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        // DKG may read a proposal parent's validator state before its FCU makes the block canonical.
        self.provider
            .find_sealed_or_recovered_block(block_hash, BlockSource::Any)
            .map_err(eyre::Report::new)
            .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty block"))
            .map(|block| block.clone_sealed_header().unseal())
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
        self.provider
            .state_by_block_hash(block_hash)
            .map_err(eyre::Report::new)
    }

    fn evm_for_block(&self, db: ConfigDb, header: &TempoHeader) -> eyre::Result<ConfigEvm> {
        self.evm_config
            .evm_for_block(db, header)
            .map_err(eyre::Report::new)
    }
}

/// Builds an EVM over the state at `block_hash`, with that block's header.
fn evm_at_block_hash(
    node: &impl ExecutionNode,
    block_hash: B256,
) -> eyre::Result<(TempoHeader, ConfigEvm)> {
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
    node: &impl ExecutionNode,
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
    evm: &mut ConfigEvm,
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

/// The active validator set in contract order, skipping entries that do not decode.
///
/// Duplicate keys are kept, because each caller answers them differently: the p2p map dedups,
/// the election falls back.
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

/// The next epoch's players at `block_hash`: the elected committee within the registry, or the
/// full registry. Fallbacks follow from state, so every node takes them; an `Err` is node-local
/// and propagates, since a fallback one node alone took would split the validator set.
#[instrument(skip_all, fields(%block_hash), err(Display))]
pub(crate) fn next_players_at_block_hash(
    node: &impl ExecutionNode,
    block_hash: B256,
    staking_election: Option<Address>,
    staking_election_time: Option<u64>,
) -> eyre::Result<ordered::Set<PublicKey>> {
    let (header, mut evm) = evm_at_block_hash(node, block_hash)?;

    let registry = read_config_on_evm(&mut evm, decoded_active_validators)
        .wrap_err("failed reading validator config v2")?;

    // The block's time, not the wall clock, so every node flips at the same boundary.
    let active = staking_election_time.is_none_or(|from| header.timestamp() >= from);
    if let Some(contract) = staking_election
        && active
        && let Some(players) = elected_players(&mut evm, contract, &registry)?
    {
        info!(%contract, players = players.len(), "next committee elected by staking contract");
        return Ok(players);
    }

    let next_players = registry_players(&registry);
    // With an election configured, falling back is worth saying at the level operators read.
    if staking_election.is_some() {
        info!(
            players = next_players.len(),
            active, "next committee is the full registry, not the election"
        );
    } else {
        debug!(?next_players, "determined next players from full registry");
    }
    Ok(next_players)
}

/// The registry's consensus keys, deduplicated — the set every fallback lands on.
fn registry_players(registry: &[DecodedValidatorV2]) -> ordered::Set<PublicKey> {
    let mut keys = HashSet::new();
    for validator in registry {
        if !keys.insert(validator.public_key().clone()) {
            warn!(duplicate = %validator.public_key(), "found duplicate public keys");
        }
    }
    ordered::Set::try_from_iter(keys).expect("a hash set does not contain duplicates")
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

    // The system call's 250M gas limit makes a revert state too; MAX_CANDIDATES = 256 keeps the
    // worst case at 22.5M (nvnm-contracts' CommitteeGas).
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
        warn!(%contract, result = ?result.result, "election call did not succeed; falling back");
        return Ok(None);
    };
    let Ok(elected) = IStakingElection::computeCommitteeCall::abi_decode_returns(output.data())
    else {
        warn!(%contract, "failed decoding computeCommittee(); falling back");
        return Ok(None);
    };

    let Some(players) = seated_players(registry, &elected) else {
        warn!(
            elected = elected.len(),
            registry = registry.len(),
            "elected committee below minimum; falling back"
        );
        return Ok(None);
    };

    // Unreachable while ValidatorConfigV2 enforces key uniqueness, but deterministic if reached.
    match ordered::Set::try_from_iter(players) {
        Ok(set) => Ok(Some(set)),
        Err(error) => {
            warn!(%error, "elected committee has duplicate keys; falling back");
            Ok(None)
        }
    }
}

/// The registry entries the election named, or `None` below `MIN_ELECTED_COMMITTEE` (capped at
/// the registry's size, so a small chain cannot halt). `ordered::Set` then sorts by key: the
/// contract's ranking decides only who makes the cut, not leader order.
fn seated_players(registry: &[DecodedValidatorV2], elected: &[Address]) -> Option<Vec<PublicKey>> {
    let elected: HashSet<&Address> = elected.iter().collect();
    let seated: Vec<PublicKey> = registry
        .iter()
        .filter(|validator| elected.contains(&validator.address()))
        .map(|validator| validator.public_key().clone())
        .collect();
    let floor = MIN_ELECTED_COMMITTEE.min(registry.len());
    (floor > 0 && seated.len() >= floor).then_some(seated)
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
pub(crate) mod testing {
    //! A mock execution node over `MockEthProvider`, seeded with real ValidatorConfigV2 storage
    //! and whatever other accounts a test plants — shared by the peer-manager and election tests.

    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use alloy_consensus::Header;
    use alloy_primitives::{Address, B256, Bytes, Keccak256, U256};
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use tempo_node::evm::TempoEvmConfig;
    use tempo_precompiles::{
        VALIDATOR_CONFIG_V2_ADDRESS,
        storage::hashmap::HashMapStorageProvider,
        validator_config_v2::{IValidatorConfigV2, VALIDATOR_NS_ADD},
    };

    use super::*;
    use crate::utils::public_key_to_b256;

    pub(crate) struct TestExecutionNode {
        pub(crate) hash: B256,
        pub(crate) height: u64,
        pub(crate) provider: MockEthProvider,
    }

    impl ExecutionNode for TestExecutionNode {
        fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
            assert_eq!(block_hash, self.hash);
            Ok(TempoHeader {
                general_gas_limit: 30_000_000,
                inner: Header {
                    number: self.height,
                    timestamp: 1,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            })
        }

        fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
            assert_eq!(block_hash, self.hash);
            Ok(Box::new(self.provider.clone()))
        }

        fn evm_for_block(&self, db: ConfigDb, header: &TempoHeader) -> eyre::Result<ConfigEvm> {
            TempoEvmConfig::moderato()
                .evm_for_block(db, header)
                .map_err(eyre::Report::new)
        }
    }

    pub(crate) struct ValidatorFixture {
        pub(crate) private_key: PrivateKey,
        pub(crate) public_key: PublicKey,
        pub(crate) validator_address: Address,
        pub(crate) ingress: String,
        pub(crate) egress: String,
        pub(crate) p2p_address: commonware_p2p::Address,
    }

    /// A validator whose keys and addresses all derive from `seed`.
    pub(crate) fn peer(seed: u8) -> ValidatorFixture {
        let private_key = PrivateKey::from_seed(u64::from(seed));
        let public_key = private_key.public_key();
        let validator_address = Address::from([seed; 20]);
        let egress_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, seed));
        let ingress_socket = SocketAddr::new(egress_ip, 8000 + u16::from(seed));
        let p2p_address = commonware_p2p::Address::Asymmetric {
            ingress: Ingress::Socket(ingress_socket),
            egress: SocketAddr::new(egress_ip, 0),
        };

        ValidatorFixture {
            private_key,
            public_key,
            validator_address,
            ingress: ingress_socket.to_string(),
            egress: egress_ip.to_string(),
            p2p_address,
        }
    }

    impl ValidatorFixture {
        fn add_validator_call(&self) -> IValidatorConfigV2::addValidatorCall {
            let mut hasher = Keccak256::new();
            hasher.update(1u64.to_be_bytes());
            hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
            hasher.update(self.validator_address.as_slice());
            hasher.update([self.ingress.len() as u8]);
            hasher.update(self.ingress.as_bytes());
            hasher.update([self.egress.len() as u8]);
            hasher.update(self.egress.as_bytes());
            hasher.update(self.validator_address.as_slice());
            let message = hasher.finalize();
            let signature = self
                .private_key
                .sign(VALIDATOR_NS_ADD, message.as_slice())
                .encode()
                .to_vec();

            IValidatorConfigV2::addValidatorCall {
                validatorAddress: self.validator_address,
                publicKey: public_key_to_b256(&self.public_key),
                ingress: self.ingress.clone(),
                egress: self.egress.clone(),
                feeRecipient: self.validator_address,
                signature: signature.into(),
            }
        }
    }

    /// An execution node whose ValidatorConfigV2 holds `validators`, plus `contracts` planted
    /// as runtime code at their addresses.
    pub(crate) fn execution_with(
        validators: &[ValidatorFixture],
        contracts: &[(Address, Bytes)],
    ) -> eyre::Result<TestExecutionNode> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0xAA; 20]);

        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut config = ValidatorConfigV2::new();
            config.initialize(owner)?;
            for validator in validators {
                config.add_validator(owner, validator.add_validator_call())?;
            }
            Ok(())
        })?;

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
        for (address, code) in contracts {
            provider.add_account(
                *address,
                ExtendedAccount::new(0, U256::ZERO).with_bytecode(code.clone()),
            );
        }

        Ok(TestExecutionNode {
            hash: B256::from([0x42; 32]),
            height: 7,
            provider,
        })
    }

    /// Runtime code that returns `blob` verbatim: CODECOPY it out of the tail, then RETURN.
    pub(crate) fn returning(blob: &[u8]) -> Bytes {
        const HEADER: usize = 15;
        let len = (blob.len() as u16).to_be_bytes();
        let offset = (HEADER as u16).to_be_bytes();
        let mut code = vec![
            0x61, len[0], len[1], // PUSH2 size
            0x61, offset[0], offset[1], // PUSH2 offset
            0x60, 0x00, // PUSH1 0 (destOffset)
            0x39, // CODECOPY
            0x61, len[0], len[1], // PUSH2 size
            0x60, 0x00, // PUSH1 0 (offset)
            0xf3, // RETURN
        ];
        assert_eq!(code.len(), HEADER);
        code.extend_from_slice(blob);
        code.into()
    }

    /// Runtime code that reverts with no data.
    pub(crate) fn reverting() -> Bytes {
        Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd])
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::{
        testing::{ValidatorFixture, execution_with, peer, returning, reverting},
        *,
    };

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
        let players = seated_players(&reg, &elected).expect("meets minimum");
        assert_eq!(players.len(), 4);
        assert!(players.iter().eq(reg[..4].iter().map(|v| v.public_key())));
    }

    #[test]
    fn committee_below_minimum_falls_back() {
        let reg = registry(6);
        let elected: Vec<Address> = reg[..3].iter().map(|v| v.address()).collect();
        assert!(seated_players(&reg, &elected).is_none());
    }

    #[test]
    fn small_registry_lowers_the_minimum() {
        // A 2-validator devnet: electing both is enough; electing one is not.
        let reg = registry(2);
        let both: Vec<Address> = reg.iter().map(|v| v.address()).collect();
        assert_eq!(seated_players(&reg, &both).unwrap().len(), 2);
        assert!(seated_players(&reg, &both[..1]).is_none());
    }

    #[test]
    fn unknown_elected_addresses_are_ignored() {
        let reg = registry(5);
        let mut elected: Vec<Address> = reg[..4].iter().map(|v| v.address()).collect();
        elected.push(Address::repeat_byte(0xEE)); // not in the registry
        assert_eq!(seated_players(&reg, &elected).unwrap().len(), 4);
    }

    #[test]
    fn empty_registry_falls_back() {
        assert!(seated_players(&[], &[Address::repeat_byte(1)]).is_none());
    }

    // -- the election, end to end over a mock execution node -------------------------------

    const ELECTION: Address = Address::repeat_byte(0xE1);

    /// Six validators in the registry, and an election contract running `code` — or no
    /// contract at all.
    fn election(code: Option<Bytes>) -> (testing::TestExecutionNode, Vec<ValidatorFixture>) {
        let validators: Vec<_> = (1..=6).map(peer).collect();
        let contracts: Vec<_> = code.into_iter().map(|c| (ELECTION, c)).collect();
        let node = execution_with(&validators, &contracts).expect("seeded execution node");
        (node, validators)
    }

    /// Runtime code whose `computeCommittee()` returns exactly `elected`.
    fn electing(elected: &[&ValidatorFixture]) -> Bytes {
        let addresses: Vec<Address> = elected.iter().map(|v| v.validator_address).collect();
        returning(&IStakingElection::computeCommitteeCall::abi_encode_returns(
            &addresses,
        ))
    }

    fn elected_at(node: &testing::TestExecutionNode) -> Option<ordered::Set<PublicKey>> {
        let (_, mut evm) = evm_at_block_hash(node, node.hash).expect("evm");
        let registry = read_config_on_evm(&mut evm, decoded_active_validators).expect("registry");
        elected_players(&mut evm, ELECTION, &registry).expect("no node-local failure")
    }

    fn keys(validators: &[&ValidatorFixture]) -> ordered::Set<PublicKey> {
        ordered::Set::try_from_iter(validators.iter().map(|v| v.public_key.clone())).unwrap()
    }

    #[test]
    fn no_code_at_the_election_address_falls_back() {
        let (node, _) = election(None);
        assert_eq!(elected_at(&node), None);
    }

    #[test]
    fn a_reverting_election_falls_back() {
        let (node, _) = election(Some(reverting()));
        assert_eq!(elected_at(&node), None);
    }

    #[test]
    fn an_undecodable_election_return_falls_back() {
        let (node, _) = election(Some(returning(&[0x01])));
        assert_eq!(elected_at(&node), None);
    }

    #[test]
    fn an_elected_committee_is_seated() {
        let seats: Vec<_> = (1..=4).map(peer).collect();
        let seats: Vec<&ValidatorFixture> = seats.iter().collect();
        let (node, _) = election(Some(electing(&seats)));
        assert_eq!(elected_at(&node), Some(keys(&seats)));
    }

    #[test]
    fn a_committee_below_the_floor_falls_back() {
        let few: Vec<_> = (1..=3).map(peer).collect();
        let few: Vec<&ValidatorFixture> = few.iter().collect();
        let (node, _) = election(Some(electing(&few)));
        assert_eq!(elected_at(&node), None);
    }

    #[test]
    fn next_players_is_the_full_registry_without_an_election() {
        let (node, validators) = election(None);
        let all: Vec<&ValidatorFixture> = validators.iter().collect();
        let players = next_players_at_block_hash(&node, node.hash, None, None).unwrap();
        assert_eq!(players, keys(&all));
    }

    #[test]
    fn next_players_is_the_committee_once_the_election_is_active() {
        let seats: Vec<_> = (1..=4).map(peer).collect();
        let seats: Vec<&ValidatorFixture> = seats.iter().collect();
        let (node, _) = election(Some(electing(&seats)));
        // The mock header sits at timestamp 1: an activation at 1 is live, at 2 is not yet.
        let live = next_players_at_block_hash(&node, node.hash, Some(ELECTION), Some(1)).unwrap();
        assert_eq!(live, keys(&seats));
    }

    #[test]
    fn next_players_ignores_the_election_before_its_activation_time() {
        let seats: Vec<_> = (1..=4).map(peer).collect();
        let seats: Vec<&ValidatorFixture> = seats.iter().collect();
        let (node, validators) = election(Some(electing(&seats)));
        let all: Vec<&ValidatorFixture> = validators.iter().collect();
        let early = next_players_at_block_hash(&node, node.hash, Some(ELECTION), Some(2)).unwrap();
        assert_eq!(early, keys(&all));
    }

    #[test]
    fn an_election_without_an_activation_time_is_live_from_genesis() {
        let seats: Vec<_> = (1..=4).map(peer).collect();
        let seats: Vec<&ValidatorFixture> = seats.iter().collect();
        let (node, _) = election(Some(electing(&seats)));
        let players = next_players_at_block_hash(&node, node.hash, Some(ELECTION), None).unwrap();
        assert_eq!(players, keys(&seats));
    }
}
