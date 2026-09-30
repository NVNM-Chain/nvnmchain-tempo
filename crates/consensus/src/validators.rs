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
    Database as _, State,
    context::result::{EVMError, ExecutionResult},
    database::StateProviderDatabase,
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
    /// `NVNMStaking.computeCommittee`: the committee as addresses (the engine is unit-weighted),
    /// drawn only from `eligible`, the registry's addresses.
    interface IStakingElection {
        function computeCommittee(address[] eligible) external view returns (address[] vals);
    }
}

/// The smallest committee the election, or its fallback, may seat (3f+1, f=1).
const MIN_ELECTED_COMMITTEE: usize = 4;

/// The next epoch's players at `block_hash`. With an active election: the elected committee, else
/// the `current_players` still registered, else the whole registry; without one, the registry.
/// Each choice is a function of state, so every node makes it; an `Err` is node-local.
#[instrument(skip_all, fields(%block_hash), err(Display))]
pub(crate) fn next_players_at_block_hash(
    node: &impl ExecutionNode,
    block_hash: B256,
    staking_election: Option<Address>,
    staking_election_time: Option<u64>,
    current_players: &ordered::Set<PublicKey>,
) -> eyre::Result<ordered::Set<PublicKey>> {
    let (header, mut evm) = evm_at_block_hash(node, block_hash)?;
    let registry = read_config_on_evm(&mut evm, decoded_active_validators)
        .wrap_err("failed reading validator config v2")?;

    // The block's time, not the wall clock, so every node flips at the same boundary.
    let active = staking_election_time.is_none_or(|from| header.timestamp() >= from);
    if let Some(contract) = staking_election
        && active
    {
        if let Some(players) = elected_players(&mut evm, contract, &registry)? {
            info!(%contract, players = players.len(), "next committee elected by staking contract");
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

    let next_players = registry_players(&registry);
    if staking_election.is_some() {
        info!(
            players = next_players.len(),
            active, "next committee is the full registry"
        );
    } else {
        debug!(?next_players, "determined next players from full registry");
    }
    Ok(next_players)
}

/// The registry's consensus keys, deduplicated.
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

    // Running out of the system call's 250M gas is a revert too; nvnm-contracts' CommitteeGas
    // puts the worst case at 33M.
    let call = IStakingElection::computeCommitteeCall {
        eligible: registry.iter().map(|v| v.address()).collect(),
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
    let players = seated_players(registry, |validator| named.contains(&validator.address()));
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
    use alloy_primitives::{Bytes, U256};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use reth_provider::test_utils::ExtendedAccount;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::tip20_slots};

    use super::{
        testing::{TestExecutionNode, execution_with, peer, returning, reverting},
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

    /// Picks the registry entries at `addresses`, as the election does.
    fn at(addresses: &[Address]) -> impl Fn(&DecodedValidatorV2) -> bool + '_ {
        move |validator| addresses.contains(&validator.address())
    }

    #[test]
    fn small_registry_lowers_the_minimum() {
        // A 2-validator devnet: electing both is enough; electing one is not.
        let reg = registry(2);
        let both: Vec<Address> = reg.iter().map(|v| v.address()).collect();
        assert_eq!(seated_players(&reg, at(&both)).unwrap().len(), 2);
        assert!(seated_players(&reg, at(&both[..1])).is_none());
    }

    #[test]
    fn unknown_elected_addresses_are_ignored() {
        let reg = registry(5);
        let mut elected: Vec<Address> = reg[..4].iter().map(|v| v.address()).collect();
        elected.push(Address::repeat_byte(0xEE)); // not in the registry
        assert_eq!(seated_players(&reg, at(&elected)).unwrap().len(), 4);
    }

    #[test]
    fn empty_registry_falls_back() {
        assert!(seated_players(&[], at(&[Address::repeat_byte(1)])).is_none());
    }

    // -- the election, end to end over a mock execution node -------------------------------

    const ELECTION: Address = Address::repeat_byte(0xE1);

    /// Peers 1 through 6 in the registry, and an election contract running `code`, if any.
    fn election(code: Option<Bytes>) -> TestExecutionNode {
        let validators: Vec<_> = (1..=6).map(peer).collect();
        let contracts: Vec<_> = code.into_iter().map(|c| (ELECTION, c)).collect();
        execution_with(&validators, &contracts).expect("seeded execution node")
    }

    /// Runtime code whose `computeCommittee` returns these peers, whoever is eligible.
    fn electing(seeds: &[u8]) -> Bytes {
        let addresses: Vec<Address> = seeds.iter().map(|&s| peer(s).validator_address).collect();
        returning(&IStakingElection::computeCommitteeCall::abi_encode_returns(
            &addresses,
        ))
    }

    /// The keys of these peers.
    fn seeds(seeds: &[u8]) -> ordered::Set<PublicKey> {
        ordered::Set::try_from_iter(seeds.iter().map(|&seed| peer(seed).public_key)).unwrap()
    }

    fn elected_at(node: &TestExecutionNode) -> eyre::Result<Option<ordered::Set<PublicKey>>> {
        let (_, mut evm) = evm_at_block_hash(node, node.hash)?;
        let registry = read_config_on_evm(&mut evm, decoded_active_validators)?;
        elected_players(&mut evm, ELECTION, &registry)
    }

    fn next_players(
        node: &TestExecutionNode,
        election: Option<Address>,
        from: Option<u64>,
        current: &[u8],
    ) -> ordered::Set<PublicKey> {
        next_players_at_block_hash(node, node.hash, election, from, &seeds(current)).unwrap()
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
        assert_eq!(seated, Some(seeds(&[1, 2, 3, 4])));
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
        let validators: Vec<_> = (1..=6).rev().map(peer).collect();
        let node = execution_with(&validators, &[(ELECTION, code)]).expect("seeded");
        assert_eq!(elected_at(&node).unwrap(), Some(seeds(&[6, 5, 4, 3])));
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

        let (_, mut evm) = evm_at_block_hash(&node, node.hash).unwrap();
        let call = evm.transact_system_call(Address::ZERO, ELECTION, Bytes::new());
        assert!(matches!(call, Err(EVMError::Custom(_))), "{call:?}");
        assert!(elected_at(&node).is_err());
    }

    #[test]
    fn next_players_is_the_registry_without_an_election() {
        let all = seeds(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(
            next_players(&election(None), None, None, &[1, 2, 3, 4]),
            all
        );
    }

    #[test]
    fn the_election_takes_effect_at_its_activation_time() {
        let node = election(Some(electing(&[1, 2, 3, 4])));
        // The mock header sits at timestamp 1.
        for from in [None, Some(1)] {
            assert_eq!(
                next_players(&node, Some(ELECTION), from, &[]),
                seeds(&[1, 2, 3, 4])
            );
        }
        let all = seeds(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(next_players(&node, Some(ELECTION), Some(2), &[]), all);
    }

    #[test]
    fn a_fallback_keeps_the_current_players_still_registered() {
        let node = election(Some(reverting()));
        let kept = next_players(&node, Some(ELECTION), None, &[1, 2, 3, 4, 5, 9]);
        assert_eq!(kept, seeds(&[1, 2, 3, 4, 5]));
        // Below the floor, the whole registry.
        let all = next_players(&node, Some(ELECTION), None, &[1, 2, 3, 9]);
        assert_eq!(all, seeds(&[1, 2, 3, 4, 5, 6]));
    }
}
