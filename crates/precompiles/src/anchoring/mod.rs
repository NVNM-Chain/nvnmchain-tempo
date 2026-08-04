//! Anchoring precompile: registries and versioned records with scoped RBAC.
//! Enabled at `TempoHardfork::Genesis`.
//!
//! An ABI-compatible port of the `x/anchoring` EVM precompile at the same address. That
//! module's source is normative — where its readme disagrees with the code, the code wins,
//! and those divergences are noted at the relevant call sites here.
//!
//! A registry holds records; a record is versioned per `(registryId, checksum)`, where
//! `recordId` identifies the version stream and `index` is the 1-based version within it. Only
//! the newest version of a stream carries `isLatest`.
//!
//! Unlike the rest of tempo's precompiles, failures revert with `Error(string)` reason strings
//! rather than typed custom errors: the reason text is observable and existing callers match
//! on it.

pub mod dispatch;

use crate::{
    ANCHORING_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx},
};
use alloy::{
    primitives::{Address, B256, Bytes, hex, keccak256},
    sol_types::SolValue,
};
pub use tempo_contracts::precompiles::{
    AnchoringEvent, DEFAULT_PAGE_LIMIT, IAnchoring, MAX_PAGE_LIMIT, MAX_RECORD_CHECKSUM_ALGO_LEN,
    MAX_RECORD_CHECKSUM_LEN, MAX_RECORD_METADATA_LEN, MAX_RECORD_STATUS_LEN, MAX_RECORD_URI_LEN,
    MAX_REGISTRY_DESCRIPTION_LEN, MAX_REGISTRY_METADATA_LEN, MAX_REGISTRY_NAME_LEN, ROLE_ADMIN,
    ROLE_EDITOR,
};
use tempo_precompiles_macros::contract;

/// Reverts with a plain `Error(string)`, matching the legacy module's reason text.
fn revert<T>(reason: impl Into<String>) -> Result<T> {
    Err(TempoPrecompileError::Revert(reason.into()))
}

/// Registries and versioned records, gated by scoped RBAC.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers. EVM storage cannot be iterated, so the module's prefix walks are
/// replaced by dense 1-based counters (`registry_count`, `record_count`) plus one explicit
/// index vector (`registries_by_checksum`) and one membership counter (`role_member_count`).
#[contract(addr = ANCHORING_ADDRESS)]
pub struct Anchoring {
    /// Highest assigned `registryId`. Ids are 1-based and dense.
    registry_count: u64,
    /// `registryId → Registry`, ABI-encoded — one serialized value per key, as the module
    /// stores one marshalled record per key.
    registries: Mapping<u64, Bytes>,
    /// `registryId → highest recordId` in that registry. Also 1-based and dense.
    record_count: Mapping<u64, u64>,
    /// `(registryId, recordId) → latest index`.
    record_index: Mapping<u64, Mapping<u64, u64>>,
    /// `(registryId, recordId, index) → Record`, ABI-encoded.
    records: Mapping<u64, Mapping<u64, Mapping<u64, Bytes>>>,
    /// `(registryId, keccak(checksum)) → recordId`. Checksums are hashed because they are
    /// variable-length strings and cannot key a mapping directly.
    record_id_by_checksum: Mapping<u64, Mapping<B256, u64>>,
    /// `keccak(checksum) → registryIds holding it`, replacing the module's prefix walk over
    /// `RecordIdByChecksumAndRegistry` for the checksum-only query.
    registries_by_checksum: Mapping<B256, Vec<u64>>,
    /// `role → its admin role`.
    role_admins: Mapping<B256, B256>,
    /// `(role, account) → is member`.
    role_members: Mapping<B256, Mapping<Address, bool>>,
    /// `role → member count`, so the last-admin check is O(1) rather than a walk.
    role_member_count: Mapping<B256, u64>,
    /// Break-glass grantor, able to grant a registry admin without holding the admin role.
    module_admin: Address,
}

impl Anchoring {
    /// Initializes the precompile by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Rejects calls the legacy precompile would refuse before dispatching a write.
    ///
    /// Mirrors the module's `ensureNoValue` + `ensureEOACaller`: a write must carry no value
    /// and must come straight from the transaction signer. The caller has to *be* `tx.origin`
    /// and that account must carry no code, so a contract cannot reach these methods —
    /// including from its constructor, where the account's code is not yet set but the caller
    /// still differs from the origin.
    ///
    /// An EIP-7702 delegation designator is still an EOA, so it is allowed.
    fn ensure_eoa_write(&self, msg_sender: Address) -> Result<()> {
        let value = StorageCtx.call_value();
        if !value.is_zero() {
            return revert(format!("cannot receive funds, received: {value}"));
        }
        let origin = StorageCtx.tx_origin();
        if msg_sender != origin {
            return revert("sender not an eoa");
        }
        let (_, code) = StorageCtx.account_code(origin)?;
        if !code.is_empty() && !is_delegation_designator(code.original_byte_slice()) {
            return revert("sender not an eoa");
        }
        Ok(())
    }

    /// Sets the module admin, the only account that may use the break-glass admin grant.
    pub fn set_module_admin(&mut self, admin: Address) -> Result<()> {
        self.module_admin.write(admin)
    }

    // ────────────────── Role derivation ──────────────────

    /// `keccak256("registry:<registryId>:<role>")`.
    fn registry_role(registry_id: u64, role: &str) -> B256 {
        keccak256(format!("registry:{registry_id}:{role}"))
    }

    /// `keccak256("record:<registryId>:<hex(checksum)>:<hex(role)>")`.
    ///
    /// The readme documents `keccak256("<checksum>:<role>")`; the module's code is what
    /// actually runs, and hex-encodes the user-controlled fields so a value containing `:`
    /// cannot forge another scope's role id. Dropping the registry would let one grant
    /// authorize every registry sharing a checksum.
    fn record_role(registry_id: u64, checksum: &str, role: &str) -> B256 {
        keccak256(format!(
            "record:{registry_id}:{}:{}",
            hex::encode(checksum),
            hex::encode(role)
        ))
    }

    /// A role is record-scoped only when both a registry and a checksum are given.
    fn is_record_role(registry_id: u64, checksum: &str) -> bool {
        registry_id != 0 && !checksum.is_empty()
    }

    /// The role id for the scope implied by `(registry_id, checksum)`.
    fn scoped_role(registry_id: u64, checksum: &str, role: &str) -> B256 {
        if Self::is_record_role(registry_id, checksum) {
            Self::record_role(registry_id, checksum, role)
        } else {
            Self::registry_role(registry_id, role)
        }
    }

    // ────────────────── RBAC ──────────────────

    fn has_role(&self, role: B256, account: Address) -> Result<bool> {
        self.role_members[role][account].read()
    }

    /// Adds `account` to `role`, keeping `role_member_count` in step. Idempotent.
    fn add_role_member(&mut self, role: B256, account: Address) -> Result<()> {
        if self.has_role(role, account)? {
            return Ok(());
        }
        self.role_members[role][account].write(true)?;
        let count = self.role_member_count[role].read()?;
        self.role_member_count[role].write(count + 1)
    }

    /// Removes `account` from `role`, keeping `role_member_count` in step.
    fn remove_role_member(&mut self, role: B256, account: Address) -> Result<()> {
        if !self.has_role(role, account)? {
            return Ok(());
        }
        self.role_members[role][account].write(false)?;
        let count = self.role_member_count[role].read()?;
        self.role_member_count[role].write(count.saturating_sub(1))
    }

    /// Passes if `account` holds `admin` or `editor` at record scope, or failing that at
    /// registry scope. There is no global role, despite the readme mentioning one.
    fn check_permission(&self, account: Address, registry_id: u64, checksum: &str) -> Result<()> {
        for role in [ROLE_ADMIN, ROLE_EDITOR] {
            if !checksum.is_empty()
                && self.has_role(Self::record_role(registry_id, checksum, role), account)?
            {
                return Ok(());
            }
        }
        for role in [ROLE_ADMIN, ROLE_EDITOR] {
            if self.has_role(Self::registry_role(registry_id, role), account)? {
                return Ok(());
            }
        }
        revert("unauthorized")
    }

    fn ensure_registry_exists(&self, registry_id: u64) -> Result<()> {
        if self.registries[registry_id].read()?.is_empty() {
            return revert(format!("registry {registry_id} does not exist"));
        }
        Ok(())
    }

    /// The registry must exist, and for a record-scoped role the checksum must already have a
    /// record in that registry.
    fn ensure_role_scope_exists(&self, registry_id: u64, checksum: &str) -> Result<()> {
        self.ensure_registry_exists(registry_id)?;
        if Self::is_record_role(registry_id, checksum)
            && self.record_id_by_checksum[registry_id][keccak256(checksum)].read()? == 0
        {
            return revert(format!(
                "record with checksum {checksum} does not exist in registry {registry_id}"
            ));
        }
        Ok(())
    }

    // ────────────────── Writes ──────────────────

    /// Creates a registry owned by `msg_sender`.
    ///
    /// Permissionless by design: there is no RBAC check here, and `name` is not required to
    /// be unique — `id` is the canonical reference.
    pub fn add_registry(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::addRegistryCall,
    ) -> Result<u64> {
        self.ensure_eoa_write(msg_sender)?;
        validate_non_empty("name", &call.name, MAX_REGISTRY_NAME_LEN)?;
        validate_max_len(
            "description",
            &call.description,
            MAX_REGISTRY_DESCRIPTION_LEN,
        )?;
        validate_max_len("metadata", &call.metadata, MAX_REGISTRY_METADATA_LEN)?;

        let registry_id = self.registry_count.read()? + 1;
        let registry = IAnchoring::Registry {
            id: registry_id,
            name: call.name.clone(),
            description: call.description,
            creator: msg_sender.to_string(),
            createdAt: block_time_string(),
            metadata: call.metadata,
        };
        self.registries[registry_id].write(registry.abi_encode().into())?;

        // The registry admin role administers itself, and the creator is its first member.
        let admin_role = Self::registry_role(registry_id, ROLE_ADMIN);
        self.role_admins[admin_role].write(admin_role)?;
        self.add_role_member(admin_role, msg_sender)?;

        self.record_count[registry_id].write(0)?;
        self.registry_count.write(registry_id)?;

        self.emit_event(AnchoringEvent::add_registry(
            msg_sender,
            registry_id,
            call.name,
        ))?;
        Ok(registry_id)
    }

    /// Appends a version to `(registryId, checksum)`, creating the stream on first use.
    ///
    /// Caller-supplied `recordId`, `index`, `isLatest`, and `timestamp` are ignored; the chain
    /// assigns them.
    pub fn add_record(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::addRecordCall,
    ) -> Result<u64> {
        self.ensure_eoa_write(msg_sender)?;
        let mut record = call.record;
        validate_non_empty("checksum", &record.checksum, MAX_RECORD_CHECKSUM_LEN)?;
        validate_non_empty(
            "checksum algorithm",
            &record.checksumAlgo,
            MAX_RECORD_CHECKSUM_ALGO_LEN,
        )?;
        validate_non_empty("uri", &record.uri, MAX_RECORD_URI_LEN)?;
        if record.metadata.is_empty() || record.metadata == "{}" {
            return revert("metadata cannot be empty");
        }
        validate_max_len("metadata", &record.metadata, MAX_RECORD_METADATA_LEN)?;
        validate_non_empty("status", &record.status, MAX_RECORD_STATUS_LEN)?;
        if record.registryId == 0 {
            return revert("registry id cannot be zero");
        }

        let registry_id = record.registryId;
        self.ensure_registry_exists(registry_id)?;
        self.check_permission(msg_sender, registry_id, &record.checksum)?;

        // Resolve the version stream, creating it if this checksum is new to the registry.
        let checksum_key = keccak256(&record.checksum);
        let mut record_id = self.record_id_by_checksum[registry_id][checksum_key].read()?;
        if record_id == 0 {
            record_id = self.record_count[registry_id].read()? + 1;
            self.record_count[registry_id].write(record_id)?;
            self.record_id_by_checksum[registry_id][checksum_key].write(record_id)?;

            let mut holders = self.registries_by_checksum[checksum_key].read()?;
            holders.push(registry_id);
            self.registries_by_checksum[checksum_key].write(holders)?;
        }

        let index = self.record_index[registry_id][record_id].read()? + 1;
        self.record_index[registry_id][record_id].write(index)?;

        record.recordId = record_id;
        record.index = index;
        record.isLatest = true;
        record.timestamp = block_time_string();
        let checksum = record.checksum.clone();
        self.records[registry_id][record_id][index].write(record.abi_encode().into())?;

        // Only the newest version of a stream carries `isLatest`.
        if index > 1 {
            let mut previous = self.load_record(registry_id, record_id, index - 1)?;
            previous.isLatest = false;
            self.records[registry_id][record_id][index - 1].write(previous.abi_encode().into())?;
        }

        self.emit_event(AnchoringEvent::add_record(
            msg_sender,
            registry_id,
            record_id,
            index,
            checksum,
        ))?;
        Ok(record_id)
    }

    /// Sets the status of one record version. Idempotent — re-asserting the current status is
    /// allowed, unlike a no-op-rejecting design.
    pub fn update_record_status(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::updateRecordStatusCall,
    ) -> Result<()> {
        self.ensure_eoa_write(msg_sender)?;
        validate_non_empty("status", &call.status, MAX_RECORD_STATUS_LEN)?;

        let mut record = self.load_record(call.registryId, call.recordId, call.index)?;
        // The permission scope comes from the stored record's checksum, not from the caller.
        self.check_permission(msg_sender, call.registryId, &record.checksum)?;

        record.status = call.status.clone();
        self.records[call.registryId][call.recordId][call.index]
            .write(record.abi_encode().into())?;

        self.emit_event(AnchoringEvent::update_record_status(
            msg_sender,
            call.registryId,
            call.recordId,
            call.index,
            call.status,
        ))
    }

    /// Grants a role, scoped by `(registryId, checksum)`.
    ///
    /// The caller must hold the registry's admin role, except that the module admin may always
    /// grant a registry-level `admin` — the break-glass path that makes the last-admin rule in
    /// [`Self::revoke_role`] safe.
    pub fn grant_role(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::grantRoleCall,
    ) -> Result<()> {
        self.ensure_eoa_write(msg_sender)?;
        self.ensure_role_scope_exists(call.registryId, &call.checksum)?;

        let role = Self::scoped_role(call.registryId, &call.checksum, &call.role);
        let admin_role = Self::registry_role(call.registryId, ROLE_ADMIN);
        self.role_admins[role].write(admin_role)?;

        let break_glass = !Self::is_record_role(call.registryId, &call.checksum)
            && call.role == ROLE_ADMIN
            && msg_sender == self.module_admin.read()?;
        if !break_glass && !self.has_role(admin_role, msg_sender)? {
            return revert("unauthorized");
        }

        self.add_role_member(role, call.account)?;
        self.emit_event(AnchoringEvent::grant_role(
            msg_sender,
            call.registryId,
            call.checksum,
            call.account,
            call.role,
        ))
    }

    /// Revokes a role. The last registry admin cannot be removed — recover by granting a
    /// replacement first, so a registry is never left with zero admins.
    pub fn revoke_role(
        &mut self,
        msg_sender: Address,
        call: IAnchoring::revokeRoleCall,
    ) -> Result<()> {
        self.ensure_eoa_write(msg_sender)?;
        if call.role.is_empty() {
            return revert("role cannot be empty");
        }
        self.ensure_role_scope_exists(call.registryId, &call.checksum)?;

        let role = Self::scoped_role(call.registryId, &call.checksum, &call.role);
        if !self.has_role(role, call.account)? {
            return revert("address does not have the specified role");
        }

        if !Self::is_record_role(call.registryId, &call.checksum) && call.role == ROLE_ADMIN {
            let admin_role = Self::registry_role(call.registryId, ROLE_ADMIN);
            if self.role_member_count[admin_role].read()? <= 1 {
                return revert("cannot revoke the last registry admin");
            }
        }

        let admin_role = self.role_admins[role].read()?;
        if !self.has_role(admin_role, msg_sender)? {
            return revert("unauthorized");
        }

        self.remove_role_member(role, call.account)?;
        self.emit_event(AnchoringEvent::revoke_role(
            msg_sender,
            call.registryId,
            call.checksum,
            call.account,
            call.role,
        ))
    }

    // ────────────────── Reads ──────────────────

    fn load_record(
        &self,
        registry_id: u64,
        record_id: u64,
        index: u64,
    ) -> Result<IAnchoring::Record> {
        let raw = self.records[registry_id][record_id][index].read()?;
        if raw.is_empty() {
            return revert(format!(
                "record ({registry_id}, {record_id}, {index}) not found"
            ));
        }
        IAnchoring::Record::abi_decode(&raw)
            .map_err(|_| TempoPrecompileError::Fatal("corrupt record encoding".into()))
    }

    fn load_registry(&self, registry_id: u64) -> Result<IAnchoring::Registry> {
        let raw = self.registries[registry_id].read()?;
        if raw.is_empty() {
            return revert(format!("registry {registry_id} does not exist"));
        }
        IAnchoring::Registry::abi_decode(&raw)
            .map_err(|_| TempoPrecompileError::Fatal("corrupt registry encoding".into()))
    }

    /// The latest version of `(registryId, recordId)`, or the one at `index` when non-zero.
    fn record_at(
        &self,
        registry_id: u64,
        record_id: u64,
        index: u64,
    ) -> Result<IAnchoring::Record> {
        let index = if index == 0 {
            self.record_index[registry_id][record_id].read()?
        } else {
            index
        };
        self.load_record(registry_id, record_id, index)
    }

    /// Queries records. Which filters are set selects the strategy; `PageResponse` is always
    /// empty because total-count scans are refused.
    pub fn records(&self, call: IAnchoring::recordsCall) -> Result<IAnchoring::recordsReturn> {
        let (registry_id, checksum, mut record_id) =
            (call.registryId, call.checksum.as_str(), call.recordId);

        if record_id != 0 && registry_id == 0 {
            return revert("record_id requires registry_id");
        }
        if call.index != 0 && (registry_id == 0 || (record_id == 0 && checksum.is_empty())) {
            return revert("index requires registry_id and either record_id or checksum");
        }

        let page = Page::new(&call.pagination);

        if record_id == 0 && !checksum.is_empty() && registry_id != 0 {
            record_id = self.record_id_by_checksum[registry_id][keccak256(checksum)].read()?;
            if record_id == 0 {
                return revert(format!(
                    "record with checksum {checksum} does not exist in registry {registry_id}"
                ));
            }
        }

        // A single fully-qualified version.
        if registry_id != 0 && record_id != 0 {
            return Ok(records_return(vec![self.record_at(
                registry_id,
                record_id,
                call.index,
            )?]));
        }

        // The latest version of every stream in one registry.
        if registry_id != 0 {
            let count = self.record_count[registry_id].read()?;
            let mut out = Vec::new();
            for id in page.range(1..=count) {
                out.push(self.record_at(registry_id, id, 0)?);
            }
            return Ok(records_return(out));
        }

        // The latest version of one checksum in every registry holding it.
        if !checksum.is_empty() {
            let holders = self.registries_by_checksum[keccak256(checksum)].read()?;
            let mut out = Vec::new();
            for registry in page.select(&holders) {
                let id = self.record_id_by_checksum[*registry][keccak256(checksum)].read()?;
                out.push(self.record_at(*registry, id, 0)?);
            }
            return Ok(records_return(out));
        }

        // Unfiltered: the latest version of every stream on the chain.
        let mut out = Vec::new();
        let mut seen = 0u64;
        for registry in 1..=self.registry_count.read()? {
            for id in 1..=self.record_count[registry].read()? {
                if page.accepts(seen) {
                    out.push(self.record_at(registry, id, 0)?);
                }
                seen += 1;
                if out.len() as u64 == page.limit {
                    return Ok(records_return(out));
                }
            }
        }
        Ok(records_return(out))
    }

    /// One registry by id, or a page over all of them.
    pub fn registries(
        &self,
        call: IAnchoring::registriesCall,
    ) -> Result<IAnchoring::registriesReturn> {
        if call.registryId != 0 {
            return Ok(registries_return(vec![
                self.load_registry(call.registryId)?,
            ]));
        }

        let page = Page::new(&call.pagination);
        let mut out = Vec::new();
        for id in page.range(1..=self.registry_count.read()?) {
            out.push(self.load_registry(id)?);
        }
        Ok(registries_return(out))
    }
}

/// Total-count scans are disabled, so the `PageResponse` in a return is always empty.
fn empty_page() -> IAnchoring::PageResponse {
    IAnchoring::PageResponse {
        nextKey: Bytes::new(),
        total: 0,
    }
}

fn records_return(records: Vec<IAnchoring::Record>) -> IAnchoring::recordsReturn {
    IAnchoring::recordsReturn {
        records,
        pagination: empty_page(),
    }
}

fn registries_return(registries: Vec<IAnchoring::Registry>) -> IAnchoring::registriesReturn {
    IAnchoring::registriesReturn {
        registries,
        pagination: empty_page(),
    }
}

/// Offset/limit paging. `key` and `reverse` are accepted for ABI compatibility and ignored,
/// and `countTotal` is forced off, matching the module's request sanitizer.
struct Page {
    offset: u64,
    limit: u64,
}

impl Page {
    fn new(request: &IAnchoring::PageRequest) -> Self {
        let limit = match request.limit {
            0 => DEFAULT_PAGE_LIMIT,
            n => n.min(MAX_PAGE_LIMIT),
        };
        Self {
            offset: request.offset,
            limit,
        }
    }

    /// The ids of one page out of an inclusive 1-based range.
    fn range(&self, all: std::ops::RangeInclusive<u64>) -> impl Iterator<Item = u64> + '_ {
        all.skip(self.offset as usize).take(self.limit as usize)
    }

    /// One page out of an explicit list.
    fn select<'a, T>(&self, all: &'a [T]) -> impl Iterator<Item = &'a T> {
        all.iter()
            .skip(self.offset as usize)
            .take(self.limit as usize)
    }

    /// Whether the item at position `seen` falls inside this page.
    fn accepts(&self, seen: u64) -> bool {
        seen >= self.offset && seen < self.offset.saturating_add(self.limit)
    }
}

/// Whether `code` is an EIP-7702 delegation designator (`0xef0100 ‖ address`). Such an
/// account is still an EOA, so the module's `isEOACode` treats it as one.
fn is_delegation_designator(code: &[u8]) -> bool {
    code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00])
}

/// The block timestamp, rendered as the record/registry time string.
///
/// The module stores a formatted wall-clock string
/// (`"2026-01-30 05:39:59.971631 +0000 UTC"`). That format is not reproducible from a Unix
/// timestamp without civil-date arithmetic, and nothing on-chain parses it, so this stores the
/// seconds since epoch as decimal. Consumers that need wall-clock time should take it from the
/// block header, which is authoritative either way.
fn block_time_string() -> String {
    StorageCtx.timestamp().to::<u64>().to_string()
}

fn validate_max_len(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return revert(format!("{field} exceeds max length {max}"));
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() {
        return revert(format!("{field} cannot be empty"));
    }
    validate_max_len(field, value, max)
}

/// Covers the `x/anchoring` behaviours the precompile has to reproduce.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use tempo_chainspec::hardfork::TempoHardfork;

    fn with_anchoring<T>(f: impl FnOnce(Anchoring) -> eyre::Result<T>) -> eyre::Result<T> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || f(Anchoring::new()))
    }

    /// Writes require `msg.sender == tx.origin`, so each call is its own transaction from
    /// `sender`. Every helper below sets the origin first.
    fn as_eoa(sender: Address) {
        StorageCtx.set_tx_origin(sender);
    }

    fn add_registry(a: &mut Anchoring, sender: Address, name: &str) -> Result<u64> {
        as_eoa(sender);
        a.add_registry(
            sender,
            IAnchoring::addRegistryCall {
                name: name.into(),
                description: String::new(),
                metadata: String::new(),
            },
        )
    }

    fn record(registry_id: u64, checksum: &str, uri: &str) -> IAnchoring::Record {
        IAnchoring::Record {
            uri: uri.into(),
            checksum: checksum.into(),
            checksumAlgo: "sha256".into(),
            metadata: r#"{"document":"d"}"#.into(),
            timestamp: String::new(),
            status: "active".into(),
            recordId: 0,
            index: 0,
            isLatest: false,
            registryId: registry_id,
        }
    }

    fn add_record(a: &mut Anchoring, sender: Address, rec: IAnchoring::Record) -> Result<u64> {
        as_eoa(sender);
        a.add_record(sender, IAnchoring::addRecordCall { record: rec })
    }

    fn grant(
        a: &mut Anchoring,
        sender: Address,
        reg: u64,
        checksum: &str,
        to: Address,
        role: &str,
    ) -> Result<()> {
        as_eoa(sender);
        a.grant_role(
            sender,
            IAnchoring::grantRoleCall {
                registryId: reg,
                checksum: checksum.into(),
                account: to,
                role: role.into(),
            },
        )
    }

    fn revoke(
        a: &mut Anchoring,
        sender: Address,
        reg: u64,
        checksum: &str,
        from: Address,
        role: &str,
    ) -> Result<()> {
        as_eoa(sender);
        a.revoke_role(
            sender,
            IAnchoring::revokeRoleCall {
                registryId: reg,
                checksum: checksum.into(),
                account: from,
                role: role.into(),
            },
        )
    }

    fn query(
        a: &Anchoring,
        reg: u64,
        checksum: &str,
        record_id: u64,
        index: u64,
        limit: u64,
    ) -> Result<Vec<IAnchoring::Record>> {
        Ok(a.records(IAnchoring::recordsCall {
            registryId: reg,
            checksum: checksum.into(),
            recordId: record_id,
            index,
            pagination: IAnchoring::PageRequest {
                key: Bytes::new(),
                offset: 0,
                limit,
                countTotal: false,
                reverse: false,
            },
        })?
        .records)
    }

    fn reason(err: TempoPrecompileError) -> String {
        match err {
            TempoPrecompileError::Revert(reason) => reason,
            other => panic!("expected a string revert, got {other:?}"),
        }
    }

    /// permissionless, ids increment, names need not be unique.
    #[test]
    fn add_registry_is_permissionless_and_names_may_repeat() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (alice, bob) = (Address::random(), Address::random());
            assert_eq!(add_registry(&mut a, alice, "docs")?, 1);
            assert_eq!(add_registry(&mut a, bob, "docs")?, 2);

            let all = a.registries(IAnchoring::registriesCall {
                registryId: 0,
                pagination: IAnchoring::PageRequest {
                    key: Bytes::new(),
                    offset: 0,
                    limit: 0,
                    countTotal: false,
                    reverse: false,
                },
            })?;
            assert_eq!(all.registries.len(), 2);
            assert_eq!(all.registries[0].creator, alice.to_string());
            assert_eq!(all.registries[1].name, "docs");
            Ok(())
        })
    }

    #[test]
    fn add_record_assigns_ids_and_is_queryable() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let reg = add_registry(&mut a, admin, "docs")?;
            assert_eq!(
                add_record(&mut a, admin, record(reg, "abc", "ipfs://a"))?,
                1
            );

            let found = query(&a, reg, "abc", 0, 0, 0)?;
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].recordId, 1);
            assert_eq!(found[0].index, 1);
            assert!(found[0].isLatest);
            assert_eq!(found[0].uri, "ipfs://a");
            Ok(())
        })
    }

    /// a re-anchored checksum keeps its
    /// `recordId` and bumps `index`, and only the newest version stays `isLatest`.
    #[test]
    fn same_checksum_keeps_record_id_and_versions() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let reg = add_registry(&mut a, admin, "docs")?;
            add_record(&mut a, admin, record(reg, "abc", "ipfs://v1"))?;
            assert_eq!(
                add_record(&mut a, admin, record(reg, "abc", "ipfs://v2"))?,
                1
            );

            let latest = query(&a, reg, "abc", 0, 0, 0)?;
            assert_eq!((latest[0].recordId, latest[0].index), (1, 2));
            assert!(latest[0].isLatest);

            let first = query(&a, reg, "", 1, 1, 0)?;
            assert!(!first[0].isLatest, "previous version must lose isLatest");
            assert_eq!(first[0].uri, "ipfs://v1");
            Ok(())
        })
    }

    #[test]
    fn checksum_streams_are_per_registry() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let (r1, r2) = (
                add_registry(&mut a, admin, "a")?,
                add_registry(&mut a, admin, "b")?,
            );
            // A leading record in r2 shifts the shared checksum onto a different recordId.
            add_record(&mut a, admin, record(r2, "other", "ipfs://o"))?;
            assert_eq!(
                add_record(&mut a, admin, record(r1, "shared", "ipfs://1"))?,
                1
            );
            assert_eq!(
                add_record(&mut a, admin, record(r2, "shared", "ipfs://2"))?,
                2
            );

            // Checksum-only spans every registry holding it.
            let across = query(&a, 0, "shared", 0, 0, 0)?;
            assert_eq!(across.len(), 2);
            assert_eq!(
                (across[0].registryId, across[1].registryId),
                (r1, r2),
                "ordered by the registry that first anchored the checksum"
            );
            Ok(())
        })
    }

    #[test]
    fn only_a_registry_admin_may_grant() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (admin, editor, stranger) =
                (Address::random(), Address::random(), Address::random());
            let reg = add_registry(&mut a, admin, "docs")?;

            assert_eq!(
                reason(grant(&mut a, stranger, reg, "", editor, ROLE_EDITOR).unwrap_err()),
                "unauthorized"
            );
            grant(&mut a, admin, reg, "", editor, ROLE_EDITOR)?;
            add_record(&mut a, editor, record(reg, "abc", "ipfs://a"))?;

            revoke(&mut a, admin, reg, "", editor, ROLE_EDITOR)?;
            assert_eq!(
                reason(add_record(&mut a, editor, record(reg, "def", "ipfs://d")).unwrap_err()),
                "unauthorized"
            );
            Ok(())
        })
    }

    /// a registry must never reach zero admins.
    #[test]
    fn the_last_registry_admin_cannot_be_revoked() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (admin, second) = (Address::random(), Address::random());
            let reg = add_registry(&mut a, admin, "docs")?;

            assert_eq!(
                reason(revoke(&mut a, admin, reg, "", admin, ROLE_ADMIN).unwrap_err()),
                "cannot revoke the last registry admin"
            );

            // With a replacement in place the original can step down.
            grant(&mut a, admin, reg, "", second, ROLE_ADMIN)?;
            revoke(&mut a, second, reg, "", admin, ROLE_ADMIN)?;
            assert!(!a.has_role(Anchoring::registry_role(reg, ROLE_ADMIN), admin)?);
            Ok(())
        })
    }

    /// break-glass bypasses the admin check,
    /// but only for a registry-level `admin` grant.
    #[test]
    fn module_admin_can_recover_a_registry() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (owner, module_admin, rescuer) =
                (Address::random(), Address::random(), Address::random());
            a.set_module_admin(module_admin)?;
            let reg = add_registry(&mut a, owner, "docs")?;

            grant(&mut a, module_admin, reg, "", rescuer, ROLE_ADMIN)?;
            assert!(a.has_role(Anchoring::registry_role(reg, ROLE_ADMIN), rescuer)?);

            // The bypass does not extend to other roles.
            assert_eq!(
                reason(grant(&mut a, module_admin, reg, "", rescuer, ROLE_EDITOR).unwrap_err()),
                "unauthorized"
            );
            Ok(())
        })
    }

    /// A record-scoped grant authorizes only its own checksum.
    #[test]
    fn record_scoped_roles_are_per_checksum() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (admin, editor) = (Address::random(), Address::random());
            let reg = add_registry(&mut a, admin, "docs")?;
            add_record(&mut a, admin, record(reg, "abc", "ipfs://a"))?;
            add_record(&mut a, admin, record(reg, "def", "ipfs://d"))?;

            grant(&mut a, admin, reg, "abc", editor, ROLE_EDITOR)?;
            add_record(&mut a, editor, record(reg, "abc", "ipfs://a2"))?;
            assert_eq!(
                reason(add_record(&mut a, editor, record(reg, "def", "ipfs://d2")).unwrap_err()),
                "unauthorized",
                "a role on one checksum must not authorize another"
            );
            Ok(())
        })
    }

    /// Pins the record-role derivation against the readme's stale `keccak256("<checksum>:<role>")`.
    ///
    /// That form omits the registry, so the same checksum in two registries would share one
    /// role and a grant in either would authorize both. The module scopes by registry, so it
    /// must not.
    #[test]
    fn record_roles_are_scoped_by_registry() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (admin, editor) = (Address::random(), Address::random());
            let (r1, r2) = (
                add_registry(&mut a, admin, "a")?,
                add_registry(&mut a, admin, "b")?,
            );
            add_record(&mut a, admin, record(r1, "shared", "ipfs://1"))?;
            add_record(&mut a, admin, record(r2, "shared", "ipfs://2"))?;

            grant(&mut a, admin, r1, "shared", editor, ROLE_EDITOR)?;
            assert_ne!(
                Anchoring::record_role(r1, "shared", ROLE_EDITOR),
                Anchoring::record_role(r2, "shared", ROLE_EDITOR),
            );
            add_record(&mut a, editor, record(r1, "shared", "ipfs://1b"))?;
            assert_eq!(
                reason(add_record(&mut a, editor, record(r2, "shared", "ipfs://2b")).unwrap_err()),
                "unauthorized",
                "a record role in one registry must not carry into another"
            );
            Ok(())
        })
    }

    /// writes must come straight from the
    /// transaction signer.
    #[test]
    fn writes_require_an_eoa_caller() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (eoa, contract) = (Address::random(), Address::random());

            // A contract forwarding a call: msg.sender is the contract, tx.origin the EOA.
            StorageCtx.set_tx_origin(eoa);
            assert_eq!(
                reason(
                    a.add_registry(
                        contract,
                        IAnchoring::addRegistryCall {
                            name: "docs".into(),
                            description: String::new(),
                            metadata: String::new(),
                        },
                    )
                    .unwrap_err()
                ),
                "sender not an eoa"
            );

            // Same address, but it carries code — a contract calling from its constructor.
            StorageCtx.set_tx_origin(contract);
            StorageCtx.set_code(
                contract,
                revm::state::Bytecode::new_legacy(Bytes::from_static(&[0x60, 0x00])),
            )?;
            assert_eq!(
                reason(add_registry(&mut a, contract, "docs").unwrap_err()),
                "sender not an eoa"
            );

            // A plain EOA succeeds.
            assert_eq!(add_registry(&mut a, eoa, "docs")?, 1);
            Ok(())
        })
    }

    /// An EIP-7702 delegation designator is still an EOA, matching the legacy `isEOACode`.
    #[test]
    fn a_7702_delegated_account_is_still_an_eoa() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let account = Address::random();
            let mut designator = vec![0xef, 0x01, 0x00];
            designator.extend_from_slice(Address::random().as_slice());
            StorageCtx.set_code(
                account,
                revm::state::Bytecode::new_raw(Bytes::from(designator)),
            )?;

            assert_eq!(add_registry(&mut a, account, "docs")?, 1);
            Ok(())
        })
    }

    /// `ensureNoValue`: a payable call is refused before anything else.
    #[test]
    fn writes_reject_call_value() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Genesis)
            .with_call_value(alloy::primitives::U256::from(1));
        StorageCtx::enter(&mut storage, || {
            let mut a = Anchoring::new();
            let sender = Address::random();
            assert!(
                reason(add_registry(&mut a, sender, "docs").unwrap_err())
                    .starts_with("cannot receive funds, received: 1")
            );
            Ok(())
        })
    }

    /// roles cannot be granted into a scope that
    /// does not exist yet.
    #[test]
    fn role_scope_must_exist() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (admin, other) = (Address::random(), Address::random());
            assert!(
                reason(grant(&mut a, admin, 99, "", other, ROLE_EDITOR).unwrap_err())
                    .contains("registry 99 does not exist")
            );

            let reg = add_registry(&mut a, admin, "docs")?;
            assert!(
                reason(grant(&mut a, admin, reg, "nope", other, ROLE_EDITOR).unwrap_err())
                    .contains("does not exist in registry")
            );
            Ok(())
        })
    }

    /// repeated grants do not
    /// inflate the member count, which the last-admin rule depends on.
    #[test]
    fn repeated_grants_are_idempotent() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let (admin, second) = (Address::random(), Address::random());
            let reg = add_registry(&mut a, admin, "docs")?;
            let admin_role = Anchoring::registry_role(reg, ROLE_ADMIN);

            for _ in 0..3 {
                grant(&mut a, admin, reg, "", second, ROLE_ADMIN)?;
            }
            assert_eq!(a.role_member_count[admin_role].read()?, 2);

            revoke(&mut a, admin, reg, "", second, ROLE_ADMIN)?;
            assert_eq!(a.role_member_count[admin_role].read()?, 1);
            assert_eq!(
                reason(revoke(&mut a, admin, reg, "", second, ROLE_ADMIN).unwrap_err()),
                "address does not have the specified role"
            );
            Ok(())
        })
    }

    /// an empty role is rejected before anything else.
    #[test]
    fn revoke_requires_a_role() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let reg = add_registry(&mut a, admin, "docs")?;
            assert_eq!(
                reason(revoke(&mut a, admin, reg, "", admin, "").unwrap_err()),
                "role cannot be empty"
            );
            Ok(())
        })
    }

    #[test]
    fn queries_respect_limits_and_reject_bad_filters() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let reg = add_registry(&mut a, admin, "docs")?;
            for i in 0..3 {
                add_record(&mut a, admin, record(reg, &format!("c{i}"), "ipfs://x"))?;
            }
            // A second registry sharing one checksum, for the checksum-only path.
            let reg2 = add_registry(&mut a, admin, "other")?;
            add_record(&mut a, admin, record(reg2, "c0", "ipfs://y"))?;

            assert_eq!(query(&a, reg, "", 0, 0, 2)?.len(), 2, "registry-only limit");
            assert_eq!(query(&a, reg, "", 0, 0, 0)?.len(), 3, "default limit");
            assert_eq!(query(&a, 0, "c0", 0, 0, 1)?.len(), 1, "checksum-only limit");

            assert_eq!(
                reason(query(&a, 0, "", 5, 0, 0).unwrap_err()),
                "record_id requires registry_id"
            );
            assert_eq!(
                reason(query(&a, 0, "", 0, 1, 0).unwrap_err()),
                "index requires registry_id and either record_id or checksum"
            );
            Ok(())
        })
    }

    #[test]
    fn versions_are_independent_across_registries() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let (r1, r2) = (
                add_registry(&mut a, admin, "a")?,
                add_registry(&mut a, admin, "b")?,
            );
            for _ in 0..3 {
                add_record(&mut a, admin, record(r1, "shared", "ipfs://1"))?;
            }
            add_record(&mut a, admin, record(r2, "shared", "ipfs://2"))?;

            assert_eq!(query(&a, r1, "shared", 0, 0, 0)?[0].index, 3);
            assert_eq!(query(&a, r2, "shared", 0, 0, 0)?[0].index, 1);
            Ok(())
        })
    }

    /// `updateRecordStatus` is idempotent, unlike a no-op-rejecting design.
    #[test]
    fn update_record_status_is_idempotent() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            let reg = add_registry(&mut a, admin, "docs")?;
            add_record(&mut a, admin, record(reg, "abc", "ipfs://a"))?;

            let call = |status: &str| IAnchoring::updateRecordStatusCall {
                registryId: reg,
                recordId: 1,
                index: 1,
                status: status.into(),
            };
            as_eoa(admin);
            a.update_record_status(admin, call("redacted"))?;
            a.update_record_status(admin, call("redacted"))?;

            assert_eq!(query(&a, reg, "abc", 0, 0, 0)?[0].status, "redacted");
            Ok(())
        })
    }

    /// Field validation, matching the module's record and registry rules.
    #[test]
    fn validation_matches_the_module() -> eyre::Result<()> {
        with_anchoring(|mut a| {
            let admin = Address::random();
            assert_eq!(
                reason(add_registry(&mut a, admin, "").unwrap_err()),
                "name cannot be empty"
            );

            let reg = add_registry(&mut a, admin, "docs")?;
            let mut empty_metadata = record(reg, "abc", "ipfs://a");
            empty_metadata.metadata = "{}".into();
            assert_eq!(
                reason(add_record(&mut a, admin, empty_metadata).unwrap_err()),
                "metadata cannot be empty",
                "`{{}}` counts as empty, as the module's record validation requires"
            );

            let mut long_checksum =
                record(reg, &"a".repeat(MAX_RECORD_CHECKSUM_LEN + 1), "ipfs://a");
            long_checksum.uri = "ipfs://a".into();
            assert!(
                reason(add_record(&mut a, admin, long_checksum).unwrap_err())
                    .contains("checksum exceeds max length")
            );
            Ok(())
        })
    }
}
