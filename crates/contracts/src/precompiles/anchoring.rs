pub use IAnchoring::IAnchoringEvents as AnchoringEvent;

crate::sol! {
    /// Registries and records for anchoring off-chain artifacts, with scoped RBAC.
    ///
    /// ABI-compatible with the `x/anchoring` module's EVM precompile at the same address, so
    /// existing integrations keep working unchanged. Signatures, selectors, event signatures,
    /// and revert-reason strings are all fixed by that module, which is the normative
    /// reference.
    ///
    /// A registry holds records; a record is versioned per `(registryId, checksum)`, with
    /// `recordId` identifying the version stream and `index` the 1-based version within it.
    /// Only the newest version of a stream carries `isLatest`.
    ///
    /// Unlike the rest of tempo's precompiles, failures here revert with `Error(string)`
    /// reason strings rather than typed custom errors, because the reason text is observable
    /// and depended upon by existing callers.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IAnchoring {
        /// An anchored artifact version.
        ///
        /// On `addRecord` the chain overwrites `timestamp`, `index`, `isLatest`, and
        /// `recordId`; callers supply the rest.
        struct Record {
            string uri;
            string checksum;
            string checksumAlgo;
            string metadata;
            string timestamp;
            string status;
            uint64 recordId;
            uint64 index;
            bool isLatest;
            uint64 registryId;
        }

        /// A named collection of records. `name` is deliberately not unique; `id` is canonical.
        struct Registry {
            uint64 id;
            string name;
            string description;
            string creator;
            string createdAt;
            string metadata;
        }

        /// Pagination request. `key` and `countTotal` are accepted for ABI compatibility but
        /// ignored: queries paginate by `offset`/`limit` only.
        struct PageRequest {
            bytes key;
            uint64 offset;
            uint64 limit;
            bool countTotal;
            bool reverse;
        }

        /// Pagination response. Always empty, matching the module, which disables
        /// total-count scans.
        struct PageResponse {
            bytes nextKey;
            uint64 total;
        }

        /// Creates a registry and makes the caller its admin. Permissionless: any caller may
        /// create one, and names need not be unique.
        function addRegistry(string name, string description, string metadata)
            external
            returns (uint64 registryId);

        /// Appends a version to `(record.registryId, record.checksum)`, creating the stream on
        /// first use. Requires `admin` or `editor`, record- or registry-scoped.
        function addRecord(Record record) external returns (uint64 recordId);

        /// Sets the status of one record version. Requires `admin` or `editor`.
        function updateRecordStatus(uint64 registryId, uint64 recordId, uint64 index, string status)
            external;

        /// Queries records. With `registryId` and a `recordId`/`checksum`, returns that single
        /// version (the latest unless `index` is given); otherwise pages over the latest
        /// version of each stream.
        function records(
            uint64 registryId,
            string checksum,
            uint64 recordId,
            uint64 index,
            PageRequest pagination
        ) external view returns (Record[] records, PageResponse pagination);

        /// Queries registries: one by `registryId`, or a page over all of them.
        function registries(uint64 registryId, PageRequest pagination)
            external
            view
            returns (Registry[] registries, PageResponse pagination);

        /// Grants a role. Scope is record-level when `registryId != 0 && checksum != ""`,
        /// registry-level otherwise. Caller must hold the registry's admin role, except that
        /// the module admin may always grant a registry admin (break-glass recovery).
        function grantRole(uint64 registryId, string checksum, address account, string role)
            external;

        /// Revokes a role. Caller must hold the registry's admin role. The last registry admin
        /// cannot be revoked — grant a replacement first.
        function revokeRole(uint64 registryId, string checksum, address account, string role)
            external;

        event AddRegistry(address indexed caller, uint64 registryId, string name);
        event AddRecord(
            address indexed caller,
            uint64 registryId,
            uint64 recordId,
            uint64 index,
            string checksum
        );
        event UpdateRecordStatus(
            address indexed caller,
            uint64 registryId,
            uint64 recordId,
            uint64 index,
            string status
        );
        event GrantRole(
            address indexed caller,
            uint64 registryId,
            string checksum,
            address account,
            string role
        );
        event RevokeRole(
            address indexed caller,
            uint64 registryId,
            string checksum,
            address account,
            string role
        );
    }
}

/// Role names recognised by the module. Roles are opaque strings elsewhere, but only these two
/// are consulted when authorizing writes.
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_EDITOR: &str = "editor";

/// Field length limits, from the module's record and registry validation.
pub const MAX_REGISTRY_NAME_LEN: usize = 128;
pub const MAX_REGISTRY_DESCRIPTION_LEN: usize = 2048;
pub const MAX_REGISTRY_METADATA_LEN: usize = 2048;
pub const MAX_RECORD_CHECKSUM_LEN: usize = 64;
pub const MAX_RECORD_CHECKSUM_ALGO_LEN: usize = 128;
pub const MAX_RECORD_URI_LEN: usize = 2048;
pub const MAX_RECORD_METADATA_LEN: usize = 2048;
pub const MAX_RECORD_STATUS_LEN: usize = 64;

/// Query pagination bounds, from the module's query server.
pub const DEFAULT_PAGE_LIMIT: u64 = 50;
pub const MAX_PAGE_LIMIT: u64 = 200;

#[cfg(test)]
mod tests {
    use super::IAnchoring;
    use alloy_primitives::{b256, hex};
    use alloy_sol_types::{SolCall, SolEvent};

    /// Selectors and event topics are fixed by the `x/anchoring` precompile. A mismatch here
    /// silently breaks every existing integration, so they are pinned against the values that
    /// module publishes.
    #[test]
    fn legacy_abi_is_binary_compatible() {
        assert_eq!(IAnchoring::addRegistryCall::SELECTOR, hex!("0x318b38b1"));
        assert_eq!(IAnchoring::addRecordCall::SELECTOR, hex!("0x64d25295"));
        assert_eq!(
            IAnchoring::updateRecordStatusCall::SELECTOR,
            hex!("0x97b40c25")
        );
        assert_eq!(IAnchoring::recordsCall::SELECTOR, hex!("0xc7be5e37"));
        assert_eq!(IAnchoring::registriesCall::SELECTOR, hex!("0x17bd3e65"));
        assert_eq!(IAnchoring::grantRoleCall::SELECTOR, hex!("0xb8fdd1a7"));
        assert_eq!(IAnchoring::revokeRoleCall::SELECTOR, hex!("0xacd58bc7"));
    }

    /// The module documents these event signatures; topic0 is their keccak256.
    #[test]
    fn event_signatures_match_the_legacy_module() {
        assert_eq!(
            IAnchoring::AddRegistry::SIGNATURE,
            "AddRegistry(address,uint64,string)"
        );
        assert_eq!(
            IAnchoring::AddRecord::SIGNATURE,
            "AddRecord(address,uint64,uint64,uint64,string)"
        );
        assert_eq!(
            IAnchoring::UpdateRecordStatus::SIGNATURE,
            "UpdateRecordStatus(address,uint64,uint64,uint64,string)"
        );
        assert_eq!(
            IAnchoring::GrantRole::SIGNATURE,
            "GrantRole(address,uint64,string,address,string)"
        );
        assert_eq!(
            IAnchoring::RevokeRole::SIGNATURE,
            "RevokeRole(address,uint64,string,address,string)"
        );

        // Spot-check one topic0 end to end so a signature typo cannot pass unnoticed.
        assert_eq!(
            IAnchoring::AddRegistry::SIGNATURE_HASH,
            b256!("0x181791bc379acedd3615cf065d3c275dfa6a3c4614c9065d54c98773f576108d")
        );
    }
}
