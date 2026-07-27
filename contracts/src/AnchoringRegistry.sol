// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {EnumerableRoles} from "solady/auth/EnumerableRoles.sol";

/// @title AnchoringRegistry
/// @notice On-chain document anchoring: named registries hold checksum records, versioned per
///         checksum, with RBAC and status updates.
/// @dev UUPS proxy; `owner` (a Safe) is the upgrade authority and top admin, delegating to the
///      ADMIN / REGISTRAR / STATUS_UPDATER roles. Storage is ERC-7201-namespaced.
contract AnchoringRegistry is UUPSUpgradeable, Initializable, Ownable, EnumerableRoles {
    // -- roles ---------------------------------------------------------------
    uint256 public constant ADMIN = 1; // may grant/revoke roles
    uint256 public constant REGISTRAR = 2; // may add registries and records
    uint256 public constant STATUS_UPDATER = 3; // may update record status

    /// @dev Caps the role space so `setRole` rejects unknown roles (solady self-staticcalls this).
    function MAX_ROLE() public pure returns (uint256) {
        return STATUS_UPDATER;
    }

    // -- data model (mirrors anchoring/v1/document.proto) --------------------
    struct Registry {
        uint256 id;
        string name;
        string description;
        address creator;
        uint256 createdAt;
        string metadata;
    }

    struct Record {
        uint256 registryId;
        string uri;
        string checksum;
        string checksumAlgo;
        string metadata;
        uint256 timestamp;
        string status;
        uint256 recordId;
        uint256 index;
        bool isLatest;
    }

    /// @dev A (registryId, recordId) pointer, for cross-registry checksum lookups.
    struct RecordRef {
        uint256 registryId;
        uint256 recordId;
    }

    // -- ERC-7201 namespaced storage -----------------------------------------
    /// @custom:storage-location erc7201:anchoring.registry.storage
    struct AnchoringStorage {
        uint256 registryCount;
        mapping(uint256 => Registry) registries;
        mapping(bytes32 => uint256) registryIdByName; // keccak(name) => id (1-based; 0 = none)
        mapping(uint256 => uint256) recordCount; // registryId => count (1-based recordId)
        mapping(uint256 => mapping(bytes32 => uint256)) recordIdByChecksum; // registryId => keccak(checksum) => recordId
        mapping(uint256 => mapping(uint256 => Record[])) recordVersions; // registryId => recordId => versions
        mapping(bytes32 => RecordRef[]) refsByChecksum; // keccak(checksum) => refs across registries
    }

    // keccak256(abi.encode(uint256(keccak256("anchoring.registry.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_SLOT =
        0x8b49649f5faffe6fb556822f369f5b9093cb15727ca57978ba8ef3ec01def500;

    function _s() private pure returns (AnchoringStorage storage $) {
        assembly {
            $.slot := _STORAGE_SLOT
        }
    }

    // -- events --------------------------------------------------------------
    event RegistryAdded(uint256 indexed id, string name, address indexed creator);
    event RecordAdded(
        uint256 indexed registryId, uint256 indexed recordId, uint256 index, string checksum, address indexed by
    );
    event RecordStatusUpdated(
        uint256 indexed registryId, uint256 indexed recordId, uint256 index, string status, address indexed by
    );

    // -- errors --------------------------------------------------------------
    error EmptyName();
    error EmptyChecksum();
    error RegistryExists(string name);
    error RegistryNotFound(string name);
    error RecordNotFound(uint256 registryId, uint256 recordId, uint256 index);
    error LastAdmin();

    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the proxy. `owner_` (the Safe) also receives ADMIN.
    function initialize(address owner_, address registrar, address statusUpdater) external initializer {
        _initializeOwner(owner_);
        _setRole(owner_, ADMIN, true);
        if (registrar != address(0)) _setRole(registrar, REGISTRAR, true);
        if (statusUpdater != address(0)) _setRole(statusUpdater, STATUS_UPDATER, true);
    }

    // -- registries ----------------------------------------------------------
    /// @notice Create a uniquely-named registry.
    function addRegistry(string calldata name, string calldata description, string calldata metadata)
        external
        onlyOwnerOrRole(REGISTRAR)
        returns (uint256 id)
    {
        if (bytes(name).length == 0) revert EmptyName();
        bytes32 nameKey = keccak256(bytes(name));
        AnchoringStorage storage $ = _s();
        if ($.registryIdByName[nameKey] != 0) revert RegistryExists(name);

        id = ++$.registryCount;
        Registry storage r = $.registries[id];
        r.id = id;
        r.name = name;
        r.description = description;
        r.creator = msg.sender;
        r.createdAt = block.timestamp;
        r.metadata = metadata;
        $.registryIdByName[nameKey] = id;
        emit RegistryAdded(id, name, msg.sender);
    }

    // -- records -------------------------------------------------------------
    /// @notice Anchor a document under `registry`. Re-anchoring the same checksum in the same
    ///         registry keeps its `recordId` and appends a new version (index++, prior !isLatest).
    function addRecord(
        string calldata registry,
        string calldata uri,
        string calldata checksum,
        string calldata checksumAlgo,
        string calldata metadata
    ) external onlyOwnerOrRole(REGISTRAR) returns (uint256 recordId, uint256 index) {
        if (bytes(checksum).length == 0) revert EmptyChecksum();
        AnchoringStorage storage $ = _s();
        uint256 registryId = $.registryIdByName[keccak256(bytes(registry))];
        if (registryId == 0) revert RegistryNotFound(registry);

        bytes32 cs = keccak256(bytes(checksum));
        recordId = $.recordIdByChecksum[registryId][cs];
        if (recordId == 0) {
            recordId = ++$.recordCount[registryId];
            $.recordIdByChecksum[registryId][cs] = recordId;
            $.refsByChecksum[cs].push(RecordRef(registryId, recordId));
            index = 0;
        } else {
            Record[] storage versions = $.recordVersions[registryId][recordId];
            versions[versions.length - 1].isLatest = false;
            index = versions.length;
        }

        $.recordVersions[registryId][recordId].push(
            Record({
                registryId: registryId,
                uri: uri,
                checksum: checksum,
                checksumAlgo: checksumAlgo,
                metadata: metadata,
                timestamp: block.timestamp,
                status: "active",
                recordId: recordId,
                index: index,
                isLatest: true
            })
        );
        emit RecordAdded(registryId, recordId, index, checksum, msg.sender);
    }

    /// @notice Update the status of a specific record version (e.g. "active" -> "redacted").
    function updateRecordStatus(uint256 registryId, uint256 recordId, uint256 index, string calldata status)
        external
        onlyOwnerOrRole(STATUS_UPDATER)
    {
        AnchoringStorage storage $ = _s();
        Record[] storage versions = $.recordVersions[registryId][recordId];
        if (index >= versions.length) revert RecordNotFound(registryId, recordId, index);
        versions[index].status = status;
        emit RecordStatusUpdated(registryId, recordId, index, status, msg.sender);
    }

    // -- role management -----------------------------------------------------
    /// @notice Grant `role` to `holder` (owner or an ADMIN).
    function grantRole(address holder, uint256 role) external {
        setRole(holder, role, true);
    }

    /// @notice Revoke `role` from `holder` (owner or an ADMIN). The last ADMIN cannot self-revoke.
    function revokeRole(address holder, uint256 role) external {
        setRole(holder, role, false);
    }

    /// @dev Authorize role changes for the owner or any ADMIN, and forbid removing the final ADMIN
    ///      (except by the owner, who can always recover).
    function _authorizeSetRole(address holder, uint256 role, bool active) internal view override {
        if (msg.sender != owner() && !hasRole(msg.sender, ADMIN)) revert EnumerableRolesUnauthorized();
        if (
            !active && role == ADMIN && msg.sender != owner() && hasRole(holder, ADMIN)
                && roleHolderCount(ADMIN) == 1
        ) revert LastAdmin();
    }

    // -- queries -------------------------------------------------------------
    function registryCount() external view returns (uint256) {
        return _s().registryCount;
    }

    function getRegistry(uint256 id) external view returns (Registry memory) {
        return _s().registries[id];
    }

    function registryIdByName(string calldata name) public view returns (uint256) {
        return _s().registryIdByName[keccak256(bytes(name))];
    }

    /// @notice recordId for `checksum` within a registry (0 if not anchored there).
    function recordIdForChecksum(uint256 registryId, string calldata checksum) external view returns (uint256) {
        return _s().recordIdByChecksum[registryId][keccak256(bytes(checksum))];
    }

    function versionCount(uint256 registryId, uint256 recordId) external view returns (uint256) {
        return _s().recordVersions[registryId][recordId].length;
    }

    function getRecord(uint256 registryId, uint256 recordId, uint256 index)
        external
        view
        returns (Record memory)
    {
        Record[] storage versions = _s().recordVersions[registryId][recordId];
        if (index >= versions.length) revert RecordNotFound(registryId, recordId, index);
        return versions[index];
    }

    function getLatestRecord(uint256 registryId, uint256 recordId) external view returns (Record memory) {
        Record[] storage versions = _s().recordVersions[registryId][recordId];
        if (versions.length == 0) revert RecordNotFound(registryId, recordId, 0);
        return versions[versions.length - 1];
    }

    function getRecordVersions(uint256 registryId, uint256 recordId) external view returns (Record[] memory) {
        return _s().recordVersions[registryId][recordId];
    }

    /// @notice Number of (registry, record) pairs anchoring `checksum` across all registries.
    function checksumRefCount(string calldata checksum) external view returns (uint256) {
        return _s().refsByChecksum[keccak256(bytes(checksum))].length;
    }

    /// @notice Up to `limit` (registry, record) refs anchoring `checksum` across registries.
    function queryByChecksum(string calldata checksum, uint256 limit)
        external
        view
        returns (RecordRef[] memory out)
    {
        RecordRef[] storage refs = _s().refsByChecksum[keccak256(bytes(checksum))];
        uint256 n = refs.length;
        if (limit < n) n = limit;
        out = new RecordRef[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = refs[i];
        }
    }

    // -- upgrade authority ---------------------------------------------------
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Prevent the owner slot from being re-initialized on an upgradeable deployment.
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }
}
