// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {EnumerableRoles} from "solady/auth/EnumerableRoles.sol";
import {AnchoringRegistry} from "../src/AnchoringRegistry.sol";

/// @dev A trivial V2 to prove upgrades preserve storage and swap logic.
contract AnchoringRegistryV2 is AnchoringRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract AnchoringRegistryTest is Test {
    AnchoringRegistry reg;

    // Mirror the contract's role ids as locals so tests never inject an extra
    // external `reg.ROLE()` call that would consume a pending prank/expectRevert.
    uint256 constant ADMIN = 1;
    uint256 constant REGISTRAR = 2;
    uint256 constant STATUS_UPDATER = 3;

    address owner = makeAddr("safe"); // Safe multisig stand-in: owner + ADMIN
    address registrar = makeAddr("registrar");
    address statusUpdater = makeAddr("statusUpdater");
    address stranger = makeAddr("stranger");

    function setUp() public {
        address impl = address(new AnchoringRegistry());
        reg = AnchoringRegistry(LibClone.deployERC1967(impl));
        reg.initialize(owner, registrar, statusUpdater);
    }

    // -- registries ----------------------------------------------------------
    function test_addRegistry() public {
        vm.prank(registrar);
        uint256 id = reg.addRegistry("docs", "document registry", "{}");
        assertEq(id, 1);
        assertEq(reg.registryCount(), 1);
        assertEq(reg.registryIdByName("docs"), 1);

        AnchoringRegistry.Registry memory r = reg.getRegistry(1);
        assertEq(r.name, "docs");
        assertEq(r.description, "document registry");
        assertEq(r.creator, registrar);
        assertEq(r.metadata, "{}");
    }

    function test_addRegistry_duplicateNameReverts() public {
        vm.startPrank(registrar);
        reg.addRegistry("docs", "", "");
        vm.expectRevert(abi.encodeWithSelector(AnchoringRegistry.RegistryExists.selector, "docs"));
        reg.addRegistry("docs", "", "");
        vm.stopPrank();
    }

    function test_addRegistry_emptyNameReverts() public {
        vm.prank(registrar);
        vm.expectRevert(AnchoringRegistry.EmptyName.selector);
        reg.addRegistry("", "", "");
    }

    function test_addRegistry_unauthorizedReverts() public {
        vm.prank(stranger);
        vm.expectRevert(EnumerableRoles.EnumerableRolesUnauthorized.selector);
        reg.addRegistry("docs", "", "");
    }

    function test_owner_canActWithoutExplicitRole() public {
        // owner has ADMIN but not REGISTRAR; onlyOwnerOrRole still admits the owner.
        vm.prank(owner);
        uint256 id = reg.addRegistry("owned", "", "");
        assertEq(id, 1);
    }

    // -- records -------------------------------------------------------------
    function _seedRegistry(string memory name) internal {
        vm.prank(registrar);
        reg.addRegistry(name, "", "");
    }

    function test_addRecord() public {
        _seedRegistry("docs");
        vm.prank(registrar);
        (uint256 recordId, uint256 index) = reg.addRecord("docs", "ipfs://a", "0xabc", "SHA-256", "{}");
        assertEq(recordId, 1);
        assertEq(index, 0);

        AnchoringRegistry.Record memory rec = reg.getRecord(1, 1, 0);
        assertEq(rec.uri, "ipfs://a");
        assertEq(rec.checksum, "0xabc");
        assertEq(rec.checksumAlgo, "SHA-256");
        assertEq(rec.status, "active");
        assertTrue(rec.isLatest);
        assertEq(reg.versionCount(1, 1), 1);
    }

    function test_addRecord_unknownRegistryReverts() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(AnchoringRegistry.RegistryNotFound.selector, "nope"));
        reg.addRecord("nope", "ipfs://a", "0xabc", "SHA-256", "");
    }

    function test_addRecord_emptyChecksumReverts() public {
        _seedRegistry("docs");
        vm.prank(registrar);
        vm.expectRevert(AnchoringRegistry.EmptyChecksum.selector);
        reg.addRecord("docs", "ipfs://a", "", "SHA-256", "");
    }

    function test_sameChecksum_maintainsRecordIdAndVersions() public {
        _seedRegistry("docs");
        vm.startPrank(registrar);
        (uint256 id0, uint256 i0) = reg.addRecord("docs", "ipfs://v1", "0xabc", "SHA-256", "");
        (uint256 id1, uint256 i1) = reg.addRecord("docs", "ipfs://v2", "0xabc", "SHA-256", "");
        vm.stopPrank();

        assertEq(id0, id1, "same checksum keeps recordId");
        assertEq(i0, 0);
        assertEq(i1, 1);
        assertEq(reg.versionCount(1, 1), 2);

        assertFalse(reg.getRecord(1, 1, 0).isLatest, "old version demoted");
        assertTrue(reg.getRecord(1, 1, 1).isLatest, "new version is latest");
        assertEq(reg.getLatestRecord(1, 1).uri, "ipfs://v2");
    }

    function test_differentChecksum_incrementsRecordId() public {
        _seedRegistry("docs");
        vm.startPrank(registrar);
        (uint256 id0,) = reg.addRecord("docs", "ipfs://a", "0xaaa", "SHA-256", "");
        (uint256 id1,) = reg.addRecord("docs", "ipfs://b", "0xbbb", "SHA-256", "");
        vm.stopPrank();
        assertEq(id0, 1);
        assertEq(id1, 2);
    }

    function test_perRegistry_recordIdIsolation_andCrossRegistryRefs() public {
        _seedRegistry("regA");
        _seedRegistry("regB");
        vm.startPrank(registrar);
        (uint256 idA,) = reg.addRecord("regA", "ipfs://a", "0xshared", "SHA-256", "");
        (uint256 idB,) = reg.addRecord("regB", "ipfs://b", "0xshared", "SHA-256", "");
        vm.stopPrank();

        // Independent per-registry recordId sequences (both start at 1).
        assertEq(idA, 1);
        assertEq(idB, 1);
        assertEq(reg.recordIdForChecksum(1, "0xshared"), 1);
        assertEq(reg.recordIdForChecksum(2, "0xshared"), 1);
        // But two distinct (registry, record) refs share the checksum.
        assertEq(reg.checksumRefCount("0xshared"), 2);
    }

    function test_queryByChecksum_respectsLimit() public {
        _seedRegistry("r1");
        _seedRegistry("r2");
        _seedRegistry("r3");
        vm.startPrank(registrar);
        reg.addRecord("r1", "ipfs://1", "0xshared", "SHA-256", "");
        reg.addRecord("r2", "ipfs://2", "0xshared", "SHA-256", "");
        reg.addRecord("r3", "ipfs://3", "0xshared", "SHA-256", "");
        vm.stopPrank();

        assertEq(reg.checksumRefCount("0xshared"), 3);
        assertEq(reg.queryByChecksum("0xshared", 2).length, 2);
        assertEq(reg.queryByChecksum("0xshared", 10).length, 3);
    }

    // -- status --------------------------------------------------------------
    function test_updateRecordStatus() public {
        _seedRegistry("docs");
        vm.prank(registrar);
        reg.addRecord("docs", "ipfs://a", "0xabc", "SHA-256", "");

        vm.prank(statusUpdater);
        reg.updateRecordStatus(1, 1, 0, "redacted");
        assertEq(reg.getRecord(1, 1, 0).status, "redacted");
    }

    function test_updateRecordStatus_unauthorizedReverts() public {
        _seedRegistry("docs");
        vm.prank(registrar);
        reg.addRecord("docs", "ipfs://a", "0xabc", "SHA-256", "");

        vm.prank(registrar); // has REGISTRAR, not STATUS_UPDATER
        vm.expectRevert(EnumerableRoles.EnumerableRolesUnauthorized.selector);
        reg.updateRecordStatus(1, 1, 0, "redacted");
    }

    function test_updateRecordStatus_badIndexReverts() public {
        _seedRegistry("docs");
        vm.prank(registrar);
        reg.addRecord("docs", "ipfs://a", "0xabc", "SHA-256", "");
        vm.prank(statusUpdater);
        vm.expectRevert(abi.encodeWithSelector(AnchoringRegistry.RecordNotFound.selector, uint256(1), uint256(1), uint256(5)));
        reg.updateRecordStatus(1, 1, 5, "redacted");
    }

    // -- roles ---------------------------------------------------------------
    function test_grantRole_lets_newRegistrarAdd() public {
        vm.prank(owner);
        reg.grantRole(stranger, REGISTRAR);
        assertTrue(reg.hasRole(stranger, REGISTRAR));

        vm.prank(stranger);
        uint256 id = reg.addRegistry("docs", "", "");
        assertEq(id, 1);
    }

    function test_admin_canGrantRoles() public {
        // owner promotes alice to ADMIN; alice then grants REGISTRAR to bob.
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        vm.prank(owner);
        reg.grantRole(alice, ADMIN);

        vm.prank(alice);
        reg.grantRole(bob, REGISTRAR);
        assertTrue(reg.hasRole(bob, REGISTRAR));
    }

    function test_nonAdmin_cannotGrantRoles() public {
        vm.prank(stranger);
        vm.expectRevert(EnumerableRoles.EnumerableRolesUnauthorized.selector);
        reg.grantRole(stranger, REGISTRAR);
    }

    function test_invalidRoleReverts() public {
        vm.prank(owner);
        vm.expectRevert(EnumerableRoles.InvalidRole.selector);
        reg.grantRole(stranger, 42);
    }

    function test_lastAdmin_cannotSelfRevoke_butOwnerCanRecover() public {
        address alice = makeAddr("alice");
        vm.startPrank(owner);
        reg.grantRole(alice, ADMIN); // ADMIN holders: owner, alice (count 2)
        reg.revokeRole(owner, ADMIN); // owner drops own ADMIN -> alice is sole ADMIN
        vm.stopPrank();
        assertEq(reg.roleHolderCount(ADMIN), 1);

        // alice, the last admin, cannot self-revoke.
        vm.prank(alice);
        vm.expectRevert(AnchoringRegistry.LastAdmin.selector);
        reg.revokeRole(alice, ADMIN);

        // owner (emergency authority) can force-remove and re-grant.
        vm.startPrank(owner);
        reg.revokeRole(alice, ADMIN);
        assertEq(reg.roleHolderCount(ADMIN), 0);
        address bob = makeAddr("bob");
        reg.grantRole(bob, ADMIN);
        vm.stopPrank();
        assertTrue(reg.hasRole(bob, ADMIN));
    }

    // -- lifecycle -----------------------------------------------------------
    function test_initialize_onlyOnce() public {
        vm.expectRevert(); // Initializable: InvalidInitialization
        reg.initialize(owner, registrar, statusUpdater);
    }

    function test_upgrade_preservesStorage_onlyOwner() public {
        _seedRegistry("docs");
        vm.prank(registrar);
        reg.addRecord("docs", "ipfs://a", "0xabc", "SHA-256", "");

        address v2 = address(new AnchoringRegistryV2());

        // Non-owner cannot upgrade.
        vm.prank(stranger);
        vm.expectRevert(); // Ownable.Unauthorized
        reg.upgradeToAndCall(v2, "");

        // Owner upgrades; storage survives and new logic is live.
        vm.prank(owner);
        reg.upgradeToAndCall(v2, "");
        assertEq(AnchoringRegistryV2(address(reg)).version(), 2);
        assertEq(reg.getRecord(1, 1, 0).uri, "ipfs://a");
        assertEq(reg.registryIdByName("docs"), 1);
    }
}
