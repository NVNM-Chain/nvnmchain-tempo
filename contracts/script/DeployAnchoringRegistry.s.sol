// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console} from "forge-std/Script.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {AnchoringRegistry} from "../src/AnchoringRegistry.sol";

/// @dev Slice of the canonical CreateX factory (https://github.com/pcaversaccio/createx). CREATE3
/// makes the proxy address depend only on `salt`, so the registry lands at the same address on
/// every chain where CreateX is deployed.
interface ICreateX {
    function deployCreate3(bytes32 salt, bytes calldata initCode) external payable returns (address);
}

/// @notice Deploy AnchoringRegistry as a CREATE3 ERC-1967 proxy owned by a Safe.
///
/// The Safe becomes `owner` (UUPS upgrade authority) + ADMIN, so upgrades and role changes are
/// Safe transactions. Set `SAFE_ADDRESS`; optionally `REGISTRAR` / `STATUS_UPDATER` / `SALT`.
///
///   forge script script/DeployAnchoringRegistry.s.sol --rpc-url $RPC --broadcast --sender $SAFE
contract DeployAnchoringRegistry is Script {
    ICreateX constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function run() external {
        address safe = vm.envAddress("SAFE_ADDRESS"); // owner + ADMIN + upgrade authority
        address registrar = vm.envOr("REGISTRAR", safe);
        address statusUpdater = vm.envOr("STATUS_UPDATER", safe);
        bytes32 salt = vm.envOr("SALT", keccak256("nvm.anchoring.registry.v1"));

        vm.startBroadcast();
        // 1. Implementation (logic only; its own initializers are disabled in the constructor).
        address impl = address(new AnchoringRegistry());
        // 2. Deterministic ERC-1967 proxy via CreateX CREATE3.
        address proxy = CREATEX.deployCreate3(salt, LibClone.initCodeERC1967(impl));
        // 3. Initialize behind the proxy: the Safe becomes owner + ADMIN.
        AnchoringRegistry(proxy).initialize(safe, registrar, statusUpdater);
        vm.stopBroadcast();

        console.log("AnchoringRegistry impl :", impl);
        console.log("AnchoringRegistry proxy:", proxy);
        console.log("owner / admin (Safe)   :", safe);
    }
}
