// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console} from "forge-std/Script.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {AnchoringRegistry} from "../src/AnchoringRegistry.sol";

/// @dev Slice of the canonical CreateX factory (https://github.com/pcaversaccio/createx).
/// CREATE3 makes the proxy address depend only on the (guarded) salt, not the initcode.
interface ICreateX {
    struct Values {
        uint256 constructorAmount;
        uint256 initCallAmount;
    }

    function deployCreate3AndInit(
        bytes32 salt,
        bytes calldata initCode,
        bytes calldata data,
        Values calldata values
    ) external payable returns (address);
}

/// @notice Deploy AnchoringRegistry as a CREATE3 ERC-1967 proxy owned by a Safe.
///
/// A deployer EOA broadcasts; the Safe only becomes `owner` (UUPS upgrade authority) + ADMIN, so
/// upgrades and role changes are Safe transactions. Deploy and initialize happen atomically in
/// one tx (no uninitialized-proxy window), and the salt embeds the deployer address (CreateX
/// permissioned deploy protection), so only this deployer can claim the address — the same
/// deployer + salt yields the same address on every chain.
///
///   SAFE_ADDRESS=0x... forge script script/DeployAnchoringRegistry.s.sol \
///     --rpc-url $RPC --broadcast --account deployer
contract DeployAnchoringRegistry is Script {
    ICreateX constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function run() external {
        address safe = vm.envAddress("SAFE_ADDRESS"); // owner + ADMIN + upgrade authority
        address registrar = vm.envOr("REGISTRAR", safe);
        address statusUpdater = vm.envOr("STATUS_UPDATER", safe);

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        // salt = deployer (20B, sender-bound) | 0x00 (no cross-chain redeploy protection) | entropy.
        bytes32 salt = bytes32(abi.encodePacked(deployer, hex"00", bytes11("anchoring.1")));

        address impl = address(new AnchoringRegistry());
        address proxy = CREATEX.deployCreate3AndInit(
            salt,
            LibClone.initCodeERC1967(impl),
            abi.encodeCall(AnchoringRegistry.initialize, (safe, registrar, statusUpdater)),
            ICreateX.Values(0, 0)
        );
        vm.stopBroadcast();

        console.log("AnchoringRegistry impl :", impl);
        console.log("AnchoringRegistry proxy:", proxy);
        console.log("owner / admin (Safe)   :", safe);
    }
}
