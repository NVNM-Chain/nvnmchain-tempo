// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {LibClone} from "solady/utils/LibClone.sol";
import {AnchoringRegistry} from "../../src/AnchoringRegistry.sol";

/// @notice One-shot deployer for local/e2e use: a single create tx deploys the impl + an ERC-1967
///         proxy and initializes it, granting the calling EOA all roles. Read the proxy from
///         `registry()`. Production uses CreateX + a Safe instead (see the deploy script).
contract AnchoringDeployer {
    AnchoringRegistry public immutable registry;

    constructor() {
        address caller = msg.sender; // the EOA that sent the create tx
        address impl = address(new AnchoringRegistry());
        AnchoringRegistry r = AnchoringRegistry(LibClone.deployERC1967(impl));
        r.initialize(caller, caller, caller);
        registry = r;
    }
}
