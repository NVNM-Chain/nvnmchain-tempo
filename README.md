# NVNMChain

A Layer 1, purpose-built blockchain for anchoring.

NVNMChain is an EVM Layer 1 built for one job: putting data commitments on-chain and proving
they are still there.

## What makes NVNMChain different

- Anchoring as a first-class primitive

  - The anchoring contract lives at a well-known address (`0x…0A00`).
  - Registries, ids and names are stored on-chain.

- No native gas token

  - Fees are paid in TIP-20 balances, so an anchoring workload costs a stablecoin balance
    rather than a speculative asset. The Fee AMM converts to the validator's preferred token.
  - Receipts name each transaction's fee token and fee payer; the fee is
    `gasUsed × effectiveGasPrice / 10^12` in that token's units, rounded up.

- Native smart accounts (`0x76` transactions)

  - Atomic batching: one signature can anchor a batch of records.
  - Fee sponsorship: a service can pay the gas for the accounts anchoring into it.
  - Validity windows and 2D nonces: timed anchoring campaigns and parallel submission.
  - Passkeys via WebAuthn/P256 — biometric sign-in, secure enclave, cross-device use.

- Performance and finality

  - Built on the [Reth SDK](https://github.com/paradigmxyz/reth) for execution, state and
    `eth_*` RPC.
  - Simplex BFT via [Commonware](https://commonware.xyz/) drives ordering and finality in
    process: Engine API calls go over a channel, not HTTP. Sub-second blocks and fast
    finality.

## What makes NVNMChain familiar

- Fully compatible with the Ethereum Virtual Machine (EVM), targeting the Osaka hardfork.
- Deploy and interact with smart contracts using Solidity, Foundry, Hardhat and the rest of
  the Ethereum toolchain.
- All Ethereum JSON-RPC methods work out of the box.

## Getting Started

```bash
git clone https://github.com/NVNM-Chain/nvnmchain-tempo
cd nvnmchain-tempo
```

Configure Git to run the repository hooks:

```bash
./scripts/setup-hooks.sh
```

Build:

```bash
cargo build --release --bin tempo
```

Run the tests:

```bash
cargo nextest run
```

Start a dev chain (chain id 1337, RPC at `http://127.0.0.1:8545`). It has no anchoring
contract.

```bash
./target/release/tempo node --dev --chain dev --dev.block-time 500ms --http
```

### As an operator

Install from a release or the Docker image `ghcr.io/nvnm-chain/tempo`. Releases are not
signed; check an archive against the release's `checksums.txt`:

```bash
TAG=v1.16.0-nvnm.1
gh release download "$TAG" --repo NVNM-Chain/nvnmchain-tempo \
  -p "tempo-${TAG}-x86_64-unknown-linux-gnu.tar.gz" -p checksums.txt
sha256sum -c --ignore-missing checksums.txt
```

Genesis-time import is a separate path: `init-from-binary-dump <file>` with an optional
`--sha256` verified **before the database is opened**.

## Contributing

See [`tips/tip-0000.md`](./tips/tip-0000.md) for the proposal process, and
[`AGENTS.md`](./AGENTS.md) for repository conventions. Format Rust code with
`cargo +nightly fmt`.

## Security

See [`SECURITY.md`](./SECURITY.md). Report vulnerabilities privately; do not open a public
issue. NVNMChain is still undergoing audit and has no active bug bounty.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
