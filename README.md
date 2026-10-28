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
  - Because money never leaves the TIP-20 domain, per-transaction fee token and amount are
    reconcilable from receipts alone.

- Native smart accounts (`0x76` transactions)

  - Atomic batching: one signature can anchor a batch of records.
  - Fee sponsorship: a service can pay the gas for the accounts anchoring into it.
  - Validity windows and 2D nonces: timed anchoring campaigns and parallel submission.
  - Passkeys via WebAuthn/P256 — biometric sign-in, secure enclave, cross-device use.

- Performance and finality

  - Built on the [Reth SDK](https://github.com/paradigmxyz/reth) for execution, state and
    `eth_*` RPC.
  - Simplex BFT via [Commonware](https://commonware.xyz/) drives ordering and finality in
    process — no Engine API hop, sub-second blocks and fast finality.

## What makes NVNMChain familiar

- Fully compatible with the Ethereum Virtual Machine (EVM), targeting the Osaka hardfork.
- Deploy and interact with smart contracts using Solidity, Foundry, Hardhat and the rest of
  the Ethereum toolchain.
- All Ethereum JSON-RPC methods work out of the box; anchoring adds its own namespace
  alongside them.

## Getting Started

Build the node, run a localnet, and point your tooling at it.

```bash
git clone https://github.com/NVNM-Chain/nvnmchain-tempo
cd nvnmchain-tempo
```

Install [`just`](https://github.com/casey/just?tab=readme-ov-file#packages), then the
dependencies:

```bash
just
```

Configure Git to run the repository hooks:

```bash
./scripts/setup-hooks.sh
```

Build:

```bash
just build-all
```

Run the tests:

```bash
cargo nextest run
```

Start a localnet:

```bash
just localnet
```

For a bootstrapped localnet container (deterministic accounts, prefunded TIP-20 tokens, Fee
AMM and DEX liquidity), see [`docs/localnet.md`](./docs/localnet.md).

### As an operator

Install from a pre-built release, build from source, or use the provided Docker image. Each
release ships `<binary>-<version>-<target>.tar.gz` plus `.sha256` (archive checksum) and
`.asc` (GPG signature), and is covered by Sigstore-signed SLSA build provenance.

To verify manually, pick **one** of the two paths below —

**Path A — offline / no GitHub auth required (checksum + GPG):**

```bash
TAG=v1.6.0
ARCHIVE=<binary>-${TAG}-x86_64-unknown-linux-gnu.tar.gz

gh release download "$TAG" --repo NVNM-Chain/nvnmchain-tempo \
  -p "$ARCHIVE" -p "$ARCHIVE.sha256" -p "$ARCHIVE.asc"

sha256sum -c "$ARCHIVE.sha256"

# Public key + fingerprint: see the release notes.
gpg --verify "$ARCHIVE.asc" "$ARCHIVE"
```

**Path B — Sigstore (requires `gh` installed and authenticated):**

```bash
TAG=v1.6.0
ARCHIVE=<binary>-${TAG}-x86_64-unknown-linux-gnu.tar.gz

gh release download "$TAG" --repo NVNM-Chain/nvnmchain-tempo -p "$ARCHIVE"
gh attestation verify "$ARCHIVE" --repo NVNM-Chain/nvnmchain-tempo \
  --predicate-type https://slsa.dev/provenance/v1
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
