# Releasing

This repository is a fork of `tempoxyz/tempo`. The release, benchmark, and
publishing workflows that were wired to Tempo's own runners, secrets, and
registries have been removed. What is left targets this repository.

## What a tag produces

Pushing a tag matching `v*.*.*` triggers two workflows:

| Workflow | Artifacts |
| --- | --- |
| `release.yml` | `tempo` and `tempo-sidecar` archives for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, each with `.sha256`, SBOM, and build-provenance attestations |
| `docker.yml` | Multi-arch (`linux/amd64`, `linux/arm64`) images for `tempo`, `tempo-localnet`, `tempo-sidecar`, `tempo-xtask` in GHCR |

Both are also reachable via **Actions → workflow_dispatch**. `release.yml`
accepts `dry_run: true` to build the binaries without creating a release.

The release is created as a **draft**. Publishing it is a manual step.

## One-time repository setup

1. **Enable Actions.** Forks start with workflows disabled; open the Actions tab
   and accept the prompt if it appears.
2. **Workflow permissions.** Settings → Actions → General → Workflow
   permissions must be **Read and write**. The release workflow needs
   `contents: write` to create the release and push the version-bump branch.
3. **Tag protection** (optional). If main is protected, allow tags matching
   `v*`.
4. **GPG signing** (optional). Set `GPG_SIGNING_KEY` (base64-encoded armored
   private key) and `GPG_PASSPHRASE` as repository or `release` environment
   secrets. Without them the release still publishes, minus the `.asc`
   signature.
5. **GitHub Pages docs** (optional). Set the repository variable
   `ENABLE_DOCS_DEPLOY=true` and enable Pages to publish rustdoc from `main`.
6. **Package visibility.** After the first successful `docker.yml` run, set the
   four GHCR packages to public, or give each deployment target a read-scoped
   token.

No other secrets or repository variables are required for a binary/Docker
release. Registry credentials are supplied by `GITHUB_TOKEN`.

## Cutting a release

```bash
git checkout main && git pull
git tag vX.Y.Z
git push origin vX.Y.Z
```

`check-version` fails the run unless the tag matches the workspace version in
`Cargo.toml` (`[workspace.package] version`). To release a commit that is not
yet bumped, run **Release** from Actions with `dry_run: true` first, or push an
`rc/*` branch (which builds without creating a release).

The `bump-main-cargo-version` job opens a PR on `main` that sets the workspace
version to the released tag. PRs opened with `GITHUB_TOKEN` do not trigger other
workflows, so CI on that PR has to be started manually if you need it.

## Images

Images are published to `ghcr.io/<repository-owner>` — `ghcr.io/nvnm-chain`
for `NVNM-Chain/nvnmchain-tempo`. The namespace is derived from
`github.repository_owner` and lowercased automatically, so renaming the
organisation needs no workflow change.

Each architecture is built natively on its own runner (`ubuntu-latest` and
`ubuntu-24.04-arm`). QEMU is deliberately not used: `Dockerfile.chef` compiles
the whole reth dependency tree, which is not viable under emulation.

Because images are built on GitHub-hosted runners, no layer cache survives
between runs and every build recompiles from scratch. Adding a
`type=gha` cache backend to the bake invocation is the obvious follow-up if
build times become a problem.

## Known remaining coupling

Workflows still pin actions from `tempoxyz/gh-actions`, a public vendoring
repository (`vendor/dtolnay/rust-toolchain`, `vendor/mozilla-actions/sccache-action`,
`actions/setup-mold`, `vendor/anchore/sbom-action`, `vendor/docker/*`,
`vendor/sigstore/cosign-installer`, `actions/check-*`). These work for any
repository owner, but they are an external dependency: if that repository is
made private or deleted, the pins must be repointed at the upstream actions.

`rpc-tests.yml` and `test.yml` default to Tempo's public RPC endpoints
(`rpc.moderato.tempo.xyz`, `rpc.devnet.tempoxyz.dev`) when
`TEMPO_TESTNET_RPC_URL` / `TEMPO_DEVNET_RPC_URL` / `TEMPO_MAINNET_RPC_URL` are
unset.
