//! Copies the contract runtimes `tempo-contracts` embeds from the contracts repo's build, or with
//! `--check` fails when one has gone stale. Each copy is a fork's payload, pinned by hash: a build
//! that differs is refused, and belongs to the next fork. The implementation and its address are
//! only checked: the chain deploys it.

use crate::check_abi::find_workspace_root;
use alloy::primitives::{B256, keccak256};
use eyre::{Context, bail};
use std::path::{Path, PathBuf};
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS,
    anchoring::{
        T12_ANCHORING_IMPLEMENTATION, T12_ANCHORING_IMPLEMENTATION_HASH,
        T12_ANCHORING_PROXY_RUNTIME_HASH,
    },
};

/// `layout/` build, its embedded copy relative to the workspace root, if any, and its pinned hash.
const BUILDS: &[(&str, Option<&str>, B256)] = &[
    (
        "proxy.bin",
        Some("crates/contracts/src/t12_anchoring_proxy.bin"),
        T12_ANCHORING_PROXY_RUNTIME_HASH,
    ),
    ("anchoring.bin", None, T12_ANCHORING_IMPLEMENTATION_HASH),
];

#[derive(Debug, clap::Args)]
pub(crate) struct AnchoringRuntime {
    /// Path to the contracts repo's `layout/` directory.
    #[arg(long)]
    layout: PathBuf,

    /// Fail if a copy is out of date, instead of rewriting it.
    #[arg(long)]
    check: bool,
}

impl AnchoringRuntime {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let root = find_workspace_root()?;
        for (build, copy, pinned) in BUILDS {
            let built = self.layout.join(build);
            let bytes = read_hex(&built)?;
            let hash = keccak256(&bytes);
            if hash != *pinned {
                bail!(
                    "{} hashes to {hash}, not the pinned {pinned}",
                    built.display()
                );
            }
            let Some(copy) = copy else {
                println!("{} is the pinned build", built.display());
                continue;
            };

            let copy_path = root.join(copy);
            if std::fs::read(&copy_path).is_ok_and(|current| current == bytes) {
                println!("{copy} is up to date with {}", built.display());
                continue;
            }
            if self.check {
                bail!(
                    "{copy} is stale against {}; rerun without --check",
                    built.display()
                );
            }
            std::fs::write(&copy_path, bytes)
                .with_context(|| format!("failed writing {}", copy_path.display()))?;
            println!("wrote {copy} from {}", built.display());
        }

        let init = self.layout.join("anchoring.init.bin");
        let deployed =
            ARACHNID_CREATE2_FACTORY_ADDRESS.create2_from_code(B256::ZERO, read_hex(&init)?);
        if deployed != T12_ANCHORING_IMPLEMENTATION {
            bail!(
                "{} deploys to {deployed}, not the pinned {T12_ANCHORING_IMPLEMENTATION}",
                init.display()
            );
        }
        println!("{} deploys to the pinned address", init.display());
        Ok(())
    }
}

fn read_hex(path: &Path) -> eyre::Result<Vec<u8>> {
    let hex = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading {}", path.display()))?;
    alloy::primitives::hex::decode(hex.trim())
        .with_context(|| format!("{} is not hex", path.display()))
}
