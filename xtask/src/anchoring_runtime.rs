//! Copies the contract runtimes `tempo-contracts` embeds from the contracts repo's build, or with
//! `--check` fails when one has gone stale. Each copy is a fork's payload, pinned by hash: a build
//! that differs is refused, and belongs to the next fork.

use crate::check_abi::find_workspace_root;
use alloy::primitives::{B256, keccak256};
use eyre::{Context, bail};
use std::path::PathBuf;
use tempo_contracts::anchoring::T12_ANCHORING_RUNTIME_HASH;

/// `layout/` build, embedded copy relative to the workspace root, and the copy's pinned hash.
const COPIES: &[(&str, &str, B256)] = &[(
    "anchoring.bin",
    "crates/contracts/src/t12_anchoring_runtime.bin",
    T12_ANCHORING_RUNTIME_HASH,
)];

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
        for (build, copy, pinned) in COPIES {
            let built = self.layout.join(build);
            let hex = std::fs::read_to_string(&built)
                .with_context(|| format!("failed reading {}", built.display()))?;
            let bytes = alloy::primitives::hex::decode(hex.trim())
                .with_context(|| format!("{} is not hex", built.display()))?;
            let hash = keccak256(&bytes);
            if hash != *pinned {
                bail!(
                    "{} hashes to {hash}, not the {pinned} that {copy} is pinned to",
                    built.display()
                );
            }

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
        Ok(())
    }
}
