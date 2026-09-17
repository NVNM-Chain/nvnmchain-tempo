//! Copies the contract runtimes `tempo-contracts` embeds from the contracts repo's build, or with
//! `--check` fails when one has gone stale.

use crate::check_abi::find_workspace_root;
use eyre::{Context, bail};
use std::path::PathBuf;

/// Each `layout/` build and the copy of it this binary embeds, relative to the workspace root.
const COPIES: &[(&str, &str)] = &[
    (
        "anchoring.bin",
        "crates/contracts/src/anchoring_runtime.bin",
    ),
    (
        "module-admin-multisig.bin",
        "crates/contracts/src/module_admin_runtime.bin",
    ),
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
        for (build, copy) in COPIES {
            let built = self.layout.join(build);
            let hex = std::fs::read_to_string(&built)
                .with_context(|| format!("failed reading {}", built.display()))?;
            let bytes = alloy::primitives::hex::decode(hex.trim())
                .with_context(|| format!("{} is not hex", built.display()))?;

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
