//! Copies the anchoring runtime `tempo-contracts` embeds from the contracts repo's build; with
//! `--check`, fails when the copy has gone stale instead.

use crate::check_abi::find_workspace_root;
use eyre::{Context, bail};
use std::path::PathBuf;

/// The copy, relative to the workspace root: `layout/anchoring.bin` decoded.
const RUNTIME: &str = "crates/contracts/src/anchoring_runtime.bin";

#[derive(Debug, clap::Args)]
pub(crate) struct AnchoringRuntime {
    /// Path to the contracts repo's `layout/anchoring.bin`.
    #[arg(long)]
    layout: PathBuf,

    /// Fail if the copy is out of date, instead of rewriting it.
    #[arg(long)]
    check: bool,
}

impl AnchoringRuntime {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let hex = std::fs::read_to_string(&self.layout)
            .with_context(|| format!("failed reading {}", self.layout.display()))?;
        let built = alloy::primitives::hex::decode(hex.trim())
            .with_context(|| format!("{} is not hex", self.layout.display()))?;

        let copy = find_workspace_root()?.join(RUNTIME);
        if std::fs::read(&copy).is_ok_and(|current| current == built) {
            println!("{RUNTIME} is up to date with {}", self.layout.display());
            return Ok(());
        }
        if self.check {
            bail!(
                "{RUNTIME} is stale against {}; rerun without --check",
                self.layout.display()
            );
        }
        std::fs::write(&copy, built)
            .with_context(|| format!("failed writing {}", copy.display()))?;
        println!("wrote {RUNTIME} from {}", self.layout.display());
        Ok(())
    }
}
