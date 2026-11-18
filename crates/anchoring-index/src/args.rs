use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
#[command(next_help_heading = "Anchoring name index")]
pub struct AnchoringIndexArgs {
    /// Index the anchoring contract's registry names and serve
    /// `anchoring_searchRegistriesByName` from them. Off by default: the contract answers an
    /// exact name without it.
    #[arg(
        id = "anchoring.name-index",
        long = "anchoring.name-index",
        default_value_t = false
    )]
    pub enabled: bool,

    /// Where the index lives; a relative path resolves under the datadir. Deleting it costs
    /// a rebuild from the contract.
    // The field name alone is the id, and reth already has a `path`.
    #[arg(
        id = "anchoring.name-index.path",
        long = "anchoring.name-index.path",
        requires = "anchoring.name-index",
        value_name = "PATH"
    )]
    pub path: Option<PathBuf>,
}
