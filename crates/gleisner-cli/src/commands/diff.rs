//! The `gleisner diff` subcommand.
//!
//! Compares two attestation bundles and shows what changed.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::Result;
use gleisner_lacerta::diff;

/// Compare two attestation bundles and show what changed.
///
/// Reports differences in subjects (output files), materials (inputs),
/// environment configuration, and session timing.
#[derive(Args)]
pub struct DiffArgs {
    /// Path to the "before" attestation bundle.
    pub before: PathBuf,

    /// Path to the "after" attestation bundle.
    pub after: PathBuf,

    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Execute the diff command.
pub fn execute(args: &DiffArgs) -> Result<()> {
    let before_json = std::fs::read_to_string(&args.before)?;
    let after_json = std::fs::read_to_string(&args.after)?;

    let result = diff::diff_bundles(&before_json, &after_json)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", diff::format_diff(&result));
    }

    Ok(())
}
