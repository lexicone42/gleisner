//! The `gleisner forge-diff` subcommand.
//!
//! Compares two forge attestation outputs and shows package-level changes.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};
use gleisner_forge::diff;

/// Compare two forge attestation outputs and show what changed.
///
/// Reports packages added/removed, source hash changes, and
/// verification status changes between two evaluation runs.
#[derive(Args)]
pub struct ForgeDiffArgs {
    /// Path to the "before" forge attestation JSON.
    pub before: PathBuf,

    /// Path to the "after" forge attestation JSON.
    pub after: PathBuf,

    /// Output as JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

/// Execute the forge-diff command.
pub fn execute(args: &ForgeDiffArgs) -> Result<()> {
    let before_str = std::fs::read_to_string(&args.before)
        .map_err(|e| eyre!("failed to read {}: {e}", args.before.display()))?;
    let after_str = std::fs::read_to_string(&args.after)
        .map_err(|e| eyre!("failed to read {}: {e}", args.after.display()))?;

    let before: serde_json::Value = serde_json::from_str(&before_str)
        .map_err(|e| eyre!("failed to parse {}: {e}", args.before.display()))?;
    let after: serde_json::Value = serde_json::from_str(&after_str)
        .map_err(|e| eyre!("failed to parse {}: {e}", args.after.display()))?;

    let result = diff::diff_attestations(&before, &after);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", diff::format_diff(&result));
    }

    Ok(())
}
