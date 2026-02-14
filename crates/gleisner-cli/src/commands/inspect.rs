//! The `gleisner inspect` subcommand.
//!
//! Displays an attestation bundle in human-readable format.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::Result;
use gleisner_lacerta::inspect;

/// Arguments for `gleisner inspect`.
#[derive(Args)]
pub struct InspectArgs {
    /// Path to the attestation bundle JSON file.
    pub bundle: PathBuf,

    /// Show all subjects, materials, and verification material.
    #[arg(long)]
    pub detailed: bool,

    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Execute the inspect command.
pub fn execute(args: &InspectArgs) -> Result<()> {
    let bundle_json = std::fs::read_to_string(&args.bundle)?;

    if args.json {
        // Parse and re-emit as pretty JSON
        let bundle: serde_json::Value = serde_json::from_str(&bundle_json)?;

        // Also parse the payload for structured output
        let payload_str = bundle
            .get("payload")
            .and_then(|p| p.as_str())
            .unwrap_or("{}");
        let payload: serde_json::Value = serde_json::from_str(payload_str)?;

        let output = serde_json::json!({
            "payload": payload,
            "signature": bundle.get("signature"),
            "verification_material": bundle.get("verification_material"),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if args.detailed {
        let output = inspect::format_detailed(&bundle_json)?;
        print!("{output}");
    } else {
        let summary = inspect::summarize(&bundle_json)?;
        let output = inspect::format_summary(&summary);
        print!("{output}");
    }

    Ok(())
}
