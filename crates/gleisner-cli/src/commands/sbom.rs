//! The `gleisner sbom` subcommand.
//!
//! Generates a `CycloneDX` 1.5 Software Bill of Materials from Cargo.lock.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::Result;
use gleisner_bridger::sbom;

/// Arguments for `gleisner sbom`.
#[derive(Args)]
pub struct SbomArgs {
    /// Project directory to scan for Cargo.lock.
    /// Defaults to the current directory.
    #[arg(long, value_name = "PATH")]
    pub project_dir: Option<PathBuf>,

    /// Write output to a file instead of stdout.
    #[arg(long, short, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Output the full `CycloneDX` JSON instead of a summary.
    #[arg(long)]
    pub json: bool,
}

/// Execute the sbom command.
pub fn execute(args: &SbomArgs) -> Result<()> {
    let project_dir = args
        .project_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));

    let bom = sbom::generate(&project_dir)?;

    let output_text = if args.json {
        serde_json::to_string_pretty(&bom)?
    } else {
        format_summary(&bom)
    };

    if let Some(path) = &args.output {
        std::fs::write(path, &output_text)?;
        println!("SBOM written to {}", path.display());
    } else {
        println!("{output_text}");
    }

    Ok(())
}

/// Format a human-readable summary of the BOM.
fn format_summary(bom: &gleisner_bridger::cyclonedx::CycloneDxBom) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    writeln!(
        out,
        "CycloneDX {spec} SBOM — {count} components",
        spec = bom.spec_version,
        count = bom.components.len()
    )
    .ok();
    writeln!(out, "Serial: {}", bom.serial_number).ok();
    writeln!(out).ok();

    for comp in &bom.components {
        let hash_info = if comp.hashes.is_empty() {
            String::new()
        } else {
            format!(
                "  [{}]",
                &comp.hashes[0].content[..12.min(comp.hashes[0].content.len())]
            )
        };
        writeln!(
            out,
            "  {name} {ver}{hash_info}",
            name = comp.name,
            ver = comp.version
        )
        .ok();
    }

    out
}
