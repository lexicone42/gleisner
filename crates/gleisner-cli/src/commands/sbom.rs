//! The `gleisner sbom` subcommand.
//!
//! Generates a `CycloneDX` Software Bill of Materials.
//!
//! Two modes:
//! - **Cargo mode** (default): scans `Cargo.lock` → `CycloneDX` 1.6
//! - **Forge mode** (`--forge <path>`): reads forge attestation JSON →
//!   `CycloneDX` 1.6 with proof-carrying declarations

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};
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

    /// Path to a forge composed-env.json to include minimal.dev package
    /// metadata and proof declarations in the SBOM.
    /// Produces `CycloneDX` 1.6 output with formal verification evidence.
    #[arg(long, value_name = "PATH")]
    pub forge: Option<PathBuf>,
}

/// Execute the sbom command.
pub fn execute(args: &SbomArgs) -> Result<()> {
    let project_dir = args
        .project_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));

    if let Some(forge_path) = &args.forge {
        return execute_forge(args, forge_path);
    }

    let bom = sbom::generate(&project_dir)?;

    let output_text = if args.json {
        serde_json::to_string_pretty(&bom)?
    } else {
        format_cargo_summary(&bom)
    };

    if let Some(path) = &args.output {
        std::fs::write(path, &output_text)?;
        println!("SBOM written to {}", path.display());
    } else {
        println!("{output_text}");
    }

    Ok(())
}

/// Execute forge-mode SBOM generation.
///
/// Reads a composed-env.json (output of `gleisner forge`), extracts the
/// attestation data, and generates a CycloneDX 1.6 SBOM with proof
/// declarations.
fn execute_forge(args: &SbomArgs, forge_path: &PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(forge_path).map_err(|e| {
        eyre!(
            "failed to read forge output at {}: {e}",
            forge_path.display()
        )
    })?;

    let full_json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| eyre!("invalid JSON in {}: {e}", forge_path.display()))?;

    let attestation_json = full_json
        .get("attestation")
        .ok_or_else(|| eyre!("no 'attestation' field in {}", forge_path.display()))?;

    let attestation: gleisner_forge::attest::ForgeAttestation =
        serde_json::from_value(attestation_json.clone())
            .map_err(|e| eyre!("failed to parse attestation: {e}"))?;

    let bom = gleisner_forge::sbom::forge_to_cyclonedx(&attestation);

    let output_text = if args.json {
        serde_json::to_string_pretty(&bom)?
    } else {
        format_forge_summary(&bom)
    };

    if let Some(path) = &args.output {
        std::fs::write(path, &output_text)?;
        println!("SBOM written to {}", path.display());
    } else {
        println!("{output_text}");
    }

    Ok(())
}

/// Format a human-readable summary of a Cargo BOM.
fn format_cargo_summary(bom: &gleisner_bridger::cyclonedx::CycloneDxBom) -> String {
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

/// Format a human-readable summary of a forge SBOM.
fn format_forge_summary(bom: &gleisner_forge::sbom::CycloneDxBom) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    writeln!(
        out,
        "CycloneDX {spec} SBOM — {count} components (minimal.dev packages)",
        spec = bom.spec_version,
        count = bom.components.len()
    )
    .ok();
    writeln!(out, "Serial: {}", bom.serial_number).ok();
    writeln!(out).ok();

    for comp in &bom.components {
        let version = comp.version.as_deref().unwrap_or("(no version)");
        let purl = comp.purl.as_deref().unwrap_or("");

        let proof_info = comp
            .properties
            .iter()
            .find(|p| p.name == "cdx:forge:verified-properties")
            .map(|p| format!("  [proofs: {}]", p.value))
            .unwrap_or_default();

        writeln!(out, "  {name} {version}{proof_info}", name = comp.name).ok();
        if !purl.is_empty() {
            writeln!(out, "    {purl}").ok();
        }
    }

    if let Some(decl) = &bom.declarations {
        writeln!(out).ok();
        let claim_count: usize = decl.attestations.iter().map(|a| a.map.len()).sum();
        let verified_count = decl
            .attestations
            .iter()
            .flat_map(|a| &a.map)
            .filter(|c| c.conformance.score == 1.0)
            .count();
        writeln!(
            out,
            "Formal verification: {verified_count}/{claim_count} properties verified"
        )
        .ok();
        for att in &decl.attestations {
            for claim in &att.map {
                let status = if claim.conformance.score == 1.0 {
                    "VERIFIED"
                } else {
                    "unchecked"
                };
                writeln!(out, "  [{status}] {}", claim.requirement).ok();
            }
        }
    }

    out
}
