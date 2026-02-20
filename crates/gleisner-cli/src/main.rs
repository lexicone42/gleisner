//! Gleisner CLI — supply chain security for Claude Code.
//!
//! Sandbox Claude Code sessions, attest every action, verify provenance.
//! cosign test: 2026-02-20

mod commands;
mod config;

use clap::Parser;
use color_eyre::eyre::Result;

/// Gleisner — supply chain security for Claude Code.
///
/// Sandbox Claude Code sessions, attest every action, verify provenance.
/// Named after the Gleisner robots in Greg Egan's "Diaspora" — software
/// intelligence housed in constrained physical bodies.
#[derive(Parser)]
#[command(name = "gleisner", version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging (repeat for more detail: -v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Output logs as JSON (for machine consumption).
    #[arg(long, global = true)]
    json_logs: bool,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run Claude Code inside a Gleisner sandbox (isolation only, no attestation).
    Wrap(commands::wrap::WrapArgs),
    /// Run Claude Code inside a sandbox with full attestation recording.
    Record(commands::record::RecordArgs),
    /// Verify an attestation bundle's signatures, digests, and policies.
    Verify(commands::verify::VerifyArgs),
    /// Compare two attestation bundles and show what changed.
    Diff(commands::diff::DiffArgs),
    /// Display an attestation bundle in human-readable format.
    Inspect(commands::inspect::InspectArgs),
    /// Generate a Software Bill of Materials (`CycloneDX` 1.5).
    Sbom(commands::sbom::SbomArgs),
    /// Generate a sandbox profile from audit log observations.
    Learn(commands::learn::LearnArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    // Initialize tracing subscriber based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);

    if cli.json_logs {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    match cli.command {
        Commands::Wrap(args) => commands::wrap::execute(args).await,
        Commands::Record(args) => commands::record::execute(args).await,
        Commands::Diff(args) => commands::diff::execute(&args),
        Commands::Verify(args) => commands::verify::execute(args),
        Commands::Inspect(args) => commands::inspect::execute(&args),
        Commands::Sbom(args) => commands::sbom::execute(&args),
        Commands::Learn(args) => commands::learn::execute(args).await,
    }
}
