//! The `gleisner learn` subcommand.
//!
//! Generates a sandbox profile from audit log observations. Implements
//! the `audit2allow` pattern: record a session with a permissive profile,
//! then analyze what was accessed to produce a minimal profile.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};
use gleisner_polis::learner::{LearnerConfig, ProfileLearner, format_profile_toml, format_summary};
use gleisner_polis::profile::resolve_profile;
use gleisner_scapes::audit::open_audit_log_reader;

/// Arguments for `gleisner learn`.
#[derive(Args)]
pub struct LearnArgs {
    /// Path to the JSONL audit log from `gleisner record`.
    #[arg(long, value_name = "PATH")]
    pub audit_log: PathBuf,

    /// Extend an existing profile instead of generating fresh (audit2allow mode).
    #[arg(long, value_name = "NAME")]
    pub base_profile: Option<String>,

    /// Output file for the generated TOML profile (default: stdout).
    #[arg(long, short, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Project directory for path classification (default: current directory).
    #[arg(long, value_name = "PATH")]
    pub project_dir: Option<PathBuf>,

    /// Name for the generated profile.
    #[arg(long, default_value = "learned")]
    pub name: String,

    /// Suppress summary, emit only TOML.
    #[arg(long)]
    pub quiet: bool,
}

/// Execute the learn command.
pub fn execute(args: LearnArgs) -> Result<()> {
    let project_dir = args
        .project_dir
        .unwrap_or_else(|| std::env::current_dir().expect("current dir"));

    let home_dir = directories::BaseDirs::new()
        .ok_or_else(|| eyre!("could not determine home directory"))?
        .home_dir()
        .to_path_buf();

    let base_profile = args
        .base_profile
        .map(|name| resolve_profile(&name))
        .transpose()?;

    let config = LearnerConfig {
        project_dir,
        home_dir,
        name: args.name,
        base_profile,
    };

    let mut learner = ProfileLearner::new(config);
    let mut reader = open_audit_log_reader(&args.audit_log)?;
    let mut malformed_count: u64 = 0;

    loop {
        match reader.next_event() {
            Ok(Some(event)) => learner.observe(&event),
            Ok(None) => break,
            Err(e) => {
                malformed_count += 1;
                eprintln!(
                    "warning: skipping malformed event at line {}: {e}",
                    reader.line_number()
                );
            }
        }
    }

    let (profile, summary) = learner.generate_profile();
    let toml_output =
        format_profile_toml(&profile).map_err(|e| eyre!("TOML serialization failed: {e}"))?;

    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &toml_output)?;
        if !args.quiet {
            eprintln!("Profile written to {}", output_path.display());
        }
    } else {
        print!("{toml_output}");
    }

    if !args.quiet {
        eprintln!();
        eprint!("{}", format_summary(&summary));
        if malformed_count > 0 {
            eprintln!("Malformed lines skipped: {malformed_count}");
        }
    }

    Ok(())
}
