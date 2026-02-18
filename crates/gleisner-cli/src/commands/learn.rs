//! The `gleisner learn` subcommand.
//!
//! Generates a sandbox profile from audit log observations. Implements
//! the `audit2allow` pattern: record a session with a permissive profile,
//! then analyze what was accessed to produce a minimal profile.
//!
//! Supports two input sources (can be combined):
//! - **JSONL audit log** from `gleisner record` — captures successful
//!   file/network/process accesses observed by inotify and procmon.
//! - **Kernel audit log** — Landlock V7 denial records (type 1423) from
//!   audisp, capturing what the sandbox *blocked*.
//!
//! The kernel audit log is especially useful for iterative profile
//! tightening: run `gleisner wrap` with a profile, see what gets denied,
//! then widen the profile to allow what was actually needed.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};
use gleisner_polis::learner::{LearnerConfig, ProfileLearner, format_profile_toml, format_summary};
use gleisner_polis::profile::resolve_profile;

/// Arguments for `gleisner learn`.
#[derive(Args)]
pub struct LearnArgs {
    /// Path to the JSONL audit log from `gleisner record`.
    ///
    /// Contains file, network, and process events observed during a
    /// sandboxed session. At least one of `--audit-log` or
    /// `--kernel-audit-log` must be provided.
    #[arg(long, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,

    /// Path to a kernel audit log with Landlock V7 denial records.
    ///
    /// Contains `UNKNOWN[1423]`/`LANDLOCK_ACCESS` records from the
    /// kernel audit subsystem (typically routed by audisp to
    /// `/var/log/gleisner/landlock-audit.log`). Denial events widen
    /// the generated profile to allow what the sandbox blocked.
    #[arg(long, value_name = "PATH")]
    pub kernel_audit_log: Option<PathBuf>,

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
    if args.audit_log.is_none() && args.kernel_audit_log.is_none() {
        return Err(eyre!(
            "at least one of --audit-log or --kernel-audit-log must be provided"
        ));
    }

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
    let mut malformed_count: u64 = 0;

    // ── Ingest JSONL audit log (if provided) ────────────────────────
    if let Some(ref audit_log_path) = args.audit_log {
        let mut reader = gleisner_scapes::audit::open_audit_log_reader(audit_log_path)?;
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
    }

    // ── Ingest kernel audit log denials (if provided) ───────────────
    if let Some(ref kernel_log_path) = args.kernel_audit_log {
        let denial_events = gleisner_polis::parse_kernel_denials(kernel_log_path)
            .map_err(|e| eyre!("failed to read kernel audit log: {e}"))?;

        let denial_count = denial_events.len();
        for event in &denial_events {
            learner.observe(event);
        }

        if !args.quiet {
            eprintln!("Ingested {denial_count} denial event(s) from kernel audit log");
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
