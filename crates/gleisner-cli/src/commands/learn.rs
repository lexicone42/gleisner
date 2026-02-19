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
//!
//! **Watch mode** (`--watch`) tails the kernel audit log in real-time,
//! showing denials as they happen and emitting an updated profile on exit.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

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
    /// `--kernel-audit-log` must be provided (unless `--watch` is used).
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

    /// Watch the kernel audit log in real-time, showing denials as they happen.
    ///
    /// Tails the kernel audit log file (like `tail -f`), ingesting new
    /// Landlock denial records as they appear. Press Ctrl+C to stop
    /// watching and emit the final profile.
    ///
    /// Requires `--kernel-audit-log`. Conflicts with `--audit-log`.
    #[arg(long, conflicts_with = "audit_log")]
    pub watch: bool,

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
pub async fn execute(args: LearnArgs) -> Result<()> {
    if args.watch {
        #[cfg(target_os = "linux")]
        return watch_loop(args).await;
        #[cfg(not(target_os = "linux"))]
        return Err(eyre!("--watch requires Linux (Landlock V7 audit records)"));
    }

    if args.audit_log.is_none() && args.kernel_audit_log.is_none() {
        return Err(eyre!(
            "at least one of --audit-log or --kernel-audit-log must be provided"
        ));
    }

    let project_dir = match args.project_dir {
        Some(d) => d,
        None => std::env::current_dir().map_err(|e| {
            eyre!("--project-dir not specified and current directory is inaccessible: {e}")
        })?,
    };

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
    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    if args.kernel_audit_log.is_some() {
        return Err(eyre!(
            "--kernel-audit-log requires Linux (Landlock V7 audit records)"
        ));
    }

    emit_profile(&learner, &args.output, args.quiet, malformed_count)
}

/// Emit profile and summary from the learner's current state.
fn emit_profile(
    learner: &ProfileLearner,
    output: &Option<PathBuf>,
    quiet: bool,
    malformed_count: u64,
) -> Result<()> {
    let (profile, summary) = learner.generate_profile();
    let toml_output =
        format_profile_toml(&profile).map_err(|e| eyre!("TOML serialization failed: {e}"))?;

    if let Some(output_path) = output {
        // Atomic write: write to .tmp, then rename
        let tmp_path = output_path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, &toml_output)?;
        std::fs::rename(&tmp_path, output_path)?;
        if !quiet {
            eprintln!("Profile written to {}", output_path.display());
        }
    } else {
        print!("{toml_output}");
    }

    if !quiet {
        eprintln!();
        eprint!("{}", format_summary(&summary));
        if malformed_count > 0 {
            eprintln!("Malformed lines skipped: {malformed_count}");
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
/// Watch mode: tail the kernel audit log in real-time.
///
/// Opens the kernel audit log, seeks to end, and polls for new lines.
/// Each Landlock denial is parsed, fed to the learner, and printed to
/// stderr. On Ctrl+C, emits the final profile.
async fn watch_loop(args: LearnArgs) -> Result<()> {
    let kernel_log_path = args
        .kernel_audit_log
        .as_ref()
        .ok_or_else(|| eyre!("--watch requires --kernel-audit-log"))?;

    let project_dir = match args.project_dir {
        Some(d) => d,
        None => std::env::current_dir().map_err(|e| {
            eyre!("--project-dir not specified and current directory is inaccessible: {e}")
        })?,
    };

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
        name: args.name.clone(),
        base_profile,
    };

    let mut learner = ProfileLearner::new(config);
    let output = args.output.clone();
    let quiet = args.quiet;

    if !quiet {
        eprintln!(
            "Watching {} for Landlock denials...",
            kernel_log_path.display()
        );
        eprintln!("Press Ctrl+C to stop and emit profile.\n");
    }

    // Channel for raw lines from the tailing thread
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TailEvent>(256);
    let log_path = kernel_log_path.clone();

    let tail_handle = tokio::task::spawn_blocking(move || tail_file(&log_path, &tx));

    let mut total_denials: u64 = 0;
    let mut new_entries: u64 = 0;
    let mut last_write: Option<Instant> = None;
    let debounce = Duration::from_secs(2);
    let start = Instant::now();

    loop {
        // Debounced file output: if we have pending changes and enough time has passed
        let timeout = if output.is_some() && new_entries > 0 {
            if let Some(lw) = last_write {
                debounce.saturating_sub(lw.elapsed())
            } else {
                debounce
            }
        } else {
            Duration::from_secs(3600) // effectively infinite
        };

        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(TailEvent::Line(raw_line)) => {
                        if let Some(denial) = gleisner_polis::parse_audit_line(&raw_line) {
                            let events = gleisner_polis::denial_to_events(&denial);
                            let before = count_learned_paths(&learner);
                            for ev in &events {
                                learner.observe(ev);
                            }
                            let after = count_learned_paths(&learner);

                            total_denials += events.len() as u64;

                            if !quiet {
                                let elapsed = start.elapsed();
                                let mins = elapsed.as_secs() / 60;
                                let secs = elapsed.as_secs() % 60;

                                for ev in &events {
                                    let desc = format_denial_event(ev);
                                    let status = if after > before {
                                        new_entries += (after - before) as u64;
                                        "new"
                                    } else {
                                        "covered"
                                    };
                                    eprintln!("  [{mins:02}:{secs:02}] {desc} ({status})");
                                }
                            }

                            last_write = Some(Instant::now());
                        }
                    }
                    Some(TailEvent::Error(e)) => {
                        eprintln!("  [error] {e}");
                    }
                    None => break, // Channel closed (tailer exited)
                }
            }
            () = tokio::time::sleep(timeout) => {
                // Debounce timer fired — write intermediate profile
                if let Some(ref out_path) = output {
                    if matches!(emit_profile(&learner, &output, true, 0), Ok(()))
                        && !quiet {
                            eprintln!("  [updated] {}", out_path.display());
                        }
                }
                last_write = None;
                new_entries = 0;
            }
            _ = tokio::signal::ctrl_c() => {
                if !quiet {
                    eprintln!();
                }
                break;
            }
        }
    }

    // Clean up tailer
    drop(rx);
    let _ = tail_handle.await;

    if !quiet {
        eprintln!("Summary: {total_denials} denial(s), {new_entries} new profile entry/entries");
    }

    emit_profile(&learner, &output, quiet, 0)
}

#[cfg(target_os = "linux")]
/// Events from the file-tailing thread.
enum TailEvent {
    /// A raw line read from the file.
    Line(String),
    /// An error reading the file.
    Error(String),
}

#[cfg(target_os = "linux")]
/// Count total learned paths for change detection.
fn count_learned_paths(learner: &ProfileLearner) -> usize {
    let (_, summary) = learner.generate_profile();
    summary.path_groups.home_readonly.len()
        + summary.path_groups.home_readwrite.len()
        + summary.path_groups.other_readonly.len()
        + summary.path_groups.other_readwrite.len()
        + summary.path_groups.claude_dirs.len()
}

#[cfg(target_os = "linux")]
/// Format a denial event for stderr output.
fn format_denial_event(event: &gleisner_scapes::audit::AuditEvent) -> String {
    use gleisner_scapes::audit::EventKind;
    match &event.event {
        EventKind::FileRead { path, .. } => {
            format!("fs.read_file -> {}", path.display())
        }
        EventKind::FileWrite { path, .. } => {
            format!("fs.write_file -> {}", path.display())
        }
        EventKind::FileDelete { path, .. } => {
            format!("fs.remove -> {}", path.display())
        }
        EventKind::ProcessExec { command, .. } => {
            format!("fs.execute -> {command}")
        }
        EventKind::NetworkConnect { target, port } => {
            format!("net.connect_tcp -> {target}:{port}")
        }
        EventKind::NetworkDns { query, .. } => {
            format!("net.dns -> {query}")
        }
        other => format!("{other:?}"),
    }
}

#[cfg(target_os = "linux")]
/// Tail a file (`tail -f` style), sending lines through the channel.
///
/// Opens the file, seeks to end, and polls for new lines every 500ms.
/// Stops when the channel is closed (receiver dropped).
fn tail_file(path: &std::path::Path, tx: &tokio::sync::mpsc::Sender<TailEvent>) -> Result<()> {
    let file =
        std::fs::File::open(path).map_err(|e| eyre!("failed to open {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::End(0))?;

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data — poll interval
                std::thread::sleep(Duration::from_millis(500));
                if tx.is_closed() {
                    break;
                }
            }
            Ok(_) => {
                let trimmed = line.trim().to_owned();
                if trimmed.is_empty() {
                    continue;
                }
                if tx.blocking_send(TailEvent::Line(trimmed)).is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.blocking_send(TailEvent::Error(e.to_string()));
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    Ok(())
}
