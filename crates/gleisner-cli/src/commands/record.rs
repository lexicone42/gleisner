//! `gleisner record` — run Claude Code in a sandbox with full attestation.
//!
//! Orchestrates the complete attestation pipeline:
//! 1. Capture pre-session state (git, Claude Code context)
//! 2. Set up event bus with JSONL writer and session recorder
//! 3. Start event monitors (inotify filesystem, /proc process)
//! 4. Run Claude Code in a bwrap sandbox
//! 5. On exit: cancel monitors, finalize recorder, assemble in-toto statement, sign
//! 6. Write attestation bundle (or unsigned statement) to disk

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::Result;

use super::wrap::WrapArgs;

/// Run Claude Code inside a sandbox with full attestation recording.
///
/// Creates a cryptographically signed in-toto attestation bundle
/// capturing materials (inputs), subjects (outputs), and provenance
/// metadata for the sandboxed session.
#[derive(Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecordArgs {
    /// All sandbox configuration (profile, paths, network, etc.).
    #[command(flatten)]
    pub wrap: WrapArgs,

    /// Output path for the attestation bundle JSON.
    ///
    /// Defaults to `.gleisner/attestation-{timestamp}.json`.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output path for the JSONL audit log.
    ///
    /// Defaults to `.gleisner/audit-{timestamp}.jsonl`.
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Path to the ECDSA signing key (PKCS#8 PEM).
    ///
    /// If the file does not exist, a new key pair is generated.
    /// Default: `~/.config/gleisner/keys/local.pem`.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,

    /// Skip signing — write an unsigned in-toto statement only.
    #[arg(long)]
    pub no_sign: bool,

    /// Disable filesystem monitoring (inotify + snapshot reconciliation).
    #[arg(long)]
    pub no_fs_monitor: bool,

    /// Disable process monitoring (/proc scanning).
    #[arg(long)]
    pub no_proc_monitor: bool,

    /// Disable cgroup resource limits.
    #[arg(long)]
    pub no_cgroups: bool,

    /// Don't link to previous attestation (start a new chain).
    #[arg(long)]
    pub no_chain: bool,

    /// Path to a user-readable kernel audit log for Landlock V7 denial
    /// collection. Set up audisp to write `LANDLOCK_ACCESS` records here.
    /// Omit to skip denial collection.
    #[arg(long)]
    pub kernel_audit_log: Option<PathBuf>,

    /// Use Sigstore keyless signing (Fulcio + Rekor) instead of a local key.
    ///
    /// Authentication order: (1) --sigstore-token if provided,
    /// (2) ambient CI credentials (GitHub Actions, GitLab CI),
    /// (3) interactive browser OIDC flow.
    #[cfg(feature = "keyless")]
    #[arg(long)]
    pub sigstore: bool,

    /// Pre-supplied OIDC identity token JWT for Sigstore signing.
    ///
    /// Useful in headless environments or CI systems that don't support
    /// ambient credential detection. Obtain a token from your OIDC
    /// provider and pass it here.
    #[cfg(feature = "keyless")]
    #[arg(long, value_name = "JWT", requires = "sigstore")]
    pub sigstore_token: Option<String>,
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub async fn execute(_args: RecordArgs) -> Result<()> {
    color_eyre::eyre::bail!("gleisner record requires Linux (bubblewrap sandbox)")
}

// ── Linux implementation ────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub async fn execute(args: RecordArgs) -> Result<()> {
    linux_impl::execute_impl(args).await
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::path::PathBuf;

    use chrono::Utc;
    use color_eyre::eyre::{Result, eyre};
    use sha2::{Digest, Sha256};
    use tokio_util::sync::CancellationToken;

    use gleisner_introdus::claude_code::ClaudeCodeContext;
    use gleisner_introdus::metadata;
    use gleisner_introdus::provenance::{
        BuildMetadata, Builder, ChainMetadata, ClaudeCodeEnvironment, Completeness,
        GleisnerProvenance, Invocation, SandboxProfileSummary,
    };
    use gleisner_introdus::recorder::{self, RecorderOutput};
    use gleisner_introdus::signer::{LocalSigner, Signer, default_key_path};
    use gleisner_introdus::statement::InTotoStatement;
    use gleisner_introdus::vcs;
    use gleisner_scapes::stream::{EventBus, spawn_jsonl_writer};

    use super::RecordArgs;

    /// Execute the `record` command.
    ///
    /// # Errors
    ///
    /// Returns an error if profile resolution, sandbox creation, attestation
    /// assembly, or signing fails.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn execute_impl(args: RecordArgs) -> Result<()> {
        let project_dir = args
            .wrap
            .project_dir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .ok_or_else(|| {
                eyre!("--project-dir not specified and current directory is inaccessible")
            })?;

        // ── 1. Resolve output paths ──────────────────────────────────────
        let gleisner_dir = project_dir.join(".gleisner");
        std::fs::create_dir_all(&gleisner_dir)?;

        let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");

        let output_path = args
            .output
            .unwrap_or_else(|| gleisner_dir.join(format!("attestation-{timestamp}.json")));

        let audit_log_path = args
            .audit_log
            .unwrap_or_else(|| gleisner_dir.join(format!("audit-{timestamp}.jsonl")));

        let key_path = args.signing_key.unwrap_or_else(default_key_path);

        // ── 2. Resolve profile ───────────────────────────────────────────
        let profile = gleisner_polis::resolve_profile(&args.wrap.profile)?;
        let profile_digest = hash_profile_toml(&args.wrap.profile).unwrap_or_default();

        let sandbox_summary = SandboxProfileSummary {
            name: profile.name.clone(),
            profile_digest,
            network_policy: format!("{:?}", profile.network.default).to_lowercase(),
            filesystem_deny_count: profile.filesystem.deny.len(),
        };

        tracing::info!(
            profile = %profile.name,
            project_dir = %project_dir.display(),
            output = %output_path.display(),
            "starting attested Claude Code session"
        );

        // ── 3. Capture pre-session state ─────────────────────────────────
        let cc_context = ClaudeCodeContext::capture(&project_dir);
        let git_state = vcs::capture(&project_dir).ok();

        if let Some(ref gs) = git_state {
            tracing::info!(
                commit = %gs.commit,
                branch = gs.branch.as_deref().unwrap_or("detached"),
                dirty = gs.dirty,
                "captured git state"
            );
        }

        // ── 4. Set up event bus + consumers ──────────────────────────────
        let bus = EventBus::new();
        let rx_writer = bus.subscribe();
        let rx_recorder = bus.subscribe();
        let publisher = bus.publisher();

        let writer_handle = spawn_jsonl_writer(rx_writer, &audit_log_path)
            .map_err(|e| eyre!("failed to start audit log writer: {e}"))?;

        let recorder_handle = tokio::spawn(recorder::run(rx_recorder));

        // ── 5. Spawn sandbox child (don't await exit yet) ────────────────
        let session_start = Utc::now();

        let inner_command = gleisner_polis::build_claude_inner_command(
            &args.wrap.claude_bin,
            &profile,
            &args.wrap.claude_args,
        );

        let sandbox_config = gleisner_polis::SandboxSessionConfig {
            profile: profile.clone(),
            project_dir: project_dir.clone(),
            extra_allow_network: args.wrap.allow_network,
            extra_allow_paths: args.wrap.allow_path,
            no_landlock: args.wrap.no_landlock,
        };

        let prepared = gleisner_polis::prepare_sandbox(sandbox_config, &inner_command)?;

        // Convert std::process::Command → tokio::process::Command for async await.
        // Recreate from program + args (build_command only sets args, no env vars).
        let mut cmd = tokio::process::Command::new(prepared.command.get_program());
        cmd.args(prepared.command.get_args());
        // Prevent Claude Code from detecting a nested session — gleisner IS the
        // outer orchestrator, not another Claude Code instance.
        cmd.env_remove("CLAUDECODE");
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());

        let mut child = cmd
            .spawn()
            .map_err(|e| eyre!("failed to spawn sandboxed process: {e}"))?;

        // Apply rlimits (NOFILE, AS, NPROC) — fallback for cgroup limits and defense-in-depth.
        if let Some(pid) = child.id() {
            #[expect(clippy::cast_possible_wrap, reason = "PID fits in i32")]
            if let Err(e) = prepared.apply_rlimits(nix::unistd::Pid::from_raw(pid as i32)) {
                tracing::warn!(error = %e, "failed to apply rlimits — continuing without resource limits");
            }
        }

        let child_pid = child.id().unwrap_or(0);

        // ── 6. Optionally create cgroup scope ────────────────────────────
        let cgroup_scope = if !args.no_cgroups && child_pid > 0 {
            match gleisner_polis::CgroupScope::create(&profile.resources) {
                Ok(scope) => {
                    if let Err(e) = scope.add_pid(child_pid) {
                        tracing::warn!(error = %e, "failed to add child to cgroup — rlimits will still apply");
                        None
                    } else {
                        tracing::info!(pid = child_pid, "applied cgroup resource limits");
                        Some(scope)
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create cgroup — rlimits will still apply");
                    None
                }
            }
        } else {
            None
        };

        // ── 7. Start event monitors ──────────────────────────────────────
        let cancel = CancellationToken::new();
        let mut monitor_handles = Vec::new();

        let fs_ignore_patterns = vec![
            "target".to_owned(),
            ".git".to_owned(),
            "node_modules".to_owned(),
            ".gleisner".to_owned(),
        ];

        // Snapshot the project directory before starting monitors.
        // This baseline enables post-session reconciliation for completeness.
        let pre_snapshot = if args.no_fs_monitor {
            None
        } else {
            tracing::info!("capturing pre-session filesystem snapshot");
            Some(gleisner_polis::fs_monitor::snapshot_directory(
                &project_dir,
                &fs_ignore_patterns,
            ))
        };

        if !args.no_fs_monitor {
            let fs_config = gleisner_polis::FsMonitorConfig {
                mount_path: project_dir.clone(),
                ignore_patterns: fs_ignore_patterns.clone(),
            };
            let fs_publisher = publisher.clone();
            let fs_cancel = cancel.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) =
                    gleisner_polis::fs_monitor::run_fs_monitor(fs_config, fs_publisher, fs_cancel)
                        .await
                {
                    tracing::warn!(error = %e, "filesystem monitor failed — continuing without fs monitoring");
                }
            });
            monitor_handles.push(handle);
        }

        if !args.no_proc_monitor && child_pid > 0 {
            let proc_config = gleisner_polis::ProcMonitorConfig {
                root_pid: child_pid,
                poll_interval: gleisner_polis::ProcMonitorConfig::DEFAULT_POLL_INTERVAL,
            };
            let proc_publisher = publisher.clone();
            let proc_cancel = cancel.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = gleisner_polis::procmon::run_proc_monitor(
                    proc_config,
                    proc_publisher,
                    proc_cancel,
                )
                .await
                {
                    tracing::warn!(error = %e, "process monitor failed — continuing without proc monitoring");
                }
            });
            monitor_handles.push(handle);
        }

        // ── 8. Await child exit ──────────────────────────────────────────
        let status = child
            .wait()
            .await
            .map_err(|e| eyre!("failed to wait on sandboxed process: {e}"))?;

        let exit_code = status.code().unwrap_or(1);
        if status.success() {
            tracing::info!("sandboxed session completed successfully");
        } else {
            tracing::warn!(exit_code, "sandboxed session exited with error");
        }

        // ── 9. Cancel monitors and await their completion ────────────────
        cancel.cancel();
        for handle in monitor_handles {
            let _ = handle.await;
        }

        // ── 9b. Post-session snapshot reconciliation ────────────────────
        // Compare the current filesystem state against the pre-session
        // snapshot and publish events for any changes inotify missed.
        if let Some(ref before) = pre_snapshot {
            tracing::info!("running post-session filesystem reconciliation");
            let after =
                gleisner_polis::fs_monitor::snapshot_directory(&project_dir, &fs_ignore_patterns);
            // Use an empty seen-set: reconcile publishes only for changes
            // where the hash differs — duplicates from inotify are harmless
            // since the recorder de-duplicates by path.
            let seen = std::collections::HashSet::new();
            let stats =
                gleisner_polis::fs_monitor::reconcile_snapshots(before, &after, &seen, &publisher);
            if stats.total_missed() > 0 {
                tracing::info!(
                    missed_writes = stats.missed_writes,
                    missed_creates = stats.missed_creates,
                    missed_deletes = stats.missed_deletes,
                    "reconciliation captured events missed by real-time monitor"
                );
            }
        }

        // ── 9c. Collect Landlock V7 audit denials ─────────────────────────
        if let Some(ref audit_path) = args.kernel_audit_log {
            let config = gleisner_polis::KernelAuditConfig {
                session_start,
                session_end: Utc::now(),
                audit_log_path: audit_path.clone(),
            };
            let n = gleisner_polis::collect_and_publish_denials(&config, &publisher);
            if n > 0 {
                tracing::info!(
                    denials = n,
                    "published Landlock denial events from kernel audit log"
                );
            }
        }

        // ── 10. Finalize recording ───────────────────────────────────────
        // Drop publisher/bus to close channels, then await both tasks.
        // IMPORTANT: await writer BEFORE hashing the audit log — the writer
        // must flush all events (including reconciliation) before we hash.
        drop(publisher);
        drop(bus);
        let recorder_output = recorder_handle
            .await
            .map_err(|e| eyre!("recorder task panicked: {e}"))?;
        writer_handle
            .await
            .map_err(|e| eyre!("audit writer panicked: {e}"))?;

        // Hash the fully-written audit log file
        let audit_log_digest = recorder::hash_file(&audit_log_path).unwrap_or_default();

        tracing::info!(
            event_count = recorder_output.event_count,
            materials = recorder_output.materials.len(),
            subjects = recorder_output.subjects.len(),
            "session recording complete"
        );

        // ── 11. Chain: find parent attestation ─────────────────────────
        let chain_metadata = if args.no_chain {
            None
        } else {
            match gleisner_introdus::chain::find_latest_attestation(&gleisner_dir) {
                Ok(Some(link)) => {
                    tracing::info!(
                        parent = %link.path.display(),
                        digest = %link.payload_digest,
                        "linking to parent attestation"
                    );
                    Some(ChainMetadata {
                        parent_digest: link.payload_digest,
                        parent_path: link.path.display().to_string(),
                    })
                }
                Ok(None) => {
                    tracing::info!("no previous attestation found — starting new chain");
                    None
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to discover parent attestation — starting new chain");
                    None
                }
            }
        };

        // ── 12. Assemble and sign ────────────────────────────────────────
        let statement = assemble_statement(
            recorder_output,
            audit_log_digest,
            git_state.as_ref(),
            cc_context,
            sandbox_summary,
            exit_code,
            chain_metadata,
        );

        #[cfg(feature = "keyless")]
        let use_sigstore = args.sigstore;
        #[cfg(not(feature = "keyless"))]
        let use_sigstore = false;

        #[cfg(feature = "keyless")]
        let sigstore_token = args.sigstore_token;
        #[cfg(not(feature = "keyless"))]
        let sigstore_token: Option<String> = None;

        write_attestation(
            &statement,
            &output_path,
            &audit_log_path,
            &key_path,
            args.no_sign,
            use_sigstore,
            sigstore_token,
        )
        .await?;

        // Drop handles before exit() — exit() skips destructors,
        // which would leak slirp4netns and namespace holder processes.
        drop(prepared);
        drop(cgroup_scope);

        std::process::exit(exit_code);
    }

    /// Assemble the in-toto attestation statement from recorder output.
    fn assemble_statement(
        recorder_output: RecorderOutput,
        audit_log_digest: String,
        git_state: Option<&vcs::GitState>,
        cc_context: ClaudeCodeContext,
        sandbox_summary: SandboxProfileSummary,
        exit_code: i32,
        chain: Option<ChainMetadata>,
    ) -> InTotoStatement {
        let mut materials = recorder_output.materials;
        if let Some(gs) = git_state {
            materials.push(gs.to_material());
        }

        let effective_model = cc_context.effective_model().map(str::to_owned);
        let api_base_url = cc_context
            .config
            .as_ref()
            .and_then(|c| c.api_base_url.clone())
            .unwrap_or_else(|| "https://api.anthropic.com".to_owned());

        InTotoStatement {
            statement_type: InTotoStatement::TYPE,
            subject: recorder_output.subjects,
            predicate_type: InTotoStatement::PREDICATE_TYPE,
            predicate: GleisnerProvenance {
                build_type: GleisnerProvenance::BUILD_TYPE,
                builder: Builder {
                    id: metadata::builder_id(),
                },
                invocation: Invocation {
                    parameters: serde_json::json!({
                        "exit_code": exit_code,
                        "profile": sandbox_summary.name,
                    }),
                    environment: ClaudeCodeEnvironment {
                        tool: "claude-code",
                        claude_code_version: cc_context.version,
                        model: effective_model,
                        claude_md_hash: cc_context.claude_md_hash,
                        context_hash: None,
                        sandboxed: true,
                        profile: sandbox_summary.name.clone(),
                        api_base_url,
                    },
                },
                metadata: BuildMetadata {
                    build_started_on: recorder_output.start_time,
                    build_finished_on: recorder_output.finish_time,
                    completeness: Completeness {
                        parameters: true,
                        environment: true,
                        materials: false,
                    },
                },
                materials,
                audit_log_digest,
                sandbox_profile: sandbox_summary,
                denial_count: recorder_output.denial_count,
                chain,
            },
        }
    }

    /// Sign and write the attestation to disk.
    async fn write_attestation(
        statement: &InTotoStatement,
        output_path: &std::path::Path,
        audit_log_path: &std::path::Path,
        key_path: &std::path::Path,
        no_sign: bool,
        use_sigstore: bool,
        #[cfg_attr(not(feature = "keyless"), allow(unused_variables))] sigstore_token: Option<
            String,
        >,
    ) -> Result<()> {
        if no_sign {
            let payload = serde_json::to_string(statement)?;
            let bundle = gleisner_introdus::bundle::AttestationBundle {
                payload,
                signature: String::new(),
                verification_material: gleisner_introdus::bundle::VerificationMaterial::None,
            };
            let json = serde_json::to_string_pretty(&bundle)?;
            std::fs::write(output_path, &json)?;

            eprintln!(
                "Attestation bundle (unsigned) written to: {}",
                output_path.display()
            );
            eprintln!("Audit log: {}", audit_log_path.display());
        } else if use_sigstore {
            #[cfg(feature = "keyless")]
            {
                use gleisner_introdus::signer::SigstoreSigner;

                let sigstore_bundle_path = output_path.with_extension("sigstore.json");
                let signer =
                    SigstoreSigner::new(Some(sigstore_bundle_path.clone()), sigstore_token.clone());

                eprintln!("Signing with: {}", signer.description());

                let bundle = signer
                    .sign(statement)
                    .await
                    .map_err(|e| eyre!("Sigstore signing failed: {e}"))?;

                let json = serde_json::to_string_pretty(&bundle)?;
                std::fs::write(output_path, &json)?;

                eprintln!("Attestation bundle written to: {}", output_path.display());
                eprintln!("Sigstore bundle (v0.3): {}", sigstore_bundle_path.display());
                eprintln!("Audit log: {}", audit_log_path.display());
            }
            #[cfg(not(feature = "keyless"))]
            {
                return Err(eyre!(
                    "Sigstore keyless signing requires the `keyless` feature.\n\
                     Rebuild with: cargo build --features keyless"
                ));
            }
        } else {
            let signer = LocalSigner::load_or_generate(key_path)
                .map_err(|e| eyre!("signing key error: {e}"))?;

            eprintln!("Signing with: {}", signer.description());

            let bundle = signer
                .sign(statement)
                .await
                .map_err(|e| eyre!("signing failed: {e}"))?;

            let json = serde_json::to_string_pretty(&bundle)?;
            std::fs::write(output_path, &json)?;

            eprintln!("Attestation bundle written to: {}", output_path.display());
            eprintln!("Audit log: {}", audit_log_path.display());
            eprintln!("Signing key: {}", key_path.display());
        }

        Ok(())
    }

    /// Hash a profile TOML file by name, searching the same paths as `resolve_profile`.
    fn hash_profile_toml(name_or_path: &str) -> Option<String> {
        let path = std::path::Path::new(name_or_path);

        if path.extension().is_some_and(|ext| ext == "toml") && path.exists() {
            return hash_file(path);
        }

        let search_dirs = [
            directories::ProjectDirs::from("dev", "gleisner", "gleisner")
                .map(|d| d.config_dir().join("profiles")),
            Some(PathBuf::from("profiles")),
            Some(PathBuf::from("/usr/share/gleisner/profiles")),
        ];

        for dir in search_dirs.into_iter().flatten() {
            let candidate = dir.join(format!("{name_or_path}.toml"));
            if candidate.exists() {
                return hash_file(&candidate);
            }
        }

        None
    }

    fn hash_file(path: &std::path::Path) -> Option<String> {
        let content = std::fs::read(path).ok()?;
        let hash = Sha256::digest(&content);
        Some(hex::encode(hash))
    }
}
