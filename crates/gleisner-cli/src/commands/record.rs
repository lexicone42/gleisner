//! `gleisner record` — run Claude Code in a sandbox with full attestation.
//!
//! Orchestrates the complete attestation pipeline:
//! 1. Capture pre-session state (git, Claude Code context)
//! 2. Set up event bus with JSONL writer and session recorder
//! 3. Run Claude Code in a bwrap sandbox
//! 4. On exit: finalize recorder, assemble in-toto statement, sign
//! 5. Write attestation bundle (or unsigned statement) to disk

use std::path::PathBuf;

use chrono::Utc;
use clap::Args;
use color_eyre::eyre::{Result, eyre};
use sha2::{Digest, Sha256};

use gleisner_introdus::claude_code::ClaudeCodeContext;
use gleisner_introdus::metadata;
use gleisner_introdus::provenance::{
    BuildMetadata, Builder, ClaudeCodeEnvironment, Completeness, GleisnerProvenance, Invocation,
    SandboxProfileSummary,
};
use gleisner_introdus::recorder::{self, RecorderOutput};
use gleisner_introdus::signer::{LocalSigner, Signer, default_key_path};
use gleisner_introdus::statement::InTotoStatement;
use gleisner_introdus::vcs;
use gleisner_scapes::stream::{EventBus, spawn_jsonl_writer};

use super::wrap::WrapArgs;

/// Run Claude Code inside a sandbox with full attestation recording.
///
/// Creates a cryptographically signed in-toto attestation bundle
/// capturing materials (inputs), subjects (outputs), and provenance
/// metadata for the sandboxed session.
#[derive(Args)]
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
}

/// Execute the `record` command.
///
/// # Errors
///
/// Returns an error if profile resolution, sandbox creation, attestation
/// assembly, or signing fails.
pub async fn execute(args: RecordArgs) -> Result<()> {
    let project_dir = args
        .wrap
        .project_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine cwd"));

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

    let writer_handle = spawn_jsonl_writer(rx_writer, &audit_log_path)
        .map_err(|e| eyre!("failed to start audit log writer: {e}"))?;

    let recorder_handle = tokio::spawn(recorder::run(rx_recorder, audit_log_path.clone()));

    // ── 5. Run sandboxed process ─────────────────────────────────────
    let exit_code = run_sandbox(
        profile,
        project_dir,
        args.wrap.allow_network,
        args.wrap.allow_path,
        args.wrap.claude_bin,
        args.wrap.claude_args,
    )
    .await?;

    // ── 6. Finalize recording ────────────────────────────────────────
    drop(bus);
    let recorder_output = recorder_handle
        .await
        .map_err(|e| eyre!("recorder task panicked: {e}"))?;
    writer_handle
        .await
        .map_err(|e| eyre!("audit writer panicked: {e}"))?;

    tracing::info!(
        event_count = recorder_output.event_count,
        materials = recorder_output.materials.len(),
        subjects = recorder_output.subjects.len(),
        "session recording complete"
    );

    // ── 7. Assemble and sign ─────────────────────────────────────────
    let statement = assemble_statement(
        recorder_output,
        git_state.as_ref(),
        cc_context,
        sandbox_summary,
        exit_code,
    );

    write_attestation(
        &statement,
        &output_path,
        &audit_log_path,
        &key_path,
        args.no_sign,
    )
    .await?;

    std::process::exit(exit_code);
}

/// Run the sandboxed Claude Code process. Returns the exit code.
async fn run_sandbox(
    profile: gleisner_polis::Profile,
    project_dir: PathBuf,
    allow_network: Vec<String>,
    allow_path: Vec<PathBuf>,
    claude_bin: String,
    claude_args: Vec<String>,
) -> Result<i32> {
    let mut sandbox = gleisner_polis::BwrapSandbox::new(profile, project_dir)?;

    if !allow_network.is_empty() {
        sandbox.allow_domains(allow_network);
    }
    if !allow_path.is_empty() {
        sandbox.allow_paths(allow_path);
    }

    let mut inner_command = vec![claude_bin];
    inner_command.extend(claude_args);

    let std_cmd = sandbox.build_command(&inner_command);
    let mut cmd = tokio::process::Command::from(std_cmd);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .await
        .map_err(|e| eyre!("failed to spawn sandboxed process: {e}"))?;

    let exit_code = status.code().unwrap_or(1);
    if status.success() {
        tracing::info!("sandboxed session completed successfully");
    } else {
        tracing::warn!(exit_code, "sandboxed session exited with error");
    }

    Ok(exit_code)
}

/// Assemble the in-toto attestation statement from recorder output.
fn assemble_statement(
    recorder_output: RecorderOutput,
    git_state: Option<&vcs::GitState>,
    cc_context: ClaudeCodeContext,
    sandbox_summary: SandboxProfileSummary,
    exit_code: i32,
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
            audit_log_digest: recorder_output.audit_log_digest,
            sandbox_profile: sandbox_summary,
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
) -> Result<()> {
    if no_sign {
        let json = serde_json::to_string_pretty(statement)?;
        std::fs::write(output_path, &json)?;

        eprintln!(
            "Attestation statement (unsigned) written to: {}",
            output_path.display()
        );
        eprintln!("Audit log: {}", audit_log_path.display());
    } else {
        let signer =
            LocalSigner::load_or_generate(key_path).map_err(|e| eyre!("signing key error: {e}"))?;

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
