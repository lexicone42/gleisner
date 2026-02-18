//! Profile learner — generates sandbox profiles from audit log observations.
//!
//! Implements the `audit2allow` pattern: record a session with a permissive
//! profile, then analyze the audit log to produce a minimal profile that
//! allows exactly what was observed.
//!
//! Two modes:
//! - **Learn** (`base_profile: None`) — generate a fresh profile from scratch
//! - **Merge** (`base_profile: Some`) — extend an existing profile with
//!   newly observed paths/domains

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use gleisner_scapes::audit::{AuditEvent, EventKind, EventResult};

use crate::profile::{
    FilesystemPolicy, NetworkPolicy, PluginPolicy, PolicyDefault, ProcessPolicy, Profile,
    ResourceLimits,
};

/// Configuration for the profile learner.
pub struct LearnerConfig {
    /// Project directory — paths under here are skipped (always bind-mounted).
    pub project_dir: PathBuf,
    /// User's home directory — for `~/.X` relative path extraction.
    pub home_dir: PathBuf,
    /// Name for the generated profile.
    pub name: String,
    /// Base profile to merge into (None = generate fresh).
    pub base_profile: Option<Profile>,
}

/// Accumulates observations from audit events and generates profiles.
pub struct ProfileLearner {
    config: LearnerConfig,
    paths_read: BTreeSet<PathBuf>,
    paths_written: BTreeSet<PathBuf>,
    paths_deleted: BTreeSet<PathBuf>,
    network_targets: BTreeSet<(String, u16)>,
    dns_queries: BTreeSet<String>,
    commands_executed: BTreeSet<String>,
    denials: Vec<String>,
    event_count: u64,
}

/// Summary of what the learner observed.
pub struct LearningSummary {
    /// Total events processed.
    pub event_count: u64,
    /// Unique filesystem paths observed.
    pub unique_paths: usize,
    /// Unique network host:port targets.
    pub unique_network_targets: usize,
    /// Unique commands executed.
    pub unique_commands: usize,
    /// Number of denied events.
    pub denial_count: usize,
    /// Classified path groups.
    pub path_groups: PathGroups,
    /// Mapping from each learned path to the raw paths that contributed to it.
    pub detail_groups: BTreeMap<PathBuf, Vec<PathBuf>>,
}

/// Paths classified into profile sections.
pub struct PathGroups {
    /// Home-relative paths that were only read.
    pub home_readonly: BTreeSet<PathBuf>,
    /// Home-relative paths that were written.
    pub home_readwrite: BTreeSet<PathBuf>,
    /// Non-home paths that were only read.
    pub other_readonly: BTreeSet<PathBuf>,
    /// Non-home paths that were written.
    pub other_readwrite: BTreeSet<PathBuf>,
    /// `~/.claude/<subdir>` paths → `plugins.add_dirs`.
    pub claude_dirs: BTreeSet<PathBuf>,
    /// Paths that were skipped (system, project, virtual FS).
    pub skipped_count: usize,
}

/// Classification of a single path.
#[derive(Debug)]
enum PathClass {
    /// Path should be skipped (project dir, system prefix, virtual FS).
    Skip,
    /// Path is under `~/.claude/<subdir>` — routed to `plugins.add_dirs`.
    ClaudeDir(PathBuf),
    /// Path is under $HOME — stored as `~/.component`.
    HomeRelative(PathBuf),
    /// Path is outside $HOME and not a system prefix.
    Other(PathBuf),
}

/// Paths that should never appear in generated profiles.
const CREDENTIAL_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".docker",
];

/// XDG umbrella directories that should extract two components instead of one.
///
/// Without this, `~/.config/nvim/init.lua` would become `~/.config` (too broad).
/// With umbrella detection: `~/.config/nvim` (just what was needed).
const UMBRELLA_DIRS: &[&str] = &[".config", ".local", ".cache"];

/// System prefixes — always available via base `readonly_bind`, skip in learning.
const SYSTEM_PREFIXES: &[&str] = &["/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin", "/opt"];

/// Virtual filesystem prefixes — handled by tmpfs or kernel, skip in learning.
const VIRTUAL_PREFIXES: &[&str] = &["/tmp", "/proc", "/dev", "/sys", "/run"];

/// Claude Code's own infrastructure domains — these go into `network.allow_domains`.
/// Everything else observed on the network goes into `plugins.mcp_network_domains`.
const CLAUDE_CODE_DOMAINS: &[&str] = &["api.anthropic.com", "sentry.io", "statsig.anthropic.com"];

impl ProfileLearner {
    /// Create a new learner with the given configuration.
    pub const fn new(config: LearnerConfig) -> Self {
        Self {
            config,
            paths_read: BTreeSet::new(),
            paths_written: BTreeSet::new(),
            paths_deleted: BTreeSet::new(),
            network_targets: BTreeSet::new(),
            dns_queries: BTreeSet::new(),
            commands_executed: BTreeSet::new(),
            denials: Vec::new(),
            event_count: 0,
        }
    }

    /// Ingest a single audit event into the learner's observation set.
    ///
    /// Both allowed and denied events are processed — denied events widen
    /// the profile to include what the session *needed* but was blocked from
    /// accessing. Sentinel values (`<unknown>`, `<denied>`) from the kernel
    /// audit parser are filtered out.
    pub fn observe(&mut self, event: &AuditEvent) {
        self.event_count += 1;

        if let EventResult::Denied { reason } = &event.result {
            self.denials
                .push(format!("seq {}: {reason}", event.sequence));
        }

        match &event.event {
            EventKind::FileRead { path, .. } if !is_sentinel_path(path) => {
                self.paths_read.insert(path.clone());
            }
            EventKind::FileWrite { path, .. } if !is_sentinel_path(path) => {
                self.paths_written.insert(path.clone());
            }
            EventKind::FileDelete { path, .. } if !is_sentinel_path(path) => {
                self.paths_deleted.insert(path.clone());
            }
            EventKind::ProcessExec { command, .. } if !is_sentinel(command) => {
                self.commands_executed.insert(command.clone());
            }
            EventKind::NetworkConnect { target, port } if !is_sentinel(target) => {
                self.network_targets.insert((target.clone(), *port));
            }
            EventKind::NetworkDns { query, .. } => {
                self.dns_queries.insert(query.clone());
            }
            _ => {}
        }
    }

    /// Generate a profile and summary from accumulated observations.
    pub fn generate_profile(&self) -> (Profile, LearningSummary) {
        let (path_groups, detail_groups) = self.classify_paths();

        let all_paths: BTreeSet<&PathBuf> = self
            .paths_read
            .iter()
            .chain(&self.paths_written)
            .chain(&self.paths_deleted)
            .collect();

        let summary = LearningSummary {
            event_count: self.event_count,
            unique_paths: all_paths.len(),
            unique_network_targets: self.network_targets.len(),
            unique_commands: self.commands_executed.len(),
            denial_count: self.denials.len(),
            path_groups,
            detail_groups,
        };

        let profile = if let Some(base) = &self.config.base_profile {
            self.merge_into_base(base, &summary.path_groups)
        } else {
            self.build_fresh_profile(&summary.path_groups)
        };

        (profile, summary)
    }

    fn classify_paths(&self) -> (PathGroups, BTreeMap<PathBuf, Vec<PathBuf>>) {
        let mut home_readonly = BTreeSet::new();
        let mut home_readwrite = BTreeSet::new();
        let mut other_readonly = BTreeSet::new();
        let mut other_readwrite = BTreeSet::new();
        let mut claude_dirs = BTreeSet::new();
        let mut skipped_count: usize = 0;
        let mut detail_groups: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();

        // Collect all unique paths
        let all_paths: BTreeSet<&PathBuf> = self
            .paths_read
            .iter()
            .chain(&self.paths_written)
            .chain(&self.paths_deleted)
            .collect();

        let written_or_deleted: BTreeSet<&PathBuf> = self
            .paths_written
            .iter()
            .chain(&self.paths_deleted)
            .collect();

        for path in &all_paths {
            let is_write = written_or_deleted.contains(path);
            match classify_single_path(path, &self.config.home_dir, &self.config.project_dir) {
                PathClass::Skip => {
                    skipped_count += 1;
                }
                PathClass::ClaudeDir(rel) => {
                    detail_groups
                        .entry(rel.clone())
                        .or_default()
                        .push((*path).clone());
                    claude_dirs.insert(rel);
                }
                PathClass::HomeRelative(rel) => {
                    // Check against credential deny list
                    let component_str = rel.to_string_lossy();
                    if is_credential_path(&component_str) {
                        skipped_count += 1;
                        continue;
                    }
                    detail_groups
                        .entry(rel.clone())
                        .or_default()
                        .push((*path).clone());
                    if is_write {
                        home_readwrite.insert(rel);
                    } else {
                        home_readonly.insert(rel);
                    }
                }
                PathClass::Other(p) => {
                    if is_write {
                        other_readwrite.insert(p);
                    } else {
                        other_readonly.insert(p);
                    }
                }
            }
        }

        // Promote: if a home path appears in both readonly and readwrite, keep only readwrite
        home_readonly.retain(|p| !home_readwrite.contains(p));
        other_readonly.retain(|p| !other_readwrite.contains(p));

        (
            PathGroups {
                home_readonly,
                home_readwrite,
                other_readonly,
                other_readwrite,
                claude_dirs,
                skipped_count,
            },
            detail_groups,
        )
    }

    fn build_fresh_profile(&self, groups: &PathGroups) -> Profile {
        let mut readonly_bind: Vec<PathBuf> = SYSTEM_PREFIXES.iter().map(PathBuf::from).collect();

        // Add home-relative readonly paths as ~/.<component>
        for p in &groups.home_readonly {
            readonly_bind.push(PathBuf::from(format!("~/{}", p.display())));
        }
        for p in &groups.other_readonly {
            readonly_bind.push(p.clone());
        }

        let mut readwrite_bind: Vec<PathBuf> = Vec::new();
        for p in &groups.home_readwrite {
            readwrite_bind.push(PathBuf::from(format!("~/{}", p.display())));
        }
        for p in &groups.other_readwrite {
            readwrite_bind.push(p.clone());
        }

        let deny: Vec<PathBuf> = CREDENTIAL_DIRS
            .iter()
            .map(|d| PathBuf::from(format!("~/{d}")))
            .collect();

        // Split network targets: core Claude Code domains vs MCP server domains
        let all_hosts: BTreeSet<String> = self
            .network_targets
            .iter()
            .map(|(host, _)| host.clone())
            .collect();

        let mut allow_domains = Vec::new();
        let mut mcp_network_domains = Vec::new();
        for host in &all_hosts {
            if CLAUDE_CODE_DOMAINS.iter().any(|d| *d == host) {
                allow_domains.push(host.clone());
            } else {
                mcp_network_domains.push(host.clone());
            }
        }

        let allow_ports: Vec<u16> = self
            .network_targets
            .iter()
            .map(|(_, port)| *port)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let has_network = !self.network_targets.is_empty();
        let has_dns = !self.dns_queries.is_empty();

        // Collect ~/.claude/ subdirs for plugins.add_dirs
        let add_dirs: Vec<PathBuf> = groups
            .claude_dirs
            .iter()
            .map(|p| PathBuf::from(format!("~/{}", p.display())))
            .collect();

        Profile {
            name: self.config.name.clone(),
            description: format!("Learned profile from {} audit events", self.event_count),
            filesystem: FilesystemPolicy {
                readonly_bind,
                readwrite_bind,
                deny,
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains,
                allow_ports,
                allow_dns: has_dns || has_network,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: self.commands_executed.iter().cloned().collect(),
                seccomp_profile: None,
            },
            resources: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 100,
                max_pids: 256,
                max_file_descriptors: 1024,
                max_disk_write_mb: 10240,
            },
            plugins: PluginPolicy {
                add_dirs,
                mcp_network_domains,
                ..PluginPolicy::default()
            },
        }
    }

    fn merge_into_base(&self, base: &Profile, groups: &PathGroups) -> Profile {
        let mut profile = base.clone();
        profile.name.clone_from(&self.config.name);
        profile.description = format!(
            "Extended from '{}' with {} new observations",
            base.name, self.event_count
        );

        // Add new readonly paths not already present
        let existing_readonly: BTreeSet<PathBuf> =
            profile.filesystem.readonly_bind.iter().cloned().collect();
        for p in &groups.home_readonly {
            let full = PathBuf::from(format!("~/{}", p.display()));
            if !existing_readonly.contains(&full) {
                profile.filesystem.readonly_bind.push(full);
            }
        }
        for p in &groups.other_readonly {
            if !existing_readonly.contains(p) {
                profile.filesystem.readonly_bind.push(p.clone());
            }
        }

        // Add new readwrite paths not already present
        let existing_readwrite: BTreeSet<PathBuf> =
            profile.filesystem.readwrite_bind.iter().cloned().collect();
        for p in &groups.home_readwrite {
            let full = PathBuf::from(format!("~/{}", p.display()));
            if !existing_readwrite.contains(&full) {
                profile.filesystem.readwrite_bind.push(full);
            }
        }
        for p in &groups.other_readwrite {
            if !existing_readwrite.contains(p) {
                profile.filesystem.readwrite_bind.push(p.clone());
            }
        }

        // Route new network domains: core → allow_domains, MCP → mcp_network_domains
        let existing_core_domains: BTreeSet<String> =
            profile.network.allow_domains.iter().cloned().collect();
        let existing_mcp_domains: BTreeSet<String> = profile
            .plugins
            .mcp_network_domains
            .iter()
            .cloned()
            .collect();

        for (host, _) in &self.network_targets {
            if CLAUDE_CODE_DOMAINS.iter().any(|d| d == host) {
                if !existing_core_domains.contains(host) {
                    profile.network.allow_domains.push(host.clone());
                }
            } else if !existing_mcp_domains.contains(host) {
                profile.plugins.mcp_network_domains.push(host.clone());
            }
        }

        // Add new ports
        let existing_ports: BTreeSet<u16> = profile.network.allow_ports.iter().copied().collect();
        for (_, port) in &self.network_targets {
            if !existing_ports.contains(port) {
                profile.network.allow_ports.push(*port);
            }
        }

        // Add new ~/.claude/ dirs to plugins.add_dirs
        let existing_add_dirs: BTreeSet<PathBuf> =
            profile.plugins.add_dirs.iter().cloned().collect();
        for p in &groups.claude_dirs {
            let full = PathBuf::from(format!("~/{}", p.display()));
            if !existing_add_dirs.contains(&full) {
                profile.plugins.add_dirs.push(full);
            }
        }

        // Add new commands
        let existing_cmds: BTreeSet<String> =
            profile.process.command_allowlist.iter().cloned().collect();
        for cmd in &self.commands_executed {
            if !existing_cmds.contains(cmd) {
                profile.process.command_allowlist.push(cmd.clone());
            }
        }

        // Note: base disallowed_tools are preserved — never overwritten by learner
        profile
    }
}

/// Classify a single path for profile generation.
fn classify_single_path(path: &Path, home_dir: &Path, project_dir: &Path) -> PathClass {
    // Project dir — always bind-mounted, skip
    if path.starts_with(project_dir) {
        return PathClass::Skip;
    }

    // System prefixes — part of standard readonly_bind
    for prefix in SYSTEM_PREFIXES {
        if path.starts_with(prefix) {
            return PathClass::Skip;
        }
    }

    // Virtual FS — handled by tmpfs or kernel
    for prefix in VIRTUAL_PREFIXES {
        if path.starts_with(prefix) {
            return PathClass::Skip;
        }
    }

    // Home-relative: extract first component (e.g., .rustup from ~/.rustup/...)
    if let Ok(rel) = path.strip_prefix(home_dir) {
        let mut components = rel.components();
        if let Some(first) = components.next() {
            let first_str = first.as_os_str().to_string_lossy();

            // ~/.claude/<subdir> → route to plugins.add_dirs
            if first_str == ".claude" {
                if let Some(second) = components.next() {
                    let claude_subpath =
                        PathBuf::from(format!(".claude/{}", second.as_os_str().to_string_lossy()));
                    return PathClass::ClaudeDir(claude_subpath);
                }
                // Path is exactly ~/.claude — skip (not a useful bind target)
                return PathClass::Skip;
            }

            // XDG umbrella dirs (.config, .local, .cache) → extract two components
            if UMBRELLA_DIRS.iter().any(|u| *u == &*first_str) {
                if let Some(second) = components.next() {
                    let sub = PathBuf::from(format!(
                        "{}/{}",
                        first_str,
                        second.as_os_str().to_string_lossy()
                    ));
                    return PathClass::HomeRelative(sub);
                }
                // Bare ~/.config etc. — not a useful bind target
                return PathClass::Skip;
            }

            return PathClass::HomeRelative(PathBuf::from(first.as_os_str()));
        }
        // Path is exactly $HOME — skip
        return PathClass::Skip;
    }

    PathClass::Other(path.to_path_buf())
}

/// Check if a path is a sentinel value from the kernel audit parser.
///
/// Sentinels like `<unknown>` and `<denied>` are emitted when the audit
/// record lacks concrete path information. These should not appear in
/// generated profiles.
fn is_sentinel_path(path: &Path) -> bool {
    path.to_string_lossy().starts_with('<')
}

/// Check if a string value is a sentinel from the kernel audit parser.
fn is_sentinel(value: &str) -> bool {
    value.starts_with('<')
}

/// Check if a path component matches a credential directory.
fn is_credential_path(component: &str) -> bool {
    CREDENTIAL_DIRS.iter().any(|cred| {
        component
            .strip_prefix('.')
            .is_some_and(|c| cred.strip_prefix('.').unwrap_or(cred) == c)
    })
}

/// Format a learning summary as human-readable text.
pub fn format_summary(summary: &LearningSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Profile Learning Summary");
    let _ = writeln!(out, "========================");
    let _ = writeln!(out, "Events processed:     {}", summary.event_count);
    let _ = writeln!(out, "Unique paths:         {}", summary.unique_paths);
    let _ = writeln!(
        out,
        "Network targets:      {}",
        summary.unique_network_targets
    );
    let _ = writeln!(out, "Commands executed:     {}", summary.unique_commands);
    let _ = writeln!(out, "Denied events:        {}", summary.denial_count);
    let _ = writeln!(out);
    let _ = writeln!(out, "Path Classification:");
    let _ = writeln!(
        out,
        "  Home readonly:      {}",
        summary.path_groups.home_readonly.len()
    );
    let _ = writeln!(
        out,
        "  Home readwrite:     {}",
        summary.path_groups.home_readwrite.len()
    );
    let _ = writeln!(
        out,
        "  Other readonly:     {}",
        summary.path_groups.other_readonly.len()
    );
    let _ = writeln!(
        out,
        "  Other readwrite:    {}",
        summary.path_groups.other_readwrite.len()
    );
    let _ = writeln!(
        out,
        "  Claude dirs:        {}",
        summary.path_groups.claude_dirs.len()
    );
    let _ = writeln!(
        out,
        "  Skipped:            {}",
        summary.path_groups.skipped_count
    );

    // Path details: show which raw paths contributed to each learned path
    if !summary.detail_groups.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Path Details:");
        for (learned, raw_paths) in &summary.detail_groups {
            let mode = if summary.path_groups.home_readwrite.contains(learned) {
                "readwrite"
            } else if summary.path_groups.claude_dirs.contains(learned) {
                "claude-dir"
            } else {
                "readonly"
            };
            let _ = writeln!(
                out,
                "  ~/{}: {} file(s) ({})",
                learned.display(),
                raw_paths.len(),
                mode
            );
        }
    }

    out
}

/// Serialize a profile as TOML with a descriptive header comment.
///
/// # Errors
///
/// Returns an error if TOML serialization fails.
pub fn format_profile_toml(profile: &Profile) -> Result<String, toml::ser::Error> {
    let mut out = String::new();
    let _ = writeln!(out, "# {} — Generated by `gleisner learn`", profile.name);
    let _ = writeln!(out, "# {}", profile.description);
    out.push_str("#\n");
    out.push_str("# Review this profile before using it in production.\n");
    out.push_str("# Paths with tilde (~) are expanded at sandbox creation time.\n\n");
    out.push_str(&toml::to_string_pretty(profile)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    fn make_event(seq: u64, kind: EventKind, result: EventResult) -> AuditEvent {
        AuditEvent {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
            sequence: seq,
            event: kind,
            result,
        }
    }

    fn default_config() -> LearnerConfig {
        LearnerConfig {
            project_dir: PathBuf::from("/home/user/myproject"),
            home_dir: PathBuf::from("/home/user"),
            name: "test-profile".to_owned(),
            base_profile: None,
        }
    }

    #[test]
    fn project_dir_paths_skipped() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/myproject/src/main.rs"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (profile, summary) = learner.generate_profile();
        assert_eq!(summary.path_groups.skipped_count, 1);
        // Project dir paths should not appear in any bind list
        assert!(profile.filesystem.readwrite_bind.is_empty());
    }

    #[test]
    fn system_prefix_paths_skipped() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/usr/lib/libstdc++.so"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::FileRead {
                path: PathBuf::from("/etc/resolv.conf"),
                sha256: "def".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        assert_eq!(summary.path_groups.skipped_count, 2);
    }

    #[test]
    fn virtual_fs_paths_skipped() {
        let mut learner = ProfileLearner::new(default_config());
        for path in ["/tmp/cargo-build", "/proc/self/status", "/dev/null"] {
            learner.observe(&make_event(
                0,
                EventKind::FileRead {
                    path: PathBuf::from(path),
                    sha256: "x".to_owned(),
                },
                EventResult::Allowed,
            ));
        }
        let (_, summary) = learner.generate_profile();
        assert_eq!(summary.path_groups.skipped_count, 3);
    }

    #[test]
    fn home_relative_first_component_extraction() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.rustup/toolchains/stable/lib/libstd.so"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        assert!(
            summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".rustup"))
        );
    }

    #[test]
    fn written_paths_promoted_to_readwrite() {
        let mut learner = ProfileLearner::new(default_config());
        // Read a path first
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.cargo/registry/cache/foo"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        // Then write to the same tree
        learner.observe(&make_event(
            1,
            EventKind::FileWrite {
                path: PathBuf::from("/home/user/.cargo/registry/cache/bar"),
                sha256_before: None,
                sha256_after: "def".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        // .cargo should be in readwrite (promoted from readonly due to write)
        assert!(
            summary
                .path_groups
                .home_readwrite
                .contains(&PathBuf::from(".cargo"))
        );
        // And NOT in readonly
        assert!(
            !summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".cargo"))
        );
    }

    #[test]
    fn network_targets_produce_domains_and_ports() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::NetworkConnect {
                target: "api.anthropic.com".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::NetworkConnect {
                target: "sentry.io".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));
        let (profile, _) = learner.generate_profile();
        assert!(
            profile
                .network
                .allow_domains
                .contains(&"api.anthropic.com".to_owned())
        );
        assert!(
            profile
                .network
                .allow_domains
                .contains(&"sentry.io".to_owned())
        );
        assert!(profile.network.allow_ports.contains(&443));
        assert!(profile.network.allow_dns);
    }

    #[test]
    fn merge_with_base_adds_new_paths() {
        let base = Profile {
            name: "base".to_owned(),
            description: "base profile".to_owned(),
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp_profile: None,
            },
            resources: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 100,
                max_pids: 256,
                max_file_descriptors: 1024,
                max_disk_write_mb: 10240,
            },
            plugins: PluginPolicy::default(),
        };

        let mut config = default_config();
        config.base_profile = Some(base);
        let mut learner = ProfileLearner::new(config);

        // Observe a new network target
        learner.observe(&make_event(
            0,
            EventKind::NetworkConnect {
                target: "registry.npmjs.org".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));
        // And a new home path
        learner.observe(&make_event(
            1,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.npm/cache/foo"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));

        let (profile, _) = learner.generate_profile();

        // Should keep existing core domain
        assert!(
            profile
                .network
                .allow_domains
                .contains(&"api.anthropic.com".to_owned())
        );
        // New non-core domain goes to mcp_network_domains
        assert!(
            profile
                .plugins
                .mcp_network_domains
                .contains(&"registry.npmjs.org".to_owned())
        );
        // Should add new readonly path
        assert!(
            profile
                .filesystem
                .readonly_bind
                .contains(&PathBuf::from("~/.npm"))
        );
        // Should keep existing readonly
        assert!(
            profile
                .filesystem
                .readonly_bind
                .contains(&PathBuf::from("/usr"))
        );
    }

    #[test]
    fn credential_paths_excluded() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.ssh/id_rsa"),
                sha256: "secret".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.aws/credentials"),
                sha256: "secret2".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        // Credential paths should be skipped, not appear in readonly
        assert!(summary.path_groups.home_readonly.is_empty());
        assert_eq!(summary.path_groups.skipped_count, 2);
    }

    #[test]
    fn empty_audit_log_produces_minimal_profile() {
        let learner = ProfileLearner::new(default_config());
        let (profile, summary) = learner.generate_profile();
        assert_eq!(summary.event_count, 0);
        assert_eq!(summary.unique_paths, 0);
        // Should still have system prefixes in readonly
        assert!(!profile.filesystem.readonly_bind.is_empty());
        // Should have credential dirs in deny
        assert!(!profile.filesystem.deny.is_empty());
        assert_eq!(profile.name, "test-profile");
    }

    #[test]
    fn generated_profile_round_trips_through_toml() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.rustup/toolchains/stable/lib/libstd.so"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::NetworkConnect {
                target: "api.anthropic.com".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));

        let (profile, _) = learner.generate_profile();
        let toml_str = format_profile_toml(&profile).expect("TOML serialization");

        // Strip comment header for parsing
        let toml_body: String = toml_str
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");

        let parsed: Profile = toml::from_str(&toml_body).expect("TOML round-trip parse");
        assert_eq!(parsed.name, profile.name);
        assert_eq!(
            parsed.filesystem.readonly_bind.len(),
            profile.filesystem.readonly_bind.len()
        );
        assert_eq!(
            parsed.network.allow_domains.len(),
            profile.network.allow_domains.len()
        );
    }

    #[test]
    fn mcp_domains_separated_from_core_domains() {
        let mut learner = ProfileLearner::new(default_config());
        // Core Claude Code domain
        learner.observe(&make_event(
            0,
            EventKind::NetworkConnect {
                target: "api.anthropic.com".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));
        // MCP server domain
        learner.observe(&make_event(
            1,
            EventKind::NetworkConnect {
                target: "context7.com".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));
        // Another MCP domain
        learner.observe(&make_event(
            2,
            EventKind::NetworkConnect {
                target: "api.greptile.com".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));
        let (profile, _) = learner.generate_profile();

        // Core domain → network.allow_domains
        assert!(
            profile
                .network
                .allow_domains
                .contains(&"api.anthropic.com".to_owned())
        );
        assert!(
            !profile
                .network
                .allow_domains
                .contains(&"context7.com".to_owned())
        );

        // MCP domains → plugins.mcp_network_domains
        assert!(
            profile
                .plugins
                .mcp_network_domains
                .contains(&"context7.com".to_owned())
        );
        assert!(
            profile
                .plugins
                .mcp_network_domains
                .contains(&"api.greptile.com".to_owned())
        );
        assert!(
            !profile
                .plugins
                .mcp_network_domains
                .contains(&"api.anthropic.com".to_owned())
        );
    }

    #[test]
    fn claude_dirs_routed_to_plugins_add_dirs() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.claude/exo-self/journal.md"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::FileWrite {
                path: PathBuf::from("/home/user/.claude/projects/foo/notes.md"),
                sha256_before: None,
                sha256_after: "def".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (profile, summary) = learner.generate_profile();

        // Should be in plugins.add_dirs, NOT in filesystem readonly/readwrite
        assert!(
            profile
                .plugins
                .add_dirs
                .contains(&PathBuf::from("~/.claude/exo-self"))
        );
        assert!(
            profile
                .plugins
                .add_dirs
                .contains(&PathBuf::from("~/.claude/projects"))
        );
        assert!(
            summary
                .path_groups
                .claude_dirs
                .contains(&PathBuf::from(".claude/exo-self"))
        );
        assert!(
            summary
                .path_groups
                .claude_dirs
                .contains(&PathBuf::from(".claude/projects"))
        );

        // Should NOT appear in home_readonly or home_readwrite
        assert!(
            !summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".claude"))
        );
        assert!(
            !summary
                .path_groups
                .home_readwrite
                .contains(&PathBuf::from(".claude"))
        );
    }

    #[test]
    fn merge_routes_new_domains_to_mcp_network_domains() {
        let base = Profile {
            name: "base".to_owned(),
            description: "base profile".to_owned(),
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp_profile: None,
            },
            resources: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 100,
                max_pids: 256,
                max_file_descriptors: 1024,
                max_disk_write_mb: 10240,
            },
            plugins: PluginPolicy::default(),
        };

        let mut config = default_config();
        config.base_profile = Some(base);
        let mut learner = ProfileLearner::new(config);

        // New MCP domain (not a core domain)
        learner.observe(&make_event(
            0,
            EventKind::NetworkConnect {
                target: "registry.npmjs.org".to_owned(),
                port: 443,
            },
            EventResult::Allowed,
        ));

        let (profile, _) = learner.generate_profile();

        // Base core domain preserved
        assert!(
            profile
                .network
                .allow_domains
                .contains(&"api.anthropic.com".to_owned())
        );
        // New domain goes to mcp_network_domains, not allow_domains
        assert!(
            profile
                .plugins
                .mcp_network_domains
                .contains(&"registry.npmjs.org".to_owned())
        );
        assert!(
            !profile
                .network
                .allow_domains
                .contains(&"registry.npmjs.org".to_owned())
        );
    }

    #[test]
    fn merge_preserves_base_disallowed_tools() {
        let mut base = Profile {
            name: "base".to_owned(),
            description: "base profile".to_owned(),
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec![],
                allow_ports: vec![],
                allow_dns: false,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp_profile: None,
            },
            resources: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 100,
                max_pids: 256,
                max_file_descriptors: 1024,
                max_disk_write_mb: 10240,
            },
            plugins: PluginPolicy::default(),
        };
        base.plugins.disallowed_tools = vec!["mcp__dangerous_tool".to_owned()];

        let mut config = default_config();
        config.base_profile = Some(base);
        let mut learner = ProfileLearner::new(config);

        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.npm/cache/foo"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));

        let (profile, _) = learner.generate_profile();

        // disallowed_tools must be preserved from base
        assert_eq!(
            profile.plugins.disallowed_tools,
            vec!["mcp__dangerous_tool".to_owned()]
        );
    }

    #[test]
    fn denied_events_widen_profile() {
        let mut learner = ProfileLearner::new(default_config());
        // A denied file read — learner should include this path
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.config/something/data"),
                sha256: "<denied>".to_owned(),
            },
            EventResult::Denied {
                reason: "landlock: fs.read_file".to_owned(),
            },
        ));
        // A denied network connect — learner should include this target
        learner.observe(&make_event(
            1,
            EventKind::NetworkConnect {
                target: "example.com".to_owned(),
                port: 443,
            },
            EventResult::Denied {
                reason: "landlock: net.connect_tcp".to_owned(),
            },
        ));
        let (profile, summary) = learner.generate_profile();
        assert_eq!(summary.denial_count, 2);
        // Denied path should appear in readonly_bind (two-component for umbrella dirs)
        assert!(
            summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".config/something"))
        );
        // Denied network target should appear in mcp_network_domains
        assert!(
            profile
                .plugins
                .mcp_network_domains
                .contains(&"example.com".to_owned())
        );
    }

    #[test]
    fn sentinel_values_filtered_from_profile() {
        let mut learner = ProfileLearner::new(default_config());
        // Sentinel path from kernel audit parser — should be skipped
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("<unknown>"),
                sha256: "<denied>".to_owned(),
            },
            EventResult::Denied {
                reason: "landlock: fs.read_file".to_owned(),
            },
        ));
        // Sentinel network target — should be skipped
        learner.observe(&make_event(
            1,
            EventKind::NetworkConnect {
                target: "<unknown>".to_owned(),
                port: 0,
            },
            EventResult::Denied {
                reason: "landlock: net.connect_tcp".to_owned(),
            },
        ));
        // Sentinel command — should be skipped
        learner.observe(&make_event(
            2,
            EventKind::ProcessExec {
                command: "<unknown>".to_owned(),
                args: vec![],
                cwd: PathBuf::from("<denied>"),
            },
            EventResult::Denied {
                reason: "landlock: fs.execute".to_owned(),
            },
        ));
        let (profile, summary) = learner.generate_profile();
        assert_eq!(summary.denial_count, 3);
        // No sentinel paths should appear in the profile
        assert_eq!(summary.unique_paths, 0);
        assert_eq!(summary.unique_network_targets, 0);
        assert_eq!(summary.unique_commands, 0);
        assert!(profile.process.command_allowlist.is_empty());
    }

    #[test]
    fn umbrella_dir_extracts_two_components() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.config/nvim/init.lua"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.local/share/nvim/shada"),
                sha256: "def".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            2,
            EventKind::FileWrite {
                path: PathBuf::from("/home/user/.cache/pip/wheels/abc.whl"),
                sha256_before: None,
                sha256_after: "ghi".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (profile, summary) = learner.generate_profile();
        // Two-component extraction for umbrella dirs
        assert!(
            summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".config/nvim"))
        );
        assert!(
            summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".local/share"))
        );
        assert!(
            summary
                .path_groups
                .home_readwrite
                .contains(&PathBuf::from(".cache/pip"))
        );
        // Should NOT contain single-component versions
        assert!(
            !summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".config"))
        );
        assert!(
            !summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".local"))
        );
        assert!(
            !summary
                .path_groups
                .home_readwrite
                .contains(&PathBuf::from(".cache"))
        );
        // Profile paths should have tilde prefix
        assert!(
            profile
                .filesystem
                .readonly_bind
                .contains(&PathBuf::from("~/.config/nvim"))
        );
        assert!(
            profile
                .filesystem
                .readonly_bind
                .contains(&PathBuf::from("~/.local/share"))
        );
        assert!(
            profile
                .filesystem
                .readwrite_bind
                .contains(&PathBuf::from("~/.cache/pip"))
        );
    }

    #[test]
    fn bare_umbrella_dir_skipped() {
        let mut learner = ProfileLearner::new(default_config());
        // Access to exactly ~/.config (no subdir) should be skipped
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.config"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        assert!(summary.path_groups.home_readonly.is_empty());
        assert_eq!(summary.path_groups.skipped_count, 1);
    }

    #[test]
    fn credential_under_umbrella_dir_excluded() {
        let mut learner = ProfileLearner::new(default_config());
        // .config/gcloud is in CREDENTIAL_DIRS
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.config/gcloud/credentials.json"),
                sha256: "secret".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        assert!(summary.path_groups.home_readonly.is_empty());
        assert_eq!(summary.path_groups.skipped_count, 1);
    }

    #[test]
    fn detail_groups_populated() {
        let mut learner = ProfileLearner::new(default_config());
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.config/nvim/init.lua"),
                sha256: "a".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            1,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.config/nvim/colors/foo.vim"),
                sha256: "b".to_owned(),
            },
            EventResult::Allowed,
        ));
        learner.observe(&make_event(
            2,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.cargo/registry/foo"),
                sha256: "c".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        // .config/nvim should have 2 raw paths
        let nvim_detail = summary
            .detail_groups
            .get(&PathBuf::from(".config/nvim"))
            .expect("should have .config/nvim detail");
        assert_eq!(nvim_detail.len(), 2);
        // .cargo should have 1 raw path (non-umbrella, single component)
        let cargo_detail = summary
            .detail_groups
            .get(&PathBuf::from(".cargo"))
            .expect("should have .cargo detail");
        assert_eq!(cargo_detail.len(), 1);
    }

    #[test]
    fn non_umbrella_home_dirs_still_single_component() {
        let mut learner = ProfileLearner::new(default_config());
        // .rustup is NOT an umbrella dir — should stay single component
        learner.observe(&make_event(
            0,
            EventKind::FileRead {
                path: PathBuf::from("/home/user/.rustup/toolchains/stable/lib/libstd.so"),
                sha256: "abc".to_owned(),
            },
            EventResult::Allowed,
        ));
        let (_, summary) = learner.generate_profile();
        assert!(
            summary
                .path_groups
                .home_readonly
                .contains(&PathBuf::from(".rustup"))
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Generate an arbitrary absolute path under /home/user.
        fn arb_home_path() -> impl Strategy<Value = PathBuf> {
            // Pick 1-4 path components, each 1-20 alphanumeric chars with optional dot prefix
            prop::collection::vec(
                prop::bool::ANY.prop_flat_map(|dot| {
                    "[a-z][a-z0-9_-]{0,15}".prop_map(move |s| if dot { format!(".{s}") } else { s })
                }),
                1..=4,
            )
            .prop_map(|parts| {
                let mut p = PathBuf::from("/home/user");
                for part in parts {
                    p.push(part);
                }
                p
            })
        }

        /// Generate an arbitrary absolute path (could be anywhere in the filesystem).
        fn arb_absolute_path() -> impl Strategy<Value = PathBuf> {
            prop::collection::vec("[a-zA-Z0-9._-]{1,20}", 1..=5).prop_map(|parts| {
                let mut p = PathBuf::from("/");
                for part in parts {
                    p.push(part);
                }
                p
            })
        }

        proptest! {
            /// classify_single_path never panics on arbitrary paths.
            #[test]
            fn classify_never_panics(path in arb_absolute_path()) {
                let home = PathBuf::from("/home/user");
                let project = PathBuf::from("/home/user/myproject");
                let _ = classify_single_path(&path, &home, &project);
            }

            /// Umbrella dirs always extract exactly two components.
            #[test]
            fn umbrella_dir_always_two_components(
                umbrella in prop::sample::select(vec![".config", ".local", ".cache"]),
                subdir in "[a-z][a-z0-9_-]{0,15}",
                file in "[a-z][a-z0-9._-]{0,15}",
            ) {
                let path = PathBuf::from(format!("/home/user/{umbrella}/{subdir}/{file}"));
                let home = PathBuf::from("/home/user");
                let project = PathBuf::from("/home/user/myproject");
                let class = classify_single_path(&path, &home, &project);
                match class {
                    PathClass::HomeRelative(rel) => {
                        let components: Vec<_> = rel.components().collect();
                        prop_assert_eq!(
                            components.len(),
                            2,
                            "umbrella path {:?} should have 2 components, got {:?}",
                            path,
                            rel
                        );
                    }
                    other => prop_assert!(false, "expected HomeRelative, got {:?}", other),
                }
            }

            /// No credential path ever leaks into a generated profile.
            #[test]
            fn credential_paths_never_in_profile(
                cred in prop::sample::select(vec![
                    ".ssh", ".aws", ".gnupg", ".config/gcloud", ".azure", ".kube", ".docker"
                ]),
                file in "[a-z][a-z0-9._-]{0,15}",
            ) {
                let mut learner = ProfileLearner::new(default_config());
                let path = PathBuf::from(format!("/home/user/{cred}/{file}"));
                learner.observe(&make_event(
                    0,
                    EventKind::FileRead {
                        path: path.clone(),
                        sha256: "test".to_owned(),
                    },
                    EventResult::Allowed,
                ));
                let (profile, _) = learner.generate_profile();
                // No credential path should appear in readonly_bind
                for bind in &profile.filesystem.readonly_bind {
                    let bind_str = bind.to_string_lossy();
                    prop_assert!(
                        !bind_str.contains(&cred.replace('.', "")),
                        "credential path {} leaked into profile bind: {}",
                        cred,
                        bind_str
                    );
                }
                // Also not in readwrite_bind
                for bind in &profile.filesystem.readwrite_bind {
                    let bind_str = bind.to_string_lossy();
                    prop_assert!(
                        !bind_str.contains(&cred.replace('.', "")),
                        "credential path {} leaked into profile readwrite: {}",
                        cred,
                        bind_str
                    );
                }
            }

            /// Generated profiles always survive TOML roundtrip.
            #[test]
            fn profile_roundtrips_through_toml(
                paths in prop::collection::vec(arb_home_path(), 0..10),
            ) {
                let mut learner = ProfileLearner::new(default_config());
                for (i, path) in paths.iter().enumerate() {
                    learner.observe(&make_event(
                        i as u64,
                        EventKind::FileRead {
                            path: path.clone(),
                            sha256: format!("hash{i}"),
                        },
                        EventResult::Allowed,
                    ));
                }
                let (profile, _) = learner.generate_profile();
                let toml_str = format_profile_toml(&profile).expect("serialization");
                // Extract just the TOML part (skip comment header)
                let toml_body: String = toml_str
                    .lines()
                    .filter(|l| !l.starts_with('#'))
                    .collect::<Vec<_>>()
                    .join("\n");
                let parsed: Profile = toml::from_str(&toml_body).expect("deserialization");
                prop_assert_eq!(parsed.name, profile.name);
                prop_assert_eq!(
                    parsed.filesystem.readonly_bind.len(),
                    profile.filesystem.readonly_bind.len()
                );
                prop_assert_eq!(
                    parsed.filesystem.readwrite_bind.len(),
                    profile.filesystem.readwrite_bind.len()
                );
            }

            /// classify_single_path is deterministic — same input always same output.
            #[test]
            fn classify_is_deterministic(path in arb_home_path()) {
                let home = PathBuf::from("/home/user");
                let project = PathBuf::from("/home/user/myproject");
                let class1 = classify_single_path(&path, &home, &project);
                let class2 = classify_single_path(&path, &home, &project);
                let repr1 = format!("{class1:?}");
                let repr2 = format!("{class2:?}");
                prop_assert_eq!(repr1, repr2);
            }

            /// Home-relative paths never reference system prefixes.
            #[test]
            fn home_relative_never_system_prefix(path in arb_home_path()) {
                let home = PathBuf::from("/home/user");
                let project = PathBuf::from("/home/user/myproject");
                if let PathClass::HomeRelative(rel) = classify_single_path(&path, &home, &project) {
                    let rel_str = rel.to_string_lossy();
                    for prefix in SYSTEM_PREFIXES {
                        prop_assert!(
                            !rel_str.starts_with(prefix),
                            "home-relative path {:?} starts with system prefix {}",
                            rel,
                            prefix
                        );
                    }
                }
            }
        }
    }
}
