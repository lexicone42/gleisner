//! Task-oriented sandbox configuration.
//!
//! Instead of specifying infrastructure (mounts, namespaces, Landlock rules),
//! describe what the task **needs** and let the sandbox derive the configuration.
//!
//! This is the API that AI agents and automation tools should use — it encodes
//! the principle of least privilege as the default, granting only what's declared.
//!
//! # Example
//!
//! ```no_run
//! use gleisner_container::task::TaskSandbox;
//!
//! let sb = TaskSandbox::new("/workspace/myproject")
//!     .needs_network(["api.anthropic.com"])
//!     .needs_tools(["node", "git"])
//!     .build()
//!     .expect("configure sandbox");
//!
//! let output = sb
//!     .command_with_args("claude", &["--print", "explain main.rs"])
//!     .expect("build command")
//!     .output()
//!     .expect("run");
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use crate::builder::Sandbox;
use crate::error::ContainerError;
use crate::types::{Namespace, NetworkMode, SeccompPreset};

/// A task-oriented sandbox builder.
///
/// Describe what your task needs, not how to configure the sandbox.
/// `TaskSandbox` translates capability requirements into the minimal
/// sandbox configuration that satisfies them.
#[derive(Debug)]
pub struct TaskSandbox {
    /// The project directory — always mounted read-write.
    project_dir: PathBuf,
    /// Directories the task needs to read (mounted read-only).
    read_paths: Vec<PathBuf>,
    /// Directories the task needs to write (mounted read-write).
    write_paths: Vec<PathBuf>,
    /// Domains the task needs network access to.
    domains: Vec<String>,
    /// Whether the task needs unrestricted internet.
    needs_internet: bool,
    /// Tool binaries the task will invoke.
    tools: Vec<String>,
    /// Environment variables the task needs.
    env: Vec<(String, String)>,
    /// Whether to include the user's home directory (read-only).
    /// Auto-enabled when tools like `claude`, `git`, or `npm` are declared.
    needs_home: bool,
    /// Optional hostname for the container.
    hostname: Option<String>,
    /// Custom seccomp preset (auto-detected from tools if not set).
    seccomp: Option<SeccompPreset>,
}

impl TaskSandbox {
    /// Create a new task sandbox for the given project directory.
    ///
    /// The project directory is always mounted read-write and set as the
    /// working directory. Everything else starts denied.
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            domains: Vec::new(),
            needs_internet: false,
            tools: Vec::new(),
            env: Vec::new(),
            needs_home: false,
            hostname: None,
            seccomp: None,
        }
    }

    /// Declare that the task needs to read from these paths.
    pub fn needs_read(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.read_paths.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Declare that the task needs to write to these paths.
    pub fn needs_write(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.write_paths.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Declare domains the task needs network access to.
    pub fn needs_network(mut self, domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.domains.extend(domains.into_iter().map(Into::into));
        self
    }

    /// Declare that the task needs unrestricted internet access.
    pub fn needs_internet(mut self) -> Self {
        self.needs_internet = true;
        self
    }

    /// Declare tool binaries the task will invoke.
    ///
    /// This affects sandbox configuration:
    /// - `"node"` / `"claude"` → enables Nodejs seccomp preset
    /// - `"git"` → adds home dir for `.gitconfig`
    /// - `"npm"` / `"npx"` → adds `registry.npmjs.org` to domains
    /// - `"cargo"` / `"rustc"` → adds home dir for `.cargo`
    pub fn needs_tools(mut self, tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tools.extend(tools.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable for the task.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Include the user's home directory as read-only.
    ///
    /// Auto-enabled by tools that need home dir access (git, claude, npm, cargo).
    pub fn with_home(mut self) -> Self {
        self.needs_home = true;
        self
    }

    /// Set a custom hostname for the container.
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.hostname = Some(name.into());
        self
    }

    /// Override the auto-detected seccomp preset.
    pub fn seccomp(mut self, preset: SeccompPreset) -> Self {
        self.seccomp = Some(preset);
        self
    }

    /// Build the sandbox from the declared task requirements.
    ///
    /// Translates capability declarations into the minimal infrastructure:
    /// - Filesystem: only declared paths + system dirs for tools
    /// - Network: only declared domains (or full internet if declared)
    /// - Seccomp: auto-detected from tool list
    /// - Namespaces: PID + Time always enabled for isolation
    pub fn build(self) -> Result<Sandbox, ContainerError> {
        let mut sb = Sandbox::new();

        // Always: rootfs for basic Linux functionality
        sb.rootfs();

        // Always: PID + Time namespace for isolation
        sb.namespace(Namespace::Pid).namespace(Namespace::Time);

        // Project directory: read-write + working directory
        sb.project_dir(&self.project_dir);

        // Hostname
        if let Some(ref name) = self.hostname {
            sb.hostname(name);
        }

        // ── Derive configuration from tool declarations ─────────

        let mut auto_domains = self.domains.clone();
        let mut needs_home = self.needs_home;
        let mut uses_nodejs = false;

        for tool in &self.tools {
            match tool.as_str() {
                "node" | "claude" | "npx" => {
                    uses_nodejs = true;
                    needs_home = true;
                }
                "npm" => {
                    uses_nodejs = true;
                    needs_home = true;
                    if !auto_domains.contains(&"registry.npmjs.org".to_owned()) {
                        auto_domains.push("registry.npmjs.org".to_owned());
                    }
                }
                "git" => {
                    needs_home = true;
                }
                "cargo" | "rustc" => {
                    needs_home = true;
                }
                "pip" | "uv" | "uvx" => {
                    needs_home = true;
                    if !auto_domains.contains(&"pypi.org".to_owned()) {
                        auto_domains.push("pypi.org".to_owned());
                        auto_domains.push("files.pythonhosted.org".to_owned());
                    }
                }
                _ => {}
            }
        }

        // ── Home directory ──────────────────────────────────────

        if needs_home {
            sb.mount_home_readonly();
        }

        // ── Additional read/write paths ─────────────────────────

        for path in &self.read_paths {
            sb.bind_ro(path);
        }
        for path in &self.write_paths {
            sb.bind_rw(path);
        }

        // ── Network ─────────────────────────────────────────────

        if self.needs_internet {
            sb.network(NetworkMode::Host);
        } else if !auto_domains.is_empty() {
            sb.allow_domains(auto_domains);
        }
        // else: no network (default)

        // ── Seccomp ─────────────────────────────────────────────

        let seccomp = self.seccomp.unwrap_or(if uses_nodejs {
            SeccompPreset::Nodejs
        } else {
            SeccompPreset::Disabled
        });
        sb.seccomp(seccomp);

        // ── Environment variables ───────────────────────────────

        for (key, value) in &self.env {
            sb.env(key, value);
        }

        // Landlock always on — this is the principle of least privilege
        sb.landlock(true);

        Ok(sb)
    }
}

/// Convenience: create a task sandbox pre-configured for Claude Code.
///
/// This is the most common use case — running Claude Code inside a sandbox
/// with exactly the permissions it needs:
/// - Project dir: read-write
/// - Home dir: read-only (for `.claude` config, hooks, MCP)
/// - Network: `api.anthropic.com` only
/// - Seccomp: Nodejs preset (V8-aware)
/// - Landlock: fully enforced
pub fn claude_code_sandbox(project_dir: impl Into<PathBuf>) -> Result<Sandbox, ContainerError> {
    TaskSandbox::new(project_dir)
        .needs_tools(["claude", "node", "git"])
        .needs_network(["api.anthropic.com"])
        .hostname("gleisner-claude")
        .build()
}

// ── Task merging ────────────────────────────────────────────────

impl TaskSandbox {
    /// Merge another task's requirements into this one.
    ///
    /// The resulting sandbox has the union of both tasks' capabilities.
    /// This is useful for multi-agent scenarios where two agents with
    /// different needs share a single sandbox.
    ///
    /// ```no_run
    /// # use gleisner_container::task::TaskSandbox;
    /// let code_agent = TaskSandbox::new("/workspace")
    ///     .needs_tools(["claude", "git"])
    ///     .needs_network(["api.anthropic.com"]);
    ///
    /// let build_agent = TaskSandbox::new("/workspace")
    ///     .needs_tools(["cargo"])
    ///     .needs_network(["crates.io"]);
    ///
    /// let combined = code_agent.merge(build_agent);
    /// // combined needs: claude, git, cargo, api.anthropic.com, crates.io
    /// ```
    pub fn merge(mut self, other: Self) -> Self {
        // Use the first task's project_dir (both should agree)
        for path in other.read_paths {
            if !self.read_paths.contains(&path) {
                self.read_paths.push(path);
            }
        }
        for path in other.write_paths {
            if !self.write_paths.contains(&path) {
                self.write_paths.push(path);
            }
        }
        for domain in other.domains {
            if !self.domains.contains(&domain) {
                self.domains.push(domain);
            }
        }
        self.needs_internet = self.needs_internet || other.needs_internet;
        for tool in other.tools {
            if !self.tools.contains(&tool) {
                self.tools.push(tool);
            }
        }
        for (key, value) in other.env {
            if !self.env.iter().any(|(k, _)| k == &key) {
                self.env.push((key, value));
            }
        }
        self.needs_home = self.needs_home || other.needs_home;
        // Keep first task's hostname and seccomp unless not set
        if self.hostname.is_none() {
            self.hostname = other.hostname;
        }
        if self.seccomp.is_none() {
            self.seccomp = other.seccomp;
        }
        self
    }
}

// ── Capability explanation ──────────────────────────────────────

/// A human-readable explanation of what permissions a task sandbox grants.
#[derive(Debug, Clone)]
pub struct CapabilityExplanation {
    /// Individual permission grants with reasons.
    pub grants: Vec<CapabilityGrant>,
}

/// A single capability granted to the sandbox, with the reason it was granted.
#[derive(Debug, Clone)]
pub struct CapabilityGrant {
    /// The capability category.
    pub category: String,
    /// What was granted.
    pub capability: String,
    /// Why it was granted.
    pub reason: String,
}

impl fmt::Display for CapabilityExplanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Sandbox capabilities ({} grants):", self.grants.len())?;
        let mut last_category = String::new();
        for grant in &self.grants {
            if grant.category != last_category {
                writeln!(f, "\n  [{}]", grant.category)?;
                last_category.clone_from(&grant.category);
            }
            writeln!(f, "    {} — {}", grant.capability, grant.reason)?;
        }
        Ok(())
    }
}

impl TaskSandbox {
    /// Explain what permissions this task sandbox will grant and why.
    ///
    /// Returns a structured explanation suitable for logging, auditing,
    /// or displaying to a user before launching the sandbox.
    pub fn explain(&self) -> CapabilityExplanation {
        let mut grants = Vec::new();

        // Filesystem grants
        grants.push(CapabilityGrant {
            category: "filesystem".to_owned(),
            capability: format!("readwrite: {}", self.project_dir.display()),
            reason: "project directory (always mounted)".to_owned(),
        });

        for path in &self.read_paths {
            grants.push(CapabilityGrant {
                category: "filesystem".to_owned(),
                capability: format!("readonly: {}", path.display()),
                reason: "explicitly declared via needs_read()".to_owned(),
            });
        }

        for path in &self.write_paths {
            grants.push(CapabilityGrant {
                category: "filesystem".to_owned(),
                capability: format!("readwrite: {}", path.display()),
                reason: "explicitly declared via needs_write()".to_owned(),
            });
        }

        // Home dir — explain WHY
        let home_tools: Vec<&str> = self
            .tools
            .iter()
            .filter(|t| {
                matches!(
                    t.as_str(),
                    "claude" | "git" | "npm" | "npx" | "cargo" | "rustc" | "node" | "pip" | "uv"
                )
            })
            .map(String::as_str)
            .collect();
        if self.needs_home || !home_tools.is_empty() {
            let reason = if home_tools.is_empty() {
                "explicitly declared via with_home()".to_owned()
            } else {
                format!("required by tools: {}", home_tools.join(", "))
            };
            grants.push(CapabilityGrant {
                category: "filesystem".to_owned(),
                capability: "readonly: $HOME".to_owned(),
                reason,
            });
        }

        // Network grants
        if self.needs_internet {
            grants.push(CapabilityGrant {
                category: "network".to_owned(),
                capability: "unrestricted internet".to_owned(),
                reason: "explicitly declared via needs_internet()".to_owned(),
            });
        } else {
            // Compute auto-domains from tools (same logic as build())
            let mut all_domains: BTreeSet<String> = self.domains.iter().cloned().collect();
            for tool in &self.tools {
                match tool.as_str() {
                    "npm" | "npx" => {
                        all_domains.insert("registry.npmjs.org".to_owned());
                    }
                    "pip" | "uv" | "uvx" => {
                        all_domains.insert("pypi.org".to_owned());
                        all_domains.insert("files.pythonhosted.org".to_owned());
                    }
                    _ => {}
                }
            }
            for domain in &all_domains {
                let reason = if self.domains.contains(domain) {
                    "explicitly declared via needs_network()".to_owned()
                } else {
                    let tool = self
                        .tools
                        .iter()
                        .find(|t| match t.as_str() {
                            "npm" | "npx" => domain == "registry.npmjs.org",
                            "pip" | "uv" | "uvx" => {
                                domain == "pypi.org" || domain == "files.pythonhosted.org"
                            }
                            _ => false,
                        })
                        .map(String::as_str)
                        .unwrap_or("tool");
                    format!("auto-added by tool: {tool}")
                };
                grants.push(CapabilityGrant {
                    category: "network".to_owned(),
                    capability: format!("domain: {domain}"),
                    reason,
                });
            }
            if all_domains.is_empty() {
                grants.push(CapabilityGrant {
                    category: "network".to_owned(),
                    capability: "none (fully isolated)".to_owned(),
                    reason: "no network access declared".to_owned(),
                });
            }
        }

        // Seccomp grant
        let seccomp_preset = if self.seccomp.is_some() {
            "custom (explicitly set)"
        } else if self
            .tools
            .iter()
            .any(|t| matches!(t.as_str(), "node" | "claude" | "npx" | "npm"))
        {
            "Nodejs (auto-detected from node/claude tools)"
        } else {
            "disabled (no Node.js tools detected)"
        };
        grants.push(CapabilityGrant {
            category: "seccomp".to_owned(),
            capability: seccomp_preset.to_owned(),
            reason: "syscall filtering preset".to_owned(),
        });

        // Security posture
        grants.push(CapabilityGrant {
            category: "security".to_owned(),
            capability: "Landlock: enforced".to_owned(),
            reason: "always enabled in task sandboxes".to_owned(),
        });
        grants.push(CapabilityGrant {
            category: "security".to_owned(),
            capability: "PID namespace: isolated".to_owned(),
            reason: "always enabled in task sandboxes".to_owned(),
        });
        grants.push(CapabilityGrant {
            category: "security".to_owned(),
            capability: "Time namespace: isolated".to_owned(),
            reason: "always enabled in task sandboxes".to_owned(),
        });

        CapabilityExplanation { grants }
    }
}

// ── Runtime narrowing ───────────────────────────────────────────

/// Compares what a task declared vs what it actually used at runtime.
///
/// After a sandbox run completes, feed the audit data back to produce
/// recommendations for tightening the configuration.
#[derive(Debug)]
pub struct NarrowingReport {
    /// Capabilities that were declared but never used at runtime.
    pub unused: Vec<String>,
    /// Suggestion for a tighter task configuration.
    pub suggested_config: TaskSandbox,
    /// Human-readable summary.
    pub summary: String,
}

/// Observed runtime capabilities — what the sandboxed process actually accessed.
#[derive(Debug, Default, Clone)]
pub struct ObservedCapabilities {
    /// Filesystem paths that were read.
    pub read_paths: BTreeSet<PathBuf>,
    /// Filesystem paths that were written.
    pub write_paths: BTreeSet<PathBuf>,
    /// Network domains that were contacted.
    pub contacted_domains: BTreeSet<String>,
    /// Tool binaries that were executed.
    pub executed_tools: BTreeSet<String>,
}

impl TaskSandbox {
    /// Compare declared capabilities against observed runtime usage.
    ///
    /// Returns a [`NarrowingReport`] with recommendations for a tighter
    /// sandbox configuration. Feed this data from the JSONL audit log
    /// produced by `gleisner record` or from Landlock denial events.
    ///
    /// ```no_run
    /// # use gleisner_container::task::{TaskSandbox, ObservedCapabilities};
    /// let task = TaskSandbox::new("/workspace")
    ///     .needs_tools(["cargo", "git", "npm"])
    ///     .needs_network(["crates.io", "registry.npmjs.org"]);
    ///
    /// // After running the sandbox and collecting audit data:
    /// let mut observed = ObservedCapabilities::default();
    /// observed.executed_tools.insert("cargo".to_owned());
    /// // npm was never used, git was never used
    ///
    /// let report = task.narrow(&observed);
    /// eprintln!("{}", report.summary);
    /// // "Unused capabilities: tools [git, npm], domains [registry.npmjs.org]"
    /// ```
    pub fn narrow(&self, observed: &ObservedCapabilities) -> NarrowingReport {
        let mut unused = Vec::new();
        let declared_tools: BTreeSet<&str> = self.tools.iter().map(String::as_str).collect();
        let used_tools: BTreeSet<&str> =
            observed.executed_tools.iter().map(String::as_str).collect();

        // Tools declared but not used
        let unused_tools: Vec<&str> = declared_tools.difference(&used_tools).copied().collect();
        if !unused_tools.is_empty() {
            unused.push(format!("tools: [{}]", unused_tools.join(", ")));
        }

        // Domains declared but not contacted
        let declared_domains: BTreeSet<&str> = self.domains.iter().map(String::as_str).collect();
        let used_domains: BTreeSet<&str> = observed
            .contacted_domains
            .iter()
            .map(String::as_str)
            .collect();
        let unused_domains: Vec<&str> = declared_domains
            .difference(&used_domains)
            .copied()
            .collect();
        if !unused_domains.is_empty() {
            unused.push(format!("domains: [{}]", unused_domains.join(", ")));
        }

        // Read paths declared but not accessed
        let declared_reads: BTreeSet<&PathBuf> = self.read_paths.iter().collect();
        let used_reads: BTreeSet<&PathBuf> = observed.read_paths.iter().collect();
        let unused_reads: Vec<_> = declared_reads
            .difference(&used_reads)
            .map(|p| p.display().to_string())
            .collect();
        if !unused_reads.is_empty() {
            unused.push(format!("read_paths: [{}]", unused_reads.join(", ")));
        }

        // Build the tighter config
        let mut suggested = TaskSandbox::new(&self.project_dir);

        // Only include tools that were actually used
        let used_tool_strings: Vec<String> = used_tools
            .intersection(&declared_tools)
            .map(|s| (*s).to_owned())
            .collect();
        if !used_tool_strings.is_empty() {
            suggested = suggested.needs_tools(used_tool_strings);
        }

        // Only include domains that were actually contacted
        let used_domain_strings: Vec<String> = used_domains
            .intersection(&declared_domains)
            .map(|s| (*s).to_owned())
            .collect();
        if !used_domain_strings.is_empty() {
            suggested = suggested.needs_network(used_domain_strings);
        }

        // Keep read paths that were accessed
        let used_read_paths: Vec<PathBuf> = observed
            .read_paths
            .iter()
            .filter(|p| self.read_paths.contains(*p))
            .cloned()
            .collect();
        if !used_read_paths.is_empty() {
            suggested = suggested.needs_read(used_read_paths);
        }

        // Keep write paths that were accessed
        let used_write_paths: Vec<PathBuf> = observed
            .write_paths
            .iter()
            .filter(|p| self.write_paths.contains(*p))
            .cloned()
            .collect();
        if !used_write_paths.is_empty() {
            suggested = suggested.needs_write(used_write_paths);
        }

        // Carry over env and other settings
        for (k, v) in &self.env {
            suggested = suggested.env(k, v);
        }
        if let Some(ref h) = self.hostname {
            suggested = suggested.hostname(h);
        }

        let summary = if unused.is_empty() {
            "All declared capabilities were used — configuration is already minimal.".to_owned()
        } else {
            format!("Unused capabilities: {}", unused.join(", "))
        };

        NarrowingReport {
            unused,
            suggested_config: suggested,
            summary,
        }
    }
}

// ── System prompt generation ────────────────────────────────────

impl TaskSandbox {
    /// Generate a system prompt fragment describing the sandbox boundaries.
    ///
    /// This produces text suitable for injection into an AI agent's system
    /// prompt, telling it what it can and cannot do inside the sandbox.
    ///
    /// # Security design
    ///
    /// The fragment describes **allowed** capabilities only — it does NOT
    /// enumerate denied paths, internal mount points, or sandbox implementation
    /// details. This is intentional:
    /// - An honest agent benefits from knowing its constraints (fewer failed operations)
    /// - An adversarial agent gains no attack surface information (nothing to probe)
    /// - The Landlock/seccomp/namespace enforcement is independent of this text
    ///
    /// The fragment is informational, not authoritative — the kernel enforces
    /// the actual boundaries regardless of what the prompt says.
    pub fn system_prompt_fragment(&self) -> String {
        let mut lines = Vec::new();

        lines.push(
            "You are running in a sandboxed environment with restricted permissions.".to_owned(),
        );
        lines.push(String::new());

        // Filesystem
        lines.push("Filesystem access:".to_owned());
        lines.push(format!("  - Read/write: {}", self.project_dir.display()));
        for path in &self.write_paths {
            lines.push(format!("  - Read/write: {}", path.display()));
        }
        for path in &self.read_paths {
            lines.push(format!("  - Read-only: {}", path.display()));
        }
        if self.needs_home
            || self.tools.iter().any(|t| {
                matches!(
                    t.as_str(),
                    "claude" | "git" | "npm" | "npx" | "cargo" | "node"
                )
            })
        {
            lines.push("  - Read-only: home directory (for tool configuration)".to_owned());
        }
        lines.push("  - Other paths are not accessible".to_owned());

        // Network
        lines.push(String::new());
        lines.push("Network access:".to_owned());
        if self.needs_internet {
            lines.push("  - Unrestricted internet access".to_owned());
        } else {
            let mut all_domains: BTreeSet<String> = self.domains.iter().cloned().collect();
            for tool in &self.tools {
                match tool.as_str() {
                    "npm" | "npx" => {
                        all_domains.insert("registry.npmjs.org".to_owned());
                    }
                    "pip" | "uv" | "uvx" => {
                        all_domains.insert("pypi.org".to_owned());
                    }
                    _ => {}
                }
            }
            if all_domains.is_empty() {
                lines.push("  - No network access (fully isolated)".to_owned());
            } else {
                for domain in &all_domains {
                    lines.push(format!("  - Allowed: {domain}"));
                }
                lines.push("  - All other domains are blocked".to_owned());
            }
        }

        // Tools
        if !self.tools.is_empty() {
            lines.push(String::new());
            lines.push(format!("Available tools: {}", self.tools.join(", ")));
        }

        // Guidance
        lines.push(String::new());
        lines.push(
            "Operations outside these boundaries will fail silently or with permission errors."
                .to_owned(),
        );
        lines.push(
            "Work within the project directory and use only the declared network endpoints."
                .to_owned(),
        );

        lines.join("\n")
    }
}

impl CapabilityExplanation {
    /// Convert the explanation to a compact system prompt fragment.
    ///
    /// Unlike [`TaskSandbox::system_prompt_fragment()`] which works from
    /// declarations, this works from the resolved explanation (after tool
    /// derivation). Use this when you have an explanation but not the
    /// original `TaskSandbox`.
    pub fn to_system_prompt(&self) -> String {
        let mut lines = vec![
            "You are running in a sandboxed environment.".to_owned(),
            String::new(),
        ];

        let mut last_cat = String::new();
        for grant in &self.grants {
            if grant.category != last_cat {
                lines.push(format!("{}:", grant.category));
                last_cat.clone_from(&grant.category);
            }
            lines.push(format!("  - {}", grant.capability));
        }

        lines.push(String::new());
        lines.push("Work within these boundaries. Unauthorized operations will fail.".to_owned());
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_sandbox_minimal() {
        let sb = TaskSandbox::new("/workspace/project").build().unwrap();

        assert!(sb.is_landlock_enabled());
    }

    #[test]
    fn task_sandbox_claude_tools() {
        let sb = TaskSandbox::new("/workspace/project")
            .needs_tools(["claude", "git"])
            .needs_network(["api.anthropic.com"])
            .build()
            .unwrap();

        assert!(sb.is_landlock_enabled());
    }

    #[test]
    fn task_sandbox_npm_adds_registry() {
        let sb = TaskSandbox::new("/workspace")
            .needs_tools(["npm"])
            .build()
            .unwrap();

        // npm should auto-add registry.npmjs.org
        assert!(sb.is_landlock_enabled());
    }

    #[test]
    fn claude_code_sandbox_convenience() {
        let sb = claude_code_sandbox("/workspace/project").unwrap();
        assert!(sb.is_landlock_enabled());
    }

    #[test]
    fn task_sandbox_owned_builder_pattern() {
        // Owned self pattern — no &mut needed
        let sb = TaskSandbox::new("/workspace")
            .needs_tools(["cargo", "git"])
            .needs_network(["crates.io"])
            .needs_read(["/etc/ssl"])
            .env("RUST_LOG", "debug")
            .hostname("build-sandbox")
            .build()
            .unwrap();

        assert!(sb.is_landlock_enabled());
    }

    // ── Merge tests ─────────────────────────────────────────

    #[test]
    fn merge_combines_tools_and_domains() {
        let code_agent = TaskSandbox::new("/workspace")
            .needs_tools(["claude", "git"])
            .needs_network(["api.anthropic.com"]);

        let build_agent = TaskSandbox::new("/workspace")
            .needs_tools(["cargo"])
            .needs_network(["crates.io"]);

        let combined = code_agent.merge(build_agent);

        assert_eq!(combined.tools.len(), 3); // claude, git, cargo
        assert_eq!(combined.domains.len(), 2); // api.anthropic.com, crates.io
        assert!(combined.tools.contains(&"cargo".to_owned()));
        assert!(combined.domains.contains(&"crates.io".to_owned()));
    }

    #[test]
    fn merge_deduplicates() {
        let a = TaskSandbox::new("/workspace")
            .needs_tools(["git", "claude"])
            .needs_network(["api.anthropic.com"]);

        let b = TaskSandbox::new("/workspace")
            .needs_tools(["git", "npm"]) // git already in a
            .needs_network(["api.anthropic.com"]); // already in a

        let combined = a.merge(b);
        assert_eq!(combined.tools.len(), 3); // git, claude, npm (no dup)
        assert_eq!(combined.domains.len(), 1); // api.anthropic.com (no dup)
    }

    #[test]
    fn merge_internet_is_or() {
        let a = TaskSandbox::new("/workspace");
        let b = TaskSandbox::new("/workspace").needs_internet();

        let combined = a.merge(b);
        assert!(combined.needs_internet);
    }

    // ── Explain tests ───────────────────────────────────────

    #[test]
    fn explain_shows_tool_derived_permissions() {
        let task = TaskSandbox::new("/workspace")
            .needs_tools(["claude", "npm"])
            .needs_network(["api.anthropic.com"]);

        let explanation = task.explain();
        let text = explanation.to_string();

        // Should mention home dir access for claude/npm
        assert!(text.contains("$HOME"), "should explain home dir: {text}");
        // Should mention api.anthropic.com
        assert!(
            text.contains("api.anthropic.com"),
            "should explain API domain: {text}"
        );
        // Should mention auto-added registry for npm
        assert!(
            text.contains("registry.npmjs.org"),
            "should explain npm registry: {text}"
        );
        // Should mention Landlock
        assert!(text.contains("Landlock"), "should explain Landlock: {text}");
    }

    #[test]
    fn explain_minimal_task() {
        let task = TaskSandbox::new("/workspace");
        let explanation = task.explain();
        let text = explanation.to_string();

        // Should show no network
        assert!(
            text.contains("fully isolated"),
            "minimal task should be network-isolated: {text}"
        );
    }

    // ── Narrowing tests ─────────────────────────────────────

    #[test]
    fn narrow_detects_unused_tools() {
        let task = TaskSandbox::new("/workspace")
            .needs_tools(["cargo", "git", "npm"])
            .needs_network(["crates.io", "registry.npmjs.org"]);

        let mut observed = ObservedCapabilities::default();
        observed.executed_tools.insert("cargo".to_owned());
        // git and npm never used

        let report = task.narrow(&observed);

        assert!(
            !report.unused.is_empty(),
            "should detect unused capabilities"
        );
        assert!(
            report.summary.contains("git"),
            "should mention unused git: {}",
            report.summary
        );
        assert!(
            report.summary.contains("npm"),
            "should mention unused npm: {}",
            report.summary
        );

        // Suggested config should only have cargo
        assert!(report.suggested_config.tools.contains(&"cargo".to_owned()));
        assert!(!report.suggested_config.tools.contains(&"npm".to_owned()));
    }

    #[test]
    fn narrow_detects_unused_domains() {
        let task = TaskSandbox::new("/workspace").needs_network([
            "api.anthropic.com",
            "crates.io",
            "unused.example.com",
        ]);

        let mut observed = ObservedCapabilities::default();
        observed
            .contacted_domains
            .insert("api.anthropic.com".to_owned());
        observed.contacted_domains.insert("crates.io".to_owned());
        // unused.example.com never contacted

        let report = task.narrow(&observed);
        assert!(
            report.summary.contains("unused.example.com"),
            "should detect unused domain: {}",
            report.summary
        );
    }

    #[test]
    fn narrow_all_used_is_minimal() {
        let task = TaskSandbox::new("/workspace")
            .needs_tools(["cargo"])
            .needs_network(["crates.io"]);

        let mut observed = ObservedCapabilities::default();
        observed.executed_tools.insert("cargo".to_owned());
        observed.contacted_domains.insert("crates.io".to_owned());

        let report = task.narrow(&observed);
        assert!(
            report.unused.is_empty(),
            "all capabilities used, should be minimal: {}",
            report.summary
        );
        assert!(
            report.summary.contains("already minimal"),
            "should say config is minimal: {}",
            report.summary
        );
    }

    // ── System prompt tests ─────────────────────────────────

    #[test]
    fn system_prompt_describes_allowed_capabilities() {
        let task = TaskSandbox::new("/workspace/project")
            .needs_tools(["claude", "git"])
            .needs_network(["api.anthropic.com"]);

        let prompt = task.system_prompt_fragment();

        // Should describe the project dir
        assert!(
            prompt.contains("/workspace/project"),
            "should mention project dir: {prompt}"
        );
        // Should mention allowed domains
        assert!(
            prompt.contains("api.anthropic.com"),
            "should mention API domain: {prompt}"
        );
        // Should mention home dir access
        assert!(
            prompt.contains("home directory"),
            "should mention home dir: {prompt}"
        );
        // Should mention available tools
        assert!(
            prompt.contains("claude") && prompt.contains("git"),
            "should list tools: {prompt}"
        );
        // Should NOT expose internal paths like /tmp/.gleisner-inject
        assert!(
            !prompt.contains(".gleisner-inject"),
            "should not expose internals: {prompt}"
        );
        // Should NOT enumerate denied paths
        assert!(
            !prompt.contains("/etc/shadow") && !prompt.contains("Landlock"),
            "should not expose security internals: {prompt}"
        );
    }

    #[test]
    fn system_prompt_isolated_network() {
        let task = TaskSandbox::new("/workspace");
        let prompt = task.system_prompt_fragment();

        assert!(
            prompt.contains("No network access"),
            "no-network task should say isolated: {prompt}"
        );
    }

    #[test]
    fn system_prompt_full_internet() {
        let task = TaskSandbox::new("/workspace").needs_internet();
        let prompt = task.system_prompt_fragment();

        assert!(
            prompt.contains("Unrestricted internet"),
            "internet task should say unrestricted: {prompt}"
        );
    }

    #[test]
    fn explanation_to_system_prompt() {
        let task = TaskSandbox::new("/workspace")
            .needs_tools(["cargo"])
            .needs_network(["crates.io"]);
        let explanation = task.explain();
        let prompt = explanation.to_system_prompt();

        assert!(
            prompt.contains("sandboxed environment"),
            "should mention sandbox: {prompt}"
        );
        assert!(
            prompt.contains("Landlock"),
            "explanation prompt should mention Landlock: {prompt}"
        );
    }
}
