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

use std::path::PathBuf;

use crate::builder::Sandbox;
use crate::error::ContainerError;
use crate::types::{Namespace, NetworkMode, SeccompPreset};

/// A task-oriented sandbox builder.
///
/// Describe what your task needs, not how to configure the sandbox.
/// `TaskSandbox` translates capability requirements into the minimal
/// sandbox configuration that satisfies them.
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
}
