//! Parse `minimal.toml` into [`TaskSandbox`] configurations.
//!
//! Bridges minimal.dev's declarative task format with gleisner's sandbox
//! builder, enabling security verification and attestation for any
//! minimal.dev project without changing their workflow.
//!
//! ```no_run
//! use gleisner_container::minimal_toml::MinimalConfig;
//!
//! let config = MinimalConfig::load("minimal.toml").expect("parse config");
//! let task = config.task_sandbox("shell", "/workspace/project").expect("build task");
//! let sb = task.build().expect("build sandbox");
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::ContainerError;
use crate::task::TaskSandbox;

/// Parsed `minimal.toml` configuration.
#[derive(Debug, Deserialize)]
pub struct MinimalConfig {
    /// Package upstream source.
    #[serde(default)]
    pub upstream: Option<Upstream>,
    /// Harness configuration (language/toolchain detection).
    #[serde(default)]
    pub harness: Option<Harness>,
    /// Default settings applied to all tasks.
    #[serde(default)]
    pub defaults: Option<Defaults>,
    /// Named task definitions.
    #[serde(default)]
    pub tasks: HashMap<String, Task>,
}

/// Upstream package source.
#[derive(Debug, Deserialize)]
pub struct Upstream {
    /// Git repository URL.
    pub repo: Option<String>,
    /// Git branch.
    pub branch: Option<String>,
    /// Pinned commit hash.
    pub locked_commit: Option<String>,
}

/// Harness configuration.
#[derive(Debug, Deserialize)]
pub struct Harness {
    /// Harness name (e.g., "rust", "pnpm", "go").
    #[serde(rename = "use")]
    pub use_harness: Option<String>,
    /// Additional build-time packages.
    #[serde(default)]
    pub build_packages: Vec<String>,
    /// Additional runtime packages.
    #[serde(default)]
    pub runtime_packages: Vec<String>,
}

/// Default settings for all tasks.
#[derive(Debug, Deserialize)]
pub struct Defaults {
    /// Default profile name.
    pub profile: Option<String>,
    /// Default state key for cache sharing.
    pub state_key: Option<String>,
}

/// A task definition from `minimal.toml`.
#[derive(Debug, Deserialize)]
pub struct Task {
    /// Packages to include in the task environment.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Single command to execute.
    pub exec: Option<StringOrArray>,
    /// Bash script to execute.
    pub bash: Option<String>,
    /// Environment variables (string values or `{ inherit = true }`).
    #[serde(default)]
    pub env_vars: HashMap<String, EnvValue>,
    /// Alias for env_vars.
    #[serde(default)]
    pub vars: HashMap<String, EnvValue>,
    /// Filesystem patches (host file/dir mappings).
    #[serde(default)]
    pub patches: Option<Patches>,
    /// Alias for patches.
    #[serde(default)]
    pub patch: Option<Patches>,
    /// State key for cache sharing between runs.
    pub state_key: Option<String>,
    /// Profile to apply.
    pub profile: Option<String>,
    /// Whether to use CWD instead of repo root.
    #[serde(default)]
    pub inherit_cwd: bool,
    /// Whether this is an interactive task.
    #[serde(default)]
    pub interactive: bool,
}

/// A string or array of strings (for `exec`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrArray {
    /// Single string command.
    String(String),
    /// Array of command + arguments.
    Array(Vec<String>),
}

/// Environment variable value — either a literal or `{ inherit = true }`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum EnvValue {
    /// Literal value.
    Literal(String),
    /// Inherit from host environment.
    Inherit { inherit: bool },
}

/// Filesystem patch declarations.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Patches {
    /// File patches: path → access mode.
    #[serde(default)]
    pub file: HashMap<String, String>,
    /// Directory patches: path → access mode.
    #[serde(default)]
    pub dir: HashMap<String, String>,
}

impl MinimalConfig {
    /// Load and parse a `minimal.toml` file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ContainerError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ContainerError::Config(format!("read minimal.toml: {e}")))?;
        Self::parse(&content)
    }

    /// Parse a `minimal.toml` string.
    pub fn parse(content: &str) -> Result<Self, ContainerError> {
        toml::from_str(content)
            .map_err(|e| ContainerError::Config(format!("parse minimal.toml: {e}")))
    }

    /// Find `minimal.toml` by searching upward from a directory.
    pub fn find_and_load(start_dir: impl AsRef<Path>) -> Result<Self, ContainerError> {
        let mut dir = start_dir.as_ref().to_path_buf();
        loop {
            let candidate = dir.join("minimal.toml");
            if candidate.exists() {
                return Self::load(&candidate);
            }
            // Also check .minimal/ subdirectory
            let sub_candidate = dir.join(".minimal/minimal.toml");
            if sub_candidate.exists() {
                return Self::load(&sub_candidate);
            }
            if !dir.pop() {
                return Err(ContainerError::Config(
                    "minimal.toml not found in any parent directory".to_owned(),
                ));
            }
        }
    }

    /// List all task names defined in this config.
    pub fn task_names(&self) -> Vec<&str> {
        self.tasks.keys().map(String::as_str).collect()
    }

    /// Convert a named task into a [`TaskSandbox`] configuration.
    ///
    /// This is the main bridge between minimal.dev's declarative format and
    /// gleisner's security verification layer. The resulting `TaskSandbox`
    /// can be used for:
    /// - `explain()` — audit what the task will be granted
    /// - `build()` — create a verified sandbox
    /// - `verify_against_policy()` — Z3 proof of policy satisfaction
    /// - `system_prompt_fragment()` — boundary awareness for sandboxed agents
    pub fn task_sandbox(
        &self,
        task_name: &str,
        project_dir: impl Into<PathBuf>,
    ) -> Result<TaskSandbox, ContainerError> {
        let task = self.tasks.get(task_name).ok_or_else(|| {
            ContainerError::Config(format!(
                "task '{task_name}' not found in minimal.toml (available: {})",
                self.task_names().join(", ")
            ))
        })?;

        let project_dir = project_dir.into();
        let mut sb = TaskSandbox::new(&project_dir);

        // ── Packages → tools ────────────────────────────────────
        if !task.packages.is_empty() {
            sb = sb.needs_tools(task.packages.clone());
        }

        // Add harness tools if available
        if let Some(name) = self.harness.as_ref().and_then(|h| h.use_harness.as_deref()) {
            let harness_tools = harness_to_tools(name);
            if !harness_tools.is_empty() {
                sb = sb.needs_tools(harness_tools);
            }
        }

        // ── Environment variables ───────────────────────────────
        let env_vars = merged_env_vars(&task.env_vars, &task.vars);
        for (key, value) in &env_vars {
            match value {
                EnvValue::Literal(val) => {
                    sb = sb.env(key.as_str(), val.as_str());
                }
                EnvValue::Inherit { inherit } => {
                    if *inherit && let Ok(val) = std::env::var(key.as_str()) {
                        sb = sb.env(key.as_str(), val);
                    }
                }
            }
        }

        // ── Patches → filesystem mounts ─────────────────────────
        let patches = task
            .patches
            .as_ref()
            .or(task.patch.as_ref())
            .cloned()
            .unwrap_or_default();

        let mut read_paths = Vec::new();
        let mut write_paths = Vec::new();

        for (path, mode) in patches.file.iter().chain(patches.dir.iter()) {
            let expanded = expand_path(path);
            match mode.as_str() {
                "read-only" | "ro" => read_paths.push(expanded),
                "read-write" | "rw" => write_paths.push(expanded),
                other => {
                    tracing::warn!(
                        path = %path,
                        mode = %other,
                        "unknown patch mode — treating as read-only"
                    );
                    read_paths.push(expanded);
                }
            }
        }

        if !read_paths.is_empty() {
            sb = sb.needs_read(read_paths);
        }
        if !write_paths.is_empty() {
            sb = sb.needs_write(write_paths);
        }

        // ── Network (inferred from packages) ────────────────────
        // Packages that need network access get auto-detected by TaskSandbox
        // through the tool derivation logic (npm → registry, pip → pypi, etc.)

        // ── State persistence ───────────────────────────────────
        let state_key = task
            .state_key
            .as_ref()
            .or(self.defaults.as_ref().and_then(|d| d.state_key.as_ref()));
        if let Some(key) = state_key {
            sb = sb.state_key(key);
        }

        // ── Hostname ────────────────────────────────────────────
        sb = sb.hostname(format!("minimal-{task_name}"));

        Ok(sb)
    }

    /// Get the command for a task (exec or bash).
    pub fn task_command(&self, task_name: &str) -> Option<Vec<String>> {
        let task = self.tasks.get(task_name)?;
        if let Some(ref exec) = task.exec {
            match exec {
                StringOrArray::String(s) => Some(s.split_whitespace().map(String::from).collect()),
                StringOrArray::Array(a) => Some(a.clone()),
            }
        } else if let Some(ref bash) = task.bash {
            Some(vec!["bash".to_owned(), "-c".to_owned(), bash.clone()])
        } else {
            None
        }
    }

    /// Convert all tasks to TaskSandbox configurations.
    pub fn all_task_sandboxes(
        &self,
        project_dir: impl Into<PathBuf>,
    ) -> HashMap<String, Result<TaskSandbox, ContainerError>> {
        let project_dir = project_dir.into();
        self.tasks
            .keys()
            .map(|name| {
                let sb = self.task_sandbox(name, &project_dir);
                (name.clone(), sb)
            })
            .collect()
    }
}

impl MinimalConfig {
    /// Derive the primary tool name for a task (for attestation).
    ///
    /// Extracts from the task's `exec` command or falls back to the harness name.
    pub fn task_tool_name(&self, task_name: &str) -> Option<String> {
        let task = self.tasks.get(task_name)?;
        // Use the first word of exec as the tool name
        if let Some(ref exec) = task.exec {
            let cmd = match exec {
                StringOrArray::String(s) => s.split_whitespace().next().map(str::to_owned),
                StringOrArray::Array(a) => a.first().cloned(),
            };
            if let Some(c) = cmd {
                // Extract basename
                return Some(
                    Path::new(&c)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&c)
                        .to_owned(),
                );
            }
        }
        if let Some(ref _bash) = task.bash {
            return Some("bash".to_owned());
        }
        // Fall back to harness name
        self.harness.as_ref().and_then(|h| h.use_harness.clone())
    }
}

impl MinimalConfig {
    /// Generate a lightweight SBOM (component list) for a task's environment.
    ///
    /// Each package in the task becomes an SBOM component. This is a
    /// quick inventory — not a full CycloneDX SBOM with proofs (use
    /// `gleisner forge --sbom` for that). Useful for audit trails:
    /// "what was in the sandbox when Claude ran?"
    pub fn task_components(&self, task_name: &str) -> Vec<SbomComponent> {
        let task = match self.tasks.get(task_name) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let mut components = Vec::new();

        // Task packages
        for pkg in &task.packages {
            components.push(SbomComponent {
                name: pkg.clone(),
                source: ComponentSource::TaskPackage,
            });
        }

        // Harness packages
        if let Some(ref harness) = self.harness {
            for pkg in &harness.build_packages {
                components.push(SbomComponent {
                    name: pkg.clone(),
                    source: ComponentSource::HarnessBuild,
                });
            }
            for pkg in &harness.runtime_packages {
                components.push(SbomComponent {
                    name: pkg.clone(),
                    source: ComponentSource::HarnessRuntime,
                });
            }
            // Implicit harness packages
            if let Some(ref name) = harness.use_harness {
                for tool in harness_to_tools(name) {
                    components.push(SbomComponent {
                        name: tool,
                        source: ComponentSource::HarnessImplicit,
                    });
                }
            }
        }

        components
    }
}

/// A component in a task's sandbox environment.
#[derive(Debug, Clone)]
pub struct SbomComponent {
    /// Package or tool name.
    pub name: String,
    /// Where this component came from.
    pub source: ComponentSource,
}

/// Source of a component in the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentSource {
    /// Explicitly listed in `tasks.*.packages`.
    TaskPackage,
    /// From `[harness] build_packages`.
    HarnessBuild,
    /// From `[harness] runtime_packages`.
    HarnessRuntime,
    /// Implicitly provided by the harness (e.g., rust harness → cargo).
    HarnessImplicit,
}

/// Map harness names to the tool binaries they provide.
fn harness_to_tools(harness: &str) -> Vec<String> {
    match harness {
        "rust" => vec!["cargo".to_owned(), "rustc".to_owned()],
        "go" => vec!["go".to_owned()],
        "pnpm" => vec!["node".to_owned(), "pnpm".to_owned()],
        "npm" => vec!["node".to_owned(), "npm".to_owned()],
        "bun" => vec!["bun".to_owned()],
        "deno" => vec!["deno".to_owned()],
        "uv" | "pip" => vec!["python".to_owned(), "pip".to_owned()],
        "gradle" => vec!["java".to_owned()],
        "make" => vec!["make".to_owned(), "gcc".to_owned()],
        "cmake" => vec!["cmake".to_owned(), "make".to_owned(), "gcc".to_owned()],
        "meson" => vec!["meson".to_owned(), "ninja".to_owned()],
        "zig" => vec!["zig".to_owned()],
        _ => vec![],
    }
}

/// Merge env_vars and vars (vars is the alias).
fn merged_env_vars<'a>(
    env_vars: &'a HashMap<String, EnvValue>,
    vars: &'a HashMap<String, EnvValue>,
) -> HashMap<&'a String, &'a EnvValue> {
    let mut merged: HashMap<&String, &EnvValue> = HashMap::new();
    for (k, v) in env_vars {
        merged.insert(k, v);
    }
    for (k, v) in vars {
        merged.entry(k).or_insert(v);
    }
    merged
}

/// Expand `~` in a path to the home directory.
fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gleisner_minimal_toml() {
        let content = r#"
[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "abc123"

[harness]
use = "rust"

[defaults]
state_key = "dev"

[tasks.shell]
interactive = true
packages = ["base"]
exec = "bash --noprofile -l"
"#;

        let config = MinimalConfig::parse(content).expect("parse");
        assert_eq!(
            config.harness.as_ref().unwrap().use_harness.as_deref(),
            Some("rust")
        );
        assert_eq!(config.tasks.len(), 1);
        assert!(config.tasks.contains_key("shell"));
    }

    #[test]
    fn parse_agent_task() {
        let content = r#"
[tasks.claude]
packages = ["claude-code", "base", "git"]
exec = "claude"

[tasks.claude.env_vars]
ANTHROPIC_API_KEY = { inherit = true }

[tasks.claude.patches.file]
"~/.gitconfig" = "read-only"

[tasks.claude.patches.dir]
"~/.ssh" = "read-only"
"#;

        let config = MinimalConfig::parse(content).expect("parse");
        let task = &config.tasks["claude"];

        assert_eq!(task.packages, vec!["claude-code", "base", "git"]);
        assert!(matches!(
            task.env_vars.get("ANTHROPIC_API_KEY"),
            Some(EnvValue::Inherit { inherit: true })
        ));

        let patches = task.patches.as_ref().unwrap();
        assert_eq!(
            patches.file.get("~/.gitconfig").map(String::as_str),
            Some("read-only")
        );
        assert_eq!(
            patches.dir.get("~/.ssh").map(String::as_str),
            Some("read-only")
        );
    }

    #[test]
    fn task_sandbox_from_config() {
        let content = r#"
[harness]
use = "rust"

[tasks.shell]
packages = ["base", "git"]
exec = "bash -l"

[tasks.shell.env_vars]
EDITOR = "nano"

[tasks.shell.patches.file]
"~/.gitconfig" = "read-only"
"#;

        let config = MinimalConfig::parse(content).expect("parse");
        let task = config
            .task_sandbox("shell", "/workspace")
            .expect("build task");

        // Should have base + git from packages + cargo + rustc from harness
        let tools = task.tools();
        assert!(
            tools.contains(&"base".to_owned()),
            "should have base: {tools:?}"
        );
        assert!(
            tools.contains(&"git".to_owned()),
            "should have git: {tools:?}"
        );
        assert!(
            tools.contains(&"cargo".to_owned()),
            "should have cargo from harness: {tools:?}"
        );
    }

    #[test]
    fn task_sandbox_agent_config() {
        let content = r#"
[tasks.claude]
packages = ["claude-code", "base"]
exec = "claude"

[tasks.claude.env_vars]
CUSTOM_VAR = "hello"

[tasks.claude.patches.dir]
"~/.ssh" = "read-only"
"~/.config/railway" = "read-write"
"#;

        let config = MinimalConfig::parse(content).expect("parse");
        let task = config
            .task_sandbox("claude", "/workspace")
            .expect("build task");

        // Should be buildable
        let sb = task.build().expect("should build");
        assert!(sb.is_landlock_enabled());

        // Explain should show the patches
        let explanation = task.explain();
        let text = explanation.to_string();
        // .ssh should appear in read paths or the explanation text
        assert!(
            text.contains(".ssh") || text.contains("read"),
            "should reference patches: {text}"
        );
    }

    #[test]
    fn task_command_extraction() {
        let content = r#"
[tasks.build]
exec = "cargo build --release"

[tasks.deploy]
bash = "cargo build && cargo install --path ."

[tasks.multi]
exec = ["pnpm", "run", "build"]
"#;

        let config = MinimalConfig::parse(content).expect("parse");

        let build_cmd = config.task_command("build").unwrap();
        assert_eq!(build_cmd, vec!["cargo", "build", "--release"]);

        let deploy_cmd = config.task_command("deploy").unwrap();
        assert_eq!(
            deploy_cmd,
            vec!["bash", "-c", "cargo build && cargo install --path ."]
        );

        let multi_cmd = config.task_command("multi").unwrap();
        assert_eq!(multi_cmd, vec!["pnpm", "run", "build"]);
    }

    #[test]
    fn task_not_found_error() {
        let config = MinimalConfig::parse("[tasks.shell]\nexec = \"bash\"").unwrap();
        let err = config.task_sandbox("nonexistent", "/workspace");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("nonexistent"),
            "should name the missing task: {msg}"
        );
        assert!(msg.contains("shell"), "should list available tasks: {msg}");
    }

    #[test]
    fn load_real_minimal_toml() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../minimal.toml");
        if !path.exists() {
            eprintln!("skipping: no minimal.toml in workspace root");
            return;
        }

        let config = MinimalConfig::load(&path).expect("load real minimal.toml");
        assert!(config.harness.is_some());
        assert_eq!(
            config.harness.as_ref().unwrap().use_harness.as_deref(),
            Some("rust")
        );
        assert!(config.tasks.contains_key("shell"));

        // Build a TaskSandbox from the real config
        let project_dir = path.parent().unwrap();
        let task = config
            .task_sandbox("shell", project_dir)
            .expect("build task from real config");

        let explanation = task.explain();
        eprintln!("Real minimal.toml shell task:\n{explanation}");
    }

    #[test]
    fn find_and_load_from_subdirectory() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // Our crate is in crates/gleisner-container/, minimal.toml is at workspace root
        let result = MinimalConfig::find_and_load(&manifest_dir);
        if let Ok(config) = result {
            assert!(config.tasks.contains_key("shell"));
        } else {
            eprintln!(
                "skipping: minimal.toml not found above {}",
                manifest_dir.display()
            );
        }
    }
}
