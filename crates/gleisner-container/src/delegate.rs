//! Claude-to-Claude delegation protocol.
//!
//! An orchestrating Claude reasons about a task, derives the minimal sandbox
//! for a worker Claude, and collects attested results. This module provides
//! the structured protocol for this coordination.
//!
//! # Design
//!
//! The delegation flow:
//! 1. **Plan**: Outer Claude describes the task and context
//! 2. **Derive**: Capabilities are derived from the task description
//! 3. **Verify**: Z3 can verify the sandbox satisfies a policy (optional)
//! 4. **Execute**: Inner Claude runs in the derived sandbox
//! 5. **Attest**: Result includes what was done and what was accessed
//! 6. **Narrow**: Observation data tightens the next delegation
//!
//! ```no_run
//! use gleisner_container::delegate::Delegation;
//! use std::time::Duration;
//!
//! let result = Delegation::to("/workspace/project")
//!     .task("Fix the JWT expiry validation bug in src/auth.rs")
//!     .context("The bug is on line 42 — expiry check is skipped when iat is present")
//!     .allow_tools(["claude", "cargo", "git"])
//!     .allow_network(["api.anthropic.com"])
//!     .timeout(Duration::from_secs(300))
//!     .build()
//!     .expect("configure delegation");
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::Output;
use crate::error::ContainerError;
use crate::task::{CapabilityExplanation, TaskSandbox};

/// A structured delegation from an outer Claude to an inner Claude.
///
/// Bundles everything the inner Claude needs:
/// - Task description and context
/// - Sandbox configuration (derived from capabilities)
/// - System prompt with boundary awareness
/// - Timeout and resource constraints
#[derive(Debug)]
pub struct Delegation {
    /// Project directory for the inner Claude.
    project_dir: PathBuf,
    /// Human-readable task description.
    task_description: String,
    /// Additional context the inner Claude needs (e.g., bug location, prior analysis).
    context: Vec<String>,
    /// The underlying task sandbox configuration.
    task: TaskSandbox,
    /// Maximum time the inner Claude is allowed to run.
    timeout: Option<Duration>,
    /// Claude binary to use.
    claude_bin: String,
    /// Additional CLI arguments for the inner Claude.
    claude_args: Vec<String>,
}

/// Result of a completed delegation.
#[derive(Debug)]
pub struct DelegationResult {
    /// Captured output from the inner Claude process.
    pub output: Output,
    /// The system prompt that was injected.
    pub injected_prompt: String,
    /// The capability explanation for audit.
    pub capabilities: CapabilityExplanation,
    /// Path to the context file written to the project dir.
    pub context_file: Option<PathBuf>,
}

impl Delegation {
    /// Start building a delegation to a project directory.
    ///
    /// By default includes `claude` and `node` as tools. Does NOT forward
    /// `ANTHROPIC_API_KEY` — call [`.forward_api_key()`](Delegation::forward_api_key)
    /// explicitly to grant the inner Claude API access.
    pub fn to(project_dir: impl Into<PathBuf>) -> Self {
        let project_dir = project_dir.into();
        let task = TaskSandbox::new(&project_dir).needs_tools(["claude", "node"]);
        Self {
            task,
            project_dir,
            task_description: String::new(),
            context: Vec::new(),
            timeout: None,
            claude_bin: "claude".to_owned(),
            claude_args: Vec::new(),
        }
    }

    /// Build a delegation from a minimal.toml task definition.
    ///
    /// Parses the minimal.toml config, extracts the named task's sandbox
    /// configuration, and adds `claude` + `node` as additional tools.
    /// The task description becomes the delegation's task.
    ///
    /// ```no_run
    /// use gleisner_container::delegate::Delegation;
    /// use gleisner_container::minimal_toml::MinimalConfig;
    ///
    /// let config = MinimalConfig::from_file("minimal.toml").unwrap();
    /// let delegation = Delegation::from_minimal_task(
    ///     &config,
    ///     "claude",
    ///     "/workspace/project",
    ///     "Fix the auth bug in src/auth.rs",
    /// ).unwrap();
    /// ```
    pub fn from_minimal_task(
        config: &crate::minimal_toml::MinimalConfig,
        task_name: &str,
        project_dir: impl Into<PathBuf>,
        task_description: impl Into<String>,
    ) -> Result<Self, ContainerError> {
        let project_dir = project_dir.into();
        let mut task = config.task_sandbox(task_name, &project_dir)?;
        // Always add claude + node for delegation
        task = task.needs_tools(["claude", "node"]);

        Ok(Self {
            task,
            project_dir,
            task_description: task_description.into(),
            context: Vec::new(),
            timeout: None,
            claude_bin: "claude".to_owned(),
            claude_args: Vec::new(),
        })
    }

    /// Describe the task for the inner Claude.
    pub fn task(mut self, description: impl Into<String>) -> Self {
        self.task_description = description.into();
        self
    }

    /// Add context the inner Claude needs (can be called multiple times).
    pub fn context(mut self, ctx: impl Into<String>) -> Self {
        self.context.push(ctx.into());
        self
    }

    /// Declare tools the inner Claude will need.
    pub fn allow_tools(mut self, tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.task = self.task.needs_tools(tools);
        self
    }

    /// Declare network domains the inner Claude will need.
    pub fn allow_network(mut self, domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.task = self.task.needs_network(domains);
        self
    }

    /// Declare paths the inner Claude needs to read.
    pub fn allow_read(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.task = self.task.needs_read(paths);
        self
    }

    /// Declare paths the inner Claude needs to write.
    pub fn allow_write(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.task = self.task.needs_write(paths);
        self
    }

    /// Forward the `ANTHROPIC_API_KEY` environment variable to the inner Claude.
    ///
    /// This is required for the inner Claude to make API calls. It is NOT
    /// forwarded by default because the API key is a sensitive credential
    /// that the inner process could exfiltrate if compromised.
    ///
    /// Only call this when the inner Claude genuinely needs API access
    /// (e.g., for `--print` mode or interactive sessions).
    pub fn forward_api_key(mut self) -> Self {
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            self.task = self.task.env("ANTHROPIC_API_KEY", key);
        }
        self
    }

    /// Set a timeout for the delegation.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Set the Claude binary path.
    pub fn claude_bin(mut self, bin: impl Into<String>) -> Self {
        self.claude_bin = bin.into();
        self
    }

    /// Add CLI arguments for the inner Claude.
    pub fn claude_arg(mut self, arg: impl Into<String>) -> Self {
        self.claude_args.push(arg.into());
        self
    }

    /// Get the explanation of what the delegation will grant.
    pub fn explain(&self) -> CapabilityExplanation {
        self.task.explain()
    }

    /// Get the system prompt that will be injected.
    pub fn system_prompt(&self) -> String {
        let mut prompt = self.task.system_prompt_fragment();

        if !self.task_description.is_empty() {
            prompt.push_str("\n\nTask:\n");
            prompt.push_str(&self.task_description);
        }

        if !self.context.is_empty() {
            prompt.push_str("\n\nContext:\n");
            for ctx in &self.context {
                prompt.push_str("- ");
                prompt.push_str(ctx);
                prompt.push('\n');
            }
        }

        prompt
    }

    /// Build the delegation — writes context file, builds sandbox.
    ///
    /// This prepares everything for execution but doesn't launch the
    /// inner Claude yet. Call [`execute()`](PreparedDelegation::execute)
    /// on the result.
    pub fn build(self) -> Result<PreparedDelegation, ContainerError> {
        // Write context file to project dir
        let context_file = match self.task.write_context_file() {
            Ok(path) => Some(path),
            Err(e) => {
                tracing::warn!(error = %e, "failed to write sandbox-context.md — inner agent will lack boundary awareness");
                None
            }
        };

        // Build the sandbox
        let sandbox = self.task.build()?;

        Ok(PreparedDelegation {
            sandbox,
            project_dir: self.project_dir,
            task_description: self.task_description,
            context: self.context,
            timeout: self.timeout,
            claude_bin: self.claude_bin,
            claude_args: self.claude_args,
            context_file,
            capabilities: self.task.explain(),
            prompt: self.task.system_prompt_fragment(),
        })
    }
}

/// A prepared delegation ready for execution.
pub struct PreparedDelegation {
    sandbox: crate::builder::Sandbox,
    /// Reserved for future use (attestation, workspace management).
    #[allow(dead_code)]
    project_dir: PathBuf,
    task_description: String,
    /// Reserved for future use (structured context injection).
    #[allow(dead_code)]
    context: Vec<String>,
    timeout: Option<Duration>,
    claude_bin: String,
    claude_args: Vec<String>,
    context_file: Option<PathBuf>,
    capabilities: CapabilityExplanation,
    prompt: String,
}

impl PreparedDelegation {
    /// Execute the delegation — spawns the inner Claude in the sandbox.
    ///
    /// The inner Claude receives:
    /// - The task description via `--print` (non-interactive one-shot mode)
    /// - The sandbox context file at `.gleisner/sandbox-context.md`
    /// - A sandboxed environment with exactly the declared capabilities
    pub fn execute(self) -> Result<DelegationResult, ContainerError> {
        let mut args = vec![self.claude_bin.clone()];
        args.push("--print".to_owned());
        args.push(self.task_description.clone());
        args.extend(self.claude_args.clone());

        let cmd = self.sandbox.command_with_args(&args[0], &args[1..])?;

        let cmd = if let Some(timeout) = self.timeout {
            cmd.timeout(timeout)
        } else {
            cmd
        };

        let output = cmd.output()?;

        Ok(DelegationResult {
            output,
            injected_prompt: self.prompt,
            capabilities: self.capabilities,
            context_file: self.context_file,
        })
    }

    /// The explanation of what was granted.
    pub fn capabilities(&self) -> &CapabilityExplanation {
        &self.capabilities
    }

    /// The system prompt that will be visible to the inner Claude.
    pub fn system_prompt(&self) -> &str {
        &self.prompt
    }

    /// The path to the context file, if written.
    pub fn context_file(&self) -> Option<&Path> {
        self.context_file.as_deref()
    }
}

impl DelegationResult {
    /// Whether the inner Claude completed successfully.
    pub fn success(&self) -> bool {
        self.output.status.success()
    }

    /// The inner Claude's response (stdout).
    pub fn response(&self) -> String {
        self.output.stdout_str()
    }

    /// Any errors from the inner Claude (stderr).
    pub fn errors(&self) -> String {
        self.output.stderr_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_builder() {
        let d = Delegation::to("/workspace/project")
            .task("Fix the auth bug")
            .context("Bug is in src/auth.rs:42")
            .context("JWT expiry check is skipped")
            .allow_tools(["cargo", "git"])
            .allow_network(["api.anthropic.com"])
            .timeout(Duration::from_secs(300));

        // Check the system prompt includes task and context
        let prompt = d.system_prompt();
        assert!(
            prompt.contains("Fix the auth bug"),
            "should include task: {prompt}"
        );
        assert!(
            prompt.contains("src/auth.rs:42"),
            "should include context: {prompt}"
        );
        assert!(
            prompt.contains("api.anthropic.com"),
            "should include network: {prompt}"
        );
    }

    #[test]
    fn forward_api_key_is_opt_in() {
        // Default: API key is NOT forwarded
        let d = Delegation::to("/workspace")
            .task("Test")
            .allow_tools(["sh"]);

        let prompt = d.system_prompt();
        assert!(
            !prompt.contains("ANTHROPIC_API_KEY"),
            "API key should not be in prompt by default: {prompt}"
        );

        // The task's env should not contain the key by default
        // (We test this indirectly via the explain output)
        let explanation = d.explain();
        let has_api_key_grant = explanation
            .grants
            .iter()
            .any(|g| g.capability.contains("ANTHROPIC_API_KEY"));
        assert!(
            !has_api_key_grant,
            "API key should not be in grants by default: {:?}",
            explanation.grants
        );
    }

    #[test]
    fn delegation_explain() {
        let d = Delegation::to("/workspace")
            .task("Run tests")
            .allow_tools(["cargo", "git"]);

        let explanation = d.explain();
        assert!(
            explanation.grants.len() >= 4,
            "should have grants: {:?}",
            explanation.grants.len()
        );
    }

    #[test]
    fn delegation_system_prompt_security() {
        let d = Delegation::to("/workspace")
            .task("Secret task")
            .allow_tools(["claude"]);

        let prompt = d.system_prompt();

        // Should NOT expose sandbox internals
        assert!(
            !prompt.contains("Landlock"),
            "no sandbox internals: {prompt}"
        );
        assert!(
            !prompt.contains("seccomp"),
            "no sandbox internals: {prompt}"
        );
        assert!(
            !prompt.contains("gleisner-sandbox-init"),
            "no binary paths: {prompt}"
        );

        // Should include the task
        assert!(
            prompt.contains("Secret task"),
            "should include task: {prompt}"
        );
    }

    #[test]
    fn prepared_delegation_has_metadata() {
        let d = Delegation::to("/tmp/test-delegation")
            .task("Test delegation")
            .allow_tools(["sh"]);

        // Create the project dir so write_context_file works
        std::fs::create_dir_all("/tmp/test-delegation/.gleisner").ok();

        let prepared = d.build().expect("build delegation");

        assert!(!prepared.system_prompt().is_empty());
        assert!(prepared.capabilities().grants.len() >= 4);

        // Clean up
        std::fs::remove_dir_all("/tmp/test-delegation/.gleisner").ok();
    }
}
