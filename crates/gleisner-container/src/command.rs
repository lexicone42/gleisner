//! Command execution within a configured container.

use std::process::ExitStatus;
use std::time::Duration;

use crate::error::ContainerError;

/// Standard I/O stream configuration for a container command.
#[derive(Debug, Clone, Copy)]
pub enum Stdio {
    /// Inherit from the parent process.
    Inherit,
    /// Capture into a buffer (available in [`Output`]).
    Piped,
    /// Discard (connect to `/dev/null`).
    Null,
}

impl From<Stdio> for std::process::Stdio {
    fn from(s: Stdio) -> Self {
        match s {
            Stdio::Inherit => std::process::Stdio::inherit(),
            Stdio::Piped => std::process::Stdio::piped(),
            Stdio::Null => std::process::Stdio::null(),
        }
    }
}

/// A command to execute inside a container, analogous to [`std::process::Command`].
///
/// Configure stdio and timeouts before calling [`run()`](Command::run),
/// [`output()`](Command::output), or [`spawn()`](Command::spawn).
pub struct Command {
    pub(crate) prepared: gleisner_polis::PreparedSandbox,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    timeout: Option<Duration>,
}

impl Command {
    pub(crate) fn new(prepared: gleisner_polis::PreparedSandbox) -> Self {
        Self {
            prepared,
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
            timeout: None,
        }
    }

    /// Set the stdin configuration.
    pub fn stdin(mut self, stdio: Stdio) -> Self {
        self.stdin = stdio;
        self
    }

    /// Set the stdout configuration.
    pub fn stdout(mut self, stdio: Stdio) -> Self {
        self.stdout = stdio;
        self
    }

    /// Set the stderr configuration.
    pub fn stderr(mut self, stdio: Stdio) -> Self {
        self.stderr = stdio;
        self
    }

    /// Set a timeout for the command. If the process doesn't exit within
    /// this duration, it will be killed and an error returned.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Apply configured stdio to the underlying command.
    fn apply_stdio(&mut self) {
        self.prepared
            .command
            .stdin(std::process::Stdio::from(self.stdin));
        self.prepared
            .command
            .stdout(std::process::Stdio::from(self.stdout));
        self.prepared
            .command
            .stderr(std::process::Stdio::from(self.stderr));
    }

    /// Inherit stdin/stdout/stderr and wait for the process to exit.
    ///
    /// This is the typical mode for interactive processes like Claude Code.
    /// Respects any configured [`timeout()`](Command::timeout).
    pub fn run(mut self) -> Result<ExitStatus, ContainerError> {
        self.apply_stdio();

        let mut child = self.prepared.command.spawn()?;

        if let Some(timeout) = self.timeout {
            return wait_with_timeout(&mut child, timeout);
        }
        let status = child.wait()?;
        Ok(status)
    }

    /// Capture stdout and stderr, returning them with the exit status.
    ///
    /// By default captures both stdout and stderr. Override with
    /// [`.stdout()`](Command::stdout) / [`.stderr()`](Command::stderr)
    /// to change behavior (e.g., stream stderr while capturing stdout).
    ///
    /// Respects any configured [`timeout()`](Command::timeout).
    pub fn output(mut self) -> Result<Output, ContainerError> {
        // Default to piped for capture unless explicitly overridden
        if matches!(self.stdout, Stdio::Inherit) {
            self.stdout = Stdio::Piped;
        }
        if matches!(self.stderr, Stdio::Inherit) {
            self.stderr = Stdio::Piped;
        }
        self.stdin = Stdio::Null;
        self.apply_stdio();

        let start = std::time::Instant::now();

        if let Some(timeout) = self.timeout {
            let mut child = self.prepared.command.spawn()?;
            let status = wait_with_timeout(&mut child, timeout)?;
            // Read whatever was captured
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut out) = child.stdout.take() {
                std::io::Read::read_to_end(&mut out, &mut stdout).ok();
            }
            if let Some(mut err) = child.stderr.take() {
                std::io::Read::read_to_end(&mut err, &mut stderr).ok();
            }
            return Ok(Output {
                status,
                stdout,
                stderr,
                elapsed: start.elapsed(),
            });
        }

        let child_output = self.prepared.command.output()?;
        Ok(Output {
            status: child_output.status,
            stdout: child_output.stdout,
            stderr: child_output.stderr,
            elapsed: start.elapsed(),
        })
    }

    /// Spawn the process without waiting. Returns a [`Child`] handle.
    ///
    /// The caller must keep the `Child` alive — dropping it does NOT kill the
    /// process but does release namespace handles.
    pub fn spawn(mut self) -> Result<Child, ContainerError> {
        self.apply_stdio();
        let inner = self.prepared.command.spawn()?;
        Ok(Child {
            inner,
            _prepared: self.prepared,
            timeout: self.timeout,
        })
    }
}

/// A running process inside a container.
pub struct Child {
    inner: std::process::Child,
    /// Holds namespace/TAP handles alive while child runs.
    _prepared: gleisner_polis::PreparedSandbox,
    timeout: Option<Duration>,
}

/// Captured output from a finished container process.
#[derive(Debug)]
pub struct Output {
    /// Exit status of the process.
    pub status: ExitStatus,
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// Wall-clock duration of the process.
    pub elapsed: Duration,
}

impl Output {
    /// Stdout as a UTF-8 string, trimmed.
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }

    /// Stderr as a UTF-8 string, trimmed.
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }

    /// The exit code, or `None` if terminated by signal.
    pub fn exit_code(&self) -> Option<i32> {
        self.status.code()
    }

    /// The signal that terminated the process, if any (Unix only).
    #[cfg(unix)]
    pub fn signal(&self) -> Option<i32> {
        std::os::unix::process::ExitStatusExt::signal(&self.status)
    }

    /// Whether the process was killed by a signal (e.g., OOM killer, SIGKILL).
    #[cfg(unix)]
    pub fn was_signaled(&self) -> bool {
        self.signal().is_some()
    }
}

impl Child {
    /// Wait for the process to exit. Respects the timeout set on the
    /// original [`Command`], if any.
    pub fn wait(&mut self) -> Result<ExitStatus, ContainerError> {
        if let Some(timeout) = self.timeout {
            return wait_with_timeout(&mut self.inner, timeout);
        }
        Ok(self.inner.wait()?)
    }

    /// Get the OS-assigned process ID.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Attempt to kill the process.
    pub fn kill(&mut self) -> Result<(), ContainerError> {
        Ok(self.inner.kill()?)
    }
}

/// Wait for a child process with a timeout, killing it if exceeded.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<ExitStatus, ContainerError> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None => {
                if start.elapsed() >= timeout {
                    child.kill().ok();
                    child.wait().ok();
                    return Err(ContainerError::Timeout(timeout));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}
