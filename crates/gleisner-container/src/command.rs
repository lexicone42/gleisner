//! Command execution within a configured container.

use std::process::ExitStatus;

use crate::error::ContainerError;

/// A command to execute inside a container, analogous to [`std::process::Command`].
pub struct Command {
    pub(crate) prepared: gleisner_polis::PreparedSandbox,
}

/// A running process inside a container.
pub struct Child {
    inner: std::process::Child,
    /// Holds namespace/TAP handles alive while child runs.
    _prepared: gleisner_polis::PreparedSandbox,
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
}

impl Command {
    /// Inherit stdin/stdout/stderr and wait for the process to exit.
    ///
    /// This is the typical mode for interactive processes like Claude Code.
    pub fn run(mut self) -> Result<ExitStatus, ContainerError> {
        self.prepared
            .command
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());

        let mut child = self.prepared.command.spawn()?;
        let status = child.wait()?;
        Ok(status)
    }

    /// Capture stdout and stderr, returning them with the exit status.
    pub fn output(mut self) -> Result<Output, ContainerError> {
        self.prepared
            .command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let child_output = self.prepared.command.output()?;
        Ok(Output {
            status: child_output.status,
            stdout: child_output.stdout,
            stderr: child_output.stderr,
        })
    }

    /// Spawn the process without waiting. Returns a [`Child`] handle.
    ///
    /// The caller must keep the `Child` alive — dropping it does NOT kill the
    /// process but does release namespace handles.
    pub fn spawn(mut self) -> Result<Child, ContainerError> {
        self.prepared
            .command
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());

        let inner = self.prepared.command.spawn()?;
        Ok(Child {
            inner,
            _prepared: self.prepared,
        })
    }
}

impl Child {
    /// Wait for the process to exit.
    pub fn wait(&mut self) -> Result<ExitStatus, ContainerError> {
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
