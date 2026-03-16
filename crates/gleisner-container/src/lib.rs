//! Builder-pattern Linux container library with Landlock V7, seccomp, and
//! optional attestation hooks.
//!
//! `gleisner-container` wraps the sandbox internals from `gleisner-polis` into
//! an ergonomic builder API. Configure namespaces, mounts, security policies,
//! and network isolation through method chaining, then spawn isolated processes.
//!
//! # Quick start
//!
//! ```no_run
//! use gleisner_container::{Sandbox, Namespace};
//!
//! let mut sb = Sandbox::new();
//! sb.rootfs()                             // auto-discover host OS dirs
//!     .namespace(Namespace::Pid)
//!     .mount_readwrite("/workspace", "/workspace")
//!     .hostname("my-sandbox");
//!
//! let output = sb
//!     .command_with_args("/bin/echo", &["hello from sandbox"])
//!     .expect("build command")
//!     .output()
//!     .expect("run sandbox");
//!
//! assert!(output.status.success());
//! ```
//!
//! # Forge integration
//!
//! With the `forge` feature, sandboxes can be auto-configured from a
//! [minimal.dev](https://minimal.dev) forge composition:
//!
//! ```ignore
//! let sandbox = Sandbox::from_forge_output(&composed_env, project_dir)?;
//! ```

mod builder;
mod command;
mod error;
pub mod task;
mod types;

#[cfg(feature = "forge")]
mod forge;

#[cfg(feature = "lattice")]
pub mod verify;

pub use builder::Sandbox;
pub use command::{Child, Command, Output, Stdio};
pub use error::ContainerError;
pub use types::{
    ContainerDir, ContainerFile, ContainerSymlink, LandlockRule, Mount, Namespace, NetworkMode,
    SeccompPreset,
};

#[cfg(feature = "forge")]
pub use forge::{ForgeComposition, detect_harness, resolve_harness};
