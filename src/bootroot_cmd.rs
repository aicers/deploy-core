//! Product-neutral primitives for invoking the bootroot binary.
//!
//! [`BootrootRunner`] runs the bootroot CLI on a host through an [`Executor`],
//! from a pinned working directory so bootroot resolves one absolute
//! `state.json`/`secrets/` tree rather than a cwd-relative one. [`AppRole`] is
//! the role-id/secret-id credential pair bootroot mints. Neither carries any
//! product concept, so a runtime consumer (the on-host agent acting as the
//! registrar) can run `service add` and hold the resulting credential without
//! the installer: it constructs a runner from a resolved command path and
//! working directory ([`BootrootRunner::new`]) rather than from the installer's
//! payload/manifest.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::executor::{CommandOutput, Executor, ExecutorError, Identity};

/// Invokes the bootroot binary on a host through its executor, from a pinned
/// working directory.
///
/// Every invocation runs from the pinned **working directory** (the bootroot
/// state tree, `/var/lib/clumit-<product>/bootroot`) so bootroot reads and
/// writes one absolute state tree rather than a cwd-relative one that would
/// drift with wherever the caller was invoked from. bootroot resolves
/// `state.json` relative to its cwd (its CLI exposes no global `--state-file`,
/// and `--secrets-dir` is accepted by only a handful of subcommands, so a flag
/// cannot pin it uniformly), and records its `secrets/` location into that
/// `state.json` at `init` time. Pinning the directory here keeps every phase
/// consistent: `service add` finds the infra state `init` wrote, and a caller
/// fetches the remote-bootstrap bundle from exactly where `service add` wrote it
/// (`<state-dir>/secrets/...`).
pub struct BootrootRunner<'a> {
    executor: &'a dyn Executor,
    command_path: String,
    state_dir: PathBuf,
}

impl<'a> BootrootRunner<'a> {
    /// Builds a runner from an already-resolved bootroot command path and pinned
    /// working directory. The installer resolves these from its payload/manifest;
    /// a runtime consumer resolves them from its own configuration.
    #[must_use]
    pub fn new(executor: &'a dyn Executor, command_path: String, state_dir: PathBuf) -> Self {
        Self {
            executor,
            command_path,
            state_dir,
        }
    }

    /// Returns the resolved bootroot command path.
    #[must_use]
    pub fn command_path(&self) -> &str {
        &self.command_path
    }

    /// Returns the pinned working directory every bootroot invocation runs from,
    /// so bootroot resolves its `state.json`/`secrets/` tree there (also set as
    /// the `WorkingDirectory=` of the detached rotation units).
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Runs bootroot with `args` as `identity`, from the pinned working
    /// directory, capturing its output.
    ///
    /// The infra commands name [`Identity::Root`]: bootroot drives Docker and
    /// writes to system paths, so they elevate. The read-only queries name
    /// [`Identity::Operator`].
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when the command cannot be spawned, elevation
    /// fails, or the transport fails. A non-zero exit is a [`CommandOutput`],
    /// not an error.
    pub fn run(&self, identity: Identity, args: &[&str]) -> Result<CommandOutput, ExecutorError> {
        self.executor
            .run_in(identity, &self.state_dir, &self.command_path, args)
    }
}

/// One AppRole captured from the `init` summary — the service-registration
/// credential and the two rotation credentials (RFC 0001 §6 Phase 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRole {
    /// The AppRole role id.
    pub role_id: String,
    /// The AppRole secret id.
    pub secret_id: String,
}
