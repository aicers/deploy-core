//! Product-neutral execution-provider vocabulary.
//!
//! The install/update primitives dispatch their per-host work through an
//! [`ExecutorProvider`]: given a host name, hand back an [`Executor`]. This is
//! the seam that lets the same primitives run over SSH (the CLI), the local
//! seat, or in-process inside a daemon (`InDaemonExecutor`) — so an external
//! consumer such as the on-host agent can drive them without the CLI's phase
//! machinery.
//!
//! [`CoreError`] is the **generic** error these primitives raise — an executor
//! failure, an undefined host, or a credential that could not be acquired.
//! Product-specific failures (a component that would not render, a secret that
//! could not be generated, installer state) are **not** here; the installer's
//! own richer error wraps `CoreError` via `From` and adds those. Keeping the
//! generic vocabulary separate is what lets the primitives stay free of any
//! product concept.

use crate::executor::{Executor, ExecutorError, SudoAuth};
use crate::payload::PayloadError;

/// A generic failure raised by an execution primitive.
///
/// This is deliberately small: only the failures inherent to *reaching and
/// running on a host*, independent of any product. The installer maps these
/// into its own `InstallError` through
/// `From<CoreError>`, which preserves the exact variant, so callers that render
/// or match the installer error are unaffected.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// An executor primitive failed.
    #[error(transparent)]
    Executor(#[from] ExecutorError),
    /// A phase referenced a host absent from `[hosts]`.
    #[error("host `{0}` is not defined in the config")]
    UndefinedHost(String),
    /// The credential provider could not acquire a sudo credential for a host
    /// (for example a cancelled or failed password prompt).
    #[error("failed to acquire sudo credentials for host `{host}`: {reason}")]
    Elevation {
        /// The host the credential was being acquired for.
        host: String,
        /// Why acquisition failed.
        reason: String,
    },
    /// A root command run by an apply primitive exited non-zero on a host. The
    /// `subject` is a generic label the caller supplies (the installer folds it
    /// back into the component name of its own richer error); `diagnostic` is the
    /// command's own `stderr`, passed through verbatim.
    #[error("command failed for `{subject}` on host `{host}`: {diagnostic}")]
    Command {
        /// A generic label for what the command was acting on.
        subject: String,
        /// The host the command ran on.
        host: String,
        /// The command's own diagnostic output.
        diagnostic: String,
    },
    /// An on-host staging step (creating a namespace directory) failed.
    #[error("staging step `{step}` failed on host `{host}`: {reason}")]
    Staging {
        /// The staging step that failed.
        step: String,
        /// The host it ran on.
        host: String,
        /// The command's diagnostic output.
        reason: String,
    },
    /// Reading a local source artifact off the seat before it is placed on a
    /// host failed.
    #[error(transparent)]
    Payload(#[from] PayloadError),
    /// A `bootroot service add` invocation exited non-zero while registering a
    /// certificate consumer.
    #[error("failed to register service `{service}` on host `{host}`: {reason}")]
    ServiceRegistration {
        /// The service whose registration failed.
        service: String,
        /// The host bootroot ran on.
        host: String,
        /// bootroot's own diagnostic output.
        reason: String,
    },
}

/// Hands out an executor for a host, the seam the install/update primitives
/// dispatch through.
///
/// The installer's `InstallContext` implements it in production; a primitive
/// takes `&dyn ExecutorProvider` so it can be unit-tested against fake
/// executors — and so an in-daemon consumer can supply an `InDaemonExecutor`
/// without building real transports.
pub trait ExecutorProvider {
    /// Returns the executor for `host_name`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the host is undefined or its credential
    /// cannot be acquired.
    fn executor_for(&self, host_name: &str) -> Result<Box<dyn Executor>, CoreError>;
}

/// Acquires the sudo credential for a host, the seam the executor factory uses
/// to decide how a remote command elevates.
pub trait ElevationProvider {
    /// Returns the sudo authentication to use for `host`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Elevation`] when the credential cannot be acquired.
    fn elevation_for(&self, host: &str) -> Result<SudoAuth, CoreError>;
}
