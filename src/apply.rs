//! Product-neutral apply primitives: how bytes, directories and images land on a
//! host as root.
//!
//! These are the low-level actuation steps the install and update paths — and an
//! external consumer such as the on-host agent — drive to realise a computed diff:
//! place a file at a root-owned path, create a directory, run a root command,
//! back up the prior artifact before a swap, `docker load` an image tarball, and
//! extract a compose bundle. They carry no product or component concept; the
//! caller supplies every path, meta and subject label, and a failure surfaces as
//! [`CoreError`] (the installer folds it back into its own error via `From`).
//!
//! The directory primitives report a reconciled directory into a phase-scoped
//! [`CorrectionReport`], which rides back beside the phase's own outcome so a
//! correction is surfaced as it happens rather than held for an end-of-run summary.

use std::path::{Path, PathBuf};

use crate::exec::CoreError;
use crate::executor::{DirOutcome, Executor, FileMeta, Identity, ServiceAccount, TEST};
use crate::layout::NAMESPACE_ROOT_TRAVERSE_MODE;

/// The `docker` binary the apply path drives to load image tarballs.
const DOCKER: &str = "docker";

/// The `tar` binary the apply path extracts compose bundles with.
const TAR: &str = "tar";

/// The `cp` binary the apply path preserves the prior artifact with.
const CP: &str = "cp";

/// The suffix the prior artifact is copied aside to before a swap overwrites it,
/// so a failed update leaves it recoverable on disk (no automatic rollback).
///
/// Crate-visible because the shipped supervisor units exec exactly this sibling
/// of the roxyd binary, and [`crate::roxyd_selfupdate`] pins their text against
/// it so the suffix stays one decision rather than two.
pub(crate) const PREVIOUS_ARTIFACT_SUFFIX: &str = ".previous";

/// A root-owned directory that existed with different metadata and was
/// reconciled (RFC 0003 §9.2).
///
/// `meta` is the metadata that was **applied**, not what was found: the elevated
/// script reports only that it corrected the directory, never the previous owner
/// or mode, so the before-state is not available to report here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryCorrection {
    /// The directory that was reconciled.
    pub path: PathBuf,
    /// The owner, group and mode now in force.
    pub meta: FileMeta,
}

/// The corrections one install phase observed, handed back alongside that
/// phase's own outcome.
///
/// **Phase-scoped, deliberately not an install-wide accumulator.** Each phase
/// builds its own report and the CLI renders it next to that phase's existing
/// outcome, so a correction is surfaced as it happens rather than held for an
/// end-of-run summary — and a later phase failing cannot lose it. A phase that
/// observes a correction and *then* fails carries its report out through
/// `crate::install::InstallFailure`.
///
/// Only [`DirOutcome::Corrected`] lands here: a directory that was created or
/// already matched is not news, so a clean install reports nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CorrectionReport {
    /// The reconciled directories, in the order the phase observed them.
    pub directories: Vec<DirectoryCorrection>,
}

impl CorrectionReport {
    /// Records `outcome` for the directory at `path`, keeping only a correction.
    ///
    /// This is the single place a [`DirOutcome`] becomes reportable, so every
    /// `make_dir` call site funnels its outcome here rather than each deciding
    /// which variants are worth mentioning.
    pub fn record(&mut self, path: &Path, meta: FileMeta, outcome: DirOutcome) {
        if matches!(outcome, DirOutcome::Corrected) {
            self.directories.push(DirectoryCorrection {
                path: path.to_path_buf(),
                meta,
            });
        }
    }

    /// Returns whether the phase corrected nothing — the clean-install case.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.directories.is_empty()
    }
}

/// Places a staged file at a root-owned namespace path: creates the parent
/// directory and writes the bytes with `meta`, both as root.
///
/// `meta` is what used to be a follow-up `chmod`. A native binary lands `0755`
/// because that is what the write asks for, not because a later command widened
/// it; there is no window in which the runner's binary exists non-executable, or
/// any other artifact exists at the umask.
/// # Errors
///
/// Returns [`CoreError::Staging`] if the parent directory cannot be created,
/// [`CoreError::Payload`] if `source` cannot be read from the staging area, and
/// whatever [`Executor::put_file`] reports if the write on the host fails.
pub fn place_file(
    executor: &dyn Executor,
    host_name: &str,
    source: &Path,
    dest: &Path,
    meta: FileMeta,
    dir_meta: FileMeta,
    corrections: &mut CorrectionReport,
) -> Result<(), CoreError> {
    if let Some(parent) = dest.parent() {
        make_dir(executor, host_name, parent, dir_meta, corrections)?;
    }
    let bytes = std::fs::read(source).map_err(|error| CoreError::Payload(error.into()))?;
    executor.put_file(dest, &bytes, meta)?;
    Ok(())
}

/// Runs `command` as root on `host`, mapping a non-zero exit to
/// [`CoreError::Command`] labelled with `subject` — the generic host-command
/// primitive the apply path drives systemd, `docker`, `cp` and friends through.
///
/// `subject` is a caller-supplied label (the installer passes a component name so
/// the folded `crate::install::InstallError::Component` reads the same as
/// before); the generic layer itself carries no product concept. The command's
/// `stderr` rides through verbatim.
/// # Errors
///
/// Returns the executor's own error if the command cannot be run at all — a
/// transport failure, or a missing binary — and [`CoreError::Command`] if it
/// runs and exits non-zero, carrying `subject`, `host`, and the command's
/// trimmed `stderr`.
pub fn run_root_checked(
    executor: &dyn Executor,
    subject: &str,
    host: &str,
    command: &str,
    args: &[&str],
) -> Result<(), CoreError> {
    let output = executor.run(Identity::Root, command, args)?;
    if output.success() {
        Ok(())
    } else {
        Err(CoreError::Command {
            subject: subject.to_string(),
            host: host.to_string(),
            diagnostic: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// Copies the currently-installed artifact aside to a `<path>.previous` sibling
/// before a swap overwrites it, so a failed update (no automatic rollback, RFC
/// 0001 §9) leaves the prior artifact recoverable on disk. A newly-added artifact
/// has no prior file on disk, so the backup is skipped.
/// # Errors
///
/// Returns the executor's own error if the `test -e` probe cannot be run, and
/// [`CoreError::Command`] if the copy itself fails. A probe that runs and
/// reports the path absent is not an error: there is nothing to preserve.
pub fn backup_previous_artifact(
    executor: &dyn Executor,
    subject: &str,
    host: &str,
    dest: &Path,
) -> Result<(), CoreError> {
    let dest = dest.to_string_lossy().into_owned();
    // Only an artifact already on disk (a changed one) is preserved; `test -e`
    // exiting non-zero means a newly-added path with nothing to back up.
    if !executor
        .run(Identity::Root, TEST, &["-e", dest.as_str()])?
        .success()
    {
        return Ok(());
    }
    let previous = format!("{dest}{PREVIOUS_ARTIFACT_SUFFIX}");
    // `-f` overwrites any older backup; `-p` keeps the artifact's mode/timestamps.
    run_root_checked(
        executor,
        subject,
        host,
        CP,
        &["-fp", dest.as_str(), previous.as_str()],
    )
}

/// `docker load`s a staged image tarball on `host` (as root), mapping a non-zero
/// exit to [`CoreError::Command`] labelled with `subject`. This is the apply
/// path's load, distinct from the Phase-4 stage engine's load in
/// `crate::staging`, which reports through the installer's error.
/// # Errors
///
/// Returns the executor's own error if `docker` cannot be run, and
/// [`CoreError::Command`] if it exits non-zero — an unreadable tarball, a
/// daemon that is not running, or an image the daemon rejects.
pub fn docker_load_image(
    executor: &dyn Executor,
    subject: &str,
    host: &str,
    tarball: &Path,
) -> Result<(), CoreError> {
    run_root_checked(
        executor,
        subject,
        host,
        DOCKER,
        &["load", "-i", &tarball.to_string_lossy()],
    )
}

/// Extracts a staged tar archive into `dest_dir` on `host` (as root), mapping a
/// non-zero exit to [`CoreError::Command`] labelled with `subject` — the apply
/// path's compose-bundle unpack.
/// # Errors
///
/// Returns the executor's own error if `tar` cannot be run, and
/// [`CoreError::Command`] if it exits non-zero — a corrupt or absent archive,
/// or a destination it cannot write into.
pub fn tar_extract(
    executor: &dyn Executor,
    subject: &str,
    host: &str,
    tarball: &Path,
    dest_dir: &Path,
) -> Result<(), CoreError> {
    run_root_checked(
        executor,
        subject,
        host,
        TAR,
        &[
            "-xf",
            &tarball.to_string_lossy(),
            "-C",
            &dest_dir.to_string_lossy(),
        ],
    )
}

/// Creates `dir` (and any parents) on `host_name` with the owner, group and mode
/// `dir_meta` names, recording a reconciled directory into `corrections`.
///
/// Directories under `<opt>` pass a root-owned [`FileMeta::namespace_root`] so the
/// namespace root and `bin/` are group-owned by the product account and `0751`
/// (traversable, not listable, by non-members); the module store passes
/// [`FileMeta::ROOT_RESTRICTED_DIR`] (RFC 0003 §7.1). The staged *files* keep their
/// own `meta` (a binary stays `root:root 0755`, excluded from the confidentiality
/// boundary because execution requires read, §11.7).
/// # Errors
///
/// Returns [`CoreError::Staging`] if the directory cannot be created or cannot
/// be given the ownership and mode `dir_meta` names, naming the directory and
/// the host.
pub fn make_dir(
    executor: &dyn Executor,
    host_name: &str,
    dir: &Path,
    dir_meta: FileMeta,
    corrections: &mut CorrectionReport,
) -> Result<(), CoreError> {
    let outcome = executor
        .make_dir(dir, dir_meta)
        .map_err(|error| CoreError::Staging {
            step: format!("create {}", dir.display()),
            host: host_name.to_string(),
            reason: error.to_string(),
        })?;
    corrections.record(dir, dir_meta, outcome);
    Ok(())
}

/// The directory meta for staged artifacts written under a product's `<opt>` tree:
/// the namespace root and its `bin/` are root-owned, group the product account,
/// `0751` (RFC 0003 §7.1).
#[must_use]
pub fn opt_dir_meta(account: ServiceAccount) -> FileMeta {
    FileMeta::namespace_root(account, NAMESPACE_ROOT_TRAVERSE_MODE)
}

/// Establishes the `<opt>` namespace root itself at its §7.1 meta before any
/// artifact is placed beneath it.
///
/// `install -d -o … -g … -m … <opt>/bin/x` applies the ownership and mode to the
/// **named leaf only** — the parents it creates land root-owned at the umask
/// (`root:root 0755`). So placing a binary under `<opt>/bin` would leave `<opt>`
/// itself `root:root 0755` rather than `root:<account> 0751`. Creating the root
/// explicitly first (idempotent; a wrong meta left by an earlier phase is
/// corrected, since it is root-owned) fixes that, and the leaves below keep the
/// same meta so they need no separate correction.
/// # Errors
///
/// Returns [`CoreError::Staging`] if the namespace root cannot be created or
/// corrected, as [`make_dir`] reports it.
pub fn ensure_opt_root(
    executor: &dyn Executor,
    host_name: &str,
    opt_dir: &Path,
    account: ServiceAccount,
    corrections: &mut CorrectionReport,
) -> Result<(), CoreError> {
    make_dir(
        executor,
        host_name,
        opt_dir,
        opt_dir_meta(account),
        corrections,
    )
}
