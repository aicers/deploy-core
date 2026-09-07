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
use crate::executor::{
    DirOutcome, Executor, ExecutorError, FileMeta, Identity, ServiceAccount, TEST, path_present,
};
use crate::layout::NAMESPACE_ROOT_TRAVERSE_MODE;

/// The `docker` binary the apply path drives to load image tarballs.
const DOCKER: &str = "docker";

/// The `tar` binary the apply path extracts compose bundles with.
const TAR: &str = "tar";

/// The suffix the prior artifact is linked aside to before a swap overwrites it,
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
/// primitive the apply path drives systemd, `docker`, `tar` and friends through.
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

/// Links the currently-installed artifact aside to a `<path>.previous` sibling
/// before a swap overwrites it, so a failed update (no automatic rollback, RFC
/// 0001 §9) leaves the prior artifact recoverable on disk. A newly-added artifact
/// has no prior file on disk, so the backup is skipped.
///
/// **The backup is a hard link, not a copy**, taken through
/// [`Executor::hard_link_over`]: `link` to a temporary sibling, `rename` over
/// `.previous`, flush the directory. An interrupted copy leaves a *truncated*
/// `.previous` that a later revert succeeds onto — a broken artifact installed
/// by a rollback that reported success — while an interrupted link leaves no
/// `.previous` at all, so the revert fails where anyone looking can see it.
/// Sharing an inode also preserves the artifact's mode and timestamps by
/// construction rather than by copying them, and the link cannot be undone by
/// the swap that follows: [`place_file`] writes a temporary and renames over
/// the destination, so the swap replaces the directory entry and the linked
/// inode survives behind `.previous`.
///
/// **The artifact must be a regular file.** A symlink at `dest` is refused
/// rather than followed — the backup would otherwise be a copy of, or a pointer
/// to, wherever the symlink pointed — and so is a directory or any other
/// non-regular file. This primitive is specified for the single path
/// [`place_file`] puts down; a compose bundle or a container image never
/// reaches it. The refusal covers a symlink that resolves to nothing too: the
/// presence probe below looks for the *entry* rather than for what it resolves
/// to, so a dangling one is refused as the non-regular file it is instead of
/// passing for the absent path a plain `test -e` reads it as.
///
/// **It is still not idempotent.** A resumed apply that runs it a second time
/// backs up the half-applied bytes and destroys the rollback point — a property
/// of *when* the backup runs, not of copying versus linking. The caller's apply
/// journal remains what guards it, and this step stays conditional on that
/// journal's backup-taken record. That record is also the only answer available
/// after a power loss: nothing between the rename and the directory flush is
/// claimed portably, so a caller that finds no record re-takes the backup, which
/// is sound because this runs *before* [`place_file`] and what gets linked is
/// still the live, un-replaced artifact.
/// # Errors
///
/// Returns the executor's own error if the presence probe cannot be run or if
/// the link sequence fails to run at all — a transport or elevation failure —
/// and [`CoreError::Command`], labelled with `subject` and `host`, if the
/// sequence runs and refuses or fails on the target. A probe that runs and
/// finds no entry at all is not an error: there is nothing to preserve.
pub fn backup_previous_artifact(
    executor: &dyn Executor,
    subject: &str,
    host: &str,
    dest: &Path,
) -> Result<(), CoreError> {
    // Only an artifact already on disk (a changed one) is preserved; a probe
    // that finds no entry means a newly-added path with nothing to back up. An
    // entry that is there but is not a regular file is not that case, and goes
    // on to the refusal `hard_link_over` makes of it.
    if !entry_present(executor, dest)? {
        return Ok(());
    }
    // Built on the `OsStr` rather than through a lossy string, so a path that is
    // not UTF-8 gets its own sibling instead of a mangled one.
    let mut previous = dest.as_os_str().to_owned();
    previous.push(PREVIOUS_ARTIFACT_SUFFIX);
    executor
        .hard_link_over(dest, Path::new(&previous))
        .map_err(|error| match error {
            // The on-host failures the primitive reports uniformly across
            // transports, folded into the same subject-labelled error the copy
            // this replaced raised, so a consumer's rendering is unchanged. An
            // elevation or transport failure is not one of them and stays the
            // executor's own error, exactly as it was when a `cp` could not be
            // run at all.
            ExecutorError::Transfer { reason, .. } => CoreError::Command {
                subject: subject.to_string(),
                host: host.to_string(),
                diagnostic: reason,
            },
            other => CoreError::Executor(other),
        })
}

/// Reports whether a directory entry exists at `path`, without resolving a
/// symlink standing there.
///
/// [`path_present`]'s `test -e` resolves the path it is given, so a *dangling*
/// symlink answers exactly as an absent path does — and
/// [`backup_previous_artifact`] would skip it as a newly-added artifact rather
/// than refuse it as the non-regular file it is, leaving the swap that follows
/// to replace it with no backup taken and nothing said. The `test -h` runs only
/// where `-e` said no, so the two cases that actually occur — a regular file,
/// or nothing at all — cost the single probe they always did.
fn entry_present(executor: &dyn Executor, path: &Path) -> Result<bool, ExecutorError> {
    if path_present(executor, path)? {
        return Ok(true);
    }
    let output = executor.run(Identity::Root, TEST, &["-h", &path.to_string_lossy()])?;
    Ok(output.success())
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{PREVIOUS_ARTIFACT_SUFFIX, backup_previous_artifact};
    use crate::exec::CoreError;
    use crate::executor::{Executor, FileMeta, InDaemonExecutor, Principal};

    /// The caller-supplied label and host the folded [`CoreError::Command`] must
    /// carry back unchanged.
    const SUBJECT: &str = "runner";
    const HOST: &str = "seat";
    /// The mode a native binary is installed with, so the backup can be shown to
    /// carry it without anything preserving it separately.
    const ARTIFACT_MODE: u32 = 0o755;

    /// The transport the apply path drives inside the root daemon, which runs
    /// the link sequence as direct syscalls.
    ///
    /// The whole sequence — `link`, `rename`, `fsync` — needs no privilege
    /// beyond writing the directory, so these tests exercise the production
    /// path for real against a real filesystem rather than asserting on a
    /// captured invocation. Nothing here skips when non-root.
    fn executor() -> InDaemonExecutor {
        InDaemonExecutor::new(HOST)
    }

    /// Writes an artifact two levels below `root`, so the write path's staging
    /// walk has the tempdir itself — owned by the test process, writable by
    /// nobody else — to land on when a test swaps the artifact afterwards.
    fn artifact(root: &TempDir, bytes: &[u8]) -> PathBuf {
        let dir = root.path().join("namespace");
        std::fs::create_dir_all(&dir).expect("namespace dir");
        let path = dir.join("runner");
        std::fs::write(&path, bytes).expect("seed the artifact");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(ARTIFACT_MODE))
            .expect("chmod the artifact");
        path
    }

    /// Returns the `.previous` sibling of `path`.
    fn previous_of(path: &Path) -> PathBuf {
        let mut previous = path.as_os_str().to_owned();
        previous.push(PREVIOUS_ARTIFACT_SUFFIX);
        PathBuf::from(previous)
    }

    /// Returns `path`'s inode, without following a symlink at it.
    fn inode(path: &Path) -> u64 {
        std::fs::symlink_metadata(path).expect("stat").ino()
    }

    /// Returns the temporary names the link sequence left in `dir`.
    fn strays(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .expect("read the artifact's directory")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".bootler."))
            })
            .collect()
    }

    /// Returns the metadata naming the ids the test process already runs as, so
    /// a `put_file` standing in for the swap can chown to itself.
    fn current_meta(root: &TempDir) -> FileMeta {
        let meta = std::fs::metadata(root.path()).expect("stat the tempdir");
        FileMeta::new(
            Principal::Fixture(meta.uid()),
            Principal::Fixture(meta.gid()),
            ARTIFACT_MODE,
        )
    }

    /// Asserts `error` is the subject-labelled command failure, and returns its
    /// diagnostic.
    fn command_diagnostic(error: CoreError) -> String {
        match error {
            CoreError::Command {
                subject,
                host,
                diagnostic,
            } => {
                assert_eq!(subject, SUBJECT, "the caller's label rides back out");
                assert_eq!(host, HOST, "so does the host");
                diagnostic
            }
            other => panic!("expected a command failure, got {other:?}"),
        }
    }

    #[test]
    fn the_backup_is_a_hard_link_to_the_artifact_itself() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = artifact(&root, b"installed-bytes");
        let previous = previous_of(&path);

        backup_previous_artifact(&executor(), SUBJECT, HOST, &path).expect("back up the artifact");

        assert_eq!(
            inode(&previous),
            inode(&path),
            "a link shares the artifact's inode; a copy would be a second one"
        );
        // Mode and timestamps are properties of that shared inode, so nothing
        // preserves them separately the way `cp -p` had to.
        let backed_up = std::fs::metadata(&previous).expect("stat the backup");
        assert_eq!(backed_up.permissions().mode() & 0o777, ARTIFACT_MODE);
        assert_eq!(
            backed_up.mtime(),
            std::fs::metadata(&path).expect("stat").mtime()
        );
        assert_eq!(
            std::fs::read(&previous).expect("read the backup"),
            b"installed-bytes",
            "the backup holds the artifact's bytes, whole"
        );
        assert!(
            strays(path.parent().expect("the artifact has a directory")).is_empty(),
            "the sequence leaves no temporary name behind"
        );
    }

    #[test]
    fn an_absent_artifact_is_not_backed_up() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = artifact(&root, b"placeholder");
        std::fs::remove_file(&path).expect("remove the artifact");

        backup_previous_artifact(&executor(), SUBJECT, HOST, &path)
            .expect("a newly-added artifact has nothing to preserve");

        assert!(
            !previous_of(&path).exists(),
            "no backup is invented for a path that was not there"
        );
    }

    #[test]
    fn a_symlink_at_the_artifact_is_refused_rather_than_followed() {
        let root = tempfile::tempdir().expect("tempdir");
        let elsewhere = artifact(&root, b"the operator's own file");
        let path = elsewhere.with_file_name("linked-runner");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("plant the symlink");

        let error = backup_previous_artifact(&executor(), SUBJECT, HOST, &path)
            .expect_err("a symlink is refused");

        let diagnostic = command_diagnostic(error);
        assert!(
            diagnostic.contains("is a symbolic link"),
            "the refusal says what it refused: {diagnostic}"
        );
        assert!(
            !previous_of(&path).exists(),
            "a refused backup writes no `.previous`, whether of the link or of its target"
        );
        assert!(strays(elsewhere.parent().expect("directory")).is_empty());
    }

    #[test]
    fn a_dangling_symlink_at_the_artifact_is_refused_rather_than_skipped() {
        // The refusal has to survive the presence probe that guards it: `test
        // -e` resolves the link, so a symlink pointing at nothing reads as an
        // absent path and would be skipped as a newly-added artifact — the swap
        // replacing the operator's link with no backup taken and nothing said.
        let root = tempfile::tempdir().expect("tempdir");
        let seeded = artifact(&root, b"a sibling, so the directory exists");
        let path = seeded.with_file_name("linked-runner");
        std::os::unix::fs::symlink(seeded.with_file_name("nothing-here"), &path)
            .expect("plant the dangling symlink");

        let error = backup_previous_artifact(&executor(), SUBJECT, HOST, &path)
            .expect_err("a symlink is refused whether or not it resolves");

        let diagnostic = command_diagnostic(error);
        assert!(
            diagnostic.contains("is a symbolic link"),
            "the refusal says what it refused: {diagnostic}"
        );
        assert!(
            !previous_of(&path).exists(),
            "a refused backup writes no `.previous`"
        );
        assert!(
            path.symlink_metadata().is_ok(),
            "and leaves the operator's link where it stands"
        );
        assert!(strays(seeded.parent().expect("directory")).is_empty());
    }

    #[test]
    fn a_directory_at_the_artifact_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("namespace").join("bundle");
        std::fs::create_dir_all(&path).expect("plant the directory");

        let error = backup_previous_artifact(&executor(), SUBJECT, HOST, &path)
            .expect_err("a directory is refused");

        assert!(
            command_diagnostic(error).contains("is not a regular file"),
            "a directory is refused as the non-regular file it is"
        );
        assert!(!previous_of(&path).exists());
    }

    #[test]
    fn a_fifo_at_the_artifact_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("namespace");
        std::fs::create_dir_all(&dir).expect("namespace dir");
        let path = dir.join("pipe");
        // Every other non-regular file is refused on the same terms as a
        // directory, and a fifo is the one an unprivileged test can create.
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo should be runnable");
        assert!(made.success(), "the fifo should be created");

        let error = backup_previous_artifact(&executor(), SUBJECT, HOST, &path)
            .expect_err("a fifo is refused");

        assert!(command_diagnostic(error).contains("is not a regular file"));
        assert!(!previous_of(&path).exists());
    }

    #[test]
    fn a_later_backup_replaces_the_earlier_one() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = artifact(&root, b"first-generation");
        let previous = previous_of(&path);
        let executor = executor();

        backup_previous_artifact(&executor, SUBJECT, HOST, &path).expect("first backup");
        // The swap the caller performs between two applies, run through the
        // primitive that performs it in production: a rename over the
        // destination, which replaces the directory entry and leaves the linked
        // inode alone.
        executor
            .put_file(&path, b"second-generation", current_meta(&root))
            .expect("swap the artifact");
        assert_eq!(
            std::fs::read(&previous).expect("read the backup"),
            b"first-generation",
            "the swap must not write through the link and destroy the backup"
        );

        backup_previous_artifact(&executor, SUBJECT, HOST, &path).expect("second backup");

        assert_eq!(
            inode(&previous),
            inode(&path),
            "the backup now names the artifact that is installed"
        );
        assert_eq!(
            std::fs::read(&previous).expect("read the backup"),
            b"second-generation"
        );
        assert!(strays(path.parent().expect("directory")).is_empty());
    }

    #[test]
    fn a_temporary_stranded_by_an_interrupted_attempt_does_not_block_the_resumed_backup() {
        // An attempt interrupted between the link and the rename leaves a
        // completed temporary sibling and no `.previous`, and the caller's
        // journal correctly holds no backup-taken record — so the resumed apply
        // calls this function again. It must take the backup rather than fail
        // on the leftover, which under a reused pid is the very first name it
        // draws, and it must leave the leftover alone: clearing it away is what
        // the refusal of a planted entry exists to prevent.
        let root = tempfile::tempdir().expect("tempdir");
        let path = artifact(&root, b"installed-bytes");
        let previous = previous_of(&path);
        let dir = path.parent().expect("directory").to_path_buf();
        let stranded = dir.join(format!(".bootler.link.{}.0", std::process::id()));
        std::fs::hard_link(&path, &stranded).expect("strand the interrupted attempt's link");

        backup_previous_artifact(&executor(), SUBJECT, HOST, &path).expect("the resumed backup");

        assert_eq!(
            inode(&previous),
            inode(&path),
            "the resumed apply publishes the backup out of a free sibling"
        );
        assert_eq!(
            inode(&stranded),
            inode(&path),
            "and leaves the leftover standing rather than consuming or clearing it"
        );
        assert_eq!(
            strays(&dir),
            vec![stranded],
            "the only temporary beside the artifact is the one that was already there"
        );
    }

    #[test]
    fn backing_up_an_unchanged_artifact_twice_leaves_one_link_and_no_stray() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = artifact(&root, b"unchanged");
        let previous = previous_of(&path);
        let executor = executor();

        backup_previous_artifact(&executor, SUBJECT, HOST, &path).expect("first backup");
        // The rename is a no-op when both names already refer to one inode,
        // which is what this asks for; the temporary must not survive it.
        backup_previous_artifact(&executor, SUBJECT, HOST, &path).expect("second backup");

        assert_eq!(inode(&previous), inode(&path));
        assert_eq!(
            std::fs::metadata(&previous).expect("stat").nlink(),
            2,
            "two names for the artifact's inode, not three"
        );
        assert!(strays(path.parent().expect("directory")).is_empty());
    }
}
