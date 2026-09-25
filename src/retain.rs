//! Private byte retention and no-clobber publication.
//!
//! Every untrusted source is copied **once** into a new library-owned regular
//! file, created with mode 0600 inside a fresh private directory created with
//! mode 0700, both relative to a directory handle this module holds open.
//! Once the writes finish, a read-only descriptor is opened, the name is
//! unlinked and every writable descriptor closed — and only then does a
//! [`RetainedBytes`] exist to validate or expose. Every later read goes to that
//! same unlinked inode, so caller writes, replaced pathnames and descriptors
//! the caller kept open on its original cannot affect it.
//!
//! Snapshots are transient, not recovery records: they are never synced, and
//! the operating system reclaims them when the process exits. Publication, in
//! [`publish_file`] and [`publish_directory`], is where durability is paid
//! for.
//!
//! Retention costs disk, deliberately, and one [`RetentionScope`] budgets it:
//! every live snapshot and publication temporary is charged for the bytes it
//! holds, and a write fails at the first byte beyond the limit.
//!
//! Everything here works relative to held, no-follow directory handles through
//! `rustix`, because `std` has no directory-relative `openat`, `mkdirat`,
//! `linkat`, `renameat` or `unlinkat`. A missing platform or filesystem
//! capability fails with a contextual I/O error keeping its kind; nothing
//! retries with weaker flags, falls back from link to rename, or moves.
//!
//! The trust boundary is the one [`crate::package`] states: nothing here
//! defends against root, same-user processes, same-process memory access or a
//! malicious filesystem.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ring::rand::SecureRandom;
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::package::{DirectoryTrustReason, RetainedBytes};
use crate::payload::to_hex;

/// Runs `$op`, an `io::Result` expression, after the test seam has had its
/// say about `$step`. A release build expands to `$op` alone.
macro_rules! step {
    ($step:ident, $op:expr) => {{
        #[cfg(test)]
        let injected = $crate::retain::fault::hit($crate::retain::fault::Step::$step);
        #[cfg(not(test))]
        let injected: ::std::io::Result<()> = Ok(());
        match injected {
            Ok(()) => $op,
            Err(error) => Err(error),
        }
    }};
}

#[cfg(test)]
pub(crate) mod fault;
mod publish;
#[cfg(test)]
mod tests;
pub(crate) mod trusted_dir;

// Re-exported for the preparation and finalization work that publishes
// through them; until it lands only the tests use these paths.
#[allow(unused_imports)]
pub(crate) use publish::{PublishedFileName, publish_directory, publish_file};
use trusted_dir::{TrustedDir, TrustedDirError, open_trusted_dir};

/// The prefix of the private directory a scope creates in its staging parent.
const RETAIN_PREFIX: &str = ".deploy-core-retain-";
/// How many fresh names are drawn before a create gives up on `AlreadyExists`.
const NAME_ATTEMPTS: usize = 8;
const PRIVATE_DIR_MODE: Mode = Mode::RWXU;
const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

/// Why retention failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RetentionError {
    /// The operation's retained-disk budget ran out.
    #[error("retention exceeded the retained-disk budget of {limit} bytes")]
    BudgetExceeded { limit: u64 },

    /// The source held more than the per-source maximum.
    #[error("source is longer than {max_len} bytes")]
    SourceTooLong { max_len: u64 },

    /// The staging parent was refused by the directory trust policy.
    #[error("staging parent {} is not trusted: {reason}", .path.display())]
    UnsafeStagingParent {
        path: PathBuf,
        reason: DirectoryTrustReason,
    },

    /// A finished snapshot did not match what was written to it.
    #[error("snapshot does not match what was written: {kind}")]
    SnapshotMismatch { kind: SnapshotMismatchKind },

    /// A filesystem operation failed. `path` is `None` for source reads and
    /// anything touching an anonymous retained inode.
    #[error("{operation} failed{}: {source}", describe_path(.path.as_deref()))]
    Io {
        operation: RetentionOperation,
        path: Option<PathBuf>,
        #[source]
        source: io::Error,
    },
}

fn describe_path(path: Option<&Path>) -> String {
    path.map(|path| format!(" at {}", path.display()))
        .unwrap_or_default()
}

impl RetentionError {
    fn io(operation: RetentionOperation, path: Option<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path,
            source,
        }
    }

    /// Carries this error across a `Write` boundary as an `io::Error` payload.
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// Recovers a `RetentionError` carried by [`into_io`](Self::into_io), or
    /// wraps any other error as `Io` under `operation` and `path`.
    ///
    /// Nothing is classified by kind or message: only the payload's type
    /// decides.
    pub(crate) fn from_io(
        error: io::Error,
        operation: RetentionOperation,
        path: Option<PathBuf>,
    ) -> Self {
        if error
            .get_ref()
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<RetentionError>)
        {
            match error
                .into_inner()
                .map(<dyn std::error::Error + Send + Sync>::downcast::<RetentionError>)
            {
                Some(Ok(retention)) => return *retention,
                // Unreachable after the `is` check above, but recovered
                // rather than asserted.
                Some(Err(inner)) => return Self::io(operation, path, io::Error::other(inner)),
                None => return Self::io(operation, path, io::Error::other("empty i/o error")),
            }
        }
        Self::io(operation, path, error)
    }
}

/// How a finished snapshot differed from what was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotMismatchKind {
    /// The reopened name was not the inode that was written.
    Identity,
    /// The retained inode's length differs from the bytes counted in.
    Length { expected: u64, actual: u64 },
}

impl std::fmt::Display for SnapshotMismatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity => f.write_str("the reopened snapshot is a different file"),
            Self::Length { expected, actual } => {
                write!(f, "expected {expected} bytes, found {actual}")
            }
        }
    }
}

/// The retention step a [`RetentionError::Io`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionOperation {
    OpenStagingParent,
    CreateStagingDirectory,
    CreateSnapshot,
    /// Writing a snapshot, and the flush in `finish`.
    WriteSnapshot,
    ReopenSnapshot,
    /// The `fstat` in `finish`.
    InspectSnapshot,
    UnlinkSnapshot,
    ReadSource,
    /// Removing an entry from the private directory, and listing it.
    RemoveStagingEntry,
    RemoveStagingDirectory,
}

impl std::fmt::Display for RetentionOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenStagingParent => "opening the staging parent",
            Self::CreateStagingDirectory => "creating the private staging directory",
            Self::CreateSnapshot => "creating a snapshot",
            Self::WriteSnapshot => "writing a snapshot",
            Self::ReopenSnapshot => "reopening a snapshot",
            Self::InspectSnapshot => "inspecting a snapshot",
            Self::UnlinkSnapshot => "unlinking a snapshot",
            Self::ReadSource => "reading the source",
            Self::RemoveStagingEntry => "removing a staging entry",
            Self::RemoveStagingDirectory => "removing the private staging directory",
        })
    }
}

/// The retained-disk budget one operation shares across every live snapshot,
/// output candidate and publication temporary.
#[derive(Clone, Debug)]
pub(crate) struct DiskBudget {
    state: Arc<BudgetState>,
}

#[derive(Debug)]
struct BudgetState {
    limit: u64,
    used: AtomicU64,
    high_water: AtomicU64,
}

impl DiskBudget {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            state: Arc::new(BudgetState {
                limit,
                used: AtomicU64::new(0),
                high_water: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn limit(&self) -> u64 {
        self.state.limit
    }

    pub(crate) fn used(&self) -> u64 {
        self.state.used.load(Ordering::Acquire)
    }

    pub(crate) fn high_water(&self) -> u64 {
        self.state.high_water.load(Ordering::Acquire)
    }

    /// Returns a charge holding nothing yet.
    pub(crate) fn empty_charge(&self) -> Charge {
        Charge {
            state: Arc::clone(&self.state),
            bytes: 0,
        }
    }
}

/// Bytes charged against a [`DiskBudget`], released when dropped.
#[derive(Debug)]
pub(crate) struct Charge {
    state: Arc<BudgetState>,
    bytes: u64,
}

impl Charge {
    /// Adds up to `want` bytes to this charge, as many as the budget has
    /// left, and returns how many were granted. The atomic update never lets
    /// the total pass the limit, however many writers race.
    pub(crate) fn grow(&mut self, want: u64) -> u64 {
        let limit = self.state.limit;
        let mut granted = 0;
        let updated = self
            .state
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                granted = want.min(limit.saturating_sub(used));
                (granted > 0).then(|| used + granted)
            });
        match updated {
            Ok(previous) => {
                self.state
                    .high_water
                    .fetch_max(previous + granted, Ordering::AcqRel);
                self.bytes += granted;
                granted
            }
            Err(_) => 0,
        }
    }

    /// Gives `bytes` of this charge back to the budget.
    pub(crate) fn shrink(&mut self, bytes: u64) {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        self.state.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.state.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Draws a fresh random name component: 16 bytes of `SystemRandom`, as
/// lowercase hex.
///
/// A failed draw is not retried.
fn random_hex() -> io::Result<String> {
    step!(DrawName, Ok(()))?;
    #[cfg(test)]
    if let Some(forced) = fault::forced_name() {
        return Ok(to_hex(&forced));
    }
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("system random source failed"))?;
    Ok(to_hex(&bytes))
}

/// Creates a fresh directory `<prefix><hex><suffix>` in `parent` with
/// `mkdirat`, redrawing the name on `AlreadyExists` up to
/// [`NAME_ATTEMPTS`] times and never adopting an existing entry.
///
/// Returns the name, or the error with the path it concerns: the parent for
/// a failed draw, the new entry otherwise.
fn make_fresh_dir(
    parent: &TrustedDir,
    prefix: &str,
    suffix: &str,
) -> Result<String, (Option<PathBuf>, io::Error)> {
    let mut last = None;
    for _ in 0..NAME_ATTEMPTS {
        let name = format!(
            "{prefix}{}{suffix}",
            random_hex().map_err(|e| (Some(parent.path().to_owned()), e))?
        );
        match step!(
            MakeDirectory,
            rustix::fs::mkdirat(parent.file(), name.as_str(), PRIVATE_DIR_MODE)
                .map_err(io::Error::from)
        ) {
            Ok(()) => return Ok(name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last = Some((Some(parent.path().join(&name)), e));
            }
            Err(e) => return Err((Some(parent.path().join(&name)), e)),
        }
    }
    Err(last.unwrap_or_else(|| {
        (
            Some(parent.path().to_owned()),
            io::Error::other("no name attempt was made"),
        )
    }))
}

/// Creates a fresh regular file `<prefix><hex><suffix>` in `dir`, mode 0600,
/// with `O_EXCL | O_NOFOLLOW`, redrawing the name on `AlreadyExists`.
fn create_fresh_file(
    dir: &TrustedDir,
    prefix: &str,
    suffix: &str,
) -> Result<(String, File), (PathBuf, io::Error)> {
    let mut last = None;
    for _ in 0..NAME_ATTEMPTS {
        let name = format!(
            "{prefix}{}{suffix}",
            random_hex().map_err(|e| (dir.path().to_owned(), e))?
        );
        match step!(
            CreateTemporary,
            create_exclusive(dir.file(), OsStr::new(&name))
        ) {
            Ok(file) => return Ok((name, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last = Some((dir.path().join(&name), e));
            }
            Err(e) => return Err((dir.path().join(&name), e)),
        }
    }
    Err(last.unwrap_or_else(|| {
        (
            dir.path().to_owned(),
            io::Error::other("no name attempt was made"),
        )
    }))
}

/// Creates `name` in `dir` as a new regular file, read-write, mode 0600.
///
/// Callers wrap this in their own seam step.
fn create_exclusive(dir: &File, name: &OsStr) -> io::Result<File> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        PRIVATE_FILE_MODE,
    )
    .map(File::from)
    .map_err(io::Error::from)
}

/// Returns whether two `fstat` results describe the same inode.
fn same_inode(stat: &rustix::fs::Stat, other: &rustix::fs::Stat) -> bool {
    stat.st_dev == other.st_dev && stat.st_ino == other.st_ino
}

/// Returns a file's length from its `fstat`.
fn stat_len(stat: &rustix::fs::Stat) -> io::Result<u64> {
    u64::try_from(stat.st_size).map_err(io::Error::other)
}

/// The operation-scoped private staging area: a fresh 0700 directory inside a
/// trusted staging parent, and the disk budget every snapshot in it shares.
///
/// The parent is storage placement only. Nothing is written into it directly,
/// and no existing entry in it is ever adopted. Closing or dropping the scope
/// removes the private directory at once, even while [`RetainedBytes`] taken
/// from it are alive: those are already unlinked and stay readable through
/// their descriptors.
pub(crate) struct RetentionScope {
    parent: TrustedDir,
    private: TrustedDir,
    private_name: String,
    budget: DiskBudget,
    copy_buffer: NonZeroUsize,
    next_snapshot: AtomicU64,
    closed: bool,
}

impl std::fmt::Debug for RetentionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetentionScope")
            .field("private", &self.private.path())
            .field("budget", &self.budget)
            .field("copy_buffer", &self.copy_buffer)
            .finish_non_exhaustive()
    }
}

impl RetentionScope {
    /// Opens `staging_parent` as a trusted directory and creates a fresh
    /// private directory in it.
    ///
    /// # Errors
    ///
    /// Returns `UnsafeStagingParent` for a policy refusal, `Io` under
    /// `OpenStagingParent` for a failure opening the parent, and `Io` under
    /// `CreateStagingDirectory` for a failed name draw, `mkdirat`, open or
    /// `fstat` of the new directory.
    pub(crate) fn new(
        staging_parent: &Path,
        disk_budget: u64,
        copy_buffer: NonZeroUsize,
    ) -> Result<RetentionScope, RetentionError> {
        let parent = open_trusted_dir(staging_parent).map_err(|e| match e {
            TrustedDirError::Unsafe { path, reason } => {
                RetentionError::UnsafeStagingParent { path, reason }
            }
            TrustedDirError::Io { path, source } => {
                RetentionError::io(RetentionOperation::OpenStagingParent, Some(path), source)
            }
        })?;
        let private_name = make_fresh_dir(&parent, RETAIN_PREFIX, "").map_err(|(path, e)| {
            RetentionError::io(RetentionOperation::CreateStagingDirectory, path, e)
        })?;
        let private_path = parent.path().join(&private_name);
        let private = open_owned_dir(&parent, &private_name).map_err(|e| {
            // Best effort, and only `rmdir`: an entry this call just created
            // and could not use is not left behind when it can be helped.
            let _ = rustix::fs::unlinkat(parent.file(), private_name.as_str(), AtFlags::REMOVEDIR);
            RetentionError::io(
                RetentionOperation::CreateStagingDirectory,
                Some(private_path.clone()),
                e,
            )
        })?;
        Ok(RetentionScope {
            parent,
            private: TrustedDir::from_parts(private, private_path),
            private_name,
            budget: DiskBudget::new(disk_budget),
            copy_buffer,
            next_snapshot: AtomicU64::new(0),
            closed: false,
        })
    }

    pub(crate) fn budget(&self) -> &DiskBudget {
        &self.budget
    }

    pub(crate) fn copy_buffer(&self) -> NonZeroUsize {
        self.copy_buffer
    }

    /// Returns the private directory's path, for diagnostics and tests.
    pub(crate) fn private_path(&self) -> &Path {
        self.private.path()
    }

    /// Returns the bytes currently charged against the budget.
    pub(crate) fn budget_used(&self) -> u64 {
        self.budget.used()
    }

    /// Returns the most bytes ever charged against the budget at once.
    pub(crate) fn budget_high_water(&self) -> u64 {
        self.budget.high_water()
    }

    /// Creates a new snapshot file in the private directory.
    ///
    /// # Errors
    ///
    /// Returns `Io` under `CreateSnapshot` with the new file's path.
    pub(crate) fn snapshot_writer(&self) -> Result<SnapshotWriter<'_>, RetentionError> {
        let n = self.next_snapshot.fetch_add(1, Ordering::Relaxed);
        let name = format!("snap-{n}");
        let file = step!(
            CreateSnapshot,
            create_exclusive(self.private.file(), OsStr::new(&name))
        )
        .map_err(|e| {
            RetentionError::io(
                RetentionOperation::CreateSnapshot,
                Some(self.private.path().join(&name)),
                e,
            )
        })?;
        Ok(SnapshotWriter {
            scope: self,
            file: Some(file),
            name,
            charge: self.budget.empty_charge(),
            hasher: Sha256::new(),
            len: 0,
            unlinked: false,
        })
    }

    /// Copies `source` into a new snapshot in one pass, reading at most
    /// `max_len + 1` bytes.
    ///
    /// # Errors
    ///
    /// Returns `SourceTooLong` when the source holds more than `max_len`
    /// bytes, `BudgetExceeded` when the budget runs out first, `Io` under
    /// `ReadSource` (with no path) for a source error, and whatever
    /// [`snapshot_writer`](Self::snapshot_writer) and
    /// [`SnapshotWriter::finish`] return.
    pub(crate) fn snapshot_from<R: Read + ?Sized>(
        &self,
        source: &mut R,
        max_len: u64,
    ) -> Result<RetainedBytes, RetentionError> {
        let mut writer = self.snapshot_writer()?;
        let mut buf = vec![0u8; self.copy_buffer.get()];
        let mut total = 0u64;
        loop {
            let remaining = max_len - total;
            if remaining == 0 {
                let mut probe = [0u8; 1];
                return match read_source(source, &mut probe)? {
                    0 => writer.finish(),
                    _ => Err(RetentionError::SourceTooLong { max_len }),
                };
            }
            let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
            let window = buf
                .get_mut(..want)
                .expect("want never exceeds the buffer length");
            let read = read_source(source, window)?;
            if read == 0 {
                return writer.finish();
            }
            let chunk = window.get(..read).ok_or_else(|| {
                RetentionError::io(
                    RetentionOperation::ReadSource,
                    None,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "source reported more bytes than it was asked for",
                    ),
                )
            })?;
            writer.write_all(chunk).map_err(|e| {
                RetentionError::from_io(e, RetentionOperation::WriteSnapshot, Some(writer.path()))
            })?;
            total += u64::try_from(read).expect("a read within the window fits in u64");
        }
    }

    /// Removes the private directory, attempting every removal and returning
    /// the first failure.
    ///
    /// # Errors
    ///
    /// Returns `Io` under `RemoveStagingEntry` for a failure listing the
    /// private directory or removing an entry left in it, and under
    /// `RemoveStagingDirectory` for a failure removing the directory itself.
    /// Either way the directory, or an entry in it, may remain.
    pub(crate) fn close(mut self) -> Result<(), RetentionError> {
        self.closed = true;
        self.remove_private()
    }

    fn remove_private(&self) -> Result<(), RetentionError> {
        let mut first = None;
        let entry_error = |path: PathBuf, e: io::Error| {
            RetentionError::io(RetentionOperation::RemoveStagingEntry, Some(path), e)
        };
        match self.list_private() {
            Ok(names) => {
                for name in names {
                    let path = self.private.path().join(OsStr::from_bytes(&name));
                    let removed = step!(
                        RemoveStagingEntry,
                        rustix::fs::unlinkat(
                            self.private.file(),
                            OsStr::from_bytes(&name),
                            AtFlags::empty()
                        )
                        .map_err(io::Error::from)
                    );
                    if let Err(e) = removed {
                        first.get_or_insert(entry_error(path, e));
                    }
                }
            }
            Err(e) => {
                first.get_or_insert(entry_error(self.private.path().to_owned(), e));
            }
        }
        let removed = step!(
            RemoveStagingDirectory,
            rustix::fs::unlinkat(
                self.parent.file(),
                self.private_name.as_str(),
                AtFlags::REMOVEDIR
            )
            .map_err(io::Error::from)
        );
        if let Err(e) = removed {
            first.get_or_insert(RetentionError::io(
                RetentionOperation::RemoveStagingDirectory,
                Some(self.private.path().to_owned()),
                e,
            ));
        }
        first.map_or(Ok(()), Err)
    }

    /// Lists the private directory through its handle, skipping `.` and `..`.
    fn list_private(&self) -> io::Result<Vec<Vec<u8>>> {
        let dir = step!(
            ListStaging,
            rustix::fs::Dir::read_from(self.private.file()).map_err(io::Error::from)
        )?;
        let mut names = Vec::new();
        for entry in dir {
            let entry = entry.map_err(io::Error::from)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        Ok(names)
    }
}

impl Drop for RetentionScope {
    fn drop(&mut self) {
        if !self.closed {
            // Best effort: the crate has no logging dependency, and a drop
            // must not panic. `close` is the path that reports.
            let _ = self.remove_private();
        }
    }
}

/// Opens `name`, a directory this call just created in `parent`, and
/// confirms it is a directory the effective user owns.
fn open_owned_dir(parent: &TrustedDir, name: &str) -> io::Result<OwnedFd> {
    let fd = step!(
        OpenStagingDirectory,
        rustix::fs::openat(parent.file(), name, trusted_dir::dir_flags(), Mode::empty())
            .map_err(io::Error::from)
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    let is_dir =
        rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory;
    if !is_dir || stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "created directory is not a directory owned by the effective user",
        ));
    }
    Ok(fd)
}

/// Reads from an untrusted source, retrying `Interrupted`.
fn read_source<R: Read + ?Sized>(source: &mut R, buf: &mut [u8]) -> Result<usize, RetentionError> {
    loop {
        match source.read(buf) {
            Ok(read) => return Ok(read),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(RetentionError::io(RetentionOperation::ReadSource, None, e)),
        }
    }
}

/// An unfinished snapshot: a new 0600 file in the scope's private directory,
/// written through the budget.
///
/// Dropping it unfinished unlinks its name best-effort and releases its
/// charge. [`finish`](Self::finish) turns it into a [`RetainedBytes`].
pub(crate) struct SnapshotWriter<'s> {
    scope: &'s RetentionScope,
    file: Option<File>,
    name: String,
    charge: Charge,
    hasher: Sha256,
    len: u64,
    unlinked: bool,
}

impl std::fmt::Debug for SnapshotWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotWriter")
            .field("name", &self.name)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl SnapshotWriter<'_> {
    fn path(&self) -> PathBuf {
        self.scope.private.path().join(&self.name)
    }

    fn fail(&self, operation: RetentionOperation, e: impl Into<io::Error>) -> RetentionError {
        RetentionError::io(operation, Some(self.path()), e.into())
    }

    /// Returns the snapshot file's mode, for the creation-mode test.
    #[cfg(test)]
    pub(crate) fn mode_for_test(&self) -> u32 {
        let file = self
            .file
            .as_ref()
            .expect("an unfinished writer holds its file");
        trusted_dir::widen_mode(rustix::fs::fstat(file).expect("fstat").st_mode) & 0o7777
    }

    /// Retains what was written: flushes, reopens the name read-only, checks
    /// that the reopened inode is the one written, unlinks the name, drops
    /// the writable descriptor and checks the length — in that order, all
    /// before a [`RetainedBytes`] exists.
    ///
    /// # Errors
    ///
    /// Returns `Io` under `WriteSnapshot`, `ReopenSnapshot`,
    /// `InspectSnapshot` or `UnlinkSnapshot` with the snapshot's path, or
    /// `SnapshotMismatch`. On any failure the name is unlinked best-effort,
    /// the charge is released and no handle exists.
    pub(crate) fn finish(mut self) -> Result<RetainedBytes, RetentionError> {
        let private = self.scope.private.file();
        let Some(mut writable) = self.file.take() else {
            return Err(self.fail(
                RetentionOperation::WriteSnapshot,
                io::Error::other("snapshot writer has no file"),
            ));
        };
        step!(FlushSnapshot, writable.flush())
            .map_err(|e| self.fail(RetentionOperation::WriteSnapshot, e))?;
        let readable = step!(
            ReopenSnapshot,
            rustix::fs::openat(
                private,
                self.name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)
        )
        .map_err(|e| self.fail(RetentionOperation::ReopenSnapshot, e))?;
        let (written, retained) = step!(
            StatSnapshot,
            rustix::fs::fstat(&writable)
                .and_then(|w| rustix::fs::fstat(&readable).map(|r| (w, r)))
                .map_err(io::Error::from)
        )
        .map_err(|e| self.fail(RetentionOperation::InspectSnapshot, e))?;
        if !same_inode(&written, &retained) {
            return Err(RetentionError::SnapshotMismatch {
                kind: SnapshotMismatchKind::Identity,
            });
        }
        step!(
            UnlinkSnapshot,
            rustix::fs::unlinkat(private, self.name.as_str(), AtFlags::empty())
                .map_err(io::Error::from)
        )
        .map_err(|e| self.fail(RetentionOperation::UnlinkSnapshot, e))?;
        self.unlinked = true;
        drop(writable);
        let actual =
            stat_len(&retained).map_err(|e| self.fail(RetentionOperation::InspectSnapshot, e))?;
        if actual != self.len {
            return Err(RetentionError::SnapshotMismatch {
                kind: SnapshotMismatchKind::Length {
                    expected: self.len,
                    actual,
                },
            });
        }
        let charge = std::mem::replace(&mut self.charge, self.scope.budget.empty_charge());
        let sha256 = std::mem::take(&mut self.hasher).finalize().into();
        Ok(RetainedBytes::new(
            File::from(readable),
            self.len,
            sha256,
            charge,
        ))
    }
}

impl Write for SnapshotWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let want = u64::try_from(buf.len()).map_err(io::Error::other)?;
        let granted = self.charge.grow(want);
        if granted == 0 {
            return Err(RetentionError::BudgetExceeded {
                limit: self.scope.budget.limit(),
            }
            .into_io());
        }
        let granted_len = usize::try_from(granted).expect("granted never exceeds buf.len()");
        let result = self.write_charged(buf.get(..granted_len).unwrap_or(buf));
        let written = match &result {
            Ok(written) => u64::try_from(*written).expect("written never exceeds buf.len()"),
            Err(_) => 0,
        };
        self.charge.shrink(granted - written);
        match result {
            Ok(written) => Ok(written),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(e),
            Err(e) => Err(self.fail(RetentionOperation::WriteSnapshot, e).into_io()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SnapshotWriter<'_> {
    /// Writes an already-charged `chunk` and feeds what landed to the
    /// running digest and length.
    fn write_charged(&mut self, chunk: &[u8]) -> io::Result<usize> {
        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::other("snapshot writer has no file"));
        };
        #[cfg(test)]
        let chunk = {
            let cap = fault::cap_write(self.len, chunk.len())?;
            chunk.get(..cap).unwrap_or(chunk)
        };
        let written = step!(WriteSnapshot, file.write(chunk))?;
        let landed = chunk
            .get(..written)
            .ok_or_else(|| io::Error::other("file reported more bytes than it was given"))?;
        self.hasher.update(landed);
        self.len = self
            .len
            .checked_add(u64::try_from(written).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("snapshot length overflowed"))?;
        Ok(written)
    }
}

impl Drop for SnapshotWriter<'_> {
    fn drop(&mut self) {
        if !self.unlinked {
            // Best effort; a name left behind is removed by `close`.
            let _ = step!(
                UnlinkSnapshot,
                rustix::fs::unlinkat(
                    self.scope.private.file(),
                    self.name.as_str(),
                    AtFlags::empty()
                )
                .map_err(io::Error::from)
            );
        }
    }
}
