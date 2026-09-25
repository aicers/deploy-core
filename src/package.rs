//! Retained package bytes and the publication of verified output.
//!
//! Validated package and image content has to be read from bytes nothing
//! outside this library can change between the check and the use.
//! [`RetainedBytes`] is that: a read-only handle on a private, already
//! unlinked copy the library made of an untrusted source, readable only
//! through a [`RetainedReader`]. It exposes no path, file or descriptor, so
//! caller writes, replaced pathnames and descriptors the caller kept open on
//! the original cannot reach it.
//!
//! The protection has a boundary. The caller supplies a trusted filesystem and
//! process isolation; nothing here defends against root, against other
//! processes running as the same user, against same-process memory access or
//! same-user `/proc` descriptor access, or against a malicious filesystem or
//! failing hardware. Retained copies are transient, not durable: the operating
//! system reclaims them when their last handle drops or the process exits.
//!
//! Publishing retained bytes to a caller-chosen destination reports through
//! [`PublishedPackage`] and [`PublicationError`]. Publication never replaces
//! an existing entry, and a failure after the output became visible is
//! reported as [`PublicationError::PublishDurability`] rather than as success
//! or as a clean failure. A failure before that point leaves the destination
//! absent, but may leave a dot-prefixed `.deploy-core-publish-<hex>.tmp`
//! sibling behind when its own removal fails; removing stale ones is the
//! caller's job.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::retain::Charge;

/// A read-only handle on bytes the library copied once into private storage.
///
/// The bytes are those of exactly one pass over the source, taken before any
/// check ran on them; [`len`](Self::len) and [`sha256`](Self::sha256) describe
/// them and never change. Every read goes to the same unlinked inode through a
/// [`RetainedReader`], and the handle offers no way to reach a path, a file or
/// a descriptor.
///
/// A `RetainedBytes` cannot be made outside this crate:
///
/// ```compile_fail
/// let bytes = deploy_core::package::RetainedBytes::default();
/// ```
///
/// ```compile_fail
/// fn forge(file: std::fs::File) -> deploy_core::package::RetainedBytes {
///     deploy_core::package::RetainedBytes { backing: todo!() }
/// }
/// ```
///
/// nor copied by a caller:
///
/// ```compile_fail
/// fn copy(bytes: &deploy_core::package::RetainedBytes) -> deploy_core::package::RetainedBytes {
///     bytes.clone()
/// }
/// ```
///
/// and it offers no descriptor, path or inner file:
///
/// ```compile_fail
/// use std::os::fd::AsRawFd;
/// fn fd(bytes: &deploy_core::package::RetainedBytes) -> i32 {
///     bytes.as_raw_fd()
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::AsFd;
/// fn fd(bytes: &deploy_core::package::RetainedBytes) {
///     let _ = bytes.as_fd();
/// }
/// ```
///
/// ```compile_fail
/// fn path(bytes: &deploy_core::package::RetainedBytes) -> &std::path::Path {
///     bytes.path()
/// }
/// ```
///
/// ```compile_fail
/// fn file(bytes: deploy_core::package::RetainedBytes) -> std::fs::File {
///     bytes.into_inner()
/// }
/// ```
pub struct RetainedBytes {
    backing: Arc<Backing>,
}

/// What every handle sharing one retained copy owns together.
struct Backing {
    file: File,
    len: u64,
    sha256: [u8; 32],
    /// Held for its drop: the budget charge for the bytes this inode holds
    /// is released with the last handle.
    _charge: Charge,
}

impl RetainedBytes {
    /// Wraps a finished snapshot: `file` is read-only, its name is gone, and
    /// `len` and `sha256` describe exactly the bytes written to it.
    pub(crate) fn new(file: File, len: u64, sha256: [u8; 32], charge: Charge) -> Self {
        Self {
            backing: Arc::new(Backing {
                file,
                len,
                sha256,
                _charge: charge,
            }),
        }
    }

    /// Returns another handle on the same retained copy.
    // Consumed by the verification and finalization work that lands after
    // this storage core; until then only tests call it.
    #[allow(dead_code)]
    pub(crate) fn share(&self) -> RetainedBytes {
        Self {
            backing: Arc::clone(&self.backing),
        }
    }

    /// Returns the number of retained bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.backing.len
    }

    /// Returns whether no byte was retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backing.len == 0
    }

    /// Returns the SHA-256 digest of exactly the retained bytes.
    #[must_use]
    pub fn sha256(&self) -> &[u8; 32] {
        &self.backing.sha256
    }

    /// Returns a reader over the retained bytes, positioned at the start.
    ///
    /// Each reader keeps its own cursor, so readers never disturb each other.
    #[must_use]
    pub fn reader(&self) -> RetainedReader<'_> {
        RetainedReader {
            backing: &self.backing,
            pos: 0,
        }
    }

    /// Returns the raw descriptor number, for the close-on-exec test.
    #[cfg(test)]
    pub(crate) fn raw_fd_for_test(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.backing.file.as_raw_fd()
    }
}

impl fmt::Debug for RetainedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedBytes")
            .field("len", &self.backing.len)
            .field("sha256", &hex(&self.backing.sha256))
            .finish()
    }
}

/// A reader over [`RetainedBytes`], with its own cursor.
///
/// It reads positionally, so any number of readers over one retained copy
/// return identical bytes. Its errors are plain [`io::Error`]s with no path,
/// because the retained copy has none.
///
/// A reader cannot outlive the bytes it reads:
///
/// ```compile_fail
/// fn detach(bytes: deploy_core::package::RetainedBytes) -> deploy_core::package::RetainedReader<'static> {
///     bytes.reader()
/// }
/// ```
///
/// and it offers no descriptor, path or inner file:
///
/// ```compile_fail
/// use std::os::fd::AsRawFd;
/// fn fd(reader: &deploy_core::package::RetainedReader<'_>) -> i32 {
///     reader.as_raw_fd()
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::AsFd;
/// fn fd(reader: &deploy_core::package::RetainedReader<'_>) {
///     let _ = reader.as_fd();
/// }
/// ```
///
/// ```compile_fail
/// fn path<'a>(reader: &'a deploy_core::package::RetainedReader<'_>) -> &'a std::path::Path {
///     reader.path()
/// }
/// ```
///
/// ```compile_fail
/// fn file(reader: deploy_core::package::RetainedReader<'_>) -> std::fs::File {
///     reader.into_inner()
/// }
/// ```
pub struct RetainedReader<'a> {
    backing: &'a Backing,
    pos: u64,
}

impl fmt::Debug for RetainedReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedReader")
            .field("len", &self.backing.len)
            .field("pos", &self.pos)
            .finish()
    }
}

impl Read for RetainedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(remaining) = self.backing.len.checked_sub(self.pos).filter(|&r| r > 0) else {
            return Ok(0);
        };
        let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let Some(window) = buf.get_mut(..want) else {
            return Ok(0);
        };
        if window.is_empty() {
            return Ok(0);
        }
        let read = self.backing.file.read_at(window, self.pos)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "retained bytes ended before their recorded length",
            ));
        }
        self.pos = self
            .pos
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("retained reader position overflowed"))?;
        Ok(read)
    }
}

impl Seek for RetainedReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(offset) => self.backing.len.checked_add_signed(offset),
            SeekFrom::Current(offset) => self.pos.checked_add_signed(offset),
        };
        let target = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative or overflowing position",
            )
        })?;
        self.pos = target;
        Ok(target)
    }
}

/// The receipt for a successful publication.
///
/// It records what was published, not what is there now: the destination is
/// an ordinary path anyone with access can change afterwards, so it is not
/// evidence of anything.
#[derive(Debug, Clone)]
pub struct PublishedPackage {
    destination: PathBuf,
    sha256: [u8; 32],
    len: u64,
}

impl PublishedPackage {
    pub(crate) fn new(destination: PathBuf, sha256: [u8; 32], len: u64) -> Self {
        Self {
            destination,
            sha256,
            len,
        }
    }

    /// Returns the path the bytes were published to.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the SHA-256 digest of the published bytes.
    #[must_use]
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Returns the number of published bytes.
    // A receipt reports a length; an `is_empty` beside it would be a second
    // spelling of `len() == 0` that no caller of a receipt has asked for.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }
}

/// Why a publication failed.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    /// An entry of some type — a file, a directory, a symlink, dangling or
    /// not — already exists at the destination. It was left untouched.
    #[error("publication destination {} already exists", .destination.display())]
    DestinationExists { destination: PathBuf },

    /// The destination path, or its parent directory, was refused by the
    /// directory trust policy.
    #[error("publication destination {} is not trusted: {reason}", .path.display())]
    UnsafeDestinationParent {
        path: PathBuf,
        reason: DirectoryTrustReason,
    },

    /// The operation's retained-disk budget ran out. This is the library's
    /// own limit, distinct from a full filesystem, which is
    /// [`PublicationError::Io`] carrying the operating system's error kind.
    #[error("publication exceeded the retained-disk budget of {limit} bytes")]
    DiskBudgetExceeded { limit: u64 },

    /// A filesystem operation failed before the output was published. `path`
    /// is `None` only for [`PublicationOperation::ReadRetained`], whose
    /// retained copy has no path.
    #[error("{operation} failed{}: {source}", describe_path(.path.as_deref()))]
    Io {
        operation: PublicationOperation,
        path: Option<PathBuf>,
        #[source]
        source: io::Error,
    },

    /// The synced copy read back differently from the retained bytes.
    #[error("published copy {} does not match the retained bytes: {kind}", .path.display())]
    CopyMismatch {
        path: PathBuf,
        kind: CopyMismatchKind,
    },

    /// A step after the publish point failed. The complete output may
    /// already be present at `destination`; its durability is uncertain.
    #[error(
        "{operation} failed after {} was published; the complete output may already be present, durability is uncertain: {source}",
        .destination.display()
    )]
    PublishDurability {
        destination: PathBuf,
        operation: PublicationOperation,
        #[source]
        source: io::Error,
    },
}

fn describe_path(path: Option<&Path>) -> String {
    path.map(|path| format!(" at {}", path.display()))
        .unwrap_or_default()
}

/// How a published copy differed from its retained bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMismatchKind {
    /// The copy holds a different number of bytes.
    Length { expected: u64, actual: u64 },
    /// The copy has the right length but a different SHA-256 digest.
    Digest,
}

impl fmt::Display for CopyMismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "expected {expected} bytes, found {actual}")
            }
            Self::Digest => f.write_str("sha-256 digest differs"),
        }
    }
}

/// The publication step a [`PublicationError`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationOperation {
    /// Opening and judging the destination's parent directory.
    OpenDestinationParent,
    /// Checking whether the destination already exists.
    InspectDestination,
    /// Creating the staging directory a directory is assembled in.
    CreateStagingDirectory,
    /// Creating a temporary file.
    CreateTemporary,
    /// Reading the retained bytes being published.
    ReadRetained,
    /// Writing a temporary file.
    WriteTemporary,
    /// Flushing a temporary file to disk.
    SyncFile,
    /// Reading a synced temporary back to verify it.
    Verify,
    /// Flushing a directory to disk.
    SyncDirectory,
    /// Linking the temporary file into place.
    Link,
    /// Renaming the staging directory into place.
    Rename,
    /// Removing the temporary name after the publish point.
    RemoveTemporary,
}

impl fmt::Display for PublicationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenDestinationParent => "opening the destination parent",
            Self::InspectDestination => "inspecting the destination",
            Self::CreateStagingDirectory => "creating the staging directory",
            Self::CreateTemporary => "creating a temporary file",
            Self::ReadRetained => "reading the retained bytes",
            Self::WriteTemporary => "writing a temporary file",
            Self::SyncFile => "syncing a temporary file",
            Self::Verify => "verifying a temporary file",
            Self::SyncDirectory => "syncing a directory",
            Self::Link => "linking the output into place",
            Self::Rename => "renaming the output into place",
            Self::RemoveTemporary => "removing the temporary name",
        })
    }
}

/// Why a directory was refused as a staging parent or a publication
/// destination parent.
///
/// These checks stop unrelated users from redirecting or replacing the
/// library's storage. They do not defend against root, against other
/// processes of the effective user, or against a malicious filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryTrustReason {
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path has an empty, `.` or `..` segment, or a trailing `/`. The
    /// library never canonicalizes; a caller may before passing it in.
    NotCanonical,
    /// A publication destination is exactly `/`, so it names nothing to
    /// create.
    NoFinalComponent,
    /// A component on the path is a symbolic link.
    SymlinkComponent,
    /// A component on the path exists but is not a directory.
    NotDirectory,
    /// An ancestor is owned by someone other than root or the effective
    /// user, or is writable by others without being a root-owned sticky
    /// directory over a child the effective user or root owns.
    UntrustedAncestor,
    /// The directory is owned by someone other than root or the effective
    /// user.
    UntrustedOwner,
    /// The directory is group- or other-writable, sticky or not.
    GroupOrOtherWritable,
    /// The effective user cannot write to and search the directory by its
    /// mode bits.
    NotWritableByEffectiveUser,
}

impl DirectoryTrustReason {
    /// Returns the [`io::ErrorKind`] a consumer reporting this refusal as
    /// I/O uses.
    // Consumed by the verification, preparation and finalization work that
    // maps these refusals onto its own I/O errors; until then only tests call
    // it.
    #[allow(dead_code)]
    pub(crate) fn io_kind(self) -> io::ErrorKind {
        match self {
            Self::NotAbsolute
            | Self::NotCanonical
            | Self::NoFinalComponent
            | Self::SymlinkComponent
            | Self::NotDirectory => io::ErrorKind::InvalidInput,
            Self::UntrustedAncestor
            | Self::UntrustedOwner
            | Self::GroupOrOtherWritable
            | Self::NotWritableByEffectiveUser => io::ErrorKind::PermissionDenied,
        }
    }
}

impl fmt::Display for DirectoryTrustReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAbsolute => "the path is not absolute",
            Self::NotCanonical => "the path is not canonical",
            Self::NoFinalComponent => "the path has no final component",
            Self::SymlinkComponent => "a path component is a symbolic link",
            Self::NotDirectory => "a path component is not a directory",
            Self::UntrustedAncestor => "an ancestor directory is not trusted",
            Self::UntrustedOwner => "the directory is owned by another user",
            Self::GroupOrOtherWritable => "the directory is group- or other-writable",
            Self::NotWritableByEffectiveUser => "the effective user cannot write to the directory",
        })
    }
}

/// Lowercase hex, for `Debug`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}
