//! No-clobber, durable publication of retained bytes.
//!
//! A file is published by writing a 0600 dot-prefixed sibling temporary under
//! the held destination parent, syncing it, reading it back to verify it, and
//! then `linkat`-ing it to the destination name: `linkat` never replaces an
//! existing entry, so the destination is never clobbered. Its success is the
//! **publish point**. A failure before it leaves the destination absent; a
//! failure after it is [`PublicationError::PublishDurability`], because the
//! complete output is already visible and only its durability is uncertain.
//!
//! A directory is assembled in a 0700 dot-prefixed staging sibling and
//! published by `renameat`, after a second destination-absent check. POSIX
//! `rename` replaces an **empty** directory at the destination, and nothing
//! portable across Linux and macOS refuses that, so an empty directory created
//! concurrently between the recheck and the rename is replaced. Directory
//! publication therefore relies on the caller serializing writers under a
//! trusted parent; this module provides no cross-process lock and claims no
//! transactional multi-file rename.
//!
//! Cleanup before the publish point is best effort. When it fails, a
//! `.deploy-core-publish-<hex>.tmp` file or directory may remain beside the
//! destination; removing stale ones is the caller's job.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

use rustix::fs::AtFlags;
use sha2::{Digest, Sha256};

use super::trusted_dir::{TrustedDir, TrustedDirError, canonical_components, open_trusted_dir};
use super::{
    Charge, RetentionScope, create_exclusive, create_fresh_file, make_fresh_dir, open_owned_dir,
};
use crate::durability::sync_open_dir;
use crate::package::{
    CopyMismatchKind, DirectoryTrustReason, PublicationError, PublicationOperation,
    PublishedPackage, RetainedBytes,
};

/// The prefix of every publication temporary and staging directory.
const PUBLISH_PREFIX: &str = ".deploy-core-publish-";
const PUBLISH_SUFFIX: &str = ".tmp";

/// The names a published directory may contain. No caller string is ever used
/// as a name.
// The shared prefix is the point: every name is one of a preparation's
// files, and the variants read as such at their use sites.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublishedFileName {
    PreparationManifest,
    PreparationArchive,
    PreparationRecord,
}

impl PublishedFileName {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PreparationManifest => "manifest.json",
            Self::PreparationArchive => "archive.tar.zst",
            Self::PreparationRecord => "preparation.json",
        }
    }
}

/// Publishes `bytes` as a new regular file at `destination`, mode 0600,
/// without ever replacing an existing entry.
///
/// The bytes go to a `.deploy-core-publish-<hex>.tmp` sibling under the held
/// parent handle, charged against `scope`'s budget, synced and verified by
/// length and then digest, and are published by `linkat`. The temporary name
/// is then removed and the parent synced.
///
/// # Errors
///
/// - Before the publish point: the primary error, with the destination
///   absent. The temporary is removed best-effort, and may remain when that
///   removal fails.
/// - [`PublicationError::DestinationExists`] when any entry is at the
///   destination, found by the precheck or by inspecting it after `linkat`
///   fails, whatever error number the platform gave.
/// - [`PublicationError::PublishDurability`] when removing the temporary
///   name or syncing the parent fails after the publish point.
pub(crate) fn publish_file(
    bytes: &RetainedBytes,
    destination: &Path,
    scope: &RetentionScope,
) -> Result<PublishedPackage, PublicationError> {
    let (parent, name) = open_destination_parent(destination)?;
    check_absent(&parent, name, destination)?;

    let (temp_name, mut temp) = create_fresh_file(&parent, PUBLISH_PREFIX, PUBLISH_SUFFIX)
        .map_err(|(path, source)| PublicationError::Io {
            operation: PublicationOperation::CreateTemporary,
            path: Some(path),
            source,
        })?;
    let mut temporary = TemporaryFile {
        parent: &parent,
        name: &temp_name,
        armed: true,
    };
    let temp_path = parent.path().join(&temp_name);
    let mut charge = scope.budget().empty_charge();
    copy_verified(bytes, &mut temp, &temp_path, &mut charge, scope)?;
    drop(temp);

    #[cfg(test)]
    super::fault::before_publish();
    step!(
        Link,
        rustix::fs::linkat(
            parent.file(),
            temp_name.as_str(),
            parent.file(),
            name,
            AtFlags::empty()
        )
        .map_err(io::Error::from)
    )
    .map_err(|e| {
        classify_publish_failure(&parent, name, destination, PublicationOperation::Link, e)
    })?;

    // The publish point has passed: nothing below is a clean failure, and
    // the temporary name is removed exactly once, here.
    temporary.armed = false;
    step!(
        RemoveTemporary,
        rustix::fs::unlinkat(parent.file(), temp_name.as_str(), AtFlags::empty())
            .map_err(io::Error::from)
    )
    .map_err(|source| {
        durability_error(destination, PublicationOperation::RemoveTemporary, source)
    })?;
    step!(SyncParent, sync_open_dir(parent.file())).map_err(|source| {
        durability_error(destination, PublicationOperation::SyncDirectory, source)
    })?;
    drop(charge);
    Ok(PublishedPackage::new(
        destination.to_owned(),
        *bytes.sha256(),
        bytes.len(),
    ))
}

/// Publishes a new directory at `destination` holding exactly `files`, each
/// a 0600 regular file, without ever replacing an existing entry.
///
/// The files are written, synced and verified in a
/// `.deploy-core-publish-<hex>.tmp` staging sibling, which is synced, checked
/// once more for an absent destination and published by `renameat`. The
/// parent is then synced.
///
/// **Callers must serialize writers under a trusted parent.** `renameat`
/// replaces an *empty* directory created concurrently at the destination
/// after the recheck, and this function provides no cross-process lock and no
/// transactional multi-file rename.
///
/// # Errors
///
/// - Before the publish point: the primary error, with the destination
///   absent. The created files and the staging directory are removed
///   best-effort, and the staging sibling may remain when that fails. A
///   duplicated name fails as [`PublicationOperation::CreateTemporary`] with
///   `AlreadyExists`.
/// - [`PublicationError::DestinationExists`] when any entry is at the
///   destination, found by either check or by inspecting it after
///   `renameat` fails, whatever error number the platform gave.
/// - [`PublicationError::PublishDurability`] when syncing the parent fails
///   after the publish point, with the complete directory present.
pub(crate) fn publish_directory(
    files: &[(PublishedFileName, &RetainedBytes)],
    destination: &Path,
    scope: &RetentionScope,
) -> Result<(), PublicationError> {
    let (parent, name) = open_destination_parent(destination)?;
    check_absent(&parent, name, destination)?;

    let staging_name =
        make_fresh_dir(&parent, PUBLISH_PREFIX, PUBLISH_SUFFIX).map_err(|(path, source)| {
            PublicationError::Io {
                operation: PublicationOperation::CreateStagingDirectory,
                path,
                source,
            }
        })?;
    let mut staging = StagingDirectory {
        parent: &parent,
        name: &staging_name,
        dir: None,
        created: Vec::new(),
        armed: true,
    };
    let staging_path = parent.path().join(&staging_name);
    let dir = open_owned_dir(&parent, &staging_name).map_err(|source| PublicationError::Io {
        operation: PublicationOperation::CreateStagingDirectory,
        path: Some(staging_path.clone()),
        source,
    })?;
    let dir: &TrustedDir = staging
        .dir
        .insert(TrustedDir::from_parts(dir, staging_path.clone()));

    let mut charge = scope.budget().empty_charge();
    for (file_name, bytes) in files {
        let file_path = staging_path.join(file_name.as_str());
        let mut file = step!(
            CreateTemporary,
            create_exclusive(dir.file(), OsStr::new(file_name.as_str()))
        )
        .map_err(|source| PublicationError::Io {
            operation: PublicationOperation::CreateTemporary,
            path: Some(file_path.clone()),
            source,
        })?;
        staging.created.push(*file_name);
        copy_verified(bytes, &mut file, &file_path, &mut charge, scope)?;
    }
    step!(SyncStagingDirectory, sync_open_dir(dir.file())).map_err(|source| {
        PublicationError::Io {
            operation: PublicationOperation::SyncDirectory,
            path: Some(staging_path.clone()),
            source,
        }
    })?;
    check_absent(&parent, name, destination)?;

    #[cfg(test)]
    super::fault::before_publish();
    step!(
        Rename,
        rustix::fs::renameat(parent.file(), staging_name.as_str(), parent.file(), name)
            .map_err(io::Error::from)
    )
    .map_err(|e| {
        classify_publish_failure(&parent, name, destination, PublicationOperation::Rename, e)
    })?;

    // The publish point has passed: the staging directory is the
    // destination now, and must not be cleaned up.
    staging.armed = false;
    step!(SyncParent, sync_open_dir(parent.file())).map_err(|source| {
        durability_error(destination, PublicationOperation::SyncDirectory, source)
    })?;
    drop(charge);
    Ok(())
}

/// Checks `destination`'s syntax, splits off its final component, and opens
/// its parent as a trusted directory.
fn open_destination_parent(destination: &Path) -> Result<(TrustedDir, &OsStr), PublicationError> {
    let unsafe_destination = |reason| PublicationError::UnsafeDestinationParent {
        path: destination.to_owned(),
        reason,
    };
    let components = canonical_components(destination).map_err(unsafe_destination)?;
    let Some(name) = components.last().copied() else {
        return Err(unsafe_destination(DirectoryTrustReason::NoFinalComponent));
    };
    let parent_path = destination
        .parent()
        .ok_or_else(|| unsafe_destination(DirectoryTrustReason::NoFinalComponent))?;
    let parent = open_trusted_dir(parent_path).map_err(|e| match e {
        TrustedDirError::Unsafe { path, reason } => {
            PublicationError::UnsafeDestinationParent { path, reason }
        }
        TrustedDirError::Io { path, source } => PublicationError::Io {
            operation: PublicationOperation::OpenDestinationParent,
            path: Some(path),
            source,
        },
    })?;
    Ok((parent, name))
}

/// Refuses any entry at `name` in `parent`, a dangling symlink included.
fn check_absent(
    parent: &TrustedDir,
    name: &OsStr,
    destination: &Path,
) -> Result<(), PublicationError> {
    match inspect(parent, name) {
        Ok(()) => Err(PublicationError::DestinationExists {
            destination: destination.to_owned(),
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PublicationError::Io {
            operation: PublicationOperation::InspectDestination,
            path: Some(destination.to_owned()),
            source,
        }),
    }
}

/// Succeeds when an entry of any type is at `name` in `parent`.
fn inspect(parent: &TrustedDir, name: &OsStr) -> io::Result<()> {
    step!(
        InspectDestination,
        rustix::fs::statat(parent.file(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map(drop)
            .map_err(io::Error::from)
    )
}

/// Names a failed `linkat` or `renameat` by inspecting the destination
/// through the held parent, for diagnostics only: any entry there is
/// `DestinationExists`, and anything else — nothing there, or a failed
/// inspection — is the original error, kind preserved.
fn classify_publish_failure(
    parent: &TrustedDir,
    name: &OsStr,
    destination: &Path,
    operation: PublicationOperation,
    source: io::Error,
) -> PublicationError {
    if inspect(parent, name).is_ok() {
        PublicationError::DestinationExists {
            destination: destination.to_owned(),
        }
    } else {
        PublicationError::Io {
            operation,
            path: Some(destination.to_owned()),
            source,
        }
    }
}

fn durability_error(
    destination: &Path,
    operation: PublicationOperation,
    source: io::Error,
) -> PublicationError {
    PublicationError::PublishDurability {
        destination: destination.to_owned(),
        operation,
        source,
    }
}

/// Copies `bytes` into `file` through the budget, syncs it, and reads it back
/// to verify its length and then its digest.
fn copy_verified(
    bytes: &RetainedBytes,
    file: &mut File,
    path: &Path,
    charge: &mut Charge,
    scope: &RetentionScope,
) -> Result<(), PublicationError> {
    let io_error = |operation, source| PublicationError::Io {
        operation,
        path: Some(path.to_owned()),
        source,
    };
    let mut buf = vec![0u8; scope.copy_buffer().get()];
    let mut reader = bytes.reader();
    loop {
        let read =
            read_retrying(|| step!(ReadRetained, reader.read(&mut buf))).map_err(|source| {
                PublicationError::Io {
                    operation: PublicationOperation::ReadRetained,
                    path: None,
                    source,
                }
            })?;
        if read == 0 {
            break;
        }
        let chunk = buf.get(..read).ok_or_else(|| PublicationError::Io {
            operation: PublicationOperation::ReadRetained,
            path: None,
            source: io::Error::other("retained read overran its buffer"),
        })?;
        let want = u64::try_from(read)
            .map_err(|e| io_error(PublicationOperation::WriteTemporary, io::Error::other(e)))?;
        let granted = charge.grow(want);
        let granted_len = usize::try_from(granted).expect("granted never exceeds the chunk length");
        let charged = chunk.get(..granted_len).unwrap_or(chunk);
        step!(WriteTemporary, file.write_all(charged))
            .map_err(|source| io_error(PublicationOperation::WriteTemporary, source))?;
        if granted < want {
            return Err(PublicationError::DiskBudgetExceeded {
                limit: scope.budget().limit(),
            });
        }
    }
    step!(SyncFile, file.sync_all())
        .map_err(|source| io_error(PublicationOperation::SyncFile, source))?;

    #[cfg(test)]
    corrupt_for_test(file, bytes.len());

    let (actual, digest) = read_back(file, &mut buf)
        .map_err(|source| io_error(PublicationOperation::Verify, source))?;
    if actual != bytes.len() {
        return Err(PublicationError::CopyMismatch {
            path: path.to_owned(),
            kind: CopyMismatchKind::Length {
                expected: bytes.len(),
                actual,
            },
        });
    }
    if &digest != bytes.sha256() {
        return Err(PublicationError::CopyMismatch {
            path: path.to_owned(),
            kind: CopyMismatchKind::Digest,
        });
    }
    Ok(())
}

/// Reads `file` from offset 0 on the same descriptor, returning its length
/// and SHA-256.
fn read_back(file: &File, buf: &mut [u8]) -> io::Result<(u64, [u8; 32])> {
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    loop {
        let read = read_retrying(|| step!(VerifyRead, file.read_at(buf, offset)))?;
        if read == 0 {
            return Ok((offset, hasher.finalize().into()));
        }
        let chunk = buf
            .get(..read)
            .ok_or_else(|| io::Error::other("read overran its buffer"))?;
        hasher.update(chunk);
        offset = offset
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("read-back length overflowed"))?;
    }
}

fn read_retrying(mut read: impl FnMut() -> io::Result<usize>) -> io::Result<usize> {
    loop {
        match read() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Damages a synced temporary the way the test seam arranged, if it did.
#[cfg(test)]
fn corrupt_for_test(file: &File, len: u64) {
    match super::fault::corruption() {
        Some(super::fault::Corruption::FlipFirstByte) => {
            let mut byte = [0u8; 1];
            file.read_exact_at(&mut byte, 0).expect("read first byte");
            byte[0] = !byte[0];
            file.write_all_at(&byte, 0).expect("flip first byte");
        }
        Some(super::fault::Corruption::TruncateOne) => {
            file.set_len(len - 1).expect("truncate");
        }
        None => {}
    }
}

/// A publication temporary file, removed best-effort unless disarmed at the
/// publish point.
struct TemporaryFile<'a> {
    parent: &'a TrustedDir,
    name: &'a str,
    armed: bool,
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Best effort: the primary error is what the caller sees, and a
            // temporary whose removal fails remains under its dot-prefixed
            // name.
            let _ = step!(
                RemoveTemporary,
                rustix::fs::unlinkat(self.parent.file(), self.name, AtFlags::empty())
                    .map_err(io::Error::from)
            );
        }
    }
}

/// A publication staging directory, removed best-effort with the files
/// created in it unless disarmed at the publish point.
struct StagingDirectory<'a> {
    parent: &'a TrustedDir,
    name: &'a str,
    dir: Option<TrustedDir>,
    created: Vec<PublishedFileName>,
    armed: bool,
}

impl Drop for StagingDirectory<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best effort, as for `TemporaryFile`: a staging sibling whose
        // removal fails remains under its dot-prefixed name.
        if let Some(dir) = &self.dir {
            for file_name in &self.created {
                let _ = step!(
                    RemoveTemporary,
                    rustix::fs::unlinkat(dir.file(), file_name.as_str(), AtFlags::empty())
                        .map_err(io::Error::from)
                );
            }
        }
        let _ = step!(
            RemoveTemporary,
            rustix::fs::unlinkat(self.parent.file(), self.name, AtFlags::REMOVEDIR)
                .map_err(io::Error::from)
        );
    }
}
