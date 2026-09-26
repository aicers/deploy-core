//! [`reopen_prepared`]: turning a persisted preparation back into a
//! [`PreparedPackage`] against an independently saved binding.
//!
//! Every filesystem step works relative to a held directory handle. The
//! directory is reached by an `O_NOFOLLOW` walk from `/`, its files are
//! inspected, opened and listed relative to that handle, and bytes are copied
//! only through descriptors whose `fstat` matched what was inspected. No path
//! is checked and then opened again by name.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};

use super::binding::{PreparationBinding, parse_record};
use super::contents::RetentionSite;
use super::prepare::{
    DirectoryFault, PackageWriteError, PreparationFault, PreparationFile, PreparedPackage, limit,
    new_scope, read_snapshot_error, retention, validate,
};
use super::source::{RetainedIoFault, RetainedSource, SourceRole};
use super::{BindingField, ContentError, ContentLimits, IoOperation, LimitResource, RetainedBytes};
use crate::content::ResourceLimit;
use crate::manifest::TargetArch;
use crate::package::DirectoryTrustReason;
use crate::retain::trusted_dir::{canonical_components, dir_flags, widen_mode};
use crate::retain::{RetentionScope, step};
use crate::verify::VerifyRequest;

#[cfg(test)]
mod tests;

/// Group- and other-write bits.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const STICKY: u32 = 0o1000;

/// Reopens the preparation persisted at `directory`, holding it to
/// `expected_binding` and revalidating everything from fresh private copies.
///
/// `expected_binding` must come from the caller's own saved request
/// correlation — for example the record it kept when it sent the signing
/// request — and not merely from the record found beside the archive: a
/// record, manifest and archive changed together are self-consistent and only
/// an independent expectation refuses them. Crossing a process or job
/// boundary always loses a package's standing, and only this call makes a new
/// one.
///
/// The steps run in this order, and the first failure is the result:
///
/// 0. `expected_binding` is compared with `request` and `target_arch`, before
///    any filesystem access;
/// 1. `directory` is reached by an `O_NOFOLLOW` walk over held handles from
///    `/`, and it and its parent are held to their modes;
/// 2. it is listed, and must hold exactly `manifest.json`, `archive.tar.zst`
///    and `preparation.json`;
/// 3. all three are inspected, opened without following links or blocking,
///    checked to be the files inspected, and held to their size limits,
///    before any byte is copied;
/// 4. the record is copied, parsed under `limits`, and compared with
///    `expected_binding`;
/// 5. the manifest is copied, and its digest and length compared;
/// 6. the archive is copied, and its digest and length compared;
/// 7. the manifest is reparsed and every check [`prepare_package`] runs is
///    run again.
///
/// Neither block is regenerated, and nothing is marked signed. Files at mode
/// 0644 owned by another user are accepted: modes are not authentication,
/// and the binding, the fresh copies and the revalidation are. Every copy
/// made is charged to `RetainedDisk`, and all but the archive's are released
/// before this returns.
///
/// This defends against link and substitution races by unrelated users, not
/// against root, processes of the same user, or a malicious filesystem.
///
/// [`prepare_package`]: super::prepare_package
///
/// # Errors
///
/// The first failure, in step order:
///
/// - [`PackageWriteError::BindingMismatch`] naming the first field, in record
///   order, in which `expected_binding` disagrees with `request` or
///   `target_arch`.
/// - [`PreparationFault::UnsafeDirectory`] for a path that is not absolute
///   or canonical, `/`, a symbolic-link or non-directory component, a group-
///   or other-writable directory, or a group- or other-writable parent
///   without the sticky bit.
/// - [`PreparationFault::ExtraMember`] for any other entry, then
///   [`PreparationFault::MissingMember`] for the first absent file.
/// - Per file, in file order: [`PreparationFault::Symlink`],
///   [`PreparationFault::NotRegularFile`],
///   [`PreparationFault::GroupOrOtherWritable`],
///   [`PreparationFault::IdentityChanged`], then
///   [`ContentError::LimitExceeded`] naming `RawManifest`,
///   `CompressedArchive` or `PreparationRecord` for a file larger than that.
/// - [`ContentError::Io`] with [`IoOperation::InspectStagingParent`] or
///   [`IoOperation::CreateStaging`] when private storage cannot be set up.
/// - The record's faults as
///   [`PreparationBinding::from_record_bytes`] names them, under `limits`,
///   then [`PackageWriteError::BindingMismatch`] for its first field
///   differing from `expected_binding`.
/// - [`PackageWriteError::BindingMismatch`] naming `ManifestSha256` or
///   `ManifestLength`, then `ArchiveSha256` or `ArchiveLength`; the archive
///   is never read once the manifest has failed.
/// - The content verdict [`prepare_package`] gives.
/// - [`ContentError::LimitExceeded`] for a file that grows past its limit
///   while it is copied, or naming `RetainedDisk`, and [`ContentError::Io`]
///   with [`IoOperation::OpenPreparation`] and the directory, component or
///   file path for a failed walk, listing, inspection, open or read — or with
///   a snapshot operation when retained storage fails.
pub fn reopen_prepared(
    directory: &Path,
    expected_binding: &PreparationBinding,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<PreparedPackage, PackageWriteError> {
    // 0. The request, before any filesystem access.
    if let Some(field) = expected_binding.request_difference(request, target_arch) {
        return Err(PackageWriteError::BindingMismatch { field });
    }

    // 1-3. The directory, its listing and its three files.
    let dir = open_directory(directory)?;
    list(&dir)?;
    let manifest_file = open_file(&dir, PreparationFile::Manifest, limits)?;
    let archive_file = open_file(&dir, PreparationFile::Archive, limits)?;
    let record_file = open_file(&dir, PreparationFile::Record, limits)?;

    // 4. The record.
    let scope = new_scope(limits, staging_parent)?;
    let record = {
        let snapshot = record_file.copy(&scope)?;
        read_small(&snapshot)?
    };
    let recorded = parse_record(&record, limits)?;
    if let Some(field) = recorded.first_difference(expected_binding) {
        return Err(PackageWriteError::BindingMismatch { field });
    }

    // 5. M.
    let manifest: Arc<[u8]> = {
        let snapshot = manifest_file.copy(&scope)?;
        compare(
            &snapshot,
            expected_binding.manifest_sha256(),
            expected_binding.manifest_length(),
            [BindingField::ManifestSha256, BindingField::ManifestLength],
        )?;
        Arc::from(read_small(&snapshot)?)
    };

    // 6. A.
    let archive = archive_file.copy(&scope)?;
    compare(
        &archive,
        expected_binding.archive_sha256(),
        expected_binding.archive_length(),
        [BindingField::ArchiveSha256, BindingField::ArchiveLength],
    )?;

    // 7. Revalidate.
    validate(&manifest, &archive, request, target_arch, limits, &scope)?;

    // 8. A new handle.
    Ok(PreparedPackage::new(
        manifest,
        archive,
        expected_binding.clone(),
        limits.clone(),
        scope,
    ))
}

/// A directory held open, with the path it was reached by for diagnostics.
struct HeldDir {
    fd: OwnedFd,
    path: PathBuf,
}

fn unsafe_directory(reason: DirectoryFault) -> PackageWriteError {
    PackageWriteError::InvalidPreparation {
        reason: PreparationFault::UnsafeDirectory { reason },
    }
}

fn invalid(reason: PreparationFault) -> PackageWriteError {
    PackageWriteError::InvalidPreparation { reason }
}

/// Reports a failed filesystem step on `path`, keeping the original error.
fn open_io(path: PathBuf, source: io::Error) -> PackageWriteError {
    PackageWriteError::Content(ContentError::Io {
        operation: IoOperation::OpenPreparation,
        path: Some(path),
        source,
    })
}

/// Step 1: checks the syntax, walks to the directory through held no-follow
/// handles, and holds it and its parent to their modes.
fn open_directory(directory: &Path) -> Result<HeldDir, PackageWriteError> {
    let components = canonical_components(directory).map_err(|reason| {
        unsafe_directory(match reason {
            DirectoryTrustReason::NotAbsolute => DirectoryFault::NotAbsolute,
            _ => DirectoryFault::NotCanonical,
        })
    })?;
    if components.is_empty() {
        return Err(unsafe_directory(DirectoryFault::NoParent));
    }

    let mut current_path = PathBuf::from("/");
    let mut current: OwnedFd = step!(
        OpenPreparationComponent,
        rustix::fs::open("/", dir_flags(), Mode::empty()).map_err(io::Error::from)
    )
    .map_err(|source| open_io(current_path.clone(), source))?;
    let mut parent = None;
    for component in components {
        let child_path = current_path.join(component);
        let child = match step!(
            OpenPreparationComponent,
            rustix::fs::openat(&current, component, dir_flags(), Mode::empty())
                .map_err(io::Error::from)
        ) {
            Ok(child) => child,
            Err(source) => return Err(classify_component(&current, component, child_path, source)),
        };
        parent = Some((std::mem::replace(&mut current, child), current_path));
        current_path = child_path;
    }
    let Some((parent, parent_path)) = parent else {
        return Err(unsafe_directory(DirectoryFault::NoParent));
    };

    let mode = mode_of(&current, &current_path)?;
    if mode & GROUP_OR_OTHER_WRITE != 0 {
        return Err(unsafe_directory(DirectoryFault::GroupOrOtherWritable));
    }
    let parent_mode = mode_of(&parent, &parent_path)?;
    if parent_mode & GROUP_OR_OTHER_WRITE != 0 && parent_mode & STICKY == 0 {
        return Err(unsafe_directory(DirectoryFault::ParentGroupOrOtherWritable));
    }
    Ok(HeldDir {
        fd: current,
        path: current_path,
    })
}

fn mode_of(fd: &OwnedFd, path: &Path) -> Result<u32, PackageWriteError> {
    step!(
        InspectPreparationDirectory,
        rustix::fs::fstat(fd).map_err(io::Error::from)
    )
    .map(|stat| widen_mode(stat.st_mode))
    .map_err(|source| open_io(path.to_owned(), source))
}

/// Names a component the walk could not open, for diagnostics only: the
/// refusal already happened on the held-handle open.
fn classify_component(
    parent: &OwnedFd,
    component: &OsStr,
    path: PathBuf,
    source: io::Error,
) -> PackageWriteError {
    let inspected = step!(
        InspectPreparationComponent,
        rustix::fs::statat(parent, component, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
    );
    match inspected.map(|stat| FileType::from_raw_mode(stat.st_mode)) {
        Ok(FileType::Symlink) => unsafe_directory(DirectoryFault::SymlinkComponent),
        Ok(FileType::Directory) | Err(_) => open_io(path, source),
        Ok(_) => unsafe_directory(DirectoryFault::NotDirectory),
    }
}

/// Step 2: lists the directory through its handle. It stops at the first
/// name that is not one of the three files, so at most four are read.
fn list(dir: &HeldDir) -> Result<(), PackageWriteError> {
    let entries = step!(
        ListPreparation,
        rustix::fs::Dir::read_from(&dir.fd).map_err(io::Error::from)
    )
    .map_err(|source| open_io(dir.path.clone(), source))?;
    let mut present = [false; PreparationFile::ALL.len()];
    for entry in entries {
        let entry = entry.map_err(|errno| open_io(dir.path.clone(), errno.into()))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let Some(at) = PreparationFile::ALL
            .iter()
            .position(|file| file.name().as_bytes() == name)
        else {
            return Err(invalid(PreparationFault::ExtraMember));
        };
        if let Some(slot) = present.get_mut(at) {
            *slot = true;
        }
    }
    for (file, present) in PreparationFile::ALL.into_iter().zip(present) {
        if !present {
            return Err(invalid(PreparationFault::MissingMember { file }));
        }
    }
    Ok(())
}

/// One preparation file, opened and checked, ready to copy.
struct OpenedFile {
    file: File,
    path: PathBuf,
    limit: ResourceLimit,
}

fn same_inode(stat: &Stat, other: &Stat) -> bool {
    stat.st_dev == other.st_dev && stat.st_ino == other.st_ino
}

/// Step 3 for one file: inspects it, opens it without following a link or
/// blocking, checks the descriptor is what was inspected, and holds its size
/// to its limit.
fn open_file(
    dir: &HeldDir,
    which: PreparationFile,
    limits: &ContentLimits,
) -> Result<OpenedFile, PackageWriteError> {
    let name = which.name();
    let path = dir.path.join(name);
    let inspected = step!(
        StatPreparationFile,
        rustix::fs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
    )
    .map_err(|source| open_io(path.clone(), source))?;
    match FileType::from_raw_mode(inspected.st_mode) {
        FileType::RegularFile => {}
        FileType::Symlink => return Err(invalid(PreparationFault::Symlink { file: which })),
        _ => return Err(invalid(PreparationFault::NotRegularFile { file: which })),
    }
    if widen_mode(inspected.st_mode) & GROUP_OR_OTHER_WRITE != 0 {
        return Err(invalid(PreparationFault::GroupOrOtherWritable {
            file: which,
        }));
    }
    let fd = step!(
        OpenPreparationFile,
        rustix::fs::openat(
            &dir.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)
    )
    .map_err(|source| open_io(path.clone(), source))?;
    let opened = step!(
        InspectPreparationFile,
        rustix::fs::fstat(&fd).map_err(io::Error::from)
    )
    .map_err(|source| open_io(path.clone(), source))?;
    if !same_inode(&inspected, &opened)
        || FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
    {
        return Err(invalid(PreparationFault::IdentityChanged { file: which }));
    }
    let limit = limits.resource_limit(match which {
        PreparationFile::Manifest => LimitResource::RawManifest,
        PreparationFile::Archive => LimitResource::CompressedArchive,
        PreparationFile::Record => LimitResource::PreparationRecord,
    });
    if u64::try_from(opened.st_size).map_or(true, |size| size > limit.max) {
        return Err(self::limit(limit.resource, limits));
    }
    Ok(OpenedFile {
        file: File::from(fd),
        path,
        limit,
    })
}

impl OpenedFile {
    /// Copies the file through its checked descriptor into a new snapshot,
    /// holding it to its limit on the bytes actually read.
    fn copy(self, scope: &RetentionScope) -> Result<RetainedBytes, PackageWriteError> {
        let site = RetentionSite {
            read_source: IoOperation::OpenPreparation,
            source_path: Some(&self.path),
            max_len: self.limit,
            staging_parent: None,
        };
        scope
            .snapshot_from(&mut PreparationReader(&self.file), self.limit.max)
            .map_err(|error| retention(error, &site))
    }
}

/// A checked preparation file's descriptor, read through the test seam.
struct PreparationReader<'a>(&'a File);

impl Read for PreparationReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut file = self.0;
        step!(ReadPreparationFile, file.read(buf))
    }
}

/// Reads a bounded snapshot — the record or the manifest — into memory.
fn read_small(snapshot: &RetainedBytes) -> Result<Vec<u8>, PackageWriteError> {
    let len = usize::try_from(snapshot.len())
        .map_err(|_| read_snapshot_error(io::Error::from(io::ErrorKind::OutOfMemory)))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| read_snapshot_error(io::Error::from(io::ErrorKind::OutOfMemory)))?;
    RetainedSource::new(snapshot.reader(), SourceRole::Reopened)
        .take(snapshot.len())
        .read_to_end(&mut bytes)
        .map_err(|error| read_snapshot_error(RetainedIoFault::unwrap_or_same(error)))?;
    Ok(bytes)
}

/// Compares a snapshot's digest, then its length, with the binding's.
fn compare(
    snapshot: &RetainedBytes,
    sha256: &[u8; 32],
    length: u64,
    fields: [BindingField; 2],
) -> Result<(), PackageWriteError> {
    let [digest_field, length_field] = fields;
    if snapshot.sha256() != sha256 {
        return Err(PackageWriteError::BindingMismatch {
            field: digest_field,
        });
    }
    if snapshot.len() != length {
        return Err(PackageWriteError::BindingMismatch {
            field: length_field,
        });
    }
    Ok(())
}
