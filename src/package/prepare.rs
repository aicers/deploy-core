//! Unsigned package preparation: [`prepare_package`], the
//! [`PreparedPackage`] it returns, its [`persist`](PreparedPackage::persist),
//! and the [`PackageWriteError`] every writer step reports.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::binding::{BindingParts, PreparationBinding};
use super::bounded::{BoundedVec, Ceiling, LimitFault, LimitWriter};
use super::contents::{RetentionSite, check_contents, from_retention};
use super::source::{RetainedIoFault, RetainedSource, SourceRole};
use super::{
    BindingField, ContentError, ContentLimits, IoOperation, LimitResource, PublicationError,
    RecordFault, RetainedBytes,
};
use crate::manifest::{PayloadManifest, TargetArch};
use crate::payload::{
    ArtifactInput, ED25519_SIGNATURE_LEN, FOOTER_SIZE, FORMAT_VERSION, KEY_ID_HEX_LEN,
    MemberLength, MemberLengthFault, PayloadError, derive_manifest, to_hex, write_archive_block,
};
use crate::retain::{PublishedFileName, RetentionError, RetentionScope, publish_directory, step};
use crate::verify::{VerifyRequest, check_statements, map_manifest_error};

#[cfg(test)]
mod tests;

/// Bytes a finalized standalone package adds around the manifest and the
/// archive block: the Ed25519 signature, its key ID and the current footer.
const ENVELOPE_OVERHEAD: usize = ED25519_SIGNATURE_LEN + KEY_ID_HEX_LEN + FOOTER_SIZE;

/// Prepares an **unsigned** standalone package from `inputs`: exactly one raw
/// manifest block (M) and one compressed archive block (A), validated against
/// each other and against `request` and `target_arch`, ready for a signing
/// step that sees only M.
///
/// The steps run in this order, and the first failure is the result:
///
/// 1. **stage** — every `input.source` is opened once, in input order, and
///    copied into private retained storage under `staging_parent`; its length
///    and SHA-256 are those of the copy, and no source path is opened again;
/// 2. **manifest** — the manifest is derived from those copies as the legacy
///    writers derive it, and serialized once into a buffer bounded by
///    `RawManifest` and by what `Package` leaves once the signature, key ID
///    and footer a finalized package adds are counted;
/// 3. **archive** — the copies, in input order, are written through the
///    legacy writers' archive layout, each member held to exactly its copy's
///    length, into a private snapshot bounded by `CompressedArchive` and by
///    what `Package` leaves; the input copies are then released;
/// 4. **validation** — M is reparsed and run through the statement checks
///    that need no trust set (completeness, safe identifiers, the exact
///    target, and the image-declaration passes) and then through the same
///    content checks [`verify_contents`](super::verify_contents) runs: the
///    architecture, legacy images, the full outer walk and every nested image;
/// 5. **binding** — the [`PreparationBinding`] is built, and refused when its
///    record would be longer than `PreparationRecord`, so every prepared
///    package can be persisted and reopened under the same limits.
///
/// Nothing here holds a key, signs, or reads a trust set. Withdrawal and the
/// reserved-target epoch are not decided, and a withdrawn build or a trust
/// package with a stale epoch prepares; both are decided at finalization,
/// under the trust supplied there. A reserved trust package passes the target
/// check only under [`VerifyRequest::for_trust`], whose epoch is recorded in
/// the binding and compared against nothing. The output is always the
/// standalone layout: no base executable, no executable prefix, no installer
/// carrier.
///
/// A source that changes while it is copied yields either a refusal or one
/// copy that M declares and A carries consistently; that copy is never
/// presented as an atomic snapshot of the original.
///
/// # Errors
///
/// The first failure, in step order:
///
/// - [`ContentError::LimitExceeded`] naming `OuterMembers` for more inputs
///   than that, before any source is opened.
/// - [`ContentError::Io`] with [`IoOperation::InspectStagingParent`] or
///   [`IoOperation::CreateStaging`] when the private storage cannot be set up
///   under `staging_parent`.
/// - [`ContentError::Io`] with [`IoOperation::SourceRead`] and the source's
///   path when an input cannot be opened or read, and
///   [`ContentError::LimitExceeded`] naming `OuterUncompressedTotal` when the
///   inputs together are longer than that.
/// - [`PackageWriteError::Payload`] for a manifest the inputs cannot make —
///   an undeclared image among them — and
///   [`PayloadError::ManifestSerialize`] when serializing it fails,
///   allocation included.
/// - [`ContentError::LimitExceeded`] naming `RawManifest`, `CompressedArchive`
///   or `Package`, before the byte that would cross it is allocated or
///   written, the per-item limit winning when one byte crosses both.
/// - [`PackageWriteError::Payload`] carrying
///   [`PayloadError::ArchivePathTooLong`] for an archive path a `tar` header
///   cannot hold.
/// - [`ContentError::Verify`] or [`ContentError::ArchitectureMismatch`], the
///   verdict [`verify_contents`](super::verify_contents) gives the same
///   content, image-archive faults included.
/// - [`ContentError::LimitExceeded`] naming `PreparationRecord` for a binding
///   whose record would be too long.
/// - [`ContentError::LimitExceeded`] naming `RetainedDisk` whenever a
///   snapshot would take the operation past it, and [`ContentError::Io`] with
///   [`IoOperation::WriteSnapshot`] or [`IoOperation::ReadSnapshot`] when
///   retained storage fails, a full filesystem included.
pub fn prepare_package(
    inputs: &[ArtifactInput],
    pinset: Option<&str>,
    trust_set_bytes: Option<&[u8]>,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<PreparedPackage, PackageWriteError> {
    // 1. Stage the inputs.
    let members = limits.get(LimitResource::OuterMembers);
    if u64::try_from(inputs.len()).map_or(true, |count| count > members) {
        return Err(limit(LimitResource::OuterMembers, limits));
    }
    let scope = new_scope(limits, staging_parent)?;
    let snapshots = stage_inputs(&scope, inputs, limits)?;

    // 2. Build M.
    let manifest = build_manifest(inputs, &snapshots, pinset, trust_set_bytes, limits)?;

    // 3. Build A from the same snapshots, then let them go.
    let archive = build_archive(&scope, inputs, &snapshots, manifest.len(), limits)?;
    drop(snapshots);

    // 4. Validate without a signature or a trust set.
    validate(&manifest, &archive, request, target_arch, limits, &scope)?;

    // 5. Bind.
    let binding = bind(&manifest, &archive, request, target_arch)?;
    let record_limit = limits.get(LimitResource::PreparationRecord);
    if binding.record_len() > record_limit {
        return Err(limit(LimitResource::PreparationRecord, limits));
    }
    Ok(PreparedPackage::new(
        manifest,
        archive,
        binding,
        limits.clone(),
        scope,
    ))
}

/// Creates the operation's retention scope under `staging_parent`.
pub(super) fn new_scope(
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<RetentionScope, PackageWriteError> {
    // `CopyBuffer` is never zero; the fallback only keeps that invariant out
    // of a panic.
    let copy_buffer = NonZeroUsize::new(limits.copy_buffer_len()).unwrap_or(NonZeroUsize::MIN);
    RetentionScope::new(
        staging_parent,
        limits.get(LimitResource::RetainedDisk),
        copy_buffer,
    )
    .map_err(|error| {
        retention(
            error,
            &RetentionSite {
                read_source: IoOperation::SourceRead,
                source_path: None,
                max_len: limits.resource_limit(LimitResource::RetainedDisk),
                staging_parent: Some(staging_parent),
            },
        )
    })
}

/// Copies every input, in input order, into its own snapshot. Each source is
/// opened exactly once.
fn stage_inputs(
    scope: &RetentionScope,
    inputs: &[ArtifactInput],
    limits: &ContentLimits,
) -> Result<Vec<RetainedBytes>, PackageWriteError> {
    let total = limits.resource_limit(LimitResource::OuterUncompressedTotal);
    let mut used = 0u64;
    let mut snapshots = Vec::with_capacity(inputs.len());
    for input in inputs {
        let site = RetentionSite {
            read_source: IoOperation::SourceRead,
            source_path: Some(&input.source),
            max_len: total,
            staging_parent: None,
        };
        let file = step!(OpenInput, File::open(&input.source)).map_err(|source| {
            PackageWriteError::Content(ContentError::Io {
                operation: IoOperation::SourceRead,
                path: Some(input.source.clone()),
                source,
            })
        })?;
        let snapshot = scope
            .snapshot_from(&mut InputReader(file), total.max - used)
            .map_err(|error| retention(error, &site))?;
        used = used
            .checked_add(snapshot.len())
            .filter(|used| *used <= total.max)
            .ok_or_else(|| limit(LimitResource::OuterUncompressedTotal, limits))?;
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

/// An input's source file, read through the test seam.
struct InputReader(File);

impl Read for InputReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        step!(ReadInput, self.0.read(buf))
    }
}

/// Derives the manifest from the snapshots and serializes it once, bounded.
fn build_manifest(
    inputs: &[ArtifactInput],
    snapshots: &[RetainedBytes],
    pinset: Option<&str>,
    trust_set_bytes: Option<&[u8]>,
    limits: &ContentLimits,
) -> Result<Arc<[u8]>, PackageWriteError> {
    let package = limits.get(LimitResource::Package);
    let overhead = u64::try_from(ENVELOPE_OVERHEAD).unwrap_or(u64::MAX);
    let Some(package_allowance) = package.checked_sub(overhead) else {
        return Err(limit(LimitResource::Package, limits));
    };
    let measured: Vec<(&ArtifactInput, String, u64)> = inputs
        .iter()
        .zip(snapshots)
        .map(|(input, snapshot)| (input, to_hex(snapshot.sha256()), snapshot.len()))
        .collect();
    let manifest =
        derive_manifest(pinset, trust_set_bytes, &measured).map_err(PackageWriteError::Payload)?;
    let mut buffer = BoundedVec::new(vec![
        Ceiling::whole(
            LimitResource::RawManifest,
            limits.get(LimitResource::RawManifest),
        ),
        Ceiling {
            resource: LimitResource::Package,
            limit: package,
            allowance: package_allowance,
        },
    ]);
    serde_json::to_writer(&mut buffer, &manifest).map_err(serialize_error)?;
    Ok(Arc::from(buffer.into_inner()))
}

/// Maps a failure serializing M: a limit carried inside it is the limit, and
/// anything else — an allocation failure included — is the serialization
/// failure the legacy writer reports for the same step.
fn serialize_error(error: serde_json::Error) -> PackageWriteError {
    if !error.is_io() {
        return PackageWriteError::Payload(PayloadError::ManifestSerialize(error));
    }
    match LimitFault::recover(io::Error::from(error)) {
        Ok(fault) => limit_fault(fault),
        Err(error) => PackageWriteError::Payload(PayloadError::ManifestSerialize(
            serde_json::Error::io(error),
        )),
    }
}

/// Writes A from the snapshots into a new snapshot, bounded by
/// `CompressedArchive` and by what `Package` leaves beside M and the
/// envelope.
fn build_archive(
    scope: &RetentionScope,
    inputs: &[ArtifactInput],
    snapshots: &[RetainedBytes],
    manifest_len: usize,
    limits: &ContentLimits,
) -> Result<RetainedBytes, PackageWriteError> {
    let site = RetentionSite {
        read_source: IoOperation::ReadSnapshot,
        source_path: None,
        max_len: limits.resource_limit(LimitResource::CompressedArchive),
        staging_parent: None,
    };
    let package = limits.get(LimitResource::Package);
    // Step 2 held M to `Package` less the envelope, so this never overflows
    // or underflows; either is reported as the limit rather than trusted.
    let fixed = u64::try_from(manifest_len)
        .ok()
        .zip(u64::try_from(ENVELOPE_OVERHEAD).ok())
        .and_then(|(manifest, overhead)| manifest.checked_add(overhead));
    let Some(package_allowance) = fixed.and_then(|fixed| package.checked_sub(fixed)) else {
        return Err(limit(LimitResource::Package, limits));
    };
    let writer = scope
        .snapshot_writer()
        .map_err(|error| retention(error, &site))?;
    let mut limited = LimitWriter::new(
        writer,
        vec![
            Ceiling::whole(
                LimitResource::CompressedArchive,
                limits.get(LimitResource::CompressedArchive),
            ),
            Ceiling {
                resource: LimitResource::Package,
                limit: package,
                allowance: package_allowance,
            },
        ],
    );
    let members = inputs.iter().zip(snapshots).map(|(input, snapshot)| {
        Ok((
            input.archive_path.as_str(),
            snapshot.len(),
            RetainedSource::new(snapshot.reader(), SourceRole::Input),
        ))
    });
    write_archive_block(members, &mut limited, MemberLength::Exact)
        .map_err(|error| archive_error(error, &site))?;
    limited
        .into_inner()
        .finish()
        .map_err(|error| retention(error, &site))
}

/// Maps a failure writing A by the typed payload it carries.
fn archive_error(error: PayloadError, site: &RetentionSite<'_>) -> PackageWriteError {
    let PayloadError::Io(error) = error else {
        return PackageWriteError::Payload(error);
    };
    let error = match LimitFault::recover(error) {
        Ok(fault) => return limit_fault(fault),
        Err(error) => error,
    };
    let error = match error.downcast::<RetentionError>() {
        Ok(error) => return retention(error, site),
        Err(error) => error,
    };
    let error = match RetainedIoFault::recover(error) {
        Ok(original) => return read_snapshot_error(original),
        Err(error) => error,
    };
    if error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<MemberLengthFault>)
    {
        return read_snapshot_error(error);
    }
    PackageWriteError::Payload(PayloadError::Io(error))
}

/// Step 4 of preparation, and step 7 of reopen: reparses M and runs every
/// check that needs neither a signature nor a trust set.
pub(super) fn validate(
    manifest: &[u8],
    archive: &RetainedBytes,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
    scope: &RetentionScope,
) -> Result<(), PackageWriteError> {
    let parsed = PayloadManifest::parse(manifest, FORMAT_VERSION).map_err(|error| {
        PackageWriteError::Content(ContentError::Verify(map_manifest_error(error)))
    })?;
    check_statements(&parsed, request, None)
        .map_err(|error| PackageWriteError::Content(ContentError::Verify(error)))?;
    let checked = check_contents(&parsed, archive, target_arch, limits, scope)
        .map_err(PackageWriteError::Content)?;
    drop(checked);
    Ok(())
}

fn bind(
    manifest: &[u8],
    archive: &RetainedBytes,
    request: &VerifyRequest,
    target_arch: TargetArch,
) -> Result<PreparationBinding, PackageWriteError> {
    let parts = BindingParts {
        manifest_sha256: Sha256::digest(manifest).into(),
        manifest_length: u64::try_from(manifest.len()).unwrap_or(u64::MAX),
        archive_sha256: *archive.sha256(),
        archive_length: archive.len(),
        request,
        target_arch,
    };
    PreparationBinding::from_parts(&parts).map_err(|fault| PackageWriteError::InvalidPreparation {
        reason: PreparationFault::RecordInvalid(fault),
    })
}

/// Reports `resource`'s configured limit as exceeded.
pub(super) fn limit(resource: LimitResource, limits: &ContentLimits) -> PackageWriteError {
    PackageWriteError::Content(ContentError::LimitExceeded {
        resource,
        limit: limits.get(resource),
    })
}

/// Reports the limit a bounded writer refused a byte under.
fn limit_fault(fault: LimitFault) -> PackageWriteError {
    PackageWriteError::Content(ContentError::LimitExceeded {
        resource: fault.resource,
        limit: fault.limit,
    })
}

/// Maps a retention failure at `site`.
pub(super) fn retention(error: RetentionError, site: &RetentionSite<'_>) -> PackageWriteError {
    PackageWriteError::Content(from_retention(error, site))
}

/// Reports a failed read of a finished snapshot, which has no path.
pub(super) fn read_snapshot_error(source: io::Error) -> PackageWriteError {
    PackageWriteError::Content(ContentError::Io {
        operation: IoOperation::ReadSnapshot,
        path: None,
        source,
    })
}

/// An **unsigned** package, **untrusted for installation**: one raw manifest
/// block and one compressed archive block, checked against each other and
/// against the request, awaiting a signature.
///
/// Its existence promises nothing about whether a signer or a trust set will
/// later accept it. Preparation holds no key, reads no trust set, and makes
/// no withdrawal, epoch, signature or trust-floor decision; those are made at
/// finalization, under the trust supplied there.
///
/// The manifest lives in memory, bounded by `RawManifest`, and the archive
/// block in private retained storage; the archive is the only disk storage
/// the package keeps alive, whether [`prepare_package`] or
/// [`reopen_prepared`](super::reopen_prepared) made it. It borrows nothing,
/// is `Send` and `Sync`, and its `Debug` shows only the binding.
///
/// It cannot be built, defaulted, deserialized or copied outside this crate:
///
/// ```compile_fail
/// fn forge(
///     binding: deploy_core::package::PreparationBinding,
/// ) -> deploy_core::package::PreparedPackage {
///     deploy_core::package::PreparedPackage {
///         manifest: todo!(),
///         archive: todo!(),
///         binding,
///         limits: todo!(),
///         scope: todo!(),
///     }
/// }
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::PreparedPackage::default();
/// ```
///
/// ```compile_fail
/// let _: deploy_core::package::PreparedPackage = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// fn copy(
///     prepared: &deploy_core::package::PreparedPackage,
/// ) -> deploy_core::package::PreparedPackage {
///     prepared.clone()
/// }
/// ```
pub struct PreparedPackage {
    manifest: Arc<[u8]>,
    archive: RetainedBytes,
    binding: PreparationBinding,
    limits: ContentLimits,
    /// The operation's private directory and disk budget, held so that
    /// [`persist`](Self::persist) charges the same budget.
    scope: RetentionScope,
}

impl PreparedPackage {
    pub(super) fn new(
        manifest: Arc<[u8]>,
        archive: RetainedBytes,
        binding: PreparationBinding,
        limits: ContentLimits,
        scope: RetentionScope,
    ) -> PreparedPackage {
        PreparedPackage {
            manifest,
            archive,
            binding,
            limits,
            scope,
        }
    }

    /// Returns the raw manifest block exactly as serialized once; it is never
    /// reserialized.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }

    /// Returns the compressed archive block exactly as written.
    #[must_use]
    pub fn archive(&self) -> &RetainedBytes {
        &self.archive
    }

    /// Returns the binding: the data a signing request is correlated by.
    #[must_use]
    pub fn binding(&self) -> &PreparationBinding {
        &self.binding
    }

    /// Returns the retained disk this package keeps alive: the archive block
    /// alone.
    // Finalization accounts for this storage; until that lands only the
    // tests read it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retained_disk_bytes(&self) -> u64 {
        self.archive.len()
    }

    /// Returns the scope, for the budget and staging tests.
    #[cfg(test)]
    pub(crate) fn scope_for_test(&self) -> &RetentionScope {
        &self.scope
    }

    /// Persists the preparation as a new directory at `destination_directory`
    /// holding exactly three 0600 files: `manifest.json` (the raw manifest),
    /// `archive.tar.zst` (the archive block) and `preparation.json` (the
    /// canonical binding record).
    ///
    /// The record and the manifest are first copied into private snapshots
    /// charged to this package's budget, and released when this returns. The
    /// files are written into a fresh 0700 sibling directory, each synced,
    /// then that directory is synced, published without replacing any
    /// existing destination, and the parent synced.
    ///
    /// **The parent must be trusted, and callers must serialize writers to
    /// it**: a concurrently created empty directory at the destination can be
    /// replaced, and there is no cross-process lock. Crossing a job boundary
    /// this way loses the package's standing; only
    /// [`reopen_prepared`](super::reopen_prepared), against an independently
    /// saved binding, makes one again.
    ///
    /// # Errors
    ///
    /// - [`PackageWriteError::Content`] when the record or the manifest cannot
    ///   be snapshotted: [`ContentError::LimitExceeded`] naming
    ///   `PreparationRecord` or `RetainedDisk`, or [`ContentError::Io`] for a
    ///   failure of retained storage.
    /// - [`PackageWriteError::Publication`] carrying exactly what publication
    ///   reports: [`PublicationError::DestinationExists`] for any existing
    ///   entry, which is left untouched;
    ///   [`PublicationError::UnsafeDestinationParent`];
    ///   [`PublicationError::DiskBudgetExceeded`]; [`PublicationError::Io`]
    ///   or [`PublicationError::CopyMismatch`] before the publish point, with
    ///   the destination absent; and [`PublicationError::PublishDurability`]
    ///   after it, when the complete directory may already be present.
    pub fn persist(&self, destination_directory: &Path) -> Result<(), PackageWriteError> {
        let record_site = RetentionSite {
            read_source: IoOperation::ReadSnapshot,
            source_path: None,
            max_len: self.limits.resource_limit(LimitResource::PreparationRecord),
            staging_parent: None,
        };
        let record = {
            let writer = self
                .scope
                .snapshot_writer()
                .map_err(|error| retention(error, &record_site))?;
            let mut limited = LimitWriter::new(
                writer,
                vec![Ceiling::whole(
                    LimitResource::PreparationRecord,
                    self.limits.get(LimitResource::PreparationRecord),
                )],
            );
            self.binding
                .write_record(&mut limited)
                .map_err(|error| snapshot_write_error(error, &record_site))?;
            limited
                .into_inner()
                .finish()
                .map_err(|error| retention(error, &record_site))?
        };
        let manifest_site = RetentionSite {
            read_source: IoOperation::ReadSnapshot,
            source_path: None,
            max_len: self.limits.resource_limit(LimitResource::RawManifest),
            staging_parent: None,
        };
        let manifest = self
            .scope
            .snapshot_from(
                &mut &self.manifest[..],
                self.limits.get(LimitResource::RawManifest),
            )
            .map_err(|error| retention(error, &manifest_site))?;
        let published = publish_directory(
            &[
                (PublishedFileName::PreparationManifest, &manifest),
                (PublishedFileName::PreparationArchive, &self.archive),
                (PublishedFileName::PreparationRecord, &record),
            ],
            destination_directory,
            &self.scope,
        );
        drop(manifest);
        drop(record);
        published.map_err(PackageWriteError::Publication)
    }
}

/// Maps a failure streaming bytes into a snapshot through a limit.
fn snapshot_write_error(error: io::Error, site: &RetentionSite<'_>) -> PackageWriteError {
    let error = match LimitFault::recover(error) {
        Ok(fault) => return limit_fault(fault),
        Err(error) => error,
    };
    match error.downcast::<RetentionError>() {
        Ok(error) => retention(error, site),
        Err(error) => PackageWriteError::Content(ContentError::Io {
            operation: IoOperation::WriteSnapshot,
            path: None,
            source: error,
        }),
    }
}

impl fmt::Debug for PreparedPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedPackage")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// Why preparing, persisting or reopening a package failed.
#[derive(Debug, thiserror::Error)]
pub enum PackageWriteError {
    /// A content verdict, a resource limit or an I/O failure, exactly as the
    /// full-content verifier names it.
    #[error(transparent)]
    Content(ContentError),

    /// Persisting failed; the publication error verbatim.
    #[error(transparent)]
    Publication(PublicationError),

    /// Deriving the manifest, serializing it, or laying out the archive
    /// block failed: an undeclared image input, an archive path a `tar`
    /// header cannot hold, and so on.
    #[error(transparent)]
    Payload(PayloadError),

    /// The preparation, the request or the architecture disagrees with the
    /// expected binding in `field`, the first differing one in record order.
    #[error("the preparation does not match the expected binding in `{field}`")]
    BindingMismatch {
        /// The first differing field.
        field: BindingField,
    },

    /// A persisted preparation was refused before its content was read.
    #[error("the persisted preparation is invalid: {reason}")]
    InvalidPreparation {
        /// What was wrong with it.
        reason: PreparationFault,
    },
}

/// One of the three files of a persisted preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationFile {
    /// `manifest.json`, the raw manifest block.
    Manifest,
    /// `archive.tar.zst`, the compressed archive block.
    Archive,
    /// `preparation.json`, the binding record.
    Record,
}

impl PreparationFile {
    /// Every file, in the order reopen checks them.
    pub(super) const ALL: [PreparationFile; 3] = [
        PreparationFile::Manifest,
        PreparationFile::Archive,
        PreparationFile::Record,
    ];

    /// Returns the file's name in the preparation directory.
    pub(super) fn name(self) -> &'static str {
        self.published().as_str()
    }

    fn published(self) -> PublishedFileName {
        match self {
            Self::Manifest => PublishedFileName::PreparationManifest,
            Self::Archive => PublishedFileName::PreparationArchive,
            Self::Record => PublishedFileName::PreparationRecord,
        }
    }
}

impl fmt::Display for PreparationFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a preparation directory was refused before any file in it was read.
///
/// Modes are not authentication: these checks stop unrelated users from
/// redirecting the read, and the expected binding, a fresh snapshot and full
/// revalidation establish the content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryFault {
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path has an empty, `.` or `..` segment, or a trailing `/`.
    NotCanonical,
    /// The path is `/`, which has no parent.
    NoParent,
    /// A component of the path is a symbolic link.
    SymlinkComponent,
    /// A component of the path exists but is not a directory.
    NotDirectory,
    /// The directory is group- or other-writable.
    GroupOrOtherWritable,
    /// The directory's parent is group- or other-writable without the sticky
    /// bit.
    ParentGroupOrOtherWritable,
}

impl fmt::Display for DirectoryFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAbsolute => "the path is not absolute",
            Self::NotCanonical => "the path is not canonical",
            Self::NoParent => "the path has no parent",
            Self::SymlinkComponent => "a path component is a symbolic link",
            Self::NotDirectory => "a path component is not a directory",
            Self::GroupOrOtherWritable => "the directory is group- or other-writable",
            Self::ParentGroupOrOtherWritable => {
                "the parent directory is group- or other-writable and not sticky"
            }
        })
    }
}

/// Why a persisted preparation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationFault {
    /// The directory could not be trusted.
    UnsafeDirectory {
        /// Why.
        reason: DirectoryFault,
    },
    /// A file is a symbolic link.
    Symlink {
        /// The file.
        file: PreparationFile,
    },
    /// A file is neither a regular file nor a symbolic link.
    NotRegularFile {
        /// The file.
        file: PreparationFile,
    },
    /// A file is group- or other-writable.
    GroupOrOtherWritable {
        /// The file.
        file: PreparationFile,
    },
    /// The directory holds an entry other than the three files.
    ExtraMember,
    /// One of the three files is absent.
    MissingMember {
        /// The first absent file, in file order.
        file: PreparationFile,
    },
    /// A file opened is not the one inspected, or is no longer regular.
    IdentityChanged {
        /// The file.
        file: PreparationFile,
    },
    /// The record was refused.
    RecordInvalid(RecordFault),
}

impl fmt::Display for PreparationFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeDirectory { reason } => {
                write!(f, "the preparation directory is not trusted: {reason}")
            }
            Self::Symlink { file } => write!(f, "{file} is a symbolic link"),
            Self::NotRegularFile { file } => write!(f, "{file} is not a regular file"),
            Self::GroupOrOtherWritable { file } => {
                write!(f, "{file} is group- or other-writable")
            }
            Self::ExtraMember => f.write_str("the preparation directory holds an extra entry"),
            Self::MissingMember { file } => write!(f, "{file} is missing"),
            Self::IdentityChanged { file } => write!(f, "{file} changed while it was opened"),
            Self::RecordInvalid(fault) => write!(f, "the preparation record is invalid: {fault}"),
        }
    }
}
