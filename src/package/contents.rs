//! [`verify_contents`], the evidence it returns, and the crate-private pieces
//! it is composed of.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use super::source::{RetainedIoFault, RetainedSource, SourceRole};
use super::{ContentLimits, LimitResource, PublicationError, PublishedPackage, RetainedBytes};
use crate::content::Budget;
use crate::image::{
    ImageArchiveFault, ImageDeclaration, ValidatedImageArchive, validate_image_archive,
};
use crate::manifest::{ArtifactKind, PayloadArtifact, PayloadManifest, TargetArch};
use crate::payload::{
    ContainerBounds, MemberSink, OuterLimits, PayloadError, SinkFault, WalkError, to_hex,
    walk_outer,
};
use crate::retain::{RetentionError, RetentionOperation, RetentionScope, publish_file};
use crate::verify::{
    BoundedVerifyError, ImageVerifyError, TrustSet, VerifyError, VerifyRequest,
    verify_package_bounded,
};

#[cfg(test)]
mod tests;

/// Verifies the package in `source` in full and returns immutable evidence of
/// what it holds.
///
/// `source` is sought to its start and copied exactly once into private
/// retained storage under `staging_parent`; nothing after that reads `source`
/// again, so changing, replacing or deleting the original — or writing through
/// a descriptor kept open on it — cannot affect the result. A caller that
/// wants to keep its reader passes `&mut reader`. The copy is then
/// authenticated by the same pipeline as
/// [`verify_package`](crate::verify::verify_package), every artifact is
/// required to be built for `target_arch`, legacy undeclared images are
/// refused, the whole outer archive is extracted and checked into private
/// snapshots, and only then is each image archive held to its signed
/// declaration, in manifest order. `limits` bounds every step; see the
/// [module documentation](super) for the order and the threat boundary.
///
/// The call is synchronous and blocking. The returned value owns its
/// snapshots and borrows nothing from any argument.
///
/// # Errors
///
/// The first failure in pipeline order:
///
/// - [`ContentError::Io`] with [`IoOperation::InspectStagingParent`] when
///   `staging_parent` is missing, not a directory, or refused by the directory
///   trust policy — kind `InvalidInput` or `PermissionDenied` for a policy
///   refusal — and [`IoOperation::CreateStaging`] when the private directory
///   cannot be created in it.
/// - [`ContentError::Io`] with [`IoOperation::SourceSeek`] or
///   [`IoOperation::SourceRead`] when `source` fails, and
///   [`ContentError::LimitExceeded`] naming `Package` when it is longer than
///   that limit.
/// - [`ContentError::LimitExceeded`] naming `RawManifest` or
///   `CompressedArchive` when the footer advertises a block longer than that
///   limit, decided before the block is read and before the signature.
/// - [`ContentError::Verify`] carrying exactly the verdict
///   [`verify_package`](crate::verify::verify_package) gives the same bytes.
/// - [`ContentError::ArchitectureMismatch`] for the first artifact, in
///   manifest order, not built for `target_arch`.
/// - [`ContentError::Verify`] carrying
///   [`ImageVerifyError::LegacyImageEvidence`] for the first container image
///   without a declaration, which only an admitted legacy manifest can carry.
/// - [`ContentError::Verify`] carrying
///   [`VerifyError::ManifestHashMismatch`] or [`VerifyError::Payload`] for the
///   first rule the outer archive breaks, and
///   [`ContentError::LimitExceeded`] naming `ZstdWindow`, `OuterMembers` or
///   `OuterUncompressedTotal` for a limit it passes — every member and the
///   archive's end checked before any image.
/// - [`ContentError::Verify`] carrying [`VerifyError::Image`], or
///   [`ContentError::LimitExceeded`] naming an image resource, for the first
///   image archive, in manifest order, that disagrees with its declaration.
/// - [`ContentError::LimitExceeded`] naming `RetainedDisk` whenever a
///   snapshot would take the operation past that limit, and
///   [`ContentError::Io`] with [`IoOperation::CreateStaging`],
///   [`IoOperation::WriteSnapshot`] or [`IoOperation::ReadSnapshot`] when
///   retained storage fails — a full filesystem included, which is never
///   reported as the budget.
pub fn verify_contents<R: Read + Seek>(
    mut source: R,
    trust: &TrustSet,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<VerifiedContents, ContentError> {
    // `CopyBuffer` is never zero; the fallback only keeps that invariant out
    // of a panic.
    let copy_buffer = NonZeroUsize::new(limits.copy_buffer_len()).unwrap_or(NonZeroUsize::MIN);
    let scope = RetentionScope::new(
        staging_parent,
        limits.get(LimitResource::RetainedDisk),
        copy_buffer,
    )
    .map_err(|error| {
        from_retention(
            error,
            &RetentionSite {
                read_source: IoOperation::SourceRead,
                max_len: limits.resource_limit(LimitResource::Package),
                staging_parent: Some(staging_parent),
            },
        )
    })?;

    source
        .seek(SeekFrom::Start(0))
        .map_err(|source| ContentError::Io {
            operation: IoOperation::SourceSeek,
            path: None,
            source,
        })?;
    let package = scope
        .snapshot_from(&mut source, limits.get(LimitResource::Package))
        .map_err(|error| {
            from_retention(
                error,
                &RetentionSite {
                    read_source: IoOperation::SourceRead,
                    max_len: limits.resource_limit(LimitResource::Package),
                    staging_parent: None,
                },
            )
        })?;
    drop(source);

    verify_retained(scope, package, trust, request, target_arch, limits)
}

/// Runs everything [`verify_contents`] does after its snapshot over
/// `package`, an already-retained container, inside the caller's `scope`.
///
/// Every snapshot made here — the archive-block copy, each member — is charged
/// to `scope`'s budget, and the returned evidence takes ownership of `scope`.
/// The archive-block copy is dropped once [`check_contents`] returns.
///
/// # Errors
///
/// As [`verify_contents`], from bounded authentication onwards.
pub(crate) fn verify_retained(
    scope: RetentionScope,
    package: RetainedBytes,
    trust: &TrustSet,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
) -> Result<VerifiedContents, ContentError> {
    let bounds = ContainerBounds {
        max_manifest_len: limits.get(LimitResource::RawManifest),
        max_archive_len: limits.get(LimitResource::CompressedArchive),
    };
    let verified = verify_package_bounded(
        RetainedSource::new(package.reader(), SourceRole::Package),
        trust,
        request,
        bounds,
    )
    .map_err(ContentError::from_bounded)?;

    let archive = {
        let mut reader = RetainedSource::new(package.reader(), SourceRole::ArchiveCopy);
        reader
            .seek(SeekFrom::Start(verified.archive_offset))
            .map_err(read_snapshot)?;
        let mut block = reader.take(verified.archive_len);
        let archive = scope
            .snapshot_from(&mut block, verified.archive_len)
            .map_err(|error| {
                from_retention(
                    error,
                    &RetentionSite {
                        read_source: IoOperation::ReadSnapshot,
                        max_len: limits.resource_limit(LimitResource::CompressedArchive),
                        staging_parent: None,
                    },
                )
            })?;
        if archive.len() != verified.archive_len {
            return Err(read_snapshot(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the retained package ended inside its archive block",
            )));
        }
        archive
    };

    let checked = check_contents(&verified.manifest, &archive, target_arch, limits, &scope)?;
    drop(archive);
    Ok(VerifiedContents::new(
        scope,
        package,
        verified.manifest,
        checked,
    ))
}

/// The unsigned-content core: steps 3 to 6 of [`verify_contents`] over an
/// already-retained compressed archive block, with every snapshot charged to
/// `scope`.
///
/// It decides nothing about a signature, a trust floor, withdrawal or an
/// epoch, and runs none of the statement checks: a caller that needs those
/// runs them first.
///
/// # Errors
///
/// [`ContentError::LimitExceeded`] naming `CompressedArchive` for an `archive`
/// longer than that limit, before any of it is read; then as
/// [`verify_contents`] from the architecture check onwards.
pub(crate) fn check_contents(
    manifest: &PayloadManifest,
    archive: &RetainedBytes,
    target_arch: TargetArch,
    limits: &ContentLimits,
    scope: &RetentionScope,
) -> Result<CheckedContents, ContentError> {
    let compressed = limits.get(LimitResource::CompressedArchive);
    if archive.len() > compressed {
        return Err(ContentError::LimitExceeded {
            resource: LimitResource::CompressedArchive,
            limit: compressed,
        });
    }

    // 3. The requested architecture, never inferred from the host.
    if let Some(artifact) = manifest
        .artifacts()
        .iter()
        .find(|artifact| artifact.target_arch != target_arch)
    {
        return Err(ContentError::ArchitectureMismatch {
            archive_path: artifact.archive_path.clone(),
            expected: target_arch,
            actual: artifact.target_arch,
        });
    }

    // 4. A container image with no declaration can only come from an admitted
    //    legacy manifest, and no evidence can be made for it. It is refused,
    //    never reported as no images.
    if let Some(artifact) = manifest
        .artifacts()
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::ContainerImage && artifact.image.is_none())
    {
        return Err(ContentError::Verify(VerifyError::Image(
            ImageVerifyError::LegacyImageEvidence {
                archive_path: artifact.archive_path.clone(),
            },
        )));
    }

    // 5. Every member and the archive's end, before any image.
    let members = extract_members(manifest, archive, limits, scope)?;

    // 6. Each image against its declaration, one at a time, in manifest order.
    #[cfg(test)]
    super::source::seam::before_images(scope.private_path());
    let mut operation_decoded =
        Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
    let mut images = Vec::new();
    for (index, (artifact, bytes)) in manifest.artifacts().iter().zip(&members).enumerate() {
        let Some(declaration) = artifact.image.as_ref() else {
            continue;
        };
        let summary = validate_image_archive(
            RetainedSource::new(bytes.reader(), SourceRole::Image),
            declaration,
            &artifact.archive_path,
            limits,
            &mut operation_decoded,
        )
        .map_err(|fault| match fault {
            ImageArchiveFault::Image(error) => ContentError::Verify(VerifyError::Image(error)),
            ImageArchiveFault::LimitExceeded { resource, limit } => {
                ContentError::LimitExceeded { resource, limit }
            }
            ImageArchiveFault::Io(error) => read_snapshot(error),
        })?;
        images.push(CheckedImage { index, summary });
    }

    Ok(CheckedContents { members, images })
}

/// What [`check_contents`] found: every artifact's retained bytes, in manifest
/// order, and a summary of each image. Dropping it releases the snapshots and
/// their budget charge.
#[derive(Debug)]
pub(crate) struct CheckedContents {
    members: Vec<RetainedBytes>,
    images: Vec<CheckedImage>,
}

#[derive(Debug)]
struct CheckedImage {
    /// The image artifact's position in the manifest.
    index: usize,
    // Kept for the preparation and finalization work that reports it; the
    // evidence exposes the declaration it was held against instead.
    #[allow(dead_code)]
    summary: ValidatedImageArchive,
}

/// Step 5: walks the outer archive in `archive` through the shared walker,
/// retaining each member, and returns the snapshots in manifest order.
fn extract_members(
    manifest: &PayloadManifest,
    archive: &RetainedBytes,
    limits: &ContentLimits,
    scope: &RetentionScope,
) -> Result<Vec<RetainedBytes>, ContentError> {
    let outer = OuterLimits {
        members: limits.get(LimitResource::OuterMembers),
        uncompressed_total: limits.get(LimitResource::OuterUncompressedTotal),
        zstd_window: limits.get(LimitResource::ZstdWindow),
        copy_buffer: limits.copy_buffer_len(),
    };
    let mut source = RetainedSource::new(archive.reader(), SourceRole::Archive);
    source.seek(SeekFrom::Start(0)).map_err(read_snapshot)?;
    let mut sink = RetainingSink {
        scope,
        max_len: outer.uncompressed_total,
        pending: None,
        retained: HashMap::new(),
    };
    walk_outer(source, manifest, Some(&outer), &mut sink).map_err(|error| match error {
        WalkError::Payload(error) => from_payload(error),
        WalkError::Limit { resource, limit } => ContentError::LimitExceeded { resource, limit },
        WalkError::Sink(error) => from_retention(
            error,
            &RetentionSite {
                read_source: IoOperation::ReadSnapshot,
                max_len: limits.resource_limit(LimitResource::OuterUncompressedTotal),
                staging_parent: None,
            },
        ),
    })?;
    let mut retained = sink.retained;
    manifest
        .artifacts()
        .iter()
        .map(|artifact| {
            // The walk refuses an archive missing any artifact, so every one
            // is here; reported as that refusal rather than trusted to a
            // panic.
            retained
                .remove(artifact.archive_path.as_str())
                .ok_or_else(|| {
                    from_payload(PayloadError::ArtifactMissingFromArchive(
                        artifact.archive_path.clone(),
                    ))
                })
        })
        .collect()
}

/// The full-content walk's [`MemberSink`]: each member becomes a finished
/// snapshot as soon as it has been read, so its name is unlinked and its
/// writer closed before the next member starts.
struct RetainingSink<'s, 'm> {
    scope: &'s RetentionScope,
    max_len: u64,
    /// The member received last and not yet accepted.
    pending: Option<(&'m str, RetainedBytes)>,
    retained: HashMap<&'m str, RetainedBytes>,
}

impl<'m> MemberSink<'m> for RetainingSink<'_, 'm> {
    type Error = RetentionError;

    fn receive(
        &mut self,
        artifact: &'m PayloadArtifact,
        _member_path: &str,
        stream: &mut dyn Read,
    ) -> Result<(String, u64), SinkFault<RetentionError>> {
        let bytes =
            self.scope
                .snapshot_from(stream, self.max_len)
                .map_err(|error| match error {
                    RetentionError::Io {
                        operation: RetentionOperation::ReadSource,
                        source,
                        ..
                    } => SinkFault::Stream(source),
                    other => SinkFault::Sink(other),
                })?;
        let digest = to_hex(bytes.sha256());
        let length = bytes.len();
        self.pending = Some((artifact.archive_path.as_str(), bytes));
        Ok((digest, length))
    }

    fn accept(&mut self) -> Result<(), RetentionError> {
        if let Some((path, bytes)) = self.pending.take() {
            self.retained.insert(path, bytes);
        }
        Ok(())
    }
}

/// Maps a container-layer condition met while walking retained storage: a
/// retained-storage failure is [`IoOperation::ReadSnapshot`], recovered by
/// its payload's type, and everything else the verdict the legacy walk gives.
fn from_payload(error: PayloadError) -> ContentError {
    match error {
        PayloadError::Io(error) => match RetainedIoFault::recover(error) {
            Ok(original) => read_snapshot(original),
            Err(error) => ContentError::Verify(VerifyError::from(PayloadError::Io(error))),
        },
        other => ContentError::Verify(VerifyError::from(other)),
    }
}

/// Reports a failed read or seek of an already-retained snapshot, which has no
/// path to name.
fn read_snapshot(error: io::Error) -> ContentError {
    ContentError::Io {
        operation: IoOperation::ReadSnapshot,
        path: None,
        source: RetainedIoFault::unwrap_or_same(error),
    }
}

/// What one retention call site knows that the retention error does not.
struct RetentionSite<'a> {
    /// What a failed read of the snapshot's source is at this site.
    read_source: IoOperation,
    /// The resource and value this site passed as the snapshot's `max_len`.
    max_len: crate::content::ResourceLimit,
    /// The staging parent, at the one site that creates the private directory
    /// in it.
    staging_parent: Option<&'a Path>,
}

/// Maps a retention failure onto a [`ContentError`] under what `site` knows.
fn from_retention(error: RetentionError, site: &RetentionSite<'_>) -> ContentError {
    match error {
        RetentionError::BudgetExceeded { limit } => ContentError::LimitExceeded {
            resource: LimitResource::RetainedDisk,
            limit,
        },
        RetentionError::SourceTooLong { .. } => ContentError::LimitExceeded {
            resource: site.max_len.resource,
            limit: site.max_len.max,
        },
        RetentionError::UnsafeStagingParent { path, reason } => ContentError::Io {
            operation: IoOperation::InspectStagingParent,
            path: Some(path),
            source: io::Error::new(
                reason.io_kind(),
                format!("the staging parent is not trusted: {reason}"),
            ),
        },
        RetentionError::SnapshotMismatch { kind } => ContentError::Io {
            operation: IoOperation::WriteSnapshot,
            path: None,
            source: io::Error::other(format!(
                "the snapshot does not match what was written: {kind}"
            )),
        },
        RetentionError::Io {
            operation,
            path,
            source,
        } => {
            let (operation, path) = match operation {
                RetentionOperation::OpenStagingParent => (IoOperation::InspectStagingParent, path),
                // The entry is the private directory, created in the staging
                // parent, which this site names; a failed name draw already
                // reports that parent.
                RetentionOperation::CreateStagingDirectory => (
                    IoOperation::CreateStaging,
                    site.staging_parent.map(Path::to_path_buf).or(path),
                ),
                // A snapshot is created in the private directory.
                RetentionOperation::CreateSnapshot => (
                    IoOperation::CreateStaging,
                    path.map(|path| path.parent().map_or_else(|| path.clone(), Path::to_path_buf)),
                ),
                RetentionOperation::WriteSnapshot
                | RetentionOperation::ReopenSnapshot
                | RetentionOperation::InspectSnapshot
                | RetentionOperation::UnlinkSnapshot
                // Reached only through `RetentionScope::close`, which nothing
                // here calls: a dropped scope cleans up best-effort and never
                // reports.
                | RetentionOperation::RemoveStagingEntry
                | RetentionOperation::RemoveStagingDirectory => (IoOperation::WriteSnapshot, path),
                RetentionOperation::ReadSource => {
                    return ContentError::Io {
                        operation: site.read_source,
                        path: None,
                        source: RetainedIoFault::unwrap_or_same(source),
                    };
                }
            };
            ContentError::Io {
                operation,
                path,
                source,
            }
        }
    }
}

/// Why [`verify_contents`] refused a package.
#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    /// A verification verdict, exactly as
    /// [`verify_package`](crate::verify::verify_package) names it for the same
    /// bytes — or, past authentication, the outer archive, legacy-image and
    /// image-archive verdicts under their existing names.
    #[error(transparent)]
    Verify(VerifyError),

    /// An artifact is built for another architecture than the one requested.
    #[error(
        "artifact `{archive_path}` is built for {}, not the requested {}",
        arch_label(*.actual),
        arch_label(*.expected)
    )]
    ArchitectureMismatch {
        /// `archive_path` of the first such artifact in manifest order.
        archive_path: String,
        /// The requested architecture.
        expected: TargetArch,
        /// The artifact's architecture.
        actual: TargetArch,
    },

    /// A configured resource limit was reached.
    #[error("the {resource} limit of {limit} was exceeded")]
    LimitExceeded {
        /// The resource.
        resource: LimitResource,
        /// Its configured value.
        limit: u64,
    },

    /// An I/O operation failed.
    ///
    /// `path` is `Some` only for a concrete filesystem target of the failed
    /// operation — the staging parent, the private directory or a snapshot
    /// file — and `None` for the caller's source and for retained snapshots,
    /// which have no path. `source` keeps the underlying error and its kind.
    #[error("{operation} failed{}: {source}", describe_path(.path.as_deref()))]
    Io {
        /// Where the failure happened.
        operation: IoOperation,
        /// The filesystem target involved, when there is one.
        path: Option<PathBuf>,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

impl From<VerifyError> for ContentError {
    /// Wraps a verdict unchanged. Written by hand so no remapping can hide in
    /// a derive.
    fn from(error: VerifyError) -> Self {
        ContentError::Verify(error)
    }
}

impl ContentError {
    /// Maps a bounded authentication failure one-to-one.
    fn from_bounded(error: BoundedVerifyError) -> ContentError {
        match error {
            BoundedVerifyError::Verify(error) => ContentError::Verify(error),
            BoundedVerifyError::LimitExceeded { resource, limit } => {
                ContentError::LimitExceeded { resource, limit }
            }
            BoundedVerifyError::Io(source) => ContentError::Io {
                operation: IoOperation::ReadSnapshot,
                path: None,
                source,
            },
        }
    }
}

fn describe_path(path: Option<&Path>) -> String {
    path.map(|path| format!(" at {}", path.display()))
        .unwrap_or_default()
}

fn arch_label(arch: TargetArch) -> &'static str {
    match arch {
        TargetArch::X86_64 => "x86_64",
        TargetArch::Aarch64 => "aarch64",
    }
}

/// The boundary at which a [`ContentError::Io`] failure happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOperation {
    /// Seeking the caller's source to its start.
    SourceSeek,
    /// Reading the caller's source.
    SourceRead,
    /// Opening or checking the staging parent, including refusing an unsafe
    /// one.
    InspectStagingParent,
    /// Creating the private staging directory or a snapshot file.
    CreateStaging,
    /// Writing, flushing, reopening, inspecting or unlinking a snapshot
    /// before it is finished.
    WriteSnapshot,
    /// Reading or seeking an already-retained snapshot.
    ReadSnapshot,
}

impl fmt::Display for IoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SourceSeek => "seeking the source",
            Self::SourceRead => "reading the source",
            Self::InspectStagingParent => "inspecting the staging parent",
            Self::CreateStaging => "creating private staging",
            Self::WriteSnapshot => "writing a snapshot",
            Self::ReadSnapshot => "reading a retained snapshot",
        })
    }
}

/// A fully verified package: its authenticated manifest, every artifact's
/// retained bytes, its image evidence, and the exact package bytes.
///
/// It exists only as [`verify_contents`] returns it, after every check has
/// passed. It owns private retained snapshots that nothing outside this
/// library can change, and borrows nothing from the call that made it.
/// Dropping it releases them once no reader borrowed from it is alive.
///
/// It cannot be built or forged outside this crate:
///
/// ```compile_fail
/// fn forge(manifest: deploy_core::manifest::PayloadManifest) -> deploy_core::package::VerifiedContents {
///     deploy_core::package::VerifiedContents { manifest, artifacts: todo!(), images: todo!(), package: todo!(), scope: todo!() }
/// }
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::VerifiedContents::default();
/// ```
///
/// ```compile_fail
/// let _: deploy_core::package::VerifiedContents = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// fn promote<R: std::io::Read + std::io::Seek>(
///     verified: deploy_core::verify::VerifiedPackage<R>,
/// ) -> deploy_core::package::VerifiedContents {
///     verified.into()
/// }
/// ```
///
/// ```compile_fail
/// fn from_path(path: &std::path::Path) -> deploy_core::package::VerifiedContents {
///     deploy_core::package::VerifiedContents::from(path)
/// }
/// ```
///
/// ```compile_fail
/// fn copy(contents: &deploy_core::package::VerifiedContents) -> deploy_core::package::VerifiedContents {
///     contents.clone()
/// }
/// ```
///
/// A reader cannot outlive it:
///
/// ```compile_fail
/// fn detach(
///     contents: deploy_core::package::VerifiedContents,
/// ) -> deploy_core::package::RetainedReader<'static> {
///     contents.package_bytes().reader()
/// }
/// ```
///
/// ```compile_fail
/// use std::io::Read;
/// fn use_after_drop(contents: deploy_core::package::VerifiedContents) {
///     let mut reader = contents.package_bytes().reader();
///     drop(contents);
///     let _ = reader.read(&mut [0u8; 1]);
/// }
/// ```
///
/// and it offers no file, path or descriptor:
///
/// ```compile_fail
/// use std::os::fd::AsRawFd;
/// fn fd(contents: &deploy_core::package::VerifiedContents) -> i32 {
///     contents.as_raw_fd()
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::AsFd;
/// fn fd(contents: &deploy_core::package::VerifiedContents) {
///     let _ = contents.package_bytes().as_fd();
/// }
/// ```
///
/// ```compile_fail
/// fn path(contents: &deploy_core::package::VerifiedContents) -> &std::path::Path {
///     contents.path()
/// }
/// ```
///
/// ```compile_fail
/// fn file(contents: deploy_core::package::VerifiedContents) -> std::fs::File {
///     contents.into_inner()
/// }
/// ```
pub struct VerifiedContents {
    manifest: PayloadManifest,
    artifacts: Vec<VerifiedArtifact>,
    images: Vec<VerifiedImage>,
    package: RetainedBytes,
    /// The operation's private directory and disk budget, held so that
    /// [`publish_package`](Self::publish_package) charges the same budget.
    scope: RetentionScope,
}

impl VerifiedContents {
    fn new(
        scope: RetentionScope,
        package: RetainedBytes,
        manifest: PayloadManifest,
        checked: CheckedContents,
    ) -> VerifiedContents {
        let CheckedContents { members, images } = checked;
        let images = images
            .iter()
            .filter_map(|image| {
                let artifact = manifest.artifacts().get(image.index)?;
                let declaration = artifact.image.clone()?;
                let archive = members.get(image.index)?.share();
                Some(VerifiedImage {
                    artifact: artifact.clone(),
                    declaration,
                    archive,
                })
            })
            .collect();
        let artifacts = manifest
            .artifacts()
            .iter()
            .zip(members)
            .map(|(artifact, bytes)| VerifiedArtifact {
                artifact: artifact.clone(),
                bytes,
            })
            .collect();
        VerifiedContents {
            manifest,
            artifacts,
            images,
            package,
            scope,
        }
    }

    /// Returns the authenticated manifest.
    #[must_use]
    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }

    /// Returns every artifact with its retained bytes, in manifest order and
    /// of every kind.
    #[must_use]
    pub fn artifacts(&self) -> &[VerifiedArtifact] {
        &self.artifacts
    }

    /// Returns the image evidence: [`VerifiedImages::None`] when the manifest
    /// has no container image artifact, and otherwise every image in manifest
    /// order.
    #[must_use]
    pub fn images(&self) -> VerifiedImages<'_> {
        if self.images.is_empty() {
            VerifiedImages::None
        } else {
            VerifiedImages::Present(VerifiedImageSet {
                images: &self.images,
            })
        }
    }

    /// Returns the exact bytes of the package that was verified.
    #[must_use]
    pub fn package_bytes(&self) -> &RetainedBytes {
        &self.package
    }

    /// Publishes [`package_bytes`](Self::package_bytes) as a new file at
    /// `destination`, never replacing an existing entry.
    ///
    /// The temporary copy is charged to the same retained-disk budget the
    /// verification used. The receipt describes what was written; the
    /// published file is an ordinary path and not evidence.
    ///
    /// # Errors
    ///
    /// - [`PublicationError::DestinationExists`] when any entry is at
    ///   `destination`, which is left untouched.
    /// - [`PublicationError::UnsafeDestinationParent`] when `destination` or
    ///   its parent is refused by the directory trust policy.
    /// - [`PublicationError::DiskBudgetExceeded`] when the temporary copy
    ///   would exceed what is left of the budget.
    /// - [`PublicationError::Io`] or [`PublicationError::CopyMismatch`] for a
    ///   failure before the publish point, with the destination absent.
    /// - [`PublicationError::PublishDurability`] for a failure after it,
    ///   when the complete file may already be at `destination`.
    pub fn publish_package(
        &self,
        destination: &Path,
    ) -> Result<PublishedPackage, PublicationError> {
        publish_file(&self.package, destination, &self.scope)
    }

    /// Returns the scope, for the budget and staging tests.
    #[cfg(test)]
    pub(crate) fn scope_for_test(&self) -> &RetentionScope {
        &self.scope
    }
}

impl fmt::Debug for VerifiedContents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedContents")
            .field("package", &self.package)
            .field("artifacts", &self.artifacts)
            .field("images", &self.images)
            .finish_non_exhaustive()
    }
}

/// One artifact of a [`VerifiedContents`] with its retained bytes: every
/// kind, native and Compose included. It is not image evidence.
///
/// ```compile_fail
/// fn from_extracted(
///     extracted: deploy_core::payload::ExtractedArtifact,
/// ) -> deploy_core::package::VerifiedArtifact {
///     extracted.into()
/// }
/// ```
///
/// ```compile_fail
/// fn forge(artifact: deploy_core::manifest::PayloadArtifact) -> deploy_core::package::VerifiedArtifact {
///     deploy_core::package::VerifiedArtifact { artifact, bytes: todo!() }
/// }
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::VerifiedArtifact::default();
/// ```
///
/// ```compile_fail
/// fn copy(artifact: &deploy_core::package::VerifiedArtifact) -> deploy_core::package::VerifiedArtifact {
///     artifact.clone()
/// }
/// ```
///
/// ```compile_fail
/// let _: deploy_core::package::VerifiedArtifact = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// fn from_hash(sha256: [u8; 32]) -> deploy_core::package::VerifiedArtifact {
///     deploy_core::package::VerifiedArtifact::from(sha256)
/// }
/// ```
pub struct VerifiedArtifact {
    artifact: PayloadArtifact,
    bytes: RetainedBytes,
}

impl VerifiedArtifact {
    /// Returns the artifact's manifest entry.
    #[must_use]
    pub fn artifact(&self) -> &PayloadArtifact {
        &self.artifact
    }

    /// Returns the length of the member the outer archive held for it: the
    /// bytes read, hashed and retained.
    #[must_use]
    pub fn member_length(&self) -> u64 {
        self.bytes.len()
    }

    /// Returns the artifact's retained bytes.
    #[must_use]
    pub fn bytes(&self) -> &RetainedBytes {
        &self.bytes
    }
}

impl fmt::Debug for VerifiedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedArtifact")
            .field("archive_path", &self.artifact.archive_path)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// The image evidence of a [`VerifiedContents`].
#[derive(Debug)]
pub enum VerifiedImages<'a> {
    /// The manifest has no container image artifact.
    None,
    /// Every container image artifact, each held to its signed declaration.
    Present(VerifiedImageSet<'a>),
}

/// The verified images of a package: never empty, in manifest order.
///
/// It has no public constructor and cannot be emptied:
///
/// ```compile_fail
/// let _ = deploy_core::package::VerifiedImages::Present(
///     deploy_core::package::VerifiedImageSet { images: &[] },
/// );
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::VerifiedImageSet::default();
/// ```
///
/// ```compile_fail
/// fn empty(set: &mut deploy_core::package::VerifiedImageSet<'_>) {
///     set.clear();
/// }
/// ```
pub struct VerifiedImageSet<'a> {
    images: &'a [VerifiedImage],
}

impl<'a> VerifiedImageSet<'a> {
    /// Returns how many images there are, never zero.
    // The set is never empty by construction, so an `is_empty` beside this
    // would be a question with one answer.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Returns the images, in manifest order.
    pub fn iter(&self) -> impl Iterator<Item = &'a VerifiedImage> + use<'a> {
        self.images.iter()
    }
}

impl fmt::Debug for VerifiedImageSet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.images).finish()
    }
}

/// One container image, held to its signed declaration.
///
/// ```compile_fail
/// fn forge(declaration: deploy_core::image::ImageDeclaration) -> deploy_core::package::VerifiedImage {
///     deploy_core::package::VerifiedImage { declaration, artifact: todo!(), archive: todo!() }
/// }
/// ```
///
/// ```compile_fail
/// fn copy(image: &deploy_core::package::VerifiedImage) -> deploy_core::package::VerifiedImage {
///     image.clone()
/// }
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::VerifiedImage::default();
/// ```
pub struct VerifiedImage {
    artifact: PayloadArtifact,
    declaration: ImageDeclaration,
    archive: RetainedBytes,
}

impl VerifiedImage {
    /// Returns the signed declaration the image archive was held to.
    #[must_use]
    pub fn declaration(&self) -> &ImageDeclaration {
        &self.declaration
    }

    /// Returns the length of the image archive member.
    #[must_use]
    pub fn member_length(&self) -> u64 {
        self.archive.len()
    }

    /// Returns the image archive's retained bytes: the same snapshot as its
    /// artifact's [`VerifiedArtifact::bytes`].
    #[must_use]
    pub fn archive(&self) -> &RetainedBytes {
        &self.archive
    }

    /// Returns the image artifact's manifest entry.
    #[must_use]
    pub fn artifact(&self) -> &PayloadArtifact {
        &self.artifact
    }
}

impl fmt::Debug for VerifiedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedImage")
            .field("archive_path", &self.artifact.archive_path)
            .field("config_digest", &self.declaration.config_digest)
            .field("archive", &self.archive)
            .finish()
    }
}
