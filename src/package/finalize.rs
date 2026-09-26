//! Detached finalization: [`finalize_package`], the [`FinalizedPackage`] it
//! returns, and the [`prepare_sign_finalize`] composition consumers build
//! signed fixtures with.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::binding::PreparationBinding;
use super::bounded::{Ceiling, LimitWriter};
use super::contents::{RetentionSite, read_snapshot, verify_retained};
use super::prepare::{
    PackageWriteError, PreparedPackage, limit, prepare_package, retention, scope_with_budget,
    snapshot_write_error,
};
use super::source::{RetainedSource, SourceRole};
use super::{
    BindingField, ContentError, ContentLimits, IoOperation, LimitResource, PublicationError,
    PublishedPackage, RetainedBytes, VerifiedContents,
};
use crate::manifest::TargetArch;
use crate::payload::{
    ArtifactInput, PayloadError, Signed, SignerError, validate_signed, write_standalone_tail,
};
use crate::retain::RetentionScope;
use crate::verify::{TrustSet, VerifyRequest};

#[cfg(test)]
mod tests;

/// Finalizes a prepared package with a detached signature: assembles the
/// signed standalone container from exactly the prepared manifest block (M),
/// the prepared archive block (A), `signed` and the current footer, and runs
/// the full [`verify_contents`](super::verify_contents) pipeline over it.
///
/// This holds no key, signs nothing, and takes no source path: the container
/// is built only from what `prepared` retained. M is never reserialized and A
/// is never recompressed. `signed` must be a signature over **raw M** — not
/// over its digest or any reserialization — as an independently authorized
/// signer returned it.
///
/// The steps run in this order, and the first failure is the result:
///
/// 1. **binding** — `prepared.binding()` is compared with `expected_binding`
///    field by field in [`BindingField`] order, then `expected_binding` with
///    `request` and `target_arch`;
/// 2. **rehash** — the SHA-256 and length of M and of A, streamed from the
///    retained copy, are recomputed and compared with `expected_binding`;
/// 3. **framing** — `signed` must be a 64-byte signature and a 64-character
///    lowercase-hex key ID, checked before any storage is created;
/// 4. **budget** — a fresh private scope is created under `staging_parent`,
///    its disk budget the configured `RetainedDisk` less the storage
///    `prepared` still keeps alive;
/// 5. **assembly** — M, then A block by block, then the signature, the key ID
///    and a footer with `manifest_offset` 0, are written into one private
///    snapshot bounded by `Package`;
/// 6. **verification** — that snapshot goes through every step
///    [`verify_contents`](super::verify_contents) runs after its own
///    snapshot, under `trust`, `request` and `target_arch`, with each verdict
///    and its precedence unchanged.
///
/// # Signer correlation and trust
///
/// [`Signed`] carries only a signature and a key ID. Correlating the signer's
/// response with the request it answers — its request ID, run and attempt,
/// record hash — is the caller's job, done before this call; nothing here
/// verifies workflow provenance or reads response metadata as trust.
///
/// The signature is verified exactly as
/// [`verify_package`](crate::verify::verify_package) verifies it: a usable
/// key-ID hint only chooses which non-revoked anchor is tried first, every
/// other non-revoked anchor is tried after it, so the hint can never deny a
/// valid signature, and a key ID alone never confers trust. A caller that
/// needs one exact signer supplies a `trust` holding only that key's anchor.
///
/// Nothing earlier lets a check be skipped: not the preparation's own
/// validation, not the signer's response, not a matching digest.
///
/// # Disk accounting
///
/// The configured `RetainedDisk` bounds everything the operation keeps live at
/// once. While this runs, `prepared` still holds A, so finalization's own
/// scope gets only what is left of the limit once that storage is counted.
/// The assembled container, the verification snapshots and any later
/// publication copy are all charged to that scope, which the returned
/// [`FinalizedPackage`] keeps.
///
/// # Cleanup
///
/// On failure no handle exists, and every snapshot and directory this call
/// created is removed. `prepared` is only borrowed: its storage is never
/// touched, whatever the outcome, and it can be finalized again.
///
/// # Errors
///
/// The first failure, in step order:
///
/// - [`PackageWriteError::BindingMismatch`] naming the first field, in record
///   order, in which `prepared` disagrees with `expected_binding`, then the
///   first in which `expected_binding` disagrees with `request` or
///   `target_arch`, then `ManifestSha256`, `ManifestLength`, `ArchiveSha256`
///   or `ArchiveLength` for retained bytes that do not rehash to it.
/// - [`PackageWriteError::Payload`] carrying
///   [`PayloadError::InvalidSignatureLength`] or [`PayloadError::InvalidKeyId`]
///   for `signed` framing the container cannot carry, before any storage is
///   created.
/// - [`ContentError::LimitExceeded`] naming `RetainedDisk`, with the
///   configured value, when `prepared` alone already holds more than the
///   limit, before any storage is created — and whenever a snapshot would
///   take the operation past it.
/// - [`ContentError::Io`] with [`IoOperation::InspectStagingParent`] or
///   [`IoOperation::CreateStaging`] when the private scope cannot be created
///   under `staging_parent`.
/// - [`ContentError::LimitExceeded`] naming `Package` for a container longer
///   than that, and [`ContentError::Io`] with [`IoOperation::WriteSnapshot`]
///   or [`IoOperation::ReadSnapshot`] when retained storage fails during
///   assembly, a full filesystem included.
/// - Every verdict [`verify_contents`](super::verify_contents) gives the
///   same container from bounded authentication onwards, as
///   [`PackageWriteError::Content`]: a signature over anything but M is
///   [`VerifyError::BadSignature`](crate::verify::VerifyError::BadSignature),
///   and a key outside `trust`, a revoked key, a withdrawn build, a trust
///   floor above the manifest format and a stale trust epoch are the
///   existing [`VerifyError`](crate::verify::VerifyError) variants.
// The signature is the one the finalization contract fixes: the prepared
// package, the expectation, the signer's response, and the same trust,
// request, architecture, limits and staging parent every full-content call
// takes. Grouping them into a struct would only restate that list.
#[allow(clippy::too_many_arguments)]
pub fn finalize_package(
    prepared: &PreparedPackage,
    expected_binding: &PreparationBinding,
    signed: &Signed,
    trust: &TrustSet,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<FinalizedPackage, PackageWriteError> {
    // 1. The binding, the request and the architecture.
    if let Some(field) = prepared.binding().first_difference(expected_binding) {
        return Err(PackageWriteError::BindingMismatch { field });
    }
    if let Some(field) = expected_binding.request_difference(request, target_arch) {
        return Err(PackageWriteError::BindingMismatch { field });
    }

    // 2. Rehash what is actually retained.
    rehash(prepared, expected_binding, limits)?;

    // 3. Framing, before any storage exists.
    validate_signed(signed).map_err(PackageWriteError::Payload)?;

    // 4. What the configured limit leaves beside the prepared storage.
    let configured = limits.get(LimitResource::RetainedDisk);
    let Some(budget) = configured.checked_sub(prepared.retained_disk_bytes()) else {
        return Err(limit(LimitResource::RetainedDisk, limits));
    };
    let scope = scope_with_budget(limits, budget, staging_parent)?;

    // 5. Assemble M ‖ A ‖ signature ‖ key ID ‖ footer.
    let container = assemble(&scope, prepared, expected_binding, signed, limits)
        .map_err(|error| configured_disk(error, configured))?;
    #[cfg(test)]
    let container = seam::after_assembly(&scope, container)?;

    // 6. The full pipeline, which takes ownership of the scope.
    let contents = verify_retained(scope, container, trust, request, target_arch, limits)
        .map_err(|error| configured_disk(PackageWriteError::Content(error), configured))?;

    Ok(FinalizedPackage {
        contents,
        binding: expected_binding.clone(),
        retained_disk: configured,
    })
}

/// Prepares, signs and finalizes a package in one call: exactly
/// [`prepare_package`], then `sign` over the raw manifest block, then
/// [`finalize_package`] with the preparation's own binding.
///
/// It validates identically to those three calls made separately — the
/// preparation's checks, then every finalization check including the full
/// verification pipeline under `trust` — and returns byte-identical output.
/// There is no unsigned shortcut, no default key and no trust bypass: `trust`
/// must anchor the key `sign` signs with. `sign` receives the raw manifest
/// bytes, the convention
/// [`append_trailer_signed`](crate::payload::append_trailer_signed) uses. The
/// prepared package stays alive until finalization returns, so the disk
/// accounting is exactly that of the three-step composition, and it is
/// released before this returns.
///
/// # Signed fixtures
///
/// This is the complete API for constructing genuinely signed format-6
/// packages in a consumer's tests: with a test key minted per test and a
/// `TrustSet` anchoring only it, and — under the `test-support` feature, in
/// `[dev-dependencies]` only — real image archives from
/// `image::test_support::SyntheticImageArchiveBuilder`, the result passes
/// every final check a production package does. Production signing is
/// detached instead: [`prepare_package`] in one job, the signer in another,
/// and [`finalize_package`] after the caller has correlated the signer's
/// response.
///
/// A fixture that tags an image with its canonical runtime alias builds it
/// config first, tags last: create the builder and add every layer, read
/// `config_digest()`, derive the alias with
/// [`canonical_runtime_alias`](crate::image::canonical_runtime_alias), and
/// only then pass the alias and any other tags to `finish`. The config never
/// depends on the tags, so the finished archive's config digest is the one
/// the alias was derived from.
///
/// # Errors
///
/// Whatever [`prepare_package`] returns, unchanged, and then `sign` is never
/// called; [`PackageWriteError::Signer`] carrying the callback's error; and
/// then whatever [`finalize_package`] returns, unchanged.
// The preparation's arguments, the finalization's trust, and the signer: the
// composition takes exactly the union of what its three steps take.
#[allow(clippy::too_many_arguments)]
pub fn prepare_sign_finalize<F>(
    inputs: &[ArtifactInput],
    pinset: Option<&str>,
    trust_set_bytes: Option<&[u8]>,
    request: &VerifyRequest,
    target_arch: TargetArch,
    limits: &ContentLimits,
    staging_parent: &Path,
    trust: &TrustSet,
    sign: F,
) -> Result<FinalizedPackage, PackageWriteError>
where
    F: FnOnce(&[u8]) -> Result<Signed, SignerError>,
{
    let prepared = prepare_package(
        inputs,
        pinset,
        trust_set_bytes,
        request,
        target_arch,
        limits,
        staging_parent,
    )?;
    let signed = sign(prepared.manifest_bytes()).map_err(PackageWriteError::Signer)?;
    let finalized = finalize_package(
        &prepared,
        prepared.binding(),
        &signed,
        trust,
        request,
        target_arch,
        limits,
        staging_parent,
    );
    drop(prepared);
    finalized
}

/// Step 2: recomputes M's and A's digests and lengths from the retained
/// bytes and compares them with `expected`, in record order.
fn rehash(
    prepared: &PreparedPackage,
    expected: &PreparationBinding,
    limits: &ContentLimits,
) -> Result<(), PackageWriteError> {
    let manifest = prepared.manifest_bytes();
    let manifest_sha256: [u8; 32] = Sha256::digest(manifest).into();
    let manifest_length = u64::try_from(manifest.len()).unwrap_or(u64::MAX);
    compare(
        (&manifest_sha256, manifest_length),
        expected.manifest_sha256(),
        expected.manifest_length(),
        [BindingField::ManifestSha256, BindingField::ManifestLength],
    )?;

    let mut hasher = Sha256::new();
    let archive_length = for_each_block(prepared.archive(), limits, |block| {
        hasher.update(block);
        Ok(())
    })?;
    let archive_sha256: [u8; 32] = hasher.finalize().into();
    compare(
        (&archive_sha256, archive_length),
        expected.archive_sha256(),
        expected.archive_length(),
        [BindingField::ArchiveSha256, BindingField::ArchiveLength],
    )
}

fn compare(
    (sha256, length): (&[u8; 32], u64),
    expected_sha256: &[u8; 32],
    expected_length: u64,
    [digest_field, length_field]: [BindingField; 2],
) -> Result<(), PackageWriteError> {
    if sha256 != expected_sha256 {
        return Err(PackageWriteError::BindingMismatch {
            field: digest_field,
        });
    }
    if length != expected_length {
        return Err(PackageWriteError::BindingMismatch {
            field: length_field,
        });
    }
    Ok(())
}

/// Reads `bytes` from its start in `CopyBuffer`-sized blocks, handing each
/// to `each`, and returns how many bytes were read.
fn for_each_block(
    bytes: &RetainedBytes,
    limits: &ContentLimits,
    mut each: impl FnMut(&[u8]) -> Result<(), PackageWriteError>,
) -> Result<u64, PackageWriteError> {
    let mut source = RetainedSource::new(bytes.reader(), SourceRole::Prepared);
    let mut buf = vec![0u8; limits.copy_buffer_len().max(1)];
    let mut total = 0u64;
    loop {
        let read = match source.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(PackageWriteError::Content(read_snapshot(error))),
        };
        let block = buf.get(..read).ok_or_else(|| {
            PackageWriteError::Content(read_snapshot(io::Error::new(
                io::ErrorKind::InvalidData,
                "a retained read reported more bytes than it was asked for",
            )))
        })?;
        each(block)?;
        total = u64::try_from(read)
            .ok()
            .and_then(|read| total.checked_add(read))
            .ok_or_else(|| {
                PackageWriteError::Content(read_snapshot(io::Error::other(
                    "the retained length overflowed",
                )))
            })?;
    }
}

/// Step 5: writes M, A and the tail into one snapshot of `scope`, bounded by
/// `Package`. An unfinished writer is dropped on failure, which unlinks it.
fn assemble(
    scope: &RetentionScope,
    prepared: &PreparedPackage,
    binding: &PreparationBinding,
    signed: &Signed,
    limits: &ContentLimits,
) -> Result<RetainedBytes, PackageWriteError> {
    let site = RetentionSite {
        read_source: IoOperation::ReadSnapshot,
        source_path: None,
        max_len: limits.resource_limit(LimitResource::Package),
        staging_parent: None,
    };
    let writer = scope
        .snapshot_writer()
        .map_err(|error| retention(error, &site))?;
    let mut out = LimitWriter::new(
        writer,
        vec![Ceiling::whole(
            LimitResource::Package,
            limits.get(LimitResource::Package),
        )],
    );

    out.write_all(prepared.manifest_bytes())
        .map_err(|error| snapshot_write_error(error, &site))?;
    let copied = for_each_block(prepared.archive(), limits, |block| {
        out.write_all(block)
            .map_err(|error| snapshot_write_error(error, &site))
    })?;
    // The rehash already held A to this length; a retained copy cannot
    // change, so this is reported as the read failure it would be rather
    // than trusted.
    if copied != binding.archive_length() {
        return Err(PackageWriteError::Content(read_snapshot(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the prepared archive block changed length while it was copied",
        ))));
    }
    write_standalone_tail(
        &mut out,
        0,
        binding.manifest_length(),
        binding.archive_length(),
        Some(signed),
    )
    .map_err(|error| match error {
        PayloadError::Io(error) => snapshot_write_error(error, &site),
        other => PackageWriteError::Payload(other),
    })?;

    out.into_inner()
        .finish()
        .map_err(|error| retention(error, &site))
}

/// Reports a `RetainedDisk` refusal with the configured limit rather than the
/// share of it the finalization scope was given.
fn configured_disk(error: PackageWriteError, configured: u64) -> PackageWriteError {
    match error {
        PackageWriteError::Content(ContentError::LimitExceeded {
            resource: LimitResource::RetainedDisk,
            ..
        }) => PackageWriteError::Content(ContentError::LimitExceeded {
            resource: LimitResource::RetainedDisk,
            limit: configured,
        }),
        other => other,
    }
}

/// A signed standalone package, assembled from a prepared package and a
/// detached signature and then verified in full.
///
/// It exists only as [`finalize_package`] or [`prepare_sign_finalize`]
/// returns it, after every check has passed. It holds the
/// [`VerifiedContents`] that verification produced — the authenticated
/// manifest, every artifact, the image evidence and the canonical container —
/// and a copy of the binding it was finalized against. It borrows nothing, is
/// `Send` and `Sync`, and its private storage is released when it drops.
///
/// Direct installation and store publication both consume this same
/// finalized package, and each consumer rechecks trust and context at its own
/// boundary; a finalized package vouches for nothing it was not verified
/// against. Bytes the low-level [`payload`](crate::payload) writers assemble
/// are not a finalized package, and neither is a published file.
///
/// It cannot be built, defaulted, deserialized or copied outside this crate:
///
/// ```compile_fail
/// fn forge(
///     contents: deploy_core::package::VerifiedContents,
///     binding: deploy_core::package::PreparationBinding,
/// ) -> deploy_core::package::FinalizedPackage {
///     deploy_core::package::FinalizedPackage { contents, binding, retained_disk: 0 }
/// }
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::FinalizedPackage::default();
/// ```
///
/// ```compile_fail
/// let _: deploy_core::package::FinalizedPackage = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// fn copy(
///     finalized: &deploy_core::package::FinalizedPackage,
/// ) -> deploy_core::package::FinalizedPackage {
///     finalized.clone()
/// }
/// ```
///
/// ```compile_fail
/// fn promote(
///     contents: deploy_core::package::VerifiedContents,
/// ) -> deploy_core::package::FinalizedPackage {
///     contents.into()
/// }
/// ```
pub struct FinalizedPackage {
    /// The verification's evidence, which owns the finalization scope.
    contents: VerifiedContents,
    binding: PreparationBinding,
    /// The configured `RetainedDisk`, which a budget refusal reports.
    retained_disk: u64,
}

impl FinalizedPackage {
    /// Returns the verified contents: the authenticated manifest, every
    /// artifact's retained bytes, the image evidence and the canonical
    /// container.
    #[must_use]
    pub fn contents(&self) -> &VerifiedContents {
        &self.contents
    }

    /// Returns exactly the finalized container: the same retained object as
    /// [`contents().package_bytes()`](VerifiedContents::package_bytes).
    #[must_use]
    pub fn bytes(&self) -> &RetainedBytes {
        self.contents.package_bytes()
    }

    /// Returns the binding the package was finalized against.
    #[must_use]
    pub fn binding(&self) -> &PreparationBinding {
        &self.binding
    }

    /// Publishes [`bytes`](Self::bytes) as a new file at `destination`, never
    /// replacing an existing entry.
    ///
    /// This is the publication [`VerifiedContents::publish_package`] performs,
    /// charged to the finalization scope's budget: the validated snapshot is
    /// copied to a private 0600 sibling file, whose length and digest are
    /// checked and which is synced, then linked into place without clobbering,
    /// and the parent synced.
    ///
    /// The returned [`PublishedPackage`] is a receipt for a mutable path, not
    /// evidence: anyone with access can change the file afterwards, and
    /// nothing here would notice. An independent store verifies its own
    /// acceptance input rather than trusting the path.
    ///
    /// # Errors
    ///
    /// - [`PublicationError::DestinationExists`] when any entry is at
    ///   `destination`, which is left untouched.
    /// - [`PublicationError::UnsafeDestinationParent`] when `destination` or
    ///   its parent is refused by the directory trust policy.
    /// - [`PublicationError::DiskBudgetExceeded`], reporting the configured
    ///   `RetainedDisk`, when the temporary copy would exceed what the
    ///   operation has left of it.
    /// - [`PublicationError::Io`] or [`PublicationError::CopyMismatch`] for a
    ///   failure before the publish point, with the destination absent.
    /// - [`PublicationError::PublishDurability`] for a failure after it, when
    ///   the complete file may already be at `destination` and its durability
    ///   is uncertain.
    pub fn publish(&self, destination: &Path) -> Result<PublishedPackage, PublicationError> {
        self.contents
            .publish_package(destination)
            .map_err(|error| match error {
                PublicationError::DiskBudgetExceeded { .. } => {
                    PublicationError::DiskBudgetExceeded {
                        limit: self.retained_disk,
                    }
                }
                other => other,
            })
    }
}

impl fmt::Debug for FinalizedPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalizedPackage")
            .field("binding", &self.binding)
            .field("bytes", self.bytes())
            .finish_non_exhaustive()
    }
}

/// The test-only seam between assembly and verification: a test may damage
/// the assembled container before the pipeline sees it.
///
/// Per thread, like the other seams.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::RefCell;
    use std::io::Read;

    use super::super::RetainedBytes;
    use super::super::contents::RetentionSite;
    use super::super::prepare::{PackageWriteError, read_snapshot_error, retention};
    use super::super::{IoOperation, LimitResource};
    use crate::retain::RetentionScope;

    type Corruption = Box<dyn FnOnce(&mut Vec<u8>)>;

    thread_local! {
        static CORRUPTION: RefCell<Option<Corruption>> = const { RefCell::new(None) };
    }

    /// Removes the arranged corruption when dropped.
    #[must_use = "the corruption is removed when the guard drops"]
    pub(crate) struct SeamGuard(());

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            let _ = CORRUPTION.try_with(|slot| slot.borrow_mut().take());
        }
    }

    /// Runs `corrupt` over the next assembled container on this thread.
    pub(crate) fn corrupt(corrupt: impl FnOnce(&mut Vec<u8>) + 'static) -> SeamGuard {
        CORRUPTION.with(|slot| *slot.borrow_mut() = Some(Box::new(corrupt)));
        SeamGuard(())
    }

    /// Replaces `container` with its damaged copy, retained in the same
    /// scope, when a corruption is arranged.
    pub(super) fn after_assembly(
        scope: &RetentionScope,
        container: RetainedBytes,
    ) -> Result<RetainedBytes, PackageWriteError> {
        let Some(corrupt) = CORRUPTION.with(|slot| slot.borrow_mut().take()) else {
            return Ok(container);
        };
        let mut bytes = Vec::new();
        container
            .reader()
            .read_to_end(&mut bytes)
            .map_err(read_snapshot_error)?;
        drop(container);
        corrupt(&mut bytes);
        scope
            .snapshot_from(&mut bytes.as_slice(), u64::MAX)
            .map_err(|error| {
                retention(
                    error,
                    &RetentionSite {
                        read_source: IoOperation::ReadSnapshot,
                        source_path: None,
                        max_len: crate::content::ResourceLimit {
                            resource: LimitResource::Package,
                            max: u64::MAX,
                        },
                        staging_parent: None,
                    },
                )
            })
    }
}
