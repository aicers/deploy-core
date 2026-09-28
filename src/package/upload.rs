//! [`verify_upload`], the build identity it derives, and
//! [`upload_staging_bound`], the disk it may retain while doing so.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::contents::{
    ContentError, IoOperation, UploadRefusal, VerifiedContents, container_bounds, open_scope,
    snapshot_source, verify_authenticated,
};
use super::source::{RetainedSource, SourceRole};
use super::{ContentLimits, LimitResource};
use crate::manifest::{PayloadManifest, TargetArch};
use crate::verify::{
    Authenticated, BoundedAuthenticated, BoundedVerified, TrustSet, UploadRequest, VerifyRequest,
    authenticate_bounded, check_statements,
};

#[cfg(test)]
mod tests;

/// Returns the disk budget [`verify_upload`] verifies a package of
/// `package_len` bytes under: `min(RetainedDisk, 2 × package_len +
/// OuterUncompressedTotal)`, each read from `limits`, with saturating
/// arithmetic.
///
/// It is pure and does no I/O, so a caller can reserve this much disk before
/// the call, and [`verify_upload`] enforces exactly this number.
///
/// The derivation: while [`verify_upload`] runs, its private directory holds
/// the package snapshot (`package_len` bytes), the copy of the package's
/// archive block (at most `package_len`), and the extracted members (at most
/// `OuterUncompressedTotal`, which extraction enforces on what it actually
/// reads). Image validation retains nothing. So the budget is never why a
/// package within the other limits is refused, unless `RetainedDisk` was
/// lowered below it.
///
/// A caller that needs a smaller reservation lowers `OuterUncompressedTotal`
/// or `RetainedDisk` through
/// [`ContentLimits::with_limit`](super::ContentLimits::with_limit); a package
/// that then needs more is refused as
/// [`ContentError::LimitExceeded`] naming `RetainedDisk`, with `limit` the
/// budget this returns.
#[must_use]
pub fn upload_staging_bound(limits: &ContentLimits, package_len: u64) -> u64 {
    let needed = package_len
        .saturating_mul(2)
        .saturating_add(limits.get(LimitResource::OuterUncompressedTotal));
    limits.get(LimitResource::RetainedDisk).min(needed)
}

/// Verifies an uploaded package in full, deriving the build to verify it as
/// from its own authenticated manifest, and returns what was verified.
///
/// An upload hop knows only the namespace it deploys under before it has read
/// a package; the component, version, commit and architecture are statements
/// the package makes. So this runs the [`verify_contents`](super::verify_contents)
/// pipeline with those four taken from the manifest's **first** artifact
/// entry, and only once the signature over that manifest has verified:
///
/// 1. `source` is sought to its end to learn its length, then snapshotted
///    exactly as [`verify_contents`](super::verify_contents) does, into one
///    private directory created in `staging_parent` whose disk budget is
///    [`upload_staging_bound`] of that length;
/// 2. the snapshot's footer is held to `RawManifest` and `CompressedArchive`,
///    and the signature, the format floor and the typed parse run — nothing
///    in the manifest is read for any decision before the signature verifies;
/// 3. the build is taken from the first artifact entry and the request is the
///    namespaced request for it under `request`'s namespace;
/// 4. the statement checks run exactly as for
///    [`verify_package`](crate::verify::verify_package) with that request, so
///    an entry of another build is
///    [`VerifyError::TargetMismatch`](crate::verify::VerifyError::TargetMismatch);
/// 5. the rest of the pipeline runs against the first entry's architecture,
///    so an entry built for another is
///    [`ContentError::ArchitectureMismatch`] whose `expected` is the first
///    entry's.
///
/// Every snapshot is released and the private directory removed before this
/// returns, on success and on refusal; the result owns metadata only. Removal
/// is best effort, and anything a failed removal leaves is inside the private
/// directory under `staging_parent`.
///
/// Which components a store accepts is the caller's decision: no package-id
/// registry is consulted.
///
/// # Errors
///
/// As [`verify_contents`](super::verify_contents) called with the package's
/// own build and architecture and a `RetainedDisk` of
/// [`upload_staging_bound`], in the same order, and in addition:
///
/// - [`ContentError::Io`] with [`IoOperation::SourceSeek`] when `source`
///   cannot be sought to its end;
/// - [`ContentError::Upload`] with [`UploadRefusal::NoArtifacts`] when the
///   authenticated manifest carries no artifact entry, and with
///   [`UploadRefusal::ReservedTarget`] when its first entry names
///   [`TRUST_TARGET`](crate::verify::TRUST_TARGET) — both decided after the
///   signature and before every statement check.
pub fn verify_upload<R: Read + Seek>(
    source: R,
    trust: &TrustSet,
    request: &UploadRequest,
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<VerifiedUpload, ContentError> {
    let (contents, identity) = upload_contents(source, trust, request, limits, staging_parent)?;
    Ok(VerifiedUpload::new(contents, identity))
}

/// What [`upload_contents`] learned alongside the evidence: the derived build
/// and the authentication facts the evidence does not carry.
struct UploadIdentity {
    component: String,
    version: String,
    commit: String,
    target_arch: TargetArch,
    key_id: String,
    manifest_sha256: [u8; 32],
}

/// Everything [`verify_upload`] does before it releases the evidence, which
/// is returned with its scope still open.
fn upload_contents<R: Read + Seek>(
    mut source: R,
    trust: &TrustSet,
    request: &UploadRequest,
    limits: &ContentLimits,
    staging_parent: &Path,
) -> Result<(VerifiedContents, UploadIdentity), ContentError> {
    // 1. The length first, so the budget can be the one the caller reserved.
    let package_len = source
        .seek(SeekFrom::End(0))
        .map_err(|source| ContentError::Io {
            operation: IoOperation::SourceSeek,
            path: None,
            source,
        })?;
    let scope = open_scope(
        staging_parent,
        upload_staging_bound(limits, package_len),
        limits,
    )?;
    let package = snapshot_source(&scope, &mut source, limits)?;
    drop(source);

    // 2. Signature, format floor and typed parse, and nothing else.
    let BoundedAuthenticated {
        authenticated:
            Authenticated {
                manifest,
                key_id,
                manifest_sha256,
            },
        archive_offset,
        archive_len,
    } = authenticate_bounded(
        RetainedSource::new(package.reader(), SourceRole::Package),
        trust,
        container_bounds(limits),
    )
    .map_err(ContentError::from_bounded)?;

    // 3. The build, from the first entry of the authenticated manifest.
    let first = manifest
        .artifacts()
        .first()
        .ok_or(ContentError::Upload(UploadRefusal::NoArtifacts))?;
    let commit = first.commit.as_deref().unwrap_or_default();
    let derived = VerifyRequest::for_upload(&first.component, &first.version, commit, request)
        .ok_or(ContentError::Upload(UploadRefusal::ReservedTarget))?;
    let identity = UploadIdentity {
        component: first.component.clone(),
        version: first.version.clone(),
        commit: commit.to_string(),
        target_arch: first.target_arch,
        key_id,
        manifest_sha256,
    };

    // 4. Every statement, against the derived request.
    check_statements(&manifest, &derived, Some(trust))?;

    // 5. The shared post-authentication body.
    let contents = verify_authenticated(
        scope,
        package,
        BoundedVerified {
            manifest,
            archive_offset,
            archive_len,
        },
        identity.target_arch,
        limits,
    )?;
    Ok((contents, identity))
}

/// What [`verify_upload`] verified: the authenticated manifest, the build
/// derived from it, the anchor that verified it and the digests of the bytes
/// it covered.
///
/// It owns metadata only: every retained byte was released before
/// [`verify_upload`] returned. It exists only as that function returns it:
///
/// ```compile_fail
/// fn forge(manifest: deploy_core::manifest::PayloadManifest) -> deploy_core::package::VerifiedUpload {
///     deploy_core::package::VerifiedUpload { manifest, ..todo!() }
/// }
/// ```
///
/// ```compile_fail
/// let _ = deploy_core::package::VerifiedUpload::default();
/// ```
#[derive(Debug)]
pub struct VerifiedUpload {
    manifest: PayloadManifest,
    component: String,
    version: String,
    commit: String,
    target_arch: TargetArch,
    key_id: String,
    manifest_sha256: [u8; 32],
    package_sha256: [u8; 32],
    package_len: u64,
}

impl VerifiedUpload {
    /// Takes the facts the evidence holds, then releases it.
    fn new(contents: VerifiedContents, identity: UploadIdentity) -> VerifiedUpload {
        let package_sha256 = *contents.package_bytes().sha256();
        let package_len = contents.package_bytes().len();
        let manifest = contents.release();
        let UploadIdentity {
            component,
            version,
            commit,
            target_arch,
            key_id,
            manifest_sha256,
        } = identity;
        VerifiedUpload {
            manifest,
            component,
            version,
            commit,
            target_arch,
            key_id,
            manifest_sha256,
            package_sha256,
            package_len,
        }
    }

    /// Returns the authenticated manifest. Each artifact's
    /// [`spec`](crate::manifest::PayloadArtifact::spec) carries its
    /// registration template.
    #[must_use]
    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }

    /// Returns the component every artifact entry was verified as, taken from
    /// the first.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the version every artifact entry was verified as, taken from
    /// the first.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the commit every artifact entry was verified as, taken from
    /// the first.
    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// Returns the architecture every artifact was verified as built for,
    /// taken from the first.
    #[must_use]
    pub fn target_arch(&self) -> TargetArch {
        self.target_arch
    }

    /// Returns the `key_id` of the trust anchor whose key verified the
    /// signature — never the container's hint, which may name another anchor
    /// or none.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the SHA-256 of the raw manifest block, exactly as it was read
    /// and verified.
    #[must_use]
    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }

    /// Returns the SHA-256 of the package bytes that were verified: the
    /// snapshot, not whatever the source holds now.
    #[must_use]
    pub fn package_sha256(&self) -> &[u8; 32] {
        &self.package_sha256
    }

    /// Returns the length of the package bytes that were verified.
    #[must_use]
    pub fn package_len(&self) -> u64 {
        self.package_len
    }
}
