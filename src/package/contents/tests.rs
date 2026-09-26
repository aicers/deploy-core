use std::cell::RefCell;
use std::io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use tempfile::TempDir;

use super::*;
use crate::manifest::TargetArch;
use crate::package::source::seam::{self, Observed, Op, Seam};
use crate::payload::PayloadError;
use crate::verify::{VerifyError, verify_package};

mod fixture;

use fixture::{
    Art, COMMIT, COMPONENT, Entry, NAMESPACE, Signer, VERSION, archive, legacy_manifest_bytes,
    manifest_bytes, mixed, package, plain_request, request, tar, tar_unfinished,
    undeclared_manifest_bytes, zstd, zstd_window,
};

/// A private staging parent: a fresh 0700 directory, named canonically so no
/// component of its path is a symbolic link.
struct Staging {
    _dir: TempDir,
    path: PathBuf,
}

impl Staging {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn staging() -> Staging {
    let dir = tempfile::tempdir().expect("a staging parent");
    let path = std::fs::canonicalize(dir.path()).expect("a canonical path");
    Staging { _dir: dir, path }
}

fn verify(
    bytes: &[u8],
    trust: &TrustSet,
    request: &VerifyRequest,
    limits: &ContentLimits,
    staging: &Path,
) -> Result<VerifiedContents, ContentError> {
    verify_contents(
        Cursor::new(bytes),
        trust,
        request,
        TargetArch::X86_64,
        limits,
        staging,
    )
}

fn verify_default(bytes: &[u8], signer: &Signer) -> Result<VerifiedContents, ContentError> {
    let dir = staging();
    verify(
        bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        dir.path(),
    )
}

fn legacy_verdict(bytes: &[u8], trust: &TrustSet, request: &VerifyRequest) -> VerifyError {
    match verify_package(Cursor::new(bytes), trust, request) {
        Err(error) => error,
        Ok(mut verified) => {
            let dir = staging();
            verified
                .extract_to(dir.path())
                .expect_err("the legacy walk refuses")
        }
    }
}

fn read_all(bytes: &RetainedBytes) -> Vec<u8> {
    let mut out = Vec::new();
    bytes
        .reader()
        .read_to_end(&mut out)
        .expect("retained bytes read");
    out
}

fn limits(resource: LimitResource, value: u64) -> ContentLimits {
    ContentLimits::default()
        .with_limit(resource, value)
        .expect("a lower limit")
}

/// Asserts `dir` holds nothing: every private directory the call made is gone.
#[track_caller]
fn assert_empty(dir: &Path) {
    let left: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the staging parent lists")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    assert!(left.is_empty(), "left behind: {left:?}");
}

#[track_caller]
fn limit_of(error: &ContentError) -> (LimitResource, u64) {
    match error {
        ContentError::LimitExceeded { resource, limit } => (*resource, *limit),
        other => panic!("expected a limit, got {other:?}"),
    }
}

#[track_caller]
fn io_of(error: &ContentError) -> (IoOperation, Option<&Path>, ErrorKind) {
    match error {
        ContentError::Io {
            operation,
            path,
            source,
        } => (*operation, path.as_deref(), source.kind()),
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

#[test]
fn a_mixed_package_verifies_into_evidence() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let dir = staging();
    let contents = verify(
        &bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        dir.path(),
    )
    .expect("the package verifies");

    assert_eq!(contents.manifest(), &fixture::manifest(&arts));
    assert_eq!(contents.artifacts().len(), arts.len());
    for (verified, art) in contents.artifacts().iter().zip(&arts) {
        assert_eq!(verified.artifact().archive_path, art.path);
        assert_eq!(verified.member_length(), art.bytes.len() as u64);
        assert_eq!(read_all(verified.bytes()), art.bytes);
        assert_eq!(
            crate::payload::to_hex(verified.bytes().sha256()),
            verified.artifact().sha256
        );
    }
    let VerifiedImages::Present(images) = contents.images() else {
        panic!("expected images");
    };
    assert_eq!(images.len(), 2);
    let paths: Vec<&str> = images
        .iter()
        .map(|image| image.artifact().archive_path.as_str())
        .collect();
    assert_eq!(paths, ["images/db.tar", "images/web.tar"]);
    for image in images.iter() {
        assert_eq!(Some(image.declaration()), image.artifact().image.as_ref());
        assert_eq!(image.member_length(), image.archive().len());
    }
    assert_eq!(read_all(contents.package_bytes()), bytes);

    // Only the package and the members stay charged: the archive-block copy
    // was dropped once the contents were checked.
    let members: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    let scope = contents.scope_for_test();
    assert_eq!(scope.budget_used(), bytes.len() as u64 + members);
    let (_, len) = archive_block(&bytes);
    assert_eq!(
        scope.budget_high_water(),
        bytes.len() as u64 + len + members
    );

    drop(contents);
    assert_empty(dir.path());
}

/// Returns the archive block's offset and length off `bytes`' footer.
fn archive_block(bytes: &[u8]) -> (u64, u64) {
    let container =
        crate::payload::read_package_container(Cursor::new(bytes), &crate::verify::ENVELOPE_BOUNDS)
            .expect("a container");
    container.archive_block()
}

#[test]
fn an_image_free_package_verifies_with_no_images() {
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let bytes = package(&signer, &arts);
    let dir = staging();
    let contents = verify(
        &bytes,
        &signer.trust(),
        &plain_request(),
        &ContentLimits::default(),
        dir.path(),
    )
    .expect("the package verifies");
    assert!(matches!(contents.images(), VerifiedImages::None));
    assert_eq!(read_all(contents.artifacts()[0].bytes()), b"tool");
}

fn verify_on(
    bytes: &[u8],
    trust: &TrustSet,
    request: &VerifyRequest,
    arch: TargetArch,
) -> Result<VerifiedContents, ContentError> {
    let dir = staging();
    let result = verify_contents(
        Cursor::new(bytes),
        trust,
        request,
        arch,
        &ContentLimits::default(),
        dir.path(),
    );
    if result.is_err() {
        assert_empty(dir.path());
    }
    result
}

#[track_caller]
fn refusal(bytes: &[u8], trust: &TrustSet, request: &VerifyRequest) -> ContentError {
    verify_on(bytes, trust, request, TargetArch::X86_64).expect_err("the package is refused")
}

#[track_caller]
fn verdict(bytes: &[u8], trust: &TrustSet, request: &VerifyRequest) -> VerifyError {
    match refusal(bytes, trust, request) {
        ContentError::Verify(error) => error,
        other => panic!("expected a verdict, got {other:?}"),
    }
}

/// Asserts `verify_package` and `verify_contents` give the same variant with
/// the same message on `bytes`.
#[track_caller]
fn same_verdict(bytes: &[u8], trust: &TrustSet, request: &VerifyRequest) -> VerifyError {
    let legacy = legacy_verdict(bytes, trust, request);
    let new = verdict(bytes, trust, request);
    assert_eq!(format!("{legacy:?}"), format!("{new:?}"));
    new
}

/// An image whose archive disagrees with its declared config digest: a
/// nested fault, found only once the image bytes are read.
fn wrong_config(mut art: Art) -> Art {
    if let Some(image) = art.image.as_mut() {
        image.config_digest = format!("sha256:{}", "ab".repeat(32));
    }
    art
}

/// An image declared under another namespace: a whole-manifest image pass
/// fault.
fn foreign(mut art: Art) -> Art {
    if let Some(image) = art.image.as_mut() {
        image.owner.namespace = "other-product".to_string();
    }
    art
}

fn with_version(arts: Vec<Art>, version: &str) -> Vec<Art> {
    arts.into_iter()
        .map(|mut art| {
            art.version = version.to_string();
            art
        })
        .collect()
}

fn with_component(arts: Vec<Art>, component: &str) -> Vec<Art> {
    arts.into_iter()
        .map(|mut art| {
            art.component = component.to_string();
            if let Some(image) = art.image.as_mut() {
                image.owner.component = component.to_string();
            }
            art
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Verdict ordering
// ---------------------------------------------------------------------------

#[test]
fn a_bad_signature_outranks_an_image_archive_fault() {
    let signer = Signer::new();
    let arts = vec![wrong_config(Art::image(
        "images/db.tar",
        TargetArch::X86_64,
        "database",
        b"db",
    ))];
    let bytes = signer.badly_signed(&manifest_bytes(&arts), &archive(&arts));
    assert!(matches!(
        same_verdict(&bytes, &signer.trust(), &request()),
        VerifyError::BadSignature
    ));
}

#[test]
fn an_unsupported_format_outranks_a_typed_image_shape_fault() {
    let signer = Signer::new();
    let arts = mixed();
    let mut value: serde_json::Value =
        serde_json::from_slice(&undeclared_manifest_bytes(&arts)).expect("json");
    value["format_version"] = serde_json::Value::from(99);
    let manifest = serde_json::to_vec(&value).expect("json");
    let bytes = signer.container(&manifest, &archive(&arts));
    assert!(matches!(
        same_verdict(&bytes, &signer.trust(), &request()),
        VerifyError::UnsupportedManifestFormat { found: 99, .. }
    ));
}

#[test]
fn statement_order_is_identical_through_both_entry_points() {
    let signer = Signer::new();

    // An unsafe identifier outranks a withdrawn build.
    let arts = with_version(mixed(), "-1.0");
    let trust = signer.trust_with(
        vec![(
            COMPONENT.to_string(),
            "-1.0".to_string(),
            COMMIT.to_string(),
        )],
        0,
    );
    assert!(matches!(
        same_verdict(&package(&signer, &arts), &trust, &request()),
        VerifyError::UnsafeBuildIdentifier { .. }
    ));

    // A withdrawn build outranks a target mismatch.
    let trust = signer.trust_with(
        vec![(
            COMPONENT.to_string(),
            VERSION.to_string(),
            COMMIT.to_string(),
        )],
        0,
    );
    let other = VerifyRequest::for_namespaced_package(COMPONENT, "2.0.0", COMMIT, NAMESPACE)
        .expect("a request");
    assert!(matches!(
        same_verdict(&package(&signer, &mixed()), &trust, &other),
        VerifyError::WithdrawnBuild { .. }
    ));

    // A target mismatch outranks a stale epoch, and a stale epoch outranks
    // an image pass fault: a trust request carries no namespace, so its
    // declared images fail their namespace pass.
    let arts = with_version(with_component(mixed(), crate::verify::TRUST_TARGET), "8");
    let bytes = package(&signer, &arts);
    let trust = signer.trust_with(Vec::new(), 10);
    let mismatched = VerifyRequest::for_trust("9", COMMIT, 5).expect("a request");
    assert!(matches!(
        same_verdict(&bytes, &trust, &mismatched),
        VerifyError::TargetMismatch { .. }
    ));
    let stale = VerifyRequest::for_trust("8", COMMIT, 5).expect("a request");
    assert!(matches!(
        same_verdict(&bytes, &trust, &stale),
        VerifyError::StaleTrustSet {
            delivered: 5,
            active: 10
        }
    ));
    let fresh = VerifyRequest::for_trust("8", COMMIT, 11).expect("a request");
    assert!(matches!(
        same_verdict(&bytes, &trust, &fresh),
        VerifyError::Image(ImageVerifyError::MissingNamespace { .. })
    ));
}

#[test]
fn a_target_mismatch_outranks_an_image_semantic_fault() {
    let signer = Signer::new();
    let arts = vec![foreign(Art::image(
        "images/db.tar",
        TargetArch::X86_64,
        "database",
        b"db",
    ))];
    let other = VerifyRequest::for_namespaced_package(COMPONENT, "2.0.0", COMMIT, NAMESPACE)
        .expect("a request");
    assert!(matches!(
        same_verdict(&package(&signer, &arts), &signer.trust(), &other),
        VerifyError::TargetMismatch { .. }
    ));
}

#[test]
fn the_image_passes_outrank_the_requested_architecture() {
    let signer = Signer::new();
    let arts = vec![
        Art::native("bin/tool", b"tool").on(TargetArch::Aarch64),
        foreign(Art::image(
            "images/db.tar",
            TargetArch::Aarch64,
            "database",
            b"db",
        )),
    ];
    let bytes = package(&signer, &arts);
    assert!(matches!(
        verdict(&bytes, &signer.trust(), &request()),
        VerifyError::Image(ImageVerifyError::NamespaceMismatch { .. })
    ));

    // Without the namespace fault, the architecture is what is refused, and
    // it names the first artifact in manifest order.
    let arts = vec![
        Art::native("bin/tool", b"tool").on(TargetArch::Aarch64),
        Art::image("images/db.tar", TargetArch::Aarch64, "database", b"db"),
    ];
    let error = refusal(&package(&signer, &arts), &signer.trust(), &request());
    assert!(
        matches!(
            &error,
            ContentError::ArchitectureMismatch {
                archive_path,
                expected: TargetArch::X86_64,
                actual: TargetArch::Aarch64,
            } if archive_path == "bin/tool"
        ),
        "got {error:?}"
    );
    // The same package verifies when its own architecture is requested.
    verify_on(
        &package(&signer, &arts),
        &signer.trust(),
        &request(),
        TargetArch::Aarch64,
    )
    .expect("the aarch64 package verifies for aarch64");
}

#[test]
fn the_architecture_outranks_legacy_refusal_which_outranks_extraction() {
    let signer = Signer::new();
    let db = Art::image("images/db.tar", TargetArch::Aarch64, "database", b"db");
    let arts = vec![Art::native("bin/tool", b"tool").on(TargetArch::Aarch64), db];
    let bytes = signer.container(&legacy_manifest_bytes(&arts), &archive(&arts));
    assert!(matches!(
        refusal(&bytes, &signer.trust(), &plain_request()),
        ContentError::ArchitectureMismatch { .. }
    ));

    // On the requested architecture, the legacy image is refused, before an
    // archive whose member disagrees with its hash is ever walked.
    let arts = vec![
        Art::native("bin/tool", b"tool"),
        Art::image("images/db.tar", TargetArch::X86_64, "database", b"db"),
    ];
    let mut tampered = arts.clone();
    tampered[0].bytes = b"TOOL".to_vec();
    let bytes = signer.container(&legacy_manifest_bytes(&arts), &archive(&tampered));
    let error = verdict(&bytes, &signer.trust(), &plain_request());
    assert!(
        matches!(
            &error,
            VerifyError::Image(ImageVerifyError::LegacyImageEvidence { archive_path })
                if archive_path == "images/db.tar"
        ),
        "got {error:?}"
    );
    // The legacy verifier accepts the same package and calls its images
    // undeclared; it is never evidence of no images.
    let verified = verify_package(Cursor::new(&bytes), &signer.trust(), &plain_request())
        .expect("the legacy verifier admits it");
    assert!(matches!(
        verified.image_references(),
        crate::verify::ImageReferences::LegacyUndeclared
    ));
}

#[test]
fn every_outer_check_outranks_every_image_check() {
    let signer = Signer::new();
    let arts = vec![
        wrong_config(Art::image(
            "images/db.tar",
            TargetArch::X86_64,
            "database",
            b"db",
        )),
        Art::native("bin/tool", b"tool"),
    ];
    let mut tampered = arts.clone();
    tampered[1].bytes = b"TOOL".to_vec();
    let bytes = signer.container(&manifest_bytes(&arts), &archive(&tampered));
    let error = verdict(&bytes, &signer.trust(), &request());
    assert!(
        matches!(&error, VerifyError::ManifestHashMismatch { path } if path == "bin/tool"),
        "got {error:?}"
    );

    // A truncated end-of-archive marker is an outer fault too.
    let mut outer = tar_unfinished(&[
        Entry::File("images/db.tar", &arts[0].bytes),
        Entry::File("bin/tool", &arts[1].bytes),
    ]);
    outer.extend_from_slice(&[0u8; 300]);
    let bytes = signer.container(&manifest_bytes(&arts), &zstd(&outer));
    assert!(matches!(
        same_verdict(&bytes, &signer.trust(), &request()),
        VerifyError::Payload(PayloadError::Io(_))
    ));

    // With the outer archive intact, the image fault is what is reported.
    let bytes = package(&signer, &arts);
    assert!(matches!(
        verdict(&bytes, &signer.trust(), &request()),
        VerifyError::Image(ImageVerifyError::ConfigDigestMismatch { .. })
    ));
}

#[test]
fn of_two_bad_images_the_first_in_manifest_order_is_reported() {
    let signer = Signer::new();
    let arts = vec![
        Art::native("bin/tool", b"tool"),
        wrong_config(Art::image(
            "images/b.tar",
            TargetArch::X86_64,
            "bravo",
            b"b",
        )),
        wrong_config(Art::image(
            "images/a.tar",
            TargetArch::X86_64,
            "alpha",
            b"a",
        )),
    ];
    let error = verdict(&package(&signer, &arts), &signer.trust(), &request());
    assert!(
        matches!(
            &error,
            VerifyError::Image(ImageVerifyError::ConfigDigestMismatch { archive_path, .. })
                if archive_path == "images/b.tar"
        ),
        "got {error:?}"
    );
}

#[test]
fn an_undeclared_current_format_image_is_the_typed_parse_refusal() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = signer.container(&undeclared_manifest_bytes(&arts), &archive(&arts));
    assert!(matches!(
        same_verdict(&bytes, &signer.trust(), &request()),
        VerifyError::Payload(PayloadError::InvalidManifest(
            crate::manifest::ManifestError::MissingImageDeclaration(_)
        ))
    ));
}

#[test]
fn an_unversioned_legacy_image_is_refused_by_the_content_core() {
    // An unversioned manifest is admitted only from a version-1 container,
    // which carries no signature, so the authenticated pipeline refuses it as
    // `BadSignature`. The content core refuses its images all the same.
    let arts = vec![Art::image(
        "images/db.tar",
        TargetArch::X86_64,
        "database",
        b"db",
    )];
    let mut value: serde_json::Value =
        serde_json::from_slice(&legacy_manifest_bytes(&arts)).expect("json");
    let object = value.as_object_mut().expect("an object");
    object.remove("format_version");
    object.remove("archive_members");
    for artifact in object["artifacts"].as_array_mut().expect("an array") {
        artifact
            .as_object_mut()
            .expect("an object")
            .remove("commit");
    }
    let manifest = PayloadManifest::parse(
        &serde_json::to_vec(&value).expect("json"),
        crate::manifest::LEGACY_UNVERSIONED_FOOTER_VERSION,
    )
    .expect("the baseline shape parses");
    assert_eq!(manifest.format_version(), None);

    let dir = staging();
    let scope = RetentionScope::new(dir.path(), 1 << 30, NonZeroUsize::MIN).expect("a scope");
    let block = scope
        .snapshot_from(&mut archive(&arts).as_slice(), u64::MAX)
        .expect("a snapshot");
    let error = check_contents(
        &manifest,
        &block,
        TargetArch::X86_64,
        &ContentLimits::default(),
        &scope,
    )
    .expect_err("refused");
    assert!(matches!(
        error,
        ContentError::Verify(VerifyError::Image(
            ImageVerifyError::LegacyImageEvidence { .. }
        ))
    ));
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

fn verify_limited(
    bytes: &[u8],
    signer: &Signer,
    limits: &ContentLimits,
) -> Result<VerifiedContents, ContentError> {
    let dir = staging();
    let result = verify(bytes, &signer.trust(), &request(), limits, dir.path());
    if result.is_err() {
        assert_empty(dir.path());
    }
    result
}

/// Bytes the package snapshot's source returned to reads during bounded
/// authentication.
fn package_bytes_read(observed: &[Observed]) -> u64 {
    observed
        .iter()
        .filter(|seen| seen.role == SourceRole::Package && seen.op == Op::Read)
        .map(|seen| seen.outcome.expect("a read that succeeded"))
        .sum()
}

#[test]
fn raw_manifest_is_refused_before_allocation_and_before_the_signature() {
    let signer = Signer::new();
    let arts = mixed();
    let manifest = manifest_bytes(&arts);
    let len = manifest.len() as u64;
    let bytes = signer.badly_signed(&manifest, &archive(&arts));
    assert!(matches!(
        verify_package(Cursor::new(&bytes), &signer.trust(), &request()).map(|_| ()),
        Err(VerifyError::BadSignature)
    ));

    let guard = seam::install(Seam::new());
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::RawManifest, len - 1),
    )
    .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::RawManifest, len - 1));
    let read = package_bytes_read(&seam::observed());
    drop(guard);
    assert!(read < len, "read {read} bytes of a {len}-byte manifest");
    assert!(!seam_saw(SourceRole::ArchiveCopy));

    // At the limit the manifest is read, and the signature is what fails.
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::RawManifest, len))
        .expect_err("refused");
    assert!(matches!(
        error,
        ContentError::Verify(VerifyError::BadSignature)
    ));
    // Lowering the archive limit alone does not touch the manifest check.
    let (_, archive_len) = archive_block(&bytes);
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::CompressedArchive, archive_len),
    )
    .expect_err("refused");
    assert!(matches!(
        error,
        ContentError::Verify(VerifyError::BadSignature)
    ));
}

fn seam_saw(role: SourceRole) -> bool {
    seam::observed().iter().any(|seen| seen.role == role)
}

#[test]
fn the_bounded_reader_never_reads_an_oversized_manifest() {
    struct Counting {
        inner: Cursor<Vec<u8>>,
        read: Rc<RefCell<u64>>,
    }
    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            *self.read.borrow_mut() += n as u64;
            Ok(n)
        }
    }
    impl Seek for Counting {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    let signer = Signer::new();
    let arts = mixed();
    let manifest = manifest_bytes(&arts);
    let len = manifest.len() as u64;
    let bytes = signer.badly_signed(&manifest, &archive(&arts));
    let (_, archive_len) = archive_block(&bytes);
    let read = Rc::new(RefCell::new(0));
    let source = Counting {
        inner: Cursor::new(bytes.clone()),
        read: Rc::clone(&read),
    };
    let error = crate::verify::verify_package_bounded(
        source,
        &signer.trust(),
        &request(),
        ContainerBounds {
            max_manifest_len: len - 1,
            max_archive_len: archive_len,
        },
    )
    .expect_err("refused");
    assert!(matches!(
        error,
        BoundedVerifyError::LimitExceeded {
            resource: LimitResource::RawManifest,
            ..
        }
    ));
    assert!(*read.borrow() < len);

    // The archive bound is checked on its own.
    let error = crate::verify::verify_package_bounded(
        Cursor::new(bytes),
        &signer.trust(),
        &request(),
        ContainerBounds {
            max_manifest_len: len,
            max_archive_len: archive_len - 1,
        },
    )
    .expect_err("refused");
    assert!(matches!(
        error,
        BoundedVerifyError::LimitExceeded {
            resource: LimitResource::CompressedArchive,
            ..
        }
    ));
}

#[test]
fn compressed_archive_is_refused_before_any_archive_byte_and_the_signature() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = signer.badly_signed(&manifest_bytes(&arts), &archive(&arts));
    let (_, len) = archive_block(&bytes);
    assert!(matches!(
        verify_package(Cursor::new(&bytes), &signer.trust(), &request()).map(|_| ()),
        Err(VerifyError::BadSignature)
    ));

    let guard = seam::install(Seam::new());
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::CompressedArchive, len - 1),
    )
    .expect_err("refused");
    assert_eq!(
        limit_of(&error),
        (LimitResource::CompressedArchive, len - 1)
    );
    // Only the footer candidates were read.
    let read = package_bytes_read(&seam::observed());
    assert!(read <= 41 + 73, "read {read} bytes");
    assert!(!seam_saw(SourceRole::ArchiveCopy));
    drop(guard);

    // Lowering the manifest limit alone does not touch the archive check.
    let manifest_len = manifest_bytes(&arts).len() as u64;
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::RawManifest, manifest_len - 1),
    )
    .expect_err("refused");
    assert_eq!(limit_of(&error).0, LimitResource::RawManifest);
}

#[test]
fn block_lengths_exactly_at_their_limits_verify() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let (_, archive_len) = archive_block(&bytes);
    let manifest_len = manifest_bytes(&arts).len() as u64;
    let limits = ContentLimits::default()
        .with_limit(LimitResource::RawManifest, manifest_len)
        .and_then(|limits| limits.with_limit(LimitResource::CompressedArchive, archive_len))
        .and_then(|limits| limits.with_limit(LimitResource::Package, bytes.len() as u64))
        .expect("lower limits");
    verify_limited(&bytes, &signer, &limits).expect("verifies at the limits");
}

#[test]
fn a_package_over_its_limit_is_refused_during_the_snapshot() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = signer.badly_signed(&manifest_bytes(&arts), &archive(&arts));
    let len = bytes.len() as u64;
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::Package, len - 1))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::Package, len - 1));
    let error =
        verify_limited(&bytes, &signer, &limits(LimitResource::Package, len)).expect_err("refused");
    assert!(matches!(
        error,
        ContentError::Verify(VerifyError::BadSignature)
    ));
}

#[test]
fn outer_members_and_the_uncompressed_total_hold_at_their_limits() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let count = arts.len() as u64;
    verify_limited(&bytes, &signer, &limits(LimitResource::OuterMembers, count))
        .expect("verifies at the member limit");
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::OuterMembers, count - 1),
    )
    .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::OuterMembers, count - 1));

    let total: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::OuterUncompressedTotal, total),
    )
    .expect("verifies at the total limit");
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::OuterUncompressedTotal, total - 1),
    )
    .expect_err("refused");
    assert_eq!(
        limit_of(&error),
        (LimitResource::OuterUncompressedTotal, total - 1)
    );
}

#[test]
fn a_zstd_bomb_is_refused_at_the_uncompressed_total() {
    let signer = Signer::new();
    let bomb = vec![0u8; 8 << 20];
    let arts = vec![Art::native("bin/zeros", &bomb)];
    let bytes = package(&signer, &arts);
    assert!(archive_block(&bytes).1 < 4096, "the bomb compresses");
    let limit = 1 << 20;
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::OuterUncompressedTotal, limit),
    )
    .expect_err("refused");
    assert_eq!(
        limit_of(&error),
        (LimitResource::OuterUncompressedTotal, limit)
    );
}

/// The private framing allowance under the default `OuterMembers`: an
/// extension record larger than it never reaches the archive reader.
fn default_framing_allowance() -> u64 {
    crate::payload::framing_allowance(ContentLimits::default().get(LimitResource::OuterMembers))
}

/// Which override a payload verdict names.
type Overrides = fn(&PayloadError) -> bool;

fn names(error: &PayloadError) -> bool {
    matches!(error, PayloadError::NameOverridingHeader { .. })
}

fn sizes(error: &PayloadError) -> bool {
    matches!(error, PayloadError::SizeOverridingHeader { .. })
}

fn links(error: &PayloadError) -> bool {
    matches!(error, PayloadError::UnsupportedEntryType { .. })
}

/// The one-member outer tar of `tool`, broken by each extension record form
/// with a record of about `len` bytes, and the verdict the shared rules give
/// it.
fn extension_archives(len: usize) -> Vec<(&'static str, Vec<u8>, Overrides)> {
    let long = format!("bin/{}", "a".repeat(len));
    vec![
        (
            "pax path",
            tar(&[Entry::PaxPath {
                header: "bin/tool",
                path: &long,
                data: b"tool",
            }]),
            names,
        ),
        (
            "pax size",
            tar(&[Entry::PaxSizeCommented {
                path: "bin/tool",
                data: b"tool",
                comment: len,
            }]),
            sizes,
        ),
        (
            "gnu long name",
            tar(&[Entry::GnuLongName {
                header: "bin/tool",
                path: &long,
                data: b"tool",
            }]),
            names,
        ),
        (
            "gnu long link",
            tar(&[Entry::GnuLongLink {
                header: "bin/tool",
                target: &long,
            }]),
            links,
        ),
    ]
}

/// Returns the payload verdict `verify_contents` gives `bytes` under
/// `limits`, failing on any other refusal — a limit above all.
#[track_caller]
fn payload_refusal(bytes: &[u8], signer: &Signer, limits: &ContentLimits) -> PayloadError {
    match verify_limited(bytes, signer, limits).expect_err("refused") {
        ContentError::Verify(VerifyError::Payload(error)) => error,
        other => panic!("expected a payload verdict, got {other:?}"),
    }
}

#[test]
fn an_extension_record_is_refused_for_what_it_overrides_at_any_size() {
    // Small records reach the archive reader and are judged by the shared
    // rules exactly as the legacy walk judges them. Records larger than the
    // whole default framing allowance are read past it, never buffered, and
    // refused with the same variant — not as member data they are not.
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let manifest = manifest_bytes(&arts);
    let large = usize::try_from(2 * default_framing_allowance()).expect("fits");
    for len in [64, large] {
        for (name, outer, expected) in extension_archives(len) {
            let bytes = signer.container(&manifest, &zstd(&outer));
            let VerifyError::Payload(legacy) =
                legacy_verdict(&bytes, &signer.trust(), &plain_request())
            else {
                panic!("{name} ({len}): the legacy walk gives a payload verdict");
            };
            let bounded = payload_refusal(&bytes, &signer, &ContentLimits::default());
            assert!(expected(&legacy), "{name} ({len}): legacy {legacy:?}");
            assert!(expected(&bounded), "{name} ({len}): bounded {bounded:?}");
            if len < large {
                assert_eq!(format!("{legacy:?}"), format!("{bounded:?}"), "{name}");
            } else {
                // Only a bounded prefix of the record's name is reported.
                assert!(format!("{bounded:?}").len() < 1024, "{name}: {bounded:?}");
            }
        }
    }
}

#[test]
fn an_oversized_record_reports_a_bounded_prefix_of_its_name() {
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let large = usize::try_from(2 * default_framing_allowance()).expect("fits");
    let (_, outer, _) = extension_archives(large).swap_remove(0);
    let bytes = signer.container(&manifest_bytes(&arts), &zstd(&outer));
    let error = payload_refusal(&bytes, &signer, &ContentLimits::default());
    let PayloadError::NameOverridingHeader {
        header_name,
        resolved_name,
    } = error
    else {
        panic!("{error:?}");
    };
    // The member's own header lies past the record; the extension's is named.
    assert_eq!(header_name, "pax");
    assert!(resolved_name.starts_with("bin/aaaa"), "{resolved_name}");
    assert!(resolved_name.ends_with('\u{2026}'), "{resolved_name}");
    assert!(resolved_name.len() <= 256 + 3, "{}", resolved_name.len());
}

#[test]
fn an_oversized_record_the_archive_reader_refuses_on_its_header_is_its_refusal() {
    // The archive reader refuses a header whose checksum fails, and a second
    // long name for one member, before it asks for the record's body, so the
    // scan that would name an override never starts and the verdict is the
    // archive reader's, as the legacy walk reports it.
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let manifest = manifest_bytes(&arts);
    let large = usize::try_from(2 * default_framing_allowance()).expect("fits");
    let (_, long_name, _) = extension_archives(large).swap_remove(2);
    let mut corrupt = long_name.clone();
    // A mode digit changed under the header's recorded checksum.
    corrupt[100] ^= 1;
    let (_, small, _) = extension_archives(64).swap_remove(2);
    let body = tar::Header::from_byte_slice(&small[..512])
        .entry_size()
        .expect("a size");
    let small_record = 512 + usize::try_from(body.div_ceil(512) * 512).expect("fits");
    let mut duplicate = small[..small_record].to_vec();
    duplicate.extend_from_slice(&long_name);
    for (name, outer) in [("checksum", corrupt), ("duplicate", duplicate)] {
        let bytes = signer.container(&manifest, &zstd(&outer));
        let legacy = legacy_verdict(&bytes, &signer.trust(), &plain_request());
        let VerifyError::Payload(PayloadError::Io(_)) = &legacy else {
            panic!("{name}: legacy {legacy:?}");
        };
        let bounded = payload_refusal(&bytes, &signer, &ContentLimits::default());
        assert_eq!(
            format!("{legacy:?}"),
            format!("{:?}", VerifyError::Payload(bounded)),
            "{name}"
        );
    }
}

#[test]
fn a_lowered_member_count_never_reports_framing_as_member_data() {
    // One member slot leaves a few KiB of framing: every record below is
    // larger, and each is still its override, never `OuterUncompressedTotal`
    // — which the member's four bytes of data meet exactly.
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let manifest = manifest_bytes(&arts);
    let lowered = limits(LimitResource::OuterMembers, 1)
        .with_limit(LimitResource::OuterUncompressedTotal, 4)
        .expect("lower limits");
    let len = usize::try_from(4 * crate::payload::framing_allowance(1)).expect("fits");
    for (name, outer, expected) in extension_archives(len) {
        let bytes = signer.container(&manifest, &zstd(&outer));
        let bounded = payload_refusal(&bytes, &signer, &lowered);
        assert!(expected(&bounded), "{name}: {bounded:?}");
    }
    verify_limited(&package(&signer, &arts), &signer, &lowered)
        .expect("the honest archive verifies under the same limits");
}

#[test]
fn an_oversized_record_overriding_nothing_is_a_container_verdict() {
    // A PAX record carrying only a comment overrides nothing, and the legacy
    // walk, which buffers it whole, accepts the archive. The bounded walk
    // cannot hold it, and refuses it as a container verdict: the framing
    // allowance is private, and passing it is no public limit.
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let large = usize::try_from(2 * default_framing_allowance()).expect("fits");
    for (len, bounded) in [(64, false), (large, true)] {
        let outer = tar(&[Entry::PaxCommented {
            path: "bin/tool",
            data: b"tool",
            comment: len,
        }]);
        let bytes = signer.container(&manifest_bytes(&arts), &zstd(&outer));
        let mut verified = verify_package(Cursor::new(&bytes), &signer.trust(), &plain_request())
            .expect("the legacy verifier");
        let dir = staging();
        verified
            .extract_to(dir.path())
            .expect("the legacy walk extracts");
        let result = verify_limited(&bytes, &signer, &ContentLimits::default());
        if bounded {
            let error = payload_refusal(&bytes, &signer, &ContentLimits::default());
            let PayloadError::Io(error) = error else {
                panic!("{error:?}");
            };
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains("framing"), "{error}");
        } else {
            result.expect("a record the allowance holds verifies");
        }
    }
}

#[test]
fn framing_consumes_none_of_the_uncompressed_total() {
    // One and `OuterMembers` members, each archive verifying with the total
    // set to exactly its member bytes: headers, padding and the end marker
    // are not member data. A package of no members authenticates to nothing,
    // so the walk's own tests hold the empty archive to a zero total.
    let signer = Signer::new();
    let many: Vec<Art> = (0..5)
        .map(|index| Art::native(&format!("bin/tool{index}"), &vec![b'x'; 700 + index]))
        .collect();
    for arts in [many[..1].to_vec(), many.clone()] {
        let bytes = package(&signer, &arts);
        let total: u64 = arts
            .iter()
            .map(|art| u64::try_from(art.bytes.len()).expect("fits"))
            .sum();
        let count = u64::try_from(arts.len()).expect("fits");
        let exact = limits(LimitResource::OuterMembers, count)
            .with_limit(LimitResource::OuterUncompressedTotal, total)
            .expect("lower limits");
        verify_limited(&bytes, &signer, &exact).expect("verifies at the exact total");
        let under = exact
            .with_limit(LimitResource::OuterUncompressedTotal, total - 1)
            .expect("a lower limit");
        let error = verify_limited(&bytes, &signer, &under).expect_err("refused");
        assert_eq!(
            limit_of(&error),
            (LimitResource::OuterUncompressedTotal, total - 1)
        );
    }
}

#[test]
fn an_empty_archive_walks_under_a_zero_total_and_no_members() {
    // No package of no members authenticates, so the content core is held to
    // it directly: the end marker alone consumes no member byte and no slot.
    let dir = staging();
    let scope = RetentionScope::new(dir.path(), 1 << 30, NonZeroUsize::MIN).expect("a scope");
    let block = scope
        .snapshot_from(&mut zstd(&tar(&[])).as_slice(), u64::MAX)
        .expect("a snapshot");
    let zero = limits(LimitResource::OuterMembers, 0)
        .with_limit(LimitResource::OuterUncompressedTotal, 0)
        .expect("lower limits");
    let checked = check_contents(
        &fixture::manifest(&[]),
        &block,
        TargetArch::X86_64,
        &zero,
        &scope,
    )
    .expect("the empty archive walks");
    assert!(checked.members.is_empty());
}

#[test]
fn a_zstd_window_above_its_limit_is_refused_before_decoding() {
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"tool")];
    let outer = tar(&[Entry::File("bin/tool", b"tool")]);
    let bytes = signer.container(&manifest_bytes(&arts), &zstd_window(&outer, 20));
    verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 20))
        .expect("verifies at the window limit");
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 19))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::ZstdWindow, 1 << 19));

    // The smallest window above the limit a descriptor can state: one eighth
    // more than 512 KiB. The frame still decodes under a larger limit.
    let mut frame = zstd_window(&outer, 19);
    let descriptor = frame[5];
    assert_eq!(descriptor & 0x07, 0);
    frame[5] = descriptor | 1;
    let bytes = signer.container(&manifest_bytes(&arts), &frame);
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 19))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::ZstdWindow, 1 << 19));
    verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 20))
        .expect("verifies under a larger window");

    // A single-segment frame's window is its content size.
    let single = zstd::bulk::compress(&outer, 3).expect("compresses");
    assert_ne!(single[4] & 0x20, 0, "a single-segment frame");
    let bytes = signer.container(&manifest_bytes(&arts), &single);
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1024))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::ZstdWindow, 1024));
    verify_limited(&bytes, &signer, &ContentLimits::default()).expect("verifies");
}

#[test]
fn a_later_zstd_frame_above_the_window_is_named_as_the_limit() {
    let signer = Signer::new();
    let arts = vec![
        Art::native("bin/first", b"first"),
        Art::native("bin/second", b"second"),
    ];
    let outer = tar(&[
        Entry::File("bin/first", b"first"),
        Entry::File("bin/second", b"second"),
    ]);
    // The tar split across two frames, the second declaring the larger
    // window; the decoder joins their output.
    let (head, tail) = outer.split_at(outer.len() / 2);
    let mut block = zstd_window(head, 19);
    block.extend(zstd_window(tail, 20));
    let bytes = signer.container(&manifest_bytes(&arts), &block);
    verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 20))
        .expect("verifies at the window limit");
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 19))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::ZstdWindow, 1 << 19));

    // Behind a skippable frame, which the decoder passes over, too.
    let mut block = vec![0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 0, 0, 0, 0];
    block.extend(zstd_window(&outer, 20));
    let bytes = signer.container(&manifest_bytes(&arts), &block);
    verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 20))
        .expect("verifies at the window limit");
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::ZstdWindow, 1 << 19))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::ZstdWindow, 1 << 19));

    // A frame in a legacy zstd format, whose window the walk cannot read
    // before the decoder would size one, is a container refusal.
    let mut block = zstd(&outer);
    block[0] = 0x27;
    let bytes = signer.container(&manifest_bytes(&arts), &block);
    let error = verify_limited(&bytes, &signer, &ContentLimits::default()).expect_err("refused");
    assert!(
        matches!(
            error,
            ContentError::Verify(VerifyError::Payload(PayloadError::Io(_)))
        ),
        "{error:?}"
    );
}

#[test]
fn no_archive_read_exceeds_the_copy_buffer() {
    let signer = Signer::new();
    let arts = vec![Art::native("bin/tool", b"a small native tool")];
    let bytes = package(&signer, &arts);
    let guard = seam::install(Seam::new());
    let contents = verify_limited(&bytes, &signer, &limits(LimitResource::CopyBuffer, 1))
        .expect("verifies a byte at a time");
    assert_eq!(seam::largest_request(SourceRole::Archive), 1);
    drop(guard);
    assert_eq!(
        read_all(contents.artifacts()[0].bytes()),
        b"a small native tool"
    );
}

#[test]
fn retained_disk_holds_at_the_high_water_mark() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let (_, archive_len) = archive_block(&bytes);
    let members: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    let high_water = bytes.len() as u64 + archive_len + members;

    let contents = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::RetainedDisk, high_water),
    )
    .expect("verifies at the high-water mark");
    assert_eq!(contents.scope_for_test().budget_high_water(), high_water);
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::RetainedDisk, high_water - 1),
    )
    .expect_err("refused");
    assert_eq!(
        limit_of(&error),
        (LimitResource::RetainedDisk, high_water - 1)
    );

    // A budget that fits the package but not its archive-block copy is
    // refused while that copy is written, before the walk starts.
    let guard = seam::install(Seam::new());
    let tight = bytes.len() as u64 + archive_len - 1;
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::RetainedDisk, tight))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::RetainedDisk, tight));
    assert!(seam_saw(SourceRole::ArchiveCopy));
    assert!(!seam_saw(SourceRole::Archive));
    drop(guard);
}

#[test]
fn verify_retained_charges_the_scope_it_is_given() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let (_, archive_len) = archive_block(&bytes);
    let members: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    let filler = vec![7u8; 1000];
    let needed = bytes.len() as u64 + archive_len + members;

    for (budget, fits) in [
        (filler.len() as u64 + needed, true),
        (filler.len() as u64 + needed - 1, false),
    ] {
        let dir = staging();
        let scope = RetentionScope::new(dir.path(), budget, NonZeroUsize::MIN.saturating_add(4095))
            .expect("a scope");
        let held = scope
            .snapshot_from(&mut filler.as_slice(), u64::MAX)
            .expect("the filler fits");
        let package = scope
            .snapshot_from(&mut bytes.as_slice(), u64::MAX)
            .expect("the package fits");
        let result = verify_retained(
            scope,
            package,
            &signer.trust(),
            &request(),
            TargetArch::X86_64,
            &ContentLimits::default(),
        );
        if fits {
            let contents = result.expect("fits the remaining budget");
            assert_eq!(
                contents.scope_for_test().budget_used(),
                filler.len() as u64 + bytes.len() as u64 + members
            );
        } else {
            assert_eq!(
                limit_of(&result.expect_err("refused")),
                (LimitResource::RetainedDisk, budget)
            );
        }
        drop(held);
    }
}

#[test]
fn nested_image_limits_surface_as_limits() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let image_len = arts[0].bytes.len() as u64;
    let error = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::ImageArchive, image_len - 1),
    )
    .expect_err("refused");
    assert_eq!(
        limit_of(&error),
        (LimitResource::ImageArchive, image_len - 1)
    );
    let error = verify_limited(&bytes, &signer, &limits(LimitResource::ConfigJson, 10))
        .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::ConfigJson, 10));
    // The per-operation decoded budget is shared across images: one layer
    // tar decodes to a header, a data block and the end marker, 2 KiB, which
    // is enough for either image alone but not for both.
    let per_operation = limits(LimitResource::DecodedLayersPerOperation, 2048);
    for single in [&arts[0], &arts[2]] {
        let lone = vec![single.clone()];
        verify_limited(&package(&signer, &lone), &signer, &per_operation).expect("one image fits");
    }
    let error = verify_limited(&bytes, &signer, &per_operation).expect_err("refused");
    assert_eq!(
        limit_of(&error),
        (LimitResource::DecodedLayersPerOperation, 2048)
    );
}

// ---------------------------------------------------------------------------
// I/O error representation
// ---------------------------------------------------------------------------

/// A caller's source that fails as arranged and records what was asked of it.
struct Scripted {
    inner: Cursor<Vec<u8>>,
    fail_seek: Option<ErrorKind>,
    /// Fails the first read at or past this offset.
    fail_read_at: Option<(u64, ErrorKind)>,
    /// Interrupts the first read at or past this offset, once.
    interrupt_at: Option<u64>,
    log: Rc<RefCell<SourceLog>>,
}

#[derive(Default)]
struct SourceLog {
    reads: Vec<(u64, usize)>,
    seeks: usize,
    interrupts: usize,
}

impl Scripted {
    fn new(bytes: Vec<u8>) -> (Scripted, Rc<RefCell<SourceLog>>) {
        let log = Rc::new(RefCell::new(SourceLog::default()));
        (
            Scripted {
                inner: Cursor::new(bytes),
                fail_seek: None,
                fail_read_at: None,
                interrupt_at: None,
                log: Rc::clone(&log),
            },
            log,
        )
    }
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self.inner.position();
        if let Some(at) = self.interrupt_at
            && pos >= at
        {
            self.interrupt_at = None;
            self.log.borrow_mut().interrupts += 1;
            return Err(ErrorKind::Interrupted.into());
        }
        if let Some((at, kind)) = self.fail_read_at {
            if pos >= at {
                return Err(io::Error::new(kind, "scripted read failure"));
            }
            let room = usize::try_from(at - pos).unwrap_or(usize::MAX);
            let len = buf.len().min(room);
            let n = self.inner.read(&mut buf[..len])?;
            self.log.borrow_mut().reads.push((pos, n));
            return Ok(n);
        }
        let n = self.inner.read(buf)?;
        self.log.borrow_mut().reads.push((pos, n));
        Ok(n)
    }
}

impl Seek for Scripted {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.log.borrow_mut().seeks += 1;
        if let Some(kind) = self.fail_seek {
            return Err(io::Error::new(kind, "scripted seek failure"));
        }
        self.inner.seek(pos)
    }
}

fn verify_source(
    source: Scripted,
    signer: &Signer,
    dir: &Path,
) -> Result<VerifiedContents, ContentError> {
    verify_contents(
        source,
        &signer.trust(),
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        dir,
    )
}

#[test]
fn a_failed_source_seek_is_source_seek_and_nothing_is_read() {
    let signer = Signer::new();
    let (mut source, log) = Scripted::new(package(&signer, &mixed()));
    source.fail_seek = Some(ErrorKind::PermissionDenied);
    let dir = staging();
    let error = verify_source(source, &signer, dir.path()).expect_err("refused");
    assert_eq!(
        io_of(&error),
        (IoOperation::SourceSeek, None, ErrorKind::PermissionDenied)
    );
    assert!(log.borrow().reads.is_empty());
    assert_empty(dir.path());
}

#[test]
fn a_failed_source_read_is_source_read_and_an_interruption_is_retried() {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let (mut source, _) = Scripted::new(bytes.clone());
    source.fail_read_at = Some((100, ErrorKind::ConnectionReset));
    let dir = staging();
    let error = verify_source(source, &signer, dir.path()).expect_err("refused");
    assert_eq!(
        io_of(&error),
        (IoOperation::SourceRead, None, ErrorKind::ConnectionReset)
    );
    assert_empty(dir.path());

    let (mut source, log) = Scripted::new(bytes.clone());
    source.interrupt_at = Some(100);
    let contents = verify_source(source, &signer, dir.path()).expect("an interruption is retried");
    assert_eq!(log.borrow().interrupts, 1);
    assert_eq!(read_all(contents.package_bytes()), bytes);
}

#[test]
fn the_source_is_read_once_in_a_single_pass() {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let (source, log) = Scripted::new(bytes.clone());
    let dir = staging();
    verify_source(source, &signer, dir.path()).expect("verifies");
    let log = log.borrow();
    assert_eq!(log.seeks, 1);
    let mut expected = 0u64;
    for (pos, n) in &log.reads {
        assert_eq!(*pos, expected, "reads are contiguous");
        expected += *n as u64;
    }
    assert_eq!(expected, bytes.len() as u64);
}

#[test]
fn an_unsafe_or_missing_staging_parent_is_inspect_staging_parent() {
    use std::os::unix::fs::PermissionsExt as _;

    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let root = staging();

    let real = root.path().join("real");
    std::fs::create_dir(&real).expect("a directory");
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink");
    let error = verify(
        &bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        &link,
    )
    .expect_err("refused");
    assert_eq!(
        io_of(&error),
        (
            IoOperation::InspectStagingParent,
            Some(link.as_path()),
            ErrorKind::InvalidInput
        )
    );

    let sticky = root.path().join("sticky");
    std::fs::create_dir(&sticky).expect("a directory");
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).expect("chmod");
    let error = verify(
        &bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        &sticky,
    )
    .expect_err("refused");
    let (operation, path, kind) = io_of(&error);
    assert_eq!(operation, IoOperation::InspectStagingParent);
    assert_eq!(kind, ErrorKind::PermissionDenied);
    assert!(path.is_some_and(|path| path.starts_with(root.path())));

    let missing = root.path().join("missing");
    let error = verify(
        &bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        &missing,
    )
    .expect_err("refused");
    let (operation, path, kind) = io_of(&error);
    assert_eq!(operation, IoOperation::InspectStagingParent);
    assert_eq!(kind, ErrorKind::NotFound);
    assert!(path.is_some_and(|path| path.starts_with(root.path())));
}

#[test]
fn a_failed_private_directory_is_create_staging_at_the_staging_parent() {
    use crate::retain::fault::{self, Step};

    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let dir = staging();
    let _guard =
        fault::install(fault::Seam::new().fail(Step::MakeDirectory, ErrorKind::PermissionDenied));
    let error = verify(
        &bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        dir.path(),
    )
    .expect_err("refused");
    assert_eq!(
        io_of(&error),
        (
            IoOperation::CreateStaging,
            Some(dir.path()),
            ErrorKind::PermissionDenied
        )
    );
    assert_empty(dir.path());
}

#[test]
fn a_full_filesystem_writing_a_member_is_write_snapshot_not_the_budget() {
    use crate::retain::fault::{self, Step};

    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let dir = staging();
    // The package snapshot and the archive-block copy are one write each;
    // the third write is the first member's.
    let _guard =
        fault::install(fault::Seam::new().fail_nth(Step::WriteSnapshot, 3, ErrorKind::StorageFull));
    let error = verify(
        &bytes,
        &signer.trust(),
        &request(),
        &ContentLimits::default(),
        dir.path(),
    )
    .expect_err("refused");
    let (operation, path, kind) = io_of(&error);
    assert_eq!(operation, IoOperation::WriteSnapshot);
    assert_eq!(kind, ErrorKind::StorageFull);
    let path = path.expect("the snapshot's path");
    assert!(path.starts_with(dir.path()));
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("snap-2")
    );
    assert_empty(dir.path());
}

#[test]
fn a_snapshot_mismatch_is_write_snapshot_at_the_snapshot_name() {
    use crate::retain::SnapshotMismatchKind;

    let name = PathBuf::from("/staging/.deploy-core-retain-x/snap-3");
    for kind in [
        SnapshotMismatchKind::Identity,
        SnapshotMismatchKind::Length {
            expected: 3,
            actual: 4,
        },
    ] {
        let error = from_retention(
            RetentionError::SnapshotMismatch {
                path: name.clone(),
                kind,
            },
            &RetentionSite {
                read_source: IoOperation::ReadSnapshot,
                max_len: ContentLimits::default().resource_limit(LimitResource::Package),
                staging_parent: None,
            },
        );
        assert_eq!(
            io_of(&error),
            (
                IoOperation::WriteSnapshot,
                Some(name.as_path()),
                ErrorKind::Other
            )
        );
    }
}

/// Verifies the mixed fixture with the `n`th `op` of a `role` source failing
/// with `kind`, and returns the refusal.
fn retained_fault(role: SourceRole, op: Op, n: usize, kind: ErrorKind) -> ContentError {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let _guard = seam::install(Seam::new().fail_nth(role, op, n, kind));
    verify_limited(&bytes, &signer, &ContentLimits::default()).expect_err("refused")
}

#[test]
fn every_retained_read_and_seek_failure_is_read_snapshot() {
    let cases = [
        // Bounded authentication: the seek locating the footer, the seek to
        // the manifest block after the two footer candidates, and the read
        // of the manifest block after theirs.
        (SourceRole::Package, Op::Seek, 1),
        (SourceRole::Package, Op::Seek, 4),
        (SourceRole::Package, Op::Read, 3),
        // The archive-block copy: its seek and its first read.
        (SourceRole::ArchiveCopy, Op::Seek, 1),
        (SourceRole::ArchiveCopy, Op::Read, 1),
        // The outer walk: its seek, its first read, and the read that meets
        // the end of the block, both under the zstd decoder.
        (SourceRole::Archive, Op::Seek, 1),
        (SourceRole::Archive, Op::Read, 1),
        (SourceRole::Archive, Op::Read, 2),
        // Image validation: the first read and seek, and a later read.
        (SourceRole::Image, Op::Read, 1),
        (SourceRole::Image, Op::Seek, 1),
        (SourceRole::Image, Op::Read, 5),
    ];
    for (at, (role, op, n)) in cases.into_iter().enumerate() {
        let kind = if at % 2 == 0 {
            ErrorKind::Other
        } else {
            ErrorKind::PermissionDenied
        };
        let error = retained_fault(role, op, n, kind);
        assert_eq!(
            io_of(&error),
            (IoOperation::ReadSnapshot, None, kind),
            "{role:?} {op:?} #{n}: {error:?}"
        );
    }
}

#[test]
fn a_retained_failure_in_bounded_authentication_is_its_io_case() {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let dir = staging();
    let scope = RetentionScope::new(dir.path(), 1 << 30, NonZeroUsize::MIN.saturating_add(4095))
        .expect("a scope");
    let retained = scope
        .snapshot_from(&mut bytes.as_slice(), u64::MAX)
        .expect("a snapshot");
    for (op, n) in [(Op::Seek, 1), (Op::Seek, 4), (Op::Read, 3)] {
        let _guard = seam::install(Seam::new().fail_nth(
            SourceRole::Package,
            op,
            n,
            ErrorKind::PermissionDenied,
        ));
        let error = crate::verify::verify_package_bounded(
            RetainedSource::new(retained.reader(), SourceRole::Package),
            &signer.trust(),
            &request(),
            ContainerBounds {
                max_manifest_len: u64::MAX,
                max_archive_len: u64::MAX,
            },
        )
        .expect_err("refused");
        match error {
            BoundedVerifyError::Io(error) => {
                assert_eq!(error.kind(), ErrorKind::PermissionDenied);
                // The original error, not the wrapper it travelled in.
                assert!(
                    error
                        .get_ref()
                        .is_none_or(|inner| !inner.is::<RetainedIoFault>())
                );
            }
            other => panic!("{op:?} #{n}: expected Io, got {other:?}"),
        }
    }
}

#[test]
fn a_framing_end_of_file_is_a_verdict_not_retained_io() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let manifest_len = manifest_bytes(&arts).len();

    // Bytes cut out of the manifest block, the footer kept.
    let mut short = bytes.clone();
    short.drain(manifest_len / 2..manifest_len / 2 + 10);
    // And a package cut off before its footer.
    let cut = bytes[..bytes.len() - 20].to_vec();
    for truncated in [short, cut] {
        let guard = seam::install(Seam::new());
        let error = same_verdict(&truncated, &signer.trust(), &request());
        assert!(matches!(error, VerifyError::Payload(_)), "got {error:?}");
        assert!(
            seam::observed().iter().all(|seen| seen.outcome.is_ok()),
            "the retained reader returned only Ok"
        );
        drop(guard);
    }
}

#[test]
fn the_legacy_verifier_still_maps_a_read_failure_to_payload_io() {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let (mut source, _) = Scripted::new(bytes);
    source.fail_read_at = Some((0, ErrorKind::PermissionDenied));
    let error = verify_package(source, &signer.trust(), &request())
        .map(|_| ())
        .expect_err("refused");
    assert!(matches!(
        error,
        VerifyError::Payload(PayloadError::Io(ref e)) if e.kind() == ErrorKind::PermissionDenied
    ));
}

#[test]
fn bounded_authentication_reads_the_footer_then_the_manifest_then_the_envelope() {
    // Pins which operation each injected Package fault above lands on.
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let manifest_len = manifest_bytes(&arts).len() as u64;
    let guard = seam::install(Seam::new());
    verify_limited(&bytes, &signer, &ContentLimits::default()).expect("verifies");
    let package: Vec<(Op, u64)> = seam::observed()
        .into_iter()
        .filter(|seen| seen.role == SourceRole::Package)
        .map(|seen| (seen.op, seen.outcome.expect("ok")))
        .collect();
    drop(guard);
    let len = bytes.len() as u64;
    assert_eq!(
        package.get(..7),
        Some(
            &[
                (Op::Seek, len),
                (Op::Seek, len - 41),
                (Op::Read, 41),
                (Op::Seek, len - 73),
                (Op::Read, 73),
                (Op::Seek, 0),
                (Op::Read, manifest_len),
            ][..]
        )
    );
}

// ---------------------------------------------------------------------------
// The outer walk, shared with the legacy extraction
// ---------------------------------------------------------------------------

/// Malformed archives for two honest members, each with the verdict both
/// walks must reach.
/// One malformed archive: its name, the manifest it is signed with, the
/// compressed archive block, and the verdict both walks must reach.
type CorpusCase<'a> = (&'static str, &'a [u8], Vec<u8>, fn(&VerifyError) -> bool);

// One table of cases reads best whole; splitting it would scatter the corpus.
#[allow(clippy::too_many_lines)]
#[test]
fn old_and_new_walks_agree_on_a_corpus_of_malformed_archives() {
    let signer = Signer::new();
    let a = Art::native("bin/a", b"alpha");
    let b = Art::native("bin/b", b"bravo bravo");
    let arts = vec![a.clone(), b.clone()];
    let manifest = manifest_bytes(&arts);
    let honest = tar(&[
        Entry::File("bin/a", &a.bytes),
        Entry::File("bin/b", &b.bytes),
    ]);

    let mut long_manifest: serde_json::Value = serde_json::from_slice(&manifest).expect("json");
    long_manifest["archive_members"][0]["length"] = serde_json::Value::from(a.bytes.len() + 1);
    let long_manifest = serde_json::to_vec(&long_manifest).expect("json");

    let mut truncated = tar_unfinished(&[
        Entry::File("bin/a", &a.bytes),
        Entry::File("bin/b", &b.bytes),
    ]);
    let truncated_header = truncated[..512 + 512 + 100].to_vec();
    truncated.truncate(512 + 512 + 512 + 4);
    let mut trailing = honest.clone();
    trailing.extend_from_slice(b"junk");
    let mut concatenated = honest.clone();
    concatenated.extend_from_slice(&tar(&[Entry::File("bin/a", &a.bytes)]));
    let compressed = zstd(&honest);
    let cut_frame = zstd(&honest)[..compressed.len() / 2].to_vec();

    let cases: Vec<CorpusCase<'_>> = vec![
        (
            "unsafe path",
            &manifest,
            zstd(&tar(&[
                Entry::RawName(b"../evil", b"x"),
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| matches!(e, VerifyError::Payload(PayloadError::UnsafeMemberPath(_))),
        ),
        (
            "duplicate",
            &manifest,
            zstd(&tar(&[
                Entry::File("bin/a", &a.bytes),
                Entry::File("bin/a", &a.bytes),
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| matches!(e, VerifyError::Payload(PayloadError::DuplicateMember(_))),
        ),
        (
            "unlisted",
            &manifest,
            zstd(&tar(&[
                Entry::File("bin/a", &a.bytes),
                Entry::File("bin/b", &b.bytes),
                Entry::File("bin/c", b"c"),
            ])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::MemberNotInManifest(_))
                )
            },
        ),
        (
            "missing",
            &manifest,
            zstd(&tar(&[Entry::File("bin/a", &a.bytes)])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::ArtifactMissingFromArchive(_))
                )
            },
        ),
        (
            "reordered",
            &manifest,
            zstd(&tar(&[
                Entry::File("bin/b", &b.bytes),
                Entry::File("bin/a", &a.bytes),
            ])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::MemberListMismatch { .. })
                )
            },
        ),
        ("wrong length", &long_manifest, zstd(&honest), |e| {
            matches!(
                e,
                VerifyError::Payload(PayloadError::MemberListMismatch { .. })
            )
        }),
        (
            "wrong hash",
            &manifest,
            zstd(&tar(&[
                Entry::File("bin/a", b"ALPHA"),
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| matches!(e, VerifyError::ManifestHashMismatch { .. }),
        ),
        (
            "pax path",
            &manifest,
            zstd(&tar(&[
                Entry::PaxPath {
                    header: "bin/x",
                    path: "bin/a",
                    data: &a.bytes,
                },
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::NameOverridingHeader { .. })
                )
            },
        ),
        (
            "gnu long name",
            &manifest,
            zstd(&tar(&[
                Entry::GnuLongName {
                    header: "bin/x",
                    path: "bin/a",
                    data: &a.bytes,
                },
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::NameOverridingHeader { .. })
                )
            },
        ),
        (
            "pax size",
            &manifest,
            zstd(&tar(&[
                Entry::PaxSize("bin/a", &a.bytes),
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::SizeOverridingHeader { .. })
                )
            },
        ),
        (
            "symlink",
            &manifest,
            zstd(&tar(&[
                Entry::Symlink("bin/a"),
                Entry::File("bin/b", &b.bytes),
            ])),
            |e| {
                matches!(
                    e,
                    VerifyError::Payload(PayloadError::UnsupportedEntryType { .. })
                )
            },
        ),
        (
            // A member cut short reads as fewer bytes than it holds.
            "truncated member",
            &manifest,
            zstd(&truncated),
            |e| matches!(e, VerifyError::ManifestHashMismatch { .. }),
        ),
        (
            "truncated header",
            &manifest,
            zstd(&truncated_header),
            |e| matches!(e, VerifyError::Payload(PayloadError::Io(_))),
        ),
        ("trailing bytes", &manifest, zstd(&trailing), |e| {
            matches!(e, VerifyError::Payload(PayloadError::TrailingArchiveBytes))
        }),
        ("concatenated tar", &manifest, zstd(&concatenated), |e| {
            matches!(e, VerifyError::Payload(PayloadError::TrailingArchiveBytes))
        }),
        ("truncated frame", &manifest, cut_frame, |e| {
            matches!(e, VerifyError::Payload(PayloadError::Io(_)))
        }),
    ];
    for (name, manifest, archive, expected) in cases {
        let bytes = signer.container(manifest, &archive);
        let error = same_verdict(&bytes, &signer.trust(), &plain_request());
        assert!(expected(&error), "{name}: {error:?}");
    }
}

#[test]
fn the_legacy_extraction_applies_no_limit_of_the_new_path() {
    // A member far larger than a small injected limit still extracts, and
    // the legacy verifier reads a manifest and archive the bounded read
    // would refuse.
    let signer = Signer::new();
    let arts = vec![Art::native("bin/big", &vec![3u8; 64 << 10])];
    let bytes = package(&signer, &arts);
    let small = limits(LimitResource::OuterUncompressedTotal, 1024)
        .with_limit(LimitResource::RawManifest, 16)
        .and_then(|limits| limits.with_limit(LimitResource::CompressedArchive, 16))
        .expect("lower limits");
    assert_eq!(
        limit_of(&verify_limited(&bytes, &signer, &small).expect_err("refused")).0,
        LimitResource::RawManifest
    );
    let mut verified = verify_package(Cursor::new(&bytes), &signer.trust(), &plain_request())
        .expect("the legacy verifier takes no bounds");
    crate::payload::read_package_container(Cursor::new(&bytes), &crate::verify::ENVELOPE_BOUNDS)
        .expect("the legacy container read takes no bounds");
    let dir = staging();
    let extracted = verified.extract_to(dir.path()).expect("extracts");
    assert_eq!(
        std::fs::read(&extracted[0].path).expect("the published file"),
        arts[0].bytes
    );
}

// ---------------------------------------------------------------------------
// Staging, evidence and immutability
// ---------------------------------------------------------------------------

#[test]
fn a_failure_after_the_first_member_or_the_last_image_leaves_nothing_behind() {
    let signer = Signer::new();
    let arts = mixed();
    let mut tampered = arts.clone();
    tampered[3].bytes = b"TAMPERED".to_vec();
    let after_members = signer.container(&manifest_bytes(&arts), &archive(&tampered));
    let mut bad_last = arts.clone();
    bad_last[2] = wrong_config(bad_last[2].clone());
    let after_images = package(&signer, &bad_last);
    for bytes in [after_members, after_images] {
        let dir = staging();
        verify(
            &bytes,
            &signer.trust(),
            &request(),
            &ContentLimits::default(),
            dir.path(),
        )
        .expect_err("refused");
        assert_empty(dir.path());
    }
}

#[test]
fn no_snapshot_name_remains_when_image_validation_starts() {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let listed = Rc::new(RefCell::new(None));
    let seen = Rc::clone(&listed);
    let _guard = seam::install(Seam::new().before_images(move |private| {
        let names: Vec<_> = std::fs::read_dir(private)
            .expect("the private directory lists")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        *seen.borrow_mut() = Some(names);
    }));
    verify_limited(&bytes, &signer, &ContentLimits::default()).expect("verifies");
    assert_eq!(listed.borrow().as_deref(), Some(&[][..]));
}

#[test]
fn readers_interleave_with_independent_cursors() {
    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let contents = verify_default(&bytes, &signer).expect("verifies");
    let VerifiedImages::Present(images) = contents.images() else {
        panic!("expected images");
    };
    let image = images.iter().next().expect("an image");
    let artifact = &contents.artifacts()[0];
    let mut readers = [
        contents.package_bytes().reader(),
        contents.package_bytes().reader(),
        artifact.bytes().reader(),
        image.archive().reader(),
    ];
    let mut outputs = vec![Vec::new(); readers.len()];
    loop {
        let mut progressed = false;
        for (reader, out) in readers.iter_mut().zip(outputs.iter_mut()) {
            let mut chunk = [0u8; 7];
            let n = reader.read(&mut chunk).expect("reads");
            out.extend_from_slice(&chunk[..n]);
            progressed |= n > 0;
        }
        if !progressed {
            break;
        }
    }
    assert_eq!(outputs[0], bytes);
    assert_eq!(outputs[1], bytes);
    assert_eq!(outputs[2], read_all(artifact.bytes()));
    assert_eq!(
        outputs[3], outputs[2],
        "the image is its artifact's snapshot"
    );
}

/// A file-backed source that runs `mutate` on the backing file once `after`
/// bytes have been delivered, and keeps what it delivered.
struct Racing {
    file: std::fs::File,
    after: u64,
    delivered: Vec<u8>,
    mutate: Option<Box<dyn FnOnce()>>,
}

impl Read for Racing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.delivered.len() as u64 >= self.after
            && let Some(mutate) = self.mutate.take()
        {
            mutate();
        }
        let room = usize::try_from(self.after.saturating_sub(self.delivered.len() as u64))
            .unwrap_or(usize::MAX);
        let len = if room == 0 {
            buf.len()
        } else {
            buf.len().min(room)
        };
        let n = self.file.read(&mut buf[..len])?;
        self.delivered.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Seek for Racing {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

#[test]
fn a_source_changing_during_the_snapshot_yields_a_refusal_or_exactly_what_was_read() {
    use std::os::unix::fs::FileExt as _;

    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let manifest_len = manifest_bytes(&arts).len() as u64;
    let dir = staging();
    let path = dir.path().join("package.pkg");
    // (after, offset, accepted): a byte already read changes, then one not
    // yet read.
    for (after, offset, accepted) in [(manifest_len + 10, 5, true), (10, manifest_len / 2, false)] {
        std::fs::write(&path, &bytes).expect("the package file");
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("a second handle");
        let mut source = Racing {
            file: std::fs::File::open(&path).expect("the package opens"),
            after,
            delivered: Vec::new(),
            mutate: Some(Box::new(move || {
                writer.write_all_at(b"#", offset).expect("mutates");
            })),
        };
        let parent = staging();
        match verify_contents(
            &mut source,
            &signer.trust(),
            &request(),
            TargetArch::X86_64,
            &ContentLimits::default(),
            parent.path(),
        ) {
            Ok(contents) => {
                assert!(accepted);
                assert_eq!(read_all(contents.package_bytes()), source.delivered);
                assert_eq!(source.delivered, bytes, "the change came after its bytes");
            }
            Err(error) => {
                assert!(!accepted);
                assert!(matches!(
                    error,
                    ContentError::Verify(VerifyError::BadSignature)
                ));
                assert_ne!(source.delivered, bytes);
                assert_empty(parent.path());
            }
        }
        assert!(source.mutate.is_none(), "the mutation ran");
        std::fs::remove_file(&path).expect("removed");
    }
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

#[test]
fn publication_is_charged_to_the_remaining_budget() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let (_, archive_len) = archive_block(&bytes);
    let members: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    let high_water = bytes.len() as u64 + archive_len + members;
    let dir = staging();

    // The archive block is smaller than the package, so at the verification's
    // own high-water mark there is no room for the package's temporary copy.
    let contents = verify_limited(
        &bytes,
        &signer,
        &limits(LimitResource::RetainedDisk, high_water),
    )
    .expect("verifies");
    let error = contents
        .publish_package(&dir.path().join("out.pkg"))
        .expect_err("refused");
    assert!(matches!(error, PublicationError::DiskBudgetExceeded { limit } if limit == high_water));
    assert_empty(dir.path());

    let roomy = bytes.len() as u64 * 2 + members;
    let contents = verify_limited(&bytes, &signer, &limits(LimitResource::RetainedDisk, roomy))
        .expect("verifies");
    let receipt = contents
        .publish_package(&dir.path().join("out.pkg"))
        .expect("publishes");
    assert_eq!(receipt.len(), bytes.len() as u64);
}

#[test]
fn a_failure_after_the_link_is_publish_durability() {
    use crate::retain::fault::{self, Step};

    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let contents = verify_default(&bytes, &signer).expect("verifies");
    let dir = staging();
    let destination = dir.path().join("out.pkg");
    let _guard = fault::install(fault::Seam::new().fail(Step::SyncParent, ErrorKind::Other));
    let error = contents.publish_package(&destination).expect_err("refused");
    assert!(matches!(error, PublicationError::PublishDurability { .. }));
    assert_eq!(std::fs::read(&destination).expect("published"), bytes);
}

#[test]
fn evidence_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VerifiedContents>();
    assert_send_sync::<VerifiedArtifact>();
    assert_send_sync::<VerifiedImage>();
    assert_send_sync::<VerifiedImageSet<'static>>();
    assert_send_sync::<VerifiedImages<'static>>();
    assert_send_sync::<ContentError>();
}

#[test]
fn debug_shows_lengths_digests_and_paths_only() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let contents = verify_default(&bytes, &signer).expect("verifies");
    let debug = format!("{contents:?}");
    assert!(debug.contains("images/db.tar"));
    assert!(debug.contains(&crate::payload::to_hex(contents.package_bytes().sha256())));
    assert!(!debug.contains("services"), "no artifact content: {debug}");
    assert!(
        !debug.contains(".deploy-core-retain-"),
        "no staging path: {debug}"
    );
}

#[test]
fn the_legacy_extraction_still_renames_all_or_nothing_then_publishes_partially() {
    use std::os::unix::fs::PermissionsExt as _;

    let signer = Signer::new();
    let arts = vec![
        Art::native("bin/a", b"alpha"),
        Art::native("bin/b", b"bravo"),
    ];
    let bytes = package(&signer, &arts);
    let extract = |dest: &Path| {
        verify_package(Cursor::new(&bytes), &signer.trust(), &plain_request())
            .expect("verifies")
            .extract_to(dest)
    };

    // Published by rename: each file keeps the owner-only mode it was staged
    // with, and nothing else is left in the destination.
    let dir = staging();
    let extracted = extract(dir.path()).expect("extracts");
    for (file, art) in extracted.iter().zip(&arts) {
        assert_eq!(std::fs::read(&file.path).expect("published"), art.bytes);
        let mode = std::fs::metadata(&file.path)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let top: Vec<_> = std::fs::read_dir(dir.path())
        .expect("lists")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(top, ["bin"]);

    // All or nothing before the publish step: a tampered last member leaves
    // nothing behind.
    let mut tampered = arts.clone();
    tampered[1].bytes = b"BRAVO".to_vec();
    let bad = signer.container(&manifest_bytes(&arts), &archive(&tampered));
    let dir = staging();
    let error = verify_package(Cursor::new(&bad), &signer.trust(), &plain_request())
        .expect("verifies")
        .extract_to(dir.path())
        .expect_err("refused");
    assert!(matches!(error, VerifyError::ManifestHashMismatch { .. }));
    assert_empty(dir.path());

    // A failure during the publish step may leave earlier members published.
    let dir = staging();
    std::fs::create_dir_all(dir.path().join("bin/b/occupied")).expect("a blocking directory");
    let error = extract(dir.path()).expect_err("the second rename fails");
    assert!(matches!(error, VerifyError::Payload(PayloadError::Io(_))));
    assert_eq!(
        std::fs::read(dir.path().join("bin/a")).expect("the first member was published"),
        b"alpha"
    );
    let top: Vec<_> = std::fs::read_dir(dir.path())
        .expect("lists")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(top, ["bin"], "no staging directory survives");
}
