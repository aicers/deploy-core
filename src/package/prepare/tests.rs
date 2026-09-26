use std::io::{Cursor, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SecureRandom;
use sha2::{Digest, Sha256};

use super::super::bounded::seam as bounded_seam;
use super::super::contents::tests::fixture::{
    Art, COMMIT, COMPONENT, NAMESPACE, Signer, VERSION, plain_request,
};
use super::super::prepare_fixture::{
    Dir, Prepared, Ready, container, entries, inputs, limits, prepare, prepare_with, read_all,
    request, six_images, verify,
};
use super::super::source::seam::{self as source_seam, Op, Seam as SourceSeam};
use super::super::{PublicationOperation, VerifiedImages};
use super::*;
use crate::payload::ArtifactInput;
use crate::retain::fault::{self, Seam, Step};
use crate::verify::statement_order::recorded;
use crate::verify::{Statement, TRUST_TARGET, VerifyError, verify_package};

/// The bytes a finalized package adds around M and A.
const OVERHEAD: u64 = 201;

#[track_caller]
fn limit_of(error: &PackageWriteError) -> (LimitResource, u64) {
    match error {
        PackageWriteError::Content(ContentError::LimitExceeded { resource, limit }) => {
            (*resource, *limit)
        }
        other => panic!("expected a limit, got {other:?}"),
    }
}

#[track_caller]
fn io_of(error: &PackageWriteError) -> (IoOperation, Option<PathBuf>, ErrorKind) {
    match error {
        PackageWriteError::Content(ContentError::Io {
            operation,
            path,
            source,
        }) => (*operation, path.clone(), source.kind()),
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

/// Asserts `error` is the content verdict `expected`, variant and fields.
#[track_caller]
fn same_content_verdict(error: &PackageWriteError, expected: &ContentError) {
    match error {
        PackageWriteError::Content(actual) => {
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        }
        other => panic!("expected a content verdict, got {other:?}"),
    }
}

fn manifest_len(ready: &Ready) -> u64 {
    u64::try_from(ready.package.manifest_bytes().len()).unwrap()
}

fn natives() -> Vec<Art> {
    vec![
        Art::native("bin/tool", b"\x7fELF tool"),
        Art::compose("compose.yaml", b"services: {}\n"),
    ]
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("random bytes");
    bytes
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

#[test]
fn six_images_prepare_into_a_consistent_binding_that_final_verification_accepts() {
    let signer = Signer::new();
    for arch in [TargetArch::X86_64, TargetArch::Aarch64] {
        let arts = six_images(arch);
        let ready = prepare_with(&arts, &request(), arch, &ContentLimits::default()).ok();
        let package = &ready.package;
        let binding = package.binding();

        assert_eq!(binding.schema(), 1);
        assert_eq!(binding.target(), COMPONENT);
        assert_eq!(binding.version(), VERSION);
        assert_eq!(binding.commit(), COMMIT);
        assert_eq!(binding.target_arch(), arch);
        assert_eq!(binding.namespace(), Some(NAMESPACE));
        assert_eq!(binding.trust_epoch(), None);

        let manifest = package.manifest_bytes();
        let archive = read_all(package.archive());
        let manifest_digest: [u8; 32] = Sha256::digest(manifest).into();
        let archive_digest: [u8; 32] = Sha256::digest(&archive).into();
        assert_eq!(binding.manifest_sha256(), &manifest_digest);
        assert_eq!(binding.manifest_length(), manifest_len(&ready));
        assert_eq!(binding.archive_sha256(), &archive_digest);
        assert_eq!(package.archive().sha256(), &archive_digest);
        assert_eq!(binding.archive_length(), package.archive().len());
        assert_eq!(binding.archive_length(), archive.len() as u64);

        // Only A is kept alive.
        let scope = package.scope_for_test();
        assert_eq!(package.retained_disk_bytes(), package.archive().len());
        assert_eq!(scope.live_snapshots(), 1);
        assert_eq!(scope.budget_used(), package.archive().len());

        // M ‖ A ‖ signature ‖ key ID ‖ footer passes final verification.
        let bytes = container(&signer, package);
        let contents = verify(&bytes, &signer.trust(), &request(), arch)
            .expect("the assembled container verifies");
        let package_bytes = read_all(contents.package_bytes());
        assert_eq!(package_bytes, bytes);
        assert_eq!(&package_bytes[..manifest.len()], manifest);
        assert_eq!(
            &package_bytes[manifest.len()..manifest.len() + archive.len()],
            &archive[..]
        );
        let VerifiedImages::Present(images) = contents.images() else {
            panic!("the images are present");
        };
        assert_eq!(images.len(), 6);
        for (verified, art) in contents.artifacts().iter().zip(&arts) {
            assert_eq!(read_all(verified.bytes()), art.bytes);
        }
    }
}

#[test]
fn the_manifest_is_the_single_serialization_of_the_derived_manifest() {
    let arts = super::super::contents::tests::fixture::mixed();
    let ready = prepare(&arts, &ContentLimits::default()).ok();
    let measured: Vec<(&ArtifactInput, String, u64)> = ready
        .inputs
        .iter()
        .zip(&arts)
        .map(|(input, art)| {
            (
                input,
                crate::payload::sha256_hex(&art.bytes),
                art.bytes.len() as u64,
            )
        })
        .collect();
    let manifest = derive_manifest(None, None, &measured).expect("a manifest");
    assert_eq!(
        ready.package.manifest_bytes(),
        serde_json::to_vec(&manifest).expect("serializes")
    );
}

#[test]
fn opaque_native_bytes_prepare_with_their_snapshot_digest() {
    let bytes = random_bytes(100_000);
    let arts = vec![Art::native("bin/blob", &bytes)];
    let ready = prepare_with(
        &arts,
        &plain_request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    let parsed =
        PayloadManifest::parse(ready.package.manifest_bytes(), FORMAT_VERSION).expect("M parses");
    let artifact = &parsed.artifacts()[0];
    assert_eq!(artifact.sha256, crate::payload::sha256_hex(&bytes));
    let members = parsed.archive_members().expect("members");
    assert_eq!(members[0].length, bytes.len() as u64);
}

#[test]
fn the_namespace_is_recorded_only_when_the_request_carries_one() {
    let plain = prepare_with(
        &natives(),
        &plain_request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    assert_eq!(plain.package.binding().namespace(), None);
    let namespaced = prepare(&natives(), &ContentLimits::default()).ok();
    assert_eq!(namespaced.package.binding().namespace(), Some(NAMESPACE));
}

fn trust_art() -> Art {
    let mut art = Art::native("trust-set.json", b"{}");
    art.kind = crate::manifest::ArtifactKind::StaticAssets;
    art.component = TRUST_TARGET.to_string();
    art.version = "8".to_string();
    art
}

#[test]
fn a_reserved_trust_package_prepares_only_under_a_trust_request() {
    let signer = Signer::new();
    let arts = vec![trust_art()];
    let for_trust = VerifyRequest::for_trust("8", COMMIT, 3).expect("a request");
    let ready = prepare_with(
        &arts,
        &for_trust,
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    let binding = ready.package.binding();
    assert_eq!(binding.target(), TRUST_TARGET);
    assert_eq!(binding.trust_epoch(), Some(3));
    assert_eq!(binding.namespace(), None);

    // A stale epoch is not decided here: final verification refuses it under
    // an active epoch of 10, and preparation does not look.
    let stale = VerifyRequest::for_trust("8", COMMIT, 10).expect("a request");
    prepare_with(&arts, &stale, TargetArch::X86_64, &ContentLimits::default()).ok();
    let bytes = container(&signer, &ready.package);
    assert!(matches!(
        verify(
            &bytes,
            &signer.trust_with(Vec::new(), 10),
            &stale,
            TargetArch::X86_64
        ),
        Err(ContentError::Verify(VerifyError::StaleTrustSet { .. }))
    ));

    // Under an ordinary request the exact-target check refuses it, exactly
    // as the verifier does.
    let other = VerifyRequest::for_package(COMPONENT, "8", COMMIT).expect("a request");
    let error = prepare_with(&arts, &other, TargetArch::X86_64, &ContentLimits::default()).err();
    let expected = verify_package(Cursor::new(&bytes), &signer.trust(), &other)
        .expect_err("the verifier refuses it");
    assert!(matches!(expected, VerifyError::TargetMismatch { .. }));
    same_content_verdict(&error, &ContentError::Verify(expected));
}

#[test]
fn preparation_decides_no_withdrawal_and_runs_no_trust_set_check() {
    let signer = Signer::new();
    let arts = super::super::contents::tests::fixture::mixed();
    let (prepared, order) = recorded(|| prepare(&arts, &ContentLimits::default()));
    let ready = prepared.ok();
    assert_eq!(
        order,
        [
            Statement::Completeness,
            Statement::Identifiers,
            Statement::Target,
            Statement::Images
        ]
    );
    let withdrawn = signer.trust_with(
        vec![(
            COMPONENT.to_string(),
            VERSION.to_string(),
            COMMIT.to_string(),
        )],
        0,
    );
    let bytes = container(&signer, &ready.package);
    assert!(matches!(
        verify(&bytes, &withdrawn, &request(), TargetArch::X86_64),
        Err(ContentError::Verify(VerifyError::WithdrawnBuild { .. }))
    ));
}

#[test]
fn identical_inputs_prepare_identical_bytes() {
    let arts = super::super::contents::tests::fixture::mixed();
    let first = prepare(&arts, &ContentLimits::default()).ok();
    let second = prepare(&arts, &ContentLimits::default()).ok();
    assert_eq!(
        first.package.manifest_bytes(),
        second.package.manifest_bytes()
    );
    assert_eq!(
        read_all(first.package.archive()),
        read_all(second.package.archive())
    );
    assert_eq!(first.package.binding(), second.package.binding());
}

#[test]
fn a_prepared_package_is_send_and_sync_and_debugs_only_its_binding() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PreparedPackage>();
    let ready = prepare(&natives(), &ContentLimits::default()).ok();
    let debug = format!("{:?}", ready.package);
    assert!(debug.starts_with("PreparedPackage { binding: PreparationBinding {"));
    assert!(!debug.contains("manifest_bytes"));
}

// ---------------------------------------------------------------------------
// Content refusals
// ---------------------------------------------------------------------------

/// Prepares `arts` under `request` for `arch`, and verifies the container of
/// the same content — prepared under the fixture's own request — under the
/// same `request`, returning both refusals.
fn both_refuse(
    arts: &[Art],
    request: &VerifyRequest,
    arch: TargetArch,
) -> (PackageWriteError, ContentError) {
    let signer = Signer::new();
    let manifest = super::super::contents::tests::fixture::manifest_bytes(arts);
    let archive = super::super::contents::tests::fixture::archive(arts);
    let bytes = signer.container(&manifest, &archive);
    let expected = verify(&bytes, &signer.trust(), request, arch).expect_err("verify refuses");
    let error = prepare_with(arts, request, arch, &ContentLimits::default()).err();
    (error, expected)
}

#[test]
fn a_wrong_build_or_namespace_is_the_verifiers_verdict() {
    let arts = super::super::contents::tests::fixture::mixed();
    let requests = [
        VerifyRequest::for_namespaced_package("other-app", VERSION, COMMIT, NAMESPACE),
        VerifyRequest::for_namespaced_package(COMPONENT, "2.0.0", COMMIT, NAMESPACE),
        VerifyRequest::for_namespaced_package(
            COMPONENT,
            VERSION,
            "89abcdef0123456789abcdef0123456789abcdef",
            NAMESPACE,
        ),
        VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, "other-product"),
    ];
    for request in requests {
        let request = request.expect("a request");
        let (error, expected) = both_refuse(&arts, &request, TargetArch::X86_64);
        same_content_verdict(&error, &expected);
    }
}

#[test]
fn an_architecture_mismatch_is_the_verifiers_verdict() {
    let arts = super::super::contents::tests::fixture::mixed();
    let (error, expected) = both_refuse(&arts, &request(), TargetArch::Aarch64);
    assert!(matches!(
        expected,
        ContentError::ArchitectureMismatch { .. }
    ));
    same_content_verdict(&error, &expected);
}

#[test]
fn an_invalid_declaration_is_the_verifiers_verdict() {
    let mut arts = super::super::contents::tests::fixture::mixed();
    if let Some(image) = arts[0].image.as_mut() {
        image.platform.architecture = crate::image::ImageArchitecture::Arm64;
    }
    let (error, expected) = both_refuse(&arts, &request(), TargetArch::X86_64);
    assert!(matches!(
        expected,
        ContentError::Verify(VerifyError::Image(_))
    ));
    same_content_verdict(&error, &expected);
}

#[test]
fn an_undeclared_image_is_a_payload_refusal() {
    let mut arts = super::super::contents::tests::fixture::mixed();
    arts[0].image = None;
    let error = prepare(&arts, &ContentLimits::default()).err();
    assert!(
        matches!(
            error,
            PackageWriteError::Payload(PayloadError::InvalidManifest(
                crate::manifest::ManifestError::MissingImageDeclaration(_)
            ))
        ),
        "{error:?}"
    );
}

#[test]
fn a_placeholder_image_archive_is_the_verifiers_verdict() {
    let mut arts = super::super::contents::tests::fixture::mixed();
    arts[0].bytes = b"placeholder image bytes".to_vec();
    let (error, expected) = both_refuse(&arts, &request(), TargetArch::X86_64);
    assert!(matches!(
        expected,
        ContentError::Verify(VerifyError::Image(_))
    ));
    same_content_verdict(&error, &expected);
}

/// The checked-in #95 package, whose image members are placeholders: its
/// artifacts prepared from its own member bytes are refused exactly as the
/// full-content verifier refuses the package itself.
#[test]
fn the_checked_in_placeholder_images_are_the_verifiers_verdict() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/test-fixtures/signed-v6-images");
    let package = std::fs::read(dir.join("package.pkg")).expect("the fixture");
    let key_hex = std::fs::read_to_string(dir.join("public-key.hex")).expect("its key");
    let key: Vec<u8> = (0..key_hex.trim().len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&key_hex[at..at + 2], 16).expect("hex"))
        .collect();
    let trust = crate::verify::TrustSet::new(
        vec![crate::verify::TrustAnchor::new(
            key.try_into().expect("32 bytes"),
            false,
        )],
        Vec::new(),
        0,
        0,
    )
    .expect("a trust set");

    let members = Dir::new();
    let mut payload = crate::payload::open_package(Cursor::new(&package)).expect("it opens");
    let extracted = payload.extract_to(members.path()).expect("it extracts");
    let first = &extracted[0].artifact;
    let request = VerifyRequest::for_namespaced_package(
        &first.component,
        &first.version,
        first.commit.as_deref().expect("a commit"),
        NAMESPACE,
    )
    .expect("a request");
    let arch = first.target_arch;
    let expected = verify(&package, &trust, &request, arch).expect_err("the verifier refuses");
    assert!(matches!(
        expected,
        ContentError::Verify(VerifyError::Image(_))
    ));

    let inputs: Vec<ArtifactInput> = extracted
        .iter()
        .map(|member| ArtifactInput {
            component: member.artifact.component.clone(),
            version: member.artifact.version.clone(),
            commit: member.artifact.commit.clone().expect("a commit"),
            target_arch: member.artifact.target_arch,
            kind: member.artifact.kind,
            dispositions: member.artifact.dispositions.clone(),
            archive_path: member.artifact.archive_path.clone(),
            spec: member.artifact.spec.clone(),
            image: member.artifact.image.clone(),
            source: member.path.clone(),
        })
        .collect();
    let staging = Dir::new();
    let error = prepare_package(
        &inputs,
        None,
        None,
        &request,
        arch,
        &ContentLimits::default(),
        staging.path(),
    )
    .expect_err("preparation refuses");
    same_content_verdict(&error, &expected);
    assert!(staging.entries().is_empty());
}

#[test]
fn a_builder_archive_with_other_tags_is_the_verifiers_verdict() {
    let mut arts = super::super::contents::tests::fixture::mixed();
    let other = Art::image(
        "images/db.tar",
        TargetArch::X86_64,
        "elsewhere",
        b"db layer",
    );
    arts[0].bytes = other.bytes;
    let (error, expected) = both_refuse(&arts, &request(), TargetArch::X86_64);
    assert!(matches!(
        expected,
        ContentError::Verify(VerifyError::Image(_))
    ));
    same_content_verdict(&error, &expected);
}

#[test]
fn a_statement_verdict_wins_over_an_image_fault() {
    let mut arts = super::super::contents::tests::fixture::mixed();
    arts[0].bytes = b"placeholder image bytes".to_vec();
    let other = VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, "other-product")
        .expect("a request");
    let (error, expected) = both_refuse(&arts, &other, TargetArch::X86_64);
    same_content_verdict(&error, &expected);
    let clean = super::super::contents::tests::fixture::mixed();
    let (_, statement) = both_refuse(&clean, &other, TargetArch::X86_64);
    same_content_verdict(&error, &statement);
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[test]
fn outer_members_passes_at_its_limit() {
    let arts = natives();
    prepare(&arts, &limits(LimitResource::OuterMembers, 2)).ok();
    let error = prepare(&arts, &limits(LimitResource::OuterMembers, 1)).err();
    assert_eq!(limit_of(&error), (LimitResource::OuterMembers, 1));
}

#[test]
fn too_many_members_are_refused_before_any_source_is_opened() {
    let arts = natives();
    let sources = Dir::new();
    let mut inputs = inputs(&sources, &arts);
    inputs[0].source = sources.path().join("missing");
    let staging = Dir::new();
    let _seam = fault::install(Seam::new());
    let error = prepare_package(
        &inputs,
        None,
        None,
        &request(),
        TargetArch::X86_64,
        &limits(LimitResource::OuterMembers, 1),
        staging.path(),
    )
    .expect_err("refused");
    assert_eq!(limit_of(&error), (LimitResource::OuterMembers, 1));
    assert!(!fault::record().contains(&Step::OpenInput));
    assert!(fault::record().is_empty(), "{:?}", fault::record());
}

#[test]
fn outer_uncompressed_total_passes_at_its_limit() {
    let arts = natives();
    let total: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    prepare(&arts, &limits(LimitResource::OuterUncompressedTotal, total)).ok();
    let error = prepare(
        &arts,
        &limits(LimitResource::OuterUncompressedTotal, total - 1),
    )
    .err();
    assert_eq!(
        limit_of(&error),
        (LimitResource::OuterUncompressedTotal, total - 1)
    );
}

#[test]
fn a_missing_first_source_is_named_before_an_oversize_second() {
    let mut arts = natives();
    arts[1].bytes = vec![b'x'; 4096];
    let sources = Dir::new();
    let mut inputs = inputs(&sources, &arts);
    let missing = sources.path().join("missing");
    inputs[0].source = missing.clone();
    let staging = Dir::new();
    let error = prepare_package(
        &inputs,
        None,
        None,
        &request(),
        TargetArch::X86_64,
        &limits(LimitResource::OuterUncompressedTotal, 10),
        staging.path(),
    )
    .expect_err("refused");
    assert_eq!(
        io_of(&error),
        (IoOperation::SourceRead, Some(missing), ErrorKind::NotFound)
    );
    assert!(staging.entries().is_empty());
}

#[test]
fn raw_manifest_passes_at_its_limit_and_stores_nothing_past_it() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let len = manifest_len(&reference);
    prepare(&arts, &limits(LimitResource::RawManifest, len)).ok();

    let _seam = bounded_seam::install(None);
    let error = prepare(&arts, &limits(LimitResource::RawManifest, len - 1)).err();
    assert_eq!(limit_of(&error), (LimitResource::RawManifest, len - 1));
    let cap = usize::try_from(len - 1).unwrap();
    assert_eq!(bounded_seam::stored(), Some(cap));
    for (held, additional) in bounded_seam::reservations() {
        assert!(held + additional <= cap, "{held} + {additional} > {cap}");
    }
    assert!(bounded_seam::passed().is_empty(), "no byte of A is written");
}

#[test]
fn compressed_archive_passes_at_its_limit_and_is_never_overwritten() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let len = reference.package.archive().len();
    prepare(&arts, &limits(LimitResource::CompressedArchive, len)).ok();

    let _seam = bounded_seam::install(None);
    let error = prepare(&arts, &limits(LimitResource::CompressedArchive, len - 1)).err();
    assert_eq!(
        limit_of(&error),
        (LimitResource::CompressedArchive, len - 1)
    );
    assert_eq!(bounded_seam::passed().iter().max(), Some(&(len - 1)));
}

#[test]
fn package_is_enforced_while_writing_the_manifest() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let len = manifest_len(&reference);
    let package = OVERHEAD + len - 1;

    let _seam = bounded_seam::install(None);
    let error = prepare(&arts, &limits(LimitResource::Package, package)).err();
    assert_eq!(limit_of(&error), (LimitResource::Package, package));
    assert_eq!(
        bounded_seam::stored(),
        Some(usize::try_from(package - OVERHEAD).unwrap())
    );
    assert!(bounded_seam::passed().is_empty(), "no byte of A is written");
}

#[test]
fn package_below_the_envelope_allocates_no_manifest() {
    let _seam = bounded_seam::install(None);
    let error = prepare(&natives(), &limits(LimitResource::Package, OVERHEAD - 1)).err();
    assert_eq!(limit_of(&error), (LimitResource::Package, OVERHEAD - 1));
    assert!(bounded_seam::reservations().is_empty());
    assert_eq!(bounded_seam::stored(), None);
}

#[test]
fn package_is_enforced_while_writing_the_archive() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let fixed = OVERHEAD + manifest_len(&reference);
    let exact = fixed + reference.package.archive().len();
    prepare(&arts, &limits(LimitResource::Package, exact)).ok();

    let _seam = bounded_seam::install(None);
    let error = prepare(&arts, &limits(LimitResource::Package, exact - 1)).err();
    assert_eq!(limit_of(&error), (LimitResource::Package, exact - 1));
    assert_eq!(
        bounded_seam::passed().iter().max(),
        Some(&(exact - 1 - fixed))
    );

    // A package with room for M and the envelope and none for A writes no
    // byte of A.
    let _seam = bounded_seam::install(None);
    let error = prepare(&arts, &limits(LimitResource::Package, fixed)).err();
    assert_eq!(limit_of(&error), (LimitResource::Package, fixed));
    assert_eq!(bounded_seam::passed().iter().max().copied().unwrap_or(0), 0);
}

fn long_namespace_request(len: usize) -> VerifyRequest {
    VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, &"n".repeat(len))
        .expect("a request")
}

#[test]
fn an_oversize_record_is_refused_before_it_is_built() {
    let arts = natives();
    let request = long_namespace_request(4096);
    let reference = prepare_with(
        &arts,
        &request,
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    let len = reference.package.binding().record_len();
    assert_eq!(
        len,
        reference.package.binding().to_record_bytes().len() as u64
    );
    prepare_with(
        &arts,
        &request,
        TargetArch::X86_64,
        &limits(LimitResource::PreparationRecord, len),
    )
    .ok();

    let built = super::super::binding::seam::records_built();
    let error = prepare_with(
        &arts,
        &request,
        TargetArch::X86_64,
        &limits(LimitResource::PreparationRecord, len - 1),
    )
    .err();
    assert_eq!(
        limit_of(&error),
        (LimitResource::PreparationRecord, len - 1)
    );
    assert_eq!(super::super::binding::seam::records_built(), built);
}

#[test]
fn retained_disk_passes_at_its_high_water_mark() {
    let arts = super::super::contents::tests::fixture::mixed();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let high = reference.package.scope_for_test().budget_high_water();
    let inputs: u64 = arts.iter().map(|art| art.bytes.len() as u64).sum();
    assert_eq!(high, inputs + reference.package.archive().len());
    prepare(&arts, &limits(LimitResource::RetainedDisk, high)).ok();
    let error = prepare(&arts, &limits(LimitResource::RetainedDisk, high - 1)).err();
    assert_eq!(limit_of(&error), (LimitResource::RetainedDisk, high - 1));
}

#[test]
fn raw_manifest_wins_over_package_on_the_same_byte() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let len = manifest_len(&reference);
    let limits = limits(LimitResource::RawManifest, len - 1)
        .with_limit(LimitResource::Package, OVERHEAD + len - 1)
        .expect("a lower limit");
    let error = prepare(&arts, &limits).err();
    assert_eq!(limit_of(&error), (LimitResource::RawManifest, len - 1));
}

#[test]
fn raw_manifest_wins_over_an_oversize_archive() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let len = manifest_len(&reference);
    let limits = limits(LimitResource::RawManifest, len - 1)
        .with_limit(LimitResource::CompressedArchive, 1)
        .expect("a lower limit");
    let _seam = bounded_seam::install(None);
    let error = prepare(&arts, &limits).err();
    assert_eq!(limit_of(&error), (LimitResource::RawManifest, len - 1));
    assert!(bounded_seam::passed().is_empty(), "no byte of A is written");
}

#[test]
fn compressed_archive_wins_over_package_on_the_same_byte() {
    let arts = natives();
    let reference = prepare(&arts, &ContentLimits::default()).ok();
    let archive = reference.package.archive().len();
    let package = OVERHEAD + manifest_len(&reference) + archive - 1;
    let limits = limits(LimitResource::CompressedArchive, archive - 1)
        .with_limit(LimitResource::Package, package)
        .expect("a lower limit");
    let error = prepare(&arts, &limits).err();
    assert_eq!(
        limit_of(&error),
        (LimitResource::CompressedArchive, archive - 1)
    );
}

#[test]
fn a_failed_manifest_allocation_is_a_serialization_failure() {
    let _seam = bounded_seam::install(Some(1));
    let error = prepare(&natives(), &ContentLimits::default()).err();
    match error {
        PackageWriteError::Payload(PayloadError::ManifestSerialize(error)) => {
            assert!(error.is_io());
            let error = std::io::Error::from(error);
            assert_eq!(error.kind(), ErrorKind::OutOfMemory);
            assert!(error.get_ref().is_some_and(
                <dyn std::error::Error + Send + Sync>::is::<super::super::bounded::AllocFault>
            ));
        }
        other => panic!("expected ManifestSerialize, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Snapshots and sources
// ---------------------------------------------------------------------------

#[test]
fn each_source_is_opened_exactly_once() {
    let arts = super::super::contents::tests::fixture::mixed();
    let _seam = fault::install(Seam::new());
    prepare(&arts, &ContentLimits::default()).ok();
    let opens = fault::record()
        .iter()
        .filter(|step| **step == Step::OpenInput)
        .count();
    assert_eq!(opens, arts.len());
}

#[test]
fn a_source_rewritten_mid_copy_is_declared_as_copied() {
    let signer = Signer::new();
    let original: Vec<u8> = (0..64u8).collect();
    let arts = vec![Art::native("bin/tool", &original)];
    let sources = Dir::new();
    let inputs = inputs(&sources, &arts);
    let staging = Dir::new();
    let source = inputs[0].source.clone();
    let _seam = fault::install(Seam::new().before(Step::ReadInput, 2, move || {
        std::fs::write(&source, vec![b'z'; 100]).expect("rewritten");
    }));
    let result = prepare_package(
        &inputs,
        None,
        None,
        &plain_request(),
        TargetArch::X86_64,
        &limits(LimitResource::CopyBuffer, 16),
        staging.path(),
    );
    let Ok(prepared) = result else {
        assert!(staging.entries().is_empty());
        return;
    };
    let bytes = container(&signer, &prepared);
    let contents = verify(
        &bytes,
        &signer.trust(),
        &plain_request(),
        TargetArch::X86_64,
    )
    .expect("M declares exactly what A carries");
    let member = read_all(contents.artifacts()[0].bytes());
    assert_eq!(&member[..16], &original[..16]);
    assert_eq!(
        contents.artifacts()[0].artifact().sha256,
        crate::payload::sha256_hex(&member)
    );
}

#[test]
fn changing_the_sources_afterwards_changes_nothing() {
    let signer = Signer::new();
    let arts = super::super::contents::tests::fixture::mixed();
    let ready = prepare(&arts, &ContentLimits::default()).ok();
    let manifest = ready.package.manifest_bytes().to_vec();
    let archive = read_all(ready.package.archive());

    std::fs::write(&ready.inputs[0].source, b"overwritten").expect("overwritten");
    std::fs::remove_file(&ready.inputs[1].source).expect("deleted");
    let replacement = ready.sources.path().join("replacement");
    std::fs::write(&replacement, b"replaced").expect("written");
    std::fs::rename(&replacement, &ready.inputs[2].source).expect("replaced");

    assert_eq!(ready.package.manifest_bytes(), manifest);
    assert_eq!(read_all(ready.package.archive()), archive);
    let bytes = container(&signer, &ready.package);
    verify(&bytes, &signer.trust(), &request(), TargetArch::X86_64)
        .expect("the container still verifies");
}

/// How many snapshot writes staging `arts` makes, and the index of the
/// archive's snapshot.
fn staging_writes(arts: &[Art]) -> usize {
    let _seam = fault::install(Seam::new());
    prepare(arts, &ContentLimits::default()).ok();
    let record = fault::record();
    let mut creates = 0;
    let mut writes = 0;
    for step in record {
        match step {
            Step::CreateSnapshot => {
                creates += 1;
                if creates > arts.len() {
                    return writes;
                }
            }
            Step::WriteSnapshot => writes += 1,
            _ => {}
        }
    }
    panic!("the archive snapshot was never created");
}

#[test]
fn a_full_filesystem_while_writing_the_archive_names_the_linked_snapshot() {
    let arts = natives();
    let writes = staging_writes(&arts);
    let _seam = fault::install(Seam::new().fail_nth(
        Step::WriteSnapshot,
        writes + 1,
        ErrorKind::StorageFull,
    ));
    let prepared = prepare(&arts, &ContentLimits::default());
    let error = prepared.err();
    let (operation, path, kind) = io_of(&error);
    assert_eq!(operation, IoOperation::WriteSnapshot);
    assert_eq!(kind, ErrorKind::StorageFull);
    let path = path.expect("the linked snapshot is named");
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(format!("snap-{}", arts.len()).as_str())
    );
}

#[test]
fn a_failed_retained_read_while_writing_the_archive_has_no_path() {
    let _seam = source_seam::install(SourceSeam::new().fail_nth(
        SourceRole::Input,
        Op::Read,
        1,
        ErrorKind::Other,
    ));
    let error = prepare(&natives(), &ContentLimits::default()).err();
    assert_eq!(
        io_of(&error),
        (IoOperation::ReadSnapshot, None, ErrorKind::Other)
    );
}

#[test]
fn a_failed_source_read_names_the_source() {
    let arts = natives();
    let _seam = fault::install(Seam::new().fail_nth(Step::ReadInput, 1, ErrorKind::BrokenPipe));
    let prepared = prepare(&arts, &ContentLimits::default());
    let source = prepared.inputs[0].source.clone();
    let error = prepared.err();
    assert_eq!(
        io_of(&error),
        (IoOperation::SourceRead, Some(source), ErrorKind::BrokenPipe)
    );
}

#[test]
fn a_failed_private_directory_names_the_staging_parent() {
    let _seam = fault::install(Seam::new().fail(Step::MakeDirectory, ErrorKind::PermissionDenied));
    let prepared = prepare(&natives(), &ContentLimits::default());
    let parent = prepared.staging.path().to_owned();
    let error = prepared.err();
    assert_eq!(
        io_of(&error),
        (
            IoOperation::CreateStaging,
            Some(parent),
            ErrorKind::PermissionDenied
        )
    );
}

#[test]
fn an_unsafe_staging_parent_is_refused_with_its_kind() {
    let arts = natives();
    let sources = Dir::new();
    let inputs = inputs(&sources, &arts);
    let root = Dir::new();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(root.path(), &link).expect("a symlink");
    let error = prepare_package(
        &inputs,
        None,
        None,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        &link,
    )
    .expect_err("refused");
    assert_eq!(
        io_of(&error),
        (
            IoOperation::InspectStagingParent,
            Some(link),
            ErrorKind::InvalidInput
        )
    );
}

// ---------------------------------------------------------------------------
// Persist
// ---------------------------------------------------------------------------

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn persist_writes_exactly_three_private_files() {
    let ready = prepare(
        &super::super::contents::tests::fixture::mixed(),
        &ContentLimits::default(),
    )
    .ok();
    let out = Dir::new();
    let destination = out.path().join("prepared");
    let _seam = fault::install(Seam::new());
    ready.package.persist(&destination).expect("persisted");
    let durability = [
        Step::SyncFile,
        Step::SyncStagingDirectory,
        Step::Rename,
        Step::SyncParent,
    ];
    let synced: Vec<Step> = fault::record()
        .into_iter()
        .filter(|step| durability.contains(step))
        .collect();
    assert_eq!(
        synced,
        [
            Step::SyncFile,
            Step::SyncFile,
            Step::SyncFile,
            Step::SyncStagingDirectory,
            Step::Rename,
            Step::SyncParent
        ]
    );

    assert_eq!(entries(out.path()), ["prepared"]);
    assert_eq!(mode_of(&destination), 0o700);
    assert_eq!(
        entries(&destination),
        ["archive.tar.zst", "manifest.json", "preparation.json"]
    );
    let read = |name: &str| std::fs::read(destination.join(name)).expect("read");
    assert_eq!(read("manifest.json"), ready.package.manifest_bytes());
    assert_eq!(read("archive.tar.zst"), read_all(ready.package.archive()));
    assert_eq!(
        read("preparation.json"),
        ready.package.binding().to_record_bytes()
    );
    for name in ["manifest.json", "archive.tar.zst", "preparation.json"] {
        assert_eq!(mode_of(&destination.join(name)), 0o600);
    }

    let scope = ready.package.scope_for_test();
    assert_eq!(scope.live_snapshots(), 1);
    assert_eq!(scope.budget_used(), ready.package.archive().len());
}

#[test]
fn persist_never_clobbers_an_existing_destination() {
    let ready = prepare(&natives(), &ContentLimits::default()).ok();
    let out = Dir::new();
    let file = out.path().join("file");
    std::fs::write(&file, b"keep").expect("written");
    let dir = out.path().join("dir");
    std::fs::create_dir(&dir).expect("created");
    for destination in [&file, &dir] {
        let error = ready.package.persist(destination).expect_err("refused");
        assert!(
            matches!(
                &error,
                PackageWriteError::Publication(PublicationError::DestinationExists { destination: d })
                    if d == destination
            ),
            "{error:?}"
        );
    }
    assert_eq!(std::fs::read(&file).expect("read"), b"keep");
    assert!(entries(&dir).is_empty());
    assert_eq!(entries(out.path()), ["dir", "file"]);
    assert_eq!(ready.package.scope_for_test().live_snapshots(), 1);
}

#[test]
fn persist_returns_publication_failures_verbatim() {
    let ready = prepare(&natives(), &ContentLimits::default()).ok();
    for (step, operation) in [
        (Step::WriteTemporary, PublicationOperation::WriteTemporary),
        (Step::SyncFile, PublicationOperation::SyncFile),
        (
            Step::SyncStagingDirectory,
            PublicationOperation::SyncDirectory,
        ),
        (Step::Rename, PublicationOperation::Rename),
    ] {
        let out = Dir::new();
        let destination = out.path().join("prepared");
        let _seam = fault::install(Seam::new().fail(step, ErrorKind::StorageFull));
        let error = ready.package.persist(&destination).expect_err("refused");
        match error {
            PackageWriteError::Publication(PublicationError::Io {
                operation: actual,
                source,
                ..
            }) => {
                assert_eq!(actual, operation, "{step:?}");
                assert_eq!(source.kind(), ErrorKind::StorageFull);
            }
            other => panic!("{step:?}: expected Publication(Io), got {other:?}"),
        }
        assert!(!destination.exists(), "{step:?}");
        assert!(out.entries().is_empty(), "{step:?}: {:?}", out.entries());
        assert_eq!(ready.package.scope_for_test().live_snapshots(), 1);
    }
}

#[test]
fn a_sync_failure_after_publication_is_publish_durability() {
    let ready = prepare(&natives(), &ContentLimits::default()).ok();
    let out = Dir::new();
    let destination = out.path().join("prepared");
    let _seam = fault::install(Seam::new().fail(Step::SyncParent, ErrorKind::Other));
    let error = ready.package.persist(&destination).expect_err("refused");
    assert!(
        matches!(
            &error,
            PackageWriteError::Publication(PublicationError::PublishDurability {
                destination: d,
                operation: PublicationOperation::SyncDirectory,
                ..
            }) if *d == destination
        ),
        "{error:?}"
    );
    assert_eq!(
        entries(&destination),
        ["archive.tar.zst", "manifest.json", "preparation.json"]
    );
}

#[test]
fn a_publication_temporary_over_budget_is_disk_budget_exceeded() {
    let arts = vec![Art::native("bin/blob", &random_bytes(65_536))];
    let reference = prepare_with(
        &arts,
        &plain_request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    let high = reference.package.scope_for_test().budget_high_water();
    let ready = prepare_with(
        &arts,
        &plain_request(),
        TargetArch::X86_64,
        &limits(LimitResource::RetainedDisk, high),
    )
    .ok();
    let out = Dir::new();
    let error = ready
        .package
        .persist(&out.path().join("prepared"))
        .expect_err("refused");
    assert!(
        matches!(
            &error,
            PackageWriteError::Publication(PublicationError::DiskBudgetExceeded { limit })
                if *limit == high
        ),
        "{error:?}"
    );
    assert!(out.entries().is_empty());
}

#[test]
fn a_record_that_cannot_be_snapshotted_is_a_content_error() {
    let ready = prepare(&natives(), &ContentLimits::default()).ok();
    let out = Dir::new();
    let _seam = fault::install(Seam::new().fail(Step::CreateSnapshot, ErrorKind::StorageFull));
    let error = ready
        .package
        .persist(&out.path().join("prepared"))
        .expect_err("refused");
    let (operation, path, kind) = io_of(&error);
    assert_eq!(operation, IoOperation::CreateStaging);
    assert_eq!(kind, ErrorKind::StorageFull);
    assert_eq!(
        path.as_deref(),
        Some(ready.package.scope_for_test().private_path())
    );
    assert!(out.entries().is_empty());
}

#[test]
fn errors_display_in_lowercase_without_echoing_content() {
    let faults = [
        PreparationFault::UnsafeDirectory {
            reason: DirectoryFault::NotAbsolute,
        },
        PreparationFault::Symlink {
            file: PreparationFile::Manifest,
        },
        PreparationFault::NotRegularFile {
            file: PreparationFile::Archive,
        },
        PreparationFault::GroupOrOtherWritable {
            file: PreparationFile::Record,
        },
        PreparationFault::ExtraMember,
        PreparationFault::MissingMember {
            file: PreparationFile::Archive,
        },
        PreparationFault::IdentityChanged {
            file: PreparationFile::Record,
        },
        PreparationFault::RecordInvalid(RecordFault::Malformed),
    ];
    for fault in faults {
        let text = fault.to_string();
        assert_eq!(text, text.to_lowercase(), "{text}");
        let error = PackageWriteError::InvalidPreparation { reason: fault };
        assert!(!error.to_string().is_empty());
    }
    for reason in [
        DirectoryFault::NotAbsolute,
        DirectoryFault::NotCanonical,
        DirectoryFault::NoParent,
        DirectoryFault::SymlinkComponent,
        DirectoryFault::NotDirectory,
        DirectoryFault::GroupOrOtherWritable,
        DirectoryFault::ParentGroupOrOtherWritable,
    ] {
        let text = reason.to_string();
        assert_eq!(text, text.to_lowercase(), "{text}");
    }
    assert_eq!(
        PackageWriteError::BindingMismatch {
            field: BindingField::ArchiveSha256
        }
        .to_string(),
        "the preparation does not match the expected binding in `archive_sha256`"
    );
    assert_eq!(
        IoOperation::OpenPreparation.to_string(),
        "opening the persisted preparation"
    );
}

/// Exercises `Prepared` so the helper's refusal path is used here too.
#[test]
fn a_refused_preparation_leaves_the_staging_parent_empty() {
    let prepared: Prepared = prepare(&natives(), &limits(LimitResource::RawManifest, 1));
    let error = prepared.err();
    assert_eq!(limit_of(&error), (LimitResource::RawManifest, 1));
}

/// A preparation that fails after its archive was built releases the
/// archive's snapshot and every other one with its private directory.
#[test]
fn a_refusal_after_the_archive_releases_everything() {
    let mut arts = super::super::contents::tests::fixture::mixed();
    arts[0].bytes = b"placeholder image bytes".to_vec();
    let error = prepare(&arts, &ContentLimits::default()).err();
    assert!(matches!(
        error,
        PackageWriteError::Content(ContentError::Verify(VerifyError::Image(_)))
    ));
}
