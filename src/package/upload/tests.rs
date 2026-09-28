use std::ffi::OsString;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::*;
use crate::package::contents::tests::fixture::{
    self, Art, COMMIT, COMPONENT, NAMESPACE, Signer, VERSION, archive, legacy_manifest_bytes,
    manifest_bytes, mixed, package, undeclared_manifest_bytes, unsigned,
};
use crate::package::{ContentLimits, LimitResource, verify_contents};
use crate::trust_fixture::{default_document, generation_pkg, keypair, public_key_of};
use crate::verify::{
    ImageVerifyError, TRUST_TARGET, TrustAnchor, TrustSet, UploadRequest, VerifyError,
    VerifyRequest, key_id,
};

/// A private staging parent: a fresh directory, named canonically so no
/// component of its path is a symbolic link, already holding one entry of
/// someone else's so "unchanged" is not the same as "empty".
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
    std::fs::write(path.join("unrelated"), b"not ours").expect("an unrelated entry");
    Staging { _dir: dir, path }
}

fn entries(dir: &Path) -> Vec<OsString> {
    let mut names: Vec<OsString> = std::fs::read_dir(dir)
        .expect("the staging parent lists")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    names.sort_unstable();
    names
}

fn namespace() -> UploadRequest {
    UploadRequest::new(NAMESPACE).expect("a valid namespace")
}

/// Runs [`verify_upload`] in a fresh staging parent and asserts the parent
/// holds exactly what it held before, whatever the result.
fn upload_with(
    bytes: &[u8],
    trust: &TrustSet,
    request: &UploadRequest,
    limits: &ContentLimits,
) -> Result<VerifiedUpload, ContentError> {
    let dir = staging();
    let before = entries(dir.path());
    let result = verify_upload(Cursor::new(bytes), trust, request, limits, dir.path());
    assert_eq!(entries(dir.path()), before, "the staging parent changed");
    result
}

fn upload(bytes: &[u8], trust: &TrustSet) -> Result<VerifiedUpload, ContentError> {
    upload_with(bytes, trust, &namespace(), &ContentLimits::default())
}

#[track_caller]
fn refused(bytes: &[u8], trust: &TrustSet) -> ContentError {
    upload(bytes, trust).expect_err("the upload is refused")
}

fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("a fixture fits in u64")
}

/// Limits whose `RetainedDisk` is the upload bound for `bytes`.
fn bounded_limits(bytes: &[u8]) -> ContentLimits {
    let limits = ContentLimits::default();
    let bound = upload_staging_bound(&limits, len_u64(bytes));
    limits
        .with_limit(LimitResource::RetainedDisk, bound)
        .expect("the bound never exceeds RetainedDisk")
}

/// Runs [`verify_contents`] as the parity criterion states: the fixture's
/// true build and architecture, the namespace, and `RetainedDisk` set to the
/// upload bound for the package.
fn contents_with(
    bytes: &[u8],
    trust: &TrustSet,
    build: &Art,
) -> Result<crate::package::VerifiedContents, ContentError> {
    let dir = staging();
    let request = VerifyRequest::for_namespaced_package(
        &build.component,
        &build.version,
        &build.commit,
        NAMESPACE,
    )
    .expect("a namespaced request");
    verify_contents(
        Cursor::new(bytes),
        trust,
        &request,
        build.arch,
        &bounded_limits(bytes),
        dir.path(),
    )
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn native_on(arch: TargetArch) -> Vec<Art> {
    vec![
        Art::native("bin/tool", b"\x7fELF tool").on(arch),
        Art::compose("compose.yaml", b"services: {}\n").on(arch),
    ]
}

fn images_on(arch: TargetArch) -> Vec<Art> {
    vec![
        Art::image("images/db.tar", arch, "database", b"db layer"),
        Art::native("bin/tool", b"\x7fELF tool").on(arch),
    ]
}

/// A package whose second entry is another build of the same component.
fn two_builds() -> Vec<Art> {
    let mut second = Art::native("bin/other", b"other");
    second.version = "2.0.0".to_string();
    vec![Art::native("bin/tool", b"tool"), second]
}

/// A package whose second entry is built for another architecture.
fn two_architectures() -> Vec<Art> {
    vec![
        Art::native("bin/tool", b"tool"),
        Art::native("bin/tool-arm", b"arm").on(TargetArch::Aarch64),
    ]
}

/// A package whose only entry names the reserved trust target.
fn reserved() -> Vec<Art> {
    let mut art = Art::native("trust-set.json", b"{}");
    art.component = TRUST_TARGET.to_string();
    vec![art]
}

/// An image declared under `namespace`.
fn image_in(namespace: &str) -> Vec<Art> {
    let mut art = Art::image("images/db.tar", TargetArch::X86_64, "database", b"db layer");
    if let Some(image) = art.image.as_mut() {
        image.owner.namespace = namespace.to_string();
    }
    vec![art]
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ---------------------------------------------------------------------------
// Signature first
// ---------------------------------------------------------------------------

/// The four signature failures, each paired with every manifest that would be
/// refused for something else once authenticated: the signature verdict wins
/// every time, so nothing in the manifest decided anything first.
#[test]
fn every_signature_failure_outranks_every_upload_refusal() {
    let signer = Signer::new();
    let stranger = Signer::new();
    let revoked = TrustSet::new(vec![signer.anchor(true)], Vec::new(), 0, 0)
        .expect("a revoked-only trust set");

    let refusable: [(&str, Vec<Art>); 4] = [
        ("no artifacts", Vec::new()),
        ("reserved target", reserved()),
        ("two builds", two_builds()),
        ("two architectures", two_architectures()),
    ];
    for (label, arts) in refusable {
        let manifest = manifest_bytes(&arts);
        let block = archive(&arts);

        // Signed validly, each is its own refusal.
        let valid = signer.container(&manifest, &block);
        let error = refused(&valid, &signer.trust());
        match label {
            "no artifacts" => assert!(
                matches!(error, ContentError::Upload(UploadRefusal::NoArtifacts)),
                "{error:?}"
            ),
            "reserved target" => assert!(
                matches!(error, ContentError::Upload(UploadRefusal::ReservedTarget)),
                "{error:?}"
            ),
            "two builds" => assert!(
                matches!(
                    &error,
                    ContentError::Verify(VerifyError::TargetMismatch { component, version, .. })
                        if component == COMPONENT && version == "2.0.0"
                ),
                "{error:?}"
            ),
            _ => assert!(
                matches!(
                    &error,
                    ContentError::ArchitectureMismatch { archive_path, expected, actual }
                        if archive_path == "bin/tool-arm"
                            && *expected == TargetArch::X86_64
                            && *actual == TargetArch::Aarch64
                ),
                "{error:?}"
            ),
        }

        let unsigned = unsigned(&manifest, &block);
        assert!(
            matches!(
                refused(&unsigned, &signer.trust()),
                ContentError::Verify(VerifyError::BadSignature)
            ),
            "{label}: unsigned"
        );

        let flipped = signer.badly_signed(&manifest, &block);
        assert!(
            matches!(
                refused(&flipped, &signer.trust()),
                ContentError::Verify(VerifyError::BadSignature)
            ),
            "{label}: a flipped signature bit"
        );

        let unknown = stranger.container(&manifest, &block);
        assert!(
            matches!(
                refused(&unknown, &signer.trust()),
                ContentError::Verify(VerifyError::UnknownKeyId { key_id })
                    if key_id == stranger.key_id()
            ),
            "{label}: an unknown key"
        );

        assert!(
            matches!(
                refused(&valid, &revoked),
                ContentError::Verify(VerifyError::RevokedKey { key_id })
                    if key_id == signer.key_id()
            ),
            "{label}: a revoked key"
        );
    }
}

// ---------------------------------------------------------------------------
// Parity with verify_contents
// ---------------------------------------------------------------------------

/// Asserts `verify_upload` and `verify_contents` — called with `build`, the
/// namespace and `build`'s architecture, under the bound — agree variant for
/// variant, and returns the upload's result.
#[track_caller]
fn assert_parity(
    label: &str,
    bytes: &[u8],
    trust: &TrustSet,
    build: &Art,
) -> Result<VerifiedUpload, ContentError> {
    let uploaded = upload(bytes, trust);
    let contents = contents_with(bytes, trust, build);
    match (&uploaded, &contents) {
        (Ok(uploaded), Ok(contents)) => {
            assert_eq!(uploaded.manifest(), contents.manifest(), "{label}");
            assert_eq!(
                uploaded.package_sha256(),
                contents.package_bytes().sha256(),
                "{label}"
            );
        }
        (Err(uploaded), Err(contents)) => {
            assert_eq!(format!("{uploaded:?}"), format!("{contents:?}"), "{label}");
        }
        (uploaded, contents) => panic!("{label}: upload {uploaded:?}, contents {contents:?}"),
    }
    uploaded
}

/// One parity fixture: a label, the package, the trust set it is verified
/// under, and the entry whose build and architecture are its true ones.
type ParityCase = (&'static str, Vec<u8>, TrustSet, Art);

/// Every package signed honestly by `signer` from its artifacts: the accepted
/// fixtures, then those refused past the signature.
fn signed_cases(signer: &Signer) -> Vec<ParityCase> {
    let trust = signer.trust();

    let mut cases: Vec<ParityCase> = Vec::new();
    let mut add = |label: &'static str, arts: Vec<Art>| {
        let bytes = package(signer, &arts);
        let first = arts.first().expect("a fixture has an entry").clone();
        cases.push((label, bytes, trust.clone(), first));
    };

    // Accepted.
    add("native x86_64", native_on(TargetArch::X86_64));
    add("native aarch64", native_on(TargetArch::Aarch64));
    add("images x86_64", images_on(TargetArch::X86_64));
    add("images aarch64", images_on(TargetArch::Aarch64));
    add("mixed", mixed());

    // Refused past the signature.
    let mut wrong_config = Art::image("images/db.tar", TargetArch::X86_64, "database", b"db");
    if let Some(image) = wrong_config.image.as_mut() {
        image.config_digest = format!("sha256:{}", "ab".repeat(32));
    }
    add("image archive fault", vec![wrong_config]);
    add("foreign namespace", image_in("other-product"));
    let mut foreign_owner = Art::image("images/db.tar", TargetArch::X86_64, "database", b"db");
    if let Some(image) = foreign_owner.image.as_mut() {
        image.owner.component = "another-app".to_string();
    }
    add("foreign owner component", vec![foreign_owner]);
    let mut unsafe_version = Art::native("bin/tool", b"tool");
    unsafe_version.version = "-1".to_string();
    add("unsafe identifier", vec![unsafe_version]);
    let mut platform = Art::image("images/db.tar", TargetArch::X86_64, "database", b"db");
    platform.arch = TargetArch::Aarch64;
    add("declared platform mismatch", vec![platform]);
    add(
        "two images, the second at fault",
        vec![
            Art::image("images/db.tar", TargetArch::X86_64, "database", b"db"),
            {
                let mut web = Art::image("images/web.tar", TargetArch::X86_64, "web", b"web");
                if let Some(image) = web.image.as_mut() {
                    image.config_digest = format!("sha256:{}", "cd".repeat(32));
                }
                web
            },
        ],
    );
    cases
}

#[test]
fn every_fixture_gets_the_verdict_verify_contents_gives_its_true_build() {
    let signer = Signer::new();
    let trust = signer.trust();
    let mut cases = signed_cases(&signer);

    // Refused for what the manifest or the archive says, built by hand.
    let arts = mixed();
    let first = arts.first().expect("an entry").clone();
    cases.push((
        "legacy image",
        signer.container(&legacy_manifest_bytes(&arts), &archive(&arts)),
        trust.clone(),
        first.clone(),
    ));
    cases.push((
        "undeclared current-format image",
        signer.container(&undeclared_manifest_bytes(&arts), &archive(&arts)),
        trust.clone(),
        first.clone(),
    ));
    cases.push((
        "an archive missing a member",
        signer.container(&manifest_bytes(&arts), &archive(&arts[..2])),
        trust.clone(),
        first.clone(),
    ));
    cases.push((
        "an archive that is not zstd",
        signer.container(&manifest_bytes(&arts), b"not an archive"),
        trust.clone(),
        first.clone(),
    ));
    cases.push((
        "a bad signature",
        signer.badly_signed(&manifest_bytes(&arts), &archive(&arts)),
        trust.clone(),
        first.clone(),
    ));
    cases.push((
        "withdrawn",
        package(&signer, &arts),
        signer.trust_with(
            vec![(
                COMPONENT.to_string(),
                VERSION.to_string(),
                COMMIT.to_string(),
            )],
            0,
        ),
        first.clone(),
    ));
    let floor = TrustSet::new(vec![signer.anchor(false)], Vec::new(), u32::MAX, 0)
        .expect("a trust set with a floor");
    cases.push((
        "below the format floor",
        package(&signer, &arts),
        floor,
        first.clone(),
    ));
    cases.push((
        "not a container",
        b"not a package at all".to_vec(),
        trust.clone(),
        first,
    ));

    let mut accepted = 0;
    for (label, bytes, trust, build) in &cases {
        if assert_parity(label, bytes, trust, build).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 5, "exactly the five accepted fixtures verify");
}

// ---------------------------------------------------------------------------
// Derived identity
// ---------------------------------------------------------------------------

#[track_caller]
fn assert_identity(verified: &VerifiedUpload, arts: &[Art], signer: &Signer, bytes: &[u8]) {
    let first = arts.first().expect("an entry");
    assert_eq!(verified.component(), first.component);
    assert_eq!(verified.version(), first.version);
    assert_eq!(verified.commit(), first.commit);
    assert_eq!(verified.target_arch(), first.arch);
    assert_eq!(verified.key_id(), signer.key_id());
    assert_eq!(verified.manifest(), &fixture::manifest(arts));
    assert_eq!(verified.manifest_sha256(), &sha256(&manifest_bytes(arts)));
    assert_eq!(verified.package_sha256(), &sha256(bytes));
    assert_eq!(verified.package_len(), len_u64(bytes));
}

#[test]
fn the_build_architecture_signer_and_digests_are_those_of_the_package() {
    let signer = Signer::new();
    for arch in [TargetArch::X86_64, TargetArch::Aarch64] {
        for arts in [native_on(arch), images_on(arch)] {
            let bytes = package(&signer, &arts);
            let verified = upload(&bytes, &signer.trust()).expect("the package verifies");
            assert_identity(&verified, &arts, &signer, &bytes);
        }
    }
}

#[test]
fn the_key_id_is_the_verifying_anchors_whatever_the_hint_says() {
    let signer = Signer::new();
    let other = Signer::new();
    // The other anchor first, so a verifier trusting the hint or the first
    // anchor would name it.
    let trust = TrustSet::new(
        vec![other.anchor(false), signer.anchor(false)],
        Vec::new(),
        0,
        0,
    )
    .expect("a two-anchor trust set");
    let arts = native_on(TargetArch::X86_64);
    let manifest = manifest_bytes(&arts);
    let block = archive(&arts);

    for hint in [
        other.key_id(),
        "not a usable hint".to_string(),
        other.key_id().to_uppercase(),
        "z".repeat(64),
        "ab".repeat(16),
    ] {
        let bytes = signer.container_hinted(&manifest, &block, &hint);
        let verified = upload(&bytes, &trust).expect("the package verifies");
        assert_identity(&verified, &arts, &signer, &bytes);
        assert_ne!(verified.key_id(), other.key_id(), "hint {hint:?}");
    }
}

// ---------------------------------------------------------------------------
// Upload refusals
// ---------------------------------------------------------------------------

#[test]
fn a_signed_trust_generation_is_a_reserved_target() {
    let pair = keypair();
    let trust = TrustSet::new(
        vec![TrustAnchor::new(public_key_of(&pair), false)],
        Vec::new(),
        0,
        1,
    )
    .expect("a trust set");
    let bytes = generation_pkg(&pair, &default_document(&pair), 4711);
    assert!(matches!(
        refused(&bytes, &trust),
        ContentError::Upload(UploadRefusal::ReservedTarget)
    ));
    // The same bytes under a set that does not anchor the key are a signature
    // verdict instead: the reserved target is decided only once authenticated.
    let stranger = Signer::new();
    assert!(matches!(
        refused(&bytes, &stranger.trust()),
        ContentError::Verify(VerifyError::UnknownKeyId { key_id: id })
            if id == key_id(&public_key_of(&pair))
    ));
}

#[test]
fn a_manifest_without_artifacts_names_no_build() {
    let signer = Signer::new();
    let bytes = package(&signer, &[]);
    assert!(matches!(
        refused(&bytes, &signer.trust()),
        ContentError::Upload(UploadRefusal::NoArtifacts)
    ));
}

#[test]
fn a_mixed_architecture_expects_the_first_entrys() {
    let signer = Signer::new();
    let mut arts = two_architectures();
    arts.reverse();
    let error = refused(&package(&signer, &arts), &signer.trust());
    assert!(
        matches!(
            &error,
            ContentError::ArchitectureMismatch { archive_path, expected, actual }
                if archive_path == "bin/tool"
                    && *expected == TargetArch::Aarch64
                    && *actual == TargetArch::X86_64
        ),
        "{error:?}"
    );
}

// ---------------------------------------------------------------------------
// Namespace
// ---------------------------------------------------------------------------

#[test]
fn an_image_is_held_to_the_upload_namespace() {
    let signer = Signer::new();
    let arts = image_in("clumit-other");
    let bytes = package(&signer, &arts);
    let limits = ContentLimits::default();

    let security = UploadRequest::new("clumit-security").expect("a valid namespace");
    let error = upload_with(&bytes, &signer.trust(), &security, &limits)
        .expect_err("another namespace's image is refused");
    assert!(
        matches!(
            &error,
            ContentError::Verify(VerifyError::Image(
                ImageVerifyError::NamespaceMismatch { .. }
            ))
        ),
        "{error:?}"
    );

    let own = UploadRequest::new("clumit-other").expect("a valid namespace");
    let verified = upload_with(&bytes, &signer.trust(), &own, &limits)
        .expect("the image verifies under its own namespace");
    assert_identity(&verified, &arts, &signer, &bytes);
}

#[test]
fn a_package_declaring_no_image_verifies_under_any_namespace() {
    let signer = Signer::new();
    let arts = native_on(TargetArch::X86_64);
    let bytes = package(&signer, &arts);
    for namespace in ["clumit-security", "clumit-other"] {
        let request = UploadRequest::new(namespace).expect("a valid namespace");
        upload_with(&bytes, &signer.trust(), &request, &ContentLimits::default())
            .expect("an image-free package verifies");
    }
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

/// Runs the upload up to the point it releases the evidence, and returns the
/// most bytes its scope ever held.
fn high_water(bytes: &[u8], trust: &TrustSet, limits: &ContentLimits) -> u64 {
    let dir = staging();
    let (contents, _) =
        upload_contents(Cursor::new(bytes), trust, &namespace(), limits, dir.path())
            .expect("the package verifies");
    let scope = contents.scope_for_test();
    assert_eq!(
        scope.budget().limit(),
        upload_staging_bound(limits, len_u64(bytes)),
        "the scope's budget is the bound"
    );
    scope.budget_high_water()
}

#[test]
fn the_high_water_mark_stays_within_the_bound_and_the_bound_is_enforced() {
    let signer = Signer::new();
    let arts = mixed();
    let bytes = package(&signer, &arts);
    let trust = signer.trust();
    let limits = ContentLimits::default();

    let mark = high_water(&bytes, &trust, &limits);
    assert!(mark <= upload_staging_bound(&limits, len_u64(&bytes)));
    // The package, its archive block and every member.
    let members: u64 = arts.iter().map(|art| len_u64(&art.bytes)).sum();
    assert!(mark > len_u64(&bytes) + members);

    // The tightest bound that still admits it: `OuterUncompressedTotal`
    // lowered to exactly what the members need.
    let tight = limits
        .clone()
        .with_limit(LimitResource::OuterUncompressedTotal, members)
        .expect("a lower total");
    let tight_mark = high_water(&bytes, &trust, &tight);
    assert!(tight_mark <= upload_staging_bound(&tight, len_u64(&bytes)));

    // One byte below the mark: refused for the budget, naming the budget.
    let lowered = limits
        .with_limit(LimitResource::RetainedDisk, mark - 1)
        .expect("a lower budget");
    let error = upload_with(&bytes, &trust, &namespace(), &lowered).expect_err("over budget");
    assert!(
        matches!(
            error,
            ContentError::LimitExceeded {
                resource: LimitResource::RetainedDisk,
                limit,
            } if limit == mark - 1
        ),
        "{error:?}"
    );
}

#[test]
fn an_untrusted_staging_parent_is_refused_before_anything_is_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let signer = Signer::new();
    let bytes = package(&signer, &mixed());
    let root = staging();
    let group_writable = root.path().join("group-writable");
    std::fs::create_dir(&group_writable).expect("a directory");
    std::fs::set_permissions(&group_writable, std::fs::Permissions::from_mode(0o770))
        .expect("chmod");

    let error = verify_upload(
        Cursor::new(&bytes),
        &signer.trust(),
        &namespace(),
        &ContentLimits::default(),
        &group_writable,
    )
    .expect_err("refused");
    let ContentError::Io {
        operation, path, ..
    } = &error
    else {
        panic!("expected an I/O refusal, got {error:?}");
    };
    assert_eq!(*operation, IoOperation::InspectStagingParent);
    assert_eq!(path.as_deref(), Some(group_writable.as_path()));
    assert!(entries(&group_writable).is_empty());
}

// ---------------------------------------------------------------------------
// The bound
// ---------------------------------------------------------------------------

#[test]
fn the_bound_is_the_formula_and_saturates() {
    let defaults = ContentLimits::default();
    let disk = defaults.get(LimitResource::RetainedDisk);
    let total = defaults.get(LimitResource::OuterUncompressedTotal);
    assert_eq!(upload_staging_bound(&defaults, 0), total.min(disk));
    assert_eq!(upload_staging_bound(&defaults, 1), (total + 2).min(disk));
    assert_eq!(upload_staging_bound(&defaults, u64::MAX), disk);
    assert_eq!(upload_staging_bound(&defaults, u64::MAX / 2 + 1), disk);

    let small_total = defaults
        .clone()
        .with_limit(LimitResource::OuterUncompressedTotal, 100)
        .expect("a lower total");
    assert_eq!(upload_staging_bound(&small_total, 0), 100);
    assert_eq!(upload_staging_bound(&small_total, 1), 102);
    assert_eq!(upload_staging_bound(&small_total, 1000), 2100);
    assert_eq!(upload_staging_bound(&small_total, u64::MAX), disk);

    let small_disk = defaults
        .with_limit(LimitResource::RetainedDisk, 50)
        .expect("a lower budget");
    assert_eq!(upload_staging_bound(&small_disk, 0), 50);
    assert_eq!(upload_staging_bound(&small_disk, 1), 50);
    assert_eq!(upload_staging_bound(&small_disk, u64::MAX), 50);

    let zero = small_total
        .with_limit(LimitResource::OuterUncompressedTotal, 0)
        .and_then(|limits| limits.with_limit(LimitResource::RetainedDisk, 10))
        .expect("lower limits");
    assert_eq!(upload_staging_bound(&zero, 0), 0);
    assert_eq!(upload_staging_bound(&zero, 1), 2);
    assert_eq!(upload_staging_bound(&zero, 5), 10);
    assert_eq!(upload_staging_bound(&zero, 6), 10);
}
