//! The public `image::test_support` API, exercised from outside the crate the
//! way a dependent's tests use it.

use std::io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom};

use deploy_core::image::test_support::{
    ArchiveCheckError, LayerCompression, MAX_SYNTHETIC_ENTRIES_PER_LAYER,
    MAX_SYNTHETIC_IMAGE_BYTES, MAX_SYNTHETIC_LAYER_BYTES, MAX_SYNTHETIC_LAYERS,
    MAX_SYNTHETIC_LINK_BYTES, MAX_SYNTHETIC_PATH_BYTES, MAX_SYNTHETIC_REF_BYTES,
    MAX_SYNTHETIC_REFS, MAX_SYNTHETIC_TOTAL_ENTRIES, SyntheticImageArchive,
    SyntheticImageArchiveBuilder, SyntheticImageError, SyntheticLayer, check_image_archive,
};
use deploy_core::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle,
    canonical_runtime_alias,
};
use deploy_core::package::LimitResource;
use deploy_core::verify::{
    ImageVerifyError, InvalidArchiveReason, PlatformFacet, PlatformLocation, ReferenceSource,
    TarFault,
};

const ARCHIVE_PATH: &str = "images/app.tar";
const REF: &str = "registry.example/synthetic/app:1.0";
const NAMESPACE: &str = "example-product";
const COMPONENT: &str = "example-app";
const DEPENDENCY: &str = "database";

fn platform(architecture: ImageArchitecture, variant: Option<&str>) -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture,
        variant: variant.map(ToString::to_string),
    }
}

fn amd64() -> ImagePlatform {
    platform(ImageArchitecture::Amd64, None)
}

fn refs(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn builder(platform: ImagePlatform) -> SyntheticImageArchiveBuilder {
    SyntheticImageArchiveBuilder::new(platform).expect("the platform is valid")
}

fn hello() -> SyntheticLayer {
    SyntheticLayer::new().file("hello.txt", "hello")
}

/// The declaration a synthetic archive's own values determine.
fn declaration(
    platform: &ImagePlatform,
    config_digest: &str,
    public_refs: &[String],
) -> ImageDeclaration {
    ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: ImageOwner {
            namespace: NAMESPACE.to_string(),
            component: COMPONENT.to_string(),
        },
        dependency: DEPENDENCY.to_string(),
        public_refs: public_refs.to_vec(),
        platform: platform.clone(),
        config_digest: config_digest.to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
            repository: "https://example.com/app.git".to_string(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        }),
    }
}

fn matching(archive: &SyntheticImageArchive, public_refs: &[String]) -> ImageDeclaration {
    declaration(archive.platform(), archive.config_digest(), public_refs)
}

fn check(
    archive: &SyntheticImageArchive,
    declaration: &ImageDeclaration,
) -> Result<(), ArchiveCheckError> {
    check_image_archive(Cursor::new(archive.bytes()), ARCHIVE_PATH, declaration)
}

#[track_caller]
fn accept(builder: SyntheticImageArchiveBuilder, public_refs: &[String]) -> SyntheticImageArchive {
    let archive = builder
        .finish(public_refs)
        .expect("the references are accepted");
    if let Err(error) = check(&archive, &matching(&archive, public_refs)) {
        panic!("refused: {error:?}");
    }
    archive
}

fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Returns 256 distinct references of exactly [`MAX_SYNTHETIC_REF_BYTES`]
/// bytes.
fn longest_refs() -> Vec<String> {
    (0..MAX_SYNTHETIC_REFS)
        .map(|at| {
            let tail = format!(".example/app:t{at:03}{}", "x".repeat(124));
            let head = format!("r{at:03}");
            let pad = MAX_SYNTHETIC_REF_BYTES - tail.len() - head.len();
            let reference = format!("{head}{}{tail}", "a".repeat(pad));
            assert_eq!(reference.len(), MAX_SYNTHETIC_REF_BYTES);
            reference
        })
        .collect()
}

/// Names every variant with its fields, so a new variant fails to compile
/// here until it is covered.
fn describe_builder_error(error: &SyntheticImageError) -> String {
    match error {
        SyntheticImageError::InvalidVariant => "InvalidVariant".to_string(),
        SyntheticImageError::TooManyLayers => "TooManyLayers".to_string(),
        SyntheticImageError::TooManyEntries { layer } => format!("TooManyEntries {layer}"),
        SyntheticImageError::TooManyTotalEntries { layer } => {
            format!("TooManyTotalEntries {layer}")
        }
        SyntheticImageError::LayerTooLarge { layer } => format!("LayerTooLarge {layer}"),
        SyntheticImageError::ImageTooLarge { layer } => format!("ImageTooLarge {layer}"),
        SyntheticImageError::InvalidEntryPath { layer, entry } => {
            format!("InvalidEntryPath {layer} {entry}")
        }
        SyntheticImageError::PathNotRepresentable { layer, entry } => {
            format!("PathNotRepresentable {layer} {entry}")
        }
        SyntheticImageError::InvalidLinkTarget { layer, entry } => {
            format!("InvalidLinkTarget {layer} {entry}")
        }
        SyntheticImageError::CompressionExpanded { layer } => {
            format!("CompressionExpanded {layer}")
        }
        SyntheticImageError::NoReferences => "NoReferences".to_string(),
        SyntheticImageError::TooManyReferences => "TooManyReferences".to_string(),
        SyntheticImageError::ReferenceTooLong { index } => format!("ReferenceTooLong {index}"),
        SyntheticImageError::InvalidReference { index } => format!("InvalidReference {index}"),
        SyntheticImageError::DuplicateReference { index } => {
            format!("DuplicateReference {index}")
        }
        SyntheticImageError::Generation { kind } => format!("Generation {kind:?}"),
    }
}

/// Names every classifier variant with its fields.
fn describe_check_error(error: &ArchiveCheckError) -> String {
    match error {
        ArchiveCheckError::Image(error) => format!("Image {error}"),
        ArchiveCheckError::LimitExceeded { resource, limit } => {
            format!("LimitExceeded {resource} {limit}")
        }
        ArchiveCheckError::Io(error) => format!("Io {:?}", error.kind()),
    }
}

#[test]
fn the_bounds_are_the_documented_public_constants() {
    assert_eq!(MAX_SYNTHETIC_LAYERS, 256);
    assert_eq!(MAX_SYNTHETIC_ENTRIES_PER_LAYER, 4096);
    assert_eq!(MAX_SYNTHETIC_TOTAL_ENTRIES, 65_536);
    assert_eq!(MAX_SYNTHETIC_LAYER_BYTES, 256 * 1024 * 1024);
    assert_eq!(MAX_SYNTHETIC_IMAGE_BYTES, 1024 * 1024 * 1024);
    assert_eq!(MAX_SYNTHETIC_PATH_BYTES, 255);
    assert_eq!(MAX_SYNTHETIC_LINK_BYTES, 100);
    assert_eq!(MAX_SYNTHETIC_REFS, 256);
    assert_eq!(MAX_SYNTHETIC_REF_BYTES, 512);
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

#[test]
fn every_supported_shape_is_accepted() {
    let tagged = refs(&[REF]);
    accept(
        builder(amd64())
            .layer(hello(), LayerCompression::Uncompressed)
            .unwrap(),
        &tagged,
    );
    accept(
        builder(amd64())
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &tagged,
    );
    accept(
        builder(amd64())
            .layer(hello(), LayerCompression::Uncompressed)
            .unwrap()
            .layer(
                SyntheticLayer::new().file("b.txt", "b"),
                LayerCompression::Gzip,
            )
            .unwrap(),
        &tagged,
    );
    let scratch = accept(builder(amd64()), &tagged);
    assert!(scratch.diff_ids().is_empty());
    let repeated = accept(
        builder(amd64())
            .layer(hello(), LayerCompression::Gzip)
            .unwrap()
            .layer(
                SyntheticLayer::new().dir("etc"),
                LayerCompression::Uncompressed,
            )
            .unwrap()
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &tagged,
    );
    assert_eq!(repeated.diff_ids()[0], repeated.diff_ids()[2]);
    accept(
        builder(platform(ImageArchitecture::Arm64, Some("v8")))
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &tagged,
    );
    let token = "A.b_c-9".repeat(9) + "Z";
    assert_eq!(token.len(), 64);
    accept(
        builder(platform(ImageArchitecture::Amd64, Some(&token)))
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &tagged,
    );
    accept(
        builder(platform(ImageArchitecture::Arm64, None))
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &tagged,
    );
    accept(
        builder(amd64())
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &refs(&[
            REF,
            "registry.example/synthetic/app:latest",
            "app:1",
            "localhost:5000/app:2",
        ]),
    );
    accept(
        builder(amd64())
            .layer(
                SyntheticLayer::new()
                    .dir("etc")
                    .dir("usr/share")
                    .file("etc/os-release", "ID=synthetic\n")
                    .symlink("etc/localtime", "/usr/share/zoneinfo/UTC")
                    .symlink("etc/release", "os-release")
                    .symlink("etc/up", "../usr/share"),
                LayerCompression::Gzip,
            )
            .unwrap(),
        &tagged,
    );
}

#[test]
fn edge_entries_the_builder_admits_are_accepted() {
    let tagged = refs(&[REF]);
    // A full-width target leaves the ustar `linkname` field with no NUL, and
    // a target is copied through as given: non-ASCII, absolute or climbing.
    let full_target = "t".repeat(MAX_SYNTHETIC_LINK_BYTES);
    let full_name = "n".repeat(100);
    accept(
        builder(amd64())
            .layer(
                SyntheticLayer::new()
                    .file(&full_name, "full")
                    .symlink("full", &full_target)
                    .symlink("utf8", "caf\u{e9}")
                    .symlink("climb", "../../../etc/passwd"),
                LayerCompression::Gzip,
            )
            .unwrap(),
        &tagged,
    );
    // One layer stored both ways: two blobs sharing one diff ID.
    let both = accept(
        builder(amd64())
            .layer(hello(), LayerCompression::Uncompressed)
            .unwrap()
            .layer(hello(), LayerCompression::Gzip)
            .unwrap(),
        &tagged,
    );
    assert_eq!(both.diff_ids()[0], both.diff_ids()[1]);
}

// ---------------------------------------------------------------------------
// Determinism and config before tags
// ---------------------------------------------------------------------------

fn sample() -> SyntheticImageArchiveBuilder {
    builder(platform(ImageArchitecture::Arm64, Some("v8")))
        .layer(hello(), LayerCompression::Gzip)
        .expect("the first sample layer is accepted")
        .layer(
            SyntheticLayer::new().dir("etc"),
            LayerCompression::Uncompressed,
        )
        .expect("the second sample layer is accepted")
}

#[test]
fn identical_inputs_build_identical_archives() {
    let first = sample().finish(&refs(&[REF])).unwrap();
    let second = sample().finish(&refs(&[REF])).unwrap();
    assert_eq!(first.bytes(), second.bytes());

    let retagged = sample()
        .finish(&refs(&["registry.example/synthetic/app:2.0"]))
        .unwrap();
    assert_eq!(retagged.config_digest(), first.config_digest());
    assert_ne!(retagged.bytes(), first.bytes());
}

#[test]
fn the_config_digest_is_known_before_the_tags_and_names_the_canonical_alias() {
    let builder = sample();
    let digest = builder.config_digest();
    let platform = builder.platform().clone();
    let alias = canonical_runtime_alias(NAMESPACE, COMPONENT, DEPENDENCY, &digest).unwrap();
    let public_refs = vec![alias, REF.to_string()];
    let archive = builder.finish(&public_refs).unwrap();
    assert_eq!(archive.config_digest(), digest);
    assert_eq!(archive.platform(), &platform);

    let mut declaration = declaration(&platform, &digest, &public_refs);
    declaration.reference_lifecycle = ReferenceLifecycle::ManagedRuntime;
    assert_eq!(
        declaration.canonical_runtime_alias().unwrap(),
        public_refs[0]
    );
    check(&archive, &declaration).unwrap();
}

#[test]
fn the_accessors_report_the_archive() {
    let input = platform(ImageArchitecture::Arm64, Some("v8"));
    let archive = sample().finish(&refs(&[REF])).unwrap();
    let borrowed: &[u8] = archive.bytes();
    let copy = borrowed.to_vec();
    let config_digest: &str = archive.config_digest();
    let manifest_digest: &str = archive.manifest_digest();
    let diff_ids: &[String] = archive.diff_ids();
    let stated: &ImagePlatform = archive.platform();
    assert!(is_digest(config_digest));
    assert!(is_digest(manifest_digest));
    assert_ne!(config_digest, manifest_digest);
    assert_eq!(diff_ids.len(), 2);
    assert!(diff_ids.iter().all(|diff_id| is_digest(diff_id)));
    assert_ne!(diff_ids[0], diff_ids[1]);
    assert_eq!(stated, &input);

    let debug = format!("{archive:?}");
    assert!(debug.contains(config_digest) && debug.contains(manifest_digest));
    assert!(debug.contains(&copy.len().to_string()));
    assert!(!debug.contains("hello"), "{debug}");
    assert!(!debug.contains(&format!("{:?}", &copy[..16])));

    let owned: Vec<u8> = archive.into_bytes();
    assert_eq!(owned, copy);
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[track_caller]
fn refuse_layer(layer: SyntheticLayer) -> SyntheticImageError {
    builder(amd64())
        .layer(layer, LayerCompression::Gzip)
        .expect_err("the layer is refused")
}

#[track_caller]
fn refuse_refs(public_refs: &[String]) -> SyntheticImageError {
    builder(amd64())
        .finish(public_refs)
        .expect_err("the references are refused")
}

#[test]
fn an_invalid_variant_is_refused() {
    for variant in [
        "v".repeat(65),
        "v8/a".to_string(),
        "v 8".to_string(),
        "v8é".to_string(),
        "x".repeat(10_000),
        String::new(),
    ] {
        let error =
            SyntheticImageArchiveBuilder::new(platform(ImageArchitecture::Arm64, Some(&variant)))
                .unwrap_err();
        assert_eq!(error, SyntheticImageError::InvalidVariant);
        assert!(!error.to_string().contains(&variant) || variant.is_empty());
    }
}

#[test]
fn invalid_entries_are_refused_with_their_positions() {
    let long = "a".repeat(MAX_SYNTHETIC_PATH_BYTES + 1);
    for path in [
        "", "/abs", "a/../b", "a//b", "./a", "a/", "é", "a\u{1}b", "a\\b", &long,
    ] {
        let layer = SyntheticLayer::new().dir("ok").file(path, "x");
        assert_eq!(
            refuse_layer(layer),
            SyntheticImageError::InvalidEntryPath { layer: 0, entry: 1 },
            "{path:?}"
        );
    }
    assert_eq!(
        refuse_layer(SyntheticLayer::new().file(&"a".repeat(120), "x")),
        SyntheticImageError::PathNotRepresentable { layer: 0, entry: 0 }
    );
    let too_long = "t".repeat(MAX_SYNTHETIC_LINK_BYTES + 1);
    for target in ["", "a\0b", &too_long] {
        assert_eq!(
            refuse_layer(SyntheticLayer::new().file("a", "x").symlink("b", target)),
            SyntheticImageError::InvalidLinkTarget { layer: 0, entry: 1 },
            "{target:?}"
        );
    }
    let mut many = SyntheticLayer::new();
    for at in 0..=MAX_SYNTHETIC_ENTRIES_PER_LAYER {
        many = many.dir(&format!("d{at}"));
    }
    assert_eq!(
        refuse_layer(many),
        SyntheticImageError::TooManyEntries { layer: 0 }
    );
}

#[test]
fn the_layer_and_payload_bounds_are_refused() {
    let mut full = builder(amd64());
    for _ in 0..MAX_SYNTHETIC_LAYERS {
        full = full
            .layer(SyntheticLayer::new(), LayerCompression::Uncompressed)
            .unwrap();
    }
    assert_eq!(
        full.layer(SyntheticLayer::new(), LayerCompression::Uncompressed)
            .unwrap_err(),
        SyntheticImageError::TooManyLayers
    );

    let len = usize::try_from(MAX_SYNTHETIC_LAYER_BYTES + 1).unwrap();
    assert_eq!(
        refuse_layer(SyntheticLayer::new().file("big.bin", vec![0u8; len])),
        SyntheticImageError::LayerTooLarge { layer: 0 }
    );
}

#[test]
fn invalid_references_are_refused_with_their_index() {
    assert_eq!(refuse_refs(&[]), SyntheticImageError::NoReferences);
    let many: Vec<String> = (0..=MAX_SYNTHETIC_REFS)
        .map(|at| format!("r:{at}"))
        .collect();
    assert_eq!(refuse_refs(&many), SyntheticImageError::TooManyReferences);
    let too_long = format!(
        "{}.example/app:1",
        "a".repeat(MAX_SYNTHETIC_REF_BYTES + 1 - ".example/app:1".len())
    );
    assert_eq!(too_long.len(), 513);
    assert_eq!(
        refuse_refs(&[REF.to_string(), too_long]),
        SyntheticImageError::ReferenceTooLong { index: 1 }
    );
    assert_eq!(
        refuse_refs(&refs(&[REF, "not a ref"])),
        SyntheticImageError::InvalidReference { index: 1 }
    );
    assert_eq!(
        refuse_refs(&refs(&["registry.example/app"])),
        SyntheticImageError::InvalidReference { index: 0 }
    );
    assert_eq!(
        refuse_refs(&refs(&[REF, "a:1", REF])),
        SyntheticImageError::DuplicateReference { index: 2 }
    );
    assert_eq!(
        refuse_refs(&refs(&["x:1", "docker.io/library/x:1"])),
        SyntheticImageError::DuplicateReference { index: 1 }
    );
}

#[test]
fn every_error_variant_is_nameable_with_its_fields() {
    let errors = [
        SyntheticImageError::InvalidVariant,
        SyntheticImageError::TooManyLayers,
        SyntheticImageError::TooManyEntries { layer: 1 },
        SyntheticImageError::TooManyTotalEntries { layer: 2 },
        SyntheticImageError::LayerTooLarge { layer: 3 },
        SyntheticImageError::ImageTooLarge { layer: 4 },
        SyntheticImageError::InvalidEntryPath { layer: 5, entry: 6 },
        SyntheticImageError::PathNotRepresentable { layer: 7, entry: 8 },
        SyntheticImageError::InvalidLinkTarget {
            layer: 9,
            entry: 10,
        },
        SyntheticImageError::CompressionExpanded { layer: 11 },
        SyntheticImageError::NoReferences,
        SyntheticImageError::TooManyReferences,
        SyntheticImageError::ReferenceTooLong { index: 12 },
        SyntheticImageError::InvalidReference { index: 13 },
        SyntheticImageError::DuplicateReference { index: 14 },
        SyntheticImageError::Generation {
            kind: ErrorKind::OutOfMemory,
        },
    ];
    for error in &errors {
        let message = error.to_string();
        assert!(!message.is_empty());
        assert!(!message.ends_with('.'), "{message}");
        assert_eq!(
            message.chars().next().map(char::is_lowercase),
            Some(true),
            "{message}"
        );
        assert!(!describe_builder_error(error).is_empty());
    }
    let checks = [
        ArchiveCheckError::Image(ImageVerifyError::LegacyImageEvidence {
            archive_path: ARCHIVE_PATH.to_string(),
        }),
        ArchiveCheckError::LimitExceeded {
            resource: LimitResource::ImageArchive,
            limit: 7,
        },
        ArchiveCheckError::Io(io::Error::from(ErrorKind::PermissionDenied)),
    ];
    for error in &checks {
        assert!(!describe_check_error(error).is_empty());
        assert!(!error.to_string().ends_with('.'));
    }
}

// ---------------------------------------------------------------------------
// Worst case
// ---------------------------------------------------------------------------

#[test]
fn an_archive_at_the_combined_maxima_is_accepted_under_default_limits() {
    let entries_per_layer = MAX_SYNTHETIC_TOTAL_ENTRIES / MAX_SYNTHETIC_LAYERS;
    assert_eq!(entries_per_layer, 256);
    let split = format!("{}/{}", "p".repeat(155), "n".repeat(99));
    assert_eq!(split.len(), MAX_SYNTHETIC_PATH_BYTES);
    let variant = "v".repeat(64);
    let mut builder = builder(platform(ImageArchitecture::Arm64, Some(&variant)));
    for at in 0..MAX_SYNTHETIC_LAYERS {
        let mut layer = SyntheticLayer::new();
        let mut entries = 0;
        if at == 0 {
            layer = layer.file(&split, "split");
            entries += 1;
        }
        while entries < entries_per_layer {
            layer = layer.file(
                &format!("l{at}/e{entries}"),
                vec![u8::try_from(entries % 251).unwrap()],
            );
            entries += 1;
        }
        builder = builder
            .layer(layer, LayerCompression::Uncompressed)
            .unwrap();
    }
    let public_refs = longest_refs();
    let archive = builder.finish(&public_refs).unwrap();
    assert_eq!(archive.diff_ids().len(), MAX_SYNTHETIC_LAYERS);
    check(&archive, &matching(&archive, &public_refs)).unwrap();
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

#[test]
fn a_mismatched_declaration_is_the_validators_verdict_with_the_callers_path() {
    let public_refs = refs(&[REF]);
    let archive = sample().finish(&public_refs).unwrap();
    let good = matching(&archive, &public_refs);

    let mut wrong_digest = good.clone();
    wrong_digest.config_digest = format!("sha256:{}", "0".repeat(64));
    match check(&archive, &wrong_digest) {
        Err(ArchiveCheckError::Image(ImageVerifyError::ConfigDigestMismatch {
            archive_path,
            declared,
            actual,
        })) => {
            assert_eq!(archive_path, ARCHIVE_PATH);
            assert_eq!(declared, wrong_digest.config_digest);
            assert_eq!(actual, archive.config_digest());
        }
        other => panic!("expected a config digest mismatch, got {other:?}"),
    }

    let mut wrong_tags = good.clone();
    wrong_tags.public_refs = refs(&["registry.example/synthetic/app:2.0"]);
    match check(&archive, &wrong_tags) {
        Err(ArchiveCheckError::Image(ImageVerifyError::UndeclaredReference {
            archive_path,
            reference,
            source: ReferenceSource::RepoTags,
        })) => {
            assert_eq!(archive_path, ARCHIVE_PATH);
            assert_eq!(reference, REF);
        }
        other => panic!("expected an undeclared reference, got {other:?}"),
    }

    let mut wrong_variant = good;
    wrong_variant.platform.variant = Some("v7".to_string());
    match check(&archive, &wrong_variant) {
        Err(ArchiveCheckError::Image(ImageVerifyError::ConfigPlatformMismatch {
            archive_path,
            location: PlatformLocation::Config,
            facet: PlatformFacet::Variant,
            declared,
            actual,
        })) => {
            assert_eq!(archive_path, ARCHIVE_PATH);
            assert_eq!(declared.as_deref(), Some("v7"));
            assert_eq!(actual.as_deref(), Some("v8"));
        }
        other => panic!("expected a variant mismatch, got {other:?}"),
    }
}

/// A source that fails with `PermissionDenied` once `limit` bytes have been
/// read.
struct Failing {
    inner: Cursor<Vec<u8>>,
    limit: u64,
}

impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let position = self.inner.position();
        if position >= self.limit {
            return Err(io::Error::new(ErrorKind::PermissionDenied, "denied"));
        }
        let allowed =
            usize::try_from(self.limit - position).map_or(buf.len(), |left| left.min(buf.len()));
        self.inner.read(&mut buf[..allowed])
    }
}

impl Seek for Failing {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn a_failing_source_is_an_io_error_with_its_kind() {
    let public_refs = refs(&[REF]);
    let archive = sample().finish(&public_refs).unwrap();
    let declaration = matching(&archive, &public_refs);
    let source = Failing {
        inner: Cursor::new(archive.bytes().to_vec()),
        limit: 1500,
    };
    match check_image_archive(source, "not/a/real/path.tar", &declaration) {
        Err(ArchiveCheckError::Io(error)) => {
            assert_eq!(error.kind(), ErrorKind::PermissionDenied);
            assert!(!error.to_string().contains("not/a/real/path.tar"));
        }
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

#[test]
fn the_placeholder_image_of_the_signed_v6_fixture_is_refused() {
    let package = std::fs::File::open(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/test-fixtures/signed-v6-images/package.pkg"
    ))
    .unwrap();
    let mut payload = deploy_core::payload::open_package(package).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let extracted = payload.extract_to(dir.path()).unwrap();
    let mut images = 0;
    for artifact in &extracted {
        let Some(declaration) = &artifact.artifact.image else {
            continue;
        };
        images += 1;
        let member = std::fs::File::open(&artifact.path).unwrap();
        let archive_path = &artifact.artifact.archive_path;
        match check_image_archive(member, archive_path, declaration) {
            Err(ArchiveCheckError::Image(ImageVerifyError::InvalidArchive {
                archive_path: reported,
                reason:
                    InvalidArchiveReason::Tar {
                        fault: TarFault::Truncated,
                    },
            })) => assert_eq!(&reported, archive_path),
            other => panic!("expected the placeholder to be refused, got {other:?}"),
        }
    }
    assert_eq!(images, 2);
}
