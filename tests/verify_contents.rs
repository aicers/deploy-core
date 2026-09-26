//! `package::verify_contents`, exercised from outside the crate the way a
//! consumer calls it: packages written by the public writer and signed by a
//! key minted for the test, images from the synthetic builder.

use std::collections::BTreeSet;
use std::io::{Cursor, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use deploy_core::image::test_support::{
    LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer,
};
use deploy_core::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle, RegistryProvenance,
    canonical_runtime_alias,
};
use deploy_core::manifest::{ArtifactKind, Disposition, ManifestError, TargetArch};
use deploy_core::package::{
    ContentError, ContentLimits, IoOperation, LimitResource, PublicationError, RetainedBytes,
    VerifiedContents, VerifiedImages, verify_contents,
};
use deploy_core::payload::{
    ArtifactInput, FORMAT_VERSION, MAGIC, PayloadError, Signed, append_trailer_signed,
};
use deploy_core::verify::{
    ImageReferences, ImageVerifyError, InvalidArchiveReason, TRUST_TARGET, TarFault, TrustAnchor,
    TrustSet, VerifyError, VerifyRequest, key_id, verify_package,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const COMPONENT: &str = "example-app";
const VERSION: &str = "1.0.0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const NEXT_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";
const NAMESPACE: &str = "example-product";
const PINNED: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SELECTED: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct Signer {
    pair: Ed25519KeyPair,
}

impl Signer {
    fn new() -> Signer {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a fresh test key");
        Signer {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("the key parses"),
        }
    }

    fn public_key(&self) -> [u8; 32] {
        self.pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("a 32-byte key")
    }

    fn trust(&self) -> TrustSet {
        self.trust_at(0)
    }

    fn trust_at(&self, epoch: u64) -> TrustSet {
        TrustSet::new(
            vec![TrustAnchor::new(self.public_key(), false)],
            Vec::new(),
            0,
            epoch,
        )
        .expect("a one-anchor trust set")
    }

    fn sign(&self, manifest: &[u8]) -> Signed {
        Signed {
            signature: self.pair.sign(manifest).as_ref().to_vec(),
            key_id: key_id(&self.public_key()),
        }
    }
}

/// A canonical staging parent: no component of its path is a symlink.
struct Staging {
    _dir: TempDir,
    path: PathBuf,
}

impl Staging {
    fn new() -> Staging {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = std::fs::canonicalize(dir.path()).expect("a canonical path");
        Staging { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.path)
            .expect("the directory lists")
            .next()
            .is_none()
    }
}

/// One artifact to write: its bytes and how the manifest describes it.
struct Input {
    path: &'static str,
    kind: ArtifactKind,
    arch: TargetArch,
    bytes: Vec<u8>,
    image: Option<ImageDeclaration>,
}

fn platform(arch: TargetArch, variant: Option<&str>) -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::for_target(arch),
        variant: variant.map(ToString::to_string),
    }
}

fn owner() -> ImageOwner {
    ImageOwner {
        namespace: NAMESPACE.to_string(),
        component: COMPONENT.to_string(),
    }
}

fn product_build() -> ImageProvenance {
    ImageProvenance::ProductBuild(ProductBuildProvenance {
        repository: "https://example.com/app.git".to_string(),
        commit: COMMIT.to_string(),
    })
}

/// A product-built image under its own tag, shared externally.
fn product_image(
    path: &'static str,
    arch: TargetArch,
    dependency: &str,
    variant: Option<&str>,
    compression: LayerCompression,
) -> Input {
    let platform = platform(arch, variant);
    let refs = vec![format!("ghcr.io/example/{dependency}:{VERSION}")];
    let archive = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new()
                .dir("app")
                .file("app/run", format!("{dependency} binary")),
            compression,
        )
        .expect("a valid layer")
        .finish(&refs)
        .expect("valid references");
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: dependency.to_string(),
        public_refs: refs,
        platform,
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: product_build(),
    };
    Input {
        path,
        kind: ArtifactKind::ContainerImage,
        arch,
        bytes: archive.into_bytes(),
        image: Some(declaration),
    }
}

/// A third-party image normalized under its canonical runtime alias, which
/// is derived from the config digest before the image is tagged.
fn normalized_image(
    path: &'static str,
    arch: TargetArch,
    dependency: &str,
    variant: Option<&str>,
    compression: LayerCompression,
) -> Input {
    let platform = platform(arch, variant);
    let builder = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new().file("etc/conf", format!("{dependency} config")),
            compression,
        )
        .expect("a valid layer")
        .layer(
            SyntheticLayer::new().symlink("etc/link", "conf"),
            LayerCompression::Uncompressed,
        )
        .expect("a valid layer");
    let config = builder.config_digest();
    let alias =
        canonical_runtime_alias(NAMESPACE, COMPONENT, dependency, &config).expect("an alias");
    let declaration = ImageDeclaration::normalized_third_party(
        owner(),
        dependency,
        platform,
        &config,
        RegistryProvenance {
            repository: format!("docker.io/library/{dependency}"),
            tag: "1.0".to_string(),
            version: Some("1.0.0".to_string()),
            pinned_digest: PINNED.to_string(),
            selected_manifest_digest: SELECTED.to_string(),
        },
    )
    .expect("a normalized declaration");
    assert_eq!(declaration.public_refs, [alias]);
    let archive = builder
        .finish(&declaration.public_refs)
        .expect("the alias tags it");
    Input {
        path,
        kind: ArtifactKind::ContainerImage,
        arch,
        bytes: archive.into_bytes(),
        image: Some(declaration),
    }
}

fn plain(path: &'static str, kind: ArtifactKind, arch: TargetArch, bytes: &[u8]) -> Input {
    Input {
        path,
        kind,
        arch,
        bytes: bytes.to_vec(),
        image: None,
    }
}

/// Six images and two deployment files for `arch`, covering both
/// provenances, both lifecycles, canonical aliases, explicit and null
/// variants, and gzip and uncompressed layers.
fn six_images(arch: TargetArch) -> Vec<Input> {
    let variant = match arch {
        TargetArch::X86_64 => "v3",
        TargetArch::Aarch64 => "v8",
    };
    vec![
        product_image("images/web.tar", arch, "web", None, LayerCompression::Gzip),
        normalized_image(
            "images/database.tar",
            arch,
            "database",
            None,
            LayerCompression::Gzip,
        ),
        plain(
            "compose.yaml",
            ArtifactKind::ComposeBundle,
            arch,
            b"services:\n  web: {}\n",
        ),
        product_image(
            "images/worker.tar",
            arch,
            "worker",
            Some(variant),
            LayerCompression::Uncompressed,
        ),
        normalized_image(
            "images/cache.tar",
            arch,
            "cache",
            Some(variant),
            LayerCompression::Uncompressed,
        ),
        product_image(
            "images/api.tar",
            arch,
            "api",
            None,
            LayerCompression::Uncompressed,
        ),
        normalized_image(
            "images/queue.tar",
            arch,
            "queue",
            None,
            LayerCompression::Gzip,
        ),
        plain(
            "bin/agent",
            ArtifactKind::NativeBinary,
            arch,
            b"\x7fELF agent",
        ),
    ]
}

/// Writes `inputs` as a signed package through the public writer.
fn write(signer: &Signer, inputs: &[Input], component: &str, commit: &str) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("a source directory");
    let artifact_inputs: Vec<ArtifactInput> = inputs
        .iter()
        .enumerate()
        .map(|(at, input)| {
            let source = dir.path().join(format!("source-{at}"));
            std::fs::write(&source, &input.bytes).expect("the source is written");
            ArtifactInput {
                component: component.to_string(),
                version: VERSION.to_string(),
                commit: commit.to_string(),
                target_arch: input.arch,
                kind: input.kind,
                dispositions: BTreeSet::from([Disposition::Install]),
                archive_path: input.path.to_string(),
                spec: None,
                image: input.image.clone().map(|mut image| {
                    image.owner.component = component.to_string();
                    image
                }),
                source,
            }
        })
        .collect();
    let mut out = Vec::new();
    append_trailer_signed(
        std::io::empty(),
        &mut out,
        None,
        None,
        &artifact_inputs,
        |manifest| Ok(signer.sign(manifest)),
    )
    .expect("the package is written");
    out
}

fn request() -> VerifyRequest {
    VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, NAMESPACE)
        .expect("a valid request")
}

fn verify(
    bytes: &[u8],
    trust: &TrustSet,
    request: &VerifyRequest,
    arch: TargetArch,
) -> (Result<VerifiedContents, ContentError>, Staging) {
    let staging = Staging::new();
    let result = verify_contents(
        Cursor::new(bytes),
        trust,
        request,
        arch,
        &ContentLimits::default(),
        staging.path(),
    );
    if result.is_err() {
        assert!(staging.is_empty(), "a refusal leaves nothing behind");
    }
    (result, staging)
}

fn read_all(bytes: &RetainedBytes) -> Vec<u8> {
    let mut out = Vec::new();
    bytes
        .reader()
        .read_to_end(&mut out)
        .expect("retained bytes read");
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Splits a current-version container into its manifest and archive blocks.
fn blocks(package: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let footer = &package[package.len() - 73..];
    assert_eq!(&footer[..8], &MAGIC);
    let field = |at: usize| {
        let start = 9 + at * 8;
        usize::try_from(u64::from_le_bytes(
            footer[start..start + 8].try_into().expect("8 bytes"),
        ))
        .expect("fits")
    };
    let (manifest_offset, manifest_len) = (field(0), field(1));
    let (archive_offset, archive_len) = (field(2), field(3));
    (
        package[manifest_offset..manifest_offset + manifest_len].to_vec(),
        package[archive_offset..archive_offset + archive_len].to_vec(),
    )
}

/// Assembles a signed `.pkg` around a raw manifest and archive block.
fn assemble(signer: &Signer, manifest: &[u8], archive: &[u8]) -> Vec<u8> {
    let stamp = signer.sign(manifest);
    let len = |bytes: &[u8]| bytes.len() as u64;
    let mut out = Vec::new();
    out.extend_from_slice(manifest);
    out.extend_from_slice(archive);
    let signature_offset = len(manifest) + len(archive);
    out.extend_from_slice(&stamp.signature);
    let key_offset = signature_offset + len(&stamp.signature);
    out.extend_from_slice(stamp.key_id.as_bytes());
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    for field in [
        0,
        len(manifest),
        len(manifest),
        len(archive),
        signature_offset,
        len(&stamp.signature),
        key_offset,
        len(stamp.key_id.as_bytes()),
    ] {
        out.extend_from_slice(&u64::to_le_bytes(field));
    }
    out
}

/// Rewrites a package's manifest JSON with `edit` and re-signs it.
fn edited(signer: &Signer, package: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let (manifest, archive) = blocks(package);
    let mut value: Value = serde_json::from_slice(&manifest).expect("json");
    edit(&mut value);
    assemble(signer, &serde_json::to_vec(&value).expect("json"), &archive)
}

fn strip_images(value: &mut Value) {
    for artifact in value["artifacts"].as_array_mut().expect("artifacts") {
        artifact.as_object_mut().expect("an object").remove("image");
    }
}

// ---------------------------------------------------------------------------
// The six-image packages
// ---------------------------------------------------------------------------

#[test]
fn a_six_image_package_verifies_into_complete_evidence_on_both_architectures() {
    for arch in [TargetArch::X86_64, TargetArch::Aarch64] {
        let signer = Signer::new();
        let inputs = six_images(arch);
        let bytes = write(&signer, &inputs, COMPONENT, COMMIT);
        let legacy = verify_package(Cursor::new(&bytes), &signer.trust(), &request())
            .expect("the metadata verifier accepts it");
        let (result, staging) = verify(&bytes, &signer.trust(), &request(), arch);
        let contents = result.expect("the package verifies");

        assert_eq!(contents.manifest(), legacy.manifest());
        assert_eq!(contents.artifacts().len(), inputs.len());
        for (verified, input) in contents.artifacts().iter().zip(&inputs) {
            let artifact = verified.artifact();
            assert_eq!(artifact.archive_path, input.path);
            assert_eq!(artifact.kind, input.kind);
            assert_eq!(verified.member_length(), input.bytes.len() as u64);
            assert_eq!(verified.bytes().len(), input.bytes.len() as u64);
            assert_eq!(verified.bytes().sha256(), &sha256(&input.bytes));
            assert_eq!(hex(verified.bytes().sha256()), artifact.sha256);
            assert_eq!(read_all(verified.bytes()), input.bytes);
        }

        let VerifiedImages::Present(images) = contents.images() else {
            panic!("expected images");
        };
        let expected: Vec<&Input> = inputs
            .iter()
            .filter(|input| input.image.is_some())
            .collect();
        assert_eq!(images.len(), 6);
        assert_eq!(images.iter().count(), 6);
        for (image, input) in images.iter().zip(expected) {
            assert_eq!(image.artifact().archive_path, input.path);
            assert_eq!(Some(image.declaration()), input.image.as_ref());
            assert_eq!(image.member_length(), input.bytes.len() as u64);
            assert_eq!(read_all(image.archive()), input.bytes);
        }
        assert_eq!(read_all(contents.package_bytes()), bytes);
        assert_eq!(contents.package_bytes().sha256(), &sha256(&bytes));

        // Dropping the evidence releases the private directory.
        assert!(!staging.is_empty());
        drop(contents);
        assert!(staging.is_empty());
    }
}

#[test]
fn a_new_commit_of_the_same_version_verifies_when_it_is_requested() {
    let signer = Signer::new();
    let bytes = write(
        &signer,
        &six_images(TargetArch::X86_64),
        COMPONENT,
        NEXT_COMMIT,
    );
    let next = VerifyRequest::for_namespaced_package(COMPONENT, VERSION, NEXT_COMMIT, NAMESPACE)
        .expect("a request");
    verify(&bytes, &signer.trust(), &next, TargetArch::X86_64)
        .0
        .expect("the new commit verifies");
    let (result, _) = verify(&bytes, &signer.trust(), &request(), TargetArch::X86_64);
    assert!(matches!(
        result,
        Err(ContentError::Verify(VerifyError::TargetMismatch { .. }))
    ));
}

#[test]
fn the_wrong_build_namespace_or_architecture_is_refused() {
    let signer = Signer::new();
    let bytes = write(&signer, &six_images(TargetArch::X86_64), COMPONENT, COMMIT);
    let trust = signer.trust();
    let refuse = |request: &VerifyRequest, arch| {
        verify(&bytes, &trust, request, arch)
            .0
            .expect_err("refused")
    };

    let commit = VerifyRequest::for_namespaced_package(COMPONENT, VERSION, NEXT_COMMIT, NAMESPACE)
        .expect("a request");
    assert!(matches!(
        refuse(&commit, TargetArch::X86_64),
        ContentError::Verify(VerifyError::TargetMismatch { .. })
    ));
    let component = VerifyRequest::for_namespaced_package("other-app", VERSION, COMMIT, NAMESPACE)
        .expect("a request");
    assert!(matches!(
        refuse(&component, TargetArch::X86_64),
        ContentError::Verify(VerifyError::TargetMismatch { .. })
    ));
    let namespace =
        VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, "other-product")
            .expect("a request");
    assert!(matches!(
        refuse(&namespace, TargetArch::X86_64),
        ContentError::Verify(VerifyError::Image(
            ImageVerifyError::NamespaceMismatch { .. }
        ))
    ));
    match refuse(&request(), TargetArch::Aarch64) {
        ContentError::ArchitectureMismatch {
            archive_path,
            expected,
            actual,
        } => {
            assert_eq!(archive_path, "images/web.tar");
            assert_eq!(expected, TargetArch::Aarch64);
            assert_eq!(actual, TargetArch::X86_64);
        }
        other => panic!("expected an architecture mismatch, got {other:?}"),
    }
}

#[test]
fn an_image_free_native_package_has_no_images() {
    let signer = Signer::new();
    let inputs = vec![plain(
        "bin/agent",
        ArtifactKind::NativeBinary,
        TargetArch::X86_64,
        b"agent",
    )];
    let bytes = write(&signer, &inputs, COMPONENT, COMMIT);
    let request = VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("a request");
    let (result, _) = verify(&bytes, &signer.trust(), &request, TargetArch::X86_64);
    let contents = result.expect("verifies");
    assert!(matches!(contents.images(), VerifiedImages::None));
    assert_eq!(read_all(contents.artifacts()[0].bytes()), b"agent");
}

#[test]
fn a_reserved_trust_package_verifies_only_under_an_advancing_epoch() {
    let signer = Signer::new();
    let dir = tempfile::tempdir().expect("a source directory");
    let source = dir.path().join("trust-set.json");
    std::fs::write(&source, b"{}").expect("written");
    let input = ArtifactInput {
        component: TRUST_TARGET.to_string(),
        version: "8".to_string(),
        commit: COMMIT.to_string(),
        target_arch: TargetArch::X86_64,
        kind: ArtifactKind::StaticAssets,
        dispositions: BTreeSet::from([Disposition::Install]),
        archive_path: "trust-set.json".to_string(),
        spec: None,
        image: None,
        source,
    };
    let mut bytes = Vec::new();
    append_trailer_signed(
        std::io::empty(),
        &mut bytes,
        None,
        None,
        &[input],
        |manifest| Ok(signer.sign(manifest)),
    )
    .expect("written");
    let fresh = VerifyRequest::for_trust("8", COMMIT, 11).expect("a request");
    verify(&bytes, &signer.trust_at(10), &fresh, TargetArch::X86_64)
        .0
        .expect("an advancing epoch verifies");
    let stale = VerifyRequest::for_trust("8", COMMIT, 10).expect("a request");
    assert!(matches!(
        verify(&bytes, &signer.trust_at(10), &stale, TargetArch::X86_64).0,
        Err(ContentError::Verify(VerifyError::StaleTrustSet {
            delivered: 10,
            active: 10
        }))
    ));
}

// ---------------------------------------------------------------------------
// Legacy and undeclared images
// ---------------------------------------------------------------------------

#[test]
fn a_legacy_package_carrying_images_is_refused_never_image_free() {
    let signer = Signer::new();
    let inputs = six_images(TargetArch::X86_64);
    let current = write(&signer, &inputs, COMPONENT, COMMIT);
    let legacy = edited(&signer, &current, |value| {
        value["format_version"] = Value::from(5);
        strip_images(value);
    });
    let plain_request = VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("a request");
    let admitted = verify_package(Cursor::new(&legacy), &signer.trust(), &plain_request)
        .expect("the legacy verifier admits a version-5 manifest");
    assert!(matches!(
        admitted.image_references(),
        ImageReferences::LegacyUndeclared
    ));
    match verify(&legacy, &signer.trust(), &plain_request, TargetArch::X86_64).0 {
        Err(ContentError::Verify(VerifyError::Image(ImageVerifyError::LegacyImageEvidence {
            archive_path,
        }))) => assert_eq!(archive_path, "images/web.tar"),
        other => panic!("expected legacy image evidence, got {other:?}"),
    }

    // An unversioned manifest is admitted only from a version-1 container,
    // which cannot be signed, so it never reaches the image checks at all.
    let unversioned = edited(&signer, &current, |value| {
        let object = value.as_object_mut().expect("an object");
        object.remove("format_version");
        object.remove("archive_members");
        strip_images(value);
    });
    assert!(matches!(
        verify(
            &unversioned,
            &signer.trust(),
            &plain_request,
            TargetArch::X86_64
        )
        .0,
        Err(ContentError::Verify(VerifyError::Payload(
            PayloadError::InvalidManifest(_)
        )))
    ));
}

#[test]
fn an_undeclared_current_format_image_is_the_typed_parse_refusal() {
    let signer = Signer::new();
    let current = write(&signer, &six_images(TargetArch::X86_64), COMPONENT, COMMIT);
    let undeclared = edited(&signer, &current, strip_images);
    let legacy = verify_package(Cursor::new(&undeclared), &signer.trust(), &request())
        .map(|_| ())
        .expect_err("refused");
    let new = verify(&undeclared, &signer.trust(), &request(), TargetArch::X86_64)
        .0
        .expect_err("refused");
    match new {
        ContentError::Verify(new) => {
            assert!(matches!(
                new,
                VerifyError::Payload(PayloadError::InvalidManifest(
                    ManifestError::MissingImageDeclaration(_)
                ))
            ));
            assert_eq!(format!("{new:?}"), format!("{legacy:?}"));
        }
        other => panic!("expected the typed parse refusal, got {other:?}"),
    }
}

#[test]
fn the_checked_in_metadata_fixture_is_not_full_content_evidence() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/test-fixtures/signed-v6-images");
    let package = std::fs::read(dir.join("package.pkg")).expect("the fixture");
    let key_hex = std::fs::read_to_string(dir.join("public-key.hex")).expect("its key");
    let key_hex = key_hex.trim();
    let key: Vec<u8> = (0..key_hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&key_hex[at..at + 2], 16).expect("hex"))
        .collect();
    let trust = TrustSet::new(
        vec![TrustAnchor::new(key.try_into().expect("32 bytes"), false)],
        Vec::new(),
        0,
        0,
    )
    .expect("a trust set");
    let manifest = deploy_core::payload::open_package(Cursor::new(&package))
        .expect("the fixture opens")
        .manifest()
        .clone();
    let first = &manifest.artifacts()[0];
    let request = VerifyRequest::for_namespaced_package(
        &first.component,
        &first.version,
        first.commit.as_deref().expect("a commit"),
        NAMESPACE,
    )
    .expect("a request");
    verify_package(Cursor::new(&package), &trust, &request).expect("its metadata verifies");
    match verify(&package, &trust, &request, first.target_arch).0 {
        Err(ContentError::Verify(VerifyError::Image(ImageVerifyError::InvalidArchive {
            reason:
                InvalidArchiveReason::Tar {
                    fault: TarFault::Truncated,
                },
            ..
        }))) => {}
        other => panic!("expected the placeholder image to be refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Readers, immutability and publication
// ---------------------------------------------------------------------------

#[test]
fn an_owned_reader_and_a_borrowed_one_both_verify() {
    let signer = Signer::new();
    let bytes = write(&signer, &six_images(TargetArch::X86_64), COMPONENT, COMMIT);
    let staging = Staging::new();
    let limits = ContentLimits::default();
    let owned = verify_contents(
        Cursor::new(bytes.clone()),
        &signer.trust(),
        &request(),
        TargetArch::X86_64,
        &limits,
        staging.path(),
    )
    .expect("an owned reader verifies");
    let mut reader = Cursor::new(bytes.clone());
    reader.seek(SeekFrom::Start(17)).expect("seeks");
    let borrowed = verify_contents(
        &mut reader,
        &signer.trust(),
        &request(),
        TargetArch::X86_64,
        &limits,
        staging.path(),
    )
    .expect("a borrowed reader verifies from its start");
    // The caller keeps its reader.
    reader.seek(SeekFrom::Start(0)).expect("still usable");
    let mut again = Vec::new();
    reader.read_to_end(&mut again).expect("still readable");
    assert_eq!(again, bytes);
    assert_eq!(
        read_all(owned.package_bytes()),
        read_all(borrowed.package_bytes())
    );
}

/// Every accessor's bytes, lengths and digests, for comparison.
fn fingerprint(contents: &VerifiedContents) -> Vec<(Vec<u8>, u64, [u8; 32])> {
    let mut out = vec![(
        read_all(contents.package_bytes()),
        contents.package_bytes().len(),
        *contents.package_bytes().sha256(),
    )];
    for artifact in contents.artifacts() {
        out.push((
            read_all(artifact.bytes()),
            artifact.bytes().len(),
            *artifact.bytes().sha256(),
        ));
    }
    if let VerifiedImages::Present(images) = contents.images() {
        for image in images.iter() {
            out.push((
                read_all(image.archive()),
                image.archive().len(),
                *image.archive().sha256(),
            ));
        }
    }
    out
}

#[test]
fn changing_the_original_after_verification_changes_no_evidence() {
    let signer = Signer::new();
    let bytes = write(&signer, &six_images(TargetArch::X86_64), COMPONENT, COMMIT);
    let source_dir = Staging::new();
    let path = source_dir.path().join("package.pkg");
    std::fs::write(&path, &bytes).expect("the package file");
    let mut kept = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("a writable descriptor");
    let staging = Staging::new();
    let contents = verify_contents(
        std::fs::File::open(&path).expect("opens"),
        &signer.trust(),
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging.path(),
    )
    .expect("verifies");
    let before = fingerprint(&contents);
    assert_eq!(before[0].0, bytes);

    // Through the descriptor kept open.
    kept.seek(SeekFrom::Start(0)).expect("seeks");
    kept.write_all(&vec![0xAA; bytes.len()])
        .expect("overwrites");
    kept.flush().expect("flushes");
    assert_eq!(fingerprint(&contents), before);
    // Overwrite, truncate, delete and replace the path.
    std::fs::write(&path, b"replaced").expect("overwrites");
    assert_eq!(fingerprint(&contents), before);
    kept.set_len(0).expect("truncates");
    assert_eq!(fingerprint(&contents), before);
    std::fs::remove_file(&path).expect("deletes");
    assert_eq!(fingerprint(&contents), before);
    let other = source_dir.path().join("other.pkg");
    std::fs::write(&other, b"something else").expect("written");
    std::fs::rename(&other, &path).expect("replaces");
    assert_eq!(fingerprint(&contents), before);
}

#[test]
fn publishing_writes_exactly_the_package_and_never_clobbers() {
    let signer = Signer::new();
    let bytes = write(&signer, &six_images(TargetArch::X86_64), COMPONENT, COMMIT);
    let (result, _staging) = verify(&bytes, &signer.trust(), &request(), TargetArch::X86_64);
    let contents = result.expect("verifies");
    let out = Staging::new();
    let destination = out.path().join("published.pkg");

    let receipt = contents.publish_package(&destination).expect("publishes");
    assert_eq!(receipt.destination(), destination);
    assert_eq!(receipt.len(), contents.package_bytes().len());
    assert_eq!(receipt.sha256(), contents.package_bytes().sha256());
    assert_eq!(std::fs::read(&destination).expect("published"), bytes);

    match contents.publish_package(&destination) {
        Err(PublicationError::DestinationExists { destination: named }) => {
            assert_eq!(named, destination);
        }
        other => panic!("expected DestinationExists, got {other:?}"),
    }
    assert_eq!(std::fs::read(&destination).expect("unchanged"), bytes);

    std::fs::write(&destination, b"mutated").expect("the published file is ordinary");
    assert_eq!(read_all(contents.package_bytes()), bytes);
}

// ---------------------------------------------------------------------------
// The error surface
// ---------------------------------------------------------------------------

/// Names every `ContentError` variant with its fields, so a new variant fails
/// to compile here until it is covered.
fn describe(error: &ContentError) -> String {
    match error {
        ContentError::Verify(error) => format!("Verify {error}"),
        ContentError::ArchitectureMismatch {
            archive_path,
            expected,
            actual,
        } => format!("ArchitectureMismatch {archive_path} {expected:?} {actual:?}"),
        ContentError::LimitExceeded { resource, limit } => {
            format!("LimitExceeded {resource} {limit}")
        }
        ContentError::Io {
            operation,
            path,
            source,
        } => format!(
            "Io {} {path:?} {:?}",
            operation_name(*operation),
            source.kind()
        ),
    }
}

fn operation_name(operation: IoOperation) -> &'static str {
    match operation {
        IoOperation::SourceSeek => "SourceSeek",
        IoOperation::SourceRead => "SourceRead",
        IoOperation::InspectStagingParent => "InspectStagingParent",
        IoOperation::CreateStaging => "CreateStaging",
        IoOperation::WriteSnapshot => "WriteSnapshot",
        IoOperation::ReadSnapshot => "ReadSnapshot",
    }
}

#[test]
fn every_error_variant_and_operation_is_nameable() {
    let operations = [
        IoOperation::SourceSeek,
        IoOperation::SourceRead,
        IoOperation::InspectStagingParent,
        IoOperation::CreateStaging,
        IoOperation::WriteSnapshot,
        IoOperation::ReadSnapshot,
    ];
    for operation in operations {
        let display = operation.to_string();
        assert!(!display.is_empty());
        assert_eq!(display, display.to_lowercase());
        let error = ContentError::Io {
            operation,
            path: None,
            source: ErrorKind::Other.into(),
        };
        assert!(describe(&error).contains(operation_name(operation)));
    }
    let errors = [
        ContentError::from(VerifyError::BadSignature),
        ContentError::ArchitectureMismatch {
            archive_path: "bin/agent".to_string(),
            expected: TargetArch::X86_64,
            actual: TargetArch::Aarch64,
        },
        ContentError::LimitExceeded {
            resource: LimitResource::Package,
            limit: 1,
        },
    ];
    for error in &errors {
        assert!(!describe(error).is_empty());
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors[1].to_string(),
        "artifact `bin/agent` is built for aarch64, not the requested x86_64"
    );
}

#[test]
fn an_unsafe_staging_parent_is_refused_with_its_path() {
    let signer = Signer::new();
    let bytes = write(&signer, &six_images(TargetArch::X86_64), COMPONENT, COMMIT);
    let root = Staging::new();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(root.path(), &link).expect("a symlink");
    let error = verify_contents(
        Cursor::new(&bytes),
        &signer.trust(),
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        &link,
    )
    .expect_err("refused");
    match error {
        ContentError::Io {
            operation: IoOperation::InspectStagingParent,
            path: Some(path),
            source,
        } => {
            assert_eq!(path, link);
            assert_eq!(source.kind(), ErrorKind::InvalidInput);
        }
        other => panic!("expected InspectStagingParent, got {}", describe(&other)),
    }
}
