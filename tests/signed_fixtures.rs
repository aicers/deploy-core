//! Genuinely signed format-6 fixtures built entirely through the public API,
//! the way an image consumer builds them in its own tests: real image
//! archives from the synthetic builder, a test key minted per test, and
//! `package::prepare_sign_finalize` — or the detached preparation, reopen and
//! finalization it composes — followed by a full re-verification of the
//! published file.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use deploy_core::image::test_support::{
    LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer,
};
use deploy_core::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle, RegistryProvenance,
    canonical_runtime_alias,
};
use deploy_core::manifest::{ArtifactKind, Disposition, TargetArch};
use deploy_core::package::{
    ContentError, ContentLimits, FinalizedPackage, PreparationBinding, VerifiedContents,
    VerifiedImages, finalize_package, prepare_package, prepare_sign_finalize, reopen_prepared,
    verify_contents,
};
use deploy_core::payload::{ArtifactInput, Signed};
use deploy_core::verify::{
    ImageVerifyError, TRUST_TARGET, TrustAnchor, TrustSet, VerifyError, VerifyRequest, key_id,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;

const COMPONENT: &str = "example-app";
const VERSION: &str = "1.0.0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const NAMESPACE: &str = "example-product";
const PINNED: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SELECTED: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

// ---------------------------------------------------------------------------
// Test key and directories
// ---------------------------------------------------------------------------

/// An Ed25519 key minted for one test, and the trust set anchoring only it.
struct TestSigner {
    pair: Ed25519KeyPair,
}

impl TestSigner {
    fn new() -> TestSigner {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a fresh test key");
        TestSigner {
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

    fn trust_at(&self, epoch: u64) -> TrustSet {
        TrustSet::new(
            vec![TrustAnchor::new(self.public_key(), false)],
            Vec::new(),
            0,
            epoch,
        )
        .expect("a one-anchor trust set")
    }

    fn trust(&self) -> TrustSet {
        self.trust_at(0)
    }

    /// Signs the raw manifest bytes, never a digest of them.
    fn sign(&self, manifest: &[u8]) -> Signed {
        Signed {
            signature: self.pair.sign(manifest).as_ref().to_vec(),
            key_id: key_id(&self.public_key()),
        }
    }
}

/// A canonical private directory: no component of its path is a symlink.
struct Dir {
    _dir: TempDir,
    path: PathBuf,
}

impl Dir {
    fn new() -> Dir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = std::fs::canonicalize(dir.path()).expect("a canonical path");
        Dir { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// One outer build: an own image, three dependencies, Compose and a binary
// ---------------------------------------------------------------------------

/// One artifact of the outer build: its bytes and how it is declared.
struct Artifact {
    path: &'static str,
    kind: ArtifactKind,
    bytes: Vec<u8>,
    image: Option<ImageDeclaration>,
}

fn owner() -> ImageOwner {
    ImageOwner {
        namespace: NAMESPACE.to_string(),
        component: COMPONENT.to_string(),
    }
}

fn platform(arch: TargetArch, variant: Option<&str>) -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::for_target(arch),
        variant: variant.map(ToString::to_string),
    }
}

fn product_build() -> ImageProvenance {
    ImageProvenance::ProductBuild(ProductBuildProvenance {
        repository: "https://example.com/app.git".to_string(),
        commit: COMMIT.to_string(),
    })
}

fn image(path: &'static str, bytes: Vec<u8>, declaration: ImageDeclaration) -> Artifact {
    Artifact {
        path,
        kind: ArtifactKind::ContainerImage,
        bytes,
        image: Some(declaration),
    }
}

/// The component's own image: built from product source, its app tag
/// managed by the runtime.
fn own_image(arch: TargetArch) -> Artifact {
    let platform = platform(arch, None);
    let refs = vec![format!("ghcr.io/example/{COMPONENT}:{VERSION}")];
    let archive = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new()
                .dir("app")
                .file("app/run", b"#!/bin/sh\nexec app\n".to_vec()),
            LayerCompression::Gzip,
        )
        .expect("a valid layer")
        .finish(&refs)
        .expect("the app tag is valid");
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: "app".to_string(),
        public_refs: refs,
        platform,
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::ManagedRuntime,
        provenance: product_build(),
    };
    image("images/app.tar", archive.into_bytes(), declaration)
}

/// A third-party dependency normalized under its canonical runtime alias,
/// built config first and tagged last.
fn managed_dependency(arch: TargetArch) -> (Artifact, String) {
    let variant = match arch {
        TargetArch::X86_64 => "v3",
        TargetArch::Aarch64 => "v8",
    };
    let platform = platform(arch, Some(variant));
    let dependency = "database";

    // 1. Every layer, and nothing after that affects the config.
    let builder = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new().file("etc/database.conf", b"port = 5432\n".to_vec()),
            LayerCompression::Gzip,
        )
        .expect("a valid layer")
        .layer(
            SyntheticLayer::new()
                .dir("var/lib/database")
                .symlink("etc/current.conf", "database.conf"),
            LayerCompression::Uncompressed,
        )
        .expect("a valid layer");
    // 2. The config digest.
    let digest = builder.config_digest();
    // 3. The alias derived from it.
    let alias =
        canonical_runtime_alias(NAMESPACE, COMPONENT, dependency, &digest).expect("an alias");
    // 4. Only now the tags.
    let archive = builder
        .finish(std::slice::from_ref(&alias))
        .expect("the alias tags it");
    // 5. The finished archive's config is the one the alias names.
    assert_eq!(archive.config_digest(), digest);

    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: dependency.to_string(),
        public_refs: vec![alias.clone()],
        platform,
        config_digest: digest,
        reference_lifecycle: ReferenceLifecycle::ManagedRuntime,
        provenance: ImageProvenance::Registry(RegistryProvenance {
            repository: "docker.io/library/postgres".to_string(),
            tag: "16".to_string(),
            version: Some("16.4.0".to_string()),
            pinned_digest: PINNED.to_string(),
            selected_manifest_digest: SELECTED.to_string(),
        }),
    };
    (
        image("images/database.tar", archive.into_bytes(), declaration),
        alias,
    )
}

/// A registry dependency shared with the world under its public tag.
fn shared_dependency(arch: TargetArch) -> Artifact {
    let platform = platform(arch, None);
    let refs = vec!["docker.io/library/redis:7.2".to_string()];
    let archive = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new().file("etc/redis.conf", b"maxmemory 64mb\n".to_vec()),
            LayerCompression::Uncompressed,
        )
        .expect("a valid layer")
        .finish(&refs)
        .expect("the public tag is valid");
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: "cache".to_string(),
        public_refs: refs,
        platform,
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::Registry(RegistryProvenance {
            repository: "docker.io/library/redis".to_string(),
            tag: "7.2".to_string(),
            version: Some("7.2.0".to_string()),
            pinned_digest: PINNED.to_string(),
            selected_manifest_digest: SELECTED.to_string(),
        }),
    };
    image("images/cache.tar", archive.into_bytes(), declaration)
}

/// A dependency the product builds from its own source.
fn product_dependency(arch: TargetArch) -> Artifact {
    let platform = platform(arch, None);
    let refs = vec![format!("ghcr.io/example/worker:{VERSION}")];
    let archive = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new().file("worker/run", b"worker binary".to_vec()),
            LayerCompression::Gzip,
        )
        .expect("a valid layer")
        .layer(
            SyntheticLayer::new().file("worker/config.toml", b"threads = 4\n".to_vec()),
            LayerCompression::Uncompressed,
        )
        .expect("a valid layer")
        .finish(&refs)
        .expect("the tag is valid");
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: "worker".to_string(),
        public_refs: refs,
        platform,
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: product_build(),
    };
    image("images/worker.tar", archive.into_bytes(), declaration)
}

fn plain(path: &'static str, kind: ArtifactKind, bytes: &[u8]) -> Artifact {
    Artifact {
        path,
        kind,
        bytes: bytes.to_vec(),
        image: None,
    }
}

/// The whole outer build for `arch`, and the alias the managed dependency
/// was tagged with.
fn outer_build(arch: TargetArch) -> (Vec<Artifact>, String) {
    let (managed, alias) = managed_dependency(arch);
    let artifacts = vec![
        own_image(arch),
        managed,
        plain(
            "compose.yaml",
            ArtifactKind::ComposeBundle,
            b"services:\n  app: {}\n  database: {}\n  cache: {}\n  worker: {}\n",
        ),
        shared_dependency(arch),
        product_dependency(arch),
        plain("bin/agent", ArtifactKind::NativeBinary, b"\x7fELF agent"),
    ];
    (artifacts, alias)
}

/// Writes each artifact to its own source file and describes it as an input
/// of one outer build.
fn inputs(
    sources: &Dir,
    artifacts: &[Artifact],
    component: &str,
    version: &str,
    arch: TargetArch,
) -> Vec<ArtifactInput> {
    artifacts
        .iter()
        .enumerate()
        .map(|(at, artifact)| {
            let source = sources.path().join(format!("source-{at}"));
            std::fs::write(&source, &artifact.bytes).expect("the source is written");
            ArtifactInput {
                component: component.to_string(),
                version: version.to_string(),
                commit: COMMIT.to_string(),
                target_arch: arch,
                kind: artifact.kind,
                dispositions: BTreeSet::from([Disposition::Install]),
                archive_path: artifact.path.to_string(),
                spec: None,
                image: artifact.image.clone(),
                source,
            }
        })
        .collect()
}

fn namespaced_request() -> VerifyRequest {
    VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, NAMESPACE)
        .expect("a valid request")
}

/// Publishes `finalized` into a fresh directory and verifies the published
/// file from scratch, as a store receiving it would.
fn publish_and_reverify(
    finalized: &FinalizedPackage,
    trust: &TrustSet,
    request: &VerifyRequest,
    arch: TargetArch,
) -> (Vec<u8>, VerifiedContents) {
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    let receipt = finalized.publish(&destination).expect("publishes");
    assert_eq!(receipt.len(), finalized.bytes().len());
    assert_eq!(receipt.sha256(), finalized.bytes().sha256());
    let published = std::fs::read(&destination).expect("the published file");
    let staging = Dir::new();
    let contents = verify_contents(
        std::fs::File::open(&destination).expect("opens"),
        trust,
        request,
        arch,
        &ContentLimits::default(),
        staging.path(),
    )
    .expect("the published package verifies");
    (published, contents)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn an_outer_build_with_its_own_image_and_three_dependencies_finalizes_and_reverifies() {
    for arch in [TargetArch::X86_64, TargetArch::Aarch64] {
        let signer = TestSigner::new();
        let (artifacts, alias) = outer_build(arch);
        let sources = Dir::new();
        let inputs = inputs(&sources, &artifacts, COMPONENT, VERSION, arch);
        let staging = Dir::new();
        let request = namespaced_request();

        let finalized = prepare_sign_finalize(
            &inputs,
            None,
            None,
            &request,
            arch,
            &ContentLimits::default(),
            staging.path(),
            &signer.trust(),
            |manifest| Ok(signer.sign(manifest)),
        )
        .expect("the outer build finalizes");
        assert_eq!(finalized.binding().target_arch(), arch);
        assert_eq!(finalized.binding().namespace(), Some(NAMESPACE));

        let (published, contents) =
            publish_and_reverify(&finalized, &signer.trust(), &request, arch);
        let mut retained = Vec::new();
        std::io::Read::read_to_end(&mut finalized.bytes().reader(), &mut retained).expect("reads");
        assert_eq!(published, retained);

        // Every image, in manifest order, with its declaration.
        let VerifiedImages::Present(images) = contents.images() else {
            panic!("the images are present");
        };
        let declared: Vec<&ImageDeclaration> = artifacts
            .iter()
            .filter_map(|artifact| artifact.image.as_ref())
            .collect();
        assert_eq!(images.len(), 4);
        for (verified, declaration) in images.iter().zip(&declared) {
            assert_eq!(verified.declaration(), *declaration);
        }
        let managed = images
            .iter()
            .find(|image| image.declaration().dependency == "database")
            .expect("the managed dependency");
        assert_eq!(
            managed.declaration().public_refs,
            std::slice::from_ref(&alias)
        );
        assert_eq!(
            managed.declaration().reference_lifecycle,
            ReferenceLifecycle::ManagedRuntime
        );
        assert!(alias.starts_with("runtime.invalid/"), "{alias}");

        // Every artifact's bytes, native and Compose included.
        for (verified, artifact) in contents.artifacts().iter().zip(&artifacts) {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut verified.bytes().reader(), &mut bytes).expect("reads");
            assert_eq!(bytes, artifact.bytes, "{}", artifact.path);
        }
    }
}

#[test]
fn the_detached_flow_across_a_persisted_preparation_gives_the_same_package() {
    let arch = TargetArch::Aarch64;
    let signer = TestSigner::new();
    let (artifacts, _) = outer_build(arch);
    let sources = Dir::new();
    let inputs = inputs(&sources, &artifacts, COMPONENT, VERSION, arch);
    let request = namespaced_request();
    let limits = ContentLimits::default();

    // The build job: prepare, persist, and save the binding independently.
    let build_staging = Dir::new();
    let prepared = prepare_package(
        &inputs,
        None,
        None,
        &request,
        arch,
        &limits,
        build_staging.path(),
    )
    .expect("prepares");
    let out = Dir::new();
    let persisted = out.path().join("prepared");
    prepared.persist(&persisted).expect("persists");
    let saved = prepared.binding().to_record_bytes();
    let manifest = prepared.manifest_bytes().to_vec();
    drop(prepared);

    // The signing job sees only raw M.
    let response = signer.sign(&manifest);

    // The finalizing job: reopen against the saved binding, then finalize.
    let binding = PreparationBinding::from_record_bytes(&saved).expect("the saved binding");
    let staging = Dir::new();
    let reopened = reopen_prepared(
        &persisted,
        &binding,
        &request,
        arch,
        &limits,
        staging.path(),
    )
    .expect("reopens");
    let finalized = finalize_package(
        &reopened,
        &binding,
        &response,
        &signer.trust(),
        &request,
        arch,
        &limits,
        staging.path(),
    )
    .expect("finalizes");
    let (detached, _) = publish_and_reverify(&finalized, &signer.trust(), &request, arch);

    // The one-call composition over the same inputs is the same package.
    let composed_staging = Dir::new();
    let composed = prepare_sign_finalize(
        &inputs,
        None,
        None,
        &request,
        arch,
        &limits,
        composed_staging.path(),
        &signer.trust(),
        |manifest| Ok(signer.sign(manifest)),
    )
    .expect("composes");
    let (composed, _) = publish_and_reverify(&composed, &signer.trust(), &request, arch);
    assert_eq!(detached, composed);
}

#[test]
fn an_image_free_native_package_finalizes_and_reverifies() {
    let arch = TargetArch::X86_64;
    let signer = TestSigner::new();
    let artifacts = [
        plain("bin/tool", ArtifactKind::NativeBinary, b"\x7fELF tool"),
        plain(
            "share/tool.conf",
            ArtifactKind::StaticAssets,
            b"level = 1\n",
        ),
    ];
    let sources = Dir::new();
    let inputs = inputs(&sources, &artifacts, COMPONENT, VERSION, arch);
    let request = VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("a request");
    let staging = Dir::new();
    let finalized = prepare_sign_finalize(
        &inputs,
        None,
        None,
        &request,
        arch,
        &ContentLimits::default(),
        staging.path(),
        &signer.trust(),
        |manifest| Ok(signer.sign(manifest)),
    )
    .expect("the native package finalizes");
    let (_, contents) = publish_and_reverify(&finalized, &signer.trust(), &request, arch);
    assert!(matches!(contents.images(), VerifiedImages::None));
    assert_eq!(contents.artifacts().len(), 2);
}

#[test]
fn a_reserved_trust_package_finalizes_and_reverifies_under_its_epoch() {
    let arch = TargetArch::X86_64;
    let signer = TestSigner::new();
    let artifacts = [plain(
        "trust-set.json",
        ArtifactKind::StaticAssets,
        b"{\"generation\":8}",
    )];
    let sources = Dir::new();
    let inputs = inputs(&sources, &artifacts, TRUST_TARGET, "8", arch);
    let request = VerifyRequest::for_trust("8", COMMIT, 5).expect("a trust request");
    let staging = Dir::new();
    let finalized = prepare_sign_finalize(
        &inputs,
        None,
        None,
        &request,
        arch,
        &ContentLimits::default(),
        staging.path(),
        &signer.trust_at(4),
        |manifest| Ok(signer.sign(manifest)),
    )
    .expect("the trust package finalizes past the active epoch");
    assert_eq!(finalized.binding().trust_epoch(), Some(5));
    publish_and_reverify(&finalized, &signer.trust_at(4), &request, arch);
}

#[test]
fn the_checked_in_placeholder_image_package_is_refused() {
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
    let staging = Dir::new();
    let result = verify_contents(
        Cursor::new(&package),
        &trust,
        &request,
        first.target_arch,
        &ContentLimits::default(),
        staging.path(),
    );
    assert!(
        matches!(
            result,
            Err(ContentError::Verify(VerifyError::Image(
                ImageVerifyError::InvalidArchive { .. }
            )))
        ),
        "the placeholder images are not image archives: {result:?}"
    );
}
