//! Fixtures shared by the preparation, persist and reopen tests: source
//! files for a set of artifacts, private staging parents, the six-image
//! package, and the signed container final verification is run over.

use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::contents::tests::fixture::{Art, COMPONENT, NAMESPACE, Signer};
use super::{
    ContentError, ContentLimits, LimitResource, PackageWriteError, PreparedPackage, RetainedBytes,
    VerifiedContents, prepare_package, verify_contents,
};
use crate::image::test_support::{LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer};
use crate::image::{
    ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner, ImagePlatform, RegistryProvenance,
    canonical_runtime_alias,
};
use crate::manifest::{ArtifactKind, Disposition, TargetArch};
use crate::payload::ArtifactInput;
use crate::verify::{TrustSet, VerifyRequest};

const PINNED: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SELECTED: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// A private, canonical directory: no component of its path is a symlink.
pub(crate) struct Dir {
    _dir: TempDir,
    path: PathBuf,
}

impl Dir {
    pub(crate) fn new() -> Dir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = std::fs::canonicalize(dir.path()).expect("a canonical path");
        Dir { _dir: dir, path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Lists the directory's entries, sorted.
    pub(crate) fn entries(&self) -> Vec<String> {
        entries(&self.path)
    }
}

/// Lists `dir`'s entry names, sorted.
pub(crate) fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the directory lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    names.sort_unstable();
    names
}

/// Writes each artifact's bytes to its own source file and describes it as
/// an input.
pub(crate) fn inputs(dir: &Dir, arts: &[Art]) -> Vec<ArtifactInput> {
    arts.iter()
        .enumerate()
        .map(|(at, art)| {
            let source = dir.path().join(format!("source-{at}"));
            std::fs::write(&source, &art.bytes).expect("the source is written");
            input_for(art, source)
        })
        .collect()
}

/// Describes `art` as an input read from `source`, which is not written.
pub(crate) fn input_for(art: &Art, source: PathBuf) -> ArtifactInput {
    ArtifactInput {
        component: art.component.clone(),
        version: art.version.clone(),
        commit: art.commit.clone(),
        target_arch: art.arch,
        kind: art.kind,
        dispositions: BTreeSet::from([Disposition::Install]),
        archive_path: art.path.clone(),
        spec: None,
        image: art.image.clone(),
        source,
    }
}

pub(crate) fn limits(resource: LimitResource, value: u64) -> ContentLimits {
    ContentLimits::default()
        .with_limit(resource, value)
        .expect("a lower limit")
}

/// What one preparation call was given and returned.
pub(crate) struct Prepared {
    pub(crate) result: Result<PreparedPackage, PackageWriteError>,
    pub(crate) sources: Dir,
    pub(crate) inputs: Vec<ArtifactInput>,
    pub(crate) staging: Dir,
}

/// A successful preparation with what it was made from.
pub(crate) struct Ready {
    pub(crate) package: PreparedPackage,
    pub(crate) sources: Dir,
    pub(crate) inputs: Vec<ArtifactInput>,
    /// Held so the package's private directory outlives the test's use.
    _staging: Dir,
}

impl Prepared {
    #[track_caller]
    pub(crate) fn ok(self) -> Ready {
        Ready {
            package: self.result.expect("the package prepares"),
            sources: self.sources,
            inputs: self.inputs,
            _staging: self.staging,
        }
    }

    #[track_caller]
    pub(crate) fn err(self) -> PackageWriteError {
        let error = self.result.expect_err("the package is refused");
        assert!(
            self.staging.entries().is_empty(),
            "a refusal leaves nothing behind: {:?}",
            self.staging.entries()
        );
        error
    }
}

/// Prepares `arts` for `arch` under `request` and `limits`.
pub(crate) fn prepare_with(
    arts: &[Art],
    request: &VerifyRequest,
    arch: TargetArch,
    limits: &ContentLimits,
) -> Prepared {
    let sources = Dir::new();
    let inputs = inputs(&sources, arts);
    let staging = Dir::new();
    let result = prepare_package(&inputs, None, None, request, arch, limits, staging.path());
    Prepared {
        result,
        sources,
        inputs,
        staging,
    }
}

/// Prepares `arts` for `x86_64` under the fixture's namespaced request.
pub(crate) fn prepare(arts: &[Art], limits: &ContentLimits) -> Prepared {
    prepare_with(arts, &request(), TargetArch::X86_64, limits)
}

pub(crate) fn request() -> VerifyRequest {
    super::contents::tests::fixture::request()
}

pub(crate) fn read_all(bytes: &RetainedBytes) -> Vec<u8> {
    let mut out = Vec::new();
    bytes
        .reader()
        .read_to_end(&mut out)
        .expect("retained bytes read");
    out
}

/// The signed standalone container `M ‖ A ‖ signature ‖ key ID ‖ footer`.
pub(crate) fn container(signer: &Signer, prepared: &PreparedPackage) -> Vec<u8> {
    signer.container(prepared.manifest_bytes(), &read_all(prepared.archive()))
}

/// Runs final verification over `bytes`.
pub(crate) fn verify(
    bytes: &[u8],
    trust: &TrustSet,
    request: &VerifyRequest,
    arch: TargetArch,
) -> Result<VerifiedContents, ContentError> {
    let staging = Dir::new();
    verify_contents(
        Cursor::new(bytes),
        trust,
        request,
        arch,
        &ContentLimits::default(),
        staging.path(),
    )
}

/// A third-party image normalized under its canonical runtime alias, derived
/// from the config digest before the image is tagged: the managed-runtime,
/// registry-provenance arm.
pub(crate) fn normalized_image(path: &str, arch: TargetArch, dependency: &str) -> Art {
    let platform = ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::for_target(arch),
        variant: None,
    };
    let builder = SyntheticImageArchiveBuilder::new(platform.clone())
        .expect("a valid platform")
        .layer(
            SyntheticLayer::new().file("etc/conf", format!("{dependency} config")),
            LayerCompression::Uncompressed,
        )
        .expect("a valid layer");
    let config = builder.config_digest();
    let alias =
        canonical_runtime_alias(NAMESPACE, COMPONENT, dependency, &config).expect("an alias");
    let declaration = ImageDeclaration::normalized_third_party(
        ImageOwner {
            namespace: NAMESPACE.to_string(),
            component: COMPONENT.to_string(),
        },
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
    let mut art = Art::native(path, &archive.into_bytes()).on(arch);
    art.kind = ArtifactKind::ContainerImage;
    art.image = Some(declaration);
    art
}

/// Six images — three product-built and shared-external, three normalized
/// third-party and managed-runtime — with a Compose file and a native binary,
/// all for `arch`.
pub(crate) fn six_images(arch: TargetArch) -> Vec<Art> {
    vec![
        Art::image("images/web.tar", arch, "web", b"web layer"),
        normalized_image("images/database.tar", arch, "database"),
        Art::compose("compose.yaml", b"services:\n  web: {}\n").on(arch),
        Art::image("images/worker.tar", arch, "worker", b"worker layer"),
        normalized_image("images/cache.tar", arch, "cache"),
        Art::image("images/api.tar", arch, "api", b"api layer"),
        normalized_image("images/queue.tar", arch, "queue"),
        Art::native("bin/agent", b"\x7fELF agent").on(arch),
    ]
}
