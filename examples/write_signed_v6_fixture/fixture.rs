//! What `assets/test-fixtures/signed-v6-images/package.pkg` contains: the
//! members of one outer build and the request it verifies under. Everything
//! here is deterministic; only the signing key is minted per run.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

use deploy_core::image::test_support::{
    LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer,
};
use deploy_core::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle, RegistryProvenance,
    canonical_runtime_alias,
};
use deploy_core::manifest::{ArtifactKind, Disposition, TargetArch};
use deploy_core::payload::ArtifactInput;
use deploy_core::verify::VerifyRequest;

pub const COMPONENT: &str = "example-app";
pub const VERSION: &str = "1.0.0";
pub const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub const NAMESPACE: &str = "example-product";
pub const TARGET: TargetArch = TargetArch::X86_64;

pub type Failure = Box<dyn Error>;

/// One member of the package: its bytes, and how it is declared.
pub struct Member {
    pub archive_path: &'static str,
    pub kind: ArtifactKind,
    pub bytes: Vec<u8>,
    pub image: Option<ImageDeclaration>,
    /// The manifest digest the synthetic builder wrote, for an image.
    pub manifest_digest: Option<String>,
}

fn owner() -> ImageOwner {
    ImageOwner {
        namespace: NAMESPACE.to_string(),
        component: COMPONENT.to_string(),
    }
}

fn platform() -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::for_target(TARGET),
        variant: None,
    }
}

/// A third-party database normalized under its canonical runtime alias.
fn database() -> Result<Member, Failure> {
    let dependency = "database";
    let builder = SyntheticImageArchiveBuilder::new(platform())?
        .layer(
            SyntheticLayer::new().file("etc/database.conf", b"port = 5432\n".to_vec()),
            LayerCompression::Uncompressed,
        )?
        .layer(
            SyntheticLayer::new().dir("var/lib/database"),
            LayerCompression::Uncompressed,
        )?;
    let config_digest = builder.config_digest();
    let alias = canonical_runtime_alias(NAMESPACE, COMPONENT, dependency, &config_digest)?;
    let archive = builder.finish(std::slice::from_ref(&alias))?;
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: dependency.to_string(),
        public_refs: vec![alias],
        platform: platform(),
        config_digest,
        reference_lifecycle: ReferenceLifecycle::ManagedRuntime,
        provenance: ImageProvenance::Registry(RegistryProvenance {
            repository: "docker.io/library/postgres".to_string(),
            tag: "18.4".to_string(),
            version: Some("18.4.0".to_string()),
            pinned_digest: format!("sha256:{}", "d".repeat(64)),
            selected_manifest_digest: format!("sha256:{}", "e".repeat(64)),
        }),
    };
    Ok(Member {
        archive_path: "images/database.tar",
        kind: ArtifactKind::ContainerImage,
        manifest_digest: Some(archive.manifest_digest().to_string()),
        bytes: archive.into_bytes(),
        image: Some(declaration),
    })
}

/// The component's own web image, built from product source under its tag.
fn web() -> Result<Member, Failure> {
    let refs = vec![format!("ghcr.io/example/{COMPONENT}:{VERSION}")];
    let archive = SyntheticImageArchiveBuilder::new(platform())?
        .layer(
            SyntheticLayer::new()
                .dir("app")
                .file("app/run", b"#!/bin/sh\nexec web\n".to_vec()),
            LayerCompression::Uncompressed,
        )?
        .finish(&refs)?;
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: owner(),
        dependency: "web".to_string(),
        public_refs: refs,
        platform: platform(),
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
            repository: "https://example.invalid/example-app.git".to_string(),
            commit: "89abcdef0123456789abcdef0123456789abcdef".to_string(),
        }),
    };
    Ok(Member {
        archive_path: "images/web.tar",
        kind: ArtifactKind::ContainerImage,
        manifest_digest: Some(archive.manifest_digest().to_string()),
        bytes: archive.into_bytes(),
        image: Some(declaration),
    })
}

/// Returns every member, in manifest order: a Compose file, then the two
/// images.
///
/// # Errors
///
/// Whatever the synthetic builder or the alias helper refuses; neither does
/// for these fixed inputs.
pub fn members() -> Result<Vec<Member>, Failure> {
    let compose = Member {
        archive_path: "compose.yaml",
        kind: ArtifactKind::ComposeBundle,
        bytes: b"services:\n  database: {}\n  web: {}\n".to_vec(),
        image: None,
        manifest_digest: None,
    };
    Ok(vec![compose, database()?, web()?])
}

/// Writes each member to its own file under `sources` and describes it as an
/// input of the one outer build.
///
/// # Errors
///
/// Any I/O error writing a source file.
pub fn inputs(members: &[Member], sources: &Path) -> Result<Vec<ArtifactInput>, Failure> {
    let mut inputs = Vec::with_capacity(members.len());
    for (at, member) in members.iter().enumerate() {
        let source = sources.join(format!("source-{at}"));
        std::fs::write(&source, &member.bytes)?;
        inputs.push(ArtifactInput {
            component: COMPONENT.to_string(),
            version: VERSION.to_string(),
            commit: COMMIT.to_string(),
            target_arch: TARGET,
            kind: member.kind,
            dispositions: BTreeSet::from([Disposition::Install]),
            archive_path: member.archive_path.to_string(),
            spec: None,
            image: member.image.clone(),
            source,
        });
    }
    Ok(inputs)
}

/// Returns the request the package verifies under.
///
/// # Errors
///
/// None for these fixed identifiers.
pub fn request() -> Result<VerifyRequest, Failure> {
    Ok(VerifyRequest::for_namespaced_package(
        COMPONENT, VERSION, COMMIT, NAMESPACE,
    )?)
}
