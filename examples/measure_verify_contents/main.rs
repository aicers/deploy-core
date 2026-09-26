//! Generates a signed package fixture and measures `package::verify_contents`
//! over it, in two separate runs so the verification's own peak memory can be
//! taken on its own.
//!
//! ```text
//! measure_verify_contents generate <six|large> <dir>
//! measure_verify_contents verify <dir> <staging-parent>
//! ```
//!
//! `six` is six small images with a Compose file and a native binary; `large`
//! is one image whose gzip layer decodes to 64 MiB of incompressible bytes,
//! with the same two files. `generate` writes `package.pkg` and
//! `public-key.hex` into `<dir>` and discards the private key. `verify` prints
//! the elapsed time and the retained-disk high-water mark, which is the
//! package snapshot plus the archive-block copy plus every member snapshot.
//! Run `verify` under `/usr/bin/time -l` (macOS) or `/usr/bin/time -v`
//! (Linux) for its peak resident set size. Build it with
//! `--features test-support`, in release mode for representative figures.

use std::collections::BTreeSet;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use deploy_core::image::test_support::{
    LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer,
};
use deploy_core::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle,
};
use deploy_core::manifest::{ArtifactKind, Disposition, TargetArch};
use deploy_core::package::{ContentLimits, VerifiedImages, verify_contents};
use deploy_core::payload::{ArtifactInput, FOOTER_SIZE, Signed, append_trailer_signed};
use deploy_core::verify::{TrustAnchor, TrustSet, VerifyRequest, key_id};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const COMPONENT: &str = "example-app";
const VERSION: &str = "1.0.0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const NAMESPACE: &str = "example-product";
const LARGE_LAYER_BYTES: usize = 64 * 1024 * 1024;

type Failure = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["generate", kind, dir] => generate(kind, Path::new(dir)),
        ["verify", dir, staging] => verify(Path::new(dir), Path::new(staging)),
        _ => Err("usage: generate <six|large> <dir> | verify <dir> <staging-parent>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn image(
    dependency: &str,
    layer: SyntheticLayer,
    compression: LayerCompression,
) -> Result<(Vec<u8>, ImageDeclaration), Failure> {
    let platform = ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::for_target(TargetArch::X86_64),
        variant: None,
    };
    let refs = vec![format!("ghcr.io/example/{dependency}:{VERSION}")];
    let archive = SyntheticImageArchiveBuilder::new(platform.clone())?
        .layer(layer, compression)?
        .finish(&refs)?;
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: ImageOwner {
            namespace: NAMESPACE.to_string(),
            component: COMPONENT.to_string(),
        },
        dependency: dependency.to_string(),
        public_refs: refs,
        platform,
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
            repository: "https://example.com/app.git".to_string(),
            commit: COMMIT.to_string(),
        }),
    };
    Ok((archive.into_bytes(), declaration))
}

/// Bytes no compressor shrinks: a xorshift stream.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn generate(kind: &str, dir: &Path) -> Result<(), Failure> {
    let mut members: Vec<(String, ArtifactKind, Vec<u8>, Option<ImageDeclaration>)> = Vec::new();
    match kind {
        "six" => {
            for (at, dependency) in ["web", "database", "worker", "cache", "api", "queue"]
                .iter()
                .enumerate()
            {
                let compression = if at % 2 == 0 {
                    LayerCompression::Gzip
                } else {
                    LayerCompression::Uncompressed
                };
                let layer = SyntheticLayer::new().file("app/run", format!("{dependency} binary"));
                let (bytes, declaration) = image(dependency, layer, compression)?;
                members.push((
                    format!("images/{dependency}.tar"),
                    ArtifactKind::ContainerImage,
                    bytes,
                    Some(declaration),
                ));
            }
        }
        "large" => {
            let layer = SyntheticLayer::new().file("data.bin", incompressible(LARGE_LAYER_BYTES));
            let (bytes, declaration) = image("bulk", layer, LayerCompression::Gzip)?;
            members.push((
                "images/bulk.tar".to_string(),
                ArtifactKind::ContainerImage,
                bytes,
                Some(declaration),
            ));
        }
        other => return Err(format!("unknown fixture `{other}`").into()),
    }
    members.push((
        "compose.yaml".to_string(),
        ArtifactKind::ComposeBundle,
        b"services: {}\n".to_vec(),
        None,
    ));
    members.push((
        "bin/agent".to_string(),
        ArtifactKind::NativeBinary,
        b"\x7fELF agent".to_vec(),
        None,
    ));

    let sources = tempfile::tempdir()?;
    let mut inputs = Vec::new();
    for (at, (path, kind, bytes, image)) in members.into_iter().enumerate() {
        let source = sources.path().join(format!("source-{at}"));
        std::fs::write(&source, bytes)?;
        inputs.push(ArtifactInput {
            component: COMPONENT.to_string(),
            version: VERSION.to_string(),
            commit: COMMIT.to_string(),
            target_arch: TargetArch::X86_64,
            kind,
            dispositions: BTreeSet::from([Disposition::Install]),
            archive_path: path,
            spec: None,
            image,
            source,
        });
    }

    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "key generation failed")?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "the key does not parse")?;
    let public: [u8; 32] = pair.public_key().as_ref().try_into()?;
    let out = File::create(dir.join("package.pkg"))?;
    append_trailer_signed(std::io::empty(), out, None, None, &inputs, |manifest| {
        Ok(Signed {
            signature: pair.sign(manifest).as_ref().to_vec(),
            key_id: key_id(&public),
        })
    })?;
    let hex = public.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    });
    std::fs::write(dir.join("public-key.hex"), hex)?;
    Ok(())
}

/// Reads the archive block's length off the footer alone.
fn archive_block_len(package: &Path) -> Result<u64, Failure> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = File::open(package)?;
    let mut footer = [0u8; FOOTER_SIZE];
    file.seek(SeekFrom::End(-i64::try_from(FOOTER_SIZE)?))?;
    file.read_exact(&mut footer)?;
    let field = footer.get(9 + 3 * 8..9 + 4 * 8).ok_or("short footer")?;
    Ok(u64::from_le_bytes(field.try_into()?))
}

fn verify(dir: &Path, staging: &Path) -> Result<(), Failure> {
    let hex = std::fs::read_to_string(dir.join("public-key.hex"))?;
    let key: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2).unwrap_or("zz"), 16))
        .collect::<Result<_, _>>()?;
    let key: [u8; 32] = key.try_into().map_err(|_| "a 32-byte key")?;
    let trust = TrustSet::new(vec![TrustAnchor::new(key, false)], Vec::new(), 0, 0)?;
    let request = VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, NAMESPACE)?;
    let package = dir.join("package.pkg");

    let started = Instant::now();
    let contents = verify_contents(
        File::open(&package)?,
        &trust,
        &request,
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging,
    )?;
    let elapsed = started.elapsed();

    let members: u64 = contents
        .artifacts()
        .iter()
        .map(|artifact| artifact.bytes().len())
        .sum();
    let images = match contents.images() {
        VerifiedImages::None => 0,
        VerifiedImages::Present(images) => images.len(),
    };
    let package_len = contents.package_bytes().len();
    let archive_len = archive_block_len(&package)?;
    println!("images: {images}");
    println!("package bytes: {package_len}");
    println!("archive block bytes: {archive_len}");
    println!("member bytes: {members}");
    println!(
        "retained-disk high-water bytes: {}",
        package_len + archive_len + members
    );
    println!("elapsed: {:.3} s", elapsed.as_secs_f64());
    Ok(())
}
