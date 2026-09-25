//! The logic of the `write_synthetic_image` example, over the public API
//! only, kept apart from `main` so a test can drive it with in-memory
//! streams.

use std::fs::File;
use std::io::{BufReader, Write};

use deploy_core::image::test_support::{
    ArchiveCheckError, LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer,
    check_image_archive,
};
use deploy_core::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ReferenceLifecycle, RegistryProvenance,
};

const SUCCESS: u8 = 0;
const REFUSED: u8 = 1;
const USAGE: u8 = 2;

const USAGE_TEXT: &str = "usage:
  write_synthetic_image write <out.tar> <out.declaration.json> <amd64|arm64> <ref>...
  write_synthetic_image classify <archive.tar> <declaration.json>";

/// The one file of the sample's one gzip layer.
const SAMPLE_PATH: &str = "etc/synthetic-sample.txt";
const SAMPLE_CONTENT: &str = "a synthetic image written by deploy-core\n";

const OWNER_NAMESPACE: &str = "example-product";
const OWNER_COMPONENT: &str = "example-app";
const DEPENDENCY: &str = "sample";
const PROVENANCE_REPOSITORY: &str = "registry.example/synthetic/sample";
const PROVENANCE_TAG: &str = "1.0.0";
const PROVENANCE_VERSION: &str = "1.0.0";

/// Runs the example with `args`, the arguments after the program name, and
/// returns its exit code: 0 for success or `accepted`, 1 for a classifier
/// refusal, 2 for a usage error or an I/O error on a named file.
pub(crate) fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    match args.split_first() {
        Some((command, rest)) if command == "write" => write(rest, stderr),
        Some((command, rest)) if command == "classify" => classify(rest, stdout, stderr),
        _ => usage(stderr, "a subcommand is required"),
    }
}

fn usage(stderr: &mut dyn Write, problem: &str) -> u8 {
    let _ = writeln!(stderr, "error: {problem}\n{USAGE_TEXT}");
    USAGE
}

fn failure(stderr: &mut dyn Write, message: &str) -> u8 {
    let _ = writeln!(stderr, "error: {message}");
    USAGE
}

fn write(args: &[String], stderr: &mut dyn Write) -> u8 {
    let [
        archive_path,
        declaration_path,
        architecture,
        public_refs @ ..,
    ] = args
    else {
        return usage(
            stderr,
            "write needs an archive, a declaration, an architecture and a ref",
        );
    };
    if public_refs.is_empty() {
        return usage(stderr, "write needs at least one ref");
    }
    let architecture = match architecture.as_str() {
        "amd64" => ImageArchitecture::Amd64,
        "arm64" => ImageArchitecture::Arm64,
        _ => return usage(stderr, "the architecture must be amd64 or arm64"),
    };
    let platform = ImagePlatform {
        os: ImageOs::Linux,
        architecture,
        variant: None,
    };
    let archive = SyntheticImageArchiveBuilder::new(platform.clone())
        .and_then(|builder| {
            builder.layer(
                SyntheticLayer::new().file(SAMPLE_PATH, SAMPLE_CONTENT),
                LayerCompression::Gzip,
            )
        })
        .and_then(|builder| builder.finish(public_refs));
    let archive = match archive {
        Ok(archive) => archive,
        Err(error) => return usage(stderr, &error.to_string()),
    };
    let declaration = ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: ImageOwner {
            namespace: OWNER_NAMESPACE.to_string(),
            component: OWNER_COMPONENT.to_string(),
        },
        dependency: DEPENDENCY.to_string(),
        public_refs: public_refs.to_vec(),
        platform,
        config_digest: archive.config_digest().to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::Registry(RegistryProvenance {
            repository: PROVENANCE_REPOSITORY.to_string(),
            tag: PROVENANCE_TAG.to_string(),
            version: Some(PROVENANCE_VERSION.to_string()),
            pinned_digest: archive.manifest_digest().to_string(),
            selected_manifest_digest: archive.manifest_digest().to_string(),
        }),
    };
    let mut declaration_bytes = match serde_json::to_vec_pretty(&declaration) {
        Ok(bytes) => bytes,
        Err(error) => return failure(stderr, &format!("serializing the declaration: {error}")),
    };
    declaration_bytes.push(b'\n');
    if let Err(error) = std::fs::write(archive_path, archive.bytes()) {
        return failure(stderr, &format!("writing {archive_path}: {error}"));
    }
    if let Err(error) = std::fs::write(declaration_path, declaration_bytes) {
        return failure(stderr, &format!("writing {declaration_path}: {error}"));
    }
    SUCCESS
}

fn classify(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let [archive_path, declaration_path] = args else {
        return usage(stderr, "classify needs an archive and a declaration");
    };
    let declaration = match std::fs::read(declaration_path) {
        Ok(bytes) => bytes,
        Err(error) => return failure(stderr, &format!("reading {declaration_path}: {error}")),
    };
    let declaration: ImageDeclaration = match serde_json::from_slice(&declaration) {
        Ok(declaration) => declaration,
        Err(error) => return failure(stderr, &format!("parsing {declaration_path}: {error}")),
    };
    let archive = match File::open(archive_path) {
        Ok(file) => BufReader::new(file),
        Err(error) => return failure(stderr, &format!("opening {archive_path}: {error}")),
    };
    match check_image_archive(archive, archive_path, &declaration) {
        Ok(()) => {
            let _ = writeln!(stdout, "accepted");
            SUCCESS
        }
        Err(ArchiveCheckError::Io(error)) => {
            failure(stderr, &format!("reading {archive_path}: {error}"))
        }
        Err(refusal) => {
            let _ = writeln!(stdout, "{refusal}");
            REFUSED
        }
    }
}
