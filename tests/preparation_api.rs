//! The exported preparation surface, compiled from outside the crate: every
//! function at its exact signature, every accessor with its return type, and
//! every variant of the preparation error and fault enums with its fields.
//! Not feature-gated: nothing here needs the synthetic image builder.

use std::collections::BTreeSet;
use std::path::Path;

use deploy_core::manifest::{ArtifactKind, Disposition, TargetArch};
use deploy_core::package::{
    BindingField, ContentError, ContentLimits, DirectoryFault, IoOperation, PackageWriteError,
    PreparationBinding, PreparationFault, PreparationFile, PreparedPackage, PublicationError,
    RecordFault, RetainedBytes, prepare_package, reopen_prepared,
};
use deploy_core::payload::{ArtifactInput, PayloadError};
use deploy_core::verify::VerifyRequest;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

type Prepare = fn(
    &[ArtifactInput],
    Option<&str>,
    Option<&[u8]>,
    &VerifyRequest,
    TargetArch,
    &ContentLimits,
    &Path,
) -> Result<PreparedPackage, PackageWriteError>;

type Reopen = fn(
    &Path,
    &PreparationBinding,
    &VerifyRequest,
    TargetArch,
    &ContentLimits,
    &Path,
) -> Result<PreparedPackage, PackageWriteError>;

#[test]
fn every_function_has_its_exact_signature() {
    let _: Prepare = prepare_package;
    let _: Reopen = reopen_prepared;

    let _: fn(&[u8]) -> Result<PreparationBinding, PackageWriteError> =
        PreparationBinding::from_record_bytes;
    let _: fn(&PreparationBinding) -> Vec<u8> = PreparationBinding::to_record_bytes;
    let _: fn(&PreparationBinding) -> u32 = PreparationBinding::schema;
    let _: fn(&PreparationBinding) -> &[u8; 32] = PreparationBinding::manifest_sha256;
    let _: fn(&PreparationBinding) -> u64 = PreparationBinding::manifest_length;
    let _: fn(&PreparationBinding) -> &[u8; 32] = PreparationBinding::archive_sha256;
    let _: fn(&PreparationBinding) -> u64 = PreparationBinding::archive_length;
    let _: fn(&PreparationBinding) -> &str = PreparationBinding::target;
    let _: fn(&PreparationBinding) -> &str = PreparationBinding::version;
    let _: fn(&PreparationBinding) -> &str = PreparationBinding::commit;
    let _: fn(&PreparationBinding) -> TargetArch = PreparationBinding::target_arch;
    let _: fn(&PreparationBinding) -> Option<&str> = PreparationBinding::namespace;
    let _: fn(&PreparationBinding) -> Option<u64> = PreparationBinding::trust_epoch;

    let _: fn(&PreparedPackage) -> &[u8] = PreparedPackage::manifest_bytes;
    let _: fn(&PreparedPackage) -> &RetainedBytes = PreparedPackage::archive;
    let _: fn(&PreparedPackage) -> &PreparationBinding = PreparedPackage::binding;
    let _: fn(&PreparedPackage, &Path) -> Result<(), PackageWriteError> = PreparedPackage::persist;
}

fn describe_error(error: &PackageWriteError) -> String {
    match error {
        PackageWriteError::Content(error) => describe_content(error),
        PackageWriteError::Publication(error) => describe_publication(error),
        PackageWriteError::Payload(error) => format!("Payload {}", describe_payload(error)),
        PackageWriteError::Signer(error) => format!("Signer {error}"),
        PackageWriteError::BindingMismatch { field } => {
            format!("BindingMismatch {}", describe_field(*field))
        }
        PackageWriteError::InvalidPreparation { reason } => {
            format!("InvalidPreparation {}", describe_fault(*reason))
        }
    }
}

fn describe_content(error: &ContentError) -> String {
    match error {
        ContentError::Io {
            operation: IoOperation::OpenPreparation,
            path,
            source,
        } => format!("OpenPreparation {path:?} {:?}", source.kind()),
        other => format!("Content {other}"),
    }
}

fn describe_publication(error: &PublicationError) -> String {
    format!("Publication {error}")
}

fn describe_payload(error: &PayloadError) -> String {
    error.to_string()
}

fn describe_field(field: BindingField) -> &'static str {
    match field {
        BindingField::Schema => "Schema",
        BindingField::ManifestSha256 => "ManifestSha256",
        BindingField::ManifestLength => "ManifestLength",
        BindingField::ArchiveSha256 => "ArchiveSha256",
        BindingField::ArchiveLength => "ArchiveLength",
        BindingField::Target => "Target",
        BindingField::Version => "Version",
        BindingField::Commit => "Commit",
        BindingField::TargetArch => "TargetArch",
        BindingField::Namespace => "Namespace",
        BindingField::TrustEpoch => "TrustEpoch",
    }
}

fn describe_file(file: PreparationFile) -> &'static str {
    match file {
        PreparationFile::Manifest => "Manifest",
        PreparationFile::Archive => "Archive",
        PreparationFile::Record => "Record",
    }
}

fn describe_directory(fault: DirectoryFault) -> &'static str {
    match fault {
        DirectoryFault::NotAbsolute => "NotAbsolute",
        DirectoryFault::NotCanonical => "NotCanonical",
        DirectoryFault::NoParent => "NoParent",
        DirectoryFault::SymlinkComponent => "SymlinkComponent",
        DirectoryFault::NotDirectory => "NotDirectory",
        DirectoryFault::GroupOrOtherWritable => "GroupOrOtherWritable",
        DirectoryFault::ParentGroupOrOtherWritable => "ParentGroupOrOtherWritable",
    }
}

fn describe_fault(fault: PreparationFault) -> String {
    match fault {
        PreparationFault::UnsafeDirectory { reason } => {
            format!("UnsafeDirectory {}", describe_directory(reason))
        }
        PreparationFault::Symlink { file } => format!("Symlink {}", describe_file(file)),
        PreparationFault::NotRegularFile { file } => {
            format!("NotRegularFile {}", describe_file(file))
        }
        PreparationFault::GroupOrOtherWritable { file } => {
            format!("GroupOrOtherWritable {}", describe_file(file))
        }
        PreparationFault::ExtraMember => "ExtraMember".to_string(),
        PreparationFault::MissingMember { file } => {
            format!("MissingMember {}", describe_file(file))
        }
        PreparationFault::IdentityChanged { file } => {
            format!("IdentityChanged {}", describe_file(file))
        }
        PreparationFault::RecordInvalid(fault) => {
            format!("RecordInvalid {}", describe_record(fault))
        }
    }
}

fn describe_record(fault: RecordFault) -> String {
    match fault {
        RecordFault::Malformed => "Malformed".to_string(),
        RecordFault::DuplicateKey => "DuplicateKey".to_string(),
        RecordFault::NotObject => "NotObject".to_string(),
        RecordFault::MissingField { field } => format!("MissingField {}", describe_field(field)),
        RecordFault::FieldType { field } => format!("FieldType {}", describe_field(field)),
        RecordFault::UnsupportedSchema => "UnsupportedSchema".to_string(),
        RecordFault::UnknownField => "UnknownField".to_string(),
        RecordFault::InvalidDigest { field } => {
            format!("InvalidDigest {}", describe_field(field))
        }
        RecordFault::InvalidTargetArch => "InvalidTargetArch".to_string(),
        RecordFault::InvalidIdentifier { field } => {
            format!("InvalidIdentifier {}", describe_field(field))
        }
    }
}

/// Requires the derives the fault enums promise.
fn copy_eq<T: Copy + Clone + std::fmt::Debug + PartialEq + Eq>(value: T) -> T {
    let copied = value;
    assert_eq!(copied, value);
    assert_eq!(value.clone(), copied);
    copied
}

#[test]
fn every_variant_is_nameable_and_the_faults_compare() {
    let fields = [
        BindingField::Schema,
        BindingField::ManifestSha256,
        BindingField::ManifestLength,
        BindingField::ArchiveSha256,
        BindingField::ArchiveLength,
        BindingField::Target,
        BindingField::Version,
        BindingField::Commit,
        BindingField::TargetArch,
        BindingField::Namespace,
        BindingField::TrustEpoch,
    ];
    for field in fields {
        assert_eq!(copy_eq(field), field);
        let text = field.to_string();
        assert_eq!(text, text.to_lowercase());
    }
    let files = [
        PreparationFile::Manifest,
        PreparationFile::Archive,
        PreparationFile::Record,
    ];
    for file in files {
        assert_eq!(copy_eq(file), file);
    }
    let directories = [
        DirectoryFault::NotAbsolute,
        DirectoryFault::NotCanonical,
        DirectoryFault::NoParent,
        DirectoryFault::SymlinkComponent,
        DirectoryFault::NotDirectory,
        DirectoryFault::GroupOrOtherWritable,
        DirectoryFault::ParentGroupOrOtherWritable,
    ];
    let records = [
        RecordFault::Malformed,
        RecordFault::DuplicateKey,
        RecordFault::NotObject,
        RecordFault::MissingField {
            field: BindingField::Schema,
        },
        RecordFault::FieldType {
            field: BindingField::ManifestLength,
        },
        RecordFault::UnsupportedSchema,
        RecordFault::UnknownField,
        RecordFault::InvalidDigest {
            field: BindingField::ArchiveSha256,
        },
        RecordFault::InvalidTargetArch,
        RecordFault::InvalidIdentifier {
            field: BindingField::Commit,
        },
    ];
    let mut faults: Vec<PreparationFault> = directories
        .iter()
        .map(|&reason| PreparationFault::UnsafeDirectory { reason })
        .collect();
    for file in files {
        faults.extend([
            PreparationFault::Symlink { file },
            PreparationFault::NotRegularFile { file },
            PreparationFault::GroupOrOtherWritable { file },
            PreparationFault::MissingMember { file },
            PreparationFault::IdentityChanged { file },
        ]);
    }
    faults.push(PreparationFault::ExtraMember);
    faults.extend(
        records
            .iter()
            .map(|&fault| PreparationFault::RecordInvalid(fault)),
    );
    for (at, fault) in faults.iter().enumerate() {
        assert_eq!(copy_eq(*fault), *fault);
        for (other_at, other) in faults.iter().enumerate() {
            assert_eq!(at == other_at, fault == other);
        }
        let error = PackageWriteError::InvalidPreparation { reason: *fault };
        assert!(describe_error(&error).starts_with("InvalidPreparation "));
        let text = error.to_string();
        assert_eq!(text, text.to_lowercase());
    }
}

#[test]
fn every_error_variant_is_nameable() {
    let errors = [
        PackageWriteError::Content(ContentError::Io {
            operation: IoOperation::OpenPreparation,
            path: Some("/prepared".into()),
            source: std::io::ErrorKind::NotFound.into(),
        }),
        PackageWriteError::Publication(PublicationError::DiskBudgetExceeded { limit: 1 }),
        PackageWriteError::Payload(PayloadError::TruncatedTrailer),
        PackageWriteError::BindingMismatch {
            field: BindingField::ArchiveSha256,
        },
    ];
    for error in &errors {
        assert!(!describe_error(error).is_empty());
        assert!(!error.to_string().is_empty());
    }
    assert!(describe_error(&errors[0]).starts_with("OpenPreparation"));
}

#[test]
fn a_native_package_prepares_persists_and_reopens_from_outside_the_crate() {
    let root = tempfile::tempdir().expect("a directory");
    let root = std::fs::canonicalize(root.path()).expect("canonical");
    let sources = root.join("sources");
    let staging = root.join("staging");
    let out = root.join("out");
    for dir in [&sources, &staging, &out] {
        std::fs::create_dir(dir).expect("created");
    }
    let source = sources.join("tool");
    std::fs::write(&source, b"\x7fELF tool").expect("written");
    let input = ArtifactInput {
        component: "example-app".to_string(),
        version: "1.0.0".to_string(),
        commit: COMMIT.to_string(),
        target_arch: TargetArch::Aarch64,
        kind: ArtifactKind::NativeBinary,
        dispositions: BTreeSet::from([Disposition::Install]),
        archive_path: "bin/tool".to_string(),
        spec: None,
        image: None,
        source,
    };
    let request = VerifyRequest::for_package("example-app", "1.0.0", COMMIT).expect("a request");
    let limits = ContentLimits::default();
    let prepared = prepare_package(
        &[input],
        None,
        None,
        &request,
        TargetArch::Aarch64,
        &limits,
        &staging,
    )
    .expect("prepared");
    let saved = prepared.binding().to_record_bytes();
    let destination = out.join("prepared");
    prepared.persist(&destination).expect("persisted");
    drop(prepared);

    let expected = PreparationBinding::from_record_bytes(&saved).expect("the saved binding");
    let reopened = reopen_prepared(
        &destination,
        &expected,
        &request,
        TargetArch::Aarch64,
        &limits,
        &staging,
    )
    .expect("reopened");
    assert_eq!(reopened.binding(), &expected);
    assert_eq!(
        reopened.manifest_bytes(),
        std::fs::read(destination.join("manifest.json")).expect("read")
    );
    assert_eq!(reopened.archive().len(), expected.archive_length());

    let error = reopen_prepared(
        &destination,
        &expected,
        &request,
        TargetArch::X86_64,
        &limits,
        &staging,
    )
    .expect_err("another architecture is refused");
    assert_eq!(describe_error(&error), "BindingMismatch TargetArch");
}
