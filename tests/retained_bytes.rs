//! The public surface of `deploy_core::package` as a dependent sees it.
//!
//! What a dependent must NOT be able to do — construct or clone a
//! `RetainedBytes`, keep a `RetainedReader` past its bytes, or reach a
//! descriptor, path or inner file — is pinned by the `compile_fail` doctests
//! on those types. This file pins what it CAN do: name and exhaustively match
//! every error variant with its fields, and rely on the auto traits the
//! types promise.

use std::io;
use std::path::PathBuf;

use deploy_core::package::{
    CopyMismatchKind, DirectoryTrustReason, PublicationError, PublicationOperation,
    PublishedPackage, RetainedBytes, RetainedReader,
};

fn assert_send_sync<T: Send + Sync>() {}
fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}
fn assert_read_seek<T: io::Read + io::Seek>() {}

#[test]
fn auto_traits() {
    assert_send_sync::<RetainedBytes>();
    assert_send_sync::<RetainedReader<'static>>();
    assert_send_sync::<PublishedPackage>();
    assert_error::<PublicationError>();
    assert_read_seek::<RetainedReader<'static>>();
}

/// Names every `PublicationError` variant with every field. Adding, removing
/// or renaming one fails to compile here.
fn describe(error: &PublicationError) -> String {
    match error {
        PublicationError::DestinationExists { destination } => {
            format!("exists {}", destination.display())
        }
        PublicationError::UnsafeDestinationParent { path, reason } => {
            format!("unsafe {} {reason:?}", path.display())
        }
        PublicationError::DiskBudgetExceeded { limit } => format!("budget {limit}"),
        PublicationError::Io {
            operation,
            path,
            source,
        } => format!("io {operation:?} {path:?} {:?}", source.kind()),
        PublicationError::CopyMismatch { path, kind } => {
            let kind = match kind {
                CopyMismatchKind::Length { expected, actual } => {
                    format!("length {expected} {actual}")
                }
                CopyMismatchKind::Digest => "digest".to_owned(),
            };
            format!("mismatch {} {kind}", path.display())
        }
        PublicationError::PublishDurability {
            destination,
            operation,
            source,
        } => format!(
            "durability {} {operation:?} {:?}",
            destination.display(),
            source.kind()
        ),
    }
}

fn reason_name(reason: DirectoryTrustReason) -> &'static str {
    match reason {
        DirectoryTrustReason::NotAbsolute => "not-absolute",
        DirectoryTrustReason::NotCanonical => "not-canonical",
        DirectoryTrustReason::NoFinalComponent => "no-final-component",
        DirectoryTrustReason::SymlinkComponent => "symlink-component",
        DirectoryTrustReason::NotDirectory => "not-directory",
        DirectoryTrustReason::UntrustedAncestor => "untrusted-ancestor",
        DirectoryTrustReason::UntrustedOwner => "untrusted-owner",
        DirectoryTrustReason::GroupOrOtherWritable => "group-or-other-writable",
        DirectoryTrustReason::NotWritableByEffectiveUser => "not-writable",
    }
}

fn operation_name(operation: PublicationOperation) -> &'static str {
    match operation {
        PublicationOperation::OpenDestinationParent => "open-destination-parent",
        PublicationOperation::InspectDestination => "inspect-destination",
        PublicationOperation::CreateStagingDirectory => "create-staging-directory",
        PublicationOperation::CreateTemporary => "create-temporary",
        PublicationOperation::ReadRetained => "read-retained",
        PublicationOperation::WriteTemporary => "write-temporary",
        PublicationOperation::SyncFile => "sync-file",
        PublicationOperation::Verify => "verify",
        PublicationOperation::SyncDirectory => "sync-directory",
        PublicationOperation::Link => "link",
        PublicationOperation::Rename => "rename",
        PublicationOperation::RemoveTemporary => "remove-temporary",
    }
}

#[test]
fn every_publication_error_variant_matches() {
    let destination = PathBuf::from("/srv/out.pkg");
    let errors = [
        PublicationError::DestinationExists {
            destination: destination.clone(),
        },
        PublicationError::UnsafeDestinationParent {
            path: PathBuf::from("/srv"),
            reason: DirectoryTrustReason::GroupOrOtherWritable,
        },
        PublicationError::DiskBudgetExceeded { limit: 512 },
        PublicationError::Io {
            operation: PublicationOperation::ReadRetained,
            path: None,
            source: io::ErrorKind::Other.into(),
        },
        PublicationError::CopyMismatch {
            path: PathBuf::from("/srv/.deploy-core-publish-00.tmp"),
            kind: CopyMismatchKind::Length {
                expected: 2,
                actual: 1,
            },
        },
        PublicationError::CopyMismatch {
            path: PathBuf::from("/srv/.deploy-core-publish-00.tmp"),
            kind: CopyMismatchKind::Digest,
        },
        PublicationError::PublishDurability {
            destination,
            operation: PublicationOperation::SyncDirectory,
            source: io::ErrorKind::Unsupported.into(),
        },
    ];
    let described: Vec<String> = errors.iter().map(describe).collect();
    assert_eq!(
        described,
        [
            "exists /srv/out.pkg",
            "unsafe /srv GroupOrOtherWritable",
            "budget 512",
            "io ReadRetained None Other",
            "mismatch /srv/.deploy-core-publish-00.tmp length 2 1",
            "mismatch /srv/.deploy-core-publish-00.tmp digest",
            "durability /srv/out.pkg SyncDirectory Unsupported",
        ]
    );
    for error in &errors {
        let message = error.to_string();
        assert!(!message.is_empty());
        assert!(!message.ends_with('.'), "{message}");
        assert!(
            message.chars().next().is_some_and(|c| !c.is_uppercase()),
            "{message}"
        );
    }
}

#[test]
fn every_directory_trust_reason_matches() {
    let reasons = [
        DirectoryTrustReason::NotAbsolute,
        DirectoryTrustReason::NotCanonical,
        DirectoryTrustReason::NoFinalComponent,
        DirectoryTrustReason::SymlinkComponent,
        DirectoryTrustReason::NotDirectory,
        DirectoryTrustReason::UntrustedAncestor,
        DirectoryTrustReason::UntrustedOwner,
        DirectoryTrustReason::GroupOrOtherWritable,
        DirectoryTrustReason::NotWritableByEffectiveUser,
    ];
    let names: Vec<&str> = reasons.iter().copied().map(reason_name).collect();
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), reasons.len());
    for reason in reasons {
        assert!(!reason.to_string().is_empty());
    }
}

#[test]
fn every_publication_operation_matches() {
    let operations = [
        PublicationOperation::OpenDestinationParent,
        PublicationOperation::InspectDestination,
        PublicationOperation::CreateStagingDirectory,
        PublicationOperation::CreateTemporary,
        PublicationOperation::ReadRetained,
        PublicationOperation::WriteTemporary,
        PublicationOperation::SyncFile,
        PublicationOperation::Verify,
        PublicationOperation::SyncDirectory,
        PublicationOperation::Link,
        PublicationOperation::Rename,
        PublicationOperation::RemoveTemporary,
    ];
    let mut names: Vec<&str> = operations.iter().copied().map(operation_name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), operations.len());
}
