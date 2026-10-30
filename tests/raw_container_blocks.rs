//! A dependent crate hashing a container's raw blocks through the public API
//! alone: the container version, the manifest block and a stream over the
//! archive block, across a rewrap — and the retired container formats the
//! test-support writers produce, refused by the same readers.

use std::collections::BTreeSet;
use std::io::{Cursor, Read};

use deploy_core::manifest::{ArtifactKind, Disposition, TargetArch};
use deploy_core::payload::{
    ArtifactInput, FORMAT_VERSION, RawArchiveBlock, append_trailer, read_package_container,
    rewrap_trailer,
};
use deploy_core::verify::ENVELOPE_BOUNDS;
use tempfile::tempdir;

const BASE: &[u8] = b"a base executable";

const OTHER_BASE: &[u8] = b"a different base executable, of another length";

/// The container version and the raw manifest and archive blocks of
/// `container`, read through the public accessors.
fn raw_blocks(container: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
    let mut read = read_package_container(Cursor::new(container), &ENVELOPE_BOUNDS)
        .expect("the container reads");
    let mut archive = Vec::new();
    let mut block: RawArchiveBlock<'_, _> = read.raw_archive_block().expect("the block is sought");
    block
        .read_to_end(&mut archive)
        .expect("the block reads to its end");
    assert_eq!(
        read.archive_block_len(),
        u64::try_from(archive.len()).expect("the archive length fits a u64")
    );
    (
        read.container_version(),
        read.raw_manifest_block().to_vec(),
        archive,
    )
}

fn rewrapped(container: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rewrap_trailer(Cursor::new(container), Cursor::new(OTHER_BASE), &mut out)
        .expect("the container rewraps");
    out
}

#[test]
fn the_raw_blocks_survive_a_rewrap_onto_another_base() {
    let tempdir = tempdir().expect("a temporary fixture directory is available");
    let source = tempdir.path().join("fixture");
    std::fs::write(&source, b"fixture artifact").expect("the fixture artifact is written");
    let inputs = [ArtifactInput {
        component: "fixture".to_string(),
        version: "1.0.0".to_string(),
        commit: "a".repeat(40),
        target_arch: TargetArch::X86_64,
        kind: ArtifactKind::StaticAssets,
        dispositions: BTreeSet::from([Disposition::Install]),
        archive_path: "fixture".to_string(),
        spec: None,
        image: None,
        source,
    }];
    let mut container = Vec::new();
    append_trailer(Cursor::new(BASE), &mut container, None, None, &inputs)
        .expect("the container is written");

    let before = raw_blocks(&container);
    assert_eq!(before.0, FORMAT_VERSION);
    assert_eq!(
        container.get(BASE.len()..BASE.len() + before.1.len()),
        Some(before.1.as_slice())
    );
    assert_eq!(raw_blocks(&rewrapped(&container)), before);
}

#[cfg(feature = "test-support")]
#[test]
fn retired_format_fixtures_are_refused_through_the_real_readers() {
    use deploy_core::payload::{
        DetachedSignature, PayloadError, append_version_1_trailer, append_version_2_trailer, open,
    };

    let manifest = b"a manifest block nothing parses";
    let archive = b"an archive block nothing decompresses";
    let ed25519 = DetachedSignature {
        signature: vec![0x5a; 64],
        key_id: "a".repeat(64),
    };
    let mut version_1 = Vec::new();
    append_version_1_trailer(Cursor::new(BASE), &mut version_1, manifest, archive)
        .expect("the fixture is written");
    let mut unsigned_2 = Vec::new();
    append_version_2_trailer(Cursor::new(BASE), &mut unsigned_2, manifest, archive, None)
        .expect("the fixture is written");
    let mut signed_2 = Vec::new();
    append_version_2_trailer(
        Cursor::new(BASE),
        &mut signed_2,
        manifest,
        archive,
        Some(&ed25519),
    )
    .expect("the fixture is written");

    for (found, container) in [(1u8, version_1), (2, unsigned_2), (2, signed_2)] {
        let refused = |error: &PayloadError| {
            matches!(
                error,
                PayloadError::UnsupportedContainerFormat { found: version, supported }
                    if *version == found && *supported == [FORMAT_VERSION]
            )
        };
        let error = read_package_container(Cursor::new(container.as_slice()), &ENVELOPE_BOUNDS)
            .err()
            .expect("the bounded reader refuses it");
        assert!(refused(&error), "{error:?}");
        let error = open(Cursor::new(container.as_slice())).expect_err("open refuses it");
        assert!(refused(&error), "{error:?}");
        let error = rewrap_trailer(
            Cursor::new(container.as_slice()),
            Cursor::new(OTHER_BASE),
            &mut Vec::new(),
        )
        .expect_err("rewrap refuses it");
        assert!(refused(&error), "{error:?}");
    }
}
