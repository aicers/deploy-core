//! A dependent crate hashing a container's raw blocks through the public API
//! alone: the container version, the manifest block and a stream over the
//! archive block, across a rewrap and at both container versions.

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
fn a_version_1_fixture_reads_through_the_real_reader() {
    use deploy_core::payload::{EnvelopeBlock, append_version_1_trailer};

    let manifest = b"a manifest block nothing parses";
    let archive = b"an archive block nothing decompresses";
    let mut container = Vec::new();
    append_version_1_trailer(Cursor::new(BASE), &mut container, manifest, archive)
        .expect("the fixture is written");

    let read = read_package_container(Cursor::new(container.as_slice()), &ENVELOPE_BOUNDS)
        .expect("the fixture reads");
    assert!(matches!(read.signature(), EnvelopeBlock::Absent));
    assert!(matches!(read.key_id(), EnvelopeBlock::Absent));
    assert!(read.parse_unverified_manifest().is_err());

    let blocks = (1, manifest.to_vec(), archive.to_vec());
    assert_eq!(raw_blocks(&container), blocks);
    assert_eq!(raw_blocks(&rewrapped(&container)), blocks);
}
