use std::collections::BTreeSet;
use std::io::{Cursor, empty};
#[cfg(feature = "test-support")]
use std::io::{Seek as _, SeekFrom, Write as _};

use deploy_core::manifest::{ArtifactKind, Disposition, TargetArch};
use deploy_core::payload::{
    ArtifactInput, EnvelopeBlock, PayloadError, Signed, append_trailer, append_trailer_signed,
    open, read_package_container,
};
#[cfg(feature = "test-support")]
use deploy_core::payload::{FOOTER_SIZE, widen_envelope_blocks};
use deploy_core::verify::{ED25519_SIGNATURE_LEN, ENVELOPE_BOUNDS, KEY_ID_HEX_LEN};
use tempfile::tempdir;

#[test]
fn a_consumer_can_read_bounded_metadata_without_a_trust_set() {
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
        source,
    }];
    let signature = vec![
        0x5a;
        usize::try_from(ED25519_SIGNATURE_LEN)
            .expect("the fixed signature length fits usize")
    ];
    let key_id =
        "a".repeat(usize::try_from(KEY_ID_HEX_LEN).expect("the fixed key-id length fits usize"));
    let mut package = Vec::new();
    append_trailer_signed(empty(), &mut package, None, None, &inputs, |_| {
        Ok(Signed {
            signature: signature.clone(),
            key_id: key_id.clone(),
        })
    })
    .expect("the signed fixture package is written");

    let container = read_package_container(Cursor::new(package.clone()), &ENVELOPE_BOUNDS)
        .expect("a consumer can read bounded metadata without a trust set");
    assert!(matches!(
        container.signature(),
        EnvelopeBlock::Present(bytes) if bytes == &signature
    ));
    assert!(matches!(
        container.key_id(),
        EnvelopeBlock::Present(bytes) if bytes == key_id.as_bytes()
    ));
    assert_eq!(
        container
            .parse_unverified_manifest()
            .expect("a consumer can parse unverified metadata"),
        open(Cursor::new(package))
            .expect("the signed fixture package opens")
            .expect("the signed fixture package has a trailer")
            .manifest()
            .clone()
    );
}

#[test]
fn a_consumer_can_parse_an_unsigned_bounded_manifest() {
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
        source,
    }];
    let mut package = Vec::new();
    append_trailer(empty(), &mut package, None, None, &inputs)
        .expect("the unsigned fixture package is written");

    let manifest = read_package_container(Cursor::new(package.clone()), &ENVELOPE_BOUNDS)
        .expect("a consumer can read unsigned bounded metadata")
        .parse_unverified_manifest()
        .expect("a consumer can parse unsigned unverified metadata");
    assert_eq!(
        manifest,
        open(Cursor::new(package))
            .expect("the unsigned fixture package opens")
            .expect("the unsigned fixture package has a trailer")
            .manifest()
            .clone()
    );
}

#[cfg(feature = "test-support")]
#[test]
fn a_consumer_can_write_the_widened_fixture_sparsely() {
    const ADVERTISED_LEN: u64 = 1_024;

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
        source,
    }];
    let mut package = Vec::new();
    append_trailer_signed(empty(), &mut package, None, None, &inputs, |_| {
        Ok(Signed {
            signature: vec![
                0x5a;
                usize::try_from(ED25519_SIGNATURE_LEN)
                    .expect("the fixed signature length fits usize")
            ],
            key_id: "a".repeat(
                usize::try_from(KEY_ID_HEX_LEN).expect("the fixed key-id length fits usize"),
            ),
        })
    })
    .expect("the signed fixture package is written");
    let compact = widen_envelope_blocks(&package, ADVERTISED_LEN);
    let prefix_len = compact.len() - FOOTER_SIZE;

    let path = tempdir.path().join("widened.pkg");
    let mut file = std::fs::File::create(&path).expect("the sparse fixture is created");
    file.write_all(
        compact
            .get(..prefix_len)
            .expect("the compact fixture has its prefix"),
    )
    .expect("the compact fixture prefix is written");
    let footer_offset = u64::try_from(prefix_len)
        .expect("the prefix length fits u64")
        .checked_add(ADVERTISED_LEN)
        .and_then(|offset| offset.checked_add(ADVERTISED_LEN))
        .expect("the sparse fixture footer offset fits u64");
    file.seek(SeekFrom::Start(footer_offset))
        .expect("the sparse fixture seeks past the envelope blocks");
    file.write_all(
        compact
            .get(prefix_len..)
            .expect("the compact fixture has its footer"),
    )
    .expect("the compact fixture footer is written");
    drop(file);
    let file = std::fs::File::open(&path).expect("the sparse fixture opens for reading");

    let container = read_package_container(file, &ENVELOPE_BOUNDS)
        .expect("the bounded reader opens the sparse fixture");
    assert!(matches!(container.signature(), EnvelopeBlock::WrongLength));
    assert!(matches!(container.key_id(), EnvelopeBlock::WrongLength));
    assert!(
        container.parse_unverified_manifest().is_ok(),
        "the sparse envelope does not affect the manifest"
    );
}

#[test]
fn a_consumer_gets_no_trailer_for_an_empty_package() {
    let result = read_package_container(Cursor::new(Vec::new()), &ENVELOPE_BOUNDS);
    assert!(matches!(result, Err(PayloadError::NoTrailer)));
}
