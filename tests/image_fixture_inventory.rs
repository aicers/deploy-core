//! The checked-in image fixtures under `assets/test-fixtures/images/`, held to
//! `inventory.json`: every recorded hash and verdict, every kind and
//! provenance, and byte-for-byte regeneration of every builder fixture
//! through the public API.

use std::collections::BTreeSet;
use std::io::Cursor;

use deploy_core::image::test_support::{
    ArchiveCheckError, LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer,
    check_image_archive,
};
use deploy_core::image::{ImageArchitecture, ImageDeclaration, ImageOs, ImagePlatform};
use deploy_core::payload::sha256_hex;
use deploy_core::verify::{ImageVerifyError, InvalidArchiveReason, LayoutFile};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/test-fixtures/images");
const REGENERATING_TEST: &str =
    "tests/image_fixture_inventory.rs::builder_fixtures_regenerate_byte_for_byte";
const CAPTURE_FIELDS: &[&str] = &[
    "engine_version",
    "store_mode",
    "architecture",
    "command",
    "source_image_digest",
    "declaration_derivation",
];

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn fixtures() -> Vec<Value> {
    let inventory: Value =
        serde_json::from_slice(&read("inventory.json")).expect("inventory.json is JSON");
    inventory["fixtures"]
        .as_array()
        .expect("inventory.json lists its fixtures")
        .clone()
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{value} is a string"))
}

/// The inventory encoding of a classifier verdict: `"accepted"`, or the
/// `ImageVerifyError` variant and the `Debug` form of its feature or reason.
/// `archive_path` is left out.
fn verdict_of(result: &Result<(), ArchiveCheckError>) -> Value {
    match result {
        Ok(()) => json!("accepted"),
        Err(ArchiveCheckError::Image(ImageVerifyError::UnsupportedArchive { feature, .. })) => {
            json!({ "error": "UnsupportedArchive", "detail": format!("{feature:?}") })
        }
        Err(ArchiveCheckError::Image(ImageVerifyError::InvalidArchive { reason, .. })) => {
            json!({ "error": "InvalidArchive", "detail": format!("{reason:?}") })
        }
        Err(other) => panic!("no inventory encoding for {other:?}"),
    }
}

fn reported_path(result: &Result<(), ArchiveCheckError>) -> Option<&str> {
    match result {
        Err(ArchiveCheckError::Image(
            ImageVerifyError::UnsupportedArchive { archive_path, .. }
            | ImageVerifyError::InvalidArchive { archive_path, .. },
        )) => Some(archive_path),
        _ => None,
    }
}

#[test]
fn every_fixture_has_its_recorded_hash_and_verdict() {
    let fixtures = fixtures();
    assert!(!fixtures.is_empty());
    for fixture in &fixtures {
        let name = text(&fixture["name"]);
        let archive_name = text(&fixture["archive"]);
        let archive = read(archive_name);
        assert!(archive.len() < 64 * 1024, "{name} is a few kilobytes");
        assert_eq!(sha256_hex(&archive), text(&fixture["sha256"]), "{name}");
        let declaration: ImageDeclaration =
            serde_json::from_slice(&read(text(&fixture["declaration"]))).unwrap();
        declaration.validate().unwrap();

        let result = check_image_archive(Cursor::new(&archive), archive_name, &declaration);
        assert_eq!(verdict_of(&result), fixture["verdict"], "{name}");
        if let Some(path) = reported_path(&result) {
            assert_eq!(path, archive_name, "{name}");
        }

        let synthetic_refusal = fixture["kind"] == "synthetic" && result.is_err();
        if name == "oci-without-compat-manifest" {
            assert!(
                matches!(
                    result,
                    Err(ArchiveCheckError::Image(ImageVerifyError::InvalidArchive {
                        reason: InvalidArchiveReason::MissingLayoutFile {
                            file: LayoutFile::CompatibilityManifest
                        },
                        ..
                    }))
                ),
                "{name}: {result:?}"
            );
        } else if synthetic_refusal {
            assert!(
                matches!(
                    result,
                    Err(ArchiveCheckError::Image(
                        ImageVerifyError::UnsupportedArchive { .. }
                    ))
                ),
                "{name}: {result:?}"
            );
        }
    }
}

#[test]
fn every_fixture_has_one_kind_and_its_provenance() {
    for fixture in fixtures() {
        let name = text(&fixture["name"]);
        let provenance = fixture["provenance"].as_object().unwrap();
        match text(&fixture["kind"]) {
            "synthetic" => {
                let generator = text(&provenance["generator"]);
                assert!(
                    generator == "builder" || generator == "raw-generator",
                    "{name}"
                );
                assert!(provenance["parameters"].is_object(), "{name}");
                assert!(!text(&provenance["test"]).is_empty(), "{name}");
                assert!(
                    CAPTURE_FIELDS
                        .iter()
                        .all(|field| !provenance.contains_key(*field)),
                    "{name}"
                );
            }
            "docker-capture" => {
                assert!(!provenance.contains_key("generator"), "{name}");
                assert!(!provenance.contains_key("test"), "{name}");
                for field in CAPTURE_FIELDS {
                    assert!(
                        provenance.get(*field).is_some_and(|value| !value.is_null()),
                        "{name} records {field}"
                    );
                }
            }
            other => panic!("{name} has kind {other}"),
        }
    }
}

/// Builds the archive builder `parameters` describe, through the public API
/// only.
fn build(parameters: &Value) -> (Vec<u8>, String, ImagePlatform) {
    let platform = ImagePlatform {
        os: ImageOs::Linux,
        architecture: match text(&parameters["architecture"]) {
            "amd64" => ImageArchitecture::Amd64,
            "arm64" => ImageArchitecture::Arm64,
            other => panic!("unknown architecture {other}"),
        },
        variant: parameters["variant"].as_str().map(ToString::to_string),
    };
    let mut builder =
        SyntheticImageArchiveBuilder::new(platform.clone()).expect("the platform is valid");
    for layer in parameters["layers"].as_array().expect("layers is an array") {
        let mut synthetic = SyntheticLayer::new();
        for entry in layer["entries"].as_array().expect("entries is an array") {
            let path = text(&entry["path"]);
            synthetic = match text(&entry["kind"]) {
                "file" => synthetic.file(path, text(&entry["text"])),
                "dir" => synthetic.dir(path),
                "symlink" => synthetic.symlink(path, text(&entry["target"])),
                other => panic!("unknown entry kind {other}"),
            };
        }
        let compression = match text(&layer["compression"]) {
            "uncompressed" => LayerCompression::Uncompressed,
            "gzip" => LayerCompression::Gzip,
            other => panic!("unknown compression {other}"),
        };
        builder = builder
            .layer(synthetic, compression)
            .expect("a recorded layer is accepted");
    }
    let public_refs: Vec<String> = parameters["public_refs"]
        .as_array()
        .expect("public_refs is an array")
        .iter()
        .map(|reference| text(reference).to_string())
        .collect();
    let archive = builder
        .finish(&public_refs)
        .expect("the recorded references are accepted");
    let config_digest = archive.config_digest().to_string();
    (archive.into_bytes(), config_digest, platform)
}

#[test]
fn builder_fixtures_regenerate_byte_for_byte() {
    let builder_fixtures: Vec<Value> = fixtures()
        .into_iter()
        .filter(|fixture| fixture["provenance"]["generator"] == "builder")
        .collect();
    let names: BTreeSet<&str> = builder_fixtures
        .iter()
        .map(|fixture| text(&fixture["name"]))
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "uncompressed",
            "gzip",
            "multi-tag",
            "scratch",
            "repeated-layer",
            "explicit-variant",
        ])
    );
    for fixture in &builder_fixtures {
        let name = text(&fixture["name"]);
        assert_eq!(text(&fixture["kind"]), "synthetic");
        assert_eq!(text(&fixture["provenance"]["test"]), REGENERATING_TEST);
        let parameters = &fixture["provenance"]["parameters"];
        let (bytes, config_digest, platform) = build(parameters);
        assert!(
            bytes == read(text(&fixture["archive"])),
            "{name} regenerates byte for byte"
        );
        let declaration: ImageDeclaration =
            serde_json::from_slice(&read(text(&fixture["declaration"]))).unwrap();
        assert_eq!(declaration.config_digest, config_digest, "{name}");
        assert_eq!(declaration.platform, platform, "{name}");
        assert_eq!(
            json!(declaration.public_refs),
            parameters["public_refs"],
            "{name}"
        );
    }
}

#[test]
fn every_raw_generator_fixture_names_its_regenerating_unit_test() {
    // The raw generator is crate-private, so its fixtures are regenerated by
    // the unit test named here rather than through the public API.
    let raw: Vec<Value> = fixtures()
        .into_iter()
        .filter(|fixture| fixture["provenance"]["generator"] == "raw-generator")
        .collect();
    let names: BTreeSet<&str> = raw.iter().map(|fixture| text(&fixture["name"])).collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "layer-sources",
            "classic-layout",
            "graphdriver-extras",
            "containerd-nested-index",
            "oci-without-compat-manifest",
            "multi-platform-index",
            "zstd-layer",
        ])
    );
    for fixture in &raw {
        assert_eq!(
            text(&fixture["provenance"]["test"]),
            "src/image/test_support/tests.rs::raw_generator_fixtures_regenerate_byte_for_byte"
        );
    }
}

#[test]
fn every_file_in_the_directory_is_in_the_inventory() {
    let recorded: BTreeSet<String> = fixtures()
        .iter()
        .flat_map(|fixture| {
            [
                text(&fixture["archive"]).to_string(),
                text(&fixture["declaration"]).to_string(),
            ]
        })
        .collect();
    let present: BTreeSet<String> = std::fs::read_dir(FIXTURES)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "INVENTORY.md" && name != "inventory.json")
        .collect();
    assert_eq!(present, recorded);
}

#[test]
fn missing_docker_captures_are_listed_as_not_run() {
    let captures = fixtures()
        .iter()
        .filter(|fixture| fixture["kind"] == "docker-capture")
        .count();
    if captures > 0 {
        return;
    }
    let inventory = String::from_utf8(read("INVENTORY.md")).unwrap();
    for store in ["graphdriver-store", "containerd-store"] {
        let line = format!("- `{store}` `docker save` capture: **not run**");
        assert!(inventory.contains(&line), "INVENTORY.md lists {store}");
    }
}
