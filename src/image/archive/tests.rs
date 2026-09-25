use std::io::{Cursor, ErrorKind, Read, Seek, Write};

use serde_json::{Value, json};

use super::assembly::{
    Built, Doc, Entry, Header, INDEX_MEDIA_TYPE, ImageBuilder, LAYER_GZIP, LAYER_TAR, Layer,
    MANIFEST_MEDIA_TYPE, Source, Tar, digest, entry_mut, gzip, layer_tar, move_entry, pax,
    remove_entry,
};
use super::{
    ImageArchiveFault, Site, ValidatedImageArchive, Verdict, convert, probe, seam,
    validate_image_archive,
};
use crate::content::{
    Budget, ContentFault, CountingReader, GzipHeaderFault as ContentGzipHeader, MalformedReason,
    PaxKey as ContentPaxKey, ResourceLimit, TarField, UnsupportedFeature,
};
use crate::image::ImageArchitecture;
use crate::package::{ContentLimits, LimitResource};
use crate::verify::{
    BlobMismatchKind, BlobRole, ConfigField, ExtensionField, GzipFault, GzipHeaderFault,
    ImageDocument, ImageVerifyError, InvalidArchiveReason, InvalidConfigReason, JsonFault,
    LayerMismatchKind, LayoutFile, PaxKey, PlatformFacet, PlatformLocation, ReferenceSource,
    TarFault, TarFeature, TarHeaderField, UnsupportedArchiveFeature,
};

const PATH: &str = "images/app.tar";
const FAKE_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn run_on<R: Read + Seek>(
    source: R,
    built: &Built,
    limits: &ContentLimits,
) -> Result<ValidatedImageArchive, ImageArchiveFault> {
    let mut operation =
        Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
    validate_image_archive(source, &built.declaration, PATH, limits, &mut operation)
}

fn run_with(
    built: &Built,
    limits: &ContentLimits,
) -> Result<ValidatedImageArchive, ImageArchiveFault> {
    run_on(Cursor::new(built.bytes.as_slice()), built, limits)
}

fn run(built: &Built) -> Result<ValidatedImageArchive, ImageArchiveFault> {
    run_with(built, &ContentLimits::default())
}

fn limits(settings: &[(LimitResource, u64)]) -> ContentLimits {
    settings
        .iter()
        .fold(ContentLimits::default(), |limits, (resource, value)| {
            limits.with_limit(*resource, *value).unwrap()
        })
}

/// Asserts `built` is accepted and its summary matches it.
fn accept(built: &Built) -> ValidatedImageArchive {
    let validated = run(built).unwrap_or_else(|fault| panic!("refused: {fault:?}"));
    assert_summary(&validated, built);
    validated
}

#[track_caller]
fn assert_summary(validated: &ValidatedImageArchive, built: &Built) {
    assert_eq!(validated.config_digest, built.config_digest);
    assert_eq!(validated.manifest_digest, built.manifest_digest);
    assert_eq!(validated.layer_count, built.layer_count);
}

fn render(fault: &ImageArchiveFault) -> String {
    match fault {
        ImageArchiveFault::Io(err) => format!("Io({:?})", err.kind()),
        other => format!("{other:?}"),
    }
}

#[track_caller]
fn assert_fault(
    result: Result<ValidatedImageArchive, ImageArchiveFault>,
    expected: &ImageArchiveFault,
) {
    match result {
        Ok(validated) => panic!("accepted {validated:?}, expected {expected:?}"),
        Err(fault) => match (&fault, expected) {
            (
                ImageArchiveFault::LimitExceeded { resource, limit },
                ImageArchiveFault::LimitExceeded {
                    resource: expected_resource,
                    limit: expected_limit,
                },
            ) => assert_eq!((resource, limit), (expected_resource, expected_limit)),
            _ => assert_eq!(render(&fault), render(expected)),
        },
    }
}

fn image(error: ImageVerifyError) -> ImageArchiveFault {
    ImageArchiveFault::Image(error)
}

fn invalid(reason: InvalidArchiveReason) -> ImageArchiveFault {
    image(ImageVerifyError::InvalidArchive {
        archive_path: PATH.to_string(),
        reason,
    })
}

fn unsupported(feature: UnsupportedArchiveFeature) -> ImageArchiveFault {
    image(ImageVerifyError::UnsupportedArchive {
        archive_path: PATH.to_string(),
        feature,
    })
}

fn limit(resource: LimitResource, limit: u64) -> ImageArchiveFault {
    ImageArchiveFault::LimitExceeded { resource, limit }
}

fn shape(document: ImageDocument) -> ImageArchiveFault {
    invalid(InvalidArchiveReason::UnexpectedShape { document })
}

fn tar_fault(fault: TarFault) -> ImageArchiveFault {
    invalid(InvalidArchiveReason::Tar { fault })
}

fn config_reason(reason: InvalidConfigReason) -> ImageArchiveFault {
    invalid(InvalidArchiveReason::InvalidConfig { reason })
}

fn platform_mismatch(
    location: PlatformLocation,
    facet: PlatformFacet,
    declared: Option<&str>,
    actual: Option<&str>,
) -> ImageArchiveFault {
    image(ImageVerifyError::ConfigPlatformMismatch {
        archive_path: PATH.to_string(),
        location,
        facet,
        declared: declared.map(str::to_string),
        actual: actual.map(str::to_string),
    })
}

fn layer_mismatch(
    position: Option<usize>,
    kind: LayerMismatchKind,
    expected: &str,
    actual: &str,
) -> ImageArchiveFault {
    image(ImageVerifyError::LayerMismatch {
        archive_path: PATH.to_string(),
        position,
        kind,
        expected: Some(expected.to_string()),
        actual: Some(actual.to_string()),
    })
}

fn reference(missing: bool, reference: &str, source: ReferenceSource) -> ImageArchiveFault {
    let reference = reference.to_string();
    let archive_path = PATH.to_string();
    image(if missing {
        ImageVerifyError::MissingReference {
            archive_path,
            reference,
            source,
        }
    } else {
        ImageVerifyError::UndeclaredReference {
            archive_path,
            reference,
            source,
        }
    })
}

fn object(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value.as_object_mut().expect("an object")
}

fn blob_name(hex: &str) -> String {
    format!("blobs/sha256/{hex}")
}

/// Renames the blob entry `from` to `blobs/sha256/<to>`.
fn rename_blob(entries: &mut [Entry], from: &str, to: &str) {
    let entry = entry_mut(entries, &blob_name(from));
    let size = entry.data.len();
    let mut header = Header::file(&blob_name(to), size);
    std::mem::swap(&mut entry.header, &mut header);
}

fn events_for(position: usize, events: &[seam::Event]) -> usize {
    events
        .iter()
        .filter(|event| match event {
            seam::Event::LayerOpened(at)
            | seam::Event::LayerDecoded(at)
            | seam::Event::LayerRead { position: at, .. } => *at == position,
            _ => false,
        })
        .count()
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

#[test]
fn one_tag_is_accepted() {
    let built = ImageBuilder::new().build();
    let validated = accept(&built);
    assert_eq!(validated.layer_count, 1);
    let names: Vec<&str> = validated.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"index.json"));
    assert!(names.contains(&"oci-layout"));
    for entry in &validated.entries {
        let end = entry.data_offset + entry.data_len;
        assert!(end <= u64::try_from(built.bytes.len()).unwrap());
        assert_eq!(entry.data_offset, entry.header_offset + 512);
    }
}

#[test]
fn several_tags_one_per_index_descriptor_are_accepted() {
    let built = ImageBuilder::new()
        .tags(&[
            "example.com/app:1.0",
            "example.com/app:latest",
            "ghcr.io/example/app:2",
        ])
        .build();
    assert_eq!(accept(&built).layer_count, 1);
}

#[test]
fn ref_name_may_be_a_bare_tag_or_an_equivalent_full_reference() {
    // The default builder writes the bare tag.
    accept(&ImageBuilder::new().build());
    let built = ImageBuilder::new()
        .tags(&["app:1"])
        .json(Doc::Index, |index| {
            index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] =
                json!("docker.io/library/app:1");
        })
        .build();
    accept(&built);
}

#[test]
fn a_fully_qualified_annotation_matches_a_familiar_repo_tag() {
    let built = ImageBuilder::new()
        .tags(&["app:1"])
        .json(Doc::Index, |index| {
            index["manifests"][0]["annotations"]["io.containerd.image.name"] =
                json!("docker.io/library/app:1");
        })
        .build();
    accept(&built);
}

#[test]
fn a_scratch_image_is_accepted() {
    let built = ImageBuilder::new().layers(Vec::new()).build();
    assert_eq!(accept(&built).layer_count, 0);
}

#[test]
fn uncompressed_gzip_and_mixed_layers_are_accepted() {
    let a = layer_tar("a.txt", b"alpha");
    let b = layer_tar("b.txt", b"bravo");
    for layers in [
        vec![Layer::plain(&a)],
        vec![Layer::gzip(&a)],
        vec![Layer::plain(&a), Layer::gzip(&b)],
        vec![Layer::gzip(&a), Layer::plain(&b)],
    ] {
        let count = layers.len();
        let built = ImageBuilder::new().layers(layers).build();
        assert_eq!(accept(&built).layer_count, count);
    }
}

#[test]
fn a_repeated_layer_position_is_decoded_and_charged_again() {
    let a = layer_tar("a.txt", b"alpha");
    let b = layer_tar("b.txt", b"bravo");
    let built = ImageBuilder::new()
        .layers(vec![Layer::gzip(&a), Layer::plain(&b)])
        .positions(&[0, 1, 0])
        .build();
    let limits = ContentLimits::default();
    let mut operation =
        Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
    seam::take();
    let validated = validate_image_archive(
        Cursor::new(built.bytes.as_slice()),
        &built.declaration,
        PATH,
        &limits,
        &mut operation,
    )
    .unwrap();
    assert_summary(&validated, &built);
    assert_eq!(validated.layer_count, 3);
    let expected = 2 * a.len() + b.len();
    assert_eq!(operation.used(), u64::try_from(expected).unwrap());
    let events = seam::take();
    // One inventory hash per distinct blob, one phase-7 decode per position.
    let inventory = events
        .iter()
        .filter(|e| matches!(e, seam::Event::InventoryBlob(_)))
        .count();
    assert_eq!(inventory, 4);
    for position in 0..3 {
        assert!(events.contains(&seam::Event::LayerOpened(position)));
    }
    assert!(events.contains(&seam::Event::LayerDecoded(0)));
    assert!(!events.contains(&seam::Event::LayerDecoded(1)));
    assert!(events.contains(&seam::Event::LayerDecoded(2)));
}

fn with_platforms(builder: ImageBuilder, platform: Value) -> ImageBuilder {
    let for_index = platform.clone();
    builder
        .json(Doc::Index, move |index| {
            index["manifests"][0]["platform"] = for_index;
        })
        .json(Doc::Manifest, move |manifest| {
            manifest["config"]["platform"] = platform;
        })
}

#[test]
fn an_arm64_v8_image_is_accepted() {
    let built = with_platforms(
        ImageBuilder::new().platform(ImageArchitecture::Arm64, Some("v8")),
        json!({"os": "linux", "architecture": "arm64", "variant": "v8"}),
    )
    .build();
    accept(&built);
}

#[test]
fn a_matching_variant_needs_no_grammar() {
    for variant in [
        "v8+crypto/sve".to_string(),
        "v 8 \u{e9}t\u{e9} \u{1f600}".to_string(),
        "x".repeat(100),
    ] {
        let for_platform = variant.clone();
        let built = with_platforms(
            ImageBuilder::new().platform(ImageArchitecture::Arm64, Some(&variant)),
            json!({"os": "linux", "architecture": "arm64", "variant": for_platform}),
        )
        .build();
        accept(&built);
    }
}

#[test]
fn a_signed_null_variant_matches_an_absent_or_null_one() {
    accept(&ImageBuilder::new().build());
    let built = ImageBuilder::new()
        .json(Doc::Config, |config| config["variant"] = Value::Null)
        .build();
    accept(&built);
}

#[test]
fn descriptors_may_state_a_null_variant_or_no_platform() {
    let built = ImageBuilder::new()
        .json(Doc::Index, |index| {
            index["manifests"][0]["platform"] =
                json!({"os": "linux", "architecture": "amd64", "variant": null});
        })
        .json(Doc::Manifest, |manifest| {
            manifest["config"]["platform"] = json!({"os": "linux", "architecture": "amd64"});
        })
        .build();
    accept(&built);
    // No `platform` anywhere is the default.
    accept(&ImageBuilder::new().build());
}

#[test]
fn conventional_config_metadata_is_opaque() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |config| {
            let config = object(config);
            config.insert("created".into(), json!("2024-01-01T00:00:00Z"));
            config.insert("author".into(), json!("someone"));
            config.insert(
                "config".into(),
                json!({"Env": ["PATH=/usr/bin"], "Cmd": ["/app"]}),
            );
            config.insert("container".into(), json!("abc"));
            config.insert("container_config".into(), json!({"Hostname": "x"}));
            config.insert("docker_version".into(), json!("27.0.1"));
        })
        .build();
    accept(&built);
    let built = ImageBuilder::new()
        .json(Doc::Config, |config| {
            let config = object(config);
            config.insert("created".into(), json!(1_700_000_000));
            config.insert("author".into(), json!(["a", "b"]));
            config.insert("config".into(), json!([1, 2, 3]));
            config.insert("container".into(), json!(null));
            config.insert("container_config".into(), json!(true));
            config.insert("docker_version".into(), json!({"major": 27}));
        })
        .build();
    accept(&built);
}

#[test]
fn unnamed_config_fields_are_opaque() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |config| {
            let config = object(config);
            config.insert("os.version".into(), json!("10.0"));
            config.insert(
                "moby.buildkit.buildinfo.v1".into(),
                json!({"deep": {"deeper": {"deepest": [1, {"x": null}]}}}),
            );
            config.insert("unknown".into(), json!(3.5));
        })
        .build();
    accept(&built);
}

#[test]
fn history_may_carry_empty_layers_and_extra_keys() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |config| {
            config["history"] = json!([
                {"created": "2024", "created_by": "ENV A=B", "empty_layer": true, "comment": 7},
                {"created_by": "COPY . .", "author": null, "extra": {"k": [1]}, "empty_layer": false},
                {"empty_layer": true, "x-meta": ["y"]},
            ]);
        })
        .build();
    accept(&built);
}

#[test]
fn history_is_optional() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |config| {
            object(config).remove("history");
        })
        .build();
    accept(&built);
}

#[test]
fn layer_sources_may_be_absent_null_empty_or_complete() {
    accept(&ImageBuilder::new().build());
    for sources in [json!(null), json!({})] {
        let built = ImageBuilder::new()
            .json(Doc::Compat, move |compat| {
                compat[0]["LayerSources"] = sources;
            })
            .build();
        accept(&built);
    }
    let a = layer_tar("a.txt", b"alpha");
    let b = layer_tar("b.txt", b"bravo");
    let (la, lb) = (Layer::gzip(&a), Layer::plain(&b));
    let sources = json!({
        la.diff_id.clone(): {"mediaType": LAYER_GZIP, "digest": digest(&la.blob), "size": la.blob.len()},
        lb.diff_id.clone(): {"mediaType": LAYER_TAR, "digest": digest(&lb.blob), "size": lb.blob.len()},
    });
    let built = ImageBuilder::new()
        .layers(vec![la, lb])
        .positions(&[0, 1, 0])
        .json(Doc::Compat, move |compat| {
            compat[0]["LayerSources"] = sources;
        })
        .build();
    accept(&built);
}

#[test]
fn parent_may_be_absent_or_empty() {
    accept(&ImageBuilder::new().build());
    let built = ImageBuilder::new()
        .json(Doc::Compat, |compat| compat[0]["Parent"] = json!(""))
        .build();
    accept(&built);
}

#[test]
fn entry_order_header_forms_and_a_long_zero_tail_are_accepted() {
    let built = ImageBuilder::new()
        .layers(vec![
            Layer::gzip(&layer_tar("a", b"a")),
            Layer::plain(&layer_tar("b", b"b")),
        ])
        .entries(|entries, _| entries.reverse())
        .build();
    accept(&built);

    // A ustar prefix joined to its name, and GNU headers throughout.
    let built = ImageBuilder::new()
        .entries(|entries, parts| {
            let name = blob_name(&parts.config_hex);
            let entry = entry_mut(entries, &name);
            let mut header = Header::file(&parts.config_hex, entry.data.len());
            header.prefix(b"blobs/sha256");
            entry.header = header;
            for entry in entries.iter_mut() {
                if entry.name() == "oci-layout" || entry.name() == "index.json" {
                    entry.header.gnu();
                }
            }
        })
        .build();
    accept(&built);

    // A zero tail of exactly 1 MiB, end marker included.
    let built = ImageBuilder::new()
        .tail(|bytes| bytes.extend(std::iter::repeat_n(0, 1_048_576 - 1024)))
        .build();
    accept(&built);
}

#[test]
fn every_permitted_manifest_annotation_is_accepted() {
    let built = ImageBuilder::new()
        .json(Doc::Manifest, |manifest| {
            let mut annotations = serde_json::Map::new();
            for key in [
                "created",
                "authors",
                "url",
                "documentation",
                "source",
                "version",
                "revision",
                "vendor",
                "licenses",
                "title",
                "description",
                "base.name",
                "base.digest",
            ] {
                annotations.insert(format!("org.opencontainers.image.{key}"), json!("v"));
            }
            annotations.insert(
                "com.docker.official-images.bashbrew.arch".into(),
                json!("amd64"),
            );
            manifest["annotations"] = Value::Object(annotations);
        })
        .build();
    accept(&built);
}

/// A layer tar holding every entry kind the layer policy admits.
fn rich_layer() -> Vec<u8> {
    let long_name = format!("{}file", "deep/".repeat(40));
    let mut tar = Tar::new();
    tar.header(&Header::dir("etc/"))
        .file("etc/hosts", b"127.0.0.1 localhost\n")
        .header(Header::new(b'2', b"etc/link", 0).linkname(b"/etc/hosts"))
        .header(Header::new(b'1', b"etc/hard", 0).linkname(b"etc/hosts"))
        .header(&Header::new(b'3', b"dev/null", 0))
        .header(&Header::new(b'4', b"dev/sda", 0))
        .header(&Header::new(b'6', b"run/fifo", 0))
        .file("etc/.wh.removed", b"")
        .file("var/.wh..wh..opq", b"")
        .extension(
            b'x',
            &pax(&[
                ("path", b"etc/pax-named"),
                ("mtime", b"1700000000.5"),
                ("SCHILY.xattr.user.k", b"v"),
            ]),
        )
        .file("etc/placeholder", b"pax data")
        .extension(b'L', format!("{long_name}\0").as_bytes())
        .entry(Header::file("truncated", 4).gnu(), b"long");
    tar.finish()
}

#[test]
fn layers_hold_links_devices_fifos_whiteouts_pax_and_long_names() {
    let rich = rich_layer();
    let built = ImageBuilder::new()
        .layers(vec![Layer::gzip(&rich), Layer::plain(&rich)])
        .build();
    assert_eq!(accept(&built).layer_count, 2);
}

// ---------------------------------------------------------------------------
// Phase 1
// ---------------------------------------------------------------------------

#[test]
fn a_compressed_outer_stream_is_refused_from_its_prefix() {
    let plain = ImageBuilder::new().build();
    let mut gz = plain;
    gz.bytes = gzip(&gz.bytes);
    assert_fault(
        run(&gz),
        &unsupported(UnsupportedArchiveFeature::CompressedOuterStream),
    );
    let mut zstd = ImageBuilder::new().build();
    let mut bytes = vec![0x28, 0xb5, 0x2f, 0xfd];
    bytes.extend_from_slice(&zstd.bytes);
    zstd.bytes = bytes;
    assert_fault(
        run(&zstd),
        &unsupported(UnsupportedArchiveFeature::CompressedOuterStream),
    );
}

#[test]
fn every_legacy_export_file_is_refused() {
    let legacy: Vec<Vec<Entry>> = vec![
        vec![Entry::file("repositories", b"{}".to_vec())],
        vec![Entry::file("VERSION", b"1.0".to_vec())],
        vec![Entry::dir(&format!("{FAKE_HEX}/"))],
        vec![Entry::file(&format!("{FAKE_HEX}/layer.tar"), vec![0; 10])],
        vec![Entry::file(&format!("{FAKE_HEX}.json"), b"{}".to_vec())],
    ];
    for extra in legacy {
        let built = ImageBuilder::new()
            .entries(move |entries, _| entries.extend(extra))
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::LegacyExportFile),
        );
    }
}

#[test]
fn every_extra_file_is_refused() {
    let extra: Vec<Vec<Entry>> = vec![
        vec![Entry::file("notes.txt", b"hi".to_vec())],
        vec![Entry::file(
            &format!("blobs/sha512/{FAKE_HEX}"),
            b"x".to_vec(),
        )],
        vec![Entry::file("blobs/sha256/not-a-digest", b"x".to_vec())],
        vec![Entry::file(
            &format!("blobs/sha256/{}", FAKE_HEX.to_uppercase()),
            b"x".to_vec(),
        )],
        vec![Entry::dir(&format!("blobs/sha256/{FAKE_HEX}/"))],
        vec![Entry::dir("blobs/sha512/")],
        vec![Entry::file("sub/index.json", b"{}".to_vec())],
    ];
    for extra in extra {
        let built = ImageBuilder::new()
            .entries(move |entries, _| entries.extend(extra))
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::ExtraFile),
        );
    }
    // A layout name that appears as a directory.
    let built = ImageBuilder::new()
        .entries(|entries, _| {
            remove_entry(entries, "index.json");
            entries.push(Entry::dir("index.json/"));
        })
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::ExtraFile),
    );
}

#[test]
fn each_missing_layout_file_is_named_in_order() {
    for (name, file) in [
        ("oci-layout", LayoutFile::OciLayout),
        ("index.json", LayoutFile::Index),
        ("manifest.json", LayoutFile::CompatibilityManifest),
    ] {
        let built = ImageBuilder::new()
            .entries(move |entries, _| remove_entry(entries, name))
            .build();
        assert_fault(
            run(&built),
            &invalid(InvalidArchiveReason::MissingLayoutFile { file }),
        );
    }
    let built = ImageBuilder::new()
        .entries(|entries, _| {
            remove_entry(entries, "manifest.json");
            remove_entry(entries, "index.json");
        })
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::MissingLayoutFile {
            file: LayoutFile::Index,
        }),
    );
}

fn with_entries(extra: Vec<Entry>) -> Built {
    ImageBuilder::new()
        .entries(move |entries, _| entries.extend(extra))
        .build()
}

#[test]
fn image_level_walker_refusals() {
    assert_fault(
        run(&with_entries(vec![Entry::file("../escape", b"x".to_vec())])),
        &tar_fault(TarFault::UnsafePath),
    );
    assert_fault(
        run(&with_entries(vec![Entry::file(
            "index.json",
            b"{}".to_vec(),
        )])),
        &tar_fault(TarFault::DuplicatePath),
    );
    assert_fault(
        run(&with_entries(vec![Entry::file(
            "oci-layout/x",
            b"x".to_vec(),
        )])),
        &tar_fault(TarFault::PathConflict),
    );
    for flag in *b"23x" {
        let built = with_entries(vec![Entry {
            header: Header::new(flag, b"special", 0),
            data: Vec::new(),
        }]);
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::ArchiveTar {
                feature: TarFeature::EntryType { flag },
            }),
        );
    }
    let mut header = Header::file("notes", 1);
    header.no_magic();
    assert_fault(
        run(&with_entries(vec![Entry {
            header,
            data: b"x".to_vec(),
        }])),
        &unsupported(UnsupportedArchiveFeature::ArchiveTar {
            feature: TarFeature::Format,
        }),
    );
}

#[test]
fn image_level_stream_refusals() {
    let trailing = ImageBuilder::new().tail(|bytes| bytes.push(1)).build();
    assert_fault(run(&trailing), &tar_fault(TarFault::TrailingData));

    let second = ImageBuilder::new().build().bytes;
    let concatenated = ImageBuilder::new()
        .tail(move |bytes| bytes.extend_from_slice(&second))
        .build();
    assert_fault(run(&concatenated), &tar_fault(TarFault::TrailingData));

    let partial = ImageBuilder::new()
        .tail(|bytes| {
            bytes.truncate(bytes.len() - 1024);
            bytes.extend_from_slice(&[0; 300]);
        })
        .build();
    assert_fault(run(&partial), &tar_fault(TarFault::Truncated));

    let unterminated = ImageBuilder::new()
        .tail(|bytes| bytes.truncate(bytes.len() - 1024))
        .build();
    assert_fault(run(&unterminated), &tar_fault(TarFault::Truncated));

    let long_tail = ImageBuilder::new()
        .tail(|bytes| bytes.extend(std::iter::repeat_n(0, 1_048_576 - 1024 + 512)))
        .build();
    assert_fault(run(&long_tail), &tar_fault(TarFault::ZeroTailTooLong));

    let cut = ImageBuilder::new()
        .tail(|bytes| bytes.truncate(bytes.len() - 1024 - 100))
        .build();
    assert_fault(run(&cut), &tar_fault(TarFault::Truncated));
}

// ---------------------------------------------------------------------------
// Phase 2
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_key_or_syntax_error_is_refused_in_each_document() {
    for (doc, document, duplicate) in [
        (
            Doc::OciLayout,
            ImageDocument::OciLayout,
            r#"{"imageLayoutVersion":"1.0.0","imageLayoutVersion":"1.0.0"}"#,
        ),
        (
            Doc::Index,
            ImageDocument::Index,
            r#"{"schemaVersion":2,"schemaVersion":2}"#,
        ),
        (
            Doc::Compat,
            ImageDocument::CompatibilityManifest,
            r#"[{"Config":"a","Config":"b"}]"#,
        ),
        (
            Doc::Manifest,
            ImageDocument::ImageManifest,
            r#"{"schemaVersion":2,"schemaVersion":2}"#,
        ),
        (
            Doc::Config,
            ImageDocument::Config,
            r#"{"os":"linux","os":"linux"}"#,
        ),
    ] {
        let built = ImageBuilder::new().raw(doc, duplicate.as_bytes()).build();
        assert_fault(
            run(&built),
            &invalid(InvalidArchiveReason::Json {
                document,
                fault: JsonFault::DuplicateKey,
            }),
        );
        let built = ImageBuilder::new()
            .bytes(doc, |bytes| {
                bytes.pop();
            })
            .build();
        assert_fault(
            run(&built),
            &invalid(InvalidArchiveReason::Json {
                document,
                fault: JsonFault::Syntax,
            }),
        );
    }
}

#[test]
fn every_oci_layout_violation_is_a_shape_fault() {
    for layout in [
        r"[]",
        r"{}",
        r#""1.0.0""#,
        r#"{"imageLayoutVersion":"1.0.1"}"#,
        r#"{"imageLayoutVersion":1}"#,
        r#"{"imageLayoutVersion":"1.0.0","extra":1}"#,
    ] {
        let built = ImageBuilder::new()
            .raw(Doc::OciLayout, layout.as_bytes())
            .build();
        assert_fault(run(&built), &shape(ImageDocument::OciLayout));
    }
}

#[test]
fn every_index_rule_is_enforced() {
    type Edit = fn(&mut Value);
    let shape_cases: &[Edit] = &[
        |index| *index = json!([]),
        |index| {
            object(index).insert("annotations".into(), json!({}));
        },
        |index| index["schemaVersion"] = json!(1),
        |index| index["schemaVersion"] = json!(2.0),
        |index| {
            object(index).remove("schemaVersion");
        },
        |index| index["mediaType"] = json!(MANIFEST_MEDIA_TYPE),
        |index| index["manifests"] = json!([]),
        |index| index["manifests"] = json!({}),
        |index| {
            object(index).remove("manifests");
        },
    ];
    for edit in shape_cases {
        let built = ImageBuilder::new().json(Doc::Index, *edit).build();
        assert_fault(run(&built), &shape(ImageDocument::Index));
    }
    // `mediaType` is optional.
    let built = ImageBuilder::new()
        .json(Doc::Index, |index| {
            object(index).remove("mediaType");
        })
        .build();
    accept(&built);
    for (key, field) in [
        ("subject", ExtensionField::Subject),
        ("artifactType", ExtensionField::ArtifactType),
    ] {
        let built = ImageBuilder::new()
            .json(Doc::Index, move |index| {
                // An unknown key too: the extension field is checked first.
                object(index).insert("zzz".into(), json!(1));
                object(index).insert(key.into(), json!({}));
            })
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::ExtensionField {
                document: ImageDocument::Index,
                field,
            }),
        );
    }
    // `subject` is checked before `artifactType`.
    let built = ImageBuilder::new()
        .json(Doc::Index, |index| {
            object(index).insert("artifactType".into(), json!("x"));
            object(index).insert("subject".into(), json!({}));
        })
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::ExtensionField {
            document: ImageDocument::Index,
            field: ExtensionField::Subject,
        }),
    );
}

#[test]
fn multiple_images_are_refused_wherever_they_appear() {
    let two_digests = ImageBuilder::new()
        .json(Doc::Index, |index| {
            let mut other = index["manifests"][0].clone();
            other["digest"] = json!(format!("sha256:{FAKE_HEX}"));
            index["manifests"].as_array_mut().unwrap().push(other);
        })
        .build();
    assert_fault(
        run(&two_digests),
        &unsupported(UnsupportedArchiveFeature::MultipleImages),
    );
    let multi_platform = ImageBuilder::new()
        .json(Doc::Index, |index| {
            index["manifests"][0]["platform"] = json!({"os": "linux", "architecture": "amd64"});
            let mut other = index["manifests"][0].clone();
            other["digest"] = json!(format!("sha256:{FAKE_HEX}"));
            other["size"] = json!(100);
            other["platform"] = json!({"os": "linux", "architecture": "arm64", "variant": "v8"});
            index["manifests"].as_array_mut().unwrap().push(other);
        })
        .build();
    assert_fault(
        run(&multi_platform),
        &unsupported(UnsupportedArchiveFeature::MultipleImages),
    );
    let same_digest_other_size = ImageBuilder::new()
        .json(Doc::Index, |index| {
            let mut other = index["manifests"][0].clone();
            other["size"] = json!(1);
            index["manifests"].as_array_mut().unwrap().push(other);
        })
        .build();
    assert_fault(
        run(&same_digest_other_size),
        &unsupported(UnsupportedArchiveFeature::MultipleImages),
    );
    let two_records = ImageBuilder::new()
        .json(Doc::Compat, |compat| {
            let record = compat[0].clone();
            compat.as_array_mut().unwrap().push(record);
        })
        .build();
    assert_fault(
        run(&two_records),
        &unsupported(UnsupportedArchiveFeature::MultipleImages),
    );
}

#[test]
fn index_descriptor_media_types() {
    for (media_type, feature) in [
        (INDEX_MEDIA_TYPE, UnsupportedArchiveFeature::NestedIndex),
        (
            "application/vnd.docker.distribution.manifest.list.v2+json",
            UnsupportedArchiveFeature::NestedIndex,
        ),
        (
            "application/vnd.docker.distribution.manifest.v2+json",
            UnsupportedArchiveFeature::ManifestMediaType,
        ),
    ] {
        let built = ImageBuilder::new()
            .json(Doc::Index, move |index| {
                index["manifests"][0]["mediaType"] = json!(media_type);
            })
            .build();
        assert_fault(run(&built), &unsupported(feature));
    }
    let attestation = ImageBuilder::new()
        .json(Doc::Index, |index| {
            index["manifests"][0]["annotations"]["vnd.docker.reference.type"] =
                json!("attestation-manifest");
        })
        .build();
    assert_fault(
        run(&attestation),
        &unsupported(UnsupportedArchiveFeature::Attestation),
    );
}

#[test]
fn image_manifest_and_config_media_types() {
    let manifest = ImageBuilder::new()
        .json(Doc::Manifest, |manifest| {
            manifest["mediaType"] = json!("application/vnd.docker.distribution.manifest.v2+json");
        })
        .build();
    assert_fault(
        run(&manifest),
        &unsupported(UnsupportedArchiveFeature::ManifestMediaType),
    );
    let config = ImageBuilder::new()
        .json(Doc::Manifest, |manifest| {
            manifest["config"]["mediaType"] =
                json!("application/vnd.docker.container.image.v1+json");
        })
        .build();
    assert_fault(
        run(&config),
        &unsupported(UnsupportedArchiveFeature::ConfigMediaType),
    );
}

#[test]
fn excluded_layer_media_types_are_refused_without_decoding() {
    for media_type in [
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    ] {
        let built = ImageBuilder::new()
            .layers(vec![
                Layer::gzip(&layer_tar("a", b"a")),
                Layer::gzip(&layer_tar("b", b"b")),
            ])
            .json(Doc::Manifest, move |manifest| {
                manifest["layers"][1]["mediaType"] = json!(media_type);
            })
            .build();
        seam::take();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::LayerMediaType { position: 1 }),
        );
        let events = seam::take();
        // The raw inventory hashed every blob; phase 7 never ran.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, seam::Event::InventoryBlob(_)))
                .count(),
            4
        );
        assert_eq!(events_for(0, &events) + events_for(1, &events), 0);
    }
}

#[test]
fn every_extension_field_is_refused() {
    for (key, field) in [
        ("subject", ExtensionField::Subject),
        ("artifactType", ExtensionField::ArtifactType),
        ("urls", ExtensionField::Urls),
        ("data", ExtensionField::Data),
    ] {
        let built = ImageBuilder::new()
            .json(Doc::Index, move |index| {
                index["manifests"][0][key] = json!("x");
            })
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::ExtensionField {
                document: ImageDocument::Index,
                field,
            }),
        );
        let built = ImageBuilder::new()
            .json(Doc::Manifest, move |manifest| {
                manifest["layers"][0][key] = json!("x");
            })
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::ExtensionField {
                document: ImageDocument::ImageManifest,
                field,
            }),
        );
    }
    for (key, field) in [
        ("subject", ExtensionField::Subject),
        ("artifactType", ExtensionField::ArtifactType),
    ] {
        let built = ImageBuilder::new()
            .json(Doc::Manifest, move |manifest| {
                manifest[key] = json!("x");
            })
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::ExtensionField {
                document: ImageDocument::ImageManifest,
                field,
            }),
        );
    }
    // Order: subject, artifactType, urls, data.
    let built = ImageBuilder::new()
        .json(Doc::Manifest, |manifest| {
            manifest["config"]["data"] = json!("x");
            manifest["config"]["urls"] = json!([]);
        })
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::ExtensionField {
            document: ImageDocument::ImageManifest,
            field: ExtensionField::Urls,
        }),
    );
}

#[test]
fn annotations_on_a_config_or_layer_descriptor_are_refused() {
    for target in ["config", "layer"] {
        let built = ImageBuilder::new()
            .json(Doc::Manifest, move |manifest| {
                let descriptor = if target == "config" {
                    &mut manifest["config"]
                } else {
                    &mut manifest["layers"][0]
                };
                descriptor["annotations"] = json!({"a": "b"});
            })
            .build();
        assert_fault(
            run(&built),
            &unsupported(UnsupportedArchiveFeature::DescriptorAnnotation),
        );
    }
}

#[test]
fn every_descriptor_shape_rule_is_enforced() {
    type Edit = fn(&mut Value);
    let index_cases: &[Edit] = &[
        |d| *d = json!("not an object"),
        |d| d["unknown"] = json!(1),
        |d| d["mediaType"] = json!(1),
        |d| {
            object(d).remove("mediaType");
        },
        |d| d["digest"] = json!(format!("sha256:{}", FAKE_HEX.to_uppercase())),
        |d| d["digest"] = json!(format!("sha512:{FAKE_HEX}")),
        |d| d["digest"] = json!("sha256:abc"),
        |d| {
            object(d).remove("digest");
        },
        |d| d["size"] = json!(-1),
        |d| d["size"] = json!(1.5),
        |d| d["size"] = json!("12"),
        |d| d["size"] = json!(18_446_744_073_709_551_616.0),
        |d| {
            object(d).remove("size");
        },
        |d| d["annotations"] = json!([]),
        |d| d["annotations"]["x"] = json!(1),
        |d| d["platform"] = json!("linux/amd64"),
        |d| d["platform"] = json!({"os": 1, "architecture": "amd64"}),
        |d| d["platform"] = json!({"os": "linux", "architecture": "amd64", "variant": 8}),
        |d| d["platform"] = json!({"os": "linux", "architecture": "amd64", "os.version": "1"}),
        |d| d["platform"] = json!({"os": "linux"}),
    ];
    for edit in index_cases {
        let built = ImageBuilder::new()
            .json(Doc::Index, move |index| edit(&mut index["manifests"][0]))
            .build();
        assert_fault(run(&built), &shape(ImageDocument::Index));
    }
    let manifest_cases: &[Edit] = &[
        |m| m["config"] = json!(null),
        |m| {
            object(m).remove("config");
        },
        |m| m["config"]["platform"] = json!({"architecture": "amd64"}),
        |m| m["layers"][0]["platform"] = json!({"os": "linux", "architecture": "amd64"}),
        |m| m["layers"][0] = json!([]),
        |m| m["layers"] = json!({}),
        |m| {
            object(m).remove("layers");
        },
        |m| m["schemaVersion"] = json!(1),
        |m| m["mediaType"] = json!(null),
        |m| {
            object(m).remove("mediaType");
        },
        |m| m["unknown"] = json!(1),
        |m| m["annotations"] = json!({"org.opencontainers.image.title": 1}),
        |m| *m = json!([]),
    ];
    for edit in manifest_cases {
        let built = ImageBuilder::new().json(Doc::Manifest, *edit).build();
        assert_fault(run(&built), &shape(ImageDocument::ImageManifest));
    }
    let built = ImageBuilder::new()
        .json(Doc::Manifest, |m| {
            m["annotations"] = json!({"org.opencontainers.image.ref.name": "x"});
        })
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::ManifestAnnotation),
    );
}

#[test]
fn an_empty_descriptor_variant_is_refused_where_it_appears() {
    let built = ImageBuilder::new()
        .json(Doc::Index, |index| {
            index["manifests"][0]["platform"] =
                json!({"os": "linux", "architecture": "amd64", "variant": ""});
        })
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::EmptyPlatformVariant {
            location: PlatformLocation::IndexDescriptor { index: 0 },
        }),
    );
    let built = ImageBuilder::new()
        .json(Doc::Manifest, |manifest| {
            manifest["config"]["platform"] =
                json!({"os": "linux", "architecture": "amd64", "variant": ""});
        })
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::EmptyPlatformVariant {
            location: PlatformLocation::ConfigDescriptor,
        }),
    );
}

#[test]
fn every_compatibility_record_rule_is_enforced() {
    type Edit = fn(&mut Value);
    let cases: &[Edit] = &[
        |c| *c = json!({}),
        |c| *c = json!([]),
        |c| c[0] = json!("record"),
        |c| c[0]["Extra"] = json!(1),
        |c| c[0]["Config"] = json!(1),
        |c| {
            object(&mut c[0]).remove("Config");
        },
        |c| c[0]["RepoTags"] = json!([]),
        |c| c[0]["RepoTags"] = json!([1]),
        |c| c[0]["RepoTags"] = json!(null),
        |c| {
            object(&mut c[0]).remove("RepoTags");
        },
        |c| c[0]["Layers"] = json!("x"),
        |c| c[0]["Layers"] = json!([1]),
        |c| {
            object(&mut c[0]).remove("Layers");
        },
        |c| c[0]["Parent"] = json!(null),
        |c| c[0]["Parent"] = json!("sha256:abc"),
        |c| c[0]["LayerSources"] = json!([]),
    ];
    for edit in cases {
        let built = ImageBuilder::new().json(Doc::Compat, *edit).build();
        assert_fault(run(&built), &shape(ImageDocument::CompatibilityManifest));
    }
}

#[test]
fn every_manifest_blob_check_is_enforced() {
    let missing = ImageBuilder::new()
        .entries(|entries, parts| remove_entry(entries, &blob_name(&parts.manifest_hex)))
        .build();
    assert_fault(
        run(&missing),
        &invalid(InvalidArchiveReason::MissingBlob {
            role: BlobRole::Manifest,
        }),
    );
    let length = ImageBuilder::new()
        .json(Doc::Index, |index| {
            let size = index["manifests"][0]["size"].as_u64().unwrap();
            index["manifests"][0]["size"] = json!(size + 1);
        })
        .build();
    assert_fault(
        run(&length),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Manifest,
            kind: BlobMismatchKind::Length,
        }),
    );
    let digest_mismatch = ImageBuilder::new()
        .json(Doc::Index, |index| {
            index["manifests"][0]["digest"] = json!(format!("sha256:{FAKE_HEX}"));
        })
        .entries(|entries, parts| rename_blob(entries, &parts.manifest_hex, FAKE_HEX))
        .build();
    assert_fault(
        run(&digest_mismatch),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Manifest,
            kind: BlobMismatchKind::Digest,
        }),
    );
}

// ---------------------------------------------------------------------------
// Phase 3
// ---------------------------------------------------------------------------

#[test]
fn every_compatibility_link_is_checked() {
    let inconsistent = invalid(InvalidArchiveReason::InconsistentCompatibility);
    let config = ImageBuilder::new()
        .json(Doc::Compat, |c| {
            c[0]["Config"] = json!(format!("blobs/sha256/{FAKE_HEX}"));
        })
        .build();
    assert_fault(run(&config), &inconsistent);
    let config_form = ImageBuilder::new()
        .json(Doc::Compat, |c| {
            let path = c[0]["Config"].as_str().unwrap().to_string();
            c[0]["Config"] = json!(format!("./{path}"));
        })
        .build();
    assert_fault(run(&config_form), &inconsistent);
    let count = ImageBuilder::new()
        .json(Doc::Compat, |c| c[0]["Layers"] = json!([]))
        .build();
    assert_fault(run(&count), &inconsistent);
    let path = ImageBuilder::new()
        .json(Doc::Compat, |c| {
            c[0]["Layers"][0] = json!(format!("blobs/sha256/{FAKE_HEX}"));
        })
        .build();
    assert_fault(run(&path), &inconsistent);
    let a = layer_tar("a", b"a");
    let repeated = ImageBuilder::new()
        .layers(vec![Layer::gzip(&a)])
        .positions(&[0, 0])
        .json(Doc::Manifest, |m| {
            m["layers"][1]["mediaType"] = json!(LAYER_TAR);
        })
        .build();
    assert_fault(run(&repeated), &inconsistent);
}

#[test]
fn missing_and_unreferenced_blobs() {
    let config = ImageBuilder::new()
        .entries(|entries, parts| remove_entry(entries, &blob_name(&parts.config_hex)))
        .build();
    assert_fault(
        run(&config),
        &invalid(InvalidArchiveReason::MissingBlob {
            role: BlobRole::Config,
        }),
    );
    let a = layer_tar("a", b"a");
    let b = layer_tar("b", b"b");
    let layer = ImageBuilder::new()
        .layers(vec![Layer::gzip(&a), Layer::gzip(&b)])
        .positions(&[0, 1, 1])
        .entries(|entries, parts| remove_entry(entries, &blob_name(&parts.layer_hexes[1])))
        .build();
    assert_fault(
        run(&layer),
        &invalid(InvalidArchiveReason::MissingBlob {
            role: BlobRole::Layer { position: 1 },
        }),
    );
    let unreferenced = with_entries(vec![Entry::file(&blob_name(FAKE_HEX), b"x".to_vec())]);
    assert_fault(
        run(&unreferenced),
        &unsupported(UnsupportedArchiveFeature::UnreferencedBlob),
    );
}

// ---------------------------------------------------------------------------
// Phase 4
// ---------------------------------------------------------------------------

fn with_repo_tags(declared: &[&str], repo_tags: Value) -> Built {
    let declared: Vec<String> = declared.iter().map(ToString::to_string).collect();
    let refs: Vec<&str> = declared.iter().map(String::as_str).collect();
    ImageBuilder::new()
        .tags(&refs)
        .json(Doc::Compat, move |c| c[0]["RepoTags"] = repo_tags)
        .build()
}

#[test]
fn every_repo_tag_rule_is_enforced() {
    assert_fault(
        run(&with_repo_tags(&["a:1"], json!(["a:1", "Bad/Name:1"]))),
        &invalid(InvalidArchiveReason::InvalidRepoTag { index: 1 }),
    );
    assert_fault(
        run(&with_repo_tags(&["a:1"], json!(["a"]))),
        &invalid(InvalidArchiveReason::InvalidRepoTag { index: 0 }),
    );
    assert_fault(
        run(&with_repo_tags(&["a:1"], json!(["a:1", "a:1"]))),
        &invalid(InvalidArchiveReason::DuplicateTag {
            source: ReferenceSource::RepoTags,
        }),
    );
    assert_fault(
        run(&with_repo_tags(&["a:1", "b:1"], json!(["a:1"]))),
        &reference(true, "b:1", ReferenceSource::RepoTags),
    );
    assert_fault(
        run(&with_repo_tags(&["a:1"], json!(["a:1", "c:1"]))),
        &reference(false, "c:1", ReferenceSource::RepoTags),
    );
    // The byte-wise smallest of missing and extra is reported.
    assert_fault(
        run(&with_repo_tags(&["a:1", "z:1"], json!(["a:1", "b:1"]))),
        &reference(false, "b:1", ReferenceSource::RepoTags),
    );
    assert_fault(
        run(&with_repo_tags(&["a:1", "b:1"], json!(["a:1", "z:1"]))),
        &reference(true, "b:1", ReferenceSource::RepoTags),
    );
    // A normalized-equivalent spelling is both missing and extra.
    assert_fault(
        run(&with_repo_tags(&["x:1"], json!(["docker.io/library/x:1"]))),
        &reference(false, "docker.io/library/x:1", ReferenceSource::RepoTags),
    );
    assert_fault(
        run(&with_repo_tags(&["docker.io/library/x:1"], json!(["x:1"]))),
        &reference(true, "docker.io/library/x:1", ReferenceSource::RepoTags),
    );
}

fn with_annotations(declared: &[&str], edit: impl FnOnce(&mut Value) + 'static) -> Built {
    ImageBuilder::new()
        .tags(declared)
        .json(Doc::Index, edit)
        .build()
}

#[test]
fn every_index_annotation_rule_is_enforced() {
    let invalid_at = |index| invalid(InvalidArchiveReason::InvalidAnnotation { index });
    assert_fault(
        run(&with_annotations(&["a:1"], |i| {
            i["manifests"][0]["annotations"]["org.example.other"] = json!("x");
        })),
        &unsupported(UnsupportedArchiveFeature::DescriptorAnnotation),
    );
    assert_fault(
        run(&with_annotations(&["a:1"], |i| {
            object(&mut i["manifests"][0]).remove("annotations");
        })),
        &invalid_at(0),
    );
    assert_fault(
        run(&with_annotations(&["a:1", "b:1"], |i| {
            object(&mut i["manifests"][1]["annotations"]).remove("io.containerd.image.name");
        })),
        &invalid_at(1),
    );
    assert_fault(
        run(&with_annotations(&["a:1"], |i| {
            i["manifests"][0]["annotations"]["io.containerd.image.name"] = json!("a");
        })),
        &invalid_at(0),
    );
    for ref_name in ["2", "1.0", "docker.io/library/a:2", "b:1", "A:1"] {
        assert_fault(
            run(&with_annotations(&["a:1"], move |i| {
                i["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] =
                    json!(ref_name);
            })),
            &invalid_at(0),
        );
    }
    // The tag comparison is case-sensitive.
    assert_fault(
        run(&with_annotations(&["a:Latest"], |i| {
            i["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = json!("latest");
        })),
        &invalid_at(0),
    );
    // `ref.name` is optional.
    accept(&with_annotations(&["a:1"], |i| {
        object(&mut i["manifests"][0]["annotations"]).remove("org.opencontainers.image.ref.name");
    }));
    assert_fault(
        run(&with_annotations(&["a:1", "b:1"], |i| {
            i["manifests"][1]["annotations"]["io.containerd.image.name"] =
                json!("docker.io/library/a:1");
            i["manifests"][1]["annotations"]["org.opencontainers.image.ref.name"] = json!("1");
        })),
        &invalid(InvalidArchiveReason::DuplicateTag {
            source: ReferenceSource::IndexAnnotation,
        }),
    );
    // Missing items are named by their signed literal, extra ones by theirs.
    assert_fault(
        run(&with_annotations(&["a:1", "b:1"], |i| {
            i["manifests"][1]["annotations"]["io.containerd.image.name"] = json!("c:1");
        })),
        &reference(true, "b:1", ReferenceSource::IndexAnnotation),
    );
    assert_fault(
        run(&with_annotations(&["a:1", "z:1"], |i| {
            i["manifests"][1]["annotations"]["io.containerd.image.name"] = json!("c:1");
        })),
        &reference(false, "c:1", ReferenceSource::IndexAnnotation),
    );
    assert_fault(
        run(&with_annotations(&["x:1"], |i| {
            i["manifests"][0]["annotations"]["io.containerd.image.name"] =
                json!("registry.example/x:1");
        })),
        &reference(
            false,
            "registry.example/x:1",
            ReferenceSource::IndexAnnotation,
        ),
    );
}

// ---------------------------------------------------------------------------
// Phase 5
// ---------------------------------------------------------------------------

#[test]
fn the_config_must_hash_to_the_declared_digest() {
    let mut built = ImageBuilder::new().build();
    let actual = built.config_digest.clone();
    built.declaration.config_digest = format!("sha256:{FAKE_HEX}");
    assert_fault(
        run(&built),
        &image(ImageVerifyError::ConfigDigestMismatch {
            archive_path: PATH.to_string(),
            declared: format!("sha256:{FAKE_HEX}"),
            actual,
        }),
    );
}

#[test]
fn the_config_blob_must_match_its_descriptor() {
    let length = ImageBuilder::new()
        .json(Doc::Manifest, |m| {
            let size = m["config"]["size"].as_u64().unwrap();
            m["config"]["size"] = json!(size + 1);
        })
        .build();
    assert_fault(
        run(&length),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Config,
            kind: BlobMismatchKind::Length,
        }),
    );
    // The declared digest is the real one, and the descriptor and file name
    // claim another: the declaration passes and the descriptor does not.
    let digest_mismatch = ImageBuilder::new()
        .json(Doc::Manifest, |m| {
            m["config"]["digest"] = json!(format!("sha256:{FAKE_HEX}"));
        })
        .json(Doc::Compat, |c| c[0]["Config"] = json!(blob_name(FAKE_HEX)))
        .entries(|entries, parts| rename_blob(entries, &parts.config_hex, FAKE_HEX))
        .build();
    assert_fault(
        run(&digest_mismatch),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Config,
            kind: BlobMismatchKind::Digest,
        }),
    );
}

#[test]
// A table of every reason, one row each.
#[allow(clippy::too_many_lines)]
fn every_invalid_config_reason() {
    type Edit = fn(&mut Value);
    let cases: &[(Edit, InvalidConfigReason)] = &[
        (|c| *c = json!([]), InvalidConfigReason::NotObject),
        (
            |c| {
                object(c).remove("architecture");
            },
            InvalidConfigReason::MissingField {
                field: ConfigField::Architecture,
            },
        ),
        (
            |c| {
                object(c).remove("os");
            },
            InvalidConfigReason::MissingField {
                field: ConfigField::Os,
            },
        ),
        (
            |c| {
                object(c).remove("rootfs");
            },
            InvalidConfigReason::MissingField {
                field: ConfigField::Rootfs,
            },
        ),
        (
            |c| c["architecture"] = json!(1),
            InvalidConfigReason::FieldType {
                field: ConfigField::Architecture,
            },
        ),
        (
            |c| c["os"] = json!(null),
            InvalidConfigReason::FieldType {
                field: ConfigField::Os,
            },
        ),
        (
            |c| c["variant"] = json!(8),
            InvalidConfigReason::FieldType {
                field: ConfigField::Variant,
            },
        ),
        (
            |c| c["rootfs"] = json!("layers"),
            InvalidConfigReason::FieldType {
                field: ConfigField::Rootfs,
            },
        ),
        (
            |c| c["history"] = json!({}),
            InvalidConfigReason::FieldType {
                field: ConfigField::History,
            },
        ),
        (
            |c| c["variant"] = json!(""),
            InvalidConfigReason::EmptyVariant,
        ),
        (
            |c| c["rootfs"]["type"] = json!("snapshot"),
            InvalidConfigReason::RootfsShape,
        ),
        (
            |c| c["rootfs"]["extra"] = json!(1),
            InvalidConfigReason::RootfsShape,
        ),
        (
            |c| {
                object(&mut c["rootfs"]).remove("diff_ids");
            },
            InvalidConfigReason::RootfsShape,
        ),
        (
            |c| {
                object(&mut c["rootfs"]).remove("type");
            },
            InvalidConfigReason::RootfsShape,
        ),
        (
            |c| c["rootfs"]["diff_ids"] = json!("x"),
            InvalidConfigReason::RootfsShape,
        ),
        (
            |c| c["rootfs"]["diff_ids"][0] = json!(format!("sha256:{}", FAKE_HEX.to_uppercase())),
            InvalidConfigReason::DiffIdSyntax { index: 0 },
        ),
        (
            |c| c["rootfs"]["diff_ids"][0] = json!(7),
            InvalidConfigReason::DiffIdSyntax { index: 0 },
        ),
        (
            |c| {
                c["history"] = json!([{"created_by": "x"}, "not an object"]);
            },
            InvalidConfigReason::HistoryEntryShape { index: 1 },
        ),
        (
            |c| c["history"][0]["empty_layer"] = json!("true"),
            InvalidConfigReason::HistoryEntryShape { index: 0 },
        ),
        (
            |c| {
                c["history"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"created_by": "y"}));
            },
            InvalidConfigReason::HistoryLayerCount,
        ),
        (
            |c| c["history"][0]["empty_layer"] = json!(true),
            InvalidConfigReason::HistoryLayerCount,
        ),
    ];
    for (edit, reason) in cases {
        let built = ImageBuilder::new().json(Doc::Config, *edit).build();
        assert_fault(run(&built), &config_reason(*reason));
    }
}

#[test]
fn additional_config_metadata_stays_bounded() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |c| c["notes"] = json!("x".repeat(1000)))
        .build();
    let size = built_config_len(&built);
    let validated = run_with(&built, &limits(&[(LimitResource::ConfigJson, size)])).unwrap();
    assert_summary(&validated, &built);
    assert_fault(
        run_with(&built, &limits(&[(LimitResource::ConfigJson, size - 1)])),
        &limit(LimitResource::ConfigJson, size - 1),
    );
    let mut nested = json!("leaf");
    for _ in 0..64 {
        nested = json!([nested]);
    }
    let deep = ImageBuilder::new()
        .json(Doc::Config, move |c| c["nested"] = nested)
        .build();
    assert_fault(run(&deep), &limit(LimitResource::JsonDepth, 64));
}

/// Returns the stored length of `built`'s config blob.
fn built_config_len(built: &Built) -> u64 {
    blob_len(built, &built.parts.config_hex)
}

fn blob_len(built: &Built, hex: &str) -> u64 {
    let validated = accept(built);
    validated
        .entries
        .iter()
        .find(|entry| entry.name == blob_name(hex))
        .map(|entry| entry.data_len)
        .unwrap()
}

// ---------------------------------------------------------------------------
// Phase 6
// ---------------------------------------------------------------------------

#[test]
// Every facet at every location, in one place.
#[allow(clippy::too_many_lines)]
fn every_platform_facet_at_every_location() {
    let config_os = ImageBuilder::new()
        .json(Doc::Config, |c| c["os"] = json!("windows"))
        .build();
    assert_fault(
        run(&config_os),
        &platform_mismatch(
            PlatformLocation::Config,
            PlatformFacet::Os,
            Some("linux"),
            Some("windows"),
        ),
    );
    let config_arch = ImageBuilder::new()
        .json(Doc::Config, |c| c["architecture"] = json!("arm64"))
        .build();
    assert_fault(
        run(&config_arch),
        &platform_mismatch(
            PlatformLocation::Config,
            PlatformFacet::Architecture,
            Some("amd64"),
            Some("arm64"),
        ),
    );
    // The variant: one byte off, case only, present against null, absent
    // against a signed value.
    for (config_variant, signed, actual) in [
        (Some("v7"), Some("v8"), Some("v7")),
        (Some("V8"), Some("v8"), Some("V8")),
        (Some("v8"), None, Some("v8")),
        (None, Some("v8"), None),
    ] {
        let mut built = ImageBuilder::new()
            .platform(ImageArchitecture::Arm64, config_variant)
            .build();
        built.declaration.platform.variant = signed.map(str::to_string);
        assert_fault(
            run(&built),
            &platform_mismatch(
                PlatformLocation::Config,
                PlatformFacet::Variant,
                signed,
                actual,
            ),
        );
    }
    // A signed variant never matches a null one.
    let mut null_variant = ImageBuilder::new()
        .json(Doc::Config, |c| c["variant"] = Value::Null)
        .build();
    null_variant.declaration.platform.variant = Some("v8".to_string());
    assert_fault(
        run(&null_variant),
        &platform_mismatch(
            PlatformLocation::Config,
            PlatformFacet::Variant,
            Some("v8"),
            None,
        ),
    );

    let descriptor_cases = [
        (
            json!({"os": "Linux", "architecture": "amd64"}),
            PlatformFacet::Os,
            Some("linux"),
            Some("Linux"),
        ),
        (
            json!({"os": "linux", "architecture": "x86_64"}),
            PlatformFacet::Architecture,
            Some("amd64"),
            Some("x86_64"),
        ),
        (
            json!({"os": "linux", "architecture": "amd64", "variant": "v3"}),
            PlatformFacet::Variant,
            None,
            Some("v3"),
        ),
    ];
    for (platform, facet, declared, actual) in descriptor_cases {
        let for_index = platform.clone();
        let built = ImageBuilder::new()
            .tags(&["a:1", "b:1"])
            .json(Doc::Index, move |i| {
                i["manifests"][1]["platform"] = for_index;
            })
            .build();
        assert_fault(
            run(&built),
            &platform_mismatch(
                PlatformLocation::IndexDescriptor { index: 1 },
                facet,
                declared,
                actual,
            ),
        );
        let built = ImageBuilder::new()
            .json(Doc::Manifest, move |m| m["config"]["platform"] = platform)
            .build();
        assert_fault(
            run(&built),
            &platform_mismatch(PlatformLocation::ConfigDescriptor, facet, declared, actual),
        );
    }
    // Order: config, index descriptors, config descriptor.
    let built = ImageBuilder::new()
        .json(Doc::Index, |i| {
            i["manifests"][0]["platform"] = json!({"os": "linux", "architecture": "arm64"});
        })
        .json(Doc::Manifest, |m| {
            m["config"]["platform"] = json!({"os": "plan9", "architecture": "amd64"});
        })
        .build();
    assert_fault(
        run(&built),
        &platform_mismatch(
            PlatformLocation::IndexDescriptor { index: 0 },
            PlatformFacet::Architecture,
            Some("amd64"),
            Some("arm64"),
        ),
    );
}

#[test]
fn a_platform_mismatch_message_never_renders_the_observed_value() {
    let observed = "v8-\u{1f47b}-observed-secret";
    let mut built = ImageBuilder::new()
        .platform(ImageArchitecture::Arm64, Some(observed))
        .build();
    built.declaration.platform.variant = Some("v8".to_string());
    let Err(ImageArchiveFault::Image(error)) = run(&built) else {
        panic!("expected an image error");
    };
    assert!(matches!(
        &error,
        ImageVerifyError::ConfigPlatformMismatch { actual: Some(actual), .. } if actual == observed
    ));
    let message = error.to_string();
    assert!(!message.contains(observed), "{message}");
    assert!(!message.contains("observed-secret"), "{message}");
    assert!(message.contains("v8"), "{message}");
    assert!(message.contains(PATH), "{message}");
}

// ---------------------------------------------------------------------------
// Phase 7
// ---------------------------------------------------------------------------

#[test]
fn the_layer_count_must_match_the_diff_ids() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |c| {
            c["rootfs"]["diff_ids"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("sha256:{FAKE_HEX}")));
            c["history"].as_array_mut().unwrap().push(json!({}));
        })
        .build();
    assert_fault(
        run(&built),
        &layer_mismatch(None, LayerMismatchKind::CountMismatch, "2", "1"),
    );
}

#[test]
fn stored_layer_length_and_digest() {
    let length = ImageBuilder::new()
        .json(Doc::Manifest, |m| {
            let size = m["layers"][0]["size"].as_u64().unwrap();
            m["layers"][0]["size"] = json!(size - 1);
        })
        .build();
    assert_fault(
        run(&length),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Layer { position: 0 },
            kind: BlobMismatchKind::Length,
        }),
    );
    let tar = layer_tar("a", b"a");
    let layer = Layer::gzip(&tar);
    let actual = digest(&layer.blob);
    let stored = ImageBuilder::new()
        .layers(vec![layer])
        .json(Doc::Manifest, |m| {
            m["layers"][0]["digest"] = json!(format!("sha256:{FAKE_HEX}"));
        })
        .json(Doc::Compat, |c| {
            c[0]["Layers"][0] = json!(blob_name(FAKE_HEX));
        })
        .entries(|entries, parts| rename_blob(entries, &parts.layer_hexes[0], FAKE_HEX))
        .build();
    assert_fault(
        run(&stored),
        &layer_mismatch(
            Some(0),
            LayerMismatchKind::StoredDigest,
            &format!("sha256:{FAKE_HEX}"),
            &actual,
        ),
    );
}

#[test]
fn a_decoded_layer_must_hash_to_its_diff_id() {
    let a = layer_tar("a", b"alpha");
    let b = layer_tar("b", b"bravo");
    // A substituted blob.
    let substituted = ImageBuilder::new()
        .layers(vec![Layer::raw(gzip(&b), digest(&a), LAYER_GZIP)])
        .build();
    assert_fault(
        run(&substituted),
        &layer_mismatch(Some(0), LayerMismatchKind::DiffId, &digest(&a), &digest(&b)),
    );
    // Swapped layers.
    let (da, db) = (digest(&a), digest(&b));
    let swapped = ImageBuilder::new()
        .layers(vec![Layer::gzip(&a), Layer::gzip(&b)])
        .json(Doc::Config, move |c| {
            c["rootfs"]["diff_ids"] = json!([db, da]);
        })
        .build();
    assert_fault(
        run(&swapped),
        &layer_mismatch(Some(0), LayerMismatchKind::DiffId, &digest(&b), &digest(&a)),
    );
    // An uncompressed layer.
    let plain = ImageBuilder::new()
        .layers(vec![Layer::raw(b.clone(), digest(&a), LAYER_TAR)])
        .build();
    assert_fault(
        run(&plain),
        &layer_mismatch(Some(0), LayerMismatchKind::DiffId, &digest(&a), &digest(&b)),
    );
}

fn gzip_layer_fault(blob: Vec<u8>, tar: &[u8]) -> Result<ValidatedImageArchive, ImageArchiveFault> {
    let built = ImageBuilder::new()
        .layers(vec![Layer::raw(blob, digest(tar), LAYER_GZIP)])
        .build();
    run(&built)
}

fn gzip_fault(fault: GzipFault) -> ImageArchiveFault {
    invalid(InvalidArchiveReason::Gzip { position: 0, fault })
}

/// A member with FHCRC set and a header CRC that does not match.
fn bad_header_crc(tar: &[u8]) -> Vec<u8> {
    let plain = gzip(tar);
    let mut member = vec![0x1f, 0x8b, 8, 0x02, 0, 0, 0, 0, 0, 3, 0xde, 0xad];
    member.extend_from_slice(&plain[10..]);
    member
}

#[test]
fn every_gzip_fault() {
    let tar = layer_tar("a", b"alpha");
    let good = gzip(&tar);
    let edit = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut blob = good.clone();
        f(&mut blob);
        blob
    };
    let header = |fault| gzip_fault(GzipFault::Header { fault });
    let len = good.len();
    let cases: Vec<(Vec<u8>, ImageArchiveFault)> = vec![
        (edit(&|b| b[1] = 0x8c), header(GzipHeaderFault::Magic)),
        (edit(&|b| b[2] = 7), header(GzipHeaderFault::Method)),
        (
            edit(&|b| b[3] |= 0x20),
            header(GzipHeaderFault::ReservedFlags),
        ),
        (bad_header_crc(&tar), header(GzipHeaderFault::HeaderCrc)),
        // BFINAL with the reserved block type.
        (edit(&|b| b[10] = 0x07), gzip_fault(GzipFault::Deflate)),
        (edit(&|b| b[len - 8] ^= 1), gzip_fault(GzipFault::Crc32)),
        (edit(&|b| b[len - 4] ^= 1), gzip_fault(GzipFault::Isize)),
        (
            edit(&|b| b.truncate(len - 3)),
            gzip_fault(GzipFault::Truncated),
        ),
        (edit(&|b| b.truncate(12)), gzip_fault(GzipFault::Truncated)),
        (edit(&|b| b.truncate(5)), gzip_fault(GzipFault::Truncated)),
        (edit(&|b| b.push(0)), gzip_fault(GzipFault::TrailingData)),
    ];
    for (blob, expected) in cases {
        assert_fault(gzip_layer_fault(blob, &tar), &expected);
    }
}

#[test]
fn a_concatenated_member_is_refused_without_inflating_it() {
    let tar = layer_tar("a", b"alpha");
    let mut blob = gzip(&tar);
    // A second member whose body is garbage: inflating it would be a
    // `Deflate` fault, so the verdict shows it was never inflated.
    blob.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0x07, 0xff, 0xff]);
    assert_fault(
        gzip_layer_fault(blob, &tar),
        &unsupported(UnsupportedArchiveFeature::ConcatenatedGzipMember { position: 0 }),
    );
}

fn layer_tar_fault(tar: &[u8]) -> Result<ValidatedImageArchive, ImageArchiveFault> {
    let built = ImageBuilder::new()
        .layers(vec![
            Layer::plain(&layer_tar("ok", b"ok")),
            Layer::gzip(tar),
        ])
        .build();
    run(&built)
}

#[test]
fn excluded_layer_tar_features() {
    for flag in *b"Sg" {
        let tar = Tar::new().entry(&Header::new(flag, b"x", 0), &[]).finish();
        assert_fault(
            layer_tar_fault(&tar),
            &unsupported(UnsupportedArchiveFeature::LayerTar {
                position: 1,
                feature: TarFeature::EntryType { flag },
            }),
        );
    }
    let tar = Tar::new()
        .extension(b'x', &pax(&[("comment", b"hi")]))
        .file("x", b"x")
        .finish();
    assert_fault(
        layer_tar_fault(&tar),
        &unsupported(UnsupportedArchiveFeature::LayerTar {
            position: 1,
            feature: TarFeature::PaxKey,
        }),
    );
}

#[test]
fn malformed_layer_tars() {
    let layer_fault = |fault| invalid(InvalidArchiveReason::LayerTar { position: 1, fault });
    let dangling = Tar::new().extension(b'x', &pax(&[("path", b"x")])).finish();
    assert_fault(
        layer_tar_fault(&dangling),
        &layer_fault(TarFault::DanglingExtension),
    );
    let dotdot = Tar::new().file("../x", b"x").finish();
    assert_fault(layer_tar_fault(&dotdot), &layer_fault(TarFault::UnsafePath));
    let symlink = Tar::new()
        .entry(Header::new(b'2', b"link", 4).linkname(b"x"), b"data")
        .finish();
    assert_fault(
        layer_tar_fault(&symlink),
        &layer_fault(TarFault::NonRegularWithData),
    );
    // A tar cut short inside a gzip member that is itself complete.
    let cut = Tar::new().file("x", b"x").unfinished();
    assert_fault(layer_tar_fault(&cut), &layer_fault(TarFault::Truncated));
    let checksum = Tar::new()
        .entry(Header::file("x", 1).wrong_checksum(), b"x")
        .finish();
    assert_fault(layer_tar_fault(&checksum), &layer_fault(TarFault::Checksum));
    let pax_value = Tar::new()
        .extension(b'x', &pax(&[("size", b"-1")]))
        .file("x", b"x")
        .finish();
    assert_fault(
        layer_tar_fault(&pax_value),
        &layer_fault(TarFault::PaxValue { key: PaxKey::Size }),
    );
    // Uncompressed: the walker's own truncation.
    let built = ImageBuilder::new()
        .layers(vec![Layer::plain(&Tar::new().file("x", b"x").unfinished())])
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::LayerTar {
            position: 0,
            fault: TarFault::Truncated,
        }),
    );
}

// ---------------------------------------------------------------------------
// Phase 8
// ---------------------------------------------------------------------------

fn with_layer_sources(edit: impl FnOnce(&mut Value, &Layer) + 'static) -> Built {
    let tar = layer_tar("a", b"alpha");
    let layer = Layer::gzip(&tar);
    let for_edit = layer.clone();
    ImageBuilder::new()
        .layers(vec![layer])
        .json(Doc::Compat, move |c| {
            let mut sources = json!({
                for_edit.diff_id.clone(): {
                    "mediaType": LAYER_GZIP,
                    "digest": digest(&for_edit.blob),
                    "size": for_edit.blob.len(),
                },
            });
            edit(&mut sources, &for_edit);
            c[0]["LayerSources"] = sources;
        })
        .build()
}

#[test]
fn every_layer_sources_rule_is_enforced() {
    type Edit = fn(&mut Value, &Layer);
    let inconsistent = invalid(InvalidArchiveReason::InconsistentLayerSources);
    accept(&with_layer_sources(|_, _| {}));
    let cases: &[Edit] = &[
        |s, _| s[format!("sha256:{FAKE_HEX}")] = json!({}),
        |s, l| {
            let value = s[&l.diff_id].take();
            *s = json!({ format!("sha256:{FAKE_HEX}"): value });
        },
        |s, l| s[&l.diff_id] = json!("x"),
        |s, l| s[&l.diff_id]["extra"] = json!(1),
        |s, l| {
            object(&mut s[&l.diff_id]).remove("size");
        },
        |s, l| s[&l.diff_id]["size"] = json!(1),
        |s, l| s[&l.diff_id]["digest"] = json!(format!("sha256:{FAKE_HEX}")),
        |s, l| s[&l.diff_id]["mediaType"] = json!(LAYER_TAR),
    ];
    for edit in cases {
        assert_fault(run(&with_layer_sources(*edit)), &inconsistent);
    }
    for (key, field) in [
        ("subject", ExtensionField::Subject),
        ("artifactType", ExtensionField::ArtifactType),
        ("urls", ExtensionField::Urls),
        ("data", ExtensionField::Data),
    ] {
        assert_fault(
            run(&with_layer_sources(move |s, l| {
                s[&l.diff_id][key] = json!(["https://example.com/blob"]);
            })),
            &unsupported(UnsupportedArchiveFeature::ExtensionField {
                document: ImageDocument::CompatibilityManifest,
                field,
            }),
        );
    }
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

#[test]
fn each_earlier_phase_wins_over_the_next() {
    // 1. Inventory before JSON.
    let built = ImageBuilder::new()
        .raw(Doc::Index, b"{")
        .entries(|entries, _| entries.push(Entry::file("extra", b"x".to_vec())))
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::ExtraFile),
    );
    // 2. JSON before tags.
    let built = ImageBuilder::new()
        .raw(
            Doc::OciLayout,
            br#"{"imageLayoutVersion":"1.0.0","imageLayoutVersion":"1"}"#,
        )
        .json(Doc::Compat, |c| c[0]["RepoTags"] = json!(["other:1"]))
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::Json {
            document: ImageDocument::OciLayout,
            fault: JsonFault::DuplicateKey,
        }),
    );
    // 3. Manifest blob before tags.
    let built = ImageBuilder::new()
        .json(Doc::Index, |i| {
            let size = i["manifests"][0]["size"].as_u64().unwrap();
            i["manifests"][0]["size"] = json!(size + 1);
        })
        .json(Doc::Compat, |c| c[0]["RepoTags"] = json!(["other:1"]))
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Manifest,
            kind: BlobMismatchKind::Length,
        }),
    );
    // 4. Tags before config.
    let mut built = ImageBuilder::new()
        .json(Doc::Compat, |c| c[0]["RepoTags"] = json!(["other:1"]))
        .build();
    built.declaration.config_digest = format!("sha256:{FAKE_HEX}");
    assert_fault(
        run(&built),
        &reference(true, "example.com/app:1.0", ReferenceSource::RepoTags),
    );
    // 5. Config before platform.
    let built = ImageBuilder::new()
        .json(Doc::Config, |c| {
            c["os"] = json!("windows");
            c["history"].as_array_mut().unwrap().push(json!({}));
        })
        .build();
    assert_fault(
        run(&built),
        &config_reason(InvalidConfigReason::HistoryLayerCount),
    );
    // 6. Platform before layers.
    let a = layer_tar("a", b"a");
    let b = layer_tar("b", b"b");
    let built = ImageBuilder::new()
        .layers(vec![Layer::raw(gzip(&b), digest(&a), LAYER_GZIP)])
        .json(Doc::Config, |c| c["variant"] = json!("v2"))
        .build();
    assert_fault(
        run(&built),
        &platform_mismatch(
            PlatformLocation::Config,
            PlatformFacet::Variant,
            None,
            Some("v2"),
        ),
    );
    // 7. Layers before LayerSources.
    let bad_blob = gzip(&b);
    let built = ImageBuilder::new()
        .layers(vec![Layer::raw(bad_blob, digest(&a), LAYER_GZIP)])
        .json(Doc::Compat, |c| c[0]["LayerSources"] = json!({"x": {}}))
        .build();
    assert_fault(
        run(&built),
        &layer_mismatch(Some(0), LayerMismatchKind::DiffId, &digest(&a), &digest(&b)),
    );
}

#[test]
fn the_compatibility_links_fall_between_documents_and_tags() {
    // Image manifest shape before compatibility links.
    let built = ImageBuilder::new()
        .json(Doc::Manifest, |m| m["annotations"] = json!({"x": "y"}))
        .json(Doc::Compat, |c| {
            c[0]["Config"] = json!(format!("blobs/sha256/{FAKE_HEX}"));
        })
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::ManifestAnnotation),
    );
    // Blob set before tags.
    let built = ImageBuilder::new()
        .entries(|entries, _| entries.push(Entry::file(&blob_name(FAKE_HEX), b"x".to_vec())))
        .json(Doc::Compat, |c| c[0]["RepoTags"] = json!(["other:1"]))
        .build();
    assert_fault(
        run(&built),
        &unsupported(UnsupportedArchiveFeature::UnreferencedBlob),
    );
}

#[test]
fn a_deferred_finding_loses_to_a_later_hazard() {
    let extra = || Entry::file("extra", b"x".to_vec());
    let checksum = ImageBuilder::new()
        .entries(move |entries, _| {
            entries.insert(0, extra());
            entries.last_mut().unwrap().header.wrong_checksum();
        })
        .build();
    assert_fault(run(&checksum), &tar_fault(TarFault::Checksum));
    let trailing = ImageBuilder::new()
        .entries(move |entries, _| entries.insert(0, extra()))
        .tail(|bytes| bytes.push(7))
        .build();
    assert_fault(run(&trailing), &tar_fault(TarFault::TrailingData));
    let overflow = ImageBuilder::new()
        .entries(move |entries, _| entries.insert(0, extra()))
        .build();
    let len = u64::try_from(overflow.bytes.len()).unwrap();
    assert_fault(
        run_with(
            &overflow,
            &limits(&[(LimitResource::ImageArchive, len - 1)]),
        ),
        &limit(LimitResource::ImageArchive, len - 1),
    );
}

#[test]
fn the_first_deferred_finding_in_archive_order_wins() {
    let build = |legacy_first: bool| {
        ImageBuilder::new()
            .entries(move |entries, _| {
                let legacy = Entry::file("repositories", b"{}".to_vec());
                let extra = Entry::file("extra", b"x".to_vec());
                if legacy_first {
                    entries.insert(0, legacy);
                    entries.push(extra);
                } else {
                    entries.insert(0, extra);
                    entries.push(legacy);
                }
            })
            .build()
    };
    assert_fault(
        run(&build(true)),
        &unsupported(UnsupportedArchiveFeature::LegacyExportFile),
    );
    assert_fault(
        run(&build(false)),
        &unsupported(UnsupportedArchiveFeature::ExtraFile),
    );
    let missing_index = ImageBuilder::new()
        .entries(|entries, _| {
            remove_entry(entries, "index.json");
            entries.push(Entry::file("extra", b"x".to_vec()));
        })
        .build();
    assert_fault(
        run(&missing_index),
        &unsupported(UnsupportedArchiveFeature::ExtraFile),
    );
}

#[test]
fn the_raw_walk_completes_before_any_semantic_check() {
    let mut built = ImageBuilder::new()
        .entries(|entries, _| {
            entries.last_mut().unwrap().header.wrong_checksum();
        })
        .build();
    built.declaration.config_digest = format!("sha256:{FAKE_HEX}");
    assert_fault(run(&built), &tar_fault(TarFault::Checksum));
}

#[test]
fn the_compression_probe_charges_each_byte_once() {
    let mut tiny = ImageBuilder::new().build();
    tiny.bytes = b"abcd".to_vec();
    let (source, log) = Source::new(tiny.bytes.clone());
    assert_fault(
        run_on(source, &tiny, &limits(&[(LimitResource::ImageArchive, 2)])),
        &limit(LimitResource::ImageArchive, 2),
    );
    // Two bytes delivered and charged, then one probe byte read to tell end of
    // file from excess, and never delivered.
    assert_eq!(log.borrow().delivered, 3);
    // The same, at the probe itself: the source gave up three bytes, and only
    // the two within the limit were delivered to it and charged.
    let (mut source, log) = Source::new(b"abcd".to_vec());
    let mut counted = CountingReader::new(
        &mut source,
        ResourceLimit {
            resource: LimitResource::ImageArchive,
            max: 2,
        },
        Vec::new(),
        ContentLimits::default().copy_buffer_len(),
    );
    assert!(matches!(
        probe(&mut counted),
        Err(Verdict::Limit {
            resource: LimitResource::ImageArchive,
            limit: 2,
        })
    ));
    assert_eq!(counted.position(), 2);
    assert_eq!(counted.own().used(), 2);
    drop(counted);
    assert_eq!(log.borrow().delivered, 3);

    let built = ImageBuilder::new().build();
    let len = u64::try_from(built.bytes.len()).unwrap();
    let validated = run_with(&built, &limits(&[(LimitResource::ImageArchive, len)])).unwrap();
    assert_summary(&validated, &built);
    assert_fault(
        run_with(&built, &limits(&[(LimitResource::ImageArchive, len - 1)])),
        &limit(LimitResource::ImageArchive, len - 1),
    );
    // A limit below the probe itself.
    let mut short = ImageBuilder::new().build();
    short.bytes = vec![0x1f];
    assert_fault(
        run_with(&short, &limits(&[(LimitResource::ImageArchive, 0)])),
        &limit(LimitResource::ImageArchive, 0),
    );
    assert_fault(
        run_with(&short, &limits(&[(LimitResource::ImageArchive, 1)])),
        &tar_fault(TarFault::Truncated),
    );
}

#[test]
fn entry_order_never_changes_a_semantic_verdict() {
    let expected = reference(false, "extra:1", ReferenceSource::RepoTags);
    for order in 0..3 {
        let built = ImageBuilder::new()
            .json(Doc::Compat, |c| {
                c[0]["RepoTags"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("extra:1"));
            })
            .entries(move |entries, _| match order {
                0 => {}
                1 => entries.reverse(),
                _ => {
                    move_entry(entries, "oci-layout", 0);
                    move_entry(entries, "manifest.json", 3);
                }
            })
            .build();
        assert_fault(run(&built), &expected);
    }
}

#[test]
fn within_one_position_a_decode_fault_wins_over_the_diff_id() {
    let a = layer_tar("a", b"alpha");
    let b = layer_tar("b", b"bravo");
    let mut corrupt = gzip(&b);
    let len = corrupt.len();
    corrupt[len - 8] ^= 1;
    assert_fault(
        gzip_layer_fault(corrupt.clone(), &a),
        &gzip_fault(GzipFault::Crc32),
    );
    let built = ImageBuilder::new()
        .layers(vec![Layer::raw(gzip(&b), digest(&a), LAYER_GZIP)])
        .build();
    let decoded = u64::try_from(b.len()).unwrap();
    assert_fault(
        run_with(
            &built,
            &limits(&[(LimitResource::DecodedLayer, decoded - 1)]),
        ),
        &limit(LimitResource::DecodedLayer, decoded - 1),
    );
    let built = ImageBuilder::new()
        .layers(vec![Layer::raw(corrupt, digest(&b), LAYER_GZIP)])
        .json(Doc::Manifest, |m| {
            let size = m["layers"][0]["size"].as_u64().unwrap();
            m["layers"][0]["size"] = json!(size + 1);
        })
        .build();
    assert_fault(
        run(&built),
        &invalid(InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Layer { position: 0 },
            kind: BlobMismatchKind::Length,
        }),
    );
}

#[test]
fn no_later_position_is_read_after_a_verdict() {
    let a = layer_tar("a", b"alpha");
    let b = layer_tar("b", b"bravo");
    let mut corrupt = gzip(&b);
    corrupt[10] = 0x07;
    let built = ImageBuilder::new()
        .layers(vec![
            Layer::raw(gzip(&b), digest(&a), LAYER_GZIP),
            Layer::raw(corrupt, digest(&b), LAYER_GZIP),
        ])
        .build();
    seam::take();
    assert_fault(
        run(&built),
        &layer_mismatch(Some(0), LayerMismatchKind::DiffId, &digest(&a), &digest(&b)),
    );
    let events = seam::take();
    assert!(events_for(0, &events) > 0);
    assert_eq!(events_for(1, &events), 0);
    // The raw inventory read and hashed layer 1's blob, as it must.
    assert!(events.contains(&seam::Event::InventoryBlob(
        built.parts.layer_hexes[1].clone()
    )));

    // Positions reusing one blob: the verdict at position 1 stops position 2.
    let built = ImageBuilder::new()
        .layers(vec![
            Layer::plain(&a),
            Layer::raw(gzip(&b), digest(&a), LAYER_GZIP),
        ])
        .positions(&[0, 1, 0])
        .json(Doc::Config, move |c| {
            let da = c["rootfs"]["diff_ids"][0].clone();
            c["rootfs"]["diff_ids"] = json!([da.clone(), da.clone(), da]);
        })
        .build();
    seam::take();
    assert_fault(
        run(&built),
        &layer_mismatch(Some(1), LayerMismatchKind::DiffId, &digest(&a), &digest(&b)),
    );
    let events = seam::take();
    assert!(events_for(0, &events) > 0);
    assert!(events_for(1, &events) > 0);
    assert_eq!(events_for(2, &events), 0);
}

#[test]
fn config_profile_order() {
    let built = ImageBuilder::new()
        .json(Doc::Config, |c| {
            c["zzz-extra"] = json!({"any": "thing"});
            object(c).remove("rootfs");
        })
        .build();
    assert_fault(
        run(&built),
        &config_reason(InvalidConfigReason::MissingField {
            field: ConfigField::Rootfs,
        }),
    );
    let built = ImageBuilder::new()
        .json(Doc::Config, |c| {
            object(c).remove("architecture");
            c["rootfs"]["diff_ids"][0] = json!("bad");
        })
        .build();
    assert_fault(
        run(&built),
        &config_reason(InvalidConfigReason::MissingField {
            field: ConfigField::Architecture,
        }),
    );
    let built = ImageBuilder::new()
        .json(Doc::Config, |c| {
            c["variant"] = json!("");
            c["os"] = json!("windows");
        })
        .build();
    assert_fault(
        run(&built),
        &config_reason(InvalidConfigReason::EmptyVariant),
    );
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// Asserts `built` succeeds at `value` and exceeds `resource` at `value - 1`.
#[track_caller]
fn boundary(built: &Built, resource: LimitResource, value: u64) {
    let validated = run_with(built, &limits(&[(resource, value)]))
        .unwrap_or_else(|fault| panic!("{resource:?} refused at its limit {value}: {fault:?}"));
    assert_summary(&validated, built);
    assert_fault(
        run_with(built, &limits(&[(resource, value - 1)])),
        &limit(resource, value - 1),
    );
}

/// Asserts an inconsistent fixture reaches its exact semantic verdict at the
/// limit, but exceeds `resource` at `value - 1` before reaching that verdict.
#[track_caller]
fn boundary_refused(
    built: &Built,
    resource: LimitResource,
    value: u64,
    expected: &ImageArchiveFault,
) {
    assert_fault(run_with(built, &limits(&[(resource, value)])), expected);
    assert_fault(
        run_with(built, &limits(&[(resource, value - 1)])),
        &limit(resource, value - 1),
    );
}

fn len(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap()
}

#[test]
fn image_archive_limits() {
    let built = ImageBuilder::new().build();
    accept(&built);
    boundary(&built, LimitResource::ImageArchive, len(built.bytes.len()));
    // Two directories, three blobs and three layout files.
    boundary(&built, LimitResource::ImageEntries, 8);
    boundary(
        &built,
        LimitResource::ImagePathBytes,
        len("blobs/sha256/".len() + 64),
    );
}

#[test]
fn tag_limits_at_each_site() {
    let built = ImageBuilder::new().tags(&["a:1", "b:1", "c:1"]).build();
    accept(&built);
    // The index is read first.
    boundary(&built, LimitResource::TagsPerImage, 3);
    // RepoTags alone over the limit.
    let built = ImageBuilder::new()
        .tags(&["a:1"])
        .json(Doc::Compat, |c| {
            c[0]["RepoTags"] = json!(["a:1", "b:1", "c:1"]);
        })
        .build();
    boundary_refused(
        &built,
        LimitResource::TagsPerImage,
        3,
        &reference(false, "b:1", ReferenceSource::RepoTags),
    );
}

#[test]
fn layer_limits_at_each_site() {
    let layers = || {
        vec![
            Layer::plain(&layer_tar("a", b"a")),
            Layer::plain(&layer_tar("b", b"b")),
        ]
    };
    let built = ImageBuilder::new().layers(layers()).build();
    accept(&built);
    // `Layers` is read first.
    boundary(&built, LimitResource::LayersPerImage, 2);
    // Manifest `layers` alone over the limit.
    let built = ImageBuilder::new()
        .layers(layers())
        .json(Doc::Compat, |c| {
            c[0]["Layers"].as_array_mut().unwrap().pop();
        })
        .build();
    boundary_refused(
        &built,
        LimitResource::LayersPerImage,
        2,
        &invalid(InvalidArchiveReason::InconsistentCompatibility),
    );
    // `diff_ids` alone over the limit.
    let built = ImageBuilder::new()
        .layers(layers())
        .positions(&[0])
        .json(Doc::Config, |c| {
            c["rootfs"]["diff_ids"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("sha256:{FAKE_HEX}")));
            c["history"].as_array_mut().unwrap().push(json!({}));
        })
        .build();
    boundary_refused(
        &built,
        LimitResource::LayersPerImage,
        2,
        &layer_mismatch(None, LayerMismatchKind::CountMismatch, "2", "1"),
    );
}

#[test]
fn json_document_limits() {
    let built = ImageBuilder::new().build();
    let validated = accept(&built);
    let size = |name: &str| {
        validated
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .unwrap()
            .data_len
    };
    boundary(&built, LimitResource::OciLayout, size("oci-layout"));
    boundary(&built, LimitResource::IndexJson, size("index.json"));
    boundary(
        &built,
        LimitResource::CompatibilityJson,
        size("manifest.json"),
    );
    let manifest = size(&blob_name(&built.parts.manifest_hex));
    boundary(&built, LimitResource::ImageManifestJson, manifest);
    let config = size(&blob_name(&built.parts.config_hex));
    boundary(&built, LimitResource::ConfigJson, config);
    let total = size("oci-layout") + size("index.json") + size("manifest.json") + manifest + config;
    boundary(&built, LimitResource::ImageJsonTotal, total);
    // The index is the deepest document: object, array, object, object.
    boundary(&built, LimitResource::JsonDepth, 4);
}

#[test]
fn stored_and_decoded_layer_limits() {
    let a = layer_tar("a", &[7; 3000]);
    let b = layer_tar("b", &[9; 1000]);
    let (la, lb) = (Layer::gzip(&a), Layer::gzip(&b));
    let stored = len(la.blob.len().max(lb.blob.len()));
    let built = ImageBuilder::new().layers(vec![la, lb]).build();
    accept(&built);
    boundary(&built, LimitResource::StoredLayerBlob, stored);
    // Both members have the plain ten-byte header.
    boundary(&built, LimitResource::GzipHeader, 10);
    boundary(&built, LimitResource::DecodedLayer, len(a.len()));
    boundary(
        &built,
        LimitResource::DecodedLayersPerImage,
        len(a.len() + b.len()),
    );
    boundary(
        &built,
        LimitResource::DecodedLayersPerOperation,
        len(a.len() + b.len()),
    );
}

#[test]
fn the_operation_budget_is_shared_across_images() {
    let tar = layer_tar("a", b"alpha");
    let built = ImageBuilder::new().layers(vec![Layer::gzip(&tar)]).build();
    let limits = ContentLimits::default();
    let mut operation = Budget::new(crate::content::ResourceLimit {
        resource: LimitResource::DecodedLayersPerOperation,
        max: len(tar.len() * 2),
    });
    for _ in 0..2 {
        let validated = validate_image_archive(
            Cursor::new(built.bytes.as_slice()),
            &built.declaration,
            PATH,
            &limits,
            &mut operation,
        )
        .unwrap();
        assert_summary(&validated, &built);
    }
    assert_fault(
        validate_image_archive(
            Cursor::new(built.bytes.as_slice()),
            &built.declaration,
            PATH,
            &limits,
            &mut operation,
        ),
        &limit(LimitResource::DecodedLayersPerOperation, len(tar.len() * 2)),
    );
}

#[test]
fn layer_entry_and_extension_limits() {
    let target = "t".repeat(40);
    let payload_a = pax(&[("path", b"pax/one"), ("mtime", b"1")]);
    let payload_b = pax(&[("path", b"pax/two/longer"), ("uid", b"0")]);
    let first = Tar::new()
        .file("dir/a-long-file-name", b"x")
        .entry(
            Header::new(b'2', b"link", 0).linkname(target.as_bytes()),
            &[],
        )
        .extension(b'x', &payload_a)
        .file("x", b"x")
        .finish();
    let second = Tar::new()
        .extension(b'x', &payload_b)
        .file("y", b"y")
        .finish();
    let built = ImageBuilder::new()
        .layers(vec![Layer::gzip(&first), Layer::plain(&second)])
        .build();
    accept(&built);
    // Four headers in the first layer and two in the second.
    boundary(&built, LimitResource::LayerEntries, 6);
    boundary(
        &built,
        LimitResource::LayerPathBytes,
        len("dir/a-long-file-name".len()),
    );
    boundary(
        &built,
        LimitResource::LayerLinkTargetBytes,
        len(target.len()),
    );
    let largest = payload_a.len().max(payload_b.len());
    boundary(&built, LimitResource::LayerExtension, len(largest));
    boundary(
        &built,
        LimitResource::LayerExtensionTotal,
        len(payload_a.len() + payload_b.len()),
    );
}

#[test]
fn a_size_of_u64_max_is_refused_without_overflow() {
    let built = ImageBuilder::new()
        .json(Doc::Manifest, |m| m["layers"][0]["size"] = json!(u64::MAX))
        .build();
    assert_fault(
        run(&built),
        &limit(
            LimitResource::StoredLayerBlob,
            LimitResource::StoredLayerBlob.default_limit(),
        ),
    );
    let built = ImageBuilder::new()
        .json(Doc::Index, |i| i["manifests"][0]["size"] = json!(u64::MAX))
        .build();
    assert_fault(
        run(&built),
        &limit(
            LimitResource::ImageManifestJson,
            LimitResource::ImageManifestJson.default_limit(),
        ),
    );
}

#[test]
fn a_high_ratio_layer_is_refused_under_each_decoded_budget() {
    let tar = layer_tar("zeros", &vec![0; 4 << 20]);
    let layer = Layer::gzip(&tar);
    assert!(layer.blob.len() * 100 < tar.len());
    let built = ImageBuilder::new().layers(vec![layer]).build();
    for resource in [
        LimitResource::DecodedLayer,
        LimitResource::DecodedLayersPerImage,
        LimitResource::DecodedLayersPerOperation,
    ] {
        assert_fault(
            run_with(&built, &limits(&[(resource, 1 << 20)])),
            &limit(resource, 1 << 20),
        );
    }
}

#[test]
fn source_failures() {
    let built = ImageBuilder::new().build();
    let (source, _) = Source::new(built.bytes.clone());
    assert_fault(
        run_on(
            source.fail_at(700, ErrorKind::ConnectionReset),
            &built,
            &ContentLimits::default(),
        ),
        &ImageArchiveFault::Io(ErrorKind::ConnectionReset.into()),
    );
    // A document range the inventory recorded ends early on re-reading.
    let (source, _) = Source::new(built.bytes.clone());
    assert_fault(
        run_on(source.shrink_after(2, 0), &built, &ContentLimits::default()),
        &ImageArchiveFault::Io(ErrorKind::UnexpectedEof.into()),
    );
    // So does a layer range: one seek for the inventory, five for the
    // documents, and the seventh opens the layer.
    let layer_offset = accept(&built)
        .entries
        .iter()
        .find(|entry| entry.name == blob_name(&built.parts.layer_hexes[0]))
        .unwrap()
        .data_offset;
    let (source, _) = Source::new(built.bytes.clone());
    assert_fault(
        run_on(
            source.shrink_after(7, layer_offset + 5),
            &built,
            &ContentLimits::default(),
        ),
        &ImageArchiveFault::Io(ErrorKind::UnexpectedEof.into()),
    );
}

// ---------------------------------------------------------------------------
// Fault conversion
// ---------------------------------------------------------------------------

fn converted(fault: ContentFault, site: Site) -> String {
    format!("{:?}", convert(fault, site))
}

fn malformed(reason: MalformedReason) -> ContentFault {
    ContentFault::Malformed(reason)
}

#[test]
// The whole conversion table, site by site, in one place.
#[allow(clippy::too_many_lines)]
fn every_primitive_fault_converts_by_its_table() {
    let image_walk = Site::ImageWalk;
    let walker = Site::LayerWalk {
        position: 3,
        decoder: false,
    };
    let decoder = Site::LayerWalk {
        position: 3,
        decoder: true,
    };
    let document = Site::Document(ImageDocument::Config);
    let impossible = format!("{:?}", super::impossible());

    // Limits and I/O are the same wherever they come from.
    for site in [image_walk, walker, decoder, document] {
        assert_eq!(
            converted(
                ContentFault::LimitExceeded {
                    resource: LimitResource::DecodedLayer,
                    limit: 9
                },
                site
            ),
            format!(
                "{:?}",
                Verdict::Limit {
                    resource: LimitResource::DecodedLayer,
                    limit: 9
                }
            )
        );
        assert!(matches!(
            convert(ContentFault::Io(ErrorKind::BrokenPipe.into()), site),
            Verdict::Io(err) if err.kind() == ErrorKind::BrokenPipe
        ));
    }

    let tar_reasons = [
        (MalformedReason::Truncated, TarFault::Truncated),
        (MalformedReason::TarChecksum, TarFault::Checksum),
        (
            MalformedReason::TarNumericField {
                field: TarField::DevMinor,
            },
            TarFault::NumericField {
                field: TarHeaderField::DevMinor,
            },
        ),
        (
            MalformedReason::TarNameField {
                field: TarField::Prefix,
            },
            TarFault::NameField {
                field: TarHeaderField::Prefix,
            },
        ),
        (MalformedReason::OffsetOverflow, TarFault::OffsetOverflow),
        (MalformedReason::TrailingData, TarFault::TrailingData),
        (MalformedReason::ZeroTailTooLong, TarFault::ZeroTailTooLong),
        (MalformedReason::UnsafePath, TarFault::UnsafePath),
        (MalformedReason::DuplicatePath, TarFault::DuplicatePath),
        (MalformedReason::PathConflict, TarFault::PathConflict),
        (
            MalformedReason::NonRegularWithData,
            TarFault::NonRegularWithData,
        ),
    ];
    for (reason, fault) in tar_reasons {
        assert_eq!(
            converted(malformed(reason), image_walk),
            format!(
                "{:?}",
                Verdict::Invalid(InvalidArchiveReason::Tar { fault })
            )
        );
        assert_eq!(
            converted(malformed(reason), walker),
            format!(
                "{:?}",
                Verdict::Invalid(InvalidArchiveReason::LayerTar { position: 3, fault })
            )
        );
        assert_eq!(converted(malformed(reason), document), impossible);
    }
    let extension_reasons = [
        (MalformedReason::PaxRecord, TarFault::PaxRecord),
        (MalformedReason::PaxDuplicateKey, TarFault::PaxDuplicateKey),
        (
            MalformedReason::PaxValue {
                key: ContentPaxKey::Xattr,
            },
            TarFault::PaxValue { key: PaxKey::Xattr },
        ),
        (
            MalformedReason::ExtensionPayload,
            TarFault::ExtensionPayload,
        ),
        (
            MalformedReason::DuplicateExtension,
            TarFault::DuplicateExtension,
        ),
        (
            MalformedReason::ConflictingAuthority,
            TarFault::ConflictingAuthority,
        ),
        (
            MalformedReason::DanglingExtension,
            TarFault::DanglingExtension,
        ),
        (MalformedReason::LinkOnNonLink, TarFault::LinkOnNonLink),
    ];
    for (reason, fault) in extension_reasons {
        assert_eq!(
            converted(malformed(reason), walker),
            format!(
                "{:?}",
                Verdict::Invalid(InvalidArchiveReason::LayerTar { position: 3, fault })
            )
        );
        assert_eq!(converted(malformed(reason), image_walk), impossible);
        assert_eq!(converted(malformed(reason), decoder), impossible);
    }
    let gzip_reasons = [
        (
            MalformedReason::GzipHeader(ContentGzipHeader::Magic),
            GzipFault::Header {
                fault: GzipHeaderFault::Magic,
            },
        ),
        (
            MalformedReason::GzipHeader(ContentGzipHeader::Method),
            GzipFault::Header {
                fault: GzipHeaderFault::Method,
            },
        ),
        (
            MalformedReason::GzipHeader(ContentGzipHeader::ReservedFlags),
            GzipFault::Header {
                fault: GzipHeaderFault::ReservedFlags,
            },
        ),
        (
            MalformedReason::GzipHeader(ContentGzipHeader::HeaderCrc),
            GzipFault::Header {
                fault: GzipHeaderFault::HeaderCrc,
            },
        ),
        (MalformedReason::DeflateData, GzipFault::Deflate),
        (MalformedReason::GzipCrc32, GzipFault::Crc32),
        (MalformedReason::GzipIsize, GzipFault::Isize),
        (MalformedReason::GzipTrailingData, GzipFault::TrailingData),
        (MalformedReason::Truncated, GzipFault::Truncated),
    ];
    for (reason, fault) in gzip_reasons {
        assert_eq!(
            converted(malformed(reason), decoder),
            format!(
                "{:?}",
                Verdict::Invalid(InvalidArchiveReason::Gzip { position: 3, fault })
            )
        );
        if reason != MalformedReason::Truncated {
            assert_eq!(converted(malformed(reason), walker), impossible);
            assert_eq!(converted(malformed(reason), image_walk), impossible);
        }
    }
    for (reason, fault) in [
        (MalformedReason::JsonSyntax, JsonFault::Syntax),
        (MalformedReason::JsonDuplicateKey, JsonFault::DuplicateKey),
    ] {
        assert_eq!(
            converted(malformed(reason), document),
            format!(
                "{:?}",
                Verdict::Invalid(InvalidArchiveReason::Json {
                    document: ImageDocument::Config,
                    fault
                })
            )
        );
        assert_eq!(converted(malformed(reason), image_walk), impossible);
        assert_eq!(converted(malformed(reason), walker), impossible);
    }
    assert_eq!(
        converted(malformed(MalformedReason::JsonShape), document),
        format!(
            "{:?}",
            Verdict::Invalid(InvalidArchiveReason::UnexpectedShape {
                document: ImageDocument::Config
            })
        )
    );
    assert_eq!(
        converted(malformed(MalformedReason::JsonShape), decoder),
        impossible
    );

    for (feature, expected) in [
        (UnsupportedFeature::TarFormat, TarFeature::Format),
        (
            UnsupportedFeature::EntryType { flag: b'S' },
            TarFeature::EntryType { flag: b'S' },
        ),
        (UnsupportedFeature::PaxKey, TarFeature::PaxKey),
    ] {
        assert_eq!(
            converted(ContentFault::Unsupported(feature), image_walk),
            format!(
                "{:?}",
                Verdict::Unsupported(UnsupportedArchiveFeature::ArchiveTar { feature: expected })
            )
        );
        assert_eq!(
            converted(ContentFault::Unsupported(feature), walker),
            format!(
                "{:?}",
                Verdict::Unsupported(UnsupportedArchiveFeature::LayerTar {
                    position: 3,
                    feature: expected
                })
            )
        );
        assert_eq!(
            converted(ContentFault::Unsupported(feature), document),
            impossible
        );
    }
    let concatenated = ContentFault::Unsupported(UnsupportedFeature::ConcatenatedGzipMember);
    assert_eq!(
        converted(concatenated, decoder),
        format!(
            "{:?}",
            Verdict::Unsupported(UnsupportedArchiveFeature::ConcatenatedGzipMember { position: 3 })
        )
    );
    let concatenated = ContentFault::Unsupported(UnsupportedFeature::ConcatenatedGzipMember);
    assert_eq!(converted(concatenated, walker), impossible);
    // An impossible reason is an `Other` source failure, never a panic.
    assert!(matches!(
        super::impossible(),
        Verdict::Io(err) if err.kind() == ErrorKind::Other
    ));
}

// ---------------------------------------------------------------------------
// Messages and the checked-in fixture
// ---------------------------------------------------------------------------

#[test]
fn reason_enums_display_fixed_lowercase_phrases() {
    let rendered = [
        UnsupportedArchiveFeature::LayerTar {
            position: 4,
            feature: TarFeature::EntryType { flag: b'S' },
        }
        .to_string(),
        UnsupportedArchiveFeature::ExtensionField {
            document: ImageDocument::CompatibilityManifest,
            field: ExtensionField::Urls,
        }
        .to_string(),
        InvalidArchiveReason::Gzip {
            position: 2,
            fault: GzipFault::Header {
                fault: GzipHeaderFault::HeaderCrc,
            },
        }
        .to_string(),
        InvalidArchiveReason::LayerTar {
            position: 7,
            fault: TarFault::NumericField {
                field: TarHeaderField::DevMajor,
            },
        }
        .to_string(),
        InvalidArchiveReason::InvalidConfig {
            reason: InvalidConfigReason::HistoryEntryShape { index: 5 },
        }
        .to_string(),
        InvalidArchiveReason::EmptyPlatformVariant {
            location: PlatformLocation::IndexDescriptor { index: 6 },
        }
        .to_string(),
        InvalidArchiveReason::BlobMismatch {
            role: BlobRole::Layer { position: 8 },
            kind: BlobMismatchKind::Length,
        }
        .to_string(),
    ];
    for text in &rendered {
        assert_eq!(*text, text.to_lowercase());
    }
    assert!(rendered[0].contains("layer 4") && rendered[0].contains("0x53"));
    assert!(rendered[1].contains("urls"));
    assert!(rendered[2].contains("layer 2") && rendered[2].contains("header crc"));
    assert!(rendered[3].contains("layer 7") && rendered[3].contains("devmajor"));
    assert!(rendered[4].contains("history entry 5"));
    assert!(rendered[5].contains("index descriptor 6"));
    assert!(rendered[6].contains("layer 8") && rendered[6].contains("length"));
    let error = ImageVerifyError::LayerMismatch {
        archive_path: PATH.to_string(),
        position: Some(1),
        kind: LayerMismatchKind::DiffId,
        expected: Some("sha256:aa".to_string()),
        actual: Some("sha256:bb".to_string()),
    };
    let message = error.to_string();
    assert!(message.contains("diff id") && message.contains("layer 1"));
    assert!(message.contains("sha256:aa") && message.contains("sha256:bb"));
}

#[test]
fn the_checked_in_placeholder_image_is_refused() {
    const PACKAGE: &[u8] =
        include_bytes!("../../../assets/test-fixtures/signed-v6-images/package.pkg");
    let mut payload = crate::payload::open_package(Cursor::new(PACKAGE)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let extracted = payload.extract_to(dir.path()).unwrap();
    let images: Vec<_> = extracted
        .iter()
        .filter_map(|artifact| {
            artifact
                .artifact
                .image
                .as_ref()
                .map(|declaration| (artifact, declaration))
        })
        .collect();
    assert_eq!(images.len(), 2);
    for (artifact, declaration) in images {
        let file = std::fs::File::open(&artifact.path).unwrap();
        let limits = ContentLimits::default();
        let mut operation =
            Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
        let result = validate_image_archive(
            file,
            declaration,
            &artifact.artifact.archive_path,
            &limits,
            &mut operation,
        );
        let expected = ImageArchiveFault::Image(ImageVerifyError::InvalidArchive {
            archive_path: artifact.artifact.archive_path.clone(),
            reason: InvalidArchiveReason::Tar {
                fault: TarFault::Truncated,
            },
        });
        assert_fault(result, &expected);
    }
}

// ---------------------------------------------------------------------------
// Bounded memory
// ---------------------------------------------------------------------------

/// Streams a tar holding one `decoded`-byte file through a gzip encoder into
/// `file`, returning the tar's digest. No buffer is the size of the layer.
fn stream_large_layer(file: &mut std::fs::File, decoded: u64) -> String {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut write = |bytes: &[u8]| {
        sha2::Digest::update(&mut hasher, bytes);
        encoder.write_all(bytes).unwrap();
    };
    write(&Header::new(b'0', b"big.bin", decoded).build());
    let mut block = [0u8; 4096];
    for (i, byte) in block.iter_mut().enumerate() {
        *byte = u8::try_from((i * 7 + i / 13) % 251).unwrap();
    }
    let mut left = decoded;
    while left > 0 {
        let n = usize::try_from(left.min(4096)).unwrap();
        write(&block[..n]);
        left -= len(n);
    }
    write(&[0; 1024]);
    encoder.finish().unwrap();
    format!(
        "sha256:{}",
        crate::payload::to_hex(&sha2::Digest::finalize(hasher))
    )
}

#[test]
fn a_large_layer_validates_from_a_file_within_bounded_buffers() {
    const DECODED: u64 = 64 << 20;
    let dir = tempfile::tempdir().unwrap();
    let blob_path = dir.path().join("layer.gz");
    let mut blob_file = std::fs::File::create(&blob_path).unwrap();
    let diff_id = stream_large_layer(&mut blob_file, DECODED);
    drop(blob_file);
    // The compressed blob is small enough to assemble in memory; the decoded
    // stream never exists anywhere but in the validator's bounded buffers.
    let blob = std::fs::read(&blob_path).unwrap();
    let blob_size = len(blob.len());
    let built = ImageBuilder::new()
        .layers(vec![Layer::raw(blob, diff_id, LAYER_GZIP)])
        .build();
    let archive_path = dir.path().join("image.tar");
    std::fs::write(&archive_path, &built.bytes).unwrap();

    let limits = ContentLimits::default();
    let copy_buffer = limits.copy_buffer_len();
    let mut operation =
        Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
    seam::take();
    let started = std::time::Instant::now();
    let validated = validate_image_archive(
        std::fs::File::open(&archive_path).unwrap(),
        &built.declaration,
        PATH,
        &limits,
        &mut operation,
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert_summary(&validated, &built);
    assert_eq!(validated.layer_count, 1);
    assert!(operation.used() >= DECODED);
    let events = seam::take();
    // The only buffer the validator sizes itself is one copy buffer, and every
    // stored read stays within it.
    for event in &events {
        match event {
            seam::Event::Buffer(size) => assert!(*size <= copy_buffer),
            seam::Event::LayerRead { bytes, .. } => assert!(*bytes <= copy_buffer),
            _ => {}
        }
    }
    let stored: usize = events
        .iter()
        .filter_map(|event| match event {
            seam::Event::LayerRead { bytes, .. } => Some(*bytes),
            _ => None,
        })
        .sum();
    assert_eq!(len(stored), blob_size);
    assert!(elapsed.as_secs() < 600, "took {elapsed:?}");
}

#[test]
fn limits_hold_on_the_bytes_actually_read() {
    // The image tar: never more than one probe byte past the limit.
    let built = ImageBuilder::new().build();
    let total = len(built.bytes.len());
    for allowance in [0, 3, 511, 512, 1500, total - 1] {
        let (source, log) = Source::new(built.bytes.clone());
        assert_fault(
            run_on(
                source,
                &built,
                &limits(&[(LimitResource::ImageArchive, allowance)]),
            ),
            &limit(LimitResource::ImageArchive, allowance),
        );
        assert!(log.borrow().delivered <= allowance + 1);
    }

    // Decoded bytes: nothing past a decoded budget is ever charged, and a
    // repeated position is charged again.
    let tar = layer_tar("a", &[5; 4000]);
    let built = ImageBuilder::new()
        .layers(vec![Layer::gzip(&tar)])
        .positions(&[0, 0])
        .build();
    let decoded = len(tar.len());
    for (resource, allowance) in [
        (LimitResource::DecodedLayer, decoded - 1),
        (LimitResource::DecodedLayersPerImage, 2 * decoded - 1),
        (LimitResource::DecodedLayersPerOperation, 2 * decoded - 1),
    ] {
        let limits = limits(&[(resource, allowance)]);
        let mut operation =
            Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
        assert_fault(
            validate_image_archive(
                Cursor::new(built.bytes.as_slice()),
                &built.declaration,
                PATH,
                &limits,
                &mut operation,
            ),
            &limit(resource, allowance),
        );
        assert!(operation.used() <= allowance);
    }

    // Stored bytes: a phase-7 read never goes past the recorded blob.
    seam::take();
    accept(&built);
    let stored: usize = seam::take()
        .iter()
        .filter_map(|event| match event {
            seam::Event::LayerRead { bytes, .. } => Some(*bytes),
            _ => None,
        })
        .sum();
    let blob = gzip(&tar);
    assert_eq!(stored, 2 * blob.len());
}
