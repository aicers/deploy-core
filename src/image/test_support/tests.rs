use std::io::{Cursor, Read};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::raw::{self, RawEntry};
use super::seam::{self, GzipReplacement};
use super::*;
use crate::content::{CountingReader, EntryPolicy, TarEntry, TarWalker};
use crate::verify::{BlobMismatchKind, BlobRole, InvalidArchiveReason, LayoutFile};

const KIB: u64 = 1024;
/// A 512-byte header plus under 512 bytes of padding: what one tar entry
/// adds beyond its data, at most.
const ENTRY_OVERHEAD: u64 = 1024;
/// The two-block end-of-archive marker.
const END_MARKER: u64 = 1024;
/// Entries of the image-level tar beyond the layer blobs: `oci-layout`,
/// `index.json`, `manifest.json`, the image manifest and the config.
const FIXED_IMAGE_ENTRIES: u64 = 5;

/// Per-item JSON allowances of Scope §2, in bytes.
const INDEX_PER_REF: u64 = 128 + 320;
const INDEX_FIXED: u64 = 128;
const COMPAT_PER_REF: u64 = 4;
const COMPAT_PER_LAYER: u64 = 80;
const COMPAT_FIXED: u64 = 128;
const MANIFEST_PER_LAYER: u64 = 180;
const MANIFEST_FIXED: u64 = 320;
const CONFIG_PER_DIFF_ID: u64 = 74;
const CONFIG_PER_HISTORY: u64 = 64;
const CONFIG_FIXED: u64 = 256;
const OCI_LAYOUT_BOUND: u64 = 30;
const JSON_DEPTH_BOUND: u64 = 5;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/test-fixtures/images");

fn default_limit(resource: LimitResource) -> u64 {
    ContentLimits::default().get(resource)
}

fn u(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

fn amd64() -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::Amd64,
        variant: None,
    }
}

fn arm64(variant: &str) -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture: ImageArchitecture::Arm64,
        variant: Some(variant.to_string()),
    }
}

fn refs(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn hello() -> SyntheticLayer {
    SyntheticLayer::new().file("hello.txt", "hello")
}

/// Classifies `archive` against a declaration built from its own values.
fn classify(
    archive: &SyntheticImageArchive,
    public_refs: &[String],
) -> Result<(), ArchiveCheckError> {
    let declaration = raw::builder_declaration(archive, public_refs.to_vec());
    check_image_archive(Cursor::new(archive.bytes()), "images/app.tar", &declaration)
}

/// The inventory encoding of a classifier verdict.
fn verdict_of(result: Result<(), ArchiveCheckError>) -> Value {
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

/// A 64-byte variant token.
fn long_variant() -> String {
    "v".repeat(MAX_VARIANT_BYTES)
}

/// Returns 256 distinct references of exactly [`MAX_SYNTHETIC_REF_BYTES`]
/// bytes, each with a 128-byte tag.
fn longest_refs() -> Vec<String> {
    (0..MAX_SYNTHETIC_REFS)
        .map(|at| {
            let tag = format!("t{at:03}{}", "x".repeat(124));
            let tail = format!(".example/app:{tag}");
            let head = format!("r{at:03}");
            let pad = MAX_SYNTHETIC_REF_BYTES - tail.len() - head.len();
            let reference = format!("{head}{}{tail}", "a".repeat(pad));
            assert_eq!(reference.len(), MAX_SYNTHETIC_REF_BYTES);
            reference
        })
        .collect()
}

/// Returns the entries of an image tar, walked with the image-archive policy,
/// with each entry's data.
fn image_entries(archive: &[u8]) -> Vec<(TarEntry, Vec<u8>)> {
    let limits = ContentLimits::default();
    let counted = CountingReader::new(
        archive,
        limits.resource_limit(LimitResource::ImageArchive),
        Vec::new(),
        limits.copy_buffer_len(),
    );
    let mut walker = TarWalker::new(counted, EntryPolicy::ImageArchive, &limits);
    let mut entries = Vec::new();
    while let Some(entry) = walker.next_entry().unwrap() {
        let mut data = Vec::new();
        walker.entry_reader().read_to_end(&mut data).unwrap();
        entries.push((entry, data));
    }
    entries
}

/// Returns the entries of a layer tar, walked with the layer policy.
fn layer_entries(tar: &[u8]) -> Vec<TarEntry> {
    let limits = ContentLimits::default();
    let mut entries_budget = Budget::new(limits.resource_limit(LimitResource::LayerEntries));
    let mut extension_budget =
        Budget::new(limits.resource_limit(LimitResource::LayerExtensionTotal));
    let counted = CountingReader::new(
        tar,
        limits.resource_limit(LimitResource::DecodedLayer),
        Vec::new(),
        limits.copy_buffer_len(),
    );
    let mut walker = TarWalker::new(
        counted,
        EntryPolicy::Layer {
            entries: &mut entries_budget,
            extension_total: &mut extension_budget,
        },
        &limits,
    );
    let mut entries = Vec::new();
    while let Some(entry) = walker.next_entry().unwrap() {
        entries.push(entry);
    }
    entries
}

fn json_depth(value: &Value) -> u64 {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn padded(len: u64) -> u64 {
    len.next_multiple_of(512)
}

// ---------------------------------------------------------------------------
// Static bounds proof
// ---------------------------------------------------------------------------

/// Evaluates Scope §2's conservative size bounds from the public constants
/// and holds each to the default limit it must stay within.
#[test]
// One figure after another, in the order the bounds build on each other;
// splitting them would only pass the intermediate figures around.
#[allow(clippy::too_many_lines)]
fn the_synthetic_bounds_imply_every_default_limit() {
    let layers = u(MAX_SYNTHETIC_LAYERS);
    let refs = u(MAX_SYNTHETIC_REFS);

    // Counts.
    assert!(layers <= default_limit(LimitResource::LayersPerImage));
    let image_entries = FIXED_IMAGE_ENTRIES.checked_add(layers).unwrap();
    assert_eq!(image_entries, 261);
    assert!(image_entries <= default_limit(LimitResource::ImageEntries));
    assert!(u(MAX_SYNTHETIC_TOTAL_ENTRIES) <= default_limit(LimitResource::LayerEntries));
    assert!(
        refs <= default_limit(LimitResource::TagsPerImage),
        "repo tags"
    );
    assert!(
        refs <= default_limit(LimitResource::TagsPerImage),
        "index descriptors"
    );

    // Paths and links: a directory's written name adds one `/`, and every
    // image-level name is a 77-byte blob path at most.
    let directory_name = u(MAX_SYNTHETIC_PATH_BYTES).checked_add(1).unwrap();
    assert!(directory_name <= default_limit(LimitResource::LayerPathBytes));
    assert!(
        u(USTAR_PREFIX_BYTES + 1 + USTAR_NAME_BYTES) >= directory_name,
        "every written name of an accepted path has room for a split"
    );
    assert!(u(MAX_SYNTHETIC_LINK_BYTES) <= default_limit(LimitResource::LayerLinkTargetBytes));
    // The ustar linkname field.
    const { assert!(MAX_SYNTHETIC_LINK_BYTES <= USTAR_NAME_BYTES) };
    let blob_name = u(BLOB_PREFIX.len() + 64);
    assert!(blob_name <= default_limit(LimitResource::ImagePathBytes));

    // One layer, decoded and stored under the enforced gzip ceiling.
    let decoded_layer = MAX_SYNTHETIC_LAYER_BYTES
        .checked_add(
            ENTRY_OVERHEAD
                .checked_mul(u(MAX_SYNTHETIC_ENTRIES_PER_LAYER))
                .unwrap(),
        )
        .and_then(|sum| sum.checked_add(END_MARKER))
        .unwrap();
    assert_eq!(decoded_layer, 256 * 1024 * KIB + 4 * 1024 * KIB + KIB);
    assert!(decoded_layer <= default_limit(LimitResource::DecodedLayer));
    let stored_layer = decoded_layer
        .checked_add(decoded_layer / GZIP_CEILING_DIVISOR)
        .and_then(|sum| sum.checked_add(GZIP_CEILING_SLACK))
        .unwrap();
    assert_eq!(
        stored_layer,
        gzip_ceiling(decoded_layer),
        "the enforced ceiling"
    );
    assert!(stored_layer <= default_limit(LimitResource::StoredLayerBlob));

    // Every position, decoded.
    let decoded_total = MAX_SYNTHETIC_IMAGE_BYTES
        .checked_add(
            ENTRY_OVERHEAD
                .checked_mul(u(MAX_SYNTHETIC_TOTAL_ENTRIES))
                .unwrap(),
        )
        .and_then(|sum| sum.checked_add(END_MARKER.checked_mul(layers).unwrap()))
        .unwrap();
    assert_eq!(
        decoded_total,
        1024 * 1024 * KIB + 64 * 1024 * KIB + 256 * KIB
    );
    assert!(decoded_total <= default_limit(LimitResource::DecodedLayersPerImage));
    assert!(decoded_total <= default_limit(LimitResource::DecodedLayersPerOperation));
    // The unique blobs are a subset of the positions, so their stored sizes
    // sum to at most the ceiling of the decoded total plus one slack each.
    let stored_total = decoded_total
        .checked_add(decoded_total / GZIP_CEILING_DIVISOR)
        .and_then(|sum| sum.checked_add(GZIP_CEILING_SLACK.checked_mul(layers).unwrap()))
        .unwrap();

    // JSON documents.
    let ref_bytes = u(MAX_SYNTHETIC_REF_BYTES);
    let index = refs
        .checked_mul(ref_bytes + INDEX_PER_REF)
        .and_then(|sum| sum.checked_add(INDEX_FIXED))
        .unwrap();
    assert!(index <= default_limit(LimitResource::IndexJson));
    let compatibility = refs
        .checked_mul(ref_bytes + COMPAT_PER_REF)
        .and_then(|sum| sum.checked_add(layers.checked_mul(COMPAT_PER_LAYER)?))
        .and_then(|sum| sum.checked_add(COMPAT_FIXED))
        .unwrap();
    assert!(compatibility <= default_limit(LimitResource::CompatibilityJson));
    let manifest = layers
        .checked_mul(MANIFEST_PER_LAYER)
        .and_then(|sum| sum.checked_add(MANIFEST_FIXED))
        .unwrap();
    assert!(manifest <= default_limit(LimitResource::ImageManifestJson));
    // The fixed 256 covers `architecture`, `os`, a 64-byte variant, `rootfs`
    // and the punctuation.
    assert_eq!(MAX_VARIANT_BYTES, 64);
    let config = layers
        .checked_mul(CONFIG_PER_DIFF_ID + CONFIG_PER_HISTORY)
        .and_then(|sum| sum.checked_add(CONFIG_FIXED))
        .unwrap();
    assert!(config <= default_limit(LimitResource::ConfigJson));
    assert!(OCI_LAYOUT_BOUND <= default_limit(LimitResource::OciLayout));
    let json_total = [index, compatibility, manifest, config, OCI_LAYOUT_BOUND]
        .into_iter()
        .try_fold(0u64, u64::checked_add)
        .unwrap();
    assert!(json_total <= default_limit(LimitResource::ImageJsonTotal));
    assert!(JSON_DEPTH_BOUND <= default_limit(LimitResource::JsonDepth));

    // The whole image archive.
    let archive = image_entries
        .checked_mul(ENTRY_OVERHEAD)
        .and_then(|sum| sum.checked_add(END_MARKER))
        .and_then(|sum| sum.checked_add(json_total))
        .and_then(|sum| sum.checked_add(stored_total))
        .unwrap();
    assert!(archive <= default_limit(LimitResource::ImageArchive));
}

#[test]
fn the_default_bounds_are_the_public_constants() {
    let bounds = SyntheticBounds::default();
    assert_eq!(bounds.layers, MAX_SYNTHETIC_LAYERS);
    assert_eq!(bounds.entries_per_layer, MAX_SYNTHETIC_ENTRIES_PER_LAYER);
    assert_eq!(bounds.total_entries, MAX_SYNTHETIC_TOTAL_ENTRIES);
    assert_eq!(bounds.layer_bytes, MAX_SYNTHETIC_LAYER_BYTES);
    assert_eq!(bounds.image_bytes, MAX_SYNTHETIC_IMAGE_BYTES);
    assert_eq!(bounds.path_bytes, MAX_SYNTHETIC_PATH_BYTES);
    assert_eq!(bounds.link_bytes, MAX_SYNTHETIC_LINK_BYTES);
    assert_eq!(bounds.refs, MAX_SYNTHETIC_REFS);
    assert_eq!(bounds.ref_bytes, MAX_SYNTHETIC_REF_BYTES);
    assert_eq!(MAX_SYNTHETIC_LAYERS, 256);
    assert_eq!(MAX_SYNTHETIC_ENTRIES_PER_LAYER, 4096);
    assert_eq!(MAX_SYNTHETIC_TOTAL_ENTRIES, 65_536);
    assert_eq!(MAX_SYNTHETIC_LAYER_BYTES, 256 * 1024 * KIB);
    assert_eq!(MAX_SYNTHETIC_IMAGE_BYTES, 1024 * 1024 * KIB);
    assert_eq!(MAX_SYNTHETIC_PATH_BYTES, 255);
    assert_eq!(MAX_SYNTHETIC_LINK_BYTES, 100);
    assert_eq!(MAX_SYNTHETIC_REFS, 256);
    assert_eq!(MAX_SYNTHETIC_REF_BYTES, 512);
}

// ---------------------------------------------------------------------------
// Gzip
// ---------------------------------------------------------------------------

fn assert_unchanged(builder: &SyntheticImageArchiveBuilder) {
    assert!(builder.positions.is_empty());
    assert!(builder.blobs.is_empty());
    assert_eq!(builder.total_entries, 0);
    assert_eq!(builder.total_bytes, 0);
}

#[test]
fn a_gzip_blob_over_its_ceiling_is_refused_and_discarded() {
    let mut builder = SyntheticImageArchiveBuilder::new(amd64()).unwrap();
    seam::replace_next_gzip(GzipReplacement::OverCeiling);
    assert_eq!(
        builder.add_layer(&hello(), LayerCompression::Gzip),
        Err(SyntheticImageError::CompressionExpanded { layer: 0 })
    );
    assert_unchanged(&builder);

    seam::replace_next_gzip(GzipReplacement::AtCeiling);
    builder.add_layer(&hello(), LayerCompression::Gzip).unwrap();
    let decoded = write_layer_tar(&hello().entries).unwrap();
    let stored = builder.blobs.first().unwrap().size();
    assert_eq!(stored, gzip_ceiling(widen(decoded.len())));
}

#[test]
fn incompressible_bytes_compress_within_the_ceiling() {
    // A sanity check only: the bounds rest on the enforced ceiling.
    let mut block = Sha256::digest(b"deploy-core incompressible").to_vec();
    let mut payload = Vec::with_capacity(1024 * 1024);
    while payload.len() < 1024 * 1024 {
        block = Sha256::digest(&block).to_vec();
        payload.extend_from_slice(&block);
    }
    let payload_len = widen(payload.len());
    let layer = SyntheticLayer::new().file("random.bin", payload);
    let decoded = widen(write_layer_tar(&layer.entries).unwrap().len());
    let builder = SyntheticImageArchiveBuilder::new(amd64())
        .unwrap()
        .layer(layer, LayerCompression::Gzip)
        .unwrap();
    let stored = builder.blobs.first().unwrap().size();
    assert!(stored > payload_len, "the payload really is incompressible");
    assert!(stored <= gzip_ceiling(decoded));
}

#[test]
fn a_gzip_blob_has_the_fixed_header() {
    let builder = SyntheticImageArchiveBuilder::new(amd64())
        .unwrap()
        .layer(hello(), LayerCompression::Gzip)
        .unwrap();
    let blob = &builder.blobs.first().unwrap().bytes.0;
    // flate2 derives XFL 0 for any level between fast (1) and best (9).
    let xfl = 0x00;
    assert_eq!(
        blob.get(..10).unwrap(),
        &[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, xfl, 0xff],
        "magic, deflate, FLG 0 (no FEXTRA, FNAME or FCOMMENT), MTIME 0, XFL, OS 255"
    );
    // The level: re-encoding at level 6 gives the same bytes.
    let tar = write_layer_tar(&hello().entries).unwrap();
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::new(6));
    encoder.write_all(&tar).unwrap();
    assert_eq!(&encoder.finish().unwrap(), blob);
}

// ---------------------------------------------------------------------------
// JSON bounds, measured
// ---------------------------------------------------------------------------

#[test]
fn generated_documents_stay_within_their_bounds_at_the_maxima() {
    let mut builder = SyntheticImageArchiveBuilder::new(arm64(&long_variant())).unwrap();
    for at in 0..MAX_SYNTHETIC_LAYERS {
        builder = builder
            .layer(
                SyntheticLayer::new().file(&format!("f{at}"), format!("{at}")),
                LayerCompression::Gzip,
            )
            .unwrap();
    }
    let public_refs = longest_refs();
    let archive = builder.finish(&public_refs).unwrap();
    let entries = raw::read_entries(archive.bytes());
    let data = |name: &str| {
        entries
            .iter()
            .find(|entry| entry.name == name)
            .and_then(|entry| entry.data.clone())
            .unwrap()
    };
    let config = data(&blob_path(
        archive.config_digest().strip_prefix("sha256:").unwrap(),
    ));
    let manifest = data(&blob_path(
        archive.manifest_digest().strip_prefix("sha256:").unwrap(),
    ));
    let layers = u(MAX_SYNTHETIC_LAYERS);
    let refs = u(MAX_SYNTHETIC_REFS);
    let ref_bytes = u(MAX_SYNTHETIC_REF_BYTES);
    let documents = [
        (
            data(INDEX_FILE),
            refs * (ref_bytes + INDEX_PER_REF) + INDEX_FIXED,
        ),
        (
            data(COMPATIBILITY_FILE),
            refs * (ref_bytes + COMPAT_PER_REF) + layers * COMPAT_PER_LAYER + COMPAT_FIXED,
        ),
        (manifest, layers * MANIFEST_PER_LAYER + MANIFEST_FIXED),
        (
            config,
            layers * (CONFIG_PER_DIFF_ID + CONFIG_PER_HISTORY) + CONFIG_FIXED,
        ),
        (data(OCI_LAYOUT_FILE), OCI_LAYOUT_BOUND),
    ];
    for (bytes, bound) in documents {
        assert!(widen(bytes.len()) <= bound, "{} > {bound}", bytes.len());
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json_depth(&value) <= JSON_DEPTH_BOUND);
    }
    classify(&archive, &public_refs).unwrap();
}

// ---------------------------------------------------------------------------
// Scaled-down aggregate checks and check order
// ---------------------------------------------------------------------------

fn scaled() -> SyntheticBounds {
    SyntheticBounds {
        layers: 2,
        entries_per_layer: 3,
        total_entries: 5,
        layer_bytes: 10,
        image_bytes: 15,
        ..SyntheticBounds::default()
    }
}

fn scaled_builder() -> SyntheticImageArchiveBuilder {
    SyntheticImageArchiveBuilder::with_bounds(amd64(), scaled()).unwrap()
}

/// Adds `layer`, asserting a refusal generated nothing and changed nothing.
#[track_caller]
fn refuse(
    builder: &mut SyntheticImageArchiveBuilder,
    layer: &SyntheticLayer,
) -> SyntheticImageError {
    let positions = builder.positions.len();
    let (entries, bytes) = (builder.total_entries, builder.total_bytes);
    seam::take_tar_writes();
    let error = builder
        .add_layer(layer, LayerCompression::Uncompressed)
        .unwrap_err();
    assert_eq!(seam::take_tar_writes(), 0, "a refused layer wrote no tar");
    assert_eq!(builder.positions.len(), positions);
    assert_eq!(
        (builder.total_entries, builder.total_bytes),
        (entries, bytes)
    );
    error
}

#[test]
fn every_aggregate_bound_is_inclusive_and_refused_one_step_past() {
    // Exactly at every bound.
    let mut builder = scaled_builder();
    builder
        .add_layer(
            &SyntheticLayer::new()
                .file("a", "12345")
                .file("b", "12345")
                .dir("c"),
            LayerCompression::Uncompressed,
        )
        .unwrap();
    builder
        .add_layer(
            &SyntheticLayer::new().file("d", "123").file("e", "12"),
            LayerCompression::Uncompressed,
        )
        .unwrap();
    assert_eq!((builder.total_entries, builder.total_bytes), (5, 15));
    assert_eq!(builder.positions.len(), 2);
    assert_eq!(
        refuse(&mut builder, &SyntheticLayer::new()),
        SyntheticImageError::TooManyLayers
    );

    let four = SyntheticLayer::new().dir("a").dir("b").dir("c").dir("d");
    assert_eq!(
        refuse(&mut scaled_builder(), &four),
        SyntheticImageError::TooManyEntries { layer: 0 }
    );

    let mut builder = scaled_builder();
    builder
        .add_layer(
            &SyntheticLayer::new().dir("a").dir("b").dir("c"),
            LayerCompression::Uncompressed,
        )
        .unwrap();
    assert_eq!(
        refuse(
            &mut builder,
            &SyntheticLayer::new().dir("d").dir("e").dir("f")
        ),
        SyntheticImageError::TooManyTotalEntries { layer: 1 }
    );

    assert_eq!(
        refuse(
            &mut scaled_builder(),
            &SyntheticLayer::new().file("a", "12345678901")
        ),
        SyntheticImageError::LayerTooLarge { layer: 0 }
    );

    let mut builder = scaled_builder();
    builder
        .add_layer(
            &SyntheticLayer::new().file("a", "1234567890"),
            LayerCompression::Uncompressed,
        )
        .unwrap();
    assert_eq!(
        refuse(&mut builder, &SyntheticLayer::new().file("b", "123456")),
        SyntheticImageError::ImageTooLarge { layer: 1 }
    );
}

#[test]
fn refusals_at_the_path_and_target_steps_generate_nothing() {
    let mut builder = SyntheticImageArchiveBuilder::new(amd64()).unwrap();
    assert_eq!(
        refuse(&mut builder, &SyntheticLayer::new().file("/abs", "x")),
        SyntheticImageError::InvalidEntryPath { layer: 0, entry: 0 }
    );
    assert_eq!(
        refuse(
            &mut builder,
            &SyntheticLayer::new().file(&"a".repeat(120), "x")
        ),
        SyntheticImageError::PathNotRepresentable { layer: 0, entry: 0 }
    );
    assert_eq!(
        refuse(&mut builder, &SyntheticLayer::new().symlink("a", "")),
        SyntheticImageError::InvalidLinkTarget { layer: 0, entry: 0 }
    );
    seam::take_tar_writes();
    builder
        .add_layer(&hello(), LayerCompression::Uncompressed)
        .unwrap();
    assert_eq!(seam::take_tar_writes(), 1, "the counter does count writes");
}

#[test]
fn the_entry_bound_is_checked_before_any_path() {
    let bounds = SyntheticBounds {
        entries_per_layer: 1,
        ..SyntheticBounds::default()
    };
    let mut builder = SyntheticImageArchiveBuilder::with_bounds(amd64(), bounds).unwrap();
    assert_eq!(
        refuse(
            &mut builder,
            &SyntheticLayer::new().file("", "x").file("a", "y")
        ),
        SyntheticImageError::TooManyEntries { layer: 0 }
    );
}

#[test]
fn every_path_is_checked_before_any_link_target() {
    let layer = SyntheticLayer::new()
        .symlink("link", "")
        .file("a/../b", "x");
    assert_eq!(
        refuse(
            &mut SyntheticImageArchiveBuilder::new(amd64()).unwrap(),
            &layer
        ),
        SyntheticImageError::InvalidEntryPath { layer: 0, entry: 1 }
    );
}

#[test]
fn references_are_checked_one_at_a_time_in_order() {
    let builder = SyntheticImageArchiveBuilder::new(amd64()).unwrap();
    let too_long = format!("{}.example/app:1", "a".repeat(499));
    assert_eq!(too_long.len(), 513);
    assert_eq!(
        builder
            .finish(&[String::from("not a ref"), too_long])
            .unwrap_err(),
        SyntheticImageError::InvalidReference { index: 0 }
    );
    let scaled = SyntheticImageArchiveBuilder::with_bounds(
        amd64(),
        SyntheticBounds {
            refs: 1,
            ..SyntheticBounds::default()
        },
    )
    .unwrap();
    assert_eq!(
        scaled.finish(&refs(&["a:1", "b:1"])).unwrap_err(),
        SyntheticImageError::TooManyReferences
    );
}

// ---------------------------------------------------------------------------
// Ustar representability
// ---------------------------------------------------------------------------

#[test]
fn ustar_representability_follows_the_name_and_prefix_fields() {
    let accepted = [
        "a".repeat(100),
        format!("{}/{}", "a".repeat(75), "b".repeat(74)),
        format!("{}/{}", "p".repeat(155), "n".repeat(99)),
    ];
    for path in &accepted {
        let layer = SyntheticLayer::new().file(path, "x");
        let builder = SyntheticImageArchiveBuilder::new(amd64())
            .unwrap()
            .layer(layer, LayerCompression::Uncompressed)
            .unwrap_or_else(|error| panic!("{} bytes: {error}", path.len()));
        let archive = builder.finish(&refs(&["app:1"])).unwrap();
        classify(&archive, &refs(&["app:1"])).unwrap();
    }
    assert_eq!(accepted[2].len(), 255);
    let directory = "d".repeat(99);
    SyntheticImageArchiveBuilder::new(amd64())
        .unwrap()
        .layer(
            SyntheticLayer::new().dir(&directory),
            LayerCompression::Uncompressed,
        )
        .unwrap();

    let refused = [
        SyntheticLayer::new().file(&"a".repeat(101), "x"),
        SyntheticLayer::new().file(&format!("ab/{}", "c".repeat(120)), "x"),
        SyntheticLayer::new().file(&format!("{}/{}", "a".repeat(98), "b".repeat(101)), "x"),
        SyntheticLayer::new().dir(&"d".repeat(100)),
    ];
    for layer in refused {
        assert_eq!(
            SyntheticImageArchiveBuilder::new(amd64())
                .unwrap()
                .layer(layer, LayerCompression::Uncompressed)
                .unwrap_err(),
            SyntheticImageError::PathNotRepresentable { layer: 0, entry: 0 }
        );
    }
}

#[test]
fn the_rightmost_valid_split_is_chosen() {
    let path = format!("{}/{}/{}", "a".repeat(50), "b".repeat(50), "c".repeat(50));
    let (prefix, name) = ustar_split(&path).unwrap();
    assert_eq!(prefix, format!("{}/{}", "a".repeat(50), "b".repeat(50)));
    assert_eq!(name, "c".repeat(50));

    // The rightmost `/` of a directory's written name leaves an empty name,
    // so the split moves left.
    let written = format!("{}/{}/", "a".repeat(120), "b".repeat(20));
    assert_eq!(
        ustar_split(&written),
        Some((&*"a".repeat(120), &*format!("{}/", "b".repeat(20))))
    );
}

// ---------------------------------------------------------------------------
// Layer headers
// ---------------------------------------------------------------------------

#[test]
fn every_layer_header_is_plain_ustar_with_the_fixed_fields() {
    let long = format!("{}/{}", "p".repeat(150), "n".repeat(90));
    let layer = SyntheticLayer::new()
        .dir("etc")
        .file("etc/hello.txt", "hello")
        .symlink("etc/link", "/usr/share/zoneinfo/UTC")
        .symlink("etc/up", "../..")
        .dir(&long)
        .file(&format!("{long}/f"), vec![7u8; 700]);
    let expected: Vec<(u8, String, &[u8], Option<&str>)> = vec![
        (b'5', "etc/".to_string(), b"0000755\0", None),
        (b'0', "etc/hello.txt".to_string(), b"0000644\0", None),
        (
            b'2',
            "etc/link".to_string(),
            b"0000777\0",
            Some("/usr/share/zoneinfo/UTC"),
        ),
        (b'2', "etc/up".to_string(), b"0000777\0", Some("../..")),
        (b'5', format!("{long}/"), b"0000755\0", None),
        (b'0', format!("{long}/f"), b"0000644\0", None),
    ];
    let builder = SyntheticImageArchiveBuilder::new(amd64())
        .unwrap()
        .layer(layer, LayerCompression::Uncompressed)
        .unwrap();
    let tar = &builder.blobs.first().unwrap().bytes.0;
    let entries = layer_entries(tar);
    assert_eq!(entries.len(), expected.len());
    let mut next_header = 0u64;
    for (entry, (flag, name, mode, target)) in entries.iter().zip(&expected) {
        assert_eq!(
            entry.header_offset, next_header,
            "no extension record between"
        );
        let at = usize::try_from(entry.header_offset).unwrap();
        let block = tar.get(at..at + 512).unwrap();
        assert_eq!(&block[257..263], b"ustar\0");
        assert_eq!(&block[263..265], b"00");
        assert_eq!(block[156], *flag);
        assert_eq!(&block[100..108], *mode);
        assert_eq!(&block[108..116], b"0000000\0", "uid");
        assert_eq!(&block[116..124], b"0000000\0", "gid");
        assert_eq!(&block[136..148], b"00000000000\0", "mtime");
        assert!(
            block[265..329].iter().all(|byte| *byte == 0),
            "uname, gname"
        );
        assert_eq!(entry.name, name.as_bytes());
        assert_eq!(entry.link_target.as_deref(), target.map(str::as_bytes));
        next_header = entry.data_offset + padded(entry.data_len);
    }
    assert_eq!(widen(tar.len()), next_header + END_MARKER);
    assert!(
        tar[usize::try_from(next_header).unwrap()..]
            .iter()
            .all(|byte| *byte == 0)
    );
}

// ---------------------------------------------------------------------------
// Exact wire format
// ---------------------------------------------------------------------------

#[test]
// One golden string per document, each built from the digests the last one
// produced; splitting them apart would only thread those digests around.
#[allow(clippy::too_many_lines)]
fn every_document_has_exactly_the_stated_bytes() {
    let builder = SyntheticImageArchiveBuilder::new(arm64("v8"))
        .unwrap()
        .layer(
            SyntheticLayer::new().file("a.txt", "a"),
            LayerCompression::Uncompressed,
        )
        .unwrap()
        .layer(
            SyntheticLayer::new().file("b.txt", "b"),
            LayerCompression::Gzip,
        )
        .unwrap()
        .layer(
            SyntheticLayer::new().file("b.txt", "b"),
            LayerCompression::Gzip,
        )
        .unwrap();
    assert_eq!(builder.blobs.len(), 2, "the repeated layer shares its blob");
    let blobs: Vec<(String, u64)> = builder
        .blobs
        .iter()
        .map(|blob| (blob.hex.clone(), blob.size()))
        .collect();
    let [(a, a_size), (b, b_size)] = blobs.as_slice() else {
        panic!("two blobs");
    };
    let public_refs = refs(&["registry.example/app:1.0", "app:2.0"]);
    let archive = builder.finish(&public_refs).unwrap();
    let diff_ids = archive.diff_ids();
    assert_eq!(diff_ids.len(), 3);
    assert_eq!(diff_ids[1], diff_ids[2]);

    let entries = image_entries(archive.bytes());
    let names: Vec<String> = entries
        .iter()
        .map(|(entry, _)| String::from_utf8(entry.name.clone()).unwrap())
        .collect();
    let cfg = archive.config_digest().strip_prefix("sha256:").unwrap();
    let man = archive.manifest_digest().strip_prefix("sha256:").unwrap();
    assert_eq!(
        names,
        [
            "oci-layout".to_string(),
            "index.json".to_string(),
            "manifest.json".to_string(),
            format!("blobs/sha256/{man}"),
            format!("blobs/sha256/{cfg}"),
            format!("blobs/sha256/{a}"),
            format!("blobs/sha256/{b}"),
        ]
    );
    assert!(
        entries
            .iter()
            .all(|(entry, _)| entry.kind == crate::content::EntryKind::Regular)
    );
    let document = |at: usize| String::from_utf8(entries[at].1.clone()).unwrap();

    let config = format!(
        concat!(
            r#"{{"architecture":"arm64","os":"linux","variant":"v8","rootfs":{{"type":"layers","#,
            r#""diff_ids":["{d0}","{d1}","{d2}"]}},"history":[{{"created_by":"deploy-core synthetic layer 0"}},"#,
            r#"{{"created_by":"deploy-core synthetic layer 1"}},{{"created_by":"deploy-core synthetic layer 2"}}]}}"#
        ),
        d0 = diff_ids[0],
        d1 = diff_ids[1],
        d2 = diff_ids[2],
    );
    assert_eq!(document(4), config);
    let layer = |media: &str, hex: &str, size: u64| {
        format!(r#"{{"mediaType":"{media}","digest":"sha256:{hex}","size":{size}}}"#)
    };
    let manifest = format!(
        concat!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
            r#""config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{cfg}","size":{size}}},"#,
            r#""layers":[{l0},{l1},{l2}]}}"#
        ),
        cfg = cfg,
        size = config.len(),
        l0 = layer("application/vnd.oci.image.layer.v1.tar", a, *a_size),
        l1 = layer("application/vnd.oci.image.layer.v1.tar+gzip", b, *b_size),
        l2 = layer("application/vnd.oci.image.layer.v1.tar+gzip", b, *b_size),
    );
    assert_eq!(document(3), manifest);
    let descriptor = |reference: &str, tag: &str| {
        format!(
            concat!(
                r#"{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{man}","size":{size},"#,
                r#""annotations":{{"io.containerd.image.name":"{reference}","org.opencontainers.image.ref.name":"{tag}"}}}}"#
            ),
            man = man,
            size = manifest.len(),
            reference = reference,
            tag = tag,
        )
    };
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{},{}]}}"#,
        descriptor("registry.example/app:1.0", "1.0"),
        descriptor("app:2.0", "2.0"),
    );
    assert_eq!(document(1), index);
    let compatibility = format!(
        concat!(
            r#"[{{"Config":"blobs/sha256/{cfg}","RepoTags":["registry.example/app:1.0","app:2.0"],"#,
            r#""Layers":["blobs/sha256/{a}","blobs/sha256/{b}","blobs/sha256/{b}"]}}]"#
        ),
        cfg = cfg,
        a = a,
        b = b,
    );
    assert_eq!(document(2), compatibility);
    assert_eq!(document(0), r#"{"imageLayoutVersion":"1.0.0"}"#);

    // Exactly two zero blocks end the archive.
    let (last, data) = entries.last().unwrap();
    assert_eq!(widen(data.len()), last.data_len);
    let end = last.data_offset + padded(last.data_len);
    assert_eq!(widen(archive.bytes().len()), end + END_MARKER);
    classify(&archive, &public_refs).unwrap();
}

#[test]
fn a_scratch_image_has_empty_diff_ids_and_history_and_no_null_variant() {
    let builder = SyntheticImageArchiveBuilder::new(amd64()).unwrap();
    assert_eq!(
        String::from_utf8(builder.config_bytes()).unwrap(),
        r#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"history":[]}"#
    );
    let public_refs = refs(&["scratch:1"]);
    let archive = builder.finish(&public_refs).unwrap();
    assert!(archive.diff_ids().is_empty());
    assert_eq!(image_entries(archive.bytes()).len(), 5);
    classify(&archive, &public_refs).unwrap();
}

// ---------------------------------------------------------------------------
// Classifier limit mapping
// ---------------------------------------------------------------------------

#[test]
fn a_limit_fault_maps_to_limit_exceeded_and_nothing_else() {
    let public_refs = refs(&["registry.example/app:1.0"]);
    let archive = SyntheticImageArchiveBuilder::new(amd64())
        .unwrap()
        .layer(hello(), LayerCompression::Gzip)
        .unwrap()
        .finish(&public_refs)
        .unwrap();
    let declaration = raw::builder_declaration(&archive, public_refs);
    let limit = default_limit(LimitResource::ImageManifestJson);
    assert_eq!(limit, 1_048_576);

    let over = raw::with_index_size(archive.bytes(), limit + 1);
    match check_image_archive(Cursor::new(over), "images/app.tar", &declaration) {
        Err(ArchiveCheckError::LimitExceeded { resource, limit }) => {
            assert_eq!(resource, LimitResource::ImageManifestJson);
            assert_eq!(limit, 1_048_576);
        }
        other => panic!("expected a limit, got {other:?}"),
    }

    let at = raw::with_index_size(archive.bytes(), limit);
    match check_image_archive(Cursor::new(at), "images/app.tar", &declaration) {
        Err(ArchiveCheckError::Image(ImageVerifyError::InvalidArchive {
            archive_path,
            reason:
                InvalidArchiveReason::BlobMismatch {
                    role: BlobRole::Manifest,
                    kind: BlobMismatchKind::Length,
                },
        })) => assert_eq!(archive_path, "images/app.tar"),
        other => panic!("expected the next verdict, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Raw generator fixtures
// ---------------------------------------------------------------------------

fn inventory() -> Value {
    serde_json::from_slice(&std::fs::read(format!("{FIXTURES}/inventory.json")).unwrap()).unwrap()
}

fn fixtures_of(inventory: &Value, generator: &str) -> Vec<Value> {
    inventory["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|fixture| fixture["provenance"]["generator"] == generator)
        .cloned()
        .collect()
}

/// Regenerates the fixture `fixture` records, through the generator it
/// names.
fn regenerate(fixture: &Value) -> raw::Generated {
    let parameters = &fixture["provenance"]["parameters"];
    match fixture["provenance"]["generator"].as_str().unwrap() {
        "builder" => {
            let archive = raw::build(parameters);
            let public_refs = parameters["public_refs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|reference| reference.as_str().unwrap().to_string())
                .collect();
            let declaration = raw::builder_declaration(&archive, public_refs);
            raw::Generated {
                bytes: archive.into_bytes(),
                declaration,
            }
        }
        "raw-generator" => raw::generate(parameters),
        other => panic!("unknown generator {other}"),
    }
}

#[test]
fn raw_generator_fixtures_regenerate_byte_for_byte() {
    let inventory = inventory();
    let fixtures = fixtures_of(&inventory, "raw-generator");
    assert_eq!(fixtures.len(), 7);
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let archive_name = fixture["archive"].as_str().unwrap();
        assert_eq!(
            fixture["provenance"]["test"],
            "src/image/test_support/tests.rs::raw_generator_fixtures_regenerate_byte_for_byte"
        );
        let generated = regenerate(&fixture);
        let checked_in = std::fs::read(format!("{FIXTURES}/{archive_name}")).unwrap();
        assert!(
            generated.bytes == checked_in,
            "{name} regenerates byte for byte"
        );
        assert_eq!(
            fixture["sha256"].as_str().unwrap(),
            sha256_hex(&checked_in),
            "{name}"
        );
        let declaration: ImageDeclaration = serde_json::from_slice(
            &std::fs::read(format!(
                "{FIXTURES}/{}",
                fixture["declaration"].as_str().unwrap()
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(declaration, generated.declaration, "{name}");
        let verdict = verdict_of(check_image_archive(
            Cursor::new(&checked_in),
            archive_name,
            &declaration,
        ));
        assert_eq!(verdict, fixture["verdict"], "{name}");
    }
}

#[test]
fn the_layout_without_a_compatibility_manifest_holds_only_the_layout_and_referenced_blobs() {
    let inventory = inventory();
    let fixture = fixtures_of(&inventory, "raw-generator")
        .into_iter()
        .find(|fixture| fixture["name"] == "oci-without-compat-manifest")
        .unwrap();
    let generated = raw::generate(&fixture["provenance"]["parameters"]);
    let base = raw::build(&fixture["provenance"]["parameters"]["base"]);
    let mut expected: Vec<String> = raw::read_entries(base.bytes())
        .into_iter()
        .map(|entry| entry.name)
        .filter(|name| name != COMPATIBILITY_FILE)
        .collect();
    let mut names: Vec<String> = raw::read_entries(&generated.bytes)
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names.first().map(String::as_str), Some(OCI_LAYOUT_FILE));
    assert_eq!(names.get(1).map(String::as_str), Some(INDEX_FILE));
    names.sort_unstable();
    expected.sort_unstable();
    assert_eq!(names, expected);
    match check_image_archive(
        Cursor::new(&generated.bytes),
        "oci-without-compat-manifest.tar",
        &generated.declaration,
    ) {
        Err(ArchiveCheckError::Image(ImageVerifyError::InvalidArchive {
            reason:
                InvalidArchiveReason::MissingLayoutFile {
                    file: LayoutFile::CompatibilityManifest,
                },
            ..
        })) => {}
        other => panic!("expected a missing compatibility manifest, got {other:?}"),
    }
}

#[test]
fn a_raw_zstd_frame_decodes_to_its_input() {
    let data: Vec<u8> = (0..300_000u32).map(|at| (at % 251) as u8).collect();
    for input in [&data[..], b"", b"x"] {
        let frame = raw::zstd_frame(input);
        assert_eq!(zstd::decode_all(frame.as_slice()).unwrap(), input);
    }
}

#[test]
fn the_raw_tar_writer_round_trips() {
    let entries = vec![
        RawEntry::file("a", b"1".to_vec()),
        RawEntry::file("b/c", Vec::new()),
    ];
    let names: Vec<String> = raw::read_entries(&raw::write_tar(&entries))
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names, ["a", "b/c"]);
}

/// Rewrites every synthetic fixture, its declaration and its inventory
/// record from the parameters `inventory.json` holds.
///
/// A maintenance tool, never run by `cargo test`: run it with
/// `cargo test --lib -- --ignored write_synthetic_fixtures` after a change
/// that moves generated bytes, such as a `flate2` or `miniz_oxide` update,
/// and review the diff. `docker-capture` fixtures are left untouched.
#[test]
#[ignore = "rewrites the checked-in fixtures"]
fn write_synthetic_fixtures() {
    let mut inventory = inventory();
    for fixture in inventory["fixtures"].as_array_mut().unwrap() {
        if fixture["kind"] != "synthetic" {
            continue;
        }
        let generated = regenerate(fixture);
        let archive_name = fixture["archive"].as_str().unwrap().to_string();
        let declaration_name = fixture["declaration"].as_str().unwrap().to_string();
        std::fs::write(format!("{FIXTURES}/{archive_name}"), &generated.bytes).unwrap();
        let mut declaration = serde_json::to_vec_pretty(&generated.declaration).unwrap();
        declaration.push(b'\n');
        std::fs::write(format!("{FIXTURES}/{declaration_name}"), declaration).unwrap();
        fixture["sha256"] = json!(sha256_hex(&generated.bytes));
        fixture["verdict"] = verdict_of(check_image_archive(
            Cursor::new(&generated.bytes),
            &archive_name,
            &generated.declaration,
        ));
    }
    let mut bytes = serde_json::to_vec_pretty(&inventory).unwrap();
    bytes.push(b'\n');
    std::fs::write(format!("{FIXTURES}/inventory.json"), bytes).unwrap();
}
