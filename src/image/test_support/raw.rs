//! The test-only raw generator: image archives outside what the public
//! builder writes, assembled from builder output or from scratch.
//!
//! It produces the `raw-generator` fixtures of
//! `assets/test-fixtures/images/inventory.json` — one archive the profile
//! accepts with a `LayerSources` the builder never emits, and small
//! representatives of each refused `docker save` form — and the in-memory
//! rewrites the classifier tests need. Every output is a pure function of its
//! recorded parameters. Nothing here is reachable outside this crate's tests.

use std::io::Read;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    BLOB_PREFIX, COMPATIBILITY_FILE, INDEX_FILE, LayerCompression, OCI_GZIP_LAYER_MEDIA_TYPE,
    OCI_INDEX_MEDIA_TYPE, OCI_LAYOUT_FILE, OCI_MANIFEST_MEDIA_TYPE, SHA256_PREFIX,
    SyntheticImageArchive, SyntheticImageArchiveBuilder, SyntheticLayer, fixed_header,
    set_ustar_name, widen,
};
use crate::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle,
};
use crate::payload::to_hex;

const ZSTD_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const IN_TOTO_MEDIA_TYPE: &str = "application/vnd.in-toto+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// Frame header descriptor: a single segment with a 4-byte content size, no
/// checksum and no dictionary.
const ZSTD_FRAME_HEADER: u8 = 0xa0;
/// The largest block a zstd frame may carry.
const ZSTD_MAX_BLOCK: usize = 128 * 1024;

/// One entry of a raw image tar: a regular file, or a directory when `data`
/// is `None`.
#[derive(Clone, Debug)]
pub(super) struct RawEntry {
    pub(super) name: String,
    pub(super) data: Option<Vec<u8>>,
}

impl RawEntry {
    pub(super) fn file(name: &str, data: Vec<u8>) -> RawEntry {
        RawEntry {
            name: name.to_string(),
            data: Some(data),
        }
    }

    fn dir(name: &str) -> RawEntry {
        RawEntry {
            name: name.to_string(),
            data: None,
        }
    }
}

/// A generated archive and the declaration it is classified against.
pub(super) struct Generated {
    pub(super) bytes: Vec<u8>,
    pub(super) declaration: ImageDeclaration,
}

// ---------------------------------------------------------------------------
// Builder parameters, as `inventory.json` records them
// ---------------------------------------------------------------------------

/// Builds the archive `parameters` describe through the public builder.
///
/// `parameters` holds `architecture`, `variant`, `layers` — each a
/// `compression` and a list of `entries`, each a `kind` of `file`, `dir` or
/// `symlink` with a `path` and a `text` or `target` — and `public_refs`.
pub(super) fn build(parameters: &Value) -> SyntheticImageArchive {
    let mut builder = SyntheticImageArchiveBuilder::new(platform(parameters)).unwrap();
    for layer in parameters["layers"].as_array().unwrap() {
        let mut synthetic = SyntheticLayer::new();
        for entry in layer["entries"].as_array().unwrap() {
            let path = entry["path"].as_str().unwrap();
            synthetic = match entry["kind"].as_str().unwrap() {
                "file" => synthetic.file(path, entry["text"].as_str().unwrap()),
                "dir" => synthetic.dir(path),
                "symlink" => synthetic.symlink(path, entry["target"].as_str().unwrap()),
                other => panic!("unknown entry kind {other}"),
            };
        }
        let compression = match layer["compression"].as_str().unwrap() {
            "uncompressed" => LayerCompression::Uncompressed,
            "gzip" => LayerCompression::Gzip,
            other => panic!("unknown compression {other}"),
        };
        builder = builder.layer(synthetic, compression).unwrap();
    }
    builder.finish(&public_refs(parameters)).unwrap()
}

fn platform(parameters: &Value) -> ImagePlatform {
    ImagePlatform {
        os: ImageOs::Linux,
        architecture: match parameters["architecture"].as_str().unwrap() {
            "amd64" => ImageArchitecture::Amd64,
            "arm64" => ImageArchitecture::Arm64,
            other => panic!("unknown architecture {other}"),
        },
        variant: parameters["variant"].as_str().map(str::to_string),
    }
}

fn public_refs(parameters: &Value) -> Vec<String> {
    parameters["public_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reference| reference.as_str().unwrap().to_string())
        .collect()
}

/// Returns the declaration every fixture is classified against: the given
/// platform, config digest and references under a fixed owner, dependency,
/// lifecycle and provenance.
pub(super) fn declaration(
    platform: ImagePlatform,
    config_digest: &str,
    public_refs: Vec<String>,
) -> ImageDeclaration {
    ImageDeclaration {
        schema: IMAGE_DECLARATION_SCHEMA,
        owner: ImageOwner {
            namespace: "example-product".to_string(),
            component: "example-app".to_string(),
        },
        dependency: "app".to_string(),
        public_refs,
        platform,
        config_digest: config_digest.to_string(),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
            repository: "https://example.com/synthetic-images.git".to_string(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        }),
    }
}

/// Returns the declaration matching a builder archive and its references.
pub(super) fn builder_declaration(
    archive: &SyntheticImageArchive,
    public_refs: Vec<String>,
) -> ImageDeclaration {
    declaration(
        archive.platform().clone(),
        archive.config_digest(),
        public_refs,
    )
}

// ---------------------------------------------------------------------------
// Raw generation
// ---------------------------------------------------------------------------

/// Generates the raw-generator fixture `parameters` describe.
///
/// `parameters.form` names the form; `base`, and for `multi-platform-index`
/// `second`, are builder parameters of the image it starts from. The
/// declaration is always the base image's, so a refusal reflects the
/// representation rather than a declaration mismatch.
pub(super) fn generate(parameters: &Value) -> Generated {
    let base_parameters = &parameters["base"];
    let base = build(base_parameters);
    let declaration = builder_declaration(&base, public_refs(base_parameters));
    let bytes = match parameters["form"].as_str().unwrap() {
        "layer-sources" => layer_sources(&base),
        "classic-layout" => classic_layout(&base, &declaration.public_refs),
        "graphdriver-extras" => graphdriver_extras(&base, &declaration.public_refs),
        "containerd-nested-index" => containerd_nested_index(&base),
        "oci-without-compat-manifest" => oci_without_compat_manifest(&base),
        "multi-platform-index" => multi_platform_index(&base, &build(&parameters["second"])),
        "zstd-layer" => zstd_layer(&base),
        other => panic!("unknown raw form {other}"),
    };
    Generated { bytes, declaration }
}

/// Adds a complete, consistent `LayerSources` to the compatibility record:
/// one value per distinct diff ID, equal to its layer descriptor.
fn layer_sources(base: &SyntheticImageArchive) -> Vec<u8> {
    let mut entries = read_entries(base.bytes());
    let manifest = json_blob(&entries, base.manifest_digest());
    let mut sources = Map::new();
    for (diff_id, descriptor) in base
        .diff_ids()
        .iter()
        .zip(manifest["layers"].as_array().unwrap())
    {
        sources.insert(diff_id.clone(), descriptor.clone());
    }
    edit_json(&mut entries, COMPATIBILITY_FILE, |compatibility| {
        compatibility[0]["LayerSources"] = Value::Object(sources);
    });
    write_tar(&entries)
}

/// The classic `docker save` layout: a directory per layer holding
/// `layer.tar`, `json` and `VERSION`, the config as `<hex>.json`, a legacy
/// `manifest.json` and `repositories`.
fn classic_layout(base: &SyntheticImageArchive, public_refs: &[String]) -> Vec<u8> {
    let entries = read_entries(base.bytes());
    let config = entry(&entries, &blob_name(base.config_digest())).to_vec();
    let config_hex = hex_of(base.config_digest());
    let manifest = json_blob(&entries, base.manifest_digest());
    let mut layer_entries = Vec::new();
    let mut layer_paths = Vec::new();
    let mut parent: Option<String> = None;
    for (diff_id, descriptor) in base
        .diff_ids()
        .iter()
        .zip(manifest["layers"].as_array().unwrap())
    {
        let tar = decode(&entries, descriptor);
        let id = sha256_hex(format!("{}{diff_id}", parent.as_deref().unwrap_or("")).as_bytes());
        let mut v1 = json!({
            "id": id,
            "created": "1970-01-01T00:00:00Z",
            "os": "linux",
        });
        if let Some(parent) = &parent {
            v1["parent"] = json!(parent);
        }
        layer_entries.push(RawEntry::dir(&format!("{id}/")));
        layer_entries.push(RawEntry::file(&format!("{id}/VERSION"), b"1.0".to_vec()));
        layer_entries.push(RawEntry::file(&format!("{id}/json"), to_vec(&v1)));
        layer_entries.push(RawEntry::file(&format!("{id}/layer.tar"), tar));
        layer_paths.push(format!("{id}/layer.tar"));
        parent = Some(id);
    }
    let last = parent.unwrap_or_default();
    let mut repositories = Map::new();
    for reference in public_refs {
        let (name, tag) = reference.rsplit_once(':').unwrap();
        repositories
            .entry(name.to_string())
            .or_insert_with(|| json!({}))[tag] = json!(last);
    }
    let compatibility = json!([{
        "Config": format!("{config_hex}.json"),
        "RepoTags": public_refs,
        "Layers": layer_paths,
    }]);
    let mut raw = layer_entries;
    raw.push(RawEntry::file(&format!("{config_hex}.json"), config));
    raw.push(RawEntry::file(COMPATIBILITY_FILE, to_vec(&compatibility)));
    raw.push(RawEntry::file(
        "repositories",
        to_vec(&Value::Object(repositories)),
    ));
    write_tar(&raw)
}

/// A supported archive with what a graphdriver-store export adds: an
/// unreferenced legacy V1 config blob and `repositories`.
fn graphdriver_extras(base: &SyntheticImageArchive, public_refs: &[String]) -> Vec<u8> {
    let mut entries = read_entries(base.bytes());
    let v1_config = to_vec(&json!({
        "id": sha256_hex(base.config_digest().as_bytes()),
        "created": "1970-01-01T00:00:00Z",
        "os": "linux",
        "architecture": base.platform().architecture.to_string(),
    }));
    let v1_hex = sha256_hex(&v1_config);
    entries.push(RawEntry::file(&format!("{BLOB_PREFIX}{v1_hex}"), v1_config));
    let mut repositories = Map::new();
    for reference in public_refs {
        let (name, tag) = reference.rsplit_once(':').unwrap();
        repositories
            .entry(name.to_string())
            .or_insert_with(|| json!({}))[tag] = json!(v1_hex);
    }
    entries.push(RawEntry::file(
        "repositories",
        to_vec(&Value::Object(repositories)),
    ));
    write_tar(&entries)
}

/// What a containerd-store export writes: `index.json` names a nested index,
/// which lists the image manifest and an attestation manifest, and whose
/// descriptors carry annotations beyond the reference names.
fn containerd_nested_index(base: &SyntheticImageArchive) -> Vec<u8> {
    let mut entries = read_entries(base.bytes());
    let manifest_len = entry(&entries, &blob_name(base.manifest_digest())).len();

    let statement = to_vec(&json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{
            "name": "synthetic",
            "digest": { "sha256": hex_of(base.manifest_digest()) },
        }],
        "predicate": {},
    }));
    let statement_digest = digest(&statement);
    let attestation_config = to_vec(&json!({
        "architecture": "unknown",
        "os": "unknown",
        "config": {},
        "rootfs": { "type": "layers", "diff_ids": [statement_digest] },
    }));
    let attestation_manifest = to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": descriptor(OCI_CONFIG_MEDIA_TYPE, &attestation_config),
        "layers": [{
            "mediaType": IN_TOTO_MEDIA_TYPE,
            "digest": statement_digest,
            "size": statement.len(),
            "annotations": { "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2" },
        }],
    }));
    let platform = &base.platform();
    let mut image_platform = json!({
        "architecture": platform.architecture.to_string(),
        "os": "linux",
    });
    if let Some(variant) = &platform.variant {
        image_platform["variant"] = json!(variant);
    }
    let nested = to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX_MEDIA_TYPE,
        "manifests": [
            {
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "digest": base.manifest_digest(),
                "size": manifest_len,
                "platform": image_platform,
                "annotations": {
                    "containerd.io/distribution.source.registry.example": "synthetic/app",
                },
            },
            {
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "digest": digest(&attestation_manifest),
                "size": attestation_manifest.len(),
                "platform": { "architecture": "unknown", "os": "unknown" },
                "annotations": {
                    "vnd.docker.reference.digest": base.manifest_digest(),
                    "vnd.docker.reference.type": "attestation-manifest",
                },
            },
        ],
    }));
    edit_json(&mut entries, INDEX_FILE, |index| {
        for descriptor in index["manifests"].as_array_mut().unwrap() {
            descriptor["mediaType"] = json!(OCI_INDEX_MEDIA_TYPE);
            descriptor["digest"] = json!(digest(&nested));
            descriptor["size"] = json!(nested.len());
        }
    });
    for blob in [nested, attestation_manifest, attestation_config, statement] {
        entries.push(RawEntry::file(
            &format!("{BLOB_PREFIX}{}", sha256_hex(&blob)),
            blob,
        ));
    }
    write_tar(&entries)
}

/// An OCI layout with no compatibility `manifest.json`: `oci-layout`,
/// `index.json` and the referenced blobs, and nothing else.
fn oci_without_compat_manifest(base: &SyntheticImageArchive) -> Vec<u8> {
    let mut entries = read_entries(base.bytes());
    entries.retain(|entry| entry.name != COMPATIBILITY_FILE);
    write_tar(&entries)
}

/// Two images for different platforms in one layout: `index.json` names both
/// manifests, each with its platform, and `manifest.json` has a record for
/// each.
fn multi_platform_index(base: &SyntheticImageArchive, second: &SyntheticImageArchive) -> Vec<u8> {
    let first_entries = read_entries(base.bytes());
    let second_entries = read_entries(second.bytes());
    let mut descriptors = Vec::new();
    let mut records = Vec::new();
    for entries in [&first_entries, &second_entries] {
        let index = parse(entry(entries, INDEX_FILE));
        descriptors.extend(index["manifests"].as_array().unwrap().iter().cloned());
        let compatibility = parse(entry(entries, COMPATIBILITY_FILE));
        records.extend(compatibility.as_array().unwrap().iter().cloned());
    }
    for (descriptor, archive) in descriptors.iter_mut().zip([base, second]) {
        let platform = archive.platform();
        let mut stated = json!({
            "architecture": platform.architecture.to_string(),
            "os": "linux",
        });
        if let Some(variant) = &platform.variant {
            stated["variant"] = json!(variant);
        }
        descriptor["platform"] = stated;
    }
    let index = json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX_MEDIA_TYPE,
        "manifests": descriptors,
    });
    let mut raw = vec![
        RawEntry::file(
            OCI_LAYOUT_FILE,
            entry(&first_entries, OCI_LAYOUT_FILE).to_vec(),
        ),
        RawEntry::file(INDEX_FILE, to_vec(&index)),
        RawEntry::file(COMPATIBILITY_FILE, to_vec(&Value::Array(records))),
    ];
    for entry in first_entries.iter().chain(&second_entries) {
        if entry.name.starts_with(BLOB_PREFIX) && !raw.iter().any(|seen| seen.name == entry.name) {
            raw.push(entry.clone());
        }
    }
    write_tar(&raw)
}

/// A supported archive whose layers are re-stored as zstd frames under the
/// zstd layer media type. The config, and so every diff ID, is unchanged.
fn zstd_layer(base: &SyntheticImageArchive) -> Vec<u8> {
    let entries = read_entries(base.bytes());
    let mut manifest = json_blob(&entries, base.manifest_digest());
    let mut blobs = Vec::new();
    for descriptor in manifest["layers"].as_array_mut().unwrap() {
        let blob = zstd_frame(&decode(&entries, descriptor));
        *descriptor = json!({
            "mediaType": ZSTD_LAYER_MEDIA_TYPE,
            "digest": digest(&blob),
            "size": blob.len(),
        });
        if !blobs.contains(&blob) {
            blobs.push(blob);
        }
    }
    let manifest = to_vec(&manifest);
    let config_name = blob_name(base.config_digest());
    let config = entry(&entries, &config_name).to_vec();
    let mut raw = vec![
        RawEntry::file(OCI_LAYOUT_FILE, entry(&entries, OCI_LAYOUT_FILE).to_vec()),
        RawEntry::file(INDEX_FILE, entry(&entries, INDEX_FILE).to_vec()),
        RawEntry::file(
            COMPATIBILITY_FILE,
            entry(&entries, COMPATIBILITY_FILE).to_vec(),
        ),
    ];
    edit_json(&mut raw, INDEX_FILE, |index| {
        for descriptor in index["manifests"].as_array_mut().unwrap() {
            descriptor["digest"] = json!(digest(&manifest));
            descriptor["size"] = json!(manifest.len());
        }
    });
    edit_json(&mut raw, COMPATIBILITY_FILE, |compatibility| {
        compatibility[0]["Layers"] = blobs
            .iter()
            .map(|blob| json!(format!("{BLOB_PREFIX}{}", sha256_hex(blob))))
            .collect();
    });
    raw.push(RawEntry::file(
        &format!("{BLOB_PREFIX}{}", sha256_hex(&manifest)),
        manifest,
    ));
    raw.push(RawEntry::file(&config_name, config));
    for blob in blobs {
        raw.push(RawEntry::file(
            &format!("{BLOB_PREFIX}{}", sha256_hex(&blob)),
            blob,
        ));
    }
    write_tar(&raw)
}

/// Rewrites `index.json` so its first descriptor states `size`, and changes
/// nothing else.
pub(super) fn with_index_size(archive: &[u8], size: u64) -> Vec<u8> {
    let mut entries = read_entries(archive);
    edit_json(&mut entries, INDEX_FILE, |index| {
        index["manifests"][0]["size"] = json!(size);
    });
    write_tar(&entries)
}

/// Returns `data` as one zstd frame of raw blocks, which every decoder reads
/// and no encoder version changes.
pub(super) fn zstd_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = ZSTD_MAGIC.to_vec();
    frame.push(ZSTD_FRAME_HEADER);
    frame.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    let mut chunks: Vec<&[u8]> = data.chunks(ZSTD_MAX_BLOCK).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let last = chunks.len() - 1;
    for (at, chunk) in chunks.into_iter().enumerate() {
        let header = (u32::try_from(chunk.len()).unwrap() << 3) | u32::from(at == last);
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(chunk);
    }
    frame
}

// ---------------------------------------------------------------------------
// Tar and JSON helpers
// ---------------------------------------------------------------------------

/// Returns every entry of an image tar, in archive order.
pub(super) fn read_entries(archive: &[u8]) -> Vec<RawEntry> {
    let mut reader = tar::Archive::new(archive);
    reader
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let name = String::from_utf8(entry.path_bytes().into_owned()).unwrap();
            if entry.header().entry_type().is_dir() {
                RawEntry::dir(&name)
            } else {
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                RawEntry::file(&name, data)
            }
        })
        .collect()
}

/// Writes `entries` as a ustar image tar with the builder's fixed header
/// fields: regular files at mode `0o644`, directories at `0o755`.
pub(super) fn write_tar(entries: &[RawEntry]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        let (mut header, data): (tar::Header, &[u8]) = match &entry.data {
            Some(data) => (
                fixed_header(tar::EntryType::Regular, 0o644, widen(data.len())),
                data,
            ),
            None => (fixed_header(tar::EntryType::Directory, 0o755, 0), &[]),
        };
        assert!(
            entry.name.len() <= 100,
            "raw names fit the ustar name field"
        );
        set_ustar_name(&mut header, "", &entry.name);
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }
    builder.into_inner().unwrap()
}

fn entry<'e>(entries: &'e [RawEntry], name: &str) -> &'e [u8] {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .and_then(|entry| entry.data.as_deref())
        .unwrap_or_else(|| panic!("no file {name}"))
}

fn edit_json(entries: &mut [RawEntry], name: &str, edit: impl FnOnce(&mut Value)) {
    let entry = entries
        .iter_mut()
        .find(|entry| entry.name == name)
        .unwrap_or_else(|| panic!("no file {name}"));
    let mut value = parse(entry.data.as_deref().unwrap());
    edit(&mut value);
    entry.data = Some(to_vec(&value));
}

/// Returns the blob named by a `sha256:` digest, parsed as JSON.
fn json_blob(entries: &[RawEntry], digest: &str) -> Value {
    parse(entry(entries, &blob_name(digest)))
}

/// Returns the decoded tar of the layer blob `descriptor` names.
fn decode(entries: &[RawEntry], descriptor: &Value) -> Vec<u8> {
    let blob = entry(entries, &blob_name(descriptor["digest"].as_str().unwrap()));
    if descriptor["mediaType"] == OCI_GZIP_LAYER_MEDIA_TYPE {
        let mut tar = Vec::new();
        flate2::read::GzDecoder::new(blob)
            .read_to_end(&mut tar)
            .unwrap();
        tar
    } else {
        blob.to_vec()
    }
}

fn descriptor(media_type: &str, blob: &[u8]) -> Value {
    json!({ "mediaType": media_type, "digest": digest(blob), "size": blob.len() })
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn to_vec(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn blob_name(digest: &str) -> String {
    format!("{BLOB_PREFIX}{}", hex_of(digest))
}

fn hex_of(digest: &str) -> &str {
    digest.strip_prefix(SHA256_PREFIX).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    format!("{SHA256_PREFIX}{}", sha256_hex(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}
