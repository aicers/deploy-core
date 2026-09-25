//! Test-only assembly of image archives from raw parts: tar headers set byte
//! for byte, every JSON document before and after serialization, entry order,
//! trailing bytes, and layer blobs in any encoding.
//!
//! Writing is not validating, so nothing here goes through the content
//! primitives. The defaults build an archive the validator accepts; every
//! test changes exactly the part it is about.

use std::cell::RefCell;
use std::io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::documents::{
    OCI_GZIP_LAYER_MEDIA_TYPE, OCI_INDEX_MEDIA_TYPE, OCI_LAYER_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
};
use crate::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle,
};
use crate::payload::to_hex;

pub(super) const BLOCK: usize = 512;
pub(super) const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub(super) const LAYER_TAR: &str = OCI_LAYER_MEDIA_TYPE;
pub(super) const LAYER_GZIP: &str = OCI_GZIP_LAYER_MEDIA_TYPE;
pub(super) const MANIFEST_MEDIA_TYPE: &str = OCI_MANIFEST_MEDIA_TYPE;
pub(super) const INDEX_MEDIA_TYPE: &str = OCI_INDEX_MEDIA_TYPE;

/// Returns `sha256:<hex>` of `bytes`.
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", to_hex(&Sha256::digest(bytes)))
}

/// Returns the hex of `bytes`' SHA-256.
pub(super) fn hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// Returns `data` as one gzip member.
pub(super) fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Which checksum a [`Header`] is stamped with.
#[derive(Clone, Copy)]
enum Checksum {
    Correct,
    Wrong,
}

/// A raw 512-byte tar header, set byte for byte.
#[derive(Clone)]
pub(super) struct Header {
    block: [u8; BLOCK],
    checksum: Checksum,
}

impl Header {
    /// Returns a POSIX ustar header with `flag`, `name` and `size`, mode 0644
    /// and every other field zero.
    pub(super) fn new(flag: u8, name: &[u8], size: u64) -> Header {
        let mut header = Header {
            block: [0; BLOCK],
            checksum: Checksum::Correct,
        };
        header.set(0, name);
        header.set(100, b"0000644\0");
        header.set(108, b"0000000\0");
        header.set(116, b"0000000\0");
        header.size(size);
        header.set(136, b"00000000000\0");
        header.block[156] = flag;
        header.set(257, b"ustar\0").set(263, b"00");
        header
    }

    pub(super) fn file(name: &str, size: usize) -> Header {
        Header::new(b'0', name.as_bytes(), u64::try_from(size).unwrap())
    }

    pub(super) fn dir(name: &str) -> Header {
        Header::new(b'5', name.as_bytes(), 0)
    }

    /// Overwrites bytes starting at `offset`.
    pub(super) fn set(&mut self, offset: usize, bytes: &[u8]) -> &mut Header {
        self.block[offset..offset + bytes.len()].copy_from_slice(bytes);
        self
    }

    /// Writes `size` as eleven octal digits and a NUL.
    pub(super) fn size(&mut self, size: u64) -> &mut Header {
        let text = format!("{size:011o}\0");
        assert_eq!(text.len(), 12, "size {size} needs base-256");
        self.set(124, text.as_bytes())
    }

    pub(super) fn linkname(&mut self, linkname: &[u8]) -> &mut Header {
        self.set(157, &[0; 100]).set(157, linkname)
    }

    /// Splits nothing: writes `prefix` into the ustar prefix field as is.
    pub(super) fn prefix(&mut self, prefix: &[u8]) -> &mut Header {
        self.set(345, &[0; 155]).set(345, prefix)
    }

    pub(super) fn gnu(&mut self) -> &mut Header {
        self.set(257, b"ustar  \0")
    }

    pub(super) fn no_magic(&mut self) -> &mut Header {
        self.set(257, &[0; 8])
    }

    pub(super) fn wrong_checksum(&mut self) -> &mut Header {
        self.checksum = Checksum::Wrong;
        self
    }

    /// Returns the finished block, with its checksum stamped.
    pub(super) fn build(&self) -> [u8; BLOCK] {
        let mut block = self.block;
        block[148..156].copy_from_slice(b"        ");
        let mut sum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        if matches!(self.checksum, Checksum::Wrong) {
            sum += 1;
        }
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    }
}

/// Returns a PAX payload holding `records` in order, each with its length
/// computed.
pub(super) fn pax(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (key, value) in records {
        let body = key.len() + value.len() + 3;
        let mut len = body + 1;
        while format!("{len}").len() + body != len {
            len += 1;
        }
        payload.extend_from_slice(format!("{len} {key}=").as_bytes());
        payload.extend_from_slice(value);
        payload.push(b'\n');
    }
    payload
}

/// A tar stream under construction.
#[derive(Default)]
pub(super) struct Tar {
    bytes: Vec<u8>,
}

impl Tar {
    pub(super) fn new() -> Tar {
        Tar::default()
    }

    /// Appends `header` and `data`, zero-padded to a whole block.
    pub(super) fn entry(&mut self, header: &Header, data: &[u8]) -> &mut Tar {
        self.bytes.extend_from_slice(&header.build());
        self.bytes.extend_from_slice(data);
        let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
        self.bytes.extend(std::iter::repeat_n(0, pad));
        self
    }

    /// Appends a regular file.
    pub(super) fn file(&mut self, name: &str, data: &[u8]) -> &mut Tar {
        self.entry(&Header::file(name, data.len()), data)
    }

    /// Appends a header with no data.
    pub(super) fn header(&mut self, header: &Header) -> &mut Tar {
        self.entry(header, &[])
    }

    /// Appends an extension record of type `flag` carrying `payload`.
    pub(super) fn extension(&mut self, flag: u8, payload: &[u8]) -> &mut Tar {
        let name: &[u8] = if flag == b'x' || flag == b'g' {
            b"PaxHeader"
        } else {
            b"././@LongLink"
        };
        let mut header = Header::new(flag, name, u64::try_from(payload.len()).unwrap());
        if flag == b'L' || flag == b'K' {
            header.gnu();
        }
        self.entry(&header, payload)
    }

    /// Appends the two-block end-of-archive marker and returns the stream.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        self.bytes.extend_from_slice(&[0; 2 * BLOCK]);
        std::mem::take(&mut self.bytes)
    }

    /// Returns the stream as it stands, with no end marker.
    pub(super) fn unfinished(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

/// A layer tar holding one regular file.
pub(super) fn layer_tar(name: &str, content: &[u8]) -> Vec<u8> {
    Tar::new().file(name, content).finish()
}

/// A layer blob, the tar it decodes to, and its media type.
#[derive(Clone)]
pub(super) struct Layer {
    pub(super) blob: Vec<u8>,
    pub(super) diff_id: String,
    pub(super) media_type: String,
}

impl Layer {
    /// An uncompressed layer.
    pub(super) fn plain(tar: &[u8]) -> Layer {
        Layer {
            blob: tar.to_vec(),
            diff_id: digest(tar),
            media_type: LAYER_TAR.to_string(),
        }
    }

    /// A gzip layer.
    pub(super) fn gzip(tar: &[u8]) -> Layer {
        Layer {
            blob: gzip(tar),
            diff_id: digest(tar),
            media_type: LAYER_GZIP.to_string(),
        }
    }

    /// A layer whose blob and diff ID are set independently.
    pub(super) fn raw(blob: Vec<u8>, diff_id: String, media_type: &str) -> Layer {
        Layer {
            blob,
            diff_id,
            media_type: media_type.to_string(),
        }
    }
}

/// A document an [`ImageBuilder`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Doc {
    OciLayout,
    Index,
    Compat,
    Manifest,
    Config,
}

/// One entry of the image tar.
#[derive(Clone)]
pub(super) struct Entry {
    pub(super) header: Header,
    pub(super) data: Vec<u8>,
}

impl Entry {
    pub(super) fn file(name: &str, data: Vec<u8>) -> Entry {
        Entry {
            header: Header::file(name, data.len()),
            data,
        }
    }

    pub(super) fn dir(name: &str) -> Entry {
        Entry {
            header: Header::dir(name),
            data: Vec::new(),
        }
    }

    /// Returns the name field up to its first NUL.
    pub(super) fn name(&self) -> String {
        let name = &self.header.block[..100];
        let end = name.iter().position(|byte| *byte == 0).unwrap_or(100);
        String::from_utf8_lossy(&name[..end]).into_owned()
    }
}

type JsonEdit = Box<dyn FnOnce(&mut Value)>;
type BytesEdit = Box<dyn FnOnce(&mut Vec<u8>)>;
type EntriesEdit = Box<dyn FnOnce(&mut Vec<Entry>, &Parts)>;

/// What a build produced before the tar was assembled, for edits that need
/// to name the blobs.
pub(super) struct Parts {
    pub(super) manifest_hex: String,
    pub(super) config_hex: String,
    pub(super) layer_hexes: Vec<String>,
}

/// Builds an image archive the validator accepts, then applies each edit in
/// the order the parts are built.
pub(super) struct ImageBuilder {
    tags: Vec<String>,
    layers: Vec<Layer>,
    positions: Option<Vec<usize>>,
    architecture: ImageArchitecture,
    variant: Option<String>,
    json_edits: Vec<(Doc, JsonEdit)>,
    bytes_edits: Vec<(Doc, BytesEdit)>,
    entries_edits: Vec<EntriesEdit>,
    tail_edits: Vec<BytesEdit>,
}

/// A built archive and the declaration it matches.
pub(super) struct Built {
    pub(super) bytes: Vec<u8>,
    pub(super) declaration: ImageDeclaration,
    pub(super) config_digest: String,
    pub(super) manifest_digest: String,
    /// Number of layer positions specified by the builder, including repeats.
    pub(super) layer_count: usize,
    pub(super) parts: Parts,
}

impl Default for ImageBuilder {
    fn default() -> Self {
        ImageBuilder::new()
    }
}

impl ImageBuilder {
    /// One tag, one gzip layer, amd64 with no variant.
    pub(super) fn new() -> ImageBuilder {
        ImageBuilder {
            tags: vec!["example.com/app:1.0".to_string()],
            layers: vec![Layer::gzip(&layer_tar("hello.txt", b"hello"))],
            positions: None,
            architecture: ImageArchitecture::Amd64,
            variant: None,
            json_edits: Vec::new(),
            bytes_edits: Vec::new(),
            entries_edits: Vec::new(),
            tail_edits: Vec::new(),
        }
    }

    pub(super) fn tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(ToString::to_string).collect();
        self
    }

    /// Sets the distinct layer blobs; each is used once, in order, unless
    /// [`positions`](Self::positions) says otherwise.
    pub(super) fn layers(mut self, layers: Vec<Layer>) -> Self {
        self.layers = layers;
        self
    }

    /// Sets which distinct layer each manifest position uses.
    pub(super) fn positions(mut self, positions: &[usize]) -> Self {
        self.positions = Some(positions.to_vec());
        self
    }

    pub(super) fn platform(
        mut self,
        architecture: ImageArchitecture,
        variant: Option<&str>,
    ) -> Self {
        self.architecture = architecture;
        self.variant = variant.map(ToString::to_string);
        self
    }

    /// Edits a document as JSON before it is serialized and hashed.
    pub(super) fn json(mut self, doc: Doc, edit: impl FnOnce(&mut Value) + 'static) -> Self {
        self.json_edits.push((doc, Box::new(edit)));
        self
    }

    /// Edits a document's serialized bytes before they are hashed.
    pub(super) fn bytes(mut self, doc: Doc, edit: impl FnOnce(&mut Vec<u8>) + 'static) -> Self {
        self.bytes_edits.push((doc, Box::new(edit)));
        self
    }

    /// Replaces a document's bytes outright.
    pub(super) fn raw(self, doc: Doc, bytes: &[u8]) -> Self {
        let bytes = bytes.to_vec();
        self.bytes(doc, move |current| *current = bytes)
    }

    /// Edits the list of image tar entries before it is written.
    pub(super) fn entries(mut self, edit: impl FnOnce(&mut Vec<Entry>, &Parts) + 'static) -> Self {
        self.entries_edits.push(Box::new(edit));
        self
    }

    /// Edits the finished image tar bytes, end marker included.
    pub(super) fn tail(mut self, edit: impl FnOnce(&mut Vec<u8>) + 'static) -> Self {
        self.tail_edits.push(Box::new(edit));
        self
    }

    fn finish_doc(&mut self, doc: Doc, mut value: Value) -> Vec<u8> {
        for (_, edit) in extract(&mut self.json_edits, doc) {
            edit(&mut value);
        }
        let mut bytes = serde_json::to_vec(&value).unwrap();
        for (_, edit) in extract(&mut self.bytes_edits, doc) {
            edit(&mut bytes);
        }
        bytes
    }

    // Each document is built in the order its digest is needed; splitting
    // them apart would only thread the digests through more signatures.
    #[allow(clippy::too_many_lines)]
    pub(super) fn build(mut self) -> Built {
        let positions = self
            .positions
            .clone()
            .unwrap_or_else(|| (0..self.layers.len()).collect());
        let used: Vec<&Layer> = positions.iter().map(|at| &self.layers[*at]).collect();
        let diff_ids: Vec<String> = used.iter().map(|layer| layer.diff_id.clone()).collect();
        let layer_descriptors: Vec<Value> = used
            .iter()
            .map(|layer| {
                json!({
                    "mediaType": layer.media_type,
                    "digest": digest(&layer.blob),
                    "size": layer.blob.len(),
                })
            })
            .collect();
        let layer_paths: Vec<String> = used
            .iter()
            .map(|layer| format!("blobs/sha256/{}", hex(&layer.blob)))
            .collect();
        let history: Vec<Value> = (0..positions.len())
            .map(|at| json!({ "created_by": format!("layer {at}") }))
            .collect();

        let mut config = json!({
            "architecture": self.architecture.to_string(),
            "os": "linux",
            "rootfs": { "type": "layers", "diff_ids": diff_ids },
            "history": history,
        });
        if let Some(variant) = &self.variant {
            config["variant"] = json!(variant);
        }
        let config = self.finish_doc(Doc::Config, config);
        let config_digest = digest(&config);

        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": config.len(),
            },
            "layers": layer_descriptors,
        });
        let manifest = self.finish_doc(Doc::Manifest, manifest);
        let manifest_digest = digest(&manifest);

        let descriptors: Vec<Value> = self
            .tags
            .iter()
            .map(|tag| {
                let short = tag.rsplit_once(':').map_or(tag.as_str(), |(_, tag)| tag);
                json!({
                    "mediaType": MANIFEST_MEDIA_TYPE,
                    "digest": manifest_digest,
                    "size": manifest.len(),
                    "annotations": {
                        "io.containerd.image.name": tag,
                        "org.opencontainers.image.ref.name": short,
                    },
                })
            })
            .collect();
        let index = json!({
            "schemaVersion": 2,
            "mediaType": INDEX_MEDIA_TYPE,
            "manifests": descriptors,
        });
        let index = self.finish_doc(Doc::Index, index);

        let compat = json!([{
            "Config": format!("blobs/sha256/{}", hex(&config)),
            "RepoTags": self.tags,
            "Layers": layer_paths,
        }]);
        let compat = self.finish_doc(Doc::Compat, compat);
        let layout = self.finish_doc(Doc::OciLayout, json!({ "imageLayoutVersion": "1.0.0" }));

        let parts = Parts {
            manifest_hex: hex(&manifest),
            config_hex: hex(&config),
            layer_hexes: self.layers.iter().map(|layer| hex(&layer.blob)).collect(),
        };
        let mut entries = vec![
            Entry::dir("blobs/"),
            Entry::dir("blobs/sha256/"),
            Entry::file(&format!("blobs/sha256/{}", parts.manifest_hex), manifest),
            Entry::file(&format!("blobs/sha256/{}", parts.config_hex), config),
        ];
        let mut written = Vec::new();
        for at in &positions {
            let layer = &self.layers[*at];
            let name = format!("blobs/sha256/{}", hex(&layer.blob));
            if !written.contains(&name) {
                entries.push(Entry::file(&name, layer.blob.clone()));
                written.push(name);
            }
        }
        entries.push(Entry::file("index.json", index));
        entries.push(Entry::file("manifest.json", compat));
        entries.push(Entry::file("oci-layout", layout));
        for edit in std::mem::take(&mut self.entries_edits) {
            edit(&mut entries, &parts);
        }
        let mut tar = Tar::new();
        for entry in &entries {
            tar.entry(&entry.header, &entry.data);
        }
        let mut bytes = tar.finish();
        for edit in std::mem::take(&mut self.tail_edits) {
            edit(&mut bytes);
        }

        let declaration = ImageDeclaration {
            schema: IMAGE_DECLARATION_SCHEMA,
            owner: ImageOwner {
                namespace: "example-product".to_string(),
                component: "example-app".to_string(),
            },
            dependency: "app".to_string(),
            public_refs: self.tags.clone(),
            platform: ImagePlatform {
                os: ImageOs::Linux,
                architecture: self.architecture,
                variant: self.variant.clone(),
            },
            config_digest: config_digest.clone(),
            reference_lifecycle: ReferenceLifecycle::SharedExternal,
            provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: "https://example.com/app.git".to_string(),
                commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            }),
        };
        Built {
            bytes,
            declaration,
            config_digest,
            manifest_digest,
            layer_count: positions.len(),
            parts,
        }
    }
}

/// Removes and returns every edit for `doc`, in the order they were added.
fn extract<E>(edits: &mut Vec<(Doc, E)>, doc: Doc) -> Vec<(Doc, E)> {
    let (matching, rest) = std::mem::take(edits)
        .into_iter()
        .partition(|(target, _)| *target == doc);
    *edits = rest;
    matching
}

/// Moves the entry named `name` to position `to`.
pub(super) fn move_entry(entries: &mut Vec<Entry>, name: &str, to: usize) {
    let from = entries
        .iter()
        .position(|entry| entry.name() == name)
        .unwrap_or_else(|| panic!("no entry {name}"));
    let entry = entries.remove(from);
    entries.insert(to, entry);
}

/// Removes the entry named `name`.
pub(super) fn remove_entry(entries: &mut Vec<Entry>, name: &str) {
    entries.retain(|entry| entry.name() != name);
}

/// Returns the entry named `name`.
pub(super) fn entry_mut<'a>(entries: &'a mut [Entry], name: &str) -> &'a mut Entry {
    entries
        .iter_mut()
        .find(|entry| entry.name() == name)
        .unwrap_or_else(|| panic!("no entry {name}"))
}

/// What a [`Source`] was asked for and gave.
#[derive(Debug, Default)]
pub(super) struct SourceLog {
    /// Bytes delivered, in total.
    pub(super) delivered: u64,
    /// How many seeks were made.
    pub(super) seeks: usize,
}

/// An in-memory `Read + Seek` source that logs what it delivers, and can fail
/// at an offset or shrink after a number of seeks.
pub(super) struct Source {
    inner: Cursor<Vec<u8>>,
    log: Rc<RefCell<SourceLog>>,
    fail_at: Option<(u64, ErrorKind)>,
    /// After this many seeks, the source ends at this length.
    shrink: Option<(usize, u64)>,
}

impl Source {
    pub(super) fn new(bytes: Vec<u8>) -> (Source, Rc<RefCell<SourceLog>>) {
        let log = Rc::new(RefCell::new(SourceLog::default()));
        (
            Source {
                inner: Cursor::new(bytes),
                log: Rc::clone(&log),
                fail_at: None,
                shrink: None,
            },
            log,
        )
    }

    /// Fails every read at or beyond `offset`.
    pub(super) fn fail_at(mut self, offset: u64, kind: ErrorKind) -> Source {
        self.fail_at = Some((offset, kind));
        self
    }

    /// Ends the source at `len` once `seeks` seeks have been made.
    pub(super) fn shrink_after(mut self, seeks: usize, len: u64) -> Source {
        self.shrink = Some((seeks, len));
        self
    }

    fn end(&self) -> u64 {
        let len = u64::try_from(self.inner.get_ref().len()).unwrap();
        match self.shrink {
            Some((seeks, shrunk)) if self.log.borrow().seeks >= seeks => shrunk.min(len),
            _ => len,
        }
    }
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let position = self.inner.position();
        if let Some((offset, kind)) = self.fail_at
            && position >= offset
        {
            return Err(io::Error::from(kind));
        }
        let mut limit = self.end().saturating_sub(position);
        if let Some((offset, _)) = self.fail_at {
            limit = limit.min(offset - position);
        }
        let len = buf.len().min(usize::try_from(limit).unwrap());
        let n = self.inner.read(&mut buf[..len])?;
        self.log.borrow_mut().delivered += u64::try_from(n).unwrap();
        Ok(n)
    }
}

impl Seek for Source {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.log.borrow_mut().seeks += 1;
        self.inner.seek(pos)
    }
}
