//! The byte-level check that a container image artifact's archive is the
//! image its signed [`ImageDeclaration`] describes.
//!
//! One representation is accepted: an OCI-layout, single-image `docker save`
//! tar carrying a Docker compatibility `manifest.json`, with uncompressed or
//! gzip layers. Whether an archive is accepted depends only on its bytes.
//!
//! [`validate_image_archive`] runs eight phases in a fixed order and returns
//! the first verdict:
//!
//! 1. **raw inventory** — the whole image tar is walked once, every blob's
//!    length and SHA-256 recorded, and any entry outside the layout noted;
//! 2. **documents** — `oci-layout`, `index.json`, `manifest.json` and the
//!    image manifest blob are read and held to their closed shapes;
//! 3. **compatibility links** — the compatibility record against the image
//!    manifest, and the blob set against what they reference;
//! 4. **tags** — `RepoTags` literally, and the index annotations by
//!    normalized identity, against the signed `public_refs`;
//! 5. **config** — its digest against the declaration, then its profile;
//! 6. **platform** — every stated platform against the declared one;
//! 7. **layers** — each position's stored blob, decoded tar and diff ID;
//! 8. **`LayerSources`** — against the manifest's layer descriptors.
//!
//! A structural, limit or I/O fault anywhere in phase 1 wins at once, since
//! nothing after it is safe to read otherwise; an entry outside the layout is
//! remembered and reported only once the walk has completed. Phases 2 through
//! 8 read only what they name, so reordering archive entries never changes
//! their verdict. Nothing here touches a registry, the network, Docker or the
//! host filesystem, and no buffer is ever the size of an image or a layer.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Read, Seek, SeekFrom};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{ImageDeclaration, ImageOs, NormalizedReference, parse_tagged_reference};
use crate::content::json::{parse, read_bounded};
use crate::content::{
    Budget, ContentFault, CountingReader, EntryKind, EntryPolicy, GzipDecoder, MalformedReason,
    TarField, TarWalker, UnsupportedFeature,
};
use crate::manifest::IMAGE_DIGEST_HEX_LEN;
use crate::package::{ContentLimits, LimitResource};
use crate::payload::to_hex;
use crate::verify::{
    BlobMismatchKind, BlobRole, ConfigField, GzipFault, GzipHeaderFault, ImageDocument,
    ImageVerifyError, InvalidArchiveReason, InvalidConfigReason, JsonFault, LayerMismatchKind,
    LayoutFile, PaxKey, PlatformFacet, PlatformLocation, ReferenceSource, TarFault, TarFeature,
    TarHeaderField, UnsupportedArchiveFeature,
};

mod documents;

use documents::{Compatibility, Descriptor, ImageManifest};

const OCI_LAYOUT_FILE: &str = "oci-layout";
const INDEX_FILE: &str = "index.json";
const COMPATIBILITY_FILE: &str = "manifest.json";
const BLOBS_DIR: &str = "blobs";
const BLOBS_SHA256_DIR: &str = "blobs/sha256";
const BLOB_PREFIX: &str = "blobs/sha256/";
const SHA256_PREFIX: &str = "sha256:";

/// Top-level files of the classic `docker save` layout.
const LEGACY_FILES: &[&str] = &["repositories", "VERSION"];
const JSON_SUFFIX: &str = ".json";

/// How many leading bytes the outer-compression probe reads.
const PROBE_LEN: usize = 4;
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];

/// The index descriptor annotations the profile admits.
const CONTAINERD_NAME_ANNOTATION: &str = "io.containerd.image.name";
const OCI_REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

const CONFIG_ARCHITECTURE: &str = "architecture";
const CONFIG_OS: &str = "os";
const CONFIG_VARIANT: &str = "variant";
const CONFIG_ROOTFS: &str = "rootfs";
const CONFIG_HISTORY: &str = "history";
const ROOTFS_TYPE: &str = "type";
const ROOTFS_LAYERS: &str = "layers";
const ROOTFS_DIFF_IDS: &str = "diff_ids";
const HISTORY_EMPTY_LAYER: &str = "empty_layer";

/// The message of a primitive fault a call site cannot raise. Reported as a
/// source failure rather than trusted to a panic.
const IMPOSSIBLE_FAULT: &str = "a content primitive reported a fault its call site cannot raise";

/// A summary of an image archive that passed validation, for the caller's
/// bookkeeping. It is not evidence: the evidence is the declaration it was
/// held against.
// Consumed by package verification, whose wiring lands separately; until
// then only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedImageArchive {
    /// The verified `sha256:` config digest.
    pub(crate) config_digest: String,
    /// The `sha256:` digest of the image manifest.
    pub(crate) manifest_digest: String,
    /// How many layer positions the image has.
    pub(crate) layer_count: usize,
    /// Every accepted regular file of the image tar, in archive order.
    pub(crate) entries: Vec<RecordedEntry>,
}

/// Where one accepted regular file of the image tar lies.
// Consumed by package verification, whose wiring lands separately; until
// then only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordedEntry {
    /// Its canonical name.
    pub(crate) name: String,
    /// Offset of its header block.
    pub(crate) header_offset: u64,
    /// Offset of its first data byte.
    pub(crate) data_offset: u64,
    /// Length of its data.
    pub(crate) data_len: u64,
}

/// Why [`validate_image_archive`] refused an archive.
// Consumed by package verification, whose wiring lands separately; until
// then only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum ImageArchiveFault {
    /// The archive is excluded from the profile, malformed, or disagrees with
    /// its declaration.
    Image(ImageVerifyError),
    /// Reading it would exceed a configured resource.
    LimitExceeded {
        /// The resource.
        resource: LimitResource,
        /// Its configured value.
        limit: u64,
    },
    /// The source failed during an allowed read, or ended before an entry
    /// the raw inventory recorded.
    Io(io::Error),
}

/// Validates the image archive in `source` against `declaration`.
///
/// `source` must not change between seeks: package verification passes a
/// retained, immutable snapshot. `archive_path` names the artifact in every
/// error. Every per-image budget is created here; `operation_decoded` is the
/// operation's shared `DecodedLayersPerOperation` budget and is charged for
/// every decoded layer position.
///
/// # Errors
///
/// Returns the first verdict in phase order, as the module documentation
/// states it.
// Consumed by package verification, whose wiring lands separately; until
// then only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_image_archive<R: Read + Seek>(
    mut source: R,
    declaration: &ImageDeclaration,
    archive_path: &str,
    limits: &ContentLimits,
    operation_decoded: &mut Budget,
) -> Result<ValidatedImageArchive, ImageArchiveFault> {
    validate(&mut source, declaration, limits, operation_decoded)
        .map_err(|verdict| verdict.into_fault(archive_path))
}

fn validate<R: Read + Seek>(
    source: &mut R,
    declaration: &ImageDeclaration,
    limits: &ContentLimits,
    operation_decoded: &mut Budget,
) -> Checked<ValidatedImageArchive> {
    let copy_buffer = limits.copy_buffer_len();

    // Phase 1.
    let inventory = raw_inventory(source, limits, copy_buffer)?;
    let mut reader = DocumentReader {
        source,
        limits,
        copy_buffer,
        total: Budget::new(limits.resource_limit(LimitResource::ImageJsonTotal)),
    };

    // Phase 2.
    let oci_layout = reader.read(inventory.oci_layout, ImageDocument::OciLayout)?;
    documents::oci_layout(&oci_layout)?;
    let index = reader.read(inventory.index, ImageDocument::Index)?;
    let index = documents::index(&index, limits)?;
    let compatibility = reader.read(
        inventory.compatibility,
        ImageDocument::CompatibilityManifest,
    )?;
    let compatibility = documents::compatibility(&compatibility, limits)?;
    let manifest_descriptor = index.first().ok_or_else(|| shape(ImageDocument::Index))?;
    let manifest_blob = inventory
        .blobs
        .get(manifest_descriptor.hex())
        .ok_or_else(|| {
            invalid(InvalidArchiveReason::MissingBlob {
                role: BlobRole::Manifest,
            })
        })?;
    check_blob(manifest_blob, manifest_descriptor, BlobRole::Manifest)?;
    let manifest = reader.read(manifest_blob.span, ImageDocument::ImageManifest)?;
    let manifest = documents::image_manifest(&manifest, limits)?;

    // Phase 3.
    let config_blob =
        compatibility_links(&inventory, manifest_descriptor, &compatibility, &manifest)?;

    // Phase 4.
    repo_tags(&compatibility.repo_tags, declaration)?;
    index_annotations(&index, declaration)?;

    // Phase 5.
    let config = config(
        &mut reader,
        config_blob,
        &manifest.config,
        declaration,
        limits,
    )?;

    // Phase 6.
    platforms(&config, &index, &manifest.config, declaration)?;

    // Phase 7.
    let mut budgets = LayerBudgets::new(limits);
    layers(
        reader.source,
        &inventory,
        &manifest.layers,
        &compatibility.layers,
        &config.diff_ids,
        limits,
        copy_buffer,
        &mut budgets,
        operation_decoded,
    )?;

    // Phase 8.
    layer_sources(&compatibility, &manifest.layers, &config.diff_ids)?;

    Ok(ValidatedImageArchive {
        config_digest: format!("{SHA256_PREFIX}{}", config_blob.sha256),
        manifest_digest: manifest_descriptor.digest.clone(),
        layer_count: manifest.layers.len(),
        entries: inventory.entries,
    })
}

// ---------------------------------------------------------------------------
// Verdicts and fault conversion
// ---------------------------------------------------------------------------

/// A verdict before it is given the artifact's `archive_path`.
#[derive(Debug)]
enum Verdict {
    Unsupported(UnsupportedArchiveFeature),
    Invalid(InvalidArchiveReason),
    Undeclared {
        reference: String,
        source: ReferenceSource,
    },
    Missing {
        reference: String,
        source: ReferenceSource,
    },
    ConfigDigest {
        declared: String,
        actual: String,
    },
    Platform {
        location: PlatformLocation,
        facet: PlatformFacet,
        declared: Option<String>,
        actual: Option<String>,
    },
    Layer {
        position: Option<usize>,
        kind: LayerMismatchKind,
        expected: Option<String>,
        actual: Option<String>,
    },
    Limit {
        resource: LimitResource,
        limit: u64,
    },
    Io(io::Error),
}

type Checked<T> = Result<T, Verdict>;

impl Verdict {
    fn into_fault(self, archive_path: &str) -> ImageArchiveFault {
        let archive_path = archive_path.to_string();
        let image = match self {
            Verdict::Limit { resource, limit } => {
                return ImageArchiveFault::LimitExceeded { resource, limit };
            }
            Verdict::Io(err) => return ImageArchiveFault::Io(err),
            Verdict::Unsupported(feature) => ImageVerifyError::UnsupportedArchive {
                archive_path,
                feature,
            },
            Verdict::Invalid(reason) => ImageVerifyError::InvalidArchive {
                archive_path,
                reason,
            },
            Verdict::Undeclared { reference, source } => ImageVerifyError::UndeclaredReference {
                archive_path,
                reference,
                source,
            },
            Verdict::Missing { reference, source } => ImageVerifyError::MissingReference {
                archive_path,
                reference,
                source,
            },
            Verdict::ConfigDigest { declared, actual } => ImageVerifyError::ConfigDigestMismatch {
                archive_path,
                declared,
                actual,
            },
            Verdict::Platform {
                location,
                facet,
                declared,
                actual,
            } => ImageVerifyError::ConfigPlatformMismatch {
                archive_path,
                location,
                facet,
                declared,
                actual,
            },
            Verdict::Layer {
                position,
                kind,
                expected,
                actual,
            } => ImageVerifyError::LayerMismatch {
                archive_path,
                position,
                kind,
                expected,
                actual,
            },
        };
        ImageArchiveFault::Image(image)
    }
}

fn invalid(reason: InvalidArchiveReason) -> Verdict {
    Verdict::Invalid(reason)
}

fn unsupported(feature: UnsupportedArchiveFeature) -> Verdict {
    Verdict::Unsupported(feature)
}

fn shape(document: ImageDocument) -> Verdict {
    invalid(InvalidArchiveReason::UnexpectedShape { document })
}

fn impossible() -> Verdict {
    Verdict::Io(io::Error::other(IMPOSSIBLE_FAULT))
}

/// Where a primitive fault was raised, which decides what it means.
#[derive(Clone, Copy)]
enum Site {
    /// The image-level walk of phase 1, the outer-compression probe included.
    ImageWalk,
    /// The layer walk at a position, and whether the gzip decoder raised the
    /// fault rather than the walker.
    LayerWalk { position: usize, decoder: bool },
    /// Reading or parsing one JSON document.
    Document(ImageDocument),
}

/// Converts a primitive fault raised at `site` into a verdict.
fn convert(fault: ContentFault, site: Site) -> Verdict {
    match fault {
        ContentFault::LimitExceeded { resource, limit } => Verdict::Limit { resource, limit },
        ContentFault::Io(err) => Verdict::Io(err),
        ContentFault::Malformed(reason) => malformed(reason, site),
        ContentFault::Unsupported(feature) => unsupported_content(feature, site),
    }
}

/// A tar reason either walk can raise, as the verdict of the walk it came
/// from.
fn tar(fault: TarFault, site: Site) -> Verdict {
    match site {
        Site::ImageWalk => invalid(InvalidArchiveReason::Tar { fault }),
        Site::LayerWalk {
            position,
            decoder: false,
        } => invalid(InvalidArchiveReason::LayerTar { position, fault }),
        Site::LayerWalk { decoder: true, .. } | Site::Document(_) => impossible(),
    }
}

/// A tar extension reason, which only the layer walk raises.
fn layer_tar(fault: TarFault, site: Site) -> Verdict {
    match site {
        Site::LayerWalk {
            position,
            decoder: false,
        } => invalid(InvalidArchiveReason::LayerTar { position, fault }),
        _ => impossible(),
    }
}

/// A gzip reason, which only the decoder raises.
fn gzip(fault: GzipFault, site: Site) -> Verdict {
    match site {
        Site::LayerWalk {
            position,
            decoder: true,
        } => invalid(InvalidArchiveReason::Gzip { position, fault }),
        _ => impossible(),
    }
}

/// A JSON reason, which only the document reader raises.
fn json(fault: Option<JsonFault>, site: Site) -> Verdict {
    match (site, fault) {
        (Site::Document(document), Some(fault)) => {
            invalid(InvalidArchiveReason::Json { document, fault })
        }
        (Site::Document(document), None) => shape(document),
        _ => impossible(),
    }
}

fn malformed(reason: MalformedReason, site: Site) -> Verdict {
    use MalformedReason as M;
    match reason {
        M::Truncated => match site {
            Site::LayerWalk { decoder: true, .. } => gzip(GzipFault::Truncated, site),
            _ => tar(TarFault::Truncated, site),
        },
        M::TarChecksum => tar(TarFault::Checksum, site),
        M::TarNumericField { field } => tar(
            TarFault::NumericField {
                field: header_field(field),
            },
            site,
        ),
        M::TarNameField { field } => tar(
            TarFault::NameField {
                field: header_field(field),
            },
            site,
        ),
        M::OffsetOverflow => tar(TarFault::OffsetOverflow, site),
        M::TrailingData => tar(TarFault::TrailingData, site),
        M::ZeroTailTooLong => tar(TarFault::ZeroTailTooLong, site),
        M::UnsafePath => tar(TarFault::UnsafePath, site),
        M::DuplicatePath => tar(TarFault::DuplicatePath, site),
        M::PathConflict => tar(TarFault::PathConflict, site),
        M::NonRegularWithData => tar(TarFault::NonRegularWithData, site),
        M::PaxRecord => layer_tar(TarFault::PaxRecord, site),
        M::PaxDuplicateKey => layer_tar(TarFault::PaxDuplicateKey, site),
        M::PaxValue { key } => layer_tar(TarFault::PaxValue { key: pax_key(key) }, site),
        M::ExtensionPayload => layer_tar(TarFault::ExtensionPayload, site),
        M::DuplicateExtension => layer_tar(TarFault::DuplicateExtension, site),
        M::ConflictingAuthority => layer_tar(TarFault::ConflictingAuthority, site),
        M::DanglingExtension => layer_tar(TarFault::DanglingExtension, site),
        M::LinkOnNonLink => layer_tar(TarFault::LinkOnNonLink, site),
        M::GzipHeader(fault) => gzip(
            GzipFault::Header {
                fault: gzip_header(fault),
            },
            site,
        ),
        M::DeflateData => gzip(GzipFault::Deflate, site),
        M::GzipCrc32 => gzip(GzipFault::Crc32, site),
        M::GzipIsize => gzip(GzipFault::Isize, site),
        M::GzipTrailingData => gzip(GzipFault::TrailingData, site),
        M::JsonSyntax => json(Some(JsonFault::Syntax), site),
        M::JsonDuplicateKey => json(Some(JsonFault::DuplicateKey), site),
        M::JsonShape => json(None, site),
    }
}

fn unsupported_content(feature: UnsupportedFeature, site: Site) -> Verdict {
    let tar_feature = |feature: TarFeature| match site {
        Site::ImageWalk => unsupported(UnsupportedArchiveFeature::ArchiveTar { feature }),
        Site::LayerWalk {
            position,
            decoder: false,
        } => unsupported(UnsupportedArchiveFeature::LayerTar { position, feature }),
        Site::LayerWalk { decoder: true, .. } | Site::Document(_) => impossible(),
    };
    match feature {
        UnsupportedFeature::TarFormat => tar_feature(TarFeature::Format),
        UnsupportedFeature::EntryType { flag } => tar_feature(TarFeature::EntryType { flag }),
        UnsupportedFeature::PaxKey => tar_feature(TarFeature::PaxKey),
        UnsupportedFeature::ConcatenatedGzipMember => match site {
            Site::LayerWalk {
                position,
                decoder: true,
            } => unsupported(UnsupportedArchiveFeature::ConcatenatedGzipMember { position }),
            _ => impossible(),
        },
    }
}

fn header_field(field: TarField) -> TarHeaderField {
    match field {
        TarField::Name => TarHeaderField::Name,
        TarField::Mode => TarHeaderField::Mode,
        TarField::Uid => TarHeaderField::Uid,
        TarField::Gid => TarHeaderField::Gid,
        TarField::Size => TarHeaderField::Size,
        TarField::Mtime => TarHeaderField::Mtime,
        TarField::Checksum => TarHeaderField::Checksum,
        TarField::Linkname => TarHeaderField::Linkname,
        TarField::DevMajor => TarHeaderField::DevMajor,
        TarField::DevMinor => TarHeaderField::DevMinor,
        TarField::Prefix => TarHeaderField::Prefix,
    }
}

fn pax_key(key: crate::content::PaxKey) -> PaxKey {
    use crate::content::PaxKey as K;
    match key {
        K::Path => PaxKey::Path,
        K::Linkpath => PaxKey::Linkpath,
        K::Size => PaxKey::Size,
        K::Uid => PaxKey::Uid,
        K::Gid => PaxKey::Gid,
        K::Uname => PaxKey::Uname,
        K::Gname => PaxKey::Gname,
        K::Mtime => PaxKey::Mtime,
        K::Atime => PaxKey::Atime,
        K::Ctime => PaxKey::Ctime,
        K::Xattr => PaxKey::Xattr,
    }
}

fn gzip_header(fault: crate::content::GzipHeaderFault) -> GzipHeaderFault {
    use crate::content::GzipHeaderFault as H;
    match fault {
        H::Magic => GzipHeaderFault::Magic,
        H::Method => GzipHeaderFault::Method,
        H::ReservedFlags => GzipHeaderFault::ReservedFlags,
        H::HeaderCrc => GzipHeaderFault::HeaderCrc,
    }
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// Serves the bytes the outer-compression probe already read, then the rest
/// of the stream, so every byte reaches the walker exactly once.
struct Replay<R> {
    prefix: [u8; PROBE_LEN],
    len: usize,
    served: usize,
    rest: R,
}

impl<R: Read> Read for Replay<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pending = self.prefix.get(self.served..self.len).unwrap_or_default();
        if pending.is_empty() {
            return self.rest.read(buf);
        }
        let n = pending.len().min(buf.len());
        if let (Some(out), Some(from)) = (buf.get_mut(..n), pending.get(..n)) {
            out.copy_from_slice(from);
        }
        self.served += n;
        Ok(n)
    }
}

/// Reads exactly one recorded range of the source, from wherever the source
/// was positioned. The source ending before the range does is a source
/// failure, since the raw inventory already saw those bytes.
struct Range<R> {
    source: R,
    remaining: u64,
    /// The layer position a phase-7 read is for, recorded by the test seam.
    #[cfg(test)]
    layer: Option<usize>,
}

impl<R> Range<R> {
    fn new(source: R, len: u64) -> Range<R> {
        Range {
            source,
            remaining: len,
            #[cfg(test)]
            layer: None,
        }
    }
}

impl<R: Read> Read for Range<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let len = crate::content::chunk_len(buf.len(), self.remaining);
        let window = buf.get_mut(..len).unwrap_or_default();
        let n = self.source.read(window)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the image archive ended inside an entry the raw inventory recorded",
            ));
        }
        let read = crate::content::widen(n);
        self.remaining = self.remaining.saturating_sub(read);
        #[cfg(test)]
        if let Some(position) = self.layer {
            seam::record(seam::Event::LayerRead { position, bytes: n });
        }
        Ok(n)
    }
}

/// Hashes every byte it passes on.
struct Tee<'h, R> {
    inner: R,
    hasher: &'h mut Sha256,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(buf.get(..n).unwrap_or_default());
        Ok(n)
    }
}

/// Sits directly on the gzip decoder's output and records whether the decoder
/// raised a fault, so a `Truncated` from it is told apart from one the walker
/// raises.
struct Origin<'c, R> {
    decoder: R,
    faulted: &'c Cell<bool>,
}

impl<R: Read> Read for Origin<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.decoder
            .read(buf)
            .inspect_err(|_| self.faulted.set(true))
    }
}

// ---------------------------------------------------------------------------
// Phase 1: raw inventory
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    offset: u64,
    len: u64,
}

struct Blob {
    span: Span,
    /// Lowercase hex SHA-256 of the stored bytes.
    sha256: String,
}

struct Inventory {
    oci_layout: Span,
    index: Span,
    compatibility: Span,
    /// Every `blobs/sha256/*` entry, by the hex of its name.
    blobs: BTreeMap<String, Blob>,
    entries: Vec<RecordedEntry>,
}

/// What an image tar entry is to the profile.
enum Class {
    Layout(LayoutFile),
    Blob,
    Directory,
    Deferred(UnsupportedArchiveFeature),
}

/// Whether `value` is 64 lowercase hex characters.
fn is_digest_hex(value: &str) -> bool {
    value.len() == IMAGE_DIGEST_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `value` is `sha256:` and 64 lowercase hex characters.
fn is_digest(value: &str) -> bool {
    value.strip_prefix(SHA256_PREFIX).is_some_and(is_digest_hex)
}

/// Classifies an image tar entry by its canonical name and kind.
fn classify(name: &str, kind: EntryKind) -> Class {
    let regular = kind == EntryKind::Regular;
    match name {
        OCI_LAYOUT_FILE if regular => return Class::Layout(LayoutFile::OciLayout),
        INDEX_FILE if regular => return Class::Layout(LayoutFile::Index),
        COMPATIBILITY_FILE if regular => {
            return Class::Layout(LayoutFile::CompatibilityManifest);
        }
        BLOBS_DIR | BLOBS_SHA256_DIR if kind == EntryKind::Directory => return Class::Directory,
        _ => {}
    }
    if regular && name.strip_prefix(BLOB_PREFIX).is_some_and(is_digest_hex) {
        return Class::Blob;
    }
    let first = name.split('/').next().unwrap_or_default();
    let legacy = LEGACY_FILES.contains(&name)
        || is_digest_hex(first)
        || name.strip_suffix(JSON_SUFFIX).is_some_and(is_digest_hex);
    Class::Deferred(if legacy {
        UnsupportedArchiveFeature::LegacyExportFile
    } else {
        UnsupportedArchiveFeature::ExtraFile
    })
}

/// Probes for a compressed outer stream, then walks the whole image tar,
/// recording every layout file and blob.
fn raw_inventory<R: Read + Seek>(
    source: &mut R,
    limits: &ContentLimits,
    copy_buffer: usize,
) -> Checked<Inventory> {
    let image = |fault: ContentFault| convert(fault, Site::ImageWalk);
    let from_io = |err: io::Error| image(ContentFault::from_io(err));
    source.seek(SeekFrom::Start(0)).map_err(Verdict::Io)?;
    let archive_limit = limits.resource_limit(LimitResource::ImageArchive);
    let mut counted = CountingReader::new(&mut *source, archive_limit, Vec::new(), copy_buffer);
    let (prefix, len) = probe(&mut counted)?;
    let replay = Replay {
        prefix,
        len,
        served: 0,
        rest: counted,
    };
    // The walker takes its source as a counting reader. This one mirrors the
    // `ImageArchive` limit over exactly the bytes `counted` charged — the
    // replayed prefix and then the rest — so it can never fault ahead of it,
    // and its pre-checks of an entry's advertised length answer as `counted`
    // would.
    let mirror = CountingReader::new(replay, archive_limit, Vec::new(), copy_buffer);
    let mut walker = TarWalker::new(mirror, EntryPolicy::ImageArchive, limits);

    let mut deferred = None;
    let mut layout = [None; 3];
    let mut blobs = BTreeMap::new();
    let mut entries = Vec::new();
    let mut buffer = Vec::new();
    while let Some(entry) = walker.next_entry().map_err(image)? {
        if deferred.is_some() {
            continue;
        }
        // The image-archive policy admits ASCII names only.
        let Ok(name) = std::str::from_utf8(entry.canonical_name()).map(str::to_string) else {
            deferred = Some(UnsupportedArchiveFeature::ExtraFile);
            continue;
        };
        let span = Span {
            offset: entry.data_offset,
            len: entry.data_len,
        };
        match classify(&name, entry.kind) {
            Class::Deferred(feature) => {
                deferred = Some(feature);
                continue;
            }
            Class::Directory => continue,
            Class::Layout(file) => {
                if let Some(slot) = layout.get_mut(layout_slot(file)) {
                    *slot = Some(span);
                }
            }
            Class::Blob => {
                if buffer.is_empty() {
                    buffer = vec![0u8; copy_buffer];
                    #[cfg(test)]
                    seam::record(seam::Event::Buffer(copy_buffer));
                }
                let sha256 = hash_data(&mut walker.entry_reader(), &mut buffer).map_err(from_io)?;
                let hex = name
                    .strip_prefix(BLOB_PREFIX)
                    .unwrap_or_default()
                    .to_string();
                #[cfg(test)]
                seam::record(seam::Event::InventoryBlob(hex.clone()));
                blobs.insert(hex, Blob { span, sha256 });
            }
        }
        entries.push(RecordedEntry {
            name,
            header_offset: entry.header_offset,
            data_offset: entry.data_offset,
            data_len: entry.data_len,
        });
    }
    if let Some(feature) = deferred {
        return Err(unsupported(feature));
    }
    let [oci_layout, index, compatibility] = layout;
    let missing = |file| invalid(InvalidArchiveReason::MissingLayoutFile { file });
    Ok(Inventory {
        oci_layout: oci_layout.ok_or_else(|| missing(LayoutFile::OciLayout))?,
        index: index.ok_or_else(|| missing(LayoutFile::Index))?,
        compatibility: compatibility.ok_or_else(|| missing(LayoutFile::CompatibilityManifest))?,
        blobs,
        entries,
    })
}

/// Reads up to [`PROBE_LEN`] bytes through `counted` and refuses a gzip or
/// zstd outer stream, returning what it read.
fn probe<R: Read>(counted: &mut CountingReader<'_, R>) -> Checked<([u8; PROBE_LEN], usize)> {
    let from_io = |err: io::Error| convert(ContentFault::from_io(err), Site::ImageWalk);
    let mut prefix = [0u8; PROBE_LEN];
    let mut len = 0;
    while let Some(rest) = prefix.get_mut(len..).filter(|rest| !rest.is_empty()) {
        let n = counted.read(rest).map_err(from_io)?;
        if n == 0 {
            break;
        }
        len += n;
    }
    let probed = prefix.get(..len).unwrap_or_default();
    if probed.starts_with(GZIP_MAGIC) || probed.starts_with(ZSTD_MAGIC) {
        return Err(unsupported(
            UnsupportedArchiveFeature::CompressedOuterStream,
        ));
    }
    Ok((prefix, len))
}

/// Streams `data` through `buffer` and returns its hex SHA-256.
fn hash_data<R: Read>(data: &mut R, buffer: &mut [u8]) -> io::Result<String> {
    let mut hasher = Sha256::new();
    loop {
        let n = data.read(buffer)?;
        if n == 0 {
            return Ok(to_hex(&hasher.finalize()));
        }
        hasher.update(buffer.get(..n).unwrap_or_default());
    }
}

fn layout_slot(file: LayoutFile) -> usize {
    match file {
        LayoutFile::OciLayout => 0,
        LayoutFile::Index => 1,
        LayoutFile::CompatibilityManifest => 2,
    }
}

// ---------------------------------------------------------------------------
// Phase 2: documents
// ---------------------------------------------------------------------------

/// Reads JSON documents from recorded ranges, charging each to its own
/// resource and to the image's `ImageJsonTotal`.
struct DocumentReader<'a, R> {
    source: &'a mut R,
    limits: &'a ContentLimits,
    copy_buffer: usize,
    total: Budget,
}

impl<R: Read + Seek> DocumentReader<'_, R> {
    fn read(&mut self, span: Span, document: ImageDocument) -> Checked<Value> {
        let site = Site::Document(document);
        let limit = self.limits.resource_limit(match document {
            ImageDocument::OciLayout => LimitResource::OciLayout,
            ImageDocument::Index => LimitResource::IndexJson,
            ImageDocument::CompatibilityManifest => LimitResource::CompatibilityJson,
            ImageDocument::ImageManifest => LimitResource::ImageManifestJson,
            ImageDocument::Config => LimitResource::ConfigJson,
        });
        self.source
            .seek(SeekFrom::Start(span.offset))
            .map_err(Verdict::Io)?;
        let range = Range::new(&mut *self.source, span.len);
        let bytes = read_bounded(range, limit, &mut self.total, self.copy_buffer)
            .map_err(|fault| convert(fault, site))?;
        parse(
            &bytes,
            limit,
            self.limits.resource_limit(LimitResource::JsonDepth),
        )
        .map_err(|fault| convert(fault, site))
    }
}

/// Checks a stored blob's recorded length, then its digest, against its
/// descriptor.
fn check_blob(blob: &Blob, descriptor: &Descriptor, role: BlobRole) -> Checked<()> {
    let mismatch = |kind| invalid(InvalidArchiveReason::BlobMismatch { role, kind });
    if blob.span.len != descriptor.size {
        return Err(mismatch(BlobMismatchKind::Length));
    }
    if blob.sha256 != descriptor.hex() {
        return Err(mismatch(BlobMismatchKind::Digest));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 3: compatibility links and blob set
// ---------------------------------------------------------------------------

/// Checks the compatibility record's links and the blob set, returning the
/// config blob.
fn compatibility_links<'i>(
    inventory: &'i Inventory,
    manifest_descriptor: &Descriptor,
    compatibility: &Compatibility,
    manifest: &ImageManifest,
) -> Checked<&'i Blob> {
    let inconsistent = || invalid(InvalidArchiveReason::InconsistentCompatibility);
    if compatibility.config != manifest.config.blob_path() {
        return Err(inconsistent());
    }
    if compatibility.layers.len() != manifest.layers.len()
        || compatibility
            .layers
            .iter()
            .zip(&manifest.layers)
            .any(|(path, layer)| *path != layer.blob_path())
    {
        return Err(inconsistent());
    }
    // Where a path repeats, so must its descriptor. The first use of each path
    // is kept, in order, for the membership check below.
    let mut first_use: Vec<(&str, usize)> = Vec::new();
    for (position, layer) in manifest.layers.iter().enumerate() {
        match first_use.iter().find(|(hex, _)| *hex == layer.hex()) {
            Some((_, first)) => {
                if manifest.layers.get(*first) != Some(layer) {
                    return Err(inconsistent());
                }
            }
            None => first_use.push((layer.hex(), position)),
        }
    }
    let config = inventory.blobs.get(manifest.config.hex()).ok_or_else(|| {
        invalid(InvalidArchiveReason::MissingBlob {
            role: BlobRole::Config,
        })
    })?;
    for (hex, position) in &first_use {
        if !inventory.blobs.contains_key(*hex) {
            return Err(invalid(InvalidArchiveReason::MissingBlob {
                role: BlobRole::Layer {
                    position: *position,
                },
            }));
        }
    }
    let referenced: HashSet<&str> = first_use
        .iter()
        .map(|(hex, _)| *hex)
        .chain([manifest_descriptor.hex(), manifest.config.hex()])
        .collect();
    if inventory
        .blobs
        .keys()
        .any(|hex| !referenced.contains(hex.as_str()))
    {
        return Err(unsupported(UnsupportedArchiveFeature::UnreferencedBlob));
    }
    Ok(config)
}

// ---------------------------------------------------------------------------
// Phase 4: tags
// ---------------------------------------------------------------------------

/// Reports the byte-wise smallest of `missing` and `extra`, as missing or
/// undeclared.
fn first_difference<'a>(
    missing: impl Iterator<Item = &'a str>,
    extra: impl Iterator<Item = &'a str>,
    source: ReferenceSource,
) -> Checked<()> {
    let missing = missing.min();
    let extra = extra.min();
    match (missing, extra) {
        (Some(missing), Some(extra)) if extra < missing => Err(Verdict::Undeclared {
            reference: extra.to_string(),
            source,
        }),
        (Some(missing), _) => Err(Verdict::Missing {
            reference: missing.to_string(),
            source,
        }),
        (None, Some(extra)) => Err(Verdict::Undeclared {
            reference: extra.to_string(),
            source,
        }),
        (None, None) => Ok(()),
    }
}

/// Checks `RepoTags` literally against the signed `public_refs`.
fn repo_tags(tags: &[String], declaration: &ImageDeclaration) -> Checked<()> {
    if let Some(index) = tags
        .iter()
        .position(|tag| parse_tagged_reference(tag).is_err())
    {
        return Err(invalid(InvalidArchiveReason::InvalidRepoTag { index }));
    }
    let mut seen = HashSet::new();
    if !tags.iter().all(|tag| seen.insert(tag.as_str())) {
        return Err(invalid(InvalidArchiveReason::DuplicateTag {
            source: ReferenceSource::RepoTags,
        }));
    }
    let declared: HashSet<&str> = declaration.public_refs.iter().map(String::as_str).collect();
    first_difference(
        declaration
            .public_refs
            .iter()
            .map(String::as_str)
            .filter(|reference| !seen.contains(reference)),
        tags.iter()
            .map(String::as_str)
            .filter(|tag| !declared.contains(tag)),
        ReferenceSource::RepoTags,
    )
}

/// Checks the index descriptors' reference annotations, by normalized
/// identity, against the signed `public_refs`.
fn index_annotations(index: &[Descriptor], declaration: &ImageDeclaration) -> Checked<()> {
    let mut named: Vec<(NormalizedReference, &str)> = Vec::with_capacity(index.len());
    for (position, descriptor) in index.iter().enumerate() {
        let annotations = descriptor.annotations.as_ref();
        if annotations.is_some_and(|annotations| {
            annotations
                .keys()
                .any(|key| key != CONTAINERD_NAME_ANNOTATION && key != OCI_REF_NAME_ANNOTATION)
        }) {
            return Err(unsupported(UnsupportedArchiveFeature::DescriptorAnnotation));
        }
        let invalid_annotation =
            || invalid(InvalidArchiveReason::InvalidAnnotation { index: position });
        let annotation = |key: &str| {
            annotations
                .and_then(|annotations| annotations.get(key))
                .and_then(Value::as_str)
        };
        let name = annotation(CONTAINERD_NAME_ANNOTATION).ok_or_else(invalid_annotation)?;
        let normalized = parse_tagged_reference(name).map_err(|_| invalid_annotation())?;
        if let Some(ref_name) = annotation(OCI_REF_NAME_ANNOTATION)
            && ref_name != normalized.tag
            && parse_tagged_reference(ref_name).ok().as_ref() != Some(&normalized)
        {
            return Err(invalid_annotation());
        }
        named.push((normalized, name));
    }
    let mut seen = HashSet::new();
    if !named.iter().all(|(normalized, _)| seen.insert(normalized)) {
        return Err(invalid(InvalidArchiveReason::DuplicateTag {
            source: ReferenceSource::IndexAnnotation,
        }));
    }
    let declared: Vec<(NormalizedReference, &str)> = declaration
        .public_refs
        .iter()
        .filter_map(|reference| {
            parse_tagged_reference(reference)
                .ok()
                .map(|normalized| (normalized, reference.as_str()))
        })
        .collect();
    let declared_set: HashSet<&NormalizedReference> =
        declared.iter().map(|(normalized, _)| normalized).collect();
    first_difference(
        declared
            .iter()
            .filter(|(normalized, _)| !seen.contains(normalized))
            .map(|(_, literal)| *literal),
        named
            .iter()
            .filter(|(normalized, _)| !declared_set.contains(normalized))
            .map(|(_, literal)| *literal),
        ReferenceSource::IndexAnnotation,
    )
}

// ---------------------------------------------------------------------------
// Phase 5: config
// ---------------------------------------------------------------------------

/// The config values the profile checks.
struct ConfigProfile {
    os: String,
    architecture: String,
    variant: Option<String>,
    diff_ids: Vec<String>,
}

fn config<R: Read + Seek>(
    reader: &mut DocumentReader<'_, R>,
    blob: &Blob,
    descriptor: &Descriptor,
    declaration: &ImageDeclaration,
    limits: &ContentLimits,
) -> Checked<ConfigProfile> {
    let actual = format!("{SHA256_PREFIX}{}", blob.sha256);
    if actual != declaration.config_digest {
        return Err(Verdict::ConfigDigest {
            declared: declaration.config_digest.clone(),
            actual,
        });
    }
    check_blob(blob, descriptor, BlobRole::Config)?;
    let value = reader.read(blob.span, ImageDocument::Config)?;
    config_profile(&value, limits)
}

/// Checks the config against the open config profile.
fn config_profile(value: &Value, limits: &ContentLimits) -> Checked<ConfigProfile> {
    let refuse = |reason| invalid(InvalidArchiveReason::InvalidConfig { reason });
    let object = value
        .as_object()
        .ok_or_else(|| refuse(InvalidConfigReason::NotObject))?;
    let missing = |field| refuse(InvalidConfigReason::MissingField { field });
    let wrong_type = |field| refuse(InvalidConfigReason::FieldType { field });
    let required_string = |key: &str, field| match object.get(key) {
        None => Err(missing(field)),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(wrong_type(field)),
    };
    let architecture = required_string(CONFIG_ARCHITECTURE, ConfigField::Architecture)?;
    let os = required_string(CONFIG_OS, ConfigField::Os)?;
    let variant = match object.get(CONFIG_VARIANT) {
        None | Some(Value::Null) => None,
        Some(Value::String(variant)) if variant.is_empty() => {
            return Err(refuse(InvalidConfigReason::EmptyVariant));
        }
        Some(Value::String(variant)) => Some(variant.clone()),
        Some(_) => return Err(wrong_type(ConfigField::Variant)),
    };
    let rootfs = match object.get(CONFIG_ROOTFS) {
        None => return Err(missing(ConfigField::Rootfs)),
        Some(Value::Object(rootfs)) => rootfs,
        Some(_) => return Err(wrong_type(ConfigField::Rootfs)),
    };
    let history = match object.get(CONFIG_HISTORY) {
        None => None,
        Some(Value::Array(history)) => Some(history),
        Some(_) => return Err(wrong_type(ConfigField::History)),
    };

    let diff_ids = rootfs
        .get(ROOTFS_DIFF_IDS)
        .and_then(Value::as_array)
        .filter(|_| {
            rootfs.len() == 2
                && rootfs.get(ROOTFS_TYPE).and_then(Value::as_str) == Some(ROOTFS_LAYERS)
        })
        .ok_or_else(|| refuse(InvalidConfigReason::RootfsShape))?;
    documents::check_count(diff_ids.len(), limits, LimitResource::LayersPerImage)?;
    let diff_ids = diff_ids
        .iter()
        .enumerate()
        .map(|(index, diff_id)| {
            diff_id
                .as_str()
                .filter(|diff_id| is_digest(diff_id))
                .map(str::to_string)
                .ok_or_else(|| refuse(InvalidConfigReason::DiffIdSyntax { index }))
        })
        .collect::<Checked<Vec<_>>>()?;

    if let Some(history) = history {
        let mut layers = 0usize;
        for (index, entry) in history.iter().enumerate() {
            let empty = match entry
                .as_object()
                .map(|entry| entry.get(HISTORY_EMPTY_LAYER))
            {
                Some(None) => false,
                Some(Some(Value::Bool(empty))) => *empty,
                _ => return Err(refuse(InvalidConfigReason::HistoryEntryShape { index })),
            };
            if !empty {
                layers += 1;
            }
        }
        if layers != diff_ids.len() {
            return Err(refuse(InvalidConfigReason::HistoryLayerCount));
        }
    }
    Ok(ConfigProfile {
        os,
        architecture,
        variant,
        diff_ids,
    })
}

// ---------------------------------------------------------------------------
// Phase 6: platform
// ---------------------------------------------------------------------------

fn platforms(
    config: &ConfigProfile,
    index: &[Descriptor],
    config_descriptor: &Descriptor,
    declaration: &ImageDeclaration,
) -> Checked<()> {
    compare_platform(
        PlatformLocation::Config,
        &config.os,
        &config.architecture,
        config.variant.as_deref(),
        declaration,
    )?;
    for (position, descriptor) in index.iter().enumerate() {
        if let Some(platform) = &descriptor.platform {
            compare_platform(
                PlatformLocation::IndexDescriptor { index: position },
                &platform.os,
                &platform.architecture,
                platform.variant.as_deref(),
                declaration,
            )?;
        }
    }
    if let Some(platform) = &config_descriptor.platform {
        compare_platform(
            PlatformLocation::ConfigDescriptor,
            &platform.os,
            &platform.architecture,
            platform.variant.as_deref(),
            declaration,
        )?;
    }
    Ok(())
}

/// Compares one stated platform with the declared one, facet by facet and
/// byte for byte. An absent or null variant matches only a signed null.
fn compare_platform(
    location: PlatformLocation,
    os: &str,
    architecture: &str,
    variant: Option<&str>,
    declaration: &ImageDeclaration,
) -> Checked<()> {
    let declared_os = match declaration.platform.os {
        ImageOs::Linux => "linux",
    };
    let declared_architecture = declaration.platform.architecture.to_string();
    let declared_variant = declaration.platform.variant.as_deref();
    let mismatch = |facet, declared: Option<&str>, actual: Option<&str>| Verdict::Platform {
        location,
        facet,
        declared: declared.map(str::to_string),
        actual: actual.map(str::to_string),
    };
    if os != declared_os {
        return Err(mismatch(PlatformFacet::Os, Some(declared_os), Some(os)));
    }
    if architecture != declared_architecture {
        return Err(mismatch(
            PlatformFacet::Architecture,
            Some(&declared_architecture),
            Some(architecture),
        ));
    }
    if variant != declared_variant {
        return Err(mismatch(PlatformFacet::Variant, declared_variant, variant));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 7: ordered layers
// ---------------------------------------------------------------------------

/// The per-image budgets every layer walk shares.
struct LayerBudgets {
    decoded: Budget,
    entries: Budget,
    extension_total: Budget,
}

impl LayerBudgets {
    fn new(limits: &ContentLimits) -> LayerBudgets {
        LayerBudgets {
            decoded: Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerImage)),
            entries: Budget::new(limits.resource_limit(LimitResource::LayerEntries)),
            extension_total: Budget::new(limits.resource_limit(LimitResource::LayerExtensionTotal)),
        }
    }
}

// Phase 7 needs the source, the three views of the layers, the limits and the
// two tiers of budgets; bundling them into a struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn layers<R: Read + Seek>(
    source: &mut R,
    inventory: &Inventory,
    descriptors: &[Descriptor],
    paths: &[String],
    diff_ids: &[String],
    limits: &ContentLimits,
    copy_buffer: usize,
    budgets: &mut LayerBudgets,
    operation: &mut Budget,
) -> Checked<()> {
    if paths.len() != diff_ids.len() {
        return Err(Verdict::Layer {
            position: None,
            kind: LayerMismatchKind::CountMismatch,
            expected: Some(diff_ids.len().to_string()),
            actual: Some(paths.len().to_string()),
        });
    }
    for (position, (descriptor, diff_id)) in descriptors.iter().zip(diff_ids).enumerate() {
        let role = BlobRole::Layer { position };
        let blob = inventory
            .blobs
            .get(descriptor.hex())
            .ok_or_else(|| invalid(InvalidArchiveReason::MissingBlob { role }))?;
        if blob.span.len != descriptor.size {
            return Err(invalid(InvalidArchiveReason::BlobMismatch {
                role,
                kind: BlobMismatchKind::Length,
            }));
        }
        if blob.sha256 != descriptor.hex() {
            return Err(Verdict::Layer {
                position: Some(position),
                kind: LayerMismatchKind::StoredDigest,
                expected: Some(descriptor.digest.clone()),
                actual: Some(format!("{SHA256_PREFIX}{}", blob.sha256)),
            });
        }
        let compressed = descriptor.media_type == documents::OCI_GZIP_LAYER_MEDIA_TYPE;
        let computed = format!(
            "{SHA256_PREFIX}{}",
            decode_layer(
                source,
                blob.span,
                compressed,
                position,
                limits,
                copy_buffer,
                budgets,
                operation
            )?
        );
        if computed != *diff_id {
            return Err(Verdict::Layer {
                position: Some(position),
                kind: LayerMismatchKind::DiffId,
                expected: Some(diff_id.clone()),
                actual: Some(computed),
            });
        }
    }
    Ok(())
}

/// Decodes and walks the layer at `position` to its end, returning the hex
/// SHA-256 of its decoded tar stream. Every reader and decoder it builds is
/// dropped before it returns.
// The same bundle of inputs as `layers`, for one position.
#[allow(clippy::too_many_arguments)]
fn decode_layer<R: Read + Seek>(
    source: &mut R,
    span: Span,
    compressed: bool,
    position: usize,
    limits: &ContentLimits,
    copy_buffer: usize,
    budgets: &mut LayerBudgets,
    operation: &mut Budget,
) -> Checked<String> {
    #[cfg(test)]
    seam::record(seam::Event::LayerOpened(position));
    source
        .seek(SeekFrom::Start(span.offset))
        .map_err(Verdict::Io)?;
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut range = Range::new(&mut *source, span.len);
    #[cfg(test)]
    {
        range.layer = Some(position);
    }
    let stored = CountingReader::new(
        range,
        limits.resource_limit(LimitResource::StoredLayerBlob),
        Vec::new(),
        copy_buffer,
    );
    let decoder_faulted = Cell::new(false);
    let mut hasher = Sha256::new();
    let walked = if compressed {
        #[cfg(test)]
        seam::record(seam::Event::LayerDecoded(position));
        let decoder = GzipDecoder::new(
            stored,
            limits.resource_limit(LimitResource::GzipHeader),
            copy_buffer,
        );
        let watched = Origin {
            decoder,
            faulted: &decoder_faulted,
        };
        walk_layer(
            Tee {
                inner: watched,
                hasher: &mut hasher,
            },
            limits,
            copy_buffer,
            budgets,
            operation,
        )
    } else {
        walk_layer(
            Tee {
                inner: stored,
                hasher: &mut hasher,
            },
            limits,
            copy_buffer,
            budgets,
            operation,
        )
    };
    walked.map_err(|fault| {
        convert(
            fault,
            Site::LayerWalk {
                position,
                decoder: decoder_faulted.get(),
            },
        )
    })?;
    Ok(to_hex(&hasher.finalize()))
}

/// Walks one decoded layer tar until the walker has verified its end.
fn walk_layer<R: Read>(
    decoded: R,
    limits: &ContentLimits,
    copy_buffer: usize,
    budgets: &mut LayerBudgets,
    operation: &mut Budget,
) -> Result<(), ContentFault> {
    let counted = CountingReader::new(
        decoded,
        limits.resource_limit(LimitResource::DecodedLayer),
        vec![&mut budgets.decoded, operation],
        copy_buffer,
    );
    let mut walker = TarWalker::new(
        counted,
        EntryPolicy::Layer {
            entries: &mut budgets.entries,
            extension_total: &mut budgets.extension_total,
        },
        limits,
    );
    while walker.next_entry()?.is_some() {}
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 8: LayerSources
// ---------------------------------------------------------------------------

fn layer_sources(
    compatibility: &Compatibility,
    descriptors: &[Descriptor],
    diff_ids: &[String],
) -> Checked<()> {
    let Some(sources) = compatibility
        .layer_sources
        .as_ref()
        .filter(|sources| !sources.is_empty())
    else {
        return Ok(());
    };
    let used: BTreeSet<&str> = diff_ids.iter().map(String::as_str).collect();
    let keys: BTreeSet<&str> = sources.keys().map(String::as_str).collect();
    if keys != used {
        return Err(invalid(InvalidArchiveReason::InconsistentLayerSources));
    }
    for (descriptor, diff_id) in descriptors.iter().zip(diff_ids) {
        let value = sources
            .get(diff_id)
            .ok_or_else(|| invalid(InvalidArchiveReason::InconsistentLayerSources))?;
        documents::layer_source(value, descriptor)?;
    }
    Ok(())
}

/// A test-only record of what the validator read and decoded, labelled by
/// phase and layer position.
#[cfg(test)]
pub(super) mod seam {
    use std::cell::RefCell;

    /// One recorded step.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Event {
        /// Phase 1 hashed the blob with this hex name.
        InventoryBlob(String),
        /// Phase 1 allocated its copy buffer, of this length.
        Buffer(usize),
        /// Phase 7 opened the stored range of this position.
        LayerOpened(usize),
        /// Phase 7 read stored bytes for this position.
        LayerRead { position: usize, bytes: usize },
        /// Phase 7 built a gzip decoder for this position.
        LayerDecoded(usize),
    }

    thread_local! {
        static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(event: Event) {
        EVENTS.with(|events| events.borrow_mut().push(event));
    }

    /// Returns and clears everything recorded on this thread.
    pub(crate) fn take() -> Vec<Event> {
        EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
    }
}

#[cfg(test)]
mod assembly;
#[cfg(test)]
mod tests;
