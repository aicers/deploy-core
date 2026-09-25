//! Synthetic image archives for tests, and a classifier that holds any image
//! archive against a declaration.
//!
//! Nothing outside this crate can otherwise produce an image archive the
//! validator accepts: real `docker save` output carries attestations, nested
//! indexes, legacy files or extra blobs, all of which the supported profile
//! refuses. [`SyntheticImageArchiveBuilder`] writes one bounded, deterministic
//! form of that profile — an OCI layout holding one image, a Docker
//! compatibility `manifest.json`, and uncompressed or gzip layers — and
//! [`check_image_archive`] runs the crate's validator over any archive under
//! the default [`ContentLimits`].
//!
//! The builder exposes the config digest before any tag is chosen, so a caller
//! can derive a canonical runtime alias with
//! [`canonical_runtime_alias`](super::canonical_runtime_alias) first and tag
//! the image with it afterwards. The config never depends on the tags.
//!
//! Every limit the builder enforces is one of the `MAX_SYNTHETIC_*` constants.
//! Taken together, at their worst-case combination, they keep every archive
//! the builder can write inside every default [`ContentLimits`] ceiling, so a
//! builder archive is never refused for its size.
//!
//! This module is compiled only for this crate's tests and under the
//! `test-support` feature. Enable that feature in a dependent's
//! `[dev-dependencies]` only — never under `[dependencies]` — so none of it
//! reaches a release build.

use std::fmt;
use std::io::{self, Read, Seek, Write};

use flate2::{Compression, GzBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::archive::{ImageArchiveFault, validate_image_archive};
use super::{
    ImageArchitecture, ImageDeclaration, ImageOs, ImagePlatform, NormalizedReference,
    parse_tagged_reference,
};
use crate::content::Budget;
use crate::package::{ContentLimits, LimitResource};
use crate::payload::to_hex;
use crate::verify::ImageVerifyError;

/// Most layer positions one synthetic image has.
///
/// Keeps output within the default [`LimitResource::LayersPerImage`] of 256,
/// and so keeps the image archive's entries — three layout files, the image
/// manifest, the config and at most one blob per position, 261 in all —
/// under the default [`LimitResource::ImageEntries`] of 4,096.
pub const MAX_SYNTHETIC_LAYERS: usize = 256;

/// Most entries one synthetic layer holds.
///
/// Bounds the per-layer tar overhead — a 512-byte header and under 512 bytes
/// of padding per entry — that the decoded size bound of
/// [`MAX_SYNTHETIC_LAYER_BYTES`] adds to, keeping one decoded layer within the
/// default [`LimitResource::DecodedLayer`].
pub const MAX_SYNTHETIC_ENTRIES_PER_LAYER: usize = 4096;

/// Most entries across every layer position of one synthetic image.
///
/// Keeps output within the default [`LimitResource::LayerEntries`] of
/// 1,000,000. A layer repeated at two positions counts at both.
pub const MAX_SYNTHETIC_TOTAL_ENTRIES: usize = 65_536;

/// Most file payload bytes one synthetic layer holds: 256 MiB.
///
/// With the tar overhead of [`MAX_SYNTHETIC_ENTRIES_PER_LAYER`] entries and
/// the enforced gzip ceiling, keeps one layer within the default
/// [`LimitResource::StoredLayerBlob`] and [`LimitResource::DecodedLayer`] of
/// 16 GiB each.
pub const MAX_SYNTHETIC_LAYER_BYTES: u64 = 256 * 1024 * 1024;

/// Most file payload bytes across every layer position of one synthetic
/// image: 1 GiB.
///
/// Keeps output within the default [`LimitResource::ImageArchive`] of 32 GiB,
/// [`LimitResource::DecodedLayersPerImage`] of 128 GiB and
/// [`LimitResource::DecodedLayersPerOperation`] of 256 GiB. A layer repeated
/// at two positions counts at both.
pub const MAX_SYNTHETIC_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// Longest requested entry path, in bytes.
///
/// Keeps output within the default [`LimitResource::LayerPathBytes`] of
/// 4,096. A directory's written name adds one `/`, so it is at most 256
/// bytes, and a written name is always stored in the ustar name and prefix
/// fields: no PAX or GNU extension is ever emitted.
pub const MAX_SYNTHETIC_PATH_BYTES: usize = 255;

/// Longest symlink target, in bytes.
///
/// Fits the 100-byte ustar `linkname` field, and keeps output within the
/// default [`LimitResource::LayerLinkTargetBytes`] of 4,096.
pub const MAX_SYNTHETIC_LINK_BYTES: usize = 100;

/// Most public references one synthetic image is tagged with.
///
/// Keeps output within the default [`LimitResource::TagsPerImage`] of 256.
/// The validator holds both the `RepoTags` entries and the `index.json`
/// descriptors to that one resource, and the builder writes one of each per
/// reference.
pub const MAX_SYNTHETIC_REFS: usize = 256;

/// Longest public reference, in bytes.
///
/// Keeps the documents that repeat every reference within the default
/// [`LimitResource::IndexJson`], [`LimitResource::CompatibilityJson`] and
/// [`LimitResource::ImageJsonTotal`]. The reference grammar bounds a
/// reference's path and tag but not its domain, so this bound is the
/// builder's own.
pub const MAX_SYNTHETIC_REF_BYTES: usize = 512;

/// Longest platform variant the builder writes, in bytes.
const MAX_VARIANT_BYTES: usize = 64;

const SHA256_PREFIX: &str = "sha256:";
const BLOB_PREFIX: &str = "blobs/sha256/";

const OCI_LAYOUT_FILE: &str = "oci-layout";
const INDEX_FILE: &str = "index.json";
const COMPATIBILITY_FILE: &str = "manifest.json";

const OCI_LAYOUT_VERSION: &str = "1.0.0";
const SCHEMA_VERSION: u32 = 2;
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_GZIP_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

const LINUX: &str = "linux";
const ROOTFS_LAYERS: &str = "layers";
const HISTORY_PREFIX: &str = "deploy-core synthetic layer";

/// The ustar `name` field's width.
const USTAR_NAME_BYTES: usize = 100;
/// The ustar `prefix` field's width.
const USTAR_PREFIX_BYTES: usize = 155;

const FILE_MODE: u32 = 0o644;
const DIRECTORY_MODE: u32 = 0o755;
const SYMLINK_MODE: u32 = 0o777;

/// The gzip level every compressed layer is written at.
const GZIP_LEVEL: u32 = 6;
/// The gzip header's OS byte: unknown.
const GZIP_OS_UNKNOWN: u8 = 255;
/// The gzip ceiling's constant allowance, in bytes.
const GZIP_CEILING_SLACK: u64 = 4096;
/// The gzip ceiling's proportional allowance: one byte per this many decoded
/// bytes.
const GZIP_CEILING_DIVISOR: u64 = 1024;

/// The bounds a builder enforces. The default is the public constants; only
/// this crate's tests substitute smaller values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SyntheticBounds {
    layers: usize,
    entries_per_layer: usize,
    total_entries: usize,
    layer_bytes: u64,
    image_bytes: u64,
    path_bytes: usize,
    link_bytes: usize,
    refs: usize,
    ref_bytes: usize,
}

impl Default for SyntheticBounds {
    fn default() -> Self {
        SyntheticBounds {
            layers: MAX_SYNTHETIC_LAYERS,
            entries_per_layer: MAX_SYNTHETIC_ENTRIES_PER_LAYER,
            total_entries: MAX_SYNTHETIC_TOTAL_ENTRIES,
            layer_bytes: MAX_SYNTHETIC_LAYER_BYTES,
            image_bytes: MAX_SYNTHETIC_IMAGE_BYTES,
            path_bytes: MAX_SYNTHETIC_PATH_BYTES,
            link_bytes: MAX_SYNTHETIC_LINK_BYTES,
            refs: MAX_SYNTHETIC_REFS,
            ref_bytes: MAX_SYNTHETIC_REF_BYTES,
        }
    }
}

/// Bytes whose `Debug` form is their length, never their content.
#[derive(Clone, Default, PartialEq, Eq)]
struct Opaque(Vec<u8>);

impl fmt::Debug for Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0.len())
    }
}

/// One entry of a [`SyntheticLayer`], as requested.
#[derive(Clone, Debug)]
enum LayerEntry {
    File { path: String, bytes: Opaque },
    Directory { path: String },
    Symlink { path: String, target: String },
}

impl LayerEntry {
    fn path(&self) -> &str {
        match self {
            LayerEntry::File { path, .. }
            | LayerEntry::Directory { path }
            | LayerEntry::Symlink { path, .. } => path,
        }
    }
}

/// The description of one layer: its entries, in the order they are written.
///
/// Nothing is checked as entries are added.
/// [`SyntheticImageArchiveBuilder::layer`] checks the whole layer before it
/// writes any of it.
#[derive(Clone, Debug, Default)]
pub struct SyntheticLayer {
    entries: Vec<LayerEntry>,
}

impl SyntheticLayer {
    /// Creates a layer with no entries.
    #[must_use]
    pub fn new() -> Self {
        SyntheticLayer::default()
    }

    /// Returns this layer with a regular file at `path` holding `bytes`,
    /// written with mode `0o644`.
    #[must_use]
    pub fn file(mut self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
        self.entries.push(LayerEntry::File {
            path: path.to_string(),
            bytes: Opaque(bytes.into()),
        });
        self
    }

    /// Returns this layer with a directory at `path`, written with mode
    /// `0o755` under `path` plus one trailing `/`.
    #[must_use]
    pub fn dir(mut self, path: &str) -> Self {
        self.entries.push(LayerEntry::Directory {
            path: path.to_string(),
        });
        self
    }

    /// Returns this layer with a symlink at `path` pointing at `target`,
    /// written with mode `0o777`. The target may be absolute and may contain
    /// `..`; it is never resolved.
    #[must_use]
    pub fn symlink(mut self, path: &str, target: &str) -> Self {
        self.entries.push(LayerEntry::Symlink {
            path: path.to_string(),
            target: target.to_string(),
        });
        self
    }
}

/// How a layer's tar is stored in the image archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerCompression {
    /// The tar as is, under `application/vnd.oci.image.layer.v1.tar`.
    Uncompressed,
    /// One gzip member at level 6, under
    /// `application/vnd.oci.image.layer.v1.tar+gzip`.
    Gzip,
}

impl LayerCompression {
    fn media_type(self) -> &'static str {
        match self {
            LayerCompression::Uncompressed => OCI_LAYER_MEDIA_TYPE,
            LayerCompression::Gzip => OCI_GZIP_LAYER_MEDIA_TYPE,
        }
    }
}

/// Why the builder refused a value, or failed to write one.
///
/// `layer` is the zero-based position the refused layer would have taken,
/// `entry` the zero-based index of the entry within it, and `index` the
/// zero-based index of the reference within `public_refs`. No message
/// echoes a file's content or the refused variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyntheticImageError {
    /// The platform variant is not 1 to 64 bytes of ASCII letters, digits,
    /// `.`, `_` and `-`.
    #[error("the platform variant is not 1 to 64 ascii letters, digits, `.`, `_` or `-`")]
    InvalidVariant,
    /// The layer would take the image past [`MAX_SYNTHETIC_LAYERS`].
    #[error("the image would have more layers than a synthetic image may")]
    TooManyLayers,
    /// The layer holds more than [`MAX_SYNTHETIC_ENTRIES_PER_LAYER`] entries.
    #[error("layer {layer} holds more entries than a synthetic layer may")]
    TooManyEntries {
        /// The layer's position.
        layer: usize,
    },
    /// The layer would take the image past [`MAX_SYNTHETIC_TOTAL_ENTRIES`].
    #[error("layer {layer} would take the image past its synthetic entry total")]
    TooManyTotalEntries {
        /// The layer's position.
        layer: usize,
    },
    /// The layer's file payload exceeds [`MAX_SYNTHETIC_LAYER_BYTES`].
    #[error("layer {layer} holds more file bytes than a synthetic layer may")]
    LayerTooLarge {
        /// The layer's position.
        layer: usize,
    },
    /// The layer would take the image past [`MAX_SYNTHETIC_IMAGE_BYTES`].
    #[error("layer {layer} would take the image past its synthetic file byte total")]
    ImageTooLarge {
        /// The layer's position.
        layer: usize,
    },
    /// An entry path is empty, not ASCII, holds a control byte, NUL or
    /// backslash, is absolute, has an empty, `.` or `..` segment or a
    /// trailing `/`, or is longer than [`MAX_SYNTHETIC_PATH_BYTES`].
    #[error("entry {entry} of layer {layer} has an invalid path")]
    InvalidEntryPath {
        /// The layer's position.
        layer: usize,
        /// The entry's index in the layer.
        entry: usize,
    },
    /// An entry's written name fits neither the ustar name field nor a split
    /// across the prefix and name fields.
    #[error("the path of entry {entry} of layer {layer} does not fit a ustar header")]
    PathNotRepresentable {
        /// The layer's position.
        layer: usize,
        /// The entry's index in the layer.
        entry: usize,
    },
    /// A symlink target is empty, holds a NUL, or is longer than
    /// [`MAX_SYNTHETIC_LINK_BYTES`].
    #[error("entry {entry} of layer {layer} has an invalid symlink target")]
    InvalidLinkTarget {
        /// The layer's position.
        layer: usize,
        /// The entry's index in the layer.
        entry: usize,
    },
    /// The layer's gzip blob is larger than its decoded tar plus 1/1,024 of
    /// it plus 4,096 bytes. The blob was discarded.
    #[error("the gzip blob of layer {layer} is larger than the synthetic ceiling")]
    CompressionExpanded {
        /// The layer's position.
        layer: usize,
    },
    /// `public_refs` is empty.
    #[error("no public reference was given")]
    NoReferences,
    /// `public_refs` holds more than [`MAX_SYNTHETIC_REFS`] references.
    #[error("more public references were given than a synthetic image may carry")]
    TooManyReferences,
    /// A reference is longer than [`MAX_SYNTHETIC_REF_BYTES`].
    #[error("public reference {index} is longer than a synthetic reference may be")]
    ReferenceTooLong {
        /// The reference's index.
        index: usize,
    },
    /// A reference is not an explicit, valid `name:tag`.
    #[error("public reference {index} is not a valid tagged reference")]
    InvalidReference {
        /// The reference's index.
        index: usize,
    },
    /// A reference repeats an earlier one, literally or after Docker
    /// normalization.
    #[error("public reference {index} duplicates an earlier one")]
    DuplicateReference {
        /// The reference's index.
        index: usize,
    },
    /// Writing to an in-memory buffer failed.
    #[error("writing the synthetic archive failed: {kind}")]
    Generation {
        /// The kind of the underlying I/O error.
        kind: io::ErrorKind,
    },
}

impl From<io::Error> for SyntheticImageError {
    fn from(err: io::Error) -> Self {
        SyntheticImageError::Generation { kind: err.kind() }
    }
}

/// One stored layer blob, written once however many positions use it.
#[derive(Clone, Debug)]
struct StoredBlob {
    /// Hex SHA-256 of `bytes`.
    hex: String,
    media_type: &'static str,
    bytes: Opaque,
}

impl StoredBlob {
    fn size(&self) -> u64 {
        widen(self.bytes.0.len())
    }
}

/// One layer position.
#[derive(Clone, Debug)]
struct Position {
    /// `sha256:` digest of the decoded tar.
    diff_id: String,
    /// Index of its blob in the builder's unique blobs.
    blob: usize,
}

/// Builds one synthetic image archive, layer by layer, and tags it last.
///
/// Every method that can refuse consumes the builder: a caller that wants to
/// retry after a refusal builds again. The output is a pure function of the
/// platform, the layers in call order and the references: identical inputs
/// produce byte-identical archives, carrying no timestamp, host path or
/// randomness beyond what a caller put in a file.
#[derive(Debug)]
pub struct SyntheticImageArchiveBuilder {
    platform: ImagePlatform,
    bounds: SyntheticBounds,
    /// Unique stored blobs, in order of first use.
    blobs: Vec<StoredBlob>,
    positions: Vec<Position>,
    total_entries: usize,
    total_bytes: u64,
}

impl SyntheticImageArchiveBuilder {
    /// Creates a builder for an image of `platform` with no layers.
    ///
    /// The variant is restricted to what the builder writes, not to what an
    /// image may carry: `None`, or 1 to 64 bytes each of which is an ASCII
    /// letter, a digit, `.`, `_` or `-`. A variant refused here may still be
    /// valid in a real archive.
    ///
    /// # Errors
    ///
    /// Returns [`SyntheticImageError::InvalidVariant`] when the variant is
    /// present and is not such a token.
    pub fn new(platform: ImagePlatform) -> Result<Self, SyntheticImageError> {
        Self::with_bounds(platform, SyntheticBounds::default())
    }

    fn with_bounds(
        platform: ImagePlatform,
        bounds: SyntheticBounds,
    ) -> Result<Self, SyntheticImageError> {
        if platform
            .variant
            .as_deref()
            .is_some_and(|variant| !is_variant_token(variant))
        {
            return Err(SyntheticImageError::InvalidVariant);
        }
        Ok(SyntheticImageArchiveBuilder {
            platform,
            bounds,
            blobs: Vec::new(),
            positions: Vec::new(),
            total_entries: 0,
            total_bytes: 0,
        })
    }

    /// Returns this builder with `layer` appended at the next position,
    /// stored as `compression` says.
    ///
    /// The layer is checked whole before anything is written, and a layer
    /// identical to an earlier one shares its stored blob.
    ///
    /// # Errors
    ///
    /// Checked in this order, the first failure winning:
    ///
    /// 1. [`SyntheticImageError::TooManyLayers`] past
    ///    [`MAX_SYNTHETIC_LAYERS`];
    /// 2. [`SyntheticImageError::TooManyEntries`] past
    ///    [`MAX_SYNTHETIC_ENTRIES_PER_LAYER`], then
    ///    [`SyntheticImageError::TooManyTotalEntries`] past
    ///    [`MAX_SYNTHETIC_TOTAL_ENTRIES`];
    /// 3. [`SyntheticImageError::LayerTooLarge`] past
    ///    [`MAX_SYNTHETIC_LAYER_BYTES`], then
    ///    [`SyntheticImageError::ImageTooLarge`] past
    ///    [`MAX_SYNTHETIC_IMAGE_BYTES`];
    /// 4. entry by entry, [`SyntheticImageError::InvalidEntryPath`] for a
    ///    path that breaks the path rule, then
    ///    [`SyntheticImageError::PathNotRepresentable`] for one that fits no
    ///    ustar header;
    /// 5. [`SyntheticImageError::InvalidLinkTarget`] for the first invalid
    ///    symlink target;
    /// 6. [`SyntheticImageError::CompressionExpanded`] for a gzip blob over
    ///    its ceiling, and [`SyntheticImageError::Generation`] for a failed
    ///    in-memory write.
    ///
    /// Nothing is generated unless steps 1 to 5 pass.
    // The layer is taken by value, as the builder chain reads: a description
    // is used once, and keeping it owned leaves room for the builder to hold
    // on to it without a signature change.
    #[allow(clippy::needless_pass_by_value)]
    pub fn layer(
        mut self,
        layer: SyntheticLayer,
        compression: LayerCompression,
    ) -> Result<Self, SyntheticImageError> {
        self.add_layer(&layer, compression)?;
        Ok(self)
    }

    /// Checks, generates and records one layer. The builder is unchanged
    /// unless it succeeds.
    fn add_layer(
        &mut self,
        layer: &SyntheticLayer,
        compression: LayerCompression,
    ) -> Result<(), SyntheticImageError> {
        let position = self.positions.len();
        let (total_entries, total_bytes) = self.check_layer(layer, position)?;

        let tar = write_layer_tar(&layer.entries)?;
        let decoded = widen(tar.len());
        let diff_id = format!("{SHA256_PREFIX}{}", sha256_hex(&tar));
        let blob = match compression {
            LayerCompression::Uncompressed => tar,
            LayerCompression::Gzip => {
                let blob = gzip(&tar)?;
                #[cfg(test)]
                let blob = seam::replace_gzip(blob, gzip_ceiling(decoded));
                if widen(blob.len()) > gzip_ceiling(decoded) {
                    return Err(SyntheticImageError::CompressionExpanded { layer: position });
                }
                blob
            }
        };
        let hex = sha256_hex(&blob);
        let index = if let Some(index) = self.blobs.iter().position(|stored| stored.hex == hex) {
            index
        } else {
            self.blobs.push(StoredBlob {
                hex,
                media_type: compression.media_type(),
                bytes: Opaque(blob),
            });
            self.blobs.len() - 1
        };
        self.positions.push(Position {
            diff_id,
            blob: index,
        });
        self.total_entries = total_entries;
        self.total_bytes = total_bytes;
        Ok(())
    }

    /// Runs checks 1 to 5 of [`layer`](Self::layer) and returns the running
    /// entry and payload totals the layer would leave.
    fn check_layer(
        &self,
        layer: &SyntheticLayer,
        position: usize,
    ) -> Result<(usize, u64), SyntheticImageError> {
        let bounds = &self.bounds;
        if position >= bounds.layers {
            return Err(SyntheticImageError::TooManyLayers);
        }

        let entries = layer.entries.len();
        if entries > bounds.entries_per_layer {
            return Err(SyntheticImageError::TooManyEntries { layer: position });
        }
        let total_entries = self
            .total_entries
            .checked_add(entries)
            .filter(|total| *total <= bounds.total_entries)
            .ok_or(SyntheticImageError::TooManyTotalEntries { layer: position })?;

        let payload = layer
            .entries
            .iter()
            .try_fold(0u64, |sum, entry| match entry {
                LayerEntry::File { bytes, .. } => {
                    sum.checked_add(u64::try_from(bytes.0.len()).ok()?)
                }
                LayerEntry::Directory { .. } | LayerEntry::Symlink { .. } => Some(sum),
            })
            .filter(|payload| *payload <= bounds.layer_bytes)
            .ok_or(SyntheticImageError::LayerTooLarge { layer: position })?;
        let total_bytes = self
            .total_bytes
            .checked_add(payload)
            .filter(|total| *total <= bounds.image_bytes)
            .ok_or(SyntheticImageError::ImageTooLarge { layer: position })?;

        for (index, entry) in layer.entries.iter().enumerate() {
            let path = entry.path();
            if !is_valid_entry_path(path, bounds.path_bytes) {
                return Err(SyntheticImageError::InvalidEntryPath {
                    layer: position,
                    entry: index,
                });
            }
            let written = written_name(entry);
            if ustar_split(&written).is_none() {
                return Err(SyntheticImageError::PathNotRepresentable {
                    layer: position,
                    entry: index,
                });
            }
        }

        for (index, entry) in layer.entries.iter().enumerate() {
            if let LayerEntry::Symlink { target, .. } = entry
                && (target.is_empty() || target.contains('\0') || target.len() > bounds.link_bytes)
            {
                return Err(SyntheticImageError::InvalidLinkTarget {
                    layer: position,
                    entry: index,
                });
            }
        }
        Ok((total_entries, total_bytes))
    }

    /// Returns the `sha256:` digest of the image config as the finished
    /// archive will hold it.
    ///
    /// The config depends only on the platform and the layers added so far,
    /// never on the references [`finish`](Self::finish) is given, so a caller
    /// can derive a canonical runtime alias from this digest before choosing
    /// any tag.
    #[must_use]
    pub fn config_digest(&self) -> String {
        format!("{SHA256_PREFIX}{}", sha256_hex(&self.config_bytes()))
    }

    /// Returns the platform the image is built for.
    #[must_use]
    pub fn platform(&self) -> &ImagePlatform {
        &self.platform
    }

    /// Tags the image with `public_refs`, in order, and writes the archive.
    ///
    /// With no layers the archive holds a scratch image. Every archive this
    /// returns passes [`check_image_archive`] against a declaration whose
    /// platform, `config_digest` and `public_refs` match.
    ///
    /// # Errors
    ///
    /// Returns [`SyntheticImageError::NoReferences`] for an empty list and
    /// [`SyntheticImageError::TooManyReferences`] for one longer than
    /// [`MAX_SYNTHETIC_REFS`]. Otherwise each reference is checked in order,
    /// the first failure winning: [`SyntheticImageError::ReferenceTooLong`]
    /// past [`MAX_SYNTHETIC_REF_BYTES`], then
    /// [`SyntheticImageError::InvalidReference`] when it is not a valid
    /// tagged reference, then [`SyntheticImageError::DuplicateReference`]
    /// when it repeats an earlier one literally or after normalization.
    /// [`SyntheticImageError::Generation`] reports a failed in-memory write.
    pub fn finish(
        self,
        public_refs: &[String],
    ) -> Result<SyntheticImageArchive, SyntheticImageError> {
        let normalized = self.check_references(public_refs)?;

        let config = self.config_bytes();
        let config_hex = sha256_hex(&config);
        let manifest = self.manifest_bytes(&config_hex, widen(config.len()));
        let manifest_hex = sha256_hex(&manifest);
        let index = index_bytes(
            public_refs,
            &normalized,
            &manifest_hex,
            widen(manifest.len()),
        );
        let compatibility = self.compatibility_bytes(&config_hex, public_refs);
        let layout = to_json(&OciLayoutDocument {
            image_layout_version: OCI_LAYOUT_VERSION,
        });

        let mut builder = tar::Builder::new(Vec::new());
        append_file(&mut builder, OCI_LAYOUT_FILE, &layout)?;
        append_file(&mut builder, INDEX_FILE, &index)?;
        append_file(&mut builder, COMPATIBILITY_FILE, &compatibility)?;
        append_file(&mut builder, &blob_path(&manifest_hex), &manifest)?;
        append_file(&mut builder, &blob_path(&config_hex), &config)?;
        for blob in &self.blobs {
            append_file(&mut builder, &blob_path(&blob.hex), &blob.bytes.0)?;
        }
        let bytes = builder.into_inner()?;

        Ok(SyntheticImageArchive {
            bytes: Opaque(bytes),
            config_digest: format!("{SHA256_PREFIX}{config_hex}"),
            manifest_digest: format!("{SHA256_PREFIX}{manifest_hex}"),
            diff_ids: self
                .positions
                .iter()
                .map(|position| position.diff_id.clone())
                .collect(),
            platform: self.platform,
        })
    }

    /// Checks `public_refs` in the order [`finish`](Self::finish) documents,
    /// returning each one's normalized form.
    fn check_references(
        &self,
        public_refs: &[String],
    ) -> Result<Vec<NormalizedReference>, SyntheticImageError> {
        if public_refs.is_empty() {
            return Err(SyntheticImageError::NoReferences);
        }
        if public_refs.len() > self.bounds.refs {
            return Err(SyntheticImageError::TooManyReferences);
        }
        let mut normalized: Vec<NormalizedReference> = Vec::with_capacity(public_refs.len());
        for (index, reference) in public_refs.iter().enumerate() {
            if reference.len() > self.bounds.ref_bytes {
                return Err(SyntheticImageError::ReferenceTooLong { index });
            }
            let parsed = parse_tagged_reference(reference)
                .map_err(|_| SyntheticImageError::InvalidReference { index })?;
            if normalized.contains(&parsed) {
                return Err(SyntheticImageError::DuplicateReference { index });
            }
            normalized.push(parsed);
        }
        Ok(normalized)
    }

    fn config_bytes(&self) -> Vec<u8> {
        let diff_ids: Vec<&str> = self
            .positions
            .iter()
            .map(|position| position.diff_id.as_str())
            .collect();
        let history: Vec<HistoryEntry> = (0..self.positions.len())
            .map(|position| HistoryEntry {
                created_by: format!("{HISTORY_PREFIX} {position}"),
            })
            .collect();
        to_json(&ConfigDocument {
            architecture: architecture_name(self.platform.architecture),
            os: os_name(self.platform.os),
            variant: self.platform.variant.as_deref(),
            rootfs: Rootfs {
                kind: ROOTFS_LAYERS,
                diff_ids,
            },
            history,
        })
    }

    fn manifest_bytes(&self, config_hex: &str, config_size: u64) -> Vec<u8> {
        let layers = self
            .positions
            .iter()
            .filter_map(|position| self.blobs.get(position.blob))
            .map(|blob| DescriptorDocument {
                media_type: blob.media_type,
                digest: format!("{SHA256_PREFIX}{}", blob.hex),
                size: blob.size(),
            })
            .collect();
        to_json(&ManifestDocument {
            schema_version: SCHEMA_VERSION,
            media_type: OCI_MANIFEST_MEDIA_TYPE,
            config: DescriptorDocument {
                media_type: OCI_CONFIG_MEDIA_TYPE,
                digest: format!("{SHA256_PREFIX}{config_hex}"),
                size: config_size,
            },
            layers,
        })
    }

    fn compatibility_bytes(&self, config_hex: &str, public_refs: &[String]) -> Vec<u8> {
        let layers = self
            .positions
            .iter()
            .filter_map(|position| self.blobs.get(position.blob))
            .map(|blob| blob_path(&blob.hex))
            .collect();
        to_json(&[CompatibilityRecord {
            config: blob_path(config_hex),
            repo_tags: public_refs,
            layers,
        }])
    }
}

/// An image archive the builder wrote, with the digests it holds.
#[derive(Clone)]
pub struct SyntheticImageArchive {
    bytes: Opaque,
    config_digest: String,
    manifest_digest: String,
    diff_ids: Vec<String>,
    platform: ImagePlatform,
}

impl SyntheticImageArchive {
    /// Returns the archive's bytes: a plain docker-save tar.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes.0
    }

    /// Returns the archive's bytes, consuming it.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.0
    }

    /// Returns the `sha256:` digest of the image config.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Returns the `sha256:` digest of the OCI image manifest blob.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Returns each layer position's `sha256:` diff ID, in layer order.
    #[must_use]
    pub fn diff_ids(&self) -> &[String] {
        &self.diff_ids
    }

    /// Returns the platform the image is built for.
    #[must_use]
    pub fn platform(&self) -> &ImagePlatform {
        &self.platform
    }
}

impl fmt::Debug for SyntheticImageArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntheticImageArchive")
            .field("len", &self.bytes.0.len())
            .field("config_digest", &self.config_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("diff_ids", &self.diff_ids)
            .finish_non_exhaustive()
    }
}

/// Why [`check_image_archive`] refused an archive.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveCheckError {
    /// The archive is excluded from the supported profile, is malformed, or
    /// disagrees with the declaration, exactly as the validator reports it.
    #[error(transparent)]
    Image(ImageVerifyError),
    /// Reading the archive would exceed a default content limit.
    #[error("reading the image archive would exceed the {resource} limit of {limit}")]
    LimitExceeded {
        /// The resource.
        resource: LimitResource,
        /// Its default value.
        limit: u64,
    },
    /// The source failed during a read.
    #[error("reading the image archive failed")]
    Io(#[source] io::Error),
}

/// Holds the image archive in `source` against `declaration`, under the
/// default [`ContentLimits`].
///
/// This is the crate's own image-archive validator, run the way package
/// verification runs it: every per-image limit at its default and a fresh
/// operation budget for decoded layers. It accepts any archive, not only a
/// synthetic one, and never invokes Docker or reaches the network.
///
/// `archive_path` is the artifact's archive member path, as a package
/// manifest would record it. It is passed through verbatim as the label an
/// [`ImageVerifyError`] carries, and is never opened.
///
/// # Errors
///
/// Returns [`ArchiveCheckError::Image`] carrying the validator's verdict when
/// the archive is refused, [`ArchiveCheckError::LimitExceeded`] when reading
/// it would exceed a default limit, and [`ArchiveCheckError::Io`] with the
/// source's own error, kind preserved and no path attached, when `source`
/// fails.
pub fn check_image_archive<R: Read + Seek>(
    source: R,
    archive_path: &str,
    declaration: &ImageDeclaration,
) -> Result<(), ArchiveCheckError> {
    let limits = ContentLimits::default();
    let mut operation =
        Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
    match validate_image_archive(source, declaration, archive_path, &limits, &mut operation) {
        Ok(_) => Ok(()),
        Err(ImageArchiveFault::Image(error)) => Err(ArchiveCheckError::Image(error)),
        Err(ImageArchiveFault::LimitExceeded { resource, limit }) => {
            Err(ArchiveCheckError::LimitExceeded { resource, limit })
        }
        Err(ImageArchiveFault::Io(error)) => Err(ArchiveCheckError::Io(error)),
    }
}

// ---------------------------------------------------------------------------
// Wire documents, serialized with their keys in declaration order
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OciLayoutDocument {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: &'static str,
}

#[derive(Serialize)]
struct ConfigDocument<'a> {
    architecture: &'static str,
    os: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<&'a str>,
    rootfs: Rootfs<'a>,
    history: Vec<HistoryEntry>,
}

#[derive(Serialize)]
struct Rootfs<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    diff_ids: Vec<&'a str>,
}

#[derive(Serialize)]
struct HistoryEntry {
    created_by: String,
}

#[derive(Serialize)]
struct DescriptorDocument {
    #[serde(rename = "mediaType")]
    media_type: &'static str,
    digest: String,
    size: u64,
}

#[derive(Serialize)]
struct ManifestDocument {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: &'static str,
    config: DescriptorDocument,
    layers: Vec<DescriptorDocument>,
}

#[derive(Serialize)]
struct IndexDocument<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: &'static str,
    manifests: Vec<IndexDescriptor<'a>>,
}

#[derive(Serialize)]
struct IndexDescriptor<'a> {
    #[serde(rename = "mediaType")]
    media_type: &'static str,
    digest: &'a str,
    size: u64,
    annotations: IndexAnnotations<'a>,
}

#[derive(Serialize)]
struct IndexAnnotations<'a> {
    #[serde(rename = "io.containerd.image.name")]
    name: &'a str,
    #[serde(rename = "org.opencontainers.image.ref.name")]
    ref_name: &'a str,
}

#[derive(Serialize)]
struct CompatibilityRecord<'a> {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags")]
    repo_tags: &'a [String],
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

fn index_bytes(
    public_refs: &[String],
    normalized: &[NormalizedReference],
    manifest_hex: &str,
    manifest_size: u64,
) -> Vec<u8> {
    let digest = format!("{SHA256_PREFIX}{manifest_hex}");
    let manifests = public_refs
        .iter()
        .zip(normalized)
        .map(|(reference, normalized)| IndexDescriptor {
            media_type: OCI_MANIFEST_MEDIA_TYPE,
            digest: &digest,
            size: manifest_size,
            annotations: IndexAnnotations {
                name: reference,
                ref_name: &normalized.tag,
            },
        })
        .collect();
    to_json(&IndexDocument {
        schema_version: SCHEMA_VERSION,
        media_type: OCI_INDEX_MEDIA_TYPE,
        manifests,
    })
}

/// Serializes one of this module's wire documents compactly.
fn to_json<T: Serialize + ?Sized>(document: &T) -> Vec<u8> {
    serde_json::to_vec(document).expect(
        "every wire document is strings, integers, arrays and structs, which always serialize",
    )
}

// ---------------------------------------------------------------------------
// Checks and writers
// ---------------------------------------------------------------------------

/// Whether `variant` is 1 to 64 bytes of ASCII letters, digits, `.`, `_` and
/// `-`.
fn is_variant_token(variant: &str) -> bool {
    (1..=MAX_VARIANT_BYTES).contains(&variant.len())
        && variant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Whether `path` is nonempty ASCII with no control byte, NUL or backslash,
/// relative, free of empty, `.` and `..` segments and of a trailing `/`, and
/// at most `max` bytes.
fn is_valid_entry_path(path: &str, max: usize) -> bool {
    !path.is_empty()
        && path.len() <= max
        && path
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && byte != b'\\')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Returns the name an entry is written under: its path, plus one `/` for a
/// directory.
fn written_name(entry: &LayerEntry) -> String {
    match entry {
        LayerEntry::Directory { path } => format!("{path}/"),
        LayerEntry::File { path, .. } | LayerEntry::Symlink { path, .. } => path.clone(),
    }
}

/// Splits a written name into its ustar prefix and name fields, or returns
/// `None` when it fits neither the name field alone nor any split.
///
/// A name of at most 100 bytes goes in the name field whole. A longer one is
/// split at a `/`, tried from the rightmost leftwards, into a prefix of at
/// most 155 bytes and a nonempty name of at most 100.
fn ustar_split(written: &str) -> Option<(&str, &str)> {
    if written.len() <= USTAR_NAME_BYTES {
        return Some(("", written));
    }
    written
        .char_indices()
        .rev()
        .filter(|(_, character)| *character == '/')
        .map(|(at, _)| (written.get(..at), written.get(at + 1..)))
        .find_map(|split| match split {
            (Some(prefix), Some(name))
                if prefix.len() <= USTAR_PREFIX_BYTES
                    && !name.is_empty()
                    && name.len() <= USTAR_NAME_BYTES =>
            {
                Some((prefix, name))
            }
            _ => None,
        })
}

/// Returns a ustar header with every fixed field set: mtime, uid and gid 0,
/// empty uname and gname, `mode` and `size`.
fn fixed_header(entry_type: tar::EntryType, mode: u32, size: u64) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header
}

/// Writes `prefix` and `name` straight into a ustar header's fields.
///
/// Both have been checked to fit, so neither is ever routed through an
/// extension record.
fn set_ustar_name(header: &mut tar::Header, prefix: &str, name: &str) {
    let ustar = header
        .as_ustar_mut()
        .expect("a header made by `Header::new_ustar` carries the ustar magic");
    copy_field(&mut ustar.name, name.as_bytes());
    copy_field(&mut ustar.prefix, prefix.as_bytes());
}

/// Copies `value` into the start of `field`, which has been checked to hold
/// it, leaving the rest NUL.
fn copy_field(field: &mut [u8], value: &[u8]) {
    if let Some(slot) = field.get_mut(..value.len()) {
        slot.copy_from_slice(value);
    }
}

/// Writes one layer tar in memory: ustar headers only, entries in the order
/// requested, and the two-block end marker.
fn write_layer_tar(entries: &[LayerEntry]) -> io::Result<Vec<u8>> {
    #[cfg(test)]
    seam::record_tar_write();
    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        let written = written_name(entry);
        let (prefix, name) = ustar_split(&written).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "an entry name that was checked to fit a ustar header does not",
            )
        })?;
        let (mut header, data): (tar::Header, &[u8]) = match entry {
            LayerEntry::File { bytes, .. } => (
                fixed_header(tar::EntryType::Regular, FILE_MODE, widen(bytes.0.len())),
                &bytes.0,
            ),
            LayerEntry::Directory { .. } => (
                fixed_header(tar::EntryType::Directory, DIRECTORY_MODE, 0),
                &[],
            ),
            LayerEntry::Symlink { target, .. } => {
                let mut header = fixed_header(tar::EntryType::Symlink, SYMLINK_MODE, 0);
                copy_field(&mut header.as_old_mut().linkname, target.as_bytes());
                (header, &[])
            }
        };
        set_ustar_name(&mut header, prefix, name);
        header.set_cksum();
        builder.append(&header, data)?;
    }
    builder.into_inner()
}

/// Appends one image-level regular file: mode `0o644`, mtime, uid and gid 0.
fn append_file(
    builder: &mut tar::Builder<Vec<u8>>,
    name: &str,
    data: &[u8],
) -> Result<(), SyntheticImageError> {
    let mut header = fixed_header(tar::EntryType::Regular, FILE_MODE, widen(data.len()));
    set_ustar_name(&mut header, "", name);
    header.set_cksum();
    builder.append(&header, data)?;
    Ok(())
}

/// Compresses `tar` as one gzip member at level 6, with mtime 0, OS 255 and
/// no filename, comment or extra field.
fn gzip(tar: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(GZIP_OS_UNKNOWN)
        .write(Vec::new(), Compression::new(GZIP_LEVEL));
    encoder.write_all(tar)?;
    encoder.finish()
}

/// The largest gzip blob accepted for a `decoded`-byte tar.
fn gzip_ceiling(decoded: u64) -> u64 {
    decoded
        .saturating_add(decoded / GZIP_CEILING_DIVISOR)
        .saturating_add(GZIP_CEILING_SLACK)
}

fn blob_path(hex: &str) -> String {
    format!("{BLOB_PREFIX}{hex}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

fn architecture_name(architecture: ImageArchitecture) -> &'static str {
    match architecture {
        ImageArchitecture::Amd64 => "amd64",
        ImageArchitecture::Arm64 => "arm64",
    }
}

fn os_name(os: ImageOs) -> &'static str {
    match os {
        ImageOs::Linux => LINUX,
    }
}

/// Widens an in-memory length to `u64`, which holds every `usize` on the
/// 64-bit targets this crate builds for.
fn widen(len: usize) -> u64 {
    crate::content::widen(len)
}

/// Test-only hooks into generation: a count of layer tar writes, and a
/// replacement for the next gzip blob.
#[cfg(test)]
mod seam {
    use std::cell::Cell;

    /// What to replace a generated gzip blob with.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum GzipReplacement {
        /// A blob exactly at the ceiling.
        AtCeiling,
        /// A blob one byte over it.
        OverCeiling,
    }

    thread_local! {
        static TAR_WRITES: Cell<usize> = const { Cell::new(0) };
        static GZIP: Cell<Option<GzipReplacement>> = const { Cell::new(None) };
    }

    pub(super) fn record_tar_write() {
        TAR_WRITES.with(|writes| writes.set(writes.get() + 1));
    }

    /// Returns and resets the number of layer tars written on this thread.
    pub(super) fn take_tar_writes() -> usize {
        TAR_WRITES.with(|writes| writes.replace(0))
    }

    /// Replaces the next gzip blob generated on this thread.
    pub(super) fn replace_next_gzip(replacement: GzipReplacement) {
        GZIP.with(|gzip| gzip.set(Some(replacement)));
    }

    pub(super) fn replace_gzip(blob: Vec<u8>, ceiling: u64) -> Vec<u8> {
        let Some(replacement) = GZIP.with(Cell::take) else {
            return blob;
        };
        let len = match replacement {
            GzipReplacement::AtCeiling => ceiling,
            GzipReplacement::OverCeiling => ceiling + 1,
        };
        vec![0x1f; usize::try_from(len).unwrap()]
    }
}

#[cfg(test)]
mod raw;
#[cfg(test)]
mod tests;
