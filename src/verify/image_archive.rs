//! The typed reasons an image archive is refused for, carried by the archive
//! variants of [`ImageVerifyError`](super::ImageVerifyError).
//!
//! Every enum here is a closed discriminator. None carries archive content:
//! the only values any of them hold are positions, indices and header type
//! bytes, and every [`Display`](std::fmt::Display) form is a fixed lowercase
//! phrase built from those alone.

use std::fmt;

/// A named exclusion from the supported image archive profile, reported as
/// [`ImageVerifyError::UnsupportedArchive`](super::ImageVerifyError::UnsupportedArchive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedArchiveFeature {
    /// The image archive is a gzip or zstd stream rather than a plain tar.
    CompressedOuterStream,
    /// The image archive tar uses a format or header the profile excludes.
    ArchiveTar {
        /// The excluded tar feature.
        feature: TarFeature,
    },
    /// A file of the classic `docker save` layout: `repositories`, `VERSION`,
    /// a 64-hex layer directory or a `<64-hex>.json` config.
    LegacyExportFile,
    /// Any other entry outside the OCI layout files and `blobs/sha256`.
    ExtraFile,
    /// An index descriptor names another index rather than an image manifest.
    NestedIndex,
    /// An index descriptor is an attestation manifest.
    Attestation,
    /// The archive holds more than one image.
    MultipleImages,
    /// An image manifest media type other than the OCI image manifest.
    ManifestMediaType,
    /// A config media type other than the OCI image config.
    ConfigMediaType,
    /// A layer media type other than an uncompressed or gzip OCI layer.
    LayerMediaType {
        /// The layer's position in the manifest's `layers`.
        position: usize,
    },
    /// A descriptor or document carries a field that refers outside the
    /// archive or to another artifact.
    ExtensionField {
        /// The document holding the field.
        document: ImageDocument,
        /// The field.
        field: ExtensionField,
    },
    /// A descriptor carries an annotation the profile does not admit.
    DescriptorAnnotation,
    /// The image manifest carries an annotation the profile does not admit.
    ManifestAnnotation,
    /// A blob that neither the image manifest, its config nor its layers
    /// reference.
    UnreferencedBlob,
    /// A gzip layer holds a second member after the first.
    ConcatenatedGzipMember {
        /// The layer's position in the manifest's `layers`.
        position: usize,
    },
    /// A layer tar uses a format, entry type or PAX key the profile excludes.
    LayerTar {
        /// The layer's position in the manifest's `layers`.
        position: usize,
        /// The excluded tar feature.
        feature: TarFeature,
    },
}

impl fmt::Display for UnsupportedArchiveFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompressedOuterStream => f.write_str("a compressed outer image stream"),
            Self::ArchiveTar { feature } => write!(f, "{feature} in the image archive tar"),
            Self::LegacyExportFile => f.write_str("a legacy docker-save export file"),
            Self::ExtraFile => f.write_str("a file outside the image layout"),
            Self::NestedIndex => f.write_str("a nested image index"),
            Self::Attestation => f.write_str("an attestation manifest"),
            Self::MultipleImages => f.write_str("more than one image"),
            Self::ManifestMediaType => f.write_str("an unsupported image manifest media type"),
            Self::ConfigMediaType => f.write_str("an unsupported config media type"),
            Self::LayerMediaType { position } => {
                write!(f, "an unsupported media type for layer {position}")
            }
            Self::ExtensionField { document, field } => {
                write!(f, "the {field} field in the {document}")
            }
            Self::DescriptorAnnotation => f.write_str("an unsupported descriptor annotation"),
            Self::ManifestAnnotation => f.write_str("an unsupported image manifest annotation"),
            Self::UnreferencedBlob => f.write_str("an unreferenced blob"),
            Self::ConcatenatedGzipMember { position } => {
                write!(f, "a concatenated gzip member in layer {position}")
            }
            Self::LayerTar { position, feature } => write!(f, "{feature} in layer {position}"),
        }
    }
}

/// A tar feature the profile excludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarFeature {
    /// A header with a valid checksum but neither ustar nor GNU magic.
    Format,
    /// An entry type the profile excludes.
    EntryType {
        /// The header's typeflag byte.
        flag: u8,
    },
    /// A PAX key outside the permitted set.
    PaxKey,
}

impl fmt::Display for TarFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format => f.write_str("an unsupported tar format"),
            Self::EntryType { flag } => write!(f, "tar entry type {flag:#04x}"),
            Self::PaxKey => f.write_str("an unsupported pax key"),
        }
    }
}

/// A field that refers outside the archive or to another artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionField {
    /// `subject`.
    Subject,
    /// `artifactType`.
    ArtifactType,
    /// `urls`.
    Urls,
    /// `data`.
    Data,
}

impl fmt::Display for ExtensionField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Subject => "subject",
            Self::ArtifactType => "artifact type",
            Self::Urls => "urls",
            Self::Data => "data",
        })
    }
}

/// Why an image archive is malformed or internally inconsistent, reported as
/// [`ImageVerifyError::InvalidArchive`](super::ImageVerifyError::InvalidArchive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidArchiveReason {
    /// The image archive tar is malformed.
    Tar {
        /// What is wrong with it.
        fault: TarFault,
    },
    /// An OCI layout file is missing.
    MissingLayoutFile {
        /// The missing file.
        file: LayoutFile,
    },
    /// A JSON document is not valid JSON, or repeats a key.
    Json {
        /// The document.
        document: ImageDocument,
        /// What is wrong with it.
        fault: JsonFault,
    },
    /// A JSON document does not have the shape the profile requires.
    UnexpectedShape {
        /// The document.
        document: ImageDocument,
    },
    /// A descriptor platform's `variant` is the empty string.
    EmptyPlatformVariant {
        /// The descriptor carrying it.
        location: PlatformLocation,
    },
    /// A blob a descriptor or the compatibility manifest names is absent.
    MissingBlob {
        /// What the blob is.
        role: BlobRole,
    },
    /// A blob's stored length or digest disagrees with its descriptor.
    BlobMismatch {
        /// What the blob is.
        role: BlobRole,
        /// Which of the two disagrees.
        kind: BlobMismatchKind,
    },
    /// The compatibility manifest's config or layer paths disagree with the
    /// image manifest.
    InconsistentCompatibility,
    /// A compatibility `RepoTags` entry is not a valid tagged reference.
    InvalidRepoTag {
        /// Its index in `RepoTags`.
        index: usize,
    },
    /// One tag is named twice.
    DuplicateTag {
        /// Where.
        source: ReferenceSource,
    },
    /// An index descriptor's reference annotations are missing or invalid.
    InvalidAnnotation {
        /// The descriptor's index in `manifests`.
        index: usize,
    },
    /// The image config breaks the config profile.
    InvalidConfig {
        /// Which rule it breaks.
        reason: InvalidConfigReason,
    },
    /// A gzip layer's stream is malformed.
    Gzip {
        /// The layer's position in the manifest's `layers`.
        position: usize,
        /// What is wrong with it.
        fault: GzipFault,
    },
    /// A layer's decoded tar is malformed.
    LayerTar {
        /// The layer's position in the manifest's `layers`.
        position: usize,
        /// What is wrong with it.
        fault: TarFault,
    },
    /// The compatibility manifest's `LayerSources` disagree with the image
    /// manifest's layers.
    InconsistentLayerSources,
}

impl fmt::Display for InvalidArchiveReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tar { fault } => write!(f, "the image archive tar is malformed: {fault}"),
            Self::MissingLayoutFile { file } => write!(f, "the {file} file is missing"),
            Self::Json { document, fault } => write!(f, "the {document} {fault}"),
            Self::UnexpectedShape { document } => {
                write!(f, "the {document} does not have the expected shape")
            }
            Self::EmptyPlatformVariant { location } => {
                write!(f, "the platform variant of the {location} is empty")
            }
            Self::MissingBlob { role } => write!(f, "the {role} blob is missing"),
            Self::BlobMismatch { role, kind } => {
                write!(f, "the {role} blob {kind} does not match its descriptor")
            }
            Self::InconsistentCompatibility => {
                f.write_str("the compatibility manifest disagrees with the image manifest")
            }
            Self::InvalidRepoTag { index } => {
                write!(f, "repo tag {index} is not a valid tagged reference")
            }
            Self::DuplicateTag { source } => write!(f, "a tag is repeated in the {source}"),
            Self::InvalidAnnotation { index } => {
                write!(
                    f,
                    "the reference annotations of index descriptor {index} are invalid"
                )
            }
            Self::InvalidConfig { reason } => write!(f, "the image config is invalid: {reason}"),
            Self::Gzip { position, fault } => {
                write!(
                    f,
                    "the gzip stream of layer {position} is malformed: {fault}"
                )
            }
            Self::LayerTar { position, fault } => {
                write!(f, "the tar of layer {position} is malformed: {fault}")
            }
            Self::InconsistentLayerSources => {
                f.write_str("the compatibility layer sources disagree with the image manifest")
            }
        }
    }
}

/// What is wrong with a tar stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarFault {
    /// The stream ends inside a structure that must be complete.
    Truncated,
    /// A header checksum does not match its bytes.
    Checksum,
    /// A header numeric field breaks its lexical rule.
    NumericField {
        /// The offending field.
        field: TarHeaderField,
    },
    /// A header name field has a non-NUL byte after its first NUL.
    NameField {
        /// The offending field.
        field: TarHeaderField,
    },
    /// An entry's data or padding end does not fit in a 64-bit offset.
    OffsetOverflow,
    /// A nonzero byte follows the start of the end-of-archive marker.
    TrailingData,
    /// The zero tail after the archive is longer than the format allows.
    ZeroTailTooLong,
    /// An entry name or hardlink target is not a safe relative path.
    UnsafePath,
    /// Two entries have the same canonical name and kind.
    DuplicatePath,
    /// Two entries claim one path as different kinds, or a file is used as a
    /// directory.
    PathConflict,
    /// An entry that is not a regular file carries data.
    NonRegularWithData,
    /// A PAX record breaks the record grammar.
    PaxRecord,
    /// One PAX extended header repeats a key.
    PaxDuplicateKey,
    /// A PAX value breaks the grammar of its key.
    PaxValue {
        /// The key whose value was refused.
        key: PaxKey,
    },
    /// A GNU long-name or long-link payload has an interior NUL.
    ExtensionPayload,
    /// A second extension record of one kind precedes the same entry.
    DuplicateExtension,
    /// A PAX record and a GNU record both supply a name, or both a link
    /// target.
    ConflictingAuthority,
    /// An extension record is followed by the end of the archive.
    DanglingExtension,
    /// A link target is supplied for an entry that is not a link.
    LinkOnNonLink,
}

impl fmt::Display for TarFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the tar ends early"),
            Self::Checksum => f.write_str("a header checksum does not match"),
            Self::NumericField { field } => {
                write!(f, "the header {field} field is not a valid number")
            }
            Self::NameField { field } => {
                write!(f, "the header {field} field has bytes after its terminator")
            }
            Self::OffsetOverflow => f.write_str("an entry end offset overflows"),
            Self::TrailingData => f.write_str("nonzero bytes follow the end of the tar"),
            Self::ZeroTailTooLong => f.write_str("the zero tail is too long"),
            Self::UnsafePath => f.write_str("an entry path is unsafe"),
            Self::DuplicatePath => f.write_str("an entry path is repeated"),
            Self::PathConflict => f.write_str("entry paths conflict"),
            Self::NonRegularWithData => f.write_str("a non-regular entry carries data"),
            Self::PaxRecord => f.write_str("a pax record is malformed"),
            Self::PaxDuplicateKey => f.write_str("a pax key is repeated"),
            Self::PaxValue { key } => write!(f, "the pax {key} value is malformed"),
            Self::ExtensionPayload => {
                f.write_str("a gnu long-name or long-link payload is malformed")
            }
            Self::DuplicateExtension => {
                f.write_str("an extension record is repeated for one entry")
            }
            Self::ConflictingAuthority => {
                f.write_str("two extension records supply the same value")
            }
            Self::DanglingExtension => f.write_str("an extension record applies to no entry"),
            Self::LinkOnNonLink => f.write_str("a link target is supplied for a non-link entry"),
        }
    }
}

/// A tar header field, as POSIX ustar names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarHeaderField {
    /// `name`.
    Name,
    /// `mode`.
    Mode,
    /// `uid`.
    Uid,
    /// `gid`.
    Gid,
    /// `size`.
    Size,
    /// `mtime`.
    Mtime,
    /// `chksum`.
    Checksum,
    /// `linkname`.
    Linkname,
    /// `devmajor`.
    DevMajor,
    /// `devminor`.
    DevMinor,
    /// `prefix`.
    Prefix,
}

impl fmt::Display for TarHeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Name => "name",
            Self::Mode => "mode",
            Self::Uid => "uid",
            Self::Gid => "gid",
            Self::Size => "size",
            Self::Mtime => "mtime",
            Self::Checksum => "checksum",
            Self::Linkname => "linkname",
            Self::DevMajor => "devmajor",
            Self::DevMinor => "devminor",
            Self::Prefix => "prefix",
        })
    }
}

/// A permitted PAX key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaxKey {
    /// `path`.
    Path,
    /// `linkpath`.
    Linkpath,
    /// `size`.
    Size,
    /// `uid`.
    Uid,
    /// `gid`.
    Gid,
    /// `uname`.
    Uname,
    /// `gname`.
    Gname,
    /// `mtime`.
    Mtime,
    /// `atime`.
    Atime,
    /// `ctime`.
    Ctime,
    /// Any key beginning `SCHILY.xattr.`.
    Xattr,
}

impl fmt::Display for PaxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Path => "path",
            Self::Linkpath => "linkpath",
            Self::Size => "size",
            Self::Uid => "uid",
            Self::Gid => "gid",
            Self::Uname => "uname",
            Self::Gname => "gname",
            Self::Mtime => "mtime",
            Self::Atime => "atime",
            Self::Ctime => "ctime",
            Self::Xattr => "xattr",
        })
    }
}

/// What is wrong with a gzip layer stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipFault {
    /// The member header is malformed.
    Header {
        /// Which header check failed.
        fault: GzipHeaderFault,
    },
    /// The DEFLATE stream is malformed.
    Deflate,
    /// The CRC32 does not match the decoded bytes.
    Crc32,
    /// The ISIZE does not match the decoded length.
    Isize,
    /// The stream ends inside the member.
    Truncated,
    /// Bytes other than a second member follow the trailer.
    TrailingData,
}

impl fmt::Display for GzipFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header { fault } => write!(f, "the header is malformed: {fault}"),
            Self::Deflate => f.write_str("the deflate data is malformed"),
            Self::Crc32 => f.write_str("the crc32 does not match"),
            Self::Isize => f.write_str("the isize does not match"),
            Self::Truncated => f.write_str("the stream ends early"),
            Self::TrailingData => f.write_str("bytes follow the trailer"),
        }
    }
}

/// Which gzip header check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipHeaderFault {
    /// The first two bytes are not `1f 8b`.
    Magic,
    /// The compression method is not DEFLATE.
    Method,
    /// A reserved flag bit is set.
    ReservedFlags,
    /// The header CRC does not match the header bytes.
    HeaderCrc,
}

impl fmt::Display for GzipHeaderFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Magic => "bad magic",
            Self::Method => "unknown compression method",
            Self::ReservedFlags => "reserved flag set",
            Self::HeaderCrc => "header crc mismatch",
        })
    }
}

/// What is wrong with a JSON document that is not a shape question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonFault {
    /// It breaks the JSON grammar or is not UTF-8.
    Syntax,
    /// An object repeats a key.
    DuplicateKey,
}

impl fmt::Display for JsonFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => "is not valid json",
            Self::DuplicateKey => "repeats a json object key",
        })
    }
}

/// An OCI layout file every image archive must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutFile {
    /// `oci-layout`.
    OciLayout,
    /// `index.json`.
    Index,
    /// The compatibility `manifest.json`.
    CompatibilityManifest,
}

impl fmt::Display for LayoutFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OciLayout => "oci-layout",
            Self::Index => "index.json",
            Self::CompatibilityManifest => "manifest.json",
        })
    }
}

/// A JSON document of an image archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageDocument {
    /// `oci-layout`.
    OciLayout,
    /// `index.json`.
    Index,
    /// The compatibility `manifest.json`.
    CompatibilityManifest,
    /// The OCI image manifest blob.
    ImageManifest,
    /// The image config blob.
    Config,
}

impl fmt::Display for ImageDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OciLayout => "oci-layout file",
            Self::Index => "index.json",
            Self::CompatibilityManifest => "compatibility manifest.json",
            Self::ImageManifest => "image manifest",
            Self::Config => "image config",
        })
    }
}

/// What a blob is to the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobRole {
    /// The image manifest.
    Manifest,
    /// The image config.
    Config,
    /// A layer.
    Layer {
        /// The layer's position in the manifest's `layers`.
        position: usize,
    },
}

impl fmt::Display for BlobRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest => f.write_str("image manifest"),
            Self::Config => f.write_str("config"),
            Self::Layer { position } => write!(f, "layer {position}"),
        }
    }
}

/// Which property of a stored blob disagrees with its descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobMismatchKind {
    /// Its length.
    Length,
    /// Its SHA-256 digest.
    Digest,
}

impl fmt::Display for BlobMismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "length",
            Self::Digest => "digest",
        })
    }
}

/// Which config profile rule an image config breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidConfigReason {
    /// The config is not a JSON object.
    NotObject,
    /// A required field is absent.
    MissingField {
        /// The field.
        field: ConfigField,
    },
    /// A checked field has the wrong JSON type.
    FieldType {
        /// The field.
        field: ConfigField,
    },
    /// `variant` is the empty string.
    EmptyVariant,
    /// `rootfs` is not exactly `type` `"layers"` and a `diff_ids` array.
    RootfsShape,
    /// A diff ID is not `sha256:` and 64 lowercase hex characters.
    DiffIdSyntax {
        /// Its index in `diff_ids`.
        index: usize,
    },
    /// A `history` entry is not an object, or its `empty_layer` is not a
    /// boolean.
    HistoryEntryShape {
        /// Its index in `history`.
        index: usize,
    },
    /// The non-empty `history` entries do not match the diff IDs in number.
    HistoryLayerCount,
}

impl fmt::Display for InvalidConfigReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObject => f.write_str("it is not an object"),
            Self::MissingField { field } => write!(f, "the {field} field is missing"),
            Self::FieldType { field } => write!(f, "the {field} field has the wrong type"),
            Self::EmptyVariant => f.write_str("the variant is empty"),
            Self::RootfsShape => f.write_str("the rootfs does not have the expected shape"),
            Self::DiffIdSyntax { index } => write!(f, "diff id {index} is not a sha256 digest"),
            Self::HistoryEntryShape { index } => {
                write!(f, "history entry {index} does not have the expected shape")
            }
            Self::HistoryLayerCount => {
                f.write_str("the history does not match the diff ids in layer count")
            }
        }
    }
}

/// A config field the profile checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigField {
    /// `architecture`.
    Architecture,
    /// `os`.
    Os,
    /// `variant`.
    Variant,
    /// `rootfs`.
    Rootfs,
    /// `history`.
    History,
}

impl fmt::Display for ConfigField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Architecture => "architecture",
            Self::Os => "os",
            Self::Variant => "variant",
            Self::Rootfs => "rootfs",
            Self::History => "history",
        })
    }
}

/// Where an image archive names the references it is restored under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSource {
    /// The compatibility manifest's `RepoTags`.
    RepoTags,
    /// The index descriptors' reference annotations.
    IndexAnnotation,
}

impl fmt::Display for ReferenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RepoTags => "repo tags",
            Self::IndexAnnotation => "index annotations",
        })
    }
}

/// Where an image archive states a platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformLocation {
    /// The image config.
    Config,
    /// An index descriptor's `platform`.
    IndexDescriptor {
        /// The descriptor's index in `manifests`.
        index: usize,
    },
    /// The image manifest's config descriptor's `platform`.
    ConfigDescriptor,
}

impl fmt::Display for PlatformLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => f.write_str("image config"),
            Self::IndexDescriptor { index } => write!(f, "index descriptor {index}"),
            Self::ConfigDescriptor => f.write_str("config descriptor"),
        }
    }
}

/// One facet of a platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformFacet {
    /// `os`.
    Os,
    /// `architecture`.
    Architecture,
    /// `variant`.
    Variant,
}

impl fmt::Display for PlatformFacet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Os => "os",
            Self::Architecture => "architecture",
            Self::Variant => "variant",
        })
    }
}

/// How the archive's layers disagree with its config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerMismatchKind {
    /// The compatibility manifest lists a different number of layers than the
    /// config has diff IDs.
    CountMismatch,
    /// A stored layer blob does not hash to its descriptor's digest.
    StoredDigest,
    /// A decoded layer does not hash to its diff ID.
    DiffId,
}

impl fmt::Display for LayerMismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CountMismatch => "layer count",
            Self::StoredDigest => "stored digest",
            Self::DiffId => "diff id",
        })
    }
}
