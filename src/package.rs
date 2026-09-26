//! Whole-package content verification, the evidence it returns, the resource
//! policy it enforces, and the retained bytes and publication it reads and
//! writes through. The package writer APIs, which reuse the same checks, will
//! land here too.
//!
//! # Full-content verification
//!
//! [`verify_contents`] turns an authenticated component package into
//! immutable, fully checked evidence. It is the one path image consumers
//! reach image bytes they can load through, and native and Compose consumers
//! get the same retained bytes to install from. It runs, in this order, and
//! the first failure is the result:
//!
//! 1. **snapshot** — the caller's source is sought to its start and copied
//!    exactly once into private retained storage, at most `Package` bytes;
//!    nothing after this reads the source again;
//! 2. **bounded authentication** — the footer is located and validated, its
//!    manifest and archive lengths are held to `RawManifest` and
//!    `CompressedArchive` before either block is read, and then the snapshot
//!    goes through the pipeline [`verify_package`](crate::verify::verify_package)
//!    runs: signature over the raw bytes, format and trust floor, typed parse,
//!    then completeness, identifiers, withdrawal, target, epoch and the image
//!    declaration passes, every verdict and its precedence unchanged;
//! 3. **architecture** — every artifact must be built for the one requested
//!    [`TargetArch`](crate::manifest::TargetArch); the host's is never
//!    inferred;
//! 4. **legacy refusal** — a container image without a declaration, which only
//!    an admitted legacy manifest can carry, is refused as
//!    [`ImageVerifyError::LegacyImageEvidence`](crate::verify::ImageVerifyError::LegacyImageEvidence)
//!    and never reported as no images;
//! 5. **outer extraction** — the whole archive block is decoded, every zstd
//!    frame's declared window held to `ZstdWindow` before that frame is
//!    decoded, and walked, member by member, into private snapshots, with
//!    every rule the legacy extraction applies — the same walk, not a copy of
//!    it — and `OuterMembers` and `OuterUncompressedTotal` enforced on what is
//!    actually read; every member and the archive's end are checked before
//!    any image is;
//! 6. **images** — each image archive, in manifest order and one at a time,
//!    against its signed declaration.
//!
//! Resource, framing and I/O refusals can come before the authentication
//! verdicts: a package over a limit, or whose storage fails, is refused for
//! that whatever its signature. No image semantics ever do. No success,
//! handle or callback escapes before every step has passed, and on failure
//! every snapshot the call made and its private directory are released.
//!
//! # Immutability and its boundary
//!
//! Validated content has to be read from bytes nothing outside this library
//! can change between the check and the use. [`RetainedBytes`] is that: a
//! read-only handle on a private, already unlinked copy the library made of
//! an untrusted source, readable only through a [`RetainedReader`]. It exposes
//! no path, file or descriptor, so caller writes, replaced pathnames and
//! descriptors the caller kept open on the original cannot reach it. Every
//! [`VerifiedContents`] accessor reads such bytes.
//!
//! The protection has a boundary. The caller supplies a trusted filesystem and
//! process isolation; nothing here defends against root, against other
//! processes running as the same user, against same-process memory access or
//! same-user `/proc` descriptor access, or against a malicious filesystem or
//! failing hardware. Retained copies are transient, not durable: the operating
//! system reclaims them when their last handle drops or the process exits.
//!
//! # What is not evidence
//!
//! [`VerifiedPackage`](crate::verify::VerifiedPackage) is a metadata handle
//! over authenticated statements, and
//! [`extract_to`](crate::verify::VerifiedPackage::extract_to) writes files a
//! caller can change afterwards; both remain legacy interfaces, and nothing
//! turns either into evidence. Neither does a path, a claimed hash, an
//! [`ExtractedArtifact`](crate::payload::ExtractedArtifact) or a document.
//!
//! Publishing retained bytes to a caller-chosen destination, through
//! [`VerifiedContents::publish_package`], reports through [`PublishedPackage`]
//! and [`PublicationError`]. A [`PublishedPackage`] is a receipt for a mutable
//! path, not evidence. Publication never replaces an existing entry, and a
//! failure after the output became visible is reported as
//! [`PublicationError::PublishDurability`] rather than as success or as a
//! clean failure. A failure before that point leaves the destination absent,
//! but may leave a dot-prefixed `.deploy-core-publish-<hex>.tmp` sibling
//! behind when its own removal fails; removing stale ones is the caller's job.
//!
//! # Blocking
//!
//! Everything here is synchronous: it starts no task or thread, never sleeps,
//! and reaches no network or container runtime. An async consumer runs it on
//! a blocking worker of its own and owns that worker's cancellation.
//!
//! # Resource policy
//!
//! [`ContentLimits`] is the policy every step enforces: the finite ceilings on
//! every resource reading a package's full content can consume — bytes stored
//! and decoded, entries, path lengths, JSON documents and nesting, disk and
//! buffers — together with [`LimitResource`], which names each ceiling, and
//! [`ContentLimitsError`], which reports a setting that was refused.
//!
//! The defaults are deliberately generous: they admit GB-scale images streamed
//! through bounded memory while still bounding parser state, decompression and
//! disk use. A caller may lower any of them for its own operation and never
//! raise one. Raising a default is a reviewed change to this library, not a
//! configuration choice, and nothing makes a resource unlimited.
//!
//! These are operational ceilings only. They change neither the manifest
//! versions a verifier accepts nor any trust floor.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::content::ResourceLimit;
use crate::payload::to_hex;
use crate::retain::Charge;

mod contents;
mod source;

// The unsigned-content core and the retained entry point, which the package
// preparation and detached finalization work reuses. Only `contents` itself
// calls them until that work lands, so the re-export is unused until then.
#[allow(unused_imports)]
pub(crate) use contents::{CheckedContents, check_contents, verify_retained};
pub use contents::{
    ContentError, IoOperation, VerifiedArtifact, VerifiedContents, VerifiedImage, VerifiedImageSet,
    VerifiedImages, verify_contents,
};
pub(crate) use source::RetainedIoFault;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Smallest `ZstdWindow` a caller may set: a 1 KiB window, the least zstd
/// itself can describe.
const MIN_ZSTD_WINDOW: u64 = 1024;

/// A read-only handle on bytes the library copied once into private storage.
///
/// The bytes are those of exactly one pass over the source, taken before any
/// check ran on them; [`len`](Self::len) and [`sha256`](Self::sha256) describe
/// them and never change. Every read goes to the same unlinked inode through a
/// [`RetainedReader`], and the handle offers no way to reach a path, a file or
/// a descriptor.
///
/// A `RetainedBytes` cannot be made outside this crate:
///
/// ```compile_fail
/// let bytes = deploy_core::package::RetainedBytes::default();
/// ```
///
/// ```compile_fail
/// fn forge(file: std::fs::File) -> deploy_core::package::RetainedBytes {
///     deploy_core::package::RetainedBytes { backing: todo!() }
/// }
/// ```
///
/// nor copied by a caller:
///
/// ```compile_fail
/// fn copy(bytes: &deploy_core::package::RetainedBytes) -> deploy_core::package::RetainedBytes {
///     bytes.clone()
/// }
/// ```
///
/// and it offers no descriptor, path or inner file:
///
/// ```compile_fail
/// use std::os::fd::AsRawFd;
/// fn fd(bytes: &deploy_core::package::RetainedBytes) -> i32 {
///     bytes.as_raw_fd()
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::AsFd;
/// fn fd(bytes: &deploy_core::package::RetainedBytes) {
///     let _ = bytes.as_fd();
/// }
/// ```
///
/// ```compile_fail
/// fn path(bytes: &deploy_core::package::RetainedBytes) -> &std::path::Path {
///     bytes.path()
/// }
/// ```
///
/// ```compile_fail
/// fn file(bytes: deploy_core::package::RetainedBytes) -> std::fs::File {
///     bytes.into_inner()
/// }
/// ```
pub struct RetainedBytes {
    backing: Arc<Backing>,
}

/// What every handle sharing one retained copy owns together.
struct Backing {
    file: File,
    len: u64,
    sha256: [u8; 32],
    /// Held for its drop: the budget charge for the bytes this inode holds
    /// is released with the last handle.
    _charge: Charge,
}

impl RetainedBytes {
    /// Wraps a finished snapshot: `file` is read-only, its name is gone, and
    /// `len` and `sha256` describe exactly the bytes written to it.
    pub(crate) fn new(file: File, len: u64, sha256: [u8; 32], charge: Charge) -> Self {
        Self {
            backing: Arc::new(Backing {
                file,
                len,
                sha256,
                _charge: charge,
            }),
        }
    }

    /// Returns another handle on the same retained copy.
    pub(crate) fn share(&self) -> RetainedBytes {
        Self {
            backing: Arc::clone(&self.backing),
        }
    }

    /// Returns the number of retained bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.backing.len
    }

    /// Returns whether no byte was retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backing.len == 0
    }

    /// Returns the SHA-256 digest of exactly the retained bytes.
    #[must_use]
    pub fn sha256(&self) -> &[u8; 32] {
        &self.backing.sha256
    }

    /// Returns a reader over the retained bytes, positioned at the start.
    ///
    /// Each reader keeps its own cursor, so readers never disturb each other.
    #[must_use]
    pub fn reader(&self) -> RetainedReader<'_> {
        RetainedReader {
            backing: &self.backing,
            pos: 0,
        }
    }

    /// Returns the raw descriptor number, for the close-on-exec test.
    #[cfg(test)]
    pub(crate) fn raw_fd_for_test(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.backing.file.as_raw_fd()
    }
}

impl fmt::Debug for RetainedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedBytes")
            .field("len", &self.backing.len)
            .field("sha256", &to_hex(&self.backing.sha256))
            .finish()
    }
}

/// A reader over [`RetainedBytes`], with its own cursor.
///
/// It reads positionally, so any number of readers over one retained copy
/// return identical bytes. Its errors are plain [`io::Error`]s with no path,
/// because the retained copy has none.
///
/// A reader cannot outlive the bytes it reads:
///
/// ```compile_fail
/// fn detach(bytes: deploy_core::package::RetainedBytes) -> deploy_core::package::RetainedReader<'static> {
///     bytes.reader()
/// }
/// ```
///
/// and it offers no descriptor, path or inner file:
///
/// ```compile_fail
/// use std::os::fd::AsRawFd;
/// fn fd(reader: &deploy_core::package::RetainedReader<'_>) -> i32 {
///     reader.as_raw_fd()
/// }
/// ```
///
/// ```compile_fail
/// use std::os::fd::AsFd;
/// fn fd(reader: &deploy_core::package::RetainedReader<'_>) {
///     let _ = reader.as_fd();
/// }
/// ```
///
/// ```compile_fail
/// fn path<'a>(reader: &'a deploy_core::package::RetainedReader<'_>) -> &'a std::path::Path {
///     reader.path()
/// }
/// ```
///
/// ```compile_fail
/// fn file(reader: deploy_core::package::RetainedReader<'_>) -> std::fs::File {
///     reader.into_inner()
/// }
/// ```
pub struct RetainedReader<'a> {
    backing: &'a Backing,
    pos: u64,
}

impl fmt::Debug for RetainedReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedReader")
            .field("len", &self.backing.len)
            .field("pos", &self.pos)
            .finish()
    }
}

impl Read for RetainedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(remaining) = self.backing.len.checked_sub(self.pos).filter(|&r| r > 0) else {
            return Ok(0);
        };
        let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let Some(window) = buf.get_mut(..want) else {
            return Ok(0);
        };
        if window.is_empty() {
            return Ok(0);
        }
        let read = self.backing.file.read_at(window, self.pos)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "retained bytes ended before their recorded length",
            ));
        }
        self.pos = self
            .pos
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("retained reader position overflowed"))?;
        Ok(read)
    }
}

impl Seek for RetainedReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(offset) => self.backing.len.checked_add_signed(offset),
            SeekFrom::Current(offset) => self.pos.checked_add_signed(offset),
        };
        let target = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative or overflowing position",
            )
        })?;
        self.pos = target;
        Ok(target)
    }
}

/// The receipt for a successful publication.
///
/// It records what was published, not what is there now: the destination is
/// an ordinary path anyone with access can change afterwards, so it is not
/// evidence of anything.
#[derive(Debug, Clone)]
pub struct PublishedPackage {
    destination: PathBuf,
    sha256: [u8; 32],
    len: u64,
}

impl PublishedPackage {
    pub(crate) fn new(destination: PathBuf, sha256: [u8; 32], len: u64) -> Self {
        Self {
            destination,
            sha256,
            len,
        }
    }

    /// Returns the path the bytes were published to.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the SHA-256 digest of the published bytes.
    #[must_use]
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Returns the number of published bytes.
    // A receipt reports a length; an `is_empty` beside it would be a second
    // spelling of `len() == 0` that no caller of a receipt has asked for.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }
}

/// Why a publication failed.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    /// An entry of some type — a file, a directory, a symlink, dangling or
    /// not — already exists at the destination. It was left untouched.
    #[error("publication destination {} already exists", .destination.display())]
    DestinationExists { destination: PathBuf },

    /// The destination path, or its parent directory, was refused by the
    /// directory trust policy.
    #[error("publication destination {} is not trusted: {reason}", .path.display())]
    UnsafeDestinationParent {
        path: PathBuf,
        reason: DirectoryTrustReason,
    },

    /// The operation's retained-disk budget ran out. This is the library's
    /// own limit, distinct from a full filesystem, which is
    /// [`PublicationError::Io`] carrying the operating system's error kind.
    #[error("publication exceeded the retained-disk budget of {limit} bytes")]
    DiskBudgetExceeded { limit: u64 },

    /// A filesystem operation failed before the output was published. `path`
    /// is `None` only for [`PublicationOperation::ReadRetained`], whose
    /// retained copy has no path.
    #[error("{operation} failed{}: {source}", describe_path(.path.as_deref()))]
    Io {
        operation: PublicationOperation,
        path: Option<PathBuf>,
        #[source]
        source: io::Error,
    },

    /// The synced copy read back differently from the retained bytes.
    #[error("published copy {} does not match the retained bytes: {kind}", .path.display())]
    CopyMismatch {
        path: PathBuf,
        kind: CopyMismatchKind,
    },

    /// A step after the publish point failed. The complete output may
    /// already be present at `destination`; its durability is uncertain.
    #[error(
        "{operation} failed after {} was published; the complete output may already be present, durability is uncertain: {source}",
        .destination.display()
    )]
    PublishDurability {
        destination: PathBuf,
        operation: PublicationOperation,
        #[source]
        source: io::Error,
    },
}

fn describe_path(path: Option<&Path>) -> String {
    path.map(|path| format!(" at {}", path.display()))
        .unwrap_or_default()
}

/// How a published copy differed from its retained bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMismatchKind {
    /// The copy holds a different number of bytes.
    Length { expected: u64, actual: u64 },
    /// The copy has the right length but a different SHA-256 digest.
    Digest,
}

impl fmt::Display for CopyMismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "expected {expected} bytes, found {actual}")
            }
            Self::Digest => f.write_str("sha-256 digest differs"),
        }
    }
}

/// The publication step a [`PublicationError`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationOperation {
    /// Opening and judging the destination's parent directory.
    OpenDestinationParent,
    /// Checking whether the destination already exists.
    InspectDestination,
    /// Creating the staging directory a directory is assembled in.
    CreateStagingDirectory,
    /// Creating a temporary file.
    CreateTemporary,
    /// Reading the retained bytes being published.
    ReadRetained,
    /// Writing a temporary file.
    WriteTemporary,
    /// Flushing a temporary file to disk.
    SyncFile,
    /// Reading a synced temporary back to verify it.
    Verify,
    /// Flushing a directory to disk.
    SyncDirectory,
    /// Linking the temporary file into place.
    Link,
    /// Renaming the staging directory into place.
    Rename,
    /// Removing the temporary name after the publish point.
    RemoveTemporary,
}

impl fmt::Display for PublicationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenDestinationParent => "opening the destination parent",
            Self::InspectDestination => "inspecting the destination",
            Self::CreateStagingDirectory => "creating the staging directory",
            Self::CreateTemporary => "creating a temporary file",
            Self::ReadRetained => "reading the retained bytes",
            Self::WriteTemporary => "writing a temporary file",
            Self::SyncFile => "syncing a temporary file",
            Self::Verify => "verifying a temporary file",
            Self::SyncDirectory => "syncing a directory",
            Self::Link => "linking the output into place",
            Self::Rename => "renaming the output into place",
            Self::RemoveTemporary => "removing the temporary name",
        })
    }
}

/// Why a directory was refused as a staging parent or a publication
/// destination parent.
///
/// These checks stop unrelated users from redirecting or replacing the
/// library's storage. They do not defend against root, against other
/// processes of the effective user, or against a malicious filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryTrustReason {
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path has an empty, `.` or `..` segment, or a trailing `/`. The
    /// library never canonicalizes; a caller may before passing it in.
    NotCanonical,
    /// A publication destination is exactly `/`, so it names nothing to
    /// create.
    NoFinalComponent,
    /// A component on the path is a symbolic link.
    SymlinkComponent,
    /// A component on the path exists but is not a directory.
    NotDirectory,
    /// An ancestor is owned by someone other than root or the effective
    /// user, or is writable by others without being a root-owned sticky
    /// directory over a child the effective user or root owns.
    UntrustedAncestor,
    /// The directory is owned by someone other than root or the effective
    /// user.
    UntrustedOwner,
    /// The directory is group- or other-writable, sticky or not.
    GroupOrOtherWritable,
    /// The effective user cannot write to and search the directory by its
    /// mode bits.
    NotWritableByEffectiveUser,
}

impl DirectoryTrustReason {
    /// Returns the [`io::ErrorKind`] a consumer reporting this refusal as
    /// I/O uses.
    pub(crate) fn io_kind(self) -> io::ErrorKind {
        match self {
            Self::NotAbsolute
            | Self::NotCanonical
            | Self::NoFinalComponent
            | Self::SymlinkComponent
            | Self::NotDirectory => io::ErrorKind::InvalidInput,
            Self::UntrustedAncestor
            | Self::UntrustedOwner
            | Self::GroupOrOtherWritable
            | Self::NotWritableByEffectiveUser => io::ErrorKind::PermissionDenied,
        }
    }
}

impl fmt::Display for DirectoryTrustReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAbsolute => "the path is not absolute",
            Self::NotCanonical => "the path is not canonical",
            Self::NoFinalComponent => "the path has no final component",
            Self::SymlinkComponent => "a path component is a symbolic link",
            Self::NotDirectory => "a path component is not a directory",
            Self::UntrustedAncestor => "an ancestor directory is not trusted",
            Self::UntrustedOwner => "the directory is owned by another user",
            Self::GroupOrOtherWritable => "the directory is group- or other-writable",
            Self::NotWritableByEffectiveUser => "the effective user cannot write to the directory",
        })
    }
}

/// Declares [`LimitResource`], its default table and its labels, and the
/// private per-resource storage of [`ContentLimits`], from one table, so a
/// resource cannot gain a variant without also gaining a default, a label and
/// a slot.
macro_rules! limit_resources {
    ($(
        $(#[$doc:meta])*
        $variant:ident => $field:ident, $label:literal, $default:expr;
    )*) => {
        /// One finite resource a [`ContentLimits`] bounds.
        ///
        /// Each variant names a single ceiling. Its [`Display`](fmt::Display)
        /// form is a fixed lowercase label, such as `decoded layer`, suitable
        /// for a diagnostic.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum LimitResource {
            $(
                $(#[$doc])*
                $variant,
            )*
        }

        impl LimitResource {
            /// Every resource exactly once, in the order of the default table.
            pub const ALL: &'static [LimitResource] = &[$(LimitResource::$variant,)*];

            /// Returns the library default for this resource, which is also
            /// the highest value [`ContentLimits::with_limit`] accepts for it.
            #[must_use]
            pub fn default_limit(self) -> u64 {
                match self {
                    $(LimitResource::$variant => $default,)*
                }
            }

            fn label(self) -> &'static str {
                match self {
                    $(LimitResource::$variant => $label,)*
                }
            }
        }

        /// The configured value of every resource, one private slot each.
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct LimitValues {
            $($field: u64,)*
        }

        impl Default for LimitValues {
            fn default() -> Self {
                Self {
                    $($field: $default,)*
                }
            }
        }

        impl LimitValues {
            fn get(&self, resource: LimitResource) -> u64 {
                match resource {
                    $(LimitResource::$variant => self.$field,)*
                }
            }

            fn slot(&mut self, resource: LimitResource) -> &mut u64 {
                match resource {
                    $(LimitResource::$variant => &mut self.$field,)*
                }
            }
        }
    };
}

limit_resources! {
    /// Bytes of one package's raw manifest.
    RawManifest => raw_manifest, "raw manifest", 16 * MIB;
    /// Bytes of one package's compressed archive block.
    CompressedArchive => compressed_archive, "compressed archive", 64 * GIB;
    /// Bytes of one whole package file: the archive block, the manifest and
    /// the fixed-size envelope around them.
    Package => package, "package", 64 * GIB + 16 * MIB + 201;
    /// Members of one package's outer archive.
    OuterMembers => outer_members, "outer members", 1024;
    /// Uncompressed bytes across every member of one package's outer archive.
    OuterUncompressedTotal => outer_uncompressed_total, "outer uncompressed total", 128 * GIB;
    /// Bytes of one image archive: the docker-save tar a package carries.
    ImageArchive => image_archive, "image archive", 32 * GIB;
    /// Stored bytes of one layer blob, before any decompression.
    StoredLayerBlob => stored_layer_blob, "stored layer blob", 16 * GIB;
    /// Decoded bytes of one layer.
    DecodedLayer => decoded_layer, "decoded layer", 16 * GIB;
    /// Decoded bytes across every layer of one image.
    DecodedLayersPerImage => decoded_layers_per_image, "decoded layers per image", 128 * GIB;
    /// Decoded bytes across every layer one operation reads.
    DecodedLayersPerOperation => decoded_layers_per_operation, "decoded layers per operation", 256 * GIB;
    /// Bytes of one gzip member header, from its first magic byte through its
    /// header CRC.
    GzipHeader => gzip_header, "gzip header", 64 * KIB;
    /// Entries of one image archive.
    ImageEntries => image_entries, "image entries", 4096;
    /// Bytes of one image archive entry name, as written.
    ImagePathBytes => image_path_bytes, "image path bytes", 255;
    /// Layers of one image.
    LayersPerImage => layers_per_image, "layers per image", 256;
    /// Tags of one image.
    TagsPerImage => tags_per_image, "tags per image", 256;
    /// Bytes of one image's `index.json`.
    IndexJson => index_json, "index json", MIB;
    /// Bytes of one image's OCI image manifest.
    ImageManifestJson => image_manifest_json, "image manifest json", MIB;
    /// Bytes of one image's docker-save compatibility `manifest.json`.
    CompatibilityJson => compatibility_json, "compatibility json", MIB;
    /// Bytes of one image config.
    ConfigJson => config_json, "config json", 4 * MIB;
    /// Bytes of one image's `oci-layout`.
    OciLayout => oci_layout, "oci layout", KIB;
    /// Bytes across every JSON document of one image.
    ImageJsonTotal => image_json_total, "image json total", 16 * MIB;
    /// Nesting depth of one JSON document, counting each array or object as
    /// one level.
    JsonDepth => json_depth, "json depth", 64;
    /// Tar headers across every layer of one image, extension headers
    /// included.
    LayerEntries => layer_entries, "layer entries", 1_000_000;
    /// Bytes of one layer entry's effective name.
    LayerPathBytes => layer_path_bytes, "layer path bytes", 4096;
    /// Bytes of one layer entry's effective link target.
    LayerLinkTargetBytes => layer_link_target_bytes, "layer link target bytes", 4096;
    /// Payload bytes of one layer extension record.
    LayerExtension => layer_extension, "layer extension", 64 * KIB;
    /// Payload bytes across every layer extension record of one image.
    LayerExtensionTotal => layer_extension_total, "layer extension total", 64 * MIB;
    /// Bytes of disk one operation may retain.
    RetainedDisk => retained_disk, "retained disk", 512 * GIB;
    /// Bytes of one copy buffer, and so of any single request made of a
    /// caller's source.
    CopyBuffer => copy_buffer, "copy buffer", MIB;
    /// Bytes of the zstd window a decoder may use.
    ZstdWindow => zstd_window, "zstd window", 64 * MIB;
    /// Bytes of one preparation record.
    PreparationRecord => preparation_record, "preparation record", 64 * KIB;
}

impl LimitResource {
    /// Whether a zero setting would leave the resource unable to do any work
    /// at all rather than merely admitting nothing: a copy needs a buffer, a
    /// JSON document has a root, and a zstd frame has a window.
    fn refuses_zero(self) -> bool {
        matches!(
            self,
            LimitResource::CopyBuffer | LimitResource::JsonDepth | LimitResource::ZstdWindow
        )
    }
}

impl fmt::Display for LimitResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The finite resource policy every full-content package API enforces.
///
/// Every [`LimitResource`] has a value, which starts at the library default —
/// [`ContentLimits::default`] holds every [`LimitResource::default_limit`] —
/// and can only be lowered. There is no way to raise a value above its default
/// and no unlimited setting. A zero, where accepted, admits nothing of that
/// resource; it never disables the bound.
///
/// ```
/// use deploy_core::package::{ContentLimits, LimitResource};
///
/// let limits = ContentLimits::default()
///     .with_limit(LimitResource::JsonDepth, 10)?
///     .with_limit(LimitResource::JsonDepth, 20)?;
/// assert_eq!(limits.get(LimitResource::JsonDepth), 20);
/// # Ok::<(), deploy_core::package::ContentLimitsError>(())
/// ```
///
/// Its storage is private, so a value cannot be set around
/// [`with_limit`](Self::with_limit):
///
/// ```compile_fail
/// let limits = deploy_core::package::ContentLimits::default();
/// let _ = limits.values;
/// ```
///
/// and it cannot be read from a configuration document either, since it
/// implements neither `Deserialize` nor `Serialize`:
///
/// ```compile_fail
/// let _: deploy_core::package::ContentLimits = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentLimits {
    values: LimitValues,
}

impl ContentLimits {
    /// Returns the configured value of `resource`.
    #[must_use]
    pub fn get(&self, resource: LimitResource) -> u64 {
        self.values.get(resource)
    }

    /// Returns this policy with `resource` set to `value`, replacing whatever
    /// value it had.
    ///
    /// The ceiling is always the library default, never the current value, so
    /// a lowered value may be raised again as far as the default. Lowering one
    /// resource never checks or adjusts another. An accepted `ZstdWindow` is
    /// stored rounded down to the largest power of two not above it.
    ///
    /// # Errors
    ///
    /// Checked in this order:
    ///
    /// - [`ContentLimitsError::AboveDefault`] when `value` is above the
    ///   resource's default, which `u64::MAX` always is.
    /// - [`ContentLimitsError::Zero`] when `value` is zero and the resource is
    ///   `CopyBuffer`, `JsonDepth` or `ZstdWindow`.
    /// - [`ContentLimitsError::BelowMinimum`] when `value` is a `ZstdWindow`
    ///   below 1,024.
    ///
    /// On error the consumed policy is gone; clone it first to keep it.
    pub fn with_limit(
        mut self,
        resource: LimitResource,
        value: u64,
    ) -> Result<ContentLimits, ContentLimitsError> {
        let default = resource.default_limit();
        if value > default {
            return Err(ContentLimitsError::AboveDefault {
                resource,
                requested: value,
                default,
            });
        }
        if value == 0 && resource.refuses_zero() {
            return Err(ContentLimitsError::Zero { resource });
        }
        let stored = if resource == LimitResource::ZstdWindow {
            if value < MIN_ZSTD_WINDOW {
                return Err(ContentLimitsError::BelowMinimum {
                    resource,
                    requested: value,
                    minimum: MIN_ZSTD_WINDOW,
                });
            }
            1 << value.ilog2()
        } else {
            value
        };
        *self.values.slot(resource) = stored;
        Ok(self)
    }

    /// Returns `resource` with its configured value, the form every primitive
    /// takes a per-item limit in, so each fault names the resource it hit.
    pub(crate) fn resource_limit(&self, resource: LimitResource) -> ResourceLimit {
        ResourceLimit {
            resource,
            max: self.get(resource),
        }
    }

    /// Returns the configured `CopyBuffer` as a buffer length.
    pub(crate) fn copy_buffer_len(&self) -> usize {
        crate::content::alloc_len(
            self.get(LimitResource::CopyBuffer),
            self.resource_limit(LimitResource::CopyBuffer),
        )
        .expect("CopyBuffer never exceeds its 1 MiB default, which fits in usize on every target")
    }
}

/// A refused [`ContentLimits::with_limit`] setting.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContentLimitsError {
    /// The requested value is above the resource's library default.
    #[error("the {resource} limit {requested} is above its default of {default}")]
    AboveDefault {
        /// The resource being set.
        resource: LimitResource,
        /// The value that was requested.
        requested: u64,
        /// The library default, the highest value the resource accepts.
        default: u64,
    },
    /// The resource cannot be set to zero.
    #[error("the {resource} limit cannot be zero")]
    Zero {
        /// The resource being set.
        resource: LimitResource,
    },
    /// The requested value is below the smallest the resource accepts.
    #[error("the {resource} limit {requested} is below its minimum of {minimum}")]
    BelowMinimum {
        /// The resource being set.
        resource: LimitResource,
        /// The value that was requested.
        requested: u64,
        /// The smallest value the resource accepts.
        minimum: u64,
    },
}
