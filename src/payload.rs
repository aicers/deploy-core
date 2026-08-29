//! Self-extracting payload trailer format.
//!
//! A payload is a trailer appended to the bootler executable rather than
//! embedded with `include_bytes!`, so GB-scale payloads never pass through
//! rustc or the linker and dev builds can run with no payload at all (RFC 0001
//! §3). This module provides the writer that appends a trailer onto a base
//! binary and the reader that locates, parses, verifies, and extracts it.
//!
//! # On-disk layout
//!
//! The same container is read whether it rides on a base executable or not. A
//! self-contained release asset is `base ‖ trailer`; a **`.pkg` module package**
//! is the very same trailer with **no base**, so its manifest block starts at
//! offset `0`. One reader serves both (see [`open`] and [`open_package`]).
//!
//! From the start of the appended region to end-of-file, the trailer holds four
//! kinds of block followed by the footer:
//!
//! 1. **Manifest block** — a [`PayloadManifest`] serialized as JSON.
//! 2. **Archive block** — a `tar` archive of the artifact files (each member
//!    keyed by its `archive_path`), `zstd`-compressed. Its shape — how many
//!    members it holds, what they are called, in what order and how long each
//!    one is — is stated by the manifest's `archive_members`, which the reader
//!    compares the sequence it walked against rather than reconstructing it
//!    from the per-artifact entries.
//! 3. **Signature block** — the detached signature over the manifest block,
//!    optionally stamped by [`append_trailer_signed`] (see
//!    [`Payload::signature`]).
//! 4. **`key_id` block** — the identifier of the key that signature was made
//!    with, present alongside it or absent alongside the signature (see
//!    [`Payload::key_id`]).
//! 5. **Footer** — a fixed-size record at the very end of the file with an
//!    exact binary layout: the [`MAGIC`] bytes (8), a `u8` container format
//!    version, then **eight** `u64` little-endian fields — the manifest,
//!    archive, signature and `key_id` absolute file offsets and lengths, in
//!    that order. At the current [`FORMAT_VERSION`] that is [`FOOTER_SIZE`] =
//!    73 bytes; a version-1 footer stops after the archive pair and is 41.
//!
//! ## Absent blocks
//!
//! Only the signature and `key_id` pairs may be absent, and **absent is the
//! all-zero pair**: offset `0` *and* length `0`. Present means a non-zero
//! length at an offset inside the trailer body. A half-zero pair — one of the
//! two zero and the other not — is [`PayloadError::MalformedFooter`], never
//! read as either state: zero is a legal offset in this layout, since a `.pkg`
//! has no base and its manifest block therefore starts at `0`.
//!
//! Present blocks sit in the order above, adjacent: the first starts at the
//! trailer body's start, each subsequent one starts exactly where the previous
//! present block ended, and the last ends exactly where the footer begins. An
//! absent pair occupies no bytes, so the walk steps over it — which is why an
//! unsigned container, whose archive block is the last present block, is valid.
//! A gap, an overlap, or a last present block that stops short of the footer is
//! [`PayloadError::MalformedFooter`].
//!
//! ## Locating the footer
//!
//! Two footer sizes exist, so the reader probes: it walks the known sizes in
//! **ascending order** (41 paired with version 1, then 73 with version 2),
//! reading a candidate at `file_len - size` and skipping any size the file is
//! shorter than. A candidate is *selected* only when its [`MAGIC`] matches and
//! its version byte equals the version that size belongs to; the walk stops
//! there, and every later check validates that candidate rather than sending
//! the walk on. Ascending order is what makes both directions safe, and the
//! reasons are stated beside the size list in this module's source.
//!
//! # Empty payload versus corrupt trailer
//!
//! A file in which no probed candidate is a footer is an **empty payload** —
//! the normal state of an ordinary binary with no trailer, reported as
//! `Ok(None)` from [`open`] and as [`PayloadError::NoTrailer`] from
//! [`open_package`], for which a missing trailer is a broken package. A
//! candidate whose [`MAGIC`] matches under a version byte naming no version
//! this build implements is instead
//! [`PayloadError::UnsupportedContainerFormat`], decided once the whole list
//! has been walked with nothing selected. Past a selected footer, any further
//! problem (offsets outside the file, a malformed block layout, an unparseable
//! manifest, a hash mismatch, an unsafe or unknown archive member) is a
//! [`PayloadError`].

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};
use tempfile::Builder as TempBuilder;
use zstd::{Decoder, Encoder};

use crate::durability::sync_dir;
use crate::manifest::{
    ArchiveMember, ArtifactKind, Disposition, ManifestError, PayloadArtifact, PayloadManifest,
    TargetArch, is_safe_archive_path,
};
use crate::module_spec::ModuleSpec;

/// Magic bytes at the start of the footer, identifying a bootler payload.
pub const MAGIC: [u8; 8] = *b"BTLRPYLD";

/// Length of [`MAGIC`] in bytes.
const MAGIC_LEN: usize = MAGIC.len();

/// Current container format version.
///
/// This versions the **container layout** — which offset/length pairs the
/// footer carries and in what order — and nothing else. The manifest's own
/// `format_version` versions the manifest schema and is gated separately by
/// [`PayloadManifest::parse`], so adding a manifest field is not a container
/// change and a container change is not a manifest one.
pub const FORMAT_VERSION: u8 = 2;

/// Footer size of a version-1 container: [`MAGIC`] (8) + version (1) + four
/// `u64` fields (32).
const FOOTER_SIZE_V1: usize = MAGIC_LEN + 1 + 4 * 8;

/// Footer size of a version-2 container: [`MAGIC`] (8) + version (1) + eight
/// `u64` fields (64).
const FOOTER_SIZE_V2: usize = MAGIC_LEN + 1 + 8 * 8;

/// Total size of the footer of a container written at [`FORMAT_VERSION`], in
/// bytes: [`MAGIC`] (8) + version (1) + eight `u64` fields (64) = 73.
///
/// This names the **current** version's size only. A reader must not seek to
/// `file_len - FOOTER_SIZE`; it walks the module's ordered list of known
/// footer sizes, which is where the sizes of every version this build still
/// opens are stated.
pub const FOOTER_SIZE: usize = FOOTER_SIZE_V2;

/// First container version whose footer carries the signature and `key_id`
/// pairs.
///
/// A footer written at any earlier version stops after the archive pair, so
/// its two envelope pairs are read as absent rather than from bytes that are
/// not there.
const FIRST_ENVELOPE_VERSION: u8 = 2;

/// One entry of the footer-size probe: a footer size and the single container
/// version a footer of that size records.
struct FooterSize {
    /// Total size of the footer in bytes.
    bytes: usize,
    /// Container version this size belongs to. A candidate at this size is
    /// selected only when its version byte equals this.
    version: u8,
}

/// The footer sizes this build knows, **in ascending size order**, one entry
/// per container version it implements.
///
/// Order is part of the format, not an implementation detail, and both
/// directions of the walk rest on this layout's arithmetic rather than on a
/// probability argument:
///
/// - In a **version-1** payload the 73-byte candidate offset falls inside the
///   archive block, whose bytes are artifact content and can carry [`MAGIC`]
///   followed by any byte at all — including `2`, which pairs with 73 and
///   would therefore be selected, sending the reader off a fabricated footer's
///   offsets. Reading 41 first means the real footer is selected before that
///   candidate is ever read.
/// - In a **version-2** container the 41-byte candidate offset falls inside the
///   footer's own field region: `file_len - 41` is the most significant byte of
///   `archive_offset`, so the candidate's first magic byte could only be `0x42`
///   (`B`) in a container of at least `0x42 << 56` bytes — about 4.7 exabytes.
///   Below that bound the walk falls through to 73 and finds the real footer.
///
/// This list is the format's compatibility surface: a footer whose [`MAGIC`]
/// lands at no probed offset is indistinguishable from absent, so every future
/// container version must be inserted here at its ascending position — and its
/// ordering argument re-checked at the same time, since what protects a
/// smaller probed offset is that it lands inside a larger real footer's field
/// region, on a byte that cannot be `0x42`.
const KNOWN_FOOTER_SIZES: [FooterSize; 2] = [
    FooterSize {
        bytes: FOOTER_SIZE_V1,
        version: 1,
    },
    FooterSize {
        bytes: FOOTER_SIZE_V2,
        version: FORMAT_VERSION,
    },
];

/// Container versions this build implements, in [`KNOWN_FOOTER_SIZES`] order.
///
/// Derived from the probe list rather than restated, so adding a footer size
/// cannot leave [`PayloadError::UnsupportedContainerFormat`] announcing the old
/// set.
const SUPPORTED_CONTAINER_VERSIONS: [u8; KNOWN_FOOTER_SIZES.len()] = {
    let mut versions = [0u8; KNOWN_FOOTER_SIZES.len()];
    let mut index = 0;
    while index < KNOWN_FOOTER_SIZES.len() {
        versions[index] = KNOWN_FOOTER_SIZES[index].version;
        index += 1;
    }
    versions
};

/// zstd compression level used by the writer.
const ZSTD_LEVEL: i32 = 3;

/// Size of one `tar` block, and the unit the end-of-archive marker is measured
/// in.
const TAR_BLOCK_SIZE: usize = 512;

/// Most bytes allowed to remain in the decompressed archive block once the
/// entry walk has stopped, and all of them must be zero.
///
/// The end-of-archive marker is two zero blocks. [`Archive::entries`] reads the
/// first of them, sees an all-zero header, and reports the end without touching
/// the second, so a well-formed archive leaves exactly one block unread. That
/// block is the whole allowance: a zero byte past it belongs to no marker, and
/// tolerating it would admit padding the manifest cannot bind.
const MAX_END_OF_ARCHIVE_BYTES: usize = TAR_BLOCK_SIZE;

/// Width of the `tar` header's name field, and so the longest `archive_path`
/// the writer can store in the header block a member is named by.
const TAR_NAME_FIELD_LEN: usize = 100;

/// Number of bytes an Ed25519 detached signature occupies.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Number of lowercase hexadecimal ASCII characters in a `key_id`.
const KEY_ID_HEX_LEN: usize = 64;

/// A detached signature and its signer identifier for a payload manifest.
#[derive(Debug)]
pub struct Signed {
    /// The detached signature, exactly 64 bytes.
    pub signature: Vec<u8>,
    /// The signer's `key_id`, exactly 64 lowercase-hex ASCII characters, as
    /// [`crate::verify::key_id`] derives.
    pub key_id: String,
}

/// An error returned by a callback passed to [`append_trailer_signed`].
#[derive(Debug)]
pub struct SignerError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl SignerError {
    /// Creates a signer error from its foreign source.
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(source))
    }
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for SignerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Errors raised while writing, locating, or extracting a payload trailer.
///
/// The empty-payload case is not an error variant; it is reported as `Ok(None)`
/// from [`open`].
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// An I/O operation failed.
    #[error("payload i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The manifest could not be serialized while writing a trailer.
    #[error("failed to serialize payload manifest: {0}")]
    ManifestSerialize(#[source] serde_json::Error),

    /// A callback could not sign the manifest bytes.
    #[error("failed to sign payload manifest: {0}")]
    Signer(#[source] SignerError),

    /// A signer returned a detached signature with the wrong length.
    #[error(
        "signer returned a signature of {found} bytes; an Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes"
    )]
    InvalidSignatureLength {
        /// Number of bytes returned by the signer.
        found: usize,
    },

    /// A signer returned a `key_id` that cannot occupy the envelope block.
    #[error("signer returned an invalid key_id: {reason}")]
    InvalidKeyId {
        /// Why the `key_id` was rejected.
        reason: &'static str,
    },

    /// A caller-supplied manifest failed validation while writing a trailer.
    #[error("invalid payload manifest: {0}")]
    InvalidManifest(#[from] ManifestError),

    /// The footer recorded a container format version this build does not
    /// implement.
    ///
    /// Raised exactly when no probed candidate was a footer and at least one
    /// of them matched [`MAGIC`] under a version byte naming no version this
    /// build implements — the only signal a newer container format can give a
    /// reader that cannot even locate its manifest. Every other no-footer
    /// outcome is "this file carries no trailer", resolved per entry point.
    #[error("unrecognized container format version {found} (this build implements {})", describe_versions(.supported))]
    UnsupportedContainerFormat {
        /// Version read from the candidate footer. When several candidates
        /// carried an unknown version, this is the first in probe order.
        found: u8,
        /// Container versions this build implements, in the probe list's
        /// ascending order.
        supported: &'static [u8],
    },

    /// The footer's offsets or lengths point outside the file.
    #[error("trailer offsets point outside the file (truncated trailer)")]
    TruncatedTrailer,

    /// The footer's block layout is internally inconsistent: a half-zero
    /// signature or `key_id` pair, or present blocks that do not sit adjacent
    /// in the fixed order and end where the footer begins.
    ///
    /// Distinct from [`PayloadError::TruncatedTrailer`], which is about blocks
    /// falling outside the file rather than about how they sit inside it, and
    /// from "no trailer": the footer was selected, so this is a corrupt
    /// container and never a file that simply carries no trailer.
    #[error("malformed trailer footer: {reason}")]
    MalformedFooter {
        /// What about the block layout was rejected.
        reason: &'static str,
    },

    /// The manifest block failed to parse.
    #[error("failed to parse payload manifest: {0}")]
    ManifestParse(#[source] serde_json::Error),

    /// An artifact's bytes did not match the SHA-256 recorded in the manifest.
    #[error("sha-256 mismatch for artifact `{path}`")]
    HashMismatch {
        /// `archive_path` of the offending artifact.
        path: String,
    },

    /// An archive member used an unsafe path (absolute, containing `..`, or
    /// otherwise escaping the extraction root).
    #[error("unsafe archive member path `{0}`")]
    UnsafeMemberPath(String),

    /// An archive member was not a regular file (symlink, hardlink, directory,
    /// or device/special entry).
    #[error("unsupported tar entry type for `{path}` (only regular files are allowed)")]
    UnsupportedEntryType {
        /// Path of the offending member.
        path: String,
    },

    /// An archive member was named by an extension header — a PAX `path`
    /// record or a GNU long-name entry — rather than by the raw `ustar`
    /// header block it applies to.
    ///
    /// What this rejects is the name's provenance, not the path and not the
    /// entry type: the resolved name may be a perfectly safe relative path and
    /// the member an ordinary regular file. Two readers that disagree about
    /// which of the two names is the member's are enough to make the manifest
    /// bind one occurrence while extraction writes another.
    #[error("archive member name `{resolved_name}` overrides header name `{header_name}`")]
    NameOverridingHeader {
        /// Name recorded in the raw `ustar` header block.
        header_name: String,
        /// Name the archive reader resolved the member to.
        resolved_name: String,
    },

    /// An archive member's size came from a PAX `size` record rather than from
    /// the raw `ustar` header block it applies to.
    ///
    /// The size decides where the member ends and so where the next header
    /// begins: a reader that honours the record and one that does not disagree
    /// about the whole remainder of the stream, and a second member at a
    /// manifest-listed path fits inside the bytes only one of them attributes
    /// to this one. That is the divergence
    /// [`PayloadError::NameOverridingHeader`] rejects, reached through the
    /// other field an extension header can override.
    #[error(
        "archive member `{path}` resolves to size {resolved_size}, overriding header size {header_size}"
    )]
    SizeOverridingHeader {
        /// The member's path as the reader resolved it.
        path: String,
        /// Size recorded in the raw `ustar` header block.
        header_size: u64,
        /// Size the archive reader resolved the member to.
        resolved_size: u64,
    },

    /// An `archive_path` did not fit the raw `tar` header's name field while
    /// writing a trailer.
    ///
    /// Storing it would mean naming the member from a GNU long-name entry
    /// instead of from its own header block, which [`Payload::extract_to`]
    /// refuses as [`PayloadError::NameOverridingHeader`]. The writer refuses
    /// the path here rather than emitting a payload its own reader rejects.
    #[error(
        "archive path `{path}` does not fit a tar header name field ({len} bytes, limit {TAR_NAME_FIELD_LEN})"
    )]
    ArchivePathTooLong {
        /// The offending `archive_path`.
        path: String,
        /// Its length in bytes.
        len: usize,
    },

    /// The decompressed archive block carried bytes past the end-of-archive
    /// marker, where this reader stops and another reader would not.
    #[error("archive block carries bytes after the end-of-archive marker")]
    TrailingArchiveBytes,

    /// An archive member had no matching manifest entry, so it could not be
    /// hash-verified.
    #[error("archive member `{0}` is not present in the manifest")]
    MemberNotInManifest(String),

    /// A manifest artifact had no matching archive member, so it was neither
    /// extracted nor hash-verified.
    #[error("manifest artifact `{0}` is missing from the archive")]
    ArtifactMissingFromArchive(String),

    /// Two archive members shared the same `archive_path`, so a single manifest
    /// artifact could not be mapped deterministically to one member.
    #[error("archive member `{0}` appears more than once")]
    DuplicateMember(String),

    /// The archive block's members disagreed with the ordered member list the
    /// manifest binds — in name, order, count, or per-member length.
    ///
    /// This is a whole-sequence verdict decided once the archive has been
    /// walked, so it is the one rejection here that no single member is
    /// individually guilty of: a permuted archive holds nothing but members
    /// that pass every per-member check. The position and the two sides are
    /// carried rather than the whole list, which is what a reader needs to act
    /// on and is already in front of it.
    #[error(
        "archive members disagree with the manifest at position {index}: manifest binds {}, archive carries {}",
        describe_member(.expected.as_ref()),
        describe_member(.found.as_ref())
    )]
    MemberListMismatch {
        /// Zero-based position in archive order where the two first disagree.
        index: usize,
        /// What the manifest's bound list holds there, or `None` when the list
        /// ends at that position and the archive carried more.
        expected: Option<ArchiveMember>,
        /// What the archive carried there, or `None` when the archive ended at
        /// that position and the bound list held more.
        found: Option<ArchiveMember>,
    },

    /// The source binary handed to [`rewrap_trailer`] carries no payload
    /// trailer, so there is nothing to graft onto the new base.
    #[error("source binary carries no payload trailer to rewrap")]
    NoTrailer,
}

/// Renders the container versions a build implements for
/// [`PayloadError::UnsupportedContainerFormat`]'s message, as `1, 2`.
fn describe_versions(versions: &[u8]) -> String {
    versions
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders one side of a [`PayloadError::MemberListMismatch`], where absence
/// means the sequence ended before the position under comparison.
fn describe_member(member: Option<&ArchiveMember>) -> String {
    member.map_or_else(
        || "nothing".to_string(),
        |member| format!("`{}` ({} bytes)", member.name, member.length),
    )
}

/// One artifact to embed, referenced by the file that holds its bytes.
///
/// The writer streams each artifact from `source` — once to compute its
/// SHA-256, once to write it into the archive — so a GB-scale artifact never
/// resides in memory in full and the manifest stays consistent with the
/// archive.
#[derive(Debug, Clone)]
pub struct ArtifactInput {
    /// Component the artifact belongs to.
    pub component: String,
    /// Version string of the built component.
    pub version: String,
    /// Immutable build identity of the artifact, stamped onto the manifest entry
    /// derived from this input: a full 40-hex git commit SHA for an artifact
    /// built from a clone, or a 64-hex image digest with its `sha256:` prefix
    /// stripped for a third-party container image.
    ///
    /// Required on the producer side — absence is a read-side baseline state
    /// only — and validated by
    /// [`is_valid_commit`](crate::manifest::is_valid_commit) when the manifest
    /// is assembled.
    pub commit: String,
    /// Architecture the artifact is built for.
    pub target_arch: TargetArch,
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// One or more dispositions; the empty set is rejected.
    pub dispositions: std::collections::BTreeSet<Disposition>,
    /// Path of this artifact's member inside the tar archive.
    pub archive_path: String,
    /// How this artifact is installed, stamped verbatim onto the manifest entry
    /// derived from this input.
    ///
    /// `None` for an artifact whose package declares nothing, which is every
    /// artifact shipping today. When present it is validated by
    /// [`validate`](crate::module_spec::validate) as the manifest is assembled,
    /// so a producer cannot write a spec a reader would refuse.
    pub spec: Option<ModuleSpec>,
    /// File holding the raw artifact bytes.
    pub source: PathBuf,
}

/// An artifact extracted and verified from a payload.
#[derive(Debug, Clone)]
pub struct ExtractedArtifact {
    /// Manifest entry the extracted file corresponds to.
    pub artifact: PayloadArtifact,
    /// On-disk path the artifact was written to.
    pub path: PathBuf,
}

/// The parsed footer of a trailer. Fields are absolute file offsets/lengths.
///
/// A footer read at a version below [`FIRST_ENVELOPE_VERSION`] carries no
/// signature or `key_id` fields on the wire; they are filled in here with the
/// all-zero absent encoding, so the rest of the reader treats an old container
/// as an unsigned one rather than as a special case.
struct Footer {
    version: u8,
    manifest_offset: u64,
    manifest_len: u64,
    archive_offset: u64,
    archive_len: u64,
    signature_offset: u64,
    signature_len: u64,
    key_id_offset: u64,
    key_id_len: u64,
}

impl Footer {
    /// Encodes the footer to the exact wire form of **its own** `version`.
    ///
    /// The size is a function of the version, not of [`FORMAT_VERSION`]: a
    /// version-1 footer stops after the archive pair and is [`FOOTER_SIZE_V1`]
    /// bytes, which is what lets a version-1 payload be rewrapped as a
    /// version-1 payload. Writing the two extra pairs into it would move its
    /// magic 32 bytes away from where the probe pairs that version's size with,
    /// and the container would no longer open at all.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FOOTER_SIZE);
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.extend_from_slice(&self.manifest_offset.to_le_bytes());
        buf.extend_from_slice(&self.manifest_len.to_le_bytes());
        buf.extend_from_slice(&self.archive_offset.to_le_bytes());
        buf.extend_from_slice(&self.archive_len.to_le_bytes());
        if self.version >= FIRST_ENVELOPE_VERSION {
            buf.extend_from_slice(&self.signature_offset.to_le_bytes());
            buf.extend_from_slice(&self.signature_len.to_le_bytes());
            buf.extend_from_slice(&self.key_id_offset.to_le_bytes());
            buf.extend_from_slice(&self.key_id_len.to_le_bytes());
        }
        buf
    }
}

/// Whether an offset/length pair carries the all-zero absent encoding.
///
/// The two fields are read as a unit because zero is a legal offset in this
/// layout — a `.pkg` has no base executable, so its manifest block starts at
/// `0` — which is why a half-zero pair is malformed rather than absent.
fn is_absent_pair(offset: u64, len: u64) -> bool {
    offset == 0 && len == 0
}

/// Cursor over a candidate footer's field region, handing out its little-endian
/// `u64`s in wire order.
struct FieldReader<'a> {
    bytes: &'a [u8],
    next: usize,
}

impl<'a> FieldReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            next: MAGIC_LEN + 1,
        }
    }

    /// Returns the next field, or `None` once the region is exhausted.
    fn next_u64(&mut self) -> Option<u64> {
        let end = self.next.checked_add(8)?;
        let field: [u8; 8] = self.bytes.get(self.next..end)?.try_into().ok()?;
        self.next = end;
        Some(u64::from_le_bytes(field))
    }
}

/// What one probed candidate turned out to be.
///
/// Inspecting a candidate raises nothing: all four outcomes are ordinary return
/// values, because an unknown version byte at one probed offset must be
/// recorded while the walk continues to the next size rather than ending it.
enum Candidate {
    /// The bytes at this offset do not begin with [`MAGIC`] — or, unreachably,
    /// the candidate region was too short to hold the fields its size promises,
    /// which the probe's own sizing rules out.
    NoMagic,
    /// [`MAGIC`] under the version this candidate's size is paired with: a
    /// footer, and the one thing the walk stops at.
    Selected(Footer),
    /// [`MAGIC`] under a version this build implements but which belongs to a
    /// *different* footer size. Neither a footer nor an unknown format, so the
    /// walk ignores it: a magic-plus-known-version byte pattern at a fixed
    /// distance from end-of-file is a coincidence any archive block can carry.
    Mismatched,
    /// [`MAGIC`] under a version this build does not implement.
    Unknown(u8),
}

/// Classifies the candidate footer `bytes` read at the offset [`FooterSize`]
/// `size` names, without deciding anything else about the container.
fn classify_candidate(bytes: &[u8], size: &FooterSize) -> Candidate {
    if bytes.get(..MAGIC_LEN) != Some(MAGIC.as_slice()) {
        return Candidate::NoMagic;
    }
    let Some(&version) = bytes.get(MAGIC_LEN) else {
        return Candidate::NoMagic;
    };
    if version != size.version {
        return if SUPPORTED_CONTAINER_VERSIONS.contains(&version) {
            Candidate::Mismatched
        } else {
            Candidate::Unknown(version)
        };
    }

    let mut fields = FieldReader::new(bytes);
    let (Some(manifest_offset), Some(manifest_len), Some(archive_offset), Some(archive_len)) = (
        fields.next_u64(),
        fields.next_u64(),
        fields.next_u64(),
        fields.next_u64(),
    ) else {
        return Candidate::NoMagic;
    };
    let (signature_offset, signature_len, key_id_offset, key_id_len) = if version
        >= FIRST_ENVELOPE_VERSION
    {
        let (Some(signature_offset), Some(signature_len), Some(key_id_offset), Some(key_id_len)) = (
            fields.next_u64(),
            fields.next_u64(),
            fields.next_u64(),
            fields.next_u64(),
        ) else {
            return Candidate::NoMagic;
        };
        (signature_offset, signature_len, key_id_offset, key_id_len)
    } else {
        // A pre-envelope footer records neither pair, which is exactly the
        // absent encoding.
        (0, 0, 0, 0)
    };

    Candidate::Selected(Footer {
        version,
        manifest_offset,
        manifest_len,
        archive_offset,
        archive_len,
        signature_offset,
        signature_len,
        key_id_offset,
        key_id_len,
    })
}

/// Where the probe left off once the whole of [`KNOWN_FOOTER_SIZES`] had been
/// walked.
enum Located {
    /// A candidate was selected: the container's footer, and the absolute
    /// offset its own bytes start at.
    Found { footer: Footer, footer_start: u64 },
    /// No candidate was a footer and none carried an unknown version, so the
    /// file carries no trailer. What that means is the caller's to decide: an
    /// empty payload for [`open`], [`PayloadError::NoTrailer`] for
    /// [`open_package`] and [`rewrap_trailer`], and the whole file as its own
    /// base for [`read_base_executable`].
    NoTrailer,
}

/// Locates the container's footer in `src` by walking [`KNOWN_FOOTER_SIZES`] in
/// ascending size order.
///
/// This is the one implementation every entry point locates a footer through,
/// and the one place [`PayloadError::UnsupportedContainerFormat`] is
/// constructed. Selection is the only decision made here: an offsets check, the
/// block-layout walk and the manifest parse all validate an already-selected
/// candidate, and their failures never send the walk to another size — a probe
/// that re-entered the walk on a validation failure would report a genuinely
/// corrupt footer as "no trailer".
///
/// # Errors
///
/// Returns [`PayloadError::UnsupportedContainerFormat`] when nothing was
/// selected and some candidate matched [`MAGIC`] under a version this build
/// does not implement, or [`PayloadError::Io`] when a candidate cannot be read.
fn locate_footer<R: Read + Seek>(src: &mut R, file_len: u64) -> Result<Located, PayloadError> {
    // The first unknown version seen, in probe order — the smallest size, the
    // offset nearest end-of-file. Recorded once and never overwritten, so which
    // value the error reports is fixed by the format rather than by which
    // candidate an implementation happened to look at last.
    let mut first_unknown: Option<u8> = None;

    for size in &KNOWN_FOOTER_SIZES {
        let size_bytes = size.bytes as u64;
        if file_len < size_bytes {
            continue;
        }
        let candidate_start = file_len - size_bytes;
        src.seek(SeekFrom::Start(candidate_start))?;
        let mut bytes = vec![0u8; size.bytes];
        src.read_exact(&mut bytes)?;

        match classify_candidate(&bytes, size) {
            Candidate::Selected(footer) => {
                return Ok(Located::Found {
                    footer,
                    footer_start: candidate_start,
                });
            }
            Candidate::Unknown(version) => {
                first_unknown.get_or_insert(version);
            }
            Candidate::NoMagic | Candidate::Mismatched => {}
        }
    }

    // Classification happens here and nowhere else: only now is it settled that
    // no later size held the real footer.
    match first_unknown {
        Some(found) => Err(PayloadError::UnsupportedContainerFormat {
            found,
            supported: &SUPPORTED_CONTAINER_VERSIONS,
        }),
        None => Ok(Located::NoTrailer),
    }
}

/// Checks that a selected footer's blocks fall inside the file and sit adjacent
/// in the fixed order.
///
/// Three checks, in the order their errors are decided:
///
/// 1. Neither envelope pair is half-zero — the absent encoding is all-zero, and
///    a pair that is half of it is neither present nor absent.
/// 2. Every block ends at or before `footer_start`, so nothing points outside
///    the file.
/// 3. The **present** blocks — manifest, archive, then whichever of the
///    signature and `key_id` are present — start at the trailer body's start,
///    each where the previous one ended, and the last ends exactly at
///    `footer_start`. An absent pair occupies no bytes and is stepped over.
///
/// # Errors
///
/// Returns [`PayloadError::MalformedFooter`] for a half-zero pair or a gap,
/// overlap or short final block, and [`PayloadError::TruncatedTrailer`] when a
/// block runs past the footer or an offset plus length overflows.
fn validate_footer(footer: &Footer, footer_start: u64) -> Result<(), PayloadError> {
    // Only the two envelope pairs have an absent encoding; the manifest and the
    // archive are always present, so an all-zero pair there is a layout to be
    // checked rather than a block to be stepped over.
    let signature_present = envelope_present(
        footer.signature_offset,
        footer.signature_len,
        "signature pair is half-zero: neither present nor absent",
    )?;
    let key_id_present = envelope_present(
        footer.key_id_offset,
        footer.key_id_len,
        "key_id pair is half-zero: neither present nor absent",
    )?;

    let blocks = [
        (footer.manifest_offset, footer.manifest_len, true),
        (footer.archive_offset, footer.archive_len, true),
        (
            footer.signature_offset,
            footer.signature_len,
            signature_present,
        ),
        (footer.key_id_offset, footer.key_id_len, key_id_present),
    ];

    let end_of = |offset: u64, len: u64| {
        offset
            .checked_add(len)
            .ok_or(PayloadError::TruncatedTrailer)
    };
    for (offset, len, _) in blocks {
        if end_of(offset, len)? > footer_start {
            return Err(PayloadError::TruncatedTrailer);
        }
    }

    // The trailer body starts where the manifest block does: a container's base
    // executable, if it has one, is exactly the prefix before it.
    let mut cursor = footer.manifest_offset;
    for (offset, len, present) in blocks {
        if !present {
            continue;
        }
        if offset != cursor {
            return Err(PayloadError::MalformedFooter {
                reason: "trailer blocks are not adjacent in the fixed order",
            });
        }
        cursor = end_of(offset, len)?;
    }
    if cursor != footer_start {
        return Err(PayloadError::MalformedFooter {
            reason: "the last present block does not end where the footer begins",
        });
    }

    Ok(())
}

/// Resolves one envelope pair to whether the block it describes is present,
/// refusing the half-zero spelling that is neither state.
///
/// The two fields are read as a unit because zero is a legal offset in this
/// layout: a `.pkg` has no base executable, so its manifest block starts at
/// `0`, and "offset zero" therefore cannot on its own mean "no block".
///
/// # Errors
///
/// Returns [`PayloadError::MalformedFooter`] carrying `reason` when one field
/// is zero and the other is not.
fn envelope_present(offset: u64, len: u64, reason: &'static str) -> Result<bool, PayloadError> {
    if is_absent_pair(offset, len) {
        Ok(false)
    } else if offset == 0 || len == 0 {
        Err(PayloadError::MalformedFooter { reason })
    } else {
        Ok(true)
    }
}

/// Builds a compact sparse-file fixture with widened envelope blocks.
///
/// `container` must be a current-format container produced by
/// [`append_trailer_signed`]. The returned bytes consist of the real prefix
/// before its signature followed immediately by a rewritten [`FOOTER_SIZE`]
/// footer. That footer advertises `advertised_len` for both envelope blocks;
/// its `key_id` starts immediately after the widened signature.
///
/// Do **not** write the returned bytes contiguously. To construct the fixture
/// without materializing the advertised bytes, write every byte except the
/// final [`FOOTER_SIZE`], seek to `prefix_len + 2 * advertised_len`, then write
/// those final footer bytes. The unwritten signature and `key_id` ranges stay
/// sparse, while the footer still describes both as present. A bounded reader
/// can reject them from their advertised lengths without reading them; an
/// unbounded reader reaches the sparse ranges and attempts to allocate their
/// advertised sizes.
///
/// This test-support fixture is not compiled into a default-feature build.
/// Enable `test-support` only under a dependent's `[dev-dependencies]`.
///
/// # Panics
///
/// Panics when `container` is not a well-formed current-format signed
/// container, when `advertised_len` does not widen both blocks, or when the
/// widened envelope cannot be represented by the container format.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn widen_envelope_blocks(container: &[u8], advertised_len: u64) -> Vec<u8> {
    let Some(ContainerHead { footer, .. }) = read_container_head(std::io::Cursor::new(container))
        .expect("the fixture input is readable")
    else {
        panic!("the fixture input carries a container");
    };

    assert_eq!(
        footer.version, FORMAT_VERSION,
        "the fixture input uses the current container format"
    );
    assert!(
        envelope_present(
            footer.signature_offset,
            footer.signature_len,
            "the fixture input has a signature",
        )
        .expect("the fixture input has a well-formed signature pair"),
        "the fixture input has a signature"
    );
    assert!(
        envelope_present(
            footer.key_id_offset,
            footer.key_id_len,
            "the fixture input has a key_id",
        )
        .expect("the fixture input has a well-formed key_id pair"),
        "the fixture input has a key_id"
    );
    assert!(
        advertised_len > footer.signature_len && advertised_len > footer.key_id_len,
        "the advertised length widens both envelope blocks"
    );

    let mut footer = footer;
    footer.signature_len = advertised_len;
    footer.key_id_offset = footer
        .signature_offset
        .checked_add(advertised_len)
        .expect("the widened key_id offset fits the container format");
    footer.key_id_len = advertised_len;
    footer
        .key_id_offset
        .checked_add(footer.key_id_len)
        .expect("the widened envelope fits the container format");

    let prefix_len = usize::try_from(footer.signature_offset)
        .expect("the fixture input is addressable as a slice");
    let mut compact = container
        .get(..prefix_len)
        .expect("the signature starts inside the fixture input")
        .to_vec();
    compact.extend_from_slice(&footer.encode());
    compact
}

/// Computes the lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

/// Formats bytes as a lowercase hex string.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Streams `reader` into `writer` in bounded-size chunks, returning the
/// lowercase hex SHA-256 of the bytes copied and how many of them there were.
///
/// This is the streaming primitive behind both writing (hash a source file into
/// [`std::io::sink`]) and extraction (hash a member while spooling it to disk),
/// so no artifact is ever buffered in memory in full. The byte count comes out
/// of the same pass as the digest, which is what lets both sides state a length
/// that is a property of the bytes they hashed rather than of a size field
/// consulted separately.
fn hash_copy<R: Read, W: Write>(mut reader: R, mut writer: W) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    // On the heap: 64 KiB is a large frame to claim on a thread whose stack
    // size this crate does not choose, and the one allocation disappears
    // against the I/O and hashing it serves.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = buf
            .get(..read)
            .expect("read never exceeds the buffer length");
        hasher.update(chunk);
        writer.write_all(chunk)?;
        length += chunk.len() as u64;
    }
    Ok((to_hex(&hasher.finalize()), length))
}

/// A `Write` wrapper that counts the bytes written through it, used to measure
/// the compressed archive length without buffering it or seeking `out`.
struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }

    fn count(&self) -> u64 {
        self.count
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Streams a payload trailer built from `inputs` onto `base`, writing the
/// combined binary — the base bytes followed by the trailer — to `out`.
///
/// The manifest is derived from `inputs` (each artifact's SHA-256 is streamed
/// from its `source` file) and validated before writing. Both the base and
/// every artifact stream straight through to `out`, so a GB-scale payload never
/// resides in memory in full (RFC 0001 §3). `out` should start empty; the
/// recorded offsets are absolute from the start of `out`.
///
/// `pinset` is stamped into the manifest as the `bootler.pinset.v1` digest of the
/// recipe these `inputs` were produced from, binding the payload's bytes to that
/// recipe rather than letting the asset's name merely claim one. Pass `None` only
/// where no recipe is in play (for example a test fixture).
///
/// `trust_set` is the signed release-signing generation container the installer
/// seeds from, stored verbatim and opaquely; pass `None` where the producer has
/// no generation to stamp, which is a legitimate state and not a claim that the
/// payload is old.
///
/// The manifest's `format_version` is stamped from
/// [`MANIFEST_FORMAT_VERSION`](crate::manifest::MANIFEST_FORMAT_VERSION) with no
/// caller-supplied value, and the container's own [`FORMAT_VERSION`] into the
/// footer. Both envelope pairs — signature and `key_id` — are written absent.
///
/// Passing an empty `base` (for example [`std::io::empty`]) writes a **`.pkg`
/// module package**: the same container with no base executable, whose manifest
/// block therefore starts at offset `0`. It is read back with
/// [`open_package`], not [`open`].
///
/// The ordered archive member list the manifest binds is derived here too, in
/// `inputs` order, from the same pre-pass that computes each artifact's
/// SHA-256. There is no member-list parameter and no override hook, for the
/// reason there is none for `sha256`: this function is the only one that writes
/// an archive, so a list it did not derive would be a caller's *prediction* of
/// what its `tar` writer does — the writer's ordering and framing rules
/// restated in a second place, which is exactly the two-implementations-must-
/// agree failure the bound list exists to prevent.
///
/// # Errors
///
/// Returns [`PayloadError`] when a `source` file cannot be read, the derived
/// manifest is invalid (empty dispositions, unsafe or duplicate `archive_path`,
/// a malformed `commit`, a `spec` violating a rule
/// [`validate`](crate::module_spec::validate) enforces, an empty `trust_set`), an
/// `archive_path` is longer than a `tar` header's name field
/// ([`PayloadError::ArchivePathTooLong`], since storing it would need a
/// name-overriding extension header the reader refuses), or serialization,
/// archive construction, or writing to `out` fails.
pub fn append_trailer<B: Read, W: Write>(
    base: B,
    out: W,
    pinset: Option<&str>,
    trust_set: Option<&[u8]>,
    inputs: &[ArtifactInput],
) -> Result<(), PayloadError> {
    append_trailer_with_signer(base, out, pinset, trust_set, inputs, |_| Ok(None))
}

/// Streams a signed payload trailer built from `inputs` onto `base`.
///
/// This has the same layout and derives the same manifest and archive as
/// [`append_trailer`], but writes a signature block and its `key_id` block
/// after the archive. `sign` receives the manifest member's bytes exactly as
/// they will be written to the container; it must return a detached Ed25519
/// signature and the corresponding [`crate::verify::key_id`]. The callback is
/// invoked and its return value is validated before this function writes any
/// bytes to `out`.
///
/// Passing an empty `base` (for example [`std::io::empty`]) writes a signed
/// **`.pkg` module package**: the manifest starts at offset `0`, and the
/// signature covers those exact bytes.
///
/// # Errors
///
/// Returns [`PayloadError`] for the same conditions as [`append_trailer`], when
/// `sign` returns a [`SignerError`], or when it returns a signature or `key_id`
/// whose shape the container verifier cannot accept.
pub fn append_trailer_signed<B: Read, W: Write, F>(
    base: B,
    out: W,
    pinset: Option<&str>,
    trust_set: Option<&[u8]>,
    inputs: &[ArtifactInput],
    sign: F,
) -> Result<(), PayloadError>
where
    F: FnOnce(&[u8]) -> Result<Signed, SignerError>,
{
    append_trailer_with_signer(base, out, pinset, trust_set, inputs, |manifest| {
        sign(manifest).map(Some)
    })
}

fn append_trailer_with_signer<B: Read, W: Write, F>(
    mut base: B,
    mut out: W,
    pinset: Option<&str>,
    trust_set: Option<&[u8]>,
    inputs: &[ArtifactInput],
    sign: F,
) -> Result<(), PayloadError>
where
    F: FnOnce(&[u8]) -> Result<Option<Signed>, SignerError>,
{
    // The member list is derived here, from the pre-pass that already streams
    // every input: the manifest block is written before the archive block, so
    // it cannot be collected while the `tar` is being built. Each input is
    // measured exactly once, and that one count becomes both the member's
    // recorded `length` and the size written into its `tar` header below —
    // two reads of the same file can disagree, and the whole point of the
    // field is that they cannot.
    let mut archive_members = Vec::with_capacity(inputs.len());
    let mut artifacts = Vec::with_capacity(inputs.len());
    for input in inputs {
        let source = std::fs::File::open(&input.source)?;
        let (sha256, length) = hash_copy(source, std::io::sink())?;
        archive_members.push(ArchiveMember {
            name: input.archive_path.clone(),
            length,
        });
        artifacts.push(PayloadArtifact {
            component: input.component.clone(),
            version: input.version.clone(),
            commit: Some(input.commit.clone()),
            target_arch: input.target_arch,
            kind: input.kind,
            dispositions: input.dispositions.clone(),
            archive_path: input.archive_path.clone(),
            sha256,
            spec: input.spec.clone(),
        });
    }
    // Taken off the member list itself, so the number the header states below
    // is the very one the manifest binds rather than a second measurement of
    // the same file.
    let member_lengths: Vec<u64> = archive_members.iter().map(|member| member.length).collect();
    let manifest = PayloadManifest::new(pinset.map(str::to_string), archive_members, artifacts)?;
    let manifest = match trust_set {
        Some(generation) => manifest.with_trust_set(generation)?,
        None => manifest,
    };
    let manifest_json = serde_json::to_vec(&manifest).map_err(PayloadError::ManifestSerialize)?;
    let signed = sign(&manifest_json).map_err(PayloadError::Signer)?;
    if let Some(signed) = signed.as_ref() {
        validate_signed(signed)?;
    }

    let manifest_offset = std::io::copy(&mut base, &mut out)?;
    out.write_all(&manifest_json)?;
    let manifest_len = manifest_json.len() as u64;
    let archive_offset = manifest_offset + manifest_len;

    let archive_len = {
        let mut counter = CountingWriter::new(&mut out);
        let encoder = Encoder::new(&mut counter, ZSTD_LEVEL)?;
        let mut builder = Builder::new(encoder);
        // The header's size is the length the manifest now binds, not a second
        // look at the source file's metadata: the two are required to be the
        // same number, and the only way to guarantee that is for there to be
        // one number.
        for (input, length) in inputs.iter().zip(member_lengths) {
            let source = std::fs::File::open(&input.source)?;
            let mut header = Header::new_gnu();
            // The name is written into the header block and the header is
            // appended verbatim, because `Builder::append_data` falls back to a
            // GNU long-name entry for a path the field cannot hold — and the
            // reader refuses a member whose name comes from an extension header
            // rather than from the block it applies to. Refusing the path is the
            // only outcome that keeps the writer and the reader agreeing.
            header
                .set_path(&input.archive_path)
                .map_err(|_| PayloadError::ArchivePathTooLong {
                    path: input.archive_path.clone(),
                    len: input.archive_path.len(),
                })?;
            header.set_size(length);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder.append(&header, source)?;
        }
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        counter.count()
    };

    let (signature_offset, signature_len, key_id_offset, key_id_len) = match signed {
        Some(signed) => {
            let signature_len = u64::try_from(ED25519_SIGNATURE_LEN)
                .expect("the fixed signature length always fits the u64 footer field");
            let key_id_len = u64::try_from(KEY_ID_HEX_LEN)
                .expect("the fixed key_id length always fits the u64 footer field");
            let signature_offset = archive_offset + archive_len;
            out.write_all(&signed.signature)?;
            let key_id_offset = signature_offset + signature_len;
            out.write_all(signed.key_id.as_bytes())?;
            (signature_offset, signature_len, key_id_offset, key_id_len)
        }
        None => (0, 0, 0, 0),
    };
    let footer = Footer {
        version: FORMAT_VERSION,
        manifest_offset,
        manifest_len,
        archive_offset,
        archive_len,
        signature_offset,
        signature_len,
        key_id_offset,
        key_id_len,
    };
    out.write_all(&footer.encode())?;
    Ok(())
}

fn validate_signed(signed: &Signed) -> Result<(), PayloadError> {
    if signed.signature.len() != ED25519_SIGNATURE_LEN {
        return Err(PayloadError::InvalidSignatureLength {
            found: signed.signature.len(),
        });
    }
    if signed.key_id.len() != KEY_ID_HEX_LEN {
        return Err(PayloadError::InvalidKeyId {
            reason: "must be exactly 64 lowercase-hex ASCII characters",
        });
    }
    if !signed
        .key_id
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PayloadError::InvalidKeyId {
            reason: "must contain only lowercase hexadecimal ASCII characters",
        });
    }
    Ok(())
}

/// Copies an existing payload's trailer verbatim onto a different base binary,
/// rewriting every present block's absolute offset by the base-length delta.
///
/// A self-contained release asset is a base executable with a trailer appended
/// (`base | manifest | archive | footer`). To run a CI-built `bootler-security`
/// against the operator's frozen payload, the payload trailer must be grafted
/// onto that fresh base. Rather than re-extracting and re-hashing the (GB-scale)
/// payload, this streams the source's trailer body — the present blocks in
/// their fixed order, which adjacency makes one contiguous run from the
/// manifest to the footer — straight onto `new_base`, then writes a fresh footer
/// whose **present** offsets are each shifted by `new_base_len - old_base_len`;
/// every length is unchanged. The archive bytes and their manifest SHA-256s stay
/// byte-identical, so the reader still hash-verifies every artifact — a caller
/// can confirm the graft by re-opening the output with [`open`].
///
/// An **absent** signature or `key_id` pair is carried across untouched, still
/// exactly all-zero. Adding the delta to it would make offset `0` a non-zero
/// offset beside a zero length — a half-zero pair, which the reader refuses as
/// [`PayloadError::MalformedFooter`] — so a blind shift would turn an unsigned
/// container into a malformed one.
///
/// The body is copied **verbatim** and the manifest is never re-serialized, so
/// the manifest block is byte-identical across the graft and a signature over
/// it remains valid.
/// The source footer's own `version` is written back rather than the current
/// one, so a version-1 payload stays a version-1 payload — footer size and all.
///
/// `source` must carry a trailer; `new_base` is streamed first, then the copied
/// trailer body, then the rewritten footer, so a GB-scale payload never resides
/// in memory in full.
///
/// Because the manifest is never decoded here, the shape it was read in is
/// preserved in both directions by construction: a pre-versioned baseline
/// payload rewraps as one, with no `format_version`, `commit` or `trust_set`
/// synthesized into it — upgraded bytes would claim a build identity nobody
/// resolved, or a trust anchor nobody signed — and a current-format payload
/// round-trips all three unchanged.
///
/// # Errors
///
/// Returns [`PayloadError::NoTrailer`] when `source` carries no trailer,
/// [`PayloadError::UnsupportedContainerFormat`] when a probed candidate's magic
/// matched under a container version this build does not implement,
/// [`PayloadError::TruncatedTrailer`] when the footer's offsets fall outside
/// `source`, [`PayloadError::MalformedFooter`] when its blocks do not sit
/// adjacent in order or an envelope pair is half-zero, or [`PayloadError::Io`]
/// on any read or write failure.
pub fn rewrap_trailer<S, B, W>(
    mut source: S,
    mut new_base: B,
    mut out: W,
) -> Result<(), PayloadError>
where
    S: Read + Seek,
    B: Read,
    W: Write,
{
    let source_len = source.seek(SeekFrom::End(0))?;
    let Located::Found {
        footer,
        footer_start,
    } = locate_footer(&mut source, source_len)?
    else {
        return Err(PayloadError::NoTrailer);
    };

    // Validate the source footer before trusting it (the same check `open`
    // makes). Adjacency is what makes the whole-body copy below valid: the body
    // is the present blocks in fixed order, contiguous from the manifest to the
    // footer start.
    validate_footer(&footer, footer_start)?;

    // The trailer body is everything from the manifest to the start of the
    // footer; it is copied verbatim.
    let old_base_len = footer.manifest_offset;
    let body_len = footer_start - old_base_len;

    let new_base_len = std::io::copy(&mut new_base, &mut out)?;
    source.seek(SeekFrom::Start(old_base_len))?;
    let copied = std::io::copy(&mut source.by_ref().take(body_len), &mut out)?;
    if copied != body_len {
        return Err(PayloadError::TruncatedTrailer);
    }

    // Every present block sits at a fixed distance from the start of the
    // trailer body, so its new offset is that distance past the new base.
    let shifted = |offset: u64| -> Result<u64, PayloadError> {
        offset
            .checked_sub(old_base_len)
            .and_then(|within_body| new_base_len.checked_add(within_body))
            .ok_or(PayloadError::TruncatedTrailer)
    };
    // An absent envelope pair is left exactly all-zero: it is nowhere, so there
    // is nothing to shift, and shifting it would spell a half-zero pair. The
    // manifest and archive have no absent encoding and are always shifted.
    let shifted_envelope = |offset: u64, len: u64| -> Result<u64, PayloadError> {
        if is_absent_pair(offset, len) {
            Ok(0)
        } else {
            shifted(offset)
        }
    };

    // The version is the source's own, never [`FORMAT_VERSION`], so a
    // version-1 payload rewraps as a version-1 payload — including the footer
    // size `encode` derives from it.
    let rewritten = Footer {
        version: footer.version,
        manifest_offset: new_base_len,
        manifest_len: footer.manifest_len,
        archive_offset: shifted(footer.archive_offset)?,
        archive_len: footer.archive_len,
        signature_offset: shifted_envelope(footer.signature_offset, footer.signature_len)?,
        signature_len: footer.signature_len,
        key_id_offset: shifted_envelope(footer.key_id_offset, footer.key_id_len)?,
        key_id_len: footer.key_id_len,
    };
    out.write_all(&rewritten.encode())?;
    Ok(())
}

/// A located container whose manifest block has been read but **not** parsed,
/// together with the bounded envelope metadata a caller can inspect.
///
/// [`open`] parses the manifest as it reads it, which is the right order for a
/// caller that already trusts the bytes it is opening. A verifier does not:
/// the signature is over the raw manifest bytes, so it needs those bytes, and
/// it has to answer for them **before** attacker-supplied JSON reaches a
/// parser. This carries exactly what that decision takes — the raw block, the
/// footer's container version, and the two envelope blocks — and hands the
/// rest back through an internal conversion once the manifest has been
/// authenticated and parsed.
///
/// It is an added path, not a replacement: [`open`] reads the container
/// through the same internal head reader this is built from, so the two cannot
/// come to disagree about where a block is.
pub struct UnparsedContainer<R: Read + Seek> {
    src: R,
    footer_version: u8,
    manifest_bytes: Vec<u8>,
    signature: EnvelopeBlock,
    key_id: EnvelopeBlock,
    archive_offset: u64,
    archive_len: u64,
}

impl<R: Read + Seek> UnparsedContainer<R> {
    /// Returns the container format version the selected footer recorded.
    ///
    /// The manifest parse takes it, because only a reader that knows it can
    /// evaluate the pre-versioned baseline conjunction.
    pub(crate) fn footer_version(&self) -> u8 {
        self.footer_version
    }

    /// Returns the manifest block exactly as it sits in the container.
    ///
    /// These are the bytes a signature is computed over, so they are handed
    /// out unparsed and never re-serialized from a parsed manifest.
    pub(crate) fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Parses this container's unauthenticated manifest for metadata reporting.
    ///
    /// The returned manifest is not authenticated. A caller holding a
    /// [`crate::verify::TrustSet`] follows `verify.rs`' authenticate-then-parse
    /// order instead, authenticating the raw manifest bytes before decoding
    /// them. This entry point serves supported metadata reporting when no key
    /// material is present.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::ManifestParse`] when the manifest bytes are not
    /// decodable JSON, or [`PayloadError::InvalidManifest`] for every other
    /// manifest validation failure.
    pub fn parse_unverified_manifest(&self) -> Result<PayloadManifest, PayloadError> {
        PayloadManifest::parse(self.manifest_bytes(), self.footer_version()).map_err(|error| {
            match error {
                ManifestError::Decode(source) => PayloadError::ManifestParse(source),
                other => PayloadError::InvalidManifest(other),
            }
        })
    }

    /// Returns the detached signature block as the bounded read left it:
    /// absent, present at the bounded length, or present at some other length
    /// and therefore never read.
    #[must_use]
    pub fn signature(&self) -> &EnvelopeBlock {
        &self.signature
    }

    /// Returns the `key_id` block as the bounded read left it, under the same
    /// three states [`UnparsedContainer::signature`] reports.
    #[must_use]
    pub fn key_id(&self) -> &EnvelopeBlock {
        &self.key_id
    }

    /// Finishes opening the container with the `manifest` its own bytes parsed
    /// to.
    ///
    /// Taking the manifest rather than parsing it here is the whole point of
    /// the split: the caller decides when — and whether — those bytes are
    /// trusted enough to parse.
    pub(crate) fn into_payload(self, manifest: PayloadManifest) -> Payload<R> {
        Payload {
            src: self.src,
            manifest,
            archive_offset: self.archive_offset,
            archive_len: self.archive_len,
            // A block the bounded read declined to allocate has no bytes to
            // hand on, so it arrives here as absent. Nothing observes the
            // difference: a signature at any other length verifies under no
            // key, so a container carrying one never reaches this point, and a
            // `key_id` at any other length is not a usable hint — a value the
            // verified package exposes to nobody.
            signature: self.signature.into_bytes(),
            key_id: self.key_id.into_bytes(),
        }
    }
}

/// One envelope block as a bounded read leaves it.
///
/// The container layer reads an envelope block into memory, and a footer's
/// lengths are attacker-controlled: `validate_footer` proves only that a
/// block fits inside the input, which a sparse file — or a hostile
/// `Read + Seek` source — can make arbitrarily large for almost nothing. A
/// reader that states the length it can use therefore has a third answer
/// besides the block's bytes and its absence, and this is it.
#[derive(Debug)]
pub enum EnvelopeBlock {
    /// The container records no such block: the all-zero absent encoding.
    Absent,
    /// The block is present at the bounded length, and these are its bytes.
    Present(Vec<u8>),
    /// The block is present at some other length, so its contents were never
    /// read and never allocated.
    ///
    /// This is deliberately not merged into [`EnvelopeBlock::Absent`]: the
    /// verifier answers an absent signature and an unusable one differently.
    WrongLength,
}

impl EnvelopeBlock {
    /// Returns the block's bytes, or `None` when there are none to return.
    fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            EnvelopeBlock::Present(bytes) => Some(bytes),
            EnvelopeBlock::Absent | EnvelopeBlock::WrongLength => None,
        }
    }
}

/// The exact lengths [`read_package_container`] uses for its two envelope
/// blocks.
///
/// Both blocks have exactly one useful length, and both are read before
/// anything has been authenticated, so the release format states those lengths
/// rather than trusting the footer's. A block of any other length is answered
/// from its length alone — which is the answer its contents would have produced
/// anyway — so nothing is lost by refusing to allocate it. The fields stay
/// crate-private: callers use [`crate::verify::ENVELOPE_BOUNDS`], the only
/// bounds this release format defines.
///
/// [`open`] takes no bounds and reads whatever the footer describes, as it
/// always has: its callers are opening a payload they already trust, and
/// changing what they see is not this reader's to do.
pub struct EnvelopeBounds {
    /// The one length at which the signature block is read.
    pub(crate) signature_len: u64,
    /// The one length at which the `key_id` block is read.
    pub(crate) key_id_len: u64,
}

/// A located container's source, selected footer and unparsed manifest block:
/// everything both readers need before they diverge over when the envelope
/// blocks are read.
struct ContainerHead<R: Read + Seek> {
    src: R,
    footer: Footer,
    manifest_bytes: Vec<u8>,
}

/// The two envelope blocks as the container carries them, each `None` when the
/// container carries none.
struct Envelope {
    signature: Option<Vec<u8>>,
    key_id: Option<Vec<u8>>,
}

/// The two envelope blocks as a bounded read leaves them.
struct BoundedEnvelope {
    signature: EnvelopeBlock,
    key_id: EnvelopeBlock,
}

/// Locates a container in `src` and reads its manifest block without parsing
/// it, reporting `Ok(None)` for a file that carries no trailer.
///
/// Every decision the container layer makes before the manifest is in memory —
/// the footer probe, the offsets check, the block-layout walk — is made here,
/// so [`open`] and [`read_package_container`] cannot locate a block
/// differently. It stops short of the envelope blocks precisely because the
/// two disagree about when those are read: [`open`] must not touch them until
/// its parse has succeeded, and a verifier must have them before any parse
/// happens at all.
///
/// # Errors
///
/// Returns [`PayloadError`] on the container-layer conditions [`open`]
/// reports, minus the envelope and manifest ones it does not reach.
fn read_container_head<R: Read + Seek>(
    mut src: R,
) -> Result<Option<ContainerHead<R>>, PayloadError> {
    let file_len = src.seek(SeekFrom::End(0))?;
    let Located::Found {
        footer,
        footer_start,
    } = locate_footer(&mut src, file_len)?
    else {
        return Ok(None);
    };

    validate_footer(&footer, footer_start)?;

    let manifest_len =
        usize::try_from(footer.manifest_len).map_err(|_| PayloadError::TruncatedTrailer)?;
    src.seek(SeekFrom::Start(footer.manifest_offset))?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    src.read_exact(&mut manifest_bytes)?;

    Ok(Some(ContainerHead {
        src,
        footer,
        manifest_bytes,
    }))
}

/// Reads the signature and `key_id` blocks `footer` locates.
///
/// Both readers come through here, so where an envelope block sits is known in
/// one place even though the two read it at different points.
///
/// # Errors
///
/// Returns [`PayloadError::TruncatedTrailer`] for a length no `usize` can hold
/// and [`PayloadError::Io`] when the read itself fails.
fn read_envelope<R: Read + Seek>(src: &mut R, footer: &Footer) -> Result<Envelope, PayloadError> {
    let signature = read_block(src, footer.signature_offset, footer.signature_len)?;
    let key_id = read_block(src, footer.key_id_offset, footer.key_id_len)?;
    Ok(Envelope { signature, key_id })
}

/// Reads one envelope block, but only when the footer's length for it is
/// `bound`.
///
/// The length decides before the seek does, so a block the caller cannot use is
/// never allocated. That matters because this runs ahead of any authentication:
/// the length comes from a footer an attacker wrote, and
/// [`validate_footer`] confines it only to the input's own size, which costs
/// nothing to inflate in a sparse file.
fn read_bounded_block<R: Read + Seek>(
    src: &mut R,
    offset: u64,
    len: u64,
    bound: u64,
) -> Result<EnvelopeBlock, PayloadError> {
    if is_absent_pair(offset, len) {
        return Ok(EnvelopeBlock::Absent);
    }
    // Compared as `u64`, the type the footer records it in: narrowing the
    // length to `usize` first would turn a block too large for the platform's
    // `usize` into an error rather than the wrong length it is, and an error is
    // a rejection an attacker could drive.
    if len != bound {
        return Ok(EnvelopeBlock::WrongLength);
    }
    match read_block(src, offset, len)? {
        Some(bytes) => Ok(EnvelopeBlock::Present(bytes)),
        None => Ok(EnvelopeBlock::Absent),
    }
}

/// Reads the signature and `key_id` blocks `footer` locates, each only at the
/// length `bounds` states for it.
///
/// # Errors
///
/// Returns [`PayloadError::Io`] when a read itself fails. A block whose length
/// is not the one `bounds` states is reported rather than read, so no length a
/// footer can carry reaches an allocation here.
fn read_bounded_envelope<R: Read + Seek>(
    src: &mut R,
    footer: &Footer,
    bounds: &EnvelopeBounds,
) -> Result<BoundedEnvelope, PayloadError> {
    let signature = read_bounded_block(
        src,
        footer.signature_offset,
        footer.signature_len,
        bounds.signature_len,
    )?;
    let key_id = read_bounded_block(
        src,
        footer.key_id_offset,
        footer.key_id_len,
        bounds.key_id_len,
    )?;
    Ok(BoundedEnvelope { signature, key_id })
}

/// Reads a **`.pkg` module package**'s container without parsing its manifest,
/// under [`open_package`]'s answer to a file with no trailer.
///
/// The envelope blocks are read here, before the caller has parsed anything,
/// because that caller is a verifier: it has to answer for the manifest bytes
/// against the signature before they reach a parser. [`open`], which parses
/// first, defers the same read until afterwards.
///
/// Reading unauthenticated bytes this early is also why the caller passes
/// [`crate::verify::ENVELOPE_BOUNDS`]: a block whose footer length is not one
/// the release format can use is reported as [`EnvelopeBlock::WrongLength`] and
/// never allocated. See [`EnvelopeBounds`].
///
/// A package that carries no container is broken, not an ordinary file, so
/// that condition is [`PayloadError::NoTrailer`] here exactly as it is there.
///
/// # Errors
///
/// Returns [`PayloadError::NoTrailer`] when `src` carries no trailer, and any
/// other container-layer error the bounded read encounters.
pub fn read_package_container<R: Read + Seek>(
    src: R,
    bounds: &EnvelopeBounds,
) -> Result<UnparsedContainer<R>, PayloadError> {
    let ContainerHead {
        mut src,
        footer,
        manifest_bytes,
    } = read_container_head(src)?.ok_or(PayloadError::NoTrailer)?;
    let envelope = read_bounded_envelope(&mut src, &footer, bounds)?;

    Ok(UnparsedContainer {
        src,
        footer_version: footer.version,
        manifest_bytes,
        signature: envelope.signature,
        key_id: envelope.key_id,
        archive_offset: footer.archive_offset,
        archive_len: footer.archive_len,
    })
}

/// A located and parsed payload trailer, holding the source it was read from so
/// its artifacts can be extracted and verified.
#[derive(Debug)]
pub struct Payload<R: Read + Seek> {
    src: R,
    manifest: PayloadManifest,
    archive_offset: u64,
    archive_len: u64,
    signature: Option<Vec<u8>>,
    key_id: Option<Vec<u8>>,
}

impl<R: Read + Seek> Payload<R> {
    /// Returns the payload manifest.
    #[must_use]
    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
    }

    /// Returns the container's detached signature block, or `None` when the
    /// container carries none.
    ///
    /// An absent block is `None` and never an empty slice, so a caller cannot
    /// mistake "nothing was signed" for "a zero-byte signature was". Whether
    /// an *unsigned* container is acceptable is not this layer's call: the
    /// container reader reports what is there, and a verifier decides what
    /// that is worth.
    #[must_use]
    pub fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }

    /// Returns the identifier of the key the [`signature`](Self::signature) was
    /// made with, or `None` when the container carries none.
    ///
    /// Independent of the signature at this layer: the container layout does
    /// not require one to arrive with the other, and defines no error for one
    /// without it.
    #[must_use]
    pub fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_deref()
    }

    /// Extracts every artifact into `dest`, verifying each member against its
    /// manifest entry.
    ///
    /// The archive block is constrained to what the manifest can bind: a member
    /// is admitted only when it is a regular file, is named and sized by its
    /// own raw `ustar` header rather than by an overriding extension header,
    /// uses a normalized relative path, appears in the manifest exactly once,
    /// and hashes to the SHA-256 the manifest records. Every one of those checks
    /// runs before the member's bytes can reach a final path. Nothing may
    /// follow the end-of-archive marker, so a second archive appended past it —
    /// invisible to this reader, visible to others — is refused rather than
    /// ignored. After the walk, every manifest artifact must have been seen; a
    /// manifest entry with no archive member is rejected so nothing the
    /// manifest promises is silently skipped.
    ///
    /// Also after the walk, the sequence of members the archive turned out to
    /// hold — each one's resolved name and the byte count this reader consumed
    /// for it — must equal the ordered list the manifest binds as
    /// `archive_members`, in name, order, count and per-member length. That
    /// check is skipped, and only that check, for a manifest read off the
    /// pre-versioned baseline path, which binds no list to compare against.
    ///
    /// Each member streams from the archive into a staging directory while its
    /// SHA-256 is computed, so no member is buffered in memory in full and a
    /// GB-scale artifact still streams.
    ///
    /// # All-or-nothing
    ///
    /// On any rejection this function decides — a refused member, a hash
    /// mismatch, a member sequence disagreeing with the bound list, or an I/O
    /// failure met while reading the archive or staging a member — `dest` is
    /// left exactly as it was found: no extracted artifact,
    /// no directory created to hold one, no staging directory and no temporary
    /// file. `dest` and its missing ancestors are created if absent, and that
    /// is the only difference a rejection is allowed to leave behind: after a
    /// rejection a previously absent `dest` is either still absent or exists
    /// and is empty.
    ///
    /// Two cases lie outside that guarantee. It does not survive a process
    /// crash: nothing runs on the way out, so a crash mid-walk can leave the
    /// staging directory and whatever is under it behind, and a crash mid-
    /// publish can leave both that and already-published artifacts. And it does
    /// not cover the final publish step — the moves that put already-verified
    /// members at their target paths once every check has passed. Publishing
    /// several files is not one atomic operation, so **a failure during the
    /// publish step may leave already-verified members at their target paths**;
    /// making it otherwise would mean owning `dest` rather than writing into
    /// it, which is a different function's contract. Even there, no staging
    /// directory and no temporary file survives, and no partially written
    /// artifact appears at a target path, because each individual move is
    /// atomic.
    ///
    /// # Durability
    ///
    /// What a crash cannot undo is a publish that *completed*. On a successful
    /// return every extracted artifact is on disk — its bytes, and the entry
    /// naming it, along with every directory between it and `dest` that this
    /// call may have created — so a power loss immediately after an install
    /// reports success cannot leave an artifact empty, truncated or missing.
    /// The one thing left unflushed is the directory holding `dest` itself,
    /// which belongs to whoever chose `dest`.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError`] when a member is a non-regular entry, is named
    /// or sized by an overriding extension header, uses an unsafe path, is
    /// absent from the manifest, is a repeated `archive_path`, or fails its
    /// hash check; when the archive block carries bytes past the
    /// end-of-archive marker; when a manifest artifact has no matching member;
    /// when the members walked disagree with the manifest's bound
    /// `archive_members` in name, order, count or per-member length
    /// ([`PayloadError::MemberListMismatch`]); or when the archive cannot be
    /// read, or a staged member cannot be written, flushed or published.
    pub fn extract_to(&mut self, dest: &Path) -> Result<Vec<ExtractedArtifact>, PayloadError> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let manifest = &self.manifest;
        let by_path: HashMap<&str, &PayloadArtifact> = manifest
            .artifacts()
            .iter()
            .map(|artifact| (artifact.archive_path.as_str(), artifact))
            .collect();

        // `dest` is created up front rather than incidentally by the first
        // member's parent directory, so how far the walk got before a rejection
        // cannot decide whether it exists.
        std::fs::create_dir_all(dest)?;
        // Every member lands here first and is published only once the whole
        // archive has been walked and every check has passed. The staging
        // directory sits inside `dest` so the publishing renames stay on one
        // filesystem, and its `Drop` removes it — with everything staged under
        // it — on every path out of this function. Owner-only at creation, and
        // not left to the umask: a member sits under it for the whole walk with
        // its hash still unchecked, so nothing outside this process has any
        // business reading it.
        let staging = TempBuilder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(dest)?;

        self.src.seek(SeekFrom::Start(self.archive_offset))?;
        let limited = (&mut self.src).take(self.archive_len);
        let decoder = Decoder::new(limited)?;
        let mut archive = Archive::new(decoder);

        let mut staged: Vec<(PathBuf, &PayloadArtifact)> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        // What the archive actually turned out to hold, recorded member by
        // member as it streams past and compared against the bound list only
        // once the walk is over: count and order are not decidable before then.
        let mut walked: Vec<ArchiveMember> = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let member_path = admitted_member_path(&entry)?;
            let Some(artifact) = by_path.get(member_path.as_str()).copied() else {
                return Err(PayloadError::MemberNotInManifest(member_path));
            };
            if !seen.insert(artifact.archive_path.as_str()) {
                return Err(PayloadError::DuplicateMember(member_path));
            }

            let relative = PathBuf::from(&member_path);
            let staged_path = staging.path().join(&relative);
            if let Some(parent) = staged_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Owner-only from the moment it is created, the mode the
            // `NamedTempFile` this staging replaced gave a member's bytes: the
            // artifact reaches its target path by rename, so this is the only
            // moment its permissions are chosen.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&staged_path)?;
            let (digest, length) = hash_copy(&mut entry, &mut file)?;
            if !digest.eq_ignore_ascii_case(&artifact.sha256) {
                return Err(PayloadError::HashMismatch {
                    path: artifact.archive_path.clone(),
                });
            }
            // Protects the artifact's own bytes, which the publish step below
            // does no more than rename into place. After the check, so a member
            // about to be rejected does not buy a disk round trip, and here
            // rather than at the publish, which holds no descriptor for this
            // file and would have to reopen it to get one.
            file.sync_all()?;
            // The length recorded is the count of data bytes this reader
            // consumed while hashing the member, never the size read back out
            // of its `tar` header: the bound length has to be a property of the
            // bytes that were hashed.
            walked.push(ArchiveMember {
                name: member_path,
                length,
            });
            staged.push((relative, artifact));
        }

        reject_trailing_bytes(&mut archive.into_inner())?;

        for artifact in manifest.artifacts() {
            if !seen.contains(artifact.archive_path.as_str()) {
                return Err(PayloadError::ArtifactMissingFromArchive(
                    artifact.archive_path.clone(),
                ));
            }
        }

        // The walk against the list the manifest binds — an addition to every
        // check above, never a replacement for one. It is compared against
        // `archive_members` and never reconstructed from `artifacts`: deriving
        // the expected sequence from the other field would leave the
        // enumeration exactly as unstated as it was before it was recorded. A
        // manifest read off the pre-versioned baseline path binds no list, so
        // there is nothing to compare against and this check alone is skipped.
        if let Some(bound) = manifest.archive_members() {
            compare_member_list(bound, &walked)?;
        }

        // Publish. Every check has passed, so from here a failure may leave
        // already-verified members behind; each individual move is atomic, so
        // no partial artifact can appear at a target path.
        let mut extracted = Vec::with_capacity(staged.len());
        let mut published: Vec<PathBuf> = Vec::with_capacity(staged.len());
        for (relative, artifact) in staged {
            let out_path = dest.join(&relative);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(staging.path().join(&relative), &out_path)?;
            extracted.push(ExtractedArtifact {
                artifact: artifact.clone(),
                path: out_path,
            });
            published.push(relative);
        }

        // The artifacts' bytes are down, but the names the renames just gave
        // them are not, and neither are the directories the loop above may have
        // created to hold them. What this protects is a host that boots: an
        // install that reported success and lost a binary does not come back
        // up. Every level is flushed rather than the innermost alone, because a
        // directory's own entry lives in its parent. The staging directory is
        // not flushed at all — its `Drop` removes it.
        for dir in publish_dirs(dest, &published) {
            sync_dir(&dir)?;
        }

        Ok(extracted)
    }
}

/// The directories a completed [`Payload::extract_to`] flushes: for every
/// published artifact, the directory holding it and each ancestor between that
/// and `dest`, with `dest` itself, each returned exactly once.
///
/// `relatives` are the artifact paths relative to `dest`, as the publish loop
/// joins them. Each chain is walked innermost first, since a directory's own
/// entry lives in its parent, and the walk stops at `dest`: `dest` is created by
/// the same call, but the directory holding *it* is the caller's to flush.
///
/// Split out from the publish loop because the arithmetic — which levels, how
/// far up, how often — is the part of this worth testing, and none of it is
/// observable from the flushes themselves.
fn publish_dirs(dest: &Path, relatives: &[PathBuf]) -> Vec<PathBuf> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut dirs = Vec::new();
    for relative in relatives {
        // `Path::parent` of a bare file name is the empty path, whose parent is
        // `None`, so the walk terminates at `dest` on its own rather than by
        // comparing paths for ancestry.
        let mut current = relative.parent();
        while let Some(rel_dir) = current {
            let dir = if rel_dir.as_os_str().is_empty() {
                dest.to_path_buf()
            } else {
                dest.join(rel_dir)
            };
            if seen.insert(dir.clone()) {
                dirs.push(dir);
            }
            current = rel_dir.parent();
        }
    }
    dirs
}

/// Compares the sequence the archive walk produced against the ordered member
/// list the manifest binds.
///
/// A whole-sequence check, not a per-member one: a permuted archive holds
/// nothing but members that pass every individual check, and reducing this to a
/// comparison made as each member streams past would let a prefix of the
/// archive through before the disagreement is reached. The first position the
/// two disagree at is reported, whether they differ in name, in length, or in
/// having a member there at all.
///
/// # Errors
///
/// Returns [`PayloadError::MemberListMismatch`] naming that position.
fn compare_member_list(
    bound: &[ArchiveMember],
    walked: &[ArchiveMember],
) -> Result<(), PayloadError> {
    for index in 0..bound.len().max(walked.len()) {
        let expected = bound.get(index);
        let found = walked.get(index);
        if expected != found {
            return Err(PayloadError::MemberListMismatch {
                index,
                expected: expected.cloned(),
                found: found.cloned(),
            });
        }
    }
    Ok(())
}

/// Admits one archive member on the archive format's own terms and returns the
/// path it may be looked up in the manifest under.
///
/// Every rejection here is decided before any manifest lookup, so the member is
/// refused for what the archive says about it rather than for what the manifest
/// does or does not name. Each refusal carries its own variant: two readers that
/// disagree about a member is a different defect from an unusable path, which is
/// a different defect again from an entry that is not a file at all.
///
/// # Errors
///
/// Returns [`PayloadError::UnsupportedEntryType`] for anything but a regular
/// file, [`PayloadError::NameOverridingHeader`] or
/// [`PayloadError::SizeOverridingHeader`] when an extension header replaces the
/// name or the size the raw `ustar` header block states, and
/// [`PayloadError::UnsafeMemberPath`] for a name that is not valid UTF-8 or not
/// a normalized relative path.
fn admitted_member_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, PayloadError> {
    // The raw `ustar` name field, taken from the header block itself, against
    // the name the archive library resolved — which a PAX `path` record or a
    // GNU long-name entry silently replaces. The disagreement between the two
    // is the whole diagnostic, so both are read before either is trusted.
    let header_name = entry.header().path_bytes();
    let resolved_name = entry.path_bytes();
    let display = String::from_utf8_lossy(&resolved_name).into_owned();

    if entry.header().entry_type() != EntryType::Regular {
        return Err(PayloadError::UnsupportedEntryType { path: display });
    }
    if header_name != resolved_name {
        return Err(PayloadError::NameOverridingHeader {
            header_name: String::from_utf8_lossy(&header_name).into_owned(),
            resolved_name: display,
        });
    }
    // The name is not the only field an extension header can override. The size
    // the reader attributes to the member decides where the member ends and so
    // where the next header starts, so a PAX `size` record hides a whole second
    // member inside this one's bytes from whichever of two readers honours it.
    let header_size = entry.header().entry_size()?;
    let resolved_size = entry.size();
    if header_size != resolved_size {
        return Err(PayloadError::SizeOverridingHeader {
            path: display,
            header_size,
            resolved_size,
        });
    }
    let Ok(path) = std::str::from_utf8(&resolved_name) else {
        return Err(PayloadError::UnsafeMemberPath(display));
    };
    if !is_safe_archive_path(path) {
        return Err(PayloadError::UnsafeMemberPath(display));
    }
    Ok(display)
}

/// Reads `reader` — the decompressed archive block, positioned where the entry
/// walk stopped — to its end, refusing anything but the one zero block the
/// end-of-archive marker leaves unread.
///
/// [`Archive::entries`] stops at that marker and reports nothing about what
/// follows it, so a second archive appended past it is invisible to this reader
/// and visible to one that keeps going. Draining the decoder is what makes the
/// difference observable.
///
/// # Errors
///
/// Returns [`PayloadError::TrailingArchiveBytes`] when a non-zero byte or more
/// than [`MAX_END_OF_ARCHIVE_BYTES`] of them remain, and [`PayloadError::Io`]
/// when the read itself fails.
fn reject_trailing_bytes<R: Read>(reader: &mut R) -> Result<(), PayloadError> {
    let mut buf = [0u8; TAR_BLOCK_SIZE];
    let mut remaining = 0usize;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }
        remaining += read;
        if buf.iter().take(read).any(|byte| *byte != 0) || remaining > MAX_END_OF_ARCHIVE_BYTES {
            return Err(PayloadError::TrailingArchiveBytes);
        }
    }
}

/// Reads one trailer block into memory, or reports it absent.
///
/// Only the small envelope blocks are read this way; the archive streams. A
/// crafted length cannot make one large, because the caller has already run
/// [`validate_footer`], whose adjacency walk and offsets check together confine
/// every present block to bytes the file actually holds.
fn read_block<R: Read + Seek>(
    src: &mut R,
    offset: u64,
    len: u64,
) -> Result<Option<Vec<u8>>, PayloadError> {
    if is_absent_pair(offset, len) {
        return Ok(None);
    }
    let len = usize::try_from(len).map_err(|_| PayloadError::TruncatedTrailer)?;
    src.seek(SeekFrom::Start(offset))?;
    let mut block = vec![0u8; len];
    src.read_exact(&mut block)?;
    Ok(Some(block))
}

/// Locates and reads a trailer from `src`.
///
/// This whole-container reader does not bound its envelope blocks. Call
/// [`read_package_container`] with [`crate::verify::ENVELOPE_BOUNDS`] instead
/// when reading untrusted metadata alone.
///
/// Returns `Ok(None)` for an empty payload — a file in which the size probe
/// selected no footer, which is the normal state of an ordinary dev or CI
/// build. Use [`open_package`] for a `.pkg`, where the same condition is a
/// broken package rather than an ordinary file.
///
/// # Errors
///
/// Returns [`PayloadError`] when a container was found but is unusable: a
/// candidate magic under a container version this build does not implement
/// ([`PayloadError::UnsupportedContainerFormat`]), offsets pointing outside the
/// file ([`PayloadError::TruncatedTrailer`]), a half-zero envelope pair or
/// blocks that do not sit adjacent in order
/// ([`PayloadError::MalformedFooter`]), a manifest whose `format_version` this
/// build does not implement (reported as [`PayloadError::InvalidManifest`]
/// carrying [`ManifestError::UnsupportedManifestFormat`]), or a manifest that
/// fails to parse or validate.
pub fn open<R: Read + Seek>(src: R) -> Result<Option<Payload<R>>, PayloadError> {
    let Some(ContainerHead {
        mut src,
        footer,
        manifest_bytes,
    }) = read_container_head(src)?
    else {
        return Ok(None);
    };
    // The manifest is read through the two-stage parse rather than a direct
    // `serde_json::from_slice`, because only a reader that already knows the
    // container footer version can evaluate the pre-versioned baseline
    // conjunction. An undecodable manifest block keeps reporting as
    // `ManifestParse`, distinct from a version this build does not implement.
    // The two versions stay distinct here: this is the container's, and what it
    // gates is the baseline conjunction, not the manifest schema range.
    let manifest =
        PayloadManifest::parse(&manifest_bytes, footer.version).map_err(|error| match error {
            ManifestError::Decode(source) => PayloadError::ManifestParse(source),
            other => PayloadError::InvalidManifest(other),
        })?;

    // Only now, after the parse: this reader answers for the manifest before it
    // ever seeks to an envelope offset, and that order is observable — a
    // container with both an unparseable manifest and an unreadable envelope
    // block reports the manifest fault, as it did before the verifier's
    // container-read split existed.
    let envelope = read_envelope(&mut src, &footer)?;

    Ok(Some(Payload {
        src,
        manifest,
        archive_offset: footer.archive_offset,
        archive_len: footer.archive_len,
        signature: envelope.signature,
        key_id: envelope.key_id,
    }))
}

/// Opens the binary at `path` and reads its trailer.
///
/// Returns `Ok(None)` when the binary carries no trailer.
///
/// This whole-container reader does not bound its envelope blocks. Call
/// [`read_package_container`] with [`crate::verify::ENVELOPE_BOUNDS`] instead
/// when reading untrusted metadata alone.
///
/// # Errors
///
/// Returns [`PayloadError`] when the file cannot be opened or its trailer is
/// corrupt (see [`open`]).
pub fn open_path(path: &Path) -> Result<Option<Payload<std::fs::File>>, PayloadError> {
    let file = std::fs::File::open(path)?;
    open(file)
}

/// Opens a **`.pkg` module package** read from `src`.
///
/// A `.pkg` is this module's container with no base executable: the same
/// manifest, archive, signature and `key_id` blocks under the same footer, with
/// the manifest block starting at offset `0`. It is read by exactly the reader
/// [`open`] uses — the same size probe, the same footer validation, the same
/// manifest parse — under one different answer: a package with no trailer is
/// broken, so this returns [`PayloadError::NoTrailer`] where [`open`] would
/// report an empty payload, and yields a [`Payload`] rather than an `Option`.
///
/// That is also what makes a package self-verifying wherever it lands,
/// air-gapped transfer included: the footer says what the container holds, and
/// nothing about the transport does.
///
/// There is no `.pkg` counterpart of [`open_current_exe`]: the running
/// executable is a payload, not a package.
///
/// This whole-container reader does not bound its envelope blocks. Call
/// [`read_package_container`] with [`crate::verify::ENVELOPE_BOUNDS`] instead
/// when reading untrusted metadata alone.
///
/// # Errors
///
/// Returns [`PayloadError::NoTrailer`] when `src` carries no trailer, and
/// otherwise every error [`open`] raises.
pub fn open_package<R: Read + Seek>(src: R) -> Result<Payload<R>, PayloadError> {
    // The one place "no trailer found" becomes `NoTrailer` for the package
    // side, so no wrapper can quietly reclassify it.
    open(src)?.ok_or(PayloadError::NoTrailer)
}

/// Opens the `.pkg` at `path` and reads its container.
///
/// Carries no logic of its own: it opens the file and delegates to
/// [`open_package`], exactly as [`open_path`] delegates to [`open`].
///
/// This whole-container reader does not bound its envelope blocks. Call
/// [`read_package_container`] with [`crate::verify::ENVELOPE_BOUNDS`] instead
/// when reading untrusted metadata alone.
///
/// # Errors
///
/// Returns [`PayloadError`] when the file cannot be opened, or any error
/// [`open_package`] raises — including [`PayloadError::NoTrailer`] when the
/// file carries no container.
pub fn open_package_path(path: &Path) -> Result<Payload<std::fs::File>, PayloadError> {
    let file = std::fs::File::open(path)?;
    open_package(file)
}

/// Reads the running executable's own trailer via
/// [`std::env::current_exe`].
///
/// Returns `Ok(None)` when the running binary has no trailer (dev/CI builds).
///
/// # Errors
///
/// Returns [`PayloadError`] when the current executable path cannot be resolved
/// or opened, or its trailer is corrupt (see [`open`]).
pub fn open_current_exe() -> Result<Option<Payload<std::fs::File>>, PayloadError> {
    let exe = std::env::current_exe()?;
    open_path(&exe)
}

/// Reads the **payload-free base executable** out of `src` — the ELF bytes before
/// any appended trailer.
///
/// A trailered release binary is `base ‖ trailer`, so the base is exactly the
/// first `footer.manifest_offset` bytes (`rewrap_trailer` relies on the same
/// prefix). A binary with no trailer (a dev/CI build, or one already stripped)
/// *is* its own base, so the whole file is returned — a third answer to "no
/// trailer found", neither [`open`]'s empty payload nor [`open_package`]'s
/// [`PayloadError::NoTrailer`]. Only the base bytes are read into memory, never
/// the multi-hundred-megabyte payload.
///
/// bootler self-installs these bytes onto each core host so the `roxyd-activate`
/// oneshot has a small, root-owned validator to run; the activation subcommand
/// touches no payload, so shipping it without one is both correct and far cheaper
/// than copying the fat binary (RFC 0003 §8.3).
///
/// # Errors
///
/// Returns [`PayloadError`] when `src` cannot be read, a probed candidate names
/// a container version this build does not implement
/// ([`PayloadError::UnsupportedContainerFormat`]), or the located footer's
/// manifest block starts past the footer ([`PayloadError::TruncatedTrailer`]).
pub fn read_base_executable<R: Read + Seek>(mut src: R) -> Result<Vec<u8>, PayloadError> {
    let file_len = src.seek(SeekFrom::End(0))?;
    let base_len = match locate_footer(&mut src, file_len)? {
        // The base is the prefix before the manifest block.
        Located::Found {
            footer,
            footer_start,
        } => {
            if footer.manifest_offset > footer_start {
                return Err(PayloadError::TruncatedTrailer);
            }
            footer.manifest_offset
        }
        // No trailer: the file is its own base.
        Located::NoTrailer => file_len,
    };
    let base_len = usize::try_from(base_len).map_err(|_| PayloadError::TruncatedTrailer)?;
    src.seek(SeekFrom::Start(0))?;
    let mut base = vec![0u8; base_len];
    src.read_exact(&mut base)?;
    Ok(base)
}

/// Reads the running executable's payload-free base bytes via
/// [`std::env::current_exe`] (see [`read_base_executable`]).
///
/// # Errors
///
/// Returns [`PayloadError`] when the current executable path cannot be resolved or
/// opened, or its trailer is corrupt.
pub fn current_exe_base() -> Result<Vec<u8>, PayloadError> {
    let exe = std::env::current_exe()?;
    let file = std::fs::File::open(exe)?;
    read_base_executable(file)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use tar::{Builder, EntryType, Header};
    use zstd::{Decoder, Encoder};

    use super::{
        ArtifactInput, Candidate, ED25519_SIGNATURE_LEN, EnvelopeBlock, FOOTER_SIZE,
        FOOTER_SIZE_V1, FOOTER_SIZE_V2, FORMAT_VERSION, Footer, KEY_ID_HEX_LEN, KNOWN_FOOTER_SIZES,
        MAGIC, MAGIC_LEN, PayloadError, PayloadManifest, Signed, SignerError, TAR_BLOCK_SIZE,
        TAR_NAME_FIELD_LEN, append_trailer, append_trailer_signed, classify_candidate, open,
        open_current_exe, open_package, open_package_path, publish_dirs, read_base_executable,
        read_package_container, rewrap_trailer, sha256_hex, widen_envelope_blocks,
    };
    use crate::manifest::{
        ArchiveMember, ArtifactKind, Disposition, MANIFEST_FORMAT_VERSION,
        MAX_MANIFEST_FORMAT_VERSION, MIN_MANIFEST_FORMAT_VERSION, ManifestError, PayloadArtifact,
        TargetArch,
    };
    use crate::module_spec::{
        Arg, ModuleSpec, PlacementClass, RegistrationTemplate, ReloadSpec, RenderVar,
        RestartPolicy, SystemdTarget, UnitTemplate,
    };
    use crate::verify::ENVELOPE_BOUNDS;

    const BASE: &[u8] = b"#!/bin/false\nnot a real executable, just a base binary\n";

    /// A full 40-hex git commit SHA, the build identity a producer stamps onto
    /// every current-format artifact.
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// Opaque stand-in for the signed trust-set generation container.
    const GENERATION: &[u8] = b"a signed generation container, opaque to this crate";

    struct CountingSource {
        inner: Cursor<Vec<u8>>,
        read_count: Rc<Cell<usize>>,
        seek_count: Rc<Cell<usize>>,
    }

    impl Read for CountingSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read_count.set(self.read_count.get() + 1);
            self.inner.read(buf)
        }
    }

    impl Seek for CountingSource {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.seek_count.set(self.seek_count.get() + 1);
            self.inner.seek(pos)
        }
    }

    fn dispositions(values: &[Disposition]) -> BTreeSet<Disposition> {
        values.iter().copied().collect()
    }

    /// Writes `bytes` to `dir/name` and returns an [`ArtifactInput`] sourced
    /// from that file, so the streaming writer has a real file to read.
    fn input(
        dir: &Path,
        name: &str,
        archive_path: &str,
        bytes: &[u8],
        dispositions_values: &[Disposition],
    ) -> ArtifactInput {
        let source = dir.join(name);
        std::fs::write(&source, bytes).expect("write source file");
        ArtifactInput {
            component: "example".to_string(),
            version: "1.0.0".to_string(),
            commit: COMMIT.to_string(),
            target_arch: TargetArch::X86_64,
            kind: ArtifactKind::NativeBinary,
            dispositions: dispositions(dispositions_values),
            archive_path: archive_path.to_string(),
            spec: None,
            source,
        }
    }

    /// Builds the combined binary the streaming writer would produce for
    /// `inputs`, returning it as a buffer the in-memory reader tests consume.
    fn build_binary(inputs: &[ArtifactInput]) -> Vec<u8> {
        build_binary_with_trust_set(inputs, None)
    }

    fn build_binary_with_trust_set(inputs: &[ArtifactInput], trust_set: Option<&[u8]>) -> Vec<u8> {
        let mut binary = Vec::new();
        append_trailer(Cursor::new(BASE), &mut binary, None, trust_set, inputs)
            .expect("writer should succeed");
        binary
    }

    /// Builds a zstd-compressed tar archive from raw members, bypassing the
    /// writer so adversarial members (symlinks, unsafe paths, unknown files)
    /// can be crafted.
    #[derive(Clone, Copy)]
    enum Member<'a> {
        File {
            path: &'a str,
            bytes: &'a [u8],
        },
        /// A regular file whose name bytes are written straight into the GNU
        /// header, bypassing `tar`'s write-time path validation so unsafe paths
        /// (absolute or containing `..`) can be crafted.
        RawFile {
            path: &'a str,
            bytes: &'a [u8],
        },
        Symlink {
            path: &'a str,
            target: &'a str,
        },
        Hardlink {
            path: &'a str,
            target: &'a str,
        },
        CharDevice {
            path: &'a str,
        },
        Directory {
            path: &'a str,
        },
        /// A GNU long-name entry (`L`) followed by the member it renames, so
        /// the resolved name comes from the extension header while the raw
        /// `ustar` name field says something else. The `tar` reader applies it
        /// transparently.
        GnuLongName {
            /// Name written into the renamed member's raw header block.
            header_path: &'a str,
            /// Name the long-name entry resolves that member to.
            resolved_path: &'a str,
            bytes: &'a [u8],
        },
        /// A PAX local extension entry (`x`) carrying a `path` record, followed
        /// by the member it renames. Also applied transparently.
        PaxPath {
            /// Name written into the renamed member's raw header block.
            header_path: &'a str,
            /// Name the `path` record resolves that member to.
            resolved_path: &'a str,
            bytes: &'a [u8],
        },
        /// A PAX local extension entry (`x`) carrying a `size` record that
        /// disagrees with the raw `ustar` header's size field, followed by the
        /// member it resizes. `tar` honours the record, so this reader
        /// attributes all of `bytes` to the member while a reader that ignores
        /// PAX stops after `header_size` and resynchronizes inside them.
        PaxSize {
            path: &'a str,
            /// Size written into the member's raw header block.
            header_size: u64,
            /// Bytes actually following it, and the size the record names.
            bytes: &'a [u8],
        },
    }

    /// Builds the GNU header a raw regular member is named by, with the name
    /// bytes written straight into the header block so `tar`'s write-time path
    /// validation never sees them, and the size stated independently of the
    /// bytes that will follow.
    fn raw_regular_header(path: &str, size: u64) -> Header {
        let mut header = Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(EntryType::Regular);
        {
            let gnu = header.as_gnu_mut().expect("gnu header");
            let name_bytes = path.as_bytes();
            gnu.name[..name_bytes.len()].copy_from_slice(name_bytes);
        }
        header.set_cksum();
        header
    }

    /// Appends a regular member whose name bytes go straight into the GNU
    /// header, bypassing `tar`'s write-time path validation.
    fn append_raw_regular<W: std::io::Write>(builder: &mut Builder<W>, path: &str, bytes: &[u8]) {
        let header = raw_regular_header(path, bytes.len() as u64);
        builder.append(&header, bytes).unwrap();
    }

    /// Encodes one PAX extended-header record, `"<len> <key>=<value>\n"`, whose
    /// length field counts its own digits — so the width is found by fixed
    /// point rather than assumed.
    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let without_len = key.len() + value.len() + 3;
        let mut total = without_len + 1;
        loop {
            let candidate = without_len + total.to_string().len();
            if candidate == total {
                break;
            }
            total = candidate;
        }
        format!("{total} {key}={value}\n").into_bytes()
    }

    /// Appends an extension header entry of `entry_type` named `name` carrying
    /// `body`, the shape both name-overriding fixtures are built from.
    fn append_extension_header<W: std::io::Write>(
        builder: &mut Builder<W>,
        entry_type: EntryType,
        name: &[u8],
        body: &[u8],
    ) {
        let mut header = Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(entry_type);
        {
            let gnu = header.as_gnu_mut().expect("gnu header");
            gnu.name[..name.len()].copy_from_slice(name);
        }
        header.set_cksum();
        builder.append(&header, body).unwrap();
    }

    /// Builds the uncompressed tar stream for `members`, terminated by the
    /// two-block end-of-archive marker `Builder::into_inner` writes.
    fn tar_bytes(members: &[Member]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for member in members {
            match member {
                Member::File { path, bytes } => {
                    let mut header = Header::new_gnu();
                    header.set_size(bytes.len() as u64);
                    header.set_mode(0o644);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Regular);
                    header.set_cksum();
                    builder.append_data(&mut header, path, *bytes).unwrap();
                }
                Member::RawFile { path, bytes } => {
                    append_raw_regular(&mut builder, path, bytes);
                }
                Member::GnuLongName {
                    header_path,
                    resolved_path,
                    bytes,
                } => {
                    // GNU writes the long name as the body of an `L` entry
                    // conventionally named `././@LongLink`, NUL-terminated.
                    let mut name = resolved_path.as_bytes().to_vec();
                    name.push(0);
                    append_extension_header(
                        &mut builder,
                        EntryType::GNULongName,
                        b"././@LongLink",
                        &name,
                    );
                    append_raw_regular(&mut builder, header_path, bytes);
                }
                Member::PaxPath {
                    header_path,
                    resolved_path,
                    bytes,
                } => {
                    let body = pax_record("path", resolved_path);
                    append_extension_header(
                        &mut builder,
                        EntryType::XHeader,
                        b"PaxHeaders.0/override",
                        &body,
                    );
                    append_raw_regular(&mut builder, header_path, bytes);
                }
                Member::PaxSize {
                    path,
                    header_size,
                    bytes,
                } => {
                    let body = pax_record("size", &bytes.len().to_string());
                    append_extension_header(
                        &mut builder,
                        EntryType::XHeader,
                        b"PaxHeaders.0/resize",
                        &body,
                    );
                    // `Builder::append` pads from the bytes it copies, not from
                    // the header's size field, so the two are free to disagree.
                    let header = raw_regular_header(path, *header_size);
                    builder.append(&header, *bytes).unwrap();
                }
                Member::Symlink { path, target } => {
                    let mut header = Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o777);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Symlink);
                    builder.append_link(&mut header, path, target).unwrap();
                }
                Member::Hardlink { path, target } => {
                    let mut header = Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o644);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Link);
                    builder.append_link(&mut header, path, target).unwrap();
                }
                Member::CharDevice { path } => {
                    let mut header = Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o644);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Char);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, path, std::io::empty())
                        .unwrap();
                }
                Member::Directory { path } => {
                    let mut header = Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o755);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Directory);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, path, std::io::empty())
                        .unwrap();
                }
            }
        }
        builder.into_inner().unwrap()
    }

    fn zstd_compress(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new(), 3).unwrap();
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// Builds a zstd-compressed tar archive from raw members, bypassing the
    /// writer so adversarial members (symlinks, unsafe paths, unknown files)
    /// can be crafted.
    fn zstd_tar(members: &[Member]) -> Vec<u8> {
        zstd_compress(&tar_bytes(members))
    }

    /// The same, with `trailing` appended inside the compressed block, past the
    /// end-of-archive marker where a `tar` reader stops looking.
    fn zstd_tar_with_trailing(members: &[Member], trailing: &[u8]) -> Vec<u8> {
        let mut bytes = tar_bytes(members);
        bytes.extend_from_slice(trailing);
        zstd_compress(&bytes)
    }

    /// Lists `root`'s contents recursively as sorted relative paths, with a
    /// trailing `/` on directories, so an unchanged destination can be asserted
    /// as an equality of two walks and a stray created directory fails as
    /// loudly as a stray file.
    fn walk(root: &Path) -> Vec<String> {
        fn visit(dir: &Path, prefix: &Path, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries {
                let entry = entry.expect("directory entry");
                let relative = prefix.join(entry.file_name());
                if entry.file_type().expect("file type").is_dir() {
                    out.push(format!("{}/", relative.display()));
                    visit(&entry.path(), &relative, out);
                } else {
                    out.push(relative.display().to_string());
                }
            }
        }
        let mut out = Vec::new();
        visit(root, Path::new(""), &mut out);
        out.sort_unstable();
        out
    }

    /// Drives extraction of a hand-built payload into a destination seeded with
    /// pre-existing content, and asserts the rejection left that destination
    /// exactly as it was found — walked recursively before and after.
    ///
    /// The temporary directory is returned alongside the error so a caller can
    /// add assertions of its own before it is removed.
    fn extract_error_leaving_dest_unchanged(
        json: &[u8],
        archive: &[u8],
    ) -> (PayloadError, tempfile::TempDir) {
        extract_error_at_version(FORMAT_VERSION, json, archive)
    }

    /// The same, at a stated container version — which a baseline manifest
    /// needs, since the pre-versioned baseline path is keyed on footer
    /// version 1.
    fn extract_error_at_version(
        version: u8,
        json: &[u8],
        archive: &[u8],
    ) -> (PayloadError, tempfile::TempDir) {
        let footer = footer_at_version(version, BASE.len(), json, archive);
        let binary = assemble(BASE, json, archive, &footer);
        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("pre/existing")).expect("seed directory");
        std::fs::write(dir.path().join("pre/existing/file"), b"kept").expect("seed file");
        let before = walk(dir.path());

        let error = payload
            .extract_to(dir.path())
            .expect_err("extraction should be rejected");
        assert_eq!(
            walk(dir.path()),
            before,
            "a rejection must leave the destination exactly as it was found"
        );
        (error, dir)
    }

    /// The footer a writer would stamp on `base | manifest | archive`: both
    /// envelope pairs absent, so the archive block is the last present block
    /// and ends where the footer begins.
    fn valid_footer(base_len: usize, manifest_json: &[u8], archive: &[u8]) -> Footer {
        footer_at_version(FORMAT_VERSION, base_len, manifest_json, archive)
    }

    /// The same at a stated container version, so a fixture can reproduce a
    /// published version-1 payload byte-for-byte — `encode` derives the 41-byte
    /// wire form from the version it is given.
    fn footer_at_version(
        version: u8,
        base_len: usize,
        manifest_json: &[u8],
        archive: &[u8],
    ) -> Footer {
        let manifest_offset = base_len as u64;
        let manifest_len = manifest_json.len() as u64;
        Footer {
            version,
            manifest_offset,
            manifest_len,
            archive_offset: manifest_offset + manifest_len,
            archive_len: archive.len() as u64,
            signature_offset: 0,
            signature_len: 0,
            key_id_offset: 0,
            key_id_len: 0,
        }
    }

    /// The container version the pre-versioned baseline payloads carry.
    const LEGACY_VERSION: u8 = 1;

    /// Locates and parses `binary`'s footer exactly as the reader's probe does:
    /// the known sizes in ascending order, selecting on magic plus the
    /// size/version pairing.
    ///
    /// Returns the footer and the offset its own bytes start at.
    fn probe_footer(binary: &[u8]) -> (Footer, usize) {
        for size in &KNOWN_FOOTER_SIZES {
            if binary.len() < size.bytes {
                continue;
            }
            let start = binary.len() - size.bytes;
            let candidate = binary.get(start..).expect("candidate in range");
            if let Candidate::Selected(footer) = classify_candidate(candidate, size) {
                return (footer, start);
            }
        }
        panic!("the fixture must carry a footer the probe selects");
    }

    fn assemble(base: &[u8], manifest_json: &[u8], archive: &[u8], footer: &Footer) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(base);
        out.extend_from_slice(manifest_json);
        out.extend_from_slice(archive);
        out.extend_from_slice(&footer.encode());
        out
    }

    /// Wire JSON of a current-format manifest describing one artifact per entry
    /// and binding one archive member per entry, both in the order given — the
    /// shape the writer produces, since both lists come from one `inputs` slice.
    fn manifest_json(entries: &[(&str, &[u8])]) -> Vec<u8> {
        manifest_json_binding(&members_of(entries), entries)
    }

    /// The same, with the bound member list stated outright, so a test can make
    /// the manifest disagree with the archive in exactly one respect.
    fn manifest_json_binding(members: &[ArchiveMember], entries: &[(&str, &[u8])]) -> Vec<u8> {
        let artifacts = entries
            .iter()
            .map(|(archive_path, bytes)| artifact(archive_path, bytes))
            .collect();
        let manifest = PayloadManifest::new(None, members.to_vec(), artifacts)
            .expect("manifest should be valid");
        serde_json::to_vec(&manifest).expect("serialization should succeed")
    }

    /// The member list an archive holding exactly `entries`, in order, presents
    /// to the reader.
    fn members_of(entries: &[(&str, &[u8])]) -> Vec<ArchiveMember> {
        entries
            .iter()
            .map(|(archive_path, bytes)| ArchiveMember {
                name: (*archive_path).to_string(),
                length: bytes.len() as u64,
            })
            .collect()
    }

    /// Slices `binary`'s trailer the way the reader locates it: the base, the
    /// manifest block, and the archive block.
    fn trailer_parts(binary: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let (footer, _) = probe_footer(binary);
        let at = |offset: u64| usize::try_from(offset).expect("fixture offsets fit in usize");
        let manifest_at = at(footer.manifest_offset);
        let archive_at = at(footer.archive_offset);
        (
            binary.get(..manifest_at).expect("base in range"),
            binary
                .get(manifest_at..manifest_at + at(footer.manifest_len))
                .expect("manifest block in range"),
            binary
                .get(archive_at..archive_at + at(footer.archive_len))
                .expect("archive block in range"),
        )
    }

    /// Rebuilds `binary` with `manifest_json` in place of its manifest block,
    /// leaving the base and the archive block exactly as they were.
    ///
    /// This is what lets a mismatch case mutate only the bytes under test — one
    /// recorded length, one member name — over an archive the writer produced.
    fn with_manifest_block(binary: &[u8], manifest_json: &[u8]) -> Vec<u8> {
        let (base, _, archive) = trailer_parts(binary);
        let footer = valid_footer(base.len(), manifest_json, archive);
        assemble(base, manifest_json, archive, &footer)
    }

    /// Decodes `binary`'s manifest block as a generic JSON document, hands the
    /// bound member array to `mutate`, and rebuilds the container around the
    /// rewritten block.
    fn mutating_bound_members(
        binary: &[u8],
        mutate: impl FnOnce(&mut Vec<serde_json::Value>),
    ) -> Vec<u8> {
        let (_, block, _) = trailer_parts(binary);
        let mut document: serde_json::Value =
            serde_json::from_slice(block).expect("the manifest block decodes");
        let members = document
            .get_mut("archive_members")
            .expect("a written manifest binds a member list")
            .as_array_mut()
            .expect("the bound list is an array");
        mutate(members);
        let json = serde_json::to_vec(&document).expect("serialization should succeed");
        with_manifest_block(binary, &json)
    }

    fn artifact(archive_path: &str, bytes: &[u8]) -> PayloadArtifact {
        PayloadArtifact {
            component: "example".to_string(),
            version: "1.0.0".to_string(),
            commit: Some(COMMIT.to_string()),
            target_arch: TargetArch::X86_64,
            kind: ArtifactKind::NativeBinary,
            dispositions: dispositions(&[Disposition::Install]),
            archive_path: archive_path.to_string(),
            sha256: sha256_hex(bytes),
            spec: None,
        }
    }

    /// Hand-rolls the wire JSON of a **pre-versioned baseline** manifest: no
    /// `format_version`, no artifact `commit`, no `trust_set`. It cannot come
    /// from [`PayloadManifest::new`], which stamps the current schema version,
    /// so the already-published assets this shape stands for are reproduced
    /// byte-wise here instead.
    fn baseline_manifest_json(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let artifacts: Vec<String> = entries
            .iter()
            .map(|(archive_path, bytes)| {
                format!(
                    r#"{{"component":"example","version":"1.0.0","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"{archive_path}","sha256":"{}"}}"#,
                    sha256_hex(bytes)
                )
            })
            .collect();
        format!(r#"{{"artifacts":[{}]}}"#, artifacts.join(",")).into_bytes()
    }

    #[test]
    fn rewrap_grafts_the_trailer_onto_a_new_base_and_still_verifies() {
        let roxyd = b"roxyd binary bytes";
        let web = b"static web assets";
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![
            input(
                src.path(),
                "roxyd.src",
                "bin/roxyd",
                roxyd,
                &[Disposition::Install],
            ),
            input(
                src.path(),
                "web.src",
                "assets/web.tar",
                web,
                &[Disposition::Install],
            ),
        ];
        // The published self-contained asset: a trailer appended onto `BASE`.
        let asset = build_binary(&inputs);

        // A CI-built base of a DIFFERENT length, so the offsets must shift.
        let new_base: &[u8] = b"a freshly built bootler-security base, of a different length";
        assert_ne!(new_base.len(), BASE.len());

        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(&asset), Cursor::new(new_base), &mut rewrapped)
            .expect("rewrap should succeed");

        // The new base is the prefix, and the footer is still the final bytes.
        assert!(rewrapped.starts_with(new_base));
        let footer_start = rewrapped.len() - FOOTER_SIZE;
        assert_eq!(
            rewrapped.get(footer_start..footer_start + MAGIC.len()),
            Some(MAGIC.as_slice()),
        );

        // The grafted payload reads back and every artifact hash still verifies.
        let mut payload = open(Cursor::new(rewrapped))
            .expect("reader should succeed")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().artifacts().len(), 2);
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 2);
        assert_eq!(std::fs::read(dir.path().join("bin/roxyd")).unwrap(), roxyd);
        assert_eq!(
            std::fs::read(dir.path().join("assets/web.tar")).unwrap(),
            web
        );
    }

    #[test]
    fn rewrap_rejects_a_source_with_no_trailer() {
        let new_base: &[u8] = b"new base";
        let err = rewrap_trailer(Cursor::new(BASE), Cursor::new(new_base), &mut Vec::new())
            .expect_err("a source without a trailer must be rejected");
        assert!(matches!(err, PayloadError::NoTrailer), "got: {err:?}");
    }

    #[test]
    fn write_read_and_extract_round_trip() {
        let roxyd = b"roxyd binary bytes";
        let web = b"static web assets";
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![
            input(
                src.path(),
                "roxyd.src",
                "bin/roxyd",
                roxyd,
                &[Disposition::Install, Disposition::Stage],
            ),
            input(
                src.path(),
                "web.src",
                "assets/web.tar",
                web,
                &[Disposition::Install],
            ),
        ];

        let binary = build_binary(&inputs);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().artifacts().len(), 2);

        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 2);

        let roxyd_out = dir.path().join("bin/roxyd");
        assert_eq!(std::fs::read(&roxyd_out).unwrap(), roxyd);
        let web_out = dir.path().join("assets/web.tar");
        assert_eq!(std::fs::read(&web_out).unwrap(), web);
        // Owner-only, as the staged file was created — the rename that
        // publishes it carries its mode across unchanged.
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&roxyd_out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "got: {mode:o}");
        }
        // The two artifacts and their parents, and nothing else: a successful
        // extraction leaves no staging directory behind either.
        assert_eq!(
            walk(dir.path()),
            vec![
                "assets/".to_string(),
                "assets/web.tar".to_string(),
                "bin/".to_string(),
                "bin/roxyd".to_string(),
            ]
        );

        let roxyd_entry = extracted
            .iter()
            .find(|e| e.artifact.archive_path == "bin/roxyd")
            .expect("roxyd artifact should be extracted");
        assert_eq!(
            roxyd_entry.artifact.dispositions,
            dispositions(&[Disposition::Install, Disposition::Stage])
        );
    }

    #[test]
    fn a_written_payload_carries_the_format_version_and_each_commit() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        let binary = build_binary(&inputs);

        let payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer should be present");
        assert_eq!(
            payload.manifest().format_version(),
            Some(MANIFEST_FORMAT_VERSION)
        );
        assert_eq!(
            payload
                .manifest()
                .artifacts()
                .first()
                .expect("one artifact")
                .commit
                .as_deref(),
            Some(COMMIT)
        );
    }

    #[test]
    fn a_trust_set_round_trips_byte_for_byte_and_adds_no_artifact() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];

        let with = build_binary_with_trust_set(&inputs, Some(GENERATION));
        let payload = open(Cursor::new(with))
            .expect("reader should succeed")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().trust_set(), Some(GENERATION));
        assert_eq!(payload.manifest().artifacts().len(), 1);

        let without = build_binary_with_trust_set(&inputs, None);
        let payload = open(Cursor::new(without))
            .expect("reader should succeed")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().trust_set(), None);
        assert_eq!(payload.manifest().artifacts().len(), 1);
    }

    #[test]
    fn the_writer_rejects_an_empty_trust_set() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        let error = append_trailer(Cursor::new(BASE), &mut Vec::new(), None, Some(b""), &inputs)
            .expect_err("an empty generation must be rejected");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::EmptyTrustSet)
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_undecodable_trust_set_reaches_open_as_invalid_manifest() {
        // The trust-set refusals ride the same `InvalidManifest` channel the
        // version gate does, so a hand-edited generation blob is reported for
        // what it is rather than swallowed as a generic `ManifestParse`.
        let roxyd = b"roxyd binary bytes";
        let json = String::from_utf8(manifest_json(&[("bin/roxyd", roxyd)]))
            .expect("fixture is utf-8")
            .replacen('{', r#"{"trust_set":"not base64!!","#, 1)
            .into_bytes();
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let error = open(Cursor::new(binary)).expect_err("a non-base64 trust_set must be refused");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::TrustSetNotBase64(_))
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_unimplemented_manifest_format_version_reaches_open_as_invalid_manifest() {
        // The out-of-range refusal needs no new `PayloadError` variant: it
        // rides the existing `InvalidManifest` channel, and stays distinct from
        // the `ManifestParse` an undecodable block reports. The body here is
        // deliberately one this build cannot decode — `artifacts` is not even an
        // array — so reaching the version variant proves `open` refused it for
        // its version rather than for its shape.
        let found = MAX_MANIFEST_FORMAT_VERSION + 1;
        let json =
            format!(r#"{{"format_version":{found},"artifacts":"a future shape"}}"#).into_bytes();
        let archive = zstd_tar(&[]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let error =
            open(Cursor::new(binary)).expect_err("an unimplemented format version must be refused");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::UnsupportedManifestFormat {
                    found: got,
                    min,
                    max,
                }) if got == found
                    && min == MIN_MANIFEST_FORMAT_VERSION
                    && max == MAX_MANIFEST_FORMAT_VERSION
            ),
            "got: {error:?}"
        );
    }

    /// A spec a producer may stamp onto the `example` component's native
    /// binary.
    fn module_spec() -> ModuleSpec {
        ModuleSpec {
            unit: Some(UnitTemplate {
                description: "Roxyd host agent".to_string(),
                after: vec![SystemdTarget::NetworkOnline],
                wants: vec![SystemdTarget::NetworkOnline],
                wanted_by: vec![SystemdTarget::MultiUser],
                exec_start: vec![
                    Arg::Var(RenderVar::ArtifactPath),
                    Arg::Literal("-c".to_string()),
                    Arg::Var(RenderVar::ConfigPath),
                ],
                exec_reload: None,
                working_directory: None,
                environment: Vec::new(),
                restart: RestartPolicy::Always,
                restart_sec: 5,
                limit_nofile: None,
                protect_home: true,
                private_tmp: true,
                no_new_privileges: true,
            }),
            registration: RegistrationTemplate {
                package_id: "example".to_string(),
                service_name: "example".to_string(),
                reload: ReloadSpec::Sighup {
                    process_path: "/opt/clumit-security/bin/roxyd".to_string(),
                },
                cert_group_gid: None,
            },
            placement: PlacementClass::ModuleHosts,
        }
    }

    #[test]
    fn the_writer_stamps_an_inputs_spec_onto_the_derived_manifest_entry() {
        // `append_trailer` derives each entry from one `ArtifactInput`, so a
        // field present only on `PayloadArtifact` would be one no producer
        // could populate. It is copied across unchanged.
        let src = tempfile::tempdir().expect("source tempdir");
        let mut inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        inputs[0].spec = Some(module_spec());

        let payload = open(Cursor::new(build_binary(&inputs)))
            .expect("reader should succeed")
            .expect("trailer should be present");
        let entry = payload
            .manifest()
            .artifacts()
            .first()
            .expect("one artifact");
        assert_eq!(entry.spec.as_ref(), Some(&module_spec()));
    }

    #[test]
    fn the_writer_refuses_an_input_whose_spec_a_reader_would_reject() {
        let src = tempfile::tempdir().expect("source tempdir");
        let mut inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        let mut spec = module_spec();
        spec.registration.package_id = "somewhere-else".to_string();
        inputs[0].spec = Some(spec);

        let error = append_trailer(Cursor::new(BASE), &mut Vec::new(), None, None, &inputs)
            .expect_err("a mismatched package_id must be rejected");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::InvalidSpec { ref archive_path, .. })
                    if archive_path == "bin/roxyd"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn the_writer_rejects_an_abbreviated_commit_on_an_input() {
        // `ArtifactInput::commit` is a plain `String`, so the width and charset
        // rule is enforced where the manifest is assembled rather than by the
        // type. A producer that stamps an abbreviation is refused here.
        let src = tempfile::tempdir().expect("source tempdir");
        let mut inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        inputs[0].commit = "abc1234".to_string();

        let error = append_trailer(Cursor::new(BASE), &mut Vec::new(), None, None, &inputs)
            .expect_err("an abbreviated commit must be rejected");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::InvalidCommit {
                    ref archive_path,
                    ref commit,
                }) if archive_path == "bin/roxyd" && commit == "abc1234"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_pre_versioned_baseline_payload_opens_verifies_and_extracts() {
        // The already-published release assets carry none of the bump's fields
        // and sit at footer version 1; a required CI preflight reads exactly
        // those, so they must keep opening.
        let roxyd = b"roxyd binary bytes";
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);
        // A published asset's footer is the 41-byte version-1 one, and the
        // probe still finds it.
        assert_eq!(probe_footer(&binary).0.version, LEGACY_VERSION);
        assert_eq!(binary.len() - probe_footer(&binary).1, FOOTER_SIZE_V1);

        let mut payload = open(Cursor::new(binary))
            .expect("a baseline payload must open")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().format_version(), None);
        assert_eq!(payload.manifest().trust_set(), None);
        // A version-1 footer records neither envelope pair, so both read absent.
        assert_eq!(payload.signature(), None);
        assert_eq!(payload.key_id(), None);
        assert_eq!(
            payload
                .manifest()
                .artifacts()
                .first()
                .expect("one artifact")
                .commit,
            None
        );

        // It binds no member list, so that one check has nothing to compare
        // against and is skipped.
        assert_eq!(payload.manifest().archive_members(), None);
        // Re-serializing it emits no `archive_members` key and no `null`, so
        // the wire form of a published asset is unchanged by this field.
        let round_tripped =
            serde_json::to_string(payload.manifest()).expect("serialization should succeed");
        assert!(
            !round_tripped.contains("archive_members"),
            "got: {round_tripped}"
        );
        assert!(!round_tripped.contains("null"), "got: {round_tripped}");

        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 1);
        assert_eq!(std::fs::read(dir.path().join("bin/roxyd")).unwrap(), roxyd);
    }

    #[test]
    fn a_baseline_payload_extracts_with_members_in_an_order_its_artifacts_do_not_repeat() {
        // The archive walks `assets/web.tar` first, while the manifest names
        // `bin/roxyd` first. A baseline manifest binds no member list, so there
        // is nothing for the order to disagree with and the comparison is
        // skipped outright. That permutation is what makes this test
        // discriminating: were the expected sequence ever reconstructed from
        // `artifacts` rather than the bound list, the walk would not match it
        // and extraction would fail here. The single-member baseline test
        // cannot catch that — with one member there is no order to permute and
        // no count to disagree about.
        let roxyd = b"roxyd binary bytes";
        let web = b"static web assets";
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd), ("assets/web.tar", web)]);
        let archive = zstd_tar(&[
            Member::File {
                path: "assets/web.tar",
                bytes: web,
            },
            Member::File {
                path: "bin/roxyd",
                bytes: roxyd,
            },
        ]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("a baseline payload must open")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().format_version(), None);
        // Unambiguously the baseline path: no list is bound.
        assert_eq!(payload.manifest().archive_members(), None);

        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 2);
        assert_eq!(std::fs::read(dir.path().join("bin/roxyd")).unwrap(), roxyd);
        assert_eq!(
            std::fs::read(dir.path().join("assets/web.tar")).unwrap(),
            web
        );
    }

    #[test]
    fn a_baseline_payload_still_rejects_a_member_its_manifest_does_not_name() {
        // Skipping the member-list check disables nothing else: every
        // pre-existing member and archive check still runs on the baseline
        // path, so a member the manifest never named is refused exactly as it
        // is on the current-format path.
        let roxyd = b"roxyd binary bytes";
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        let archive = zstd_tar(&[
            Member::File {
                path: "bin/roxyd",
                bytes: roxyd,
            },
            Member::File {
                path: "bin/stowaway",
                bytes: b"attacker bytes",
            },
        ]);

        let (error, dir) = extract_error_at_version(LEGACY_VERSION, &json, &archive);
        assert!(
            matches!(error, PayloadError::MemberNotInManifest(ref path) if path == "bin/stowaway"),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn a_baseline_payload_with_a_commit_on_one_artifact_is_rejected() {
        let roxyd = b"roxyd binary bytes";
        let baseline = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        // Hand-edit a `commit` into the otherwise unversioned manifest: no
        // producer ever wrote that shape, since all three fields land in one
        // bump.
        let json = String::from_utf8(baseline)
            .expect("fixture is utf-8")
            .replace(
                r#""component":"example""#,
                &format!(r#""component":"example","commit":"{COMMIT}""#),
            )
            .into_bytes();
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let error = open(Cursor::new(binary)).expect_err("a half-legacy manifest must be rejected");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::BaselineWithCommit(ref path))
                    if path == "bin/roxyd"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn rewrap_preserves_the_manifest_shape_in_both_directions() {
        let new_base: &[u8] = b"a freshly built base binary, of a different length entirely";
        assert_ne!(new_base.len(), BASE.len());
        let roxyd = b"roxyd binary bytes";

        // A baseline payload rewraps as a baseline payload: nothing is
        // synthesized into it, because the trailer body is copied verbatim.
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let baseline = assemble(BASE, &json, &archive, &footer);

        let mut rewrapped = Vec::new();
        rewrap_trailer(
            Cursor::new(&baseline),
            Cursor::new(new_base),
            &mut rewrapped,
        )
        .expect("rewrap should succeed");
        let payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped baseline must open")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().format_version(), None);
        assert_eq!(payload.manifest().trust_set(), None);
        assert_eq!(
            payload
                .manifest()
                .artifacts()
                .first()
                .expect("one artifact")
                .commit,
            None
        );

        // A current-format payload carrying all three fields round-trips each
        // of them unchanged.
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            roxyd,
            &[Disposition::Install],
        )];
        let current = build_binary_with_trust_set(&inputs, Some(GENERATION));

        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(&current), Cursor::new(new_base), &mut rewrapped)
            .expect("rewrap should succeed");
        let payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped payload must open")
            .expect("trailer should be present");
        assert_eq!(
            payload.manifest().format_version(),
            Some(MANIFEST_FORMAT_VERSION)
        );
        assert_eq!(payload.manifest().trust_set(), Some(GENERATION));
        assert_eq!(
            payload
                .manifest()
                .artifacts()
                .first()
                .expect("one artifact")
                .commit
                .as_deref(),
            Some(COMMIT)
        );
    }

    #[test]
    fn writer_rejects_dot_prefixed_archive_path() {
        // The `tar` crate normalizes away a leading `./`, so a `./`-bearing
        // `archive_path` would be recorded in the manifest yet stored under a
        // different member name — a self-inconsistent trailer the extractor
        // would then reject as `MemberNotInManifest`. Construction must refuse
        // it up front instead.
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            "./bin/roxyd",
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        let mut out = Vec::new();
        let error = append_trailer(Cursor::new(BASE), &mut out, None, None, &inputs)
            .expect_err("dot-prefixed archive_path must be rejected");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::UnsafeArchivePath(_))
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn writer_rejects_an_archive_path_longer_than_a_header_name_field() {
        // `tar` stores a path the name field cannot hold in a GNU long-name
        // entry, which the reader refuses as `NameOverridingHeader`. The writer
        // must therefore refuse the path up front, at the producer, rather than
        // emitting a payload whose members its own reader rejects.
        let src = tempfile::tempdir().expect("source tempdir");
        let long = format!("bin/{}", "a".repeat(TAR_NAME_FIELD_LEN));
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            &long,
            b"roxyd binary bytes",
            &[Disposition::Install],
        )];
        let mut out = Vec::new();
        let error = append_trailer(Cursor::new(BASE), &mut out, None, None, &inputs)
            .expect_err("an over-long archive_path must be rejected");
        assert!(
            matches!(error, PayloadError::ArchivePathTooLong { ref path, len }
                if path == &long && len == long.len()),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_archive_path_filling_the_header_name_field_still_round_trips() {
        // The boundary from the other side: a path that exactly fills the name
        // field needs no extension header, so the guard above must not reject
        // it and extraction must accept the member it produces.
        let bytes = b"roxyd binary bytes";
        let exact = format!("bin/{}", "a".repeat(TAR_NAME_FIELD_LEN - 4));
        assert_eq!(exact.len(), TAR_NAME_FIELD_LEN);
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            &exact,
            bytes,
            &[Disposition::Install],
        )];
        let binary = build_binary(&inputs);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload.extract_to(dir.path()).expect("extraction succeeds");
        let [only] = extracted.as_slice() else {
            panic!("expected exactly one artifact, got {extracted:?}");
        };
        assert_eq!(only.artifact.archive_path, exact);
        assert_eq!(std::fs::read(&only.path).expect("read extracted"), bytes);
    }

    #[test]
    fn an_io_failure_mid_walk_leaves_the_destination_unchanged() {
        // The all-or-nothing guarantee covers I/O failures met while reading the
        // archive, not only refused members. The tar stream is cut inside the
        // second member's header, so the first member is fully staged and
        // verified before the read fails — and must still not survive.
        let roxyd = b"roxyd binary bytes";
        let web = b"static web assets";
        let json = manifest_json(&[("bin/roxyd", roxyd), ("assets/web.tar", web)]);
        let first = Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        };
        let second = Member::File {
            path: "assets/web.tar",
            bytes: web,
        };
        // Everything `tar_bytes` writes for the first member alone, less the
        // two-block end-of-archive marker: the offset the second member's
        // header starts at.
        let second_header_at = tar_bytes(&[first]).len() - 2 * TAR_BLOCK_SIZE;
        let mut stream = tar_bytes(&[first, second]);
        stream.truncate(second_header_at + TAR_BLOCK_SIZE / 2);
        let archive = zstd_compress(&stream);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(matches!(error, PayloadError::Io(_)), "got: {error:?}");
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn binary_without_trailer_is_an_empty_payload() {
        // Shorter than the footer.
        assert!(open(Cursor::new(vec![0u8; 4])).unwrap().is_none());
        // Longer than the footer but trailing bytes are not the magic.
        assert!(open(Cursor::new(vec![0xABu8; 200])).unwrap().is_none());
        // A plausible base binary with no trailer at all.
        assert!(open(Cursor::new(BASE.to_vec())).unwrap().is_none());
    }

    #[test]
    fn magic_mismatch_on_a_real_trailer_reads_as_empty() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = vec![input(
            src.path(),
            "roxyd.src",
            "bin/roxyd",
            b"bytes",
            &[Disposition::Install],
        )];
        let mut binary = build_binary(&inputs);
        // Corrupt the first magic byte (start of the footer region).
        let footer_start = binary.len() - FOOTER_SIZE;
        let magic_byte = binary.get_mut(footer_start).expect("footer start in range");
        *magic_byte ^= 0xFF;
        assert!(open(Cursor::new(binary)).unwrap().is_none());
    }

    #[test]
    fn a_corrupted_magic_gives_each_site_its_own_no_trailer_answer() {
        // One reader, four answers. A corrupted magic is not a version
        // condition at all, so none of these is `UnsupportedContainerFormat`
        // and none is `MalformedFooter`.
        let src = tempfile::tempdir().expect("source tempdir");
        let mut binary = two_member_binary(src.path());
        let footer_start = binary.len() - FOOTER_SIZE;
        let magic_byte = binary.get_mut(footer_start).expect("footer start in range");
        *magic_byte ^= 0xFF;

        assert!(
            open(Cursor::new(binary.clone()))
                .expect("open reports an empty payload")
                .is_none()
        );
        let error =
            open_package(Cursor::new(binary.clone())).expect_err("a package must carry a trailer");
        assert!(matches!(error, PayloadError::NoTrailer), "got: {error:?}");
        let error = rewrap_trailer(Cursor::new(&binary), Cursor::new(BASE), &mut Vec::new())
            .expect_err("there is nothing to rewrap");
        assert!(matches!(error, PayloadError::NoTrailer), "got: {error:?}");
        let base = read_base_executable(Cursor::new(&binary)).expect("the file is its own base");
        assert_eq!(base, binary);
    }

    #[test]
    fn tampered_artifact_byte_fails_the_hash_check() {
        let original = b"roxyd binary bytes";
        // The manifest records the SHA-256 of the original bytes, but the
        // archive member carries a one-byte-flipped copy: a tampered artifact.
        let mut tampered = original.to_vec();
        let byte = tampered.get_mut(0).expect("non-empty");
        *byte ^= 0x01;

        let json = manifest_json(&[("bin/roxyd", original)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: &tampered,
        }]);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::HashMismatch { ref path } if path == "bin/roxyd"),
            "got: {error:?}"
        );
        // Nothing is written when the hash check fails.
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn truncated_trailer_is_rejected() {
        let bytes = b"payload bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);
        let mut footer = valid_footer(BASE.len(), &json, &archive);
        // Claim the archive is far larger than the file actually holds.
        footer.archive_len += 10_000;
        let binary = assemble(BASE, &json, &archive, &footer);

        let error = open(Cursor::new(binary)).expect_err("truncated trailer expected");
        assert!(
            matches!(error, PayloadError::TruncatedTrailer),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_unknown_container_version_is_rejected_from_every_probing_site() {
        // Only the version byte moves: the container keeps its 73-byte footer,
        // so its magic still sits at the 73-byte candidate offset and the probe
        // still reaches it — it just names a version this build has never heard
        // of. Every site that locates a footer must say so.
        let src = tempfile::tempdir().expect("source tempdir");
        let mut binary = two_member_binary(src.path());
        let unknown = FORMAT_VERSION + 7;
        let version_at = binary.len() - FOOTER_SIZE + MAGIC_LEN;
        let version_byte = binary.get_mut(version_at).expect("version byte in range");
        *version_byte = unknown;

        let expect_unsupported = |error: PayloadError, site: &str| {
            assert!(
                matches!(
                    error,
                    PayloadError::UnsupportedContainerFormat { found, supported }
                        if found == unknown && supported == [1, FORMAT_VERSION]
                ),
                "{site} got: {error:?}"
            );
        };

        expect_unsupported(
            open(Cursor::new(binary.clone())).expect_err("open must reject it"),
            "open",
        );
        expect_unsupported(
            open_package(Cursor::new(binary.clone())).expect_err("open_package must reject it"),
            "open_package",
        );
        expect_unsupported(
            rewrap_trailer(Cursor::new(&binary), Cursor::new(BASE), &mut Vec::new())
                .expect_err("rewrap_trailer must reject it"),
            "rewrap_trailer",
        );
        expect_unsupported(
            read_base_executable(Cursor::new(&binary))
                .expect_err("read_base_executable must reject it"),
            "read_base_executable",
        );
    }

    #[test]
    fn the_unsupported_container_format_message_names_found_and_the_accepted_set() {
        let error = PayloadError::UnsupportedContainerFormat {
            found: 9,
            supported: &[1, 2],
        };
        let rendered = error.to_string();
        assert!(rendered.contains('9'), "got: {rendered}");
        assert!(rendered.contains("1, 2"), "got: {rendered}");
    }

    #[test]
    fn manifest_that_fails_to_parse_is_rejected() {
        let bytes = b"payload bytes";
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);
        let json = b"{ this is not valid json";
        let footer = valid_footer(BASE.len(), json, &archive);
        let binary = assemble(BASE, json, &archive, &footer);

        let error = open(Cursor::new(binary)).expect_err("manifest parse failure expected");
        assert!(
            matches!(error, PayloadError::ManifestParse(_)),
            "got: {error:?}"
        );
    }

    #[test]
    fn bounded_manifest_parse_matches_open_error_mapping() {
        let bytes = b"payload bytes";
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);

        let invalid_json = b"{ this is not valid json";
        let footer = valid_footer(BASE.len(), invalid_json, &archive);
        let binary = assemble(BASE, invalid_json, &archive, &footer);
        let open_error = open(Cursor::new(binary.clone())).expect_err("open must reject JSON");
        let bounded_error = read_package_container(Cursor::new(binary), &ENVELOPE_BOUNDS)
            .expect("the bounded reader only locates the manifest")
            .parse_unverified_manifest()
            .expect_err("the bounded parser must reject JSON");
        assert!(matches!(open_error, PayloadError::ManifestParse(_)));
        assert!(matches!(bounded_error, PayloadError::ManifestParse(_)));

        let mut document: serde_json::Value =
            serde_json::from_slice(&manifest_json(&[("bin/roxyd", bytes)]))
                .expect("the fixture manifest decodes");
        document["format_version"] =
            serde_json::Value::from(u64::from(MAX_MANIFEST_FORMAT_VERSION + 1));
        let unsupported_version =
            serde_json::to_vec(&document).expect("the fixture manifest serializes");
        let footer = valid_footer(BASE.len(), &unsupported_version, &archive);
        let binary = assemble(BASE, &unsupported_version, &archive, &footer);
        let open_error = open(Cursor::new(binary.clone()))
            .expect_err("open must reject an unsupported manifest version");
        let bounded_error = read_package_container(Cursor::new(binary), &ENVELOPE_BOUNDS)
            .expect("the bounded reader only locates the manifest")
            .parse_unverified_manifest()
            .expect_err("the bounded parser must reject an unsupported manifest version");
        assert!(matches!(open_error, PayloadError::InvalidManifest(_)));
        assert!(matches!(bounded_error, PayloadError::InvalidManifest(_)));
    }

    #[test]
    fn bounded_manifest_parse_ignores_refused_envelope_blocks() {
        let bytes = b"payload bytes";
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);
        let binary = signed_fixture(&manifest_json(&[("bin/roxyd", bytes)]), &archive);

        let container = read_package_container(Cursor::new(binary), &ENVELOPE_BOUNDS)
            .expect("the bounded reader accepts a wrong-length envelope block");
        assert!(matches!(container.signature(), EnvelopeBlock::WrongLength));
        assert!(
            container.parse_unverified_manifest().is_ok(),
            "a refused envelope block must not affect manifest parsing"
        );
    }

    #[test]
    fn widened_envelope_fixture_bounds_metadata_without_reading_holes() {
        const ADVERTISED_LEN: u64 = 1_024;

        let source = tempfile::tempdir().expect("source tempdir");
        let inputs = [input(
            source.path(),
            "roxyd.src",
            "bin/roxyd",
            ROXYD,
            &[Disposition::Install],
        )];
        let mut package = Vec::new();
        append_trailer_signed(std::io::empty(), &mut package, None, None, &inputs, |_| {
            Ok(Signed {
                signature: vec![0x5a; ED25519_SIGNATURE_LEN],
                key_id: "a".repeat(KEY_ID_HEX_LEN),
            })
        })
        .expect("the signed package is written");
        let compact = widen_envelope_blocks(&package, ADVERTISED_LEN);

        let container = read_package_container(
            SparseEnvelopeSource::new(compact.clone(), ADVERTISED_LEN),
            &ENVELOPE_BOUNDS,
        )
        .expect("the bounded reader does not read the widened blocks");
        assert!(matches!(container.signature(), EnvelopeBlock::WrongLength));
        assert!(matches!(container.key_id(), EnvelopeBlock::WrongLength));
        assert!(
            container.parse_unverified_manifest().is_ok(),
            "widening the envelope does not affect the manifest"
        );

        let error = open_package(SparseEnvelopeSource::new(compact, ADVERTISED_LEN))
            .expect_err("the unbounded reader tries to read the sparse envelope");
        assert!(matches!(error, PayloadError::Io(_)), "got: {error:?}");
    }

    #[test]
    #[should_panic(expected = "the advertised length widens both envelope blocks")]
    fn widened_envelope_fixture_refuses_a_non_widening_length() {
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: ROXYD,
        }]);
        let package = signed_fixture(&manifest_json(&[("bin/roxyd", ROXYD)]), &archive);

        let _ = widen_envelope_blocks(&package, 1);
    }

    #[test]
    #[should_panic(expected = "the widened envelope fits the container format")]
    fn widened_envelope_fixture_refuses_an_unrepresentable_extent() {
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: ROXYD,
        }]);
        let package = signed_fixture(&manifest_json(&[("bin/roxyd", ROXYD)]), &archive);
        let signature_len =
            u64::try_from(ED25519_SIGNATURE_LEN).expect("the signature length fits u64");
        let key_id_len = u64::try_from(KEY_ID_HEX_LEN).expect("the key ID length fits u64");
        let prefix_len = u64::try_from(package.len() - FOOTER_SIZE)
            .expect("the signed fixture length fits u64")
            - signature_len
            - key_id_len;
        let advertised_len = (u64::MAX - prefix_len) / 2 + 1;

        let _ = widen_envelope_blocks(&package, advertised_len);
    }

    #[test]
    fn bounded_manifest_parse_does_not_touch_the_source() {
        let bytes = b"payload bytes";
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);
        let binary = signed_fixture(&manifest_json(&[("bin/roxyd", bytes)]), &archive);
        let read_count = Rc::new(Cell::new(0));
        let seek_count = Rc::new(Cell::new(0));
        let container = read_package_container(
            CountingSource {
                inner: Cursor::new(binary),
                read_count: Rc::clone(&read_count),
                seek_count: Rc::clone(&seek_count),
            },
            &ENVELOPE_BOUNDS,
        )
        .expect("the bounded reader accepts the fixture");
        let reads_before_parse = read_count.get();
        let seeks_before_parse = seek_count.get();

        container
            .parse_unverified_manifest()
            .expect("parsing retained manifest bytes succeeds without source I/O");

        assert_eq!(read_count.get(), reads_before_parse);
        assert_eq!(seek_count.get(), seeks_before_parse);
    }

    /// A `Read + Seek` source whose reads fail once the cursor sits inside
    /// `fail`, and succeed everywhere else.
    ///
    /// Reading a container is a sequence of seeks and reads, so *where* a read
    /// fails is what makes the reader's order of operations observable from
    /// outside.
    #[derive(Debug)]
    struct FailingSource {
        inner: Cursor<Vec<u8>>,
        fail: std::ops::Range<u64>,
    }

    impl FailingSource {
        fn new(bytes: Vec<u8>, fail: std::ops::Range<u64>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                fail,
            }
        }
    }

    impl Read for FailingSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.fail.contains(&self.inner.position()) {
                return Err(std::io::Error::other("read inside the failing region"));
            }
            self.inner.read(buf)
        }
    }

    impl Seek for FailingSource {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// A compact widened fixture presented as a sparse file whose envelope
    /// holes fail if a reader tries to read them.
    #[derive(Debug)]
    struct SparseEnvelopeSource {
        compact: Vec<u8>,
        prefix_len: u64,
        footer_start: u64,
        position: u64,
    }

    impl SparseEnvelopeSource {
        fn new(compact: Vec<u8>, advertised_len: u64) -> Self {
            let prefix_len =
                u64::try_from(compact.len() - FOOTER_SIZE).expect("fixture prefix length fits u64");
            let footer_start = prefix_len
                .checked_add(advertised_len)
                .and_then(|offset| offset.checked_add(advertised_len))
                .expect("fixture footer offset fits u64");
            Self {
                compact,
                prefix_len,
                footer_start,
                position: 0,
            }
        }

        fn len(&self) -> u64 {
            self.footer_start + u64::try_from(FOOTER_SIZE).expect("footer size fits u64")
        }
    }

    impl Read for SparseEnvelopeSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.position >= self.len() {
                return Ok(0);
            }
            if self.position >= self.prefix_len && self.position < self.footer_start {
                return Err(std::io::Error::other(
                    "read inside an unwritten envelope block",
                ));
            }

            let (bytes, start) = if self.position < self.prefix_len {
                (
                    self.compact
                        .get(..usize::try_from(self.prefix_len).expect("prefix fits usize"))
                        .expect("fixture compact prefix is present"),
                    0,
                )
            } else {
                (
                    self.compact
                        .get(usize::try_from(self.prefix_len).expect("prefix fits usize")..)
                        .expect("fixture footer is present"),
                    self.footer_start,
                )
            };
            let offset = usize::try_from(self.position - start).expect("fixture offset fits usize");
            let available = bytes
                .get(offset..)
                .expect("fixture read begins inside its available bytes");
            let count = available.len().min(buf.len());
            buf.get_mut(..count)
                .expect("the destination contains the chosen range")
                .copy_from_slice(
                    available
                        .get(..count)
                        .expect("the fixture source contains the chosen range"),
                );
            self.position += u64::try_from(count).expect("read count fits u64");
            Ok(count)
        }
    }

    impl Seek for SparseEnvelopeSource {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            let target = match pos {
                SeekFrom::Start(offset) => Some(offset),
                SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
                SeekFrom::End(offset) => self.len().checked_add_signed(offset),
            }
            .ok_or_else(|| std::io::Error::other("seek lies outside the fixture source"))?;
            self.position = target;
            Ok(target)
        }
    }

    /// The byte range the envelope blocks occupy in `binary`: everything
    /// between the end of the archive and the start of the footer.
    fn envelope_range(binary: &[u8]) -> std::ops::Range<u64> {
        let (footer, footer_start) = probe_footer(binary);
        let footer_start = u64::try_from(footer_start).expect("fixture offsets fit in u64");
        footer.archive_offset + footer.archive_len..footer_start
    }

    /// Builds `BASE ‖ manifest ‖ archive ‖ signature ‖ key_id ‖ footer` around
    /// `manifest_json`, whatever that block happens to contain.
    fn signed_fixture(manifest_json: &[u8], archive: &[u8]) -> Vec<u8> {
        let footer = valid_footer(BASE.len(), manifest_json, archive);
        let unsigned = assemble(BASE, manifest_json, archive, &footer);
        with_envelope(&unsigned, Some(SIGNATURE), Some(KEY_ID), 0)
    }

    #[test]
    fn open_reports_the_manifest_fault_before_it_reads_an_envelope_block() {
        // `open` parses the manifest as it reads it and only then reads the
        // envelope blocks. The verifier's container-read split must not move
        // that boundary: a container that is broken in both places has to keep
        // reporting the manifest fault, not the I/O one.
        let bytes = b"payload bytes";
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);

        let broken = signed_fixture(b"{ this is not valid json", &archive);
        let range = envelope_range(&broken);
        assert!(!range.is_empty(), "the fixture must carry envelope blocks");
        let error =
            open(FailingSource::new(broken, range)).expect_err("manifest parse failure expected");
        assert!(
            matches!(error, PayloadError::ManifestParse(_)),
            "got: {error:?}"
        );

        // The failure really is on `open`'s path rather than never reached: the
        // same injection over a manifest that parses surfaces as `Io`.
        let sound = signed_fixture(&manifest_json(&[("bin/roxyd", bytes)]), &archive);
        let range = envelope_range(&sound);
        let error =
            open(FailingSource::new(sound, range)).expect_err("the envelope read must fail");
        assert!(matches!(error, PayloadError::Io(_)), "got: {error:?}");
    }

    #[test]
    fn unsafe_member_path_is_rejected() {
        let bytes = b"evil";
        // The manifest itself is valid (a safe path); the archive smuggles in a
        // member with an unsafe path. Extraction must reject the member on its
        // path, before it can be joined onto the extraction root.
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::RawFile {
            path: "../escape",
            bytes,
        }]);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsafeMemberPath(_)),
            "got: {error:?}"
        );
        assert!(!dir.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn a_dot_prefixed_alias_of_a_manifest_listed_path_is_an_unsafe_member_path() {
        // `./bin/roxyd` resolves to the same file as the manifest-listed
        // `bin/roxyd` for a reader that normalizes, and to a second member for
        // one that does not. The name is not overridden — the raw header says
        // exactly what the reader resolved — so this is a path defect, and the
        // normalization rule is what catches it.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[
            Member::File {
                path: "bin/roxyd",
                bytes,
            },
            Member::RawFile {
                path: "./bin/roxyd",
                bytes: b"attacker bytes",
            },
        ]);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsafeMemberPath(ref path) if path == "./bin/roxyd"),
            "got: {error:?}"
        );
        // The earlier, individually valid member is not left behind either.
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn a_gnu_long_name_entry_overriding_the_header_name_is_rejected() {
        // The `L` entry renames a member the raw header calls `harmless.txt` to
        // the manifest-listed `bin/roxyd`, and the `tar` reader applies it
        // transparently — so the resolved name alone looks perfectly ordinary.
        // Only the raw header field disagrees, and that disagreement is the
        // defect.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::GnuLongName {
            header_path: "harmless.txt",
            resolved_path: "bin/roxyd",
            bytes,
        }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(
                error,
                PayloadError::NameOverridingHeader {
                    ref header_name,
                    ref resolved_name,
                } if header_name == "harmless.txt" && resolved_name == "bin/roxyd"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_pax_path_record_overriding_the_header_name_is_rejected() {
        // The same provenance defect through the other extension mechanism.
        // The resolved name is a safe, manifest-listed relative path and the
        // entry is an ordinary regular file whose bytes even match the manifest
        // hash, so neither `UnsafeMemberPath` nor `UnsupportedEntryType` would
        // be true of it and a silent pass is exactly the hole.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::PaxPath {
            header_path: "harmless.txt",
            resolved_path: "bin/roxyd",
            bytes,
        }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(
                error,
                PayloadError::NameOverridingHeader {
                    ref header_name,
                    ref resolved_name,
                } if header_name == "harmless.txt" && resolved_name == "bin/roxyd"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_pax_size_record_overriding_the_header_size_is_rejected() {
        // The name is not overridden and the member's bytes hash to exactly
        // what the manifest records, so every other check passes. What the
        // `size` record moves is where the member ends: this reader attributes
        // the whole smuggled stream to `bin/roxyd`, while a reader that ignores
        // PAX reads the raw header's `0`, resynchronizes at the next block, and
        // finds a second `bin/roxyd` carrying attacker bytes waiting there.
        let smuggled = tar_bytes(&[Member::File {
            path: "bin/roxyd",
            bytes: b"attacker bytes",
        }]);
        let json = manifest_json(&[("bin/roxyd", &smuggled)]);
        let archive = zstd_tar(&[Member::PaxSize {
            path: "bin/roxyd",
            header_size: 0,
            bytes: &smuggled,
        }]);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(
                error,
                PayloadError::SizeOverridingHeader {
                    ref path,
                    header_size: 0,
                    resolved_size,
                } if path == "bin/roxyd" && resolved_size == smuggled.len() as u64
            ),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn bytes_after_the_end_of_archive_marker_are_rejected() {
        // A second archive hides past the marker: this reader stops there and
        // would never see it, while a reader that keeps going finds a member
        // the manifest never named.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let smuggled = tar_bytes(&[Member::File {
            path: "bin/stowaway",
            bytes: b"attacker bytes",
        }]);
        let archive = zstd_tar_with_trailing(
            &[Member::File {
                path: "bin/roxyd",
                bytes,
            }],
            &smuggled,
        );

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::TrailingArchiveBytes),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
        assert!(!dir.path().join("bin/stowaway").exists());
    }

    #[test]
    fn the_end_of_archive_marker_alone_still_extracts() {
        // One edge of the drain's allowance. `tar`'s reader consumes the first
        // of the marker's two zero blocks before reporting the end, so a
        // well-formed archive leaves exactly one block unread and that block
        // must not be mistaken for trailing content.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar_with_trailing(
            &[Member::File {
                path: "bin/roxyd",
                bytes,
            }],
            &[],
        );
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload.extract_to(dir.path()).expect("extraction succeeds");
        assert_eq!(extracted.len(), 1);
        assert_eq!(
            std::fs::read(dir.path().join("bin/roxyd")).expect("read extracted"),
            bytes
        );
    }

    #[test]
    fn a_single_zero_byte_past_the_end_of_archive_marker_is_rejected() {
        // The other edge, one byte away from the test above. The allowance
        // covers the marker's own unread block and nothing else, so the very
        // next byte is trailing content even though it names no member and no
        // reader could resynchronize inside it.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar_with_trailing(
            &[Member::File {
                path: "bin/roxyd",
                bytes,
            }],
            &[0u8],
        );

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::TrailingArchiveBytes),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn a_rejection_on_the_last_member_leaves_no_earlier_member_on_disk() {
        // The first member is individually valid and hashes correctly; the
        // second is a symlink. Extraction is all-or-nothing, so the first must
        // not survive the second's rejection.
        let roxyd = b"roxyd binary bytes";
        let web = b"static web assets";
        let json = manifest_json(&[("bin/roxyd", roxyd), ("assets/web.tar", web)]);
        let archive = zstd_tar(&[
            Member::File {
                path: "bin/roxyd",
                bytes: roxyd,
            },
            Member::Symlink {
                path: "assets/web.tar",
                target: "/etc/passwd",
            },
        ]);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
        assert!(!dir.path().join("bin").exists());
    }

    #[test]
    fn a_rejection_against_a_missing_destination_leaves_it_absent_or_empty() {
        // A destination that does not exist is still accepted and created, so
        // the call must fail with the rejection's own variant rather than with
        // a missing-destination I/O error — and leave nothing behind but, at
        // most, the empty directory itself.
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::Symlink {
            path: "bin/roxyd",
            target: "/etc/passwd",
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let parent = tempfile::tempdir().expect("tempdir");
        let dest = parent.path().join("missing/destination");
        assert!(!dest.exists());

        let error = payload
            .extract_to(&dest)
            .expect_err("extraction should be rejected");
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
        assert!(
            walk(&dest).is_empty(),
            "a rejection may leave the destination absent or empty, nothing more: {:?}",
            walk(&dest)
        );
    }

    #[test]
    fn manifest_artifact_missing_from_archive_is_rejected() {
        let present = b"present bytes";
        // The manifest promises two artifacts, but the archive carries only one.
        // The absent one is neither extracted nor hash-verified, so extraction
        // must fail rather than silently return the shorter set.
        let json = manifest_json(&[("bin/roxyd", present), ("bin/missing", b"absent bytes")]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: present,
        }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::ArtifactMissingFromArchive(ref path) if path == "bin/missing"),
            "got: {error:?}"
        );
    }

    #[test]
    fn absolute_member_path_is_rejected() {
        let bytes = b"evil";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::RawFile {
            path: "/etc/evil",
            bytes,
        }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsafeMemberPath(ref path) if path == "/etc/evil"),
            "got: {error:?}"
        );
    }

    #[test]
    fn symlink_member_is_rejected() {
        let json = manifest_json(&[("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::Symlink {
            path: "bin/roxyd",
            target: "/etc/passwd",
        }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn hardlink_member_is_rejected() {
        let json = manifest_json(&[("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::Hardlink {
            path: "bin/roxyd",
            target: "bin/other",
        }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn char_device_member_is_rejected() {
        let json = manifest_json(&[("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::CharDevice { path: "bin/roxyd" }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn directory_member_is_rejected_as_non_regular() {
        let json = manifest_json(&[("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::Directory { path: "bin/" }]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn member_absent_from_manifest_is_rejected() {
        let json = manifest_json(&[("bin/roxyd", b"bytes")]);
        // Archive holds a different, safe, regular file not named in the manifest.
        let archive = zstd_tar(&[Member::File {
            path: "bin/stowaway",
            bytes: b"unexpected",
        }]);

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::MemberNotInManifest(_)),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/stowaway").exists());
    }

    #[test]
    fn duplicate_archive_member_is_rejected() {
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        // Two regular members share one `archive_path`; both even match the
        // manifest hash. A single manifest artifact must map to one member, so
        // the second occurrence is rejected rather than extracted twice.
        let archive = zstd_tar(&[
            Member::File {
                path: "bin/roxyd",
                bytes,
            },
            Member::File {
                path: "bin/roxyd",
                bytes,
            },
        ]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::DuplicateMember(ref path) if path == "bin/roxyd"),
            "got: {error:?}"
        );
    }

    /// The two-member payload the member-list cases are built from, written by
    /// this crate's own writer with nothing supplied by a caller.
    fn two_member_binary(dir: &Path) -> Vec<u8> {
        let inputs = vec![
            input(
                dir,
                "roxyd.src",
                "bin/roxyd",
                ROXYD,
                &[Disposition::Install],
            ),
            input(
                dir,
                "web.src",
                "assets/web.tar",
                WEB,
                &[Disposition::Install],
            ),
        ];
        build_binary(&inputs)
    }

    /// Bytes of the first member of [`two_member_binary`].
    const ROXYD: &[u8] = b"roxyd binary bytes";

    /// Bytes of its second member, of a different length.
    const WEB: &[u8] = b"static web assets, of another length entirely";

    #[test]
    fn a_written_payload_binds_the_member_list_its_own_archive_presents() {
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());

        // The manifest block, read as a generic document, pins the on-disk
        // shape rather than only the round trip: an array of `{name, length}`
        // objects in archive order, each length the member's uncompressed byte
        // length.
        let (_, block, _) = trailer_parts(&binary);
        let document: serde_json::Value =
            serde_json::from_slice(block).expect("the manifest block decodes");
        assert_eq!(
            document.get("archive_members"),
            Some(&serde_json::json!([
                {"name": "bin/roxyd", "length": ROXYD.len()},
                {"name": "assets/web.tar", "length": WEB.len()},
            ]))
        );

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer should be present");
        assert_eq!(
            payload.manifest().archive_members(),
            Some(members_of(&[("bin/roxyd", ROXYD), ("assets/web.tar", WEB)]).as_slice())
        );

        // And the walk agrees with it, on bytes this crate's writer produced.
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn a_member_name_disagreeing_with_the_bound_list_is_a_mismatch() {
        // Only the bound name is touched; the archive is the one the writer
        // produced, and its member is still named by the manifest's artifacts,
        // so every per-member check passes.
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = mutating_bound_members(&two_member_binary(src.path()), |members| {
            let first = members.first_mut().expect("two bound members");
            *first
                .get_mut("name")
                .expect("a bound member carries a name") = serde_json::json!("bin/other");
        });
        let (_, json, archive) = trailer_parts(&binary);
        let (json, archive) = (json.to_vec(), archive.to_vec());

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(
                error,
                PayloadError::MemberListMismatch {
                    index: 0,
                    expected: Some(ref expected),
                    found: Some(ref found),
                } if expected.name == "bin/other" && found.name == "bin/roxyd"
            ),
            "got: {error:?}"
        );
        // The rendered message carries the position and both sides, so it is
        // actionable without the list.
        let message = error.to_string();
        assert!(message.contains("position 0"), "got: {message}");
        assert!(message.contains("bin/other"), "got: {message}");
        assert!(message.contains("bin/roxyd"), "got: {message}");
    }

    #[test]
    fn a_permuted_archive_is_a_mismatch() {
        // The case nothing else in the crate catches: every member is a regular
        // file at a safe, manifest-listed path, hashes correctly, appears once,
        // and every artifact is seen. Only the order differs.
        let entries: [(&str, &[u8]); 2] = [("bin/roxyd", ROXYD), ("assets/web.tar", WEB)];
        let json = manifest_json(&entries);
        let archive = zstd_tar(&[
            Member::File {
                path: "assets/web.tar",
                bytes: WEB,
            },
            Member::File {
                path: "bin/roxyd",
                bytes: ROXYD,
            },
        ]);

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(
                error,
                PayloadError::MemberListMismatch {
                    index: 0,
                    expected: Some(ref expected),
                    found: Some(ref found),
                } if expected.name == "bin/roxyd" && found.name == "assets/web.tar"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_member_count_disagreeing_with_the_bound_list_is_a_mismatch() {
        let entries: [(&str, &[u8]); 2] = [("bin/roxyd", ROXYD), ("assets/web.tar", WEB)];
        let both = zstd_tar(&[
            Member::File {
                path: "bin/roxyd",
                bytes: ROXYD,
            },
            Member::File {
                path: "assets/web.tar",
                bytes: WEB,
            },
        ]);

        // One member too many for the bound list. Both members are named by the
        // manifest's artifacts, so nothing refuses either one individually.
        let short = manifest_json_binding(&members_of(&entries[..1]), &entries);
        let (error, _dir) = extract_error_leaving_dest_unchanged(&short, &both);
        assert!(
            matches!(
                error,
                PayloadError::MemberListMismatch {
                    index: 1,
                    expected: None,
                    found: Some(ref found),
                } if found.name == "assets/web.tar"
            ),
            "got: {error:?}"
        );

        // One member too few: the bound list names a second member the manifest
        // declares no artifact for, so the every-artifact-was-seen loop has
        // nothing to say about it either.
        let long = manifest_json_binding(&members_of(&entries), &entries[..1]);
        let only_first = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: ROXYD,
        }]);
        let (error, _dir) = extract_error_leaving_dest_unchanged(&long, &only_first);
        assert!(
            matches!(
                error,
                PayloadError::MemberListMismatch {
                    index: 1,
                    expected: Some(ref expected),
                    found: None,
                } if expected.name == "assets/web.tar"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_single_recorded_length_disagreeing_is_a_mismatch() {
        // The archive is exactly what the writer produced; one recorded length
        // is off by one byte.
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = mutating_bound_members(&two_member_binary(src.path()), |members| {
            let second = members.get_mut(1).expect("two bound members");
            let length = second
                .get_mut("length")
                .expect("a bound member carries a length");
            *length = serde_json::json!(WEB.len() + 1);
        });
        let (_, json, archive) = trailer_parts(&binary);
        let (json, archive) = (json.to_vec(), archive.to_vec());

        let (error, _dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        let expected_len = WEB.len() as u64;
        assert!(
            matches!(
                error,
                PayloadError::MemberListMismatch {
                    index: 1,
                    expected: Some(ref expected),
                    found: Some(ref found),
                } if expected.length == expected_len + 1 && found.length == expected_len
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_mismatch_on_the_last_member_leaves_the_destination_unchanged() {
        // The first member is individually valid, hashes correctly and agrees
        // with the bound list; the disagreement is only reachable once the
        // whole archive has been walked. Deciding it before the publish loop is
        // what keeps `dest` in the state every other rejection leaves it in.
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = mutating_bound_members(&two_member_binary(src.path()), |members| {
            let second = members.get_mut(1).expect("two bound members");
            *second
                .get_mut("name")
                .expect("a bound member carries a name") = serde_json::json!("assets/other.tar");
        });
        let (_, json, archive) = trailer_parts(&binary);
        let (json, archive) = (json.to_vec(), archive.to_vec());

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(error, PayloadError::MemberListMismatch { index: 1, .. }),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
        assert!(!dir.path().join("bin").exists());
        assert!(!dir.path().join("assets").exists());
    }

    #[test]
    fn a_header_length_the_stream_does_not_deliver_never_passes_silently() {
        // The raw `ustar` header claims a whole block of data and the stream
        // stops after 18 bytes, so the header's size and the bytes the reader
        // consumes disagree while nothing overrides anything: `entry.size()`
        // and the header field are the same number, and the manifest binds it.
        // A comparison that trusted that number would pass this; one made from
        // the bytes actually consumed cannot. Which layer says so is not the
        // point: the `tar` reader refuses to resynchronize on a stream that
        // ends inside a member, and if it ever stopped doing that the byte
        // count would be the disagreement the comparison reports.
        let declared = TAR_BLOCK_SIZE as u64;
        let header = raw_regular_header("bin/roxyd", declared);
        let mut stream = header.as_bytes().to_vec();
        stream.extend_from_slice(ROXYD);
        let archive = zstd_compress(&stream);
        let json = manifest_json_binding(
            &[ArchiveMember {
                name: "bin/roxyd".to_string(),
                length: declared,
            }],
            &[("bin/roxyd", ROXYD)],
        );

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
        assert!(
            matches!(
                error,
                PayloadError::MemberListMismatch { .. } | PayloadError::Io(_)
            ),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/roxyd").exists());
    }

    #[test]
    fn a_versioned_manifest_binding_no_member_list_is_refused_by_both_doors() {
        // Through the container read path, where it rides the existing
        // `InvalidManifest` channel and needs no payload-layer variant of its
        // own...
        let json =
            String::from_utf8(manifest_json(&[("bin/roxyd", ROXYD)])).expect("fixture is utf-8");
        let start = json
            .find(r#""archive_members""#)
            .expect("the key is written");
        let end = json
            .find(r#""artifacts""#)
            .expect("the artifacts follow it");
        let stripped = format!("{}{}", &json[..start], &json[end..]).into_bytes();
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: ROXYD,
        }]);
        let footer = valid_footer(BASE.len(), &stripped, &archive);
        let binary = assemble(BASE, &stripped, &archive, &footer);

        let error =
            open(Cursor::new(binary)).expect_err("a versioned manifest must bind a member list");
        assert!(
            matches!(
                error,
                PayloadError::InvalidManifest(ManifestError::MissingArchiveMembers)
            ),
            "got: {error:?}"
        );

        // ...and through plain deserialization of the same manifest block, so
        // neither door is laxer than the other.
        let error = serde_json::from_slice::<PayloadManifest>(&stripped)
            .expect_err("the serde door must be no laxer");
        assert!(
            error.to_string().contains("archive_members"),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_rewrapped_container_copies_the_manifest_block_verbatim() {
        // A graft leaves the archive block untouched, so the member list needs
        // no recomputation: the rewrapped manifest block must be byte-identical
        // to its source's, and the rewrapped container must still read back
        // through the member-list check.
        let src = tempfile::tempdir().expect("source tempdir");
        let asset = two_member_binary(src.path());
        let new_base: &[u8] = b"a freshly built base binary, of a different length entirely";
        assert_ne!(new_base.len(), BASE.len());

        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(&asset), Cursor::new(new_base), &mut rewrapped)
            .expect("rewrap should succeed");
        let (_, source_block, _) = trailer_parts(&asset);
        let (_, rewrapped_block, _) = trailer_parts(&rewrapped);
        assert_eq!(source_block, rewrapped_block);

        let mut payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped container must open")
            .expect("trailer should be present");
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("the rewrapped container reads back with no mismatch");
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn footer_round_trips_through_encode_and_parse() {
        let footer = Footer {
            version: FORMAT_VERSION,
            manifest_offset: 10,
            manifest_len: 20,
            archive_offset: 30,
            archive_len: 40,
            signature_offset: 70,
            signature_len: 5,
            key_id_offset: 75,
            key_id_len: 3,
        };
        let encoded = footer.encode();
        assert_eq!(encoded.len(), FOOTER_SIZE);
        assert_eq!(FOOTER_SIZE, 73);
        assert!(encoded.starts_with(&MAGIC));

        let Candidate::Selected(parsed) = classify_candidate(
            &encoded,
            KNOWN_FOOTER_SIZES
                .get(1)
                .expect("the current version is the second probe entry"),
        ) else {
            panic!("a freshly encoded footer must be selected at its own size");
        };
        assert_eq!(parsed.version, FORMAT_VERSION);
        assert_eq!(parsed.manifest_offset, 10);
        assert_eq!(parsed.manifest_len, 20);
        assert_eq!(parsed.archive_offset, 30);
        assert_eq!(parsed.archive_len, 40);
        assert_eq!(parsed.signature_offset, 70);
        assert_eq!(parsed.signature_len, 5);
        assert_eq!(parsed.key_id_offset, 75);
        assert_eq!(parsed.key_id_len, 3);
    }

    #[test]
    fn a_version_1_footer_encodes_at_its_own_size_with_no_envelope_pairs() {
        // The size is a function of the footer's own version, which is what
        // lets `rewrap_trailer` write a version-1 payload back at version 1.
        let footer = Footer {
            version: 1,
            manifest_offset: 10,
            manifest_len: 20,
            archive_offset: 30,
            archive_len: 40,
            signature_offset: 0,
            signature_len: 0,
            key_id_offset: 0,
            key_id_len: 0,
        };
        let encoded = footer.encode();
        assert_eq!(encoded.len(), FOOTER_SIZE_V1);
        assert_eq!(FOOTER_SIZE_V1, 41);

        let Candidate::Selected(parsed) = classify_candidate(
            &encoded,
            KNOWN_FOOTER_SIZES
                .first()
                .expect("version 1 is the first probe entry"),
        ) else {
            panic!("a version-1 footer must be selected at the 41-byte size");
        };
        assert_eq!(parsed.version, 1);
        // A pre-envelope footer records neither pair, and both read as absent.
        assert_eq!(parsed.signature_offset, 0);
        assert_eq!(parsed.signature_len, 0);
        assert_eq!(parsed.key_id_offset, 0);
        assert_eq!(parsed.key_id_len, 0);
    }

    #[test]
    fn the_probe_list_is_ascending_and_pairs_each_size_with_one_version() {
        let sizes: Vec<usize> = KNOWN_FOOTER_SIZES.iter().map(|size| size.bytes).collect();
        let versions: Vec<u8> = KNOWN_FOOTER_SIZES.iter().map(|size| size.version).collect();
        assert_eq!(sizes, vec![FOOTER_SIZE_V1, FOOTER_SIZE_V2]);
        assert_eq!(sizes, vec![41, 73]);
        assert_eq!(versions, vec![1, 2]);
        assert!(
            sizes.windows(2).all(|pair| pair[0] < pair[1]),
            "the probe walks ascending size order"
        );
        assert_eq!(FORMAT_VERSION, 2);
        assert_eq!(FOOTER_SIZE, FOOTER_SIZE_V2);
    }

    /// Writes a `.pkg` module package: the same container with no base
    /// executable, so its manifest block starts at offset `0`.
    fn build_package(inputs: &[ArtifactInput]) -> Vec<u8> {
        let mut pkg = Vec::new();
        append_trailer(std::io::empty(), &mut pkg, None, None, inputs)
            .expect("writer should succeed");
        pkg
    }

    /// The two-member `.pkg` the package tests read.
    fn two_member_package(dir: &Path) -> Vec<u8> {
        let inputs = vec![
            input(
                dir,
                "roxyd.src",
                "bin/roxyd",
                ROXYD,
                &[Disposition::Install],
            ),
            input(
                dir,
                "web.src",
                "assets/web.tar",
                WEB,
                &[Disposition::Install],
            ),
        ];
        build_package(&inputs)
    }

    /// Rebuilds `binary` with `footer` in place of its own, leaving every byte
    /// before the footer exactly as it was.
    fn with_footer(binary: &[u8], footer: &Footer) -> Vec<u8> {
        let (_, footer_start) = probe_footer(binary);
        let mut out = binary
            .get(..footer_start)
            .expect("trailer body in range")
            .to_vec();
        out.extend_from_slice(&footer.encode());
        out
    }

    /// One footer-mutation case: what it breaks, and the mutation that breaks
    /// it.
    type FooterCase = (&'static str, fn(&mut Footer));

    /// One malformed signer return and the error it must produce.
    type SignedValidationCase = (&'static str, Signed, fn(&PayloadError) -> bool);

    /// A stand-in signature block. Opaque at this layer, which reports what is
    /// there and leaves what it is worth to a verifier.
    const SIGNATURE: &[u8] = b"an opaque detached signature, meaningless to this layer";

    /// A stand-in `key_id` block, of another length.
    const KEY_ID: &[u8] = b"key-2026-08";

    /// Rebuilds `binary` with independently present or absent envelope blocks
    /// and `slack` bytes before the footer that the footer accounts for
    /// nowhere.
    ///
    /// A present block is appended after the archive in the fixed order and
    /// recorded at the offset the previous *present* block ended at; an absent
    /// one occupies no bytes and keeps the all-zero pair, so the layout is the
    /// one the reader's adjacency walk expects.
    fn with_envelope(
        binary: &[u8],
        signature: Option<&[u8]>,
        key_id: Option<&[u8]>,
        slack: usize,
    ) -> Vec<u8> {
        let (base, manifest_block, archive) = trailer_parts(binary);
        let mut footer = valid_footer(base.len(), manifest_block, archive);
        let mut cursor = footer.archive_offset + footer.archive_len;
        if let Some(bytes) = signature {
            footer.signature_offset = cursor;
            footer.signature_len = bytes.len() as u64;
            cursor += footer.signature_len;
        }
        if let Some(bytes) = key_id {
            footer.key_id_offset = cursor;
            footer.key_id_len = bytes.len() as u64;
        }

        let mut out = Vec::new();
        out.extend_from_slice(base);
        out.extend_from_slice(manifest_block);
        out.extend_from_slice(archive);
        out.extend_from_slice(signature.unwrap_or_default());
        out.extend_from_slice(key_id.unwrap_or_default());
        out.extend(std::iter::repeat_n(0u8, slack));
        out.extend_from_slice(&footer.encode());
        out
    }

    /// Rebuilds `binary` with `mutate` applied to its footer.
    fn mutating_footer(binary: &[u8], mutate: impl FnOnce(&mut Footer)) -> Vec<u8> {
        let (mut footer, _) = probe_footer(binary);
        mutate(&mut footer);
        with_footer(binary, &footer)
    }

    #[test]
    fn a_package_round_trips_through_open_package_and_open_package_path() {
        let src = tempfile::tempdir().expect("source tempdir");
        let pkg = two_member_package(src.path());

        // A `.pkg` has no base, so its manifest block legitimately starts at
        // offset `0` — a zero offset that is never read as absence.
        let (footer, _) = probe_footer(&pkg);
        assert_eq!(footer.manifest_offset, 0);
        assert_eq!(footer.version, FORMAT_VERSION);

        let mut package = open_package(Cursor::new(&pkg)).expect("the package must open");
        assert_eq!(package.manifest().artifacts().len(), 2);
        assert_eq!(package.signature(), None);
        assert_eq!(package.key_id(), None);
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = package
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 2);
        assert_eq!(std::fs::read(dir.path().join("bin/roxyd")).unwrap(), ROXYD);
        assert_eq!(
            std::fs::read(dir.path().join("assets/web.tar")).unwrap(),
            WEB
        );

        // And through the path entry point, which opens the file and delegates.
        let on_disk = src.path().join("module.pkg");
        std::fs::write(&on_disk, &pkg).expect("write the package");
        let mut from_path = open_package_path(&on_disk).expect("the package must open by path");
        assert_eq!(from_path.manifest().artifacts().len(), 2);
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            from_path
                .extract_to(dir.path())
                .expect("extraction should succeed")
                .len(),
            2
        );
        assert_eq!(std::fs::read(dir.path().join("bin/roxyd")).unwrap(), ROXYD);
    }

    #[test]
    fn a_written_container_records_both_envelope_pairs_absent() {
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());

        // On the wire: the four fields after the archive pair are all zero.
        let (footer, footer_start) = probe_footer(&binary);
        assert_eq!(binary.len() - footer_start, FOOTER_SIZE_V2);
        assert_eq!(
            binary
                .get(footer_start + MAGIC_LEN + 1 + 4 * 8..)
                .expect("the envelope fields are in range"),
            [0u8; 32].as_slice(),
        );
        assert_eq!(footer.signature_offset, 0);
        assert_eq!(footer.signature_len, 0);
        assert_eq!(footer.key_id_offset, 0);
        assert_eq!(footer.key_id_len, 0);

        // The archive block is the last present block, so it ends exactly where
        // the footer begins.
        assert_eq!(
            footer.archive_offset + footer.archive_len,
            footer_start as u64
        );

        // And the reader accepts it, reporting each pair as absent rather than
        // as an empty block.
        let payload = open(Cursor::new(binary))
            .expect("the container must open")
            .expect("trailer should be present");
        assert_eq!(payload.signature(), None);
        assert_eq!(payload.key_id(), None);
    }

    #[test]
    fn unsigned_writer_matches_pre_signing_block_fixtures() {
        const EXPECTED_FOOTER_VERSION: u8 = 2;
        const EXPECTED_MANIFEST: &[u8] =
            include_bytes!("../assets/test-fixtures/unsigned-container/manifest.json");
        const EXPECTED_ARCHIVE: &[u8] =
            include_bytes!("../assets/test-fixtures/unsigned-container/archive.tar");

        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = [input(
            src.path(),
            "app.src",
            "bin/app",
            b"application bytes",
            &[Disposition::Install],
        )];
        let mut container = Vec::new();
        append_trailer(Cursor::new(BASE), &mut container, None, None, &inputs)
            .expect("the unsigned writer should succeed");

        let (footer, footer_start) = probe_footer(&container);
        let manifest_offset = u64::try_from(BASE.len()).expect("base length fits in u64");
        let manifest_len =
            u64::try_from(EXPECTED_MANIFEST.len()).expect("fixture manifest length fits in u64");
        assert_eq!(footer.version, EXPECTED_FOOTER_VERSION);
        assert_eq!(footer.manifest_offset, manifest_offset);
        assert_eq!(footer.manifest_len, manifest_len);
        assert_eq!(footer.archive_offset, manifest_offset + manifest_len);
        assert_eq!(footer.signature_offset, 0);
        assert_eq!(footer.signature_len, 0);
        assert_eq!(footer.key_id_offset, 0);
        assert_eq!(footer.key_id_len, 0);
        assert_eq!(
            footer.archive_offset + footer.archive_len,
            u64::try_from(footer_start).expect("footer offset fits in u64")
        );

        let manifest_start =
            usize::try_from(footer.manifest_offset).expect("fixture manifest offset fits in usize");
        let manifest_end = manifest_start
            + usize::try_from(footer.manifest_len).expect("fixture manifest length fits in usize");
        let archive_start =
            usize::try_from(footer.archive_offset).expect("fixture archive offset fits in usize");
        let archive_end = archive_start
            + usize::try_from(footer.archive_len).expect("fixture archive length fits in usize");
        assert_eq!(
            container.get(..manifest_start).expect("base is in range"),
            BASE
        );
        assert_eq!(
            container
                .get(manifest_start..manifest_end)
                .expect("manifest block is in range"),
            EXPECTED_MANIFEST,
            "manifest block differs from the pre-signing fixture"
        );

        let mut archive = Vec::new();
        Decoder::new(Cursor::new(
            container
                .get(archive_start..archive_end)
                .expect("archive block is in range"),
        ))
        .expect("archive block must decode")
        .read_to_end(&mut archive)
        .expect("archive block must read");
        assert_eq!(
            archive, EXPECTED_ARCHIVE,
            "decoded archive block differs from the pre-signing fixture"
        );
    }

    #[test]
    fn a_signed_writer_stamps_the_callback_manifest_and_envelope() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = [input(
            src.path(),
            "app.src",
            "bin/app",
            b"application bytes",
            &[Disposition::Install],
        )];
        let captured = std::cell::RefCell::new(None);
        let mut package = Vec::new();
        append_trailer_signed(
            std::io::empty(),
            &mut package,
            None,
            None,
            &inputs,
            |manifest| {
                *captured.borrow_mut() = Some(manifest.to_vec());
                Ok(Signed {
                    signature: vec![0x5a; ED25519_SIGNATURE_LEN],
                    key_id: "a".repeat(KEY_ID_HEX_LEN),
                })
            },
        )
        .expect("the signed writer should succeed");

        let (footer, footer_start) = probe_footer(&package);
        let manifest_end = footer.manifest_offset + footer.manifest_len;
        let manifest_start =
            usize::try_from(footer.manifest_offset).expect("a fixture offset fits usize");
        let manifest_end = usize::try_from(manifest_end).expect("a fixture offset fits usize");
        let manifest = package
            .get(manifest_start..manifest_end)
            .expect("the manifest range is in the package");
        assert_eq!(captured.into_inner(), Some(manifest.to_vec()));
        assert_eq!(footer.manifest_offset, 0);
        assert_eq!(
            footer.signature_offset,
            footer.archive_offset + footer.archive_len
        );
        assert_eq!(
            footer.signature_len,
            u64::try_from(ED25519_SIGNATURE_LEN).expect("fixed signature length fits u64")
        );
        assert_eq!(
            footer.key_id_offset,
            footer.signature_offset + footer.signature_len
        );
        assert_eq!(
            footer.key_id_len,
            u64::try_from(KEY_ID_HEX_LEN).expect("fixed key_id length fits u64")
        );
        assert_eq!(
            footer.key_id_offset + footer.key_id_len,
            footer_start as u64
        );

        let package = open_package(Cursor::new(package)).expect("the package must open");
        assert_eq!(
            package.signature(),
            Some([0x5a; ED25519_SIGNATURE_LEN].as_slice())
        );
        assert_eq!(
            package.key_id(),
            Some("a".repeat(KEY_ID_HEX_LEN).as_bytes())
        );
    }

    #[test]
    fn a_signed_writer_rewraps_with_corrected_envelope_offsets() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = [input(
            src.path(),
            "app.src",
            "bin/app",
            b"application bytes",
            &[Disposition::Install],
        )];
        let mut signed = Vec::new();
        append_trailer_signed(Cursor::new(BASE), &mut signed, None, None, &inputs, |_| {
            Ok(Signed {
                signature: vec![0x5a; ED25519_SIGNATURE_LEN],
                key_id: "a".repeat(KEY_ID_HEX_LEN),
            })
        })
        .expect("the signed writer should succeed");
        let (source_footer, _) = probe_footer(&signed);

        let new_base = b"a replacement executable base of a distinct length";
        assert_ne!(new_base.len(), BASE.len());
        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(signed), Cursor::new(new_base), &mut rewrapped)
            .expect("the signed container should rewrap");

        let (footer, footer_start) = probe_footer(&rewrapped);
        let shifted = |offset: u64| {
            offset - source_footer.manifest_offset
                + u64::try_from(new_base.len()).expect("fixture base length fits u64")
        };
        assert_eq!(
            footer.manifest_offset,
            shifted(source_footer.manifest_offset)
        );
        assert_eq!(footer.archive_offset, shifted(source_footer.archive_offset));
        assert_eq!(
            footer.signature_offset,
            shifted(source_footer.signature_offset)
        );
        assert_eq!(footer.key_id_offset, shifted(source_footer.key_id_offset));
        assert_eq!(
            footer.signature_len,
            u64::try_from(ED25519_SIGNATURE_LEN).expect("fixed signature length fits u64")
        );
        assert_eq!(
            footer.key_id_len,
            u64::try_from(KEY_ID_HEX_LEN).expect("fixed key_id length fits u64")
        );
        assert_eq!(
            footer.key_id_offset + footer.key_id_len,
            u64::try_from(footer_start).expect("fixture offset fits u64")
        );

        let payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped container must open")
            .expect("trailer should be present");
        assert_eq!(
            payload.signature(),
            Some([0x5a; ED25519_SIGNATURE_LEN].as_slice())
        );
        assert_eq!(
            payload.key_id(),
            Some("a".repeat(KEY_ID_HEX_LEN).as_bytes())
        );
    }

    #[test]
    fn a_signed_writer_rejects_invalid_envelope_values_before_writing() {
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = [input(
            src.path(),
            "app.src",
            "bin/app",
            b"application bytes",
            &[Disposition::Install],
        )];
        let cases: [SignedValidationCase; 5] = [
            (
                "short signature",
                Signed {
                    signature: vec![0; ED25519_SIGNATURE_LEN - 1],
                    key_id: "a".repeat(KEY_ID_HEX_LEN),
                },
                |error| {
                    matches!(
                        error,
                        PayloadError::InvalidSignatureLength { found }
                            if *found == ED25519_SIGNATURE_LEN - 1
                    )
                },
            ),
            (
                "short key_id",
                Signed {
                    signature: vec![0; ED25519_SIGNATURE_LEN],
                    key_id: "a".repeat(KEY_ID_HEX_LEN - 1),
                },
                |error| {
                    matches!(
                        error,
                        PayloadError::InvalidKeyId { reason }
                            if *reason == "must be exactly 64 lowercase-hex ASCII characters"
                    )
                },
            ),
            (
                "uppercase key_id",
                Signed {
                    signature: vec![0; ED25519_SIGNATURE_LEN],
                    key_id: "A".repeat(KEY_ID_HEX_LEN),
                },
                |error| {
                    matches!(
                        error,
                        PayloadError::InvalidKeyId { reason }
                            if *reason == "must contain only lowercase hexadecimal ASCII characters"
                    )
                },
            ),
            (
                "non-hex key_id",
                Signed {
                    signature: vec![0; ED25519_SIGNATURE_LEN],
                    key_id: "g".repeat(KEY_ID_HEX_LEN),
                },
                |error| {
                    matches!(
                        error,
                        PayloadError::InvalidKeyId { reason }
                            if *reason == "must contain only lowercase hexadecimal ASCII characters"
                    )
                },
            ),
            (
                "non-ASCII key_id at the required byte length",
                Signed {
                    signature: vec![0; ED25519_SIGNATURE_LEN],
                    key_id: "é".repeat(KEY_ID_HEX_LEN / 2),
                },
                |error| {
                    matches!(
                        error,
                        PayloadError::InvalidKeyId { reason }
                            if *reason == "must contain only lowercase hexadecimal ASCII characters"
                    )
                },
            ),
        ];
        for (label, signed, expected_error) in cases {
            let mut out = Vec::new();
            let error =
                append_trailer_signed(std::io::empty(), &mut out, None, None, &inputs, |_| {
                    Ok(signed)
                })
                .expect_err("an invalid envelope must be rejected");
            assert!(
                expected_error(&error),
                "{label} returned the wrong error: {error:?}"
            );
            assert!(
                out.is_empty(),
                "{label} must fail before the writer's first byte"
            );
        }
    }

    #[test]
    fn a_signer_failure_keeps_output_empty_and_its_source_reachable() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<PayloadError>();
        let src = tempfile::tempdir().expect("source tempdir");
        let inputs = [input(
            src.path(),
            "app.src",
            "bin/app",
            b"application bytes",
            &[Disposition::Install],
        )];
        let mut out = Vec::new();
        let error = append_trailer_signed(std::io::empty(), &mut out, None, None, &inputs, |_| {
            Err(SignerError::new(std::io::Error::other(
                "signer unavailable",
            )))
        })
        .expect_err("the signer error must surface");
        assert!(matches!(&error, PayloadError::Signer(_)), "got: {error:?}");
        let source = std::error::Error::source(&error).expect("the signer is a source");
        let source = source.source().expect("the callback error is reachable");
        assert_eq!(source.to_string(), "signer unavailable");
        assert!(out.is_empty(), "the writer must fail before its first byte");
    }

    #[test]
    fn a_half_zero_envelope_pair_is_malformed() {
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());

        // A length with no offset, and an offset with no length, for each pair:
        // four ways to be neither present nor absent.
        let cases: [FooterCase; 4] = [
            ("signature length without an offset", |footer| {
                footer.signature_len = 7;
            }),
            ("signature offset without a length", |footer| {
                footer.signature_offset = 7;
            }),
            ("key_id length without an offset", |footer| {
                footer.key_id_len = 7;
            }),
            ("key_id offset without a length", |footer| {
                footer.key_id_offset = 7;
            }),
        ];
        for (label, mutate) in cases {
            let broken = mutating_footer(&binary, mutate);
            let error = open(Cursor::new(broken)).expect_err("a half-zero pair must be rejected");
            assert!(
                matches!(error, PayloadError::MalformedFooter { .. }),
                "{label} got: {error:?}"
            );
        }
    }

    #[test]
    fn a_gap_an_overlap_or_a_short_last_block_is_malformed() {
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());

        let cases: [FooterCase; 3] = [
            // The archive starts one byte past where the manifest ended.
            ("gap", |footer| {
                footer.archive_offset += 1;
                footer.archive_len -= 1;
            }),
            // And one byte before it.
            ("overlap", |footer| {
                footer.archive_offset -= 1;
                footer.archive_len += 1;
            }),
            // The last present block stops short of the footer.
            ("short last block", |footer| {
                footer.archive_len -= 1;
            }),
        ];
        for (label, mutate) in cases {
            let broken = mutating_footer(&binary, mutate);
            let error =
                open(Cursor::new(broken)).expect_err("a broken block layout must be rejected");
            assert!(
                matches!(error, PayloadError::MalformedFooter { .. }),
                "{label} got: {error:?}"
            );
        }
    }

    #[test]
    fn a_present_signature_block_is_accepted_and_still_held_to_adjacency() {
        // The reader accepts envelope blocks of arbitrary lengths. This
        // hand-built container exercises that structural property separately
        // from the signed writer's fixed Ed25519 and `key_id` lengths.
        let src = tempfile::tempdir().expect("source tempdir");
        let written = two_member_binary(src.path());
        // The second argument is `slack`: bytes the footer accounts for
        // nowhere.
        let signed = |slack: usize| with_envelope(&written, Some(SIGNATURE), Some(KEY_ID), slack);

        let mut payload = open(Cursor::new(signed(0)))
            .expect("a signed container must open")
            .expect("trailer should be present");
        assert_eq!(payload.signature(), Some(SIGNATURE));
        assert_eq!(payload.key_id(), Some(KEY_ID));
        // The walk stepped over nothing here, and every other check still ran.
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            payload
                .extract_to(dir.path())
                .expect("extraction should succeed")
                .len(),
            2
        );

        // One byte of slack before the footer, and the last present block no
        // longer ends where the footer begins.
        let error = open(Cursor::new(signed(1)))
            .expect_err("a last present block short of the footer must be rejected");
        assert!(
            matches!(error, PayloadError::MalformedFooter { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn one_envelope_block_present_beside_an_absent_one_is_accepted() {
        // The two pairs are independently present or absent, so the walk has to
        // step over an absent block wherever it sits. A `key_id` with no
        // signature is the discriminating case: the absent pair sits *between*
        // two present blocks, so the `key_id` starts where the archive ended
        // rather than where a signature would have.
        let src = tempfile::tempdir().expect("source tempdir");
        let written = two_member_binary(src.path());

        // A signature with no `key_id`: the absent pair is last, and the
        // signature is the block that must end where the footer begins.
        let mut payload = open(Cursor::new(with_envelope(
            &written,
            Some(SIGNATURE),
            None,
            0,
        )))
        .expect("a signature with no key_id must open")
        .expect("trailer should be present");
        assert_eq!(payload.signature(), Some(SIGNATURE));
        assert_eq!(payload.key_id(), None);
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            payload
                .extract_to(dir.path())
                .expect("extraction should succeed")
                .len(),
            2
        );

        // A `key_id` with no signature: the walk steps over the absent pair in
        // the middle and still reads the block that follows it.
        let payload = open(Cursor::new(with_envelope(&written, None, Some(KEY_ID), 0)))
            .expect("a key_id with no signature must open")
            .expect("trailer should be present");
        assert_eq!(payload.signature(), None);
        assert_eq!(payload.key_id(), Some(KEY_ID));
    }

    #[test]
    fn envelope_blocks_out_of_the_fixed_order_are_malformed() {
        // Adjacency is a walk in a *fixed* order, so two present blocks that sit
        // adjacent and fill the body exactly are still refused when each is
        // claimed at the other's offset. Only the footer moves here: the body's
        // bytes are the ones `with_envelope` laid down.
        let src = tempfile::tempdir().expect("source tempdir");
        let signed = with_envelope(
            &two_member_binary(src.path()),
            Some(SIGNATURE),
            Some(KEY_ID),
            0,
        );
        let swapped = mutating_footer(&signed, |footer| {
            let archive_end = footer.archive_offset + footer.archive_len;
            footer.key_id_offset = archive_end;
            footer.signature_offset = archive_end + footer.key_id_len;
        });

        let error =
            open(Cursor::new(swapped)).expect_err("the signature must come before the key_id");
        assert!(
            matches!(error, PayloadError::MalformedFooter { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_present_envelope_block_claiming_bytes_the_file_lacks_is_truncated() {
        // What makes reading the envelope blocks into memory safe: a crafted
        // length is bounded against the footer start before any allocation is
        // sized from it, so it can never name more than the container holds.
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());

        let cases: [FooterCase; 2] = [
            // A block starting where the archive ended and running past the
            // footer.
            ("a length past the footer", |footer| {
                footer.signature_offset = footer.archive_offset + footer.archive_len;
                footer.signature_len = u64::from(u32::MAX);
            }),
            // And one whose offset plus length does not even fit a `u64`.
            ("an offset plus length that overflows", |footer| {
                footer.key_id_offset = u64::MAX;
                footer.key_id_len = 1;
            }),
        ];
        for (label, mutate) in cases {
            let broken = mutating_footer(&binary, mutate);
            let error = open(Cursor::new(broken))
                .expect_err("a block outside the container must be rejected");
            assert!(
                matches!(error, PayloadError::TruncatedTrailer),
                "{label} got: {error:?}"
            );
        }
    }

    #[test]
    fn a_broken_layout_is_malformed_rather_than_falling_through_to_the_smaller_size() {
        // Selection is the only decision the walk makes. A validation failure
        // against the selected 73-byte footer must not send the probe back to
        // the 41-byte candidate, which would report a genuinely corrupt
        // container as "no trailer" and put `MalformedFooter` out of reach.
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());
        let broken = mutating_footer(&binary, |footer| {
            footer.archive_offset += 1;
            footer.archive_len -= 1;
        });

        let error = open(Cursor::new(&broken)).expect_err("the broken layout must be reported");
        assert!(
            matches!(error, PayloadError::MalformedFooter { .. }),
            "got: {error:?}"
        );
        let error = open_package(Cursor::new(&broken)).expect_err("likewise for a package");
        assert!(
            matches!(error, PayloadError::MalformedFooter { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_version_2_container_rewraps_with_its_absent_pairs_untouched() {
        let src = tempfile::tempdir().expect("source tempdir");
        let asset = two_member_binary(src.path());
        let new_base: &[u8] = b"a freshly built base binary, of a different length entirely";
        assert_ne!(new_base.len(), BASE.len());

        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(&asset), Cursor::new(new_base), &mut rewrapped)
            .expect("rewrap should succeed");

        // Asserted on the raw footer bytes as well as through the reader: a
        // shifted absent pair is a half-zero pair, which would surface as
        // `MalformedFooter` on re-open rather than as a wrong number.
        let (footer, footer_start) = probe_footer(&rewrapped);
        assert_eq!(footer.version, FORMAT_VERSION);
        assert_eq!(
            rewrapped
                .get(footer_start + MAGIC_LEN + 1 + 4 * 8..)
                .expect("the envelope fields are in range"),
            [0u8; 32].as_slice(),
        );

        // Every present offset resolves against the new base.
        assert_eq!(footer.manifest_offset, new_base.len() as u64);
        assert_eq!(
            footer.archive_offset,
            footer.manifest_offset + footer.manifest_len
        );
        assert_eq!(
            footer.archive_offset + footer.archive_len,
            footer_start as u64
        );

        // The manifest block is byte-identical, and every length survived.
        let (source_footer, _) = probe_footer(&asset);
        let (_, source_block, _) = trailer_parts(&asset);
        let (_, rewrapped_block, _) = trailer_parts(&rewrapped);
        assert_eq!(source_block, rewrapped_block);
        assert_eq!(footer.manifest_len, source_footer.manifest_len);
        assert_eq!(footer.archive_len, source_footer.archive_len);

        let mut payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped container must open")
            .expect("trailer should be present");
        assert_eq!(payload.signature(), None);
        assert_eq!(payload.key_id(), None);
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            payload
                .extract_to(dir.path())
                .expect("extraction should succeed")
                .len(),
            2
        );
    }

    #[test]
    fn a_rewrap_shifts_a_present_envelope_pair_with_the_rest_of_the_body() {
        // The signed writer uses fixed envelope lengths, so this hand-built
        // source separately proves that rewrapping carries arbitrary present
        // envelope blocks along with the manifest and archive.
        let src = tempfile::tempdir().expect("source tempdir");
        let signed = with_envelope(
            &two_member_binary(src.path()),
            Some(SIGNATURE),
            Some(KEY_ID),
            0,
        );
        let (source, _) = probe_footer(&signed);

        let new_base: &[u8] = b"a freshly built base binary, of a different length entirely";
        assert_ne!(new_base.len(), BASE.len());
        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(&signed), Cursor::new(new_base), &mut rewrapped)
            .expect("rewrap should succeed");

        // Each present block sits at the same distance into the body as before,
        // now measured from the new base, and every length survived.
        let shifted =
            |offset: u64| offset - source.manifest_offset + u64::try_from(new_base.len()).unwrap();
        let (footer, footer_start) = probe_footer(&rewrapped);
        assert_eq!(footer.manifest_offset, shifted(source.manifest_offset));
        assert_eq!(footer.archive_offset, shifted(source.archive_offset));
        assert_eq!(footer.signature_offset, shifted(source.signature_offset));
        assert_eq!(footer.key_id_offset, shifted(source.key_id_offset));
        assert_eq!(footer.manifest_len, source.manifest_len);
        assert_eq!(footer.archive_len, source.archive_len);
        assert_eq!(footer.signature_len, source.signature_len);
        assert_eq!(footer.key_id_len, source.key_id_len);
        // The `key_id` is the last present block, so it ends at the footer.
        assert_eq!(
            footer.key_id_offset + footer.key_id_len,
            u64::try_from(footer_start).unwrap()
        );

        let mut payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped container must open")
            .expect("trailer should be present");
        assert_eq!(payload.signature(), Some(SIGNATURE));
        assert_eq!(payload.key_id(), Some(KEY_ID));
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            payload
                .extract_to(dir.path())
                .expect("extraction should succeed")
                .len(),
            2
        );
    }

    #[test]
    fn a_version_1_payload_rewraps_at_version_1() {
        // The published assets are version-1 containers, and a graft must not
        // upgrade one: the source footer's own version is written back, and its
        // 41-byte wire form with it.
        let roxyd = b"roxyd binary bytes";
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let asset = assemble(BASE, &json, &archive, &footer);

        let new_base: &[u8] = b"a freshly built base binary, of a different length entirely";
        assert_ne!(new_base.len(), BASE.len());
        let mut rewrapped = Vec::new();
        rewrap_trailer(Cursor::new(&asset), Cursor::new(new_base), &mut rewrapped)
            .expect("rewrap should succeed");

        let (rewritten, footer_start) = probe_footer(&rewrapped);
        assert_eq!(rewritten.version, LEGACY_VERSION);
        assert_eq!(rewrapped.len() - footer_start, FOOTER_SIZE_V1);
        assert_eq!(rewritten.manifest_offset, new_base.len() as u64);
        assert_eq!(rewritten.manifest_len, footer.manifest_len);
        assert_eq!(rewritten.archive_len, footer.archive_len);

        let mut payload = open(Cursor::new(rewrapped))
            .expect("the rewrapped version-1 payload must open")
            .expect("trailer should be present");
        assert_eq!(payload.manifest().format_version(), None);
        assert_eq!(payload.signature(), None);
        assert_eq!(payload.key_id(), None);
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            payload
                .extract_to(dir.path())
                .expect("extraction should succeed")
                .len(),
            1
        );
    }

    #[test]
    fn read_base_executable_returns_the_base_prefix_at_either_container_version() {
        let src = tempfile::tempdir().expect("source tempdir");
        let version_2 = two_member_binary(src.path());
        assert_eq!(
            read_base_executable(Cursor::new(&version_2)).expect("the base must be readable"),
            BASE
        );

        let roxyd = b"roxyd binary bytes";
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let version_1 = assemble(BASE, &json, &archive, &footer);
        assert_eq!(
            read_base_executable(Cursor::new(&version_1)).expect("the base must be readable"),
            BASE
        );

        // A binary with no trailer is its own base — the third no-trailer
        // answer, and the state every dev and CI build is in.
        assert_eq!(
            read_base_executable(Cursor::new(BASE.to_vec())).expect("the base must be readable"),
            BASE
        );
        // Including one shorter than the smallest known footer.
        let stub = vec![0xABu8; 4];
        assert_eq!(
            read_base_executable(Cursor::new(stub.clone())).expect("the base must be readable"),
            stub
        );
    }

    #[test]
    fn a_version_1_payload_opens_whatever_sits_at_the_73_byte_candidate_offset() {
        // The 73-byte candidate offset of a version-1 payload falls inside its
        // archive block, whose bytes are artifact content and can spell
        // anything at all. The `2` case is the discriminating one: that
        // candidate pairs with the 73-byte size, so a descending walk would
        // select it and follow the archive's bytes as offsets. The ascending
        // walk selects the real 41-byte footer before it is ever read.
        let roxyd = b"roxyd binary bytes that comfortably outrun the 32 bytes under test";
        let json = baseline_manifest_json(&[("bin/roxyd", roxyd)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: roxyd,
        }]);
        let footer = footer_at_version(LEGACY_VERSION, BASE.len(), &json, &archive);
        let asset = assemble(BASE, &json, &archive, &footer);

        for version_byte in [1u8, 2, 200] {
            let mut forged = asset.clone();
            let candidate_at = forged.len() - FOOTER_SIZE_V2;
            assert!(
                candidate_at >= usize::try_from(footer.archive_offset).expect("fits"),
                "the candidate offset must land inside the archive block"
            );
            let candidate = forged
                .get_mut(candidate_at..candidate_at + MAGIC_LEN + 1)
                .expect("candidate region in range");
            candidate
                .get_mut(..MAGIC_LEN)
                .expect("magic in range")
                .copy_from_slice(&MAGIC);
            *candidate.get_mut(MAGIC_LEN).expect("version byte in range") = version_byte;

            let (located, footer_start) = probe_footer(&forged);
            assert_eq!(located.version, LEGACY_VERSION, "version {version_byte}");
            assert_eq!(forged.len() - footer_start, FOOTER_SIZE_V1);

            let payload = open(Cursor::new(forged))
                .expect("the real version-1 footer must still be selected")
                .expect("trailer should be present");
            assert_eq!(payload.manifest().artifacts().len(), 1);
        }
    }

    #[test]
    fn a_version_2_containers_41_byte_candidate_carries_no_magic() {
        // `file_len - 41` lands on the most significant byte of a version-2
        // footer's own `archive_offset`, which is zero for any container below
        // about 4.7 exabytes — so the walk falls through to 73 and finds the
        // real footer.
        let src = tempfile::tempdir().expect("source tempdir");
        let binary = two_member_binary(src.path());
        let candidate_at = binary.len() - FOOTER_SIZE_V1;
        assert_eq!(
            binary.get(candidate_at).copied(),
            Some(0),
            "the 41-byte candidate's first byte is `archive_offset`'s most significant one"
        );
        assert_ne!(
            binary.get(candidate_at..candidate_at + MAGIC_LEN),
            Some(MAGIC.as_slice())
        );

        let (footer, footer_start) = probe_footer(&binary);
        assert_eq!(footer.version, FORMAT_VERSION);
        assert_eq!(binary.len() - footer_start, FOOTER_SIZE_V2);
    }

    #[test]
    fn two_unknown_version_candidates_report_the_first_in_probe_order() {
        // Neither candidate is a footer, and both name versions this build has
        // never implemented. `found` is the 41-byte candidate's byte: the first
        // in probe order, recorded and never overwritten.
        let mut file = vec![0xABu8; 400];
        let len = file.len();
        for (size, version) in [(FOOTER_SIZE_V1, 9u8), (FOOTER_SIZE_V2, 11u8)] {
            let at = len - size;
            let candidate = file
                .get_mut(at..at + MAGIC_LEN + 1)
                .expect("candidate region in range");
            candidate
                .get_mut(..MAGIC_LEN)
                .expect("magic in range")
                .copy_from_slice(&MAGIC);
            *candidate.get_mut(MAGIC_LEN).expect("version byte in range") = version;
        }

        let error = open(Cursor::new(file)).expect_err("an unknown container version is an error");
        assert!(
            matches!(
                error,
                PayloadError::UnsupportedContainerFormat { found, supported }
                    if found == 9 && supported == [1, 2]
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_magic_under_a_known_version_at_the_wrong_size_is_no_trailer() {
        // The only matching magic sits at the 73-byte candidate offset under a
        // version-1 byte. The pairing fails, so it is not a footer; the version
        // is one this build implements, so it is not an unknown format either.
        // Both buckets refuse it, and what is left is "this file carries no
        // trailer" — never `UnsupportedContainerFormat` and never
        // `MalformedFooter`.
        let mut file = vec![0xABu8; 400];
        let at = file.len() - FOOTER_SIZE_V2;
        let candidate = file
            .get_mut(at..at + MAGIC_LEN + 1)
            .expect("candidate region in range");
        candidate
            .get_mut(..MAGIC_LEN)
            .expect("magic in range")
            .copy_from_slice(&MAGIC);
        *candidate.get_mut(MAGIC_LEN).expect("version byte in range") = 1;

        assert!(
            open(Cursor::new(file.clone()))
                .expect("an ignored candidate is not an error")
                .is_none()
        );
        let error = open_package(Cursor::new(file)).expect_err("a package must carry a trailer");
        assert!(matches!(error, PayloadError::NoTrailer), "got: {error:?}");
    }

    #[test]
    fn a_file_shorter_than_the_smallest_known_footer_carries_no_trailer() {
        for len in [0usize, 4, FOOTER_SIZE_V1 - 1] {
            assert!(
                open(Cursor::new(vec![0xABu8; len]))
                    .expect("a short file is not an error")
                    .is_none(),
                "length {len}"
            );
            let error = open_package(Cursor::new(vec![0xABu8; len]))
                .expect_err("a package must carry a trailer");
            assert!(matches!(error, PayloadError::NoTrailer), "length {len}");
        }
    }

    #[test]
    fn current_exe_without_trailer_is_an_empty_payload() {
        // The test binary carries no appended trailer.
        assert!(
            open_current_exe()
                .expect("current exe read should succeed")
                .is_none()
        );
    }

    /// The directory set a publish flushes, over paths alone: what the flushes
    /// themselves do is not observable, but which directories they are asked
    /// for is.
    fn dirs_for(relatives: &[&str]) -> Vec<PathBuf> {
        let owned: Vec<PathBuf> = relatives.iter().map(PathBuf::from).collect();
        publish_dirs(Path::new("/install/dest"), &owned)
    }

    #[test]
    fn an_artifact_directly_in_dest_flushes_dest_alone() {
        assert_eq!(dirs_for(&["bootler"]), vec![PathBuf::from("/install/dest")]);
    }

    #[test]
    fn a_nested_artifact_flushes_every_level_down_to_dest() {
        assert_eq!(
            dirs_for(&["opt/share/lib/libfoo.so"]),
            vec![
                PathBuf::from("/install/dest/opt/share/lib"),
                PathBuf::from("/install/dest/opt/share"),
                PathBuf::from("/install/dest/opt"),
                PathBuf::from("/install/dest"),
            ],
            "innermost first, since a directory's entry lives in its parent"
        );
    }

    #[test]
    fn two_artifacts_sharing_a_parent_flush_it_once() {
        assert_eq!(
            dirs_for(&["bin/one", "bin/two", "bin/nested/three"]),
            vec![
                PathBuf::from("/install/dest/bin"),
                PathBuf::from("/install/dest"),
                PathBuf::from("/install/dest/bin/nested"),
            ],
            "each directory appears once, at the position it was first reached"
        );
    }

    #[test]
    fn the_walk_stops_at_dest() {
        for dir in dirs_for(&["a/b/c", "top"]) {
            assert!(
                dir.starts_with("/install/dest"),
                "nothing above dest is flushed: {}",
                dir.display()
            );
        }
    }
}
