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
//! From the start of the appended region to end-of-file:
//!
//! 1. **Manifest block** — a [`PayloadManifest`] serialized as JSON.
//! 2. **Archive block** — a `tar` archive of the artifact files (each member
//!    keyed by its `archive_path`), `zstd`-compressed.
//! 3. **Footer** — a fixed-size record at the very end of the file with an
//!    exact binary layout (see [`FOOTER_SIZE`]): the [`MAGIC`] bytes, a `u8`
//!    format version ([`FORMAT_VERSION`]), then four `u64` little-endian fields
//!    — the manifest and archive absolute file offsets and lengths, in that
//!    order.
//!
//! The footer makes the trailer locatable: the reader seeks to
//! `file_len - FOOTER_SIZE`, checks the magic, then uses the recorded offsets.
//!
//! # Empty payload versus corrupt trailer
//!
//! A file shorter than [`FOOTER_SIZE`], or whose trailing [`FOOTER_SIZE`] bytes
//! do not match [`MAGIC`], is an **empty payload** — the normal state of an
//! ordinary binary with no trailer, reported as `Ok(None)` rather than an
//! error. Once the magic matches, any further problem (unrecognized version,
//! offsets outside the file, unparseable manifest, hash mismatch, unsafe or
//! unknown archive member) is a [`PayloadError`].

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};
use tempfile::Builder as TempBuilder;
use zstd::{Decoder, Encoder};

use crate::manifest::{
    ArchiveMember, ArtifactKind, Disposition, ManifestError, PayloadArtifact, PayloadManifest,
    TargetArch, is_safe_archive_path,
};
use crate::module_spec::ModuleSpec;

/// Magic bytes at the start of the footer, identifying a bootler payload.
pub const MAGIC: [u8; 8] = *b"BTLRPYLD";

/// Length of [`MAGIC`] in bytes.
const MAGIC_LEN: usize = MAGIC.len();

/// Current trailer format version.
pub const FORMAT_VERSION: u8 = 1;

/// Total size of the footer in bytes: [`MAGIC`] (8) + version (1) + four `u64`
/// fields (32) = 41.
pub const FOOTER_SIZE: usize = MAGIC_LEN + 1 + 4 * 8;

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

    /// A caller-supplied manifest failed validation while writing a trailer.
    #[error("invalid payload manifest: {0}")]
    InvalidManifest(#[from] ManifestError),

    /// The footer recorded a format version this build does not understand.
    #[error("unrecognized trailer format version {found} (expected {expected})")]
    UnsupportedVersion {
        /// Version read from the footer.
        found: u8,
        /// Version this build understands.
        expected: u8,
    },

    /// The footer's offsets or lengths point outside the file.
    #[error("trailer offsets point outside the file (truncated trailer)")]
    TruncatedTrailer,

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
struct Footer {
    version: u8,
    manifest_offset: u64,
    manifest_len: u64,
    archive_offset: u64,
    archive_len: u64,
}

impl Footer {
    /// Encodes the footer to its exact [`FOOTER_SIZE`]-byte wire form.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FOOTER_SIZE);
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.extend_from_slice(&self.manifest_offset.to_le_bytes());
        buf.extend_from_slice(&self.manifest_len.to_le_bytes());
        buf.extend_from_slice(&self.archive_offset.to_le_bytes());
        buf.extend_from_slice(&self.archive_len.to_le_bytes());
        buf
    }
}

/// Reads a little-endian `u64` from `reader`.
fn read_u64<R: Read>(reader: &mut R) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Parses a candidate footer.
///
/// Returns `Ok(None)` when the magic does not match (an empty payload), or the
/// parsed [`Footer`] once the magic and version check out.
fn parse_footer(bytes: &[u8]) -> Result<Option<Footer>, PayloadError> {
    let mut cursor = Cursor::new(bytes);

    let mut magic = [0u8; MAGIC_LEN];
    cursor.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Ok(None);
    }

    let mut version_buf = [0u8; 1];
    cursor.read_exact(&mut version_buf)?;
    let [version] = version_buf;
    if version != FORMAT_VERSION {
        return Err(PayloadError::UnsupportedVersion {
            found: version,
            expected: FORMAT_VERSION,
        });
    }

    let manifest_offset = read_u64(&mut cursor)?;
    let manifest_len = read_u64(&mut cursor)?;
    let archive_offset = read_u64(&mut cursor)?;
    let archive_len = read_u64(&mut cursor)?;

    Ok(Some(Footer {
        version,
        manifest_offset,
        manifest_len,
        archive_offset,
        archive_len,
    }))
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
/// caller-supplied value.
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
    mut base: B,
    mut out: W,
    pinset: Option<&str>,
    trust_set: Option<&[u8]>,
    inputs: &[ArtifactInput],
) -> Result<(), PayloadError> {
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

    let footer = Footer {
        version: FORMAT_VERSION,
        manifest_offset,
        manifest_len,
        archive_offset,
        archive_len,
    };
    out.write_all(&footer.encode())?;
    Ok(())
}

/// Copies an existing payload's trailer verbatim onto a different base binary,
/// rewriting only the footer's two absolute offsets by the base-length delta.
///
/// A self-contained release asset is a base executable with a trailer appended
/// (`base | manifest | archive | footer`). To run a CI-built `bootler-security`
/// against the operator's frozen payload, the payload trailer must be grafted
/// onto that fresh base. Rather than re-extracting and re-hashing the (GB-scale)
/// payload, this streams the source's trailer body (`manifest | archive`)
/// straight onto `new_base`, then writes a fresh footer whose `manifest_offset`
/// and `archive_offset` are shifted by `new_base_len - old_base_len`; the two
/// lengths are unchanged. The archive bytes and their manifest SHA-256s stay
/// byte-identical, so the reader still hash-verifies every artifact — a caller
/// can confirm the graft by re-opening the output with [`open`].
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
/// [`PayloadError::UnsupportedVersion`] for an unrecognized footer version,
/// [`PayloadError::TruncatedTrailer`] when the footer's offsets fall outside
/// `source`, or [`PayloadError::Io`] on any read or write failure.
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
    let footer_size = FOOTER_SIZE as u64;
    if source_len < footer_size {
        return Err(PayloadError::NoTrailer);
    }

    let footer_start = source_len - footer_size;
    source.seek(SeekFrom::Start(footer_start))?;
    let mut footer_bytes = vec![0u8; FOOTER_SIZE];
    source.read_exact(&mut footer_bytes)?;
    let Some(footer) = parse_footer(&footer_bytes)? else {
        return Err(PayloadError::NoTrailer);
    };

    // Validate the source footer's offsets before trusting them (mirrors `open`).
    let manifest_end = footer
        .manifest_offset
        .checked_add(footer.manifest_len)
        .ok_or(PayloadError::TruncatedTrailer)?;
    let archive_end = footer
        .archive_offset
        .checked_add(footer.archive_len)
        .ok_or(PayloadError::TruncatedTrailer)?;
    if manifest_end > footer_start || archive_end > footer_start {
        return Err(PayloadError::TruncatedTrailer);
    }

    // The trailer body is everything from the manifest to the start of the
    // footer (`manifest | archive`); it is copied verbatim.
    let old_base_len = footer.manifest_offset;
    let body_len = footer_start - old_base_len;

    let new_base_len = std::io::copy(&mut new_base, &mut out)?;
    source.seek(SeekFrom::Start(old_base_len))?;
    let copied = std::io::copy(&mut source.by_ref().take(body_len), &mut out)?;
    if copied != body_len {
        return Err(PayloadError::TruncatedTrailer);
    }

    // Shift only the two absolute offsets by the base-length delta; the two
    // lengths are unchanged. The trailer body is contiguous `manifest | archive`
    // placed right after the new base, so the manifest starts at `new_base_len`
    // and the archive at `new_base_len + manifest_len`.
    let rewritten = Footer {
        version: footer.version,
        manifest_offset: new_base_len,
        manifest_len: footer.manifest_len,
        archive_offset: new_base_len
            .checked_add(footer.manifest_len)
            .ok_or(PayloadError::TruncatedTrailer)?,
        archive_len: footer.archive_len,
    };
    out.write_all(&rewritten.encode())?;
    Ok(())
}

/// A located and parsed payload trailer, holding the source it was read from so
/// its artifacts can be extracted and verified.
#[derive(Debug)]
pub struct Payload<R: Read + Seek> {
    src: R,
    manifest: PayloadManifest,
    archive_offset: u64,
    archive_len: u64,
}

impl<R: Read + Seek> Payload<R> {
    /// Returns the payload manifest.
    #[must_use]
    pub fn manifest(&self) -> &PayloadManifest {
        &self.manifest
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
    /// crash. And it does not cover the final publish step — the moves that put
    /// already-verified members at their target paths once every check has
    /// passed. Publishing several files is not one atomic operation, so **a
    /// failure during the publish step may leave already-verified members at
    /// their target paths**; making it otherwise would mean owning `dest`
    /// rather than writing into it, which is a different function's contract.
    /// Even there, no staging directory and no temporary file survives, and no
    /// partially written artifact appears at a target path, because each
    /// individual move is atomic.
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
    /// read or a staged member cannot be written.
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
        }

        Ok(extracted)
    }
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

/// Locates and reads a trailer from `src`.
///
/// Returns `Ok(None)` for an empty payload — a file shorter than
/// [`FOOTER_SIZE`], or one whose trailing bytes do not match [`MAGIC`].
///
/// # Errors
///
/// Returns [`PayloadError`] when the magic matches but the trailer is unusable:
/// an unrecognized container version, offsets pointing outside the file, a
/// manifest whose `format_version` this build does not implement (reported as
/// [`PayloadError::InvalidManifest`] carrying
/// [`ManifestError::UnsupportedManifestFormat`]), or a manifest that fails to
/// parse or validate.
pub fn open<R: Read + Seek>(mut src: R) -> Result<Option<Payload<R>>, PayloadError> {
    let file_len = src.seek(SeekFrom::End(0))?;
    let footer_size = FOOTER_SIZE as u64;
    if file_len < footer_size {
        return Ok(None);
    }

    let footer_start = file_len - footer_size;
    src.seek(SeekFrom::Start(footer_start))?;
    let mut footer_bytes = vec![0u8; FOOTER_SIZE];
    src.read_exact(&mut footer_bytes)?;

    let Some(footer) = parse_footer(&footer_bytes)? else {
        return Ok(None);
    };

    let manifest_end = footer
        .manifest_offset
        .checked_add(footer.manifest_len)
        .ok_or(PayloadError::TruncatedTrailer)?;
    let archive_end = footer
        .archive_offset
        .checked_add(footer.archive_len)
        .ok_or(PayloadError::TruncatedTrailer)?;
    if manifest_end > footer_start || archive_end > footer_start {
        return Err(PayloadError::TruncatedTrailer);
    }

    let manifest_len =
        usize::try_from(footer.manifest_len).map_err(|_| PayloadError::TruncatedTrailer)?;
    src.seek(SeekFrom::Start(footer.manifest_offset))?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    src.read_exact(&mut manifest_bytes)?;
    // The manifest is read through the two-stage parse rather than a direct
    // `serde_json::from_slice`, because only a reader that already knows the
    // container footer version can evaluate the pre-versioned baseline
    // conjunction. An undecodable manifest block keeps reporting as
    // `ManifestParse`, distinct from a version this build does not implement.
    let manifest =
        PayloadManifest::parse(&manifest_bytes, footer.version).map_err(|error| match error {
            ManifestError::Decode(source) => PayloadError::ManifestParse(source),
            other => PayloadError::InvalidManifest(other),
        })?;

    Ok(Some(Payload {
        src,
        manifest,
        archive_offset: footer.archive_offset,
        archive_len: footer.archive_len,
    }))
}

/// Opens the binary at `path` and reads its trailer.
///
/// Returns `Ok(None)` when the binary carries no trailer.
///
/// # Errors
///
/// Returns [`PayloadError`] when the file cannot be opened or its trailer is
/// corrupt (see [`open`]).
pub fn open_path(path: &Path) -> Result<Option<Payload<std::fs::File>>, PayloadError> {
    let file = std::fs::File::open(path)?;
    open(file)
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
/// A trailered release binary is `base ‖ manifest ‖ archive ‖ footer`, so the base
/// is exactly the first `footer.manifest_offset` bytes (`rewrap_trailer` relies on
/// the same prefix). A binary with no trailer (a dev/CI build, or one already
/// stripped) *is* its own base, so the whole file is returned. Only the base bytes
/// are read into memory, never the multi-hundred-megabyte payload.
///
/// bootler self-installs these bytes onto each core host so the `roxyd-activate`
/// oneshot has a small, root-owned validator to run; the activation subcommand
/// touches no payload, so shipping it without one is both correct and far cheaper
/// than copying the fat binary (RFC 0003 §8.3).
///
/// # Errors
///
/// Returns [`PayloadError`] when `src` cannot be read or carries a corrupt trailer.
pub fn read_base_executable<R: Read + Seek>(mut src: R) -> Result<Vec<u8>, PayloadError> {
    let file_len = src.seek(SeekFrom::End(0))?;
    let footer_size = FOOTER_SIZE as u64;
    let base_len = if file_len < footer_size {
        file_len
    } else {
        let footer_start = file_len - footer_size;
        src.seek(SeekFrom::Start(footer_start))?;
        let mut footer_bytes = vec![0u8; FOOTER_SIZE];
        src.read_exact(&mut footer_bytes)?;
        match parse_footer(&footer_bytes)? {
            // The base is the prefix before the manifest block.
            Some(footer) => {
                if footer.manifest_offset > footer_start {
                    return Err(PayloadError::TruncatedTrailer);
                }
                footer.manifest_offset
            }
            // No trailer: the file is its own base.
            None => file_len,
        }
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
    use std::collections::BTreeSet;
    use std::io::{Cursor, Write};
    use std::path::Path;

    use tar::{Builder, EntryType, Header};
    use zstd::Encoder;

    use super::{
        ArtifactInput, FOOTER_SIZE, FORMAT_VERSION, Footer, MAGIC, PayloadError, PayloadManifest,
        TAR_BLOCK_SIZE, TAR_NAME_FIELD_LEN, append_trailer, open, open_current_exe, parse_footer,
        rewrap_trailer, sha256_hex,
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

    const BASE: &[u8] = b"#!/bin/false\nnot a real executable, just a base binary\n";

    /// A full 40-hex git commit SHA, the build identity a producer stamps onto
    /// every current-format artifact.
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// Opaque stand-in for the signed trust-set generation container.
    const GENERATION: &[u8] = b"a signed generation container, opaque to this crate";

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
        let footer = valid_footer(BASE.len(), json, archive);
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

    fn valid_footer(base_len: usize, manifest_json: &[u8], archive: &[u8]) -> Footer {
        let manifest_offset = base_len as u64;
        let manifest_len = manifest_json.len() as u64;
        Footer {
            version: FORMAT_VERSION,
            manifest_offset,
            manifest_len,
            archive_offset: manifest_offset + manifest_len,
            archive_len: archive.len() as u64,
        }
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
        let footer_start = binary.len() - FOOTER_SIZE;
        let footer = parse_footer(binary.get(footer_start..).expect("footer in range"))
            .expect("footer should parse")
            .expect("magic should match");
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
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("a baseline payload must open")
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

        let (error, dir) = extract_error_leaving_dest_unchanged(&json, &archive);
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
        let footer = valid_footer(BASE.len(), &json, &archive);
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
        let footer = valid_footer(BASE.len(), &json, &archive);
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
    fn bad_footer_version_is_rejected() {
        let bytes = b"payload bytes";
        let json = manifest_json(&[("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes,
        }]);
        let mut footer = valid_footer(BASE.len(), &json, &archive);
        footer.version = FORMAT_VERSION + 7;
        let binary = assemble(BASE, &json, &archive, &footer);

        let error = open(Cursor::new(binary)).expect_err("bad version expected");
        assert!(
            matches!(error, PayloadError::UnsupportedVersion { found, expected }
                if found == FORMAT_VERSION + 7 && expected == FORMAT_VERSION),
            "got: {error:?}"
        );
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
        };
        let encoded = footer.encode();
        assert_eq!(encoded.len(), FOOTER_SIZE);
        assert!(encoded.starts_with(&MAGIC));

        let parsed = parse_footer(&encoded)
            .expect("parse should succeed")
            .expect("magic should match");
        assert_eq!(parsed.manifest_offset, 10);
        assert_eq!(parsed.manifest_len, 20);
        assert_eq!(parsed.archive_offset, 30);
        assert_eq!(parsed.archive_len, 40);
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
}
