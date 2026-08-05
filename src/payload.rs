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
use tempfile::NamedTempFile;
use zstd::{Decoder, Encoder};

use crate::manifest::{
    ArtifactKind, Disposition, ManifestError, PayloadArtifact, PayloadManifest, TargetArch,
    is_safe_archive_path,
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

    /// The source binary handed to [`rewrap_trailer`] carries no payload
    /// trailer, so there is nothing to graft onto the new base.
    #[error("source binary carries no payload trailer to rewrap")]
    NoTrailer,
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
/// lowercase hex SHA-256 of the bytes copied.
///
/// This is the streaming primitive behind both writing (hash a source file into
/// [`std::io::sink`]) and extraction (hash a member while spooling it to disk),
/// so no artifact is ever buffered in memory in full.
fn hash_copy<R: Read, W: Write>(mut reader: R, mut writer: W) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
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
    }
    Ok(to_hex(&hasher.finalize()))
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
/// # Errors
///
/// Returns [`PayloadError`] when a `source` file cannot be read, the derived
/// manifest is invalid (empty dispositions, unsafe or duplicate `archive_path`,
/// a malformed `commit`, an empty `trust_set`), or serialization, archive
/// construction, or writing to `out` fails.
pub fn append_trailer<B: Read, W: Write>(
    mut base: B,
    mut out: W,
    pinset: Option<&str>,
    trust_set: Option<&[u8]>,
    inputs: &[ArtifactInput],
) -> Result<(), PayloadError> {
    let mut artifacts = Vec::with_capacity(inputs.len());
    for input in inputs {
        let source = std::fs::File::open(&input.source)?;
        let sha256 = hash_copy(source, std::io::sink())?;
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
    let manifest = PayloadManifest::new(pinset.map(str::to_string), artifacts)?;
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
        for input in inputs {
            let source = std::fs::File::open(&input.source)?;
            let size = source.metadata()?.len();
            let mut header = Header::new_gnu();
            header.set_size(size);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, &input.archive_path, source)?;
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
    /// Each member is checked before its bytes reach a final path: only regular
    /// files with safe relative paths that appear in the manifest are extracted.
    /// A member is streamed into a temporary file in the destination directory
    /// while its SHA-256 is computed, and only moved into place once the hash
    /// matches — so a mismatching artifact never lands at its target path and no
    /// member is buffered in memory in full. After iteration, every manifest
    /// artifact must have been seen; a manifest entry with no archive member is
    /// rejected so nothing the manifest promises is silently skipped.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError`] when a member is a non-regular entry, uses an
    /// unsafe path, is absent from the manifest, is a repeated `archive_path`,
    /// or fails its hash check; when a manifest artifact has no matching member;
    /// or when the archive cannot be read.
    pub fn extract_to(&mut self, dest: &Path) -> Result<Vec<ExtractedArtifact>, PayloadError> {
        let manifest = &self.manifest;
        let by_path: HashMap<&str, &PayloadArtifact> = manifest
            .artifacts()
            .iter()
            .map(|artifact| (artifact.archive_path.as_str(), artifact))
            .collect();

        self.src.seek(SeekFrom::Start(self.archive_offset))?;
        let limited = (&mut self.src).take(self.archive_len);
        let decoder = Decoder::new(limited)?;
        let mut archive = Archive::new(decoder);

        let mut extracted = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();
            let raw_path = entry.path()?.into_owned();
            let display = raw_path.display().to_string();

            if entry_type != EntryType::Regular {
                return Err(PayloadError::UnsupportedEntryType { path: display });
            }
            let Some(path_str) = raw_path.to_str() else {
                return Err(PayloadError::UnsafeMemberPath(display));
            };
            if !is_safe_archive_path(path_str) {
                return Err(PayloadError::UnsafeMemberPath(display));
            }
            let Some(artifact) = by_path.get(path_str).copied() else {
                return Err(PayloadError::MemberNotInManifest(display));
            };
            if !seen.insert(artifact.archive_path.as_str()) {
                return Err(PayloadError::DuplicateMember(display));
            }

            let out_path = dest.join(&raw_path);
            let parent = match out_path.parent() {
                Some(parent) => {
                    std::fs::create_dir_all(parent)?;
                    parent
                }
                None => dest,
            };
            let mut temp = NamedTempFile::new_in(parent)?;
            let digest = hash_copy(&mut entry, &mut temp)?;
            if !digest.eq_ignore_ascii_case(&artifact.sha256) {
                return Err(PayloadError::HashMismatch {
                    path: artifact.archive_path.clone(),
                });
            }
            temp.persist(&out_path).map_err(|error| error.error)?;
            extracted.push(ExtractedArtifact {
                artifact: artifact.clone(),
                path: out_path,
            });
        }

        for artifact in manifest.artifacts() {
            if !seen.contains(artifact.archive_path.as_str()) {
                return Err(PayloadError::ArtifactMissingFromArchive(
                    artifact.archive_path.clone(),
                ));
            }
        }

        Ok(extracted)
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
    use std::io::Cursor;
    use std::path::Path;

    use tar::{Builder, EntryType, Header};
    use zstd::Encoder;

    use super::{
        ArtifactInput, FOOTER_SIZE, FORMAT_VERSION, Footer, MAGIC, PayloadError, PayloadManifest,
        append_trailer, open, open_current_exe, parse_footer, rewrap_trailer, sha256_hex,
    };
    use crate::manifest::{
        ArtifactKind, Disposition, MANIFEST_FORMAT_VERSION, MAX_MANIFEST_FORMAT_VERSION,
        MIN_MANIFEST_FORMAT_VERSION, ManifestError, PayloadArtifact, TargetArch,
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
    }

    fn zstd_tar(members: &[Member]) -> Vec<u8> {
        let mut builder = Builder::new(Encoder::new(Vec::new(), 3).unwrap());
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
                    let mut header = Header::new_gnu();
                    header.set_size(bytes.len() as u64);
                    header.set_mode(0o644);
                    header.set_mtime(0);
                    header.set_entry_type(EntryType::Regular);
                    {
                        let gnu = header.as_gnu_mut().expect("gnu header");
                        let name_bytes = path.as_bytes();
                        gnu.name[..name_bytes.len()].copy_from_slice(name_bytes);
                    }
                    header.set_cksum();
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
        builder.into_inner().unwrap().finish().unwrap()
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

    fn manifest_json(artifacts: Vec<PayloadArtifact>) -> Vec<u8> {
        let manifest = PayloadManifest::new(None, artifacts).expect("manifest should be valid");
        serde_json::to_vec(&manifest).expect("serialization should succeed")
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
        let json = String::from_utf8(manifest_json(vec![artifact("bin/roxyd", roxyd)]))
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
        // The already-published release assets carry none of the three fields
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

        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = payload
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 1);
        assert_eq!(std::fs::read(dir.path().join("bin/roxyd")).unwrap(), roxyd);
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

        let json = manifest_json(vec![artifact("bin/roxyd", original)]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: &tampered,
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should locate the trailer")
            .expect("trailer should be present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("hash mismatch expected");
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
        let json = manifest_json(vec![artifact("bin/roxyd", bytes)]);
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
        let json = manifest_json(vec![artifact("bin/roxyd", bytes)]);
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
        let json = manifest_json(vec![artifact("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::RawFile {
            path: "../escape",
            bytes,
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("unsafe path expected");
        assert!(
            matches!(error, PayloadError::UnsafeMemberPath(_)),
            "got: {error:?}"
        );
        assert!(!dir.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn manifest_artifact_missing_from_archive_is_rejected() {
        let present = b"present bytes";
        // The manifest promises two artifacts, but the archive carries only one.
        // The absent one is neither extracted nor hash-verified, so extraction
        // must fail rather than silently return the shorter set.
        let json = manifest_json(vec![
            artifact("bin/roxyd", present),
            artifact("bin/missing", b"absent bytes"),
        ]);
        let archive = zstd_tar(&[Member::File {
            path: "bin/roxyd",
            bytes: present,
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("missing manifest artifact expected");
        assert!(
            matches!(error, PayloadError::ArtifactMissingFromArchive(ref path) if path == "bin/missing"),
            "got: {error:?}"
        );
    }

    #[test]
    fn absolute_member_path_is_rejected() {
        let bytes = b"evil";
        let json = manifest_json(vec![artifact("bin/roxyd", bytes)]);
        let archive = zstd_tar(&[Member::RawFile {
            path: "/etc/evil",
            bytes,
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("absolute path rejected");
        assert!(
            matches!(
                error,
                PayloadError::UnsafeMemberPath(_) | PayloadError::MemberNotInManifest(_)
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn symlink_member_is_rejected() {
        let json = manifest_json(vec![artifact("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::Symlink {
            path: "bin/roxyd",
            target: "/etc/passwd",
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("symlink rejected");
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn hardlink_member_is_rejected() {
        let json = manifest_json(vec![artifact("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::Hardlink {
            path: "bin/roxyd",
            target: "bin/other",
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("hardlink rejected");
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn char_device_member_is_rejected() {
        let json = manifest_json(vec![artifact("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::CharDevice { path: "bin/roxyd" }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("char device rejected");
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn directory_member_is_rejected_as_non_regular() {
        let json = manifest_json(vec![artifact("bin/roxyd", b"bytes")]);
        let archive = zstd_tar(&[Member::Directory { path: "bin/" }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("directory rejected");
        assert!(
            matches!(error, PayloadError::UnsupportedEntryType { .. }),
            "got: {error:?}"
        );
    }

    #[test]
    fn member_absent_from_manifest_is_rejected() {
        let json = manifest_json(vec![artifact("bin/roxyd", b"bytes")]);
        // Archive holds a different, safe, regular file not named in the manifest.
        let archive = zstd_tar(&[Member::File {
            path: "bin/stowaway",
            bytes: b"unexpected",
        }]);
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("unknown member rejected");
        assert!(
            matches!(error, PayloadError::MemberNotInManifest(_)),
            "got: {error:?}"
        );
        assert!(!dir.path().join("bin/stowaway").exists());
    }

    #[test]
    fn duplicate_archive_member_is_rejected() {
        let bytes = b"roxyd binary bytes";
        let json = manifest_json(vec![artifact("bin/roxyd", bytes)]);
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
        let footer = valid_footer(BASE.len(), &json, &archive);
        let binary = assemble(BASE, &json, &archive, &footer);

        let mut payload = open(Cursor::new(binary))
            .expect("reader should succeed")
            .expect("trailer present");
        let dir = tempfile::tempdir().expect("tempdir");
        let error = payload
            .extract_to(dir.path())
            .expect_err("duplicate member rejected");
        assert!(
            matches!(error, PayloadError::DuplicateMember(_)),
            "got: {error:?}"
        );
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
