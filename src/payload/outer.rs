//! The one walk over a package's outer archive block, shared by the legacy
//! [`Payload::extract_to`](super::Payload::extract_to) and the full-content
//! verification in [`crate::package`].
//!
//! The walk owns every rule about the archive itself: each member a regular
//! file named and sized by its own raw `ustar` header, at a safe path, listed
//! in the manifest exactly once and hashing to the digest it records; nothing
//! but the end-of-archive marker after the last member; no manifest artifact
//! missing; and the walked sequence equal to the bound `archive_members` in
//! name, order, count and length. What happens to a member's bytes is a
//! [`MemberSink`]'s business, so the two callers cannot come to disagree about
//! what an admissible archive is.
//!
//! The legacy caller passes no [`OuterLimits`] and sees exactly the walk it
//! always had. A caller that passes them also gets every zstd frame's window
//! checked before that frame is decoded, the member count bounded, and every
//! decoded byte metered: the data of admitted members against
//! `OuterUncompressedTotal`, and the framing between the members — headers,
//! extension records, padding and the end marker — against a private
//! allowance per member slot, so an extension record cannot grow into a
//! buffer the size of the archive. The framing is no member data and never
//! reported as that resource: passing its allowance is a container verdict,
//! and an extension record too large for it is refused for what it
//! overrides, as [`framing`] describes.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader, Read};

use tar::Archive;
use zstd::Decoder;

use super::{PayloadError, admitted_member_path, compare_member_list, reject_trailing_bytes};
use crate::manifest::{ArchiveMember, PayloadArtifact, PayloadManifest};
use crate::package::LimitResource;

mod framing;

use framing::{Framing, OversizedExtension, SCAN_CHUNK};

/// The magic number opening a standard zstd frame, little-endian.
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// The bytes of a skippable frame's magic number above its low nibble,
/// little-endian: `0x184D2A5?`.
const ZSTD_SKIPPABLE_MAGIC_HIGH: [u8; 3] = [0x2a, 0x4d, 0x18];
/// The frame descriptor bit marking a single-segment frame.
const ZSTD_SINGLE_SEGMENT: u8 = 0x20;
/// The frame descriptor bit a conforming frame leaves clear.
const ZSTD_RESERVED_DESCRIPTOR_BIT: u8 = 0x08;
/// The frame descriptor bit announcing a content checksum.
const ZSTD_CHECKSUM_FLAG: u8 = 0x04;
/// The longest header a standard frame carries after its descriptor: a window
/// descriptor, a four-byte dictionary ID and an eight-byte content size.
const ZSTD_MAX_FIELD_LEN: usize = 13;
/// A block header's length.
const ZSTD_BLOCK_HEADER_LEN: usize = 3;
/// A frame content checksum's length.
const ZSTD_CHECKSUM_LEN: u64 = 4;
/// The smallest window exponent a zstd window descriptor encodes.
const ZSTD_WINDOW_LOG_BASE: u32 = 10;
/// How much the two-byte frame content size field is offset by.
const ZSTD_FCS_TWO_BYTE_OFFSET: u64 = 256;
/// Framing bytes allowed per member slot: one header block and at most one
/// block of padding.
const FRAMING_PER_SLOT: u64 = 1024;
/// Member slots of framing beyond the admitted members: the header refused
/// for exceeding the member count, and the end-of-archive marker with the one
/// trailing block the walk tolerates.
const FRAMING_EXTRA_SLOTS: u64 = 2;

/// The limits a bounded walk enforces.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OuterLimits {
    /// Most members the archive may hold, `OuterMembers`.
    pub(crate) members: u64,
    /// Most member bytes the walk may read, `OuterUncompressedTotal`.
    pub(crate) uncompressed_total: u64,
    /// Largest zstd window a frame may declare, `ZstdWindow`.
    pub(crate) zstd_window: u64,
    /// Largest single read made of the compressed or decoded stream,
    /// `CopyBuffer`.
    pub(crate) copy_buffer: usize,
}

/// Why a walk refused an archive.
#[derive(Debug)]
pub(crate) enum WalkError<E> {
    /// A container-layer verdict, the one the legacy walk has always given.
    Payload(PayloadError),
    /// A bounded walk passed one of its limits. Never produced by a walk given
    /// no [`OuterLimits`].
    Limit {
        /// The resource.
        resource: LimitResource,
        /// Its configured value.
        limit: u64,
    },
    /// The sink failed on its own account.
    Sink(E),
}

/// How a [`MemberSink`] failed while receiving a member.
#[derive(Debug)]
pub(crate) enum SinkFault<E> {
    /// Reading the member stream failed. The walk classifies it.
    Stream(io::Error),
    /// The sink failed on its own account.
    Sink(E),
}

/// Where the walk hands each admitted member's bytes.
pub(crate) trait MemberSink<'m> {
    /// The sink's own failure.
    type Error;

    /// Consumes `stream`, the whole of the member admitted as `artifact` at
    /// `member_path`, and returns the lowercase hex SHA-256 and the length of
    /// exactly the bytes it read.
    ///
    /// # Errors
    ///
    /// Returns [`SinkFault::Stream`] for a failure reading `stream`, where the
    /// sink can tell one apart, and [`SinkFault::Sink`] for anything else.
    fn receive(
        &mut self,
        artifact: &'m PayloadArtifact,
        member_path: &str,
        stream: &mut dyn Read,
    ) -> Result<(String, u64), SinkFault<Self::Error>>;

    /// Keeps the member [`receive`](Self::receive) returned last, now that
    /// its digest has been found equal to the manifest's.
    ///
    /// # Errors
    ///
    /// Returns the sink's own failure.
    fn accept(&mut self) -> Result<(), Self::Error>;
}

/// Walks the zstd-compressed tar in `archive` against `manifest`, handing
/// every admitted member to `sink`.
///
/// # Errors
///
/// Returns [`WalkError::Payload`] for every rule the archive breaks, carrying
/// the variant the legacy walk has always reported; [`WalkError::Limit`] when a
/// bounded walk passes a limit; and [`WalkError::Sink`] for a sink failure.
pub(crate) fn walk_outer<'m, R: Read, S: MemberSink<'m>>(
    archive: R,
    manifest: &'m PayloadManifest,
    limits: Option<&OuterLimits>,
    sink: &mut S,
) -> Result<(), WalkError<S::Error>> {
    let Some(limits) = limits else {
        let decoder = Decoder::new(archive).map_err(stream_error)?;
        return walk_entries(decoder, manifest, None, sink);
    };
    let buffered = BufReader::with_capacity(limits.copy_buffer, WindowGuard::new(archive, limits));
    let mut decoder = Decoder::with_buffer(buffered).map_err(stream_error)?;
    // `ZstdWindow` is never below 1 KiB; the floor only keeps a zero out of
    // `ilog2`'s panic.
    let window_log = limits
        .zstd_window
        .checked_ilog2()
        .unwrap_or(ZSTD_WINDOW_LOG_BASE)
        .max(ZSTD_WINDOW_LOG_BASE);
    decoder.window_log_max(window_log).map_err(stream_error)?;
    let counters = OuterCounters::new(limits);
    let metered = Meter {
        inner: decoder,
        counters: &counters,
        copy_buffer: limits.copy_buffer,
        framing: Framing::new(),
    };
    walk_entries(metered, manifest, Some(&counters), sink)
}

/// Maps a failed legacy walk onto the [`PayloadError`] the legacy caller has
/// always returned.
///
/// The legacy walk passes no limits and reads a caller's own source, so
/// [`WalkError::Limit`] cannot arise from it; it is reported as the source
/// failure it would otherwise be rather than trusted to a panic.
pub(crate) fn legacy_error(error: WalkError<PayloadError>) -> PayloadError {
    match error {
        WalkError::Payload(error) | WalkError::Sink(error) => error,
        WalkError::Limit { resource, limit } => {
            PayloadError::Io(OuterLimitFault { resource, limit }.into_io())
        }
    }
}

/// The walk proper, over the decoded tar stream.
fn walk_entries<'m, D: Read, S: MemberSink<'m>>(
    decoded: D,
    manifest: &'m PayloadManifest,
    counters: Option<&OuterCounters>,
    sink: &mut S,
) -> Result<(), WalkError<S::Error>> {
    let by_path: HashMap<&str, &PayloadArtifact> = manifest
        .artifacts()
        .iter()
        .map(|artifact| (artifact.archive_path.as_str(), artifact))
        .collect();
    let mut archive = Archive::new(decoded);
    let mut seen: HashSet<&str> = HashSet::new();
    // What the archive actually turned out to hold, recorded member by member
    // as it streams past and compared against the bound list only once the
    // walk is over: count and order are not decidable before then.
    let mut walked: Vec<ArchiveMember> = Vec::new();
    let mut members = 0u64;
    for entry in archive.entries().map_err(stream_error)? {
        let mut entry = entry.map_err(stream_error)?;
        if let Some(counters) = counters {
            members = members.saturating_add(1);
            if members > counters.members_limit {
                return Err(WalkError::Limit {
                    resource: LimitResource::OuterMembers,
                    limit: counters.members_limit,
                });
            }
        }
        let member_path = admitted_member_path(&entry).map_err(payload_error)?;
        let Some(artifact) = by_path.get(member_path.as_str()).copied() else {
            return Err(WalkError::Payload(PayloadError::MemberNotInManifest(
                member_path,
            )));
        };
        if !seen.insert(artifact.archive_path.as_str()) {
            return Err(WalkError::Payload(PayloadError::DuplicateMember(
                member_path,
            )));
        }

        let mut stream = MemberStream {
            entry: &mut entry,
            counters,
        };
        let (digest, length) =
            sink.receive(artifact, &member_path, &mut stream)
                .map_err(|fault| match fault {
                    SinkFault::Stream(error) => stream_error(error),
                    SinkFault::Sink(error) => WalkError::Sink(error),
                })?;
        if !digest.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(WalkError::Payload(PayloadError::HashMismatch {
                path: artifact.archive_path.clone(),
            }));
        }
        sink.accept().map_err(WalkError::Sink)?;
        // The length recorded is the count of data bytes the sink consumed
        // while hashing the member, never the size read back out of its `tar`
        // header: the bound length has to be a property of the bytes that
        // were hashed.
        walked.push(ArchiveMember {
            name: member_path,
            length,
        });
    }

    reject_trailing_bytes(&mut archive.into_inner()).map_err(payload_error)?;

    for artifact in manifest.artifacts() {
        if !seen.contains(artifact.archive_path.as_str()) {
            return Err(WalkError::Payload(
                PayloadError::ArtifactMissingFromArchive(artifact.archive_path.clone()),
            ));
        }
    }

    // The walk against the list the manifest binds — an addition to every
    // check above, never a replacement for one. It is compared against
    // `archive_members` and never reconstructed from `artifacts`: deriving the
    // expected sequence from the other field would leave the enumeration
    // exactly as unstated as it was before it was recorded. A manifest read
    // off the pre-versioned baseline path binds no list, so there is nothing
    // to compare against and this check alone is skipped.
    if let Some(bound) = manifest.archive_members() {
        compare_member_list(bound, &walked).map_err(WalkError::Payload)?;
    }
    Ok(())
}

/// Classifies a failure reading the archive: a limit a [`Meter`] enforced
/// becomes [`WalkError::Limit`], an extension record refused for what it
/// overrides becomes the [`PayloadError`] naming that override, and anything
/// else — the framing allowance among it — is the [`PayloadError::Io`] the
/// legacy walk reports. Only the payload's type decides.
fn stream_error<E>(error: io::Error) -> WalkError<E> {
    let error = match take_payload::<OuterLimitFault>(error) {
        Ok(fault) => {
            return WalkError::Limit {
                resource: fault.resource,
                limit: fault.limit,
            };
        }
        Err(error) => error,
    };
    match take_payload::<OversizedExtension>(error) {
        Ok(refusal) => WalkError::Payload(refusal.into_payload()),
        Err(error) => WalkError::Payload(PayloadError::Io(error)),
    }
}

/// Recovers the `T` `error` carries as its payload, or returns `error`
/// unchanged.
fn take_payload<T: std::error::Error + Send + Sync + 'static>(
    error: io::Error,
) -> Result<T, io::Error> {
    let carries = error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<T>);
    if !carries {
        return Err(error);
    }
    let kind = error.kind();
    match error
        .into_inner()
        .map(<dyn std::error::Error + Send + Sync>::downcast)
    {
        Some(Ok(payload)) => Ok(*payload),
        // Unreachable: the payload was just seen to be this type.
        Some(Err(inner)) => Err(io::Error::new(kind, inner)),
        None => Err(io::Error::from(kind)),
    }
}

/// [`stream_error`] for a condition already turned into a [`PayloadError`].
fn payload_error<E>(error: PayloadError) -> WalkError<E> {
    match error {
        PayloadError::Io(error) => stream_error(error),
        other => WalkError::Payload(other),
    }
}

/// A limit a [`Meter`] enforced, carried across the tar and zstd readers as
/// an [`io::Error`] payload.
#[derive(Debug, thiserror::Error)]
#[error("the {resource} limit of {limit} was exceeded")]
struct OuterLimitFault {
    resource: LimitResource,
    limit: u64,
}

impl OuterLimitFault {
    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }
}

/// Returns the private allowance of framing bytes a bounded walk admitting
/// `members` members holds the decoded stream to: every header, extension
/// record, padding block and end marker that is no member's data.
pub(crate) fn framing_allowance(members: u64) -> u64 {
    // `OuterMembers` never exceeds its default, so this cannot overflow; if it
    // could, the allowance would still be finite.
    members
        .checked_add(FRAMING_EXTRA_SLOTS)
        .and_then(|slots| slots.checked_mul(FRAMING_PER_SLOT))
        .unwrap_or(u64::MAX)
}

/// What a bounded walk has read so far, shared by the [`Meter`] under the tar
/// reader and the [`MemberStream`] a sink reads through.
struct OuterCounters {
    /// Whether the read in progress is a sink reading member data.
    in_member: Cell<bool>,
    member_bytes: Cell<u64>,
    framing_bytes: Cell<u64>,
    member_limit: u64,
    framing_limit: u64,
    members_limit: u64,
}

impl OuterCounters {
    fn new(limits: &OuterLimits) -> OuterCounters {
        OuterCounters {
            in_member: Cell::new(false),
            member_bytes: Cell::new(0),
            framing_bytes: Cell::new(0),
            member_limit: limits.uncompressed_total,
            framing_limit: framing_allowance(limits.members),
            members_limit: limits.members,
        }
    }

    /// Returns the framing bytes left of the allowance.
    fn framing_room(&self) -> u64 {
        self.framing_limit.saturating_sub(self.framing_bytes.get())
    }

    /// Charges `len` bytes to `counter`, which the caller has checked the
    /// allowance holds, so the sum stays at or below a `u64` limit.
    fn charge(counter: &Cell<u64>, len: u64) {
        counter.set(counter.get().saturating_add(len));
    }
}

/// Meters every decoded byte of a bounded walk: the data an admitted member's
/// sink reads against `OuterUncompressedTotal`, and everything else against
/// the private framing allowance, whose structure [`Framing`] follows. No
/// request exceeds the copy buffer, and none reaches more than one byte past
/// either allowance: a byte arriving beyond it is the fault. An extension
/// record the framing allowance cannot hold is read here, past the archive
/// reader, and refused for what it overrides.
struct Meter<'c, R> {
    inner: R,
    counters: &'c OuterCounters,
    copy_buffer: usize,
    framing: Framing,
}

impl<R: Read> Read for Meter<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let counters = self.counters;
        if self.framing.scanning() {
            return Err(self.refuse_extension()?);
        }
        let in_member = counters.in_member.get();
        let (counter, limit) = if in_member {
            (&counters.member_bytes, counters.member_limit)
        } else {
            (&counters.framing_bytes, counters.framing_limit)
        };
        let allowance = limit.saturating_sub(counter.get());
        let room = counters.framing_room();
        let want =
            crate::content::chunk_len(buf.len().min(self.copy_buffer), allowance.saturating_add(1));
        let Some(window) = buf.get_mut(..want) else {
            return Ok(0);
        };
        let read = self.inner.read(window)?;
        let read_len = crate::content::widen(read);
        if read_len > allowance {
            return Err(if in_member {
                OuterLimitFault {
                    resource: LimitResource::OuterUncompressedTotal,
                    limit: counters.member_limit,
                }
                .into_io()
            } else {
                framing::exceeded(counters.framing_limit)
            });
        }
        OuterCounters::charge(counter, read_len);
        self.framing
            .advance(window.get(..read).unwrap_or_default(), room);
        Ok(read)
    }
}

impl<R: Read> Meter<'_, R> {
    /// Reads the extension record [`Framing`] is scanning, within what is
    /// left of the framing allowance and never into the archive reader's
    /// buffer, and returns its refusal. Only a failure of the stream itself
    /// is returned as `Err`, unclassified, as any other read's would be.
    fn refuse_extension(&mut self) -> io::Result<io::Error> {
        let counters = self.counters;
        let mut scratch = [0u8; SCAN_CHUNK];
        let chunk = SCAN_CHUNK.min(self.copy_buffer);
        loop {
            let wanted = self.framing.wanted().min(counters.framing_room());
            let want = crate::content::chunk_len(chunk, wanted);
            let Some(window) = scratch.get_mut(..want).filter(|window| !window.is_empty()) else {
                break;
            };
            let read = self.inner.read(window)?;
            if read == 0 {
                break;
            }
            OuterCounters::charge(&counters.framing_bytes, crate::content::widen(read));
            self.framing.feed(window.get(..read).unwrap_or_default());
        }
        Ok(self.framing.conclude(counters.framing_limit))
    }
}

/// A member's data as a sink reads it, marking the reads as member data for a
/// bounded walk's [`Meter`].
struct MemberStream<'e, 'c, R> {
    entry: &'e mut R,
    counters: Option<&'c OuterCounters>,
}

impl<R: Read> Read for MemberStream<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(counters) = self.counters else {
            return self.entry.read(buf);
        };
        counters.in_member.set(true);
        let result = self.entry.read(buf);
        counters.in_member.set(false);
        result
    }
}

/// A frame the [`WindowGuard`] cannot read the window of before the decoder
/// would act on it, carried as an [`io::Error`] payload.
#[derive(Debug, thiserror::Error)]
#[error("the archive block holds a zstd frame whose window cannot be read before decoding")]
struct UnreadableFrame;

impl UnreadableFrame {
    fn into_io() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, UnreadableFrame)
    }
}

/// A zstd structure the [`WindowGuard`] collects whole before acting on it.
#[derive(Clone, Copy, Debug)]
enum Field {
    /// A frame's magic number.
    Magic,
    /// A standard frame's descriptor.
    Descriptor,
    /// The rest of a standard frame's header, which `descriptor` lays out.
    Header { descriptor: u8 },
    /// A block header, in a frame that does or does not end in a checksum.
    Block { checksum: bool },
    /// A skippable frame's length.
    SkippableLength,
}

impl Field {
    /// Returns how many bytes the field spans, never zero.
    fn len(self) -> usize {
        match self {
            Field::Magic | Field::SkippableLength => ZSTD_FRAME_MAGIC.len(),
            Field::Descriptor => 1,
            Field::Header { descriptor } => {
                let window_descriptor = usize::from(descriptor & ZSTD_SINGLE_SEGMENT == 0);
                window_descriptor + dictionary_len(descriptor) + content_size_len(descriptor)
            }
            Field::Block { .. } => ZSTD_BLOCK_HEADER_LEN,
        }
    }
}

/// Where a [`WindowGuard`] stands in the compressed stream.
#[derive(Debug)]
enum Scan {
    /// Collecting `field`, of which the first `have` bytes are in `bytes`.
    Collect {
        field: Field,
        bytes: [u8; ZSTD_MAX_FIELD_LEN],
        have: usize,
    },
    /// Passing `remaining` bytes of block content, checksum or skippable
    /// payload, then collecting `next`.
    Skip { remaining: u64, next: Field },
}

impl Scan {
    fn collect(field: Field) -> Scan {
        Scan::Collect {
            field,
            bytes: [0; ZSTD_MAX_FIELD_LEN],
            have: 0,
        }
    }

    fn skip(remaining: u64, next: Field) -> Scan {
        if remaining == 0 {
            Scan::collect(next)
        } else {
            Scan::Skip { remaining, next }
        }
    }
}

/// The compressed archive block as the decoder reads it, with every frame's
/// declared window checked against `ZstdWindow` before the decoder is handed
/// the header that declares it.
///
/// The guard follows the stream's structure as the bytes pass — frame
/// headers, block headers, block content, checksums and skippable frames —
/// without decoding any of it, so the first frame and every later one are
/// held to the same limit and named by it. A frame whose window it cannot
/// read — a legacy zstd format, or a reserved descriptor bit or block type —
/// is refused as [`UnreadableFrame`] rather than left to a decoder that might
/// size a window for it. The decoder's own window cap, set from the same
/// limit, stays underneath. No request exceeds the copy buffer, and nothing
/// but the current field, at most a frame header's worth, is held.
#[derive(Debug)]
struct WindowGuard<R> {
    inner: R,
    limit: u64,
    copy_buffer: usize,
    scan: Scan,
}

impl<R> WindowGuard<R> {
    fn new(inner: R, limits: &OuterLimits) -> WindowGuard<R> {
        WindowGuard {
            inner,
            limit: limits.zstd_window,
            copy_buffer: limits.copy_buffer,
            scan: Scan::collect(Field::Magic),
        }
    }

    /// Follows the stream over a prefix of `input` and returns its length,
    /// which is nonzero for a nonempty `input`.
    fn advance(&mut self, input: &[u8]) -> io::Result<usize> {
        match &mut self.scan {
            Scan::Skip { remaining, next } => {
                let used = crate::content::chunk_len(input.len(), *remaining);
                *remaining = remaining.saturating_sub(crate::content::widen(used));
                if *remaining == 0 {
                    self.scan = Scan::collect(*next);
                }
                Ok(used)
            }
            Scan::Collect { field, bytes, have } => {
                let need = field.len();
                let used = need.saturating_sub(*have).min(input.len());
                let end = have.saturating_add(used);
                if let (Some(slot), Some(taken)) = (bytes.get_mut(*have..end), input.get(..used)) {
                    slot.copy_from_slice(taken);
                }
                *have = end;
                if end >= need {
                    let (field, bytes) = (*field, *bytes);
                    self.scan = complete(field, bytes.get(..need).unwrap_or_default(), self.limit)?;
                }
                Ok(used)
            }
        }
    }
}

impl<R: Read> Read for WindowGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf.len().min(self.copy_buffer);
        let Some(window) = buf.get_mut(..want) else {
            return Ok(0);
        };
        let read = self.inner.read(window)?;
        let mut rest = window.get(..read).unwrap_or_default();
        while !rest.is_empty() {
            let used = self.advance(rest)?;
            rest = rest.get(used..).unwrap_or_default();
        }
        Ok(read)
    }
}

/// Acts on a field [`WindowGuard`] has collected whole, returning what comes
/// next.
fn complete(field: Field, bytes: &[u8], limit: u64) -> io::Result<Scan> {
    match field {
        Field::Magic => {
            if bytes == ZSTD_FRAME_MAGIC {
                Ok(Scan::collect(Field::Descriptor))
            } else if is_skippable_magic(bytes) {
                Ok(Scan::collect(Field::SkippableLength))
            } else {
                Err(UnreadableFrame::into_io())
            }
        }
        Field::Descriptor => match bytes.first() {
            Some(&descriptor) if descriptor & ZSTD_RESERVED_DESCRIPTOR_BIT == 0 => {
                Ok(Scan::collect(Field::Header { descriptor }))
            }
            _ => Err(UnreadableFrame::into_io()),
        },
        Field::Header { descriptor } => {
            if frame_window(descriptor, bytes) > limit {
                return Err(OuterLimitFault {
                    resource: LimitResource::ZstdWindow,
                    limit,
                }
                .into_io());
            }
            Ok(Scan::collect(Field::Block {
                checksum: descriptor & ZSTD_CHECKSUM_FLAG != 0,
            }))
        }
        Field::Block { checksum } => {
            let header = le_u64(bytes);
            let size = header >> 3;
            let content = match (header >> 1) & 0x03 {
                // Raw and compressed blocks carry `size` bytes; an RLE block
                // carries the one byte it repeats.
                0 | 2 => size,
                1 => 1,
                _ => return Err(UnreadableFrame::into_io()),
            };
            if header & 1 == 0 {
                Ok(Scan::skip(content, Field::Block { checksum }))
            } else {
                let trailer = if checksum { ZSTD_CHECKSUM_LEN } else { 0 };
                Ok(Scan::skip(content.saturating_add(trailer), Field::Magic))
            }
        }
        Field::SkippableLength => Ok(Scan::skip(le_u64(bytes), Field::Magic)),
    }
}

/// Returns whether `magic` opens a skippable frame, `0x184D2A5?`.
fn is_skippable_magic(magic: &[u8]) -> bool {
    matches!(magic, [low, rest @ ..] if low & 0xf0 == 0x50 && rest == ZSTD_SKIPPABLE_MAGIC_HIGH)
}

/// Returns the window a standard frame declares, from its descriptor and the
/// header fields after it.
fn frame_window(descriptor: u8, fields: &[u8]) -> u64 {
    if descriptor & ZSTD_SINGLE_SEGMENT == 0 {
        let window_descriptor = fields.first().copied().unwrap_or_default();
        let window_log = ZSTD_WINDOW_LOG_BASE + u32::from(window_descriptor >> 3);
        let base = 1u64.checked_shl(window_log).unwrap_or(u64::MAX);
        base.saturating_add((base / 8).saturating_mul(u64::from(window_descriptor & 0x07)))
    } else {
        // A single-segment frame's window is its content size.
        let size = fields.get(dictionary_len(descriptor)..).unwrap_or_default();
        let value = le_u64(size);
        if size.len() == 2 {
            value.saturating_add(ZSTD_FCS_TWO_BYTE_OFFSET)
        } else {
            value
        }
    }
}

/// Returns the length of the dictionary ID a frame descriptor announces.
fn dictionary_len(descriptor: u8) -> usize {
    match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    }
}

/// Returns the length of the content size a frame descriptor announces.
fn content_size_len(descriptor: u8) -> usize {
    match descriptor >> 6 {
        0 => usize::from(descriptor & ZSTD_SINGLE_SEGMENT != 0),
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

/// Reads up to eight bytes as a little-endian integer.
fn le_u64(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, &byte| (value << 8) | u64::from(byte))
}

#[cfg(test)]
mod tests;
