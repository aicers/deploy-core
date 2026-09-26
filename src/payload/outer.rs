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
//! always had. A caller that passes them also gets the zstd window checked
//! before decoding, the member count bounded, and every decoded byte metered:
//! member data against `OuterUncompressedTotal`, and the framing between the
//! members — headers, extension records, padding and the end marker — against
//! a fixed allowance per member slot, reported against that same resource, so
//! an extension record cannot grow into a buffer the size of the archive.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader, Cursor, Read};

use tar::Archive;
use zstd::Decoder;

use super::{PayloadError, admitted_member_path, compare_member_list, reject_trailing_bytes};
use crate::manifest::{ArchiveMember, PayloadArtifact, PayloadManifest};
use crate::package::LimitResource;

/// The magic number opening a standard zstd frame, little-endian.
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
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
    mut archive: R,
    manifest: &'m PayloadManifest,
    limits: Option<&OuterLimits>,
    sink: &mut S,
) -> Result<(), WalkError<S::Error>> {
    let Some(limits) = limits else {
        let decoder = Decoder::new(archive).map_err(stream_error)?;
        return walk_entries(decoder, manifest, None, sink);
    };
    let peeked = check_zstd_window(&mut archive, limits.zstd_window)?;
    let buffered = BufReader::with_capacity(limits.copy_buffer, Cursor::new(peeked).chain(archive));
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
/// becomes [`WalkError::Limit`], and anything else is the
/// [`PayloadError::Io`] the legacy walk reports. Only the payload's type
/// decides.
fn stream_error<E>(error: io::Error) -> WalkError<E> {
    match OuterLimitFault::recover(error) {
        Ok(fault) => WalkError::Limit {
            resource: fault.resource,
            limit: fault.limit,
        },
        Err(error) => WalkError::Payload(PayloadError::Io(error)),
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

    /// Recovers the fault `error` carries as its payload, or returns `error`
    /// unchanged.
    fn recover(error: io::Error) -> Result<OuterLimitFault, io::Error> {
        let carries = error
            .get_ref()
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<OuterLimitFault>);
        if !carries {
            return Err(error);
        }
        let kind = error.kind();
        match error
            .into_inner()
            .map(<dyn std::error::Error + Send + Sync>::downcast)
        {
            Some(Ok(fault)) => Ok(*fault),
            // Unreachable: the payload was just seen to be this type.
            Some(Err(inner)) => Err(io::Error::new(kind, inner)),
            None => Err(io::Error::from(kind)),
        }
    }
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
            framing_limit: limits
                .members
                .saturating_add(FRAMING_EXTRA_SLOTS)
                .saturating_mul(FRAMING_PER_SLOT),
            members_limit: limits.members,
        }
    }
}

/// Meters every decoded byte of a bounded walk: member data against
/// `OuterUncompressedTotal`, and everything else against the framing
/// allowance. No request exceeds the copy buffer, and none reaches more than
/// one byte past the allowance: a byte arriving beyond it is the fault.
struct Meter<'c, R> {
    inner: R,
    counters: &'c OuterCounters,
    copy_buffer: usize,
}

impl<R: Read> Read for Meter<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let counters = self.counters;
        let (counter, limit) = if counters.in_member.get() {
            (&counters.member_bytes, counters.member_limit)
        } else {
            (&counters.framing_bytes, counters.framing_limit)
        };
        let allowance = limit.saturating_sub(counter.get());
        let want =
            crate::content::chunk_len(buf.len().min(self.copy_buffer), allowance.saturating_add(1));
        let Some(window) = buf.get_mut(..want) else {
            return Ok(0);
        };
        let read = self.inner.read(window)?;
        let read_len = crate::content::widen(read);
        if read_len > allowance {
            return Err(OuterLimitFault {
                resource: LimitResource::OuterUncompressedTotal,
                limit: counters.member_limit,
            }
            .into_io());
        }
        counter.set(counter.get().saturating_add(read_len));
        Ok(read)
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

/// Reads the first zstd frame header off `archive` and refuses a declared
/// window above `limit`, before any byte is decoded. Returns the bytes read,
/// which the decoder is handed first.
///
/// A stream that does not open with a standard frame — a skippable frame, or
/// no frame at all — is left to the decoder, whose own window cap still
/// applies. So is every frame after the first: one declaring a larger window
/// is still never decoded, but is refused by the decoder as a
/// [`PayloadError::Io`] rather than named as the limit.
fn check_zstd_window<R: Read, E>(archive: &mut R, limit: u64) -> Result<Vec<u8>, WalkError<E>> {
    let mut peeked = Vec::new();
    let head = take(archive, &mut peeked, ZSTD_FRAME_MAGIC.len() + 1)?;
    let (Some(magic), Some(&descriptor)) = (head.get(..ZSTD_FRAME_MAGIC.len()), head.get(4)) else {
        return Ok(peeked);
    };
    if magic != ZSTD_FRAME_MAGIC {
        return Ok(peeked);
    }
    let fcs_flag = descriptor >> 6;
    let single_segment = descriptor & 0x20 != 0;
    let window = if single_segment {
        let dictionary_len = match descriptor & 0x03 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let fcs_len = match fcs_flag {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let field = take(archive, &mut peeked, dictionary_len + fcs_len)?;
        let Some(fcs) = field.get(dictionary_len..) else {
            return Ok(peeked);
        };
        let mut value = [0u8; 8];
        let Some(slot) = value.get_mut(..fcs.len()) else {
            return Ok(peeked);
        };
        slot.copy_from_slice(fcs);
        let value = u64::from_le_bytes(value);
        if fcs_len == 2 {
            value.saturating_add(ZSTD_FCS_TWO_BYTE_OFFSET)
        } else {
            value
        }
    } else {
        let field = take(archive, &mut peeked, 1)?;
        let Some(&descriptor) = field.first() else {
            return Ok(peeked);
        };
        let window_log = ZSTD_WINDOW_LOG_BASE + u32::from(descriptor >> 3);
        let base = 1u64.checked_shl(window_log).unwrap_or(u64::MAX);
        base.saturating_add((base / 8).saturating_mul(u64::from(descriptor & 0x07)))
    };
    if window > limit {
        return Err(WalkError::Limit {
            resource: LimitResource::ZstdWindow,
            limit,
        });
    }
    Ok(peeked)
}

/// Appends up to `n` more bytes of `source` to `peeked` and returns what was
/// appended, which is shorter only at the end of the stream.
fn take<'p, R: Read, E>(
    source: &mut R,
    peeked: &'p mut Vec<u8>,
    n: usize,
) -> Result<&'p [u8], WalkError<E>> {
    let start = peeked.len();
    let mut chunk = [0u8; 16];
    while peeked.len() - start < n {
        let want = (n - (peeked.len() - start)).min(chunk.len());
        let Some(window) = chunk.get_mut(..want) else {
            break;
        };
        match source.read(window) {
            Ok(0) => break,
            Ok(read) => peeked.extend_from_slice(window.get(..read).unwrap_or(window)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(stream_error(error)),
        }
    }
    Ok(peeked.get(start..).unwrap_or_default())
}
