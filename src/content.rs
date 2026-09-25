//! Bounded tar, gzip and JSON primitives, and the one fault vocabulary they
//! share.
//!
//! Two consumers read the same kinds of content: the image-archive validator,
//! which checks a docker-save tar and the layer tars nested inside it, and the
//! package verification and writer pipeline, which enforces one
//! [`ContentLimits`](crate::package::ContentLimits) policy over whole packages.
//! Both are built on what this module provides, so the same bytes reach the
//! same verdict whichever of them reads them:
//!
//! - [`CountingReader`], the only way any primitive reads a caller's source,
//!   which charges every byte to an ordered chain of [`Budget`]s and faults at
//!   the first byte actually read beyond one of them;
//! - [`TarWalker`], a pull-based walker over raw 512-byte tar headers with an
//!   image-archive policy and a layer policy;
//! - [`GzipDecoder`], a single-member gzip decoder bounded on both its stored
//!   and its decoded bytes;
//! - [`json::read_bounded`] and [`json::parse`], which read a JSON document
//!   under a byte limit and refuse duplicate keys and excess nesting before
//!   deserializing it.
//!
//! Every primitive reports one [`ContentFault`], classified as a limit, a
//! malformation, an unsupported form or a source I/O failure. The first fault
//! in stream order wins, several limits hit by the same byte resolve to the
//! narrowest scope, and a fault is terminal: a primitive that has reported one
//! reports the same one again and yields nothing more.

use std::error::Error;
use std::io;

use crate::package::LimitResource;

mod counting;
#[cfg(test)]
mod fixture;
mod gzip;
pub(crate) mod json;
mod walker;

// The consumers' vocabulary. Unused outside the tests until the image-archive
// validator and the package pipeline land on these primitives.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use counting::{Budget, CountingReader, alloc_len, charge_all};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use gzip::GzipDecoder;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use walker::{EntryKind, EntryPolicy, EntryReader, TarEntry, TarWalker};

/// One limit handed to a primitive: the resource it bounds and that resource's
/// configured value.
///
/// Every per-item limit travels in this form, so a fault names the resource it
/// hit even when two resources share one primitive — `IndexJson` and
/// `ConfigJson` both pass through the one JSON reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceLimit {
    /// The resource bounded.
    pub(crate) resource: LimitResource,
    /// Its configured value.
    pub(crate) max: u64,
}

impl ResourceLimit {
    /// Returns the fault reporting this limit exceeded.
    pub(crate) fn exceeded(self) -> ContentFault {
        ContentFault::LimitExceeded {
            resource: self.resource,
            limit: self.max,
        }
    }
}

/// The one fault every content primitive reports.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ContentFault {
    /// The next operation would exceed a configured resource. Reported before
    /// anything beyond the limit is delivered, allocated or expanded.
    #[error("the {resource} limit of {limit} was exceeded")]
    LimitExceeded {
        /// The resource whose limit was reached.
        resource: LimitResource,
        /// That resource's configured value.
        limit: u64,
    },
    /// The input is a supported format that is malformed, truncated or
    /// internally inconsistent.
    #[error("malformed content: {0}")]
    Malformed(MalformedReason),
    /// The input is a recognizable form this profile excludes. Reported as
    /// soon as it is recognized; the content is never decoded further.
    #[error("unsupported content: {0}")]
    Unsupported(UnsupportedFeature),
    /// A caller's source failed during an allowed read.
    #[error("reading the content source failed")]
    Io(#[source] io::Error),
}

impl ContentFault {
    /// Wraps this fault as the payload of an [`io::Error`], the form it takes
    /// to cross a [`Read`](io::Read) boundary.
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// Recovers the fault an [`io::Error`] carries as its payload, or treats
    /// any other error as the failure of a caller's source.
    ///
    /// The payload is identified by type alone. Nothing inspects an
    /// [`io::ErrorKind`] or a message to classify an error.
    pub(crate) fn from_io(err: io::Error) -> ContentFault {
        let carries_fault = err
            .get_ref()
            .is_some_and(<dyn Error + Send + Sync>::is::<ContentFault>);
        if !carries_fault {
            return ContentFault::Io(err);
        }
        match err
            .into_inner()
            .map(<dyn Error + Send + Sync>::downcast::<ContentFault>)
        {
            Some(Ok(fault)) => *fault,
            // Unreachable: the payload was just seen to be a `ContentFault`.
            // Reported as the source failure it would otherwise be rather than
            // trusted to an `expect`.
            Some(Err(inner)) => ContentFault::Io(io::Error::other(inner)),
            None => ContentFault::Io(io::Error::other("content fault payload vanished")),
        }
    }
}

/// Why a supported format was refused as malformed.
///
/// Each variant is one distinct cause. None carries raw content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MalformedReason {
    /// The input ended inside a structure that must be complete.
    #[error("the input ends early")]
    Truncated,
    /// A tar header's checksum does not match its bytes.
    #[error("a tar header checksum does not match")]
    TarChecksum,
    /// A tar header numeric field breaks its lexical rule.
    #[error("the tar header {field} field is not a valid number")]
    TarNumericField {
        /// The offending field.
        field: TarField,
    },
    /// A tar header name field has a non-NUL byte after its first NUL.
    #[error("the tar header {field} field has bytes after its terminator")]
    TarNameField {
        /// The offending field.
        field: TarField,
    },
    /// A tar entry's data or padding end does not fit in a `u64` offset.
    #[error("a tar entry's end offset overflows")]
    OffsetOverflow,
    /// A nonzero byte follows the start of the tar end-of-archive marker.
    #[error("nonzero bytes follow the end of the tar archive")]
    TrailingData,
    /// The zero tail after a tar archive is longer than the format allows.
    #[error("the zero tail after the tar archive is too long")]
    ZeroTailTooLong,
    /// A tar entry name or hardlink target is not a safe relative path.
    #[error("a tar entry path is unsafe")]
    UnsafePath,
    /// Two tar entries have the same canonical name and kind.
    #[error("a tar entry path is repeated")]
    DuplicatePath,
    /// Two tar entries claim one path as different kinds, or a file is used
    /// as a directory.
    #[error("tar entry paths conflict")]
    PathConflict,
    /// A tar entry that is not a regular file carries data.
    #[error("a non-regular tar entry carries data")]
    NonRegularWithData,
    /// A PAX extended-header record breaks the record grammar.
    #[error("a PAX record is malformed")]
    PaxRecord,
    /// One PAX extended header repeats a key.
    #[error("a PAX key is repeated")]
    PaxDuplicateKey,
    /// A PAX value breaks the grammar of its key.
    #[error("the PAX {key} value is malformed")]
    PaxValue {
        /// The key whose value was refused.
        key: PaxKey,
    },
    /// A GNU long-name or long-link payload has an interior NUL.
    #[error("a GNU long-name or long-link payload is malformed")]
    ExtensionPayload,
    /// A second extension record of one kind precedes the same entry.
    #[error("a tar extension record is repeated for one entry")]
    DuplicateExtension,
    /// A PAX record and a GNU record both supply a name, or both a link target.
    #[error("two tar extension records supply the same value")]
    ConflictingAuthority,
    /// An extension record is followed by the end of the archive rather than
    /// the entry it applies to.
    #[error("a tar extension record applies to no entry")]
    DanglingExtension,
    /// A link target is supplied for an entry that is not a link.
    #[error("a link target is supplied for a tar entry that is not a link")]
    LinkOnNonLink,
    /// A gzip member header is malformed.
    #[error("the gzip header is malformed: {0}")]
    GzipHeader(GzipHeaderFault),
    /// A gzip member's DEFLATE stream is malformed.
    #[error("the gzip DEFLATE stream is malformed")]
    DeflateData,
    /// A gzip member's CRC32 does not match its decoded bytes.
    #[error("the gzip CRC32 does not match")]
    GzipCrc32,
    /// A gzip member's ISIZE does not match its decoded length.
    #[error("the gzip ISIZE does not match")]
    GzipIsize,
    /// Bytes other than a second gzip member follow the member's trailer.
    #[error("bytes follow the gzip trailer")]
    GzipTrailingData,
    /// A JSON document breaks the RFC 8259 grammar or is not UTF-8.
    #[error("a JSON document is not valid JSON")]
    JsonSyntax,
    /// A JSON object repeats a key.
    #[error("a JSON object repeats a key")]
    JsonDuplicateKey,
    /// A JSON document does not have the expected shape.
    #[error("a JSON document does not have the expected shape")]
    JsonShape,
}

/// Which gzip header check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GzipHeaderFault {
    /// The first two bytes are not `1f 8b`.
    #[error("bad magic")]
    Magic,
    /// The compression method is not DEFLATE.
    #[error("unknown compression method")]
    Method,
    /// A reserved flag bit is set.
    #[error("reserved flag set")]
    ReservedFlags,
    /// The header CRC does not match the header bytes.
    #[error("header CRC mismatch")]
    HeaderCrc,
}

/// A recognizable form the profile excludes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UnsupportedFeature {
    /// A tar header with a valid checksum but neither ustar nor GNU magic,
    /// including a v7 header.
    #[error("unsupported tar format")]
    TarFormat,
    /// A tar entry type the policy excludes.
    #[error("unsupported tar entry type {flag:#04x}")]
    EntryType {
        /// The header's typeflag byte.
        flag: u8,
    },
    /// A PAX key outside the permitted set.
    #[error("unsupported PAX key")]
    PaxKey,
    /// A second gzip member follows the first.
    #[error("concatenated gzip member")]
    ConcatenatedGzipMember,
}

/// A tar header field, as named by POSIX ustar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TarField {
    Name,
    Mode,
    Uid,
    Gid,
    Size,
    Mtime,
    Checksum,
    Linkname,
    DevMajor,
    DevMinor,
    Prefix,
}

impl std::fmt::Display for TarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TarField::Name => "name",
            TarField::Mode => "mode",
            TarField::Uid => "uid",
            TarField::Gid => "gid",
            TarField::Size => "size",
            TarField::Mtime => "mtime",
            TarField::Checksum => "checksum",
            TarField::Linkname => "linkname",
            TarField::DevMajor => "devmajor",
            TarField::DevMinor => "devminor",
            TarField::Prefix => "prefix",
        })
    }
}

/// A permitted PAX key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaxKey {
    Path,
    Linkpath,
    Size,
    Uid,
    Gid,
    Uname,
    Gname,
    Mtime,
    Atime,
    Ctime,
    /// Any key beginning `SCHILY.xattr.`.
    Xattr,
}

impl std::fmt::Display for PaxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PaxKey::Path => "path",
            PaxKey::Linkpath => "linkpath",
            PaxKey::Size => "size",
            PaxKey::Uid => "uid",
            PaxKey::Gid => "gid",
            PaxKey::Uname => "uname",
            PaxKey::Gname => "gname",
            PaxKey::Mtime => "mtime",
            PaxKey::Atime => "atime",
            PaxKey::Ctime => "ctime",
            PaxKey::Xattr => "xattr",
        })
    }
}

/// The first fault a primitive reported, kept so every later call reports it
/// again.
///
/// An [`io::Error`] cannot be cloned, so a source failure is kept as its
/// [`io::ErrorKind`] and replayed as a fresh error of that kind.
#[derive(Debug, Default)]
pub(crate) struct Latch(Option<Replay>);

#[derive(Clone, Copy, Debug)]
enum Replay {
    Limit { resource: LimitResource, limit: u64 },
    Malformed(MalformedReason),
    Unsupported(UnsupportedFeature),
    Io(io::ErrorKind),
}

impl Latch {
    /// Returns the latched fault again, if there is one.
    pub(crate) fn check(&self) -> Result<(), ContentFault> {
        match self.0 {
            None => Ok(()),
            Some(Replay::Limit { resource, limit }) => {
                Err(ContentFault::LimitExceeded { resource, limit })
            }
            Some(Replay::Malformed(reason)) => Err(ContentFault::Malformed(reason)),
            Some(Replay::Unsupported(feature)) => Err(ContentFault::Unsupported(feature)),
            Some(Replay::Io(kind)) => Err(ContentFault::Io(io::Error::from(kind))),
        }
    }

    /// Latches `fault` unless a fault is already latched, and returns it.
    pub(crate) fn record(&mut self, fault: ContentFault) -> ContentFault {
        if self.0.is_none() {
            self.0 = Some(match &fault {
                ContentFault::LimitExceeded { resource, limit } => Replay::Limit {
                    resource: *resource,
                    limit: *limit,
                },
                ContentFault::Malformed(reason) => Replay::Malformed(*reason),
                ContentFault::Unsupported(feature) => Replay::Unsupported(*feature),
                ContentFault::Io(err) => Replay::Io(err.kind()),
            });
        }
        fault
    }
}

/// Widens a length to `u64`, saturating on a target where `usize` is wider,
/// where the saturated value exceeds every limit anyway.
pub(crate) fn widen(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Returns the lesser of a buffer length and a remaining allowance, as a
/// length. An allowance too large for `usize` cannot be the lesser.
pub(crate) fn chunk_len(len: usize, allowance: u64) -> usize {
    usize::try_from(allowance).map_or(len, |allowance| allowance.min(len))
}

/// Fills `buf` from `source`, where anything short of full is truncation.
pub(crate) fn read_full<R: io::Read>(source: &mut R, buf: &mut [u8]) -> Result<(), ContentFault> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = source
            .read(&mut buf[filled..])
            .map_err(ContentFault::from_io)?;
        if n == 0 {
            return Err(ContentFault::Malformed(MalformedReason::Truncated));
        }
        filled += n;
    }
    Ok(())
}

#[cfg(test)]
impl PartialEq for ContentFault {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                ContentFault::LimitExceeded { resource, limit },
                ContentFault::LimitExceeded {
                    resource: other_resource,
                    limit: other_limit,
                },
            ) => resource == other_resource && limit == other_limit,
            (ContentFault::Malformed(a), ContentFault::Malformed(b)) => a == b,
            (ContentFault::Unsupported(a), ContentFault::Unsupported(b)) => a == b,
            (ContentFault::Io(a), ContentFault::Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind};

    use super::{
        ContentFault, GzipHeaderFault, Latch, MalformedReason, PaxKey, TarField, UnsupportedFeature,
    };
    use crate::package::LimitResource;

    fn every_fault() -> Vec<ContentFault> {
        vec![
            ContentFault::LimitExceeded {
                resource: LimitResource::ConfigJson,
                limit: 7,
            },
            ContentFault::Malformed(MalformedReason::TarNumericField {
                field: TarField::Size,
            }),
            ContentFault::Malformed(MalformedReason::PaxValue { key: PaxKey::Mtime }),
            ContentFault::Malformed(MalformedReason::GzipHeader(GzipHeaderFault::HeaderCrc)),
            ContentFault::Unsupported(UnsupportedFeature::EntryType { flag: b'S' }),
            ContentFault::Unsupported(UnsupportedFeature::ConcatenatedGzipMember),
            ContentFault::Io(io::Error::from(ErrorKind::BrokenPipe)),
        ]
    }

    #[test]
    fn every_fault_survives_the_read_boundary() {
        for fault in every_fault() {
            let expected = format!("{fault:?}");
            let recovered = ContentFault::from_io(fault.into_io());
            assert_eq!(format!("{recovered:?}"), expected);
        }
    }

    #[test]
    fn a_plain_io_error_is_a_source_failure() {
        let recovered = ContentFault::from_io(io::Error::other("disk on fire"));
        assert!(matches!(&recovered, ContentFault::Io(err) if err.kind() == ErrorKind::Other));
        // Even an error whose kind and text mimic a limit is only a source
        // failure: nothing classifies by kind or message.
        let mimic = io::Error::other("the config json limit of 7 was exceeded");
        assert!(matches!(ContentFault::from_io(mimic), ContentFault::Io(_)));
    }

    #[test]
    fn a_latch_replays_the_first_fault() {
        for fault in every_fault() {
            let mut latch = Latch::default();
            assert!(latch.check().is_ok());
            let first = latch.record(fault);
            let later = latch.record(ContentFault::Malformed(MalformedReason::Truncated));
            assert_eq!(later, ContentFault::Malformed(MalformedReason::Truncated));
            assert_eq!(latch.check().unwrap_err(), first);
            assert_eq!(latch.check().unwrap_err(), first);
        }
    }
}
