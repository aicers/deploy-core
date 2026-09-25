//! A pull-based tar walker over raw 512-byte headers, with one policy for an
//! image archive and one for a layer.
//!
//! It reads headers itself rather than through `tar::Archive::entries`, which
//! consumes PAX and GNU extension headers without a trace: the image-archive
//! policy must refuse those headers, and the layer policy must account for
//! every extension byte.
//!
//! Both policies share the header checksum, the numeric and name field rules,
//! entry boundaries, and a finite zero tail — looser than the outer package
//! tar's exact end-marker rule, and applied only here. The walker never
//! rewrites a byte, never joins a name to a host path and never dereferences
//! one; hashing is the caller's, done beneath it over the original bytes.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read};

use super::{
    Budget, ContentFault, CountingReader, Latch, MalformedReason, PaxKey, ResourceLimit, TarField,
    UnsupportedFeature, alloc_len, chunk_len, read_full, widen,
};
use crate::package::{ContentLimits, LimitResource};

const BLOCK: usize = 512;
const BLOCK_U64: u64 = 512;

/// Shortest zero tail: the two-block end-of-archive marker.
const MIN_ZERO_TAIL: u64 = 2 * BLOCK_U64;
/// Longest zero tail, end marker included: 2,048 blocks. A fixed format rule of
/// this walker, not a [`LimitResource`].
const MAX_ZERO_TAIL: u64 = 1_048_576;

/// A field's place in the header block, as POSIX ustar lays it out.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    len: usize,
}

const NAME: Span = Span { start: 0, len: 100 };
const MODE: Span = Span { start: 100, len: 8 };
const UID: Span = Span { start: 108, len: 8 };
const GID: Span = Span { start: 116, len: 8 };
const SIZE: Span = Span {
    start: 124,
    len: 12,
};
const MTIME: Span = Span {
    start: 136,
    len: 12,
};
const CHECKSUM: Span = Span { start: 148, len: 8 };
const TYPEFLAG: usize = 156;
const LINKNAME: Span = Span {
    start: 157,
    len: 100,
};
const POSIX_MAGIC: Span = Span { start: 257, len: 6 };
const POSIX_VERSION: Span = Span { start: 263, len: 2 };
const GNU_MAGIC: Span = Span { start: 257, len: 8 };
const DEVMAJOR: Span = Span { start: 329, len: 8 };
const DEVMINOR: Span = Span { start: 337, len: 8 };
const PREFIX: Span = Span {
    start: 345,
    len: 155,
};

const POSIX_MAGIC_BYTES: &[u8] = b"ustar\0";
const POSIX_VERSION_BYTES: &[u8] = b"00";
const GNU_MAGIC_BYTES: &[u8] = b"ustar  \0";

/// Base-256 marker bit on a numeric field's first byte.
const BASE256_MARKER: u8 = 0x80;
/// Sign bit of a base-256 numeric field.
const BASE256_SIGN: u8 = 0x40;
/// Magnitude bits of a base-256 numeric field's first byte.
const BASE256_FIRST_MAGNITUDE: u8 = 0x3f;

const PAX_XATTR_PREFIX: &[u8] = b"SCHILY.xattr.";

type Block = [u8; BLOCK];

/// Which limits a [`TarWalker`] enforces on the entries it admits.
pub(crate) enum EntryPolicy<'b> {
    /// A docker-save container: only regular files and zero-length
    /// directories with canonical names. The walker owns the `ImageEntries`
    /// budget.
    ImageArchive,
    /// A container filesystem changeset: files, directories, links, devices
    /// and FIFOs, with bounded GNU long-name and long-link records and local
    /// PAX records.
    Layer {
        /// The `LayerEntries` budget, shared across one image's layers.
        entries: &'b mut Budget,
        /// The `LayerExtensionTotal` budget, shared across one image's layers.
        extension_total: &'b mut Budget,
    },
}

/// What a tar entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Regular,
    Hardlink,
    Symlink,
    CharDevice,
    BlockDevice,
    Directory,
    Fifo,
}

/// One real entry a [`TarWalker`] admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TarEntry {
    /// What the entry is.
    pub(crate) kind: EntryKind,
    /// Its effective name, byte for byte as its authority wrote it.
    pub(crate) name: Vec<u8>,
    /// Its effective link target, present on hardlinks and symlinks only.
    pub(crate) link_target: Option<Vec<u8>>,
    /// Its effective size.
    pub(crate) size: u64,
    /// Offset of its own header block from the start of the stream.
    pub(crate) header_offset: u64,
    /// Offset of its first data byte from the start of the stream.
    pub(crate) data_offset: u64,
    /// Length of its data.
    pub(crate) data_len: u64,
}

impl TarEntry {
    /// Returns the name with a single leading `./` and a single trailing `/`
    /// removed — the form two names are compared in.
    pub(crate) fn canonical_name(&self) -> &[u8] {
        let name = self.name.as_slice();
        let name = if name == b"." {
            &[]
        } else {
            name.strip_prefix(b"./").unwrap_or(name)
        };
        name.strip_suffix(b"/").unwrap_or(name)
    }
}

/// A pull-based walker over a tar stream.
///
/// [`next_entry`](Self::next_entry) yields each real entry in turn, and
/// [`entry_reader`](Self::entry_reader) streams the current entry's data. Any
/// data left unread is skipped before the next header is read. A fault is
/// terminal: every later call reports it again.
pub(crate) struct TarWalker<'s, 'b, R> {
    source: CountingReader<'s, R>,
    rules: Rules<'b>,
    copy_buffer: ResourceLimit,
    unread_data: u64,
    unread_padding: u64,
    skip: Vec<u8>,
    latch: Latch,
    finished: bool,
}

impl<'s, 'b, R: Read> TarWalker<'s, 'b, R> {
    /// Returns a walker over `source` applying `policy`, with the path,
    /// extension and buffer limits of `limits`.
    pub(crate) fn new(
        source: CountingReader<'s, R>,
        policy: EntryPolicy<'b>,
        limits: &ContentLimits,
    ) -> TarWalker<'s, 'b, R> {
        let rules = match policy {
            EntryPolicy::ImageArchive => Rules::Image(ImageRules {
                entries: Budget::new(limits.resource_limit(LimitResource::ImageEntries)),
                path: limits.resource_limit(LimitResource::ImagePathBytes),
                seen: BTreeMap::new(),
            }),
            EntryPolicy::Layer {
                entries,
                extension_total,
            } => Rules::Layer(LayerRules {
                entries,
                extension_total,
                extension: limits.resource_limit(LimitResource::LayerExtension),
                path: limits.resource_limit(LimitResource::LayerPathBytes),
                link: limits.resource_limit(LimitResource::LayerLinkTargetBytes),
                pending: Pending::default(),
            }),
        };
        TarWalker {
            source,
            rules,
            copy_buffer: limits.resource_limit(LimitResource::CopyBuffer),
            unread_data: 0,
            unread_padding: 0,
            skip: Vec::new(),
            latch: Latch::default(),
            finished: false,
        }
    }

    /// Returns the next real entry, or `None` once the end of the archive has
    /// been verified and the source consumed to its end.
    ///
    /// # Errors
    ///
    /// Returns the first [`ContentFault`] in stream order, and the same one on
    /// every later call.
    pub(crate) fn next_entry(&mut self) -> Result<Option<TarEntry>, ContentFault> {
        self.latch.check()?;
        if self.finished {
            return Ok(None);
        }
        self.advance().map_err(|fault| self.latch.record(fault))
    }

    /// Returns a reader over the current entry's data, bounded to its
    /// effective size.
    pub(crate) fn entry_reader(&mut self) -> EntryReader<'_, 's, 'b, R> {
        EntryReader { walker: self }
    }

    fn advance(&mut self) -> Result<Option<TarEntry>, ContentFault> {
        loop {
            self.skip_unread()?;
            let header_offset = self.source.position();
            let mut block = [0u8; BLOCK];
            read_full(&mut self.source, &mut block)?;
            if block.iter().all(|byte| *byte == 0) {
                if self.rules.has_pending() {
                    return Err(ContentFault::Malformed(MalformedReason::DanglingExtension));
                }
                self.finish_tail()?;
                self.finished = true;
                return Ok(None);
            }
            self.rules.count_header()?;
            verify_checksum(&block)?;
            let magic = read_magic(&block)?;
            let flag = block[TYPEFLAG];
            let typeflag = self.rules.classify(flag).ok_or(ContentFault::Unsupported(
                UnsupportedFeature::EntryType { flag },
            ))?;
            let header = parse_fields(&block, magic, flag)?;
            let data_offset = header_offset
                .checked_add(BLOCK_U64)
                .ok_or(ContentFault::Malformed(MalformedReason::OffsetOverflow))?;
            match typeflag {
                Typeflag::Extension(extension) => {
                    self.read_extension(extension, header.size, data_offset, flag)?;
                }
                Typeflag::Entry(kind) => {
                    let admitted = self.rules.admit(kind, header)?;
                    let padded = padded_len(data_offset, admitted.size)?;
                    self.source.check_available(padded)?;
                    self.unread_data = admitted.size;
                    self.unread_padding = padded - admitted.size;
                    return Ok(Some(TarEntry {
                        kind,
                        name: admitted.name,
                        link_target: admitted.link_target,
                        size: admitted.size,
                        header_offset,
                        data_offset,
                        data_len: admitted.size,
                    }));
                }
            }
        }
    }

    /// Reads, charges and records one layer extension record whose header has
    /// passed the lexical checks.
    fn read_extension(
        &mut self,
        extension: Extension,
        len: u64,
        data_offset: u64,
        flag: u8,
    ) -> Result<(), ContentFault> {
        let Rules::Layer(layer) = &mut self.rules else {
            // The image-archive policy classifies no typeflag as an extension.
            return Err(ContentFault::Unsupported(UnsupportedFeature::EntryType {
                flag,
            }));
        };
        layer.pending.refuse_duplicate(extension)?;
        if len > layer.extension.max {
            return Err(layer.extension.exceeded());
        }
        layer.extension_total.charge(len)?;
        let padded = padded_len(data_offset, len)?;
        self.source.check_available(padded)?;
        let mut payload = vec![0u8; alloc_len(len, layer.extension)?];
        read_full(&mut self.source, &mut payload)?;
        self.unread_padding = padded - len;
        layer.pending.record(extension, &payload)
    }

    /// Skips whatever data and padding of the current entry remain unread, in
    /// chunks of at most the copy buffer.
    fn skip_unread(&mut self) -> Result<(), ContentFault> {
        let mut left = self
            .unread_data
            .checked_add(self.unread_padding)
            .ok_or(ContentFault::Malformed(MalformedReason::OffsetOverflow))?;
        self.unread_data = 0;
        self.unread_padding = 0;
        if left > 0 && self.skip.is_empty() {
            self.skip = vec![0u8; alloc_len(self.copy_buffer.max, self.copy_buffer)?];
        }
        while left > 0 {
            let len = chunk_len(self.skip.len(), left);
            let n = self
                .source
                .read(&mut self.skip[..len])
                .map_err(ContentFault::from_io)?;
            if n == 0 {
                return Err(ContentFault::Malformed(MalformedReason::Truncated));
            }
            left = left.saturating_sub(widen(n));
        }
        Ok(())
    }

    /// Reads the zero tail from just after its first block to the end of the
    /// source, faulting at the first offending byte in stream order.
    fn finish_tail(&mut self) -> Result<(), ContentFault> {
        let mut tail = BLOCK_U64;
        let mut buf = [0u8; BLOCK];
        loop {
            // Never more than one byte past the longest tail.
            let request = chunk_len(BLOCK, (MAX_ZERO_TAIL + 1).saturating_sub(tail));
            let n = self
                .source
                .read(&mut buf[..request])
                .map_err(ContentFault::from_io)?;
            if n == 0 {
                return if tail >= MIN_ZERO_TAIL && tail.is_multiple_of(BLOCK_U64) {
                    Ok(())
                } else {
                    Err(ContentFault::Malformed(MalformedReason::Truncated))
                };
            }
            for byte in &buf[..n] {
                tail += 1;
                if tail > MAX_ZERO_TAIL {
                    return Err(ContentFault::Malformed(MalformedReason::ZeroTailTooLong));
                }
                if *byte != 0 {
                    return Err(ContentFault::Malformed(MalformedReason::TrailingData));
                }
            }
        }
    }

    fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, ContentFault> {
        if buf.is_empty() || self.unread_data == 0 {
            return Ok(0);
        }
        let len = chunk_len(buf.len(), self.unread_data);
        let n = self
            .source
            .read(&mut buf[..len])
            .map_err(ContentFault::from_io)?;
        if n == 0 {
            return Err(ContentFault::Malformed(MalformedReason::Truncated));
        }
        self.unread_data = self.unread_data.saturating_sub(widen(n));
        Ok(n)
    }
}

/// Streams the current entry's data, bounded to its effective size.
///
/// A fault here is the walker's fault: it is latched there and reported by
/// every later call to either.
pub(crate) struct EntryReader<'w, 's, 'b, R> {
    walker: &'w mut TarWalker<'s, 'b, R>,
}

impl<R: Read> Read for EntryReader<'_, '_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let walker = &mut *self.walker;
        walker.latch.check().map_err(ContentFault::into_io)?;
        walker
            .read_data(buf)
            .map_err(|fault| walker.latch.record(fault).into_io())
    }
}

/// Returns the padded length of `size` bytes of data starting at
/// `data_offset`, having checked that the data end and the padded end both fit
/// in a `u64` offset.
fn padded_len(data_offset: u64, size: u64) -> Result<u64, ContentFault> {
    let overflow = || ContentFault::Malformed(MalformedReason::OffsetOverflow);
    data_offset.checked_add(size).ok_or_else(overflow)?;
    let padded = size
        .checked_next_multiple_of(BLOCK_U64)
        .ok_or_else(overflow)?;
    data_offset.checked_add(padded).ok_or_else(overflow)?;
    Ok(padded)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Magic {
    Posix,
    Gnu,
}

#[derive(Clone, Copy)]
enum Typeflag {
    Entry(EntryKind),
    Extension(Extension),
}

#[derive(Clone, Copy)]
enum Extension {
    Pax,
    LongName,
    LongLink,
}

/// The lexically valid fields of one header that the policies consume.
struct HeaderFields {
    /// The joined header name: `prefix/name` in a POSIX header with a prefix.
    name: Vec<u8>,
    linkname: Vec<u8>,
    size: u64,
}

fn span(block: &Block, span: Span) -> &[u8] {
    block
        .get(span.start..span.start + span.len)
        .expect("every header span lies inside the 512-byte block")
}

/// Checks the header checksum against the unsigned byte sum, or the historical
/// signed one, counting the checksum field as spaces.
fn verify_checksum(block: &Block) -> Result<(), ContentFault> {
    let recorded = parse_octal(span(block, CHECKSUM))
        .filter(|(_, digits)| *digits > 0)
        .map(|(value, _)| value)
        .ok_or(ContentFault::Malformed(MalformedReason::TarNumericField {
            field: TarField::Checksum,
        }))?;
    let checksum = CHECKSUM.start..CHECKSUM.start + CHECKSUM.len;
    let bytes = block.iter().enumerate().map(|(offset, byte)| {
        if checksum.contains(&offset) {
            b' '
        } else {
            *byte
        }
    });
    // At most 512 × 255 either way, far inside both types.
    let unsigned: u64 = bytes.clone().map(u64::from).sum();
    let signed: i64 = bytes.map(|byte| i64::from(i8::from_ne_bytes([byte]))).sum();
    if recorded == unsigned || i64::try_from(recorded).is_ok_and(|recorded| recorded == signed) {
        Ok(())
    } else {
        Err(ContentFault::Malformed(MalformedReason::TarChecksum))
    }
}

fn read_magic(block: &Block) -> Result<Magic, ContentFault> {
    if span(block, POSIX_MAGIC) == POSIX_MAGIC_BYTES
        && span(block, POSIX_VERSION) == POSIX_VERSION_BYTES
    {
        Ok(Magic::Posix)
    } else if span(block, GNU_MAGIC) == GNU_MAGIC_BYTES {
        Ok(Magic::Gnu)
    } else {
        Err(ContentFault::Unsupported(UnsupportedFeature::TarFormat))
    }
}

/// Parses the fields the policies use, and checks the lexical form of every
/// other field that is not ignored, in header byte order.
fn parse_fields(block: &Block, magic: Magic, flag: u8) -> Result<HeaderFields, ContentFault> {
    let name = parse_name(span(block, NAME), TarField::Name)?;
    parse_numeric(span(block, MODE), TarField::Mode)?;
    parse_numeric(span(block, UID), TarField::Uid)?;
    parse_numeric(span(block, GID), TarField::Gid)?;
    let size = parse_numeric(span(block, SIZE), TarField::Size)?;
    parse_numeric(span(block, MTIME), TarField::Mtime)?;
    let linkname = parse_name(span(block, LINKNAME), TarField::Linkname)?;
    if flag == b'3' || flag == b'4' {
        parse_numeric(span(block, DEVMAJOR), TarField::DevMajor)?;
        parse_numeric(span(block, DEVMINOR), TarField::DevMinor)?;
    }
    // A GNU header keeps other data from offset 345 on; only POSIX has a
    // prefix.
    let prefix = match magic {
        Magic::Posix => parse_name(span(block, PREFIX), TarField::Prefix)?,
        Magic::Gnu => &[],
    };
    let name = if prefix.is_empty() {
        name.to_vec()
    } else {
        [prefix, b"/", name].concat()
    };
    Ok(HeaderFields {
        name,
        linkname: linkname.to_vec(),
        size,
    })
}

/// Parses an octal field: optional leading spaces, zero or more octal digits,
/// then only NUL or space bytes to the end. Returns the value and how many
/// digits it had, or `None` on any other layout or on overflow.
fn parse_octal(field: &[u8]) -> Option<(u64, usize)> {
    let start = field.iter().take_while(|byte| **byte == b' ').count();
    let rest = field.get(start..)?;
    let digits = rest
        .iter()
        .take_while(|byte| (b'0'..=b'7').contains(*byte))
        .count();
    let (number, terminator) = rest.split_at(digits);
    if !terminator.iter().all(|byte| *byte == 0 || *byte == b' ') {
        return None;
    }
    let value = number.iter().try_fold(0u64, |value, digit| {
        value.checked_mul(8)?.checked_add(u64::from(digit - b'0'))
    })?;
    Some((value, digits))
}

/// Parses a numeric field in octal or in GNU base-256.
fn parse_numeric(field: &[u8], which: TarField) -> Result<u64, ContentFault> {
    let fault = || ContentFault::Malformed(MalformedReason::TarNumericField { field: which });
    let Some((first, rest)) = field.split_first() else {
        return Err(fault());
    };
    if first & BASE256_MARKER == 0 {
        return parse_octal(field).map(|(value, _)| value).ok_or_else(fault);
    }
    if first & BASE256_SIGN != 0 {
        return Err(fault());
    }
    rest.iter()
        .try_fold(u64::from(first & BASE256_FIRST_MAGNITUDE), |value, byte| {
            value.checked_mul(256)?.checked_add(u64::from(*byte))
        })
        .ok_or_else(fault)
}

/// Returns a name field's bytes up to its first NUL, requiring every byte
/// after it to be NUL too.
fn parse_name(field: &[u8], which: TarField) -> Result<&[u8], ContentFault> {
    let Some(nul) = field.iter().position(|byte| *byte == 0) else {
        return Ok(field);
    };
    let (value, rest) = field.split_at(nul);
    if rest.iter().all(|byte| *byte == 0) {
        Ok(value)
    } else {
        Err(ContentFault::Malformed(MalformedReason::TarNameField {
            field: which,
        }))
    }
}

/// What a policy admitted of a real entry.
struct Admitted {
    name: Vec<u8>,
    link_target: Option<Vec<u8>>,
    size: u64,
}

enum Rules<'b> {
    Image(ImageRules),
    Layer(LayerRules<'b>),
}

impl Rules<'_> {
    fn has_pending(&self) -> bool {
        match self {
            Rules::Image(_) => false,
            Rules::Layer(layer) => layer.pending.any(),
        }
    }

    fn count_header(&mut self) -> Result<(), ContentFault> {
        match self {
            Rules::Image(image) => image.entries.charge(1),
            Rules::Layer(layer) => layer.entries.charge(1),
        }
    }

    fn classify(&self, flag: u8) -> Option<Typeflag> {
        let entry = match flag {
            b'0' | 0 => EntryKind::Regular,
            b'5' => EntryKind::Directory,
            _ if matches!(self, Rules::Image(_)) => return None,
            b'1' => EntryKind::Hardlink,
            b'2' => EntryKind::Symlink,
            b'3' => EntryKind::CharDevice,
            b'4' => EntryKind::BlockDevice,
            b'6' => EntryKind::Fifo,
            b'x' => return Some(Typeflag::Extension(Extension::Pax)),
            b'L' => return Some(Typeflag::Extension(Extension::LongName)),
            b'K' => return Some(Typeflag::Extension(Extension::LongLink)),
            _ => return None,
        };
        Some(Typeflag::Entry(entry))
    }

    fn admit(&mut self, kind: EntryKind, header: HeaderFields) -> Result<Admitted, ContentFault> {
        match self {
            Rules::Image(image) => image.admit(kind, header),
            Rules::Layer(layer) => layer.admit(kind, header),
        }
    }
}

struct ImageRules {
    entries: Budget,
    path: ResourceLimit,
    /// Every admitted canonical name and its kind. Ordered, so whether any
    /// admitted name lies under a new file's name is one range query rather
    /// than a rescan.
    seen: BTreeMap<Vec<u8>, EntryKind>,
}

impl ImageRules {
    fn admit(&mut self, kind: EntryKind, header: HeaderFields) -> Result<Admitted, ContentFault> {
        if widen(header.name.len()) > self.path.max {
            return Err(self.path.exceeded());
        }
        let directory = kind == EntryKind::Directory;
        let canonical = image_canonical(&header.name, directory)
            .ok_or(ContentFault::Malformed(MalformedReason::UnsafePath))?;
        if directory && header.size != 0 {
            return Err(ContentFault::Malformed(MalformedReason::NonRegularWithData));
        }
        self.record(canonical, kind)?;
        Ok(Admitted {
            name: header.name,
            link_target: None,
            size: header.size,
        })
    }

    fn record(&mut self, canonical: &[u8], kind: EntryKind) -> Result<(), ContentFault> {
        if let Some(existing) = self.seen.get(canonical) {
            return Err(ContentFault::Malformed(if *existing == kind {
                MalformedReason::DuplicatePath
            } else {
                MalformedReason::PathConflict
            }));
        }
        let conflict = ContentFault::Malformed(MalformedReason::PathConflict);
        // A file already admitted at one of this entry's ancestors.
        for (offset, _) in canonical
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
        {
            if self.seen.get(&canonical[..offset]) == Some(&EntryKind::Regular) {
                return Err(conflict);
            }
        }
        // An entry already admitted beneath this file.
        if kind == EntryKind::Regular {
            let mut beneath = canonical.to_vec();
            beneath.push(b'/');
            if self
                .seen
                .range(beneath.clone()..)
                .next()
                .is_some_and(|(name, _)| name.starts_with(&beneath))
            {
                return Err(conflict);
            }
        }
        self.seen.insert(canonical.to_vec(), kind);
        Ok(())
    }
}

/// Returns the canonical form of an image-archive entry name, or `None` when
/// it is not one: ASCII without controls or backslashes, relative, free of
/// empty, `.` and `..` segments, with a single trailing slash allowed on a
/// directory only and stripped.
fn image_canonical(name: &[u8], directory: bool) -> Option<&[u8]> {
    if name
        .iter()
        .any(|byte| !byte.is_ascii() || byte.is_ascii_control() || *byte == b'\\')
    {
        return None;
    }
    let name = match name.strip_suffix(b"/") {
        Some(stripped) if directory => stripped,
        Some(_) => return None,
        None => name,
    };
    if name.is_empty() || !segments_are_plain(name) {
        return None;
    }
    Some(name)
}

/// Whether every `/`-separated segment is nonempty and neither `.` nor `..`.
/// A leading `/` makes the first segment empty.
fn segments_are_plain(path: &[u8]) -> bool {
    path.split(|byte| *byte == b'/')
        .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..")
}

/// Whether `name` is a safe layer entry name: no NUL or control byte, no
/// leading `/`, an optional single leading `./`, an optional single trailing
/// slash on a directory, and otherwise no empty, `.` or `..` segment. `.` and
/// `./` name the root, which only a directory may.
fn layer_name_ok(name: &[u8], directory: bool) -> bool {
    if name.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        return false;
    }
    let name = match name.strip_suffix(b"/") {
        Some(stripped) if directory => stripped,
        Some(_) => return false,
        None => name,
    };
    if name == b"." {
        return directory;
    }
    let name = name.strip_prefix(b"./").unwrap_or(name);
    !name.is_empty() && segments_are_plain(name)
}

struct LayerRules<'b> {
    entries: &'b mut Budget,
    extension_total: &'b mut Budget,
    extension: ResourceLimit,
    path: ResourceLimit,
    link: ResourceLimit,
    pending: Pending,
}

impl LayerRules<'_> {
    fn admit(&mut self, kind: EntryKind, header: HeaderFields) -> Result<Admitted, ContentFault> {
        let Pending {
            pax,
            long_name,
            long_link,
        } = std::mem::take(&mut self.pending);
        let pax = pax.unwrap_or_default();
        let name = pax.path.or(long_name).unwrap_or(header.name);
        let explicit_link = pax.linkpath.or(long_link);
        let size = pax.size.unwrap_or(header.size);
        let link_target = match kind {
            EntryKind::Hardlink | EntryKind::Symlink => {
                Some(explicit_link.unwrap_or(header.linkname))
            }
            _ if explicit_link.is_some() => {
                return Err(ContentFault::Malformed(MalformedReason::LinkOnNonLink));
            }
            _ => None,
        };
        if widen(name.len()) > self.path.max {
            return Err(self.path.exceeded());
        }
        if link_target
            .as_ref()
            .is_some_and(|target| widen(target.len()) > self.link.max)
        {
            return Err(self.link.exceeded());
        }
        let unsafe_path = ContentFault::Malformed(MalformedReason::UnsafePath);
        if !layer_name_ok(&name, kind == EntryKind::Directory) {
            return Err(unsafe_path);
        }
        if kind == EntryKind::Hardlink
            && !link_target
                .as_deref()
                .is_some_and(|target| layer_name_ok(target, false))
        {
            return Err(unsafe_path);
        }
        if kind != EntryKind::Regular && size != 0 {
            return Err(ContentFault::Malformed(MalformedReason::NonRegularWithData));
        }
        Ok(Admitted {
            name,
            link_target,
            size,
        })
    }
}

/// Extension records read since the last real entry, applied to the next.
#[derive(Default)]
struct Pending {
    pax: Option<Pax>,
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
}

impl Pending {
    fn any(&self) -> bool {
        self.pax.is_some() || self.long_name.is_some() || self.long_link.is_some()
    }

    fn refuse_duplicate(&self, extension: Extension) -> Result<(), ContentFault> {
        let present = match extension {
            Extension::Pax => self.pax.is_some(),
            Extension::LongName => self.long_name.is_some(),
            Extension::LongLink => self.long_link.is_some(),
        };
        if present {
            Err(ContentFault::Malformed(MalformedReason::DuplicateExtension))
        } else {
            Ok(())
        }
    }

    /// Parses an extension payload and records it. A conflict with a record
    /// already pending is reported here, at the record that completes it.
    fn record(&mut self, extension: Extension, payload: &[u8]) -> Result<(), ContentFault> {
        let conflict = ContentFault::Malformed(MalformedReason::ConflictingAuthority);
        match extension {
            Extension::Pax => {
                self.pax = Some(parse_pax(
                    payload,
                    self.long_name.is_some(),
                    self.long_link.is_some(),
                )?);
            }
            Extension::LongName => {
                let name = gnu_payload(payload)?;
                if self.pax.as_ref().is_some_and(|pax| pax.path.is_some()) {
                    return Err(conflict);
                }
                self.long_name = Some(name);
            }
            Extension::LongLink => {
                let link = gnu_payload(payload)?;
                if self.pax.as_ref().is_some_and(|pax| pax.linkpath.is_some()) {
                    return Err(conflict);
                }
                self.long_link = Some(link);
            }
        }
        Ok(())
    }
}

/// The values one PAX record set supplies to the next entry.
#[derive(Default)]
struct Pax {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
}

/// Returns a GNU long-name or long-link payload with its trailing NULs
/// stripped, refusing an interior NUL.
fn gnu_payload(payload: &[u8]) -> Result<Vec<u8>, ContentFault> {
    let end = payload
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    let value = &payload[..end];
    if value.contains(&0) {
        return Err(ContentFault::Malformed(MalformedReason::ExtensionPayload));
    }
    Ok(value.to_vec())
}

/// Parses a local PAX payload record by record, the first fault winning.
fn parse_pax(
    payload: &[u8],
    long_name_pending: bool,
    long_link_pending: bool,
) -> Result<Pax, ContentFault> {
    let mut pax = Pax::default();
    let mut keys = HashSet::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (key, value, tail) =
            split_pax_record(rest).ok_or(ContentFault::Malformed(MalformedReason::PaxRecord))?;
        rest = tail;
        if !keys.insert(key) {
            return Err(ContentFault::Malformed(MalformedReason::PaxDuplicateKey));
        }
        let key = pax_key(key).ok_or(ContentFault::Unsupported(UnsupportedFeature::PaxKey))?;
        let bad_value = ContentFault::Malformed(MalformedReason::PaxValue { key });
        match key {
            PaxKey::Path | PaxKey::Linkpath => {
                if value.contains(&0) {
                    return Err(bad_value);
                }
                let conflict = ContentFault::Malformed(MalformedReason::ConflictingAuthority);
                if key == PaxKey::Path {
                    if long_name_pending {
                        return Err(conflict);
                    }
                    pax.path = Some(value.to_vec());
                } else {
                    if long_link_pending {
                        return Err(conflict);
                    }
                    pax.linkpath = Some(value.to_vec());
                }
            }
            PaxKey::Size | PaxKey::Uid | PaxKey::Gid => {
                let number = parse_decimal(value).ok_or(bad_value)?;
                if key == PaxKey::Size {
                    pax.size = Some(number);
                }
            }
            PaxKey::Mtime | PaxKey::Atime | PaxKey::Ctime => {
                if !is_pax_time(value) {
                    return Err(bad_value);
                }
            }
            PaxKey::Uname | PaxKey::Gname | PaxKey::Xattr => {}
        }
    }
    Ok(pax)
}

/// Splits one `<length> <key>=<value>\n` record off the front of `payload`,
/// returning its key, its value and the rest of the payload.
fn split_pax_record(payload: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let digits = payload
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let (length, _) = payload.split_at(digits);
    if length.first().is_none_or(|first| *first == b'0') {
        return None;
    }
    let length = usize::try_from(parse_decimal(length)?).ok()?;
    let record = payload.get(..length)?;
    let tail = payload.get(length..)?;
    // After the digits: exactly one space, then a body ending in a newline.
    // The key starts right after that space, so a second space is the key's
    // first byte rather than another separator.
    let body = record
        .get(digits..)?
        .strip_prefix(b" ")?
        .strip_suffix(b"\n")?;
    let equals = body.iter().position(|byte| *byte == b'=')?;
    let (key, value) = body.split_at(equals);
    if key.is_empty() {
        return None;
    }
    Some((key, &value[1..], tail))
}

fn pax_key(key: &[u8]) -> Option<PaxKey> {
    Some(match key {
        b"path" => PaxKey::Path,
        b"linkpath" => PaxKey::Linkpath,
        b"size" => PaxKey::Size,
        b"uid" => PaxKey::Uid,
        b"gid" => PaxKey::Gid,
        b"uname" => PaxKey::Uname,
        b"gname" => PaxKey::Gname,
        b"mtime" => PaxKey::Mtime,
        b"atime" => PaxKey::Atime,
        b"ctime" => PaxKey::Ctime,
        _ if key.starts_with(PAX_XATTR_PREFIX) => PaxKey::Xattr,
        _ => return None,
    })
}

/// Parses `[0-9]+` into a `u64` with checked arithmetic.
fn parse_decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |value, digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

/// Whether `value` matches `-?[0-9]+(\.[0-9]+)?`.
fn is_pax_time(value: &[u8]) -> bool {
    let unsigned = value.strip_prefix(b"-").unwrap_or(value);
    let (whole, fraction) = match unsigned.iter().position(|byte| *byte == b'.') {
        Some(dot) => (&unsigned[..dot], Some(&unsigned[dot + 1..])),
        None => (unsigned, None),
    };
    let all_digits = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
    all_digits(whole) && fraction.is_none_or(all_digits)
}

#[cfg(test)]
mod tests;
