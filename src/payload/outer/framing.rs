//! The tar structure of a bounded walk, followed as the decoded bytes pass so
//! that the framing between the members stays bounded without being mistaken
//! for member data.
//!
//! [`tar::Archive`] buffers the whole body of every GNU long-name, GNU
//! long-link and PAX extension record before it hands out the entry the record
//! describes, and the walk's rules can only judge that entry afterwards. A
//! bounded walk cannot let a record grow first and be judged later, so
//! [`Framing`] reads each header block as it passes and decides, before the
//! archive reader asks for a byte of an extension record's body, whether the
//! framing allowance still holds that body together with the header it
//! describes.
//!
//! A record the allowance holds goes to the archive reader and is judged by
//! the walk's shared rules exactly as the legacy walk judges it. A record it
//! does not hold never reaches the archive reader: it is scanned here instead,
//! within what is left of the allowance and never buffered, and refused for
//! what it overrides through the [`PayloadError`] variant the shared rules
//! give that override. The member's own header lies past a record the walk
//! will not read, so such a refusal names the header block the walk did read —
//! the extension's — and reports at most [`REPORTED_NAME_MAX`] bytes of the
//! name the record carries.

use std::io;

use tar::{EntryType, Header};

use crate::payload::{PayloadError, TAR_BLOCK_SIZE};

/// The longest prefix of an overriding name a refusal reports: a `ustar`
/// prefix and name field together, and so more than any raw header can state.
const REPORTED_NAME_MAX: usize = 256;
/// What a reported name ends in when the record carries more of it.
const TRUNCATION_MARK: char = '\u{2026}';
/// The longest PAX key a scan tells apart; both keys it looks for are shorter.
const PAX_KEY_MAX: usize = 8;
/// The PAX key naming a member.
const PAX_PATH: &[u8] = b"path";
/// The PAX key sizing a member.
const PAX_SIZE: &[u8] = b"size";
/// Largest read a scan makes of the decoded stream, below `CopyBuffer` too.
pub(super) const SCAN_CHUNK: usize = 4096;
/// [`TAR_BLOCK_SIZE`] as a stream length.
const BLOCK_LEN: u64 = 512;

/// The framing between the members passed the allowance the admitted member
/// count sets, carried as an [`io::Error`] payload. It is a container verdict,
/// [`PayloadError::Io`], and never a public limit: the allowance is private.
#[derive(Debug, thiserror::Error)]
#[error("the tar framing between the archive members exceeds its {limit}-byte allowance")]
pub(super) struct FramingExceeded {
    limit: u64,
}

/// Returns the error a framing overflow outside any extension record raises.
pub(super) fn exceeded(limit: u64) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, FramingExceeded { limit })
}

/// An extension record too large for the framing allowance, refused for what
/// it overrides and carried as an [`io::Error`] payload until the walk turns
/// it back into the [`PayloadError`] it names.
#[derive(Debug, thiserror::Error)]
#[error("a tar extension record too large for the framing allowance overrides its member")]
pub(super) enum OversizedExtension {
    /// A GNU long name or a PAX `path` record:
    /// [`PayloadError::NameOverridingHeader`]. The member's header lies past
    /// the record unread, so the name is refused even where it would have
    /// matched that header.
    Name {
        header_name: String,
        resolved_name: String,
    },
    /// A PAX `size` record: [`PayloadError::SizeOverridingHeader`].
    Size {
        path: String,
        header_size: u64,
        resolved_size: u64,
    },
    /// A GNU long link, which names a link entry's target:
    /// [`PayloadError::UnsupportedEntryType`], the verdict every link entry
    /// gets. The entry it describes lies past the record unread, so a crafted
    /// archive putting one before a regular file, which the legacy walk
    /// accepts, is refused the same way.
    Link { path: String },
}

impl OversizedExtension {
    /// Returns the verdict the refusal names.
    pub(super) fn into_payload(self) -> PayloadError {
        match self {
            OversizedExtension::Name {
                header_name,
                resolved_name,
            } => PayloadError::NameOverridingHeader {
                header_name,
                resolved_name,
            },
            OversizedExtension::Size {
                path,
                header_size,
                resolved_size,
            } => PayloadError::SizeOverridingHeader {
                path,
                header_size,
                resolved_size,
            },
            OversizedExtension::Link { path } => PayloadError::UnsupportedEntryType { path },
        }
    }

    fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

/// Where a bounded walk stands in the decoded tar stream.
#[derive(Debug)]
pub(super) struct Framing {
    state: State,
    /// The header block being collected, of which the first `have` bytes are
    /// read.
    block: [u8; TAR_BLOCK_SIZE],
    have: usize,
}

#[derive(Debug)]
enum State {
    /// Collecting a header block.
    Header,
    /// Passing `remaining` bytes of a body and its padding.
    Skip { remaining: u64 },
    /// Scanning an extension record the allowance does not hold.
    Extension(ExtensionScan),
    /// No longer following the structure: past the end-of-archive marker, or
    /// past an entry the walk refuses on sight, or a header the archive reader
    /// refuses too. The framing allowance still bounds every byte.
    Untracked,
}

impl State {
    fn skip(remaining: u64) -> State {
        if remaining == 0 {
            State::Header
        } else {
            State::Skip { remaining }
        }
    }
}

impl Framing {
    pub(super) fn new() -> Framing {
        Framing {
            state: State::Header,
            block: [0; TAR_BLOCK_SIZE],
            have: 0,
        }
    }

    /// Returns whether an extension record the allowance does not hold is
    /// being scanned, so that the next read is its refusal.
    pub(super) fn scanning(&self) -> bool {
        matches!(self.state, State::Extension(_))
    }

    /// Returns how many more bytes of the record being scanned the scan wants,
    /// zero once it can decide or when nothing is being scanned.
    pub(super) fn wanted(&self) -> u64 {
        match &self.state {
            State::Extension(scan) if !scan.decided() => scan.remaining,
            _ => 0,
        }
    }

    /// Follows the structure over `input`, bytes the archive reader has been
    /// handed, with `room` framing bytes left of the allowance as the first
    /// of them arrived.
    pub(super) fn advance(&mut self, input: &[u8], room: u64) {
        let mut rest = input;
        let mut room = room;
        while !rest.is_empty() {
            let used = self.step(rest, room);
            rest = rest.get(used..).unwrap_or_default();
            room = room.saturating_sub(crate::content::widen(used));
        }
    }

    /// Feeds bytes of the record being scanned, read past the archive reader.
    pub(super) fn feed(&mut self, input: &[u8]) {
        if let State::Extension(scan) = &mut self.state {
            scan.feed(input);
        }
    }

    /// Ends the scan of the record being scanned and returns its refusal:
    /// the override it carries, or [`FramingExceeded`] under `limit` for a
    /// record that overrides nothing the scan could see.
    pub(super) fn conclude(&mut self, limit: u64) -> io::Error {
        match std::mem::replace(&mut self.state, State::Untracked) {
            State::Extension(scan) => scan
                .conclude()
                .map_or_else(|| exceeded(limit), OversizedExtension::into_io),
            _ => exceeded(limit),
        }
    }

    /// Follows the structure over a nonempty prefix of `input` and returns its
    /// length.
    fn step(&mut self, input: &[u8], room: u64) -> usize {
        match &mut self.state {
            State::Header => {
                let used = TAR_BLOCK_SIZE.saturating_sub(self.have).min(input.len());
                let end = self.have.saturating_add(used);
                if let (Some(slot), Some(taken)) =
                    (self.block.get_mut(self.have..end), input.get(..used))
                {
                    slot.copy_from_slice(taken);
                }
                self.have = end;
                if end >= TAR_BLOCK_SIZE {
                    self.have = 0;
                    let room = room.saturating_sub(crate::content::widen(used));
                    self.state = after_header(&self.block, room);
                }
                used
            }
            State::Skip { remaining } => {
                let used = crate::content::chunk_len(input.len(), *remaining);
                *remaining = remaining.saturating_sub(crate::content::widen(used));
                if *remaining == 0 {
                    self.state = State::Header;
                }
                used
            }
            // Nothing past the record is scanned; the refusal comes first.
            State::Extension(scan) => match scan.feed(input) {
                0 => input.len(),
                used => used,
            },
            State::Untracked => input.len(),
        }
    }
}

/// Returns what follows the header `block`, with `room` framing bytes left of
/// the allowance after it.
fn after_header(block: &[u8; TAR_BLOCK_SIZE], room: u64) -> State {
    // The archive reader stops at the first zero block.
    if block.iter().all(|byte| *byte == 0) {
        return State::Untracked;
    }
    let mut header = Header::new_old();
    header.as_mut_bytes().copy_from_slice(block);
    // A size the archive reader cannot read or round is its own refusal.
    let Some(padded) = header
        .entry_size()
        .ok()
        .and_then(|size| size.checked_add(BLOCK_LEN - 1))
        .map(|size| size & !(BLOCK_LEN - 1))
    else {
        return State::Untracked;
    };
    // The archive reader treats these three kinds as extensions only under a
    // header it recognizes, and hands any other out as an entry the walk
    // refuses on sight.
    let recognized = header.as_gnu().is_some() || header.as_ustar().is_some();
    let entry_type = header.entry_type();
    let kind = match entry_type {
        EntryType::GNULongName if recognized => ExtensionKind::LongName,
        EntryType::GNULongLink if recognized => ExtensionKind::LongLink,
        EntryType::XHeader if recognized => ExtensionKind::Pax,
        // A regular file's data the walk may read, and a body or padding it
        // skips once the sink is done with it.
        EntryType::Regular => return State::skip(padded),
        // Every other entry the walk refuses before reading past its header,
        // except for sparse maps the archive reader reads first; those stay
        // bounded by the allowance but are not followed.
        _ => return State::Untracked,
    };
    let holds = padded
        .checked_add(BLOCK_LEN)
        .is_some_and(|needed| needed <= room);
    if holds {
        State::skip(padded)
    } else {
        State::Extension(ExtensionScan::new(kind, &header))
    }
}

/// The extension records the archive reader buffers whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExtensionKind {
    LongName,
    LongLink,
    Pax,
}

/// An extension record the allowance does not hold, read past the archive
/// reader with nothing of it kept but a bounded prefix of the name it
/// carries.
#[derive(Debug)]
struct ExtensionScan {
    kind: ExtensionKind,
    /// The extension header's own raw name.
    header_name: String,
    /// The extension header's own raw size.
    header_size: u64,
    /// Body bytes not yet scanned.
    remaining: u64,
    name: NamePrefix,
    pax: PaxScan,
}

impl ExtensionScan {
    fn new(kind: ExtensionKind, header: &Header) -> ExtensionScan {
        let header_size = header.entry_size().unwrap_or_default();
        ExtensionScan {
            kind,
            header_name: String::from_utf8_lossy(&header.path_bytes()).into_owned(),
            header_size,
            remaining: header_size,
            name: NamePrefix::default(),
            pax: PaxScan::default(),
        }
    }

    /// Returns whether the scan can decide without another byte.
    fn decided(&self) -> bool {
        self.remaining == 0
            || match self.kind {
                ExtensionKind::LongLink => true,
                ExtensionKind::LongName => self.name.is_full(),
                ExtensionKind::Pax => self.pax.path == PathLookup::Found || self.pax.ended,
            }
    }

    /// Scans a prefix of `input` within the record and returns its length.
    fn feed(&mut self, input: &[u8]) -> usize {
        let used = crate::content::chunk_len(input.len(), self.remaining);
        let body = input.get(..used).unwrap_or_default();
        match self.kind {
            ExtensionKind::LongLink => {}
            ExtensionKind::LongName => body.iter().for_each(|&byte| self.name.push(byte)),
            ExtensionKind::Pax => {
                for &byte in body {
                    self.pax.byte(byte, &mut self.name);
                }
            }
        }
        self.remaining = self.remaining.saturating_sub(crate::content::widen(used));
        used
    }

    /// Returns the override the record was seen to carry, if any.
    fn conclude(mut self) -> Option<OversizedExtension> {
        let whole = self.remaining == 0;
        match self.kind {
            ExtensionKind::LongLink => Some(OversizedExtension::Link {
                path: self.header_name,
            }),
            ExtensionKind::LongName => {
                // The archive reader drops a long name's terminating NUL.
                if whole && !self.name.truncated && self.name.bytes.last() == Some(&0) {
                    self.name.bytes.pop();
                }
                let truncated = !whole;
                Some(OversizedExtension::Name {
                    header_name: self.header_name,
                    resolved_name: self.name.display(truncated),
                })
            }
            ExtensionKind::Pax => {
                self.pax.finish(whole, &mut self.name);
                if self.pax.path == PathLookup::Found {
                    let truncated = self.pax.path_unfinished;
                    Some(OversizedExtension::Name {
                        header_name: self.header_name,
                        resolved_name: self.name.display(truncated),
                    })
                } else if let SizeLookup::Found(resolved_size) = self.pax.size {
                    Some(OversizedExtension::Size {
                        path: self.header_name,
                        header_size: self.header_size,
                        resolved_size,
                    })
                } else {
                    None
                }
            }
        }
    }
}

/// At most [`REPORTED_NAME_MAX`] bytes of a name, and whether more followed.
#[derive(Debug, Default)]
struct NamePrefix {
    bytes: Vec<u8>,
    truncated: bool,
}

impl NamePrefix {
    fn push(&mut self, byte: u8) {
        if self.bytes.len() < REPORTED_NAME_MAX {
            self.bytes.push(byte);
        } else {
            self.truncated = true;
        }
    }

    fn is_full(&self) -> bool {
        self.bytes.len() >= REPORTED_NAME_MAX
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.truncated = false;
    }

    /// Returns the name as a refusal reports it, marked when the record
    /// carries more of it than was kept.
    fn display(&self, continues: bool) -> String {
        let mut name = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.truncated || continues {
            name.push(TRUNCATION_MARK);
        }
        name
    }
}

/// Which part of a PAX record line is being read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Part {
    /// The decimal length before the first space.
    #[default]
    Length,
    /// The key, up to the first `=`.
    Key,
    /// The value, up to the newline.
    Value,
    /// The rest of a line that is already malformed.
    Malformed,
}

/// Which key a PAX line's value belongs to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Key {
    #[default]
    Other,
    Path,
    Size,
}

/// Where the lookup of a `path` record stands, as the archive reader's: the
/// first well-formed line keyed `path` names the member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PathLookup {
    #[default]
    Open,
    /// A line keyed `path` is being read, its value captured.
    Candidate,
    Found,
}

/// Where the lookup of a `size` record stands, as the archive reader's: the
/// first line keyed `size` sizes the member if it parses, and a malformed
/// line before it ends the lookup with nothing found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SizeLookup {
    #[default]
    Open,
    Found(u64),
    Closed,
}

/// A decimal number read a digit at a time, as `str::parse` reads it: an
/// optional leading `+`, then at least one digit, and no overflow.
#[derive(Clone, Copy, Debug, Default)]
struct Decimal {
    value: u64,
    digits: bool,
    len: u64,
    invalid: bool,
}

impl Decimal {
    fn push(&mut self, byte: u8) {
        let first = self.len == 0;
        self.len = self.len.saturating_add(1);
        if first && byte == b'+' {
            return;
        }
        let next = byte
            .is_ascii_digit()
            .then(|| self.value.checked_mul(10))
            .flatten()
            .and_then(|value| value.checked_add(u64::from(byte - b'0')));
        match next {
            Some(value) if !self.invalid => {
                self.value = value;
                self.digits = true;
            }
            _ => self.invalid = true,
        }
    }

    fn get(&self) -> Option<u64> {
        (self.digits && !self.invalid).then_some(self.value)
    }
}

/// The records of a PAX extension body, read a byte at a time with nothing
/// kept but the current line's bounded state and what the lookups found.
///
/// The archive reader splits the body at newlines, stops at the first empty
/// line, and takes a line as a record only when it reads `<len> <key>=<value>`
/// and `len` counts the line and its newline.
#[derive(Debug, Default)]
struct PaxScan {
    part: Part,
    /// Bytes of the current line so far, its newline not counted.
    line_len: u64,
    length: Decimal,
    key: [u8; PAX_KEY_MAX],
    key_len: usize,
    key_overlong: bool,
    value_key: Key,
    size_value: Decimal,
    path: PathLookup,
    /// Whether the path found was still unfinished when the scan stopped.
    path_unfinished: bool,
    size: SizeLookup,
    /// Whether an empty line ended the records.
    ended: bool,
}

impl PaxScan {
    fn byte(&mut self, byte: u8, name: &mut NamePrefix) {
        if self.ended {
            return;
        }
        if byte == b'\n' {
            self.end_line(name);
            return;
        }
        match self.line_len.checked_add(1) {
            Some(len) => self.line_len = len,
            None => self.part = Part::Malformed,
        }
        match self.part {
            Part::Length if byte == b' ' => {
                self.part = if self.length.get().is_some() {
                    Part::Key
                } else {
                    Part::Malformed
                };
            }
            Part::Length => self.length.push(byte),
            Part::Key if byte == b'=' => {
                let key = self.key.get(..self.key_len).unwrap_or_default();
                self.value_key = match key {
                    _ if self.key_overlong => Key::Other,
                    PAX_PATH => Key::Path,
                    PAX_SIZE => Key::Size,
                    _ => Key::Other,
                };
                if self.value_key == Key::Path && self.path == PathLookup::Open {
                    self.path = PathLookup::Candidate;
                    name.clear();
                }
                self.part = Part::Value;
            }
            Part::Key => match self.key.get_mut(self.key_len) {
                Some(slot) => {
                    *slot = byte;
                    self.key_len = self.key_len.saturating_add(1);
                }
                None => self.key_overlong = true,
            },
            Part::Value => match self.value_key {
                Key::Path if self.path == PathLookup::Candidate => name.push(byte),
                Key::Size => self.size_value.push(byte),
                Key::Path | Key::Other => {}
            },
            Part::Malformed => {}
        }
    }

    /// Returns whether the current line is well formed once it ends here.
    fn well_formed(&self) -> bool {
        self.part == Part::Value
            && self
                .line_len
                .checked_add(1)
                .is_some_and(|seen| self.length.get() == Some(seen))
    }

    fn end_line(&mut self, name: &mut NamePrefix) {
        if self.line_len == 0 {
            self.ended = true;
            return;
        }
        if self.well_formed() {
            match self.value_key {
                Key::Path if self.path == PathLookup::Candidate => self.path = PathLookup::Found,
                Key::Size if self.size == SizeLookup::Open => {
                    self.size = self
                        .size_value
                        .get()
                        .map_or(SizeLookup::Closed, SizeLookup::Found);
                }
                Key::Path | Key::Size | Key::Other => {}
            }
        } else {
            if self.size == SizeLookup::Open {
                self.size = SizeLookup::Closed;
            }
            if self.path == PathLookup::Candidate {
                self.path = PathLookup::Open;
                name.clear();
            }
        }
        *self = PaxScan {
            path: self.path,
            size: self.size,
            ended: self.ended,
            ..PaxScan::default()
        };
    }

    /// Ends the scan: at the end of the record, whose last line needs no
    /// newline, or where the allowance or the stream stopped it, where a
    /// `path` line not yet contradicted by its own length counts as found.
    fn finish(&mut self, whole: bool, name: &mut NamePrefix) {
        if self.ended || self.path == PathLookup::Found {
            return;
        }
        if whole {
            if self.line_len > 0 {
                self.end_line(name);
            }
            self.ended = true;
            return;
        }
        let plausible = self.part == Part::Value
            && self
                .line_len
                .checked_add(1)
                .zip(self.length.get())
                .is_some_and(|(seen, declared)| declared >= seen);
        if self.path == PathLookup::Candidate && plausible {
            self.path = PathLookup::Found;
            self.path_unfinished = true;
        }
        self.ended = true;
    }
}

#[cfg(test)]
mod tests;
