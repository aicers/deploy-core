//! Test-only builders and sources for the content primitives: a raw tar header
//! builder that sets every byte, a tar stream assembler, and a source that
//! records every request made of it.

use std::cell::RefCell;
use std::io::{self, ErrorKind, Read};
use std::rc::Rc;

pub(crate) const BLOCK: usize = 512;

/// What a [`RecordingSource`] observed.
#[derive(Debug, Default)]
pub(crate) struct SourceLog {
    /// The length of every `read` request, in order.
    pub(crate) requests: Vec<usize>,
    /// How many bytes were delivered.
    pub(crate) delivered: usize,
    /// How many `Interrupted` errors were injected.
    pub(crate) interrupts: usize,
}

/// An in-memory source that logs every request, can inject an error or an
/// `Interrupted` at a chosen offset, and carries an advertised length that
/// nothing is supposed to consult.
pub(crate) struct RecordingSource {
    data: Vec<u8>,
    position: usize,
    log: Rc<RefCell<SourceLog>>,
    fail_at: Option<(usize, ErrorKind)>,
    interrupt_at: Vec<usize>,
    advertised: Option<u64>,
}

impl RecordingSource {
    pub(crate) fn new(data: Vec<u8>) -> (RecordingSource, Rc<RefCell<SourceLog>>) {
        let log = Rc::new(RefCell::new(SourceLog::default()));
        (
            RecordingSource {
                data,
                position: 0,
                log: Rc::clone(&log),
                fail_at: None,
                interrupt_at: Vec::new(),
                advertised: None,
            },
            log,
        )
    }

    /// Fails every request made once `offset` bytes have been delivered.
    pub(crate) fn fail_at(&mut self, offset: usize, kind: ErrorKind) {
        self.fail_at = Some((offset, kind));
    }

    /// Answers the first request made once `offset` bytes have been delivered
    /// with `Interrupted`.
    pub(crate) fn interrupt_at(&mut self, offset: usize) {
        self.interrupt_at.push(offset);
    }

    /// Claims a length unrelated to the bytes actually held.
    pub(crate) fn advertise(&mut self, len: u64) {
        self.advertised = Some(len);
    }

    #[allow(dead_code)] // Present so a lying length exists; nothing reads it.
    pub(crate) fn advertised(&self) -> Option<u64> {
        self.advertised
    }
}

impl Read for RecordingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut log = self.log.borrow_mut();
        log.requests.push(buf.len());
        if let Some(index) = self
            .interrupt_at
            .iter()
            .position(|offset| *offset == self.position)
        {
            self.interrupt_at.remove(index);
            log.interrupts += 1;
            return Err(io::Error::from(ErrorKind::Interrupted));
        }
        if let Some((offset, kind)) = self.fail_at
            && self.position >= offset
        {
            return Err(io::Error::from(kind));
        }
        let rest = &self.data[self.position..];
        let limit = self.fail_at.map_or(rest.len(), |(offset, _)| {
            rest.len().min(offset - self.position)
        });
        let n = buf.len().min(limit);
        buf[..n].copy_from_slice(&rest[..n]);
        self.position += n;
        log.delivered += n;
        Ok(n)
    }
}

/// Which checksum a [`Header`] is stamped with.
#[derive(Clone, Copy)]
enum Checksum {
    /// The unsigned sum, as six octal digits, a NUL and a space.
    Unsigned,
    /// The historical signed sum.
    Signed,
    /// The unsigned sum plus one, which never matches.
    Wrong,
    /// These exact eight bytes.
    Raw([u8; 8]),
    /// The unsigned sum, formatted by the closure.
    Format(fn(u64) -> [u8; 8]),
}

/// A raw 512-byte tar header, set byte for byte.
#[derive(Clone)]
pub(crate) struct Header {
    block: [u8; BLOCK],
    checksum: Checksum,
}

impl Header {
    /// Returns a POSIX ustar header with `flag`, `name` and `size`, mode 0644
    /// and every other field zero.
    pub(crate) fn new(flag: u8, name: &[u8], size: u64) -> Header {
        let mut header = Header {
            block: [0; BLOCK],
            checksum: Checksum::Unsigned,
        };
        header.set(0, name);
        header.set(100, b"0000644\0");
        header.set(108, b"0000000\0");
        header.set(116, b"0000000\0");
        header.size(size);
        header.set(136, b"00000000000\0");
        header.block[156] = flag;
        header.posix();
        header
    }

    /// Returns a regular-file header.
    pub(crate) fn file(name: &[u8], size: u64) -> Header {
        Header::new(b'0', name, size)
    }

    /// Returns a directory header.
    pub(crate) fn dir(name: &[u8]) -> Header {
        Header::new(b'5', name, 0)
    }

    /// Overwrites bytes starting at `offset`.
    pub(crate) fn set(&mut self, offset: usize, bytes: &[u8]) -> &mut Header {
        self.block[offset..offset + bytes.len()].copy_from_slice(bytes);
        self
    }

    /// Writes `size` as eleven octal digits and a NUL.
    pub(crate) fn size(&mut self, size: u64) -> &mut Header {
        let text = format!("{size:011o}\0");
        assert_eq!(text.len(), 12, "size {size} needs base-256");
        self.set(124, text.as_bytes())
    }

    pub(crate) fn linkname(&mut self, linkname: &[u8]) -> &mut Header {
        self.set(157, &[0; 100]);
        self.set(157, linkname)
    }

    pub(crate) fn prefix(&mut self, prefix: &[u8]) -> &mut Header {
        self.set(345, &[0; 155]);
        self.set(345, prefix)
    }

    pub(crate) fn posix(&mut self) -> &mut Header {
        self.set(257, b"ustar\0").set(263, b"00")
    }

    pub(crate) fn gnu(&mut self) -> &mut Header {
        self.set(257, b"ustar  \0")
    }

    pub(crate) fn no_magic(&mut self) -> &mut Header {
        self.set(257, &[0; 8])
    }

    pub(crate) fn wrong_checksum(&mut self) -> &mut Header {
        self.checksum = Checksum::Wrong;
        self
    }

    pub(crate) fn signed_checksum(&mut self) -> &mut Header {
        self.checksum = Checksum::Signed;
        self
    }

    pub(crate) fn raw_checksum(&mut self, bytes: [u8; 8]) -> &mut Header {
        self.checksum = Checksum::Raw(bytes);
        self
    }

    pub(crate) fn formatted_checksum(&mut self, format: fn(u64) -> [u8; 8]) -> &mut Header {
        self.checksum = Checksum::Format(format);
        self
    }

    /// Returns the finished block, with its checksum stamped.
    pub(crate) fn build(&self) -> [u8; BLOCK] {
        let mut block = self.block;
        block[148..156].copy_from_slice(b"        ");
        let unsigned: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        let field: [u8; 8] = match self.checksum {
            Checksum::Unsigned => octal_checksum(unsigned),
            Checksum::Wrong => octal_checksum(unsigned + 1),
            Checksum::Signed => {
                let signed: i64 = block
                    .iter()
                    .map(|byte| i64::from(i8::from_ne_bytes([*byte])))
                    .sum();
                octal_checksum(u64::try_from(signed).expect("fixture signed sums stay positive"))
            }
            Checksum::Raw(bytes) => bytes,
            Checksum::Format(format) => format(unsigned),
        };
        block[148..156].copy_from_slice(&field);
        block
    }
}

/// Formats a checksum as six octal digits, a NUL and a space.
pub(crate) fn octal_checksum(sum: u64) -> [u8; 8] {
    let text = format!("{sum:06o}\0 ");
    text.as_bytes()
        .try_into()
        .expect("a checksum fits six digits")
}

/// Returns a PAX payload holding `records` in order, each with its length
/// computed.
pub(crate) fn pax(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (key, value) in records {
        let body = key.len() + value.len() + 3;
        let mut len = body + 1;
        while format!("{len}").len() + body != len {
            len += 1;
        }
        payload.extend_from_slice(format!("{len} {key}=").as_bytes());
        payload.extend_from_slice(value);
        payload.push(b'\n');
    }
    payload
}

/// A tar stream under construction.
#[derive(Default)]
pub(crate) struct Tar {
    bytes: Vec<u8>,
}

impl Tar {
    pub(crate) fn new() -> Tar {
        Tar::default()
    }

    /// Appends `header` and `data`, zero-padded to a whole block.
    pub(crate) fn entry(&mut self, header: &Header, data: &[u8]) -> &mut Tar {
        self.bytes.extend_from_slice(&header.build());
        self.bytes.extend_from_slice(data);
        let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
        self.bytes.extend(std::iter::repeat_n(0, pad));
        self
    }

    /// Appends a header with no data.
    pub(crate) fn header(&mut self, header: &Header) -> &mut Tar {
        self.entry(header, &[])
    }

    /// Appends an extension record of type `flag` carrying `payload`.
    pub(crate) fn extension(&mut self, flag: u8, payload: &[u8]) -> &mut Tar {
        let name: &[u8] = if flag == b'x' {
            b"PaxHeader"
        } else {
            b"././@LongLink"
        };
        let mut header = Header::new(flag, name, widen(payload.len()));
        if flag != b'x' {
            header.gnu();
        }
        self.entry(&header, payload)
    }

    /// Appends arbitrary bytes.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Tar {
        self.bytes.extend_from_slice(bytes);
        self
    }

    /// Appends the two-block end-of-archive marker and returns the stream.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        self.bytes.extend_from_slice(&[0; 2 * BLOCK]);
        std::mem::take(&mut self.bytes)
    }

    /// Returns the stream as it stands, with no end marker.
    pub(crate) fn unfinished(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

fn widen(len: usize) -> u64 {
    u64::try_from(len).expect("fixture lengths fit u64")
}
