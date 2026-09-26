//! Tests of the bounded walk's zstd frame guard and its framing meter.

use std::io::{self, Cursor, Read, Write};

use tar::{EntryType, Header};
use zstd::{Decoder, Encoder};

use super::{
    Field, Framing, Meter, OuterCounters, OuterLimits, Scan, UnreadableFrame, WalkError,
    WindowGuard, ZSTD_FRAME_MAGIC, framing_allowance, stream_error,
};
use crate::package::LimitResource;
use crate::payload::PayloadError;

const KIB: u64 = 1024;

fn limits(zstd_window: u64, copy_buffer: usize) -> OuterLimits {
    OuterLimits {
        members: 16,
        uncompressed_total: u64::MAX,
        zstd_window,
        copy_buffer,
    }
}

/// Compresses `bytes` into one frame declaring a window of `2^log` bytes.
fn frame(bytes: &[u8], log: u32, checksum: bool) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new(), 3).expect("an encoder");
    encoder.window_log(log).expect("a window log");
    encoder.include_checksum(checksum).expect("a checksum flag");
    encoder.write_all(bytes).expect("compresses");
    encoder.finish().expect("finishes")
}

/// A skippable frame carrying `payload`.
fn skippable(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x5a, 0x2a, 0x4d, 0x18];
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Bytes zstd can neither compress nor turn into RLE blocks.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// A reader recording the largest request made of it.
struct Counting<R> {
    inner: R,
    largest: usize,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(buf.len());
        self.inner.read(buf)
    }
}

/// A guard over an in-memory stream.
type Guard<'s> = WindowGuard<Cursor<&'s [u8]>>;

/// Reads `stream` through a guard in `chunk`-byte requests, returning what
/// passed and the guard, or the walk error a refusal becomes.
fn drain<'s>(
    stream: &'s [u8],
    limits: &OuterLimits,
    chunk: usize,
) -> Result<(Vec<u8>, Guard<'s>), WalkError<()>> {
    let mut guard = WindowGuard::new(Cursor::new(stream), limits);
    let mut out = Vec::new();
    let mut buf = vec![0; chunk];
    loop {
        match guard.read(&mut buf) {
            Ok(0) => return Ok((out, guard)),
            Ok(read) => out.extend_from_slice(&buf[..read]),
            Err(error) => return Err(stream_error(error)),
        }
    }
}

fn assert_between_frames(guard: &Guard<'_>) {
    assert!(
        matches!(
            guard.scan,
            Scan::Collect {
                field: Field::Magic,
                have: 0,
                ..
            }
        ),
        "{:?}",
        guard.scan
    );
}

fn assert_window_limit(error: &WalkError<()>, limit: u64) {
    assert!(
        matches!(
            error,
            WalkError::Limit {
                resource: LimitResource::ZstdWindow,
                limit: reported,
            } if *reported == limit
        ),
        "{error:?}"
    );
}

#[test]
fn every_block_kind_passes_and_ends_on_a_frame_boundary() {
    // Several blocks of each kind: compressible text, runs zstd stores as RLE
    // blocks, and noise it stores raw — with and without checksums, and an
    // empty frame between.
    let mut data = Vec::new();
    data.extend(b"compressible text ".iter().cycle().take(300_000));
    data.extend(std::iter::repeat_n(0u8, 300_000));
    data.extend(noise(300_000));
    let mut stream = frame(&data, 20, true);
    stream.extend(frame(b"", 10, false));
    stream.extend(skippable(b"ignored by the decoder"));
    stream.extend(frame(&data, 20, false));
    let limits = limits(1 << 20, 4096);
    for chunk in [1, 7, 4096] {
        let (out, guard) = drain(&stream, &limits, chunk).expect("passes");
        assert_eq!(out, stream);
        assert_between_frames(&guard);
    }
    let mut decoded = Vec::new();
    Decoder::new(WindowGuard::new(Cursor::new(&stream[..]), &limits))
        .expect("a decoder")
        .read_to_end(&mut decoded)
        .expect("decodes");
    assert_eq!(decoded, [data.as_slice(), &data].concat());
}

#[test]
fn a_later_frame_above_the_window_is_named_as_the_limit() {
    let mut stream = frame(b"first frame", 19, false);
    stream.extend(frame(b"second frame", 20, true));
    let error = drain(&stream, &limits(1 << 19, 64), 64).expect_err("refused");
    assert_window_limit(&error, 1 << 19);
    drain(&stream, &limits(1 << 20, 64), 64).expect("passes at the limit");

    // Behind a skippable frame too.
    let mut stream = skippable(&[0; 100]);
    stream.extend(frame(b"behind a skippable frame", 20, false));
    let error = drain(&stream, &limits(1 << 19, 64), 64).expect_err("refused");
    assert_window_limit(&error, 1 << 19);
}

#[test]
fn a_refused_header_never_reaches_the_decoder() {
    let first = frame(b"first frame", 19, false);
    let mut stream = first.clone();
    stream.extend(frame(b"second frame", 20, false));
    // One byte at a time: every byte up to the one completing the second
    // frame's header passes, and that byte is the refusal.
    let mut guard = WindowGuard::new(Cursor::new(&stream[..]), &limits(1 << 19, 1));
    let mut passed = 0;
    let mut byte = [0];
    let error = loop {
        match guard.read(&mut byte) {
            Ok(1) => passed += 1,
            Ok(_) => panic!("the stream ended"),
            Err(error) => break error,
        }
    };
    assert_window_limit(&stream_error(error), 1 << 19);
    // The magic, the descriptor and the window descriptor.
    assert_eq!(passed, first.len() + ZSTD_FRAME_MAGIC.len() + 1);
}

#[test]
fn a_single_segment_window_is_its_content_size() {
    let data = vec![7u8; 5000];
    let stream = zstd::bulk::compress(&data, 3).expect("compresses");
    assert_ne!(stream[4] & 0x20, 0, "a single-segment frame");
    let error = drain(&stream, &limits(4 * KIB, 64), 64).expect_err("refused");
    assert_window_limit(&error, 4 * KIB);
    drain(&stream, &limits(8 * KIB, 64), 64).expect("passes");
}

#[test]
fn no_request_exceeds_the_copy_buffer() {
    let stream = frame(&noise(10_000), 20, true);
    for copy_buffer in [1, 3, 5] {
        let mut guard = WindowGuard::new(
            Counting {
                inner: Cursor::new(&stream[..]),
                largest: 0,
            },
            &limits(1 << 20, copy_buffer),
        );
        let mut out = Vec::new();
        guard.read_to_end(&mut out).expect("passes");
        assert_eq!(out, stream);
        assert_eq!(guard.inner.largest, copy_buffer);
    }
}

#[test]
fn a_frame_whose_window_cannot_be_read_is_refused() {
    let good = frame(b"good", 19, false);
    let mut legacy = good.clone();
    // A zstd v0.7 frame's magic number.
    legacy[0] = 0x27;
    let mut reserved = good.clone();
    reserved[4] |= 0x08;
    let mut after = good.clone();
    after.extend(b"not a frame");
    for stream in [legacy, reserved, after, b"not zstd at all".to_vec()] {
        let error = drain(&stream, &limits(1 << 20, 64), 64).expect_err("refused");
        let WalkError::Payload(crate::payload::PayloadError::Io(error)) = error else {
            panic!("{error:?}");
        };
        assert!(
            error
                .get_ref()
                .is_some_and(<dyn std::error::Error + Send + Sync>::is::<UnreadableFrame>)
        );
    }
}

// ---------------------------------------------------------------------------
// The framing meter
// ---------------------------------------------------------------------------

/// A header block of `kind` named `name` announcing `size` body bytes.
fn header(name: &[u8], size: usize, kind: EntryType) -> Vec<u8> {
    let mut header = Header::new_gnu();
    header.as_mut_bytes()[..name.len()].copy_from_slice(name);
    header.set_size(size as u64);
    header.set_mode(0o644);
    header.set_entry_type(kind);
    header.set_cksum();
    header.as_bytes().to_vec()
}

/// `body` padded to whole blocks.
fn padded(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.resize(body.len().div_ceil(512) * 512, 0);
    out
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut len = body.len();
    while len.to_string().len() + body.len() != len {
        len = len.to_string().len() + body.len();
    }
    format!("{len}{body}").into_bytes()
}

/// A tar whose first entry is an extension record of `kind` with `body`,
/// describing a four-byte regular file `bin/tool`.
fn extended(kind: EntryType, name: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = header(name, body.len(), kind);
    out.extend(padded(body));
    out.extend(header(b"bin/tool", 4, EntryType::Regular));
    out.extend(padded(b"tool"));
    out.extend([0; 1024]);
    out
}

/// Which verdict an oversized record is refused with.
type Verdict = fn(&PayloadError) -> bool;

/// Each extension record form with a body of about `len` bytes, and the
/// verdict an oversized one is refused with.
fn oversized(len: usize) -> Vec<(&'static str, Vec<u8>, Verdict)> {
    let long = format!("bin/{}", "a".repeat(len));
    let mut size = pax_record("size", "4");
    size.extend(pax_record("comment", &"c".repeat(len)));
    vec![
        (
            "pax path",
            extended(EntryType::XHeader, b"pax", &pax_record("path", &long)),
            |e| matches!(e, PayloadError::NameOverridingHeader { .. }),
        ),
        (
            "pax size",
            extended(EntryType::XHeader, b"pax", &size),
            |e| {
                matches!(
                    e,
                    PayloadError::SizeOverridingHeader {
                        resolved_size: 4,
                        ..
                    }
                )
            },
        ),
        (
            "gnu long name",
            extended(EntryType::GNULongName, b"././@LongLink", long.as_bytes()),
            |e| matches!(e, PayloadError::NameOverridingHeader { .. }),
        ),
        (
            "gnu long link",
            extended(EntryType::GNULongLink, b"././@LongLink", long.as_bytes()),
            |e| matches!(e, PayloadError::UnsupportedEntryType { .. }),
        ),
    ]
}

/// A reader recording every request made of it and the bytes it returned.
struct Recording<R> {
    inner: R,
    largest: usize,
    returned: usize,
}

impl<R: Read> Read for Recording<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(buf.len());
        let read = self.inner.read(buf)?;
        self.returned += read;
        Ok(read)
    }
}

fn members_limits(members: u64, copy_buffer: usize) -> OuterLimits {
    OuterLimits {
        members,
        uncompressed_total: 0,
        zstd_window: 1 << 20,
        copy_buffer,
    }
}

#[test]
fn an_oversized_extension_body_never_reaches_the_archive_reader() {
    // Read as the archive reader would, in requests of `chunk` bytes: the
    // extension's header passes, and the first read of its body is the
    // refusal. The meter reads no more of the record than the allowance
    // holds, and never all of it.
    let copy_buffer = 64;
    let limits = members_limits(2, copy_buffer);
    let allowance = framing_allowance(2);
    let len = usize::try_from(allowance * 16).unwrap();
    for (name, tar, expected) in oversized(len) {
        for chunk in [1, copy_buffer] {
            let counters = OuterCounters::new(&limits);
            let mut meter = Meter {
                inner: Recording {
                    inner: Cursor::new(&tar[..]),
                    largest: 0,
                    returned: 0,
                },
                counters: &counters,
                copy_buffer,
                framing: Framing::new(),
            };
            let mut passed = 0;
            let mut buf = vec![0; chunk];
            let error = loop {
                match meter.read(&mut buf) {
                    Ok(0) => panic!("{name}: the stream ended"),
                    Ok(read) => passed += read,
                    Err(error) => break error,
                }
            };
            let WalkError::Payload(error) = stream_error::<()>(error) else {
                panic!("{name}: not a payload verdict");
            };
            assert!(expected(&error), "{name} ({chunk}): {error:?}");
            assert_eq!(passed, 512, "{name} ({chunk}): only the header passed");
            assert!(meter.inner.largest <= copy_buffer, "{name} ({chunk})");
            let pulled = u64::try_from(meter.inner.returned).unwrap();
            assert!(pulled <= allowance, "{name} ({chunk}): pulled {pulled}");
            assert_eq!(counters.member_bytes.get(), 0, "{name} ({chunk})");
        }
    }
}

#[test]
fn a_record_the_allowance_holds_reaches_the_archive_reader() {
    // Under the allowance the record passes whole, for the shared rules to
    // judge, and none of it is member data.
    let copy_buffer = 64;
    let limits = members_limits(16, copy_buffer);
    for (name, tar, _) in oversized(100) {
        let counters = OuterCounters::new(&limits);
        let mut meter = Meter {
            inner: Cursor::new(&tar[..]),
            counters: &counters,
            copy_buffer,
            framing: Framing::new(),
        };
        let mut out = Vec::new();
        meter.read_to_end(&mut out).expect("passes");
        assert_eq!(out, tar, "{name}");
        assert_eq!(counters.member_bytes.get(), 0, "{name}");
        assert_eq!(
            counters.framing_bytes.get(),
            u64::try_from(tar.len()).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn framing_past_its_allowance_is_a_container_verdict() {
    // The end marker of an ordinary archive with no member slot left: the
    // private allowance is exceeded, and that is no public limit.
    let limits = members_limits(0, 512);
    let allowance = framing_allowance(0);
    let tar = vec![0u8; usize::try_from(allowance).unwrap() + 1];
    let counters = OuterCounters::new(&limits);
    let mut meter = Meter {
        inner: Cursor::new(&tar[..]),
        counters: &counters,
        copy_buffer: 512,
        framing: Framing::new(),
    };
    let error = meter.read_to_end(&mut Vec::new()).expect_err("refused");
    let WalkError::Payload(PayloadError::Io(error)) = stream_error::<()>(error) else {
        panic!("not a container verdict");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("framing"), "{error}");
}
