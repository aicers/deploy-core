//! A single-member gzip decoder bounded on its stored and its decoded bytes.
//!
//! The header and trailer framing is parsed here; inflation goes only through
//! `flate2::Decompress` on the Rust backend. Neither std nor any other
//! dependency of this crate provides a DEFLATE decoder, and a hand-written
//! codec is not an option.
//!
//! Stored bytes — header, body and trailer alike — are bounded by the
//! [`CountingReader`] the caller hands in. Decoded bytes are bounded by the
//! [`CountingReader`] the caller wraps this decoder's output in, which asks for
//! at most one byte past its allowance, so expansion stops at the first decoded
//! byte beyond a limit whatever the compression ratio. The trailer's ISIZE is
//! only ever compared, never used to size anything.

use std::io::{self, BufRead, BufReader, Read};

use flate2::{Crc, Decompress, FlushDecompress, Status};

use super::{
    Budget, ContentFault, CountingReader, GzipHeaderFault, Latch, MalformedReason, ResourceLimit,
    UnsupportedFeature, chunk_len, read_full, widen,
};

const ID1: u8 = 0x1f;
const ID2: u8 = 0x8b;
const CM_DEFLATE: u8 = 8;

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
const RESERVED_FLAGS: u8 = 0xe0;

/// Scratch size for skipping FEXTRA bytes, a fixed stack buffer further
/// capped by the copy buffer.
const EXTRA_CHUNK: usize = 512;

/// Where the decoder is in the member, and the stored reader in the form that
/// stage reads it in.
enum Stage<'b, R> {
    /// Header fields are read straight from the stored reader, with no buffer
    /// that could prefetch past the header allowance.
    Header(CountingReader<'b, R>),
    /// Body and trailer are read through a buffer of the copy buffer's size.
    Body(BufReader<CountingReader<'b, R>>),
    /// Trailer and post-trailer checks passed.
    Finished,
}

/// A [`Read`] of the decoded bytes of one gzip member.
///
/// It returns `Ok(0)` only once the trailer has been verified and the stored
/// stream seen to end. A fault is terminal: every later call reports it again.
pub(crate) struct GzipDecoder<'b, R> {
    stage: Stage<'b, R>,
    header: Budget,
    copy_buffer: usize,
    inflate: Decompress,
    crc: Crc,
    stream_ended: bool,
    latch: Latch,
}

impl<'b, R: Read> GzipDecoder<'b, R> {
    /// Returns a decoder over `stored`, whose header may take at most
    /// `header` bytes and whose body is buffered `copy_buffer` bytes at a time.
    pub(crate) fn new(
        stored: CountingReader<'b, R>,
        header: ResourceLimit,
        copy_buffer: usize,
    ) -> GzipDecoder<'b, R> {
        GzipDecoder {
            stage: Stage::Header(stored),
            header: Budget::new(header),
            copy_buffer: copy_buffer.max(1),
            inflate: Decompress::new(false),
            crc: Crc::new(),
            stream_ended: false,
            latch: Latch::default(),
        }
    }

    fn decode(&mut self, out: &mut [u8]) -> Result<usize, ContentFault> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Stage::Header(stored) = &mut self.stage {
            read_header(stored, &mut self.header, self.copy_buffer)?;
            let Stage::Header(stored) = std::mem::replace(&mut self.stage, Stage::Finished) else {
                unreachable!("the stage was just matched as the header stage");
            };
            self.stage = Stage::Body(BufReader::with_capacity(self.copy_buffer, stored));
        }
        let Stage::Body(body) = &mut self.stage else {
            return Ok(0);
        };
        let produced = inflate(
            body,
            &mut self.inflate,
            &mut self.crc,
            &mut self.stream_ended,
            out,
        )?;
        if produced > 0 {
            return Ok(produced);
        }
        verify_trailer(body, &self.crc, self.inflate.total_out())?;
        self.stage = Stage::Finished;
        Ok(0)
    }
}

impl<R: Read> Read for GzipDecoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.latch.check().map_err(ContentFault::into_io)?;
        self.decode(buf)
            .map_err(|fault| self.latch.record(fault).into_io())
    }
}

/// Reads header fields one at a time, each checked against the header
/// allowance before any of its bytes is requested.
struct HeaderReader<'r, 'b, R> {
    stored: &'r mut CountingReader<'b, R>,
    budget: &'r mut Budget,
    crc: Crc,
}

impl<R: Read> HeaderReader<'_, '_, R> {
    fn field<const N: usize>(&mut self) -> Result<[u8; N], ContentFault> {
        let mut field = [0u8; N];
        self.read_into(&mut field)?;
        Ok(field)
    }

    /// Checks the allowance, then reads, charges and hashes `buf`. The check
    /// comes before the stored read, so a byte past both the header allowance
    /// and the stored budget reports the header, the narrower scope.
    fn read_into(&mut self, buf: &mut [u8]) -> Result<(), ContentFault> {
        let len = widen(buf.len());
        self.budget.check(len)?;
        read_full(self.stored, buf)?;
        self.budget.charge(len)?;
        self.crc.update(buf);
        Ok(())
    }

    /// Skips `len` FEXTRA bytes, all of them checked against the allowance
    /// before the first is read.
    fn skip(&mut self, len: u64, copy_buffer: usize) -> Result<(), ContentFault> {
        self.budget.check(len)?;
        let mut left = len;
        let mut scratch = [0u8; EXTRA_CHUNK];
        while left > 0 {
            let chunk = chunk_len(EXTRA_CHUNK.min(copy_buffer), left);
            self.read_into(&mut scratch[..chunk])?;
            left = left.saturating_sub(widen(chunk));
        }
        Ok(())
    }

    /// Skips a NUL-terminated field one byte at a time.
    fn skip_zero_terminated(&mut self) -> Result<(), ContentFault> {
        while self.field::<1>()? != [0] {}
        Ok(())
    }
}

fn read_header<R: Read>(
    stored: &mut CountingReader<'_, R>,
    budget: &mut Budget,
    copy_buffer: usize,
) -> Result<(), ContentFault> {
    let header_fault = |fault| ContentFault::Malformed(MalformedReason::GzipHeader(fault));
    let mut header = HeaderReader {
        stored,
        budget,
        crc: Crc::new(),
    };
    if header.field::<1>()? != [ID1] || header.field::<1>()? != [ID2] {
        return Err(header_fault(GzipHeaderFault::Magic));
    }
    if header.field::<1>()? != [CM_DEFLATE] {
        return Err(header_fault(GzipHeaderFault::Method));
    }
    let [flags] = header.field::<1>()?;
    if flags & RESERVED_FLAGS != 0 {
        return Err(header_fault(GzipHeaderFault::ReservedFlags));
    }
    header.field::<4>()?; // MTIME
    header.field::<1>()?; // XFL
    header.field::<1>()?; // OS
    if flags & FEXTRA != 0 {
        let xlen = u16::from_le_bytes(header.field::<2>()?);
        header.skip(u64::from(xlen), copy_buffer)?;
    }
    if flags & FNAME != 0 {
        header.skip_zero_terminated()?;
    }
    if flags & FCOMMENT != 0 {
        header.skip_zero_terminated()?;
    }
    if flags & FHCRC != 0 {
        let expected = header.crc.sum().to_le_bytes();
        let recorded = header.field::<2>()?;
        if recorded != [expected[0], expected[1]] {
            return Err(header_fault(GzipHeaderFault::HeaderCrc));
        }
    }
    Ok(())
}

/// Inflates into `out` until at least one byte is produced or the DEFLATE
/// stream ends, returning how many bytes were produced — zero only at its end.
fn inflate<R: Read>(
    body: &mut BufReader<CountingReader<'_, R>>,
    inflate: &mut Decompress,
    crc: &mut Crc,
    stream_ended: &mut bool,
    out: &mut [u8],
) -> Result<usize, ContentFault> {
    let deflate_fault = || ContentFault::Malformed(MalformedReason::DeflateData);
    while !*stream_ended {
        let input = body.fill_buf().map_err(ContentFault::from_io)?;
        let at_eof = input.is_empty();
        let (in_before, out_before) = (inflate.total_in(), inflate.total_out());
        let status = inflate
            .decompress(input, out, FlushDecompress::None)
            .map_err(|_| deflate_fault())?;
        let consumed = inflate
            .total_in()
            .checked_sub(in_before)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(deflate_fault)?;
        let produced = inflate
            .total_out()
            .checked_sub(out_before)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(deflate_fault)?;
        body.consume(consumed);
        crc.update(out.get(..produced).ok_or_else(deflate_fault)?);
        if status == Status::StreamEnd {
            *stream_ended = true;
        }
        if produced > 0 {
            return Ok(produced);
        }
        if *stream_ended {
            break;
        }
        if at_eof {
            return Err(ContentFault::Malformed(MalformedReason::Truncated));
        }
        if consumed == 0 {
            // Input and output space were both available and nothing moved:
            // the stream cannot make progress.
            return Err(deflate_fault());
        }
    }
    Ok(0)
}

/// Reads and checks the trailer — CRC32 first, then ISIZE — and then probes
/// for anything after it.
fn verify_trailer<R: Read>(
    body: &mut BufReader<CountingReader<'_, R>>,
    crc: &Crc,
    decoded: u64,
) -> Result<(), ContentFault> {
    let mut trailer = [0u8; 8];
    read_full(body, &mut trailer)?;
    let (crc32, isize) = trailer.split_at(4);
    if crc32 != crc.sum().to_le_bytes() {
        return Err(ContentFault::Malformed(MalformedReason::GzipCrc32));
    }
    let decoded = decoded.to_le_bytes();
    if isize != &decoded[..4] {
        return Err(ContentFault::Malformed(MalformedReason::GzipIsize));
    }
    let trailing = ContentFault::Malformed(MalformedReason::GzipTrailingData);
    let mut probe = [0u8; 1];
    if body.read(&mut probe).map_err(ContentFault::from_io)? == 0 {
        return Ok(());
    }
    if probe != [ID1] {
        return Err(trailing);
    }
    if body.read(&mut probe).map_err(ContentFault::from_io)? == 1 && probe == [ID2] {
        return Err(ContentFault::Unsupported(
            UnsupportedFeature::ConcatenatedGzipMember,
        ));
    }
    Err(trailing)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use flate2::write::GzEncoder;
    use flate2::{Compression, Crc};

    use super::GzipDecoder;
    use crate::content::fixture::{RecordingSource, SourceLog};
    use crate::content::{
        Budget, ContentFault, CountingReader, GzipHeaderFault, MalformedReason, ResourceLimit,
        UnsupportedFeature,
    };
    use crate::package::{ContentLimits, LimitResource};

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Assembles a member by hand with every optional header field.
    fn full_header_member(data: &[u8], extra: &[u8], hcrc_ok: bool) -> Vec<u8> {
        let plain = gzip(data);
        let body = &plain[10..plain.len() - 8];
        let trailer = &plain[plain.len() - 8..];
        let mut header = vec![0x1f, 0x8b, 8, 0x1e | 0x01, 1, 2, 3, 4, 0, 3];
        header.extend_from_slice(&u16::try_from(extra.len()).unwrap().to_le_bytes());
        header.extend_from_slice(extra);
        header.extend_from_slice(b"layer.tar\0");
        header.extend_from_slice(b"a comment\0");
        let mut crc = Crc::new();
        crc.update(&header);
        let mut hcrc = crc.sum().to_le_bytes();
        if !hcrc_ok {
            hcrc[0] ^= 1;
        }
        header.extend_from_slice(&hcrc[..2]);
        [header.as_slice(), body, trailer].concat()
    }

    /// A member whose header is exactly `len` bytes, padded with FEXTRA.
    fn member_with_header_len(data: &[u8], len: usize) -> Vec<u8> {
        let plain = gzip(data);
        let mut member = vec![0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 3];
        let xlen = len - 12;
        member.extend_from_slice(&u16::try_from(xlen).unwrap().to_le_bytes());
        member.extend(std::iter::repeat_n(0xaa, xlen));
        member.extend_from_slice(&plain[10..]);
        member
    }

    struct Limits {
        stored: u64,
        header: u64,
        decoded: u64,
        copy_buffer: usize,
    }

    impl Default for Limits {
        fn default() -> Self {
            Limits {
                stored: 1 << 30,
                header: 64 * 1024,
                decoded: 1 << 30,
                copy_buffer: 1 << 20,
            }
        }
    }

    fn decode_with(member: Vec<u8>, limits: &Limits) -> (Result<Vec<u8>, ContentFault>, SourceLog) {
        let (source, log) = RecordingSource::new(member);
        let stored = CountingReader::new(
            source,
            ResourceLimit {
                resource: LimitResource::StoredLayerBlob,
                max: limits.stored,
            },
            vec![],
            limits.copy_buffer,
        );
        let decoder = GzipDecoder::new(
            stored,
            ResourceLimit {
                resource: LimitResource::GzipHeader,
                max: limits.header,
            },
            limits.copy_buffer,
        );
        let mut output = CountingReader::new(
            decoder,
            ResourceLimit {
                resource: LimitResource::DecodedLayer,
                max: limits.decoded,
            },
            vec![],
            limits.copy_buffer,
        );
        let mut out = Vec::new();
        let result = output
            .read_to_end(&mut out)
            .map(|_| out)
            .map_err(ContentFault::from_io);
        drop(output);
        let log = std::rc::Rc::try_unwrap(log).unwrap().into_inner();
        (result, log)
    }

    fn decode(member: Vec<u8>) -> Result<Vec<u8>, ContentFault> {
        decode_with(member, &Limits::default()).0
    }

    fn malformed(reason: MalformedReason) -> ContentFault {
        ContentFault::Malformed(reason)
    }

    fn header_fault(fault: GzipHeaderFault) -> ContentFault {
        malformed(MalformedReason::GzipHeader(fault))
    }

    fn exceeded(resource: LimitResource, limit: u64) -> ContentFault {
        ContentFault::LimitExceeded { resource, limit }
    }

    fn multi_block() -> Vec<u8> {
        (0..300_000u32)
            .flat_map(|n| n.wrapping_mul(2_654_435_761).to_le_bytes())
            .collect()
    }

    #[test]
    fn valid_members_round_trip() {
        for data in [Vec::new(), b"hello, layer".to_vec(), multi_block()] {
            assert_eq!(decode(gzip(&data)).unwrap(), data);
        }
    }

    #[test]
    fn every_optional_header_field_decodes() {
        let data = b"with every optional header field".to_vec();
        assert_eq!(
            decode(full_header_member(&data, b"xx\x02\x00ab", true)).unwrap(),
            data
        );
        assert_eq!(
            decode(full_header_member(&data, b"", false)).unwrap_err(),
            header_fault(GzipHeaderFault::HeaderCrc)
        );
    }

    #[test]
    fn a_small_copy_buffer_decodes_identically_within_it() {
        let data = multi_block();
        for member in [gzip(&data), full_header_member(&data, b"extra field", true)] {
            let limits = Limits {
                copy_buffer: 7,
                ..Limits::default()
            };
            let (result, log) = decode_with(member, &limits);
            assert_eq!(result.unwrap(), data);
            assert!(log.requests.iter().all(|request| *request <= 7));
        }
    }

    #[test]
    fn header_faults_are_malformed() {
        let good = gzip(b"data");
        let edit = |offset: usize, value: u8| {
            let mut member = good.clone();
            member[offset] = value;
            member
        };
        assert_eq!(
            decode(edit(0, 0x1e)).unwrap_err(),
            header_fault(GzipHeaderFault::Magic)
        );
        assert_eq!(
            decode(edit(1, 0x8a)).unwrap_err(),
            header_fault(GzipHeaderFault::Magic)
        );
        assert_eq!(
            decode(edit(2, 7)).unwrap_err(),
            header_fault(GzipHeaderFault::Method)
        );
        assert_eq!(
            decode(edit(3, 0x20)).unwrap_err(),
            header_fault(GzipHeaderFault::ReservedFlags)
        );
    }

    #[test]
    fn body_and_trailer_faults_are_malformed() {
        let good = gzip(b"a body long enough to corrupt in the middle of its deflate data");
        let len = good.len();
        let mut corrupt = good.clone();
        // A reserved block type (BTYPE 11) in the first block header.
        corrupt[10] |= 0b110;
        assert_eq!(
            decode(corrupt).unwrap_err(),
            malformed(MalformedReason::DeflateData)
        );
        for cut in [5, 12, len - 4] {
            assert_eq!(
                decode(good[..cut].to_vec()).unwrap_err(),
                malformed(MalformedReason::Truncated),
                "cut at {cut}"
            );
        }
        let mut crc = good.clone();
        crc[len - 8] ^= 1;
        assert_eq!(
            decode(crc).unwrap_err(),
            malformed(MalformedReason::GzipCrc32)
        );
        let mut isize = good.clone();
        isize[len - 4] ^= 1;
        assert_eq!(
            decode(isize).unwrap_err(),
            malformed(MalformedReason::GzipIsize)
        );
        let mut both = good.clone();
        both[len - 8] ^= 1;
        both[len - 4] ^= 1;
        assert_eq!(
            decode(both).unwrap_err(),
            malformed(MalformedReason::GzipCrc32)
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let good = gzip(b"data");
        for tail in [&[0x00][..], &[0x1f], &[0x1f, 0x00], &[0, 0, 0, 0]] {
            assert_eq!(
                decode([good.as_slice(), tail].concat()).unwrap_err(),
                malformed(MalformedReason::GzipTrailingData)
            );
        }
    }

    #[test]
    fn a_second_member_is_unsupported_and_never_decoded() {
        let first = gzip(b"first");
        let second = gzip(b"second");
        let concatenated = ContentFault::Unsupported(UnsupportedFeature::ConcatenatedGzipMember);
        assert_eq!(
            decode([first.as_slice(), second.as_slice()].concat()).unwrap_err(),
            concatenated
        );
        let mut corrupt = second.clone();
        corrupt[10] |= 0b110;
        corrupt[2] = 7;
        assert_eq!(
            decode([first.as_slice(), corrupt.as_slice()].concat()).unwrap_err(),
            concatenated
        );
    }

    #[test]
    fn the_header_limit_counts_from_the_first_byte() {
        let good = gzip(b"data");
        let at = |header: u64, member: Vec<u8>| {
            decode_with(
                member,
                &Limits {
                    header,
                    ..Limits::default()
                },
            )
        };
        let (result, log) = at(0, good.clone());
        assert_eq!(result.unwrap_err(), exceeded(LimitResource::GzipHeader, 0));
        assert_eq!(log.delivered, 0);
        let (result, log) = at(1, good.clone());
        assert_eq!(result.unwrap_err(), exceeded(LimitResource::GzipHeader, 1));
        assert_eq!(log.delivered, 1);
        let mut bad_magic = good.clone();
        bad_magic[0] = 0;
        assert_eq!(
            at(1, bad_magic).0.unwrap_err(),
            header_fault(GzipHeaderFault::Magic)
        );
        assert_eq!(at(10, good.clone()).0.unwrap(), b"data");
        assert_eq!(
            at(9, good).0.unwrap_err(),
            exceeded(LimitResource::GzipHeader, 9)
        );
    }

    #[test]
    fn a_full_size_header_passes_and_one_more_byte_fails() {
        let max = 64 * 1024;
        assert_eq!(
            at_default_header(member_with_header_len(b"data", max)).unwrap(),
            b"data"
        );
        let mut over = vec![0x1f, 0x8b, 8, 0x04 | 0x08, 0, 0, 0, 0, 0, 3];
        let xlen = max - 12;
        over.extend_from_slice(&u16::try_from(xlen).unwrap().to_le_bytes());
        over.extend(std::iter::repeat_n(0xaa, xlen));
        over.extend_from_slice(b"n\0");
        assert_eq!(
            at_default_header(over).unwrap_err(),
            exceeded(LimitResource::GzipHeader, 64 * 1024)
        );
    }

    fn at_default_header(member: Vec<u8>) -> Result<Vec<u8>, ContentFault> {
        let limits = ContentLimits::default();
        decode_with(
            member,
            &Limits {
                header: limits.get(LimitResource::GzipHeader),
                ..Limits::default()
            },
        )
        .0
    }

    #[test]
    fn an_oversize_fextra_fails_before_any_of_it_is_read() {
        let member = member_with_header_len(b"data", 1000);
        let (result, log) = decode_with(
            member,
            &Limits {
                header: 500,
                ..Limits::default()
            },
        );
        assert_eq!(
            result.unwrap_err(),
            exceeded(LimitResource::GzipHeader, 500)
        );
        // ID1 through OS, then XLEN; none of the 988 extra bytes.
        assert_eq!(log.delivered, 12);
    }

    #[test]
    fn no_header_request_exceeds_the_remaining_allowance() {
        let data = b"allowance".to_vec();
        let member = full_header_member(&data, &[0x55; 40], true);
        let header_len = 10 + 2 + 40 + 10 + 10 + 2;
        let (result, log) = decode_with(
            member,
            &Limits {
                header: header_len,
                ..Limits::default()
            },
        );
        assert_eq!(result.unwrap(), data);
        let mut remaining = header_len;
        for request in &log.requests {
            if remaining == 0 {
                break;
            }
            assert!(u64::try_from(*request).unwrap() <= remaining);
            remaining -= u64::try_from(*request).unwrap();
        }
        assert_eq!(remaining, 0);
    }

    #[test]
    fn the_header_limit_wins_over_the_stored_limit_at_the_same_byte() {
        let (result, _) = decode_with(
            gzip(b"data"),
            &Limits {
                header: 4,
                stored: 4,
                ..Limits::default()
            },
        );
        assert_eq!(result.unwrap_err(), exceeded(LimitResource::GzipHeader, 4));
    }

    #[test]
    fn reserved_flags_win_over_an_oversize_name() {
        let mut member = vec![0x1f, 0x8b, 8, 0x20 | 0x08, 0, 0, 0, 0, 0, 3];
        member.extend(std::iter::repeat_n(b'n', 100));
        let (result, _) = decode_with(
            member,
            &Limits {
                header: 20,
                ..Limits::default()
            },
        );
        assert_eq!(
            result.unwrap_err(),
            header_fault(GzipHeaderFault::ReservedFlags)
        );
    }

    #[test]
    fn the_decoded_limit_stops_expansion_whatever_the_ratio() {
        let member = gzip(&vec![0u8; 4 << 20]);
        assert!(member.len() < 16 * 1024);
        let limits = Limits {
            decoded: 1 << 20,
            copy_buffer: 64 * 1024,
            ..Limits::default()
        };
        let (source, log) = RecordingSource::new(member);
        let stored = CountingReader::new(
            source,
            ResourceLimit {
                resource: LimitResource::StoredLayerBlob,
                max: limits.stored,
            },
            vec![],
            limits.copy_buffer,
        );
        let decoder = GzipDecoder::new(
            stored,
            ResourceLimit {
                resource: LimitResource::GzipHeader,
                max: limits.header,
            },
            limits.copy_buffer,
        );
        let mut per_image = Budget::new(ResourceLimit {
            resource: LimitResource::DecodedLayersPerImage,
            max: 1 << 30,
        });
        let mut output = CountingReader::new(
            decoder,
            ResourceLimit {
                resource: LimitResource::DecodedLayer,
                max: limits.decoded,
            },
            vec![&mut per_image],
            limits.copy_buffer,
        );
        let mut out = Vec::new();
        let fault = ContentFault::from_io(output.read_to_end(&mut out).unwrap_err());
        assert_eq!(fault, exceeded(LimitResource::DecodedLayer, 1 << 20));
        assert_eq!(out.len(), 1 << 20);
        drop(output);
        assert_eq!(per_image.used(), 1 << 20);
        assert!(log.borrow().delivered < 16 * 1024);
    }

    #[test]
    fn the_stored_limit_passes_at_the_limit_and_fails_one_below() {
        let member = gzip(&multi_block());
        let len = u64::try_from(member.len()).unwrap();
        let at = |stored: u64| {
            decode_with(
                member.clone(),
                &Limits {
                    stored,
                    copy_buffer: 4096,
                    ..Limits::default()
                },
            )
            .0
        };
        assert_eq!(at(len).unwrap(), multi_block());
        assert_eq!(
            at(len - 1).unwrap_err(),
            exceeded(LimitResource::StoredLayerBlob, len - 1)
        );
    }

    #[test]
    fn a_lying_isize_sizes_nothing() {
        let mut member = gzip(b"0123456789");
        let len = member.len();
        member[len - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        let (result, log) = decode_with(
            member,
            &Limits {
                copy_buffer: 64,
                ..Limits::default()
            },
        );
        assert_eq!(result.unwrap_err(), malformed(MalformedReason::GzipIsize));
        assert!(log.requests.iter().all(|request| *request <= 64));
    }

    #[test]
    fn the_first_fault_in_stream_order_wins_over_a_bad_trailer() {
        let mut member = gzip(&vec![7u8; 10_000]);
        let len = member.len();
        member[len - 8] ^= 1;
        member[len - 4] ^= 1;
        let (result, _) = decode_with(
            member,
            &Limits {
                decoded: 100,
                ..Limits::default()
            },
        );
        assert_eq!(
            result.unwrap_err(),
            exceeded(LimitResource::DecodedLayer, 100)
        );

        let mut corrupt = gzip(b"a body long enough to corrupt in the middle of its deflate data");
        let len = corrupt.len();
        corrupt[10] |= 0b110;
        corrupt[len - 8] ^= 1;
        assert_eq!(
            decode(corrupt).unwrap_err(),
            malformed(MalformedReason::DeflateData)
        );
    }

    #[test]
    fn faults_are_terminal() {
        let mut member = gzip(b"data");
        member[0] = 0;
        let (source, _) = RecordingSource::new(member);
        let stored = CountingReader::new(
            source,
            ResourceLimit {
                resource: LimitResource::StoredLayerBlob,
                max: 100,
            },
            vec![],
            64,
        );
        let mut decoder = GzipDecoder::new(
            stored,
            ResourceLimit {
                resource: LimitResource::GzipHeader,
                max: 100,
            },
            64,
        );
        let mut buf = [0u8; 16];
        for _ in 0..2 {
            assert_eq!(
                ContentFault::from_io(decoder.read(&mut buf).unwrap_err()),
                header_fault(GzipHeaderFault::Magic)
            );
        }
    }
}
