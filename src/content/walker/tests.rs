use std::io::{Read, Write};
use std::rc::Rc;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::content::fixture::{
    BLOCK, Header, RecordingSource, SourceLog, Tar, octal_checksum, pax,
};
use crate::content::{
    Budget, ContentFault, CountingReader, EntryKind, EntryPolicy, EntryReader, GzipDecoder,
    MalformedReason, PaxKey, TarEntry, TarField, TarWalker, UnsupportedFeature,
};
use crate::package::{ContentLimits, LimitResource};

type Walked = Vec<(TarEntry, Vec<u8>)>;

#[derive(Clone, Copy)]
enum Policy {
    Image,
    Layer,
}

fn collect<R: Read>(walker: &mut TarWalker<'_, '_, R>) -> Result<Walked, ContentFault> {
    let mut found = Vec::new();
    while let Some(entry) = walker.next_entry()? {
        let mut data = Vec::new();
        let mut reader: EntryReader<'_, '_, '_, R> = walker.entry_reader();
        reader
            .read_to_end(&mut data)
            .map_err(ContentFault::from_io)?;
        found.push((entry, data));
    }
    Ok(found)
}

/// Walks `bytes` under `policy`, with a layer's decoded chain limited by
/// `limits` and the per-image budget capped at `per_image`.
fn run_with(
    bytes: &[u8],
    policy: Policy,
    limits: &ContentLimits,
    per_image: u64,
) -> (Result<Walked, ContentFault>, SourceLog) {
    let (source, log) = RecordingSource::new(bytes.to_vec());
    let copy_buffer = limits.copy_buffer_len();
    let result = match policy {
        Policy::Image => {
            let reader = CountingReader::new(
                source,
                limits.resource_limit(LimitResource::ImageArchive),
                vec![],
                copy_buffer,
            );
            collect(&mut TarWalker::new(
                reader,
                EntryPolicy::ImageArchive,
                limits,
            ))
        }
        Policy::Layer => {
            let mut entries = Budget::new(limits.resource_limit(LimitResource::LayerEntries));
            let mut extension_total =
                Budget::new(limits.resource_limit(LimitResource::LayerExtensionTotal));
            let mut image = Budget::new(
                limits
                    .clone()
                    .with_limit(LimitResource::DecodedLayersPerImage, per_image)
                    .unwrap()
                    .resource_limit(LimitResource::DecodedLayersPerImage),
            );
            let mut operation =
                Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
            let reader = CountingReader::new(
                source,
                limits.resource_limit(LimitResource::DecodedLayer),
                vec![&mut image, &mut operation],
                copy_buffer,
            );
            let policy = EntryPolicy::Layer {
                entries: &mut entries,
                extension_total: &mut extension_total,
            };
            collect(&mut TarWalker::new(reader, policy, limits))
        }
    };
    let log = Rc::try_unwrap(log).unwrap().into_inner();
    (result, log)
}

fn run(
    bytes: &[u8],
    policy: Policy,
    limits: &ContentLimits,
) -> (Result<Walked, ContentFault>, SourceLog) {
    let per_image = limits.get(LimitResource::DecodedLayersPerImage);
    run_with(bytes, policy, limits, per_image)
}

fn image(bytes: &[u8]) -> Result<Walked, ContentFault> {
    run(bytes, Policy::Image, &ContentLimits::default()).0
}

fn layer(bytes: &[u8]) -> Result<Walked, ContentFault> {
    run(bytes, Policy::Layer, &ContentLimits::default()).0
}

fn limits_with(resource: LimitResource, value: u64) -> ContentLimits {
    ContentLimits::default()
        .with_limit(resource, value)
        .unwrap()
}

fn malformed(reason: MalformedReason) -> ContentFault {
    ContentFault::Malformed(reason)
}

fn unsupported(feature: UnsupportedFeature) -> ContentFault {
    ContentFault::Unsupported(feature)
}

fn entry_type(flag: u8) -> ContentFault {
    unsupported(UnsupportedFeature::EntryType { flag })
}

fn numeric(field: TarField) -> ContentFault {
    malformed(MalformedReason::TarNumericField { field })
}

fn exceeded(resource: LimitResource, limit: u64) -> ContentFault {
    ContentFault::LimitExceeded { resource, limit }
}

fn names(walked: &Walked) -> Vec<&[u8]> {
    walked
        .iter()
        .map(|(entry, _)| entry.name.as_slice())
        .collect()
}

fn one_file(header: &Header) -> Vec<u8> {
    Tar::new().header(header).finish()
}

fn both(bytes: &[u8]) -> [Result<Walked, ContentFault>; 2] {
    [image(bytes), layer(bytes)]
}

fn assert_both(bytes: &[u8], expected: &ContentFault) {
    for result in both(bytes) {
        assert_eq!(&result.unwrap_err(), expected);
    }
}

// ---------------------------------------------------------------------------
// Framing, both policies
// ---------------------------------------------------------------------------

#[test]
fn posix_and_gnu_headers_mix_in_one_stream() {
    let bytes = Tar::new()
        .entry(&Header::file(b"a", 3), b"abc")
        .entry(Header::file(b"b", 2).gnu(), b"de")
        .entry(Header::file(b"c", 1).prefix(b"dir"), b"f")
        .finish();
    for result in both(&bytes) {
        let walked = result.unwrap();
        assert_eq!(names(&walked), [&b"a"[..], b"b", b"dir/c"]);
        assert_eq!(walked[1].1, b"de");
    }
}

#[test]
fn base_256_values_are_read() {
    let mut size = Header::file(b"sized", 0);
    size.set(124, &[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00]);
    let mut uid = Header::file(b"uid", 0);
    uid.set(108, &[0x81, 0, 0, 0, 0, 0, 0, 0]);
    let mut top = Header::file(b"top", 0);
    top.set(116, &[0xbf, 0, 0, 0, 0, 0, 0, 0]);
    let bytes = Tar::new()
        .entry(&size, &[9; 4096])
        .header(&uid)
        .header(&top)
        .finish();
    let walked = image(&bytes).unwrap();
    assert_eq!(walked[0].0.size, 4096);
    assert_eq!(walked[0].1, vec![9; 4096]);
    assert_eq!(names(&walked), [&b"sized"[..], b"uid", b"top"]);
}

#[test]
fn base_256_values_have_their_exact_magnitude() {
    // Only `size` reaches an entry, so the other fields' values are checked
    // at the parser itself.
    let read = |field: &[u8]| super::parse_numeric(field, TarField::Uid);
    assert_eq!(read(&[0x81, 0, 0, 0, 0, 0, 0, 0]).unwrap(), 1 << 56);
    assert_eq!(read(&[0xbf, 0, 0, 0, 0, 0, 0, 0]).unwrap(), 63 << 56);
    assert_eq!(
        read(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00]).unwrap(),
        4096
    );
    assert_eq!(
        read(&[
            0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        ])
        .unwrap(),
        u64::MAX
    );
    assert_eq!(
        read(&[0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
        numeric(TarField::Uid)
    );
}

#[test]
fn empty_and_space_numeric_fields_read_as_zero() {
    let mut header = Header::file(b"zeroes", 0);
    header.set(108, &[0; 8]).set(116, b"        ");
    header.set(100, b"   644 \0");
    image(&one_file(&header)).unwrap();
}

#[test]
fn checksum_layouts_are_accepted() {
    let six = Header::file(b"six", 0);
    let mut seven = Header::file(b"seven", 0);
    seven.formatted_checksum(|sum| format!("{sum:07o}\0").as_bytes().try_into().unwrap());
    let mut leading = Header::file(b"leading", 0);
    leading.formatted_checksum(|sum| format!("  {sum:05o}\0").as_bytes().try_into().unwrap());
    let mut signed = Header::file("caf\u{e9}".as_bytes(), 0);
    signed.signed_checksum();
    assert_eq!(&six.build()[154..156], b"\0 ");
    let bytes = Tar::new()
        .header(&six)
        .header(&seven)
        .header(&leading)
        .finish();
    image(&bytes).unwrap();
    // Non-ASCII names are for layers; the signed sum differs from the
    // unsigned one only when a byte has its high bit set.
    assert_ne!(signed.build(), {
        let mut unsigned = signed.clone();
        unsigned.formatted_checksum(octal_checksum);
        unsigned.build()
    });
    layer(&one_file(&signed)).unwrap();
}

#[test]
fn every_entry_reports_its_offsets() {
    let bytes = Tar::new()
        .entry(&Header::file(b"a", 0), b"")
        .entry(&Header::file(b"b", 1), b"x")
        .entry(&Header::file(b"c", 512), &[1; 512])
        .entry(&Header::file(b"d", 513), &[2; 513])
        .finish();
    let walked = image(&bytes).unwrap();
    let offsets: Vec<(u64, u64, u64)> = walked
        .iter()
        .map(|(entry, _)| (entry.header_offset, entry.data_offset, entry.data_len))
        .collect();
    assert_eq!(
        offsets,
        [
            (0, 512, 0),
            (512, 1024, 1),
            (1536, 2048, 512),
            (2560, 3072, 513)
        ]
    );
}

#[test]
fn a_partly_read_entry_is_skipped_to_the_next_header() {
    let bytes = Tar::new()
        .entry(&Header::file(b"big", 3000), &[5; 3000])
        .entry(&Header::file(b"next", 4), b"next")
        .finish();
    let limits = limits_with(LimitResource::CopyBuffer, 100);
    let reader = CountingReader::new(
        bytes.as_slice(),
        limits.resource_limit(LimitResource::ImageArchive),
        vec![],
        limits.copy_buffer_len(),
    );
    let mut walker = TarWalker::new(reader, EntryPolicy::ImageArchive, &limits);
    walker.next_entry().unwrap().unwrap();
    let mut partial = [0u8; 3];
    walker.entry_reader().read_exact(&mut partial).unwrap();
    let next = walker.next_entry().unwrap().unwrap();
    assert_eq!(next.name, b"next");
    let mut data = Vec::new();
    walker.entry_reader().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"next");
    assert!(walker.next_entry().unwrap().is_none());
    assert!(walker.next_entry().unwrap().is_none());
}

#[test]
fn checksum_field_faults() {
    for raw in [
        *b"012348\0 ",
        *b"01234\x005 ",
        [0x80, 0, 0, 0, 0, 0, 0x10, 0],
        *b"        ",
        *b"\0\0\0\0\0\0\0\0",
    ] {
        let mut header = Header::file(b"a", 0);
        header.raw_checksum(raw);
        assert_both(&one_file(&header), &numeric(TarField::Checksum));
    }
}

#[test]
fn numeric_field_faults() {
    let mut after_nul = Header::file(b"a", 0);
    after_nul.set(124, b"0000000\x001234");
    assert_both(&one_file(&after_nul), &numeric(TarField::Size));
    let mut bad_digit = Header::file(b"a", 0);
    bad_digit.set(100, b"0000648\0");
    assert_both(&one_file(&bad_digit), &numeric(TarField::Mode));
    for first in [0xc0, 0xff] {
        let mut negative = Header::file(b"a", 0);
        negative.set(108, &[first, 0, 0, 0, 0, 0, 0, 1]);
        assert_both(&one_file(&negative), &numeric(TarField::Uid));
    }
    let mut too_big = Header::file(b"a", 0);
    too_big.set(124, &[0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_both(&one_file(&too_big), &numeric(TarField::Size));
    let mut mtime = Header::file(b"a", 0);
    mtime.set(136, b"0000000000x\0");
    assert_both(&one_file(&mtime), &numeric(TarField::Mtime));
    let mut gid = Header::file(b"a", 0);
    gid.set(116, b"12 3456\0");
    assert_both(&one_file(&gid), &numeric(TarField::Gid));
}

#[test]
fn device_numbers_are_parsed_on_device_entries_only() {
    let mut device = Header::new(b'3', b"dev/null", 0);
    device.set(329, b"0000001\0").set(337, b"000000x\0");
    assert_eq!(
        layer(&one_file(&device)).unwrap_err(),
        numeric(TarField::DevMinor)
    );
    let mut block = Header::new(b'4', b"dev/sda", 0);
    block.set(329, b"0000x01\0");
    assert_eq!(
        layer(&one_file(&block)).unwrap_err(),
        numeric(TarField::DevMajor)
    );
    let mut regular = Header::file(b"file", 0);
    regular.set(329, b"garbage!garbage!");
    layer(&one_file(&regular)).unwrap();
}

#[test]
fn name_field_faults() {
    let mut name = Header::file(b"a\0b", 0);
    name.set(0, b"a\0b");
    assert_both(
        &one_file(&name),
        &malformed(MalformedReason::TarNameField {
            field: TarField::Name,
        }),
    );
    let mut linkname = Header::file(b"a", 0);
    linkname.linkname(b"x\0y");
    assert_both(
        &one_file(&linkname),
        &malformed(MalformedReason::TarNameField {
            field: TarField::Linkname,
        }),
    );
    let mut prefix = Header::file(b"a", 0);
    prefix.prefix(b"p\0q");
    assert_both(
        &one_file(&prefix),
        &malformed(MalformedReason::TarNameField {
            field: TarField::Prefix,
        }),
    );
    let mut gnu = Header::file(b"a", 0);
    gnu.gnu().set(345, b"p\0q").set(500, b"\x01\x02");
    for result in both(&one_file(&gnu)) {
        assert_eq!(names(&result.unwrap()), [&b"a"[..]]);
    }
}

#[test]
fn a_full_width_name_needs_no_terminator() {
    let name = [b'n'; 100];
    for result in both(&one_file(&Header::file(&name, 0))) {
        assert_eq!(names(&result.unwrap()), [&name[..]]);
    }
}

// ---------------------------------------------------------------------------
// End of archive
// ---------------------------------------------------------------------------

fn with_tail(tail: &[u8]) -> Vec<u8> {
    Tar::new()
        .entry(&Header::file(b"a", 1), b"x")
        .raw(tail)
        .unfinished()
}

#[test]
fn zero_tails_in_whole_blocks_are_accepted() {
    for len in [1024, 1536, 1_048_576] {
        for result in both(&with_tail(&vec![0; len])) {
            assert_eq!(result.unwrap().len(), 1, "tail of {len}");
        }
    }
}

#[test]
fn a_zero_tail_past_the_allowance_is_refused_at_its_first_extra_byte() {
    let prefix = with_tail(&[]).len();
    let bytes = with_tail(&vec![0; 1_048_576 + 512]);
    for policy in [Policy::Image, Policy::Layer] {
        let (result, log) = run(&bytes, policy, &ContentLimits::default());
        assert_eq!(
            result.unwrap_err(),
            malformed(MalformedReason::ZeroTailTooLong)
        );
        assert_eq!(log.delivered, prefix + 1_048_577);
    }
    let mut nonzero = vec![0; 1_048_576];
    nonzero.push(7);
    assert_both(
        &with_tail(&nonzero),
        &malformed(MalformedReason::ZeroTailTooLong),
    );
}

#[test]
fn a_short_or_ragged_tail_is_truncated() {
    assert_both(
        &with_tail(&[0; 512]),
        &malformed(MalformedReason::Truncated),
    );
    assert_both(
        &with_tail(&[0; 1124]),
        &malformed(MalformedReason::Truncated),
    );
    assert_both(
        &with_tail(&[0; 700]),
        &malformed(MalformedReason::Truncated),
    );
}

#[test]
fn nonzero_bytes_after_the_marker_are_trailing_data() {
    let mut third = vec![0; 1536];
    third[1100] = 1;
    assert_both(
        &with_tail(&third),
        &malformed(MalformedReason::TrailingData),
    );
    let second_archive = Tar::new().entry(&Header::file(b"b", 1), b"y").finish();
    let bytes = [with_tail(&[0; 1024]), second_archive].concat();
    assert_both(&bytes, &malformed(MalformedReason::TrailingData));
    // The first offending byte decides: a nonzero byte in a short tail.
    let mut short = vec![0; 600];
    short[550] = 1;
    assert_both(
        &with_tail(&short),
        &malformed(MalformedReason::TrailingData),
    );
}

// ---------------------------------------------------------------------------
// Header faults
// ---------------------------------------------------------------------------

#[test]
fn truncation_anywhere_is_truncated() {
    let full = Tar::new()
        .entry(&Header::file(b"a", 100), &[1; 100])
        .finish();
    for cut in [0, 100, 512 + 50, 512 + 300, 1024 + 10] {
        assert_both(&full[..cut], &malformed(MalformedReason::Truncated));
    }
}

#[test]
fn a_checksum_mismatch_is_refused() {
    let mut header = Header::file(b"a", 0);
    header.wrong_checksum();
    assert_both(&one_file(&header), &malformed(MalformedReason::TarChecksum));
}

#[test]
fn a_header_without_magic_is_unsupported() {
    let mut v7 = Header::file(b"a", 0);
    v7.no_magic();
    assert_both(&one_file(&v7), &unsupported(UnsupportedFeature::TarFormat));
    let mut version = Header::file(b"a", 0);
    version.set(263, b"01");
    assert_both(
        &one_file(&version),
        &unsupported(UnsupportedFeature::TarFormat),
    );
}

#[test]
fn a_size_whose_padded_end_overflows_is_refused() {
    let mut header = Header::file(b"a", 0);
    header.set(
        124,
        &[
            0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0,
        ],
    );
    assert_both(
        &one_file(&header),
        &malformed(MalformedReason::OffsetOverflow),
    );
}

#[test]
fn a_fault_is_terminal_across_the_walker_and_its_reader() {
    let mut bad = Header::file(b"b", 0);
    bad.wrong_checksum();
    let bytes = Tar::new()
        .entry(&Header::file(b"a", 10), &[1; 10])
        .header(&bad)
        .finish();
    let limits = ContentLimits::default();
    let reader = CountingReader::new(
        bytes.as_slice(),
        limits.resource_limit(LimitResource::ImageArchive),
        vec![],
        limits.copy_buffer_len(),
    );
    let mut walker = TarWalker::new(reader, EntryPolicy::ImageArchive, &limits);
    walker.next_entry().unwrap().unwrap();
    let fault = malformed(MalformedReason::TarChecksum);
    assert_eq!(walker.next_entry().unwrap_err(), fault);
    assert_eq!(walker.next_entry().unwrap_err(), fault);
    let err = walker.entry_reader().read(&mut [0; 4]).unwrap_err();
    assert_eq!(ContentFault::from_io(err), fault);
}

// ---------------------------------------------------------------------------
// ImageArchive policy
// ---------------------------------------------------------------------------

#[test]
fn an_image_archive_admits_files_and_directories() {
    let bytes = Tar::new()
        .header(&Header::dir(b"blobs/"))
        .header(&Header::dir(b"blobs/sha256/"))
        .entry(&Header::file(b"blobs/sha256/abc", 2), b"{}")
        .entry(&Header::new(0, b"oci-layout", 2), b"{}")
        .header(&Header::dir(b"other"))
        .finish();
    let walked = image(&bytes).unwrap();
    let kinds: Vec<EntryKind> = walked.iter().map(|(entry, _)| entry.kind).collect();
    assert_eq!(
        kinds,
        [
            EntryKind::Directory,
            EntryKind::Directory,
            EntryKind::Regular,
            EntryKind::Regular,
            EntryKind::Directory
        ]
    );
    assert_eq!(walked[1].0.canonical_name(), b"blobs/sha256");
    assert_eq!(walked[1].0.name, b"blobs/sha256/");
}

#[test]
fn an_image_archive_refuses_every_other_type() {
    for flag in *b"123467SxgLKZ" {
        let header = Header::new(flag, b"a", 0);
        assert_eq!(image(&one_file(&header)).unwrap_err(), entry_type(flag));
    }
}

#[test]
fn an_image_archive_refuses_unsafe_names() {
    let unsafe_path = malformed(MalformedReason::UnsafePath);
    for name in [
        &b"/abs"[..],
        b"a/../b",
        b"a/./b",
        b"./a",
        b"a//b",
        b"a\\b",
        b"a\x01b",
        b"a\x7fb",
        "caf\u{e9}".as_bytes(),
        b"file/",
    ] {
        assert_eq!(
            image(&one_file(&Header::file(name, 0))).unwrap_err(),
            unsafe_path
        );
    }
    assert_eq!(
        image(&one_file(&Header::dir(b"dir//"))).unwrap_err(),
        unsafe_path
    );
    assert_eq!(
        image(&one_file(&Header::dir(b"/"))).unwrap_err(),
        unsafe_path
    );
    let mut joined = Header::file(b"/b", 0);
    joined.prefix(b"a");
    assert_eq!(image(&one_file(&joined)).unwrap_err(), unsafe_path);
}

#[test]
fn an_image_archive_refuses_repeated_names() {
    let duplicate = malformed(MalformedReason::DuplicatePath);
    let conflict = malformed(MalformedReason::PathConflict);
    let pair = |first: Header, second: Header| {
        image(&Tar::new().header(&first).header(&second).finish()).unwrap_err()
    };
    assert_eq!(
        pair(Header::file(b"a", 0), Header::file(b"a", 0)),
        duplicate
    );
    assert_eq!(pair(Header::dir(b"dir/"), Header::dir(b"dir")), duplicate);
    assert_eq!(pair(Header::file(b"a", 0), Header::dir(b"a/")), conflict);
    assert_eq!(pair(Header::dir(b"a/"), Header::file(b"a", 0)), conflict);
    assert_eq!(
        pair(Header::file(b"a", 0), Header::file(b"a/b", 0)),
        conflict
    );
    assert_eq!(
        pair(Header::file(b"a/b", 0), Header::file(b"a", 0)),
        conflict
    );
    assert_eq!(
        pair(Header::file(b"a", 0), Header::dir(b"a/b/c/")),
        conflict
    );
    assert_eq!(
        pair(Header::dir(b"a/b/c/"), Header::file(b"a/b", 0)),
        conflict
    );
    // A name that merely starts with a file's name is not beneath it.
    let bytes = Tar::new()
        .header(&Header::file(b"a", 0))
        .header(&Header::file(b"ab", 0))
        .header(&Header::file(b"a.b/c", 0))
        .header(&Header::dir(b"x/"))
        .header(&Header::file(b"x/y", 0))
        .finish();
    image(&bytes).unwrap();
}

#[test]
fn an_image_archive_directory_carries_no_data() {
    let mut header = Header::dir(b"dir/");
    header.size(1);
    let bytes = Tar::new().entry(&header, b"x").finish();
    assert_eq!(
        image(&bytes).unwrap_err(),
        malformed(MalformedReason::NonRegularWithData)
    );
}

/// A POSIX header whose joined name is `len` bytes, ending in `tail`.
fn long_name(len: usize, tail: &[u8], directory: bool) -> Header {
    let name_len = 100.min(len - 1 - 1) - tail.len();
    let mut name = vec![b'n'; name_len];
    name.extend_from_slice(tail);
    let prefix = vec![b'p'; len - name.len() - 1];
    let mut header = if directory {
        Header::dir(&name)
    } else {
        Header::file(&name, 0)
    };
    header.prefix(&prefix);
    header
}

#[test]
fn image_path_bytes_are_measured_as_written() {
    let limit = exceeded(LimitResource::ImagePathBytes, 255);
    image(&one_file(&long_name(255, b"", false))).unwrap();
    assert_eq!(
        image(&one_file(&long_name(256, b"", false))).unwrap_err(),
        limit
    );
    image(&one_file(&long_name(255, b"/", true))).unwrap();
    assert_eq!(
        image(&one_file(&long_name(256, b"/", true))).unwrap_err(),
        limit
    );
    // Checked before syntax.
    assert_eq!(
        image(&one_file(&long_name(256, b"/..", false))).unwrap_err(),
        limit
    );
}

#[test]
fn image_entries_pass_at_the_limit() {
    let limits = limits_with(LimitResource::ImageEntries, 3);
    let files = |n: usize| {
        let mut tar = Tar::new();
        for index in 0..n {
            tar.header(&Header::file(format!("f{index}").as_bytes(), 0));
        }
        tar.finish()
    };
    assert_eq!(run(&files(3), Policy::Image, &limits).0.unwrap().len(), 3);
    assert_eq!(
        run(&files(4), Policy::Image, &limits).0.unwrap_err(),
        exceeded(LimitResource::ImageEntries, 3)
    );
}

// ---------------------------------------------------------------------------
// Layer policy
// ---------------------------------------------------------------------------

#[test]
fn a_layer_admits_every_kind() {
    let mut hardlink = Header::new(b'1', b"link", 0);
    hardlink.linkname(b"file");
    let mut symlink = Header::new(b'2', b"sym", 0);
    symlink.linkname(b"file");
    let bytes = Tar::new()
        .entry(&Header::file(b"file", 3), b"abc")
        .header(&hardlink)
        .header(&symlink)
        .header(&Header::new(b'3', b"chr", 0))
        .header(&Header::new(b'4', b"blk", 0))
        .header(&Header::dir(b"dir/"))
        .header(&Header::new(b'6', b"fifo", 0))
        .finish();
    let walked = layer(&bytes).unwrap();
    let kinds: Vec<EntryKind> = walked.iter().map(|(entry, _)| entry.kind).collect();
    assert_eq!(
        kinds,
        [
            EntryKind::Regular,
            EntryKind::Hardlink,
            EntryKind::Symlink,
            EntryKind::CharDevice,
            EntryKind::BlockDevice,
            EntryKind::Directory,
            EntryKind::Fifo
        ]
    );
    assert_eq!(walked[1].0.link_target.as_deref(), Some(&b"file"[..]));
    assert_eq!(walked[0].0.link_target, None);
}

#[test]
fn gnu_long_records_supply_names_and_targets() {
    let long = vec![b'l'; 300];
    let mut symlink = Header::new(b'2', b"short", 0);
    symlink.linkname(b"ignored");
    let bytes = Tar::new()
        .extension(b'L', &[long.as_slice(), b"\0"].concat())
        .entry(&Header::file(b"truncated", 1), b"z")
        .extension(b'K', &long)
        .header(&symlink)
        .finish();
    let walked = layer(&bytes).unwrap();
    assert_eq!(walked[0].0.name, long);
    assert_eq!(walked[0].1, b"z");
    assert_eq!(walked[1].0.name, b"short");
    assert_eq!(walked[1].0.link_target.as_deref(), Some(long.as_slice()));
    // The entry's own header is reported, after its extension records.
    assert_eq!(walked[0].0.header_offset, 1024);
}

#[test]
fn every_extension_kind_may_precede_one_entry_in_any_order() {
    let hardlink = Header::new(b'1', b"x", 0);
    let times = pax(&[("mtime", b"1")]);
    let x_l_k = Tar::new()
        .extension(b'x', &times)
        .extension(b'L', b"named")
        .extension(b'K', b"target")
        .header(&hardlink)
        .finish();
    let k_x_l = Tar::new()
        .extension(b'K', b"target")
        .extension(b'x', &times)
        .extension(b'L', b"named")
        .header(&hardlink)
        .finish();
    for bytes in [x_l_k, k_x_l] {
        let walked = layer(&bytes).unwrap();
        assert_eq!(walked[0].0.name, b"named");
        assert_eq!(walked[0].0.link_target.as_deref(), Some(&b"target"[..]));
    }
}

#[test]
fn every_permitted_pax_key_is_accepted() {
    let records = pax(&[
        ("path", b"from/pax"),
        ("linkpath", b"/absolute/target"),
        ("size", b"0"),
        ("uid", b"1000"),
        ("gid", b"1000"),
        ("uname", b"\xffuser"),
        ("gname", b"group"),
        ("mtime", b"0"),
        ("atime", b"-1.5"),
        ("ctime", b"1700000000.123"),
        ("SCHILY.xattr.user.test", b"\x00\x01\xff=\n"),
    ]);
    let bytes = Tar::new()
        .extension(b'x', &records)
        .header(&Header::new(b'2', b"header/name", 0))
        .extension(b'x', &pax(&[("size", b"0005")]))
        .entry(&Header::file(b"sized", 0), b"12345")
        .finish();
    let walked = layer(&bytes).unwrap();
    assert_eq!(walked[0].0.name, b"from/pax");
    assert_eq!(
        walked[0].0.link_target.as_deref(),
        Some(&b"/absolute/target"[..])
    );
    assert_eq!(walked[1].0.size, 5);
    assert_eq!(walked[1].1, b"12345");
}

#[test]
fn a_pax_size_overrides_the_header_size() {
    let bytes = Tar::new()
        .extension(b'x', &pax(&[("size", b"3")]))
        .entry(&Header::file(b"a", 100), b"abc")
        .entry(&Header::file(b"b", 1), b"z")
        .finish();
    let walked = layer(&bytes).unwrap();
    assert_eq!((walked[0].0.size, walked[0].1.as_slice()), (3, &b"abc"[..]));
    assert_eq!(walked[1].1, b"z");
}

#[test]
fn a_layer_admits_its_path_forms() {
    let mut absolute = Header::new(b'2', b"abs", 0);
    absolute.linkname(b"/etc/passwd");
    let mut upward = Header::new(b'2', b"up", 0);
    upward.linkname(b"../../x");
    let bytes = Tar::new()
        .header(&Header::dir(b"."))
        .header(&Header::dir(b"./"))
        .header(&Header::file(b"./etc/passwd", 0))
        .header(&Header::file("caf\u{e9}".as_bytes(), 0))
        .header(&absolute)
        .header(&upward)
        .header(&Header::file(b"dir/.wh.foo", 0))
        .header(&Header::file(b"./etc/passwd", 0))
        .finish();
    let walked = layer(&bytes).unwrap();
    assert_eq!(walked.len(), 8);
    assert_eq!(walked[0].0.canonical_name(), b"");
    assert_eq!(walked[1].0.canonical_name(), b"");
    assert_eq!(walked[2].0.canonical_name(), b"etc/passwd");
}

#[test]
fn a_layer_refuses_other_types() {
    for flag in *b"Sg7VMNDZ" {
        let header = Header::new(flag, b"a", 0);
        assert_eq!(layer(&one_file(&header)).unwrap_err(), entry_type(flag));
    }
}

fn with_pax(payload: &[u8]) -> Vec<u8> {
    Tar::new()
        .extension(b'x', payload)
        .header(&Header::file(b"a", 0))
        .finish()
}

#[test]
fn pax_record_faults() {
    let record = malformed(MalformedReason::PaxRecord);
    for payload in [
        &b"11 path=abc\n"[..],
        b"13 path=abc\n",
        b"012 path=abc\n",
        b"11path=abc\n",
        b"9 =value\n",
        b"4 =\n",
        b"11 pathabc\n",
        b"12 path=abc\n7",
        b"1",
        b" 12 path=abc\n",
    ] {
        assert_eq!(
            layer(&with_pax(payload)).unwrap_err(),
            record,
            "{payload:?}"
        );
    }
    assert_eq!(
        layer(&with_pax(b"12 path=abc\n")).unwrap()[0].0.name,
        b"abc"
    );
    assert_eq!(
        layer(&with_pax(&pax(&[("mtime", b"1"), ("mtime", b"2")]))).unwrap_err(),
        malformed(MalformedReason::PaxDuplicateKey)
    );
    assert_eq!(
        layer(&with_pax(&pax(&[("comment", b"hi")]))).unwrap_err(),
        unsupported(UnsupportedFeature::PaxKey)
    );
}

#[test]
fn a_pax_key_may_begin_with_a_space() {
    // Only the first space after the length separates; the next one is the
    // key's own first byte, so these keys parse and then fail the key policy.
    for payload in [&b"7  a=b\n"[..], b"12  path=ab\n", b"13  path=abc\n"] {
        assert_eq!(
            layer(&with_pax(payload)).unwrap_err(),
            unsupported(UnsupportedFeature::PaxKey),
            "{payload:?}"
        );
    }
    // Record syntax still wins over the key policy when the length is wrong.
    assert_eq!(
        layer(&with_pax(b"8  a=b\n")).unwrap_err(),
        malformed(MalformedReason::PaxRecord)
    );
}

#[test]
fn pax_value_faults() {
    for (key, value, pax_key) in [
        ("size", &b"-1"[..], PaxKey::Size),
        ("size", b"18446744073709551616", PaxKey::Size),
        ("size", b"", PaxKey::Size),
        ("uid", b"1a", PaxKey::Uid),
        ("gid", b" 1", PaxKey::Gid),
        ("mtime", b"+1", PaxKey::Mtime),
        ("mtime", b".5", PaxKey::Mtime),
        ("mtime", b"1.", PaxKey::Mtime),
        ("mtime", b"1.5.2", PaxKey::Mtime),
        ("atime", b"-", PaxKey::Atime),
        ("ctime", b"1e5", PaxKey::Ctime),
        ("path", b"a\0b", PaxKey::Path),
        ("linkpath", b"\0", PaxKey::Linkpath),
    ] {
        assert_eq!(
            layer(&with_pax(&pax(&[(key, value)]))).unwrap_err(),
            malformed(MalformedReason::PaxValue { key: pax_key }),
            "{key}={value:?}"
        );
    }
    // The largest size is a value, just not one whose data fits an offset.
    assert_eq!(
        layer(&with_pax(&pax(&[("size", b"18446744073709551615")]))).unwrap_err(),
        malformed(MalformedReason::OffsetOverflow)
    );
}

#[test]
fn a_gnu_payload_with_an_interior_nul_is_refused() {
    let bytes = Tar::new()
        .extension(b'L', b"a\0b\0\0")
        .header(&Header::file(b"a", 0))
        .finish();
    assert_eq!(
        layer(&bytes).unwrap_err(),
        malformed(MalformedReason::ExtensionPayload)
    );
}

#[test]
fn extension_sequence_faults() {
    let duplicate = malformed(MalformedReason::DuplicateExtension);
    let times = pax(&[("mtime", b"1")]);
    for (flag, payload) in [(b'x', times.as_slice()), (b'L', b"n"), (b'K', b"t")] {
        let bytes = Tar::new()
            .extension(flag, payload)
            .extension(flag, payload)
            .header(&Header::new(b'2', b"a", 0))
            .finish();
        assert_eq!(layer(&bytes).unwrap_err(), duplicate);
    }
    let conflict = malformed(MalformedReason::ConflictingAuthority);
    let path = pax(&[("path", b"p")]);
    let linkpath = pax(&[("linkpath", b"t")]);
    for (first, second) in [
        ((b'L', &b"n"[..]), (b'x', path.as_slice())),
        ((b'x', path.as_slice()), (b'L', &b"n"[..])),
        ((b'K', &b"t"[..]), (b'x', linkpath.as_slice())),
        ((b'x', linkpath.as_slice()), (b'K', &b"t"[..])),
    ] {
        let bytes = Tar::new()
            .extension(first.0, first.1)
            .extension(second.0, second.1)
            .header(&Header::new(b'2', b"a", 0))
            .finish();
        assert_eq!(layer(&bytes).unwrap_err(), conflict);
    }
    let dangling = Tar::new().extension(b'L', b"n").finish();
    assert_eq!(
        layer(&dangling).unwrap_err(),
        malformed(MalformedReason::DanglingExtension)
    );
    let cut = Tar::new().extension(b'L', b"n").unfinished();
    assert_eq!(
        layer(&cut).unwrap_err(),
        malformed(MalformedReason::Truncated)
    );
    let link_on_file = Tar::new()
        .extension(b'K', b"t")
        .header(&Header::file(b"a", 0))
        .finish();
    assert_eq!(
        layer(&link_on_file).unwrap_err(),
        malformed(MalformedReason::LinkOnNonLink)
    );
    let linkpath_on_dir = Tar::new()
        .extension(b'x', &linkpath)
        .header(&Header::dir(b"d/"))
        .finish();
    assert_eq!(
        layer(&linkpath_on_dir).unwrap_err(),
        malformed(MalformedReason::LinkOnNonLink)
    );
    // A header linkname on a non-link is ignored.
    let mut ignored = Header::file(b"a", 0);
    ignored.linkname(b"../../anything");
    layer(&one_file(&ignored)).unwrap();
}

#[test]
fn non_regular_entries_carry_no_data() {
    for flag in *b"2516" {
        let mut header = Header::new(flag, b"a", 1);
        header.linkname(b"b");
        let bytes = Tar::new().entry(&header, b"x").finish();
        assert_eq!(
            layer(&bytes).unwrap_err(),
            malformed(MalformedReason::NonRegularWithData)
        );
    }
    let bytes = Tar::new()
        .extension(b'x', &pax(&[("size", b"1")]))
        .entry(Header::new(b'2', b"a", 0).linkname(b"b"), b"x")
        .finish();
    assert_eq!(
        layer(&bytes).unwrap_err(),
        malformed(MalformedReason::NonRegularWithData)
    );
}

#[test]
fn a_layer_refuses_unsafe_paths() {
    let unsafe_path = malformed(MalformedReason::UnsafePath);
    for name in [
        &b".."[..],
        b"a/../b",
        b"a//b",
        b"a\x01b",
        b"a\x7f",
        b"/abs",
        b".",
        b"./",
        b"././a",
        b"a/.",
        b"",
        b"file/",
    ] {
        assert_eq!(
            layer(&one_file(&Header::file(name, 0))).unwrap_err(),
            unsafe_path,
            "{name:?}"
        );
    }
    for name in [&b".//"[..], b"dir//", b"/"] {
        assert_eq!(
            layer(&one_file(&Header::dir(name))).unwrap_err(),
            unsafe_path,
            "{name:?}"
        );
    }
    for target in [&b"../etc/passwd"[..], b"/abs", b"dir/", b".", b""] {
        let mut hardlink = Header::new(b'1', b"a", 0);
        hardlink.linkname(target);
        assert_eq!(
            layer(&one_file(&hardlink)).unwrap_err(),
            unsafe_path,
            "{target:?}"
        );
    }
    let mut hardlink = Header::new(b'1', b"a", 0);
    hardlink.linkname(b"./ok/target");
    layer(&one_file(&hardlink)).unwrap();
}

#[test]
fn layer_path_and_link_limits_count_raw_bytes() {
    let limits = limits_with(LimitResource::LayerPathBytes, 10)
        .with_limit(LimitResource::LayerLinkTargetBytes, 10)
        .unwrap();
    let walk = |bytes: &[u8]| run(bytes, Policy::Layer, &limits).0;
    walk(&one_file(&Header::file(b"./abcdefgh", 0))).unwrap();
    assert_eq!(
        walk(&one_file(&Header::file(b"./abcdefghi", 0))).unwrap_err(),
        exceeded(LimitResource::LayerPathBytes, 10)
    );
    walk(&one_file(&Header::dir(b"abcdefghi/"))).unwrap();
    assert_eq!(
        walk(&one_file(&Header::dir(b"abcdefghij/"))).unwrap_err(),
        exceeded(LimitResource::LayerPathBytes, 10)
    );
    let symlink = |target: &[u8]| {
        let mut header = Header::new(b'2', b"s", 0);
        header.linkname(target);
        one_file(&header)
    };
    walk(&symlink(b"/abcdefghi")).unwrap();
    assert_eq!(
        walk(&symlink(b"/abcdefghij")).unwrap_err(),
        exceeded(LimitResource::LayerLinkTargetBytes, 10)
    );
}

/// A PAX payload of exactly `len` bytes. A record's length field gains a
/// digit at 100, so no single record is 100 bytes long; a short leading
/// record fills that gap.
fn pax_of_len(len: usize) -> Vec<u8> {
    [Vec::new(), pax(&[("uid", b"0")])]
        .into_iter()
        .flat_map(|lead| {
            (0..len).map(move |value| {
                [lead.clone(), pax(&[("SCHILY.xattr.a", &vec![b'v'; value])])].concat()
            })
        })
        .find(|payload| payload.len() == len)
        .expect("a payload of every length is reachable")
}

#[test]
fn layer_extension_counts_payload_bytes_only() {
    let limits = limits_with(LimitResource::LayerExtension, 100);
    let with_payload = |len: usize| {
        Tar::new()
            .extension(b'x', &pax_of_len(len))
            .header(&Header::file(b"a", 0))
            .finish()
    };
    run(&with_payload(100), Policy::Layer, &limits).0.unwrap();
    assert_eq!(
        run(&with_payload(101), Policy::Layer, &limits)
            .0
            .unwrap_err(),
        exceeded(LimitResource::LayerExtension, 100)
    );
}

/// Walks each of `layers` as one layer of the same image, sharing the
/// per-image entry and extension budgets.
fn walk_image_layers(layers: &[Vec<u8>], limits: &ContentLimits) -> Result<(), ContentFault> {
    let mut entries = Budget::new(limits.resource_limit(LimitResource::LayerEntries));
    let mut extension_total =
        Budget::new(limits.resource_limit(LimitResource::LayerExtensionTotal));
    for bytes in layers {
        let reader = CountingReader::new(
            bytes.as_slice(),
            limits.resource_limit(LimitResource::DecodedLayer),
            vec![],
            limits.copy_buffer_len(),
        );
        let policy = EntryPolicy::Layer {
            entries: &mut entries,
            extension_total: &mut extension_total,
        };
        collect(&mut TarWalker::new(reader, policy, limits))?;
    }
    Ok(())
}

#[test]
fn per_image_layer_budgets_are_shared_across_walkers() {
    let limits = limits_with(LimitResource::LayerExtensionTotal, 200);
    let with_payload = |len: usize| {
        Tar::new()
            .extension(b'x', &pax_of_len(len))
            .header(&Header::file(b"a", 0))
            .finish()
    };
    walk_image_layers(&[with_payload(100), with_payload(100)], &limits).unwrap();
    assert_eq!(
        walk_image_layers(&[with_payload(100), with_payload(101)], &limits).unwrap_err(),
        exceeded(LimitResource::LayerExtensionTotal, 200)
    );

    let limits = limits_with(LimitResource::LayerEntries, 3);
    let two_headers = Tar::new()
        .extension(b'L', b"long")
        .header(&Header::file(b"a", 0))
        .finish();
    let one_header = one_file(&Header::file(b"b", 0));
    walk_image_layers(&[two_headers.clone(), one_header], &limits).unwrap();
    assert_eq!(
        walk_image_layers(&[two_headers.clone(), two_headers], &limits).unwrap_err(),
        exceeded(LimitResource::LayerEntries, 3)
    );
}

#[test]
fn a_size_beyond_the_decoded_chain_fails_before_any_data_byte() {
    let limits = limits_with(LimitResource::DecodedLayer, 4096);
    let bytes = Tar::new()
        .entry(&Header::file(b"big", 5000), &[1; 5000])
        .finish();
    let (result, log) = run(&bytes, Policy::Layer, &limits);
    assert_eq!(
        result.unwrap_err(),
        exceeded(LimitResource::DecodedLayer, 4096)
    );
    assert_eq!(log.delivered, BLOCK);
    // Data that fits with its padding is read, and the walk goes on to find
    // the end marker missing.
    let bytes = Tar::new()
        .entry(&Header::file(b"fits", 3000), &[1; 3000])
        .unfinished();
    let (result, _) = run(&bytes, Policy::Layer, &limits);
    assert_eq!(result.unwrap_err(), malformed(MalformedReason::Truncated));
}

// ---------------------------------------------------------------------------
// Paired faults: the first-named fault wins
// ---------------------------------------------------------------------------

#[test]
fn paired_tar_faults() {
    let mut bad_checksum = Header::file(b"b", 0);
    bad_checksum.wrong_checksum();
    let bytes = Tar::new()
        .header(&Header::file(b"a", 0))
        .header(&bad_checksum)
        .finish();
    assert_eq!(
        run(
            &bytes,
            Policy::Image,
            &limits_with(LimitResource::ImageEntries, 1)
        )
        .0
        .unwrap_err(),
        exceeded(LimitResource::ImageEntries, 1)
    );

    let mut no_magic = Header::file(b"a", 0);
    no_magic.no_magic().wrong_checksum();
    assert_both(
        &one_file(&no_magic),
        &malformed(MalformedReason::TarChecksum),
    );

    let mut refused = Header::new(b'2', b"a", 0);
    refused.set(100, b"99999999");
    assert_eq!(image(&one_file(&refused)).unwrap_err(), entry_type(b'2'));

    let mut garbage = Header::file(b"a", 0);
    garbage.set(0, b"a\0garbage").set(124, b"not a number");
    assert_both(
        &one_file(&garbage),
        &malformed(MalformedReason::TarNameField {
            field: TarField::Name,
        }),
    );

    let bytes = Tar::new()
        .header(&Header::file(b"../a", 0))
        .header(&bad_checksum)
        .finish();
    assert_both(&bytes, &malformed(MalformedReason::UnsafePath));

    let over_and_invalid = one_file(&Header::file(b"../../../../x", 0));
    assert_eq!(
        run(
            &over_and_invalid,
            Policy::Layer,
            &limits_with(LimitResource::LayerPathBytes, 5)
        )
        .0
        .unwrap_err(),
        exceeded(LimitResource::LayerPathBytes, 5)
    );

    let bytes = Tar::new()
        .extension(b'x', b"garbage payload that is not a record")
        .header(&Header::file(b"a", 0))
        .finish();
    assert_eq!(
        run(
            &bytes,
            Policy::Layer,
            &limits_with(LimitResource::LayerExtension, 10)
        )
        .0
        .unwrap_err(),
        exceeded(LimitResource::LayerExtension, 10)
    );

    let payload = [pax(&[("comment", b"x")]), b"99 broken".to_vec()].concat();
    assert_eq!(
        layer(&with_pax(&payload)).unwrap_err(),
        unsupported(UnsupportedFeature::PaxKey)
    );

    let unsafe_and_huge = one_file(&Header::file(b"/abs", 1 << 30));
    assert_eq!(
        run(
            &unsafe_and_huge,
            Policy::Layer,
            &limits_with(LimitResource::DecodedLayer, 1024)
        )
        .0
        .unwrap_err(),
        malformed(MalformedReason::UnsafePath)
    );

    let huge = Tar::new()
        .entry(&Header::file(b"big", 5000), &[1; 5000])
        .finish();
    let decoded = limits_with(LimitResource::DecodedLayer, 2048);
    assert_eq!(
        run_with(&huge, Policy::Layer, &decoded, 1024)
            .0
            .unwrap_err(),
        exceeded(LimitResource::DecodedLayer, 2048)
    );
    assert_eq!(
        run_with(&huge, Policy::Layer, &ContentLimits::default(), 2048)
            .0
            .unwrap_err(),
        exceeded(LimitResource::DecodedLayersPerImage, 2048)
    );
}

#[test]
fn a_tar_fault_inside_a_gzip_layer_wins_over_its_bad_trailer() {
    let mut bad_checksum = Header::file(b"b", 0);
    bad_checksum.wrong_checksum();
    let tar = Tar::new()
        .entry(&Header::file(b"a", 3), b"abc")
        .header(&bad_checksum)
        .finish();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    let mut member = encoder.finish().unwrap();
    let len = member.len();
    member[len - 8] ^= 1;
    member[len - 4] ^= 1;

    let limits = ContentLimits::default();
    let copy_buffer = limits.copy_buffer_len();
    let stored = CountingReader::new(
        member.as_slice(),
        limits.resource_limit(LimitResource::StoredLayerBlob),
        vec![],
        copy_buffer,
    );
    let gzip = GzipDecoder::new(
        stored,
        limits.resource_limit(LimitResource::GzipHeader),
        copy_buffer,
    );
    let mut image = Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerImage));
    let mut operation =
        Budget::new(limits.resource_limit(LimitResource::DecodedLayersPerOperation));
    let output = CountingReader::new(
        gzip,
        limits.resource_limit(LimitResource::DecodedLayer),
        vec![&mut image, &mut operation],
        copy_buffer,
    );
    let mut entries = Budget::new(limits.resource_limit(LimitResource::LayerEntries));
    let mut extension_total =
        Budget::new(limits.resource_limit(LimitResource::LayerExtensionTotal));
    let policy = EntryPolicy::Layer {
        entries: &mut entries,
        extension_total: &mut extension_total,
    };
    let mut walker = TarWalker::new(output, policy, &limits);
    assert_eq!(
        collect(&mut walker).unwrap_err(),
        malformed(MalformedReason::TarChecksum)
    );

    // And an intact member decodes to the same walk as the plain tar.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    let good = Tar::new().entry(&Header::file(b"a", 3), b"abc").finish();
    encoder.write_all(&good).unwrap();
    let member = encoder.finish().unwrap();
    let stored = CountingReader::new(
        member.as_slice(),
        limits.resource_limit(LimitResource::StoredLayerBlob),
        vec![],
        copy_buffer,
    );
    let gzip = GzipDecoder::new(
        stored,
        limits.resource_limit(LimitResource::GzipHeader),
        copy_buffer,
    );
    let output = CountingReader::new(
        gzip,
        limits.resource_limit(LimitResource::DecodedLayer),
        vec![],
        copy_buffer,
    );
    let mut entries = Budget::new(limits.resource_limit(LimitResource::LayerEntries));
    let mut extension_total =
        Budget::new(limits.resource_limit(LimitResource::LayerExtensionTotal));
    let policy = EntryPolicy::Layer {
        entries: &mut entries,
        extension_total: &mut extension_total,
    };
    let plain = collect(&mut TarWalker::new(output, policy, &limits)).unwrap();
    assert_eq!(plain, layer(&good).unwrap());
}

// ---------------------------------------------------------------------------
// A small copy buffer
// ---------------------------------------------------------------------------

fn positive_layer() -> Vec<u8> {
    let mut symlink = Header::new(b'2', b"sym", 0);
    symlink.linkname(b"/target");
    Tar::new()
        .header(&Header::dir(b"./"))
        .entry(&Header::file(b"./etc/passwd", 700), &[3; 700])
        .extension(b'x', &pax(&[("path", &[b'p'; 200]), ("mtime", b"1.5")]))
        .entry(&Header::file(b"short", 5), b"hello")
        .extension(b'L', &[b'l'; 150])
        .header(&symlink)
        .raw(&[0; 4096])
        .finish()
}

#[test]
fn a_small_copy_buffer_walks_identically() {
    let small = limits_with(LimitResource::CopyBuffer, 7);
    for (policy, bytes) in [
        (Policy::Layer, positive_layer()),
        (
            Policy::Image,
            Tar::new()
                .header(&Header::dir(b"blobs/"))
                .entry(&Header::file(b"blobs/x", 1000), &[4; 1000])
                .finish(),
        ),
    ] {
        let (expected, _) = run(&bytes, policy, &ContentLimits::default());
        let (result, log) = run(&bytes, policy, &small);
        assert_eq!(result.unwrap(), expected.unwrap());
        assert!(log.requests.iter().all(|request| *request <= 7));
    }
}

#[test]
fn the_walker_never_requests_more_than_the_copy_buffer() {
    let limits = limits_with(LimitResource::CopyBuffer, 4096);
    let (result, log) = run(&positive_layer(), Policy::Layer, &limits);
    result.unwrap();
    assert!(log.requests.iter().all(|request| *request <= 4096));
}
