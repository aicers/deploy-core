//! The raw-block accessors on [`UnparsedContainer`]: the container version,
//! the manifest block and the archive block exactly as the writers emitted
//! them, and the version-1 fixture writer that reaches them through the real
//! reader.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::Path;
use std::rc::Rc;

use super::{
    ArtifactInput, ED25519_SIGNATURE_LEN, EnvelopeBlock, EnvelopeBounds, FOOTER_SIZE,
    FORMAT_VERSION, Footer, KEY_ID_HEX_LEN, MemberLength, PayloadError, Signed, UnparsedContainer,
    append_trailer, append_trailer_signed, append_version_1_trailer, open, read_package_container,
    rewrap_trailer, sha256_hex, write_archive_block,
};
use crate::manifest::{ArtifactKind, Disposition, TargetArch};
use crate::verify::ENVELOPE_BOUNDS;

const BASE: &[u8] = b"#!/bin/false\nnot a real executable, just a base binary\n";

/// A base of another length, for the rewrap cases.
const OTHER_BASE: &[u8] = b"a replacement executable base of a distinct, longer length\n";

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

const MEMBER: &str = "bin/tool";

const MEMBER_BYTES: &[u8] = b"the bytes of the one artifact this container carries";

/// A manifest block no parse accepts.
const UNPARSABLE: &[u8] = b"{ this is not a manifest";

/// An archive block that is not even a compressed stream.
const NOT_AN_ARCHIVE: &[u8] = b"not an archive, not even zstd";

fn input(dir: &Path) -> ArtifactInput {
    let source = dir.join("tool.src");
    std::fs::write(&source, MEMBER_BYTES).expect("the source file is written");
    ArtifactInput {
        component: "example".to_string(),
        version: "1.0.0".to_string(),
        commit: COMMIT.to_string(),
        target_arch: TargetArch::X86_64,
        kind: ArtifactKind::NativeBinary,
        dispositions: BTreeSet::from([Disposition::Install]),
        archive_path: MEMBER.to_string(),
        spec: None,
        image: None,
        source,
    }
}

/// The archive block the writers emit for [`MEMBER`], produced by the one
/// archive writer they all go through rather than sliced out of a container.
fn expected_archive() -> Vec<u8> {
    let mut out = Vec::new();
    let length = u64::try_from(MEMBER_BYTES.len()).expect("the member length fits a u64");
    write_archive_block(
        [Ok((MEMBER, length, MEMBER_BYTES))],
        &mut out,
        MemberLength::Legacy,
    )
    .expect("the archive block is written");
    out
}

fn unsigned(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    append_trailer(Cursor::new(BASE), &mut out, None, None, &[input(dir)])
        .expect("the unsigned writer succeeds");
    out
}

/// A signed container, with the manifest bytes its signer was handed.
fn signed(dir: &Path) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::new();
    let mut handed = Vec::new();
    append_trailer_signed(
        Cursor::new(BASE),
        &mut out,
        None,
        None,
        &[input(dir)],
        |manifest| {
            handed = manifest.to_vec();
            Ok(Signed {
                signature: vec![0x5a; ED25519_SIGNATURE_LEN],
                key_id: "a".repeat(KEY_ID_HEX_LEN),
            })
        },
    )
    .expect("the signed writer succeeds");
    (out, handed)
}

fn rewrapped(container: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rewrap_trailer(Cursor::new(container), Cursor::new(OTHER_BASE), &mut out)
        .expect("the container rewraps");
    out
}

fn version_1(base: &[u8], manifest: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append_version_1_trailer(Cursor::new(base), &mut out, manifest, archive)
        .expect("the version-1 writer succeeds");
    out
}

fn container(bytes: &[u8]) -> UnparsedContainer<Cursor<&[u8]>> {
    read_package_container(Cursor::new(bytes), &ENVELOPE_BOUNDS).expect("the container reads")
}

fn archive_of<R: Read + Seek>(container: &mut UnparsedContainer<R>) -> Vec<u8> {
    let mut bytes = Vec::new();
    container
        .raw_archive_block()
        .expect("the block is sought")
        .read_to_end(&mut bytes)
        .expect("the block reads to its end");
    bytes
}

/// Asserts the three raw accessors report `manifest` and `archive`.
#[track_caller]
fn assert_blocks<R: Read + Seek>(
    container: &mut UnparsedContainer<R>,
    manifest: &[u8],
    archive: &[u8],
) {
    assert_eq!(container.raw_manifest_block(), manifest);
    assert_eq!(
        container.archive_block_len(),
        u64::try_from(archive.len()).expect("the archive length fits a u64")
    );
    assert_eq!(archive_of(container), archive);
}

/// A current-format container over arbitrary blocks, with envelope blocks of
/// whatever length is given and an empty one recorded absent:
/// `base ‖ manifest ‖ archive ‖ signature ‖ key_id ‖ footer`.
fn version_2(manifest: &[u8], archive: &[u8], signature: &[u8], key_id: &[u8]) -> Vec<u8> {
    let len = |bytes: &[u8]| u64::try_from(bytes.len()).expect("a fixture length fits a u64");
    let manifest_offset = len(BASE);
    let archive_offset = manifest_offset + len(manifest);
    // An empty block is recorded absent, as the all-zero pair, and occupies
    // no bytes.
    let pair = |offset: u64, bytes: &[u8]| {
        if bytes.is_empty() {
            (0, 0)
        } else {
            (offset, len(bytes))
        }
    };
    let (signature_offset, signature_len) = pair(archive_offset + len(archive), signature);
    let (key_id_offset, key_id_len) = pair(archive_offset + len(archive) + len(signature), key_id);
    let footer = Footer {
        version: FORMAT_VERSION,
        manifest_offset,
        manifest_len: len(manifest),
        archive_offset,
        archive_len: len(archive),
        signature_offset,
        signature_len,
        key_id_offset,
        key_id_len,
    };
    [BASE, manifest, archive, signature, key_id, &footer.encode()].concat()
}

/// What a [`RecordingSource`] saw, shared so a test can read it while the
/// container still owns the source.
#[derive(Default)]
struct Log {
    /// Every position a seek landed on, in order.
    seeks: Vec<u64>,
    /// Every byte range a read delivered, in order.
    reads: Vec<Range<u64>>,
}

/// A [`Log`] shared between a [`RecordingSource`] and the test reading it.
type SharedLog = Rc<RefCell<Log>>;

/// The offset a [`RecordingSource`] ends at, set by the test once the
/// container has been validated.
type Truncation = Rc<Cell<Option<u64>>>;

/// A `Read + Seek` source that records every seek and read range, and that
/// can be told, once the container has been validated, to end early.
struct RecordingSource {
    inner: Cursor<Vec<u8>>,
    log: SharedLog,
    /// When set, the source reports end-of-file at and past this offset.
    end: Truncation,
}

impl RecordingSource {
    fn new(bytes: Vec<u8>) -> (Self, SharedLog, Truncation) {
        let log = Rc::new(RefCell::new(Log::default()));
        let end = Rc::new(Cell::new(None));
        let source = Self {
            inner: Cursor::new(bytes),
            log: Rc::clone(&log),
            end: Rc::clone(&end),
        };
        (source, log, end)
    }
}

impl Read for RecordingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.inner.position();
        let allowed = match self.end.get() {
            Some(end) => usize::try_from(end.saturating_sub(start))
                .expect("a fixture length fits a usize")
                .min(buf.len()),
            None => buf.len(),
        };
        let read = self.inner.read(&mut buf[..allowed])?;
        let delivered = u64::try_from(read).expect("a read count fits a u64");
        self.log.borrow_mut().reads.push(start..start + delivered);
        Ok(read)
    }
}

impl Seek for RecordingSource {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let landed = self.inner.seek(pos)?;
        self.log.borrow_mut().seeks.push(landed);
        Ok(landed)
    }
}

#[test]
fn a_version_1_container_reports_1_and_a_current_one_reports_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let current = unsigned(dir.path());
    assert_eq!(container(&current).container_version(), 2);
    assert_eq!(container(&current).container_version(), FORMAT_VERSION);

    let legacy = version_1(BASE, UNPARSABLE, NOT_AN_ARCHIVE);
    assert_eq!(container(&legacy).container_version(), 1);
    // Rewrapping keeps each container at its own version.
    assert_eq!(container(&rewrapped(&legacy)).container_version(), 1);
    assert_eq!(
        container(&rewrapped(&current)).container_version(),
        FORMAT_VERSION
    );
}

#[test]
fn the_raw_manifest_block_is_the_one_the_unsigned_writer_emitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes = unsigned(dir.path());
    let container = container(&bytes);
    let manifest = container.raw_manifest_block();

    // The writer emits the manifest block straight after the base, so the
    // bytes it wrote there are the ones the accessor must return.
    assert_eq!(
        bytes.get(BASE.len()..BASE.len() + manifest.len()),
        Some(manifest)
    );
    // And they are the serialized manifest itself, not merely bytes that
    // happen to sit there: the archive block follows them directly.
    let archive = expected_archive();
    let archive_at = BASE.len() + manifest.len();
    assert_eq!(
        bytes.get(archive_at..archive_at + archive.len()),
        Some(archive.as_slice())
    );
    assert_eq!(bytes.len(), archive_at + archive.len() + FOOTER_SIZE);
}

#[test]
fn the_raw_manifest_block_is_the_one_the_signer_was_handed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bytes, handed) = signed(dir.path());
    assert!(!handed.is_empty());
    assert_eq!(container(&bytes).raw_manifest_block(), handed.as_slice());
    assert_eq!(
        bytes.get(BASE.len()..BASE.len() + handed.len()),
        Some(handed.as_slice())
    );
    // Signing adds envelope blocks and changes nothing about the manifest.
    assert_eq!(
        container(&unsigned(dir.path())).raw_manifest_block(),
        handed.as_slice()
    );
}

#[test]
fn the_raw_archive_block_is_the_one_the_writer_emitted_and_survives_a_rewrap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = expected_archive();
    let (signed_bytes, handed) = signed(dir.path());
    let unsigned_bytes = unsigned(dir.path());
    assert_ne!(OTHER_BASE.len(), BASE.len());

    for (label, bytes) in [
        ("unsigned", unsigned_bytes.clone()),
        ("signed", signed_bytes.clone()),
        ("unsigned, rewrapped", rewrapped(&unsigned_bytes)),
        ("signed, rewrapped", rewrapped(&signed_bytes)),
    ] {
        let mut container = container(&bytes);
        assert_eq!(archive_of(&mut container), archive, "{label}");
        assert_eq!(
            container.archive_block_len(),
            u64::try_from(archive.len()).expect("the archive length fits a u64"),
            "{label}"
        );
        assert_eq!(container.raw_manifest_block(), handed.as_slice(), "{label}");
        assert_eq!(container.container_version(), FORMAT_VERSION, "{label}");
        // A second reader re-seeks and yields the same block again.
        assert_eq!(archive_of(&mut container), archive, "{label}");
    }

    // The same holds for a version-1 container rewrapped at version 1.
    let legacy = version_1(BASE, &handed, &archive);
    let moved = rewrapped(&legacy);
    let mut moved = container(&moved);
    assert_blocks(&mut moved, &handed, &archive);
}

#[test]
fn the_archive_reader_reads_exactly_the_block_and_nothing_around_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bytes, handed) = signed(dir.path());
    let archive = expected_archive();
    let offset = u64::try_from(BASE.len() + handed.len()).expect("the offset fits a u64");
    let len = u64::try_from(archive.len()).expect("the archive length fits a u64");

    // A buffer much smaller than the block and one much larger than it: the
    // first proves the reader pieces the block together, the second that it
    // never asks the source for a byte past the block's end.
    for buffer in [7, archive.len() * 4] {
        let (source, log, _) = RecordingSource::new(bytes.clone());
        let mut container =
            read_package_container(source, &ENVELOPE_BOUNDS).expect("the container reads");
        *log.borrow_mut() = Log::default();

        let mut block = container.raw_archive_block().expect("the block is sought");
        let mut delivered = Vec::new();
        let mut chunk = vec![0u8; buffer];
        loop {
            let read = block.read(&mut chunk).expect("the block reads");
            if read == 0 {
                break;
            }
            delivered.extend_from_slice(&chunk[..read]);
        }
        // Past the end it keeps answering end-of-file without touching the
        // source.
        assert_eq!(block.read(&mut chunk).expect("end-of-file"), 0);

        assert_eq!(delivered, archive, "buffer {buffer}");
        let log = log.borrow();
        assert_eq!(log.seeks, vec![offset], "buffer {buffer}");
        let mut cursor = offset;
        for range in &log.reads {
            assert_eq!(range.start, cursor, "buffer {buffer}: reads are contiguous");
            assert!(range.end > range.start, "buffer {buffer}: no empty read");
            cursor = range.end;
        }
        assert_eq!(
            cursor,
            offset + len,
            "buffer {buffer}: the block and no more"
        );
    }
}

#[test]
fn a_source_that_ends_inside_the_block_is_unexpected_eof() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bytes, handed) = signed(dir.path());
    let archive = expected_archive();
    let offset = u64::try_from(BASE.len() + handed.len()).expect("the offset fits a u64");
    let cut = 5;

    for end in [offset, offset + cut] {
        let (source, _, truncate) = RecordingSource::new(bytes.clone());
        // The container is validated against the whole file first.
        let mut container =
            read_package_container(source, &ENVELOPE_BOUNDS).expect("the container reads");
        truncate.set(Some(end));

        let mut block = container.raw_archive_block().expect("the block is sought");
        let mut delivered = Vec::new();
        let error = block
            .read_to_end(&mut delivered)
            .expect_err("a short source is not a short stream");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let prefix = usize::try_from(end - offset).expect("the cut fits a usize");
        assert_eq!(delivered, archive[..prefix]);
    }
}

#[test]
fn the_accessors_answer_whatever_the_envelope_state() {
    let archive = expected_archive();

    // Both blocks present at lengths the release format cannot use: the
    // bounded read reports them without reading them, and the raw blocks are
    // still there.
    let wrong = version_2(
        UNPARSABLE,
        &archive,
        &[0x5a; ED25519_SIGNATURE_LEN + 1],
        &[b'a'; KEY_ID_HEX_LEN - 1],
    );
    let mut read = container(&wrong);
    assert!(matches!(read.signature(), EnvelopeBlock::WrongLength));
    assert!(matches!(read.key_id(), EnvelopeBlock::WrongLength));
    assert_eq!(read.container_version(), FORMAT_VERSION);
    assert_blocks(&mut read, UNPARSABLE, &archive);

    // The same verdict reached through bounds a well-formed signed container
    // does not meet.
    let dir = tempfile::tempdir().expect("tempdir");
    let (bytes, handed) = signed(dir.path());
    let bounds = EnvelopeBounds {
        signature_len: 1,
        key_id_len: 1,
    };
    let mut read = read_package_container(Cursor::new(bytes.as_slice()), &bounds)
        .expect("the container reads");
    assert!(matches!(read.signature(), EnvelopeBlock::WrongLength));
    assert!(matches!(read.key_id(), EnvelopeBlock::WrongLength));
    assert_blocks(&mut read, &handed, &archive);

    // Present at the bounded lengths, and absent.
    let mut read = container(&bytes);
    assert!(matches!(read.signature(), EnvelopeBlock::Present(_)));
    assert_blocks(&mut read, &handed, &archive);
    let bytes = unsigned(dir.path());
    let mut read = container(&bytes);
    assert!(matches!(read.signature(), EnvelopeBlock::Absent));
    assert_blocks(&mut read, &handed, &archive);
}

#[test]
fn the_accessors_answer_for_a_manifest_that_does_not_parse() {
    for (label, bytes) in [
        ("version 1", version_1(BASE, UNPARSABLE, NOT_AN_ARCHIVE)),
        ("version 2", version_2(UNPARSABLE, NOT_AN_ARCHIVE, &[], &[])),
    ] {
        let mut read = container(&bytes);
        assert!(
            matches!(
                read.parse_unverified_manifest(),
                Err(PayloadError::ManifestParse(_))
            ),
            "{label}"
        );
        assert_blocks(&mut read, UNPARSABLE, NOT_AN_ARCHIVE);
    }
}

#[test]
fn the_version_1_writer_frames_a_container_the_real_readers_accept() {
    // A genuine pre-versioned baseline: no `format_version`, no bound member
    // list, no `commit`, over an archive the writer's own archive block
    // produces — the shape every published version-1 payload has.
    let archive = expected_archive();
    let manifest = format!(
        r#"{{"artifacts":[{{"component":"example","version":"1.0.0","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"{MEMBER}","sha256":"{}"}}]}}"#,
        sha256_hex(MEMBER_BYTES)
    )
    .into_bytes();

    let bytes = version_1(BASE, &manifest, &archive);
    let mut read = container(&bytes);
    assert_eq!(read.container_version(), 1);
    assert!(matches!(read.signature(), EnvelopeBlock::Absent));
    assert!(matches!(read.key_id(), EnvelopeBlock::Absent));
    let parsed = read
        .parse_unverified_manifest()
        .expect("the baseline parses");
    assert_eq!(parsed.format_version(), None);
    assert_blocks(&mut read, &manifest, &archive);

    // The layout is the version-1 one: the blocks follow the base and a
    // 41-byte footer closes the file.
    assert_eq!(
        bytes.len(),
        BASE.len() + manifest.len() + archive.len() + 41
    );

    // `open` accepts it too, down to extracting the artifact.
    let mut payload = open(Cursor::new(bytes))
        .expect("the payload opens")
        .expect("a payload is present");
    let dest = tempfile::tempdir().expect("tempdir");
    payload
        .extract_to(dest.path())
        .expect("the payload extracts");
    assert_eq!(
        std::fs::read(dest.path().join(MEMBER)).expect("the artifact is on disk"),
        MEMBER_BYTES
    );

    // An empty base writes a `.pkg` whose manifest starts at offset 0.
    let pkg = version_1(&[], &manifest, &archive);
    assert_eq!(pkg.get(..manifest.len()), Some(manifest.as_slice()));
    assert_blocks(&mut container(&pkg), &manifest, &archive);
}

#[test]
fn a_file_without_a_trailer_is_no_trailer() {
    assert!(matches!(
        read_package_container(Cursor::new(BASE), &ENVELOPE_BOUNDS),
        Err(PayloadError::NoTrailer)
    ));
}
