//! [`write_archive_block`] under both [`MemberLength`] policies.

use std::cell::Cell;
use std::io::{self, Cursor, Read, Write};

use tar::{Builder, EntryType, Header};
use zstd::Encoder;

use super::{
    ExactLength, MemberLength, MemberLengthFault, PayloadError, ZSTD_LEVEL, write_archive_block,
};

const PATH: &str = "bin/tool";

/// The archive block `tar::Builder::append` writes for one member whose
/// header states `length` and whose reader yields `bytes`.
fn reference(length: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let encoder = Encoder::new(&mut out, ZSTD_LEVEL).expect("an encoder");
    let mut builder = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header.set_path(PATH).expect("a short path");
    header.set_size(length);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    builder.append(&header, bytes).expect("appended");
    builder
        .into_inner()
        .expect("finished")
        .finish()
        .expect("compressed");
    out
}

fn one(length: u64, bytes: &[u8], policy: MemberLength) -> (Result<u64, PayloadError>, Vec<u8>) {
    let mut out = Vec::new();
    let result = write_archive_block([Ok((PATH, length, bytes))], &mut out, policy);
    (result, out)
}

#[track_caller]
fn fault_of(result: Result<u64, PayloadError>) -> (io::ErrorKind, MemberLengthFault) {
    match result {
        Err(PayloadError::Io(error)) => {
            let kind = error.kind();
            let fault = error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<MemberLengthFault>())
                .copied()
                .expect("a member-length payload");
            (kind, fault)
        }
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

#[test]
fn an_exact_reader_at_its_length_writes_what_legacy_writes() {
    let bytes = b"exactly twenty bytes";
    let (exact, exact_out) = one(20, bytes, MemberLength::Exact);
    let (legacy, legacy_out) = one(20, bytes, MemberLength::Legacy);
    assert_eq!(exact.expect("exact passes"), exact_out.len() as u64);
    assert_eq!(legacy.expect("legacy passes"), legacy_out.len() as u64);
    assert_eq!(exact_out, legacy_out);
    assert_eq!(exact_out, reference(20, bytes));
}

#[test]
fn an_exact_reader_one_byte_short_is_unexpected_eof() {
    let (result, _) = one(21, b"exactly twenty bytes", MemberLength::Exact);
    assert_eq!(
        fault_of(result),
        (
            io::ErrorKind::UnexpectedEof,
            MemberLengthFault::EndedEarly {
                bound: 21,
                read: 20
            }
        )
    );
}

#[test]
fn an_exact_reader_one_byte_long_is_invalid_data() {
    let (result, _) = one(19, b"exactly twenty bytes", MemberLength::Exact);
    assert_eq!(
        fault_of(result),
        (
            io::ErrorKind::InvalidData,
            MemberLengthFault::Overran { bound: 19 }
        )
    );
}

#[test]
fn the_byte_past_the_length_is_never_delivered() {
    let mut reader = ExactLength::new(&b"0123456789X"[..], 10);
    let mut delivered = Vec::new();
    let mut buf = [0u8; 64];
    let error = loop {
        match reader.read(&mut buf) {
            Ok(0) => panic!("the overrun is refused"),
            Ok(n) => delivered.extend_from_slice(&buf[..n]),
            Err(error) => break error,
        }
    };
    assert_eq!(delivered, b"0123456789");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_legacy_reader_off_by_one_matches_tar_append_without_error() {
    for bytes in [&b"twenty-one bytes long"[..], b"nineteen bytes long"] {
        let (result, out) = one(20, bytes, MemberLength::Legacy);
        assert_eq!(result.expect("legacy never refuses"), out.len() as u64);
        assert_eq!(out, reference(20, bytes));
    }
}

#[test]
fn a_failing_item_surfaces_unchanged_and_stops_the_pull() {
    let pulled = Cell::new(0usize);
    let items = (0..3).map(|at| {
        pulled.set(pulled.get() + 1);
        if at == 1 {
            Err(PayloadError::TruncatedTrailer)
        } else {
            Ok((PATH, 1, Cursor::new(vec![b'x'])))
        }
    });
    for policy in [MemberLength::Legacy, MemberLength::Exact] {
        pulled.set(0);
        let mut out = Vec::new();
        let error = write_archive_block(items.clone(), &mut out, policy).expect_err("refused");
        assert!(matches!(error, PayloadError::TruncatedTrailer), "{error:?}");
        assert_eq!(pulled.get(), 2);
    }
}

#[test]
fn an_overlong_path_is_refused_in_both_policies() {
    let long = "a".repeat(101);
    for policy in [MemberLength::Legacy, MemberLength::Exact] {
        let mut out = Vec::new();
        let error = write_archive_block([Ok((long.as_str(), 1, &b"x"[..]))], &mut out, policy)
            .expect_err("refused");
        assert!(
            matches!(&error, PayloadError::ArchivePathTooLong { path, len } if *path == long && *len == 101),
            "{error:?}"
        );
    }
}

#[test]
fn an_output_failure_keeps_its_error() {
    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = write_archive_block([Ok((PATH, 3, &b"abc"[..]))], Full, MemberLength::Exact)
        .expect_err("refused");
    assert!(
        matches!(&error, PayloadError::Io(e) if e.kind() == io::ErrorKind::StorageFull),
        "{error:?}"
    );
}
