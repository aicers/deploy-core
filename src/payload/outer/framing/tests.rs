//! Tests of the PAX record scan an oversized extension is judged by.

use super::{NamePrefix, PathLookup, PaxScan, SizeLookup};

/// Scans `body` whole, or only its first `stop` bytes.
fn scan(body: &[u8], stop: Option<usize>) -> (PaxScan, NamePrefix) {
    let mut pax = PaxScan::default();
    let mut name = NamePrefix::default();
    let seen = stop.map_or(body, |stop| &body[..stop]);
    for &byte in seen {
        pax.byte(byte, &mut name);
    }
    pax.finish(stop.is_none(), &mut name);
    (pax, name)
}

#[test]
fn the_first_well_formed_path_record_names_the_member() {
    let (pax, name) = scan(b"9 x=1234\n14 path=bin/a\n14 path=bin/b\n", None);
    assert_eq!(pax.path, PathLookup::Found);
    assert_eq!(name.bytes, b"bin/a");
    // A path record whose length does not count its line is skipped.
    let (pax, name) = scan(b"99 path=bin/a\n14 path=bin/b\n", None);
    assert_eq!(pax.path, PathLookup::Found);
    assert_eq!(name.bytes, b"bin/b");
    // The last line needs no newline.
    let (pax, _) = scan(b"14 path=bin/a", None);
    assert_eq!(pax.path, PathLookup::Found);
}

#[test]
fn an_unfinished_path_record_counts_until_its_length_contradicts_it() {
    let body = b"1000 path=bin/aaaaaaaaaaaaaaaa";
    let (pax, name) = scan(body, Some(body.len()));
    assert_eq!(pax.path, PathLookup::Found);
    assert!(pax.path_unfinished);
    assert!(name.display(true).ends_with('\u{2026}'));
    let (pax, _) = scan(b"12 path=bin/aaaaaaaa", Some(20));
    assert_ne!(pax.path, PathLookup::Found);
}

#[test]
fn the_size_lookup_stops_where_the_archive_reader_stops() {
    let (pax, _) = scan(b"9 size=4\n", None);
    assert_eq!(pax.size, SizeLookup::Found(4));
    let (pax, _) = scan(b"11 size=+4\n", None);
    assert_eq!(pax.size, SizeLookup::Found(4));
    // A malformed line before it, a value that does not parse, or an empty
    // line ending the records leaves no size.
    let (pax, _) = scan(b"5 x=1\n9 size=4\n", None);
    assert_eq!(pax.size, SizeLookup::Closed);
    let (pax, _) = scan(b"9 size=x\n9 size=4\n", None);
    assert_eq!(pax.size, SizeLookup::Closed);
    let (pax, _) = scan(b"29 size=99999999999999999999\n", None);
    assert_eq!(pax.size, SizeLookup::Closed);
    let (pax, _) = scan(b"\n9 size=4\n", None);
    assert_eq!(pax.size, SizeLookup::Open);
}

#[test]
fn a_reported_name_is_bounded() {
    let long = format!("{} path=bin/{}\n", 5000, "a".repeat(5000));
    let (pax, name) = scan(long.as_bytes(), Some(4000));
    assert_eq!(pax.path, PathLookup::Found);
    assert_eq!(name.bytes.len(), super::REPORTED_NAME_MAX);
    assert!(name.display(true).ends_with('\u{2026}'));
}
