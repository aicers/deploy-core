//! [`write_standalone_tail`]: the offsets and footer it writes, and that
//! every refusal comes before its first byte.

use std::io::{self, Write};

use super::{
    FOOTER_SIZE, FORMAT_VERSION, MAGIC, PayloadError, Signed, validate_signed,
    write_standalone_tail,
};

/// A writer that keeps every byte it accepts.
#[derive(Default)]
struct Recording {
    accepted: Vec<u8>,
}

impl Write for Recording {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.accepted.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn signed() -> Signed {
    Signed {
        signature: vec![0x5a; 64],
        key_id: "0123456789abcdef".repeat(4),
    }
}

fn fields_of(footer: &[u8]) -> (u8, [u64; 8]) {
    assert_eq!(footer.len(), FOOTER_SIZE);
    assert_eq!(&footer[..MAGIC.len()], MAGIC);
    let mut fields = [0u64; 8];
    for (at, field) in fields.iter_mut().enumerate() {
        let start = MAGIC.len() + 1 + at * 8;
        *field = u64::from_le_bytes(footer[start..start + 8].try_into().unwrap());
    }
    (footer[MAGIC.len()], fields)
}

#[test]
fn a_signed_tail_follows_the_real_manifest_offset() {
    let signed = signed();
    let mut out = Recording::default();
    write_standalone_tail(&mut out, 10, 20, 30, Some(&signed)).expect("written");
    assert_eq!(&out.accepted[..64], &signed.signature[..]);
    assert_eq!(&out.accepted[64..128], signed.key_id.as_bytes());
    assert_eq!(
        fields_of(&out.accepted[128..]),
        (FORMAT_VERSION, [10, 20, 30, 30, 60, 64, 124, 64])
    );
}

#[test]
fn an_unsigned_tail_is_the_footer_alone_with_absent_envelope_pairs() {
    let mut out = Recording::default();
    write_standalone_tail(&mut out, 0, 20, 30, None).expect("written");
    assert_eq!(
        fields_of(&out.accepted),
        (FORMAT_VERSION, [0, 20, 20, 30, 0, 0, 0, 0])
    );
}

#[test]
fn an_overflowing_offset_or_length_writes_no_tail_byte() {
    let signed = signed();
    let footer = FOOTER_SIZE as u64;
    let cases: [(u64, u64, u64, Option<&Signed>); 6] = [
        // The archive offset.
        (u64::MAX, 1, 0, None),
        // The archive's end.
        (0, u64::MAX, 1, None),
        // The key-ID offset.
        (u64::MAX - 100, 50, 50, Some(&signed)),
        // The key ID's end.
        (u64::MAX - 100, 0, 40, Some(&signed)),
        // The footer's end, unsigned and signed.
        (u64::MAX - footer + 1, 0, 0, None),
        (u64::MAX - footer - 127, 0, 0, Some(&signed)),
    ];
    for (manifest_offset, manifest_len, archive_len, signed) in cases {
        let mut out = Recording::default();
        let error =
            write_standalone_tail(&mut out, manifest_offset, manifest_len, archive_len, signed)
                .expect_err("the overflow is refused");
        assert!(
            matches!(error, PayloadError::MalformedFooter { .. }),
            "{error:?}"
        );
        assert!(out.accepted.is_empty(), "no tail byte was written");
    }

    // Just inside the limit, it writes.
    let mut out = Recording::default();
    write_standalone_tail(&mut out, u64::MAX - footer, 0, 0, None).expect("fits exactly");
    assert_eq!(out.accepted.len(), FOOTER_SIZE);
}

#[test]
fn malformed_framing_is_refused_as_validate_signed_refuses_it_with_no_tail_byte() {
    let mut short = signed();
    short.signature.pop();
    let mut uppercase = signed();
    uppercase.key_id = uppercase.key_id.to_uppercase();
    let mut long_id = signed();
    long_id.key_id.push('0');
    for signed in [short, uppercase, long_id] {
        let expected = validate_signed(&signed).expect_err("malformed");
        let mut out = Recording::default();
        let error = write_standalone_tail(&mut out, 0, 20, 30, Some(&signed))
            .expect_err("the framing is refused");
        assert_eq!(format!("{error:?}"), format!("{expected:?}"));
        assert!(out.accepted.is_empty(), "no tail byte was written");
    }
}
