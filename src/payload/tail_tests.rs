//! [`write_standalone_tail`]: the offsets and footer it writes, and that
//! every refusal comes before its first byte.

use std::io::{self, Write};

use super::{
    DetachedSignature, FOOTER_SIZE, FORMAT_VERSION, MAGIC, PayloadError, Signed, validate_signed,
    write_standalone_tail,
};

/// Bytes the four envelope blocks of a signed tail occupy: 64 + 64 + 4,627 +
/// 64.
const ENVELOPE_LEN: u64 = 4819;

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
        ed25519: DetachedSignature {
            signature: vec![0x5a; 64],
            key_id: "0123456789abcdef".repeat(4),
        },
        ml_dsa_87: DetachedSignature {
            signature: vec![0x6b; 4627],
            key_id: "fedcba9876543210".repeat(4),
        },
    }
}

fn fields_of(footer: &[u8]) -> (u8, [u64; 12]) {
    assert_eq!(footer.len(), FOOTER_SIZE);
    assert_eq!(&footer[..MAGIC.len()], MAGIC);
    let mut fields = [0u64; 12];
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
    assert_eq!(&out.accepted[..64], &signed.ed25519.signature[..]);
    assert_eq!(&out.accepted[64..128], signed.ed25519.key_id.as_bytes());
    assert_eq!(&out.accepted[128..4755], &signed.ml_dsa_87.signature[..]);
    assert_eq!(
        &out.accepted[4755..4819],
        signed.ml_dsa_87.key_id.as_bytes()
    );
    assert_eq!(
        fields_of(&out.accepted[4819..]),
        (
            FORMAT_VERSION,
            [10, 20, 30, 30, 60, 64, 124, 64, 188, 4627, 4815, 64]
        )
    );
}

#[test]
fn an_unsigned_tail_is_the_footer_alone_with_absent_envelope_pairs() {
    let mut out = Recording::default();
    write_standalone_tail(&mut out, 0, 20, 30, None).expect("written");
    assert_eq!(
        fields_of(&out.accepted),
        (FORMAT_VERSION, [0, 20, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0])
    );
}

#[test]
fn an_overflowing_offset_or_length_writes_no_tail_byte() {
    let signed = signed();
    let footer = FOOTER_SIZE as u64;
    let cases: [(u64, u64, u64, Option<&Signed>); 7] = [
        // The archive offset.
        (u64::MAX, 1, 0, None),
        // The archive's end.
        (0, u64::MAX, 1, None),
        // The Ed25519 key-ID offset.
        (u64::MAX - 100, 50, 50, Some(&signed)),
        // The Ed25519 key ID's end.
        (u64::MAX - 100, 0, 40, Some(&signed)),
        // The ML-DSA-87 signature's end.
        (u64::MAX - 4000, 0, 0, Some(&signed)),
        // The footer's end, unsigned and signed.
        (u64::MAX - footer + 1, 0, 0, None),
        (u64::MAX - footer - ENVELOPE_LEN + 1, 0, 0, Some(&signed)),
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

    // Just inside the limit, it writes, unsigned and signed.
    let mut out = Recording::default();
    write_standalone_tail(&mut out, u64::MAX - footer, 0, 0, None).expect("fits exactly");
    assert_eq!(out.accepted.len(), FOOTER_SIZE);
    let mut out = Recording::default();
    write_standalone_tail(
        &mut out,
        u64::MAX - footer - ENVELOPE_LEN,
        0,
        0,
        Some(&signed),
    )
    .expect("fits exactly");
    assert_eq!(out.accepted.len() as u64, ENVELOPE_LEN + footer);
}

#[test]
fn malformed_framing_is_refused_as_validate_signed_refuses_it_with_no_tail_byte() {
    let mut short = signed();
    short.ed25519.signature.pop();
    let mut uppercase = signed();
    uppercase.ed25519.key_id = uppercase.ed25519.key_id.to_uppercase();
    let mut long_id = signed();
    long_id.ed25519.key_id.push('0');
    let mut short_ml_dsa = signed();
    short_ml_dsa.ml_dsa_87.signature.pop();
    let mut long_ml_dsa = signed();
    long_ml_dsa.ml_dsa_87.signature.push(0);
    let mut ml_dsa_uppercase = signed();
    ml_dsa_uppercase.ml_dsa_87.key_id = ml_dsa_uppercase.ml_dsa_87.key_id.to_uppercase();
    for signed in [
        short,
        uppercase,
        long_id,
        short_ml_dsa,
        long_ml_dsa,
        ml_dsa_uppercase,
    ] {
        let expected = validate_signed(&signed).expect_err("malformed");
        let mut out = Recording::default();
        let error = write_standalone_tail(&mut out, 0, 20, 30, Some(&signed))
            .expect_err("the framing is refused");
        assert_eq!(format!("{error:?}"), format!("{expected:?}"));
        assert!(out.accepted.is_empty(), "no tail byte was written");
    }
}
