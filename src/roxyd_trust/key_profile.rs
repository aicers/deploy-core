//! The PKCS#8 private-key encodings `key_matches_cert` reads.
//!
//! `key_matches_cert` was written against the previous crypto backend, whose
//! parsers accept one narrow encoding per key type, and the set of keys it
//! reads is part of this module's policy. AWS-LC's PKCS#8 parser, which the
//! match now goes through, accepts more: bytes after the `PrivateKeyInfo`, a
//! version-2 document, an EC key without its public key, with a compressed
//! one, with explicit curve parameters or with a private scalar of the wrong
//! length, and RSA keys up to 8192 bits with any public exponent and any
//! split of the modulus between the primes. [`classify`] restores the narrow
//! profile as an explicit check made before a key reaches the provider, so a
//! key outside it stays
//! [`TrustError::UnsupportedKey`](super::TrustError::UnsupportedKey).
//!
//! What it checks is the previous backend's acceptance rule wherever that
//! rule is a matter of encoding or size: DER-minimal lengths and integers,
//! PKCS#8 v1 only, the exact `AlgorithmIdentifier` bytes, the `ECPrivateKey`
//! and `RSAPrivateKey` layouts, and that backend's bounds on the RSA modulus,
//! exponent and prime lengths. The arithmetic consistency of an EC key — its
//! public point — is left to the provider, which derives it just as that
//! backend did.
//!
//! An RSA key's arithmetic is checked here too, because AWS-LC's rule for it
//! is not the previous backend's. That backend checked that the primes
//! multiply to the modulus, that `qInv` inverts `q` modulo `p`, and that `dP`
//! and `dQ` are odd and below their primes, but never related `d`, `dP` or
//! `dQ` to the public exponent; AWS-LC checks all of them. It also refuses
//! every RSA private key whose modulus is shorter than 2048 bits, where that
//! backend rounded the modulus up to whole bytes first and so read a 2047-bit
//! modulus over two 1024-bit primes. [`RsaKey`] carries the key's own public
//! key, so `key_matches_cert` can still compare one AWS-LC refuses for either
//! reason, and the outcome for every RSA key is the previous backend's.

use num_bigint::BigUint;

/// DER tags this profile reads.
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
/// `[0]`: PKCS#8 attributes, or `ECPrivateKey` parameters.
const TAG_CONTEXT_0: u8 = 0xa0;
/// `[1]`: the `ECPrivateKey` public key.
const TAG_CONTEXT_1: u8 = 0xa1;

/// The `AlgorithmIdentifier` contents of an `id-ecPublicKey` P-256 key.
const P256_ALGORITHM: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07,
];
/// The `AlgorithmIdentifier` contents of an `id-ecPublicKey` P-384 key.
const P384_ALGORITHM: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
];
/// The `AlgorithmIdentifier` contents of an `rsaEncryption` key, with its
/// `NULL` parameters.
const RSA_ALGORITHM: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// The leading octet of an uncompressed SEC 1 point.
const UNCOMPRESSED_POINT: u8 = 0x04;

/// The smallest RSA modulus in the profile, as a length in whole bytes: the
/// previous backend rounds a modulus up to whole bytes before comparing it
/// with its 2048-bit minimum, so a 2047-bit modulus is in the profile.
const RSA_MIN_MODULUS_BYTES: usize = 256;
/// The largest RSA modulus accepted, in bits.
const RSA_MAX_MODULUS_BITS: usize = 4096;
/// The smallest RSA public exponent accepted.
const RSA_MIN_EXPONENT: u64 = 65_537;
/// The largest RSA public exponent accepted: 33 bits.
const RSA_MAX_EXPONENT: u64 = (1 << 33) - 1;
/// The longest encoding of an accepted exponent, in bytes.
const RSA_MAX_EXPONENT_BYTES: usize = 5;
/// Each RSA prime's length is a multiple of this many bits.
const RSA_PRIME_BITS_MULTIPLE: usize = 512;

/// A private key inside the profile, with what the provider's parse of it
/// must agree with.
pub(super) enum ProfiledKey<'a> {
    /// A P-256 key, carrying the uncompressed public point it embeds.
    EcP256 { public_key: &'a [u8] },
    /// A P-384 key, carrying the uncompressed public point it embeds.
    EcP384 { public_key: &'a [u8] },
    /// An RSA key, carrying its integers.
    Rsa(RsaKey<'a>),
}

/// The integers of an RSA key inside the profile, each as its minimal
/// big-endian encoding.
pub(super) struct RsaKey<'a> {
    modulus: &'a [u8],
    public_exponent: &'a [u8],
    /// `p` and `q`.
    primes: [&'a [u8]; 2],
    /// `dP` and `dQ`, in the order of `primes`.
    crt_exponents: [&'a [u8]; 2],
    /// `qInv`.
    crt_coefficient: &'a [u8],
}

impl RsaKey<'_> {
    /// Reports whether `rsa_public_key` is the DER `RSAPublicKey` of this
    /// key's modulus and public exponent, the encoding the provider derives
    /// from a key it reads. A non-minimal encoding of the same values is not.
    pub(super) fn public_key_is(&self, rsa_public_key: &[u8]) -> bool {
        let Some(mut key) = Der::only(rsa_public_key, TAG_SEQUENCE) else {
            return false;
        };
        nonnegative_integer(&mut key) == Some(self.modulus)
            && nonnegative_integer(&mut key) == Some(self.public_exponent)
            && key.is_empty()
    }
}

/// Returns the key type `pkcs8` encodes if it is inside the profile, or
/// `None` if the previous backend refused it for its encoding, its size or,
/// for an RSA key, the relations between its values.
pub(super) fn classify(pkcs8: &[u8]) -> Option<ProfiledKey<'_>> {
    let mut info = Der::only(pkcs8, TAG_SEQUENCE)?;
    // PKCS#8 v1: a version-2 document is refused even without its public key.
    if small_integer(&mut info)? != 0 {
        return None;
    }
    let algorithm = info.expect(TAG_SEQUENCE)?;
    let private_key = info.expect(TAG_OCTET_STRING)?;
    // Attributes are skipped, whatever they hold.
    if info.peek(TAG_CONTEXT_0) {
        info.read()?;
    }
    if !info.is_empty() {
        return None;
    }
    match algorithm {
        P256_ALGORITHM => {
            ec_public_key(private_key, &P256).map(|p| ProfiledKey::EcP256 { public_key: p })
        }
        P384_ALGORITHM => {
            ec_public_key(private_key, &P384).map(|p| ProfiledKey::EcP384 { public_key: p })
        }
        RSA_ALGORITHM => rsa_key(private_key).map(ProfiledKey::Rsa),
        _ => None,
    }
}

/// The per-curve facts an `ECPrivateKey` is checked against.
struct Curve {
    /// The named-curve OID, tag and length included.
    oid: &'static [u8],
    /// The length of a private scalar, in bytes.
    scalar_len: usize,
}

const P256: Curve = Curve {
    oid: &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
    scalar_len: 32,
};
const P384: Curve = Curve {
    oid: &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
    scalar_len: 48,
};

/// Reads an RFC 5915 `ECPrivateKey` for `curve` and returns the public point
/// it embeds: version 1, a scalar of exactly the curve's length, optional
/// `[0]` parameters naming this curve, and a required `[1]` uncompressed
/// public key.
fn ec_public_key<'a>(ec_private_key: &'a [u8], curve: &Curve) -> Option<&'a [u8]> {
    let mut key = Der::only(ec_private_key, TAG_SEQUENCE)?;
    if small_integer(&mut key)? != 1 {
        return None;
    }
    if key.expect(TAG_OCTET_STRING)?.len() != curve.scalar_len {
        return None;
    }
    if key.peek(TAG_CONTEXT_0) && key.expect(TAG_CONTEXT_0)? != curve.oid {
        return None;
    }
    let field = key.expect(TAG_CONTEXT_1)?;
    if !key.is_empty() {
        return None;
    }
    let bits = Der::only(field, TAG_BIT_STRING)?.rest;
    let (&unused_bits, point) = bits.split_first()?;
    let coordinates_len = curve.scalar_len.checked_mul(2)?;
    let in_profile = unused_bits == 0
        && point.first() == Some(&UNCOMPRESSED_POINT)
        && point.len() == coordinates_len.checked_add(1)?;
    in_profile.then_some(point)
}

/// Reads an RFC 8017 `RSAPrivateKey` inside the profile: a two-prime
/// version-0 key whose modulus is at least 256 bytes and at most 4096 bits
/// long, whose public exponent is odd and between 65537 and 33 bits, whose
/// primes each have half the modulus length rounded up and a length that is a
/// multiple of 512 bits, whose private exponent is odd, longer than a prime
/// and smaller than the modulus, and whose other values satisfy
/// [`rsa_relations_hold`].
///
/// None of this is constant time in the private values. The provider's parse
/// of the same bytes is not either, and this runs once over a key its own
/// writer handed over, not in a signing loop.
fn rsa_key(rsa_private_key: &[u8]) -> Option<RsaKey<'_>> {
    let mut key = Der::only(rsa_private_key, TAG_SEQUENCE)?;
    if small_integer(&mut key)? != 0 {
        return None;
    }
    let modulus = nonnegative_integer(&mut key)?;
    let public_exponent = nonnegative_integer(&mut key)?;
    let private_exponent = nonnegative_integer(&mut key)?;
    let primes = [
        nonnegative_integer(&mut key)?,
        nonnegative_integer(&mut key)?,
    ];
    let crt_exponents = [
        nonnegative_integer(&mut key)?,
        nonnegative_integer(&mut key)?,
    ];
    let crt_coefficient = nonnegative_integer(&mut key)?;
    if !key.is_empty() {
        return None;
    }

    let modulus_bits = bit_len(modulus)?;
    if !is_odd(modulus)
        || modulus.len() < RSA_MIN_MODULUS_BYTES
        || modulus_bits > RSA_MAX_MODULUS_BITS
    {
        return None;
    }
    if !exponent_in_profile(public_exponent) {
        return None;
    }
    let half_bits = modulus_bits.div_ceil(2);
    for prime in primes {
        let bits = bit_len(prime)?;
        if !is_odd(prime) || bits != half_bits || bits % RSA_PRIME_BITS_MULTIPLE != 0 {
            return None;
        }
    }
    let private_bits = bit_len(private_exponent)?;
    let below_modulus =
        private_bits < modulus_bits || (private_bits == modulus_bits && private_exponent < modulus);
    if !(is_odd(private_exponent) && private_bits > half_bits && below_modulus) {
        return None;
    }
    let key = RsaKey {
        modulus,
        public_exponent,
        primes,
        crt_exponents,
        crt_coefficient,
    };
    rsa_relations_hold(&key).then_some(key)
}

/// Reports whether `key` satisfies the relations the previous backend
/// checked between its values: `p * q` is a multiple of the modulus, which
/// with the primes' lengths makes it the modulus; `dP` and `dQ` are odd and
/// below their primes; and `qInv` is below `p` and inverts `q` modulo `p`.
/// Nothing relates `d`, `dP` or `dQ` to the public exponent, since that
/// backend did not.
fn rsa_relations_hold(key: &RsaKey<'_>) -> bool {
    let [p, q] = key.primes.map(BigUint::from_bytes_be);
    let crt_exponents_in_range = key
        .crt_exponents
        .iter()
        .zip([&p, &q])
        .all(|(exponent, prime)| is_odd(exponent) && BigUint::from_bytes_be(exponent) < *prime);
    if !crt_exponents_in_range {
        return false;
    }
    let crt_coefficient = BigUint::from_bytes_be(key.crt_coefficient);
    if crt_coefficient >= p {
        return false;
    }
    let modulus = BigUint::from_bytes_be(key.modulus);
    (&p * &q) % &modulus == BigUint::ZERO && (crt_coefficient * &q) % &p == BigUint::from(1_u8)
}

/// Reports whether `exponent`, the minimal big-endian encoding of the public
/// exponent, is odd and inside the accepted range.
fn exponent_in_profile(exponent: &[u8]) -> bool {
    if exponent.first().is_none_or(|&b| b == 0) || exponent.len() > RSA_MAX_EXPONENT_BYTES {
        return false;
    }
    let value = exponent
        .iter()
        .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
    (RSA_MIN_EXPONENT..=RSA_MAX_EXPONENT).contains(&value) && value & 1 == 1
}

/// Returns the bit length of a positive big-endian integer with no leading
/// zero, or `None` for zero.
fn bit_len(value: &[u8]) -> Option<usize> {
    let (&first, rest) = value.split_first()?;
    if first == 0 {
        return None;
    }
    let top_bits = usize::try_from(u8::BITS - first.leading_zeros()).ok()?;
    rest.len().checked_mul(8)?.checked_add(top_bits)
}

fn is_odd(value: &[u8]) -> bool {
    value.last().is_some_and(|b| b & 1 == 1)
}

/// Reads a DER-minimal non-negative `INTEGER` and returns its big-endian
/// value without a sign octet (`[0]` for zero).
fn nonnegative_integer<'a>(der: &mut Der<'a>) -> Option<&'a [u8]> {
    let value = der.expect(TAG_INTEGER)?;
    match value {
        [0] => Some(value),
        [0, rest @ ..] => rest.first().is_some_and(|b| b & 0x80 != 0).then_some(rest),
        [first, ..] if first & 0x80 == 0 => Some(value),
        _ => None,
    }
}

/// Reads a non-negative `INTEGER` that fits in one octet.
fn small_integer(der: &mut Der<'_>) -> Option<u8> {
    match nonnegative_integer(der)? {
        [value] => Some(*value),
        _ => None,
    }
}

/// A cursor over DER, strict in the same places the previous backend's
/// reader is: no high-number tags, and lengths in their shortest form up to
/// two octets.
struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    /// Opens the contents of `input` if it is exactly one element of `tag`.
    fn only(input: &'a [u8], tag: u8) -> Option<Der<'a>> {
        let mut outer = Der { rest: input };
        let contents = outer.expect(tag)?;
        outer.is_empty().then_some(Der { rest: contents })
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn peek(&self, tag: u8) -> bool {
        self.rest.first() == Some(&tag)
    }

    /// Reads the next element and returns its contents if its tag is `tag`.
    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (actual, contents) = self.read()?;
        (actual == tag).then_some(contents)
    }

    /// Reads the next element, returning its tag and contents.
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.rest.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = match first {
            len if len & 0x80 == 0 => (usize::from(len), rest),
            0x81 => {
                let (&len, rest) = rest.split_first()?;
                (len >= 0x80).then_some((usize::from(len), rest))?
            }
            0x82 => {
                let (&len, rest) = rest.split_first_chunk::<2>()?;
                let len = u16::from_be_bytes(len);
                (len >= 0x100).then_some((usize::from(len), rest))?
            }
            _ => return None,
        };
        let (contents, rest) = rest.split_at_checked(len)?;
        self.rest = rest;
        Some((tag, contents))
    }
}

#[cfg(test)]
mod tests {
    use super::{Der, bit_len, exponent_in_profile, nonnegative_integer, small_integer};

    fn read_one(input: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut der = Der { rest: input };
        let (tag, contents) = der.read()?;
        der.is_empty().then(|| (tag, contents.to_vec()))
    }

    #[test]
    fn lengths_are_read_only_in_their_shortest_form_up_to_two_octets() {
        assert_eq!(read_one(&[0x04, 0x01, 0xaa]), Some((0x04, vec![0xaa])));

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([0; 0x80]);
        assert!(read_one(&long).is_some());
        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.extend([0; 0x100]);
        assert!(read_one(&two).is_some());

        // A long form that a shorter one could have carried.
        assert_eq!(read_one(&[0x04, 0x81, 0x01, 0xaa]), None);
        let mut padded = vec![0x04, 0x82, 0x00, 0x80];
        padded.extend([0; 0x80]);
        assert_eq!(read_one(&padded), None);
        // Three length octets, an indefinite length, a high-number tag, and
        // contents shorter than their length.
        assert_eq!(read_one(&[0x04, 0x83, 0x00, 0x00, 0x01, 0xaa]), None);
        assert_eq!(read_one(&[0x24, 0x80, 0x00, 0x00]), None);
        assert_eq!(read_one(&[0x1f, 0x01, 0x00]), None);
        assert_eq!(read_one(&[0x04, 0x02, 0xaa]), None);
    }

    #[test]
    fn integers_must_be_minimal_and_non_negative() {
        let integer = |bytes: &[u8]| {
            let mut der = Der { rest: bytes };
            nonnegative_integer(&mut der).map(<[u8]>::to_vec)
        };
        assert_eq!(integer(&[0x02, 0x01, 0x00]), Some(vec![0x00]));
        assert_eq!(integer(&[0x02, 0x01, 0x7f]), Some(vec![0x7f]));
        assert_eq!(integer(&[0x02, 0x02, 0x00, 0x80]), Some(vec![0x80]));
        assert_eq!(integer(&[0x02, 0x02, 0x00, 0x7f]), None);
        assert_eq!(integer(&[0x02, 0x01, 0x80]), None);
        assert_eq!(integer(&[0x02, 0x00]), None);
        assert_eq!(integer(&[0x04, 0x01, 0x00]), None);

        let mut der = Der {
            rest: &[0x02, 0x02, 0x01, 0x00],
        };
        assert_eq!(small_integer(&mut der), None);
    }

    #[test]
    fn the_public_exponent_is_odd_and_between_65537_and_33_bits() {
        assert!(exponent_in_profile(&[0x01, 0x00, 0x01]));
        assert!(exponent_in_profile(&[0x01, 0xff, 0xff, 0xff, 0xff]));
        assert!(!exponent_in_profile(&[0x03]));
        assert!(!exponent_in_profile(&[0xff, 0xff]));
        assert!(!exponent_in_profile(&[0x01, 0x00, 0x02]));
        assert!(!exponent_in_profile(&[0x02, 0x00, 0x00, 0x00, 0x01]));
        assert!(!exponent_in_profile(&[0x00, 0x01, 0x00, 0x01]));
        assert!(!exponent_in_profile(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x01]));
        assert!(!exponent_in_profile(&[]));
    }

    #[test]
    fn bit_lengths_count_from_the_top_set_bit() {
        assert_eq!(bit_len(&[0x01]), Some(1));
        assert_eq!(bit_len(&[0x80, 0x00]), Some(16));
        assert_eq!(bit_len(&[0x7f; 256]), Some(2047));
        assert_eq!(bit_len(&[0x00, 0x01]), None);
        assert_eq!(bit_len(&[]), None);
    }
}
