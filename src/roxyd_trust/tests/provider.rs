//! Characterization of the outcomes the chain check and the key match give per
//! key type and per key encoding.
//!
//! Every expectation here was pinned against the crypto backend the module
//! was first written on, and the provider switch keeps them unchanged: which
//! chain signatures are accepted, which PKCS#8 encodings `key_matches_cert`
//! reads, and exactly which of them it refuses as
//! [`TrustError::UnsupportedKey`]. The encoding cases are the ones where
//! AWS-LC's parser and that backend's disagree, each rebuilt from a freshly
//! generated key so a case accepted by mistake shows up as `Ok(true)` rather
//! than as a quiet mismatch.
//!
//! The last section covers the RSA keys AWS-LC refuses and that backend
//! matched: one whose private exponent or CRT exponents are inconsistent with
//! the public exponent, and one whose modulus is 2047 bits long. They keep
//! that backend's outcome, and so do the refusals it made on the same values.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, SignatureAlgorithm,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::super::{TrustError, key_matches_cert, parse_pem_strict};
use super::{NOW, validate_material, window};

/// Test-only RSA keys, generated once with OpenSSL; see the README beside them.
const RSA_2048_CA: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2048-ca.pem");
const RSA_2048_LEAF: &str =
    include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2048-leaf.pem");
const RSA_1024: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-1024.pem");
const RSA_2560: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2560.pem");
const RSA_4096: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-4096.pem");
const RSA_8192: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-8192.pem");
const RSA_2048_E3: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2048-e3.pem");
const RSA_2048_E_OVER_33_BITS: &str =
    include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2048-e-over-33-bits.pem");
/// A 2047-bit RSA key over two 1024-bit primes, and its self-signed
/// certificate; built by hand, since OpenSSL splits such a modulus unevenly.
const RSA_2047: &str = include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2047.pem");
const RSA_2047_CERT: &str =
    include_str!("../../../assets/test-fixtures/roxyd-trust/rsa-2047-cert.pem");
const P256_EXPLICIT_PARAMS: &str =
    include_str!("../../../assets/test-fixtures/roxyd-trust/p256-explicit-params.pem");

/// The RFC 8032 §7.1 TEST 1 secret key: public test data, not key material.
const RFC8032_TEST1_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// What `webpki` reports, through [`TrustError::ChainInvalid`], for a leaf
/// whose signature uses an algorithm outside the supported set: the offending
/// algorithm identifier (Ed25519) and the identifiers of every accepted one.
const ED25519_SIGNED_CHAIN_ERROR: &str = "UnsupportedSignatureAlgorithmContext(UnsupportedSignatureAlgorithmContext { signature_algorithm_id: [6, 3, 43, 101, 112], supported_algorithms: [0x06082a8648ce3d040302, 0x06082a8648ce3d040303, 0x06082a8648ce3d040302, 0x06082a8648ce3d040303, 0x06092a864886f70d01010b0500, 0x06092a864886f70d01010c0500, 0x06092a864886f70d01010d0500] })";

// DER tags and the object identifiers the encoding cases are built from.
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_1: u8 = 0xa1;
/// PKCS#8 v2's `[1] IMPLICIT BIT STRING` public key.
const TAG_CONTEXT_1_PRIMITIVE: u8 = 0x81;
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
/// `pkcs-9-at-friendlyName`, carried as a PKCS#8 attribute.
const OID_FRIENDLY_NAME: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14,
];
/// A `BMPString` value for that attribute.
const FRIENDLY_NAME_VALUE: &[u8] = &[0x1e, 0x02, 0x00, 0x6b];

/// `ecdsa-with-SHA256`, `ecdsa-with-SHA384`, `sha256WithRSAEncryption`.
const SIG_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const SIG_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const SIG_RSA_SHA256: &str = "1.2.840.113549.1.1.11";

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

/// Encodes one DER TLV. Every fixture here is shorter than 64 KiB.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).expect("checked above"));
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, u8::try_from(len).expect("checked above")]);
    } else {
        let len = u16::try_from(len).expect("a fixture is shorter than 64 KiB");
        out.push(0x82);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(contents);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &parts.concat())
}

fn integer(value: u8) -> Vec<u8> {
    tlv(TAG_INTEGER, &[value])
}

/// Splits the first DER TLV off `input`, returning its tag, its contents and
/// what follows it.
fn split_tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let (&tag, rest) = input.split_first().expect("a tag");
    let (&first, rest) = rest.split_first().expect("a length");
    let (len, rest) = match first {
        n if n < 0x80 => (usize::from(n), rest),
        0x81 => {
            let (&n, rest) = rest.split_first().expect("a length byte");
            (usize::from(n), rest)
        }
        0x82 => {
            let (bytes, rest) = rest.split_first_chunk::<2>().expect("two length bytes");
            (usize::from(u16::from_be_bytes(*bytes)), rest)
        }
        other => panic!("fixture length form {other:#x} is not produced here"),
    };
    let (contents, rest) = rest.split_at(len);
    (tag, contents, rest)
}

/// Splits `input` into its top-level TLVs, each kept whole.
fn elements(mut input: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (_, _, rest) = split_tlv(input);
        let consumed = input.len() - rest.len();
        out.push(&input[..consumed]);
        input = rest;
    }
    out
}

fn contents_of(element: &[u8]) -> &[u8] {
    split_tlv(element).1
}

/// The parts of a PKCS#8 `PrivateKeyInfo`: its `AlgorithmIdentifier` contents
/// and its `privateKey` contents.
struct PrivateKeyInfo<'a> {
    algorithm: &'a [u8],
    private_key: &'a [u8],
}

fn private_key_info(pkcs8: &[u8]) -> PrivateKeyInfo<'_> {
    let (tag, body, rest) = split_tlv(pkcs8);
    assert_eq!((tag, rest.len()), (TAG_SEQUENCE, 0), "one PrivateKeyInfo");
    let fields = elements(body);
    assert_eq!(fields.len(), 3, "a plain version-0 PrivateKeyInfo");
    PrivateKeyInfo {
        algorithm: contents_of(fields[1]),
        private_key: contents_of(fields[2]),
    }
}

/// Re-encodes a `PrivateKeyInfo` from its parts.
fn pkcs8(version: u8, algorithm: &[u8], private_key: &[u8], tail: &[&[u8]]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    let version = integer(version);
    let algorithm = tlv(TAG_SEQUENCE, algorithm);
    let private_key = tlv(TAG_OCTET_STRING, private_key);
    parts.push(&version);
    parts.push(&algorithm);
    parts.push(&private_key);
    parts.extend_from_slice(tail);
    sequence(&parts)
}

/// PKCS#8 attributes holding one `friendlyName`.
fn attributes() -> Vec<u8> {
    let value_set = tlv(TAG_SET, FRIENDLY_NAME_VALUE);
    let attribute = sequence(&[OID_FRIENDLY_NAME, &value_set]);
    tlv(TAG_CONTEXT_0, &attribute)
}

// ---------------------------------------------------------------------------
// EC keys, taken apart and rebuilt
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Curve {
    P256,
    P384,
}

impl Curve {
    fn signature_algorithm(self) -> &'static SignatureAlgorithm {
        match self {
            Curve::P256 => &PKCS_ECDSA_P256_SHA256,
            Curve::P384 => &PKCS_ECDSA_P384_SHA384,
        }
    }

    fn oid(self) -> &'static [u8] {
        match self {
            Curve::P256 => OID_P256,
            Curve::P384 => OID_P384,
        }
    }

    /// The PKCS#8 `AlgorithmIdentifier` contents naming this curve.
    fn key_algorithm(self) -> Vec<u8> {
        [OID_EC_PUBLIC_KEY, self.oid()].concat()
    }

    fn other(self) -> Curve {
        match self {
            Curve::P256 => Curve::P384,
            Curve::P384 => Curve::P256,
        }
    }
}

/// A freshly generated EC key: its scalar, its uncompressed public point, and
/// a certificate carrying that point.
struct EcKey {
    curve: Curve,
    scalar: Vec<u8>,
    point: Vec<u8>,
    cert: Vec<u8>,
}

impl EcKey {
    fn generate(curve: Curve) -> EcKey {
        let key = KeyPair::generate_for(curve.signature_algorithm()).expect("an EC key");
        let der = key.serialize_der();
        let info = private_key_info(&der);
        assert_eq!(info.algorithm, curve.key_algorithm().as_slice());
        let (tag, body, rest) = split_tlv(info.private_key);
        assert_eq!((tag, rest.len()), (TAG_SEQUENCE, 0), "one ECPrivateKey");
        let mut scalar = None;
        let mut point = None;
        for field in elements(body) {
            let (tag, contents, _) = split_tlv(field);
            match tag {
                TAG_OCTET_STRING => scalar = Some(contents.to_vec()),
                TAG_CONTEXT_1 => {
                    let (tag, bits, _) = split_tlv(contents);
                    assert_eq!(tag, TAG_BIT_STRING);
                    point = Some(bits[1..].to_vec());
                }
                _ => {}
            }
        }
        let point = point.expect("the generator embeds the public key");
        assert_eq!(point.as_slice(), key.public_key_raw());
        EcKey {
            curve,
            scalar: scalar.expect("a private key"),
            point,
            cert: self_signed_cert(&key),
        }
    }

    fn compressed_point(&self) -> Vec<u8> {
        let coordinate_len = (self.point.len() - 1) / 2;
        let x = &self.point[1..=coordinate_len];
        let y_is_odd = self.point.last().expect("a point") & 1 == 1;
        let mut out = vec![if y_is_odd { 0x03 } else { 0x02 }];
        out.extend_from_slice(x);
        out
    }

    /// The canonical encoding the first backend produced: PKCS#8 v1, a named curve,
    /// no `[0]` parameters, and the uncompressed public key.
    fn canonical(&self) -> Vec<u8> {
        let inner = ec_private_key(1, &self.scalar, None, Some(&self.point));
        pkcs8(0, &self.curve.key_algorithm(), &inner, &[])
    }
}

/// An `ECPrivateKey` with the given version, scalar, `[0]` parameters and
/// `[1]` public key bytes.
fn ec_private_key(
    version: u8,
    scalar: &[u8],
    parameters: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Vec<u8> {
    let version = integer(version);
    let scalar = tlv(TAG_OCTET_STRING, scalar);
    let parameters = parameters.map(|oid| tlv(TAG_CONTEXT_0, oid));
    let public_key = public_key.map(|point| {
        let bits = [&[0u8][..], point].concat();
        tlv(TAG_CONTEXT_1, &tlv(TAG_BIT_STRING, &bits))
    });
    let mut parts: Vec<&[u8]> = vec![&version, &scalar];
    if let Some(parameters) = &parameters {
        parts.push(parameters);
    }
    if let Some(public_key) = &public_key {
        parts.push(public_key);
    }
    sequence(&parts)
}

fn self_signed_cert(key: &KeyPair) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, "key");
    params
        .self_signed(key)
        .expect("a self-signed certificate")
        .der()
        .to_vec()
}

fn pem_der(pem: &str) -> Vec<u8> {
    let mut blocks = parse_pem_strict(pem.as_bytes(), "private key").expect("fixture PEM");
    assert_eq!(blocks.len(), 1);
    blocks.remove(0).der
}

/// Runs `key_matches_cert` over DER inputs.
fn matches(key_der: &[u8], cert_der: &[u8]) -> Result<bool, TrustError> {
    let (_, cert) = X509Certificate::from_der(cert_der).expect("a certificate");
    key_matches_cert(key_der, &cert)
}

fn assert_unsupported(key_der: &[u8], cert_der: &[u8], case: &str) {
    match matches(key_der, cert_der) {
        Err(TrustError::UnsupportedKey) => {}
        other => panic!("{case}: expected UnsupportedKey, got {other:?}"),
    }
}

fn assert_matches(key_der: &[u8], cert_der: &[u8], case: &str) {
    match matches(key_der, cert_der) {
        Ok(true) => {}
        other => panic!("{case}: expected Ok(true), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Chains per signature algorithm
// ---------------------------------------------------------------------------

/// A CA over `key`, usable as a signing issuer, and its PEM.
struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

fn ca_with_key(key: KeyPair) -> Ca {
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.distinguished_name.push(DnType::CommonName, "root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let pem = params.self_signed(&key).expect("self-signed ca").pem();
    Ca {
        issuer: Issuer::new(params, key),
        pem,
    }
}

/// A client-auth leaf over `key`, signed by `ca`: its PEM, its key's PEM, and
/// the dotted OID of the signature algorithm it was signed with.
fn leaf_with_key(ca: &Ca, key: &KeyPair) -> (String, String, String) {
    let (not_before, not_after) = window();
    let mut params = CertificateParams::new(vec!["roxyd.example".to_string()]).expect("params");
    params.distinguished_name.push(DnType::CommonName, "roxyd");
    params.is_ca = IsCa::NoCa;
    params.not_before = not_before;
    params.not_after = not_after;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(key, &ca.issuer).expect("signed leaf");
    let (_, parsed) = X509Certificate::from_der(cert.der()).expect("a certificate");
    let signature_oid = parsed.signature_algorithm.algorithm.to_id_string();
    (cert.pem(), key.serialize_pem(), signature_oid)
}

fn validate(ca: &Ca, cert: &str, key: &str) -> Result<(), TrustError> {
    validate_material(
        cert.as_bytes(),
        key.as_bytes(),
        ca.pem.as_bytes(),
        ca.pem.as_bytes(),
        NOW,
    )
}

#[test]
fn a_p256_sha256_chain_is_accepted() {
    let ca = ca_with_key(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key"));
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let (cert, key, signature) = leaf_with_key(&ca, &key);
    assert_eq!(signature, SIG_ECDSA_SHA256);
    validate(&ca, &cert, &key).expect("a P-256/SHA-256 chain validates");
}

#[test]
fn a_p384_sha384_chain_is_accepted() {
    let ca = ca_with_key(KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("key"));
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("key");
    let (cert, key, signature) = leaf_with_key(&ca, &key);
    assert_eq!(signature, SIG_ECDSA_SHA384);
    validate(&ca, &cert, &key).expect("a P-384/SHA-384 chain validates");
}

#[test]
fn an_rsa_2048_pkcs1_sha256_chain_is_accepted() {
    let ca = ca_with_key(KeyPair::from_pem(RSA_2048_CA).expect("the RSA CA key"));
    let key = KeyPair::from_pem(RSA_2048_LEAF).expect("the RSA leaf key");
    let (cert, key, signature) = leaf_with_key(&ca, &key);
    assert_eq!(signature, SIG_RSA_SHA256);
    validate(&ca, &cert, &key).expect("an RSA-2048 PKCS#1/SHA-256 chain validates");
}

#[test]
fn a_chain_signed_outside_the_supported_set_is_refused() {
    let ca = ca_with_key(KeyPair::generate_for(&PKCS_ED25519).expect("key"));
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let (cert, key, _) = leaf_with_key(&ca, &key);
    match validate(&ca, &cert, &key) {
        Err(TrustError::ChainInvalid(reason)) => assert_eq!(reason, ED25519_SIGNED_CHAIN_ERROR),
        other => panic!("expected ChainInvalid, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Key ↔ certificate correspondence per key type
// ---------------------------------------------------------------------------

#[test]
fn p256_p384_and_rsa_keys_match_their_own_certificates() {
    for curve in [Curve::P256, Curve::P384] {
        let key = EcKey::generate(curve);
        assert_matches(&key.canonical(), &key.cert, "EC key");
    }
    for (pem, case) in [(RSA_2048_LEAF, "RSA-2048"), (RSA_4096, "RSA-4096")] {
        let key = KeyPair::from_pem(pem).expect("an RSA key");
        assert_matches(&pem_der(pem), &self_signed_cert(&key), case);
    }
}

#[test]
fn a_key_does_not_match_another_keys_certificate() {
    let p256 = EcKey::generate(Curve::P256);
    let other_p256 = EcKey::generate(Curve::P256);
    let p384 = EcKey::generate(Curve::P384);
    let other_p384 = EcKey::generate(Curve::P384);
    let rsa_cert = self_signed_cert(&KeyPair::from_pem(RSA_2048_CA).expect("an RSA key"));
    let rsa_leaf = pem_der(RSA_2048_LEAF);

    let cases: [(&[u8], &[u8], &str); 6] = [
        (&p256.canonical(), &other_p256.cert, "P-256 against P-256"),
        (&p384.canonical(), &other_p384.cert, "P-384 against P-384"),
        (&p256.canonical(), &p384.cert, "P-256 against P-384"),
        (&rsa_leaf, &rsa_cert, "RSA against RSA"),
        (&rsa_leaf, &p256.cert, "RSA against P-256"),
        (&p256.canonical(), &rsa_cert, "P-256 against RSA"),
    ];
    for (key, cert, case) in cases {
        match matches(key, cert) {
            Ok(false) => {}
            other => panic!("{case}: expected Ok(false), got {other:?}"),
        }
    }
}

#[test]
fn keys_outside_the_supported_types_are_unsupported() {
    let cert = EcKey::generate(Curve::P256).cert;

    // Ed25519, both as the generator emits it and as a plain PKCS#8 v1
    // document over the RFC 8032 test seed.
    let generated = KeyPair::generate_for(&PKCS_ED25519).expect("an Ed25519 key");
    assert_unsupported(&generated.serialize_der(), &cert, "generated Ed25519");
    let seed = hex_bytes(RFC8032_TEST1_SEED);
    let ed25519_v1 = pkcs8(
        0,
        &[0x06, 0x03, 0x2b, 0x65, 0x70],
        &tlv(TAG_OCTET_STRING, &seed),
        &[],
    );
    assert_unsupported(&ed25519_v1, &cert, "Ed25519 PKCS#8 v1");

    assert_unsupported(&pem_der(RSA_1024), &cert, "RSA-1024");
    assert_unsupported(b"not a key", &cert, "arbitrary bytes");
    assert_unsupported(&[], &cert, "empty input");
    assert_unsupported(&cert, &cert, "a certificate");
}

#[test]
fn rsa_keys_outside_the_accepted_profile_are_unsupported() {
    let cert = self_signed_cert(&KeyPair::from_pem(RSA_2048_LEAF).expect("an RSA key"));
    let cases = [
        // Moduli larger than 4096 bits.
        (RSA_8192, "RSA-8192"),
        // Primes whose length is not a multiple of 512 bits.
        (RSA_2560, "RSA-2560"),
        // Public exponents below 65537 and above 33 bits.
        (RSA_2048_E3, "RSA-2048 with e = 3"),
        (RSA_2048_E_OVER_33_BITS, "RSA-2048 with e = 2^33 + 1"),
    ];
    for (pem, case) in cases {
        assert_unsupported(&pem_der(pem), &cert, case);
    }
}

// ---------------------------------------------------------------------------
// Key ↔ certificate correspondence per PKCS#8 encoding
// ---------------------------------------------------------------------------

#[test]
fn ec_pkcs8_encodings_keep_their_outcomes() {
    for curve in [Curve::P256, Curve::P384] {
        let key = EcKey::generate(curve);
        let algorithm = curve.key_algorithm();
        let canonical = key.canonical();
        let full = ec_private_key(1, &key.scalar, None, Some(&key.point));

        // Accepted: the canonical form, `[0]` parameters naming the key's own
        // curve, and PKCS#8 attributes, which are ignored.
        assert_matches(&canonical, &key.cert, "canonical");
        let with_parameters = ec_private_key(1, &key.scalar, Some(curve.oid()), Some(&key.point));
        assert_matches(
            &pkcs8(0, &algorithm, &with_parameters, &[]),
            &key.cert,
            "[0] parameters naming the key's curve",
        );
        assert_matches(
            &pkcs8(0, &algorithm, &full, &[&attributes()]),
            &key.cert,
            "PKCS#8 attributes",
        );

        let without_public_key = ec_private_key(1, &key.scalar, None, None);
        let compressed = ec_private_key(1, &key.scalar, None, Some(&key.compressed_point()));
        let padded_scalar = [&[0u8][..], &key.scalar].concat();
        let padded = ec_private_key(1, &padded_scalar, None, Some(&key.point));
        let other_parameters =
            ec_private_key(1, &key.scalar, Some(curve.other().oid()), Some(&key.point));
        let version_zero = ec_private_key(0, &key.scalar, None, Some(&key.point));
        let mut trailing = canonical.clone();
        trailing.push(0);
        let public_key_field = tlv(TAG_CONTEXT_1_PRIMITIVE, &[&[0u8][..], &key.point].concat());
        let non_minimal_length = {
            let (_, body, _) = split_tlv(&canonical);
            let len = u16::try_from(body.len()).expect("a short key");
            [&[TAG_SEQUENCE, 0x82][..], &len.to_be_bytes(), body].concat()
        };

        let refused: [(Vec<u8>, &str); 11] = [
            (trailing, "a byte after the PrivateKeyInfo"),
            (non_minimal_length, "a non-minimal length"),
            (
                pkcs8(1, &algorithm, &full, &[]),
                "PKCS#8 v2 without a public key",
            ),
            (
                pkcs8(1, &algorithm, &full, &[&public_key_field]),
                "PKCS#8 v2 with a public key",
            ),
            (
                pkcs8(0, &curve.other().key_algorithm(), &full, &[]),
                "the other curve's algorithm identifier",
            ),
            (
                pkcs8(0, &algorithm, &without_public_key, &[]),
                "no [1] public key",
            ),
            (
                pkcs8(0, &algorithm, &compressed, &[]),
                "a compressed [1] public key",
            ),
            (
                pkcs8(0, &algorithm, &padded, &[]),
                "a zero-padded private scalar",
            ),
            (
                pkcs8(0, &algorithm, &other_parameters, &[]),
                "[0] parameters naming the other curve",
            ),
            (
                pkcs8(0, &algorithm, &version_zero, &[]),
                "ECPrivateKey version 0",
            ),
            (
                pkcs8(0, &algorithm, &[full.as_slice(), &[0]].concat(), &[]),
                "a byte after the ECPrivateKey",
            ),
        ];
        for (der, case) in refused {
            assert_unsupported(&der, &key.cert, case);
        }
    }

    // Explicit curve parameters in place of the named P-256 curve.
    let cert = EcKey::generate(Curve::P256).cert;
    assert_unsupported(
        &pem_der(P256_EXPLICIT_PARAMS),
        &cert,
        "explicit curve parameters",
    );
}

#[test]
fn rsa_pkcs8_encodings_keep_their_outcomes() {
    let pem = RSA_2048_LEAF;
    let cert = self_signed_cert(&KeyPair::from_pem(pem).expect("an RSA key"));
    let der = pem_der(pem);
    let info = private_key_info(&der);
    let null = tlv(TAG_NULL, &[]);
    assert_eq!(
        info.algorithm,
        [OID_RSA_ENCRYPTION, &null].concat().as_slice()
    );

    assert_matches(&der, &cert, "canonical");
    assert_matches(
        &pkcs8(0, info.algorithm, info.private_key, &[&attributes()]),
        &cert,
        "PKCS#8 attributes",
    );

    let mut trailing = der.clone();
    trailing.push(0);
    let refused: [(Vec<u8>, &str); 4] = [
        (trailing, "a byte after the PrivateKeyInfo"),
        (
            pkcs8(1, info.algorithm, info.private_key, &[]),
            "PKCS#8 v2 without a public key",
        ),
        (
            pkcs8(0, OID_RSA_ENCRYPTION, info.private_key, &[]),
            "rsaEncryption without NULL parameters",
        ),
        (
            pkcs8(0, info.algorithm, &[info.private_key, &[0]].concat(), &[]),
            "a byte after the RSAPrivateKey",
        ),
    ];
    for (der, case) in refused {
        assert_unsupported(&der, &cert, case);
    }
}

// ---------------------------------------------------------------------------
// Where the provider is stricter
// ---------------------------------------------------------------------------

/// The fields of a two-prime `RSAPrivateKey`: version, n, e, d, p, q, dP, dQ,
/// qInv.
const RSA_P: usize = 4;
const RSA_Q: usize = 5;
const RSA_DP: usize = 6;
const RSA_DQ: usize = 7;
const RSA_QINV: usize = 8;

/// The PKCS#8 `RSA_2048_LEAF` with field `index` of its `RSAPrivateKey`
/// replaced by `field`, a whole `INTEGER`.
fn rsa_leaf_with(index: usize, field: &[u8]) -> Vec<u8> {
    let der = pem_der(RSA_2048_LEAF);
    let info = private_key_info(&der);
    let (tag, body, rest) = split_tlv(info.private_key);
    assert_eq!((tag, rest.len()), (TAG_SEQUENCE, 0), "one RSAPrivateKey");
    let mut fields = elements(body);
    assert_eq!(fields.len(), 9, "a two-prime RSAPrivateKey");
    fields[index] = field;
    pkcs8(0, info.algorithm, &sequence(&fields), &[])
}

/// Field `index` of `RSA_2048_LEAF`'s `RSAPrivateKey`, as a whole `INTEGER`.
fn rsa_leaf_field(index: usize) -> Vec<u8> {
    let der = pem_der(RSA_2048_LEAF);
    let info = private_key_info(&der);
    let (_, body, _) = split_tlv(info.private_key);
    elements(body)[index].to_vec()
}

/// `integer` with the bits of `mask` flipped in its last octet.
fn with_low_bits_flipped(integer: &[u8], mask: u8) -> Vec<u8> {
    let mut value = contents_of(integer).to_vec();
    *value.last_mut().expect("a non-empty integer") ^= mask;
    tlv(TAG_INTEGER, &value)
}

/// The DER `INTEGER` of a non-negative big-endian value.
fn big_integer(value: &[u8]) -> Vec<u8> {
    let start = value
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(value.len() - 1);
    let value = &value[start..];
    if value[0] & 0x80 == 0 {
        tlv(TAG_INTEGER, value)
    } else {
        tlv(TAG_INTEGER, &[&[0], value].concat())
    }
}

/// AWS-LC relates `d`, `dP` and `dQ` to the public exponent and refuses a
/// key inconsistent there; the previous backend never validated `d`, and
/// checked only that `dP` and `dQ` were odd and below their primes, so such a
/// key matched its certificate. It still does, and still does not match
/// another key's.
#[test]
fn rsa_keys_with_an_inconsistent_private_exponent_keep_their_outcome() {
    let cert = self_signed_cert(&KeyPair::from_pem(RSA_2048_LEAF).expect("an RSA key"));
    let other = self_signed_cert(&KeyPair::from_pem(RSA_2048_CA).expect("an RSA key"));
    for (index, case) in [(3, "d"), (RSA_DP, "dP"), (RSA_DQ, "dQ")] {
        // Flipping bit 1 keeps the value's length and parity, so it stays in
        // the range the previous backend checked.
        let key = rsa_leaf_with(index, &with_low_bits_flipped(&rsa_leaf_field(index), 0x02));
        assert_matches(&key, &cert, case);
        match matches(&key, &other) {
            Ok(false) => {}
            result => panic!("{case} against another key: expected Ok(false), got {result:?}"),
        }
    }
}

/// aws-lc-rs refuses every RSA private key below 2048 bits in each
/// constructor it offers. The previous backend compared the modulus length
/// with its 2048-bit minimum after rounding it up to whole bytes, so a
/// consistent key whose two 1024-bit primes multiply to a 2047-bit modulus
/// matched its certificate. It still does, and still does not match another
/// key's.
#[test]
fn rsa_keys_with_a_2047_bit_modulus_keep_their_outcome() {
    let key = pem_der(RSA_2047);
    assert_matches(&key, &pem_der(RSA_2047_CERT), "its own certificate");
    let other = self_signed_cert(&KeyPair::from_pem(RSA_2048_LEAF).expect("an RSA key"));
    match matches(&key, &other) {
        Ok(false) => {}
        result => panic!("another key's certificate: expected Ok(false), got {result:?}"),
    }
}

/// The relations the previous backend did check between an RSA key's values
/// still refuse a key that breaks one, each on its own: the primes multiply
/// to the modulus, `dP` and `dQ` are odd and below their primes, and `qInv`
/// is below `p` and inverts `q` modulo `p`.
#[test]
fn rsa_keys_breaking_a_checked_relation_are_unsupported() {
    let cert = self_signed_cert(&KeyPair::from_pem(RSA_2048_LEAF).expect("an RSA key"));
    let p = rsa_leaf_field(RSA_P);
    let q = rsa_leaf_field(RSA_Q);
    let q_inv = rsa_leaf_field(RSA_QINV);
    // `qInv + p` still inverts `q` modulo `p`, and fails only the range check.
    let q_inv_plus_p = num_bigint::BigUint::from_bytes_be(contents_of(&q_inv))
        + num_bigint::BigUint::from_bytes_be(contents_of(&p));

    let cases: [(usize, Vec<u8>, &str); 7] = [
        (RSA_Q, with_low_bits_flipped(&q, 0x02), "p * q is not n"),
        (
            RSA_DP,
            with_low_bits_flipped(&rsa_leaf_field(RSA_DP), 0x01),
            "an even dP",
        ),
        (
            RSA_DQ,
            with_low_bits_flipped(&rsa_leaf_field(RSA_DQ), 0x01),
            "an even dQ",
        ),
        (RSA_DP, p.clone(), "dP equal to p"),
        (RSA_DQ, q, "dQ equal to q"),
        (
            RSA_QINV,
            with_low_bits_flipped(&q_inv, 0x02),
            "a qInv that does not invert q",
        ),
        (
            RSA_QINV,
            big_integer(&q_inv_plus_p.to_bytes_be()),
            "qInv + p in place of qInv",
        ),
    ];
    for (index, field, case) in cases {
        assert_unsupported(&rsa_leaf_with(index, &field), &cert, case);
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}
