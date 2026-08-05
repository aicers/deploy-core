//! Validating root helper for roxyd's trust material (RFC 0003 §8.3, bootler #99).
//!
//! roxyd runs as **root** (it verifies `euid == 0` and aborts otherwise), yet its
//! bootroot agent — like every other service's agent after the §7 non-root
//! transition — runs as the unprivileged `clumit-roxyd` account and writes roxyd's
//! cert, key, and CA bundle into `agent/roxyd/`. Left there, that material would be
//! a trust anchor and node identity a compromise of one non-root account could
//! swap under a root daemon: the deviation RFC 0003 §8.3 records.
//!
//! This module closes it. `agent/roxyd/` becomes a **staging** area the agent keeps
//! writing to; a root helper — an internal `bootler-security` oneshot triggered by a
//! systemd `.path` watch on that directory — validates the staged material against a
//! root-owned trust anchor, copies the bytes it validated into a fresh root-owned
//! generation directory under `roxyd-tls/`, and atomically repoints the `active`
//! symlink roxyd reads through. roxyd needs no code change: its unit's `ExecStart`
//! already names the paths it reads and it reloads on `SIGHUP`, so pointing those
//! paths at `roxyd-tls/active/` and reloading after each swap is entirely
//! installer-side.
//!
//! # Two trust roles, validated as such
//!
//! roxyd is a `review-protocol` **client**. It hands its cert and key to the
//! connection builder as its **own identity**, and hands the CA bundle to
//! `.root_certs()` as the anchor for verifying the **Manager** (roxyd
//! `control.rs`). The two roles need not share an issuer, so "the leaf chains to the
//! CA bundle" is **not** a correct check and this module never makes it. Instead the
//! leaf is required to chain to a separate, root-owned **client-identity anchor** —
//! an install-time snapshot of the internal CA *root* (`client-anchor.pem`) — while
//! the CA bundle is validated only for its own purpose (parses, non-empty).
//!
//! # The bytes validated are the bytes installed
//!
//! Validation runs against the **copy** already inside the root-owned generation
//! directory, never the staged file the agent can still rewrite. A staged file that
//! passes a check and is then swapped before it is copied is a TOCTOU the agent
//! wins; copying first and validating the copy closes it (RFC 0003 §8.3, AC).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    RsaKeyPair,
};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use webpki::{EndEntityCert, KeyUsage};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;

use crate::layout::{ROXYD_ACTIVE_LINK, ROXYD_GENERATION_PREFIX};

/// The signature algorithms the chain check accepts. bootroot issues ECDSA P-256
/// leaves today (rcgen's default), but P-384 and RSA are listed so a future CA
/// profile change does not silently fail closed.
static SUPPORTED_SIG_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
];

/// The PEM label of an X.509 certificate.
const LABEL_CERTIFICATE: &str = "CERTIFICATE";
/// The PEM label of a PKCS#8 private key (what rcgen's `serialize_pem` emits).
const LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";

/// A failure to validate or activate roxyd's trust material. Every variant is
/// fail-closed: on any of them the caller leaves `active/` untouched, so roxyd keeps
/// serving the last material a root helper vouched for (RFC 0003 §8.3).
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// A file could not be read or written, or a directory operation failed.
    #[error("roxyd trust i/o error at {path}: {source}")]
    Io {
        /// The path the operation targeted.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A PEM file did not parse as a sequence of PEM blocks with nothing else in it
    /// (trailing or interleaved garbage, a truncated block, or bad base64).
    #[error("{path} is not well-formed PEM: {reason}")]
    Pem {
        /// The offending file's role (`certificate`, `private key`, `CA bundle`,
        /// `anchor`).
        path: String,
        /// What was wrong.
        reason: String,
    },

    /// A certificate or key blob failed to parse as DER.
    #[error("failed to parse {what}: {reason}")]
    Parse {
        /// What was being parsed.
        what: String,
        /// The parser's message.
        reason: String,
    },

    /// The leaf certificate is outside its validity window at the current time.
    #[error(
        "roxyd certificate is not valid at this time (not before {not_before}, not after {not_after})"
    )]
    Validity {
        /// The certificate's `notBefore`.
        not_before: String,
        /// The certificate's `notAfter`.
        not_after: String,
    },

    /// The leaf certificate carries an extended-key-usage extension that does not
    /// permit TLS client authentication — it cannot be roxyd's client identity.
    #[error("roxyd certificate does not permit TLS client authentication (clientAuth EKU absent)")]
    ClientAuthMissing,

    /// The private key does not correspond to the certificate's public key.
    #[error("roxyd certificate and private key do not correspond")]
    KeyMismatch,

    /// The private key is in a format this helper cannot check (not a PKCS#8
    /// ECDSA/RSA key).
    #[error("roxyd private key is not a supported PKCS#8 ECDSA or RSA key")]
    UnsupportedKey,

    /// The leaf certificate does not chain to the root-owned client-identity anchor.
    #[error("roxyd certificate does not chain to the client-identity anchor: {0}")]
    ChainInvalid(String),

    /// The CA bundle is empty — roxyd would have no anchor for verifying the Manager.
    #[error("roxyd CA bundle contains no certificates")]
    EmptyCaBundle,

    /// The client-identity anchor snapshot is not a self-signed CA certificate.
    #[error("client-identity anchor is not a self-signed CA certificate: {0}")]
    BadAnchor(String),

    /// `systemctl reload` of the running roxyd unit failed after a swap.
    #[error("failed to reload roxyd after activation: {0}")]
    Reload(String),

    /// The manifest ships no roxyd, so there is nothing to activate.
    #[error("this product ships no roxyd")]
    NoRoxyd,
}

impl TrustError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        TrustError::Io {
            path: path.to_string_lossy().into_owned(),
            source,
        }
    }
}

/// One decoded PEM block: its label and its DER contents.
struct PemBlock {
    label: String,
    der: Vec<u8>,
}

/// Parses `input` as a sequence of PEM blocks with **nothing but ASCII whitespace**
/// around and between them, rejecting any trailing or interleaved garbage.
///
/// This is stricter than a lenient PEM scanner on purpose: "no trailing garbage" is
/// one of the §8.3 validation conditions, and a validator that silently skips bytes
/// it does not understand cannot enforce it. Base64 excludes `-`, so the `-----END`
/// marker search inside a block is unambiguous.
fn parse_pem_strict(input: &[u8], role: &str) -> Result<Vec<PemBlock>, TrustError> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const DASHES: &[u8] = b"-----";
    let bad = |reason: &str| TrustError::Pem {
        path: role.to_string(),
        reason: reason.to_string(),
    };

    let mut blocks = Vec::new();
    let mut rest = input;
    loop {
        // Only ASCII whitespace may separate/surround blocks.
        let start = rest
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(rest.len());
        rest = &rest[start..];
        if rest.is_empty() {
            break;
        }
        let after_begin = rest
            .strip_prefix(BEGIN)
            .ok_or_else(|| bad("expected a `-----BEGIN` marker"))?;
        let label_end = find(after_begin, DASHES).ok_or_else(|| bad("unterminated BEGIN line"))?;
        let label_bytes = &after_begin[..label_end];
        if label_bytes.is_empty()
            || !label_bytes
                .iter()
                .all(|b| b.is_ascii_uppercase() || *b == b' ')
        {
            return Err(bad("invalid PEM label"));
        }
        let label = String::from_utf8_lossy(label_bytes).into_owned();
        let body_start = &after_begin[label_end + DASHES.len()..];
        let end_marker = [b"-----END ", label_bytes, DASHES].concat();
        let body_end = find(body_start, &end_marker)
            .ok_or_else(|| bad("missing matching `-----END` marker"))?;
        let body = &body_start[..body_end];
        let after = &body_start[body_end + end_marker.len()..];

        let mut cleaned = Vec::with_capacity(body.len());
        cleaned.extend(body.iter().copied().filter(|b| !b.is_ascii_whitespace()));
        let der = base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .map_err(|e| bad(&format!("invalid base64 in a `{label}` block: {e}")))?;
        blocks.push(PemBlock { label, der });
        rest = after;
    }
    if blocks.is_empty() {
        return Err(bad("no PEM blocks found"));
    }
    Ok(blocks)
}

/// Returns the index of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Requires every block in `blocks` to carry `label`, returning their DER bodies.
fn require_all(blocks: &[PemBlock], label: &str, role: &str) -> Result<Vec<Vec<u8>>, TrustError> {
    if let Some(block) = blocks.iter().find(|b| b.label != label) {
        return Err(TrustError::Pem {
            path: role.to_string(),
            reason: format!("unexpected `{}` block (want only `{label}`)", block.label),
        });
    }
    Ok(blocks.iter().map(|b| b.der.clone()).collect())
}

/// The three staged files, already read into memory, that one activation validates.
struct StagedBytes {
    cert: Vec<u8>,
    key: Vec<u8>,
    ca_bundle: Vec<u8>,
}

/// Validates roxyd's staged trust material against the root-owned client-identity
/// anchor, at time `now_unix` (seconds since the Unix epoch), enforcing every §8.3
/// condition:
///
/// - every file is well-formed PEM with no trailing or interleaved garbage;
/// - the certificate and private key correspond;
/// - the certificate is within its validity window;
/// - the certificate permits TLS **client** authentication (clientAuth EKU);
/// - the leaf chains to the client-identity **anchor** (the internal CA root
///   snapshot), *not* to the CA bundle;
/// - the CA bundle parses and is non-empty.
///
/// # Errors
///
/// Returns the first [`TrustError`] a condition trips on.
pub fn validate_material(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_bundle_pem: &[u8],
    anchor_pem: &[u8],
    now_unix: u64,
) -> Result<(), TrustError> {
    // 1. Strict PEM. The cert file is a leaf optionally followed by its chain; the
    //    key is exactly one PKCS#8 block; the CA bundle and anchor are certificates.
    let cert_blocks = parse_pem_strict(cert_pem, "certificate")?;
    let cert_ders = require_all(&cert_blocks, LABEL_CERTIFICATE, "certificate")?;
    let leaf_der = cert_ders.first().cloned().ok_or_else(|| TrustError::Pem {
        path: "certificate".to_string(),
        reason: "no certificate block".to_string(),
    })?;

    let key_blocks = parse_pem_strict(key_pem, "private key")?;
    if key_blocks.len() != 1 || key_blocks[0].label != LABEL_PRIVATE_KEY {
        return Err(TrustError::Pem {
            path: "private key".to_string(),
            reason: format!("expected exactly one `{LABEL_PRIVATE_KEY}` block"),
        });
    }
    let key_der = &key_blocks[0].der;

    let ca_blocks = parse_pem_strict(ca_bundle_pem, "CA bundle")?;
    let ca_ders = require_all(&ca_blocks, LABEL_CERTIFICATE, "CA bundle")?;
    if ca_ders.is_empty() {
        return Err(TrustError::EmptyCaBundle);
    }

    let anchor_blocks = parse_pem_strict(anchor_pem, "anchor")?;
    let anchor_ders = require_all(&anchor_blocks, LABEL_CERTIFICATE, "anchor")?;
    let anchor_der = anchor_ders
        .first()
        .cloned()
        .ok_or_else(|| TrustError::BadAnchor("anchor contains no certificate".to_string()))?;

    // 2. Parse the leaf and check the cheap, message-friendly conditions first.
    let (_, leaf) = X509Certificate::from_der(&leaf_der).map_err(|e| TrustError::Parse {
        what: "roxyd certificate".to_string(),
        reason: e.to_string(),
    })?;
    let now =
        ASN1Time::from_timestamp(i64::try_from(now_unix).unwrap_or(i64::MAX)).map_err(|e| {
            TrustError::Parse {
                what: "current time".to_string(),
                reason: e.to_string(),
            }
        })?;
    if !leaf.validity().is_valid_at(now) {
        return Err(TrustError::Validity {
            not_before: leaf.validity().not_before.to_string(),
            not_after: leaf.validity().not_after.to_string(),
        });
    }
    require_client_auth(&leaf)?;

    // 3. Certificate ↔ key correspondence: derive the key's public key and compare it
    //    to the certificate's SubjectPublicKeyInfo.
    if !key_matches_cert(key_der, &leaf)? {
        return Err(TrustError::KeyMismatch);
    }

    // 4. Chain the leaf to the root-owned anchor. Intermediates come from the cert
    //    file's chain and the staged CA bundle: providing agent-writable intermediates
    //    is safe because the trust anchor is our clean root snapshot, so a forged
    //    intermediate can only fail to build a path, never substitute the root.
    let mut intermediates: Vec<Vec<u8>> = cert_ders[1..].to_vec();
    intermediates.extend(ca_ders.iter().cloned());
    verify_chain(&leaf_der, &intermediates, &anchor_der, now_unix)?;
    Ok(())
}

/// Requires the leaf to permit TLS client authentication. An absent EKU extension is
/// accepted (it permits any usage), matching webpki's own rule; a present EKU must
/// include `clientAuth`.
fn require_client_auth(leaf: &X509Certificate<'_>) -> Result<(), TrustError> {
    for ext in leaf.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            if eku.client_auth || eku.any {
                return Ok(());
            }
            return Err(TrustError::ClientAuthMissing);
        }
    }
    Ok(())
}

/// Returns whether the PKCS#8 private key `key_der` corresponds to the public key in
/// `cert`. ECDSA P-256/P-384 and RSA are supported; the derived public key
/// (uncompressed EC point, or DER `RSAPublicKey`) is compared to the certificate's
/// `SubjectPublicKeyInfo` subject public key, which carries the same encoding.
fn key_matches_cert(key_der: &[u8], cert: &X509Certificate<'_>) -> Result<bool, TrustError> {
    let cert_spki = cert.public_key().subject_public_key.data.as_ref();
    let rng = ring::rand::SystemRandom::new();
    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_der, &rng) {
        return Ok(kp.public_key().as_ref() == cert_spki);
    }
    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, key_der, &rng) {
        return Ok(kp.public_key().as_ref() == cert_spki);
    }
    if let Ok(kp) = RsaKeyPair::from_pkcs8(key_der) {
        return Ok(kp.public_key().as_ref() == cert_spki);
    }
    Err(TrustError::UnsupportedKey)
}

/// Cryptographically verifies that `leaf_der` chains to `anchor_der` for TLS client
/// authentication, using `intermediates` for path building, at `now_unix`.
fn verify_chain(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    anchor_der: &[u8],
    now_unix: u64,
) -> Result<(), TrustError> {
    let anchor_cert = CertificateDer::from(anchor_der);
    let anchor = webpki::anchor_from_trusted_cert(&anchor_cert)
        .map_err(|e| TrustError::ChainInvalid(format!("anchor unusable: {e}")))?;
    let leaf_cert = CertificateDer::from(leaf_der);
    let ee = EndEntityCert::try_from(&leaf_cert)
        .map_err(|e| TrustError::ChainInvalid(format!("leaf unusable: {e}")))?;
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_unix));
    ee.verify_for_usage(
        SUPPORTED_SIG_ALGS,
        &[anchor],
        &inter,
        now,
        KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|e| TrustError::ChainInvalid(e.to_string()))?;
    Ok(())
}

/// Validates the client-identity **anchor** snapshot before it is written: it must be
/// well-formed PEM, parse as a certificate, be self-signed (issuer == subject), carry
/// `cA = true`, and be usable by webpki as a trust anchor. bootler runs this over the
/// bytes it reads from bootroot's internal CA root at install time, so a wrong or
/// truncated snapshot is caught before it can silently break every later activation.
///
/// # Errors
///
/// Returns [`TrustError::BadAnchor`] (or a PEM/parse error) when the bytes are not a
/// self-signed CA certificate.
pub fn validate_anchor(anchor_pem: &[u8]) -> Result<(), TrustError> {
    let blocks = parse_pem_strict(anchor_pem, "anchor")?;
    let ders = require_all(&blocks, LABEL_CERTIFICATE, "anchor")?;
    let der = ders
        .first()
        .ok_or_else(|| TrustError::BadAnchor("no certificate".to_string()))?;
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| TrustError::BadAnchor(format!("not a certificate: {e}")))?;
    if cert.subject().as_raw() != cert.issuer().as_raw() {
        return Err(TrustError::BadAnchor("not self-signed".to_string()));
    }
    let is_ca = cert.extensions().iter().any(
        |ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca),
    );
    if !is_ca {
        return Err(TrustError::BadAnchor("not a CA certificate".to_string()));
    }
    let anchor_cert = CertificateDer::from(der.as_slice());
    webpki::anchor_from_trusted_cert(&anchor_cert)
        .map_err(|e| TrustError::BadAnchor(format!("unusable as a trust anchor: {e}")))?;
    Ok(())
}

/// The filesystem locations one activation reads and writes, resolved from the
/// manifest (or constructed directly by a test). All paths are absolute in
/// production; the module treats `tls_dir` as the root it owns.
#[derive(Debug, Clone)]
pub struct RoxydTrustPaths {
    /// The staged certificate the bootroot agent writes (`agent/roxyd/roxyd-cert.pem`).
    pub staging_cert: PathBuf,
    /// The staged private key (`agent/roxyd/roxyd-key.pem`).
    pub staging_key: PathBuf,
    /// The staged CA bundle (`agent/roxyd/ca-bundle.pem`).
    pub staging_ca: PathBuf,
    /// The root-owned client-identity anchor snapshot (`roxyd-tls/client-anchor.pem`).
    pub anchor: PathBuf,
    /// The root-owned trust tree root (`roxyd-tls/`), holding `active` and `gen-<n>/`.
    pub tls_dir: PathBuf,
    /// The roxyd unit to `systemctl reload` after a swap (`<ns>-roxyd.service`).
    pub reload_unit: String,
}

impl RoxydTrustPaths {
    /// The `active` symlink roxyd reads its material through.
    #[must_use]
    pub fn active_link(&self) -> PathBuf {
        self.tls_dir.join(ROXYD_ACTIVE_LINK)
    }

    /// The generation directory `roxyd-tls/gen-<n>/`.
    #[must_use]
    pub fn generation_dir(&self, generation: u64) -> PathBuf {
        self.tls_dir
            .join(format!("{ROXYD_GENERATION_PREFIX}{generation}"))
    }

    /// The cert/key/CA triple inside `dir` (a generation directory or the `active`
    /// symlink), named to match the staged files.
    fn material_in(&self, dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        (
            dir.join(file_name(&self.staging_cert)),
            dir.join(file_name(&self.staging_key)),
            dir.join(file_name(&self.staging_ca)),
        )
    }
}

/// The result of an activation attempt.
#[derive(Debug, PartialEq, Eq)]
pub struct Activation {
    /// The generation now active (the existing one when nothing changed).
    pub generation: u64,
    /// Whether a new generation was installed, or the staged bytes already matched
    /// `active` (an idempotent no-op).
    pub changed: bool,
}

/// Activates a product's roxyd trust material from a caller-resolved
/// [`RoxydTrustPaths`]: the path-driven activation core, which the installer's
/// manifest-driven entry point (`crate::roxyd::activate_roxyd_trust`, called by
/// the `roxyd-activate` oneshot, RFC 0003 §8.3) drives, and which a test can drive
/// directly against a temporary tree.
///
/// The sequence is: read the staged material and the anchor; if the staged bytes
/// already match `active`, return an idempotent no-op; otherwise copy the staged
/// bytes into a fresh root-only `gen-<n>.tmp`, **validate that copy**, finalise it to
/// `gen-<n>`, atomically repoint `active` at it, reload roxyd if it is running, and
/// prune superseded generations. A failure before the `active` swap leaves the live
/// material untouched.
///
/// # Errors
///
/// Returns [`TrustError`] on any I/O, validation, or reload failure. On error the
/// `active` tree is left exactly as it was (fail-closed).
pub fn activate_with_paths(paths: &RoxydTrustPaths) -> Result<Activation, TrustError> {
    let staged = read_staged(paths)?;
    let anchor = read_file(&paths.anchor)?;

    let active = paths.active_link();
    if let Some(current) = current_generation(paths)?
        && active_matches(paths, &active, &staged)?
    {
        return Ok(Activation {
            generation: current,
            changed: false,
        });
    }

    let generation = next_generation(paths)?;
    let final_dir = paths.generation_dir(generation);
    let tmp_dir = tmp_generation_dir(paths, generation);

    // Fresh, root-only staging copy. Remove any leftover from a prior aborted run.
    remove_dir_all_if_present(&tmp_dir)?;
    make_dir_0700(&tmp_dir)?;
    let (tmp_cert, tmp_key, tmp_ca) = paths.material_in(&tmp_dir);
    write_file_0600(&tmp_cert, &staged.cert)?;
    write_file_0600(&tmp_key, &staged.key)?;
    write_file_0600(&tmp_ca, &staged.ca_bundle)?;

    // Validate the bytes now on disk in the root-owned copy — not the staged files —
    // so what is validated is exactly what is installed.
    let copied = StagedBytes {
        cert: read_file(&tmp_cert)?,
        key: read_file(&tmp_key)?,
        ca_bundle: read_file(&tmp_ca)?,
    };
    if let Err(err) = validate_material(
        &copied.cert,
        &copied.key,
        &copied.ca_bundle,
        &anchor,
        now_unix(),
    ) {
        // Fail closed: discard the rejected copy, leave `active` as it was.
        let _ = remove_dir_all_if_present(&tmp_dir);
        return Err(err);
    }

    // Finalise the generation, then swap `active` onto it atomically.
    rename(&tmp_dir, &final_dir)?;
    swap_active_symlink(paths, &active, generation)?;
    reload_roxyd_if_active(&paths.reload_unit)?;
    prune_generations(paths, generation)?;
    Ok(Activation {
        generation,
        changed: true,
    })
}

/// Reads the three staged files into memory.
fn read_staged(paths: &RoxydTrustPaths) -> Result<StagedBytes, TrustError> {
    Ok(StagedBytes {
        cert: read_file(&paths.staging_cert)?,
        key: read_file(&paths.staging_key)?,
        ca_bundle: read_file(&paths.staging_ca)?,
    })
}

/// Returns whether the material under `active` byte-matches `staged` — the
/// idempotence check that makes repeated `.path` events (and a no-op fast-poll write)
/// cheap and keeps generation numbers from churning.
fn active_matches(
    paths: &RoxydTrustPaths,
    active: &Path,
    staged: &StagedBytes,
) -> Result<bool, TrustError> {
    let (cert, key, ca) = paths.material_in(active);
    for (path, want) in [
        (cert, &staged.cert),
        (key, &staged.key),
        (ca, &staged.ca_bundle),
    ] {
        match std::fs::read(&path) {
            Ok(bytes) if &bytes == want => {}
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(TrustError::io(&path, e)),
        }
    }
    Ok(true)
}

/// Returns the generation `active` currently points at, if any.
fn current_generation(paths: &RoxydTrustPaths) -> Result<Option<u64>, TrustError> {
    let active = paths.active_link();
    match std::fs::read_link(&active) {
        Ok(target) => Ok(parse_generation(&target)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TrustError::io(&active, e)),
    }
}

/// Returns one greater than the highest existing generation number, or 1 when none
/// exist. Numbering only ever increases, so a just-superseded generation's directory
/// is never reused while it might still be resolved through an in-flight read.
fn next_generation(paths: &RoxydTrustPaths) -> Result<u64, TrustError> {
    let mut max = 0;
    for entry in read_dir(&paths.tls_dir)? {
        let entry = entry.map_err(|e| TrustError::io(&paths.tls_dir, e))?;
        if let Some(n) = parse_generation(&PathBuf::from(entry.file_name())) {
            max = max.max(n);
        }
    }
    Ok(max + 1)
}

/// Removes every generation directory other than `keep`, plus any leftover
/// `gen-<n>.tmp`.
fn prune_generations(paths: &RoxydTrustPaths, keep: u64) -> Result<(), TrustError> {
    for entry in read_dir(&paths.tls_dir)? {
        let entry = entry.map_err(|e| TrustError::io(&paths.tls_dir, e))?;
        let name = PathBuf::from(entry.file_name());
        let is_stale_tmp = name.to_string_lossy().starts_with(ROXYD_GENERATION_PREFIX)
            && name.extension().is_some_and(|ext| ext == "tmp");
        let is_old_gen = parse_generation(&name).is_some_and(|n| n != keep);
        if is_stale_tmp || is_old_gen {
            remove_dir_all_if_present(&paths.tls_dir.join(name))?;
        }
    }
    Ok(())
}

/// Parses a `gen-<n>` directory name into its generation number, ignoring `active`,
/// `client-anchor.pem`, and `gen-<n>.tmp`.
fn parse_generation(name: &Path) -> Option<u64> {
    let name = name.file_name()?.to_str()?;
    let digits = name.strip_prefix(ROXYD_GENERATION_PREFIX)?;
    digits.parse::<u64>().ok()
}

/// The temporary directory a generation is assembled and validated in before it is
/// finalised (`gen-<n>.tmp`).
fn tmp_generation_dir(paths: &RoxydTrustPaths, generation: u64) -> PathBuf {
    paths
        .tls_dir
        .join(format!("{ROXYD_GENERATION_PREFIX}{generation}.tmp"))
}

/// Atomically repoints `active` at `gen-<generation>` by creating a temporary symlink
/// and renaming it over the existing one (rename replaces a symlink without following
/// it, so roxyd never observes a missing or half-written `active`).
fn swap_active_symlink(
    paths: &RoxydTrustPaths,
    active: &Path,
    generation: u64,
) -> Result<(), TrustError> {
    let target = format!("{ROXYD_GENERATION_PREFIX}{generation}");
    let tmp_link = paths.tls_dir.join(format!("{ROXYD_ACTIVE_LINK}.tmp"));
    // Remove a leftover temp link from a prior aborted swap, then create ours.
    match std::fs::remove_file(&tmp_link) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(TrustError::io(&tmp_link, e)),
    }
    std::os::unix::fs::symlink(&target, &tmp_link).map_err(|e| TrustError::io(&tmp_link, e))?;
    rename(&tmp_link, active)
}

/// Reloads roxyd only when it is running, so a first-install seed (roxyd not yet
/// started) and a test host (no such unit) skip cleanly, while a live rotation
/// reloads. A reload that is attempted and fails is a hard error.
fn reload_roxyd_if_active(unit: &str) -> Result<(), TrustError> {
    let active = Command::new(SYSTEMCTL)
        .args(["is-active", "--quiet", unit])
        .status();
    match active {
        Ok(status) if status.success() => {
            let reload = Command::new(SYSTEMCTL)
                .args(["reload", unit])
                .status()
                .map_err(|e| TrustError::Reload(e.to_string()))?;
            if !reload.success() {
                return Err(TrustError::Reload(format!(
                    "`systemctl reload {unit}` exited with {reload}"
                )));
            }
            Ok(())
        }
        // Not active, or systemctl unavailable (seed time / test): nothing to reload.
        _ => Ok(()),
    }
}

/// The `systemctl` binary the reload step invokes.
const SYSTEMCTL: &str = "systemctl";

/// Returns the current time in seconds since the Unix epoch, saturating at 0 for a
/// clock set before the epoch.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// --- small filesystem helpers that annotate their path on error ---

fn read_file(path: &Path) -> Result<Vec<u8>, TrustError> {
    std::fs::read(path).map_err(|e| TrustError::io(path, e))
}

/// Writes `bytes` to a new file that is `0600` from the moment it exists.
///
/// The mode is asked for at creation rather than applied afterwards. Creating
/// first and tightening second leaves the contents readable by anyone on the
/// host for as long as the two calls take, and what goes through here is a
/// certificate, a CA bundle, and a private key. `create_new` also makes a
/// pre-existing path an error rather than a silent overwrite, which is what
/// staged trust material wants.
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| TrustError::io(path, e))?;
    file.write_all(bytes).map_err(|e| TrustError::io(path, e))
}

/// Creates `path` as a directory that is `0700` from the moment it exists.
///
/// Same reasoning as [`write_file_0600`]: a directory created with the umask's
/// mode and narrowed afterwards is traversable in between.
fn make_dir_0700(path: &Path) -> Result<(), TrustError> {
    use std::os::unix::fs::DirBuilderExt as _;

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| TrustError::io(path, e))
}

fn rename(from: &Path, to: &Path) -> Result<(), TrustError> {
    std::fs::rename(from, to).map_err(|e| TrustError::io(to, e))
}

fn read_dir(path: &Path) -> Result<std::fs::ReadDir, TrustError> {
    std::fs::read_dir(path).map_err(|e| TrustError::io(path, e))
}

fn remove_dir_all_if_present(path: &Path) -> Result<(), TrustError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TrustError::io(path, e)),
    }
}

fn file_name(path: &Path) -> std::ffi::OsString {
    path.file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use tempfile::TempDir;
    use time::OffsetDateTime;

    use super::{
        Activation, RoxydTrustPaths, TrustError, activate_with_paths, make_dir_0700,
        parse_generation, parse_pem_strict, validate_anchor, validate_material, write_file_0600,
    };

    /// A fixed "now" all validity-sensitive tests share (2023-06-15T00:00:00Z), so a
    /// generated cert's default 1-year-ish window straddles it deterministically.
    const NOW: u64 = 1_686_787_200;

    /// [`NOW`] as the signed timestamp `OffsetDateTime` takes. `u64` to `i64`
    /// is not a lossless conversion in general, so it is checked; here it
    /// cannot fail, because `NOW` is a literal far below `i64::MAX`.
    fn now_offset() -> OffsetDateTime {
        let seconds = i64::try_from(NOW).expect("NOW is a literal below i64::MAX");
        OffsetDateTime::from_unix_timestamp(seconds).expect("NOW is a valid timestamp")
    }

    /// A CA usable as a signing issuer, holding its own PEM. The `Issuer` owns its
    /// key so it can sign many leaves without re-consuming a `KeyPair`.
    struct Ca {
        issuer: Issuer<'static, KeyPair>,
        pem: String,
    }

    fn self_signed_ca(cn: &str) -> Ca {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed ca");
        let pem = cert.pem();
        Ca {
            issuer: Issuer::new(params, key),
            pem,
        }
    }

    /// An intermediate CA signed by `parent`, holding its own PEM and issuer.
    fn intermediate_ca(parent: &Ca, cn: &str) -> Ca {
        let key = KeyPair::generate().expect("int key");
        let mut params = CertificateParams::new(Vec::new()).expect("int params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let cert = params
            .signed_by(&key, &parent.issuer)
            .expect("signed intermediate");
        let pem = cert.pem();
        Ca {
            issuer: Issuer::new(params, key),
            pem,
        }
    }

    /// A leaf certificate signed by `issuer_ca`, with the given EKUs and validity.
    fn leaf(
        issuer_ca: &Ca,
        client_auth: bool,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (String, String) {
        leaf_with_eku(
            issuer_ca,
            if client_auth {
                vec![ExtendedKeyUsagePurpose::ClientAuth]
            } else {
                Vec::new()
            },
            not_before,
            not_after,
        )
    }

    fn leaf_with_eku(
        issuer_ca: &Ca,
        ekus: Vec<ExtendedKeyUsagePurpose>,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (String, String) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec!["roxyd.example".to_string()]).expect("params");
        params.distinguished_name.push(DnType::CommonName, "roxyd");
        params.is_ca = IsCa::NoCa;
        params.not_before = not_before;
        params.not_after = not_after;
        params.extended_key_usages = ekus;
        let cert = params
            .signed_by(&key, &issuer_ca.issuer)
            .expect("signed leaf");
        (cert.pem(), key.serialize_pem())
    }

    fn window() -> (OffsetDateTime, OffsetDateTime) {
        let now = now_offset();
        (
            now - time::Duration::days(1),
            now + time::Duration::days(30),
        )
    }

    #[test]
    fn parse_pem_strict_accepts_clean_blocks_and_rejects_garbage() {
        let ca = self_signed_ca("root");
        let blocks = parse_pem_strict(ca.pem.as_bytes(), "anchor").expect("clean pem");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");

        // Trailing garbage after the block is rejected.
        let mut trailing = ca.pem.clone().into_bytes();
        trailing.extend_from_slice(b"\nnot pem at all\n");
        assert!(matches!(
            parse_pem_strict(&trailing, "anchor"),
            Err(TrustError::Pem { .. })
        ));

        // Garbage between two blocks is rejected.
        let interleaved = format!("{}\nGARBAGE\n{}", ca.pem, ca.pem);
        assert!(matches!(
            parse_pem_strict(interleaved.as_bytes(), "anchor"),
            Err(TrustError::Pem { .. })
        ));

        // Empty input is rejected.
        assert!(matches!(
            parse_pem_strict(b"   \n  ", "anchor"),
            Err(TrustError::Pem { .. })
        ));
    }

    #[test]
    fn validate_material_accepts_a_faithful_leaf_chaining_to_the_anchor() {
        let root = self_signed_ca("root");
        let (not_before, not_after) = window();
        let (cert, key) = leaf(&root, true, not_before, not_after);
        // Direct leaf→root: the bundle and anchor are both the root.
        validate_material(
            cert.as_bytes(),
            key.as_bytes(),
            root.pem.as_bytes(),
            root.pem.as_bytes(),
            NOW,
        )
        .expect("faithful material validates");
    }

    #[test]
    fn validate_material_accepts_a_leaf_through_an_intermediate() {
        // root → intermediate → leaf, anchored at the root, bundle = root+intermediate
        // (root-first, as bootroot writes it).
        let root = self_signed_ca("root");
        let intermediate = intermediate_ca(&root, "intermediate");
        let (not_before, not_after) = window();
        let (cert, key) = leaf(&intermediate, true, not_before, not_after);
        let bundle = format!("{}{}", root.pem, intermediate.pem);
        validate_material(
            cert.as_bytes(),
            key.as_bytes(),
            bundle.as_bytes(),
            root.pem.as_bytes(),
            NOW,
        )
        .expect("leaf via intermediate validates");
    }

    #[test]
    fn validate_material_rejects_a_mismatched_key() {
        let root = self_signed_ca("root");
        let (not_before, not_after) = window();
        let (cert, _key) = leaf(&root, true, not_before, not_after);
        // A key from an unrelated leaf does not correspond to `cert`.
        let (_other_cert, other_key) = leaf(&root, true, not_before, not_after);
        assert!(matches!(
            validate_material(
                cert.as_bytes(),
                other_key.as_bytes(),
                root.pem.as_bytes(),
                root.pem.as_bytes(),
                NOW
            ),
            Err(TrustError::KeyMismatch)
        ));
    }

    #[test]
    fn validate_material_rejects_an_expired_leaf() {
        let root = self_signed_ca("root");
        let now = now_offset();
        let (cert, key) = leaf(
            &root,
            true,
            now - time::Duration::days(30),
            now - time::Duration::days(1),
        );
        assert!(matches!(
            validate_material(
                cert.as_bytes(),
                key.as_bytes(),
                root.pem.as_bytes(),
                root.pem.as_bytes(),
                NOW
            ),
            Err(TrustError::Validity { .. })
        ));
    }

    #[test]
    fn validate_material_rejects_a_leaf_without_client_auth() {
        let root = self_signed_ca("root");
        let (not_before, not_after) = window();
        let (cert, key) = leaf(&root, false, not_before, not_after);
        // A serverAuth-only EKU is present but does not permit client auth → rejected.
        let (server_pem, server_key) = leaf_with_eku(
            &root,
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            not_before,
            not_after,
        );
        assert!(matches!(
            validate_material(
                server_pem.as_bytes(),
                server_key.as_bytes(),
                root.pem.as_bytes(),
                root.pem.as_bytes(),
                NOW
            ),
            Err(TrustError::ClientAuthMissing)
        ));
        // The no-EKU leaf, by contrast, is accepted (webpki's own rule).
        validate_material(
            cert.as_bytes(),
            key.as_bytes(),
            root.pem.as_bytes(),
            root.pem.as_bytes(),
            NOW,
        )
        .expect("absent EKU is permitted");
    }

    #[test]
    fn validate_material_rejects_a_leaf_not_chaining_to_the_anchor() {
        let real_root = self_signed_ca("root");
        let foreign_root = self_signed_ca("foreign");
        let (not_before, not_after) = window();
        // Leaf issued by the foreign root does not chain to the real anchor.
        let (cert, key) = leaf(&foreign_root, true, not_before, not_after);
        assert!(matches!(
            validate_material(
                cert.as_bytes(),
                key.as_bytes(),
                foreign_root.pem.as_bytes(),
                real_root.pem.as_bytes(),
                NOW
            ),
            Err(TrustError::ChainInvalid(_))
        ));
    }

    #[test]
    fn validate_anchor_accepts_a_self_signed_ca_and_rejects_a_leaf() {
        let root = self_signed_ca("root");
        validate_anchor(root.pem.as_bytes()).expect("self-signed CA is a valid anchor");

        let (not_before, not_after) = window();
        let (leaf_pem, _key) = leaf(&root, true, not_before, not_after);
        assert!(matches!(
            validate_anchor(leaf_pem.as_bytes()),
            Err(TrustError::BadAnchor(_))
        ));
    }

    #[test]
    fn parse_generation_reads_only_gen_dirs() {
        assert_eq!(parse_generation(Path::new("gen-7")), Some(7));
        assert_eq!(parse_generation(Path::new("/x/roxyd-tls/gen-12")), Some(12));
        assert_eq!(parse_generation(Path::new("active")), None);
        assert_eq!(parse_generation(Path::new("gen-3.tmp")), None);
        assert_eq!(parse_generation(Path::new("client-anchor.pem")), None);
    }

    // --- activation integration over a temporary tree ---

    struct Fixture {
        _tmp: TempDir,
        paths: RoxydTrustPaths,
        staging_dir: PathBuf,
        root: Ca,
    }

    fn fixture() -> Fixture {
        let tmp = TempDir::new().expect("tempdir");
        let base = tmp.path();
        let staging_dir = base.join("agent/roxyd");
        let tls_dir = base.join("roxyd-tls");
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::create_dir_all(&tls_dir).unwrap();
        let paths = RoxydTrustPaths {
            staging_cert: staging_dir.join("roxyd-cert.pem"),
            staging_key: staging_dir.join("roxyd-key.pem"),
            staging_ca: staging_dir.join("ca-bundle.pem"),
            anchor: tls_dir.join("client-anchor.pem"),
            tls_dir,
            // A unit that does not exist, so `is-active` fails and the reload is skipped.
            reload_unit: "bootler-test-nonexistent-roxyd.service".to_string(),
        };
        let root = self_signed_ca("root");
        std::fs::write(&paths.anchor, root.pem.as_bytes()).unwrap();
        Fixture {
            _tmp: tmp,
            paths,
            staging_dir,
            root,
        }
    }

    fn stage_valid(fx: &Fixture) {
        let (not_before, not_after) = window_now();
        let (cert, key) = leaf(&fx.root, true, not_before, not_after);
        std::fs::write(&fx.paths.staging_cert, cert.as_bytes()).unwrap();
        std::fs::write(&fx.paths.staging_key, key.as_bytes()).unwrap();
        std::fs::write(&fx.paths.staging_ca, fx.root.pem.as_bytes()).unwrap();
    }

    // Activation validates against the real wall clock, so stage a window around now.
    fn window_now() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (
            now - time::Duration::days(1),
            now + time::Duration::days(30),
        )
    }

    fn active_target(fx: &Fixture) -> String {
        std::fs::read_link(fx.paths.active_link())
            .expect("active symlink")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn activation_seeds_active_then_is_idempotent() {
        let fx = fixture();
        stage_valid(&fx);

        let first = activate_with_paths(&fx.paths).expect("seed");
        assert_eq!(
            first,
            Activation {
                generation: 1,
                changed: true
            }
        );
        assert_eq!(active_target(&fx), "gen-1");
        // roxyd reads active/roxyd-cert.pem through the symlink.
        assert!(fx.paths.active_link().join("roxyd-cert.pem").exists());

        // Re-running with identical staging is a no-op: no new generation.
        let second = activate_with_paths(&fx.paths).expect("idempotent");
        assert_eq!(
            second,
            Activation {
                generation: 1,
                changed: false
            }
        );
        assert_eq!(active_target(&fx), "gen-1");
        assert!(!fx.paths.generation_dir(2).exists());
    }

    #[test]
    fn activation_rotates_and_prunes_the_superseded_generation() {
        let fx = fixture();
        stage_valid(&fx);
        activate_with_paths(&fx.paths).expect("seed gen-1");

        // A trust change (new staged material) installs gen-2 and prunes gen-1.
        stage_valid(&fx);
        let rotated = activate_with_paths(&fx.paths).expect("rotate");
        assert_eq!(
            rotated,
            Activation {
                generation: 2,
                changed: true
            }
        );
        assert_eq!(active_target(&fx), "gen-2");
        assert!(!fx.paths.generation_dir(1).exists(), "gen-1 pruned");
    }

    /// The mode has to arrive with the file, not after it. A regression to
    /// create-then-chmod cannot be observed from a single thread -- the window
    /// closes before any assertion could run -- so what is pinned here is the
    /// `create_new` behaviour that came with the fix, plus the resulting mode.
    #[test]
    fn trust_material_is_written_private_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("tempdir");
        let nested = dir.path().join("gen");
        make_dir_0700(&nested).expect("mkdir");
        assert_eq!(
            std::fs::metadata(&nested)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o700,
        );
        assert!(
            make_dir_0700(&nested).is_err(),
            "an existing directory is an error, not a silent reuse",
        );

        let key = nested.join("key.pem");
        write_file_0600(&key, b"secret").expect("write");
        assert_eq!(
            std::fs::metadata(&key).expect("stat").permissions().mode() & 0o777,
            0o600,
        );
        assert_eq!(std::fs::read(&key).expect("read"), b"secret");
        assert!(
            write_file_0600(&key, b"other").is_err(),
            "an existing path is an error, not a silent overwrite",
        );
        assert_eq!(
            std::fs::read(&key).expect("read"),
            b"secret",
            "the rejected write left the original alone",
        );
    }

    #[test]
    fn activation_fails_closed_on_invalid_staging() {
        let fx = fixture();
        stage_valid(&fx);
        activate_with_paths(&fx.paths).expect("seed gen-1");

        // Stage material signed by a foreign root: it must not chain to the anchor.
        let foreign = self_signed_ca("foreign");
        let (not_before, not_after) = window_now();
        let (cert, key) = leaf(&foreign, true, not_before, not_after);
        std::fs::write(&fx.paths.staging_cert, cert.as_bytes()).unwrap();
        std::fs::write(&fx.paths.staging_key, key.as_bytes()).unwrap();
        std::fs::write(&fx.paths.staging_ca, foreign.pem.as_bytes()).unwrap();

        let err = activate_with_paths(&fx.paths).expect_err("must reject");
        assert!(matches!(err, TrustError::ChainInvalid(_)));
        // active still points at the last good generation, and no tmp was left behind.
        assert_eq!(active_target(&fx), "gen-1");
        assert!(!fx.paths.tls_dir.join("gen-2.tmp").exists());
        assert!(fx.staging_dir.exists());
    }
}
