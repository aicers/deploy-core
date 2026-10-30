//! Test-only fixtures that mint a signed single-member trust-generation
//! container.
//!
//! A generation is delivered as a signed `.pkg` whose archive block holds
//! [`TRUST_SET_MEMBER`] alone, under a manifest carrying exactly one artifact
//! entry. More than one test module needs to mint one — [`crate::trust_set`]'s,
//! which reads the document out of it, and [`crate::release_trust`]'s, whose
//! validator re-verifies a real container off disk — so the minting lives here
//! rather than inside one `mod tests`, and there is exactly one copy of it for
//! the install-time admission paths a later issue adds to reuse.
//!
//! Nothing here is compiled into a release build: the module is `#[cfg(test)]`
//! at its declaration, and minting a generation for real is release tooling in
//! another repository.
//!
//! No key material is committed to the repository and none is read from a fixed
//! path: every fixture Ed25519 key pair is minted afresh from the system RNG,
//! and the ML-DSA-87 pair beside it is derived from its private key (see
//! [`ml_dsa_companion_of`]).
//!
//! A container is format 3 and dual-signed: the Ed25519 pair a fixture is
//! given signs it, and so does that pair's ML-DSA-87 companion, whose anchor
//! the default document lists beside the Ed25519 one.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, ML_DSA_87_SIGNING, PqdsaKeyPair};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};
use zstd::Encoder;

use crate::manifest::{
    ArchiveMember, ArtifactKind, Disposition, MIN_MANIFEST_FORMAT_VERSION, PayloadArtifact,
    PayloadManifest, TargetArch,
};
use crate::payload::{DetachedSignature, FORMAT_VERSION, MAGIC, ML_DSA_87_SIGNATURE_LEN, Signed};
use crate::trust_set::{
    ANCHORS_FIELD, EPOCH_FIELD, TRUST_SET_MEMBER, TRUST_SET_VERSION, TRUST_SET_VERSION_FIELD,
    WITHDRAWN_BUILDS_FIELD, member_digest,
};
use crate::verify::{
    ML_DSA_87_PUBLIC_KEY_LEN, SignatureAlgorithm, TRUST_TARGET, TrustAnchor, key_id,
};

/// Epoch every well-formed fixture generation carries unless a test names its
/// own.
pub(crate) const EPOCH: u64 = 7;

/// zstd level the fixture archive writer uses; it only has to round-trip.
const FIXTURE_ZSTD_LEVEL: i32 = 3;

/// What an Ed25519 fixture pair signs to derive its ML-DSA-87 companion's
/// seed.
const COMPANION_SEED_LABEL: &[u8] = b"deploy-core test fixture: ML-DSA-87 companion seed";

/// Mints an ephemeral Ed25519 key pair.
pub(crate) fn keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation should succeed");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a freshly minted key pair parses")
}

/// Returns a key pair's raw 32-byte public key.
pub(crate) fn public_key_of(pair: &Ed25519KeyPair) -> [u8; 32] {
    pair.public_key()
        .as_ref()
        .try_into()
        .expect("an ed25519 public key is 32 bytes")
}

/// Mints an ephemeral ML-DSA-87 key pair, unrelated to any Ed25519 pair.
pub(crate) fn ml_dsa_keypair() -> PqdsaKeyPair {
    PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).expect("key generation should succeed")
}

/// Returns the ML-DSA-87 key pair that accompanies the Ed25519 `pair` in every
/// fixture: the second signer of each container `pair` signs, and the
/// ML-DSA-87 anchor of [`default_document`].
///
/// Its seed is the SHA-256 of `pair`'s signature over a fixed label. Ed25519
/// signing is deterministic, so the same pair always yields the same companion
/// — a test holding `pair` holds both keys, with no second value to thread
/// through — and nobody without `pair`'s private key can derive it.
pub(crate) fn ml_dsa_companion_of(pair: &Ed25519KeyPair) -> PqdsaKeyPair {
    let seed = Sha256::digest(pair.sign(COMPANION_SEED_LABEL).as_ref());
    PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &seed).expect("a 32-byte seed is an ML-DSA-87 seed")
}

/// Signs `message` with pure ML-DSA-87 under `pair`.
pub(crate) fn ml_dsa_sign(pair: &PqdsaKeyPair, message: &[u8]) -> Vec<u8> {
    let mut signature = vec![0; ML_DSA_87_SIGNATURE_LEN];
    let written = pair
        .sign(message, &mut signature)
        .expect("signing into a buffer of the signature length succeeds");
    signature.truncate(written);
    signature
}

/// Returns both signatures over `message` — `pair`'s Ed25519 one and its
/// [companion](ml_dsa_companion_of)'s ML-DSA-87 one — with their `key_id`s,
/// as a signer holding both keys returns them.
pub(crate) fn signed_by(pair: &Ed25519KeyPair, message: &[u8]) -> Signed {
    let companion = ml_dsa_companion_of(pair);
    Signed {
        ed25519: DetachedSignature {
            signature: pair.sign(message).as_ref().to_vec(),
            key_id: key_id(&public_key_of(pair)),
        },
        ml_dsa_87: DetachedSignature {
            signature: ml_dsa_sign(&companion, message),
            key_id: key_id(&ml_dsa_public_key_of(&companion)),
        },
    }
}

/// Returns the two live anchors a package `pair` signs verifies under:
/// `pair`'s Ed25519 key, then its companion's ML-DSA-87 key.
pub(crate) fn anchors_of(pair: &Ed25519KeyPair) -> Vec<TrustAnchor> {
    vec![
        TrustAnchor::new(public_key_of(pair), false),
        TrustAnchor::new_ml_dsa_87(&ml_dsa_public_key_of(&ml_dsa_companion_of(pair)), false),
    ]
}

/// Returns an ML-DSA-87 key pair's raw public key.
pub(crate) fn ml_dsa_public_key_of(pair: &PqdsaKeyPair) -> [u8; ML_DSA_87_PUBLIC_KEY_LEN] {
    pair.public_key()
        .as_ref()
        .try_into()
        .expect("an ML-DSA-87 public key is 2,592 bytes")
}

/// Returns how a document spells `algorithm`.
pub(crate) fn algorithm_name(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::MlDsa87 => "ml-dsa-87",
    }
}

/// Renders bytes as the lowercase hex a document writes them as.
pub(crate) fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("a fixture is far smaller than u64::MAX")
}

/// Renders a JSON array out of already-rendered members.
pub(crate) fn array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

/// Renders one anchor entry verbatim, so a fixture can state a `key_id` or a
/// `public_key` no derivation would produce.
pub(crate) fn anchor_json(
    algorithm: SignatureAlgorithm,
    key_id: &str,
    public_key: &str,
    revoked: bool,
) -> String {
    let algorithm = algorithm_name(algorithm);
    format!(
        r#"{{"algorithm":"{algorithm}","key_id":"{key_id}","public_key":"{public_key}","revoked":{revoked}}}"#
    )
}

/// The Ed25519 anchor entry `pair` really writes: its `key_id` derived from
/// its own `public_key`.
pub(crate) fn anchor_of(pair: &Ed25519KeyPair, revoked: bool) -> String {
    let public_key = public_key_of(pair);
    anchor_json(
        SignatureAlgorithm::Ed25519,
        &key_id(&public_key),
        &hex_of(&public_key),
        revoked,
    )
}

/// The anchor entry `pair` would have written in a version 1 document: the
/// same entry with no `algorithm`, which no reader of this build accepts.
pub(crate) fn version_1_anchor_of(pair: &Ed25519KeyPair, revoked: bool) -> String {
    let public_key = public_key_of(pair);
    format!(
        r#"{{"key_id":"{}","public_key":"{}","revoked":{revoked}}}"#,
        key_id(&public_key),
        hex_of(&public_key)
    )
}

/// The ML-DSA-87 anchor entry `pair` really writes, on the terms of
/// [`anchor_of`].
pub(crate) fn ml_dsa_anchor_of(pair: &PqdsaKeyPair, revoked: bool) -> String {
    let public_key = ml_dsa_public_key_of(pair);
    anchor_json(
        SignatureAlgorithm::MlDsa87,
        &key_id(&public_key),
        &hex_of(&public_key),
        revoked,
    )
}

/// A live ML-DSA-87 anchor entry over a freshly minted key, for a document
/// whose ML-DSA-87 half nothing else looks at. A container whose ML-DSA-87
/// signature has to verify needs [`companion_anchor_of`] instead.
pub(crate) fn live_ml_dsa_anchor() -> String {
    ml_dsa_anchor_of(&ml_dsa_keypair(), false)
}

/// The ML-DSA-87 anchor entry of `pair`'s [companion](ml_dsa_companion_of):
/// the anchor the ML-DSA-87 signature of a container `pair` signs verifies
/// under.
pub(crate) fn companion_anchor_of(pair: &Ed25519KeyPair, revoked: bool) -> String {
    ml_dsa_anchor_of(&ml_dsa_companion_of(pair), revoked)
}

/// Renders one withdrawn-build entry verbatim.
pub(crate) fn withdrawn_json(package_id: &str, version: &str, commit: &str) -> String {
    format!(r#"{{"package_id":"{package_id}","version":"{version}","commit":"{commit}"}}"#)
}

/// The five top-level members of a document, each as the JSON text it is
/// written as.
///
/// `None` omits a member outright and `extra` is appended verbatim, so one
/// builder covers an absent field, an ill-typed one, an unknown one and the same
/// one written twice — shapes the typed document could not hold.
pub(crate) struct Fields {
    pub(crate) trust_set_version: Option<String>,
    pub(crate) epoch: Option<String>,
    pub(crate) min_manifest_format_version: Option<String>,
    pub(crate) anchors: Option<String>,
    pub(crate) withdrawn_builds: Option<String>,
    pub(crate) extra: Vec<String>,
}

impl Fields {
    /// A well-formed generation trusting `pair` as its one Ed25519 anchor and
    /// `pair`'s [companion](ml_dsa_companion_of) as its one ML-DSA-87 anchor,
    /// so a container `pair` signs verifies under it.
    pub(crate) fn new(pair: &Ed25519KeyPair) -> Self {
        Self {
            trust_set_version: Some(TRUST_SET_VERSION.to_string()),
            epoch: Some(EPOCH.to_string()),
            min_manifest_format_version: Some(MIN_MANIFEST_FORMAT_VERSION.to_string()),
            anchors: Some(array(&[
                anchor_of(pair, false),
                companion_anchor_of(pair, false),
            ])),
            withdrawn_builds: Some(array(&[])),
            extra: Vec::new(),
        }
    }

    /// A generation carrying exactly `anchors`, and otherwise well-formed.
    pub(crate) fn anchored(anchors: &[String]) -> Self {
        let pair = keypair();
        Self {
            anchors: Some(array(anchors)),
            ..Self::new(&pair)
        }
    }

    /// A generation carrying `ed25519` — the Ed25519 half under test — and,
    /// after them, one live ML-DSA-87 anchor over a freshly minted key, so the
    /// document's ML-DSA-87 half is well-formed.
    pub(crate) fn with_ed25519_anchors(ed25519: &[String]) -> Self {
        let mut anchors = ed25519.to_vec();
        anchors.push(live_ml_dsa_anchor());
        Self::anchored(&anchors)
    }

    pub(crate) fn render(&self) -> Vec<u8> {
        let mut members: Vec<String> = Vec::new();
        for (name, value) in [
            (TRUST_SET_VERSION_FIELD, &self.trust_set_version),
            (EPOCH_FIELD, &self.epoch),
            (
                "min_manifest_format_version",
                &self.min_manifest_format_version,
            ),
            (ANCHORS_FIELD, &self.anchors),
            (WITHDRAWN_BUILDS_FIELD, &self.withdrawn_builds),
        ] {
            if let Some(value) = value {
                members.push(format!(r#""{name}":{value}"#));
            }
        }
        members.extend(self.extra.iter().cloned());
        format!("{{{}}}", members.join(",")).into_bytes()
    }
}

/// The document a well-formed fixture carries: one live Ed25519 anchor, `pair`,
/// one live ML-DSA-87 anchor, `pair`'s companion, nothing withdrawn.
pub(crate) fn default_document(pair: &Ed25519KeyPair) -> Vec<u8> {
    Fields::new(pair).render()
}

/// Builds the archive block: one zstd-compressed tar holding the document as its
/// only member, under `member_name` — [`TRUST_SET_MEMBER`] for a container built
/// to the envelope contract, anything else for a fixture that deliberately is
/// not.
fn archive_of(member_name: &str, member: &[u8]) -> Vec<u8> {
    let encoder = Encoder::new(Vec::new(), FIXTURE_ZSTD_LEVEL).expect("encoder should be created");
    let mut builder = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header
        .set_path(member_name)
        .expect("a fixture path fits the field");
    header.set_size(len_u64(member));
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, member)
        .expect("append should succeed");
    let encoder = builder.into_inner().expect("archive should finish");
    encoder.finish().expect("compression should finish")
}

/// Renders the manifest block of a generation container: one artifact entry,
/// `StaticAssets`, binding the one member under `member_name`.
fn manifest_json(
    member_name: &str,
    component: &str,
    version: &str,
    commit: &str,
    member: &[u8],
) -> Vec<u8> {
    let manifest = PayloadManifest::new(
        None,
        vec![ArchiveMember {
            name: member_name.to_string(),
            length: len_u64(member),
        }],
        vec![PayloadArtifact {
            component: component.to_string(),
            version: version.to_string(),
            commit: Some(commit.to_string()),
            target_arch: TargetArch::X86_64,
            kind: ArtifactKind::StaticAssets,
            dispositions: [Disposition::Install].into_iter().collect(),
            archive_path: member_name.to_string(),
            // The same digest the entry's `commit` is, over the same bytes: the
            // container layer checks this one on extraction.
            sha256: member_digest(member),
            spec: None,
            image: None,
        }],
    )
    .expect("the envelope contract builds a manifest");
    serde_json::to_vec(&manifest).expect("a manifest serializes")
}

/// Encodes a current-version footer by hand: magic, the version byte, then the
/// six offset/length pairs it records.
fn footer_bytes(fields: [u64; 12]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    for field in fields {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out
}

/// Which signatures a fixture container carries.
#[derive(Clone, Copy)]
enum Signers {
    /// Both: the Ed25519 pair's and its companion's.
    Both,
    /// The Ed25519 pair's alone, with both ML-DSA-87 pairs absent.
    Ed25519Only,
}

/// Assembles a signed format-3 `.pkg`: the manifest at offset `0`, the
/// archive, then for each signature carried its bytes over the manifest's raw
/// bytes and its signer's `key_id` hint — Ed25519 first — then the footer.
fn signed_pkg(pair: &Ed25519KeyPair, manifest: &[u8], archive: &[u8], signers: Signers) -> Vec<u8> {
    let Signed { ed25519, ml_dsa_87 } = signed_by(pair, manifest);
    let mut envelope = vec![ed25519];
    if let Signers::Both = signers {
        envelope.push(ml_dsa_87);
    }

    let mut out = Vec::new();
    out.extend_from_slice(manifest);
    out.extend_from_slice(archive);
    let mut fields = [0u64; 12];
    fields[..4].copy_from_slice(&[0, len_u64(manifest), len_u64(manifest), len_u64(archive)]);
    for (index, detached) in envelope.iter().enumerate() {
        let at = 4 + 4 * index;
        fields[at] = len_u64(&out);
        fields[at + 1] = len_u64(&detached.signature);
        out.extend_from_slice(&detached.signature);
        fields[at + 2] = len_u64(&out);
        fields[at + 3] = len_u64(detached.key_id.as_bytes());
        out.extend_from_slice(detached.key_id.as_bytes());
    }
    out.extend_from_slice(&footer_bytes(fields));
    out
}

/// The one assembler every container fixture goes through: `member` under
/// `member_name`, bound by a manifest naming `component`, `version` and
/// `commit`, signed by `pair`.
fn pkg_carrying(
    pair: &Ed25519KeyPair,
    member_name: &str,
    member: &[u8],
    component: &str,
    version: &str,
    commit: &str,
    signers: Signers,
) -> Vec<u8> {
    signed_pkg(
        pair,
        &manifest_json(member_name, component, version, commit, member),
        &archive_of(member_name, member),
        signers,
    )
}

/// A generation container whose manifest names `component`, `version` and
/// `commit`, carrying `member` as the archive's only member.
pub(crate) fn pkg_naming(
    pair: &Ed25519KeyPair,
    member: &[u8],
    component: &str,
    version: &str,
    commit: &str,
) -> Vec<u8> {
    pkg_carrying(
        pair,
        TRUST_SET_MEMBER,
        member,
        component,
        version,
        commit,
        Signers::Both,
    )
}

/// A generation container built to the envelope contract: the reserved target,
/// the epoch in decimal, and the member digest as `commit`.
pub(crate) fn generation_pkg(pair: &Ed25519KeyPair, member: &[u8], epoch: u64) -> Vec<u8> {
    pkg_naming(
        pair,
        member,
        TRUST_TARGET,
        &epoch.to_string(),
        &member_digest(member),
    )
}

/// A generation container built to the envelope contract and signed by `pair`
/// alone: format 3, its Ed25519 pairs present and both ML-DSA-87 pairs absent.
pub(crate) fn generation_pkg_ed25519_only(
    pair: &Ed25519KeyPair,
    member: &[u8],
    epoch: u64,
) -> Vec<u8> {
    pkg_carrying(
        pair,
        TRUST_SET_MEMBER,
        member,
        TRUST_TARGET,
        &epoch.to_string(),
        &member_digest(member),
        Signers::Ed25519Only,
    )
}

/// A generation container built to the envelope contract in every respect but
/// the archive member's name, which is `member_name` rather than
/// [`TRUST_SET_MEMBER`].
///
/// The manifest binds that same name, so the container is internally consistent
/// and its walk succeeds; what it does not carry is a trust-set document to
/// admit.
pub(crate) fn generation_pkg_member_named(
    pair: &Ed25519KeyPair,
    member: &[u8],
    epoch: u64,
    member_name: &str,
) -> Vec<u8> {
    pkg_carrying(
        pair,
        member_name,
        member,
        TRUST_TARGET,
        &epoch.to_string(),
        &member_digest(member),
        Signers::Both,
    )
}
