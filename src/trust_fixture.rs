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
//! path: every fixture key pair is minted afresh from the system RNG.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tar::{Builder, EntryType, Header};
use zstd::Encoder;

use crate::manifest::{
    ArchiveMember, ArtifactKind, Disposition, MIN_MANIFEST_FORMAT_VERSION, PayloadArtifact,
    PayloadManifest, TargetArch,
};
use crate::payload::{FORMAT_VERSION, MAGIC};
use crate::trust_set::{
    ANCHORS_FIELD, EPOCH_FIELD, TRUST_SET_MEMBER, TRUST_SET_VERSION, TRUST_SET_VERSION_FIELD,
    WITHDRAWN_BUILDS_FIELD, member_digest,
};
use crate::verify::{TRUST_TARGET, key_id};

/// Epoch every well-formed fixture generation carries unless a test names its
/// own.
pub(crate) const EPOCH: u64 = 7;

/// zstd level the fixture archive writer uses; it only has to round-trip.
const FIXTURE_ZSTD_LEVEL: i32 = 3;

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
pub(crate) fn anchor_json(key_id: &str, public_key: &str, revoked: bool) -> String {
    format!(r#"{{"key_id":"{key_id}","public_key":"{public_key}","revoked":{revoked}}}"#)
}

/// The anchor entry `pair` really writes: its `key_id` derived from its own
/// `public_key`.
pub(crate) fn anchor_of(pair: &Ed25519KeyPair, revoked: bool) -> String {
    let public_key = public_key_of(pair);
    anchor_json(&key_id(&public_key), &hex_of(&public_key), revoked)
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
    /// A well-formed generation trusting `pair` alone.
    pub(crate) fn new(pair: &Ed25519KeyPair) -> Self {
        Self {
            trust_set_version: Some(TRUST_SET_VERSION.to_string()),
            epoch: Some(EPOCH.to_string()),
            min_manifest_format_version: Some(MIN_MANIFEST_FORMAT_VERSION.to_string()),
            anchors: Some(array(&[anchor_of(pair, false)])),
            withdrawn_builds: Some(array(&[])),
            extra: Vec::new(),
        }
    }

    /// A well-formed generation carrying exactly `anchors`.
    pub(crate) fn anchored(anchors: &[String]) -> Self {
        let pair = keypair();
        Self {
            anchors: Some(array(anchors)),
            ..Self::new(&pair)
        }
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

/// The document a well-formed fixture carries: one live anchor, nothing
/// withdrawn.
pub(crate) fn default_document(pair: &Ed25519KeyPair) -> Vec<u8> {
    Fields::new(pair).render()
}

/// Builds the archive block: one zstd-compressed tar holding the document as its
/// only member, which is what the envelope contract states.
fn archive_of(member: &[u8]) -> Vec<u8> {
    let encoder = Encoder::new(Vec::new(), FIXTURE_ZSTD_LEVEL).expect("encoder should be created");
    let mut builder = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header
        .set_path(TRUST_SET_MEMBER)
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
/// `StaticAssets`, binding the one member.
fn manifest_json(component: &str, version: &str, commit: &str, member: &[u8]) -> Vec<u8> {
    let manifest = PayloadManifest::new(
        None,
        vec![ArchiveMember {
            name: TRUST_SET_MEMBER.to_string(),
            length: len_u64(member),
        }],
        vec![PayloadArtifact {
            component: component.to_string(),
            version: version.to_string(),
            commit: Some(commit.to_string()),
            target_arch: TargetArch::X86_64,
            kind: ArtifactKind::StaticAssets,
            dispositions: [Disposition::Install].into_iter().collect(),
            archive_path: TRUST_SET_MEMBER.to_string(),
            // The same digest the entry's `commit` is, over the same bytes: the
            // container layer checks this one on extraction.
            sha256: member_digest(member),
            spec: None,
        }],
    )
    .expect("the envelope contract builds a manifest");
    serde_json::to_vec(&manifest).expect("a manifest serializes")
}

/// Encodes a current-version footer by hand: magic, the version byte, then the
/// four offset/length pairs it records.
fn footer_bytes(fields: [u64; 8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    for field in fields {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out
}

/// Assembles a signed `.pkg`: the manifest at offset `0`, the archive, the
/// signature over the manifest's raw bytes, the signer's `key_id` hint, then the
/// footer.
fn signed_pkg(pair: &Ed25519KeyPair, manifest: &[u8], archive: &[u8]) -> Vec<u8> {
    let signature = pair.sign(manifest);
    let hint = key_id(&public_key_of(pair));
    let mut out = Vec::new();
    out.extend_from_slice(manifest);
    out.extend_from_slice(archive);
    let signature_offset = len_u64(manifest) + len_u64(archive);
    out.extend_from_slice(signature.as_ref());
    let hint_offset = signature_offset + len_u64(signature.as_ref());
    out.extend_from_slice(hint.as_bytes());
    out.extend_from_slice(&footer_bytes([
        0,
        len_u64(manifest),
        len_u64(manifest),
        len_u64(archive),
        signature_offset,
        len_u64(signature.as_ref()),
        hint_offset,
        len_u64(hint.as_bytes()),
    ]));
    out
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
    signed_pkg(
        pair,
        &manifest_json(component, version, commit, member),
        &archive_of(member),
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
