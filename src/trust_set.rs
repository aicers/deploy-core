//! The trust-set generation document, and the reader that refuses a malformed
//! one.
//!
//! [`crate::verify`] takes its trust material as a caller-injected value and
//! reads nothing from disk. This module is the other half of that split: it
//! states what one generation of that material *is* on the wire, and it parses
//! it. It opens no file, joins no path and performs no I/O — a generation tree,
//! its `epoch` record and the install-time admission paths are separate
//! concerns built on top of this one.
//!
//! Both consumers of the verifier read this material and one of them is a root
//! daemon that never links the installer, so the document and its reader live
//! here rather than in either caller.
//!
//! # The document
//!
//! One generation is one UTF-8 JSON object carried in a member named
//! `TRUST_SET_MEMBER`, with exactly the five fields of [`TrustSetDocument`]
//! and no others. The numeric domains are the verifier's own —
//! [`TrustSet::new`](crate::verify::TrustSet::new) takes a `u64` `epoch` and a
//! `u32` manifest floor — because a document is not the place to widen a type
//! the code that consumes it has already fixed.
//!
//! `min_manifest_format_version` is carried through at **any** `u32`, `0` and
//! values above this build's manifest range included. The floor is release
//! ops', not this reader's: a `0` floor refuses nothing this build would have
//! accepted anyway, and a floor above
//! [`MAX_MANIFEST_FORMAT_VERSION`](crate::manifest::MAX_MANIFEST_FORMAT_VERSION)
//! is a legitimate document that outlives this build, whose effect the verifier
//! already reports precisely. A reader that second-guessed either end would
//! couple a signed, long-lived document to one build's manifest range. `epoch`
//! is the one number this reader constrains, and for a different reason in
//! kind: `0` is not a low epoch, it is the absence of an allocated sequence
//! number.
//!
//! # The reader refuses rather than repairs
//!
//! `read_trust_set_document` runs three stages in a fixed order, and each
//! fault carries its own named [`TrustSetDocumentError`] — never the package
//! verifier's cross-repository taxonomy, and never a repair, a default or a
//! coercion:
//!
//! 1. **the version gate**, decided from `trust_set_version` alone through a
//!    permissive parse that types no other value. An unimplemented version wins
//!    over every fault the later stages could find, because a document written
//!    to a later schema is *expected* to look wrong here and answering "your
//!    anchor entry is malformed" would send an operator to repair a document
//!    that is not broken. The one thing it does not win over is the bytes not
//!    being a JSON object, which this stage refuses first, because then there is
//!    no version to read;
//! 2. **the structural decode**, from the original bytes and never from stage
//!    one's [`serde_json::Value`] — only the byte decode refuses a duplicate
//!    object key, where `Value` silently keeps the last occurrence, and a reader
//!    whose signed bytes said one thing and whose parsed form said another is
//!    the same silent divergence the unknown-field rule exists to prevent. An
//!    unknown field is determined explicitly from the object's key set rather
//!    than by matching a [`serde_json::Error`] message;
//! 3. **the semantic checks**, in the order `check_document` applies them.
//!
//! # The envelope
//!
//! A generation is delivered as a signed `.pkg` whose archive block holds the
//! document as its **only** member, under a manifest carrying exactly one
//! artifact entry: `component` = the reserved
//! [`TRUST_TARGET`](crate::verify::TRUST_TARGET), `version` = the `epoch` in
//! decimal, `commit` = `member_digest` over the member's bytes, `kind` =
//! [`ArtifactKind::StaticAssets`](crate::manifest::ArtifactKind::StaticAssets),
//! `archive_path` = `TRUST_SET_MEMBER`. Everything cryptographic comes from
//! the verifier and is not restated here.
//!
//! The signature covers the raw manifest-block bytes and nothing else, so the
//! property this module keeps is not "verify the member, then parse the member",
//! which the container format does not offer; it is that the refusing reader
//! only ever runs over member bytes whose digest a verified manifest names.
//!
//! # The one decode permitted before verification
//!
//! [`verify_package`](crate::verify::verify_package) takes a
//! [`TrustSet`](crate::verify::TrustSet) by value, so a caller admitting a
//! generation must already hold one when it calls — and for a first generation
//! the only anchors in existence are inside the delivered document. So the
//! admission path reads the member's bytes out of the container and decodes
//! part of it before anything has been authenticated. That is permitted, and it
//! is bounded; see
//! `VerifyRequest::for_trust_self_admission`,
//! whose documentation states the decode, the candidate trust set built from it
//! and the order of the call. It reads `anchors` and `epoch` and no other field,
//! it is **not** this module's refusing reader, and it admits nothing: nothing
//! it produces is stored, returned or becomes the generation. Admission is
//! `verify_package` returning `Ok`, after which `read_trust_set_document`
//! parses the member bytes again, from scratch, and the generation is built from
//! *that* parse.
//!
//! A failure of that provisional decode is a refusal of the *admission attempt*
//! and is named by the admission path's own error type. None of them may
//! surface as a [`TrustSetDocumentError`]: that type's contract is "this is what
//! a verified document said", and attaching it to bytes no anchor has vouched
//! for would dress an unauthenticated parse up as a verdict about a real
//! generation.

use std::collections::HashSet;

use serde::Deserialize;

use crate::payload;
use crate::verify::{BuildIdentifier, is_safe_build_identifier, key_id};

/// The one `trust_set_version` this reader implements.
///
/// This is the document schema's own version and is **not** the manifest
/// `format_version` floor a document carries: the two version numbers move
/// independently, and conflating them would tie a schema addition here to a
/// manifest schema addition there.
const TRUST_SET_VERSION: u32 = 1;

/// Archive member the generation document is carried in.
///
/// Crate-internal because no caller outside this crate names it: a consumer
/// receives an already-verified [`TrustSetDocument`] from an entry point this
/// crate exports rather than reaching into a container itself.
// The install-time admission path that extracts this member is a later issue;
// this `allow` goes when that work supplies the caller.
#[allow(dead_code)]
pub(crate) const TRUST_SET_MEMBER: &str = "trust-set.json";

/// Number of ASCII characters 32 bytes rendered as lowercase hex is.
///
/// Both `key_id` and `public_key` are fixed-width lowercase hex, which makes
/// length and charset a single check and leaves no separate "decoded to the
/// wrong number of bytes" case: 64 lowercase hex characters **is** 32 bytes.
const HEX_32_LEN: usize = 64;

/// Name of the field the version gate reads, and the only field it types.
const TRUST_SET_VERSION_FIELD: &str = "trust_set_version";

/// Name of the anchor array, as both a decoded field and an unknown-field
/// location.
const ANCHORS_FIELD: &str = "anchors";

/// Name of the withdrawn-build array, on the same terms as [`ANCHORS_FIELD`].
const WITHDRAWN_BUILDS_FIELD: &str = "withdrawn_builds";

/// How [`TrustSetDocumentError::UnknownField`] names the top-level object.
const DOCUMENT_LOCATION: &str = "the document";

/// Every field the top-level object may carry.
///
/// Compared against the object's own key set, so an unknown field gets its own
/// refusal instead of arriving as a decode error whose distinction lives in a
/// message. `deny_unknown_fields` stays on the derived types regardless, so a
/// field added to a struct but not to one of these lists — or the reverse —
/// cannot slip through in either direction.
const TOP_LEVEL_FIELDS: [&str; 5] = [
    TRUST_SET_VERSION_FIELD,
    "epoch",
    "min_manifest_format_version",
    ANCHORS_FIELD,
    WITHDRAWN_BUILDS_FIELD,
];

/// Every field an anchor entry may carry.
const ANCHOR_FIELDS: [&str; 3] = ["key_id", "public_key", "revoked"];

/// Every field a withdrawn-build entry may carry.
const WITHDRAWN_BUILD_FIELDS: [&str; 3] = ["package_id", "version", "commit"];

/// One generation of trust material, as it is written and as
/// `read_trust_set_document` returns it.
///
/// The five fields are the whole schema: `deny_unknown_fields` holds at the top
/// level and in every entry, and an addition bumps `TRUST_SET_VERSION` rather
/// than riding along silently. A signed trust document must not carry a field an
/// older reader drops without a word, because that is how a revocation-relevant
/// addition becomes invisible.
///
/// A value of this type that came out of `read_trust_set_document` has passed
/// `check_document`, so its `epoch` is non-zero and its anchors are
/// well-formed, distinct and not all revoked. The fields are public because this
/// type appears in the signatures of items this crate exports to a root daemon
/// that links it and cannot construct anything from the installer's repository.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSetDocument {
    /// This document schema's own version, `TRUST_SET_VERSION` today.
    pub trust_set_version: u32,

    /// The release-ops-allocated sequence number, inside the signed material.
    ///
    /// Decoded with a `0` default so that an absent `epoch` and a `0` one reach
    /// the one shared [`TrustSetDocumentError::AbsentEpoch`] rather than
    /// splitting across a semantic refusal and a generic decode error. They are
    /// one fault — no sequence number was allocated — and they share one
    /// variant on purpose.
    #[serde(default)]
    pub epoch: u64,

    /// Minimum payload-manifest `format_version` this generation accepts,
    /// carried through at any `u32` and never clamped against this build's
    /// manifest range.
    pub min_manifest_format_version: u32,

    /// The release-signing keys this generation trusts, revoked ones included.
    pub anchors: Vec<TrustSetAnchor>,

    /// The `(package-id, version, commit)` triples this generation withdraws.
    pub withdrawn_builds: Vec<WithdrawnBuild>,
}

/// One anchor entry of a [`TrustSetDocument`], as it is written.
///
/// A revoked anchor **keeps its `public_key`**: the verifier has to verify
/// *under* a revoked key to tell a revoked signer from a bad signature, so an
/// entry shape that dropped it could not answer the question.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSetAnchor {
    /// The key's index, which [`key_id`] derives from `public_key`: 64
    /// lowercase-hex characters, untruncated.
    pub key_id: String,

    /// The 32 raw Ed25519 public-key bytes, as 64 lowercase-hex characters.
    pub public_key: String,

    /// Whether this generation delivers the key as revoked.
    pub revoked: bool,
}

/// One withdrawn-build entry of a [`TrustSetDocument`]: the exact triple the
/// verifier compares a manifest's artifact entries against.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawnBuild {
    /// Package-id of the withdrawn build.
    pub package_id: String,

    /// Its version.
    pub version: String,

    /// Its commit, the immutable build identity.
    pub commit: String,
}

/// Errors describing **a trust-set generation document**.
///
/// Deliberately not [`VerifyError`](crate::verify::VerifyError) and not a
/// variant of it: that type answers "what is wrong with this package" and is a
/// cross-repository contract, while these answer "what is wrong with this
/// document" and are this crate's own. Nothing here is added to the verifier's
/// taxonomy.
///
/// Every variant names a fault in bytes a verified manifest already vouched for.
/// A failure of the provisional pre-verification decode is not one of these; it
/// belongs to the admission path's own error type.
#[derive(Debug, thiserror::Error)]
pub enum TrustSetDocumentError {
    /// The bytes are not a JSON object at all: not UTF-8, not JSON, or JSON
    /// that is not an object.
    ///
    /// The one refusal that precedes the version gate, because until the bytes
    /// are an object there is no version to read.
    #[error("the trust generation document is not a JSON object")]
    MalformedJson,

    /// `trust_set_version` is absent, `null`, or not an unsigned 32-bit
    /// integer.
    ///
    /// Separate from [`TrustSetDocumentError::UnsupportedVersion`] for the same
    /// reason [`ManifestError::MalformedFormatVersion`](crate::manifest::ManifestError::MalformedFormatVersion)
    /// is separate from its unsupported-version sibling: no `found: u32` can
    /// carry the offending value.
    #[error(
        "the trust generation document's `{TRUST_SET_VERSION_FIELD}` is absent or is not an unsigned 32-bit integer"
    )]
    MalformedVersion,

    /// `trust_set_version` names a schema version this reader does not
    /// implement.
    ///
    /// Decided before anything else the document says, so a document written to
    /// a later schema is answered for its version rather than for whichever of
    /// its fields this reader happens not to recognize.
    #[error(
        "trust generation document version {found} is not implemented by this build, which implements {TRUST_SET_VERSION}"
    )]
    UnsupportedVersion {
        /// Version the document declared.
        found: u32,
    },

    /// The top-level object or an entry carried a field this schema does not
    /// define.
    ///
    /// Its own variant rather than a decode error, and determined from the
    /// object's key set rather than from a [`serde_json::Error`] message: a
    /// signed trust document must not carry a field an older reader silently
    /// drops, because that is how a revocation-relevant addition becomes
    /// invisible.
    #[error("unknown field `{field}` in {location}")]
    UnknownField {
        /// Where the field was found: `DOCUMENT_LOCATION`, or an entry named
        /// by its array and index.
        location: String,
        /// The undefined field's name.
        field: String,
    },

    /// The document did not decode: a missing required field, a value of the
    /// wrong JSON type, an integer outside its field's domain, or a duplicate
    /// object key.
    ///
    /// One variant rather than four deliberately. Serde reports them as a single
    /// error type whose distinctions live in a human-readable message, and
    /// splitting them apart would mean parsing that message.
    #[error("the trust generation document does not decode")]
    Decode(#[source] serde_json::Error),

    /// The document carries no allocated `epoch`: the field was absent, or it
    /// was `0`.
    ///
    /// `0` is not a low epoch, it is the absence of a sequence number, which is
    /// why the two share one variant.
    #[error("the trust generation document carries no allocated `epoch`")]
    AbsentEpoch,

    /// The document's `anchors` array is empty.
    ///
    /// A generation that can never be superseded, since the next one must be
    /// signed by a key this one carries.
    #[error("the trust generation document carries no anchors")]
    NoAnchors,

    /// Every anchor the document carries is revoked.
    ///
    /// Distinct from [`TrustSetDocumentError::NoAnchors`] because it is a
    /// distinct document, even though it strands a host the same way.
    #[error("every anchor in the trust generation document is revoked")]
    AllAnchorsRevoked,

    /// An anchor's `key_id` is not exactly 64 lowercase-hex characters.
    ///
    /// Uppercase hex is refused rather than folded, because [`key_id`] emits
    /// lowercase and every comparison against it is byte-for-byte.
    #[error("anchor `key_id` `{key_id}` is not {HEX_32_LEN} lowercase-hex characters")]
    MalformedKeyId {
        /// The refused value.
        key_id: String,
    },

    /// An anchor's `public_key` is not exactly 64 lowercase-hex characters,
    /// equivalently not 32 bytes.
    #[error("anchor `public_key` `{public_key}` is not {HEX_32_LEN} lowercase-hex characters")]
    MalformedPublicKey {
        /// The refused value.
        public_key: String,
    },

    /// An anchor's `key_id` is not what [`key_id`] derives from that entry's
    /// own `public_key`, so the index lies about which key it names.
    #[error("anchor `key_id` `{declared}` is not `{derived}`, which its `public_key` derives")]
    KeyIdMismatch {
        /// The `key_id` the entry declared.
        declared: String,
        /// The `key_id` its `public_key` really derives.
        derived: String,
    },

    /// Two anchors carry the same `key_id`.
    #[error("two anchors carry the key id `{key_id}`")]
    DuplicateKeyId {
        /// The repeated index.
        key_id: String,
    },

    /// A withdrawn entry's `package_id`, `version` or `commit` is not safe to
    /// use as a build identifier (see [`is_safe_build_identifier`]).
    ///
    /// An empty identifier is this and not a separate refusal: the predicate
    /// already refuses the empty string, and a second variant for it would be
    /// two names for one answer. The field is named through the verifier's own
    /// [`BuildIdentifier`], whose `Component` is the entry's `package_id`.
    #[error("withdrawn build {field} `{value}` is not a safe build identifier")]
    UnsafeBuildIdentifier {
        /// Which identity field was refused.
        field: BuildIdentifier,
        /// The refused value.
        value: String,
    },

    /// The same `(package-id, version, commit)` triple is withdrawn twice.
    #[error("withdrawn build `{package_id}`/`{version}`/`{commit}` is listed twice")]
    DuplicateWithdrawnBuild {
        /// The repeated triple's package-id.
        package_id: String,
        /// Its version.
        version: String,
        /// Its commit.
        commit: String,
    },
}

/// Returns the digest a generation container's manifest entry records as its
/// `commit`: the lowercase-hex SHA-256 over the document member's bytes.
///
/// A named wrapper over [`payload::sha256_hex`] and not a second implementation
/// of it. It exists so no caller re-derives the rule that *this* digest is over
/// *these* bytes — the same value the entry's `sha256` carries, which the
/// container layer checks on extraction.
// The install-time admission path that compares this against a verified
// manifest is a later issue; this `allow` goes when that work supplies the
// caller.
#[allow(dead_code)]
#[must_use]
pub(crate) fn member_digest(bytes: &[u8]) -> String {
    payload::sha256_hex(bytes)
}

/// Reads a trust-set generation document out of `bytes`, refusing anything it
/// cannot account for.
///
/// The three stages run in the order this module's documentation states, and
/// where two faults are present the earlier stage's is the verdict. It opens no
/// file and resolves no path: `bytes` are the document member's bytes, whose
/// digest a verified manifest has already named.
///
/// # Errors
///
/// Returns [`TrustSetDocumentError`]: [`TrustSetDocumentError::MalformedJson`],
/// [`TrustSetDocumentError::MalformedVersion`] or
/// [`TrustSetDocumentError::UnsupportedVersion`] from the version gate;
/// [`TrustSetDocumentError::UnknownField`] or [`TrustSetDocumentError::Decode`]
/// from the structural decode; and one of the semantic refusals
/// `check_document` lists.
// The install-time admission path that parses a verified member is a later
// issue; this `allow` goes when that work supplies the caller.
#[allow(dead_code)]
pub(crate) fn read_trust_set_document(
    bytes: &[u8],
) -> Result<TrustSetDocument, TrustSetDocumentError> {
    let object = read_version_gate(bytes)?;
    check_unknown_fields(&object)?;
    let document = decode_document(bytes)?;
    check_document(&document)?;
    Ok(document)
}

/// **Stage A.** Decodes `bytes` permissively, applies the version gate, and
/// returns the top-level object for the unknown-field check.
///
/// Only `trust_set_version` is read and no other value is typed: this is
/// [`crate::manifest::parse_format_version`]'s shape, down to reading an
/// explicit `null` as absence, so that a document written to a later schema is
/// refused for its version rather than for a field this reader cannot make sense
/// of.
///
/// The returned object is used for key sets alone. Nothing is ever *decoded*
/// from it — see [`decode_document`].
pub(crate) fn read_version_gate(
    bytes: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, TrustSetDocumentError> {
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| TrustSetDocumentError::MalformedJson)?;
    let serde_json::Value::Object(object) = document else {
        return Err(TrustSetDocumentError::MalformedJson);
    };
    let found = match object.get(TRUST_SET_VERSION_FIELD) {
        None | Some(serde_json::Value::Null) => {
            return Err(TrustSetDocumentError::MalformedVersion);
        }
        Some(value) => value
            .as_u64()
            .and_then(|found| u32::try_from(found).ok())
            .ok_or(TrustSetDocumentError::MalformedVersion)?,
    };
    if found != TRUST_SET_VERSION {
        return Err(TrustSetDocumentError::UnsupportedVersion { found });
    }
    Ok(object)
}

/// **Stage B, first half.** Refuses a field this schema does not define, at the
/// top level or inside any entry.
///
/// Determined from the key sets rather than from a [`serde_json::Error`]
/// message, because the refusal needs its own variant and message-matching is
/// not a way to get one.
///
/// An array field that is not an array, or an entry that is not an object, is
/// left alone here: it is a structural fault, and [`decode_document`] names it.
pub(crate) fn check_unknown_fields(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), TrustSetDocumentError> {
    check_keys(object, &TOP_LEVEL_FIELDS, DOCUMENT_LOCATION)?;
    check_entry_keys(object, ANCHORS_FIELD, &ANCHOR_FIELDS)?;
    check_entry_keys(object, WITHDRAWN_BUILDS_FIELD, &WITHDRAWN_BUILD_FIELDS)
}

/// Refuses any key of `object` that is not in `known`, naming `location`.
fn check_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    known: &[&str],
    location: &str,
) -> Result<(), TrustSetDocumentError> {
    for field in object.keys() {
        if !known.contains(&field.as_str()) {
            return Err(TrustSetDocumentError::UnknownField {
                location: location.to_string(),
                field: field.clone(),
            });
        }
    }
    Ok(())
}

/// Applies [`check_keys`] to each object entry of `object`'s `array_field`.
fn check_entry_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    array_field: &str,
    known: &[&str],
) -> Result<(), TrustSetDocumentError> {
    let Some(serde_json::Value::Array(entries)) = object.get(array_field) else {
        return Ok(());
    };
    for (index, entry) in entries.iter().enumerate() {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        check_keys(entry, known, &format!("`{array_field}` entry {index}"))?;
    }
    Ok(())
}

/// **Stage B, second half.** Decodes the whole document from the **original
/// bytes**.
///
/// From the bytes and never from stage A's [`serde_json::Value`]: a duplicate
/// object key must be refused, and only the byte decode refuses it — serde's
/// derived struct deserialization reports a duplicate-field error naming the
/// repeated key, while `Value` silently keeps the last occurrence. A reader that
/// decoded stage A's `Value` a second time would accept a document whose signed
/// bytes say one thing and whose parsed form says another.
pub(crate) fn decode_document(bytes: &[u8]) -> Result<TrustSetDocument, TrustSetDocumentError> {
    serde_json::from_slice(bytes).map_err(TrustSetDocumentError::Decode)
}

/// **Stage C.** Applies the semantic checks, in this order: the `epoch`, then
/// the anchor list as a whole, then each anchor, then each withdrawn entry.
///
/// The order is the contract: a document carrying two of these faults is refused
/// for the earlier one. Per anchor it is `key_id` shape, `public_key` shape,
/// derivation agreement, then duplication; per withdrawn entry it is the
/// identifier predicate, then duplication.
pub(crate) fn check_document(document: &TrustSetDocument) -> Result<(), TrustSetDocumentError> {
    if document.epoch == 0 {
        return Err(TrustSetDocumentError::AbsentEpoch);
    }

    // Two refusals rather than one: an empty list and a wholly revoked one are
    // two documents, even though each describes a generation that can never be
    // superseded.
    if document.anchors.is_empty() {
        return Err(TrustSetDocumentError::NoAnchors);
    }
    if document.anchors.iter().all(|anchor| anchor.revoked) {
        return Err(TrustSetDocumentError::AllAnchorsRevoked);
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(document.anchors.len());
    for anchor in &document.anchors {
        if !is_lowercase_hex_32(&anchor.key_id) {
            return Err(TrustSetDocumentError::MalformedKeyId {
                key_id: anchor.key_id.clone(),
            });
        }
        let Some(public_key) = decode_lowercase_hex_32(&anchor.public_key) else {
            return Err(TrustSetDocumentError::MalformedPublicKey {
                public_key: anchor.public_key.clone(),
            });
        };
        let derived = key_id(&public_key);
        if derived != anchor.key_id {
            return Err(TrustSetDocumentError::KeyIdMismatch {
                declared: anchor.key_id.clone(),
                derived,
            });
        }
        if !seen.insert(anchor.key_id.as_str()) {
            return Err(TrustSetDocumentError::DuplicateKeyId {
                key_id: anchor.key_id.clone(),
            });
        }
    }

    let mut withdrawn: HashSet<(&str, &str, &str)> =
        HashSet::with_capacity(document.withdrawn_builds.len());
    for entry in &document.withdrawn_builds {
        for (field, value) in [
            (BuildIdentifier::Component, entry.package_id.as_str()),
            (BuildIdentifier::Version, entry.version.as_str()),
            (BuildIdentifier::Commit, entry.commit.as_str()),
        ] {
            if !is_safe_build_identifier(value) {
                return Err(TrustSetDocumentError::UnsafeBuildIdentifier {
                    field,
                    value: value.to_string(),
                });
            }
        }
        let triple = (
            entry.package_id.as_str(),
            entry.version.as_str(),
            entry.commit.as_str(),
        );
        if !withdrawn.insert(triple) {
            return Err(TrustSetDocumentError::DuplicateWithdrawnBuild {
                package_id: entry.package_id.clone(),
                version: entry.version.clone(),
                commit: entry.commit.clone(),
            });
        }
    }

    Ok(())
}

/// Returns the value of one lowercase-hex digit, or `None` for anything else.
///
/// Uppercase is not a digit here on purpose: the derivation emits lowercase and
/// every comparison against it is byte-for-byte, so folding case would make one
/// key expressible two ways.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Reports whether `value` is exactly [`HEX_32_LEN`] lowercase-hex characters.
fn is_lowercase_hex_32(value: &str) -> bool {
    value.len() == HEX_32_LEN && value.bytes().all(|byte| hex_nibble(byte).is_some())
}

/// Decodes exactly [`HEX_32_LEN`] lowercase-hex characters into the 32 bytes
/// they are, or `None` at any other length, on any uppercase or non-hex
/// character.
///
/// The same check [`is_lowercase_hex_32`] makes, and the decoded bytes besides,
/// so a caller that needs the key material does not test the shape twice.
fn decode_lowercase_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != HEX_32_LEN {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_nibble(*bytes.get(index * 2)?)?;
        let low = hex_nibble(*bytes.get(index * 2 + 1)?)?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tar::{Builder, EntryType, Header};
    use zstd::Encoder;

    use super::*;
    use crate::manifest::{
        ArchiveMember, ArtifactKind, Disposition, MAX_MANIFEST_FORMAT_VERSION,
        MIN_MANIFEST_FORMAT_VERSION, PayloadArtifact, PayloadManifest, TargetArch,
    };
    use crate::payload::{FORMAT_VERSION, MAGIC};
    use crate::verify::{
        TRUST_TARGET, TrustAnchor, TrustSet, VerifiedPackage, VerifyError, VerifyRequest,
        verify_package,
    };

    /// Epoch every well-formed fixture generation carries.
    const EPOCH: u64 = 7;
    /// A `key_id`-shaped value no fixture key derives.
    const STRANGER_KEY_ID: &str =
        "abababababababababababababababababababababababababababababababab";
    /// A `commit`-shaped value that is not any fixture member's digest.
    const STRANGER_COMMIT: &str =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    /// zstd level the fixture archive writer uses; it only has to round-trip.
    const FIXTURE_ZSTD_LEVEL: i32 = 3;

    /// Mints an ephemeral Ed25519 key pair. No key material is committed to the
    /// repository and none is read from a fixed path.
    fn keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation should succeed");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a freshly minted key pair parses")
    }

    /// Returns a key pair's raw 32-byte public key.
    fn public_key_of(pair: &Ed25519KeyPair) -> [u8; 32] {
        pair.public_key()
            .as_ref()
            .try_into()
            .expect("an ed25519 public key is 32 bytes")
    }

    /// Renders bytes as the lowercase hex a document writes them as.
    fn hex_of(bytes: &[u8]) -> String {
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
    fn array(items: &[String]) -> String {
        format!("[{}]", items.join(","))
    }

    /// Renders one anchor entry verbatim, so a fixture can state a `key_id` or
    /// a `public_key` no derivation would produce.
    fn anchor_json(key_id: &str, public_key: &str, revoked: bool) -> String {
        format!(r#"{{"key_id":"{key_id}","public_key":"{public_key}","revoked":{revoked}}}"#)
    }

    /// The anchor entry `pair` really writes: its `key_id` derived from its own
    /// `public_key`.
    fn anchor_of(pair: &Ed25519KeyPair, revoked: bool) -> String {
        let public_key = public_key_of(pair);
        anchor_json(&key_id(&public_key), &hex_of(&public_key), revoked)
    }

    /// Renders one withdrawn-build entry verbatim.
    fn withdrawn_json(package_id: &str, version: &str, commit: &str) -> String {
        format!(r#"{{"package_id":"{package_id}","version":"{version}","commit":"{commit}"}}"#)
    }

    /// The five top-level members of a document, each as the JSON text it is
    /// written as.
    ///
    /// `None` omits a member outright and `extra` is appended verbatim, so one
    /// builder covers an absent field, an ill-typed one, an unknown one and the
    /// same one written twice — shapes the typed document could not hold.
    struct Fields {
        trust_set_version: Option<String>,
        epoch: Option<String>,
        min_manifest_format_version: Option<String>,
        anchors: Option<String>,
        withdrawn_builds: Option<String>,
        extra: Vec<String>,
    }

    impl Fields {
        /// A well-formed generation trusting `pair` alone.
        fn new(pair: &Ed25519KeyPair) -> Self {
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
        fn anchored(anchors: &[String]) -> Self {
            let pair = keypair();
            Self {
                anchors: Some(array(anchors)),
                ..Self::new(&pair)
            }
        }

        fn render(&self) -> Vec<u8> {
            let mut members: Vec<String> = Vec::new();
            for (name, value) in [
                (TRUST_SET_VERSION_FIELD, &self.trust_set_version),
                ("epoch", &self.epoch),
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
    fn default_document(pair: &Ed25519KeyPair) -> Vec<u8> {
        Fields::new(pair).render()
    }

    /// Reads `bytes`, asserting they are refused, and returns the refusal.
    fn refusal(bytes: &[u8]) -> TrustSetDocumentError {
        read_trust_set_document(bytes).expect_err("the document should be refused")
    }

    /// Reads `bytes`, asserting they are accepted.
    fn accepted(bytes: &[u8]) -> TrustSetDocument {
        read_trust_set_document(bytes).expect("the document should be read")
    }

    /// Builds the archive block: one zstd-compressed tar holding the document
    /// as its only member, which is what the envelope contract states.
    fn archive_of(member: &[u8]) -> Vec<u8> {
        let encoder =
            Encoder::new(Vec::new(), FIXTURE_ZSTD_LEVEL).expect("encoder should be created");
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

    /// Renders the manifest block of a generation container: one artifact
    /// entry, `StaticAssets`, binding the one member.
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
                // The same digest the entry's `commit` is, over the same bytes:
                // the container layer checks this one on extraction.
                sha256: member_digest(member),
                spec: None,
            }],
        )
        .expect("the envelope contract builds a manifest");
        serde_json::to_vec(&manifest).expect("a manifest serializes")
    }

    /// Encodes a current-version footer by hand: magic, the version byte, then
    /// the four offset/length pairs it records.
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
    /// signature over the manifest's raw bytes, the signer's `key_id` hint,
    /// then the footer.
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
    fn pkg_naming(
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

    /// A generation container built to the envelope contract: the reserved
    /// target, the epoch in decimal, and the member digest as `commit`.
    fn generation_pkg(pair: &Ed25519KeyPair, member: &[u8], epoch: u64) -> Vec<u8> {
        pkg_naming(
            pair,
            member,
            TRUST_TARGET,
            &epoch.to_string(),
            &member_digest(member),
        )
    }

    /// The provisional decode the admission path is permitted to make before
    /// anything is verified: `anchors` and `epoch` only, permissively, and
    /// all-or-nothing.
    ///
    /// An entry's own `key_id` is not read at all — [`TrustAnchor::new`]
    /// derives the index from the key, so there is no second derivation site to
    /// disagree with. This is deliberately **not** `read_trust_set_document`:
    /// running that here would report a parse refusal where a signature failure
    /// belongs.
    fn provisional(member: &[u8]) -> (Vec<TrustAnchor>, u64) {
        let document: serde_json::Value =
            serde_json::from_slice(member).expect("a fixture document is JSON");
        let epoch = document
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .expect("a fixture document carries an epoch");
        let anchors = document
            .get(ANCHORS_FIELD)
            .and_then(serde_json::Value::as_array)
            .expect("a fixture document carries an anchor array")
            .iter()
            .map(|entry| {
                let public_key = entry
                    .get("public_key")
                    .and_then(serde_json::Value::as_str)
                    .and_then(decode_lowercase_hex_32)
                    .expect("a fixture anchor carries 32 key bytes");
                let revoked = entry
                    .get("revoked")
                    .and_then(serde_json::Value::as_bool)
                    .expect("a fixture anchor carries a revocation flag");
                TrustAnchor::new(public_key, revoked)
            })
            .collect();
        (anchors, epoch)
    }

    /// The candidate trust set a self-admission is verified against, with all
    /// four [`TrustSet::new`] arguments as the request form states them.
    fn candidate(member: &[u8]) -> (TrustSet, u64) {
        let (anchors, epoch) = provisional(member);
        let trust = TrustSet::new(
            // Every anchor the decode produced, revoked ones included, so a
            // generation signed by a key its own document marks revoked is
            // refused as `RevokedKey` and not as `UnknownKeyId`.
            anchors,
            // The identity of `check_withdrawal`: the only entry that could
            // ever match this container's one triple is a document withdrawing
            // itself, and the list it really carries governs later packages
            // once the verified document is installed.
            Vec::new(),
            // The identity of `check_format_version`: the parse already refuses
            // anything outside this build's manifest range, so `0` is exactly
            // that range and honours no floor read from unauthenticated bytes.
            0,
            // Read by nothing under this request form, since `check_epoch`
            // returns early; passed through so no number appears in the call
            // that did not come from the document.
            epoch,
        )
        .expect("a fixture document carries distinct anchors");
        (trust, epoch)
    }

    /// Verifies `package` as a self-admission of the generation `member`
    /// carries, in the order the request form states.
    fn self_admit(
        package: &[u8],
        member: &[u8],
    ) -> Result<VerifiedPackage<Cursor<Vec<u8>>>, VerifyError> {
        let (trust, epoch) = candidate(member);
        let request =
            VerifyRequest::for_trust_self_admission(&epoch.to_string(), &member_digest(member))
                .expect("a self-admission request is infallible");
        verify_package(Cursor::new(package.to_vec()), &trust, &request)
    }

    #[test]
    fn a_well_formed_generation_document_round_trips() {
        let pair = keypair();
        let member = default_document(&pair);
        let package = generation_pkg(&pair, &member, EPOCH);

        let verified = self_admit(&package, &member).expect("the generation should verify");
        assert_eq!(verified.manifest().artifacts().len(), 1);

        let document = accepted(&member);
        assert_eq!(document.trust_set_version, TRUST_SET_VERSION);
        assert_eq!(document.epoch, EPOCH);
        assert_eq!(
            document.min_manifest_format_version,
            MIN_MANIFEST_FORMAT_VERSION
        );
        assert!(document.withdrawn_builds.is_empty());
        let anchor = document.anchors.first().expect("one anchor");
        assert_eq!(document.anchors.len(), 1);
        assert_eq!(anchor.key_id, key_id(&public_key_of(&pair)));
        assert_eq!(anchor.public_key, hex_of(&public_key_of(&pair)));
        assert!(!anchor.revoked);
    }

    #[test]
    fn bytes_that_are_not_a_json_object_are_malformed_json() {
        for bytes in [
            b"not json at all".as_slice(),
            b"[1, 2, 3]".as_slice(),
            b"\"a string\"".as_slice(),
            // Not UTF-8, so it is not JSON either.
            &[0xff, 0xfe, 0xfd],
        ] {
            assert!(matches!(
                refusal(bytes),
                TrustSetDocumentError::MalformedJson
            ));
        }
    }

    #[test]
    fn an_absent_or_ill_typed_trust_set_version_is_malformed_version() {
        let pair = keypair();
        // The last of these is the narrowing the gate performs by hand rather
        // than through serde: a JSON integer that is a `u64` and not a `u32` is
        // no more a version than a string is.
        for version in [
            None,
            Some("null"),
            Some(r#""1""#),
            Some("-1"),
            Some("1.0"),
            Some("4294967296"),
        ] {
            let fields = Fields {
                trust_set_version: version.map(str::to_string),
                ..Fields::new(&pair)
            };
            assert!(
                matches!(
                    refusal(&fields.render()),
                    TrustSetDocumentError::MalformedVersion
                ),
                "trust_set_version {version:?} should be malformed"
            );
        }
    }

    #[test]
    fn an_unimplemented_trust_set_version_is_refused_for_its_version() {
        let pair = keypair();
        let fields = Fields {
            trust_set_version: Some((TRUST_SET_VERSION + 1).to_string()),
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::UnsupportedVersion { found } if found == TRUST_SET_VERSION + 1
        ));
    }

    #[test]
    fn the_version_gate_wins_over_every_later_fault() {
        // An unknown top-level field, a malformed anchor entry and an absent
        // `epoch` all at once: a document written to a later schema is expected
        // to look wrong here, so it is answered for its version.
        let fields = Fields {
            trust_set_version: Some((TRUST_SET_VERSION + 1).to_string()),
            epoch: None,
            anchors: Some(array(&[anchor_json("not hex", "not hex either", false)])),
            extra: vec![r#""revocations":[]"#.to_string()],
            ..Fields::anchored(&[])
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::UnsupportedVersion { found } if found == TRUST_SET_VERSION + 1
        ));
    }

    #[test]
    fn an_unknown_top_level_field_is_refused_by_name() {
        let pair = keypair();
        let fields = Fields {
            extra: vec![r#""revocations":[]"#.to_string()],
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::UnknownField { location, field }
                if location == DOCUMENT_LOCATION && field == "revocations"
        ));
    }

    #[test]
    fn an_unknown_field_inside_an_anchor_entry_is_refused_by_name() {
        let pair = keypair();
        let public_key = public_key_of(&pair);
        let anchor = format!(
            r#"{{"key_id":"{}","public_key":"{}","revoked":false,"expires":"never"}}"#,
            key_id(&public_key),
            hex_of(&public_key)
        );
        let fields = Fields::anchored(&[anchor]);
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::UnknownField { location, field }
                if location.contains(ANCHORS_FIELD) && field == "expires"
        ));
    }

    #[test]
    fn an_unknown_field_inside_a_withdrawn_entry_is_refused_by_name() {
        let pair = keypair();
        let entry = r#"{"package_id":"example","version":"1.0.0","commit":"abc","reason":"cve"}"#;
        let fields = Fields {
            withdrawn_builds: Some(array(&[entry.to_string()])),
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::UnknownField { location, field }
                if location.contains(WITHDRAWN_BUILDS_FIELD) && field == "reason"
        ));
    }

    #[test]
    fn a_duplicate_top_level_key_is_refused() {
        // Only the byte decode sees this: stage A's `serde_json::Value` keeps
        // the last occurrence and would report nothing at all.
        let pair = keypair();
        let fields = Fields {
            extra: vec![format!(r#""epoch":{}"#, EPOCH + 1)],
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::Decode(_)
        ));
    }

    #[test]
    fn a_missing_required_field_is_a_decode_refusal() {
        let pair = keypair();
        let fields = Fields {
            anchors: None,
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::Decode(_)
        ));
    }

    #[test]
    fn numeric_fields_are_refused_rather_than_coerced() {
        let pair = keypair();
        // A negative `epoch`, an over-wide one, a fractional and an over-wide
        // manifest floor, and a floor written as a string: serde's own integer
        // deserialization refuses every one of them.
        for fields in [
            Fields {
                epoch: Some("-1".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                epoch: Some("18446744073709551616".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                min_manifest_format_version: Some("1.0".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                min_manifest_format_version: Some("4294967296".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                min_manifest_format_version: Some(r#""3""#.to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                min_manifest_format_version: Some("null".to_string()),
                ..Fields::new(&pair)
            },
        ] {
            assert!(matches!(
                refusal(&fields.render()),
                TrustSetDocumentError::Decode(_)
            ));
        }
    }

    #[test]
    fn any_manifest_floor_is_carried_through() {
        // The floor is release ops', not this reader's: `0` refuses nothing
        // this build would have accepted anyway, and a floor above this build's
        // range is a document that outlives the build.
        let pair = keypair();
        for floor in [0, MAX_MANIFEST_FORMAT_VERSION + 1] {
            let fields = Fields {
                min_manifest_format_version: Some(floor.to_string()),
                ..Fields::new(&pair)
            };
            assert_eq!(
                accepted(&fields.render()).min_manifest_format_version,
                floor
            );
        }
    }

    #[test]
    fn an_absent_epoch_and_a_zero_epoch_share_one_refusal() {
        let pair = keypair();
        for epoch in [None, Some("0")] {
            let fields = Fields {
                epoch: epoch.map(str::to_string),
                ..Fields::new(&pair)
            };
            assert!(
                matches!(
                    refusal(&fields.render()),
                    TrustSetDocumentError::AbsentEpoch
                ),
                "epoch {epoch:?} should be an absent epoch"
            );
        }
    }

    #[test]
    fn a_generation_that_can_never_be_superseded_is_refused() {
        let pair = keypair();
        assert!(matches!(
            refusal(&Fields::anchored(&[]).render()),
            TrustSetDocumentError::NoAnchors
        ));
        assert!(matches!(
            refusal(&Fields::anchored(&[anchor_of(&pair, true)]).render()),
            TrustSetDocumentError::AllAnchorsRevoked
        ));
    }

    #[test]
    fn a_revoked_anchor_beside_a_live_one_is_accepted_and_keeps_its_public_key() {
        let live = keypair();
        let revoked = keypair();
        let fields = Fields::anchored(&[anchor_of(&live, false), anchor_of(&revoked, true)]);
        let document = accepted(&fields.render());
        let entry = document
            .anchors
            .iter()
            .find(|anchor| anchor.revoked)
            .expect("the revoked anchor is retained");
        assert_eq!(entry.public_key, hex_of(&public_key_of(&revoked)));
        assert_eq!(entry.key_id, key_id(&public_key_of(&revoked)));
    }

    #[test]
    fn an_anchor_index_that_is_not_lowercase_hex_of_the_right_width_is_refused() {
        let pair = keypair();
        let public_key = public_key_of(&pair);
        let derived = key_id(&public_key);
        let hex = hex_of(&public_key);

        for key_id_value in [derived.to_uppercase(), derived[..62].to_string()] {
            let fields = Fields::anchored(&[anchor_json(&key_id_value, &hex, false)]);
            assert!(matches!(
                refusal(&fields.render()),
                TrustSetDocumentError::MalformedKeyId { .. }
            ));
        }
        for public_key_value in [hex.to_uppercase(), hex[..62].to_string()] {
            let fields = Fields::anchored(&[anchor_json(&derived, &public_key_value, false)]);
            assert!(matches!(
                refusal(&fields.render()),
                TrustSetDocumentError::MalformedPublicKey { .. }
            ));
        }
    }

    #[test]
    fn a_key_id_that_the_public_key_does_not_derive_is_refused() {
        // The signature over the container is valid; the index still lies about
        // which key it names, and the reader answers that on its own.
        let pair = keypair();
        let public_key = public_key_of(&pair);
        let fields = Fields::anchored(&[anchor_json(STRANGER_KEY_ID, &hex_of(&public_key), false)]);
        let member = fields.render();
        let package = generation_pkg(&pair, &member, EPOCH);
        self_admit(&package, &member).expect("the container itself verifies");

        assert!(matches!(
            refusal(&member),
            TrustSetDocumentError::KeyIdMismatch { declared, derived }
                if declared == STRANGER_KEY_ID && derived == key_id(&public_key)
        ));
    }

    #[test]
    fn a_repeated_key_id_is_refused() {
        let pair = keypair();
        let entry = anchor_of(&pair, false);
        let fields = Fields::anchored(&[entry.clone(), entry]);
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::DuplicateKeyId { key_id: id }
                if id == key_id(&public_key_of(&pair))
        ));
    }

    #[test]
    fn an_unsafe_withdrawn_identifier_is_refused_by_field() {
        let pair = keypair();
        for (entry, expected) in [
            (
                withdrawn_json("", "1.0.0", "abc"),
                BuildIdentifier::Component,
            ),
            (
                withdrawn_json("example", "-1.0.0", "abc"),
                BuildIdentifier::Version,
            ),
            (
                withdrawn_json("example", "1.0.0", "a/b"),
                BuildIdentifier::Commit,
            ),
        ] {
            let fields = Fields {
                withdrawn_builds: Some(array(&[entry])),
                ..Fields::new(&pair)
            };
            assert!(matches!(
                refusal(&fields.render()),
                TrustSetDocumentError::UnsafeBuildIdentifier { field, .. } if field == expected
            ));
        }
    }

    #[test]
    fn a_repeated_withdrawn_triple_is_refused() {
        let pair = keypair();
        let entry = withdrawn_json("example", "1.0.0", "abc");
        let fields = Fields {
            withdrawn_builds: Some(array(&[entry.clone(), entry])),
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::DuplicateWithdrawnBuild { package_id, .. }
                if package_id == "example"
        ));
    }

    #[test]
    fn two_semantic_faults_are_refused_for_the_earlier_one() {
        // The stage C order is the contract, not an artefact of how the checks
        // happen to be written, so each pair below carries two faults and is
        // asserted against the earlier one.
        let pair = keypair();
        let public_key = public_key_of(&pair);
        let hex = hex_of(&public_key);
        let derived = key_id(&public_key);

        // The `epoch` precedes the anchor list.
        let fields = Fields {
            epoch: Some("0".to_string()),
            ..Fields::anchored(&[])
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::AbsentEpoch
        ));

        // A wholly revoked list precedes the per-anchor checks.
        let fields = Fields::anchored(&[anchor_json("not hex", "not hex either", true)]);
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::AllAnchorsRevoked
        ));

        // Within an anchor: the `key_id` shape, then the `public_key` shape,
        // then the derivation, then duplication.
        let fields = Fields::anchored(&[anchor_json(&derived.to_uppercase(), "not hex", false)]);
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::MalformedKeyId { .. }
        ));
        let fields = Fields::anchored(&[anchor_json(STRANGER_KEY_ID, "not hex", false)]);
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::MalformedPublicKey { .. }
        ));
        let entry = anchor_json(STRANGER_KEY_ID, &hex, false);
        let fields = Fields::anchored(&[entry.clone(), entry]);
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::KeyIdMismatch { .. }
        ));

        // The anchors precede the withdrawn builds, and within a withdrawn
        // entry the identifier predicate precedes duplication.
        let withdrawn = withdrawn_json("example", "1.0.0", "abc");
        let fields = Fields {
            withdrawn_builds: Some(array(&[withdrawn.clone(), withdrawn])),
            ..Fields::anchored(&[anchor_json("not hex", &hex, false)])
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::MalformedKeyId { .. }
        ));
        let unsafe_entry = withdrawn_json("example", "-1.0.0", "abc");
        let fields = Fields {
            withdrawn_builds: Some(array(&[unsafe_entry.clone(), unsafe_entry])),
            ..Fields::new(&pair)
        };
        assert!(matches!(
            refusal(&fields.render()),
            TrustSetDocumentError::UnsafeBuildIdentifier { .. }
        ));
    }

    #[test]
    fn a_manifest_commit_that_is_not_the_member_digest_is_a_target_mismatch() {
        let pair = keypair();
        let member = default_document(&pair);
        let package = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &EPOCH.to_string(),
            STRANGER_COMMIT,
        );
        assert!(matches!(
            self_admit(&package, &member).expect_err("the container should be refused"),
            VerifyError::TargetMismatch { commit, .. } if commit == STRANGER_COMMIT
        ));
    }

    #[test]
    fn a_self_admission_still_refuses_a_container_naming_something_else() {
        let pair = keypair();
        let member = default_document(&pair);
        let digest = member_digest(&member);
        for package in [
            pkg_naming(&pair, &member, "example", &EPOCH.to_string(), &digest),
            pkg_naming(
                &pair,
                &member,
                TRUST_TARGET,
                &(EPOCH + 1).to_string(),
                &digest,
            ),
            pkg_naming(
                &pair,
                &member,
                TRUST_TARGET,
                &EPOCH.to_string(),
                STRANGER_COMMIT,
            ),
        ] {
            assert!(matches!(
                self_admit(&package, &member).expect_err("the container should be refused"),
                VerifyError::TargetMismatch { .. }
            ));
        }
    }

    #[test]
    fn only_the_self_admission_form_makes_a_generation_admissible_under_its_own_epoch() {
        let pair = keypair();
        let member = default_document(&pair);
        let package = generation_pkg(&pair, &member, EPOCH);

        self_admit(&package, &member).expect("a self-admission skips the epoch comparison");

        // The same input through the epoch-carrying form: the delivered epoch
        // and the candidate set's are one number, so the strictly-greater test
        // refuses every well-formed generation.
        let (trust, epoch) = candidate(&member);
        let request = VerifyRequest::for_trust(&epoch.to_string(), &member_digest(&member), epoch)
            .expect("a trust-target request");
        let refused = verify_package(Cursor::new(package.clone()), &trust, &request)
            .expect_err("the epoch-carrying form refuses it");
        assert!(matches!(
            refused,
            VerifyError::StaleTrustSet { delivered, active } if delivered == EPOCH && active == EPOCH
        ));
    }

    #[test]
    fn a_generation_signed_by_an_anchor_it_marks_revoked_is_refused_as_revoked() {
        // The candidate set is built from every anchor, so this is `RevokedKey`
        // rather than the `UnknownKeyId` a pruned list would have produced.
        let live = keypair();
        let revoked = keypair();
        let member =
            Fields::anchored(&[anchor_of(&live, false), anchor_of(&revoked, true)]).render();
        let package = generation_pkg(&revoked, &member, EPOCH);
        assert!(matches!(
            self_admit(&package, &member).expect_err("the generation should be refused"),
            VerifyError::RevokedKey { key_id: id } if id == key_id(&public_key_of(&revoked))
        ));
    }

    #[test]
    fn a_declared_manifest_floor_above_this_build_does_not_block_self_admission() {
        // The candidate set's floor is `0`, so a document declaring a floor its
        // own envelope could not satisfy does not brick itself.
        let pair = keypair();
        let member = Fields {
            min_manifest_format_version: Some((MAX_MANIFEST_FORMAT_VERSION + 1).to_string()),
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, EPOCH);
        self_admit(&package, &member).expect("the declared floor governs later packages only");
    }

    #[test]
    fn a_declared_withdrawn_list_does_not_govern_the_envelope_carrying_it() {
        // A document cannot literally name its own member digest — the digest is
        // over bytes that would then have to contain it — so the observation is
        // made against a container whose manifest names a `commit` the document
        // *can* state. The delivered list matches that triple exactly, and the
        // candidate set's empty list is what carries the container past
        // `check_withdrawal`: the refusal that does arrive is the target
        // disagreement one step later, never `WithdrawnBuild`.
        let pair = keypair();
        let member = Fields {
            withdrawn_builds: Some(array(&[withdrawn_json(
                TRUST_TARGET,
                &EPOCH.to_string(),
                STRANGER_COMMIT,
            )])),
            ..Fields::new(&pair)
        }
        .render();
        let package = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &EPOCH.to_string(),
            STRANGER_COMMIT,
        );
        assert!(matches!(
            self_admit(&package, &member).expect_err("the container should be refused"),
            VerifyError::TargetMismatch { .. }
        ));

        // And a document that withdraws an unrelated build self-admits whole.
        let member = Fields {
            withdrawn_builds: Some(array(&[withdrawn_json("example", "1.0.0", "abc")])),
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, EPOCH);
        self_admit(&package, &member).expect("the withdrawn list governs later packages only");
    }
}
