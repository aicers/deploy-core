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
//! [`TrustSet`] by value, so a caller admitting a
//! generation must already hold one when it calls — and for a first generation
//! the only anchors in existence are inside the delivered document. So the
//! admission path reads the member's bytes out of the container and decodes
//! part of it before anything has been authenticated. That is permitted, and it
//! is bounded; see
//! `VerifyRequest::for_trust_self_admission`,
//! whose documentation states the decode, the candidate trust set built from it
//! and the order of the call. This module is where the two live —
//! `provisional_anchors_and_epoch` and `self_admission_candidate`, one copy
//! each, so the installer's validator and every admission path built on it run
//! the same decode and verify against the same candidate set. (Both are
//! crate-private, so they are code spans rather than intra-doc links: this
//! module is public, and a public doc linking to a private item is
//! `rustdoc::private_intra_doc_links`.) It reads `anchors` and `epoch` and no
//! other field,
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
use crate::verify::{BuildIdentifier, TrustAnchor, TrustSet, is_safe_build_identifier, key_id};

/// The one `trust_set_version` this reader implements.
///
/// This is the document schema's own version and is **not** the manifest
/// `format_version` floor a document carries: the two version numbers move
/// independently, and conflating them would tie a schema addition here to a
/// manifest schema addition there.
pub(crate) const TRUST_SET_VERSION: u32 = 1;

/// Archive member the generation document is carried in.
///
/// Crate-internal because no caller outside this crate names it: a consumer
/// receives an already-verified [`TrustSetDocument`] from an entry point this
/// crate exports rather than reaching into a container itself.
///
/// It is also the basename the verified member is copied out under inside a
/// release-trust generation directory (see [`crate::release_trust`]), so the
/// member's name on the wire and its name on disk cannot drift apart.
pub(crate) const TRUST_SET_MEMBER: &str = "trust-set.json";

/// Number of ASCII characters 32 bytes rendered as lowercase hex is.
///
/// Both `key_id` and `public_key` are fixed-width lowercase hex, which makes
/// length and charset a single check and leaves no separate "decoded to the
/// wrong number of bytes" case: 64 lowercase hex characters **is** 32 bytes.
const HEX_32_LEN: usize = 64;

/// Name of the field the version gate reads, and the only field it types.
pub(crate) const TRUST_SET_VERSION_FIELD: &str = "trust_set_version";

/// Name of the epoch field, which the pre-verification decode reads too.
pub(crate) const EPOCH_FIELD: &str = "epoch";

/// Name of the anchor array, as both a decoded field and an unknown-field
/// location.
pub(crate) const ANCHORS_FIELD: &str = "anchors";

/// Name of an anchor entry's raw key field, which the pre-verification decode
/// reads too.
const PUBLIC_KEY_FIELD: &str = "public_key";

/// Name of an anchor entry's revocation flag, which the pre-verification decode
/// reads too.
const REVOKED_FIELD: &str = "revoked";

/// Name of the withdrawn-build array, on the same terms as [`ANCHORS_FIELD`].
pub(crate) const WITHDRAWN_BUILDS_FIELD: &str = "withdrawn_builds";

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
    EPOCH_FIELD,
    "min_manifest_format_version",
    ANCHORS_FIELD,
    WITHDRAWN_BUILDS_FIELD,
];

/// Every field an anchor entry may carry.
const ANCHOR_FIELDS: [&str; 3] = ["key_id", PUBLIC_KEY_FIELD, REVOKED_FIELD];

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
#[must_use]
pub(crate) fn member_digest(bytes: &[u8]) -> String {
    payload::sha256_hex(bytes)
}

/// Decodes the two fields a self-admission consumes out of document bytes
/// **nothing has vouched for yet**: every anchor's raw key and revocation flag,
/// and the `epoch`.
///
/// This is the one decode permitted before verification, and the crate has
/// exactly one copy of it — this one. Both the release-trust installer's
/// validator ([`crate::release_trust`]) and the install-time admission paths
/// built on top of it run *this* function rather than each writing the same
/// permissive parse, because two copies of it could disagree about which bytes
/// a candidate trust set was built from.
///
/// It is deliberately **not** [`read_trust_set_document`]: running the refusing
/// reader here would report a parse refusal where a signature failure belongs,
/// and would decide something about bytes no anchor has vouched for. An entry's
/// own `key_id` is not read at all — [`TrustAnchor::new`] derives the index from
/// the key, so there is no second derivation site to disagree with. Nothing it
/// produces is stored or becomes the generation; see
/// `VerifyRequest::for_trust_self_admission`.
///
/// Returns `None` — never a [`TrustSetDocumentError`], whose contract is "this
/// is what a *verified* document said" — when the bytes are not a JSON object,
/// when `epoch` is absent or is not an unsigned integer, when `anchors` is
/// absent or is not an array, or when any entry fails to yield 32 key bytes and
/// a boolean flag. The decode is all-or-nothing: a caller names that failure
/// with its own error type.
pub(crate) fn provisional_anchors_and_epoch(bytes: &[u8]) -> Option<(Vec<TrustAnchor>, u64)> {
    let document: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let epoch = document
        .get(EPOCH_FIELD)
        .and_then(serde_json::Value::as_u64)?;
    let entries = document
        .get(ANCHORS_FIELD)
        .and_then(serde_json::Value::as_array)?;
    let mut anchors = Vec::with_capacity(entries.len());
    for entry in entries {
        let public_key = entry
            .get(PUBLIC_KEY_FIELD)
            .and_then(serde_json::Value::as_str)
            .and_then(decode_lowercase_hex_32)?;
        let revoked = entry
            .get(REVOKED_FIELD)
            .and_then(serde_json::Value::as_bool)?;
        anchors.push(TrustAnchor::new(public_key, revoked));
    }
    Some((anchors, epoch))
}

/// Builds the candidate [`TrustSet`] a generation is self-admitted against, and
/// returns it beside the `epoch` the decode read.
///
/// The crate's only assembly of that value, so the installer's validator and the
/// admission paths cannot end up verifying against two different candidate sets.
/// All four [`TrustSet::new`] arguments are fixed here exactly as
/// `VerifyRequest::for_trust_self_admission` states them, and none is left to a
/// caller's discretion:
///
/// - `anchors` — **every** anchor [`provisional_anchors_and_epoch`] produced,
///   each carrying its own `revoked` flag, so a container signed by a key its
///   own document marks revoked is refused as
///   [`VerifyError::RevokedKey`](crate::verify::VerifyError::RevokedKey) rather
///   than by a pruned list as an unknown key;
/// - `withdrawn_builds` — **empty**, the identity of the withdrawal check. The
///   container carries exactly one triple, its own, so the delivered list could
///   only ever match a document withdrawing itself; that list governs every
///   *later* package instead;
/// - `min_manifest_format_version` — **`0`**, the identity of the manifest-floor
///   check, so a document declaring a floor above its own envelope's
///   `format_version` does not brick itself and admission turns on no integer
///   read from unauthenticated bytes;
/// - `epoch` — the decoded epoch, passed through unchanged. Under the
///   self-admission request form it is read by nothing, since the epoch
///   comparison returns early; it is passed through rather than zeroed so that
///   no number appears in the call that did not come from the document.
///
/// Returns `None` on the same terms as [`provisional_anchors_and_epoch`], plus
/// two anchors sharing a public key, which [`TrustSet::new`] refuses.
pub(crate) fn self_admission_candidate(bytes: &[u8]) -> Option<(TrustSet, u64)> {
    let (anchors, epoch) = provisional_anchors_and_epoch(bytes)?;
    let trust = TrustSet::new(anchors, Vec::new(), 0, epoch).ok()?;
    Some((trust, epoch))
}

/// Returns a **verified** document's anchors as the verifier's own values.
///
/// Unlike [`provisional_anchors_and_epoch`] this runs over a
/// [`TrustSetDocument`] that already passed [`read_trust_set_document`], so it
/// exists to convert rather than to parse. It returns `Option` all the same
/// because `public_key` is carried as text: `check_document` has already proved
/// every entry decodes, which makes `None` unreachable through the reader, and
/// an unreachable arm is answered by the caller rather than by a panic.
pub(crate) fn document_anchors(document: &TrustSetDocument) -> Option<Vec<TrustAnchor>> {
    document
        .anchors
        .iter()
        .map(|anchor| {
            decode_lowercase_hex_32(&anchor.public_key)
                .map(|public_key| TrustAnchor::new(public_key, anchor.revoked))
        })
        .collect()
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
    if let Some(field) = unknown_key(object, &TOP_LEVEL_FIELDS) {
        return Err(TrustSetDocumentError::UnknownField {
            location: DOCUMENT_LOCATION.to_string(),
            field,
        });
    }
    check_entry_keys(object, ANCHORS_FIELD, &ANCHOR_FIELDS)?;
    check_entry_keys(object, WITHDRAWN_BUILDS_FIELD, &WITHDRAWN_BUILD_FIELDS)
}

/// Returns the first key of `object` that is not in `known`.
///
/// The name alone, so a caller names the location it found it in and nothing is
/// rendered on the path where every key is known.
fn unknown_key(
    object: &serde_json::Map<String, serde_json::Value>,
    known: &[&str],
) -> Option<String> {
    object
        .keys()
        .find(|field| !known.contains(&field.as_str()))
        .cloned()
}

/// Applies [`unknown_key`] to each object entry of `object`'s `array_field`.
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
        if let Some(field) = unknown_key(entry, known) {
            return Err(TrustSetDocumentError::UnknownField {
                location: format!("`{array_field}` entry {index}"),
                field,
            });
        }
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

    use super::*;
    use crate::manifest::{MAX_MANIFEST_FORMAT_VERSION, MIN_MANIFEST_FORMAT_VERSION};
    // The signed single-member container fixture lives beside this module rather
    // than inside it: `crate::release_trust`'s tests mint exactly the same
    // container, and the install-time admission paths built on them will too.
    use crate::trust_fixture::{
        EPOCH, Fields, anchor_json, anchor_of, array, default_document, generation_pkg, hex_of,
        keypair, pkg_naming, public_key_of, withdrawn_json,
    };
    use crate::verify::{
        TRUST_TARGET, VerifiedPackage, VerifyError, VerifyRequest, verify_package,
    };

    /// A `key_id`-shaped value no fixture key derives.
    const STRANGER_KEY_ID: &str =
        "abababababababababababababababababababababababababababababababab";
    /// A `commit`-shaped value that is not any fixture member's digest.
    const STRANGER_COMMIT: &str =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    /// Reads `bytes`, asserting they are refused, and returns the refusal.
    fn refusal(bytes: &[u8]) -> TrustSetDocumentError {
        read_trust_set_document(bytes).expect_err("the document should be refused")
    }

    /// Reads `bytes`, asserting they are accepted.
    fn accepted(bytes: &[u8]) -> TrustSetDocument {
        read_trust_set_document(bytes).expect("the document should be read")
    }

    /// Verifies `package` as a self-admission of the generation `member`
    /// carries, in the order the request form states.
    ///
    /// The candidate set is `self_admission_candidate`'s and not one assembled
    /// here, so this exercises the very value the release-trust installer's
    /// validator verifies against rather than a second copy of it.
    fn self_admit(
        package: &[u8],
        member: &[u8],
    ) -> Result<VerifiedPackage<Cursor<Vec<u8>>>, VerifyError> {
        let (trust, epoch) =
            self_admission_candidate(member).expect("a fixture document decodes provisionally");
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
    fn a_generation_carrying_withdrawn_builds_round_trips_them_in_order() {
        // The accepted path, not a refusal: a well-formed entry must reach the
        // caller with its three identity fields on the fields they were written
        // as, in the order the document listed them, since the verifier
        // compares the triples as exact strings.
        let pair = keypair();
        let member = Fields {
            withdrawn_builds: Some(array(&[
                withdrawn_json("example", "1.0.0", "abc"),
                withdrawn_json("other", "2.0.0+build", "def"),
            ])),
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, EPOCH);
        self_admit(&package, &member).expect("the generation should verify");

        let document = accepted(&member);
        assert_eq!(
            document.withdrawn_builds,
            vec![
                WithdrawnBuild {
                    package_id: "example".to_string(),
                    version: "1.0.0".to_string(),
                    commit: "abc".to_string(),
                },
                WithdrawnBuild {
                    package_id: "other".to_string(),
                    version: "2.0.0+build".to_string(),
                    commit: "def".to_string(),
                },
            ]
        );
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
    fn an_array_field_that_is_not_an_array_of_objects_is_a_decode_refusal() {
        // The unknown-field check leaves both shapes alone on purpose: there is
        // no key set to compare, they are structural faults, and the decode is
        // what names them.
        let pair = keypair();
        for anchors in ["{}", "[3]"] {
            let fields = Fields {
                anchors: Some(anchors.to_string()),
                ..Fields::new(&pair)
            };
            assert!(
                matches!(refusal(&fields.render()), TrustSetDocumentError::Decode(_)),
                "anchors {anchors} should be a decode refusal"
            );
        }
    }

    #[test]
    fn numeric_fields_are_refused_rather_than_coerced() {
        let pair = keypair();
        // A negative `epoch`, a fractional one and an over-wide one; a
        // negative, fractional and over-wide manifest floor, and a floor
        // written as a string or as `null`: serde's own integer
        // deserialization refuses every one of them, and none of them reaches
        // the semantic checks as a coerced value.
        for fields in [
            Fields {
                epoch: Some("-1".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                epoch: Some("7.5".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                epoch: Some("18446744073709551616".to_string()),
                ..Fields::new(&pair)
            },
            Fields {
                min_manifest_format_version: Some("-1".to_string()),
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
        let (trust, epoch) =
            self_admission_candidate(&member).expect("a fixture document decodes provisionally");
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
