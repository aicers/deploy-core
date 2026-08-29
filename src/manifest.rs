//! Product and component manifest types.
//!
//! A manifest describes which components make up a product stack (for example
//! Bootroot + `REview` + aice-web-next for Clumit Security) together with their
//! versions and per-product namespaces. That broader product/component manifest
//! format is still reserved space; this module currently defines the **payload
//! manifest** that describes the artifacts carried in a bootler payload trailer
//! (see the `payload` module and RFC 0001 §3).
//!
//! The payload manifest lives here rather than in `payload` so the same format
//! can later serve both the bootler payload and the Roxyd module-package path.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::module_spec::{ModuleSpec, ModuleSpecError};

/// `format_version` a producer stamps into every manifest it writes.
///
/// Stamped unconditionally, never derived from a manifest's contents: a
/// manifest's version is the producer's, not a function of which optional
/// variables its templates happen to name.
pub const MANIFEST_FORMAT_VERSION: u32 = 5;

/// Inclusive floor of the `format_version` range this build accepts.
///
/// Behind [`MANIFEST_FORMAT_VERSION`] because the schema growth since is
/// **additive**: a manifest written at this floor is exactly what an earlier
/// build of this crate produced, and it decodes, validates and renders here
/// unchanged. Moving the floor to meet the producer would make every already
/// published payload at it unreadable and force a republish of release assets
/// that are otherwise correct, so it moves only for a change an older manifest
/// genuinely cannot express.
pub const MIN_MANIFEST_FORMAT_VERSION: u32 = 3;

/// Inclusive ceiling of the `format_version` range this build accepts.
///
/// Tracks [`MANIFEST_FORMAT_VERSION`]: this build reads what it writes, and a
/// manifest naming anything newer is refused for its version alone rather than
/// failing as an opaque decode error somewhere inside it.
pub const MAX_MANIFEST_FORMAT_VERSION: u32 = 5;

/// Container footer version the pre-versioned baseline payloads were written
/// at.
///
/// Frozen to the literal `1` on purpose: it is neither an alias of the
/// `payload` module's `FORMAT_VERSION` nor a comparison against it. That
/// constant moves when the container layout grows, and a baseline path written
/// against it would follow the bump forward and become reachable by a package
/// written at the newer container version — the exact bypass the conjunction in
/// `is_pre_versioned_baseline` exists to prevent.
pub const LEGACY_UNVERSIONED_FOOTER_VERSION: u8 = 1;

/// Number of hex characters in a full git commit SHA-1.
pub const GIT_COMMIT_HEX_LEN: usize = 40;

/// Number of hex characters in a container image digest with its `sha256:`
/// prefix stripped.
pub const IMAGE_DIGEST_HEX_LEN: usize = 64;

/// Target CPU architecture a payload artifact is built for.
///
/// One release binary is produced per target architecture (RFC 0001 §3), so the
/// set is finite and modelled as an enum rather than a free string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TargetArch {
    /// 64-bit x86 (`x86_64`).
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64-bit ARM (`aarch64`).
    #[serde(rename = "aarch64")]
    Aarch64,
}

/// Kind of artifact a payload entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// A standalone executable installed directly on a host.
    NativeBinary,
    /// A container image loaded from a `docker save` tarball.
    ContainerImage,
    /// A compose stack (compose file plus its referenced images).
    ComposeBundle,
    /// A bundle of static assets (for example a web front end).
    StaticAssets,
}

/// What bootler does with an artifact on a target.
///
/// An artifact carries one or more dispositions; the empty set is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// bootler installs the artifact on a placement host.
    Install,
    /// bootler places the artifact in `REview`'s module store for later
    /// distribution.
    Stage,
}

/// One entry in a payload manifest: a single artifact and where its bytes live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadArtifact {
    /// Component the artifact belongs to (for example `roxyd`).
    pub component: String,
    /// Version string of the built component.
    pub version: String,
    /// Immutable build identity of the artifact: a full 40-hex git commit SHA
    /// for an artifact built from a clone, or a 64-hex image digest with its
    /// `sha256:` prefix stripped for a third-party container image (see
    /// [`is_valid_commit`]).
    ///
    /// `None` only on an artifact read off a pre-versioned baseline payload
    /// (see [`PayloadManifest::parse`]); it is never synthesized and never
    /// given a sentinel, because a placeholder would collapse every legacy
    /// build of a component onto one store key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Architecture the artifact is built for.
    pub target_arch: TargetArch,
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// One or more dispositions; the empty set is invalid.
    pub dispositions: BTreeSet<Disposition>,
    /// Path of this artifact's member inside the tar archive. Must be a safe
    /// relative path and unique within a manifest.
    pub archive_path: String,
    /// Lowercase hex SHA-256 over the artifact bytes, verified on extraction.
    pub sha256: String,
    /// How this artifact is installed, declared by the package itself rather
    /// than hardcoded per component by an engine.
    ///
    /// Optional per artifact: `None` means the package declares nothing and a
    /// consumer falls back to whatever it did before, which is the state every
    /// artifact shipping today is in. When present it is validated by
    /// [`crate::module_spec::validate`] on every read path, so a malformed spec
    /// never reaches the root daemon that executes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<ModuleSpec>,
}

/// One member of the archive block, named and sized as the archive stores it.
///
/// The ordered list of these is what binds the archive's *shape* to the
/// manifest: how many members it holds, what they are called, in what order, and
/// how long each one is. Every other manifest field is per-artifact, so without
/// this list the enumeration is only ever *derived* — from a reader's own
/// cross-checks agreeing — rather than stated by the producer and covered by
/// whatever eventually signs the manifest block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveMember {
    /// Member's stored name in the archive, byte-for-byte as the reader
    /// resolves it — the same string an artifact's `archive_path` is matched
    /// against, and identical to the raw `ustar` header name because a member
    /// whose two names disagree is already refused.
    pub name: String,
    /// Member's **uncompressed** data byte length: the `tar` entry's data size.
    ///
    /// Deliberately not a compressed size. The archive block is one `zstd`
    /// stream, so a per-member compressed length is not well defined.
    pub length: u64,
}

/// Errors raised while validating a payload manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// An artifact carried no dispositions.
    #[error("artifact `{0}` has an empty disposition set")]
    EmptyDispositions(String),
    /// Two artifacts shared the same `archive_path`.
    #[error("duplicate archive path `{0}`")]
    DuplicateArchivePath(String),
    /// An artifact used an unsafe `archive_path` — absolute, containing a `..`
    /// or `.` component, or with no normal component.
    #[error("unsafe archive path `{0}`")]
    UnsafeArchivePath(String),
    /// The manifest block was not decodable JSON, or its body did not match the
    /// shape this build expects. Distinct from
    /// [`ManifestError::UnsupportedManifestFormat`]: the manifest declared a
    /// version this build implements and still failed to decode.
    #[error("failed to decode payload manifest: {0}")]
    Decode(#[source] serde_json::Error),
    /// The manifest carried no `format_version` and did not match the
    /// pre-versioned baseline shape.
    #[error("payload manifest carries no `format_version`")]
    MissingFormatVersion,
    /// `format_version` was present but was not a `u32` — a string, a float, a
    /// negative number, or an integer too large for the field. Like
    /// [`ManifestError::UnsupportedManifestFormat`] this is a refusal made from
    /// the version alone, before the body is decoded; it is separate because no
    /// `found: u32` can carry the offending value.
    #[error("payload manifest `format_version` is not a 32-bit unsigned integer")]
    MalformedFormatVersion,
    /// The manifest declared a `format_version` outside the range this build
    /// implements.
    #[error("unsupported manifest format version {found} (this build accepts {min}..={max})")]
    UnsupportedManifestFormat {
        /// Version read from the manifest.
        found: u32,
        /// Inclusive floor this build accepts.
        min: u32,
        /// Inclusive ceiling this build accepts.
        max: u32,
    },
    /// An artifact in a current-format manifest carried no `commit`.
    #[error("artifact `{0}` carries no `commit`")]
    MissingCommit(String),
    /// A current-format manifest carried no `archive_members`, so it states
    /// nothing about the archive block's shape.
    #[error("payload manifest carries no `archive_members`")]
    MissingArchiveMembers,
    /// An artifact's `commit` was not a 40- or 64-character lowercase-hex
    /// identifier (see [`is_valid_commit`]).
    #[error("artifact `{archive_path}` has an invalid `commit` identifier `{commit}`")]
    InvalidCommit {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The rejected identifier.
        commit: String,
    },
    /// A manifest carrying no `format_version` had an artifact with a `commit`,
    /// so it is not the pre-versioned baseline shape.
    #[error("manifest carries no `format_version` yet artifact `{0}` carries a `commit`")]
    BaselineWithCommit(String),
    /// A manifest carrying no `format_version` had an artifact with a `spec`,
    /// so it is not the pre-versioned baseline shape.
    #[error("manifest carries no `format_version` yet artifact `{0}` carries a `spec`")]
    BaselineWithSpec(String),
    /// A manifest carrying no `format_version` had a `trust_set`, so it is not
    /// the pre-versioned baseline shape.
    #[error("manifest carries no `format_version` yet carries a `trust_set`")]
    BaselineWithTrustSet,
    /// A manifest carrying no `format_version` had an `archive_members`, so it
    /// is not the pre-versioned baseline shape.
    #[error("manifest carries no `format_version` yet carries an `archive_members`")]
    BaselineWithArchiveMembers,
    /// An artifact declared a [`ModuleSpec`] that violates a spec rule.
    #[error("artifact `{archive_path}` declares an invalid spec")]
    InvalidSpec {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The rule that was violated.
        #[source]
        source: ModuleSpecError,
    },
    /// The `trust_set` value was not valid base64.
    #[error("manifest `trust_set` is not valid base64: {0}")]
    TrustSetNotBase64(#[source] base64::DecodeError),
    /// The `trust_set` value decoded to zero bytes.
    #[error("manifest `trust_set` decodes to zero bytes")]
    EmptyTrustSet,
}

/// Reports whether `value` is a valid artifact build identifier: exactly
/// [`GIT_COMMIT_HEX_LEN`] or exactly [`IMAGE_DIGEST_HEX_LEN`] lowercase-hex
/// characters.
///
/// Both shapes are path-safe canonical identifiers, which is what lets
/// `(package-id, version, commit)` serve as a module-store key and a
/// withdrawn-build key. Every other length is rejected, so an abbreviation such
/// as `abc1234` is not a valid `commit` anywhere in the ecosystem; uppercase hex
/// is rejected too, so one build has exactly one identifier.
///
/// A producer legitimately accepts only one of the two widths per artifact — an
/// artifact built from a clone is always the git width, a third-party image
/// always the digest width — and narrows using the two constants rather than
/// restating the literals.
#[must_use]
pub fn is_valid_commit(value: &str) -> bool {
    if value.len() != GIT_COMMIT_HEX_LEN && value.len() != IMAGE_DIGEST_HEX_LEN {
        return false;
    }
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Reports whether `path` is a safe, canonical relative archive path: it is
/// relative and made up solely of plain name segments — no empty, `.`, or `..`
/// segment, and no OS-absolute or platform-prefix root.
///
/// The reader applies the same rule to untrusted tar members on extraction, so
/// enforcing it here keeps a validated [`PayloadManifest`] free of paths that
/// could escape an extraction root. Rejecting `.` segments additionally keeps
/// the manifest path byte-identical to the archive member the tar writer
/// stores: the `tar` crate normalizes `.` segments away, so a path like
/// `./bin/roxyd` (or `bin/./roxyd`) would be recorded in the manifest yet
/// stored as `bin/roxyd`, breaking the deterministic manifest-to-member
/// mapping. The raw `/`-separated segments are inspected directly rather than
/// [`Path::components`], which itself normalizes interior `.` away.
#[must_use]
pub fn is_safe_archive_path(path: &str) -> bool {
    // Reject OS-absolute paths and platform prefixes (e.g. a Windows drive or
    // UNC root) that a segment scan alone would miss.
    if Path::new(path).components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return false;
    }
    path.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Wire codec for the `trust_set` field: standard-alphabet base64 with padding,
/// over the opaque signed generation container bytes.
///
/// The engine is the one [`crate::roxyd_trust`] already uses, so the crate
/// carries exactly one base64 convention and no new dependency.
mod trust_set_codec {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::Serializer;

    use super::ManifestError;

    // `serialize_with` hands the field by reference, so `&Option<Vec<u8>>` is
    // the signature serde dictates rather than one this crate chose.
    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&STANDARD.encode(bytes)),
            // Unreachable through `PayloadManifest`, which skips the field when
            // it is `None`; kept total so the codec cannot be a second door.
            None => serializer.serialize_none(),
        }
    }

    /// Decodes the wire string into the container bytes.
    ///
    /// The wire form is decoded here rather than in a `Deserialize` impl so an
    /// undecodable value surfaces as a [`ManifestError`] variant of its own
    /// rather than a generic serde error.
    pub(super) fn decode(value: Option<&str>) -> Result<Option<Vec<u8>>, ManifestError> {
        value
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .map_err(ManifestError::TrustSetNotBase64)
            })
            .transpose()
    }
}

/// The whole payload trailer manifest: the schema version, the pin-set digest
/// the payload was built from, the release-signing trust-set generation the
/// installer seeds from, the ordered archive member list, plus an ordered list
/// of artifacts.
///
/// Constructed through [`PayloadManifest::new`], which enforces the manifest
/// invariants (non-empty dispositions, unique `archive_path`, a valid `commit`
/// per artifact). Deserialization runs the same validation, so a manifest read
/// back from JSON is always valid.
///
/// This is the one validated type that models `archive_members`, and it models
/// it as an `Option` so the pre-versioned baseline shape — the only shape that
/// carries no list — remains expressible. Nothing downstream re-models it: a
/// second optional member list is a second place that could disagree about what
/// absence means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawManifest")]
pub struct PayloadManifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    format_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pinset: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "trust_set_codec::serialize"
    )]
    trust_set: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_members: Option<Vec<ArchiveMember>>,
    artifacts: Vec<PayloadArtifact>,
}

/// Unvalidated wire form used only as the deserialization source.
///
/// `pinset` is `#[serde(default)]` rather than required, and no
/// `deny_unknown_fields` is set, so the two directions of format skew both read
/// cleanly: a payload published before the stamp existed still parses (its
/// absence is reported by `verify-manifest` as an actionable mismatch, not a
/// serde error, and the install path — which shares this parsing — is unaffected),
/// and a reader predating the field ignores it.
///
/// `format_version` is `#[serde(default)]` here so the raw form can express its
/// absence, but [`TryFrom<RawManifest>`] rejects that absence unconditionally: a
/// `Deserialize` impl cannot see the container footer, so it cannot evaluate the
/// baseline conjunction and must not become a laxer second door into the
/// baseline shape. The only door is [`PayloadManifest::parse`].
///
/// `trust_set` is carried as its wire string rather than decoded bytes so an
/// undecodable value is reported as a [`ManifestError`], not a serde error.
///
/// `archive_members` is `#[serde(default)]` for the same reason
/// `format_version` is: the unvalidated wire form has to be able to *see* the
/// key's absence in order to reject it. That is not a second validated type
/// modelling the field — validation happens in `from_parts`, where an absent
/// list on a versioned manifest is [`ManifestError::MissingArchiveMembers`].
#[derive(Deserialize)]
struct RawManifest {
    #[serde(default)]
    format_version: Option<u32>,
    #[serde(default)]
    pinset: Option<String>,
    #[serde(default)]
    trust_set: Option<String>,
    #[serde(default)]
    archive_members: Option<Vec<ArchiveMember>>,
    artifacts: Vec<PayloadArtifact>,
}

impl TryFrom<RawManifest> for PayloadManifest {
    type Error = ManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, Self::Error> {
        let format_version = raw
            .format_version
            .ok_or(ManifestError::MissingFormatVersion)?;
        let trust_set = trust_set_codec::decode(raw.trust_set.as_deref())?;
        Self::from_parts(
            Some(format_version),
            raw.pinset,
            raw.archive_members,
            raw.artifacts,
            trust_set,
        )
    }
}

/// Reads `format_version` off the stage-1 generic document.
///
/// A missing key and an explicit `null` both read as absent, matching how the
/// typed decode treats them, so the two stages cannot disagree about which
/// manifests are unversioned. This is the opposite reading from the presence-only
/// fingerprint terms in [`artifact_with_key`] and [`has_trust_set`], and it is
/// the safe direction for each: null-as-absent here routes the manifest *into*
/// the strict baseline conjunction, where null-as-absent would have widened it.
fn read_format_version(document: &serde_json::Value) -> Result<Option<u32>, ManifestError> {
    match document.get("format_version") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|found| u32::try_from(found).ok())
            .map(Some)
            .ok_or(ManifestError::MalformedFormatVersion),
    }
}

/// Reads the `format_version` a manifest block declares, running **stage one**
/// of [`PayloadManifest::parse`] and nothing else.
///
/// A verifier has to decide the version question before the body is decoded and
/// before it applies a floor of its own, which is a decision the two-stage parse
/// makes internally and reports only as a rejection. This exposes the same
/// stage-one reading rather than letting a second caller decode the document its
/// own way: an explicit `null` reads as absent here exactly as it does there, so
/// the two cannot disagree about which manifests are unversioned.
///
/// # Errors
///
/// Returns [`ManifestError::Decode`] when the block is not decodable JSON, and
/// [`ManifestError::MalformedFormatVersion`] when the key is present but is not
/// a `u32`.
pub(crate) fn parse_format_version(manifest_bytes: &[u8]) -> Result<Option<u32>, ManifestError> {
    let document: serde_json::Value =
        serde_json::from_slice(manifest_bytes).map_err(ManifestError::Decode)?;
    read_format_version(&document)
}

/// Returns the `archive_path` of the first artifact in the stage-1 document
/// carrying `key`, or its index when that entry has no string `archive_path`.
///
/// Only the presence of the key is read, never its value: an explicit
/// `"commit": null` or `"spec": null` counts as carrying it. The baseline terms
/// do not ask what an artifact declares, they ask whether the document was
/// written by a producer that knew about the schema bump — and every field of
/// that bump is `skip_serializing_if = "Option::is_none"`, so a pre-bump
/// producer could not have emitted the key in any form. The key itself is the
/// fingerprint. This is why the stage-2 decode still reads a `null` value as
/// absence and the two are not in conflict: they answer different questions.
fn artifact_with_key(document: &serde_json::Value, key: &str) -> Option<String> {
    let artifacts = document.get("artifacts")?.as_array()?;
    artifacts.iter().enumerate().find_map(|(index, artifact)| {
        artifact.get(key)?;
        Some(
            artifact
                .get("archive_path")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| format!("#{index}"), str::to_string),
        )
    })
}

/// Returns the `archive_path` of the first artifact carrying a `commit`.
fn artifact_with_commit(document: &serde_json::Value) -> Option<String> {
    artifact_with_key(document, "commit")
}

/// Returns the `archive_path` of the first artifact carrying a `spec`.
///
/// `spec` lands in the same schema bump as `commit` and `trust_set`, so it is a
/// term of the baseline conjunction on exactly the same grounds and reads
/// presence only, through the same helper.
fn artifact_with_spec(document: &serde_json::Value) -> Option<String> {
    artifact_with_key(document, "spec")
}

/// Reports whether the stage-1 `document` carries a `trust_set`. Presence only,
/// on the same grounds as [`artifact_with_key`], so all four fingerprint terms
/// of the conjunction read the document the same way.
fn has_trust_set(document: &serde_json::Value) -> bool {
    document.get("trust_set").is_some()
}

/// Reports whether the stage-1 `document` carries an `archive_members`, read
/// exactly as [`has_trust_set`] reads its key: presence alone, an explicit
/// `null` counting as carrying it.
fn has_archive_members(document: &serde_json::Value) -> bool {
    document.get("archive_members").is_some()
}

/// Reports whether a manifest is the pre-existing, pre-versioned baseline: it
/// carries no `format_version`, no artifact `commit`, no `trust_set`, no
/// artifact `spec` and no `archive_members`, and it sits in a container whose
/// footer version is [`LEGACY_UNVERSIONED_FOOTER_VERSION`].
///
/// The core payloads already published as release assets were assembled before
/// any of those fields existed, and a required CI preflight reads exactly
/// those assets, so they have to keep opening. The allowance is a conjunction
/// rather than "any manifest missing `format_version`" precisely so it cannot
/// widen: every field of a schema bump lands together, so a manifest carrying
/// one of them without `format_version` was never written by a producer and is
/// corrupt or hand-edited. `spec` is a term for that reason and for one more:
/// without it, a hand-edited manifest could hand a root daemon an instruction
/// set that bypassed the version gate entirely. `archive_members` is a term for
/// that reason and for one more too: an unversioned manifest carrying a member
/// list would otherwise reach the path where the member-list check is skipped,
/// leaving the list either honoured or dropped depending on how the parse
/// happens to be written.
///
/// Note the asymmetry this does *not* create: a `trust_set` on a current-format
/// manifest is normal, and its absence is normal on every manifest — only its
/// presence *without* `format_version` is a rejection.
///
/// **Removal condition**: this predicate, [`LEGACY_UNVERSIONED_FOOTER_VERSION`]
/// and the `Option` on `format_version` and `PayloadArtifact::commit` all go
/// away once every published payload a supported release can be asked to read
/// has been rebuilt at [`MANIFEST_FORMAT_VERSION`] or later.
fn is_pre_versioned_baseline(footer_version: u8, document: &serde_json::Value) -> bool {
    document
        .get("format_version")
        .is_none_or(serde_json::Value::is_null)
        && footer_version == LEGACY_UNVERSIONED_FOOTER_VERSION
        && artifact_with_commit(document).is_none()
        && !has_trust_set(document)
        && artifact_with_spec(document).is_none()
        && !has_archive_members(document)
}

/// Names which field made an unversioned manifest fail the baseline
/// conjunction, so a hand-edited manifest is actionable rather than reported as
/// a bare missing `format_version`.
fn non_baseline_reason(document: &serde_json::Value) -> ManifestError {
    if let Some(archive_path) = artifact_with_commit(document) {
        ManifestError::BaselineWithCommit(archive_path)
    } else if has_trust_set(document) {
        ManifestError::BaselineWithTrustSet
    } else if let Some(archive_path) = artifact_with_spec(document) {
        ManifestError::BaselineWithSpec(archive_path)
    } else if has_archive_members(document) {
        ManifestError::BaselineWithArchiveMembers
    } else {
        ManifestError::MissingFormatVersion
    }
}

impl PayloadManifest {
    /// Creates a manifest at [`MANIFEST_FORMAT_VERSION`], rejecting an empty
    /// disposition set, a duplicate `archive_path`, or an artifact with a
    /// missing or malformed `commit`.
    ///
    /// `pinset` is the `bootler.pinset.v1` digest of the recipe the payload was
    /// assembled from; `None` records a payload built before the stamp existed.
    ///
    /// This is the *producer* constructor: it stamps the format version itself
    /// rather than taking one, so no call site chooses a version, and it cannot
    /// express a pre-versioned baseline manifest. The trust-set generation is
    /// attached afterwards through [`PayloadManifest::with_trust_set`].
    ///
    /// `archive_members` is an ordinary required parameter, and it is required
    /// because every constructor routes through the one validation point, where
    /// a versioned manifest carrying no member list is refused — a constructor
    /// that could not be given one could never return a valid manifest. A
    /// hand-assembled manifest is paired with no archive, so a list it carries
    /// misdescribes nothing; a list becomes a claim about real bytes only when
    /// an archive is written, and
    /// [`append_trailer`](crate::payload::append_trailer) derives its own there
    /// rather than accepting one.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when an artifact carries no dispositions, uses
    /// an unsafe `archive_path`, shares an `archive_path` with another artifact,
    /// carries no valid `commit`, or declares a [`ModuleSpec`] that violates a
    /// spec rule.
    pub fn new(
        pinset: Option<String>,
        archive_members: Vec<ArchiveMember>,
        artifacts: Vec<PayloadArtifact>,
    ) -> Result<Self, ManifestError> {
        Self::from_parts(
            Some(MANIFEST_FORMAT_VERSION),
            pinset,
            Some(archive_members),
            artifacts,
            None,
        )
    }

    /// Attaches the signed trust-set generation container `generation` carries,
    /// returning the manifest.
    ///
    /// The bytes are stored verbatim and opaquely: this crate checks only that
    /// they are non-empty (and, on the read side, that they decoded as base64).
    /// It does not open the container, check its signature, parse the document,
    /// or read its `epoch` — that is the shared verifier's and the seeding
    /// path's work.
    ///
    /// This is the only way to attach a value, so the producer path runs the
    /// same rejection as the read path.
    ///
    /// It takes no member-list parameter: it consumes a manifest that already
    /// carries a list and forwards that field unchanged, exactly as it forwards
    /// `format_version`, `pinset` and `artifacts`. A parameter here would let a
    /// caller replace the list an already-validated manifest holds.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::EmptyTrustSet`] when `generation` is empty, or
    /// [`ManifestError::BaselineWithTrustSet`] when applied to a manifest read
    /// off the pre-versioned baseline path.
    pub fn with_trust_set(self, generation: &[u8]) -> Result<Self, ManifestError> {
        Self::from_parts(
            self.format_version,
            self.pinset,
            self.archive_members,
            self.artifacts,
            Some(generation.to_vec()),
        )
    }

    /// Reads a manifest block that sits in a container whose footer declared
    /// `footer_version`.
    ///
    /// This is a two-stage parse, and that is the contract rather than an
    /// implementation detail. **Stage 1** decodes the block into a permissive
    /// generic document and reads `format_version`; when it is present the range
    /// decision is made from that value alone, before any other key is inspected
    /// and before the typed decode, so a future manifest whose *body* this build
    /// cannot make sense of is refused for its version rather than as a generic
    /// decode error. When it is absent there is no version to gate, and stage 1
    /// additionally reads the presence flags
    /// `is_pre_versioned_baseline` takes — whether any artifact carries a
    /// `commit` or a `spec`, and whether a `trust_set` or an `archive_members`
    /// is present — which is the one
    /// sanctioned exception to the version-gate rule. **Stage 2** decodes the
    /// typed manifest, and only once a decision has been made.
    ///
    /// This is the only door in the crate that can return a manifest whose
    /// [`PayloadManifest::format_version`] or
    /// [`PayloadManifest::archive_members`] is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Decode`] when the block is not decodable JSON or
    /// its body does not match the shape this build expects,
    /// [`ManifestError::UnsupportedManifestFormat`] when `format_version` falls
    /// outside [`MIN_MANIFEST_FORMAT_VERSION`]`..=`[`MAX_MANIFEST_FORMAT_VERSION`],
    /// [`ManifestError::MissingFormatVersion`],
    /// [`ManifestError::BaselineWithCommit`],
    /// [`ManifestError::BaselineWithSpec`],
    /// [`ManifestError::BaselineWithTrustSet`] or
    /// [`ManifestError::BaselineWithArchiveMembers`] when an unversioned
    /// manifest is not the baseline shape,
    /// [`ManifestError::MissingArchiveMembers`] when a manifest carries a
    /// `format_version` but binds no member list, or any validation error
    /// [`PayloadManifest::new`] raises.
    ///
    /// [`ManifestError::MissingArchiveMembers`] is not among the errors that
    /// closing catch-all covers: [`PayloadManifest::new`] takes its member list
    /// as a required non-`Option` parameter, so it can never be handed the
    /// shape that refusal rejects. Both halves of the field's rule are raised
    /// on the read side instead — a versioned manifest binding no list here and
    /// in the derived `Deserialize`, both of which validate through the same
    /// place, and a baseline one binding a list only here, since `Deserialize`
    /// refuses an absent `format_version` before any baseline check.
    pub fn parse(manifest_bytes: &[u8], footer_version: u8) -> Result<Self, ManifestError> {
        let document: serde_json::Value =
            serde_json::from_slice(manifest_bytes).map_err(ManifestError::Decode)?;

        let format_version = read_format_version(&document)?;
        if let Some(found) = format_version {
            // The range decision is made from this value alone, before any
            // other key is inspected and before the typed decode.
            if !(MIN_MANIFEST_FORMAT_VERSION..=MAX_MANIFEST_FORMAT_VERSION).contains(&found) {
                return Err(ManifestError::UnsupportedManifestFormat {
                    found,
                    min: MIN_MANIFEST_FORMAT_VERSION,
                    max: MAX_MANIFEST_FORMAT_VERSION,
                });
            }
        } else if !is_pre_versioned_baseline(footer_version, &document) {
            // Only on the absent-`format_version` path does stage 1 read the
            // extra presence flags the baseline predicate takes.
            return Err(non_baseline_reason(&document));
        }

        let raw: RawManifest = serde_json::from_value(document).map_err(ManifestError::Decode)?;
        let trust_set = trust_set_codec::decode(raw.trust_set.as_deref())?;
        Self::from_parts(
            format_version,
            raw.pinset,
            raw.archive_members,
            raw.artifacts,
            trust_set,
        )
    }

    /// Validates and assembles a manifest from its parts.
    ///
    /// Private on purpose: it is the one place the invariants live, and every
    /// public constructor — the producer [`PayloadManifest::new`], the builder
    /// [`PayloadManifest::with_trust_set`], the read-side
    /// [`PayloadManifest::parse`], and the derived `Deserialize` — routes
    /// through it, so none of them can validate differently from another.
    fn from_parts(
        format_version: Option<u32>,
        pinset: Option<String>,
        archive_members: Option<Vec<ArchiveMember>>,
        artifacts: Vec<PayloadArtifact>,
        trust_set: Option<Vec<u8>>,
    ) -> Result<Self, ManifestError> {
        if let Some(found) = format_version
            && !(MIN_MANIFEST_FORMAT_VERSION..=MAX_MANIFEST_FORMAT_VERSION).contains(&found)
        {
            return Err(ManifestError::UnsupportedManifestFormat {
                found,
                min: MIN_MANIFEST_FORMAT_VERSION,
                max: MAX_MANIFEST_FORMAT_VERSION,
            });
        }

        // The same conditional shape `MissingCommit` is raised under, so the
        // two doors that reach this point — `TryFrom<RawManifest>`, which
        // cannot see the container footer, and `PayloadManifest::parse` — are
        // equally strict with one implementation. `None` therefore means the
        // pre-existing-baseline path and nothing else.
        match (&archive_members, format_version) {
            (None, Some(_)) => return Err(ManifestError::MissingArchiveMembers),
            (Some(_), None) => return Err(ManifestError::BaselineWithArchiveMembers),
            _ => {}
        }

        let mut seen = BTreeSet::new();
        for artifact in &artifacts {
            if artifact.dispositions.is_empty() {
                return Err(ManifestError::EmptyDispositions(
                    artifact.archive_path.clone(),
                ));
            }
            if !is_safe_archive_path(&artifact.archive_path) {
                return Err(ManifestError::UnsafeArchivePath(
                    artifact.archive_path.clone(),
                ));
            }
            if !seen.insert(artifact.archive_path.as_str()) {
                return Err(ManifestError::DuplicateArchivePath(
                    artifact.archive_path.clone(),
                ));
            }
            match (artifact.commit.as_deref(), format_version) {
                (Some(commit), Some(_)) if !is_valid_commit(commit) => {
                    return Err(ManifestError::InvalidCommit {
                        archive_path: artifact.archive_path.clone(),
                        commit: commit.to_string(),
                    });
                }
                (None, Some(_)) => {
                    return Err(ManifestError::MissingCommit(artifact.archive_path.clone()));
                }
                (Some(_), None) => {
                    return Err(ManifestError::BaselineWithCommit(
                        artifact.archive_path.clone(),
                    ));
                }
                _ => {}
            }
            if let Some(spec) = &artifact.spec {
                if format_version.is_none() {
                    return Err(ManifestError::BaselineWithSpec(
                        artifact.archive_path.clone(),
                    ));
                }
                crate::module_spec::validate(spec, &artifact.component, artifact.kind).map_err(
                    |source| ManifestError::InvalidSpec {
                        archive_path: artifact.archive_path.clone(),
                        source,
                    },
                )?;
            }
        }

        if let Some(bytes) = &trust_set {
            if bytes.is_empty() {
                return Err(ManifestError::EmptyTrustSet);
            }
            if format_version.is_none() {
                return Err(ManifestError::BaselineWithTrustSet);
            }
        }

        Ok(Self {
            format_version,
            pinset,
            trust_set,
            archive_members,
            artifacts,
        })
    }

    /// Returns the manifest schema version, or `None` for a manifest read off
    /// the pre-versioned baseline path.
    ///
    /// `None` means exactly that and nothing else. A consumer that requires a
    /// version refuses it with a typed error of its own rather than defaulting
    /// it to [`MANIFEST_FORMAT_VERSION`].
    #[must_use]
    pub fn format_version(&self) -> Option<u32> {
        self.format_version
    }

    /// Returns the pin-set digest the payload was assembled from, or `None` for
    /// a payload that predates the stamp.
    #[must_use]
    pub fn pinset(&self) -> Option<&str> {
        self.pinset.as_deref()
    }

    /// Returns the signed trust-set generation container the installer seeds
    /// from, or `None` when this payload carries none.
    ///
    /// The bytes are opaque to this crate. `None` means "this payload carries no
    /// generation", not "this payload is old": a payload assembled before
    /// release-ops minted a generation legitimately carries none. Whether a
    /// payload *must* carry one to seed an install is the installer's rule.
    #[must_use]
    pub fn trust_set(&self) -> Option<&[u8]> {
        self.trust_set.as_deref()
    }

    /// Returns the ordered archive member list the manifest binds, or `None`
    /// for a manifest read off the pre-versioned baseline path.
    ///
    /// What this reports is the shape the manifest was read in, never that the
    /// member-list check passed: that check compares a real archive walk
    /// against this list and lives in
    /// [`Payload::extract_to`](crate::payload::Payload::extract_to), where the
    /// bytes are.
    #[must_use]
    pub fn archive_members(&self) -> Option<&[ArchiveMember]> {
        self.archive_members.as_deref()
    }

    /// Returns the artifacts described by this manifest.
    #[must_use]
    pub fn artifacts(&self) -> &[PayloadArtifact] {
        &self.artifacts
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArchiveMember, ArtifactKind, Disposition, GIT_COMMIT_HEX_LEN, IMAGE_DIGEST_HEX_LEN,
        LEGACY_UNVERSIONED_FOOTER_VERSION, MANIFEST_FORMAT_VERSION, MAX_MANIFEST_FORMAT_VERSION,
        MIN_MANIFEST_FORMAT_VERSION, ManifestError, ModuleSpec, PayloadArtifact, PayloadManifest,
        TargetArch, is_pre_versioned_baseline, is_valid_commit,
    };
    use crate::module_spec::{
        Arg, ModuleSpecError, PlacementClass, RegistrationTemplate, ReloadSpec, RenderVar,
        RestartPolicy, SystemdTarget, UnitTemplate,
    };
    use crate::render::{RenderContext, RenderError, render_unit};

    /// Length every member of a fixture archive is given, where the value under
    /// test is something other than the member list itself.
    const FIXTURE_MEMBER_LEN: u64 = 12;

    /// Names one member per artifact, in the same order — the shape
    /// `append_trailer` produces, since both lists come from one `inputs` slice.
    /// A test whose subject *is* the member list states its list outright
    /// instead.
    fn members_for(artifacts: &[PayloadArtifact]) -> Vec<ArchiveMember> {
        artifacts
            .iter()
            .map(|artifact| ArchiveMember {
                name: artifact.archive_path.clone(),
                length: FIXTURE_MEMBER_LEN,
            })
            .collect()
    }

    /// [`PayloadManifest::new`] with the member list derived by
    /// [`members_for`], so a test that is not about the list does not restate
    /// it.
    fn manifest_of(
        pinset: Option<String>,
        artifacts: Vec<PayloadArtifact>,
    ) -> Result<PayloadManifest, ManifestError> {
        let members = members_for(&artifacts);
        PayloadManifest::new(pinset, members, artifacts)
    }

    fn artifact(
        archive_path: &str,
        kind: ArtifactKind,
        dispositions: &[Disposition],
    ) -> PayloadArtifact {
        PayloadArtifact {
            component: "example".to_string(),
            version: "1.2.3".to_string(),
            commit: Some(GIT_COMMIT.to_string()),
            target_arch: TargetArch::X86_64,
            kind,
            dispositions: dispositions.iter().copied().collect(),
            archive_path: archive_path.to_string(),
            sha256: "00".repeat(32),
            spec: None,
        }
    }

    /// A `bootler.pinset.v1` digest, in the 64-hex-character form the release
    /// tool stamps. This layer stores the stamp opaquely and deliberately does
    /// not validate its form — computing and checking it is `release-tool`'s job.
    const PINSET: &str = "656add7928cb1eee2d46a23546c477c9447ceb2afe78734239e21a785ddb9aec";

    /// A full 40-hex git commit SHA — the width an artifact built from a clone
    /// carries.
    const GIT_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A 64-hex image digest with its `sha256:` prefix stripped — the width a
    /// third-party container image carries.
    const IMAGE_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Opaque stand-in for the signed trust-set generation container. This
    /// crate never looks inside it, so arbitrary bytes are a faithful fixture.
    const GENERATION: &[u8] = b"a signed generation container, opaque to this crate";

    /// Renders one artifact entry as wire JSON. `commit` is written only when
    /// `Some`, so the baseline shape can be expressed.
    fn entry_json(archive_path: &str, commit: Option<&str>) -> String {
        let commit = commit.map_or_else(String::new, |value| format!(r#""commit":"{value}","#));
        format!(
            r#"{{"component":"c","version":"1",{commit}"target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"{archive_path}","sha256":"00"}}"#
        )
    }

    /// The `archive_members` fragment a versioned wire fixture carries, naming
    /// the one `bin/c` member [`entry_json`] writes, with its trailing comma.
    const MEMBERS_JSON: &str = r#""archive_members":[{"name":"bin/c","length":12}],"#;

    /// Wire JSON for a manifest carrying `format_version`, the member list every
    /// versioned manifest must bind, and one current-format artifact.
    fn versioned_json(version: u32) -> String {
        let entry = entry_json("bin/c", Some(GIT_COMMIT));
        format!(r#"{{"format_version":{version},{MEMBERS_JSON}"artifacts":[{entry}]}}"#)
    }

    /// Renders the same entry as [`entry_json`] with `spec` spliced in, so the
    /// read-path spec tests exercise the wire form a producer writes.
    fn entry_json_with_spec(archive_path: &str, commit: Option<&str>, spec: &str) -> String {
        let entry = entry_json(archive_path, commit);
        let body = entry.strip_suffix('}').expect("an entry ends with a brace");
        format!(r#"{body},"spec":{spec}}}"#)
    }

    /// Wire JSON of a spec for the `c` component `entry_json` writes, carrying
    /// `unit` verbatim so a test can vary only the unit template.
    fn spec_json(unit: &str) -> String {
        format!(
            r#"{{"unit":{unit},"registration":{{"package_id":"c","service_name":"c","reload":{{"sighup":{{"process_path":"/opt/c"}}}}}},"placement":"core-hosts"}}"#
        )
    }

    /// Wire JSON of a unit template whose `exec_start`/`exec_reload` block is
    /// `exec` verbatim; every other field is a valid fixed value.
    fn unit_json(exec: &str) -> String {
        format!(
            r#"{{"description":"C","after":[],"wants":[],"wanted_by":["multi-user"],{exec},"environment":[],"restart":"always","restart_sec":5,"protect_home":false,"private_tmp":false,"no_new_privileges":false}}"#
        )
    }

    /// The `exec_start` a valid unit template carries.
    const VALID_EXEC_START: &str = r#""exec_start":[{"var":"artifact-path"}]"#;

    /// A spec a `native-binary` artifact of component `example` may declare.
    fn module_spec() -> ModuleSpec {
        ModuleSpec {
            unit: Some(UnitTemplate {
                description: "Example module".to_string(),
                after: vec![SystemdTarget::NetworkOnline],
                wants: vec![SystemdTarget::NetworkOnline],
                wanted_by: vec![SystemdTarget::MultiUser],
                exec_start: vec![
                    Arg::Var(RenderVar::ArtifactPath),
                    Arg::Literal("-c".to_string()),
                    Arg::Var(RenderVar::ConfigPath),
                ],
                exec_reload: Some(vec![
                    Arg::Literal("/bin/kill".to_string()),
                    Arg::Literal("-HUP".to_string()),
                    Arg::Var(RenderVar::MainPid),
                ]),
                working_directory: Some(Arg::Var(RenderVar::DataDir)),
                environment: vec![
                    ("RUST_LOG".to_string(), Arg::Literal("info".to_string())),
                    ("HOST".to_string(), Arg::Var(RenderVar::Hostname)),
                ],
                restart: RestartPolicy::Always,
                restart_sec: 5,
                limit_nofile: None,
                protect_home: true,
                private_tmp: true,
                no_new_privileges: true,
            }),
            registration: RegistrationTemplate {
                package_id: "example".to_string(),
                service_name: "example".to_string(),
                reload: ReloadSpec::DockerSighup {
                    container: "example".to_string(),
                },
                cert_group_gid: Some(1000),
            },
            placement: PlacementClass::ModuleHosts,
        }
    }

    #[test]
    fn round_trips_through_serde_covering_all_kinds_and_both_dispositions() {
        let manifest = manifest_of(
            Some(PINSET.to_string()),
            vec![
                artifact(
                    "bin/native",
                    ArtifactKind::NativeBinary,
                    &[Disposition::Install],
                ),
                artifact(
                    "images/roxyd.tar",
                    ArtifactKind::ContainerImage,
                    &[Disposition::Install, Disposition::Stage],
                ),
                artifact(
                    "compose/stack.tar",
                    ArtifactKind::ComposeBundle,
                    &[Disposition::Stage],
                ),
                artifact(
                    "assets/web.tar",
                    ArtifactKind::StaticAssets,
                    &[Disposition::Install],
                ),
            ],
        )
        .expect("manifest should be valid");

        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        let restored: PayloadManifest =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(manifest, restored);
        assert_eq!(restored.artifacts().len(), 4);
        assert_eq!(restored.pinset(), Some(PINSET));
    }

    #[test]
    fn a_manifest_with_no_pinset_deserializes_and_reports_none() {
        // A payload published before the stamp existed must still parse: the
        // install path and `rewrap` share this parsing, so an absent stamp is an
        // actionable `verify-manifest` mismatch, never a serde error.
        let json = versioned_json(MANIFEST_FORMAT_VERSION);
        let manifest: PayloadManifest =
            serde_json::from_str(&json).expect("a pinset-less manifest must deserialize");
        assert_eq!(manifest.pinset(), None);
        assert_eq!(manifest.artifacts().len(), 1);
    }

    #[test]
    fn a_pinset_less_manifest_serializes_without_the_field() {
        // `RawManifest` carries no `deny_unknown_fields`, so a reader predating
        // the field ignores it; omitting it when absent additionally keeps such a
        // manifest's wire form byte-identical to the pre-stamp format.
        let manifest = manifest_of(
            None,
            vec![artifact(
                "bin/native",
                ArtifactKind::NativeBinary,
                &[Disposition::Install],
            )],
        )
        .expect("manifest should be valid");
        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        assert!(!json.contains("pinset"), "got: {json}");
    }

    #[test]
    fn an_unknown_manifest_field_is_ignored() {
        // The forward-compatibility half of the same rule: a manifest carrying a
        // field this build does not know must not fail to parse.
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"pinset":"abc","surprise":true,"archive_members":[],"artifacts":[]}}"#
        );
        let manifest: PayloadManifest =
            serde_json::from_str(&json).expect("an unknown field must be ignored");
        assert_eq!(manifest.pinset(), Some("abc"));
    }

    #[test]
    fn kinds_and_dispositions_use_kebab_case_strings() {
        let manifest = manifest_of(
            Some(PINSET.to_string()),
            vec![artifact(
                "images/roxyd.tar",
                ArtifactKind::ContainerImage,
                &[Disposition::Install, Disposition::Stage],
            )],
        )
        .expect("manifest should be valid");

        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        assert!(json.contains("\"container-image\""), "got: {json}");
        assert!(json.contains("\"install\""), "got: {json}");
        assert!(json.contains("\"stage\""), "got: {json}");
        assert!(json.contains("\"x86_64\""), "got: {json}");
    }

    #[test]
    fn new_rejects_empty_disposition_set() {
        let bad = artifact("bin/native", ArtifactKind::NativeBinary, &[]);
        let error = manifest_of(None, vec![bad]).expect_err("empty dispositions must be rejected");
        assert!(matches!(error, ManifestError::EmptyDispositions(_)));
    }

    #[test]
    fn deserialization_rejects_empty_disposition_set() {
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{{"component":"c","version":"1","commit":"{GIT_COMMIT}","target_arch":"x86_64","kind":"native-binary","dispositions":[],"archive_path":"bin/c","sha256":"00"}}]}}"#
        );
        let result: Result<PayloadManifest, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "empty dispositions must fail to deserialize"
        );
    }

    #[test]
    fn new_rejects_duplicate_archive_path() {
        let error = manifest_of(
            None,
            vec![
                artifact(
                    "bin/dup",
                    ArtifactKind::NativeBinary,
                    &[Disposition::Install],
                ),
                artifact("bin/dup", ArtifactKind::StaticAssets, &[Disposition::Stage]),
            ],
        )
        .expect_err("duplicate archive_path must be rejected");
        assert!(matches!(error, ManifestError::DuplicateArchivePath(path) if path == "bin/dup"));
    }

    #[test]
    fn deserialization_rejects_duplicate_archive_path() {
        let entry = entry_json("bin/dup", Some(GIT_COMMIT));
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry},{entry}]}}"#
        );
        let result: Result<PayloadManifest, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "duplicate archive_path must fail to deserialize"
        );
    }

    #[test]
    fn new_rejects_unsafe_archive_path() {
        for bad in [
            "../escape",
            "/abs/path",
            "bin/../../etc",
            "..",
            "",
            "./bin/roxyd",
            ".",
            "bin/./roxyd",
        ] {
            let error = manifest_of(
                None,
                vec![artifact(
                    bad,
                    ArtifactKind::NativeBinary,
                    &[Disposition::Install],
                )],
            )
            .expect_err("unsafe archive_path must be rejected");
            assert!(
                matches!(error, ManifestError::UnsafeArchivePath(_)),
                "path {bad:?} got: {error:?}"
            );
        }
    }

    #[test]
    fn deserialization_rejects_unsafe_archive_path() {
        let entry = entry_json("../escape", Some(GIT_COMMIT));
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let result: Result<PayloadManifest, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "unsafe archive_path must fail to deserialize"
        );
    }

    #[test]
    fn empty_manifest_is_valid() {
        let manifest = manifest_of(None, Vec::new()).expect("empty manifest is valid");
        assert!(manifest.artifacts().is_empty());
    }

    #[test]
    fn the_accepted_range_is_open_below_the_producer_and_closed_at_it() {
        // The producer writes at the ceiling — a build never stamps a version
        // it would then refuse to read — and the floor sits strictly below it,
        // so the window admits more than one version. Pinned rather than left
        // implicit because a later bump that moved all three together would
        // close the window again and silently strand every payload published
        // at the older version.
        //
        // Both hold at compile time, so both are stated that way: a bump that
        // closed the window fails the build rather than one test run.
        const _: () = assert!(MAX_MANIFEST_FORMAT_VERSION == MANIFEST_FORMAT_VERSION);
        const _: () = assert!(MIN_MANIFEST_FORMAT_VERSION < MANIFEST_FORMAT_VERSION);
    }

    #[test]
    fn new_stamps_the_current_format_version() {
        let manifest = manifest_of(
            None,
            vec![artifact(
                "bin/native",
                ArtifactKind::NativeBinary,
                &[Disposition::Install],
            )],
        )
        .expect("manifest should be valid");
        assert_eq!(manifest.format_version(), Some(MANIFEST_FORMAT_VERSION));
        assert_eq!(manifest.trust_set(), None);
    }

    #[test]
    fn the_commit_validator_accepts_both_widths_and_nothing_else() {
        assert!(is_valid_commit(GIT_COMMIT));
        assert!(is_valid_commit(IMAGE_DIGEST));

        // An abbreviation, an over-long value, uppercase hex, and a non-hex
        // string of an accepted length are all rejected.
        assert!(!is_valid_commit("abc1234"));
        assert!(!is_valid_commit(&format!("{GIT_COMMIT}a")));
        assert!(!is_valid_commit(&GIT_COMMIT.to_uppercase()));
        assert!(!is_valid_commit(&"z".repeat(GIT_COMMIT.len())));
        assert!(!is_valid_commit(""));
    }

    #[test]
    fn the_two_accepted_widths_are_exported_so_a_consumer_narrows_without_the_literal() {
        // A producer accepts exactly one width per artifact — the git width for
        // an artifact built from a clone, the digest width for a third-party
        // image — and must be able to say so through the constants rather than
        // by restating `40` or `64`.
        assert_eq!(GIT_COMMIT.len(), GIT_COMMIT_HEX_LEN);
        assert_eq!(IMAGE_DIGEST.len(), IMAGE_DIGEST_HEX_LEN);
        assert_ne!(GIT_COMMIT_HEX_LEN, IMAGE_DIGEST_HEX_LEN);

        let narrowed_to_git =
            |value: &str| is_valid_commit(value) && value.len() == GIT_COMMIT_HEX_LEN;
        assert!(narrowed_to_git(GIT_COMMIT));
        assert!(!narrowed_to_git(IMAGE_DIGEST));

        let narrowed_to_digest =
            |value: &str| is_valid_commit(value) && value.len() == IMAGE_DIGEST_HEX_LEN;
        assert!(narrowed_to_digest(IMAGE_DIGEST));
        assert!(!narrowed_to_digest(GIT_COMMIT));
    }

    #[test]
    fn an_image_digest_width_commit_is_accepted_on_a_manifest_artifact() {
        // The validator covers both widths; this pins that the manifest-level
        // check accepts the digest width too, so a third-party container image
        // is expressible.
        let mut digest_artifact = artifact(
            "images/vendor.tar",
            ArtifactKind::ContainerImage,
            &[Disposition::Install],
        );
        digest_artifact.commit = Some(IMAGE_DIGEST.to_string());
        let manifest = manifest_of(None, vec![digest_artifact])
            .expect("a digest-width commit must be accepted");
        assert_eq!(
            manifest
                .artifacts()
                .first()
                .expect("one artifact")
                .commit
                .as_deref(),
            Some(IMAGE_DIGEST)
        );
    }

    #[test]
    fn a_current_format_manifest_rejects_a_missing_or_malformed_commit() {
        let mut without = artifact(
            "bin/native",
            ArtifactKind::NativeBinary,
            &[Disposition::Install],
        );
        without.commit = None;
        let error = manifest_of(None, vec![without])
            .expect_err("a current-format artifact must carry a commit");
        assert!(
            matches!(error, ManifestError::MissingCommit(ref path) if path == "bin/native"),
            "got: {error:?}"
        );

        let mut abbreviated = artifact(
            "bin/native",
            ArtifactKind::NativeBinary,
            &[Disposition::Install],
        );
        abbreviated.commit = Some("abc1234".to_string());
        let error = manifest_of(None, vec![abbreviated])
            .expect_err("an abbreviated commit must be rejected");
        assert!(
            matches!(error, ManifestError::InvalidCommit { ref archive_path, .. } if archive_path == "bin/native"),
            "got: {error:?}"
        );
    }

    #[test]
    fn the_read_path_rejects_a_versioned_artifact_with_no_commit() {
        // `new` enforces this on the producer side, but the invariant a
        // consumer relies on is the read-side one: every artifact of a manifest
        // that is not on the baseline path carries a `commit`. A missing key
        // and an explicit `null` are the same absence.
        let absent = entry_json("bin/c", None);
        let explicit_null =
            absent.replace(r#""component":"c""#, r#""component":"c","commit":null"#);
        for entry in [absent, explicit_null] {
            let json = format!(
                r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
            );
            let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
                .expect_err("a current-format artifact must carry a commit");
            assert!(
                matches!(error, ManifestError::MissingCommit(ref path) if path == "bin/c"),
                "entry {entry}: got {error:?}"
            );
        }
    }

    #[test]
    fn the_read_path_rejects_a_malformed_commit() {
        let entry = entry_json("bin/c", Some("abc1234"));
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an abbreviated commit must be rejected on read too");
        assert!(
            matches!(
                error,
                ManifestError::InvalidCommit { ref archive_path, ref commit }
                    if archive_path == "bin/c" && commit == "abc1234"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_trust_set_round_trips_through_the_wire_encoding() {
        let manifest = manifest_of(
            Some(PINSET.to_string()),
            vec![artifact(
                "bin/native",
                ArtifactKind::NativeBinary,
                &[Disposition::Install],
            )],
        )
        .expect("manifest should be valid")
        .with_trust_set(GENERATION)
        .expect("a non-empty generation is accepted");
        assert_eq!(manifest.trust_set(), Some(GENERATION));

        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        // The wire form is a padded standard-alphabet base64 string.
        assert!(json.contains(r#""trust_set":"YSBzaWdu"#), "got: {json}");
        let restored: PayloadManifest =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(restored.trust_set(), Some(GENERATION));
        assert_eq!(restored, manifest);
        // It is a payload-level field, never an artifact entry.
        assert_eq!(restored.artifacts().len(), 1);
    }

    #[test]
    fn a_manifest_without_a_trust_set_emits_no_key() {
        let manifest = manifest_of(None, Vec::new()).expect("empty manifest is valid");
        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        assert!(!json.contains("trust_set"), "got: {json}");
        let restored: PayloadManifest =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(restored.trust_set(), None);
    }

    #[test]
    fn an_undecodable_trust_set_is_rejected_with_its_own_variant() {
        let entry = entry_json("bin/c", Some(GIT_COMMIT));
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"trust_set":"not base64!!",{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("a non-base64 trust_set must be rejected");
        assert!(
            matches!(error, ManifestError::TrustSetNotBase64(_)),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_empty_trust_set_is_rejected_on_both_sides() {
        // Read side: a value that decodes to zero bytes.
        let entry = entry_json("bin/c", Some(GIT_COMMIT));
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"trust_set":"",{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an empty trust_set must be rejected");
        assert!(
            matches!(error, ManifestError::EmptyTrustSet),
            "got: {error:?}"
        );

        // Producer side: the same rejection, through the same check.
        let error = manifest_of(None, Vec::new())
            .expect("empty manifest is valid")
            .with_trust_set(b"")
            .expect_err("an empty generation must be rejected");
        assert!(
            matches!(error, ManifestError::EmptyTrustSet),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_baseline_manifest_refuses_a_trust_set_through_the_builder_too() {
        // The builder is the only way to attach a value, so it runs the same
        // conjunction the read path does: a manifest that came off the baseline
        // path cannot gain a generation without also gaining a
        // `format_version`, which no constructor can give it.
        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"artifacts":[{entry}]}}"#);
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("baseline manifest should parse")
            .with_trust_set(GENERATION)
            .expect_err("a baseline manifest must not gain a trust_set");
        assert!(
            matches!(error, ManifestError::BaselineWithTrustSet),
            "got: {error:?}"
        );
    }

    #[test]
    fn the_serde_door_is_no_laxer_about_the_accepted_range() {
        // `TryFrom<RawManifest>` runs the same range check as the footer-aware
        // parse, so a direct `from_slice` cannot admit a version this build does
        // not implement either.
        let json = versioned_json(MAX_MANIFEST_FORMAT_VERSION + 1);
        let error = serde_json::from_str::<PayloadManifest>(&json)
            .expect_err("the serde path must refuse an out-of-range version");
        assert!(
            error.to_string().contains("unsupported manifest format"),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_version_above_the_ceiling_is_rejected_for_its_version_alone() {
        // The body is unreadable to this build — `artifacts` is not even an
        // array — so passing proves the range decision was made from
        // `format_version` alone, before any other key was inspected.
        let found = MAX_MANIFEST_FORMAT_VERSION + 1;
        let json = format!(r#"{{"format_version":{found},"artifacts":"a future shape"}}"#);
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("a future format version must be rejected");
        assert!(
            matches!(
                error,
                ManifestError::UnsupportedManifestFormat { found: got, min, max }
                    if got == found
                        && min == MIN_MANIFEST_FORMAT_VERSION
                        && max == MAX_MANIFEST_FORMAT_VERSION
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_version_below_the_floor_is_rejected_with_the_same_variant() {
        let found = MIN_MANIFEST_FORMAT_VERSION - 1;
        let json = versioned_json(found);
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("a below-floor format version must be rejected");
        assert!(
            matches!(
                error,
                ManifestError::UnsupportedManifestFormat { found: got, .. } if got == found
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_baseline_manifest_parses_only_through_the_footer_aware_door() {
        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"artifacts":[{entry}]}}"#);

        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a baseline manifest at the legacy footer version must parse");
        assert_eq!(manifest.format_version(), None);
        assert_eq!(manifest.trust_set(), None);
        // The one door that can yield a manifest binding no member list.
        assert_eq!(manifest.archive_members(), None);
        assert_eq!(
            manifest
                .artifacts()
                .first()
                .expect("one artifact")
                .commit
                .as_deref(),
            None
        );

        // The serde path is not a second door: it cannot see the footer, so it
        // rejects an absent `format_version` unconditionally.
        let error = serde_json::from_slice::<PayloadManifest>(json.as_bytes())
            .expect_err("the serde path must not admit a baseline manifest");
        assert!(
            error.to_string().contains("format_version"),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_parsed_baseline_manifest_re_serializes_without_a_format_version_key() {
        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"artifacts":[{entry}]}}"#);
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("baseline manifest should parse");

        let round_tripped = serde_json::to_string(&manifest).expect("serialization should succeed");
        assert!(
            !round_tripped.contains("format_version"),
            "got: {round_tripped}"
        );
        assert!(!round_tripped.contains("null"), "got: {round_tripped}");
        assert!(!round_tripped.contains("commit"), "got: {round_tripped}");
        assert!(
            !round_tripped.contains("archive_members"),
            "got: {round_tripped}"
        );
    }

    #[test]
    fn a_versioned_manifest_binding_no_member_list_is_rejected_at_both_doors() {
        // The refusal lives in `from_parts`, so the footer-aware parse and
        // plain deserialization — which cannot see the footer — are equally
        // strict with one implementation. A missing key and an explicit `null`
        // are the same absence.
        let entry = entry_json("bin/c", Some(GIT_COMMIT));
        let absent =
            format!(r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"artifacts":[{entry}]}}"#);
        let explicit_null = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"archive_members":null,"artifacts":[{entry}]}}"#
        );
        for json in [absent, explicit_null] {
            let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
                .expect_err("a versioned manifest must bind a member list");
            assert!(
                matches!(error, ManifestError::MissingArchiveMembers),
                "json {json}: got {error:?}"
            );

            let error = serde_json::from_slice::<PayloadManifest>(json.as_bytes())
                .expect_err("the serde door must be no laxer");
            assert!(
                error.to_string().contains("archive_members"),
                "json {json}: got {error:?}"
            );
        }
    }

    #[test]
    fn an_unversioned_manifest_carrying_an_archive_members_key_is_rejected() {
        // The sixth term of the baseline conjunction, read presence-only like
        // `trust_set`: the field is `skip_serializing_if = "Option::is_none"`,
        // so no pre-bump producer could have emitted the key in any form, and a
        // `null` value must not buy it back into the allowance. Without the
        // term such a manifest would reach the path where the member-list check
        // is skipped, carrying a list nothing compares against.
        let entry = entry_json("bin/c", None);
        for value in [r#"[{"name":"bin/c","length":12}]"#, "null"] {
            let json = format!(r#"{{"archive_members":{value},"artifacts":[{entry}]}}"#);
            let document: serde_json::Value =
                serde_json::from_str(&json).expect("document should decode");
            assert!(!is_pre_versioned_baseline(
                LEGACY_UNVERSIONED_FOOTER_VERSION,
                &document
            ));

            let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
                .expect_err("an unversioned manifest with a member list must be rejected");
            assert!(
                matches!(error, ManifestError::BaselineWithArchiveMembers),
                "value {value}: got {error:?}"
            );
        }
    }

    #[test]
    fn the_member_list_round_trips_and_the_builder_forwards_it_unchanged() {
        let members = vec![
            ArchiveMember {
                name: "bin/roxyd".to_string(),
                length: 12_345_678,
            },
            ArchiveMember {
                name: "images/aimer.tar".to_string(),
                length: 987_654_321,
            },
        ];
        let manifest = PayloadManifest::new(
            None,
            members.clone(),
            vec![artifact(
                "bin/roxyd",
                ArtifactKind::NativeBinary,
                &[Disposition::Install],
            )],
        )
        .expect("manifest should be valid");
        assert_eq!(manifest.archive_members(), Some(members.as_slice()));

        // `with_trust_set` takes no member-list parameter: it forwards the list
        // its receiver already holds, so a caller cannot replace the list of an
        // already-validated manifest.
        let with_generation = manifest
            .with_trust_set(GENERATION)
            .expect("a non-empty generation is accepted");
        assert_eq!(with_generation.archive_members(), Some(members.as_slice()));

        let json = serde_json::to_string(&with_generation).expect("serialization should succeed");
        let restored: PayloadManifest =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(restored.archive_members(), Some(members.as_slice()));
        assert_eq!(restored, with_generation);
    }

    #[test]
    fn the_baseline_conjunction_needs_the_frozen_footer_version() {
        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"artifacts":[{entry}]}}"#);
        let document: serde_json::Value =
            serde_json::from_str(&json).expect("document should decode");

        assert!(is_pre_versioned_baseline(
            LEGACY_UNVERSIONED_FOOTER_VERSION,
            &document
        ));
        // `parse_footer` cannot produce a version-2 container, so the predicate
        // is called directly: the missing field alone must not admit a manifest.
        assert!(!is_pre_versioned_baseline(2, &document));
    }

    #[test]
    fn an_unversioned_manifest_carrying_a_commit_is_rejected() {
        let entry = entry_json("bin/c", Some(GIT_COMMIT));
        let json = format!(r#"{{"artifacts":[{entry}]}}"#);
        let document: serde_json::Value =
            serde_json::from_str(&json).expect("document should decode");
        assert!(!is_pre_versioned_baseline(
            LEGACY_UNVERSIONED_FOOTER_VERSION,
            &document
        ));

        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("a half-legacy manifest must be rejected");
        assert!(
            matches!(error, ManifestError::BaselineWithCommit(ref path) if path == "bin/c"),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_unversioned_manifest_carrying_a_trust_set_is_rejected() {
        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"trust_set":"YWJj","artifacts":[{entry}]}}"#);
        let document: serde_json::Value =
            serde_json::from_str(&json).expect("document should decode");
        assert!(!is_pre_versioned_baseline(
            LEGACY_UNVERSIONED_FOOTER_VERSION,
            &document
        ));

        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an unversioned manifest with a trust_set must be rejected");
        assert!(
            matches!(error, ManifestError::BaselineWithTrustSet),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_absent_trust_set_is_not_a_baseline_signal() {
        // Absence alone says nothing: a current-format manifest without a
        // generation is normal and must parse.
        let json = versioned_json(MANIFEST_FORMAT_VERSION);
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a versioned manifest without a trust_set must parse");
        assert_eq!(manifest.format_version(), Some(MANIFEST_FORMAT_VERSION));
        assert_eq!(manifest.trust_set(), None);
    }

    #[test]
    fn an_undecodable_manifest_block_reports_as_a_decode_failure() {
        let error = PayloadManifest::parse(b"{ not json", LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an undecodable block must be rejected");
        assert!(matches!(error, ManifestError::Decode(_)), "got: {error:?}");
    }

    #[test]
    fn a_format_version_that_is_not_a_u32_is_rejected_as_malformed() {
        // Each of these is refused from the version alone, before the body is
        // decoded — the same guarantee `UnsupportedManifestFormat` gives, under
        // a separate variant because no `found: u32` can carry the value.
        for value in ["\"1\"", "1.5", "-1", "4294967296", "true"] {
            let entry = entry_json("bin/c", Some(GIT_COMMIT));
            let json = format!(r#"{{"format_version":{value},"artifacts":[{entry}]}}"#);
            let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
                .expect_err("a non-u32 format_version must be rejected");
            assert!(
                matches!(error, ManifestError::MalformedFormatVersion),
                "value {value}: got {error:?}"
            );
        }
    }

    #[test]
    fn a_spec_round_trips_through_the_manifest() {
        let mut declaring = artifact(
            "bin/native",
            ArtifactKind::NativeBinary,
            &[Disposition::Install],
        );
        declaring.spec = Some(module_spec());
        let manifest =
            manifest_of(None, vec![declaring.clone()]).expect("a valid spec must be accepted");

        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        let restored = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a manifest carrying a spec must parse");
        assert_eq!(restored, manifest);

        let read = restored.artifacts().first().expect("one artifact");
        assert_eq!(read, &declaring);
        let spec = read
            .spec
            .as_ref()
            .expect("the spec survives the round trip");
        assert_eq!(spec, &module_spec());
        let unit = spec.unit.as_ref().expect("the unit survives too");
        let expected = module_spec().unit.expect("fixture carries a unit");
        assert_eq!(unit.description, expected.description);
        assert_eq!(unit.after, expected.after);
        assert_eq!(unit.wants, expected.wants);
        assert_eq!(unit.wanted_by, expected.wanted_by);
        assert_eq!(unit.exec_start, expected.exec_start);
        assert_eq!(unit.exec_reload, expected.exec_reload);
        assert_eq!(unit.working_directory, expected.working_directory);
        // Order is significant and preserved: one `Environment=` directive is
        // rendered per entry in declared order.
        assert_eq!(unit.environment, expected.environment);
        assert_eq!(unit.restart, expected.restart);
        assert_eq!(unit.restart_sec, expected.restart_sec);
        assert_eq!(unit.protect_home, expected.protect_home);
        assert_eq!(unit.private_tmp, expected.private_tmp);
        assert_eq!(unit.no_new_privileges, expected.no_new_privileges);
        assert_eq!(spec.registration, module_spec().registration);
        assert_eq!(spec.placement, PlacementClass::ModuleHosts);
    }

    #[test]
    fn the_read_path_runs_the_spec_validator_rather_than_trusting_the_producer() {
        // Each of these decodes cleanly and is refused by the validator, so a
        // consumer that never links a producer still refuses it. The case is
        // named by the source variant, not by "some error occurred".
        /// Names which spec rule a read-path rejection must report.
        type RuleCheck = fn(&ModuleSpecError) -> bool;

        let cases: [(&str, RuleCheck); 4] = [
            (
                r#""exec_start":[{"var":"artifact-path"},{"var":"main-pid"}]"#,
                |error| matches!(error, ModuleSpecError::MainPidOutsideExecReload),
            ),
            (r#""exec_start":[]"#, |error| {
                matches!(error, ModuleSpecError::EmptyExecStart)
            }),
            (r#""exec_start":[{"literal":"/bin/sh"}]"#, |error| {
                matches!(error, ModuleSpecError::ExecStartNotArtifactPath)
            }),
            (
                r#""exec_start":[{"var":"artifact-path"}],"exec_reload":[]"#,
                |error| matches!(error, ModuleSpecError::EmptyExecReload),
            ),
        ];
        for (exec, is_expected) in cases {
            let entry =
                entry_json_with_spec("bin/c", Some(GIT_COMMIT), &spec_json(&unit_json(exec)));
            let json = format!(
                r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
            );
            let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
                .expect_err("a malformed spec must be refused on read");
            let ManifestError::InvalidSpec {
                ref archive_path,
                ref source,
            } = error
            else {
                panic!("exec {exec}: expected a spec rejection, got {error:?}");
            };
            assert_eq!(archive_path, "bin/c");
            assert!(is_expected(source), "exec {exec}: got {source:?}");
        }
    }

    #[test]
    fn the_read_path_enforces_the_kind_conditional_unit_rule() {
        // A `native-binary` artifact declaring a spec with no unit.
        let no_unit = r#"{"registration":{"package_id":"c","service_name":"c","reload":{"sighup":{"process_path":"/opt/c"}}},"placement":"core-hosts"}"#;
        let entry = entry_json_with_spec("bin/c", Some(GIT_COMMIT), no_unit);
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("a native-binary spec must carry a unit");
        assert!(
            matches!(
                error,
                ManifestError::InvalidSpec {
                    source: ModuleSpecError::MissingUnit(_),
                    ..
                }
            ),
            "got: {error:?}"
        );

        // An artifact declaring no spec at all stays valid for every kind, and
        // that is exactly what every artifact shipping today does.
        for kind in [
            ArtifactKind::NativeBinary,
            ArtifactKind::ComposeBundle,
            ArtifactKind::StaticAssets,
            ArtifactKind::ContainerImage,
        ] {
            manifest_of(None, vec![artifact("bin/c", kind, &[Disposition::Install])])
                .expect("an artifact declaring no spec is valid for every kind");
        }
    }

    #[test]
    fn the_read_path_rejects_a_mismatched_package_id() {
        // The entry's component is `c`; the spec claims another package.
        let spec = spec_json(&unit_json(VALID_EXEC_START))
            .replace(r#""package_id":"c""#, r#""package_id":"somewhere-else""#);
        let entry = entry_json_with_spec("bin/c", Some(GIT_COMMIT), &spec);
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("a mismatched package_id must be rejected");
        assert!(
            matches!(
                error,
                ManifestError::InvalidSpec {
                    source: ModuleSpecError::PackageIdMismatch { .. },
                    ..
                }
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_valid_spec_parses_off_the_wire_form() {
        let entry = entry_json_with_spec(
            "bin/c",
            Some(GIT_COMMIT),
            &spec_json(&unit_json(VALID_EXEC_START)),
        );
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a valid spec must parse");
        let spec = manifest
            .artifacts()
            .first()
            .expect("one artifact")
            .spec
            .as_ref()
            .expect("the spec is carried");
        assert_eq!(spec.placement, PlacementClass::CoreHosts);
        assert_eq!(spec.registration.cert_group_gid, None);
    }

    #[test]
    fn an_unknown_render_var_name_fails_to_deserialize_on_the_manifest_read_path() {
        // The typed argv element is what makes an unknown variable
        // unrepresentable: it never reaches the validator, let alone a
        // rendered `ExecStart=`.
        let unit = unit_json(r#""exec_start":[{"var":"no-such-variable"}]"#);
        let entry = entry_json_with_spec("bin/c", Some(GIT_COMMIT), &spec_json(&unit));
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an unknown variable must not decode");
        assert!(matches!(error, ManifestError::Decode(_)), "got: {error:?}");
    }

    #[test]
    fn an_unknown_artifact_field_is_still_ignored() {
        // The spec structs deny unknown fields; `PayloadArtifact` keeps the
        // behaviour it has today, because the envelope's skew is caught by the
        // `format_version` range instead.
        let entry = entry_json("bin/c", Some(GIT_COMMIT))
            .replace(r#""component":"c""#, r#""component":"c","surprise":true"#);
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("an unknown artifact field must be ignored");
        assert_eq!(manifest.artifacts().len(), 1);
    }

    #[test]
    fn a_current_format_manifest_serializes_to_the_shape_this_schema_fixes() {
        // Byte-for-byte, so the on-disk shape is pinned rather than only the
        // round trip: no `spec` key on an artifact that declares none, and
        // `archive_members` as an array of `{"name","length"}` objects.
        let manifest = manifest_of(
            None,
            vec![artifact(
                "bin/native",
                ArtifactKind::NativeBinary,
                &[Disposition::Install],
            )],
        )
        .expect("manifest should be valid");
        let json = serde_json::to_string(&manifest).expect("serialization should succeed");
        let sha256 = "00".repeat(32);
        assert_eq!(
            json,
            format!(
                r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"archive_members":[{{"name":"bin/native","length":{FIXTURE_MEMBER_LEN}}}],"artifacts":[{{"component":"example","version":"1.2.3","commit":"{GIT_COMMIT}","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"bin/native","sha256":"{sha256}"}}]}}"#
            )
        );
    }

    #[test]
    fn every_version_in_the_window_is_accepted_including_the_floor() {
        // The two refusals either side of the window have their own tests; what
        // this one pins is that the window is not a point. Written by
        // interpolating the constants, so the next bump stays a repoint of them
        // rather than a search for a literal.
        for version in MIN_MANIFEST_FORMAT_VERSION..=MAX_MANIFEST_FORMAT_VERSION {
            let manifest = PayloadManifest::parse(
                versioned_json(version).as_bytes(),
                LEGACY_UNVERSIONED_FOOTER_VERSION,
            )
            .expect("a version inside the window must be accepted");
            assert_eq!(manifest.format_version(), Some(version));
        }
    }

    /// A manager endpoint in the form [`RenderVar::ManagerEndpoint`]
    /// documents: a certificate identity, a numeric address, and a port.
    const MANAGER_ENDPOINT: &str = "review@192.0.2.10:38390";

    /// The context the two read-path render tests resolve the `c` fixture
    /// against, differing only in whether the caller has a manager endpoint to
    /// supply.
    fn read_path_context(manager_endpoint: Option<&str>) -> RenderContext<'_> {
        RenderContext {
            artifact_path: "/opt/c/bin/c",
            config_path: "/etc/c/c.toml",
            data_dir: "/var/lib/c",
            instance_id: "1",
            hostname: "host-a",
            domain: "c.internal",
            cert_path: "/var/lib/c/cert.pem",
            key_path: "/var/lib/c/key.pem",
            ca_bundle_path: "/var/lib/c/ca-bundle.pem",
            manager_endpoint,
            service_account: None,
            namespace: "c",
            service_name: "c",
            instance: None,
            component: "c",
            kind: ArtifactKind::NativeBinary,
        }
    }

    #[test]
    fn a_manifest_at_the_floor_still_carries_a_spec_that_validates_and_renders() {
        // The floor stayed put because the schema growth above it is additive,
        // and that claim is only worth as much as this: a manifest written at
        // the floor still decodes, still passes the validator on the read
        // path, and still renders the unit it declares.
        let entry = entry_json_with_spec(
            "bin/c",
            Some(GIT_COMMIT),
            &spec_json(&unit_json(VALID_EXEC_START)),
        );
        let json = format!(
            r#"{{"format_version":{MIN_MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a manifest at the floor must parse");
        let spec = manifest
            .artifacts()
            .first()
            .expect("one artifact")
            .spec
            .as_ref()
            .expect("the spec is carried");
        assert_eq!(spec.placement, PlacementClass::CoreHosts);

        // A manifest at the floor names the variable nowhere, so a caller with
        // nothing to supply still renders it.
        let rendered = render_unit(spec, &read_path_context(None))
            .expect("a spec at the floor must render")
            .expect("the spec declares a unit");
        assert_eq!(
            rendered.text,
            "[Unit]\nDescription=C\n\n[Service]\nExecStart=/opt/c/bin/c\nRestart=always\n\
             RestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn a_manifest_at_the_floor_version_still_decodes_validates_and_renders_without_a_limit() {
        // The floor stayed put across the `limit_nofile` bump precisely so an
        // already-published payload keeps working. That promise is about the
        // whole read path, so this exercises it to the rendered bytes rather
        // than stopping at the decode.
        let entry = entry_json_with_spec(
            "bin/c",
            Some(GIT_COMMIT),
            &spec_json(&unit_json(VALID_EXEC_START)),
        );
        let json = format!(
            r#"{{"format_version":{MIN_MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a manifest at the floor version must still parse");
        assert_eq!(manifest.format_version(), Some(MIN_MANIFEST_FORMAT_VERSION));

        let spec = manifest
            .artifacts()
            .first()
            .expect("one artifact")
            .spec
            .as_ref()
            .expect("the artifact declares a spec");
        let unit = spec.unit.as_ref().expect("the spec declares a unit");
        assert_eq!(unit.limit_nofile, None);

        let rendered = render_unit(spec, &read_path_context(None))
            .expect("a floor-version spec must render")
            .expect("the spec declares a unit");
        assert!(!rendered.text.contains("Limit"), "got: {}", rendered.text);
    }

    #[test]
    fn a_manifest_at_the_current_version_renders_a_spec_naming_the_manager_endpoint() {
        // The mirror of the test above, and the read path the bump was cut
        // for: a producer's manifest declares the variable, the validator on
        // the read path accepts it, and the renderer substitutes the caller's
        // value as one final argument. The wire form is what a producer
        // writes, so nothing here is reached only through a hand-built spec.
        let exec_start = r#""exec_start":[{"var":"artifact-path"},{"var":"manager-endpoint"}]"#;
        let entry = entry_json_with_spec(
            "bin/c",
            Some(GIT_COMMIT),
            &spec_json(&unit_json(exec_start)),
        );
        let json = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},{MEMBERS_JSON}"artifacts":[{entry}]}}"#
        );
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("a manifest naming the variable must parse");
        let spec = manifest
            .artifacts()
            .first()
            .expect("one artifact")
            .spec
            .as_ref()
            .expect("the spec is carried");
        assert_eq!(
            spec.unit
                .as_ref()
                .expect("the spec declares a unit")
                .exec_start,
            vec![
                Arg::Var(RenderVar::ArtifactPath),
                Arg::Var(RenderVar::ManagerEndpoint)
            ]
        );

        let rendered = render_unit(spec, &read_path_context(Some(MANAGER_ENDPOINT)))
            .expect("a spec naming a supplied variable must render")
            .expect("the spec declares a unit");
        assert_eq!(
            rendered.text,
            format!(
                "[Unit]\nDescription=C\n\n[Service]\nExecStart=/opt/c/bin/c {MANAGER_ENDPOINT}\n\
                 Restart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
            )
        );

        // And the same manifest against a caller with no such peer is refused
        // rather than rendered with anything in its place.
        let error = render_unit(spec, &read_path_context(None))
            .expect_err("an unresolved variable must be refused");
        assert!(
            matches!(
                error,
                RenderError::UnresolvedVariable {
                    var: RenderVar::ManagerEndpoint
                }
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_unversioned_manifest_carrying_a_spec_is_rejected() {
        // Without this term the version gate would not hold: a hand-edited
        // manifest with no `format_version` but a `spec` would parse as a
        // legacy payload and hand a root daemon an instruction set that
        // bypassed the gate entirely.
        let entry = entry_json_with_spec("bin/c", None, &spec_json(&unit_json(VALID_EXEC_START)));
        let json = format!(r#"{{"artifacts":[{entry}]}}"#);
        let document: serde_json::Value =
            serde_json::from_str(&json).expect("document should decode");
        assert!(!is_pre_versioned_baseline(
            LEGACY_UNVERSIONED_FOOTER_VERSION,
            &document
        ));

        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an unversioned manifest carrying a spec must be rejected");
        assert!(
            matches!(error, ManifestError::BaselineWithSpec(ref path) if path == "bin/c"),
            "got: {error:?}"
        );

        // The same manifest with the spec removed is the genuine legacy shape
        // and still opens exactly as it does today.
        let baseline = format!(r#"{{"artifacts":[{}]}}"#, entry_json("bin/c", None));
        let manifest =
            PayloadManifest::parse(baseline.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
                .expect("a genuine legacy payload still parses");
        assert_eq!(manifest.format_version(), None);
        assert_eq!(
            manifest.artifacts().first().expect("one artifact").spec,
            None
        );
    }

    #[test]
    fn an_unversioned_manifest_carrying_an_explicit_null_bump_key_is_rejected() {
        // Every fingerprint term reads presence, never the value. A
        // pre-versioned producer emitted none of these keys in any form —
        // each is `skip_serializing_if = "Option::is_none"` — so the key alone
        // proves the document was hand-edited, and a `null` value must not buy
        // it back into the baseline allowance.
        let with_null_commit = entry_json("bin/c", None)
            .replace(r#""component":"c""#, r#""component":"c","commit":null"#);
        let json = format!(r#"{{"artifacts":[{with_null_commit}]}}"#);
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an unversioned artifact with a null commit key must be rejected");
        assert!(
            matches!(error, ManifestError::BaselineWithCommit(ref path) if path == "bin/c"),
            "got: {error:?}"
        );

        let with_null_spec = entry_json("bin/c", None)
            .replace(r#""component":"c""#, r#""component":"c","spec":null"#);
        let json = format!(r#"{{"artifacts":[{with_null_spec}]}}"#);
        let document: serde_json::Value =
            serde_json::from_str(&json).expect("document should decode");
        assert!(!is_pre_versioned_baseline(
            LEGACY_UNVERSIONED_FOOTER_VERSION,
            &document
        ));
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an unversioned artifact with a null spec key must be rejected");
        assert!(
            matches!(error, ManifestError::BaselineWithSpec(ref path) if path == "bin/c"),
            "got: {error:?}"
        );

        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"trust_set":null,"artifacts":[{entry}]}}"#);
        let error = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect_err("an unversioned manifest with a null trust_set key must be rejected");
        assert!(
            matches!(error, ManifestError::BaselineWithTrustSet),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_explicit_null_format_version_reads_as_absent() {
        // A missing key and an explicit `null` must mean the same thing, so the
        // two stages cannot disagree about which manifests are unversioned.
        let entry = entry_json("bin/c", None);
        let json = format!(r#"{{"format_version":null,"artifacts":[{entry}]}}"#);
        let manifest = PayloadManifest::parse(json.as_bytes(), LEGACY_UNVERSIONED_FOOTER_VERSION)
            .expect("an explicit null format_version is the baseline shape");
        assert_eq!(manifest.format_version(), None);
    }
}
