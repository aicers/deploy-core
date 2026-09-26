//! The shared package verifier: one implementation, two independent hops.
//!
//! A control plane re-verifies a package on upload and a per-machine root
//! daemon re-verifies it before apply, and neither may reach a different
//! verdict from the other. So there is exactly one verifier and it lives here,
//! in the crate both of them link. [`VerifyError`]'s variant names are a
//! cross-repository contract: they are matched on elsewhere and are not this
//! crate's to rename.
//!
//! # What is verified, and in what order
//!
//! [`verify_package`] reads the container far enough to reach the raw manifest
//! block and the two envelope blocks, checks the Ed25519 signature over those
//! **raw bytes**, and only then parses them. Nothing on this path re-serializes
//! a parsed manifest: two serializers that disagreed about map ordering or
//! whitespace would reject an authentic package, and there is no fallback for
//! that. The bytes on disk are the canonical form, which is why no
//! canonicalization algorithm is specified.
//!
//! Past the signature the order is a total order, and where two checks would
//! fail at once the earlier one is the verdict:
//!
//! 1. the raw blocks are read, without parsing the manifest;
//! 2. the signature is verified, in [`TrustSet`] anchor order;
//! 3. `format_version` is read through stage one of the parse and checked
//!    against the trust set's injected floor, and — inside the parse's own
//!    stage one, before its body decode — against this build's range;
//! 4. the typed manifest is parsed;
//! 5. **completeness** — the bound member list against the artifact entries;
//! 6. **identifiers** — [`is_safe_build_identifier`] over each entry's
//!    `component`, `version` and `commit`;
//! 7. **withdrawal** — every distinct manifest triple against the withdrawn
//!    list;
//! 8. **target** — every artifact entry against the request;
//! 9. **epoch** — for the reserved [`TRUST_TARGET`] only;
//! 10. **declared platform** — each image declaration's architecture against
//!     its artifact's `target_arch`;
//! 11. **reserved aliases** — every reference under
//!     [`RUNTIME_ALIAS_REGISTRY`] against the canonical alias its own
//!     declaration determines, and its lifecycle;
//! 12. **reference conflicts** — one normalized reference assigned to
//!     different images across declarations;
//! 13. **namespace present** — a request carrying a namespace whenever the
//!     manifest declares images;
//! 14. **namespace** — each declaration's `owner.namespace` against it;
//! 15. **owner component** — each declaration's `owner.component` against the
//!     requested target.
//!
//! Steps 5 through 9 decide about the package first and about the request last:
//! a package that is malformed, withdrawn, or built from an unsafe identifier
//! is reported as such whatever was asked for.
//!
//! Steps 10 through 15 are the image declaration semantics, reported under
//! [`VerifyError::Image`]. Each is a pass over the whole manifest, finished
//! before the next begins, so the order of the artifacts cannot move one
//! category behind another; within a pass, artifacts are visited in manifest
//! order and references in declaration order. Only a manifest at
//! [`IMAGE_DECLARATION_FORMAT_VERSION`](crate::manifest::IMAGE_DECLARATION_FORMAT_VERSION)
//! or later carries declarations, so a legacy manifest passes all six
//! untouched. The syntax of a declaration is not among them: that is decided
//! by the typed parse in step 4, and a malformed declaration arrives as
//! [`VerifyError::Payload`] carrying [`PayloadError::InvalidManifest`].
//!
//! # What it reads before it has authenticated anything
//!
//! Step 1 runs on bytes nothing has vouched for yet, so what it reads is
//! bounded rather than described. A footer's block lengths are the attacker's
//! to choose and the container layer confines them only to the input's own
//! size, which a sparse file inflates for nothing; reading a block on that
//! say-so would be a denial of service ahead of the check that rejects it. Both
//! envelope blocks have exactly one useful length — an Ed25519 signature is 64
//! bytes and a `key_id` is 64 hex characters — so a block at any other length
//! is answered from its length and never allocated. That costs nothing: its
//! contents would have produced the same verdict.
//!
//! The manifest block is the one thing read in full, because the signature is
//! over it and there is no answering for it otherwise.
//!
//! # What it does not do
//!
//! It never walks the archive block and never hashes an artifact, and it opens no
//! image: an accepted image declaration is an authenticated *statement* about
//! an archive member, not evidence that the member's bytes agree with it. It can
//! decide
//! completeness without doing either because the manifest binds
//! `archive_members`, so the enumeration of what the archive holds is a
//! statement *inside the signed bytes*. Comparing that statement against what
//! the archive really turns out to hold is
//! [`Payload::extract_to`](crate::payload::Payload::extract_to)'s walk and
//! stays there — which is what [`VerifiedPackage::extract_to`] delegates to,
//! mapping its [`PayloadError`] into this taxonomy so a caller sees one set of
//! names end to end.
//!
//! It reads no trust generation from disk, consults no package-id registry and
//! names no product: the trust set and the request are values a caller builds
//! from whatever it has already read.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Read, Seek};
use std::path::Path;

use ring::signature::{ED25519, UnparsedPublicKey};

use crate::image::{
    ImageArchitecture, ImageDeclaration, NormalizedReference, RUNTIME_ALIAS_REGISTRY,
    ReferenceLifecycle, is_valid_segment, parse_tagged_reference,
};
use crate::manifest::{
    self, ArtifactKind, MAX_MANIFEST_FORMAT_VERSION, ManifestError, PayloadArtifact,
    PayloadManifest, TargetArch, is_safe_archive_path,
};
use crate::package::LimitResource;
use crate::payload::{
    self, BoundedContainerError, ContainerBounds, EnvelopeBlock, EnvelopeBounds, ExtractedArtifact,
    Payload, PayloadError, UnparsedContainer,
};

mod image_archive;

pub use image_archive::{
    BlobMismatchKind, BlobRole, ConfigField, ExtensionField, GzipFault, GzipHeaderFault,
    ImageDocument, InvalidArchiveReason, InvalidConfigReason, JsonFault, LayerMismatchKind,
    LayoutFile, PaxKey, PlatformFacet, PlatformLocation, ReferenceSource, TarFault, TarFeature,
    TarHeaderField, UnsupportedArchiveFeature,
};

/// Reserved package-id of the trust-material target, the one target that
/// carries a delivered `epoch`.
///
/// [`VerifyRequest::for_trust`] supplies it, and
/// [`VerifyRequest::for_package`] refuses it, so a request can never pair the
/// name with the wrong constructor.
pub const TRUST_TARGET: &str = "trust";

/// Number of ASCII characters a `key_id` is: a SHA-256 digest rendered in
/// lowercase hex, untruncated.
///
/// The `key_id` footer block holds exactly these bytes and nothing else — no
/// NUL, no newline, no `0x` or multibase prefix, no padding — so the block's
/// length is itself a check, and it is the only length at which the block is
/// read at all.
pub const KEY_ID_HEX_LEN: u64 = 64;

/// Number of bytes an Ed25519 signature is.
///
/// A signature of any other length verifies under no key, so the container read
/// answers one from its length rather than reading it.
pub const ED25519_SIGNATURE_LEN: u64 = 64;

/// The lengths at which this verifier reads the container's envelope blocks.
///
/// Both blocks are read before anything has been authenticated, from a footer
/// an attacker wrote, and each has exactly one length this verifier can do
/// anything with. Stating them here keeps the container read from allocating a
/// block advertised at gigabyte or terabyte scale — which a sparse file, or a
/// hostile `Read + Seek` source, costs nothing to claim — ahead of the check
/// that was going to reject it. Refusing to read such a block loses nothing:
/// its verdict follows from its length, exactly as it would have from its
/// contents.
pub const ENVELOPE_BOUNDS: EnvelopeBounds = EnvelopeBounds {
    signature_len: ED25519_SIGNATURE_LEN,
    key_id_len: KEY_ID_HEX_LEN,
};

/// Longest build identifier [`is_safe_build_identifier`] admits, in **bytes**
/// rather than characters.
const MAX_BUILD_IDENTIFIER_BYTES: usize = 128;

/// Derives the `key_id` of an Ed25519 public key: the lowercase-hex SHA-256 of
/// the 32 raw public-key bytes, rendered in full: 64 ASCII characters,
/// untruncated.
///
/// One producer writes this value and two independent verifiers compare it byte
/// for byte, so the derivation is fixed rather than conventional and this is the
/// only place in the crate that performs it — the anchor lookup, a trust set's
/// own anchor index, and the tests' fixture keys all route through here. A
/// second hand-rolled formatting site is precisely how a producer and a verifier
/// come to disagree.
///
/// The input is the raw key: not an SPKI or DER wrapper, not the seed, never the
/// private key. The fixed-size array carries that requirement in the type rather
/// than as a runtime check.
///
/// It is never truncated, because `key_id` doubles as an anchor index where a
/// collision would silently select the wrong key.
#[must_use]
pub fn key_id(public_key: &[u8; 32]) -> String {
    payload::sha256_hex(public_key)
}

/// Reports whether `value` is safe to use as a build identifier: made of ASCII
/// alphanumerics and `.` `-` `_` `+` `~` `:`, non-empty, not starting with `.`
/// or `-`, and at most 128 bytes long — measured in bytes rather than
/// characters.
///
/// The charset is the one a **store-path segment** may hold, which is why the
/// predicate is exported: a caller about to join one of a manifest's identity
/// fields into a path needs the same rule the verifier applies. It returns a
/// `bool` and never a `Result` because naming the failure belongs to the caller
/// — the same `false` is [`VerifyError::UnsafeBuildIdentifier`] here and
/// something else entirely to a store-path join.
///
/// This is distinct from the archive-member rule
/// [`is_safe_archive_path`] states: a
/// valid signature over a manifest does not make an identity field safe to use
/// as a directory name.
#[must_use]
pub fn is_safe_build_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_BUILD_IDENTIFIER_BYTES {
        return false;
    }
    if value.starts_with('.') || value.starts_with('-') {
        return false;
    }
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~' | b':')
    })
}

/// Which identity field of an artifact entry [`is_safe_build_identifier`]
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildIdentifier {
    /// The entry's `component`, which is its package-id.
    Component,
    /// The entry's `version`.
    Version,
    /// The entry's `commit`, the immutable build identity.
    Commit,
}

impl std::fmt::Display for BuildIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Component => "component",
            Self::Version => "version",
            Self::Commit => "commit",
        };
        f.write_str(name)
    }
}

/// Errors raised while **constructing** a [`TrustSet`] or a [`VerifyRequest`].
///
/// Deliberately not [`VerifyError`] and not a variant of it: that type answers
/// "what is wrong with this package", these answer "what is wrong with what you
/// passed in", and a caller matching exhaustively on the package taxonomy must
/// not have that match widened by someone else's input bug.
///
/// Unlike [`VerifyError`]'s, these names are this crate's own and carry no
/// cross-repository commitment.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// Two anchors carried the same public key.
    ///
    /// Refused at construction rather than resolved, because the same key
    /// entered twice — once revoked, once not — is an input whose verdict would
    /// otherwise depend on iteration order. It is refused on the *key*, since
    /// deriving the id from the key makes a duplicate id and a duplicate key
    /// the same condition.
    #[error("two trust anchors share the public key with key id `{key_id}`")]
    DuplicateAnchor {
        /// `key_id` both anchors derived.
        key_id: String,
    },

    /// An ordinary package request named the reserved [`TRUST_TARGET`].
    ///
    /// A runtime refusal because a target arriving as a plain string cannot be
    /// constrained by the type. The *epoch* pairing is a different matter and
    /// needs no check at all: it is unrepresentable, enforced by which
    /// constructor was called.
    #[error(
        "`{TRUST_TARGET}` is reserved; build a trust-target request with `VerifyRequest::for_trust`"
    )]
    ReservedTarget,

    /// A namespace-scoped request named a namespace that is not a valid
    /// identifier segment (see [`is_valid_segment`]).
    #[error("namespace `{namespace}` is not a valid identifier segment")]
    InvalidNamespace {
        /// The refused namespace.
        namespace: String,
    },
}

/// One trusted release-signing key, with the revocation flag the trust set was
/// delivered with.
///
/// A revoked anchor **keeps its public key**: telling
/// [`VerifyError::RevokedKey`] from [`VerifyError::BadSignature`] means
/// verifying *under* the revoked key, so an input shape that dropped it could
/// not answer the question.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    public_key: [u8; 32],
    revoked: bool,
    key_id: String,
}

impl TrustAnchor {
    /// Creates an anchor from its raw Ed25519 public key and revocation flag,
    /// deriving the `key_id` itself.
    ///
    /// The id is never supplied: a caller cannot hand in one that disagrees
    /// with its own key, so there is no mismatch case to define and no second
    /// derivation site to drift from [`key_id`].
    #[must_use]
    pub fn new(public_key: [u8; 32], revoked: bool) -> Self {
        let key_id = key_id(&public_key);
        Self {
            public_key,
            revoked,
            key_id,
        }
    }

    /// Returns the anchor's raw Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns whether this anchor was delivered as revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns the anchor's `key_id`, as [`key_id`] derives it from
    /// [`TrustAnchor::public_key`].
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Reports whether `signature` verifies over `message` under this anchor's
    /// key.
    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(message, signature)
            .is_ok()
    }
}

/// The trust inputs a verification is made against, as a plain injected value.
///
/// This verifier never reads a trust generation from disk — that is a later,
/// separate concern — so everything trust-derived arrives here from a caller
/// that has already read it: no paths, no I/O, no product types, no registry
/// lookup.
#[derive(Debug, Clone)]
pub struct TrustSet {
    anchors: Vec<TrustAnchor>,
    withdrawn_builds: BTreeSet<(String, String, String)>,
    min_manifest_format_version: u32,
    epoch: u64,
}

impl TrustSet {
    /// Creates a trust set from its anchors, its withdrawn builds, the minimum
    /// manifest `format_version` it accepts, and its active `epoch`.
    ///
    /// `withdrawn_builds` are `(package-id, version, commit)` triples compared
    /// as exact strings. `epoch` is used only for the reserved
    /// [`TRUST_TARGET`], and is not the manifest's own `trust_set` field, which
    /// this crate neither reads nor interprets.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::DuplicateAnchor`] when two anchors share a public
    /// key. It never panics: this is a recoverable caller error.
    pub fn new(
        anchors: Vec<TrustAnchor>,
        withdrawn_builds: Vec<(String, String, String)>,
        min_manifest_format_version: u32,
        epoch: u64,
    ) -> Result<Self, InputError> {
        let mut seen: HashSet<&str> = HashSet::with_capacity(anchors.len());
        for anchor in &anchors {
            if !seen.insert(anchor.key_id.as_str()) {
                return Err(InputError::DuplicateAnchor {
                    key_id: anchor.key_id.clone(),
                });
            }
        }
        Ok(Self {
            anchors,
            withdrawn_builds: withdrawn_builds.into_iter().collect(),
            min_manifest_format_version,
            epoch,
        })
    }

    /// Returns the anchors this set holds, revoked ones included.
    #[must_use]
    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// Reports whether `(component, version, commit)` is a withdrawn build.
    fn is_withdrawn(&self, component: &str, version: &str, commit: &str) -> bool {
        self.withdrawn_builds
            .iter()
            .any(|(package_id, withdrawn_version, withdrawn_commit)| {
                package_id == component
                    && withdrawn_version == version
                    && withdrawn_commit == commit
            })
    }
}

/// The build a caller is asking for, as a plain injected value.
///
/// Every constructor either names the reserved [`TRUST_TARGET`] itself or
/// refuses it, and only one of them carries an `epoch` — the exported forms are
/// [`VerifyRequest::for_package`], [`VerifyRequest::for_namespaced_package`] and
/// [`VerifyRequest::for_trust`], and the crate-internal
/// `for_trust_self_admission` joins them. That is what makes an `epoch` on a
/// non-[`TRUST_TARGET`] target **unrepresentable** rather than refused at
/// runtime: there is no state in which one accompanies another target, because
/// the pairing is decided by which constructor was called. A namespace is
/// paired the same way: only [`VerifyRequest::for_namespaced_package`] carries
/// one, and it refuses the reserved target.
#[derive(Debug, Clone)]
pub struct VerifyRequest {
    target: String,
    version: String,
    commit: String,
    epoch: Option<u64>,
    namespace: Option<String>,
}

impl VerifyRequest {
    /// Creates a request for an ordinary package: the package-id, the version
    /// and the commit the caller is asking for.
    ///
    /// `target` is compared against a manifest artifact entry's `component` as
    /// a plain string; no package-id registry is consulted, which is product
    /// knowledge this verifier must not need.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::ReservedTarget`] when `target` is
    /// [`TRUST_TARGET`], which has its own constructor. It never panics.
    pub fn for_package(target: &str, version: &str, commit: &str) -> Result<Self, InputError> {
        if target == TRUST_TARGET {
            return Err(InputError::ReservedTarget);
        }
        Ok(Self {
            target: target.to_string(),
            version: version.to_string(),
            commit: commit.to_string(),
            epoch: None,
            namespace: None,
        })
    }

    /// Creates a request for an ordinary package deployed in `namespace`: the
    /// form a package declaring container images must be verified under.
    ///
    /// `namespace` is the caller's own trusted ownership configuration — the
    /// namespace its product or deployment is installed under — and never a
    /// value read off the package being verified. Every image declaration's
    /// `owner.namespace` must equal it verbatim, with no prefix stripped and no
    /// normalization, and its `owner.component` must equal `target`.
    ///
    /// Everything [`VerifyRequest::for_package`] enforces still holds: every
    /// artifact entry, a dependency image included, must match `target`,
    /// `version` and `commit` exactly. A package declaring no images verifies
    /// exactly as it would under [`VerifyRequest::for_package`], and so does a
    /// legacy package whose images carry no declaration; neither acquires one.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::ReservedTarget`] when `target` is
    /// [`TRUST_TARGET`], whose epoch contract only
    /// [`VerifyRequest::for_trust`] carries, and
    /// [`InputError::InvalidNamespace`] when `namespace` is not a valid
    /// identifier segment. It never panics.
    pub fn for_namespaced_package(
        target: &str,
        version: &str,
        commit: &str,
        namespace: &str,
    ) -> Result<Self, InputError> {
        let mut request = Self::for_package(target, version, commit)?;
        if !is_valid_segment(namespace) {
            return Err(InputError::InvalidNamespace {
                namespace: namespace.to_string(),
            });
        }
        request.namespace = Some(namespace.to_string());
        Ok(request)
    }

    /// Creates a request for the reserved [`TRUST_TARGET`], supplying the
    /// reserved name itself and carrying the delivered generation's `epoch`.
    ///
    /// # Errors
    ///
    /// Infallible today, and `Result` all the same: it is the matched pair of
    /// [`VerifyRequest::for_package`], which is not, and a caller writes one
    /// shape for both. It never panics.
    pub fn for_trust(version: &str, commit: &str, epoch: u64) -> Result<Self, InputError> {
        Ok(Self {
            target: TRUST_TARGET.to_string(),
            version: version.to_string(),
            commit: commit.to_string(),
            epoch: Some(epoch),
            namespace: None,
        })
    }

    /// Creates a request for the **self-admission** of a trust generation: the
    /// reserved [`TRUST_TARGET`], and deliberately **no** delivered `epoch`, so
    /// [`check_epoch`] returns before it compares anything.
    ///
    /// A generation is admitted by verifying it under the anchors carried
    /// *inside the very document being admitted* — there is no other key
    /// material available for the first one, and the document must in any case
    /// be checked against what it itself claims. The candidate trust set is
    /// therefore built from the delivered document, so its epoch and the
    /// delivered epoch are the same number, and the strictly-greater comparison
    /// [`VerifyRequest::for_trust`] arms would answer
    /// [`VerifyError::StaleTrustSet`] for every well-formed input. Here the
    /// epoch branch is not taken at all: there is no epoch floor, and that is a
    /// property of the call rather than of a caller's arithmetic. **A caller
    /// with an active generation to compare a delivered one against wants
    /// [`VerifyRequest::for_trust`] instead** — this form applies no
    /// anti-rollback check whatsoever.
    ///
    /// Everything else the request enforces is unchanged: [`check_target`]
    /// still requires the manifest's single artifact entry to match the target,
    /// the decimal `version` and the member-digest `commit` exactly.
    ///
    /// # The decode that precedes this call
    ///
    /// [`verify_package`] takes a [`TrustSet`] by value, so a caller must
    /// already hold one, which for a first generation means decoding the
    /// delivered document before anything has authenticated it. That decode is
    /// permitted and it is bounded:
    ///
    /// - it is **permissive**, and it reads `anchors` (each entry's `key_id`,
    ///   `public_key` and `revoked`) and `epoch` and **no other field** —
    ///   those two because they are the only ones this call consumes: `anchors`
    ///   supplies the candidate anchors and `epoch` in decimal is this
    ///   request's `version`. The request's other two parts need no parse at
    ///   all: `target` is [`TRUST_TARGET`] and `commit` is the document
    ///   member's digest over the bytes just read;
    /// - it is **not** the refusing reader in
    ///   [`crate::trust_set`]. Running that here would be a defect: it would
    ///   report a parse refusal where a signature failure belongs, and would
    ///   decide things about bytes no anchor has vouched for;
    /// - it is **not admission**. Nothing it produces is stored, returned or
    ///   becomes the generation. Admission is [`verify_package`] returning
    ///   `Ok`, after which the refusing reader parses the member bytes again,
    ///   from scratch, and the generation is built from *that* parse;
    /// - the digest ties the two halves together: the bytes the provisional
    ///   decode read are the bytes whose digest [`check_target`] compares
    ///   against the signed manifest's `commit`, so a caller that verified over
    ///   one byte range and parsed another cannot pass.
    ///
    /// A failure of that decode is a refusal of the admission *attempt*, named
    /// by the admission path's own error type, and never a refusal of a
    /// document.
    ///
    /// # The candidate trust set
    ///
    /// [`TrustSet::new`] takes four arguments and the provisional decode reads
    /// two fields, so the other two are stated here rather than improvised.
    /// Each is the identity value for a check this call deliberately does not
    /// make:
    ///
    /// - `anchors` — **every** anchor the decode produced, each carrying its
    ///   `revoked` flag, revoked ones included, so a generation signed by a key
    ///   its own document marks revoked is refused as [`VerifyError::RevokedKey`]
    ///   rather than as [`VerifyError::UnknownKeyId`] by a pruned list. The
    ///   decode is all-or-nothing: every entry must yield a [`TrustAnchor`], or
    ///   the attempt fails;
    /// - `withdrawn_builds` — **empty**, the identity of [`check_withdrawal`].
    ///   This container carries exactly one triple — the reserved target, this
    ///   document's own epoch, this document's own member digest — so the only
    ///   entry that could ever match is one in which the document withdraws
    ///   *itself*, which is not a control anyone exercises. The list a document
    ///   really carries governs every *later* package and takes effect once the
    ///   verified document is installed;
    /// - `min_manifest_format_version` — **`0`**, the identity of
    ///   [`check_format_version`], which is exactly this build's own range since
    ///   [`PayloadManifest::parse`] already refuses anything outside it. A
    ///   document declaring a floor above its own envelope's `format_version`
    ///   would otherwise brick itself, and admission would turn on an integer
    ///   read from unauthenticated bytes;
    /// - `epoch` — the provisional `epoch`, passed through unchanged. Under
    ///   this request form it is **read by nothing**, since [`check_epoch`]
    ///   returns early; it is passed through rather than zeroed so that no
    ///   number appears in the call that did not come from the document.
    ///
    /// # Errors
    ///
    /// Infallible today, and `Result` all the same: it is the matched shape of
    /// the two constructors beside it, one of which is not. It never panics.
    // `Result` is the point rather than an oversight: this is the third of three
    // constructors a caller writes one shape for, and `for_package` is genuinely
    // fallible. The lint sees only this one because, unlike its two siblings, it
    // is not exported.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn for_trust_self_admission(
        version: &str,
        commit: &str,
    ) -> Result<Self, InputError> {
        Ok(Self {
            target: TRUST_TARGET.to_string(),
            version: version.to_string(),
            commit: commit.to_string(),
            epoch: None,
            namespace: None,
        })
    }

    /// Returns the package-id this request names.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the version this request names.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the commit this request names.
    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// Returns the namespace this request is scoped to, or `None` for a
    /// request built by any constructor but
    /// [`VerifyRequest::for_namespaced_package`].
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
}

/// Errors describing **the package being verified**.
///
/// The top level is exactly fifteen variants and downstream repositories match
/// on them, so neither the set nor the spelling is this crate's to change. What
/// each one carries is. The fifteenth, [`VerifyError::Image`], was added for the
/// image declaration semantics; a downstream exhaustive match gains one arm for
/// it, and every later image condition extends [`ImageVerifyError`] rather than
/// this set.
///
/// Container-layer conditions are not lifted here: they stay inside
/// [`PayloadError`] and reach a caller through [`VerifyError::Payload`], matched
/// as `VerifyError::Payload(PayloadError::MalformedFooter { .. })` and so on.
/// The four exceptions are *mapped* rather than surfaced —
/// [`PayloadError::HashMismatch`], [`ManifestError::DuplicateArchivePath`],
/// [`ManifestError::UnsafeArchivePath`] and
/// [`ManifestError::UnsupportedManifestFormat`] become top-level variants here
/// and never also arrive nested.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// No anchor's key verifies the signature over the manifest block — or the
    /// container carries no signature at all.
    ///
    /// An unsigned package is this and not a variant of its own: the unsigned
    /// [`crate::payload::append_trailer`] entry point emits both envelope pairs
    /// absent, so unsigned packages exist and must be answered, and one this
    /// verifier cannot authenticate is not a new failure mode. It is also what
    /// an unusable `key_id` hint falls back to, since a hint that is not a
    /// `key_id` at all names nothing.
    ///
    /// A signature block present at any length other than the 64 bytes an
    /// Ed25519 signature is reaches this the ordinary way rather than directly:
    /// it verifies under no anchor, so the same four-step order names the
    /// rejection, which for a usable hint naming no anchor is
    /// [`VerifyError::UnknownKeyId`].
    #[error("no trust anchor verifies the package signature")]
    BadSignature,

    /// The container's `key_id` hint was usable, named no anchor in the trust
    /// set, and nothing else verified either.
    ///
    /// "The package named a key we do not hold", which takes a well-formed
    /// name: an unusable hint falls to [`VerifyError::BadSignature`].
    #[error("the package names key id `{key_id}`, which is in no trust anchor")]
    UnknownKeyId {
        /// The hint the container carried.
        key_id: String,
    },

    /// The package's actual signer is a revoked anchor.
    ///
    /// Judged from the anchor that verified, never from the footer hint, and
    /// only once no non-revoked anchor verified.
    #[error("the package is signed by revoked key `{key_id}`")]
    RevokedKey {
        /// `key_id` of the anchor that verified the signature.
        key_id: String,
    },

    /// The manifest's `format_version` is outside the range this build
    /// implements, or below the trust set's injected floor.
    ///
    /// One name for both, and the reported range says which: a floor above the
    /// implemented ceiling is a real configuration, and reads as accepting
    /// nothing.
    #[error("unsupported manifest format version {found} (accepted range is {min}..={max})")]
    UnsupportedManifestFormat {
        /// Version the manifest declared.
        found: u32,
        /// Inclusive floor that was applied.
        min: u32,
        /// Inclusive ceiling that was applied.
        max: u32,
    },

    /// The manifest's bound member list names a member no artifact entry claims
    /// by `archive_path`.
    #[error("bound archive member `{0}` is claimed by no artifact entry")]
    UnlistedMember(String),

    /// A path appears twice — repeated in the bound member list, or, mapped
    /// from the parse, shared by two artifact entries.
    #[error("duplicate archive path `{0}`")]
    DuplicatePath(String),

    /// A path is not a safe relative path — in the bound member list, or,
    /// mapped from the parse, on an artifact entry.
    #[error("unsafe archive path `{0}`")]
    UnsafePath(String),

    /// An artifact entry's required member is absent from the bound list, or
    /// the manifest carries no artifact entries at all.
    ///
    /// The second case is a signed, structurally valid, empty allow-list, which
    /// would otherwise pass every other check precisely because it forbids
    /// nothing.
    #[error("{}", describe_missing_member(.member.as_deref()))]
    MissingRequiredMember {
        /// `archive_path` of the required member, or `None` when the manifest
        /// binds no artifact entries at all.
        member: Option<String>,
    },

    /// An artifact's bytes did not match the SHA-256 its manifest entry
    /// records.
    ///
    /// Mapped from [`PayloadError::HashMismatch`], never a second comparison:
    /// the check lives in the extraction walk, where the bytes already stream,
    /// so this is reachable through [`VerifiedPackage::extract_to`] and not
    /// from [`verify_package`] itself.
    #[error("sha-256 mismatch for artifact `{path}`")]
    ManifestHashMismatch {
        /// `archive_path` of the offending artifact.
        path: String,
    },

    /// An artifact entry's `component`, `version` or `commit` is not safe to
    /// use as a build identifier (see [`is_safe_build_identifier`]).
    #[error("artifact {field} `{value}` is not a safe build identifier")]
    UnsafeBuildIdentifier {
        /// Which identity field was refused.
        field: BuildIdentifier,
        /// The refused value.
        value: String,
    },

    /// An artifact entry does not carry the request's target, version and
    /// commit.
    ///
    /// Every entry must, not merely one: a package satisfying the request with
    /// one entry while carrying another component's artifacts alongside would
    /// be extracted and installed whole.
    ///
    /// Only the offending entry is carried. What was asked for is the request
    /// the caller passed in and still holds, and repeating it here would make
    /// this the one variant large enough to weigh down every `Result` in the
    /// module.
    #[error("artifact `{component}`/`{version}`/`{commit}` is not the requested build")]
    TargetMismatch {
        /// The disagreeing entry's `component`.
        component: String,
        /// Its `version`.
        version: String,
        /// Its `commit`.
        commit: String,
    },

    /// A build the manifest names is on the trust set's withdrawn list.
    ///
    /// Decided from the manifest, never from the request: reading it from the
    /// request would hand the anti-rollback decision to the hop the withdrawn
    /// list exists to defend against.
    #[error("build `{package_id}`/`{version}`/`{commit}` is withdrawn")]
    WithdrawnBuild {
        /// The withdrawn build's package-id.
        package_id: String,
        /// Its version.
        version: String,
        /// Its commit.
        commit: String,
    },

    /// A trust-material package's delivered `epoch` does not advance past the
    /// active one.
    #[error("delivered trust epoch {delivered} does not advance past the active epoch {active}")]
    StaleTrustSet {
        /// Epoch the delivered generation carries.
        delivered: u64,
        /// Epoch the trust set is active at.
        active: u64,
    },

    /// A container-layer condition, surfaced under its own name rather than
    /// redefined here.
    ///
    /// Carries no `#[from]`, and the [`From`] impl beside it is hand-written on
    /// purpose: a derived one would wrap *every* [`PayloadError`], including
    /// the [`PayloadError::HashMismatch`] that must arrive as
    /// [`VerifyError::ManifestHashMismatch`].
    #[error(transparent)]
    Payload(PayloadError),

    /// An image declaration the package makes disagrees with its artifact,
    /// with another declaration, or with the request.
    ///
    /// Only the semantic checks that follow the target and epoch — steps 10
    /// through 15 of the order this module states — arrive here. A declaration
    /// whose shape or syntax is invalid is refused by the typed parse and
    /// arrives as [`VerifyError::Payload`] carrying
    /// [`PayloadError::InvalidManifest`].
    #[error(transparent)]
    Image(ImageVerifyError),
}

/// Image declaration semantics a package violates, reported as
/// [`VerifyError::Image`].
///
/// This is the extension point for later image checks, so a caller matching
/// [`VerifyError`] exhaustively names image conditions through one arm.
#[derive(Debug)]
pub enum ImageVerifyError {
    /// A declaration's architecture is not the one its artifact's
    /// `target_arch` maps to.
    PlatformMismatch {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The artifact's architecture.
        target_arch: TargetArch,
        /// The architecture its declaration names.
        declared: ImageArchitecture,
    },

    /// A reference under [`RUNTIME_ALIAS_REGISTRY`] is not exactly the
    /// canonical alias its own declaration's owner, dependency and config
    /// digest determine.
    NonCanonicalReservedReference {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The refused reference, as signed.
        reference: String,
        /// The alias the declaration determines, or `None` when its segments
        /// cannot form a valid alias at all.
        expected: Option<String>,
    },

    /// A canonical reference under [`RUNTIME_ALIAS_REGISTRY`] is declared
    /// with a lifecycle other than [`ReferenceLifecycle::ManagedRuntime`].
    ReservedReferenceLifecycle {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The reference.
        reference: String,
    },

    /// Two declarations assign one normalized reference to images that
    /// differ in config digest, platform, owner or lifecycle.
    ConflictingReference {
        /// `archive_path` of the later artifact.
        archive_path: String,
        /// The later reference, as signed.
        reference: String,
        /// `archive_path` of the artifact that assigned it first.
        first_archive_path: String,
        /// The first assignment's reference, as signed.
        first_reference: String,
        /// The first facet, in that order, in which the two differ.
        conflict: ReferenceConflict,
    },

    /// The manifest declares images and the request carries no namespace to
    /// check their owner against.
    MissingNamespace {
        /// `archive_path` of the first declaring artifact.
        archive_path: String,
    },

    /// A declaration's `owner.namespace` is not verbatim the request's.
    NamespaceMismatch {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The request's namespace.
        expected: String,
        /// The declared namespace.
        declared: String,
    },

    /// A declaration's `owner.component` is not the requested target.
    OwnerComponentMismatch {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The requested target.
        expected: String,
        /// The declared owner component.
        declared: String,
    },

    /// An image artifact of a legacy manifest carries no declaration, so no
    /// image evidence can be made for it. It is refused explicitly rather
    /// than represented as no images.
    LegacyImageEvidence {
        /// `archive_path` of the offending artifact.
        archive_path: String,
    },

    /// An image archive uses a form the supported archive profile names as
    /// excluded.
    UnsupportedArchive {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The excluded feature.
        feature: UnsupportedArchiveFeature,
    },

    /// An image archive is malformed or internally inconsistent.
    InvalidArchive {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// What is wrong with it.
        reason: InvalidArchiveReason,
    },

    /// An image archive restores a reference its declaration does not sign.
    UndeclaredReference {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The reference as the archive spells it; it parsed as a tagged
        /// reference.
        reference: String,
        /// Where the archive names it.
        source: ReferenceSource,
    },

    /// An image archive does not restore a reference its declaration signs.
    MissingReference {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The signed reference, as signed.
        reference: String,
        /// Where the archive should have named it.
        source: ReferenceSource,
    },

    /// An image archive's config does not hash to the declared config digest.
    ConfigDigestMismatch {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The signed config digest.
        declared: String,
        /// The digest of the config the archive holds.
        actual: String,
    },

    /// A platform the image archive states disagrees with the declared
    /// platform.
    ///
    /// This is the archive's own config or descriptor platform against the
    /// declaration; [`ImageVerifyError::PlatformMismatch`] is the
    /// declaration against its artifact's target. The message never renders
    /// `actual`, which is archive content.
    ConfigPlatformMismatch {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// Where the archive states the platform.
        location: PlatformLocation,
        /// The first facet that disagrees.
        facet: PlatformFacet,
        /// The signed value, or `None` for a signed null variant.
        declared: Option<String>,
        /// The value the archive states, or `None` for an absent or null
        /// variant.
        actual: Option<String>,
    },

    /// An image archive's layers disagree with its config or descriptors.
    LayerMismatch {
        /// `archive_path` of the offending artifact.
        archive_path: String,
        /// The layer's position in the manifest's `layers`, or `None` for a
        /// disagreement about the layers as a whole.
        position: Option<usize>,
        /// How they disagree.
        kind: LayerMismatchKind,
        /// The digest or decimal count expected.
        expected: Option<String>,
        /// The digest or decimal count found.
        actual: Option<String>,
    },
}

// Written by hand rather than derived: `UndeclaredReference` and
// `MissingReference` carry a field named `source` that is a
// [`ReferenceSource`], and `thiserror` takes any field of that name to be the
// underlying error. None of these conditions wraps another error.
impl std::error::Error for ImageVerifyError {}

impl std::fmt::Display for ImageVerifyError {
    // One arm per variant, each a single message; splitting it would only
    // scatter them.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlatformMismatch {
                archive_path,
                target_arch,
                declared,
            } => write!(
                f,
                "image artifact `{archive_path}` is built for {target_arch:?} yet declares architecture {declared}"
            ),
            Self::NonCanonicalReservedReference {
                archive_path,
                reference,
                expected,
            } => f.write_str(&describe_reserved_reference(
                archive_path,
                reference,
                expected.as_deref(),
            )),
            Self::ReservedReferenceLifecycle {
                archive_path,
                reference,
            } => write!(
                f,
                "reserved reference `{reference}` of image artifact `{archive_path}` is not managed_runtime"
            ),
            Self::ConflictingReference {
                archive_path,
                reference,
                first_archive_path,
                first_reference,
                conflict,
            } => write!(
                f,
                "reference `{reference}` of image artifact `{archive_path}` conflicts in {conflict} with `{first_reference}` of `{first_archive_path}`"
            ),
            Self::MissingNamespace { archive_path } => write!(
                f,
                "image artifact `{archive_path}` declares an owner, and the request carries no namespace"
            ),
            Self::NamespaceMismatch {
                archive_path,
                expected,
                declared,
            } => write!(
                f,
                "image artifact `{archive_path}` is owned by namespace `{declared}`, not the requested `{expected}`"
            ),
            Self::OwnerComponentMismatch {
                archive_path,
                expected,
                declared,
            } => write!(
                f,
                "image artifact `{archive_path}` is owned by component `{declared}`, not the requested `{expected}`"
            ),
            Self::LegacyImageEvidence { archive_path } => write!(
                f,
                "image artifact `{archive_path}` is a legacy image with no declaration"
            ),
            Self::UnsupportedArchive {
                archive_path,
                feature,
            } => write!(f, "image archive `{archive_path}` uses {feature}"),
            Self::InvalidArchive {
                archive_path,
                reason,
            } => write!(f, "image archive `{archive_path}` is invalid: {reason}"),
            Self::UndeclaredReference {
                archive_path,
                reference,
                source,
            } => write!(
                f,
                "image archive `{archive_path}` restores undeclared reference `{reference}` in its {source}"
            ),
            Self::MissingReference {
                archive_path,
                reference,
                source,
            } => write!(
                f,
                "image archive `{archive_path}` does not restore declared reference `{reference}` in its {source}"
            ),
            Self::ConfigDigestMismatch {
                archive_path,
                declared,
                actual,
            } => write!(
                f,
                "image archive `{archive_path}` holds config `{actual}`, not the declared `{declared}`"
            ),
            Self::ConfigPlatformMismatch {
                archive_path,
                location,
                facet,
                declared,
                actual: _,
            } => f.write_str(&describe_config_platform_mismatch(
                archive_path,
                *location,
                *facet,
                declared.as_deref(),
            )),
            Self::LayerMismatch {
                archive_path,
                position,
                kind,
                expected,
                actual,
            } => f.write_str(&describe_layer_mismatch(
                archive_path,
                *position,
                *kind,
                expected.as_deref(),
                actual.as_deref(),
            )),
        }
    }
}

/// Which facet of two assignments of one reference differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceConflict {
    /// `config_digest`, the image identity.
    ConfigDigest,
    /// `platform`, its variant included.
    Platform,
    /// `owner`.
    Owner,
    /// `reference_lifecycle`.
    Lifecycle,
}

impl std::fmt::Display for ReferenceConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ConfigDigest => "config digest",
            Self::Platform => "platform",
            Self::Owner => "owner",
            Self::Lifecycle => "lifecycle",
        })
    }
}

/// Renders [`ImageVerifyError::NonCanonicalReservedReference`]'s message.
fn describe_reserved_reference(
    archive_path: &str,
    reference: &str,
    expected: Option<&str>,
) -> String {
    match expected {
        Some(expected) => format!(
            "reserved reference `{reference}` of image artifact `{archive_path}` is not its canonical alias `{expected}`"
        ),
        None => format!(
            "reserved reference `{reference}` of image artifact `{archive_path}` has no valid canonical alias to match"
        ),
    }
}

/// Renders [`ImageVerifyError::ConfigPlatformMismatch`]'s message, which names
/// the signed value and never the observed one.
fn describe_config_platform_mismatch(
    archive_path: &str,
    location: PlatformLocation,
    facet: PlatformFacet,
    declared: Option<&str>,
) -> String {
    let declared = declared.map_or_else(|| "no variant".to_string(), |value| format!("`{value}`"));
    format!(
        "image archive `{archive_path}` states a {facet} in its {location} that differs from the declared {declared}"
    )
}

/// Renders [`ImageVerifyError::LayerMismatch`]'s message.
fn describe_layer_mismatch(
    archive_path: &str,
    position: Option<usize>,
    kind: LayerMismatchKind,
    expected: Option<&str>,
    actual: Option<&str>,
) -> String {
    let at = position.map_or_else(String::new, |position| format!(" at layer {position}"));
    let values = match (expected, actual) {
        (Some(expected), Some(actual)) => format!(": expected {expected}, found {actual}"),
        (Some(expected), None) => format!(": expected {expected}"),
        (None, Some(actual)) => format!(": found {actual}"),
        (None, None) => String::new(),
    };
    format!("image archive `{archive_path}` has a {kind} mismatch{at}{values}")
}

/// Renders [`VerifyError::MissingRequiredMember`]'s message for both cases it
/// covers.
fn describe_missing_member(member: Option<&str>) -> String {
    member.map_or_else(
        || "the manifest binds no artifact entries at all".to_string(),
        |member| format!("required archive member `{member}` is not bound by the manifest"),
    )
}

impl From<PayloadError> for VerifyError {
    /// Hand-written, and it has to be: `#[from]` on the wrapper variant would
    /// generate a blanket impl wrapping every [`PayloadError`] — including
    /// `HashMismatch`, in flat contradiction of
    /// [`VerifyError::ManifestHashMismatch`] — and would collide with this one
    /// besides.
    fn from(error: PayloadError) -> Self {
        match error {
            PayloadError::HashMismatch { path } => Self::ManifestHashMismatch { path },
            other => Self::Payload(other),
        }
    }
}

/// Maps a [`ManifestError`] raised by the verifier's own call to
/// [`PayloadManifest::parse`].
///
/// There is deliberately no `impl From<ManifestError> for VerifyError`: three
/// of these conditions are mapped onto top-level variants and must never also
/// arrive nested, and a `From` impl would offer a second, non-selective route
/// that any `?` could take without thinking. This is the only site in the crate
/// that parses a manifest on the verification path, so it is genuinely the only
/// door.
///
/// The last two arms reproduce exactly what [`payload::open`] does with a
/// `ManifestError`, so a manifest that fails to decode reports identically
/// whether it was read through `open` or through this verifier.
fn map_manifest_error(error: ManifestError) -> VerifyError {
    match error {
        ManifestError::DuplicateArchivePath(path) => VerifyError::DuplicatePath(path),
        ManifestError::UnsafeArchivePath(path) => VerifyError::UnsafePath(path),
        ManifestError::UnsupportedManifestFormat { found, min, max } => {
            VerifyError::UnsupportedManifestFormat { found, min, max }
        }
        ManifestError::Decode(source) => VerifyError::Payload(PayloadError::ManifestParse(source)),
        other => VerifyError::Payload(PayloadError::InvalidManifest(other)),
    }
}

/// A package that has passed every check [`verify_package`] makes, holding the
/// container it was read from so its artifacts can be extracted.
///
/// A type rather than a bare [`Payload`] for two reasons: a caller forced to
/// re-open the container to learn what it just accepted would be parsing
/// attacker bytes a second time, and "verified" becomes a fact the type system
/// carries, so extraction cannot be reached without having gone through
/// verification.
#[derive(Debug)]
pub struct VerifiedPackage<R: Read + Seek> {
    payload: Payload<R>,
}

impl<R: Read + Seek> VerifiedPackage<R> {
    /// Returns the verified manifest.
    #[must_use]
    pub fn manifest(&self) -> &PayloadManifest {
        self.payload.manifest()
    }

    /// Returns what the verified manifest states about its image references.
    ///
    /// This describes authenticated statements and nothing more. No archive
    /// member has been extracted, hashed or opened as an image, so a
    /// [`ImageReferences::Declared`] result says what the signer declared and
    /// the request agreed with — not that the archive holds such an image.
    #[must_use]
    pub fn image_references(&self) -> ImageReferences<'_> {
        let images: Vec<&PayloadArtifact> = self
            .manifest()
            .artifacts()
            .iter()
            .filter(|artifact| artifact.kind == ArtifactKind::ContainerImage)
            .collect();
        if images.is_empty() {
            ImageReferences::NoImages
        } else if images.iter().all(|artifact| artifact.image.is_some()) {
            ImageReferences::Declared(DeclaredImageReferences { artifacts: images })
        } else {
            ImageReferences::LegacyUndeclared
        }
    }

    /// Extracts every artifact into `dest`, under this taxonomy's names.
    ///
    /// The walk itself is the container layer's own
    /// [`Payload::extract_to`](crate::payload::Payload::extract_to), unchanged
    /// and un-rewrapped: this adds no check of its own and converts what that
    /// returns, which is the single place [`PayloadError::HashMismatch`]
    /// becomes [`VerifyError::ManifestHashMismatch`] and every other condition
    /// becomes [`VerifyError::Payload`]. So a caller that verifies and then
    /// extracts sees one taxonomy end to end and never applies the mapping by
    /// hand.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::ManifestHashMismatch`] when an artifact's bytes
    /// do not match the SHA-256 the manifest records, and
    /// [`VerifyError::Payload`] carrying the container layer's own variant for
    /// every other rejection the walk makes.
    pub fn extract_to(&mut self, dest: &Path) -> Result<Vec<ExtractedArtifact>, VerifyError> {
        self.payload.extract_to(dest).map_err(VerifyError::from)
    }
}

/// What a verified package states about its container image references.
#[derive(Debug, Clone)]
pub enum ImageReferences<'a> {
    /// The package carries no container image artifact.
    NoImages,
    /// Every container image artifact carries an image declaration, and the
    /// declarations passed the namespace-scoped checks.
    Declared(DeclaredImageReferences<'a>),
    /// The package is a legacy manifest carrying container images that
    /// declare nothing. Their references are unknown — not empty.
    LegacyUndeclared,
}

/// The image declarations of a verified package, and the union of their
/// references.
#[derive(Debug, Clone)]
pub struct DeclaredImageReferences<'a> {
    artifacts: Vec<&'a PayloadArtifact>,
}

impl<'a> DeclaredImageReferences<'a> {
    /// Returns each container image artifact with its declaration, in manifest
    /// order.
    pub fn declarations(
        &self,
    ) -> impl Iterator<Item = (&'a PayloadArtifact, &'a ImageDeclaration)> {
        self.artifacts
            .iter()
            .filter_map(|artifact| artifact.image.as_ref().map(|image| (*artifact, image)))
    }

    /// Returns the union of every declaration's references: the signed
    /// literal strings, sorted and deduplicated as strings.
    ///
    /// Two spellings of one normalized reference both appear, because each is
    /// a literal some declaration signed; conflicts between them were decided
    /// on the normalized form during verification.
    #[must_use]
    pub fn references(&self) -> Vec<&'a str> {
        let union: BTreeSet<&'a str> = self
            .declarations()
            .flat_map(|(_, image)| image.public_refs.iter().map(String::as_str))
            .collect();
        union.into_iter().collect()
    }
}

/// Verifies the package in `src` against `trust` and `request`, returning it as
/// a [`VerifiedPackage`].
///
/// The signature is checked over the raw manifest-block bytes read off the
/// container, before those bytes are parsed, and the remaining checks run in
/// the total order this module's documentation states. Neither the archive
/// block nor any artifact's bytes are read here.
///
/// # Errors
///
/// Returns [`VerifyError`]: [`VerifyError::BadSignature`],
/// [`VerifyError::UnknownKeyId`] or [`VerifyError::RevokedKey`] when the
/// signature cannot be attributed to a usable anchor;
/// [`VerifyError::UnsupportedManifestFormat`] for a manifest version outside
/// the accepted range; [`VerifyError::UnlistedMember`],
/// [`VerifyError::DuplicatePath`], [`VerifyError::UnsafePath`] or
/// [`VerifyError::MissingRequiredMember`] for an incomplete manifest;
/// [`VerifyError::UnsafeBuildIdentifier`], [`VerifyError::WithdrawnBuild`],
/// [`VerifyError::TargetMismatch`] or [`VerifyError::StaleTrustSet`] for the
/// checks that follow; [`VerifyError::Image`] for an image declaration that
/// disagrees with its artifact, another declaration, or the request; and
/// [`VerifyError::Payload`] for a container-layer condition, including
/// [`PayloadError::NoTrailer`] when `src` carries no container at all, and for
/// a manifest that fails its typed parse, a malformed image declaration
/// included.
pub fn verify_package<R: Read + Seek>(
    src: R,
    trust: &TrustSet,
    request: &VerifyRequest,
) -> Result<VerifiedPackage<R>, VerifyError> {
    // 1. Locate the footer and read the blocks, leaving the manifest unparsed.
    //    The envelope blocks are read only at the lengths this verifier can
    //    use, because at this point nothing about the container is trusted yet.
    let container = payload::read_package_container(src, &ENVELOPE_BOUNDS)?;

    let manifest = authenticate(&container, trust, request)?;
    Ok(VerifiedPackage {
        payload: container.into_payload(manifest),
    })
}

/// What [`verify_package_bounded`] returns: the authenticated manifest and
/// where the archive block lies, as the validated footer records it.
#[derive(Debug)]
pub(crate) struct BoundedVerified {
    /// The manifest, authenticated and past every statement check.
    pub(crate) manifest: PayloadManifest,
    /// The archive block's offset within the container.
    pub(crate) archive_offset: u64,
    /// The archive block's length, at most the bound it was held to.
    pub(crate) archive_len: u64,
}

/// Why [`verify_package_bounded`] refused a package.
#[derive(Debug)]
pub(crate) enum BoundedVerifyError {
    /// A verdict, exactly as [`verify_package`] reports it.
    Verify(VerifyError),
    /// A block the footer advertises is longer than its ceiling.
    LimitExceeded {
        /// `RawManifest` or `CompressedArchive`.
        resource: LimitResource,
        /// That resource's configured value.
        limit: u64,
    },
    /// Retained storage failed a read or a seek; the original error.
    Io(std::io::Error),
}

/// Verifies a package exactly as [`verify_package`] does, with the footer's
/// manifest and archive lengths held to `bounds` before either block is read,
/// and retained-storage failures told apart from framing verdicts.
///
/// `src` is expected to be a retained snapshot read through a
/// `RetainedSource`, whose own failures carry a `RetainedIoFault` payload; one
/// is recovered, before anything else classifies the error, as
/// [`BoundedVerifyError::Io`]. Every other verdict and its order is
/// [`verify_package`]'s, since both share the framing, the envelope read and
/// every check after it.
///
/// # Errors
///
/// Returns [`BoundedVerifyError::LimitExceeded`] naming `RawManifest` or
/// `CompressedArchive`, [`BoundedVerifyError::Io`] for a retained-storage
/// failure, and [`BoundedVerifyError::Verify`] carrying what
/// [`verify_package`] would return.
pub(crate) fn verify_package_bounded<R: Read + Seek>(
    src: R,
    trust: &TrustSet,
    request: &VerifyRequest,
    bounds: ContainerBounds,
) -> Result<BoundedVerified, BoundedVerifyError> {
    let container = payload::read_package_container_bounded(src, &ENVELOPE_BOUNDS, bounds)
        .map_err(|error| match error {
            BoundedContainerError::Payload(error) => BoundedVerifyError::Verify(error.into()),
            BoundedContainerError::LimitExceeded { resource, limit } => {
                BoundedVerifyError::LimitExceeded { resource, limit }
            }
            BoundedContainerError::RetainedIo(error) => BoundedVerifyError::Io(error),
        })?;
    let manifest = authenticate(&container, trust, request).map_err(BoundedVerifyError::Verify)?;
    let (archive_offset, archive_len) = container.archive_block();
    Ok(BoundedVerified {
        manifest,
        archive_offset,
        archive_len,
    })
}

/// Steps 2 onwards of the order this module states, over a container whose
/// blocks have been read: the signature over the raw manifest bytes, the
/// version floor, the typed parse, then [`check_statements`].
fn authenticate<R: Read + Seek>(
    container: &UnparsedContainer<R>,
    trust: &TrustSet,
    request: &VerifyRequest,
) -> Result<PayloadManifest, VerifyError> {
    // 2. Authenticate the raw manifest bytes before anything parses them.
    verify_signature(container, trust)?;

    // 3. The version question, decided from stage one alone — before the body
    //    is decoded, so a manifest this build cannot make sense of is refused
    //    for its version rather than as a generic decode error. The injected
    //    floor is checked here; the build's own range is stage one's, inside
    //    the parse below, and reaches this taxonomy mapped.
    if let Some(found) =
        manifest::parse_format_version(container.manifest_bytes()).map_err(map_manifest_error)?
    {
        check_format_version(found, trust.min_manifest_format_version)?;
    }

    // 4. Parse, mapping the two path faults and the version refusal.
    let manifest = PayloadManifest::parse(container.manifest_bytes(), container.footer_version())
        .map_err(map_manifest_error)?;

    // 5-15. The statements the authenticated manifest makes.
    check_statements(&manifest, request, Some(trust))?;

    Ok(manifest)
}

/// Runs the post-parse statement checks — steps 5 through 15 — as one unit,
/// in exactly this order and each at most once:
///
/// 1. completeness;
/// 2. safe identifiers;
/// 3. withdrawal, **only when `trust` is `Some`**;
/// 4. the exact build target;
/// 5. the reserved-target epoch, **only when `trust` is `Some`**;
/// 6. the whole-manifest image passes, reported as [`VerifyError::Image`].
///
/// This is the one home of that sequence: [`verify_package`] makes a single
/// call with `Some`, whose body is exactly the order it always had.
///
/// With `None`, withdrawal and the epoch are skipped — they are the two
/// checks that read a verifier's [`TrustSet`] — and the other four run in the
/// same relative order. **An `Ok` from a `None` call decides nothing about
/// withdrawal, the epoch, the signature or the trust floor**: withdrawal and
/// the epoch are decided only when a [`TrustSet`] is supplied, and the
/// signature and trust floor only in the authenticated pipeline.
pub(crate) fn check_statements(
    manifest: &PayloadManifest,
    request: &VerifyRequest,
    trust: Option<&TrustSet>,
) -> Result<(), VerifyError> {
    // About the package first, about the request last.
    statement(Statement::Completeness);
    check_completeness(manifest)?;
    statement(Statement::Identifiers);
    check_identifiers(manifest)?;
    if let Some(trust) = trust {
        statement(Statement::Withdrawal);
        check_withdrawal(manifest, trust)?;
    }
    statement(Statement::Target);
    check_target(manifest, request)?;
    if let Some(trust) = trust {
        statement(Statement::Epoch);
        check_epoch(request, trust)?;
    }

    // The image declaration semantics, each a whole-manifest pass.
    statement(Statement::Images);
    check_images(manifest, request).map_err(VerifyError::Image)
}

/// One statement check, as the test recorder names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Statement {
    Completeness,
    Identifiers,
    Withdrawal,
    Target,
    Epoch,
    Images,
}

/// Records that `check` is about to run, for the call-order tests. A release
/// build records nothing.
#[cfg(not(test))]
fn statement(_check: Statement) {}

#[cfg(test)]
fn statement(check: Statement) {
    statement_order::record(check);
}

/// The test-only call-order recorder of [`check_statements`].
#[cfg(test)]
pub(crate) mod statement_order {
    use std::cell::RefCell;

    use super::Statement;

    thread_local! {
        static RECORD: RefCell<Option<Vec<Statement>>> = const { RefCell::new(None) };
    }

    pub(super) fn record(check: Statement) {
        RECORD.with(|slot| {
            if let Some(record) = slot.borrow_mut().as_mut() {
                record.push(check);
            }
        });
    }

    /// Runs `body` with recording on, and returns what it returned with the
    /// checks it started, in order.
    pub(crate) fn recorded<T>(body: impl FnOnce() -> T) -> (T, Vec<Statement>) {
        RECORD.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        let result = body();
        let record = RECORD.with(|slot| slot.borrow_mut().take().unwrap_or_default());
        (result, record)
    }
}

/// Reads the container's `key_id` block as a selection hint, or reports that
/// there is no usable one.
///
/// The hint rides the footer, outside the signature, so it is attacker-mutable.
/// Deciding anything from it is not an authenticity bypass — changing it can
/// only make verification fail — but treating an unusable one as a rejection
/// would be a free denial primitive, so absent, wrong length, non-ASCII,
/// uppercase and non-hex are all simply "no usable hint" and none of them is an
/// error of its own.
///
/// The wrong-length half of that rule is settled before this is called: the
/// container read is bounded to [`KEY_ID_HEX_LEN`], so a block of any other
/// length arrives as [`EnvelopeBlock::WrongLength`], with its bytes never read.
fn usable_hint(block: &EnvelopeBlock) -> Option<&str> {
    let EnvelopeBlock::Present(bytes) = block else {
        return None;
    };
    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    // Lowercase hex is ASCII, so this cannot fail; it is written as a fallible
    // conversion rather than an `expect` because the bytes came off a
    // container.
    std::str::from_utf8(bytes).ok()
}

/// Verifies the container's signature over its raw manifest bytes, trying the
/// anchors in a fixed order: the hinted non-revoked anchor, then every other
/// non-revoked one, then the revoked ones.
///
/// The hint may change which anchor is tried first, and — when the package was
/// going to be rejected regardless — which of two names the rejection carries.
/// It can never change accept into reject: every non-revoked anchor is tried
/// whatever the hint says.
fn verify_signature<R: Read + Seek>(
    container: &UnparsedContainer<R>,
    trust: &TrustSet,
) -> Result<(), VerifyError> {
    let signature = match container.signature() {
        // An unsigned package is one this verifier cannot authenticate and
        // there is nothing to fall back to, so it is refused here.
        EnvelopeBlock::Absent => return Err(VerifyError::BadSignature),
        EnvelopeBlock::Present(bytes) => Some(bytes.as_slice()),
        // A signature block at any other length was never read, and it verifies
        // under no anchor. That is *all* it means: it is not short-circuited to
        // `BadSignature` here, because the four-step order below still decides
        // which name the rejection carries, and a usable hint naming no anchor
        // is `UnknownKeyId` whatever the signature's length was.
        EnvelopeBlock::WrongLength => None,
    };
    let message = container.manifest_bytes();
    let hint = usable_hint(container.key_id());
    let verifies = |anchor: &TrustAnchor| {
        signature.is_some_and(|signature| anchor.verifies(message, signature))
    };

    // 1. A usable hint naming a non-revoked anchor selects what to try first.
    if let Some(hint) = hint
        && let Some(anchor) = trust
            .anchors
            .iter()
            .find(|anchor| !anchor.revoked && anchor.key_id == hint)
        && verifies(anchor)
    {
        return Ok(());
    }

    // 2. Otherwise, or if that failed, every other non-revoked anchor. Any one
    //    that verifies means accept, which is what makes the hint unable to
    //    deny. Re-trying the hinted anchor here costs one verification and
    //    keeps the fallback a single unconditional loop.
    for anchor in trust.anchors.iter().filter(|anchor| !anchor.revoked) {
        if verifies(anchor) {
            return Ok(());
        }
    }

    // 3. Only now the revoked anchors: a package that verifies under one really
    //    was signed by a revoked key, which is a different verdict from a
    //    signature nobody can attribute.
    for anchor in trust.anchors.iter().filter(|anchor| anchor.revoked) {
        if verifies(anchor) {
            return Err(VerifyError::RevokedKey {
                key_id: anchor.key_id.clone(),
            });
        }
    }

    // 4. Nothing verified. A usable hint naming no anchor at all — revoked ones
    //    included — is the package naming a key we do not hold; everything else
    //    is a signature we cannot attribute.
    match hint {
        Some(hint) if !trust.anchors.iter().any(|anchor| anchor.key_id == hint) => {
            Err(VerifyError::UnknownKeyId {
                key_id: hint.to_string(),
            })
        }
        _ => Err(VerifyError::BadSignature),
    }
}

/// Checks a declared manifest `format_version` against the trust set's injected
/// `floor`.
///
/// The other half of [`VerifyError::UnsupportedManifestFormat`] — a version
/// outside the range *this build* implements — is not restated here. It is
/// already decided by stage one of [`PayloadManifest::parse`], before the body
/// is decoded, and [`map_manifest_error`] maps it onto this same variant; a
/// second copy of the range would leave that mapping dead and give the two
/// copies somewhere to drift apart.
///
/// The injected floor is observable wherever it sits above
/// [`MIN_MANIFEST_FORMAT_VERSION`](crate::manifest::MIN_MANIFEST_FORMAT_VERSION),
/// which since manifest format version 4 includes values *inside* the
/// implemented range: release ops can refuse a manifest at the build's floor
/// while the build still accepts every later version. Above
/// [`MAX_MANIFEST_FORMAT_VERSION`] the accepted set is empty, and the reported
/// range says so.
fn check_format_version(found: u32, floor: u32) -> Result<(), VerifyError> {
    if found < floor {
        return Err(VerifyError::UnsupportedManifestFormat {
            found,
            min: floor,
            max: MAX_MANIFEST_FORMAT_VERSION,
        });
    }
    Ok(())
}

/// Returns the archive member an artifact entry of this kind requires.
///
/// The table is a closed one, and this `match` carries no wildcard arm so a
/// fifth [`ArtifactKind`] is a compile error rather than a silent pass. Every
/// kind requires the entry's own `archive_path` and nothing else — a compose
/// bundle's compose file and image tarballs live *inside* that one member — so
/// the four are written as one arm rather than as four identical ones.
fn required_member(artifact: &PayloadArtifact) -> &str {
    match artifact.kind {
        ArtifactKind::NativeBinary
        | ArtifactKind::ContainerImage
        | ArtifactKind::ComposeBundle
        | ArtifactKind::StaticAssets => artifact.archive_path.as_str(),
    }
}

/// Establishes a one-to-one correspondence between the manifest's bound member
/// list and its artifact entries, and then applies the required-member table.
///
/// The bound list is validated nowhere else before extraction: `from_parts`
/// checks its presence and nothing more, so a validly signed manifest can bind
/// a repeated name, an unsafe name, a name no artifact claims, or a different
/// number of entries than there are artifacts. Extraction eventually catches
/// all of it as `MemberListMismatch`, but only after the bytes have been
/// streamed and staged.
///
/// With duplicates and unsafe names refused and both directions of containment
/// checked, the two collections are a bijection and their counts agree, so no
/// separate count check is needed.
fn check_completeness(manifest: &PayloadManifest) -> Result<(), VerifyError> {
    let Some(members) = manifest.archive_members() else {
        // `Option` only so the baseline shape stays expressible; on any
        // manifest that got past the signature check it is always `Some`, so
        // absence is a rejected manifest rather than something to `expect`.
        return Err(VerifyError::Payload(PayloadError::InvalidManifest(
            ManifestError::MissingArchiveMembers,
        )));
    };

    let mut bound: HashSet<&str> = HashSet::with_capacity(members.len());
    for member in members {
        if !is_safe_archive_path(&member.name) {
            return Err(VerifyError::UnsafePath(member.name.clone()));
        }
        if !bound.insert(member.name.as_str()) {
            return Err(VerifyError::DuplicatePath(member.name.clone()));
        }
    }

    let claimed: HashSet<&str> = manifest
        .artifacts()
        .iter()
        .map(|artifact| artifact.archive_path.as_str())
        .collect();
    for member in members {
        if !claimed.contains(member.name.as_str()) {
            return Err(VerifyError::UnlistedMember(member.name.clone()));
        }
    }

    // A signed, structurally valid, empty allow-list forbids nothing and would
    // otherwise pass every check below precisely because there is nothing to
    // check.
    if manifest.artifacts().is_empty() {
        return Err(VerifyError::MissingRequiredMember { member: None });
    }
    for artifact in manifest.artifacts() {
        let required = required_member(artifact);
        if !bound.contains(required) {
            return Err(VerifyError::MissingRequiredMember {
                member: Some(required.to_string()),
            });
        }
    }

    Ok(())
}

/// Applies [`is_safe_build_identifier`] to each artifact entry's `component`,
/// `version` and `commit`, independently and in that order.
///
/// A `commit` is `Option` only for the pre-versioned baseline shape, which
/// cannot reach here — a baseline manifest sits in a version-1 container, which
/// carries no signature. An absent one is read as the empty string rather than
/// through a branch that cannot run, and the predicate refuses it for the same
/// reason it refuses any other empty identifier.
fn check_identifiers(manifest: &PayloadManifest) -> Result<(), VerifyError> {
    for artifact in manifest.artifacts() {
        for (field, value) in [
            (BuildIdentifier::Component, artifact.component.as_str()),
            (BuildIdentifier::Version, artifact.version.as_str()),
            (
                BuildIdentifier::Commit,
                artifact.commit.as_deref().unwrap_or_default(),
            ),
        ] {
            if !is_safe_build_identifier(value) {
                return Err(VerifyError::UnsafeBuildIdentifier {
                    field,
                    value: value.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Checks every triple the manifest names against the trust set's withdrawn
/// list.
///
/// Read off the manifest and never off the request, and checked **before** the
/// target agreement: the withdrawn list defends against exactly the hop that
/// supplies the request, so a hop that could turn a withdrawn verdict into a
/// mismatch verdict by sending a request it knows disagrees would be trading
/// "this build is withdrawn, stop" for a "you asked for the wrong thing, try
/// again" that a caller may reasonably retry.
fn check_withdrawal(manifest: &PayloadManifest, trust: &TrustSet) -> Result<(), VerifyError> {
    for artifact in manifest.artifacts() {
        let commit = artifact.commit.as_deref().unwrap_or_default();
        if trust.is_withdrawn(&artifact.component, &artifact.version, commit) {
            return Err(VerifyError::WithdrawnBuild {
                package_id: artifact.component.clone(),
                version: artifact.version.clone(),
                commit: commit.to_string(),
            });
        }
    }
    Ok(())
}

/// Checks that **every** artifact entry carries the request's target, version
/// and commit.
///
/// Every entry rather than at least one: a package that satisfied the request
/// with one entry while carrying a second component's artifacts alongside would
/// be accepted, and the caller would then extract and install artifacts it
/// never asked about. The practical consequence is that this entry point
/// verifies single-build packages only.
fn check_target(manifest: &PayloadManifest, request: &VerifyRequest) -> Result<(), VerifyError> {
    for artifact in manifest.artifacts() {
        let commit = artifact.commit.as_deref().unwrap_or_default();
        if artifact.component != request.target
            || artifact.version != request.version
            || commit != request.commit
        {
            return Err(VerifyError::TargetMismatch {
                component: artifact.component.clone(),
                version: artifact.version.clone(),
                commit: commit.to_string(),
            });
        }
    }
    Ok(())
}

/// Compares the delivered epoch against the active one, for the reserved
/// [`TRUST_TARGET`] only.
///
/// Two integers and nothing parsed. No other target has a delivered epoch to
/// compare, because the request constructors make that state unrepresentable.
fn check_epoch(request: &VerifyRequest, trust: &TrustSet) -> Result<(), VerifyError> {
    let Some(delivered) = request.epoch else {
        return Ok(());
    };
    if delivered > trust.epoch {
        Ok(())
    } else {
        Err(VerifyError::StaleTrustSet {
            delivered,
            active: trust.epoch,
        })
    }
}

/// Returns every artifact that carries an image declaration, with it, in
/// manifest order.
fn declared_images(
    manifest: &PayloadManifest,
) -> impl Iterator<Item = (&PayloadArtifact, &ImageDeclaration)> {
    manifest
        .artifacts()
        .iter()
        .filter_map(|artifact| artifact.image.as_ref().map(|image| (artifact, image)))
}

/// Runs steps 10 through 15, each over the whole manifest before the next.
fn check_images(
    manifest: &PayloadManifest,
    request: &VerifyRequest,
) -> Result<(), ImageVerifyError> {
    check_declared_platforms(manifest)?;
    check_reserved_aliases(manifest)?;
    check_reference_conflicts(manifest)?;
    check_owners(manifest, request)
}

/// Step 10: each declared architecture against its artifact's `target_arch`.
fn check_declared_platforms(manifest: &PayloadManifest) -> Result<(), ImageVerifyError> {
    for (artifact, image) in declared_images(manifest) {
        if image.platform.architecture != ImageArchitecture::for_target(artifact.target_arch) {
            return Err(ImageVerifyError::PlatformMismatch {
                archive_path: artifact.archive_path.clone(),
                target_arch: artifact.target_arch,
                declared: image.platform.architecture,
            });
        }
    }
    Ok(())
}

/// Returns a declaration's reference in normalized form.
///
/// The typed parse already refused every reference that does not parse, so a
/// failure here is a manifest that did not come through it; it is skipped
/// rather than trusted, since every door that yields a manifest runs that
/// parse.
fn normalized(reference: &str) -> Option<NormalizedReference> {
    parse_tagged_reference(reference).ok()
}

/// Step 11: every reference whose registry host is [`RUNTIME_ALIAS_REGISTRY`]
/// — compared case-insensitively, whatever its port — must be literally the
/// canonical alias of its own declaration, under a managed lifecycle.
fn check_reserved_aliases(manifest: &PayloadManifest) -> Result<(), ImageVerifyError> {
    for (artifact, image) in declared_images(manifest) {
        for reference in &image.public_refs {
            let Some(parsed) = normalized(reference) else {
                continue;
            };
            if !parsed.host().eq_ignore_ascii_case(RUNTIME_ALIAS_REGISTRY) {
                continue;
            }
            let expected = image.canonical_runtime_alias().ok();
            if expected.as_deref() != Some(reference.as_str()) {
                return Err(ImageVerifyError::NonCanonicalReservedReference {
                    archive_path: artifact.archive_path.clone(),
                    reference: reference.clone(),
                    expected,
                });
            }
            if image.reference_lifecycle != ReferenceLifecycle::ManagedRuntime {
                return Err(ImageVerifyError::ReservedReferenceLifecycle {
                    archive_path: artifact.archive_path.clone(),
                    reference: reference.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Returns the first facet, in [`ReferenceConflict`] order, in which two
/// declarations assigning one reference differ. Dependency and provenance are
/// not facets: two declarations of one image may differ in both.
fn conflict_between(
    first: &ImageDeclaration,
    later: &ImageDeclaration,
) -> Option<ReferenceConflict> {
    if first.config_digest != later.config_digest {
        Some(ReferenceConflict::ConfigDigest)
    } else if first.platform != later.platform {
        Some(ReferenceConflict::Platform)
    } else if first.owner != later.owner {
        Some(ReferenceConflict::Owner)
    } else if first.reference_lifecycle != later.reference_lifecycle {
        Some(ReferenceConflict::Lifecycle)
    } else {
        None
    }
}

/// Step 12: one normalized reference may be assigned by several declarations
/// only when they agree on the image it names.
fn check_reference_conflicts(manifest: &PayloadManifest) -> Result<(), ImageVerifyError> {
    let mut assigned: HashMap<NormalizedReference, (&PayloadArtifact, &str, &ImageDeclaration)> =
        HashMap::new();
    for (artifact, image) in declared_images(manifest) {
        for reference in &image.public_refs {
            let Some(key) = normalized(reference) else {
                continue;
            };
            match assigned.get(&key) {
                Some((first_artifact, first_reference, first_image)) => {
                    if let Some(conflict) = conflict_between(first_image, image) {
                        return Err(ImageVerifyError::ConflictingReference {
                            archive_path: artifact.archive_path.clone(),
                            reference: reference.clone(),
                            first_archive_path: first_artifact.archive_path.clone(),
                            first_reference: (*first_reference).to_string(),
                            conflict,
                        });
                    }
                }
                None => {
                    assigned.insert(key, (artifact, reference, image));
                }
            }
        }
    }
    Ok(())
}

/// Steps 13, 14 and 15, each a pass of its own: a namespace to check against,
/// each owner namespace verbatim against it, then each owner component against
/// the requested target.
fn check_owners(
    manifest: &PayloadManifest,
    request: &VerifyRequest,
) -> Result<(), ImageVerifyError> {
    let Some((first, _)) = declared_images(manifest).next() else {
        return Ok(());
    };
    let Some(namespace) = request.namespace.as_deref() else {
        return Err(ImageVerifyError::MissingNamespace {
            archive_path: first.archive_path.clone(),
        });
    };
    for (artifact, image) in declared_images(manifest) {
        if image.owner.namespace != namespace {
            return Err(ImageVerifyError::NamespaceMismatch {
                archive_path: artifact.archive_path.clone(),
                expected: namespace.to_string(),
                declared: image.owner.namespace.clone(),
            });
        }
    }
    for (artifact, image) in declared_images(manifest) {
        if image.owner.component != request.target {
            return Err(ImageVerifyError::OwnerComponentMismatch {
                archive_path: artifact.archive_path.clone(),
                expected: request.target.clone(),
                declared: image.owner.component.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tar::{Builder, EntryType, Header};
    use zstd::Encoder;

    use super::{
        BuildIdentifier, ED25519_SIGNATURE_LEN, ENVELOPE_BOUNDS, ImageReferences, ImageVerifyError,
        InputError, KEY_ID_HEX_LEN, MAX_BUILD_IDENTIFIER_BYTES, ReferenceConflict, TRUST_TARGET,
        TrustAnchor, TrustSet, VerifiedPackage, VerifyError, VerifyRequest,
        is_safe_build_identifier, key_id, verify_package,
    };
    use crate::image::{
        ImageArchitecture, ImageDeclaration, ImageDeclarationError, ImageOs, ImageOwner,
        ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle,
        RegistryProvenance,
    };
    use crate::manifest::{
        Disposition, IMAGE_DECLARATION_FORMAT_VERSION, MANIFEST_FORMAT_VERSION,
        MAX_MANIFEST_FORMAT_VERSION, MIN_MANIFEST_FORMAT_VERSION, ManifestError, TargetArch,
    };
    use crate::payload::{
        self, ArtifactInput, EnvelopeBlock, FORMAT_VERSION, MAGIC, PayloadError, Signed,
    };

    /// Component every fixture artifact belongs to, and the target a fixture
    /// request names.
    const COMPONENT: &str = "example";
    /// Version every fixture artifact carries.
    const VERSION: &str = "1.0.0";
    /// A full 40-hex git commit SHA — the build identity a producer stamps.
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    /// A second, different commit of the same width.
    const OTHER_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";
    /// `archive_path` of the one artifact a default fixture carries.
    const MEMBER: &str = "bin/app";
    /// The bytes that artifact holds, so a fixture archive is a real one.
    const ARTIFACT_BYTES: &[u8] = b"artifact bytes";
    /// Their lowercase-hex SHA-256, computed outside this crate.
    const ARTIFACT_SHA256: &str =
        "4659fc0570122b0e0aa14f4ff7c261b1fe51795a01ba79963f462ebf40d7520d";
    /// A `key_id`-shaped value no fixture key derives.
    const STRANGER_KEY_ID: &str =
        "abababababababababababababababababababababababababababababababab";
    /// zstd level the fixture archive writer uses; it only has to round-trip.
    const FIXTURE_ZSTD_LEVEL: i32 = 3;
    /// Length of a `key_id` block, for building fixture hints out of bytes.
    const KEY_ID_BLOCK_BYTES: usize = 64;
    /// A block length no verifier should allocate on an attacker's say-so.
    ///
    /// Large enough that reading it is a denial of service in its own right,
    /// and small enough that a regression fails as the assertion below rather
    /// than as an out-of-memory abort that reports nothing.
    const HOSTILE_BLOCK_LEN: u64 = 512 * 1024 * 1024;

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

    fn len_u64(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).expect("a fixture is far smaller than u64::MAX")
    }

    /// Encodes a footer of `version` by hand — magic, the version byte, then
    /// the offset/length pairs that version records — so a fixture can state a
    /// block layout the writer has no way to emit.
    fn footer_bytes(version: u8, fields: [u64; 8]) -> Vec<u8> {
        let pairs = if version >= FORMAT_VERSION { 8 } else { 4 };
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(version);
        for field in fields.iter().take(pairs) {
            out.extend_from_slice(&field.to_le_bytes());
        }
        out
    }

    /// Assembles a `.pkg`: the present blocks adjacent in the fixed order, with
    /// the manifest at offset `0`, then the footer.
    fn assemble(
        version: u8,
        manifest: &[u8],
        archive: &[u8],
        signature: Option<&[u8]>,
        hint: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(manifest);
        out.extend_from_slice(archive);
        let mut cursor = len_u64(manifest) + len_u64(archive);
        let mut place = |block: Option<&[u8]>, out: &mut Vec<u8>| match block {
            Some(bytes) => {
                let offset = cursor;
                out.extend_from_slice(bytes);
                cursor += len_u64(bytes);
                (offset, len_u64(bytes))
            }
            // The all-zero absent encoding, which is what the writer emits for
            // both envelope pairs today.
            None => (0, 0),
        };
        let (signature_offset, signature_len) = place(signature, &mut out);
        let (hint_offset, hint_len) = place(hint, &mut out);
        out.extend_from_slice(&footer_bytes(
            version,
            [
                0,
                len_u64(manifest),
                len_u64(manifest),
                len_u64(archive),
                signature_offset,
                signature_len,
                hint_offset,
                hint_len,
            ],
        ));
        out
    }

    /// Signs `manifest` with `pair` and assembles a current-version `.pkg`
    /// around it, carrying `hint` as its `key_id` block.
    fn signed_pkg(
        pair: &Ed25519KeyPair,
        manifest: &[u8],
        archive: &[u8],
        hint: Option<&[u8]>,
    ) -> Vec<u8> {
        let signature = pair.sign(manifest);
        assemble(
            FORMAT_VERSION,
            manifest,
            archive,
            Some(signature.as_ref()),
            hint,
        )
    }

    /// The default fixture: the default manifest, signed, hinted with the
    /// signer's own `key_id`.
    fn default_pkg(pair: &Ed25519KeyPair) -> Vec<u8> {
        let hint = key_id(&public_key_of(pair));
        signed_pkg(
            pair,
            &default_manifest(),
            &default_archive(),
            Some(hint.as_bytes()),
        )
    }

    /// Builds a real zstd-compressed tar archive block. Only the extraction
    /// tests read it back; `verify_package` never walks it.
    fn archive_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder =
            Encoder::new(Vec::new(), FIXTURE_ZSTD_LEVEL).expect("encoder should be created");
        let mut builder = Builder::new(encoder);
        for (path, bytes) in members {
            let mut header = Header::new_gnu();
            header
                .set_path(path)
                .expect("a fixture path fits the field");
            header.set_size(len_u64(bytes));
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder
                .append(&header, *bytes)
                .expect("append should succeed");
        }
        let encoder = builder.into_inner().expect("archive should finish");
        encoder.finish().expect("compression should finish")
    }

    fn default_archive() -> Vec<u8> {
        archive_of(&[(MEMBER, ARTIFACT_BYTES)])
    }

    /// Renders one artifact entry as wire JSON, so a fixture can state a shape
    /// `PayloadManifest::new` would refuse to build.
    fn artifact_json(
        component: &str,
        version: &str,
        commit: &str,
        kind: &str,
        archive_path: &str,
        sha256: &str,
    ) -> String {
        format!(
            r#"{{"component":"{component}","version":"{version}","commit":"{commit}","target_arch":"x86_64","kind":"{kind}","dispositions":["install"],"archive_path":"{archive_path}","sha256":"{sha256}"}}"#
        )
    }

    /// The one artifact entry a default fixture carries.
    fn default_artifact() -> String {
        artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "native-binary",
            MEMBER,
            ARTIFACT_SHA256,
        )
    }

    /// Renders a manifest block at `format_version`, binding `members` and
    /// carrying `artifacts`.
    fn manifest_json_at(
        format_version: u32,
        members: &[(&str, u64)],
        artifacts: &[String],
    ) -> Vec<u8> {
        let members = members
            .iter()
            .map(|(name, length)| format!(r#"{{"name":"{name}","length":{length}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let artifacts = artifacts.join(",");
        format!(
            r#"{{"format_version":{format_version},"archive_members":[{members}],"artifacts":[{artifacts}]}}"#
        )
        .into_bytes()
    }

    fn manifest_json(members: &[(&str, u64)], artifacts: &[String]) -> Vec<u8> {
        manifest_json_at(MANIFEST_FORMAT_VERSION, members, artifacts)
    }

    /// The manifest a default fixture carries: one native binary, one bound
    /// member of the length its bytes really are.
    fn default_manifest() -> Vec<u8> {
        manifest_json(&[(MEMBER, len_u64(ARTIFACT_BYTES))], &[default_artifact()])
    }

    /// A trust set holding `anchors`, withdrawing nothing, at the floor this
    /// build implements and epoch 0.
    fn trust_of(anchors: Vec<TrustAnchor>) -> TrustSet {
        TrustSet::new(anchors, Vec::new(), MIN_MANIFEST_FORMAT_VERSION, 0)
            .expect("distinct anchors build a trust set")
    }

    /// A trust set trusting exactly `pair`.
    fn trusting(pair: &Ed25519KeyPair) -> TrustSet {
        trust_of(vec![TrustAnchor::new(public_key_of(pair), false)])
    }

    /// The request the default fixture satisfies.
    fn request() -> VerifyRequest {
        VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("an ordinary target")
    }

    /// Which envelope block a sparse fixture advertises without ever writing.
    #[derive(Clone, Copy)]
    enum SparseBlock {
        Signature,
        KeyId,
    }

    /// A `Read + Seek` modelling a container with one enormous block that is
    /// not really there: it holds the blocks it wrote, reports a length far
    /// past them, and panics rather than serve a byte from the block it did
    /// not.
    ///
    /// This is the shape the hostile input takes. A footer's block lengths are
    /// attacker-controlled and the container layer checks only that a block
    /// fits inside the input, which a sparse file makes enormous for the cost
    /// of a `set_len`. The panic is what turns "the verifier never reads that
    /// block" into an assertion: a reader that allocated it would go on to
    /// read it, and land here.
    #[derive(Debug)]
    struct SparseContainer {
        /// The blocks that really exist, each at its absolute offset.
        segments: Vec<(u64, Vec<u8>)>,
        /// The advertised-but-absent block's byte range.
        sparse: std::ops::Range<u64>,
        len: u64,
        pos: u64,
    }

    impl Read for SparseContainer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() || self.pos >= self.len {
                return Ok(0);
            }
            let pos = self.pos;
            assert!(
                !self.sparse.contains(&pos),
                "the verifier read the sparse block, at offset {pos}"
            );
            let (start, bytes) = self
                .segments
                .iter()
                .find(|(start, bytes)| pos >= *start && pos - start < len_u64(bytes))
                .unwrap_or_else(|| {
                    panic!("the verifier read outside every block, at offset {pos}")
                });
            let from = usize::try_from(pos - start).expect("a fixture block is small");
            let rest = bytes.get(from..).expect("the offset is inside the block");
            let count = rest.len().min(buf.len());
            let (head, rest) = (
                buf.get_mut(..count).expect("count is at most the buffer"),
                rest.get(..count).expect("count is at most what is left"),
            );
            head.copy_from_slice(rest);
            self.pos += len_u64(rest);
            Ok(count)
        }
    }

    impl Seek for SparseContainer {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            let target = match pos {
                SeekFrom::Start(offset) => Some(offset),
                SeekFrom::End(offset) => self.len.checked_add_signed(offset),
                SeekFrom::Current(offset) => self.pos.checked_add_signed(offset),
            }
            .expect("a fixture seek stays in range");
            self.pos = target;
            Ok(target)
        }
    }

    /// Assembles a signed-shaped `.pkg` whose `sparse` envelope block is
    /// advertised at [`HOSTILE_BLOCK_LEN`] and never written, with `present`
    /// as the other envelope block's real bytes.
    fn sparse_pkg(
        manifest: &[u8],
        archive: &[u8],
        present: &[u8],
        sparse: SparseBlock,
    ) -> SparseContainer {
        let mut head = manifest.to_vec();
        head.extend_from_slice(archive);
        let head_len = len_u64(&head);

        let (signature_len, key_id_len) = match sparse {
            SparseBlock::Signature => (HOSTILE_BLOCK_LEN, len_u64(present)),
            SparseBlock::KeyId => (len_u64(present), HOSTILE_BLOCK_LEN),
        };
        let signature_offset = head_len;
        let key_id_offset = signature_offset + signature_len;
        let (present_offset, sparse_offset) = match sparse {
            SparseBlock::Signature => (key_id_offset, signature_offset),
            SparseBlock::KeyId => (signature_offset, key_id_offset),
        };

        let footer_start = key_id_offset + key_id_len;
        let footer = footer_bytes(
            FORMAT_VERSION,
            [
                0,
                len_u64(manifest),
                len_u64(manifest),
                len_u64(archive),
                signature_offset,
                signature_len,
                key_id_offset,
                key_id_len,
            ],
        );
        let len = footer_start + len_u64(&footer);

        SparseContainer {
            segments: vec![
                (0, head),
                (present_offset, present.to_vec()),
                (footer_start, footer),
            ],
            sparse: sparse_offset..sparse_offset + HOSTILE_BLOCK_LEN,
            len,
            pos: 0,
        }
    }

    /// Writes a `.pkg` with a hole standing in for one enormous envelope block.
    ///
    /// Unlike [`sparse_pkg`], this exercises the filesystem shape an attacker
    /// can create cheaply with `set_len`, rather than merely modelling it in a
    /// `Read + Seek` implementation.
    fn sparse_file_pkg(
        manifest: &[u8],
        archive: &[u8],
        present: &[u8],
        sparse: SparseBlock,
    ) -> std::fs::File {
        let mut file = tempfile::tempfile().expect("a temporary sparse fixture file is available");
        let head_len = len_u64(manifest) + len_u64(archive);
        let (signature_len, key_id_len) = match sparse {
            SparseBlock::Signature => (HOSTILE_BLOCK_LEN, len_u64(present)),
            SparseBlock::KeyId => (len_u64(present), HOSTILE_BLOCK_LEN),
        };
        let signature_offset = head_len;
        let key_id_offset = signature_offset + signature_len;
        let present_offset = match sparse {
            SparseBlock::Signature => key_id_offset,
            SparseBlock::KeyId => signature_offset,
        };
        let footer_start = key_id_offset + key_id_len;
        let footer = footer_bytes(
            FORMAT_VERSION,
            [
                0,
                len_u64(manifest),
                len_u64(manifest),
                len_u64(archive),
                signature_offset,
                signature_len,
                key_id_offset,
                key_id_len,
            ],
        );

        file.set_len(footer_start + len_u64(&footer))
            .expect("the fixture file is extended through its footer");
        file.write_all(manifest)
            .expect("the fixture manifest is written");
        file.write_all(archive)
            .expect("the fixture archive is written");
        file.seek(SeekFrom::Start(present_offset))
            .expect("the fixture seeks past its sparse block");
        file.write_all(present)
            .expect("the fixture's other envelope block is written");
        file.seek(SeekFrom::Start(footer_start))
            .expect("the fixture seeks to its footer");
        file.write_all(&footer)
            .expect("the fixture footer is written");
        file.seek(SeekFrom::Start(0))
            .expect("the fixture rewinds before its bounded read");

        // Writing the footer at the far side leaves the other envelope block
        // as a filesystem hole: it is part of the input length but consumes no
        // fixture bytes.
        file
    }

    /// Verifies `bytes` against `trust` and `request`, returning the error.
    fn verify_err(bytes: &[u8], trust: &TrustSet, request: &VerifyRequest) -> VerifyError {
        verify_package(Cursor::new(bytes.to_vec()), trust, request)
            .expect_err("verification should be refused")
    }

    /// Verifies `bytes` against `trust` and the default request, returning the
    /// error.
    fn refusal(bytes: &[u8], trust: &TrustSet) -> VerifyError {
        verify_err(bytes, trust, &request())
    }

    /// Verifies `bytes`, asserting it is accepted.
    fn accepted(bytes: &[u8], trust: &TrustSet) -> VerifiedPackage<Cursor<Vec<u8>>> {
        verify_package(Cursor::new(bytes.to_vec()), trust, &request())
            .expect("the package should verify")
    }

    #[test]
    fn an_authentic_signed_package_verifies() {
        let pair = keypair();
        let package = default_pkg(&pair);
        let verified = accepted(&package, &trusting(&pair));
        assert_eq!(verified.manifest().artifacts().len(), 1);
        assert_eq!(
            verified.manifest().format_version(),
            Some(MANIFEST_FORMAT_VERSION)
        );
    }

    #[test]
    fn flipping_one_manifest_byte_yields_bad_signature() {
        let pair = keypair();
        let mut package = default_pkg(&pair);
        // The manifest block starts at offset 0 in a `.pkg`, and the signature
        // is over exactly those bytes.
        let byte = package.get_mut(4).expect("the manifest block is longer");
        *byte ^= 0x20;
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::BadSignature
        ));
    }

    #[test]
    fn the_signature_covers_the_raw_manifest_bytes_and_not_a_re_serialization() {
        // A manifest block no serializer would emit: the keys sit in another
        // order and the whitespace is incidental. It verifies because the bytes
        // on disk are the canonical form — a verifier that re-serialized the
        // parsed manifest to reconstruct the signed input would reject this
        // authentic package rather than accept it.
        let pair = keypair();
        let manifest = format!(
            "{{\n  \"artifacts\": [ {} ],\n  \"archive_members\": [ {{ \"length\": {}, \"name\": \"{MEMBER}\" }} ],\n  \"format_version\": {MANIFEST_FORMAT_VERSION}\n}}\n",
            default_artifact(),
            len_u64(ARTIFACT_BYTES)
        )
        .into_bytes();
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let verified = accepted(&package, &trusting(&pair));
        assert_eq!(verified.manifest().artifacts().len(), 1);
    }

    #[test]
    fn a_package_the_writer_emits_carries_no_signature_and_is_bad_signature() {
        // Everything `append_trailer` writes has both envelope pairs absent, so
        // unsigned packages exist today and this verifier has to answer them.
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("app");
        std::fs::write(&source, ARTIFACT_BYTES).expect("write source file");
        let input = ArtifactInput {
            component: COMPONENT.to_string(),
            version: VERSION.to_string(),
            commit: COMMIT.to_string(),
            target_arch: TargetArch::X86_64,
            kind: crate::manifest::ArtifactKind::NativeBinary,
            dispositions: [Disposition::Install].into_iter().collect(),
            archive_path: MEMBER.to_string(),
            spec: None,
            image: None,
            source,
        };
        let mut package = Vec::new();
        payload::append_trailer(std::io::empty(), &mut package, None, None, &[input])
            .expect("the writer should succeed");

        let pair = keypair();
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::BadSignature
        ));
    }

    #[test]
    fn signed_writer_packages_verify_before_and_after_a_rewrap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("app");
        std::fs::write(&source, ARTIFACT_BYTES).expect("write source file");
        let input = ArtifactInput {
            component: COMPONENT.to_string(),
            version: VERSION.to_string(),
            commit: COMMIT.to_string(),
            target_arch: TargetArch::X86_64,
            kind: crate::manifest::ArtifactKind::NativeBinary,
            dispositions: [Disposition::Install].into_iter().collect(),
            archive_path: MEMBER.to_string(),
            spec: None,
            image: None,
            source,
        };
        let pair = keypair();
        let expected_key_id = key_id(&public_key_of(&pair));
        let mut package = Vec::new();
        payload::append_trailer_signed(
            std::io::empty(),
            &mut package,
            None,
            None,
            std::slice::from_ref(&input),
            |manifest| {
                Ok(Signed {
                    signature: pair.sign(manifest).as_ref().to_vec(),
                    key_id: expected_key_id.clone(),
                })
            },
        )
        .expect("the signed package writer should succeed");
        accepted(&package, &trusting(&pair));
        let package_payload = payload::open_package(Cursor::new(&package))
            .expect("the package must open after verification");
        assert_eq!(package_payload.key_id(), Some(expected_key_id.as_bytes()));

        let mut installer = Vec::new();
        payload::append_trailer_signed(
            Cursor::new(b"an executable base"),
            &mut installer,
            None,
            None,
            &[input],
            |manifest| {
                Ok(Signed {
                    signature: pair.sign(manifest).as_ref().to_vec(),
                    key_id: expected_key_id.clone(),
                })
            },
        )
        .expect("the signed installer writer should succeed");
        accepted(&installer, &trusting(&pair));

        let mut rewrapped = Vec::new();
        payload::rewrap_trailer(
            Cursor::new(installer),
            Cursor::new(b"a replacement executable base"),
            &mut rewrapped,
        )
        .expect("a signed container should rewrap");
        accepted(&rewrapped, &trusting(&pair));
    }

    #[test]
    fn a_version_one_container_is_bad_signature() {
        // A version-1 footer has no envelope pairs at all, so every container
        // written at it — the pre-versioned baseline shape included — is
        // refused before any manifest check is reached.
        let pair = keypair();
        let package = assemble(1, &default_manifest(), &default_archive(), None, None);
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::BadSignature
        ));
    }

    #[test]
    fn an_unsigned_baseline_is_bad_signature_whatever_its_image_key() {
        // Genuine pre-versioned baseline manifests: no `format_version`, no
        // `archive_members`, no `trust_set`, and no artifact `commit` or `spec`.
        // Each variant differs from the valid one only by the `image` key the
        // baseline forbids, so a verifier that parsed before authenticating
        // would report that key rather than the missing signature.
        let baseline_artifact = |image: Option<&str>| {
            let image = image.map_or_else(String::new, |value| format!(r#""image":{value},"#));
            format!(
                r#"{{{image}"component":"{COMPONENT}","version":"{VERSION}","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"{MEMBER}","sha256":"{ARTIFACT_SHA256}"}}"#
            )
        };
        let cases: [(&str, Option<&str>); 4] = [
            ("no image key", None),
            ("a null image", Some("null")),
            ("an object image", Some(r#"{"reference":"example"}"#)),
            ("a scalar image", Some(r#""scalar""#)),
        ];
        let pair = keypair();
        let trust = trusting(&pair);
        let archive = default_archive();

        for (label, image) in cases {
            let manifest =
                format!(r#"{{"artifacts":[{}]}}"#, baseline_artifact(image)).into_bytes();
            let package = assemble(1, &manifest, &archive, None, None);

            // The fixture is what it claims to be: a footer-v1 container with
            // no envelope blocks, whose manifest parses as a baseline when the
            // image key is absent and is refused for that key alone otherwise.
            let container =
                payload::read_package_container(Cursor::new(package.clone()), &ENVELOPE_BOUNDS)
                    .expect("the fixture container reads");
            assert_eq!(container.footer_version(), 1, "{label}");
            assert!(
                matches!(container.signature(), EnvelopeBlock::Absent),
                "{label}"
            );
            assert!(
                matches!(container.key_id(), EnvelopeBlock::Absent),
                "{label}"
            );
            let parsed = container.parse_unverified_manifest();
            if image.is_none() {
                let baseline = parsed.expect("the absent-image baseline parses");
                assert_eq!(baseline.format_version(), None, "{label}");
                assert_eq!(baseline.artifacts().len(), 1, "{label}");
            } else {
                assert!(
                    matches!(
                        parsed,
                        Err(PayloadError::InvalidManifest(ManifestError::BaselineWithImage(ref path)))
                            if path == MEMBER
                    ),
                    "{label}: the parse alone should refuse the image key, got {parsed:?}"
                );
            }

            let error = refusal(&package, &trust);
            assert!(
                matches!(error, VerifyError::BadSignature),
                "{label}: got {error:?}"
            );
            assert!(
                !matches!(error, VerifyError::Payload(_)),
                "{label}: the signature verdict must precede every manifest fault"
            );
        }
    }

    #[test]
    fn no_mutation_of_the_key_id_hint_turns_accept_into_reject() {
        let signer = keypair();
        let revoked = keypair();
        let trust = trust_of(vec![
            TrustAnchor::new(public_key_of(&signer), false),
            TrustAnchor::new(public_key_of(&revoked), true),
        ]);
        let manifest = default_manifest();
        let archive = default_archive();
        let authentic = key_id(&public_key_of(&signer));
        let revoked_id = key_id(&public_key_of(&revoked));
        let uppercased = authentic.to_uppercase();
        let truncated = authentic
            .get(..KEY_ID_BLOCK_BYTES / 2)
            .expect("a key id is longer than half of itself")
            .to_string();
        let non_hex = vec![b'z'; KEY_ID_BLOCK_BYTES];
        let non_ascii = vec![0xff; KEY_ID_BLOCK_BYTES];

        let hints: [(&str, Option<&[u8]>); 7] = [
            ("authentic", Some(authentic.as_bytes())),
            ("a revoked anchor's id", Some(revoked_id.as_bytes())),
            ("an id in no anchor", Some(STRANGER_KEY_ID.as_bytes())),
            ("truncated", Some(truncated.as_bytes())),
            ("non-hex", Some(&non_hex)),
            ("uppercased", Some(uppercased.as_bytes())),
            ("removed entirely", None),
        ];
        for (label, hint) in hints {
            let package = signed_pkg(&signer, &manifest, &archive, hint);
            assert!(
                verify_package(Cursor::new(package), &trust, &request()).is_ok(),
                "a hint that is {label} must not deny an authentic package"
            );
        }
        let package = signed_pkg(&signer, &manifest, &archive, Some(&non_ascii));
        assert!(
            verify_package(Cursor::new(package), &trust, &request()).is_ok(),
            "a non-ascii hint must not deny an authentic package"
        );
    }

    #[test]
    fn an_enormous_signature_block_is_answered_from_its_length_alone() {
        // The footer advertises a signature far larger than any signature, and
        // the bytes are not there to read: `SparseContainer` panics if the
        // verifier so much as touches them, which is what a reader that
        // allocated the block would then do. An Ed25519 signature is 64 bytes,
        // so the length settles it without reading anything.
        let signer = keypair();
        let trust = trust_of(vec![TrustAnchor::new(public_key_of(&signer), false)]);
        let hint = key_id(&public_key_of(&signer));
        let package = sparse_pkg(
            &default_manifest(),
            &default_archive(),
            hint.as_bytes(),
            SparseBlock::Signature,
        );
        let error = verify_package(package, &trust, &request())
            .expect_err("an unreadable signature cannot verify");
        assert!(matches!(error, VerifyError::BadSignature), "got: {error:?}");

        // Refusing to read it is not the same as short-circuiting the verdict:
        // the four-step order still names the rejection, so a usable hint
        // naming no anchor is `UnknownKeyId` exactly as it would be for a
        // 64-byte signature nothing verifies.
        let package = sparse_pkg(
            &default_manifest(),
            &default_archive(),
            STRANGER_KEY_ID.as_bytes(),
            SparseBlock::Signature,
        );
        let error = verify_package(package, &trust, &request())
            .expect_err("an unreadable signature cannot verify");
        assert!(
            matches!(error, VerifyError::UnknownKeyId { ref key_id } if key_id == STRANGER_KEY_ID),
            "got: {error:?}"
        );
    }

    #[test]
    fn an_enormous_key_id_block_is_an_unusable_hint_and_cannot_deny() {
        // The same hostile length on the block the hint rides in. A `key_id` is
        // 64 characters, so this one is unusable — and an unusable hint is not
        // a rejection: the authentic signature beside it still verifies, with
        // the enormous block never read.
        let signer = keypair();
        let trust = trust_of(vec![TrustAnchor::new(public_key_of(&signer), false)]);
        let manifest = default_manifest();
        let signature = signer.sign(&manifest);
        let package = sparse_pkg(
            &manifest,
            &default_archive(),
            signature.as_ref(),
            SparseBlock::KeyId,
        );
        assert!(
            verify_package(package, &trust, &request()).is_ok(),
            "an unusable hint must not deny an authentic package"
        );
    }

    #[test]
    fn bounded_container_reader_reports_envelope_metadata() {
        let manifest = default_manifest();
        let archive = default_archive();

        let unsigned = payload::read_package_container(
            Cursor::new(assemble(FORMAT_VERSION, &manifest, &archive, None, None)),
            &ENVELOPE_BOUNDS,
        )
        .expect("an unsigned package has bounded metadata");
        assert!(matches!(unsigned.signature(), EnvelopeBlock::Absent));
        assert!(matches!(unsigned.key_id(), EnvelopeBlock::Absent));

        let signer = keypair();
        let signature = signer.sign(&manifest);
        let hint = key_id(&public_key_of(&signer));
        let signed_container = payload::read_package_container(
            Cursor::new(assemble(
                FORMAT_VERSION,
                &manifest,
                &archive,
                Some(signature.as_ref()),
                Some(hint.as_bytes()),
            )),
            &ENVELOPE_BOUNDS,
        )
        .expect("a signed package has bounded metadata");
        match signed_container.signature() {
            EnvelopeBlock::Present(bytes) => assert_eq!(bytes, signature.as_ref()),
            block => panic!("signature should be present, got {block:?}"),
        }
        match signed_container.key_id() {
            EnvelopeBlock::Present(bytes) => assert_eq!(bytes, hint.as_bytes()),
            block => panic!("key id should be present, got {block:?}"),
        }

        let wrong_signature = payload::read_package_container(
            Cursor::new(assemble(
                FORMAT_VERSION,
                &manifest,
                &archive,
                Some(&[0; 63]),
                None,
            )),
            &ENVELOPE_BOUNDS,
        )
        .expect("a wrong signature length remains readable as metadata");
        assert!(matches!(
            wrong_signature.signature(),
            EnvelopeBlock::WrongLength
        ));

        let wrong_key_id = payload::read_package_container(
            Cursor::new(assemble(
                FORMAT_VERSION,
                &manifest,
                &archive,
                Some(signature.as_ref()),
                Some(&[b'a'; 63]),
            )),
            &ENVELOPE_BOUNDS,
        )
        .expect("a wrong key-id length remains readable as metadata");
        assert!(matches!(wrong_key_id.key_id(), EnvelopeBlock::WrongLength));

        let mut half_zero = manifest.clone();
        half_zero.extend_from_slice(&archive);
        half_zero.extend_from_slice(&footer_bytes(
            FORMAT_VERSION,
            [
                0,
                len_u64(&manifest),
                len_u64(&manifest),
                len_u64(&archive),
                1,
                0,
                0,
                0,
            ],
        ));
        let Err(error) = payload::read_package_container(Cursor::new(half_zero), &ENVELOPE_BOUNDS)
        else {
            panic!("a half-zero envelope pair must be malformed");
        };
        assert!(matches!(error, PayloadError::MalformedFooter { .. }));
    }

    #[test]
    fn bounded_container_reader_never_reads_a_sparse_wrong_length_block() {
        let signer = keypair();
        let hint = key_id(&public_key_of(&signer));
        let container = payload::read_package_container(
            sparse_file_pkg(
                &default_manifest(),
                &default_archive(),
                hint.as_bytes(),
                SparseBlock::Signature,
            ),
            &ENVELOPE_BOUNDS,
        )
        .expect("the hostile block length is reported without reading its bytes");

        assert!(matches!(container.signature(), EnvelopeBlock::WrongLength));
        assert!(
            matches!(container.key_id(), EnvelopeBlock::Present(bytes) if bytes == hint.as_bytes())
        );
    }

    #[test]
    fn exported_envelope_lengths_are_the_verifiers_bounds() {
        assert_eq!(ENVELOPE_BOUNDS.signature_len, ED25519_SIGNATURE_LEN);
        assert_eq!(ENVELOPE_BOUNDS.key_id_len, KEY_ID_HEX_LEN);
    }

    #[test]
    fn the_fallback_reaches_a_non_revoked_anchor_the_hint_did_not_name() {
        // The hint names a non-revoked anchor that cannot verify, and the anchor
        // that really signed is a different non-revoked one. The fallback is
        // mandatory rather than conditional, so it is still reached and the
        // package is accepted — which is what leaves a hint pointed at the
        // wrong key with nothing to deny.
        let decoy = keypair();
        let signer = keypair();
        let trust = trust_of(vec![
            TrustAnchor::new(public_key_of(&decoy), false),
            TrustAnchor::new(public_key_of(&signer), false),
        ]);
        let hint = key_id(&public_key_of(&decoy));
        let package = signed_pkg(
            &signer,
            &default_manifest(),
            &default_archive(),
            Some(hint.as_bytes()),
        );
        assert!(verify_package(Cursor::new(package), &trust, &request()).is_ok());
    }

    #[test]
    fn a_package_signed_by_a_revoked_key_is_revoked_key() {
        let signer = keypair();
        let revoked = keypair();
        let trust = trust_of(vec![
            TrustAnchor::new(public_key_of(&signer), false),
            TrustAnchor::new(public_key_of(&revoked), true),
        ]);
        // Hinted at the *non-revoked* anchor, so the verdict is read off the
        // anchor that actually verified rather than off the footer.
        let hint = key_id(&public_key_of(&signer));
        let package = signed_pkg(
            &revoked,
            &default_manifest(),
            &default_archive(),
            Some(hint.as_bytes()),
        );
        let expected = key_id(&public_key_of(&revoked));
        assert!(matches!(
            refusal(&package, &trust),
            VerifyError::RevokedKey { key_id } if key_id == expected
        ));
    }

    #[test]
    fn a_usable_hint_naming_no_anchor_is_unknown_key_id() {
        let stranger = keypair();
        let trust = trusting(&keypair());
        let hint = key_id(&public_key_of(&stranger));
        let package = signed_pkg(
            &stranger,
            &default_manifest(),
            &default_archive(),
            Some(hint.as_bytes()),
        );
        assert!(matches!(
            refusal(&package, &trust),
            VerifyError::UnknownKeyId { key_id } if key_id == hint
        ));
    }

    #[test]
    fn a_hint_naming_a_revoked_anchor_that_does_not_verify_is_bad_signature() {
        // A revoked anchor is still an anchor the set holds, so a hint naming
        // one is not the package naming a key we do not hold. `UnknownKeyId`
        // takes a hint that names nothing at all.
        let stranger = keypair();
        let revoked = keypair();
        let trust = trust_of(vec![
            TrustAnchor::new(public_key_of(&keypair()), false),
            TrustAnchor::new(public_key_of(&revoked), true),
        ]);
        let hint = key_id(&public_key_of(&revoked));
        let package = signed_pkg(
            &stranger,
            &default_manifest(),
            &default_archive(),
            Some(hint.as_bytes()),
        );
        assert!(matches!(
            refusal(&package, &trust),
            VerifyError::BadSignature
        ));
    }

    #[test]
    fn a_hint_naming_a_known_anchor_that_does_not_verify_is_bad_signature() {
        let stranger = keypair();
        let known = keypair();
        let hint = key_id(&public_key_of(&known));
        let package = signed_pkg(
            &stranger,
            &default_manifest(),
            &default_archive(),
            Some(hint.as_bytes()),
        );
        assert!(matches!(
            refusal(&package, &trusting(&known)),
            VerifyError::BadSignature
        ));
    }

    #[test]
    fn an_absent_hint_that_does_not_verify_is_bad_signature() {
        let stranger = keypair();
        let package = signed_pkg(&stranger, &default_manifest(), &default_archive(), None);
        assert!(matches!(
            refusal(&package, &trusting(&keypair())),
            VerifyError::BadSignature
        ));
    }

    #[test]
    fn a_repeated_bound_member_name_is_duplicate_path() {
        let pair = keypair();
        let manifest = manifest_json(
            &[
                (MEMBER, len_u64(ARTIFACT_BYTES)),
                (MEMBER, len_u64(ARTIFACT_BYTES)),
            ],
            &[default_artifact()],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::DuplicatePath(path) if path == MEMBER
        ));
    }

    #[test]
    fn an_unsafe_bound_member_name_is_unsafe_path() {
        let pair = keypair();
        let manifest = manifest_json(&[("../escape", 1)], &[default_artifact()]);
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::UnsafePath(path) if path == "../escape"
        ));
    }

    #[test]
    fn a_bound_member_no_artifact_claims_is_unlisted_member() {
        let pair = keypair();
        let manifest = manifest_json(
            &[(MEMBER, len_u64(ARTIFACT_BYTES)), ("bin/extra", 4)],
            &[default_artifact()],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::UnlistedMember(name) if name == "bin/extra"
        ));
    }

    #[test]
    fn a_zero_entry_manifest_is_missing_required_member() {
        // A signed, structurally valid, empty allow-list: it forbids nothing,
        // so every other check passes precisely because there is nothing there.
        let pair = keypair();
        let manifest = manifest_json(&[], &[]);
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::MissingRequiredMember { member: None }
        ));
    }

    #[test]
    fn the_required_member_table_is_exercised_for_every_artifact_kind() {
        let pair = keypair();
        let kinds = [
            "native-binary",
            "container-image",
            "compose-bundle",
            "static-assets",
        ];

        // Each kind requires the entry's own `archive_path`: bound, the package
        // verifies; unbound, it is `MissingRequiredMember`. The second entry is
        // what makes the fault reachable — a bound member no artifact claimed
        // would be `UnlistedMember` first.
        //
        // A container image at the current format carries its declaration and
        // is verified under the namespace it declares; the namespaced request
        // verifies every other kind exactly as the plain one does.
        for kind in kinds {
            let second = if kind == "container-image" {
                image_artifact_json("bin/second", &declaration("web", &[PRODUCT_REF]))
            } else {
                artifact_json(
                    COMPONENT,
                    VERSION,
                    COMMIT,
                    kind,
                    "bin/second",
                    ARTIFACT_SHA256,
                )
            };
            let bound = manifest_json(
                &[
                    (MEMBER, len_u64(ARTIFACT_BYTES)),
                    ("bin/second", len_u64(ARTIFACT_BYTES)),
                ],
                &[default_artifact(), second.clone()],
            );
            let package = signed_pkg(&pair, &bound, &default_archive(), None);
            assert!(
                verify_package(Cursor::new(package), &trusting(&pair), &namespaced()).is_ok(),
                "a bound {kind} member should verify"
            );

            let unbound = manifest_json(
                &[(MEMBER, len_u64(ARTIFACT_BYTES))],
                &[default_artifact(), second],
            );
            let package = signed_pkg(&pair, &unbound, &default_archive(), None);
            assert!(
                matches!(
                    verify_err(&package, &trusting(&pair), &namespaced()),
                    VerifyError::MissingRequiredMember { member: Some(ref name) }
                        if name == "bin/second"
                ),
                "an unbound {kind} member should be MissingRequiredMember"
            );
        }
    }

    #[test]
    fn a_duplicate_artifact_archive_path_is_duplicate_path_and_never_nested() {
        // Reachable only from a hand-written manifest block: `PayloadManifest`'s
        // own `try_from` refuses this shape, so it cannot be built and then
        // serialized.
        let pair = keypair();
        let manifest = manifest_json(
            &[(MEMBER, len_u64(ARTIFACT_BYTES))],
            &[default_artifact(), default_artifact()],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let error = refusal(&package, &trusting(&pair));
        assert!(
            matches!(error, VerifyError::DuplicatePath(ref path) if path == MEMBER),
            "got: {error:?}"
        );
        assert!(
            !matches!(error, VerifyError::Payload(_)),
            "a mapped condition must never also arrive nested"
        );
    }

    #[test]
    fn an_unsafe_artifact_archive_path_is_unsafe_path_and_never_nested() {
        let pair = keypair();
        let artifact = artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "native-binary",
            "../escape",
            ARTIFACT_SHA256,
        );
        let manifest = manifest_json(&[("../escape", 1)], &[artifact]);
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let error = refusal(&package, &trusting(&pair));
        assert!(
            matches!(error, VerifyError::UnsafePath(ref path) if path == "../escape"),
            "got: {error:?}"
        );
        assert!(
            !matches!(error, VerifyError::Payload(_)),
            "a mapped condition must never also arrive nested"
        );
    }

    #[test]
    fn a_format_version_outside_the_build_range_is_unsupported_and_never_nested() {
        let pair = keypair();
        let beyond = MAX_MANIFEST_FORMAT_VERSION + 1;
        let manifest = manifest_json_at(
            beyond,
            &[(MEMBER, len_u64(ARTIFACT_BYTES))],
            &[default_artifact()],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let error = refusal(&package, &trusting(&pair));
        assert!(
            matches!(
                error,
                VerifyError::UnsupportedManifestFormat { found, min, max }
                    if found == beyond
                        && min == MIN_MANIFEST_FORMAT_VERSION
                        && max == MAX_MANIFEST_FORMAT_VERSION
            ),
            "got: {error:?}"
        );
        assert!(
            !matches!(error, VerifyError::Payload(_)),
            "a mapped condition must never also arrive nested"
        );
    }

    #[test]
    fn a_manifest_under_an_injected_floor_is_unsupported_while_its_signature_is_valid() {
        let pair = keypair();
        let package = default_pkg(&pair);
        // The same fixture verifies at this build's own floor, so the refusal
        // below is the floor and not the signature — which is the order of
        // operations the test exists to prove.
        assert!(verify_package(Cursor::new(package.clone()), &trusting(&pair), &request()).is_ok());

        let floor = MAX_MANIFEST_FORMAT_VERSION + 1;
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            Vec::new(),
            floor,
            0,
        )
        .expect("a single anchor builds a trust set");
        assert!(matches!(
            refusal(&package, &trust),
            VerifyError::UnsupportedManifestFormat { found, min, .. }
                if found == MANIFEST_FORMAT_VERSION && min == floor
        ));
    }

    #[test]
    fn an_injected_floor_inside_the_implemented_range_refuses_only_below_itself() {
        // The build's window has spanned more than one version since manifest
        // format version 4, so a floor can sit *inside* it — above the bottom
        // yet no higher than the top, leaving versions the build still accepts
        // — rather than only above the whole window. Release ops raising the
        // floor to the producer's version must refuse a package written at the
        // build's own floor and still accept one written at the producer's.
        let pair = keypair();
        let at_floor = signed_pkg(
            &pair,
            &manifest_json_at(
                MIN_MANIFEST_FORMAT_VERSION,
                &[(MEMBER, len_u64(ARTIFACT_BYTES))],
                &[default_artifact()],
            ),
            &default_archive(),
            None,
        );
        // Both versions verify under the build's own floor, so the refusal
        // below is the injected floor and nothing else about the fixture.
        assert_eq!(
            accepted(&at_floor, &trusting(&pair))
                .manifest()
                .format_version(),
            Some(MIN_MANIFEST_FORMAT_VERSION)
        );

        let floor = MANIFEST_FORMAT_VERSION;
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            Vec::new(),
            floor,
            0,
        )
        .expect("a single anchor builds a trust set");
        assert!(
            matches!(
                refusal(&at_floor, &trust),
                VerifyError::UnsupportedManifestFormat { found, min, max }
                    if found == MIN_MANIFEST_FORMAT_VERSION
                        && min == floor
                        && max == MAX_MANIFEST_FORMAT_VERSION
            ),
            "a package below the injected floor must be refused"
        );
        // The floor is a floor and not a pin: the producer's own version, at
        // the top of the same window, still verifies under it.
        assert!(verify_package(Cursor::new(default_pkg(&pair)), &trust, &request()).is_ok());
    }

    #[test]
    fn verification_never_reads_the_archive_block() {
        // The completeness checks are decided from the bound member list and
        // the artifact entries alone, so an archive block that is not even a
        // compressed stream cannot change the verdict. Anything that walked or
        // hashed it would fail here instead of accepting.
        let pair = keypair();
        let package = signed_pkg(
            &pair,
            &default_manifest(),
            b"not an archive, not even zstd",
            None,
        );
        let verified = accepted(&package, &trusting(&pair));
        assert_eq!(verified.manifest().artifacts().len(), 1);
    }

    #[test]
    fn extracting_a_verified_package_surfaces_a_container_condition_through_the_wrapper() {
        // The other arm of the hand-written `From`: everything that is not
        // `HashMismatch` reaches the caller wrapped, still under this taxonomy
        // and still without the caller mapping anything. The archive holds a
        // member the manifest never listed, which the walk refuses — and which
        // `verify_package` accepted, because it never looked at the archive.
        let pair = keypair();
        let archive = archive_of(&[(MEMBER, ARTIFACT_BYTES), ("bin/extra", b"x")]);
        let package = signed_pkg(&pair, &default_manifest(), &archive, None);
        let mut verified = accepted(&package, &trusting(&pair));
        let dir = tempfile::tempdir().expect("tempdir");
        let error = verified
            .extract_to(dir.path())
            .expect_err("extraction should be refused");
        assert!(
            matches!(
                error,
                VerifyError::Payload(PayloadError::MemberNotInManifest(ref name))
                    if name == "bin/extra"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn extracting_a_verified_package_writes_its_artifacts() {
        let pair = keypair();
        let mut verified = accepted(&default_pkg(&pair), &trusting(&pair));
        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = verified
            .extract_to(dir.path())
            .expect("extraction should succeed");
        assert_eq!(extracted.len(), 1);
        assert_eq!(
            std::fs::read(dir.path().join(MEMBER)).expect("the artifact is on disk"),
            ARTIFACT_BYTES
        );
    }

    #[test]
    fn extracting_an_artifact_whose_bytes_disagree_is_manifest_hash_mismatch() {
        // The manifest binds the member the archive really holds, at the length
        // it really is, and records a SHA-256 of other bytes — so the walk gets
        // as far as hashing the member and no further.
        let pair = keypair();
        let artifact = artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "native-binary",
            MEMBER,
            &"00".repeat(32),
        );
        let manifest = manifest_json(&[(MEMBER, len_u64(ARTIFACT_BYTES))], &[artifact]);
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let mut verified = accepted(&package, &trusting(&pair));
        let dir = tempfile::tempdir().expect("tempdir");
        let error = verified
            .extract_to(dir.path())
            .expect_err("extraction should be refused");
        assert!(
            matches!(error, VerifyError::ManifestHashMismatch { ref path } if path == MEMBER),
            "got: {error:?}"
        );
        assert!(
            !matches!(error, VerifyError::Payload(_)),
            "a mapped condition must never also arrive nested"
        );
    }

    #[test]
    fn a_container_layer_condition_reaches_the_caller_through_the_wrapper() {
        let pair = keypair();
        // Not a container at all: no probed candidate carries the magic.
        let error = refusal(b"not a package", &trusting(&pair));
        assert!(
            matches!(error, VerifyError::Payload(PayloadError::NoTrailer)),
            "got: {error:?}"
        );
    }

    #[test]
    fn the_identifier_predicate_accepts_a_valid_triple_and_rejects_unsafe_values() {
        assert!(is_safe_build_identifier(COMPONENT));
        assert!(is_safe_build_identifier(VERSION));
        assert!(is_safe_build_identifier(COMMIT));
        assert!(is_safe_build_identifier("1.0.0-rc.1+build~2"));
        assert!(is_safe_build_identifier("sha256:abc"));
        assert!(is_safe_build_identifier(
            &"a".repeat(MAX_BUILD_IDENTIFIER_BYTES)
        ));

        for bad in [
            "", ".hidden", "-flag", "bin/app", "..", "a\0b", "naïve", "a b",
        ] {
            assert!(!is_safe_build_identifier(bad), "value {bad:?} was accepted");
        }
        assert!(!is_safe_build_identifier(
            &"a".repeat(MAX_BUILD_IDENTIFIER_BYTES + 1)
        ));
        // Measured in bytes, not characters: 65 two-byte characters is 130.
        assert!(!is_safe_build_identifier(&"é".repeat(65)));
    }

    #[test]
    fn an_unsafe_identifier_in_any_field_is_unsafe_build_identifier() {
        let pair = keypair();
        let cases = [
            (BuildIdentifier::Component, "../escape", VERSION, COMMIT),
            (BuildIdentifier::Version, COMPONENT, "-1.0", COMMIT),
        ];
        for (field, component, version, commit) in cases {
            let artifact = artifact_json(
                component,
                version,
                commit,
                "native-binary",
                MEMBER,
                ARTIFACT_SHA256,
            );
            let manifest = manifest_json(&[(MEMBER, len_u64(ARTIFACT_BYTES))], &[artifact]);
            let package = signed_pkg(&pair, &manifest, &default_archive(), None);
            let error = refusal(&package, &trusting(&pair));
            assert!(
                matches!(error, VerifyError::UnsafeBuildIdentifier { field: got, .. } if got == field),
                "got: {error:?}"
            );
        }
    }

    #[test]
    fn a_commit_the_parse_refuses_never_reaches_the_identifier_check() {
        // The verifier applies the predicate to `commit` all the same, because
        // it is exported for callers joining any of the three fields into a
        // store path and must not have a hole one has to remember. But an
        // unsafe `commit` cannot reach that check through a package: the parse
        // constrains a current-format `commit` to 40- or 64-character lowercase
        // hex first, and `InvalidCommit` gets no taxonomy name of its own.
        let pair = keypair();
        let artifact = artifact_json(
            COMPONENT,
            VERSION,
            "not hex",
            "native-binary",
            MEMBER,
            ARTIFACT_SHA256,
        );
        let manifest = manifest_json(&[(MEMBER, len_u64(ARTIFACT_BYTES))], &[artifact]);
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let error = refusal(&package, &trusting(&pair));
        assert!(
            matches!(
                error,
                VerifyError::Payload(PayloadError::InvalidManifest(
                    crate::manifest::ManifestError::InvalidCommit { .. }
                ))
            ),
            "got: {error:?}"
        );
        // Every value the parse does admit is a safe build identifier, which is
        // what makes the wrapped refusal above the only reachable verdict.
        assert!(is_safe_build_identifier(COMMIT));
    }

    #[test]
    fn a_request_disagreeing_in_any_field_is_target_mismatch() {
        let pair = keypair();
        let package = default_pkg(&pair);
        let trust = trusting(&pair);
        let requests = [
            VerifyRequest::for_package("other", VERSION, COMMIT),
            VerifyRequest::for_package(COMPONENT, "9.9.9", COMMIT),
            VerifyRequest::for_package(COMPONENT, VERSION, OTHER_COMMIT),
        ];
        for request in requests {
            let request = request.expect("an ordinary target");
            assert!(matches!(
                verify_err(&package, &trust, &request),
                VerifyError::TargetMismatch { .. }
            ));
        }
    }

    #[test]
    fn a_manifest_whose_second_entry_disagrees_is_target_mismatch() {
        // Every entry must match, not merely one: a package that satisfied the
        // request with one entry while carrying another component's artifacts
        // alongside would be extracted and installed whole.
        let pair = keypair();
        let second = artifact_json(
            "other",
            VERSION,
            COMMIT,
            "native-binary",
            "bin/other",
            ARTIFACT_SHA256,
        );
        let manifest = manifest_json(
            &[
                (MEMBER, len_u64(ARTIFACT_BYTES)),
                ("bin/other", len_u64(ARTIFACT_BYTES)),
            ],
            &[default_artifact(), second],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            refusal(&package, &trusting(&pair)),
            VerifyError::TargetMismatch { ref component, .. } if component == "other"
        ));
    }

    #[test]
    fn two_anchors_sharing_a_public_key_are_refused() {
        let pair = keypair();
        let public_key = public_key_of(&pair);
        let error = TrustSet::new(
            vec![
                TrustAnchor::new(public_key, false),
                TrustAnchor::new(public_key, true),
            ],
            Vec::new(),
            MIN_MANIFEST_FORMAT_VERSION,
            0,
        )
        .expect_err("two anchors sharing a key must be refused");
        assert!(
            matches!(error, InputError::DuplicateAnchor { ref key_id } if *key_id == key_id_of(&pair))
        );
    }

    fn key_id_of(pair: &Ed25519KeyPair) -> String {
        key_id(&public_key_of(pair))
    }

    #[test]
    fn an_anchors_key_id_is_this_crates_derivation_over_its_public_key() {
        let pair = keypair();
        let public_key = public_key_of(&pair);
        let anchor = TrustAnchor::new(public_key, false);
        assert_eq!(anchor.key_id(), key_id(&public_key));
        assert_eq!(anchor.public_key(), &public_key);
        assert!(!anchor.is_revoked());
    }

    #[test]
    fn key_id_is_the_untruncated_lowercase_hex_sha256_of_the_public_key() {
        // SHA-256 over 32 zero bytes, computed outside this crate.
        const ZEROS_SHA256: &str =
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        let derived = key_id(&[0u8; 32]);
        assert_eq!(derived, ZEROS_SHA256);
        // The literal rather than the constant: a `key_id` is 64 characters
        // because that is what the format says, not because this crate says so.
        assert_eq!(derived.len(), 64);
        assert!(derived.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!derived.bytes().any(|byte| byte.is_ascii_uppercase()));
    }

    #[test]
    fn a_withdrawn_triple_is_withdrawn_build_under_a_request_that_matches_it() {
        // The request agrees with the manifest exactly, so the verdict cannot be
        // confounded by a target disagreement.
        let pair = keypair();
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            vec![(
                COMPONENT.to_string(),
                VERSION.to_string(),
                COMMIT.to_string(),
            )],
            MIN_MANIFEST_FORMAT_VERSION,
            0,
        )
        .expect("a single anchor builds a trust set");
        assert!(matches!(
            refusal(&default_pkg(&pair), &trust),
            VerifyError::WithdrawnBuild { ref package_id, .. } if package_id == COMPONENT
        ));
    }

    #[test]
    fn withdrawal_outranks_target_mismatch() {
        // The case a compromised requesting hop would use to downgrade a "this
        // build is withdrawn, stop" into a retryable "you asked for the wrong
        // thing".
        let pair = keypair();
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            vec![(
                COMPONENT.to_string(),
                VERSION.to_string(),
                COMMIT.to_string(),
            )],
            MIN_MANIFEST_FORMAT_VERSION,
            0,
        )
        .expect("a single anchor builds a trust set");
        let disagreeing =
            VerifyRequest::for_package("other", "9.9.9", OTHER_COMMIT).expect("an ordinary target");
        assert!(matches!(
            verify_err(&default_pkg(&pair), &trust, &disagreeing),
            VerifyError::WithdrawnBuild { .. }
        ));
    }

    #[test]
    fn every_distinct_triple_is_checked_against_the_withdrawn_list() {
        // A two-triple manifest can never pass the target check, so this case
        // is reachable only because withdrawal is decided first.
        let pair = keypair();
        let second = artifact_json(
            "other",
            VERSION,
            OTHER_COMMIT,
            "native-binary",
            "bin/other",
            ARTIFACT_SHA256,
        );
        let manifest = manifest_json(
            &[
                (MEMBER, len_u64(ARTIFACT_BYTES)),
                ("bin/other", len_u64(ARTIFACT_BYTES)),
            ],
            &[default_artifact(), second],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            vec![(
                "other".to_string(),
                VERSION.to_string(),
                OTHER_COMMIT.to_string(),
            )],
            MIN_MANIFEST_FORMAT_VERSION,
            0,
        )
        .expect("a single anchor builds a trust set");
        assert!(matches!(
            refusal(&package, &trust),
            VerifyError::WithdrawnBuild { ref package_id, .. } if package_id == "other"
        ));
    }

    #[test]
    fn the_ordinary_request_constructor_refuses_the_reserved_trust_target() {
        assert!(matches!(
            VerifyRequest::for_package(TRUST_TARGET, VERSION, COMMIT)
                .expect_err("the reserved name must be refused"),
            InputError::ReservedTarget
        ));
        // And neither constructor panics on any input, empty strings included.
        assert!(VerifyRequest::for_package("", "", "").is_ok());
        let trust_request = VerifyRequest::for_trust("", "", 0).expect("the trust constructor");
        assert_eq!(trust_request.target(), TRUST_TARGET);
    }

    #[test]
    fn the_trust_target_accepts_only_a_strictly_greater_epoch() {
        const ACTIVE: u64 = 5;
        let pair = keypair();
        let artifact = artifact_json(
            TRUST_TARGET,
            VERSION,
            COMMIT,
            "native-binary",
            MEMBER,
            ARTIFACT_SHA256,
        );
        let manifest = manifest_json(&[(MEMBER, len_u64(ARTIFACT_BYTES))], &[artifact]);
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            Vec::new(),
            MIN_MANIFEST_FORMAT_VERSION,
            ACTIVE,
        )
        .expect("a single anchor builds a trust set");

        for stale in [ACTIVE - 1, ACTIVE] {
            let request = VerifyRequest::for_trust(VERSION, COMMIT, stale).expect("trust request");
            assert!(matches!(
                verify_err(&package, &trust, &request),
                VerifyError::StaleTrustSet { delivered, active }
                    if delivered == stale && active == ACTIVE
            ));
        }

        let request = VerifyRequest::for_trust(VERSION, COMMIT, ACTIVE + 1).expect("trust request");
        assert!(verify_package(Cursor::new(package), &trust, &request).is_ok());
    }

    #[test]
    fn the_manifests_own_trust_set_field_is_not_the_epoch() {
        // `trust_set` is an opaque generation fingerprint the manifest carries,
        // and this verifier neither reads nor interprets it. A trust-target
        // package carrying one is decided exactly as one without: the request's
        // delivered epoch against the trust set's active one, and the
        // fingerprint reaches the caller untouched.
        const ACTIVE: u64 = 5;
        // Base64 of `generation`, which is the wire form the field holds.
        const FINGERPRINT: &str = "Z2VuZXJhdGlvbg==";

        let pair = keypair();
        let artifact = artifact_json(
            TRUST_TARGET,
            VERSION,
            COMMIT,
            "native-binary",
            MEMBER,
            ARTIFACT_SHA256,
        );
        let member = format!(
            r#"{{"name":"{MEMBER}","length":{}}}"#,
            len_u64(ARTIFACT_BYTES)
        );
        let manifest = format!(
            r#"{{"format_version":{MANIFEST_FORMAT_VERSION},"trust_set":"{FINGERPRINT}","archive_members":[{member}],"artifacts":[{artifact}]}}"#
        )
        .into_bytes();
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        let trust = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            Vec::new(),
            MIN_MANIFEST_FORMAT_VERSION,
            ACTIVE,
        )
        .expect("a single anchor builds a trust set");

        let stale = VerifyRequest::for_trust(VERSION, COMMIT, ACTIVE).expect("trust request");
        assert!(matches!(
            verify_err(&package, &trust, &stale),
            VerifyError::StaleTrustSet { delivered, active }
                if delivered == ACTIVE && active == ACTIVE
        ));

        let fresh = VerifyRequest::for_trust(VERSION, COMMIT, ACTIVE + 1).expect("trust request");
        let verified = verify_package(Cursor::new(package), &trust, &fresh)
            .expect("the package should verify");
        assert_eq!(verified.manifest().trust_set(), Some(&b"generation"[..]));
    }

    // ---- Image declarations ----------------------------------------------

    /// The namespace image fixtures are owned by, and the one a namespaced
    /// fixture request names.
    const NAMESPACE: &str = "example-product";
    /// A product-built tag an image fixture keeps as its producer chose it.
    const PRODUCT_REF: &str = "ghcr.io/example/example:1.0.0";
    /// Synthetic digests, each naming a different object.
    const CONFIG_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONFIG_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONFIG_C: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PINNED: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const SELECTED: &str =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    /// A 64-hex outer identifier, the legacy digest width.
    const DIGEST_COMMIT: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    /// Changes one facet of a declaration.
    type Mutation = fn(&mut ImageDeclaration);
    /// Names which image refusal a case must report.
    type ImageCheck = fn(&ImageVerifyError) -> bool;

    /// The namespaced request the image fixtures satisfy.
    fn namespaced() -> VerifyRequest {
        VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, NAMESPACE)
            .expect("a valid namespace and an ordinary target")
    }

    fn owner() -> ImageOwner {
        ImageOwner {
            namespace: NAMESPACE.to_string(),
            component: COMPONENT.to_string(),
        }
    }

    fn amd64() -> ImagePlatform {
        ImagePlatform {
            os: ImageOs::Linux,
            architecture: ImageArchitecture::Amd64,
            variant: None,
        }
    }

    fn registry(repository: &str, tag: &str) -> RegistryProvenance {
        RegistryProvenance {
            repository: repository.to_string(),
            tag: tag.to_string(),
            version: None,
            pinned_digest: PINNED.to_string(),
            selected_manifest_digest: SELECTED.to_string(),
        }
    }

    /// A product-built amd64 declaration of `dependency` under `refs`, owned by
    /// the fixture namespace and component, at [`CONFIG_A`].
    fn declaration(dependency: &str, refs: &[&str]) -> ImageDeclaration {
        ImageDeclaration {
            schema: 1,
            owner: owner(),
            dependency: dependency.to_string(),
            public_refs: refs.iter().map(|value| (*value).to_string()).collect(),
            platform: amd64(),
            config_digest: CONFIG_A.to_string(),
            reference_lifecycle: ReferenceLifecycle::ManagedRuntime,
            provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: "https://example.invalid/example.git".to_string(),
                commit: COMMIT.to_string(),
            }),
        }
    }

    /// A newly normalized third-party declaration, whose one reference is its
    /// canonical alias.
    fn normalized(dependency: &str, config: &str, repository: &str) -> ImageDeclaration {
        ImageDeclaration::normalized_third_party(
            owner(),
            dependency,
            amd64(),
            config,
            registry(repository, "1.0"),
        )
        .expect("a valid normalized declaration")
    }

    /// Splices `image` into the wire entry of a `container-image` artifact of
    /// the requested build.
    fn image_artifact_json(archive_path: &str, image: &ImageDeclaration) -> String {
        image_artifact_json_with(archive_path, COMMIT, image)
    }

    fn image_artifact_json_with(
        archive_path: &str,
        commit: &str,
        image: &ImageDeclaration,
    ) -> String {
        let entry = artifact_json(
            COMPONENT,
            VERSION,
            commit,
            "container-image",
            archive_path,
            ARTIFACT_SHA256,
        );
        let body = entry.strip_suffix('}').expect("an entry ends with a brace");
        let image = serde_json::to_string(image).expect("a declaration serializes");
        format!(r#"{body},"image":{image}}}"#)
    }

    /// Wire JSON of an entry whose `archive_path` is its first field, so a
    /// fixture can put the path first and assert it in errors.
    fn member_path(entry: &str) -> String {
        let at = entry
            .find(r#""archive_path":""#)
            .expect("an entry carries a path");
        let rest = entry.get(at + 16..).expect("in range");
        rest.get(..rest.find('"').expect("closed"))
            .expect("in range")
            .to_string()
    }

    /// Signs a manifest at `format_version` carrying `entries`, binding one
    /// member per entry at the fixture artifact's length.
    fn package_of_at(pair: &Ed25519KeyPair, format_version: u32, entries: &[String]) -> Vec<u8> {
        let paths: Vec<String> = entries.iter().map(|entry| member_path(entry)).collect();
        let members: Vec<(&str, u64)> = paths
            .iter()
            .map(|path| (path.as_str(), len_u64(ARTIFACT_BYTES)))
            .collect();
        let manifest = manifest_json_at(format_version, &members, entries);
        signed_pkg(pair, &manifest, &default_archive(), None)
    }

    fn package_of(pair: &Ed25519KeyPair, entries: &[String]) -> Vec<u8> {
        package_of_at(pair, MANIFEST_FORMAT_VERSION, entries)
    }

    /// Verifies a package under the namespaced request, returning the image
    /// error it must be refused with.
    fn image_refusal(
        package: &[u8],
        trust: &TrustSet,
        request: &VerifyRequest,
    ) -> ImageVerifyError {
        match verify_err(package, trust, request) {
            VerifyError::Image(error) => error,
            other => panic!("expected an image refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_namespaced_constructor_validates_its_namespace_and_refuses_the_trust_target() {
        let scoped = namespaced();
        assert_eq!(scoped.namespace(), Some(NAMESPACE));
        assert_eq!(scoped.target(), COMPONENT);
        for invalid in ["", "Example", "a/b", "${NAMESPACE}", "../x", "-x", " x"] {
            assert!(
                matches!(
                    VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, invalid),
                    Err(InputError::InvalidNamespace { ref namespace }) if namespace == invalid
                ),
                "{invalid:?}"
            );
        }
        // The reserved target keeps its own constructor and epoch contract.
        assert!(matches!(
            VerifyRequest::for_namespaced_package(TRUST_TARGET, VERSION, COMMIT, NAMESPACE),
            Err(InputError::ReservedTarget)
        ));
        // The existing constructors carry no namespace.
        assert_eq!(request().namespace(), None);
        assert_eq!(
            VerifyRequest::for_trust(VERSION, COMMIT, 1)
                .expect("trust")
                .namespace(),
            None
        );
    }

    #[test]
    fn the_projection_distinguishes_no_images_declared_images_and_legacy_images() {
        let pair = keypair();
        let trust = trusting(&pair);

        // A native package, under either ordinary constructor.
        for request in [request(), namespaced()] {
            let verified = verify_package(Cursor::new(default_pkg(&pair)), &trust, &request)
                .expect("a native package verifies");
            assert!(matches!(
                verified.image_references(),
                ImageReferences::NoImages
            ));
        }

        // A trust package under its own constructor.
        let trust_entry = artifact_json(
            TRUST_TARGET,
            VERSION,
            COMMIT,
            "static-assets",
            MEMBER,
            ARTIFACT_SHA256,
        );
        let trust_request = VerifyRequest::for_trust(VERSION, COMMIT, 1).expect("trust request");
        let verified = verify_package(
            Cursor::new(package_of(&pair, &[trust_entry])),
            &trust,
            &trust_request,
        )
        .expect("a trust package verifies");
        assert!(matches!(
            verified.image_references(),
            ImageReferences::NoImages
        ));

        // A legacy image at every pre-declaration format, under either
        // constructor: never an empty reference set, never a declaration.
        for version in MIN_MANIFEST_FORMAT_VERSION..IMAGE_DECLARATION_FORMAT_VERSION {
            let legacy = artifact_json(
                COMPONENT,
                VERSION,
                COMMIT,
                "container-image",
                "images/legacy.tar",
                ARTIFACT_SHA256,
            );
            let package = package_of_at(&pair, version, &[default_artifact(), legacy]);
            for request in [request(), namespaced()] {
                let verified = verify_package(Cursor::new(package.clone()), &trust, &request)
                    .expect("a legacy image package verifies");
                assert!(
                    matches!(
                        verified.image_references(),
                        ImageReferences::LegacyUndeclared
                    ),
                    "v{version}"
                );
                assert!(
                    verified
                        .manifest()
                        .artifacts()
                        .iter()
                        .all(|a| a.image.is_none())
                );
            }
        }

        // A declared image, only through the namespaced constructor.
        let image = declaration("web", &[PRODUCT_REF]);
        let package = package_of(
            &pair,
            &[
                default_artifact(),
                image_artifact_json("images/web.tar", &image),
            ],
        );
        let verified = verify_package(Cursor::new(package.clone()), &trust, &namespaced())
            .expect("a declared image verifies under its namespace");
        let ImageReferences::Declared(declared) = verified.image_references() else {
            panic!("expected declared references");
        };
        assert_eq!(declared.references(), vec![PRODUCT_REF]);
        let declarations: Vec<_> = declared.declarations().collect();
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].0.archive_path, "images/web.tar");
        assert_eq!(declarations[0].1, &image);

        assert!(matches!(
            image_refusal(&package, &trust, &request()),
            ImageVerifyError::MissingNamespace { ref archive_path } if archive_path == "images/web.tar"
        ));
    }

    #[test]
    fn the_namespace_is_compared_verbatim_and_the_owner_component_against_the_target() {
        let pair = keypair();
        let trust = trusting(&pair);
        let package = package_of(
            &pair,
            &[image_artifact_json(
                "images/web.tar",
                &declaration("web", &[PRODUCT_REF]),
            )],
        );

        // No prefix is stripped in either direction, and case is not folded.
        for other in [
            "product",
            "example-product-2",
            "example_product",
            "prod-example-product",
        ] {
            let request = VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, other)
                .expect("a valid namespace");
            assert!(
                matches!(
                    image_refusal(&package, &trust, &request),
                    ImageVerifyError::NamespaceMismatch { ref expected, ref declared, .. }
                        if expected == other && declared == NAMESPACE
                ),
                "{other}"
            );
        }

        let mut foreign = declaration("web", &[PRODUCT_REF]);
        foreign.owner.component = "other".to_string();
        let package = package_of(&pair, &[image_artifact_json("images/web.tar", &foreign)]);
        assert!(matches!(
            image_refusal(&package, &trust, &namespaced()),
            ImageVerifyError::OwnerComponentMismatch { ref expected, ref declared, .. }
                if expected == COMPONENT && declared == "other"
        ));
    }

    #[test]
    fn a_declared_architecture_must_be_its_artifacts() {
        let pair = keypair();
        let trust = trusting(&pair);
        let mut arm = declaration("web", &[PRODUCT_REF]);
        arm.platform.architecture = ImageArchitecture::Arm64;
        let on_x86 = image_artifact_json("images/web.tar", &arm);
        assert!(matches!(
            image_refusal(
                &package_of(&pair, std::slice::from_ref(&on_x86)),
                &trust,
                &namespaced()
            ),
            ImageVerifyError::PlatformMismatch {
                target_arch: TargetArch::X86_64,
                declared: ImageArchitecture::Arm64,
                ..
            }
        ));
        // The same declaration on an aarch64 artifact, variant and all.
        arm.platform.variant = Some("v8".to_string());
        let on_arm = image_artifact_json("images/web.tar", &arm)
            .replace(r#""target_arch":"x86_64""#, r#""target_arch":"aarch64""#);
        verify_package(
            Cursor::new(package_of(&pair, &[on_arm])),
            &trust,
            &namespaced(),
        )
        .expect("an arm64 declaration on an aarch64 artifact verifies");
    }

    #[test]
    fn a_reserved_reference_must_be_its_own_declarations_canonical_alias() {
        let pair = keypair();
        let trust = trusting(&pair);
        let valid = normalized("database", CONFIG_C, "docker.io/library/postgres");
        let alias = valid.public_refs[0].clone();
        verify_package(
            Cursor::new(package_of(
                &pair,
                &[image_artifact_json("images/db.tar", &valid)],
            )),
            &trust,
            &namespaced(),
        )
        .expect("the canonical alias verifies");

        let hex_c = CONFIG_C.trim_start_matches("sha256:");
        let hex_b = CONFIG_B.trim_start_matches("sha256:");
        let wrong = [
            format!("runtime.invalid/other-product/{COMPONENT}/database:cfg-{hex_c}"),
            format!("runtime.invalid/{NAMESPACE}/other/database:cfg-{hex_c}"),
            format!("runtime.invalid/{NAMESPACE}/{COMPONENT}/cache:cfg-{hex_c}"),
            format!("runtime.invalid/{NAMESPACE}/{COMPONENT}/database:cfg-{hex_b}"),
            format!("RUNTIME.INVALID/{NAMESPACE}/{COMPONENT}/database:cfg-{hex_c}"),
            format!("Runtime.Invalid/{NAMESPACE}/{COMPONENT}/database:cfg-{hex_c}"),
            format!("runtime.invalid:5000/{NAMESPACE}/{COMPONENT}/database:cfg-{hex_c}"),
            format!("runtime.invalid/{NAMESPACE}/{COMPONENT}/database:{hex_c}"),
            format!("runtime.invalid/{NAMESPACE}/{COMPONENT}/database:latest"),
        ];
        for reference in wrong {
            let mut image = valid.clone();
            image.public_refs = vec![reference.clone()];
            let package = package_of(&pair, &[image_artifact_json("images/db.tar", &image)]);
            assert!(
                matches!(
                    image_refusal(&package, &trust, &namespaced()),
                    ImageVerifyError::NonCanonicalReservedReference { reference: ref got, ref expected, .. }
                        if *got == reference && expected.as_deref() == Some(alias.as_str())
                ),
                "{reference}"
            );
        }

        // The canonical alias under a shared lifecycle.
        let mut shared = valid.clone();
        shared.reference_lifecycle = ReferenceLifecycle::SharedExternal;
        let package = package_of(&pair, &[image_artifact_json("images/db.tar", &shared)]);
        assert!(matches!(
            image_refusal(&package, &trust, &namespaced()),
            ImageVerifyError::ReservedReferenceLifecycle { ref reference, .. } if *reference == alias
        ));

        // A declaration whose segments form no valid alias has nothing a
        // reserved reference could equal.
        let mut trailing = valid.clone();
        trailing.dependency = "database-".to_string();
        let package = package_of(&pair, &[image_artifact_json("images/db.tar", &trailing)]);
        assert!(matches!(
            image_refusal(&package, &trust, &namespaced()),
            ImageVerifyError::NonCanonicalReservedReference { expected: None, .. }
        ));

        // Other references beside the alias need not be canonical aliases,
        // and a managed product tag is not rewritten.
        let mut beside = valid;
        beside.public_refs.push(PRODUCT_REF.to_string());
        verify_package(
            Cursor::new(package_of(
                &pair,
                &[image_artifact_json("images/db.tar", &beside)],
            )),
            &trust,
            &namespaced(),
        )
        .expect("a product tag beside the alias verifies");
    }

    #[test]
    fn a_normalized_reference_may_be_shared_only_by_agreeing_declarations() {
        let pair = keypair();
        let trust = trusting(&pair);
        let first = declaration("proxy", &["nginx:1.27"]);
        let conflicts: [(Mutation, ReferenceConflict); 5] = [
            (
                |d| d.config_digest = CONFIG_B.to_string(),
                ReferenceConflict::ConfigDigest,
            ),
            (
                |d| d.platform.variant = Some("v2".to_string()),
                ReferenceConflict::Platform,
            ),
            (
                |d| d.owner.component = "other".to_string(),
                ReferenceConflict::Owner,
            ),
            (
                |d| d.owner.namespace = "other-product".to_string(),
                ReferenceConflict::Owner,
            ),
            (
                |d| d.reference_lifecycle = ReferenceLifecycle::SharedExternal,
                ReferenceConflict::Lifecycle,
            ),
        ];
        for (mutate, expected) in conflicts {
            let mut second = declaration("edge", &["docker.io/library/nginx:1.27"]);
            mutate(&mut second);
            let package = package_of(
                &pair,
                &[
                    image_artifact_json("images/proxy.tar", &first),
                    image_artifact_json("images/edge.tar", &second),
                ],
            );
            assert!(
                matches!(
                    image_refusal(&package, &trust, &namespaced()),
                    ImageVerifyError::ConflictingReference {
                        ref archive_path, ref reference, ref first_archive_path, ref first_reference, conflict
                    } if archive_path == "images/edge.tar"
                        && reference == "docker.io/library/nginx:1.27"
                        && first_archive_path == "images/proxy.tar"
                        && first_reference == "nginx:1.27"
                        && conflict == expected
                ),
                "{expected}"
            );
        }

        // Same image, different dependency and provenance: not a conflict.
        let mut agreeing = declaration("edge", &["docker.io/library/nginx:1.27"]);
        agreeing.provenance =
            ImageProvenance::Registry(registry("docker.io/library/nginx", "1.27"));
        let package = package_of(
            &pair,
            &[
                image_artifact_json("images/proxy.tar", &first),
                image_artifact_json("images/edge.tar", &agreeing),
            ],
        );
        verify_package(Cursor::new(package), &trust, &namespaced())
            .expect("a provenance-only difference is accepted");

        // Within one declaration a normalized duplicate is a parse refusal.
        let duplicate = declaration(
            "proxy",
            &["nginx:1.27", "index.docker.io/library/nginx:1.27"],
        );
        let package = package_of(
            &pair,
            &[image_artifact_json("images/proxy.tar", &duplicate)],
        );
        assert!(matches!(
            verify_err(&package, &trust, &namespaced()),
            VerifyError::Payload(PayloadError::InvalidManifest(
                ManifestError::InvalidImageDeclaration {
                    source: ImageDeclarationError::DuplicateReference { .. },
                    ..
                }
            ))
        ));
    }

    #[test]
    fn a_six_image_component_package_verifies_to_a_deterministic_union() {
        let pair = keypair();
        let trust = trusting(&pair);
        let database = normalized("database", CONFIG_C, "docker.io/library/postgres");
        let cache = normalized("cache", CONFIG_B, "docker.io/library/redis");
        let web = declaration("web", &[PRODUCT_REF]);
        let mut worker = declaration(
            "worker",
            &["ghcr.io/example/worker:1.0.0", "ghcr.io/example/worker:1.0"],
        );
        worker.config_digest = CONFIG_B.to_string();
        worker.reference_lifecycle = ReferenceLifecycle::SharedExternal;
        // Two spellings of one reference, on two declarations of one image
        // that differ only in dependency and provenance.
        let mut proxy = declaration("proxy", &["nginx:1.27"]);
        proxy.config_digest = CONFIG_C.to_string();
        proxy.provenance = ImageProvenance::Registry(registry("docker.io/library/nginx", "1.27"));
        let mut edge = declaration(
            "edge",
            &[
                "docker.io/library/nginx:1.27",
                "docker.io/library/nginx:stable",
            ],
        );
        edge.config_digest = CONFIG_C.to_string();

        let entries = vec![
            artifact_json(
                COMPONENT,
                VERSION,
                COMMIT,
                "compose-bundle",
                "compose/stack.tar",
                ARTIFACT_SHA256,
            ),
            image_artifact_json("images/database.tar", &database),
            image_artifact_json("images/cache.tar", &cache),
            image_artifact_json("images/web.tar", &web),
            artifact_json(
                COMPONENT,
                VERSION,
                COMMIT,
                "static-assets",
                "assets/web.tar",
                ARTIFACT_SHA256,
            ),
            image_artifact_json("images/worker.tar", &worker),
            image_artifact_json("images/proxy.tar", &proxy),
            image_artifact_json("images/edge.tar", &edge),
        ];
        let package = package_of(&pair, &entries);
        let verified = verify_package(Cursor::new(package.clone()), &trust, &namespaced())
            .expect("the component package verifies");
        let ImageReferences::Declared(declared) = verified.image_references() else {
            panic!("expected declared references");
        };
        assert_eq!(declared.declarations().count(), 6);
        let mut expected: Vec<String> = [&database, &cache, &web, &worker, &proxy, &edge]
            .iter()
            .flat_map(|image| image.public_refs.clone())
            .collect();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(declared.references(), expected);
        // Both signed spellings survive; nothing is rewritten.
        assert!(declared.references().contains(&"nginx:1.27"));
        assert!(
            declared
                .references()
                .contains(&"docker.io/library/nginx:1.27")
        );
        assert!(declared.references().contains(&PRODUCT_REF));

        // The same version at another commit is a different requested build.
        let other =
            VerifyRequest::for_namespaced_package(COMPONENT, VERSION, OTHER_COMMIT, NAMESPACE)
                .expect("a valid request");
        assert!(matches!(
            verify_err(&package, &trust, &other),
            VerifyError::TargetMismatch { .. }
        ));

        // A third-party image carrying its own digest as its outer commit is
        // not the requested build, whatever its provenance says.
        let mut exempt = entries;
        exempt[1] = image_artifact_json_with("images/database.tar", DIGEST_COMMIT, &database);
        assert!(matches!(
            verify_err(&package_of(&pair, &exempt), &trust, &namespaced()),
            VerifyError::TargetMismatch { ref commit, .. } if commit == DIGEST_COMMIT
        ));
    }

    #[test]
    fn each_image_pass_finishes_before_the_next_whatever_the_artifact_order() {
        let pair = keypair();
        let trust = trusting(&pair);
        let hex = CONFIG_C.trim_start_matches("sha256:");

        let mut platform_fault = declaration("platform", &["ghcr.io/example/platform:1"]);
        platform_fault.platform.architecture = ImageArchitecture::Arm64;
        let mut alias_fault = normalized("alias", CONFIG_C, "docker.io/library/postgres");
        alias_fault.public_refs = vec![format!(
            "runtime.invalid/{NAMESPACE}/{COMPONENT}/other:cfg-{hex}"
        )];
        let conflict_first = declaration("one", &["ghcr.io/example/shared:1"]);
        let mut conflict_second = declaration("two", &["ghcr.io/example/shared:1"]);
        conflict_second.config_digest = CONFIG_B.to_string();
        let mut namespace_fault = declaration("namespace", &["ghcr.io/example/namespace:1"]);
        namespace_fault.owner.namespace = "other-product".to_string();
        let mut component_fault = declaration("component", &["ghcr.io/example/component:1"]);
        component_fault.owner.component = "other".to_string();

        let entry = |path: &str, image: &ImageDeclaration| image_artifact_json(path, image);
        // Each pair puts the later category's fault on the earlier artifact.
        let cases: Vec<(Vec<String>, VerifyRequest, ImageCheck)> = vec![
            (
                vec![
                    entry("a.tar", &alias_fault),
                    entry("b.tar", &platform_fault),
                ],
                namespaced(),
                |e| matches!(e, ImageVerifyError::PlatformMismatch { archive_path, .. } if archive_path == "b.tar"),
            ),
            (
                vec![
                    entry("a.tar", &conflict_first),
                    entry("b.tar", &conflict_second),
                    entry("c.tar", &alias_fault),
                ],
                namespaced(),
                |e| matches!(e, ImageVerifyError::NonCanonicalReservedReference { archive_path, .. } if archive_path == "c.tar"),
            ),
            (
                vec![
                    entry("a.tar", &conflict_first),
                    entry("b.tar", &conflict_second),
                ],
                request(),
                |e| matches!(e, ImageVerifyError::ConflictingReference { .. }),
            ),
            (
                vec![
                    entry("a.tar", &conflict_first),
                    entry("b.tar", &namespace_fault),
                ],
                request(),
                |e| matches!(e, ImageVerifyError::MissingNamespace { archive_path } if archive_path == "a.tar"),
            ),
            (
                vec![
                    entry("a.tar", &component_fault),
                    entry("b.tar", &namespace_fault),
                ],
                namespaced(),
                |e| matches!(e, ImageVerifyError::NamespaceMismatch { archive_path, .. } if archive_path == "b.tar"),
            ),
            (
                vec![
                    entry("a.tar", &conflict_first),
                    entry("b.tar", &component_fault),
                ],
                namespaced(),
                |e| matches!(e, ImageVerifyError::OwnerComponentMismatch { archive_path, .. } if archive_path == "b.tar"),
            ),
        ];
        for (index, (entries, request, is_expected)) in cases.into_iter().enumerate() {
            let error = image_refusal(&package_of(&pair, &entries), &trust, &request);
            assert!(is_expected(&error), "case {index}: got {error:?}");
        }
    }

    #[test]
    fn image_semantics_follow_withdrawal_target_and_epoch() {
        let pair = keypair();
        let mut arm = declaration("web", &[PRODUCT_REF]);
        arm.platform.architecture = ImageArchitecture::Arm64;
        let package = package_of(&pair, &[image_artifact_json("images/web.tar", &arm)]);

        let withdrawn = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            vec![(
                COMPONENT.to_string(),
                VERSION.to_string(),
                COMMIT.to_string(),
            )],
            MIN_MANIFEST_FORMAT_VERSION,
            0,
        )
        .expect("a trust set");
        assert!(matches!(
            verify_err(&package, &withdrawn, &namespaced()),
            VerifyError::WithdrawnBuild { .. }
        ));
        let elsewhere = VerifyRequest::for_namespaced_package("other", VERSION, COMMIT, NAMESPACE)
            .expect("a valid request");
        assert!(matches!(
            verify_err(&package, &trusting(&pair), &elsewhere),
            VerifyError::TargetMismatch { .. }
        ));
        assert!(matches!(
            verify_err(&package, &trusting(&pair), &namespaced()),
            VerifyError::Image(ImageVerifyError::PlatformMismatch { .. })
        ));
    }

    #[test]
    fn a_malformed_declaration_loses_to_the_signature_and_the_version() {
        let pair = keypair();
        let malformed = image_artifact_json("images/web.tar", &declaration("web", &[PRODUCT_REF]))
            .replace(r#""schema":1,"#, r#""schema":1,"source_policy":"reuse","#);
        let manifest = manifest_json(
            &[("images/web.tar", len_u64(ARTIFACT_BYTES))],
            std::slice::from_ref(&malformed),
        );

        // Unsigned by anything the trust set holds.
        let stranger = signed_pkg(&keypair(), &manifest, &default_archive(), None);
        assert!(matches!(
            verify_err(&stranger, &trusting(&pair), &namespaced()),
            VerifyError::BadSignature
        ));
        // Below an injected floor.
        let floor = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            Vec::new(),
            MANIFEST_FORMAT_VERSION + 1,
            0,
        )
        .expect("a trust set");
        let signed = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            verify_err(&signed, &floor, &namespaced()),
            VerifyError::UnsupportedManifestFormat { .. }
        ));
        // A future format, whatever the body.
        let future = manifest_json_at(
            MAX_MANIFEST_FORMAT_VERSION + 1,
            &[("images/web.tar", len_u64(ARTIFACT_BYTES))],
            &[malformed],
        );
        let package = signed_pkg(&pair, &future, &default_archive(), None);
        assert!(matches!(
            verify_err(&package, &trusting(&pair), &namespaced()),
            VerifyError::UnsupportedManifestFormat { found, .. } if found == MAX_MANIFEST_FORMAT_VERSION + 1
        ));
        // And otherwise the typed parse names it, nested.
        assert!(matches!(
            verify_err(&signed, &trusting(&pair), &namespaced()),
            VerifyError::Payload(PayloadError::InvalidManifest(
                ManifestError::ImageDecode { .. }
            ))
        ));
    }

    #[test]
    fn typed_parse_faults_keep_their_artifact_order_through_the_verifier() {
        let pair = keypair();
        let trust = trusting(&pair);
        let malformed = image_artifact_json("images/bad.tar", &declaration("web", &[PRODUCT_REF]))
            .replace(
                r#""kind":"product_build","#,
                r#""kind":"product_build","pinned_digest":"x","#,
            );
        let unsafe_path = artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "native-binary",
            "../escape",
            ARTIFACT_SHA256,
        );
        let is_image_decode = |error: &VerifyError| {
            matches!(
                error,
                VerifyError::Payload(PayloadError::InvalidManifest(ManifestError::ImageDecode { archive_path, .. }))
                    if archive_path == "images/bad.tar"
            )
        };

        let error = verify_err(
            &package_of(&pair, &[unsafe_path.clone(), malformed.clone()]),
            &trust,
            &namespaced(),
        );
        assert!(
            matches!(error, VerifyError::UnsafePath(ref p) if p == "../escape"),
            "got: {error:?}"
        );
        let error = verify_err(
            &package_of(&pair, &[malformed.clone(), unsafe_path]),
            &trust,
            &namespaced(),
        );
        assert!(is_image_decode(&error), "got: {error:?}");

        let first = artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "native-binary",
            "bin/p",
            ARTIFACT_SHA256,
        );
        let second = artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "static-assets",
            "bin/p",
            ARTIFACT_SHA256,
        );
        let error = verify_err(
            &package_of(&pair, &[first.clone(), second.clone(), malformed.clone()]),
            &trust,
            &namespaced(),
        );
        assert!(
            matches!(error, VerifyError::DuplicatePath(ref p) if p == "bin/p"),
            "got: {error:?}"
        );
        let error = verify_err(
            &package_of(&pair, &[first.clone(), malformed.clone(), second]),
            &trust,
            &namespaced(),
        );
        assert!(is_image_decode(&error), "got: {error:?}");
        let second_malformed = malformed.replace("images/bad.tar", "bin/p");
        let error = verify_err(
            &package_of(&pair, &[first, second_malformed]),
            &trust,
            &namespaced(),
        );
        assert!(
            matches!(error, VerifyError::DuplicatePath(_)),
            "got: {error:?}"
        );
    }

    #[test]
    fn a_legacy_image_key_is_refused_through_the_verifier_after_earlier_faults() {
        let pair = keypair();
        let trust = trusting(&pair);
        for version in MIN_MANIFEST_FORMAT_VERSION..IMAGE_DECLARATION_FORMAT_VERSION {
            for value in ["null", "{}", r#""malformed""#] {
                let keyed = artifact_json(
                    COMPONENT,
                    VERSION,
                    COMMIT,
                    "container-image",
                    "images/k.tar",
                    ARTIFACT_SHA256,
                )
                .replace(r#""kind":"#, &format!(r#""image":{value},"kind":"#));
                let bad_commit = artifact_json(
                    COMPONENT,
                    VERSION,
                    "abc1234",
                    "native-binary",
                    "bin/c",
                    ARTIFACT_SHA256,
                );

                let error = verify_err(
                    &package_of_at(&pair, version, &[bad_commit.clone(), keyed.clone()]),
                    &trust,
                    &namespaced(),
                );
                assert!(
                    matches!(
                        error,
                        VerifyError::Payload(PayloadError::InvalidManifest(
                            ManifestError::InvalidCommit { .. }
                        ))
                    ),
                    "v{version} {value}: got {error:?}"
                );
                let error = verify_err(
                    &package_of_at(&pair, version, &[keyed.clone(), bad_commit]),
                    &trust,
                    &namespaced(),
                );
                assert!(
                    matches!(
                        error,
                        VerifyError::Payload(PayloadError::InvalidManifest(
                            ManifestError::ImageBeforeDeclarationFormat { format_version, .. }
                        )) if format_version == version
                    ),
                    "v{version} {value}: got {error:?}"
                );
                // The same artifact's own earlier check wins.
                let keyed_bad_commit = keyed.replace(COMMIT, "abc1234");
                let error = verify_err(
                    &package_of_at(&pair, version, &[keyed_bad_commit]),
                    &trust,
                    &namespaced(),
                );
                assert!(
                    matches!(
                        error,
                        VerifyError::Payload(PayloadError::InvalidManifest(
                            ManifestError::InvalidCommit { .. }
                        ))
                    ),
                    "v{version} {value}: got {error:?}"
                );
            }
        }
    }

    #[test]
    fn a_legacy_multi_fault_package_keeps_its_old_verdicts() {
        // A format-5 image package that is withdrawn and requested wrongly
        // reports withdrawal whichever ordinary constructor asks.
        let pair = keypair();
        let legacy = artifact_json(
            COMPONENT,
            VERSION,
            COMMIT,
            "container-image",
            "images/legacy.tar",
            ARTIFACT_SHA256,
        );
        let package = package_of_at(&pair, IMAGE_DECLARATION_FORMAT_VERSION - 1, &[legacy]);
        let withdrawn = TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&pair), false)],
            vec![(
                COMPONENT.to_string(),
                VERSION.to_string(),
                COMMIT.to_string(),
            )],
            MIN_MANIFEST_FORMAT_VERSION,
            0,
        )
        .expect("a trust set");
        let wrong = VerifyRequest::for_package("other", VERSION, COMMIT).expect("ordinary");
        let wrong_namespaced =
            VerifyRequest::for_namespaced_package("other", VERSION, COMMIT, "elsewhere")
                .expect("ordinary");
        for request in [wrong.clone(), wrong_namespaced.clone()] {
            assert!(matches!(
                verify_err(&package, &withdrawn, &request),
                VerifyError::WithdrawnBuild { .. }
            ));
            assert!(matches!(
                verify_err(&package, &trusting(&pair), &request),
                VerifyError::TargetMismatch { .. }
            ));
        }
    }

    #[test]
    fn a_declared_image_package_still_binds_every_member_and_reads_no_archive() {
        let pair = keypair();
        let trust = trusting(&pair);
        let image = image_artifact_json("images/web.tar", &declaration("web", &[PRODUCT_REF]));
        // A member omitted from the bound list is still missing.
        let manifest = manifest_json(
            &[(MEMBER, len_u64(ARTIFACT_BYTES))],
            &[default_artifact(), image.clone()],
        );
        let package = signed_pkg(&pair, &manifest, &default_archive(), None);
        assert!(matches!(
            verify_err(&package, &trust, &namespaced()),
            VerifyError::MissingRequiredMember { member: Some(ref m) } if m == "images/web.tar"
        ));
        // And an accepted declaration says nothing about the archive bytes:
        // an archive that is not even zstd still verifies.
        let manifest = manifest_json(&[("images/web.tar", len_u64(ARTIFACT_BYTES))], &[image]);
        let package = signed_pkg(&pair, &manifest, b"not an archive", None);
        let verified = verify_package(Cursor::new(package), &trust, &namespaced())
            .expect("verification never reads the archive");
        assert!(matches!(
            verified.image_references(),
            ImageReferences::Declared(_)
        ));
    }

    #[test]
    fn a_new_image_error_arrives_under_the_image_arm_and_never_nested() {
        let pair = keypair();
        let mut foreign = declaration("web", &[PRODUCT_REF]);
        foreign.owner.namespace = "other-product".to_string();
        let package = package_of(&pair, &[image_artifact_json("images/web.tar", &foreign)]);
        let error = verify_err(&package, &trusting(&pair), &namespaced());
        assert!(matches!(
            error,
            VerifyError::Image(ImageVerifyError::NamespaceMismatch { .. })
        ));
        assert!(!matches!(error, VerifyError::Payload(_)));
        assert!(error.to_string().contains("other-product"), "got: {error}");
    }

    /// A signed format-6 component package checked in as raw bytes: a compose
    /// bundle and two declared images — a normalized third-party database
    /// under its canonical alias and a product-built web image under its own
    /// tag — for `example-app` 1.0.0 in `example-product`.
    const SIGNED_V6_PACKAGE: &[u8] =
        include_bytes!("../assets/test-fixtures/signed-v6-images/package.pkg");
    /// The raw Ed25519 public key that signed it, in hex. Only this half was
    /// kept: the fixture is test trust and nothing else, and its private key
    /// was discarded once the package was written.
    const SIGNED_V6_PUBLIC_KEY: &str =
        include_str!("../assets/test-fixtures/signed-v6-images/public-key.hex");

    fn signed_v6_trust() -> TrustSet {
        let hex = SIGNED_V6_PUBLIC_KEY.trim();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| {
                u8::from_str_radix(hex.get(at..at + 2).expect("an even-length key"), 16)
                    .expect("hex")
            })
            .collect();
        let key: [u8; 32] = bytes.try_into().expect("a 32-byte key");
        trust_of(vec![TrustAnchor::new(key, false)])
    }

    #[test]
    fn the_checked_in_v6_package_verifies_under_its_namespace_from_its_raw_bytes() {
        let trust = signed_v6_trust();
        let request =
            VerifyRequest::for_namespaced_package("example-app", "1.0.0", COMMIT, NAMESPACE)
                .expect("a valid request");

        // The raw manifest block declares the current format; that is the
        // stage-1 reading an older reader refuses before its body decode.
        let container =
            payload::read_package_container(Cursor::new(SIGNED_V6_PACKAGE), &ENVELOPE_BOUNDS)
                .expect("the fixture is a container");
        assert_eq!(
            crate::manifest::parse_format_version(container.manifest_bytes())
                .expect("a readable version"),
            Some(IMAGE_DECLARATION_FORMAT_VERSION)
        );

        let mut verified = verify_package(Cursor::new(SIGNED_V6_PACKAGE), &trust, &request)
            .expect("the fixture verifies");
        let ImageReferences::Declared(declared) = verified.image_references() else {
            panic!("expected declared references");
        };
        assert_eq!(
            declared.references(),
            vec![
                "ghcr.io/example/example-app:1.0.0",
                "runtime.invalid/example-product/example-app/database:cfg-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ]
        );
        let dependencies: Vec<&str> = declared
            .declarations()
            .map(|(_, image)| image.dependency.as_str())
            .collect();
        assert_eq!(dependencies, vec!["database", "web"]);
        // Every artifact carries the requested build's commit, the dependency
        // image included; the web image's own source commit is provenance.
        assert!(
            verified
                .manifest()
                .artifacts()
                .iter()
                .all(|a| a.commit.as_deref() == Some(COMMIT))
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let extracted = verified
            .extract_to(dir.path())
            .expect("the archive matches its manifest");
        assert_eq!(extracted.len(), 3);

        // Without the namespace its images cannot be checked, so it is refused.
        let plain = VerifyRequest::for_package("example-app", "1.0.0", COMMIT).expect("ordinary");
        assert!(matches!(
            verify_err(SIGNED_V6_PACKAGE, &trust, &plain),
            VerifyError::Image(ImageVerifyError::MissingNamespace { .. })
        ));
        // A floor above it refuses it for its version while its signature is
        // valid — the same stage-1 refusal an older reader makes at its own
        // ceiling.
        let floor = TrustSet::new(
            signed_v6_trust().anchors().to_vec(),
            Vec::new(),
            IMAGE_DECLARATION_FORMAT_VERSION + 1,
            0,
        )
        .expect("a trust set");
        assert!(matches!(
            verify_err(SIGNED_V6_PACKAGE, &floor, &request),
            VerifyError::UnsupportedManifestFormat { found, .. } if found == IMAGE_DECLARATION_FORMAT_VERSION
        ));
    }

    // ---- The statement checks as one unit --------------------------------

    mod statements {
        use super::super::{Statement, check_statements, statement_order};
        use super::{
            ARTIFACT_BYTES, ARTIFACT_SHA256, COMMIT, COMPONENT, Ed25519KeyPair, ImagePlatform,
            MEMBER, TRUST_TARGET, TrustAnchor, TrustSet, VERSION, VerifyError, VerifyRequest,
            artifact_json, declaration, default_artifact, image_artifact_json, keypair, len_u64,
            manifest_json, namespaced, public_key_of, signed_pkg, verify_err,
        };
        use crate::image::ImageArchitecture;
        use crate::manifest::PayloadManifest;
        use crate::payload::FORMAT_VERSION;

        const ALL: [Statement; 6] = [
            Statement::Completeness,
            Statement::Identifiers,
            Statement::Withdrawal,
            Statement::Target,
            Statement::Epoch,
            Statement::Images,
        ];

        fn parse(manifest: &[u8]) -> PayloadManifest {
            PayloadManifest::parse(manifest, FORMAT_VERSION).expect("the fixture parses")
        }

        fn trust(pair: &Ed25519KeyPair, withdrawn: &[(&str, &str, &str)], epoch: u64) -> TrustSet {
            TrustSet::new(
                vec![TrustAnchor::new(public_key_of(pair), false)],
                withdrawn
                    .iter()
                    .map(|(a, b, c)| ((*a).to_string(), (*b).to_string(), (*c).to_string()))
                    .collect(),
                0,
                epoch,
            )
            .expect("a trust set")
        }

        fn manifest_of(entries: &[String]) -> Vec<u8> {
            let paths: Vec<String> = entries
                .iter()
                .enumerate()
                .map(|(at, _)| format!("m{at}"))
                .collect();
            let entries: Vec<String> = entries
                .iter()
                .zip(&paths)
                .map(|(entry, path)| entry.replace(MEMBER, path))
                .collect();
            let members: Vec<(&str, u64)> = paths
                .iter()
                .map(|path| (path.as_str(), len_u64(ARTIFACT_BYTES)))
                .collect();
            manifest_json(&members, &entries)
        }

        fn entry(component: &str, version: &str) -> String {
            artifact_json(
                component,
                version,
                COMMIT,
                "native-binary",
                MEMBER,
                ARTIFACT_SHA256,
            )
        }

        /// An image whose declared architecture is not its artifact's: an
        /// image pass fault.
        fn misdeclared_image() -> String {
            let mut image = declaration("database", &["registry.example/db:1.0"]);
            image.platform = ImagePlatform {
                architecture: ImageArchitecture::Arm64,
                ..image.platform
            };
            image_artifact_json(MEMBER, &image)
        }

        fn same_as_verify_package(
            manifest: &[u8],
            trust: &TrustSet,
            request: &VerifyRequest,
            pair: &Ed25519KeyPair,
        ) -> VerifyError {
            let direct = check_statements(&parse(manifest), request, Some(trust))
                .expect_err("the statements are refused");
            let package = signed_pkg(pair, manifest, &super::default_archive(), None);
            let through = verify_err(&package, trust, request);
            assert_eq!(format!("{direct:?}"), format!("{through:?}"));
            direct
        }

        #[test]
        fn with_a_trust_set_it_is_verify_packages_post_parse_verdict() {
            let pair = keypair();
            let plain = VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("a request");
            let manifest = manifest_of(&[default_artifact()]);
            let (result, order) = statement_order::recorded(|| {
                check_statements(&parse(&manifest), &plain, Some(&trust(&pair, &[], 0)))
            });
            result.expect("the default fixture passes");
            assert_eq!(order, ALL);

            // Identifier before withdrawal.
            let unsafe_version = manifest_of(&[entry(COMPONENT, "-1")]);
            let withdrawn_unsafe = trust(&pair, &[(COMPONENT, "-1", COMMIT)], 0);
            assert!(matches!(
                same_as_verify_package(&unsafe_version, &withdrawn_unsafe, &plain, &pair),
                VerifyError::UnsafeBuildIdentifier { .. }
            ));

            // Withdrawal before target.
            let withdrawn = trust(&pair, &[(COMPONENT, VERSION, COMMIT)], 0);
            let other = VerifyRequest::for_package(COMPONENT, "2.0.0", COMMIT).expect("a request");
            let (error, order) = statement_order::recorded(|| {
                same_as_verify_package(&manifest, &withdrawn, &other, &pair)
            });
            assert!(matches!(error, VerifyError::WithdrawnBuild { .. }));
            assert_eq!(order.get(..3), Some(&ALL[..3]), "stops at withdrawal");

            // Target before epoch, epoch before the image passes.
            let trust_manifest = manifest_of(&[
                entry(TRUST_TARGET, "8"),
                misdeclared_image()
                    .replace(COMPONENT, TRUST_TARGET)
                    .replace(VERSION, "8"),
            ]);
            let active = trust(&pair, &[], 10);
            let mismatch = VerifyRequest::for_trust("9", COMMIT, 5).expect("a request");
            assert!(matches!(
                same_as_verify_package(&trust_manifest, &active, &mismatch, &pair),
                VerifyError::TargetMismatch { .. }
            ));
            let stale = VerifyRequest::for_trust("8", COMMIT, 5).expect("a request");
            let (error, order) = statement_order::recorded(|| {
                same_as_verify_package(&trust_manifest, &active, &stale, &pair)
            });
            assert!(matches!(error, VerifyError::StaleTrustSet { .. }));
            assert_eq!(order.get(..5), Some(&ALL[..5]), "stops at the epoch");
        }

        #[test]
        fn each_check_runs_once_in_order_and_a_failure_stops_the_rest() {
            let pair = keypair();
            let manifest = manifest_of(&[entry(COMPONENT, VERSION)]);
            let other = VerifyRequest::for_package(COMPONENT, "2.0.0", COMMIT).expect("a request");
            let (result, order) = statement_order::recorded(|| {
                check_statements(&parse(&manifest), &other, Some(&trust(&pair, &[], 0)))
            });
            assert!(matches!(result, Err(VerifyError::TargetMismatch { .. })));
            assert_eq!(order, ALL[..4]);
        }

        #[test]
        fn without_a_trust_set_withdrawal_and_the_epoch_are_not_checked() {
            let pair = keypair();
            let manifest = manifest_of(&[entry(TRUST_TARGET, "8")]);
            let withdrawn_and_active = trust(&pair, &[(TRUST_TARGET, "8", COMMIT)], 10);
            let stale = VerifyRequest::for_trust("8", COMMIT, 5).expect("a request");
            // With the trust set both are refused, withdrawal first...
            assert!(matches!(
                check_statements(&parse(&manifest), &stale, Some(&withdrawn_and_active)),
                Err(VerifyError::WithdrawnBuild { .. })
            ));
            // ...and without one neither is checked at all.
            let (result, order) =
                statement_order::recorded(|| check_statements(&parse(&manifest), &stale, None));
            result.expect("nothing trust-dependent is decided");
            assert_eq!(
                order,
                [
                    Statement::Completeness,
                    Statement::Identifiers,
                    Statement::Target,
                    Statement::Images
                ]
            );
        }

        #[test]
        fn without_a_trust_set_the_other_four_keep_their_order() {
            // An unsafe identifier before a target mismatch.
            let manifest = manifest_of(&[entry(COMPONENT, "-1")]);
            let other = VerifyRequest::for_package(COMPONENT, "2.0.0", COMMIT).expect("a request");
            assert!(matches!(
                check_statements(&parse(&manifest), &other, None),
                Err(VerifyError::UnsafeBuildIdentifier { .. })
            ));
            // A target mismatch before an image pass fault.
            let manifest = manifest_of(&[misdeclared_image()]);
            let other = VerifyRequest::for_namespaced_package(
                COMPONENT,
                "2.0.0",
                COMMIT,
                "example-product",
            )
            .expect("a request");
            assert!(matches!(
                check_statements(&parse(&manifest), &other, None),
                Err(VerifyError::TargetMismatch { .. })
            ));
            // And the image pass fault once the target agrees.
            assert!(matches!(
                check_statements(&parse(&manifest), &namespaced(), None),
                Err(VerifyError::Image(_))
            ));
        }
    }
}
