//! The release-trust tree: installing one generation of release-signing trust
//! into it, recording which epoch is active, and turning the active generation
//! back into the value the package verifier takes.
//!
//! [`crate::verify`] takes its trust material as a caller-injected value and
//! reads nothing from disk, and [`crate::trust_set`] states what one generation
//! of that material is on the wire without opening a file. This module is the
//! filesystem half between them: `<etc>/release-trust/` — a **sibling** of the
//! mTLS tree, never inside it, sharing no directory, no generation index and no
//! `active` link with it — holding `active` and a series of `gen-<n>/`.
//!
//! Every entry point here takes that tree root as a path, which a caller resolves
//! through [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir);
//! `active` and each `gen-<n>/` under it resolve through the generation engine's
//! accessors, which are what
//! [`Layout::release_trust_active_dir`](crate::layout::Layout::release_trust_active_dir)
//! and
//! [`Layout::release_trust_generation_dir`](crate::layout::Layout::release_trust_generation_dir)
//! spell for an external caller. Nothing here joins a path literal for the tree,
//! its link or a generation; the only names this module spells are the three
//! material files'.
//!
//! # A generation is three files
//!
//! A generation directory holds exactly these, staged in this order and nothing
//! else:
//!
//! 1. `generation.pkg` — the delivered container verbatim, the
//!    authenticity carrier any re-verification reads;
//! 2. `trust-set.json` — the verified member bytes copied out byte for byte,
//!    so a reader that already trusts the active generation need not re-open the
//!    container;
//! 3. `epoch` — the activated epoch.
//!
//! Nothing reloads on a swap — consumers read the tree at the moment they
//! verify — so the tree is driven with `reload_unit: None`.
//!
//! **`gen-<n>` is not the `epoch`.** `n` is the generation engine's local
//! directory index, allocated from what is already on disk; `epoch` is the
//! global release-ops sequence carried inside the signed document. A host seeded
//! at release epoch 4711 has `gen-1/`. Conflating the two would break the
//! engine's pruning arithmetic.
//!
//! # The epoch is part of the generation, not per-tree state
//!
//! The record is the third material file, so it is written into `gen-<n>.tmp`,
//! finalised by the same `rename` and made live by the same `active` swap as the
//! document beside it. There is no window in which the tree is activated and the
//! record is not, and no way for the record to disagree with the
//! `trust-set.json` it was finalised with.
//!
//! A mutable `<etc>/release-trust/active-epoch` rewritten after each swap would
//! carry exactly that window: a crash between the swap and the rewrite leaves a
//! record naming the *previous* epoch, and the verifier's strictly-greater test
//! against that record would then admit a generation older than the one actually
//! active. The record is also deliberately not obtained by parsing
//! `trust-set.json`: it is a floor's foundation and has to keep working across a
//! `trust_set_version` bump, and one integer is readable without the document
//! schema.
//!
//! # Two install-time doors, one installer
//!
//! `install_generation` applies no admission policy whatsoever: it takes bytes
//! a caller has already verified and puts them into the tree atomically.
//! Exported, it would be an unconditional way to overwrite a host's active trust
//! set with anything at all — restoring a revoked `key_id`, dropping a withdrawn
//! build — reaching around the tree-state gate the install-time admission paths
//! exist to impose. So it and the `epoch` writer stay crate-internal, and every
//! generation reaches the tree through an entry point built on top of it.
//!
//! Two of those are install-time and land here: [`admit_seed_generation`], which
//! refuses a tree that already carries an active generation, and
//! [`replace_generation`], which is the same sequence **minus that one gate** and
//! exists so an operator can re-provision a host wedged by a generation minted at
//! a wrongly-high `epoch`. Neither applies an epoch floor, because neither needs
//! an existing trust set; what keeps that safe is the seed's precondition on tree
//! state, and the fact that the replace door is a separately named symbol reached
//! only from an operator-mediated installer.
//!
//! The runtime delivery channel — the one that *does* apply the epoch floor and
//! the chain rules — is neither of these. It exports its own, separately named
//! entry points, and reaches this tree through this same installer rather than
//! around it: [`accept_generation`] for one delivered generation,
//! [`accept_generation_chain`] for the ordered replay that catches a lagging host
//! up, and [`read_generation_state`] for the question a caller asks before it
//! pushes.
//!
//! # The two self-admitting doors the chain cannot serve
//!
//! An accept judges a delivered generation against the **active** one's key set,
//! and two situations have no such key set to judge against: a host offline
//! across more rotations than the control plane retains, whose intermediate keys
//! have been pruned, and a host the installer never touched. Both are admitted
//! under the anchors the delivered document itself carries — the same
//! cryptographic act the installer's seed performs, reached over a different
//! channel — through [`rebootstrap_generation`] and
//! [`bootstrap_from_join_material`]. Each relaxes the signature-chain check and
//! **only** that: re-bootstrap still applies a monotonic floor against the
//! verified epoch and reads the `require-trust-pin` marker, and the bootstrap
//! still runs the seed's tree-state gate over a generation it reads from the
//! operator-mediated join-material location rather than from its caller. Every
//! tree state is served by exactly one of the two, so neither is reachable from
//! the ordinary route by a flag.
//!
//! # Two notions of "the active generation", kept apart on purpose
//!
//! [`read_active_epoch`] and the reader behind [`active_trust_set`] ask only "is
//! anything resolvable at `active`", through one `metadata` call that **follows**
//! the link. An absent link and a dangling one are alike no generation; a real
//! directory at `active`, or a symlink to a non-canonical name, over well-formed
//! files is a success. That is the right question for "may I seed".
//!
//! The runtime paths additionally ask the generation engine's question — a
//! `read_link` on `active` with its target through the engine's own canonical
//! `gen-<n>` predicate — because "which generation am I on" is what a delivered
//! generation is compared against and what an unchanged result has to report.
//! The two disagree on exactly the trees whose `active` is not a canonical
//! symlink, and neither is wrong. They are separate functions so they cannot
//! drift back together.

use std::borrow::Cow;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::generation::{
    GenerationError, GenerationFile, GenerationTree, activate_generation, active_link,
    parse_generation,
};
use crate::layout::{JOIN_GENERATION_FILE, REQUIRE_TRUST_PIN_MARKER};
use crate::payload;
use crate::roxyd_trust::Activation;
use crate::trust_set::{
    TRUST_SET_MEMBER, TrustSetDocument, TrustSetDocumentError, document_anchors, member_digest,
    provisional_anchors_and_epoch, read_trust_set_document, self_admission_candidate,
};
use crate::verify::{InputError, TrustSet, VerifyError, VerifyRequest, verify_package};

/// Basename of the delivered container inside a generation directory, kept
/// verbatim so the generation carries its own authenticity carrier.
pub(crate) const GENERATION_PACKAGE_FILE: &str = "generation.pkg";

/// Basename of the activated epoch's record inside a generation directory.
pub(crate) const EPOCH_RECORD_FILE: &str = "epoch";

/// A failure to install, read or interpret a release-trust generation.
///
/// The trust-set reader's own taxonomy arrives by `#[from]` rather than
/// flattened into a generic "malformed document" variant, so a caller learns
/// *which* fault the active generation has and this module defines no second
/// copy of that variant list to drift from it.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseTrustError {
    /// A file could not be read or written, or a directory operation failed.
    ///
    /// This is where the tree gets named. The filesystem half of an activation
    /// is the shared crate-internal generation engine's, which reports for every
    /// root-owned trust tree and so names none of them; each caller's bridge
    /// attaches its own.
    #[error("release-trust i/o error at {path}: {source}")]
    Io {
        /// The path the operation targeted.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The document the active generation holds is malformed, as the refusing
    /// reader names it.
    #[error("the active trust generation document was refused")]
    Document(#[from] TrustSetDocumentError),

    /// The container being installed, or the one the active generation already
    /// holds, did not verify.
    #[error("the trust generation container was refused")]
    Verify(#[from] VerifyError),

    /// A verifier input built out of a generation was itself refused — two
    /// anchors sharing a public key, say.
    #[error("a verifier input built from a trust generation was refused")]
    Input(#[from] InputError),

    /// The seed door refused: the tree already carries an active generation.
    ///
    /// A precondition on the tree's *state*, never a comparison of epochs, so a
    /// delivered generation is refused here whether its `epoch` is below, equal
    /// to or above the recorded one, and a malformed or absent `epoch` record
    /// does not change the answer. Seeding a host that has already been seeded is
    /// asked about with [`read_active_epoch`], which returns `None` for exactly
    /// the tree states this refusal does not cover;
    /// [`replace_generation`] is the door for a tree that is deliberately being
    /// re-provisioned.
    #[error("the release-trust tree already carries an active generation")]
    ActiveGenerationPresent {
        /// The active generation's directory index, or `None` when `active`
        /// resolves to something that is not a canonical `gen-<n>` directory.
        ///
        /// `None` means the tree holds something this crate did not put there,
        /// which is a stronger reason to keep the seed door shut rather than a
        /// weaker one: failing to name an index never becomes failing to refuse.
        generation: Option<u64>,
    },

    /// The delivered container carries no trust-set document to admit.
    ///
    /// The container's own walk succeeded — it is internally consistent and its
    /// members hashed as its manifest binds them — but no member of it is named
    /// `trust-set.json`, so there is nothing an admission could be about. Every
    /// other container-layer fault is [`ReleaseTrustError::Verify`] instead.
    #[error("the delivered trust generation container carries no `{TRUST_SET_MEMBER}` member")]
    MissingTrustSetMember,

    /// The staged document did not survive the pre-verification decode, so no
    /// candidate trust set could be built to verify the container under.
    ///
    /// A refusal of the *admission attempt* and never a
    /// [`ReleaseTrustError::Document`]: at this point in the sequence nothing has
    /// vouched for the bytes, and dressing an unauthenticated parse up as a
    /// verdict about a real generation is what that separation exists to prevent.
    #[error("the staged trust generation document did not decode before verification")]
    ProvisionalDecode,

    /// An anchor of an otherwise well-formed document did not yield 32 key
    /// bytes.
    ///
    /// The refusing reader's own checks make this unreachable through
    /// `read_trust_set_document`; it is refused rather than unwrapped.
    #[error("an anchor of the active trust generation document does not decode to 32 key bytes")]
    MalformedAnchorKey,

    /// The tree holds no generation at all, so there is nothing to build a trust
    /// set from.
    ///
    /// Distinct from every malformed-record refusal: an absent or dangling
    /// `active` is a legitimate tree state, meaning nothing has been installed
    /// yet.
    #[error("the release-trust tree holds no active generation")]
    NoActiveGeneration,

    /// `active` resolves to a generation that carries no `epoch` record.
    #[error("the active trust generation carries no `{EPOCH_RECORD_FILE}` record")]
    MissingEpochRecord,

    /// The `epoch` record carries no digits: it is empty, or it holds nothing
    /// but its terminator.
    #[error("the active `{EPOCH_RECORD_FILE}` record carries no digits")]
    EmptyEpochRecord,

    /// The `epoch` record is not terminated by the single `\n` the grammar
    /// requires.
    #[error("the active `{EPOCH_RECORD_FILE}` record is not terminated by a newline")]
    UnterminatedEpochRecord,

    /// The `epoch` record carries bytes after its terminating newline.
    #[error("the active `{EPOCH_RECORD_FILE}` record carries a second line")]
    EpochRecordSecondLine,

    /// The `epoch` record's digit run carries ASCII whitespace — a trailing
    /// space, say.
    #[error("the active `{EPOCH_RECORD_FILE}` record carries whitespace")]
    EpochRecordWhitespace,

    /// The `epoch` record's digit run carries a byte that is neither a digit nor
    /// whitespace: a sign, a letter, anything.
    #[error("the active `{EPOCH_RECORD_FILE}` record carries the non-digit byte {byte:#04x}")]
    EpochRecordNonDigit {
        /// The offending byte.
        byte: u8,
    },

    /// The `epoch` record's digits carry a leading zero, which the grammar does
    /// not admit.
    #[error("the active `{EPOCH_RECORD_FILE}` record carries a leading zero")]
    EpochRecordLeadingZero,

    /// The `epoch` record spells out `0`.
    ///
    /// Its own variant, distinct from the no-prior-generation state and from
    /// every other malformed-record refusal: `0` is not a low epoch, it is the
    /// absence of an allocated sequence number, so a file that exists and holds
    /// it is a malformed record of a generation that *has* been installed. It is
    /// also the most dangerous member of this grammar's faults — the verifier
    /// admits a delivered generation strictly greater than the active one, so an
    /// active epoch read as `0` would be a floor under every generation ever
    /// minted.
    #[error("the active `{EPOCH_RECORD_FILE}` record spells out `0`, which is not an epoch")]
    ZeroActiveEpoch,

    /// The `epoch` record's digits do not fit a `u64`.
    #[error("the active `{EPOCH_RECORD_FILE}` record does not fit an unsigned 64-bit integer")]
    EpochRecordOverflow,

    /// The `epoch` record and the `trust-set.json` beside it name different
    /// epochs.
    ///
    /// Refused rather than resolved in either direction: the installer makes
    /// their agreement an invariant of every generation it finalises, so a
    /// violation means the tree was edited underneath it.
    #[error(
        "the trust generation's `{EPOCH_RECORD_FILE}` record names epoch {record} and its document names {document}"
    )]
    EpochDisagreement {
        /// The epoch the record names.
        record: u64,
        /// The epoch the document names.
        document: u64,
    },

    /// `active` is a link this crate did not write: its target is not a
    /// canonical `gen-<n>`.
    ///
    /// Raised by the runtime paths alone, which resolve the index with the
    /// generation engine's own pair — a `read_link` and
    /// `generation::parse_generation` — so they and the engine cannot disagree
    /// about which trees they own. It is a refusal and never the empty-tree
    /// state: a tree holding something this crate did not put there is not a
    /// tree a control-plane push may install over. Putting it right is an
    /// operator's job through the install-time paths.
    #[error(
        "the release-trust tree's `active` names `{target}`, which is not a canonical generation"
    )]
    ActiveNotCanonical {
        /// The link target, as it reads on disk.
        target: String,
    },

    /// The delivered generation states its epoch twice under the signature and
    /// the two carriers disagree.
    ///
    /// The document's own `epoch` field is authoritative; the manifest artifact
    /// entry's `version` is the second carrier, kept as the decimal string it
    /// is so a non-numeric one is reportable. Both are covered by the
    /// signature, so a disagreement is a producer bug or a crafted container.
    ///
    /// Distinct from [`ReleaseTrustError::EpochDisagreement`], which is about
    /// the *tree*: that one compares a generation already on disk against its
    /// own `epoch` record.
    #[error(
        "the delivered trust generation's document names epoch {document} and its manifest names `{manifest}`"
    )]
    DeliveredEpochDisagreement {
        /// The epoch the document's `epoch` field names.
        document: u64,
        /// The epoch the manifest artifact entry's `version` names, verbatim.
        manifest: String,
    },

    /// A re-bootstrap asserted a last-confirmed epoch the tree does not record.
    ///
    /// The caller named the host it believed it was re-bootstrapping and named it
    /// wrongly: a mis-targeted call, or one from a batch prepared before the host
    /// moved on. Refused rather than resolved in either direction — this path
    /// supersedes a host's whole trust history, and a caller that cannot say where
    /// that history stands is not a caller to do it on behalf of.
    #[error(
        "the re-bootstrap asserts last-confirmed epoch {asserted} and the tree records {recorded}"
    )]
    RebootstrapEpochMismatch {
        /// The epoch [`RebootstrapAuthorization`] carries.
        asserted: u64,
        /// The epoch the tree's active generation records.
        recorded: u64,
    },

    /// The host demands an out-of-band fingerprint pin and the re-bootstrap
    /// carried none.
    ///
    /// The host-side [`REQUIRE_TRUST_PIN_MARKER`] is present, which is the
    /// deployment saying that a path relaxing the signature chain must be pinned
    /// out of band. Deliberately distinct from
    /// [`ReleaseTrustError::FingerprintPinMismatch`]: "this host requires a pin
    /// and you supplied none" and "the pin you supplied does not match" send an
    /// operator to different places.
    #[error("the host requires an out-of-band fingerprint pin and none was supplied")]
    FingerprintPinRequired,

    /// The supplied fingerprint pin is not the delivered document's digest.
    ///
    /// Both values are public digests the signed manifest already carries as its
    /// `commit`, never key material, so naming them is what makes the refusal
    /// actionable.
    #[error("the supplied fingerprint pin `{pin}` is not the delivered document's digest {digest}")]
    FingerprintPinMismatch {
        /// The pin the caller supplied, verbatim.
        pin: String,
        /// The lowercase-hex SHA-256 of the delivered document member.
        digest: String,
    },

    /// A re-bootstrap delivered a generation that is not strictly newer than the
    /// one the tree records.
    ///
    /// This path's **own** floor, and the reason it has a variant rather than
    /// reusing [`VerifyError::StaleTrustSet`]: the self-admission request form
    /// carries no delivered epoch, so the verifier's strictly-greater comparison
    /// returns before it compares anything, and the epoch this names is the
    /// verified document's rather than a provisionally-decoded one.
    #[error(
        "the re-bootstrap delivers epoch {delivered}, which is not above the recorded {recorded}"
    )]
    StaleRebootstrap {
        /// The verified epoch the delivered document carries.
        delivered: u64,
        /// The epoch the tree's active generation records.
        recorded: u64,
    },
}

impl ReleaseTrustError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        ReleaseTrustError::Io {
            path: path.to_string_lossy().into_owned(),
            source,
        }
    }
}

/// What [`ReleaseTrustError::Io`]'s `path` names for a fault of the material set
/// as a whole, which targets no one path.
const MATERIAL_SET_TARGET: &str = "<material set>";

/// Bridges the generation engine's faults onto this tree's taxonomy, on the same
/// terms as the mTLS tree's bridge: the engine reports for every trust tree and
/// no tree widens another's error type.
///
/// The three material-set refusals are unreachable through
/// `install_generation`, which always passes exactly three distinct
/// single-component names, and need a mapping only because this impl must be
/// total. `GenerationError::Reload` is unreachable too: this tree supplies no
/// unit to reload.
//
// The two names above are crate-private, so they are code spans rather than
// intra-doc links: this impl is on a public type, and a public doc linking to a
// private item is `rustdoc::private_intra_doc_links`.
impl From<GenerationError> for ReleaseTrustError {
    fn from(err: GenerationError) -> Self {
        let invalid = |path: String, message: &str| ReleaseTrustError::Io {
            path,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, message.to_string()),
        };
        match err {
            GenerationError::Io { path, source } => ReleaseTrustError::Io { path, source },
            GenerationError::EmptyMaterial => {
                invalid(MATERIAL_SET_TARGET.to_string(), "the material set is empty")
            }
            GenerationError::DuplicateName(name) => ReleaseTrustError::Io {
                path: name.to_string_lossy().into_owned(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "two material files carry the same name",
                ),
            },
            GenerationError::InvalidName(name) => invalid(
                name.to_string_lossy().into_owned(),
                "a material file name is not a single path component",
            ),
            GenerationError::Reload { unit, reason } => invalid(
                unit,
                &format!(
                    "the release-trust tree reloads no unit, yet a reload was attempted: {reason}"
                ),
            ),
        }
    }
}

/// Renders the `epoch` record of a generation: the epoch's ASCII decimal digits
/// followed by exactly one `\n` and nothing else.
///
/// `u64`'s own rendering emits no sign, no leading zero and no padding, so the
/// grammar [`read_active_epoch`] parses is the grammar this writes by
/// construction. It cannot produce `0\n` in practice either, because it records
/// the epoch of a document that has already passed
/// [`read_trust_set_document`], which refuses `0` — and where a caller passes it
/// anyway, the installer's own validator refuses the staged record before
/// anything is finalised.
fn render_epoch_record(epoch: u64) -> Vec<u8> {
    format!("{epoch}\n").into_bytes()
}

/// The three material files of one generation, in the order they are staged.
fn material(package: &[u8], member: &[u8], epoch: u64) -> [GenerationFile; 3] {
    [
        GenerationFile::new(GENERATION_PACKAGE_FILE, package.to_vec()),
        GenerationFile::new(TRUST_SET_MEMBER, member.to_vec()),
        GenerationFile::new(EPOCH_RECORD_FILE, render_epoch_record(epoch)),
    ]
}

/// Installs one generation into the release-trust tree rooted at `root`,
/// atomically.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves.
///
/// `package` is the delivered container's bytes verbatim, `member` the
/// `trust-set.json` bytes the caller has already verified, and `epoch` that
/// verified document's own epoch. The three become the generation's three
/// material files, in the order this module's documentation states, through the
/// crate's one generation engine.
///
/// **It decides nothing about whether the delivered generation should be
/// installed.** There is no tree-state precondition here, no epoch comparison
/// against whatever is already active, and no floor: this takes bytes a caller
/// has already verified and puts them into the tree. Deciding what it may be
/// given belongs to the admission paths built on top of it, which is why this is
/// crate-internal: [`admit_seed_generation`] and [`replace_generation`] are the
/// only install-time ways to reach it, and a later runtime channel will export
/// its own entry point through it rather than around it.
///
/// What it *does* re-establish is that the copy on disk is the copy that was
/// verified. Before anything live is repointed, the validator runs the same
/// self-admission sequence an admission path runs, over the bytes read back from
/// `gen-<n>.tmp`: the pre-verification decode of the staged member, the candidate
/// trust set [`self_admission_candidate`] fixes argument for argument, a
/// self-admission request whose `commit` is the digest of the staged member's own
/// bytes, [`verify_package`] over the re-opened staged container, and only then
/// the refusing reader and the staged `epoch` record. One extra Ed25519
/// verification is a negligible price for closing the same TOCTOU the mTLS
/// validator closes.
///
/// # Errors
///
/// Returns [`ReleaseTrustError`] on any I/O fault, on a validator refusal, or on
/// a material set the engine will not write. Every failure before the `active`
/// swap is fail-closed — `gen-<n>.tmp` is removed and `active` resolves to
/// exactly what it resolved to before the call — and an I/O fault while pruning
/// after the swap returns `Err` with the new generation already live; see
/// `activate_generation`.
pub(crate) fn install_generation(
    root: &Path,
    package: &[u8],
    member: &[u8],
    epoch: u64,
) -> Result<Activation, ReleaseTrustError> {
    let material = material(package, member, epoch);
    let tree = GenerationTree {
        root,
        // Nothing reloads on a trust-set swap: consumers read the tree at the
        // moment they verify.
        reload_unit: None,
    };
    activate_generation(&tree, &material, validate_staged)
}

/// Re-establishes the whole self-check over the copied bytes in `dir`.
///
/// The steps are the admission path's own, in its order, and the candidate trust
/// set is the admission path's too — deliberately not a stronger one. Honouring
/// the staged document's `withdrawn_builds` or its declared
/// `min_manifest_format_version` here would make installation stricter than
/// admission: both bite only in the self-referential case, so the install would
/// fail inside this validator on bytes the verifier had already admitted, and an
/// operator could not tell that from a tree edited underneath the installer.
/// Those two fields govern every *later* package and take effect through
/// [`active_trust_set`].
fn validate_staged(dir: &Path, copied: &[GenerationFile]) -> Result<(), ReleaseTrustError> {
    let [_package, member, record] = copied else {
        // The engine reads back exactly the files it was handed, and what it was
        // handed is `material`'s triple, so this arm is unreachable. Fail closed
        // rather than index into the slice blindly.
        return Err(ReleaseTrustError::Io {
            path: dir.to_string_lossy().into_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the staged copy is not a container/document/epoch triple",
            ),
        });
    };

    // 1-3. The pre-verification decode over the staged member, the candidate set
    //      it fixes, and the self-admission request whose `commit` is a digest
    //      taken from the copied file. That digest is what establishes that the
    //      copied `trust-set.json` and the container's member are the same bytes
    //      rather than merely both present: the manifest's own signed `commit` is
    //      what it is compared against.
    let (trust, staged_epoch) =
        self_admission_candidate(&member.bytes).ok_or(ReleaseTrustError::ProvisionalDecode)?;
    let request = VerifyRequest::for_trust_self_admission(
        &staged_epoch.to_string(),
        &member_digest(&member.bytes),
    )?;

    // 4. Re-open the staged container and verify it under that set and request.
    let package_path = dir.join(GENERATION_PACKAGE_FILE);
    let staged_package =
        std::fs::File::open(&package_path).map_err(|e| ReleaseTrustError::io(&package_path, e))?;
    verify_package(staged_package, &trust, &request)?;

    // 5. Only now is the document parsed for real, and the staged record checked
    //    against that parse. The `epoch` file is covered by nothing above it: the
    //    self-admission request carries no delivered epoch, so the verifier's
    //    epoch comparison returns early and never reads it.
    let document = read_trust_set_document(&member.bytes)?;
    check_epoch_agreement(parse_epoch_record(&record.bytes)?, &document)
}

/// Refuses a generation whose `epoch` record and document name different epochs.
fn check_epoch_agreement(
    record: u64,
    document: &TrustSetDocument,
) -> Result<(), ReleaseTrustError> {
    if record == document.epoch {
        return Ok(());
    }
    Err(ReleaseTrustError::EpochDisagreement {
        record,
        document: document.epoch,
    })
}

/// The `epoch` record of the generation `active` resolves to.
fn active_epoch_record(root: &Path) -> PathBuf {
    active_link(root).join(EPOCH_RECORD_FILE)
}

/// The `trust-set.json` of the generation `active` resolves to.
fn active_document(root: &Path) -> PathBuf {
    active_link(root).join(TRUST_SET_MEMBER)
}

/// The delivered container of the generation `active` resolves to.
fn active_package(root: &Path) -> PathBuf {
    active_link(root).join(GENERATION_PACKAGE_FILE)
}

/// The host-side pin marker at the root of the tree.
///
/// The root-based resolution of [`REQUIRE_TRUST_PIN_MARKER`], for the entry
/// points here, which are handed the already-resolved tree root and so cannot
/// call the namespace-based
/// [`Layout::require_pin_marker`](crate::layout::Layout::require_pin_marker). The
/// basename is spelled in that constant alone; this joins it, exactly as
/// [`active_document`] joins its own.
fn require_pin_marker(root: &Path) -> PathBuf {
    root.join(REQUIRE_TRUST_PIN_MARKER)
}

/// The operator-delivered join generation at the root of the tree.
///
/// The root-based resolution of [`JOIN_GENERATION_FILE`], on the same terms as
/// [`require_pin_marker`].
fn join_generation_file(root: &Path) -> PathBuf {
    root.join(JOIN_GENERATION_FILE)
}

/// Returns the epoch the release-trust tree at `root` currently has active, or
/// `None` when no generation has been installed yet.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves.
///
/// `None` is the tree state, not a number: an absent or dangling `active` means
/// nothing has been installed, and this **never** stands that in for `0`. A
/// caller that read "no record" as "epoch 0" would silently invent a floor under
/// every generation ever minted, since the verifier admits a delivered
/// generation strictly greater than the active one. There is no input at all for
/// which this yields `Some(0)` — neither a missing record nor a file that spells
/// one out.
///
/// The record is read at `<root>/active/epoch` and is one integer, deliberately
/// not a field of the document beside it: a floor's foundation has to keep
/// working across a `trust_set_version` bump.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::Io`] when the record cannot be read,
/// [`ReleaseTrustError::MissingEpochRecord`] when `active` resolves to a
/// generation that holds none, and one named refusal per grammar fault
/// otherwise: [`ReleaseTrustError::ZeroActiveEpoch`],
/// [`ReleaseTrustError::EmptyEpochRecord`],
/// [`ReleaseTrustError::EpochRecordLeadingZero`],
/// [`ReleaseTrustError::EpochRecordWhitespace`],
/// [`ReleaseTrustError::EpochRecordNonDigit`],
/// [`ReleaseTrustError::UnterminatedEpochRecord`],
/// [`ReleaseTrustError::EpochRecordSecondLine`] and
/// [`ReleaseTrustError::EpochRecordOverflow`].
pub fn read_active_epoch(root: &Path) -> Result<Option<u64>, ReleaseTrustError> {
    let active = active_link(root);
    // One stat covers both legitimate no-generation states: this one follows the
    // link, so an `active` that is not there at all and one that is there but
    // resolves to nothing are alike `NotFound`.
    match std::fs::metadata(&active) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ReleaseTrustError::io(&active, e)),
    }

    let path = active_epoch_record(root);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        // `active` resolves, so this is a generation missing a material file
        // rather than a tree with no generation.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReleaseTrustError::MissingEpochRecord);
        }
        Err(e) => return Err(ReleaseTrustError::io(&path, e)),
    };
    parse_epoch_record(&bytes).map(Some)
}

/// Parses the `epoch` record's exact grammar: a non-zero epoch's ASCII decimal
/// digits, then exactly one `\n`, and nothing else.
///
/// Every departure is its own refusal. `0` is excluded explicitly rather than
/// left to a caller to notice: the digit grammar on its own would admit `0\n`,
/// and `1\n` is the smallest legal file.
fn parse_epoch_record(bytes: &[u8]) -> Result<u64, ReleaseTrustError> {
    let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') else {
        return Err(if bytes.is_empty() {
            ReleaseTrustError::EmptyEpochRecord
        } else {
            ReleaseTrustError::UnterminatedEpochRecord
        });
    };
    let (digits, terminator) = bytes.split_at(newline);
    if terminator.len() != 1 {
        return Err(ReleaseTrustError::EpochRecordSecondLine);
    }
    if digits.is_empty() {
        return Err(ReleaseTrustError::EmptyEpochRecord);
    }
    for byte in digits {
        if !byte.is_ascii_digit() {
            return Err(if byte.is_ascii_whitespace() {
                ReleaseTrustError::EpochRecordWhitespace
            } else {
                ReleaseTrustError::EpochRecordNonDigit { byte: *byte }
            });
        }
    }
    if digits == b"0".as_slice() {
        return Err(ReleaseTrustError::ZeroActiveEpoch);
    }
    if digits.first() == Some(&b'0') {
        return Err(ReleaseTrustError::EpochRecordLeadingZero);
    }
    let digits = std::str::from_utf8(digits)
        .expect("every byte was just checked to be an ASCII digit, which is UTF-8");
    digits
        .parse::<u64>()
        .map_err(|_| ReleaseTrustError::EpochRecordOverflow)
}

/// Turns the release-trust tree's active generation into the injected
/// [`TrustSet`] the package verifier takes: the anchors with their revoked flags
/// and public keys, the withdrawn list, the manifest-version floor, and the
/// active epoch.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves.
///
/// The crate's one constructor of that value from a tree, so no consumer
/// assembles it by hand and no two consumers assemble it differently. It reads
/// `active/trust-set.json` through the refusing reader and the epoch from
/// `active/epoch`, and **refuses when the two disagree** rather than preferring
/// one: the installer makes their agreement an invariant of every generation it
/// finalises, so a violation means the tree was edited underneath it.
///
/// Unlike the installer's candidate set, this honours the document in full — its
/// `withdrawn_builds` and its declared `min_manifest_format_version` are exactly
/// what governs every later package, and this is where they take effect.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::NoActiveGeneration`] when nothing has been
/// installed yet, [`ReleaseTrustError::Document`] carrying the refusing reader's
/// own named refusal when `active/trust-set.json` is malformed,
/// [`ReleaseTrustError::EpochDisagreement`] when the record and the document
/// disagree, whichever grammar refusal [`read_active_epoch`] raises for a
/// malformed record, and [`ReleaseTrustError::Io`] when either file cannot be
/// read.
pub fn active_trust_set(root: &Path) -> Result<TrustSet, ReleaseTrustError> {
    Ok(read_active_generation(root)?.trust)
}

/// Everything the active generation's two material reads yield, held together
/// so nothing re-reads them.
///
/// [`active_trust_set`] wants the [`TrustSet`] alone; the runtime accept path
/// wants the document and the epoch as well, to answer a byte-identical
/// redelivery from the copy that was verified when it was admitted rather than
/// from the delivered bytes.
struct ActiveGenerationMaterial {
    /// The active generation's document, as the refusing reader parsed it.
    document: TrustSetDocument,
    /// The epoch the `epoch` record names, which the document agrees with.
    epoch: u64,
    /// The verifier's injected trust set, assembled from the two.
    trust: TrustSet,
}

/// Reads the active generation's `trust-set.json` and `epoch` **once** and
/// yields the verified document, the epoch and the assembled [`TrustSet`].
///
/// This is the **following-stat** reader: it asks only "is anything resolvable
/// at `active`" — through [`read_active_epoch`], whose one `metadata` call
/// follows the link — and it calls no `read_link`. So an absent `active` and a
/// dangling one are alike [`ReleaseTrustError::NoActiveGeneration`], while a
/// real directory at `active`, or a symlink to a target that is not a canonical
/// `gen-<n>`, is a *success* over well-formed files. That is deliberately not
/// the generation engine's question, and tightening it here would change what
/// the seed and install-time paths accept; the runtime paths ask the engine's
/// question separately, through [`active_generation_index`].
///
/// # Errors
///
/// Returns exactly what [`active_trust_set`] documents, which is this reader's
/// own surface: [`ReleaseTrustError::NoActiveGeneration`],
/// [`ReleaseTrustError::Document`], [`ReleaseTrustError::EpochDisagreement`],
/// whichever grammar refusal [`read_active_epoch`] raises for a malformed
/// record, [`ReleaseTrustError::MalformedAnchorKey`],
/// [`ReleaseTrustError::Input`] and [`ReleaseTrustError::Io`].
fn read_active_generation(root: &Path) -> Result<ActiveGenerationMaterial, ReleaseTrustError> {
    let epoch = read_active_epoch(root)?.ok_or(ReleaseTrustError::NoActiveGeneration)?;

    let path = active_document(root);
    let member = std::fs::read(&path).map_err(|e| ReleaseTrustError::io(&path, e))?;
    let document = read_trust_set_document(&member)?;
    check_epoch_agreement(epoch, &document)?;

    let anchors = document_anchors(&document).ok_or(ReleaseTrustError::MalformedAnchorKey)?;
    let withdrawn = document
        .withdrawn_builds
        .iter()
        .map(|build| {
            (
                build.package_id.clone(),
                build.version.clone(),
                build.commit.clone(),
            )
        })
        .collect();
    let trust = TrustSet::new(
        anchors,
        withdrawn,
        document.min_manifest_format_version,
        epoch,
    )?;
    Ok(ActiveGenerationMaterial {
        document,
        epoch,
        trust,
    })
}

/// Resolves the canonical generation index `active` names, with the generation
/// engine's own pair: a `read_link` on `active`, its target through
/// [`parse_generation`].
///
/// A **runtime-only** probe, called by [`accept_generation`],
/// [`read_generation_state`] and each step of [`accept_generation_chain`] and by
/// nothing else. It is spelled the engine's way rather than a second way so the
/// runtime paths and the engine cannot disagree about which trees they own, and
/// it is a separate function from [`read_active_generation`] because the two
/// answer different questions and disagree on real trees.
///
/// Its four outcomes, two of them successful:
///
/// - the target parses as a canonical `gen-<n>` — `Ok(Some(n))`;
/// - `read_link` fails with `NotFound` — `Ok(None)`, the absent link, kept as an
///   outcome rather than raised as a refusal because the callers answer
///   differently about an empty tree: the accept path converts it into
///   [`ReleaseTrustError::NoActiveGeneration`] and the state query reports it;
/// - the target does not parse — [`ReleaseTrustError::ActiveNotCanonical`];
/// - `read_link` fails any other way, which is what a **real directory** at
///   `active` produces (`EINVAL`, not `NotFound`) —
///   [`ReleaseTrustError::Io`] naming `active`, fail-closed.
///
/// `None` therefore means `read_link` returned `NotFound` and nothing else:
/// neither refusal is folded into it.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::ActiveNotCanonical`] and
/// [`ReleaseTrustError::Io`] as stated above.
fn active_generation_index(root: &Path) -> Result<Option<u64>, ReleaseTrustError> {
    let active = active_link(root);
    match std::fs::read_link(&active) {
        Ok(target) => match parse_generation(&target) {
            Some(generation) => Ok(Some(generation)),
            None => Err(ReleaseTrustError::ActiveNotCanonical {
                target: target.to_string_lossy().into_owned(),
            }),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ReleaseTrustError::io(&active, e)),
    }
}

/// What an install-time admission produced.
///
/// The document is carried back rather than left to be re-read off the tree: the
/// consumer is a root daemon that links this crate and can construct nothing from
/// the installer's repository, so it reads what it just admitted from this value.
#[derive(Debug, PartialEq, Eq)]
pub struct AdmittedGeneration {
    /// The generation now active, and whether this call changed anything.
    pub activation: Activation,

    /// The epoch the activated generation records.
    ///
    /// Carried beside `document` rather than left to `document.epoch` because it
    /// is the number that was actually written to the `epoch` record, and a
    /// caller logging one number should log that one.
    pub epoch: u64,

    /// The admitted document, as the refusing reader parsed it.
    pub document: TrustSetDocument,
}

/// Reads the `trust-set.json` member out of a **delivered, unverified**
/// container.
///
/// The container layer has exactly one archive walk and this goes through it:
/// [`payload::open_package`] over the delivered bytes and
/// [`Payload::extract_to`](crate::payload::Payload::extract_to) into a temporary
/// directory, which is all-or-nothing and refuses a member whose bytes do not
/// hash as the manifest binds them. Nothing is trusted at this point — this is
/// the container's own self-consistency, not an authenticity verdict — and the
/// member it yields is what the rest of the sequence verifies and installs.
///
/// The temporary directory is created through `tempfile`, owner-only, and its
/// `Drop` removes it with everything under it on **every** path out, success and
/// failure alike, so neither the extracted member nor the directory survives the
/// call. `scratch` names the directory that temporary one is created *inside*;
/// `None` is `tempfile`'s own default location. It is a parameter so the cleanup
/// contract is observable at all: a test must not steer `TMPDIR` by mutating the
/// process environment, and it cannot safely inspect the shared system temporary
/// directory while other tests run beside it.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::MissingTrustSetMember`] when the walk succeeds
/// but produces no `trust-set.json`, [`ReleaseTrustError::Verify`] carrying the
/// container layer's own fault through the existing `PayloadError` mapping, and
/// [`ReleaseTrustError::Io`] when the temporary directory cannot be created or
/// the member cannot be read back.
fn extract_member(package: &[u8], scratch: Option<&Path>) -> Result<Vec<u8>, ReleaseTrustError> {
    use std::os::unix::fs::PermissionsExt as _;

    // Owner-only at creation and not left to the umask: an unverified document
    // sits under it for the whole walk, so nothing outside this process has any
    // business reading it.
    let owner_only = std::fs::Permissions::from_mode(0o700);
    let dir = match scratch {
        Some(parent) => tempfile::Builder::new()
            .permissions(owner_only)
            .tempdir_in(parent),
        None => tempfile::Builder::new().permissions(owner_only).tempdir(),
    }
    .map_err(|e| {
        ReleaseTrustError::io(
            &scratch.map_or_else(std::env::temp_dir, Path::to_path_buf),
            e,
        )
    })?;

    let mut payload = payload::open_package(Cursor::new(package)).map_err(VerifyError::from)?;
    payload.extract_to(dir.path()).map_err(VerifyError::from)?;

    let path = dir.path().join(TRUST_SET_MEMBER);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        // The walk was all-or-nothing and it succeeded, so this is a container
        // that carries something else rather than one that was cut short.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(ReleaseTrustError::MissingTrustSetMember)
        }
        Err(e) => Err(ReleaseTrustError::io(&path, e)),
    }
}

/// What the verification-only core of the self-admission sequence yields: a
/// generation that has verified under its own anchors and has not been installed.
///
/// The member bytes travel with the document and the epoch because they are what
/// the installer stores and what a fingerprint pin is compared against. Nothing
/// downstream re-extracts or re-reads them, which is what keeps "the bytes that
/// were verified" and "the bytes that are stored" the same slice.
struct VerifiedGeneration {
    /// The admitted document, as the refusing reader parsed it.
    document: TrustSetDocument,
    /// The verified document's own epoch — the number that will be recorded.
    epoch: u64,
    /// The container's `trust-set.json` member, verbatim.
    member: Vec<u8>,
}

/// The verification-only core of the self-admission sequence: steps 1 to 4, and
/// **no** write of any kind.
///
/// Nothing here creates, touches or prunes a directory in the tree — it does not
/// take the tree root at all. `extract_member`'s scratch is no exception: it is a
/// `tempfile::TempDir` removed when it drops, on every path out, and with
/// `scratch` `None` it is created under `std::env::temp_dir()`, outside the tree
/// altogether.
///
/// One `member` binding carries every step: the slice read out of the container
/// is the slice the pre-verification decode reads, the slice whose digest becomes
/// the self-admission request's `commit`, the slice the refusing reader parses,
/// and the slice the installer stores. Nothing re-extracts it, re-reads it from
/// disk or digests anything else, which is what ties the bytes that were verified
/// to the bytes that are stored — visible in the diff rather than asserted at
/// runtime.
///
/// There is deliberately **no** runtime cross-check between the provisional
/// decode and the verified document. Both parses consume that one slice, so
/// whenever both succeed they agree by construction; the request's `commit` is
/// checked against the *signed* manifest, so a substituted range fails there; and
/// `install_generation`'s validator independently re-runs this entire sequence
/// over the bytes read back from `gen-<n>.tmp` before `active` moves.
///
/// Splitting the verification from the installation is what lets the re-bootstrap
/// path put its epoch floor **between** them: an activating form would install
/// first and let the floor refuse second, which is the inversion that path exists
/// to avoid.
///
/// # Errors
///
/// Returns whichever [`ReleaseTrustError`] the step that refused raises: the
/// container layer's through [`ReleaseTrustError::Verify`],
/// [`ReleaseTrustError::MissingTrustSetMember`],
/// [`ReleaseTrustError::ProvisionalDecode`] for every pre-verification decode
/// fault, [`ReleaseTrustError::Verify`] again for the verdict on the container,
/// and [`ReleaseTrustError::Document`] for the refusing reader's own named
/// refusal.
fn verify_self_admitted(
    package: &[u8],
    scratch: Option<&Path>,
) -> Result<VerifiedGeneration, ReleaseTrustError> {
    // 1. The member, out of the container's one walk.
    let member = extract_member(package, scratch)?;

    // 2. The candidate set, from the crate's one pre-verification decode. Every
    //    fault of it — malformed JSON, an absent or non-integer `epoch`, absent
    //    or malformed `anchors`, two anchors sharing a `public_key` — is this one
    //    refusal of the admission *attempt*.
    let (trust, epoch) =
        self_admission_candidate(&member).ok_or(ReleaseTrustError::ProvisionalDecode)?;

    // 3. The step that binds the extracted member to the signature: `check_target`
    //    compares this digest against the *signed* manifest's `commit`, so bytes
    //    verified over one range and stored from another cannot pass, and a
    //    tampered provisional `epoch` can only produce `TargetMismatch`.
    let request =
        VerifyRequest::for_trust_self_admission(&epoch.to_string(), &member_digest(&member))?;
    verify_package(Cursor::new(package), &trust, &request)?;

    // 4. Only now is the document parsed for real. The generation is built from
    //    this parse; step 2's output reaches neither the tree nor the caller.
    let document = read_trust_set_document(&member)?;
    Ok(VerifiedGeneration {
        epoch: document.epoch,
        document,
        member,
    })
}

/// Compares an optional out-of-band fingerprint pin against the delivered
/// document member, installing nothing either way.
///
/// `None` is "no pin was supplied" and is `Ok(())`: the pin is optional by
/// default on every path that takes one, and enforced whenever supplied. A
/// supplied pin is the lowercase-hex SHA-256 of `member` — the same digest the
/// generation's signed manifest carries as its `commit` — compared as a plain
/// string, exactly as the verifier's own target check compares that value. Both
/// sides are public digests rather than key material, so there is no secret here
/// for a comparison to leak the shape of.
///
/// This writes nothing and activates nothing, which is precisely what lets the
/// re-bootstrap path run its epoch floor *after* it while the ordinary admission
/// order runs the installer straight after it. One contract, written once, two
/// orders.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::FingerprintPinMismatch`] naming both digests when
/// a supplied pin is not the member's.
fn check_fingerprint_pin(pin: Option<&str>, member: &[u8]) -> Result<(), ReleaseTrustError> {
    let Some(pin) = pin else {
        return Ok(());
    };
    let digest = member_digest(member);
    if pin == digest {
        return Ok(());
    }
    Err(ReleaseTrustError::FingerprintPinMismatch {
        pin: pin.to_string(),
        digest,
    })
}

/// The ordinary admission order: the verification-only core, the pin comparison,
/// then the one funnel onto the tree.
///
/// Nothing sits between the pin and the install here. A path that needs a further
/// refusal in that slot — the re-bootstrap's epoch floor — composes the same three
/// pieces in its own order rather than calling this, because calling it would
/// activate the generation before that refusal ever ran.
///
/// # Errors
///
/// Returns whichever refusal [`verify_self_admitted`] raises,
/// [`ReleaseTrustError::FingerprintPinMismatch`] when a supplied pin is not the
/// delivered document's digest, and the installer's own I/O and validator
/// refusals.
fn admit_with_pin(
    root: &Path,
    package: &[u8],
    scratch: Option<&Path>,
    pin: Option<&str>,
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    let verified = verify_self_admitted(package, scratch)?;
    check_fingerprint_pin(pin, &verified.member)?;

    // The one funnel onto the tree, so the record is finalised by the same
    // atomic swap that makes the generation active.
    let activation = install_generation(root, package, &verified.member, verified.epoch)?;
    Ok(AdmittedGeneration {
        activation,
        epoch: verified.epoch,
        document: verified.document,
    })
}

/// The whole install-time admission sequence, shared verbatim by both doors:
/// [`admit_with_pin`] with no pin.
///
/// # Errors
///
/// Returns exactly what [`admit_with_pin`] does, less the pin refusal it cannot
/// raise.
fn admit(
    root: &Path,
    package: &[u8],
    scratch: Option<&Path>,
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    admit_with_pin(root, package, scratch, None)
}

/// The empty-tree admission both doors onto an unseeded tree run: the tree-state
/// gate, **then** the package source, then [`admit_with_pin`].
///
/// `package` is deferred rather than taken as a slice because the two callers
/// obtain their bytes differently and the gate must run first on both.
/// [`admit_seed_generation`] hands over the slice its own caller passed, as a
/// `Cow::Borrowed`, so no package is copied to gain the deferral;
/// [`bootstrap_from_join_material`] reads the join-material file, which must not
/// happen on a tree this gate is going to refuse. The source is not consulted
/// until the gate has passed, and there is exactly one stat of `active` on either
/// path.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::ActiveGenerationPresent`] when `active` resolves
/// and [`ReleaseTrustError::Io`] naming `active` when its state cannot be read at
/// all, whatever `package` raises, and then whatever [`admit_with_pin`] raises.
fn admit_onto_empty_tree<'a>(
    root: &Path,
    pin: Option<&str>,
    package: impl FnOnce() -> Result<Cow<'a, [u8]>, ReleaseTrustError>,
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    let active = active_link(root);
    // One following stat, exactly as `read_active_epoch` makes it, so the two
    // agree on where the line is: an absent `active` and a dangling one are alike
    // `NotFound` and alike the empty-tree seed. This deliberately does not copy
    // the generation engine's own `current_generation`, which reads the link's
    // *name* and would call a dangling link a generation.
    match std::fs::metadata(&active) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Fail closed: a tree whose state cannot be read is not a tree that may
        // be seeded.
        Err(e) => return Err(ReleaseTrustError::io(&active, e)),
        Ok(_) => {
            // Naming the index is a courtesy and never a condition of refusing:
            // a link this crate did not write, or an `active` that is a real
            // directory and so cannot be read as a link at all, is refused just
            // the same with `None`.
            return Err(ReleaseTrustError::ActiveGenerationPresent {
                generation: std::fs::read_link(&active)
                    .ok()
                    .as_deref()
                    .and_then(parse_generation),
            });
        }
    }

    admit_with_pin(root, &package()?, None, pin)
}

/// Admits the delivered release-trust generation `package` onto a tree that has
/// **no** active generation, at install time.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves, and `package` is the delivered `.pkg` bytes verbatim — the same
/// bytes the generation stores as its container.
///
/// # What this proves, and what it does not
///
/// It proves the delivered document is internally consistent and was not mutated
/// in transit: the container walks whole, its members hash as its signed manifest
/// binds them, the manifest's signature verifies under an anchor the document
/// itself carries, and the document survives the refusing reader.
///
/// It does **not** prove authenticity. An attacker who replaces the whole
/// document, anchors included, and signs the container with a key that document
/// names passes every step here, because a self-admitted generation is by
/// definition checked against itself. Authenticity rests on the operator-mediated
/// channel that delivered the bytes, exactly as the mTLS CA anchor's does.
///
/// # The precondition
///
/// The tree must carry no active generation. That is decided before anything is
/// opened, walked, parsed, verified or written, by one stat of `active` that
/// **follows** the link — the same one [`read_active_epoch`] makes — so this door
/// is open exactly when that reader returns `None`, and "seed if unseeded" is a
/// two-line caller. An absent `active` and a dangling one are alike the ordinary
/// empty-tree seed; anything `active` resolves to is
/// [`ReleaseTrustError::ActiveGenerationPresent`], including a target that is not
/// a canonical `gen-<n>` and an `active` that is a real directory rather than a
/// symlink, for which `generation` is `None`.
///
/// The refusal reads neither the delivered nor the recorded epoch, and there is
/// no exemption to it — not for a byte-identical redelivery, not behind a flag.
/// "Needs no existing trust set" is not "may overwrite one": with no epoch floor
/// applied here, a seed callable over an active generation would be an
/// unconditional way to install an older, pre-revocation generation over a
/// current one. Making the precondition part of this function's contract is what
/// keeps "no floor here" safe, because it makes "here" a place where no floor
/// could apply. Passing the gate is not admission — everything after it can still
/// refuse the delivered package. Re-provisioning a tree that *does* carry a
/// generation is [`replace_generation`].
///
/// The gate and the sequence behind it are shared with
/// [`bootstrap_from_join_material`], the other door onto an empty tree, so the two
/// cannot come to disagree about what an empty tree is. What differs there is the
/// byte source — the operator-mediated join-material location rather than a
/// caller's slice — and nothing else.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::ActiveGenerationPresent`] when `active` resolves,
/// and [`ReleaseTrustError::Io`] naming `active` when its state cannot be read at
/// all — a tree whose state is unreadable is not a tree that may be seeded.
/// Past the gate, returns whichever refusal the admission sequence raises:
/// [`ReleaseTrustError::Verify`] for a container-layer fault or a verification
/// verdict, [`ReleaseTrustError::MissingTrustSetMember`] when the container
/// carries no `trust-set.json`, [`ReleaseTrustError::ProvisionalDecode`] when no
/// candidate trust set can be built from the delivered document,
/// [`ReleaseTrustError::Document`] carrying the refusing reader's own refusal,
/// and the installer's own I/O and validator refusals.
pub fn admit_seed_generation(
    root: &Path,
    package: &[u8],
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    // The source borrows the caller's slice rather than copying it: the deferral
    // exists so the gate runs before the *other* door's file read, and it must
    // cost this one nothing.
    admit_onto_empty_tree(root, None, || Ok(Cow::Borrowed(package)))
}

/// Admits the delivered release-trust generation `package` onto a tree that may
/// already carry one, at install time, under an operator's authority.
///
/// `root` and `package` are [`admit_seed_generation`]'s, and so is everything
/// this does: it runs that function's verification sequence **verbatim** and is
/// in no sense a weaker path. Its one and only difference is the *absence* of the
/// seed's tree-state precondition, which is why it is a separately named exported
/// symbol rather than a flag on the seed — "can this call bypass the tree-state
/// gate?" is then a property of a function, answerable by reading a signature and
/// greppable by name, instead of a property of a call site.
///
/// # Why it exists
///
/// A generation minted with a wrongly-high `epoch` raises the floor past anything
/// release-ops will legitimately mint next and wedges the host. The documented
/// exit is to re-provision it with the installer, and the seed's precondition
/// refuses exactly that. So this door drops the precondition, and nothing else.
///
/// # What it does not gate on
///
/// - **No epoch floor, in either direction.** A delivered `epoch` below, equal to
///   or above the recorded one is admitted alike, and the epoch recorded
///   afterwards is the delivered one — **including when that moves the floor
///   down**, which is precisely the wedged-host recovery. A replace that refused a
///   lower epoch would refuse the case it exists for.
/// - **No requirement that the tree be non-empty.** On an empty tree the seed
///   applies no floor either, so on that input the two doors do the same thing;
///   an inverted gate would only force a caller to branch between two functions
///   with identical behaviour. This is the seed *minus* a gate, not the seed with
///   a different one.
/// - **No fingerprint pin, and no reading of [`REQUIRE_TRUST_PIN_MARKER`].**
///   That marker governs [`rebootstrap_generation`], whose threat is a
///   compromised control plane pushing a forged higher-epoch generation to a
///   host that has fallen past the retention floor. An install-time replace is the operator
///   standing in that channel's place, so consulting the marker here would demand
///   an out-of-band pin from the very party the marker exists to trust, and would
///   leave the wedged host wedged. Its presence changes nothing about this call,
///   and this call leaves it exactly where it is.
///
/// Dropping the gate removes this module's precondition and nothing else: the
/// generation engine's own structural and I/O failures still propagate. A tree
/// whose `active` is a **real directory** rather than a symlink is the concrete
/// case — the engine reads that link before it allocates anything, and the read
/// fails with `EINVAL` rather than `NotFound` — so this returns
/// [`ReleaseTrustError::Io`] and installs nothing, where the seed refuses at its
/// gate. Both refuse; neither repairs.
///
/// # This is not a runtime accept path
///
/// It is reachable only from an operator-mediated, install-time caller: the
/// installer, as root, on a host under operator control. Its arguments are the
/// tree root and the delivered bytes, so there is no request struct a
/// deserializer could fill in and no wire message that can name its input. **Never
/// call it from a control-plane push.** The runtime channel applies an epoch
/// floor, chain rules and the `require-trust-pin` gate that this carries none of,
/// and exports its own, separately named entry point.
///
/// # Errors
///
/// Returns whichever refusal the admission sequence raises — the same variants
/// [`admit_seed_generation`] returns past its gate — plus the generation engine's
/// own I/O faults as [`ReleaseTrustError::Io`]. It never returns
/// [`ReleaseTrustError::ActiveGenerationPresent`].
pub fn replace_generation(
    root: &Path,
    package: &[u8],
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    #[cfg(test)]
    REPLACE_GENERATION_CALLS.with_borrow_mut(|calls| calls.push(root.to_path_buf()));

    admit(root, package, None)
}

// Every call this install-time door receives in a test build, so a test can
// assert that the runtime entry points reach it neither directly nor through a
// helper. Instrumenting the *callee* is what makes the assertion cover a
// transitive call without anyone having enumerated the helpers.
//
// Thread-local, in the shape of the engine's `SYSTEMCTL_CALLS` recorder, because
// this module's own `replace_generation` tests run in parallel in the same
// binary and a process-global recorder would see their calls. The paths under
// test do no threading of their own, so every call a drive provokes lands on the
// test's own thread.
#[cfg(test)]
thread_local! {
    pub(crate) static REPLACE_GENERATION_CALLS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Which generation a release-trust tree currently has active, as
/// [`read_generation_state`] reports it.
///
/// A read result with no invariant to protect, so its two values are public
/// fields, exactly as [`Activation`] and [`AdmittedGeneration`] carry theirs.
#[derive(Debug, PartialEq, Eq)]
pub struct ActiveGeneration {
    /// The canonical index `active` names.
    pub generation: u64,
    /// The epoch that generation records.
    pub epoch: u64,
}

/// Reports which generation the release-trust tree at `root` has active, or that
/// it carries none.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves.
///
/// A caller pushing a generation over the runtime channel needs to know which
/// situation it is in before it pushes, and this answers with the index and the
/// epoch [`accept_generation`] would compare against — the same probe and the
/// same reader that path runs, in the same order, so this can never report "you
/// are on generation *n*" for a tree the accept path would refuse.
///
/// `Ok(None)` **is** the tree state and is never a synthesized zero. It covers
/// exactly two inputs: an absent `active`, and one that dangles — the trees
/// [`read_active_epoch`] already calls empty. Every other verdict is an `Err`,
/// including a tree carrying a generation whose document or `epoch` record is
/// damaged: that tree is broken rather than empty, and the two are not the same
/// answer.
///
/// This reports no install-time door. [`replace_generation`] applies no epoch
/// floor and is not a runtime accept path, so it is not one of the situations
/// this describes and nothing here reaches it.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::ActiveNotCanonical`] when `active` names
/// something that is not a canonical `gen-<n>`, [`ReleaseTrustError::Io`] naming
/// `active` when the link cannot be read for any reason other than its absence —
/// a real directory there is the concrete case — and every refusal the common
/// reader raises about a generation that does resolve:
/// [`ReleaseTrustError::Document`], [`ReleaseTrustError::EpochDisagreement`],
/// whichever grammar refusal [`read_active_epoch`] raises for a malformed
/// `epoch` record, [`ReleaseTrustError::MalformedAnchorKey`],
/// [`ReleaseTrustError::Input`] and [`ReleaseTrustError::Io`].
pub fn read_generation_state(root: &Path) -> Result<Option<ActiveGeneration>, ReleaseTrustError> {
    // The probe first, exactly as the accept path runs it. Its absent link is
    // this caller's `Ok(None)`; both its refusals propagate.
    let Some(generation) = active_generation_index(root)? else {
        return Ok(None);
    };

    match read_active_generation(root) {
        Ok(active) => Ok(Some(ActiveGeneration {
            generation,
            epoch: active.epoch,
        })),
        // The one refusal of the common reader this maps, and only this one: a
        // dangling `active` passes the probe — `read_link` succeeds and the
        // target parses — and the following stat then sees nothing. Reporting it
        // as `None` is what keeps this reader and `read_active_epoch` agreeing
        // about which trees are empty.
        Err(ReleaseTrustError::NoActiveGeneration) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Accepts the delivered release-trust generation `package` at runtime, over the
/// control-plane channel, applying the `epoch` floor.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves, and `package` is the delivered `.pkg` bytes verbatim — a byte slice
/// because it genuinely arrived over the wire.
///
/// # The sequence
///
/// 1. **Establish the active generation.** The canonical-link probe, then the
///    common reader, yielding the index, the verified document, the epoch and
///    the trust set. Every refusal of either lands here, before verification and
///    before any write. There is no accept onto an empty tree: an absent
///    `active` and a dangling one are alike
///    [`ReleaseTrustError::NoActiveGeneration`].
/// 2. **Compare the delivered bytes against `active/generation.pkg`.** Equal
///    bytes return an unchanged result immediately — without verifying, without
///    comparing epochs, without touching the tree.
/// 3. **Read both carriers of the delivered `epoch` and refuse a disagreement**,
///    before anything is injected into the verifier.
/// 4. **Verify** through [`verify_package`], which applies the floor and the
///    rest of the taxonomy.
/// 5. **Install** through the crate's one funnel onto the tree.
///
/// No signature check, taxonomy variant or epoch comparison is written here: the
/// shared verifier already implements all of it against the injected trust set
/// and the delivered epoch this path supplies. A generation that fails
/// verification is never staged.
///
/// # Byte-identical redelivery is an idempotent no-op
///
/// A control plane with bounded retry redelivers the current generation
/// routinely, and identical bytes can restore no revocation, so the answer is
/// "unchanged" rather than a refusal. Step 2 is **this path's own** comparison
/// and it runs **before** the verifier, because for such a redelivery the
/// delivered epoch equals the active one and the strictly-greater test would
/// refuse it as [`VerifyError::StaleTrustSet`] first. The generation engine's own
/// downstream no-op therefore cannot serve here, and this path never reaches it
/// on that input.
///
/// The unchanged result is the same [`AdmittedGeneration`] every other outcome
/// returns, carrying `changed: false`, the index the probe yielded, and the
/// **active** generation's epoch and document — the copy on disk that was
/// verified when it was admitted, never a parse of the delivered bytes. A caller
/// reads whether anything moved from `activation.changed` rather than from the
/// result's type. A *different* document at an equal epoch does not match those
/// bytes, so it falls through to the verifier and is
/// [`VerifyError::StaleTrustSet`].
///
/// # The `epoch` floor
///
/// A valid signature proves a generation is authentic, not *current*, so an
/// older but validly signed generation could otherwise be replayed to restore a
/// revoked `key_id` or drop a withdrawn build. Activation therefore requires the
/// delivered signed `epoch` to be strictly greater than the active generation's;
/// equal or lower is [`VerifyError::StaleTrustSet`]. The activated epoch is
/// written to the new generation's `epoch` record, so the floor survives a
/// restart.
///
/// # The manifest-format floor is the ACTIVE generation's
///
/// The injected trust set is built from the active generation, so its
/// `min_manifest_format_version` is what governs the delivered generation's own
/// manifest — a trust generation is a package like any other here, and this
/// special-cases nothing. The consequence is worth knowing at mint time: **a
/// generation that raises the floor must itself be minted at or above the floor
/// it raises to**, and so must every generation after it. One minted at an older
/// manifest format than the floor its predecessor published is refused with
/// [`VerifyError::UnsupportedManifestFormat`] and cannot be superseded except by
/// re-provisioning the host.
///
/// # Not the install-time doors
///
/// [`admit_seed_generation`] refuses a tree that already carries a generation
/// and [`replace_generation`] applies no floor in either direction; neither is a
/// runtime accept path, and nothing here calls either of them.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::NoActiveGeneration`] for a tree whose `active` is
/// absent or dangling, [`ReleaseTrustError::ActiveNotCanonical`] when `active`
/// names something that is not a canonical `gen-<n>`,
/// [`ReleaseTrustError::Io`] naming `active` for any other link failure — a real
/// directory there is the concrete case — and every refusal the common reader
/// raises about a generation that does resolve. Past step 1,
/// [`ReleaseTrustError::Io`] naming `<root>/active/generation.pkg` when the
/// active container cannot be read, [`ReleaseTrustError::Verify`] for a
/// container-layer fault or a verification verdict,
/// [`ReleaseTrustError::MissingTrustSetMember`] when the delivered container
/// carries no `trust-set.json`, [`ReleaseTrustError::ProvisionalDecode`] when the
/// delivered document does not survive the pre-verification decode,
/// [`ReleaseTrustError::DeliveredEpochDisagreement`] when its two epoch carriers
/// disagree, [`ReleaseTrustError::Document`] carrying the refusing reader's own
/// refusal, and the installer's own I/O and validator refusals.
pub fn accept_generation(
    root: &Path,
    package: &[u8],
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    // 1. The active generation, the engine's question first and the following
    //    stat second. The order matters on one input: a dangling `active`
    //    naming a canonical `gen-<n>` passes the probe and is then refused by
    //    the reader, which is the intended answer — the probe running first must
    //    not turn a dangling link into that generation.
    let generation = active_generation_index(root)?.ok_or(ReleaseTrustError::NoActiveGeneration)?;
    let active = read_active_generation(root)?;

    // 2. This path's own byte-identity comparison, ahead of the verifier. Step 1
    //    has established that a canonical generation is active, so a container
    //    that cannot be read is a damaged tree rather than an empty one: there
    //    is deliberately no `NotFound` exemption here.
    let path = active_package(root);
    let stored = std::fs::read(&path).map_err(|e| ReleaseTrustError::io(&path, e))?;
    if stored == package {
        return Ok(AdmittedGeneration {
            activation: Activation {
                generation,
                changed: false,
            },
            epoch: active.epoch,
            document: active.document,
        });
    }

    // 3. The delivered member, out of the container's one walk, and its epoch
    //    from the crate's one pre-verification decode. Both carriers are read
    //    and compared before anything is injected into the verifier. The
    //    anchors that decode also yields are dropped on purpose: a runtime
    //    accept is judged against the **active** generation's trust set, never
    //    against one carried by the bytes being judged.
    let member = extract_member(package, None)?;
    let (_anchors, delivered_epoch) =
        provisional_anchors_and_epoch(&member).ok_or(ReleaseTrustError::ProvisionalDecode)?;
    check_delivered_epoch_carriers(package, delivered_epoch)?;

    // 4. The verdict, against the **active** generation's trust set: its anchors,
    //    its withdrawn list, its manifest-format floor, and its epoch as the
    //    floor the verifier's strictly-greater test applies.
    let request = VerifyRequest::for_trust(
        &delivered_epoch.to_string(),
        &member_digest(&member),
        delivered_epoch,
    )?;
    verify_package(Cursor::new(package), &active.trust, &request)?;

    // 5. Only now is the delivered document parsed for real, and only now does
    //    anything reach the tree.
    let document = read_trust_set_document(&member)?;
    let activation = install_generation(root, package, &member, document.epoch)?;
    Ok(AdmittedGeneration {
        activation,
        epoch: document.epoch,
        document,
    })
}

/// Refuses a delivered generation whose two epoch carriers disagree.
///
/// A generation states its epoch twice under the signature: the `epoch` field
/// inside the document, which is authoritative and arrives here as `document`,
/// and the manifest artifact entry's `version` in decimal. Reading the manifest
/// costs one footer parse and no archive walk, and refusing a disagreement costs
/// nothing, because both carriers are signed: a disagreement is a producer bug or
/// a crafted container.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::DeliveredEpochDisagreement`] when an artifact
/// entry's `version` is not `document` in decimal, and
/// [`ReleaseTrustError::Verify`] carrying the container layer's own fault when
/// the container cannot be opened at all.
fn check_delivered_epoch_carriers(package: &[u8], document: u64) -> Result<(), ReleaseTrustError> {
    let payload = payload::open_package(Cursor::new(package)).map_err(VerifyError::from)?;
    let declared = document.to_string();
    for artifact in payload.manifest().artifacts() {
        if artifact.version != declared {
            return Err(ReleaseTrustError::DeliveredEpochDisagreement {
                document,
                manifest: artifact.version.clone(),
            });
        }
    }
    Ok(())
}

/// How far a chain replay got, on the arm where it got all the way.
///
/// Carries the same two progress fields as [`ChainReplayError`], so a caller
/// reads its position off whichever value it holds without first branching on
/// which arm it got.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainReplay {
    /// How many entries of `packages` were accepted — a position in that slice,
    /// not a count of activations.
    pub completed: usize,
    /// The record the last accepted step returned, or `None` when `packages` was
    /// empty.
    pub last: Option<AdmittedGeneration>,
}

/// A chain replay that stopped, and how far it got before it did.
///
/// A struct error of its own rather than a [`ReleaseTrustError`] variant: a
/// variant wrapping a boxed `ReleaseTrustError` would make that enum recursive,
/// and would put an arm in front of every existing caller of
/// [`admit_seed_generation`] and [`replace_generation`] that their calls can
/// never produce.
///
/// It derives only `Debug`, because a `ReleaseTrustError` reaches an
/// [`std::io::Error`], which is not `Eq`.
#[derive(Debug, thiserror::Error)]
#[error("the trust generation chain stopped after {completed} step(s)")]
pub struct ChainReplayError {
    /// How many entries of `packages` were accepted before the failure, so
    /// `packages[completed]` is the step that raised `source`.
    pub completed: usize,
    /// The record the last accepted step returned, or `None` when the first step
    /// failed.
    pub last: Option<AdmittedGeneration>,
    /// The refusal that stopped the replay.
    #[source]
    pub source: ReleaseTrustError,
}

/// Replays the missing trust-generation chain onto the tree at `root`, epoch by
/// epoch, as an ordered sequence of ordinary accepts.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves. `packages` is a slice of slices so a caller replaying out of one
/// contiguous buffer copies nothing, and a caller holding owned buffers maps
/// once at the call.
///
/// # Why a chain rather than the latest generation alone
///
/// Each generation is verified against the *current* active key set, so a host
/// that skipped the generation which **introduced** a key cannot verify a later
/// one signed by that key. Rotation preserves the matching invariant — a
/// generation is only ever signed by a key present in the immediately preceding
/// one — so a lagging host is caught up by replaying what it missed, in order.
///
/// Every step is [`accept_generation`] verbatim, its byte-identity fast path
/// included, and each is subject to the `epoch` floor wherever it reaches the
/// epoch comparison at all. There is deliberately **no numeric contiguity
/// test**: epochs are allocated by hand and are not contiguous, so arithmetic
/// would refuse legitimate sequences. A gap shows up instead as the next
/// generation being signed by a key the host's active set does not carry, which
/// the verifier returns as [`VerifyError::UnknownKeyId`], and out-of-order
/// delivery shows up as [`VerifyError::StaleTrustSet`] on the step that goes
/// backwards.
///
/// # Progress is counted in input steps and is never unwound
///
/// `completed` is the number of entries of `packages` consumed without refusal,
/// so `packages[..completed]` all succeeded and, on the error arm,
/// `packages[completed]` is the step that raised the failure — the resume
/// position. A step that succeeded as the byte-identical no-op is **accepted**:
/// it increments `completed` and supplies `last` exactly as a step that
/// activated does, which is routine rather than exceptional, since a control
/// plane sending "generations *N* through *M*" to a host it believes is on *N*
/// produces one on the first step. Whether anything actually moved is read from
/// `last`'s `activation.changed`, never inferred from the count. An empty
/// `packages` is `Ok(ChainReplay { completed: 0, last: None })` and touches
/// nothing.
///
/// A failed step leaves the tree exactly as the preceding accepted steps left
/// it: activations stand, and a chain whose accepted steps were all no-ops is
/// left on the generation it started on. That is sound under both kinds of
/// accepted step — every step that activated was individually verified against
/// its own predecessor, and every step that succeeded as a no-op installed
/// nothing — and the floor moved backward in neither case. Keeping the progress
/// is strictly better than unwinding a host's only route out of being behind.
///
/// # Errors
///
/// Returns [`ChainReplayError`] carrying the refusal the stopping step raised as
/// its `#[source]`, which is any refusal [`accept_generation`] documents,
/// together with `completed` and the last accepted step's record.
// The `Err` arm is large because carrying the progress is the whole reason this
// pair exists: `last` is an `AdmittedGeneration`, holding the document the last
// accepted step returned. Boxing the error would put a caller's resume position
// behind an allocation and change the exported signature; the two arms carry the
// same two progress fields so a caller need not branch on which one it got.
#[allow(clippy::result_large_err)]
pub fn accept_generation_chain(
    root: &Path,
    packages: &[&[u8]],
) -> Result<ChainReplay, ChainReplayError> {
    let mut completed = 0;
    let mut last = None;
    for package in packages {
        match accept_generation(root, package) {
            Ok(admitted) => {
                completed += 1;
                last = Some(admitted);
            }
            Err(source) => {
                return Err(ChainReplayError {
                    completed,
                    last,
                    source,
                });
            }
        }
    }
    Ok(ChainReplay { completed, last })
}

/// A caller's assertion that a host has fallen past the control plane's retention
/// floor and may be re-bootstrapped, carrying the last-confirmed `epoch` it
/// believes that host records.
///
/// Whether a host is past the retained window is a **control-plane
/// determination**, so [`rebootstrap_generation`] is necessarily entered on the
/// caller's assertion — which is exactly why it must not be reachable by accident.
/// This type is how that is arranged: it is not a `bool`, it has no `Default`, it
/// is built only through [`RebootstrapAuthorization::asserting_last_confirmed_epoch`],
/// and it carries no `Deserialize` and no conversion from any wire or request
/// type, so no value of it can *arrive* already filled in.
///
/// # What that buys, exactly
///
/// The constructor is public and takes a `u64`, so a handler **can** write
/// `RebootstrapAuthorization::asserting_last_confirmed_epoch(request.epoch)`. That
/// is by design. This type establishes no provenance and is **not an
/// authorization capability**: what it forces is that the assertion be an explicit
/// line of source someone wrote — greppable by the constructor's name and visible
/// in review — rather than a field a deserializer filled in. Reaching the
/// re-bootstrap path stays a deliberate act; it does not become an unforgeable
/// one.
#[derive(Debug, Clone, Copy)]
pub struct RebootstrapAuthorization {
    /// The last-confirmed epoch the caller asserts the host records. Private, and
    /// read only by this module, so it cannot be built by struct literal or
    /// altered after construction.
    asserted_epoch: u64,
}

impl RebootstrapAuthorization {
    /// Creates the authorization value asserting `epoch` as the host's
    /// last-confirmed one.
    ///
    /// The only constructor. [`rebootstrap_generation`] compares `epoch` for
    /// equality against the epoch the tree actually records and refuses a
    /// disagreement with [`ReleaseTrustError::RebootstrapEpochMismatch`], which is
    /// what catches a mis-targeted or stale-batch re-bootstrap aimed at a host
    /// that has moved on.
    #[must_use]
    pub fn asserting_last_confirmed_epoch(epoch: u64) -> Self {
        Self {
            asserted_epoch: epoch,
        }
    }
}

/// Whether the host-side pin marker is present, without following symlinks and
/// without reading a byte of it.
///
/// The marker's **existence is the entire state**: there is no format, so no
/// malformed state, no parser, no encoding and no version, and an empty file is a
/// valid marker. `symlink_metadata` rather than `metadata`, so an entry of any
/// kind at that path — a dangling symlink included — reads as set; otherwise
/// deleting a symlink's target would silently clear the gate.
///
/// The classification of the stat's outcome is [`classify_pin_marker`]'s and this
/// function does not repeat it.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::Io`] naming the marker path for every stat failure
/// that is not `NotFound`.
fn require_pin_marker_set(root: &Path) -> Result<bool, ReleaseTrustError> {
    let path = require_pin_marker(root);
    classify_pin_marker(std::fs::symlink_metadata(&path).map(|_| ()), &path)
}

/// Classifies the pin marker's stat: set, unset, or a fail-closed refusal.
///
/// Pure, and the **only** place the stat result is interpreted. `Ok` is set,
/// `NotFound` — and only `NotFound` — is unset, and every other I/O failure is
/// refused through [`ReleaseTrustError::Io`] naming `path` rather than coerced
/// into "unset": whatever can make the marker unreadable is the kind of
/// interference the gate exists to survive.
///
/// It is a separate function because that last branch is what no test can reach
/// through a real filesystem. The marker is a direct child of the tree root, and
/// the re-bootstrap's earlier `read_active_epoch` already stats inside that root,
/// so stripping the root's search permission — the only ordinary way to make a
/// stat of a direct child fail with something other than `NotFound` — fails that
/// read first and the marker is never reached. A unit test feeds this a
/// synthesized [`std::io::Error`] of each kind instead. The runtime behaviour is
/// unchanged by the split: the same three outcomes at the same point in the order.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::Io`] naming `path` for every non-`NotFound` stat
/// failure.
fn classify_pin_marker(
    stat: Result<(), std::io::Error>,
    path: &Path,
) -> Result<bool, ReleaseTrustError> {
    match stat {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ReleaseTrustError::io(path, e)),
    }
}

/// Re-bootstraps a host that has fallen past the control plane's retention floor,
/// admitting `package` under the anchors it itself carries and superseding the
/// stale generation the tree holds.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves, `package` is the delivered `.pkg` bytes verbatim, `authorization` is
/// the caller's assertion of the host's last-confirmed epoch, and `pin` is the
/// optional out-of-band fingerprint — the lowercase-hex SHA-256 of the delivered
/// document member, which is the digest the generation's signed manifest carries
/// as its `commit`.
///
/// # Why this exists
///
/// [`accept_generation`] judges a delivered generation against the **active**
/// generation's key set, and a control plane prunes old generations. A host
/// offline across more rotations than the retained window cannot be chained
/// forward at all: the intermediate keys that would carry it there are gone.
/// Re-running the accept path against the stale generation fails by construction,
/// so this path admits the delivered document under its own anchors instead — the
/// same cryptographic act the installer's seed performs, reached over the runtime
/// channel.
///
/// # What this admission proves, and what stands in for the rest
///
/// Under self-admission the delivered document vouches for itself, so — exactly as
/// at install-time seeding — this proves **internal consistency and transit
/// integrity, not authenticity**. A forged generation carrying its own anchors and
/// signed by a key those anchors name passes the verification step.
///
/// What stands in for authenticity is a set of weaker things, and they are not
/// equal. Against a **compromised control plane** exactly two bite:
///
/// - the **epoch floor** against the *verified* epoch, which denies a rollback to
///   an older, pre-revocation generation; and
/// - the **out-of-band fingerprint pin**, which the host-side
///   [`REQUIRE_TRUST_PIN_MARKER`] can make mandatory.
///
/// The `authorization` value and the asserted-epoch equality check do **not**: a
/// handler that passes a wire-supplied epoch into
/// [`RebootstrapAuthorization::asserting_last_confirmed_epoch`] satisfies both.
/// What those two buy is that this path is not reachable by accident, and that a
/// mis-targeted or stale-batch re-bootstrap aimed at a host that has moved on is
/// caught. Neither establishes provenance and neither is a capability.
///
/// # The order, and where the single write is
///
/// 1. **The authorization value is required**, by the signature.
/// 2. **An empty tree is refused** as [`ReleaseTrustError::NoActiveGeneration`],
///    read through [`read_active_epoch`] — before the marker is consulted, before
///    the container is opened and before anything is written. This path exists to
///    supersede a **stale** generation; an unseeded host is
///    [`bootstrap_from_join_material`]'s, which takes no caller-supplied bytes.
/// 3. **The recorded epoch must equal the asserted one.**
/// 4. **The host-side pin marker is read**, and a call carrying no pin while it is
///    present is refused with [`ReleaseTrustError::FingerprintPinRequired`]. This
///    sits ahead of the container work deliberately: the refusal depends on
///    nothing the delivered bytes carry, so a host that demands a pin rejects an
///    unpinned call without paying for a package verification.
/// 5. **The verification-only self-admission core** runs — the container's one
///    walk, the pre-verification decode, the signature verdict under the delivered
///    document's own anchors, and the refusing reader. Nothing has been written at
///    this point.
/// 6. **A supplied pin is compared** against the digest of the member that core
///    returned, through the same helper the ordinary admission order calls.
/// 7. **The floor is enforced against the VERIFIED epoch** — strictly greater than
///    the recorded one, or [`ReleaseTrustError::StaleRebootstrap`]. This is **this
///    path's own** comparison, not the verifier's: the self-admission request form
///    carries no delivered epoch, so `verify_package`'s strictly-greater test
///    returns before it compares anything. The binding comparison is the verified
///    one, available precisely because step 5 verified without activating, so a
///    compromised control plane cannot declare a healthy host "too far behind" and
///    push an older generation on a provisionally-decoded epoch.
/// 8. **The generation is activated and recorded**, through the crate's one funnel
///    onto the tree.
///
/// Steps 1 to 7 all refuse **before** the installer is entered, so every refusal
/// this path adds leaves the host exactly as it was: the stale generation is
/// superseded by activation and pruning and is never removed up front. What the
/// tree looks like when step 8 itself fails is the generation engine's own
/// three-outcome contract, inherited unchanged.
///
/// # What is relaxed
///
/// The **chain check only**. The monotonic epoch floor stands, the package is
/// still verified rather than waved through, and this is a distinct entry point
/// from [`accept_generation`] rather than a flag on it, so the relaxation is never
/// reachable by the ordinary route.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::NoActiveGeneration`] for a tree whose `active` is
/// absent or dangling, whichever grammar refusal [`read_active_epoch`] raises for
/// a malformed `epoch` record, [`ReleaseTrustError::RebootstrapEpochMismatch`]
/// when the asserted epoch is not the recorded one,
/// [`ReleaseTrustError::FingerprintPinRequired`] when the host demands an
/// out-of-band pin and none was supplied, [`ReleaseTrustError::Io`] naming the
/// marker path when its state cannot be read at all,
/// [`ReleaseTrustError::Verify`] for a container-layer fault or a verification
/// verdict, [`ReleaseTrustError::MissingTrustSetMember`] when the delivered
/// container carries no `trust-set.json`,
/// [`ReleaseTrustError::ProvisionalDecode`] when the delivered document does not
/// survive the pre-verification decode, [`ReleaseTrustError::Document`] carrying
/// the refusing reader's own refusal,
/// [`ReleaseTrustError::FingerprintPinMismatch`] when a supplied pin is not the
/// delivered document's digest, [`ReleaseTrustError::StaleRebootstrap`] when the
/// verified epoch is not strictly greater than the recorded one, and the
/// installer's own I/O and validator refusals.
pub fn rebootstrap_generation(
    root: &Path,
    package: &[u8],
    authorization: RebootstrapAuthorization,
    pin: Option<&str>,
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    // 2. The tree state, first: this path supersedes a stale generation and has
    //    nothing to do on a tree that carries none.
    let recorded = read_active_epoch(root)?.ok_or(ReleaseTrustError::NoActiveGeneration)?;

    // 3. The assertion against the record.
    if authorization.asserted_epoch != recorded {
        return Err(ReleaseTrustError::RebootstrapEpochMismatch {
            asserted: authorization.asserted_epoch,
            recorded,
        });
    }

    // 4. Host state, ahead of the container work. The marker is read whatever the
    //    call carries, so an unreadable marker is fail-closed rather than
    //    conditional on the pin.
    if require_pin_marker_set(root)? && pin.is_none() {
        return Err(ReleaseTrustError::FingerprintPinRequired);
    }

    // 5. The verification-only core: everything the ordinary admission verifies,
    //    and no write.
    let verified = verify_self_admitted(package, None)?;

    // 6. The pin, through the shared non-activating helper.
    check_fingerprint_pin(pin, &verified.member)?;

    // 7. The floor, against the **verified** epoch and against nothing weaker.
    if verified.epoch <= recorded {
        return Err(ReleaseTrustError::StaleRebootstrap {
            delivered: verified.epoch,
            recorded,
        });
    }

    // 8. The first and only write.
    let activation = install_generation(root, package, &verified.member, verified.epoch)?;
    Ok(AdmittedGeneration {
        activation,
        epoch: verified.epoch,
        document: verified.document,
    })
}

/// Bootstraps a host with **no** prior release-trust generation from the
/// operator-delivered join material at the root of the tree.
///
/// `root` is the tree
/// [`Layout::release_trust_dir`](crate::layout::Layout::release_trust_dir)
/// resolves, and `pin` is the optional out-of-band fingerprint pin on the same
/// terms as [`rebootstrap_generation`]'s. There is deliberately **no package
/// parameter**: the generation is read from [`JOIN_GENERATION_FILE`] inside
/// `root`, which the operator-mediated join channel writes — the same
/// out-of-band delivery that carries the mTLS CA anchor. **The location is the
/// enforcement**, not who asks, so this accepts no caller-supplied bytes at all.
/// It is named for that
/// byte source rather than for the tree state it requires, so it cannot be
/// mistaken at a call site for [`admit_seed_generation`], which serves the same
/// tree state from a caller's slice.
///
/// # The sequence is the seed's
///
/// This invents no bootstrap of its own: it hands the join-material location and
/// the pin to the shared empty-tree admission, so the tree-state gate and the
/// verification sequence are [`admit_seed_generation`]'s, byte for byte. What this
/// path contributes is the byte source and the pin, and nothing else.
///
/// **The gate precedes the read.** `active` is stat'd and a non-empty tree refused
/// with [`ReleaseTrustError::ActiveGenerationPresent`] *before* the join material
/// is opened, so that refusal is what **every** non-empty tree gets whatever the
/// join-material location does or does not hold, and an
/// [`ReleaseTrustError::Io`] from that location is only ever reachable on a tree
/// the gate accepted. The refusal that depends only on tree state runs before the
/// one that depends on bytes — the same discipline the re-bootstrap follows.
///
/// The pin, when supplied, is compared inside the sequence against the member the
/// verification core returned, because that digest does not exist until the
/// container has been walked; a mismatch refuses with nothing written.
///
/// # What it does not consult
///
/// - **The pin marker.** That gate guards the path which supersedes an existing
///   trust history; this path has none to supersede.
/// - **Any epoch floor.** An empty tree records no epoch, so nothing is compared
///   and no stale refusal runs. The floor is **vacuous** here rather than relaxed,
///   and no active epoch is synthesized to have something to compare against —
///   inventing one would make the very first generation refusable.
///
/// The join material is **left in place** after a successful bootstrap: reading it
/// is idempotent, the tree-state gate refuses a second call anyway, and removing
/// operator-delivered material is not this path's business.
///
/// # What this admission proves
///
/// Exactly what [`admit_seed_generation`] proves, over a different channel:
/// internal consistency and transit integrity, never authenticity. Authenticity
/// rests on the operator-mediated channel that wrote the file.
///
/// # Errors
///
/// Returns [`ReleaseTrustError::ActiveGenerationPresent`] when `active` resolves
/// and [`ReleaseTrustError::Io`] naming `active` when its state cannot be read at
/// all. Past the gate, [`ReleaseTrustError::Io`] naming the join-material path
/// when nothing is there or it cannot be read, and then whichever refusal the
/// admission sequence raises: [`ReleaseTrustError::Verify`],
/// [`ReleaseTrustError::MissingTrustSetMember`],
/// [`ReleaseTrustError::ProvisionalDecode`], [`ReleaseTrustError::Document`],
/// [`ReleaseTrustError::FingerprintPinMismatch`] when a supplied pin is not the
/// delivered document's digest, and the installer's own I/O and validator
/// refusals.
pub fn bootstrap_from_join_material(
    root: &Path,
    pin: Option<&str>,
) -> Result<AdmittedGeneration, ReleaseTrustError> {
    admit_onto_empty_tree(root, pin, || {
        let path = join_generation_file(root);
        std::fs::read(&path)
            .map(Cow::Owned)
            .map_err(|e| ReleaseTrustError::io(&path, e))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::io::Cursor;
    use std::mem::{Discriminant, discriminant};
    use std::path::{Path, PathBuf};

    use ring::signature::Ed25519KeyPair;
    use tempfile::TempDir;

    use super::{
        ActiveGeneration, EPOCH_RECORD_FILE, GENERATION_PACKAGE_FILE, MATERIAL_SET_TARGET,
        REPLACE_GENERATION_CALLS, RebootstrapAuthorization, ReleaseTrustError, accept_generation,
        accept_generation_chain, active_package, active_trust_set, admit, admit_seed_generation,
        bootstrap_from_join_material, classify_pin_marker, install_generation,
        join_generation_file, material, read_active_epoch, read_generation_state,
        rebootstrap_generation, replace_generation, require_pin_marker, verify_self_admitted,
    };
    use crate::generation::{GenerationError, SYSTEMCTL_CALLS, active_link, generation_dir};
    use crate::layout::{ACTIVE_LINK, JOIN_GENERATION_FILE, Layout, REQUIRE_TRUST_PIN_MARKER};
    use crate::manifest::MAX_MANIFEST_FORMAT_VERSION;
    use crate::roxyd_trust::Activation;
    use crate::trust_fixture::{
        Fields, anchor_json, anchor_of, array, default_document, generation_pkg,
        generation_pkg_member_named, hex_of, keypair, pkg_naming, public_key_of, withdrawn_json,
    };
    use crate::trust_set::{
        TRUST_SET_MEMBER, TrustSetDocumentError, member_digest, read_trust_set_document,
    };
    use crate::verify::{TRUST_TARGET, VerifyError, VerifyRequest, key_id, verify_package};

    /// A release epoch far from any generation index, so a test asserting
    /// `gen-1` cannot pass by conflating the two.
    const SEED_EPOCH: u64 = 4711;
    /// The next generation's epoch, likewise unrelated to `gen-2`.
    const NEXT_EPOCH: u64 = 4712;
    /// A `commit`-shaped value that is not any fixture member's digest.
    const STRANGER_COMMIT: &str =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    struct Tree {
        _tmp: TempDir,
        root: PathBuf,
    }

    /// A release-trust tree root, resolved the way the layout resolves one: a
    /// directory the engine owns, holding `active` and `gen-<n>/`.
    fn tree() -> Tree {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path().join("release-trust");
        std::fs::create_dir_all(&root).expect("tree root");
        Tree { _tmp: tmp, root }
    }

    /// One well-formed generation: its document, and the container carrying it.
    struct Generation {
        member: Vec<u8>,
        package: Vec<u8>,
        epoch: u64,
    }

    impl Generation {
        /// A generation at `epoch` trusting `pair` alone and signed by it.
        fn new(pair: &Ed25519KeyPair, epoch: u64) -> Self {
            Self::from_fields(
                pair,
                &Fields {
                    epoch: Some(epoch.to_string()),
                    ..Fields::new(pair)
                },
                epoch,
            )
        }

        /// A generation whose document is `fields`, signed by `pair`.
        fn from_fields(pair: &Ed25519KeyPair, fields: &Fields, epoch: u64) -> Self {
            let member = fields.render();
            let package = generation_pkg(pair, &member, epoch);
            Self {
                member,
                package,
                epoch,
            }
        }

        fn install(
            &self,
            root: &Path,
        ) -> Result<crate::roxyd_trust::Activation, ReleaseTrustError> {
            install_generation(root, &self.package, &self.member, self.epoch)
        }
    }

    fn entries(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<OsString> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort_unstable();
        names
    }

    /// The generation directory's own basename, which is what `active` is a
    /// symlink to. Resolved through the engine's accessor rather than spelled
    /// out, so no test carries a `gen-<n>` literal either.
    fn generation_name(root: &Path, generation: u64) -> OsString {
        generation_dir(root, generation)
            .file_name()
            .expect("a generation directory has a name")
            .to_os_string()
    }

    /// Asserts `active` resolves to `gen-<generation>`.
    fn assert_active_is(root: &Path, generation: u64) {
        assert_eq!(
            std::fs::read_link(active_link(root)).expect("active symlink"),
            PathBuf::from(generation_name(root, generation)),
        );
    }

    /// Overwrites a file inside the active generation, standing in for a tree
    /// edited underneath the installer.
    fn overwrite_active(root: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(active_link(root).join(name), bytes).expect("overwrite");
    }

    /// Builds a tree by hand whose active generation holds exactly `record` as
    /// its `epoch` file, for the grammar tests that need no container at all.
    fn tree_with_record(record: &[u8]) -> Tree {
        let t = tree();
        let generation = generation_dir(&t.root, 1);
        std::fs::create_dir(&generation).expect("generation dir");
        std::fs::write(generation.join(EPOCH_RECORD_FILE), record).expect("record");
        std::os::unix::fs::symlink(generation_name(&t.root, 1), active_link(&t.root))
            .expect("active symlink");
        t
    }

    /// The tree this module drives is the layout's own, and so are the `active`
    /// link and the generation directories inside it. Asserted here because the
    /// two sides resolve through different accessors — the engine's inside this
    /// crate, the layout's for a caller — and a drift between them would put a
    /// generation somewhere no reader looks.
    #[test]
    fn the_tree_this_module_drives_is_the_one_the_layout_resolves() {
        let layout = Layout::new("clumit-security");
        let root = layout.release_trust_dir();
        assert_eq!(active_link(&root), layout.release_trust_active_dir());
        assert_eq!(
            generation_dir(&root, 3),
            layout.release_trust_generation_dir(3),
        );
    }

    /// Every engine fault reaches a caller as this tree's own I/O refusal, naming
    /// the target it was about.
    ///
    /// Four of the five are unreachable through `install_generation` — it hands
    /// the engine exactly three distinct single-component names, and supplies no
    /// unit to reload — so the mapping exists because the impl must be total.
    /// Asserting it here is what keeps a later engine change from dropping one of
    /// them onto a misleading target, or onto a variant this tree's callers do not
    /// expect an activation to produce.
    #[test]
    fn every_engine_fault_maps_onto_this_trees_io_refusal() {
        let tree_root = Layout::new("clumit-security")
            .release_trust_dir()
            .to_string_lossy()
            .into_owned();
        let unit = "clumit-security-roxyd.service";
        let faults: [(GenerationError, &str); 5] = [
            (
                GenerationError::Io {
                    path: tree_root.clone(),
                    source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                },
                &tree_root,
            ),
            (GenerationError::EmptyMaterial, MATERIAL_SET_TARGET),
            (
                GenerationError::DuplicateName(OsString::from(TRUST_SET_MEMBER)),
                TRUST_SET_MEMBER,
            ),
            (GenerationError::InvalidName(OsString::from("..")), ".."),
            (
                GenerationError::Reload {
                    unit: unit.to_string(),
                    reason: "exited with 1".to_string(),
                },
                unit,
            ),
        ];
        for (fault, target) in faults {
            let rendered = fault.to_string();
            match ReleaseTrustError::from(fault) {
                ReleaseTrustError::Io { path, .. } => assert_eq!(
                    path, target,
                    "`{rendered}` should name the target it was about",
                ),
                other => {
                    panic!("`{rendered}` mapped onto {other:?} rather than this tree's i/o refusal")
                }
            }
        }
    }

    #[test]
    fn the_material_set_is_the_three_files_in_order() {
        let files = material(b"container bytes", b"document bytes", SEED_EPOCH);
        let names: Vec<&OsString> = files.iter().map(|file| &file.name).collect();
        assert_eq!(
            names,
            vec![
                &OsString::from(GENERATION_PACKAGE_FILE),
                &OsString::from(TRUST_SET_MEMBER),
                &OsString::from(EPOCH_RECORD_FILE),
            ],
        );
        let record = files.last().expect("three files");
        assert_eq!(
            record.bytes,
            format!("{SEED_EPOCH}\n").into_bytes(),
            "the record is the decimal digits and exactly one newline",
        );
    }

    #[test]
    fn installing_a_generation_writes_exactly_the_three_material_files() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);

        SYSTEMCTL_CALLS.with_borrow_mut(Vec::clear);
        let activation = generation.install(&t.root).expect("seed");
        assert_eq!(activation.generation, 1);
        assert!(activation.changed);
        assert!(
            SYSTEMCTL_CALLS.with_borrow(Vec::is_empty),
            "a trust-set swap reloads nothing, so `reload_unit` is `None`",
        );

        let dir = generation_dir(&t.root, 1);
        assert_eq!(
            entries(&dir),
            vec![EPOCH_RECORD_FILE, GENERATION_PACKAGE_FILE, TRUST_SET_MEMBER],
            "a generation directory holds exactly the three material files",
        );
        assert_eq!(
            std::fs::read(dir.join(GENERATION_PACKAGE_FILE)).expect("read"),
            generation.package,
            "the delivered container is installed verbatim",
        );
        assert_eq!(
            std::fs::read(dir.join(TRUST_SET_MEMBER)).expect("read"),
            generation.member,
            "the verified member is copied byte for byte",
        );
        assert_eq!(
            std::fs::read(dir.join(EPOCH_RECORD_FILE)).expect("read"),
            b"4711\n",
            "the record is the ASCII decimal digits plus exactly one newline",
        );
    }

    /// The record survives the process that wrote it, which is the whole point of
    /// its being a file rather than a value in memory.
    #[test]
    fn the_recorded_epoch_is_read_back_through_the_active_link() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");

        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(SEED_EPOCH),
            "a restart reads the record back out of `active/`",
        );
    }

    #[test]
    fn successive_generations_allocate_and_prune_independently_of_the_epoch() {
        let t = tree();
        let pair = keypair();

        let seeded = Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        assert_eq!(seeded.generation, 1);
        let rotated = Generation::new(&pair, NEXT_EPOCH)
            .install(&t.root)
            .expect("rotate");
        assert_eq!(
            rotated.generation, 2,
            "`gen-<n>` is the tree's own index and is never derived from `epoch`",
        );
        assert_active_is(&t.root, 2);
        assert_eq!(
            entries(&t.root),
            vec![OsString::from(ACTIVE_LINK), generation_name(&t.root, 2)],
            "gen-1 is pruned",
        );
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(NEXT_EPOCH));
    }

    #[test]
    fn re_installing_the_byte_identical_material_allocates_no_generation() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        generation.install(&t.root).expect("seed");

        let again = generation.install(&t.root).expect("idempotent");
        assert_eq!(again.generation, 1);
        assert!(!again.changed, "the same bytes are an idempotent no-op");
        assert_eq!(
            entries(&t.root),
            vec![OsString::from(ACTIVE_LINK), generation_name(&t.root, 1)],
        );
    }

    #[test]
    fn the_epoch_reader_reports_no_prior_generation_for_an_absent_or_dangling_active() {
        let empty = tree();
        assert_eq!(
            read_active_epoch(&empty.root).expect("read"),
            None,
            "an empty tree has installed nothing",
        );

        let dangling = tree();
        std::os::unix::fs::symlink(
            generation_name(&dangling.root, 9),
            active_link(&dangling.root),
        )
        .expect("dangling link");
        assert_eq!(
            read_active_epoch(&dangling.root).expect("read"),
            None,
            "a dangling `active` is the same tree state",
        );
    }

    /// Every departure from the grammar is refused, and each fault carries its
    /// own variant so an operator learns which one the record has.
    ///
    /// The expectation is the error value itself, compared by discriminant and
    /// by its rendered payload, and the discriminants are collected so the table
    /// asserts *distinctness* rather than quietly naming one variant twice.
    #[test]
    fn the_epoch_reader_refuses_each_malformed_record_with_its_own_variant() {
        let cases: [(&[u8], ReleaseTrustError); 12] = [
            (b"0\n", ReleaseTrustError::ZeroActiveEpoch),
            (b"", ReleaseTrustError::EmptyEpochRecord),
            (b"\n", ReleaseTrustError::EmptyEpochRecord),
            (b"0471\n", ReleaseTrustError::EpochRecordLeadingZero),
            // The other way to spell zero, so no input at all yields `Some(0)`.
            (b"00\n", ReleaseTrustError::EpochRecordLeadingZero),
            (b"4711 \n", ReleaseTrustError::EpochRecordWhitespace),
            (b"4711\n4712\n", ReleaseTrustError::EpochRecordSecondLine),
            (b"4711\n\n", ReleaseTrustError::EpochRecordSecondLine),
            (b"4711", ReleaseTrustError::UnterminatedEpochRecord),
            (
                b"+4711\n",
                ReleaseTrustError::EpochRecordNonDigit { byte: b'+' },
            ),
            (
                b"forty\n",
                ReleaseTrustError::EpochRecordNonDigit { byte: b'f' },
            ),
            (
                b"18446744073709551616\n",
                ReleaseTrustError::EpochRecordOverflow,
            ),
        ];
        let mut variants: HashSet<Discriminant<ReleaseTrustError>> = HashSet::new();
        for (record, expected) in &cases {
            let t = tree_with_record(record);
            let err = read_active_epoch(&t.root).expect_err("the record should be refused");
            assert_eq!(
                format!("{err:?}"),
                format!("{expected:?}"),
                "record {:?} should be refused as {expected:?}",
                String::from_utf8_lossy(record),
            );
            variants.insert(discriminant(expected));
        }
        assert_eq!(
            variants.len(),
            8,
            "`0`, no digits, a leading zero, whitespace, a second line, a missing \
             terminator, a non-digit and an overflow are eight distinct refusals",
        );

        // A generation that resolves but holds no record at all is neither the
        // no-prior-generation state nor a grammar fault.
        let t = tree();
        let generation = generation_dir(&t.root, 1);
        std::fs::create_dir(&generation).expect("generation dir");
        std::os::unix::fs::symlink(generation_name(&t.root, 1), active_link(&t.root))
            .expect("active symlink");
        assert!(matches!(
            read_active_epoch(&t.root).expect_err("no record"),
            ReleaseTrustError::MissingEpochRecord
        ));
    }

    /// `0` is the record's most dangerous fault: the verifier admits a delivered
    /// generation strictly greater than the active one, so an active epoch read
    /// as `0` would be a floor under every generation ever minted.
    #[test]
    fn a_record_spelling_zero_is_neither_some_zero_nor_no_prior_generation() {
        let t = tree_with_record(b"0\n");
        let err = read_active_epoch(&t.root).expect_err("`0` is refused");
        assert!(matches!(err, ReleaseTrustError::ZeroActiveEpoch));
        assert_ne!(
            discriminant(&err),
            discriminant(&ReleaseTrustError::EpochRecordLeadingZero),
            "`0` is not the leading-zero fault",
        );

        // And the admission constructor over that same tree refuses too, rather
        // than building a trust set whose active epoch is `0`.
        assert!(matches!(
            active_trust_set(&t.root).expect_err("the tree is refused"),
            ReleaseTrustError::ZeroActiveEpoch
        ));
    }

    /// The state an interrupted activation leaves behind: `gen-<n>` finalised on
    /// disk, `active` still on the previous generation. A directory at the
    /// engine's reserved `active.tmp` scratch name is how a test reaches it,
    /// since clearing that name is a `remove_file`.
    #[test]
    fn a_finalised_but_unswapped_generation_leaves_the_record_and_the_document_agreeing() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");

        let scratch = t.root.join("active.tmp");
        std::fs::create_dir(&scratch).expect("scratch directory");
        Generation::new(&pair, NEXT_EPOCH)
            .install(&t.root)
            .expect_err("the swap fails after finalising");

        assert_active_is(&t.root, 1);
        assert!(
            generation_dir(&t.root, 2).is_dir(),
            "gen-2 was finalised and is on disk, unreferenced",
        );
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(SEED_EPOCH),
            "the readable record still names the previous generation",
        );
        let active = active_trust_set(&t.root).expect("the previous generation still resolves");
        assert_eq!(active.anchors().len(), 1);

        // A subsequent installation supersedes it, and at no point did the
        // readable record name a different epoch than the readable document.
        std::fs::remove_dir(&scratch).expect("clear the scratch name");
        let rotated = Generation::new(&pair, NEXT_EPOCH)
            .install(&t.root)
            .expect("rotate");
        assert_eq!(rotated.generation, 3);
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(NEXT_EPOCH));
    }

    /// A validator refusal is fail-closed: the staging copy is removed and
    /// `active` is byte-identical to what it was.
    fn assert_unchanged_after_refusal(root: &Path, before: &[u8]) {
        assert_eq!(
            entries(root),
            vec![OsString::from(ACTIVE_LINK), generation_name(root, 1)],
            "the rejected staging copy is removed and no generation was finalised",
        );
        assert_active_is(root, 1);
        assert_eq!(
            std::fs::read(active_link(root).join(TRUST_SET_MEMBER)).expect("read"),
            before,
            "the live material is byte-identical",
        );
    }

    #[test]
    fn a_staged_epoch_that_disagrees_with_the_staged_document_fails_in_the_validator() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");

        let next = Generation::new(&pair, NEXT_EPOCH);
        let err = install_generation(&t.root, &next.package, &next.member, NEXT_EPOCH + 1)
            .expect_err("the record disagrees with the document");
        assert!(
            matches!(
                err,
                ReleaseTrustError::EpochDisagreement { record, document }
                    if record == NEXT_EPOCH + 1 && document == NEXT_EPOCH
            ),
            "got {err:?}",
        );
        assert_unchanged_after_refusal(&t.root, &before);
    }

    /// The writer renders whatever `u64` it is handed, so a caller passing `0`
    /// would stage a record the reader refuses. The validator catches it on the
    /// staged copy, before anything is finalised, which is what makes `0`
    /// unreachable as an *active* epoch rather than merely unlikely.
    #[test]
    fn a_staged_record_spelling_zero_is_refused_before_anything_is_finalised() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");

        let next = Generation::new(&pair, NEXT_EPOCH);
        let err = install_generation(&t.root, &next.package, &next.member, 0)
            .expect_err("`0` is not an epoch");
        assert!(
            matches!(err, ReleaseTrustError::ZeroActiveEpoch),
            "got {err:?}",
        );
        assert_unchanged_after_refusal(&t.root, &before);
    }

    /// The copied document is checked against the copied container, not against
    /// the caller's buffer: a member that is not the container's own fails on the
    /// digest the manifest signed.
    #[test]
    fn a_staged_document_that_is_not_the_containers_member_fails_in_the_validator() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");

        // The container carries one document; the caller stages another, at the
        // same epoch, so only the digest can tell them apart.
        let carried = Generation::new(&pair, NEXT_EPOCH);
        let other = Fields {
            epoch: Some(NEXT_EPOCH.to_string()),
            withdrawn_builds: Some(array(&[withdrawn_json("example", "1.0.0", "abc")])),
            ..Fields::new(&pair)
        }
        .render();
        assert_ne!(other, carried.member);

        let err = install_generation(&t.root, &carried.package, &other, NEXT_EPOCH)
            .expect_err("the staged document is not the container's member");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Verify(VerifyError::TargetMismatch { .. })
            ),
            "got {err:?}",
        );
        assert_unchanged_after_refusal(&t.root, &before);
    }

    /// A staged member nothing can be decoded out of is refused as the admission
    /// attempt it is, never dressed up as a verdict about a real generation: at
    /// this point in the sequence no anchor has vouched for those bytes.
    #[test]
    fn a_staged_document_that_does_not_decode_before_verification_is_refused() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");

        let carried = Generation::new(&pair, NEXT_EPOCH);
        let err = install_generation(&t.root, &carried.package, b"not a document", NEXT_EPOCH)
            .expect_err("no candidate set can be built from these bytes");
        assert!(
            matches!(err, ReleaseTrustError::ProvisionalDecode),
            "an unauthenticated parse failure is not a document refusal, got {err:?}",
        );
        assert_unchanged_after_refusal(&t.root, &before);
    }

    /// The counterpart to the revoked-signer case: a signer its own document does
    /// not list at all is the unknown-key fault, which is what makes `RevokedKey`
    /// there evidence that the `revoked` flags travelled rather than that the
    /// anchor was simply missing.
    #[test]
    fn a_container_signed_by_a_key_its_own_document_does_not_name_is_refused_as_unknown() {
        let t = tree();
        let live = keypair();
        Generation::new(&live, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");

        // The document trusts `live` alone; a stranger signs the container.
        let stranger = keypair();
        let member = Fields {
            epoch: Some(NEXT_EPOCH.to_string()),
            ..Fields::new(&live)
        }
        .render();
        let package = generation_pkg(&stranger, &member, NEXT_EPOCH);

        let err = install_generation(&t.root, &package, &member, NEXT_EPOCH)
            .expect_err("the signer is in no anchor of its own document");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Verify(VerifyError::UnknownKeyId { key_id: ref id })
                    if *id == key_id(&public_key_of(&stranger))
            ),
            "got {err:?}",
        );
        assert_unchanged_after_refusal(&t.root, &before);
    }

    #[test]
    fn a_container_signed_by_a_key_its_own_document_marks_revoked_is_refused_as_revoked() {
        let t = tree();
        let live = keypair();
        Generation::new(&live, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");

        let revoked = keypair();
        let fields = Fields {
            epoch: Some(NEXT_EPOCH.to_string()),
            anchors: Some(array(&[anchor_of(&live, false), anchor_of(&revoked, true)])),
            ..Fields::new(&live)
        };
        let member = fields.render();
        let package = generation_pkg(&revoked, &member, NEXT_EPOCH);

        let err = install_generation(&t.root, &package, &member, NEXT_EPOCH)
            .expect_err("the signer is revoked by its own document");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Verify(VerifyError::RevokedKey { key_id: ref id })
                    if *id == key_id(&public_key_of(&revoked))
            ),
            "the staged anchors' `revoked` flags reach the candidate set, got {err:?}",
        );
        assert_unchanged_after_refusal(&t.root, &before);
    }

    /// The candidate set's `0` floor, observable at the tree level: a document
    /// declaring a floor above its own envelope's `format_version` would brick
    /// itself if the validator honoured it, and the admission path would have
    /// accepted it.
    #[test]
    fn a_document_declaring_a_floor_above_its_own_envelope_installs() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::from_fields(
            &pair,
            &Fields {
                epoch: Some(SEED_EPOCH.to_string()),
                min_manifest_format_version: Some((MAX_MANIFEST_FORMAT_VERSION + 1).to_string()),
                ..Fields::new(&pair)
            },
            SEED_EPOCH,
        );
        let activation = generation
            .install(&t.root)
            .expect("the floor governs later packages");
        assert_eq!(activation.generation, 1);
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(SEED_EPOCH));
    }

    /// The candidate set's empty withdrawn list, observable at the tree level.
    ///
    /// A document cannot literally name its own member digest — the digest is
    /// over bytes that would then have to contain it — so the self-withdrawal is
    /// observed against a container whose manifest names a `commit` the document
    /// *can* state. The empty list is what carries it past the withdrawal check:
    /// the refusal that arrives is the target disagreement one step later, never
    /// `WithdrawnBuild`. A document withdrawing an unrelated build then installs
    /// whole.
    #[test]
    fn a_declared_withdrawn_list_does_not_govern_the_envelope_carrying_it() {
        let t = tree();
        let pair = keypair();
        let member = Fields {
            epoch: Some(SEED_EPOCH.to_string()),
            withdrawn_builds: Some(array(&[withdrawn_json(
                TRUST_TARGET,
                &SEED_EPOCH.to_string(),
                STRANGER_COMMIT,
            )])),
            ..Fields::new(&pair)
        }
        .render();
        let package = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &SEED_EPOCH.to_string(),
            STRANGER_COMMIT,
        );
        let err = install_generation(&t.root, &package, &member, SEED_EPOCH)
            .expect_err("the manifest's commit is not the member digest");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Verify(VerifyError::TargetMismatch { .. })
            ),
            "the withdrawal check is the identity here, got {err:?}",
        );
        assert!(!generation_dir(&t.root, 1).exists());

        let generation = Generation::from_fields(
            &pair,
            &Fields {
                epoch: Some(SEED_EPOCH.to_string()),
                withdrawn_builds: Some(array(&[withdrawn_json("example", "1.0.0", "abc")])),
                ..Fields::new(&pair)
            },
            SEED_EPOCH,
        );
        generation
            .install(&t.root)
            .expect("the withdrawn list governs later packages only");
    }

    #[test]
    fn the_admission_constructor_refuses_a_tree_whose_record_and_document_disagree() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");

        overwrite_active(&t.root, EPOCH_RECORD_FILE, b"4712\n");
        assert!(matches!(
            active_trust_set(&t.root).expect_err("the tree was edited underneath the installer"),
            ReleaseTrustError::EpochDisagreement { record, document }
                if record == NEXT_EPOCH && document == SEED_EPOCH
        ));
    }

    #[test]
    fn the_admission_constructor_propagates_the_readers_own_refusal() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");

        overwrite_active(&t.root, TRUST_SET_MEMBER, br#"{"trust_set_version":"1"}"#);
        assert!(
            matches!(
                active_trust_set(&t.root).expect_err("the document is malformed"),
                ReleaseTrustError::Document(TrustSetDocumentError::MalformedVersion),
            ),
            "the reader's own named refusal reaches the caller",
        );
    }

    /// The counterpart to [`ReleaseTrustError::MissingEpochRecord`]: a
    /// generation the record resolves in, whose document has gone underneath the
    /// installer. That is an I/O fault about a real generation, not the
    /// no-generation tree state.
    #[test]
    fn the_admission_constructor_refuses_a_generation_whose_document_is_gone() {
        let t = tree();
        let pair = keypair();
        Generation::new(&pair, SEED_EPOCH)
            .install(&t.root)
            .expect("seed");

        std::fs::remove_file(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("remove");
        assert!(matches!(
            active_trust_set(&t.root).expect_err("the document is gone"),
            ReleaseTrustError::Io { .. }
        ));
    }

    #[test]
    fn the_admission_constructor_refuses_an_empty_tree() {
        let t = tree();
        assert!(matches!(
            active_trust_set(&t.root).expect_err("nothing is installed"),
            ReleaseTrustError::NoActiveGeneration
        ));
    }

    /// The output is the value the verifier takes, so the assertion is that it
    /// drives a real verification: an authentic package is accepted, and one
    /// signed by an anchor the generation marks revoked comes back
    /// `RevokedKey`.
    #[test]
    fn the_admission_constructors_output_drives_the_shared_verifier() {
        let t = tree();
        let live = keypair();
        let revoked = keypair();
        let generation = Generation::from_fields(
            &live,
            &Fields {
                epoch: Some(SEED_EPOCH.to_string()),
                anchors: Some(array(&[anchor_of(&live, false), anchor_of(&revoked, true)])),
                ..Fields::new(&live)
            },
            SEED_EPOCH,
        );
        generation.install(&t.root).expect("seed");

        let trust = active_trust_set(&t.root).expect("the active generation resolves");
        assert_eq!(trust.anchors().len(), 2);

        // An ordinary package the live anchor signed.
        let payload = default_document(&live);
        let commit = member_digest(&payload);
        let request =
            VerifyRequest::for_package("example", "1.0.0", &commit).expect("a package request");
        let authentic = pkg_naming(&live, &payload, "example", "1.0.0", &commit);
        verify_package(Cursor::new(authentic), &trust, &request).expect("the package verifies");

        let by_revoked = pkg_naming(&revoked, &payload, "example", "1.0.0", &commit);
        assert!(matches!(
            verify_package(Cursor::new(by_revoked), &trust, &request)
                .expect_err("the signer is revoked"),
            VerifyError::RevokedKey { key_id: id } if id == key_id(&public_key_of(&revoked))
        ));
    }

    /// The document is honoured in full here, unlike in the installer's candidate
    /// set: its withdrawn list and its declared floor are what govern every later
    /// package.
    #[test]
    fn the_admission_constructor_honours_the_documents_withdrawn_list() {
        let t = tree();
        let pair = keypair();
        let payload = default_document(&pair);
        let commit = member_digest(&payload);
        let generation = Generation::from_fields(
            &pair,
            &Fields {
                epoch: Some(SEED_EPOCH.to_string()),
                withdrawn_builds: Some(array(&[withdrawn_json("example", "1.0.0", &commit)])),
                ..Fields::new(&pair)
            },
            SEED_EPOCH,
        );
        generation.install(&t.root).expect("seed");

        let trust = active_trust_set(&t.root).expect("the active generation resolves");
        let request =
            VerifyRequest::for_package("example", "1.0.0", &commit).expect("a package request");
        let package = pkg_naming(&pair, &payload, "example", "1.0.0", &commit);
        assert!(matches!(
            verify_package(Cursor::new(package), &trust, &request)
                .expect_err("the build is withdrawn"),
            VerifyError::WithdrawnBuild { .. }
        ));
    }

    // The two install-time doors. The installer's validator already runs this
    // same sequence over staged bytes, and the suite above proves at that level
    // what the sequence decides; what follows tests what the doors add.

    /// The refusal a table-driven case expects, as a predicate over the error:
    /// two nested variants share an outer discriminant, so the assertion is a
    /// pattern rather than a comparison.
    type Refusal = fn(&ReleaseTrustError) -> bool;

    /// A document trusting `pair` alone at `epoch`, as the fixture renders it.
    fn document_at(pair: &Ed25519KeyPair, epoch: u64) -> Vec<u8> {
        Fields {
            epoch: Some(epoch.to_string()),
            ..Fields::new(pair)
        }
        .render()
    }

    /// A directory nobody else writes into, handed to `admit` as the parent its
    /// extraction scratch is created inside. A test cannot inspect the shared
    /// system temporary directory while other tests run beside it, and it must
    /// not steer `TMPDIR` by mutating the process environment, so the parameter
    /// is how the cleanup contract is observed at all.
    fn scratch() -> TempDir {
        TempDir::new().expect("scratch parent")
    }

    /// Flips a byte of the container's zstd archive frame, leaving the manifest,
    /// the signature and every offset the footer records where they were, so the
    /// container still opens and the failure falls inside the archive walk.
    fn corrupt_archive(package: &[u8]) -> Vec<u8> {
        const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
        let at = package
            .windows(ZSTD_MAGIC.len())
            .position(|window| window == ZSTD_MAGIC)
            .expect("the archive block is a zstd frame")
            + ZSTD_MAGIC.len();
        let mut out = package.to_vec();
        let byte = out
            .get_mut(at)
            .expect("the frame carries a header after its magic");
        *byte ^= 0xff;
        out
    }

    /// Rewrites the artifact `version` the **signed** manifest records, in place
    /// and at the same length, so every offset the footer holds still points
    /// where it did and the only thing that changed is material the signature
    /// covers.
    fn mutate_signed_version(package: &[u8], from: u64, to: u64) -> Vec<u8> {
        let needle = format!(r#""version":"{from}""#);
        let replacement = format!(r#""version":"{to}""#);
        assert_eq!(needle.len(), replacement.len(), "an in-place rewrite");
        let at = package
            .windows(needle.len())
            .position(|window| window == needle.as_bytes())
            .expect("the manifest records the artifact's version");
        let mut out = package.to_vec();
        out.splice(at..at + replacement.len(), replacement.into_bytes());
        out
    }

    /// The tree root's entries, with nothing installed.
    fn assert_nothing_installed(root: &Path, expected: &[OsString]) {
        assert_eq!(entries(root), expected, "no generation was allocated");
    }

    #[test]
    fn the_seed_admits_a_generation_onto_an_empty_tree() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);

        let admitted = admit_seed_generation(&t.root, &generation.package).expect("seed");
        assert_eq!(admitted.activation.generation, 1);
        assert!(admitted.activation.changed, "the tree was empty");
        assert_eq!(admitted.epoch, SEED_EPOCH);
        assert_eq!(admitted.document.epoch, SEED_EPOCH);
        assert_eq!(admitted.document.anchors.len(), 1);

        assert_active_is(&t.root, 1);
        let active = active_link(&t.root);
        assert_eq!(
            std::fs::read(active.join(TRUST_SET_MEMBER)).expect("read"),
            generation.member,
            "the stored document is the container's own member, byte for byte",
        );
        assert_eq!(
            std::fs::read(active.join(GENERATION_PACKAGE_FILE)).expect("read"),
            generation.package,
            "the delivered container is stored verbatim",
        );
        assert_eq!(
            std::fs::read(active.join(EPOCH_RECORD_FILE)).expect("read"),
            format!("{SEED_EPOCH}\n").into_bytes(),
        );
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(admitted.epoch),
            "the returned epoch is the one actually recorded",
        );
    }

    /// Neither the extracted member nor the directory it was extracted into
    /// survives the call, on the successful path and on a refused one alike.
    #[test]
    fn admission_leaves_the_scratch_directory_it_was_given_empty() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        let scratch = scratch();

        admit(&t.root, &generation.package, Some(scratch.path())).expect("seed");
        assert!(
            entries(scratch.path()).is_empty(),
            "a successful admission leaves nothing behind",
        );

        let corrupt = corrupt_archive(&generation.package);
        crate::payload::open_package(Cursor::new(&corrupt))
            .expect("the container still opens, so the failure falls inside the walk");
        admit(&t.root, &corrupt, Some(scratch.path())).expect_err("the archive walk cannot finish");
        assert!(
            entries(scratch.path()).is_empty(),
            "a refusal mid-walk leaves nothing behind either",
        );

        // And a refusal *after* the walk succeeded, which is the case a
        // temporary directory hoisted out of `extract_member` would leak: the
        // member is extracted whole and the sequence refuses it two steps later.
        let undecodable = generation_pkg(&pair, b"not a document", SEED_EPOCH);
        let err = admit(&t.root, &undecodable, Some(scratch.path()))
            .expect_err("no candidate set can be built from these bytes");
        assert!(
            matches!(err, ReleaseTrustError::ProvisionalDecode),
            "got {err:?}",
        );
        assert!(
            entries(scratch.path()).is_empty(),
            "a refusal past the walk leaves nothing behind either",
        );
    }

    /// The container walks whole and is internally consistent; what it does not
    /// carry is a document to admit. Refused before a candidate set is built,
    /// which the second case pins: bytes nothing could be decoded out of still
    /// arrive as the missing-member refusal rather than as a decode one.
    #[test]
    fn a_container_carrying_no_trust_set_document_is_refused_before_any_candidate_set() {
        let pair = keypair();
        for member in [document_at(&pair, SEED_EPOCH), b"not a document".to_vec()] {
            let t = tree();
            let package =
                generation_pkg_member_named(&pair, &member, SEED_EPOCH, "release-trust.json");
            let err = admit_seed_generation(&t.root, &package)
                .expect_err("the container carries no trust-set document");
            assert!(
                matches!(err, ReleaseTrustError::MissingTrustSetMember),
                "got {err:?}",
            );
            assert_nothing_installed(&t.root, &[]);
        }
    }

    /// `MissingTrustSetMember` is the *only* container-layer refusal this work
    /// names. Everything else the container layer decides — bytes that are no
    /// container at all, and an archive block that cannot be walked to its end —
    /// arrives through the existing `PayloadError` mapping as the verifier's own
    /// refusal, with no variant added here to carry it.
    #[test]
    fn every_other_container_fault_arrives_through_the_existing_verifier_mapping() {
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        let corrupt = corrupt_archive(&generation.package);
        crate::payload::open_package(Cursor::new(&corrupt))
            .expect("the container still opens, so the failure falls inside the walk");

        for package in [b"not a container".as_slice(), &corrupt] {
            let t = tree();
            let err = admit_seed_generation(&t.root, package)
                .expect_err("the container layer refuses these bytes");
            assert!(
                matches!(err, ReleaseTrustError::Verify(VerifyError::Payload(_))),
                "got {err:?}",
            );
            assert_nothing_installed(&t.root, &[]);
        }
    }

    /// Material mutated after it was signed is refused by the signature, not by
    /// the reader: the pre-verification decode ran over the delivered document
    /// and decided nothing.
    #[test]
    fn a_container_mutated_after_signing_is_refused_by_the_signature() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        let mutated = mutate_signed_version(&generation.package, SEED_EPOCH, NEXT_EPOCH);
        assert_ne!(mutated, generation.package);

        let err = admit_seed_generation(&t.root, &mutated)
            .expect_err("the signature no longer covers this manifest");
        assert!(
            matches!(err, ReleaseTrustError::Verify(VerifyError::BadSignature)),
            "got {err:?}",
        );
        assert_nothing_installed(&t.root, &[]);
    }

    /// Two anchors sharing a `public_key` are the candidate set's own refusal, so
    /// they arrive as the one variant every pre-verification decode fault does —
    /// never as a reader refusal about bytes nothing has vouched for.
    #[test]
    fn a_document_repeating_a_public_key_is_refused_as_a_provisional_decode() {
        let t = tree();
        let pair = keypair();
        let stranger = keypair();
        let shared = hex_of(&public_key_of(&pair));
        let member = Fields {
            epoch: Some(SEED_EPOCH.to_string()),
            anchors: Some(array(&[
                anchor_json(&key_id(&public_key_of(&pair)), &shared, false),
                anchor_json(&key_id(&public_key_of(&stranger)), &shared, false),
            ])),
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, SEED_EPOCH);

        let err = admit_seed_generation(&t.root, &package)
            .expect_err("no candidate set can be built from two entries sharing a key");
        assert!(
            matches!(err, ReleaseTrustError::ProvisionalDecode),
            "got {err:?}",
        );
        assert_nothing_installed(&t.root, &[]);
    }

    /// The decode reads no `key_id` at all, so a document repeating one across
    /// entries with *different* keys builds a candidate set, verifies, and is
    /// refused by the reader instead.
    #[test]
    fn a_document_repeating_a_key_id_string_reaches_the_refusing_reader() {
        let t = tree();
        let pair = keypair();
        let stranger = keypair();
        let member = Fields {
            epoch: Some(SEED_EPOCH.to_string()),
            anchors: Some(array(&[
                anchor_of(&pair, false),
                anchor_json(
                    &key_id(&public_key_of(&pair)),
                    &hex_of(&public_key_of(&stranger)),
                    false,
                ),
            ])),
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, SEED_EPOCH);

        let err = admit_seed_generation(&t.root, &package)
            .expect_err("the second entry's `key_id` is not derived from its key");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Document(TrustSetDocumentError::KeyIdMismatch { .. }),
            ),
            "got {err:?}",
        );
        assert_nothing_installed(&t.root, &[]);
    }

    /// The provisional `epoch` becomes the request's `version`, checked against
    /// the **signed** manifest, so a document disagreeing with the envelope
    /// carrying it can only fail.
    #[test]
    fn a_document_whose_epoch_disagrees_with_its_manifest_is_refused_as_a_target_mismatch() {
        let t = tree();
        let pair = keypair();
        let member = document_at(&pair, SEED_EPOCH);
        let package = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &NEXT_EPOCH.to_string(),
            &member_digest(&member),
        );

        let err =
            admit_seed_generation(&t.root, &package).expect_err("the manifest names another epoch");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Verify(VerifyError::TargetMismatch { .. })
            ),
            "got {err:?}",
        );
        assert_nothing_installed(&t.root, &[]);
    }

    /// The decode reads exactly `anchors` and `epoch`, so an unknown field is the
    /// refusing reader's verdict about verified bytes and never the decode's.
    #[test]
    fn a_document_carrying_an_unknown_field_is_refused_by_the_reader() {
        let t = tree();
        let pair = keypair();
        let member = Fields {
            epoch: Some(SEED_EPOCH.to_string()),
            extra: vec![r#""surprise":true"#.to_string()],
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, SEED_EPOCH);

        let err = admit_seed_generation(&t.root, &package)
            .expect_err("the document carries a field this reader cannot account for");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Document(TrustSetDocumentError::UnknownField { .. }),
            ),
            "got {err:?}",
        );
        assert_nothing_installed(&t.root, &[]);
    }

    /// Neither door reaches the verifier's epoch branch: the self-admission
    /// request carries no delivered epoch, so `0` is answered by the reader's own
    /// absent-or-zero variant rather than as a stale trust set.
    #[test]
    fn a_document_whose_epoch_is_zero_is_refused_by_the_reader_and_never_as_stale() {
        let t = tree();
        let pair = keypair();
        let member = Fields {
            epoch: Some("0".to_string()),
            ..Fields::new(&pair)
        }
        .render();
        let package = generation_pkg(&pair, &member, 0);

        let err = admit_seed_generation(&t.root, &package).expect_err("`0` is not an epoch");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Document(TrustSetDocumentError::AbsentEpoch),
            ),
            "got {err:?}",
        );
        assert_nothing_installed(&t.root, &[]);
    }

    /// No floor is applied where no prior epoch exists, which is the seed's whole
    /// premise.
    #[test]
    fn the_seed_admits_an_arbitrarily_low_epoch_onto_an_empty_tree() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, 1);

        let admitted = admit_seed_generation(&t.root, &generation.package).expect("seed");
        assert_eq!(admitted.epoch, 1);
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(1));
    }

    /// The gate is a precondition on tree state, so it refuses alike whether the
    /// delivered epoch is below, equal to or above the recorded one — and alike
    /// for the byte-identical container that produced the active generation,
    /// because no identity exemption exists.
    #[test]
    fn the_seed_refuses_a_tree_that_already_carries_an_active_generation() {
        let t = tree();
        let pair = keypair();
        let seeded = Generation::new(&pair, SEED_EPOCH);
        admit_seed_generation(&t.root, &seeded.package).expect("seed");
        let before = std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read");
        let live = vec![OsString::from(ACTIVE_LINK), generation_name(&t.root, 1)];

        let lower = Generation::new(&pair, SEED_EPOCH - 1);
        let higher = Generation::new(&pair, NEXT_EPOCH);
        for delivered in [&lower.package, &seeded.package, &higher.package] {
            let err = admit_seed_generation(&t.root, delivered)
                .expect_err("the tree already carries a generation");
            assert!(
                matches!(
                    err,
                    ReleaseTrustError::ActiveGenerationPresent {
                        generation: Some(1)
                    }
                ),
                "got {err:?}",
            );
            assert_nothing_installed(&t.root, &live);
        }

        assert_active_is(&t.root, 1);
        assert_eq!(
            std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read"),
            before,
            "the live material is byte-identical",
        );
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(SEED_EPOCH),
            "the reader tells a caller that may run twice that this host is seeded",
        );
    }

    /// The refusal must not be implemented by reading the record: a malformed or
    /// absent `epoch` file is still a tree that carries a generation, and turning
    /// that into a grammar refusal would answer a different question.
    #[test]
    fn the_seeds_refusal_reads_no_epoch_record() {
        let pair = keypair();
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        let malformed = tree();
        admit_seed_generation(&malformed.root, &Generation::new(&pair, SEED_EPOCH).package)
            .expect("seed");
        overwrite_active(&malformed.root, EPOCH_RECORD_FILE, b"not an epoch\n");

        let absent = tree();
        admit_seed_generation(&absent.root, &Generation::new(&pair, SEED_EPOCH).package)
            .expect("seed");
        std::fs::remove_file(active_link(&absent.root).join(EPOCH_RECORD_FILE)).expect("remove");

        for root in [&malformed.root, &absent.root] {
            let err = admit_seed_generation(root, &delivered.package)
                .expect_err("the tree already carries a generation");
            assert!(
                matches!(
                    err,
                    ReleaseTrustError::ActiveGenerationPresent {
                        generation: Some(1)
                    }
                ),
                "got {err:?}",
            );
        }
    }

    /// `active` resolving to something this crate did not write is a stronger
    /// reason to keep the seed door shut, not a weaker one, so the refusal is the
    /// same and only the index it can name is `None`.
    #[test]
    fn the_seed_refuses_an_active_that_names_no_canonical_generation() {
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);

        // A symlink to a directory the engine would never have written.
        let linked = tree();
        std::fs::create_dir(linked.root.join("elsewhere")).expect("a directory of its own");
        std::os::unix::fs::symlink("elsewhere", active_link(&linked.root)).expect("link");

        // And an `active` that is a real directory, where reading the link fails
        // outright.
        let real = tree();
        std::fs::create_dir(active_link(&real.root)).expect("a real directory");

        for t in [&linked, &real] {
            let before = entries(&t.root);
            let err = admit_seed_generation(&t.root, &generation.package)
                .expect_err("`active` resolves to something");
            assert!(
                matches!(
                    err,
                    ReleaseTrustError::ActiveGenerationPresent { generation: None }
                ),
                "got {err:?}",
            );
            assert_nothing_installed(&t.root, &before);
        }
    }

    /// A dangling `active` has installed nothing, so it is on the open side of
    /// the gate — the same side [`read_active_epoch`] puts it on, which is what
    /// lets a caller decide "seed if unseeded" from that reader alone.
    #[test]
    fn the_seed_admits_a_dangling_active_exactly_where_the_epoch_reader_reports_none() {
        let t = tree();
        std::os::unix::fs::symlink(generation_name(&t.root, 9), active_link(&t.root))
            .expect("dangling link");
        assert_eq!(read_active_epoch(&t.root).expect("read"), None);

        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        let admitted = admit_seed_generation(&t.root, &generation.package)
            .expect("a dangling `active` is an unseeded tree");
        assert!(admitted.activation.changed);
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(SEED_EPOCH));
    }

    /// One pair of calls over identical inputs: the tree-state precondition is
    /// the only difference between the two doors.
    #[test]
    fn the_replace_door_admits_the_tree_the_seed_refuses() {
        let t = tree();
        let pair = keypair();
        admit_seed_generation(&t.root, &Generation::new(&pair, SEED_EPOCH).package).expect("seed");
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        assert!(matches!(
            admit_seed_generation(&t.root, &delivered.package).expect_err("the seed refuses"),
            ReleaseTrustError::ActiveGenerationPresent {
                generation: Some(1)
            }
        ));

        let admitted = replace_generation(&t.root, &delivered.package).expect("replace");
        assert_eq!(admitted.activation.generation, 2);
        assert!(admitted.activation.changed);
        assert_eq!(admitted.epoch, NEXT_EPOCH);
        assert_active_is(&t.root, 2);
        assert_eq!(
            std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read"),
            delivered.member,
        );
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(NEXT_EPOCH));
    }

    /// On an empty tree the seed applies no floor either, so on that input the
    /// two doors do exactly the same thing rather than one of them erroring. The
    /// replace door gates on the tree being non-empty no more than on it being
    /// empty.
    #[test]
    fn the_replace_door_admits_an_empty_tree_exactly_as_the_seed_does() {
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);

        let seeded = tree();
        let by_seed = admit_seed_generation(&seeded.root, &generation.package).expect("seed");
        let replaced = tree();
        let by_replace = replace_generation(&replaced.root, &generation.package).expect("replace");
        assert_eq!(by_seed, by_replace, "the same activated generation");
        assert_eq!(
            read_active_epoch(&seeded.root).expect("read"),
            read_active_epoch(&replaced.root).expect("read"),
        );

        // And onto a tree whose `active` names no canonical generation, which the
        // seed refuses.
        let odd = tree();
        std::fs::create_dir(odd.root.join("elsewhere")).expect("a directory of its own");
        std::os::unix::fs::symlink("elsewhere", active_link(&odd.root)).expect("link");
        let admitted = replace_generation(&odd.root, &generation.package).expect("replace");
        assert!(admitted.activation.changed);
        assert_active_is(&odd.root, 1);
    }

    /// The one tree state on which the two doors refuse for different reasons.
    /// The engine reads `active` as a link before it allocates anything, and that
    /// read fails with `EINVAL` rather than `NotFound`, so replace fails inside
    /// the engine. This pins existing engine behaviour: neither door repairs it,
    /// and both refuse.
    #[test]
    fn an_active_that_is_a_real_directory_refuses_at_the_gate_and_inside_the_engine() {
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);

        let seeded = tree();
        std::fs::create_dir(active_link(&seeded.root)).expect("a real directory");
        assert!(matches!(
            admit_seed_generation(&seeded.root, &generation.package)
                .expect_err("`active` resolves"),
            ReleaseTrustError::ActiveGenerationPresent { generation: None }
        ));
        assert_nothing_installed(&seeded.root, &[OsString::from(ACTIVE_LINK)]);

        let replaced = tree();
        std::fs::create_dir(active_link(&replaced.root)).expect("a real directory");
        let err = replace_generation(&replaced.root, &generation.package)
            .expect_err("`active` cannot be read as a link");
        assert!(matches!(err, ReleaseTrustError::Io { .. }), "got {err:?}");
        assert_nothing_installed(&replaced.root, &[OsString::from(ACTIVE_LINK)]);
    }

    /// The wedged-host recovery: a generation minted at a wrongly-high epoch is
    /// replaced by a legitimate lower one, and the recorded epoch afterwards is
    /// the delivered one. A replace that refused this would refuse the case it
    /// exists for.
    #[test]
    fn the_replace_door_admits_an_epoch_below_the_recorded_one() {
        let t = tree();
        let pair = keypair();
        admit_seed_generation(&t.root, &Generation::new(&pair, NEXT_EPOCH).package).expect("seed");

        let admitted = replace_generation(&t.root, &Generation::new(&pair, SEED_EPOCH).package)
            .expect("no floor is applied in either direction");
        assert_eq!(admitted.epoch, SEED_EPOCH);
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(SEED_EPOCH),
            "the recorded epoch moved down",
        );
    }

    /// Dropping the gate drops the gate and nothing else: every other refusal is
    /// the seed's, against the same variant.
    #[test]
    fn the_replace_door_refuses_everything_the_seed_refuses_past_the_gate() {
        let pair = keypair();
        let revoked = keypair();

        let malformed = generation_pkg(&pair, b"not a document", SEED_EPOCH);

        let by_revoked_member = Fields {
            epoch: Some(SEED_EPOCH.to_string()),
            anchors: Some(array(&[anchor_of(&pair, false), anchor_of(&revoked, true)])),
            ..Fields::new(&pair)
        }
        .render();
        let by_revoked = generation_pkg(&revoked, &by_revoked_member, SEED_EPOCH);

        let member = document_at(&pair, SEED_EPOCH);
        let mismatched = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &NEXT_EPOCH.to_string(),
            &member_digest(&member),
        );

        let cases: [(&[u8], Refusal, &str); 3] = [
            (
                &malformed,
                |err| matches!(err, ReleaseTrustError::ProvisionalDecode),
                "a pre-verification decode refusal",
            ),
            (
                &by_revoked,
                |err| {
                    matches!(
                        err,
                        ReleaseTrustError::Verify(VerifyError::RevokedKey { .. })
                    )
                },
                "a revoked signer",
            ),
            (
                &mismatched,
                |err| {
                    matches!(
                        err,
                        ReleaseTrustError::Verify(VerifyError::TargetMismatch { .. })
                    )
                },
                "an epoch/manifest disagreement",
            ),
        ];
        for (package, is_expected, expected) in cases {
            let seeded = tree();
            let replaced = tree();
            let by_seed = admit_seed_generation(&seeded.root, package).expect_err("refused");
            let by_replace = replace_generation(&replaced.root, package).expect_err("refused");
            for (door, err) in [("the seed", &by_seed), ("replace", &by_replace)] {
                assert!(
                    is_expected(err),
                    "{door} should refuse {expected}, got {err:?}",
                );
            }
            assert_nothing_installed(&replaced.root, &[]);
        }
    }

    /// The `require-trust-pin` marker governs the runtime re-bootstrap, not this
    /// path: an install-time replace is the operator standing in the delivery
    /// channel's place, so consulting it here would demand an out-of-band pin
    /// from the very party the marker exists to trust.
    #[test]
    fn the_pin_marker_changes_nothing_about_a_replace() {
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);

        let plain = tree();
        let without = replace_generation(&plain.root, &generation.package).expect("replace");

        let pinned = tree();
        let marker = pinned.root.join(REQUIRE_TRUST_PIN_MARKER);
        assert_eq!(
            marker,
            Layout::new("clumit-security")
                .require_pin_marker()
                .file_name()
                .map(|name| pinned.root.join(name))
                .expect("the marker has a name"),
            "the marker this test writes is the one the layout resolves",
        );
        std::fs::write(&marker, b"").expect("marker");
        let with = replace_generation(&pinned.root, &generation.package).expect("replace");

        assert_eq!(without, with, "the marker decides nothing here");
        assert!(marker.is_file(), "and the replace leaves it where it was");
    }

    /// A byte-identical redelivery is the installer's existing no-op, reached
    /// through the replace door: no generation is allocated and nothing reports a
    /// change.
    #[test]
    fn replacing_with_the_byte_identical_container_allocates_no_generation() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        admit_seed_generation(&t.root, &generation.package).expect("seed");

        let again = replace_generation(&t.root, &generation.package).expect("idempotent");
        assert_eq!(again.activation.generation, 1);
        assert!(!again.activation.changed, "the same bytes are a no-op");
        assert_eq!(again.epoch, SEED_EPOCH);
        assert_nothing_installed(
            &t.root,
            &[OsString::from(ACTIVE_LINK), generation_name(&t.root, 1)],
        );
    }

    // The runtime accept path: the state query, a single accept and chain
    // replay. Every generation below is minted in-test from ephemeral keys, and
    // every epoch is far from any generation index so an assertion about `gen-1`
    // cannot pass by conflating the two.

    /// The three chain epochs, deliberately **non-contiguous**: epochs are
    /// allocated by hand, so a replay that required arithmetic between them
    /// would refuse a legitimate sequence.
    const CHAIN_EPOCHS: [u64; 3] = [5000, 6001, 9999];

    /// The name a non-canonical `active` points at in the tests that build one.
    const ELSEWHERE: &str = "elsewhere";

    /// Every path under `root` with what it holds — a directory as an empty
    /// entry, a symlink as its target, a file as its bytes — so a test can
    /// assert a tree is byte-identical before and after a call.
    ///
    /// `symlink_metadata` throughout: a snapshot that followed `active` would
    /// report the generation twice and would say nothing about where the link
    /// points.
    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                let relative = path
                    .strip_prefix(root)
                    .expect("every entry is under the root")
                    .to_path_buf();
                let meta = std::fs::symlink_metadata(&path).expect("symlink metadata");
                if meta.is_symlink() {
                    let target = std::fs::read_link(&path).expect("read_link");
                    out.push((relative, target.into_os_string().into_encoded_bytes()));
                } else if meta.is_dir() {
                    out.push((relative, Vec::new()));
                    pending.push(path);
                } else {
                    out.push((relative, std::fs::read(&path).expect("read")));
                }
            }
        }
        out.sort();
        out
    }

    /// A tree carrying `generation` as its only generation, admitted through the
    /// install-time seed exactly as a real host is provisioned.
    fn seeded_tree(generation: &Generation) -> Tree {
        let t = tree();
        admit_seed_generation(&t.root, &generation.package).expect("seed");
        t
    }

    /// A tree seeded with `generation` whose `active` is then a symlink to a
    /// well-formed generation directory under a name the engine never writes.
    fn tree_with_non_canonical_active(generation: &Generation) -> Tree {
        let t = seeded_tree(generation);
        std::fs::remove_file(active_link(&t.root)).expect("remove the link");
        std::fs::rename(generation_dir(&t.root, 1), t.root.join(ELSEWHERE)).expect("rename");
        std::os::unix::fs::symlink(ELSEWHERE, active_link(&t.root)).expect("link");
        t
    }

    /// A tree seeded with `generation` whose `active` is a **real directory**
    /// holding that generation's three files rather than a symlink, which is
    /// what makes `read_link` fail with `EINVAL` rather than `NotFound`.
    fn tree_with_real_directory_active(generation: &Generation) -> Tree {
        let t = seeded_tree(generation);
        std::fs::remove_file(active_link(&t.root)).expect("remove the link");
        std::fs::rename(generation_dir(&t.root, 1), active_link(&t.root)).expect("rename");
        t
    }

    /// A tree whose `active` dangles onto a canonical `gen-<n>` that is not
    /// there.
    fn tree_with_dangling_active() -> Tree {
        let t = tree();
        std::os::unix::fs::symlink(generation_name(&t.root, 9), active_link(&t.root))
            .expect("dangling link");
        t
    }

    /// A generation at `epoch` that is not the one [`Generation::new`] mints for
    /// it: same key, same epoch, one unrelated withdrawn build.
    fn other_document_at(pair: &Ed25519KeyPair, epoch: u64) -> Generation {
        Generation::from_fields(
            pair,
            &Fields {
                epoch: Some(epoch.to_string()),
                withdrawn_builds: Some(array(&[withdrawn_json("example", "1.0.0", "abc")])),
                ..Fields::new(pair)
            },
            epoch,
        )
    }

    /// The `VerifyError` a refusal carries, or a panic naming what arrived
    /// instead.
    fn verdict(err: &ReleaseTrustError) -> &VerifyError {
        match err {
            ReleaseTrustError::Verify(verdict) => verdict,
            other => panic!("expected a verification verdict, got {other:?}"),
        }
    }

    /// A generation one epoch above the active one is accepted and activated.
    #[test]
    fn accept_activates_a_strictly_newer_generation() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        let admitted = accept_generation(&t.root, &delivered.package).expect("a newer generation");
        assert_eq!(
            admitted.activation,
            Activation {
                generation: 2,
                changed: true,
            },
        );
        assert_eq!(admitted.epoch, NEXT_EPOCH);
        assert_eq!(admitted.document.epoch, NEXT_EPOCH);

        assert_active_is(&t.root, 2);
        assert_eq!(
            std::fs::read(active_package(&t.root)).expect("read"),
            delivered.package,
            "the delivered container is stored verbatim",
        );
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(NEXT_EPOCH),
            "the floor survives a restart",
        );
    }

    /// Equal and lower are alike stale, and the equal case carries a document
    /// that is *not* the active one — which is what makes it reach the floor at
    /// all rather than the byte-identity fast path.
    #[test]
    fn accept_refuses_an_equal_or_lower_epoch_as_stale() {
        let pair = keypair();
        let cases = [
            (other_document_at(&pair, SEED_EPOCH), SEED_EPOCH),
            (Generation::new(&pair, SEED_EPOCH - 1), SEED_EPOCH - 1),
        ];
        for (delivered, epoch) in cases {
            let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
            let before = snapshot(&t.root);
            let err = accept_generation(&t.root, &delivered.package)
                .expect_err("the floor is strictly greater");
            assert!(
                matches!(
                    verdict(&err),
                    VerifyError::StaleTrustSet { delivered, active }
                        if *delivered == epoch && *active == SEED_EPOCH
                ),
                "got {err:?}",
            );
            assert_eq!(snapshot(&t.root), before, "a refusal writes nothing");
        }
    }

    /// The redelivery a control plane with bounded retry produces routinely.
    ///
    /// This is the test that would fail if the byte comparison ran after
    /// verification: the delivered epoch equals the active one, so the verifier
    /// would refuse these very bytes as stale.
    #[test]
    fn redelivering_the_active_generations_bytes_is_an_unchanged_no_op() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let t = seeded_tree(&seed);
        let before = snapshot(&t.root);

        let admitted =
            accept_generation(&t.root, &seed.package).expect("a byte-identical redelivery");
        assert_eq!(
            admitted.activation,
            Activation {
                generation: 1,
                changed: false,
            },
            "the index `active` names, and nothing moved",
        );
        assert_eq!(admitted.epoch, SEED_EPOCH);
        assert_eq!(
            admitted.document,
            read_trust_set_document(&seed.member).expect("the seeded document"),
            "the active generation's own document, not a parse of the delivered bytes",
        );
        assert_eq!(snapshot(&t.root), before, "the tree was not touched");
    }

    /// A different document at the same epoch does not match those bytes, so it
    /// falls through to the verifier — which is what makes the comparison
    /// byte-exact rather than an epoch shortcut.
    #[test]
    fn a_different_document_at_the_active_epoch_is_stale_rather_than_unchanged() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let t = seeded_tree(&seed);
        let delivered = other_document_at(&pair, SEED_EPOCH);
        assert_ne!(delivered.package, seed.package);

        let err = accept_generation(&t.root, &delivered.package).expect_err("not these bytes");
        assert!(
            matches!(
                verdict(&err),
                VerifyError::StaleTrustSet { delivered, active }
                    if *delivered == SEED_EPOCH && *active == SEED_EPOCH
            ),
            "got {err:?}",
        );
    }

    /// The canonical-link precondition covers the whole path rather than only
    /// the fast path, so each tree is driven with a byte-identical redelivery
    /// **and** with a genuinely newer generation.
    #[test]
    fn accept_refuses_a_tree_whose_active_is_not_a_canonical_symlink() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let newer = Generation::new(&pair, NEXT_EPOCH);

        for delivered in [&seed, &newer] {
            let linked = tree_with_non_canonical_active(&seed);
            let before = snapshot(&linked.root);
            let err = accept_generation(&linked.root, &delivered.package)
                .expect_err("`active` names no canonical generation");
            assert!(
                matches!(
                    err,
                    ReleaseTrustError::ActiveNotCanonical { ref target } if target == ELSEWHERE
                ),
                "got {err:?}",
            );
            assert_eq!(snapshot(&linked.root), before);

            let real = tree_with_real_directory_active(&seed);
            let before = snapshot(&real.root);
            let err = accept_generation(&real.root, &delivered.package)
                .expect_err("`active` cannot be read as a link at all");
            assert!(
                matches!(
                    err,
                    ReleaseTrustError::Io { ref path, .. }
                        if Path::new(path) == active_link(&real.root)
                ),
                "got {err:?}",
            );
            assert_eq!(snapshot(&real.root), before);
        }
    }

    /// The two readers differ deliberately rather than accidentally: the
    /// following stat resolves a generation on both of the trees the runtime
    /// probe refuses, exactly as it did before the factoring.
    #[test]
    fn the_common_reader_still_accepts_the_two_trees_the_probe_refuses() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        for t in [
            tree_with_non_canonical_active(&seed),
            tree_with_real_directory_active(&seed),
        ] {
            let trust =
                active_trust_set(&t.root).expect("the following stat resolves a generation");
            assert_eq!(trust.anchors().len(), 1);
            assert_eq!(read_active_epoch(&t.root).expect("read"), Some(SEED_EPOCH));
        }
    }

    /// The state query never reports a generation the accept path would refuse,
    /// and never calls a tree empty that the accept path calls broken.
    #[test]
    fn the_state_query_reports_the_probes_two_refusals_rather_than_no_generation() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);

        let linked = tree_with_non_canonical_active(&seed);
        let err = read_generation_state(&linked.root).expect_err("not a canonical generation");
        assert!(
            matches!(
                err,
                ReleaseTrustError::ActiveNotCanonical { ref target } if target == ELSEWHERE
            ),
            "got {err:?}",
        );

        let real = tree_with_real_directory_active(&seed);
        let err = read_generation_state(&real.root).expect_err("`active` is no link");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Io { ref path, .. }
                    if Path::new(path) == active_link(&real.root)
            ),
            "got {err:?}",
        );
    }

    /// The probe runs first and a dangling `active` passes it, so the common
    /// reader's refusal is what decides — and each caller disposes of it the way
    /// it disposed of the absent link.
    #[test]
    fn a_dangling_active_is_no_generation_to_every_reader() {
        let t = tree_with_dangling_active();
        let pair = keypair();
        let delivered = Generation::new(&pair, SEED_EPOCH);

        let err = accept_generation(&t.root, &delivered.package)
            .expect_err("there is nothing to accept onto");
        assert!(
            matches!(err, ReleaseTrustError::NoActiveGeneration),
            "a dangling link is never generation 9, got {err:?}",
        );
        assert_eq!(read_generation_state(&t.root).expect("read"), None);
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            None,
            "the two readers still agree about which trees are empty",
        );
    }

    #[test]
    fn accept_refuses_an_empty_tree_where_the_state_query_reports_it() {
        let t = tree();
        let pair = keypair();
        let delivered = Generation::new(&pair, SEED_EPOCH);

        let err = accept_generation(&t.root, &delivered.package)
            .expect_err("there is no accept onto an empty tree");
        assert!(
            matches!(err, ReleaseTrustError::NoActiveGeneration),
            "got {err:?}",
        );
        assert_eq!(read_generation_state(&t.root).expect("read"), None);
    }

    /// Step 1 has established that a canonical generation is active, so a
    /// container that cannot be read is a damaged tree rather than an empty one:
    /// there is no `NotFound` exemption and no fall-through to verification.
    #[test]
    fn accept_refuses_a_tree_whose_active_container_cannot_be_read() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        std::fs::remove_file(active_package(&t.root)).expect("remove the container");

        let delivered = Generation::new(&pair, NEXT_EPOCH);
        let err = accept_generation(&t.root, &delivered.package)
            .expect_err("the active container is gone");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Io { ref path, .. }
                    if Path::new(path) == active_package(&t.root)
            ),
            "got {err:?}",
        );
    }

    /// Both carriers are covered by the signature, so a disagreement is refused
    /// with this path's own error before anything is injected into the verifier
    /// — never as a verifier verdict, and never as the tree's
    /// `EpochDisagreement`.
    #[test]
    fn a_delivered_generation_whose_two_epoch_carriers_disagree_is_refused_before_verification() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let before = snapshot(&t.root);

        let member = document_at(&pair, NEXT_EPOCH);
        let package = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &(NEXT_EPOCH + 1).to_string(),
            &member_digest(&member),
        );
        let err = accept_generation(&t.root, &package).expect_err("the two carriers disagree");
        assert!(
            matches!(
                err,
                ReleaseTrustError::DeliveredEpochDisagreement { document, ref manifest }
                    if document == NEXT_EPOCH && *manifest == (NEXT_EPOCH + 1).to_string()
            ),
            "the document field is authoritative, got {err:?}",
        );
        assert_eq!(snapshot(&t.root), before);
    }

    /// The delivered generation is judged against the **active** generation's
    /// manifest-format floor, with no special-casing. A generation that raises
    /// the floor past what release tooling mints therefore locks the host out of
    /// every later generation — intended behaviour, cheap to avoid at mint time,
    /// and escapable only by re-provisioning.
    #[test]
    fn a_delivered_generation_below_the_active_floor_is_refused_for_its_manifest_format() {
        let pair = keypair();
        let raised = Generation::from_fields(
            &pair,
            &Fields {
                epoch: Some(SEED_EPOCH.to_string()),
                min_manifest_format_version: Some((MAX_MANIFEST_FORMAT_VERSION + 1).to_string()),
                ..Fields::new(&pair)
            },
            SEED_EPOCH,
        );
        let t = seeded_tree(&raised);

        let delivered = Generation::new(&pair, NEXT_EPOCH);
        let err = accept_generation(&t.root, &delivered.package)
            .expect_err("the active generation published a floor above it");
        assert!(
            matches!(
                verdict(&err),
                VerifyError::UnsupportedManifestFormat { min, .. }
                    if *min == MAX_MANIFEST_FORMAT_VERSION + 1
            ),
            "got {err:?}",
        );
    }

    /// Every refusal this path raises falls before `install_generation` is
    /// called, so the tree is byte-identical afterwards. A failure *inside* the
    /// engine is deliberately not asserted against: two of its three documented
    /// outcomes legitimately leave debris behind.
    #[test]
    fn every_refusal_before_the_installer_leaves_the_tree_byte_identical() {
        let pair = keypair();
        let stranger = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let before = snapshot(&t.root);

        let carriers = document_at(&pair, NEXT_EPOCH);
        let refusals = [
            // Stale, at a lower and at an equal epoch.
            Generation::new(&pair, SEED_EPOCH - 1).package,
            other_document_at(&pair, SEED_EPOCH).package,
            // Signed by a key the active generation does not carry.
            Generation::new(&stranger, NEXT_EPOCH).package,
            // The two delivered epoch carriers disagreeing.
            pkg_naming(
                &pair,
                &carriers,
                TRUST_TARGET,
                &SEED_EPOCH.to_string(),
                &member_digest(&carriers),
            ),
            // No container at all, and a container carrying no document.
            b"not a container".to_vec(),
            generation_pkg(&pair, b"not a document", NEXT_EPOCH),
        ];
        for package in refusals {
            let err = accept_generation(&t.root, &package).expect_err("refused");
            assert_eq!(snapshot(&t.root), before, "{err:?} left the tree changed");
        }
    }

    /// The whole of the state query's two successful answers, and the refusals
    /// that are deliberately not folded into either of them.
    #[test]
    fn the_state_query_reports_the_index_and_the_epoch_or_that_there_is_none() {
        assert_eq!(
            read_generation_state(&tree().root).expect("read"),
            None,
            "an empty tree carries no generation",
        );

        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        assert_eq!(
            read_generation_state(&t.root).expect("read"),
            Some(ActiveGeneration {
                generation: 1,
                epoch: SEED_EPOCH,
            }),
        );

        // The index is the tree's own and moves with an activation; the epoch is
        // the generation's and is unrelated to it.
        accept_generation(&t.root, &Generation::new(&pair, NEXT_EPOCH).package).expect("rotate");
        assert_eq!(
            read_generation_state(&t.root).expect("read"),
            Some(ActiveGeneration {
                generation: 2,
                epoch: NEXT_EPOCH,
            }),
        );

        // A tree that carries a generation and is damaged is an `Err`, never
        // `Ok(None)` and never `Ok(Some(..))`.
        let malformed = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        overwrite_active(&malformed.root, EPOCH_RECORD_FILE, b"4711");
        assert!(
            matches!(
                read_generation_state(&malformed.root).expect_err("a malformed record"),
                ReleaseTrustError::UnterminatedEpochRecord
            ),
            "a malformed `epoch` record is not an empty tree",
        );

        let disagreeing = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        overwrite_active(&disagreeing.root, EPOCH_RECORD_FILE, b"4712\n");
        assert!(
            matches!(
                read_generation_state(&disagreeing.root).expect_err("the two disagree"),
                ReleaseTrustError::EpochDisagreement { record, document }
                    if record == NEXT_EPOCH && document == SEED_EPOCH
            ),
            "a generation whose record and document disagree is not an empty tree",
        );
    }

    /// The state query writes nothing, over every tree shape it can be handed.
    ///
    /// On its own this does not pin *which* functions it called — a
    /// byte-identical re-admission through the install door would leave the same
    /// snapshot, since the engine's own no-op returns without writing on exactly
    /// that input. The recorder test below is what pins the callee.
    #[test]
    fn the_state_query_writes_nothing_whatever_the_tree() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let trees = [
            tree(),
            tree_with_dangling_active(),
            tree_with_non_canonical_active(&seed),
            tree_with_real_directory_active(&seed),
            seeded_tree(&seed),
        ];
        for t in &trees {
            let before = snapshot(&t.root);
            let _ = read_generation_state(&t.root);
            assert_eq!(snapshot(&t.root), before, "the state query is read-only");
        }
    }

    /// Non-contiguous epochs, replayed in order, all three activated. Nothing
    /// here tests arithmetic between the epochs, because there is none to test.
    #[test]
    fn a_three_step_chain_replays_in_order_with_no_contiguity_test() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let chain: Vec<Generation> = CHAIN_EPOCHS
            .iter()
            .map(|epoch| Generation::new(&pair, *epoch))
            .collect();
        let packages: Vec<&[u8]> = chain.iter().map(|g| g.package.as_slice()).collect();

        let replay = accept_generation_chain(&t.root, &packages).expect("the chain replays");
        assert_eq!(replay.completed, 3);
        let last = replay.last.expect("three steps were accepted");
        assert_eq!(
            last.activation,
            Activation {
                generation: 4,
                changed: true,
            },
            "the seeded generation plus three activations",
        );
        assert_eq!(last.epoch, CHAIN_EPOCHS[2]);
        assert_active_is(&t.root, 4);
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(CHAIN_EPOCHS[2]),
        );
    }

    /// A gap in the chain is detected by the signature check: the step the host
    /// skipped is the one that would have introduced the key, so the next step
    /// is signed by a key its active set does not carry.
    #[test]
    fn a_chain_stops_at_a_step_signed_by_a_key_the_active_generation_does_not_carry() {
        let pair = keypair();
        let successor = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));

        let first = Generation::new(&pair, CHAIN_EPOCHS[0]);
        // Signed by, and trusting, a key the preceding generation never named.
        let orphan = Generation::new(&successor, CHAIN_EPOCHS[1]);
        let third = Generation::new(&successor, CHAIN_EPOCHS[2]);
        let packages: Vec<&[u8]> = vec![&first.package, &orphan.package, &third.package];

        let err = accept_generation_chain(&t.root, &packages).expect_err("the chain has a gap");
        assert_eq!(err.completed, 1, "`packages[1]` is the step that refused");
        let last = err.last.as_ref().expect("the first step was accepted");
        assert_eq!(
            last.activation,
            Activation {
                generation: 2,
                changed: true,
            },
        );
        assert!(
            matches!(
                verdict(&err.source),
                VerifyError::UnknownKeyId { key_id: id }
                    if *id == key_id(&public_key_of(&successor))
            ),
            "got {:?}",
            err.source,
        );

        assert_active_is(&t.root, 2);
        assert_eq!(
            read_active_epoch(&t.root).expect("read"),
            Some(CHAIN_EPOCHS[0]),
            "the accepted step stands and nothing is unwound",
        );
    }

    /// Out-of-order delivery shows up as a stale step, and the byte comparison
    /// is against the *currently* active container rather than against anything
    /// the chain passed through.
    #[test]
    fn a_chain_delivered_out_of_order_is_refused_at_the_step_that_goes_backwards() {
        let pair = keypair();
        let earlier = Generation::new(&pair, CHAIN_EPOCHS[0]);
        let later = Generation::new(&pair, CHAIN_EPOCHS[1]);

        let reversed = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let packages: Vec<&[u8]> = vec![&later.package, &earlier.package];
        let err = accept_generation_chain(&reversed.root, &packages)
            .expect_err("the second step goes backwards");
        assert_eq!(err.completed, 1);
        assert!(
            matches!(
                verdict(&err.source),
                VerifyError::StaleTrustSet { delivered, active }
                    if *delivered == CHAIN_EPOCHS[0] && *active == CHAIN_EPOCHS[1]
            ),
            "got {:?}",
            err.source,
        );
        assert_active_is(&reversed.root, 2);

        // And a chain that ends by redelivering a generation two steps back: by
        // then it is not the active container, so it falls through to the floor
        // rather than short-circuiting as a no-op.
        let looped = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let packages: Vec<&[u8]> = vec![&earlier.package, &later.package, &earlier.package];
        let err = accept_generation_chain(&looped.root, &packages)
            .expect_err("the third step goes backwards");
        assert_eq!(err.completed, 2);
        assert!(
            matches!(
                verdict(&err.source),
                VerifyError::StaleTrustSet { delivered, active }
                    if *delivered == CHAIN_EPOCHS[0] && *active == CHAIN_EPOCHS[1]
            ),
            "got {:?}",
            err.source,
        );
    }

    /// The other half of the rule the out-of-order test pins: a duplicate
    /// **adjacent** to the step that activated it is a no-op, because by then it
    /// *is* the active container. Only a duplicate further back falls through to
    /// the floor.
    ///
    /// The activating step is the chain's own, not the seed's, so the bytes the
    /// second step short-circuits against are ones this call installed rather
    /// than ones it found.
    #[test]
    fn a_duplicate_adjacent_to_the_step_that_activated_it_is_a_no_op() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let newer = Generation::new(&pair, NEXT_EPOCH);
        let packages: Vec<&[u8]> = vec![&newer.package, &newer.package];

        let replay = accept_generation_chain(&t.root, &packages).expect("the chain replays");
        assert_eq!(replay.completed, 2);
        let last = replay.last.expect("both steps were accepted");
        assert_eq!(
            last.activation,
            Activation {
                generation: 2,
                changed: false,
            },
            "the second step found its own bytes already active",
        );
        assert_eq!(last.epoch, NEXT_EPOCH);
        assert_active_is(&t.root, 2);
        assert_eq!(
            entries(&t.root),
            vec![OsString::from(ACTIVE_LINK), generation_name(&t.root, 2)],
            "the redelivery allocated no generation directory of its own",
        );
    }

    /// The routine shape: a control plane sends "generations *N* through *M*" to
    /// a host it believes is on *N*, so the first step is a redelivery.
    ///
    /// `completed: 2` is what pins the no-op as an **accepted** step: the
    /// redelivery sits at an equal epoch, so any path through it other than the
    /// byte-identical short-circuit would have been refused as stale and stopped
    /// the chain at `completed: 0`. The resulting index being exactly one past
    /// the seeded generation is what shows the no-op consumed no generation
    /// directory.
    ///
    /// The first step's own `changed: false` is deliberately not asserted here —
    /// `ChainReplay` carries only the last accepted record, and that field's
    /// semantics are pinned by the single-accept redelivery test above.
    #[test]
    fn a_chain_whose_first_step_is_a_redelivery_counts_it_as_an_accepted_step() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let t = seeded_tree(&seed);
        let newer = Generation::new(&pair, NEXT_EPOCH);
        let packages: Vec<&[u8]> = vec![&seed.package, &newer.package];

        let replay = accept_generation_chain(&t.root, &packages).expect("the chain replays");
        assert_eq!(replay.completed, 2);
        let last = replay.last.expect("two steps were accepted");
        assert_eq!(
            last.activation,
            Activation {
                generation: 2,
                changed: true,
            },
        );
        assert_eq!(last.epoch, NEXT_EPOCH);
        assert_active_is(&t.root, 2);
    }

    /// The same first step, followed by one that fails: `packages[completed]`
    /// names the failing step and the caller can resume from it.
    #[test]
    fn a_chain_that_fails_after_a_redelivery_reports_the_redelivery_as_its_last_record() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let t = seeded_tree(&seed);
        let stale = Generation::new(&pair, SEED_EPOCH - 1);
        let packages: Vec<&[u8]> = vec![&seed.package, &stale.package];

        let err =
            accept_generation_chain(&t.root, &packages).expect_err("the second step is stale");
        assert_eq!(err.completed, 1);
        let last = err.last.as_ref().expect("the redelivery was accepted");
        assert_eq!(
            last.activation,
            Activation {
                generation: 1,
                changed: false,
            },
        );
        assert_eq!(last.epoch, SEED_EPOCH);
        assert!(
            matches!(verdict(&err.source), VerifyError::StaleTrustSet { .. }),
            "got {:?}",
            err.source,
        );
    }

    /// A chain of nothing but redeliveries is accepted end to end and moves
    /// nothing. Whether anything moved is read from `last`, never from the
    /// count.
    #[test]
    fn a_chain_of_nothing_but_the_active_generations_bytes_moves_nothing() {
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        let t = seeded_tree(&seed);
        let before = snapshot(&t.root);
        let packages: Vec<&[u8]> = vec![&seed.package, &seed.package, &seed.package];

        let replay = accept_generation_chain(&t.root, &packages).expect("every step is a no-op");
        assert_eq!(replay.completed, packages.len());
        let last = replay.last.expect("three steps were accepted");
        assert!(!last.activation.changed);
        assert_eq!(last.activation.generation, 1);
        assert_eq!(snapshot(&t.root), before, "the tree is byte-identical");

        // An empty chain touches nothing at all.
        let replay = accept_generation_chain(&t.root, &[]).expect("an empty chain");
        assert_eq!(replay.completed, 0);
        assert!(replay.last.is_none());
        assert_eq!(snapshot(&t.root), before);
    }

    /// The floor is enforced on **both** accepting entry points, and neither
    /// behaves like the no-floor door.
    ///
    /// This is deliberately **not** the pin for the no-call rule: an
    /// implementation that refused here and then installed its *valid*
    /// deliveries through the replace door would pass it unchanged. The recorder
    /// test below is that pin. The state query is not driven this way at all —
    /// it takes no delivered package, so it has no delivered epoch to refuse.
    #[test]
    fn both_accepting_entry_points_refuse_a_lower_epoch() {
        let pair = keypair();
        let stale = Generation::new(&pair, SEED_EPOCH - 1);

        let single = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let err =
            accept_generation(&single.root, &stale.package).expect_err("a single accept refuses");
        assert!(
            matches!(verdict(&err), VerifyError::StaleTrustSet { .. }),
            "got {err:?}",
        );

        let chained = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let err = accept_generation_chain(&chained.root, &[&stale.package])
            .expect_err("a one-step chain refuses too");
        assert_eq!(err.completed, 0);
        assert!(err.last.is_none());
        assert!(
            matches!(verdict(&err.source), VerifyError::StaleTrustSet { .. }),
            "got {:?}",
            err.source,
        );
    }

    /// The no-call rule, pinned by observing the **callee**: a helper that
    /// reached the install-time replace door would be recorded exactly as an
    /// entry point reaching it directly, so the assertion does not depend on
    /// anyone having enumerated the helpers.
    #[test]
    fn no_runtime_entry_point_reaches_the_install_time_replace_door() {
        REPLACE_GENERATION_CALLS.with_borrow_mut(Vec::clear);

        let pair = keypair();
        let stranger = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);

        // A successful accept.
        let accepted = seeded_tree(&seed);
        accept_generation(&accepted.root, &Generation::new(&pair, NEXT_EPOCH).package)
            .expect("a newer generation");

        // A successful three-step chain replay.
        let replayed = seeded_tree(&seed);
        let chain: Vec<Generation> = CHAIN_EPOCHS
            .iter()
            .map(|epoch| Generation::new(&pair, *epoch))
            .collect();
        let packages: Vec<&[u8]> = chain.iter().map(|g| g.package.as_slice()).collect();
        accept_generation_chain(&replayed.root, &packages).expect("the chain replays");

        // A refusal of every shape, through both accepting entry points.
        let refused = seeded_tree(&seed);
        let refusals = [
            Generation::new(&pair, SEED_EPOCH - 1).package,
            other_document_at(&pair, SEED_EPOCH).package,
            Generation::new(&stranger, NEXT_EPOCH).package,
            b"not a container".to_vec(),
            generation_pkg(&pair, b"not a document", NEXT_EPOCH),
        ];
        for package in &refusals {
            accept_generation(&refused.root, package).expect_err("refused");
            accept_generation_chain(&refused.root, &[package]).expect_err("refused");
        }
        for root in [
            tree().root.clone(),
            tree_with_dangling_active().root.clone(),
            tree_with_non_canonical_active(&seed).root.clone(),
            tree_with_real_directory_active(&seed).root.clone(),
        ] {
            accept_generation(&root, &seed.package).expect_err("refused");
        }

        // The two self-admitting doors, succeeding and refusing alike.
        let rebootstrapped = seeded_tree(&seed);
        rebootstrap_generation(
            &rebootstrapped.root,
            &Generation::new(&stranger, NEXT_EPOCH).package,
            RebootstrapAuthorization::asserting_last_confirmed_epoch(SEED_EPOCH),
            None,
        )
        .expect("a re-bootstrap past the retention floor");
        // Its own refusal set: the stranger-signed generation above is exactly
        // what a re-bootstrap *admits*, so it cannot stand in for one here.
        let rebootstrap_refusals = [
            Generation::new(&pair, SEED_EPOCH - 1).package,
            other_document_at(&pair, SEED_EPOCH).package,
            b"not a container".to_vec(),
            generation_pkg(&pair, b"not a document", NEXT_EPOCH),
        ];
        for package in &rebootstrap_refusals {
            rebootstrap_generation(
                &refused.root,
                package,
                RebootstrapAuthorization::asserting_last_confirmed_epoch(SEED_EPOCH),
                None,
            )
            .expect_err("refused");
        }
        let bootstrapped = tree();
        std::fs::write(join_generation_file(&bootstrapped.root), &seed.package).expect("join");
        bootstrap_from_join_material(&bootstrapped.root, None).expect("the join channel");
        bootstrap_from_join_material(&bootstrapped.root, None).expect_err("refused");
        bootstrap_from_join_material(&tree().root, None).expect_err("no join material");

        // And the state query over every tree shape.
        let dangling = tree_with_dangling_active();
        let linked = tree_with_non_canonical_active(&seed);
        let real = tree_with_real_directory_active(&seed);
        let well_formed = seeded_tree(&seed);
        for t in [&dangling, &linked, &real, &well_formed] {
            let _ = read_generation_state(&t.root);
        }
        let _ = read_generation_state(&tree().root);

        assert!(
            REPLACE_GENERATION_CALLS.with_borrow(Vec::is_empty),
            "a runtime path reached the no-floor install-time door: {:?}",
            REPLACE_GENERATION_CALLS.with_borrow(Vec::clone),
        );

        // The recorder does fire, so an assertion that could only ever pass is
        // not mistaken for coverage.
        let direct = seeded_tree(&seed);
        replace_generation(&direct.root, &Generation::new(&pair, NEXT_EPOCH).package)
            .expect("the install-time door");
        assert_eq!(
            REPLACE_GENERATION_CALLS.with_borrow(Vec::clone),
            vec![direct.root.clone()],
        );
        REPLACE_GENERATION_CALLS.with_borrow_mut(Vec::clear);
    }

    // The two self-admitting doors: the re-bootstrap for a host past the
    // retention floor, and the bootstrap for one the installer never touched.
    // Every generation below is minted in-test from ephemeral keys, every tree is
    // `tempfile`-backed, and no test requires or detects root.

    /// The authorization value asserting `epoch`, written out at every call site
    /// exactly as a real caller has to write it.
    fn authorizing(epoch: u64) -> RebootstrapAuthorization {
        RebootstrapAuthorization::asserting_last_confirmed_epoch(epoch)
    }

    /// Writes the host-side pin marker with `contents`, at the path the root-based
    /// helper resolves.
    fn set_pin_marker(root: &Path, contents: &[u8]) {
        std::fs::write(require_pin_marker(root), contents).expect("marker");
    }

    /// Writes `package` to the join-material location the bootstrap reads.
    fn set_join_material(root: &Path, package: &[u8]) {
        std::fs::write(join_generation_file(root), package).expect("join material");
    }

    /// The two files this issue reads resolve to the same paths a caller holding a
    /// namespace resolves them to. The root-based helpers cannot call the
    /// namespace-based accessors — they are handed the tree root, which a `Layout`
    /// cannot be reconstructed from — so a drift between the two resolutions would
    /// silently read a file nobody writes.
    #[test]
    fn the_root_based_helpers_resolve_what_the_layouts_accessors_do() {
        let layout = Layout::new("clumit-security");
        let root = layout.release_trust_dir();
        assert_eq!(require_pin_marker(&root), layout.require_pin_marker());
        assert_eq!(join_generation_file(&root), layout.join_generation_path());
        assert_eq!(
            require_pin_marker(&root),
            root.join(REQUIRE_TRUST_PIN_MARKER)
        );
        assert_eq!(join_generation_file(&root), root.join(JOIN_GENERATION_FILE));
    }

    /// The core verifies and returns; the tree is the tree it was never given.
    #[test]
    fn the_verification_core_returns_a_verified_document_and_writes_nothing() {
        let t = tree();
        let pair = keypair();
        let seed = Generation::new(&pair, SEED_EPOCH);
        admit_seed_generation(&t.root, &seed.package).expect("seed");
        let before = snapshot(&t.root);

        let delivered = Generation::new(&pair, NEXT_EPOCH);
        let verified = verify_self_admitted(&delivered.package, None).expect("self-admission");
        assert_eq!(verified.epoch, NEXT_EPOCH);
        assert_eq!(verified.document.epoch, NEXT_EPOCH);
        assert_eq!(
            verified.member, delivered.member,
            "the member is the container's own bytes",
        );
        assert_eq!(
            snapshot(&t.root),
            before,
            "verification creates, touches and prunes nothing",
        );
    }

    /// A stale host takes the current generation, and the stale generation is
    /// superseded by the activation rather than removed ahead of it.
    #[test]
    fn a_rebootstrap_admits_a_strictly_newer_generation_onto_a_stale_tree() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        let admitted =
            rebootstrap_generation(&t.root, &delivered.package, authorizing(SEED_EPOCH), None)
                .expect("a re-bootstrap past the retention floor");
        assert_eq!(
            admitted.activation,
            Activation {
                generation: 2,
                changed: true,
            },
        );
        assert_eq!(admitted.epoch, NEXT_EPOCH);
        assert_eq!(admitted.document.epoch, NEXT_EPOCH);
        assert_active_is(&t.root, 2);
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(NEXT_EPOCH));
        assert_eq!(
            entries(&t.root),
            vec![OsString::from(ACTIVE_LINK), generation_name(&t.root, 2)],
            "the stale generation is superseded and pruned, never removed up front",
        );
    }

    /// The floor stands: only strictly greater activates, and the refusal is this
    /// path's own variant rather than the verifier's, which never runs on a
    /// request carrying no delivered epoch.
    #[test]
    fn a_rebootstrap_at_or_below_the_recorded_epoch_is_refused_as_stale() {
        let pair = keypair();
        for delivered in [
            Generation::new(&pair, SEED_EPOCH),
            Generation::new(&pair, SEED_EPOCH - 1),
        ] {
            let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
            let before = snapshot(&t.root);

            let err =
                rebootstrap_generation(&t.root, &delivered.package, authorizing(SEED_EPOCH), None)
                    .expect_err("the floor refuses");
            assert!(
                matches!(
                    err,
                    ReleaseTrustError::StaleRebootstrap {
                        delivered: at,
                        recorded: SEED_EPOCH,
                    } if at == delivered.epoch,
                ),
                "got {err:?}",
            );

            assert_eq!(
                snapshot(&t.root),
                before,
                "a floor refusal precedes the installer, so the tree is untouched",
            );
            assert_eq!(
                entries(&t.root),
                vec![OsString::from(ACTIVE_LINK), generation_name(&t.root, 1)],
                "no generation directory was allocated",
            );
            assert_eq!(read_active_epoch(&t.root).expect("read"), Some(SEED_EPOCH));
        }
    }

    /// The empty tree is the bootstrap's, never this path's: it has no recorded
    /// epoch to assert against or raise, and admitting one here would open a
    /// second empty-tree door taking arbitrary caller bytes.
    ///
    /// Asserted with the marker present and with bytes that are not a container at
    /// all, so the test fails if either the marker read or the container open runs
    /// before the empty-tree gate.
    #[test]
    fn a_rebootstrap_onto_an_empty_tree_is_refused_before_the_marker_and_the_container() {
        let t = tree();
        set_pin_marker(&t.root, b"");
        let before = snapshot(&t.root);

        let err =
            rebootstrap_generation(&t.root, b"not a container", authorizing(SEED_EPOCH), None)
                .expect_err("an empty tree has nothing to supersede");
        assert!(
            matches!(err, ReleaseTrustError::NoActiveGeneration),
            "got {err:?}",
        );
        assert_eq!(snapshot(&t.root), before, "and nothing was written");
    }

    /// A mis-targeted or stale-batch re-bootstrap, caught before anything is
    /// opened.
    #[test]
    fn a_rebootstrap_asserting_an_epoch_the_tree_does_not_record_is_refused() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let before = snapshot(&t.root);
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        let err = rebootstrap_generation(
            &t.root,
            &delivered.package,
            authorizing(SEED_EPOCH - 1),
            None,
        )
        .expect_err("the assertion names a host that has moved on");
        assert!(
            matches!(
                err,
                ReleaseTrustError::RebootstrapEpochMismatch {
                    asserted,
                    recorded: SEED_EPOCH,
                } if asserted == SEED_EPOCH - 1,
            ),
            "got {err:?}",
        );
        assert_eq!(snapshot(&t.root), before, "and nothing was written");
    }

    /// The central assertion: on inputs the ordinary accept path cannot serve —
    /// a generation signed by a key the stale active set does not carry, which is
    /// exactly what a pruned retention window leaves behind — the re-bootstrap
    /// succeeds. The chain check is what was relaxed, and nothing else.
    #[test]
    fn a_rebootstrap_succeeds_where_an_accept_fails_on_the_same_inputs() {
        let pair = keypair();
        let rotated = keypair();
        let delivered = Generation::new(&rotated, NEXT_EPOCH);

        let accepting = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let err = accept_generation(&accepting.root, &delivered.package)
            .expect_err("the chain is broken");
        assert!(
            matches!(verdict(&err), VerifyError::UnknownKeyId { .. }),
            "the key that would chain this forward has been pruned, got {err:?}",
        );

        let rebootstrapping = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let admitted = rebootstrap_generation(
            &rebootstrapping.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            None,
        )
        .expect("the same bytes, admitted under their own anchors");
        assert_eq!(admitted.epoch, NEXT_EPOCH);
        assert_eq!(
            read_active_epoch(&rebootstrapping.root).expect("read"),
            Some(NEXT_EPOCH),
        );
    }

    /// "The chain check is relaxed" is never "nothing is checked": the package is
    /// still self-admitted, so a signature that does not verify under a
    /// non-revoked anchor the document itself carries is refused.
    #[test]
    fn a_rebootstrap_whose_package_does_not_self_admit_is_refused() {
        let pair = keypair();
        let revoked = keypair();
        let stranger = keypair();

        let by_revoked_member = Fields {
            epoch: Some(NEXT_EPOCH.to_string()),
            anchors: Some(array(&[anchor_of(&pair, false), anchor_of(&revoked, true)])),
            ..Fields::new(&pair)
        }
        .render();
        let by_revoked = generation_pkg(&revoked, &by_revoked_member, NEXT_EPOCH);
        let by_a_key_it_does_not_name =
            generation_pkg(&stranger, &document_at(&pair, NEXT_EPOCH), NEXT_EPOCH);
        let mutated = corrupt_archive(&Generation::new(&pair, NEXT_EPOCH).package);

        let cases: [(&[u8], Refusal, &str); 3] = [
            (
                &by_revoked,
                |err| {
                    matches!(
                        err,
                        ReleaseTrustError::Verify(VerifyError::RevokedKey { .. })
                    )
                },
                "a signer its own document revokes",
            ),
            (
                &by_a_key_it_does_not_name,
                |err| {
                    matches!(
                        err,
                        ReleaseTrustError::Verify(VerifyError::UnknownKeyId { .. })
                    )
                },
                "a signer its own document does not name",
            ),
            (
                &mutated,
                |err| matches!(err, ReleaseTrustError::Verify(_)),
                "a container mutated after signing",
            ),
        ];
        for (package, is_expected, expected) in cases {
            let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
            let before = snapshot(&t.root);
            let err = rebootstrap_generation(&t.root, package, authorizing(SEED_EPOCH), None)
                .expect_err("the package is still self-admitted");
            assert!(
                is_expected(&err),
                "a re-bootstrap should refuse {expected}, got {err:?}",
            );
            assert_eq!(snapshot(&t.root), before, "and nothing was written");
        }
    }

    /// The two carriers of the delivered epoch are compared by the verifier's own
    /// target check, against the *signed* manifest. This path adds no
    /// epoch-agreement comparison of its own and needs none.
    #[test]
    fn a_rebootstrap_whose_epoch_carriers_disagree_is_refused_by_the_target_check() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let before = snapshot(&t.root);

        let member = document_at(&pair, NEXT_EPOCH);
        let package = pkg_naming(
            &pair,
            &member,
            TRUST_TARGET,
            &(NEXT_EPOCH + 1).to_string(),
            &member_digest(&member),
        );

        let err = rebootstrap_generation(&t.root, &package, authorizing(SEED_EPOCH), None)
            .expect_err("the document and the manifest disagree");
        assert!(
            matches!(
                err,
                ReleaseTrustError::Verify(VerifyError::TargetMismatch { .. })
            ),
            "got {err:?}",
        );
        assert_eq!(snapshot(&t.root), before, "and nothing was written");
    }

    /// A supplied pin is enforced on this path, compared against the digest of the
    /// member the core returned; a matching one changes nothing else.
    #[test]
    fn a_rebootstrap_pin_is_compared_against_the_delivered_document() {
        let pair = keypair();
        let delivered = Generation::new(&pair, NEXT_EPOCH);
        let digest = member_digest(&delivered.member);

        let mismatched = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let before = snapshot(&mismatched.root);
        let err = rebootstrap_generation(
            &mismatched.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            Some(STRANGER_COMMIT),
        )
        .expect_err("the pin is not this document's digest");
        assert!(
            matches!(
                &err,
                ReleaseTrustError::FingerprintPinMismatch { pin, digest: got }
                    if pin == STRANGER_COMMIT && *got == digest,
            ),
            "got {err:?}",
        );
        assert_eq!(
            snapshot(&mismatched.root),
            before,
            "a pin mismatch installs nothing",
        );

        let matched = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let admitted = rebootstrap_generation(
            &matched.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            Some(&digest),
        )
        .expect("the pin is the delivered document's digest");
        assert_eq!(admitted.epoch, NEXT_EPOCH);
    }

    /// The marker is the only difference between the two calls: identical inputs,
    /// one refused and one admitted.
    #[test]
    fn the_pin_marker_is_what_refuses_an_unpinned_rebootstrap() {
        let pair = keypair();
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        let pinned = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        set_pin_marker(&pinned.root, b"");
        let before = snapshot(&pinned.root);
        let err = rebootstrap_generation(
            &pinned.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            None,
        )
        .expect_err("the host demands an out-of-band pin");
        assert!(
            matches!(err, ReleaseTrustError::FingerprintPinRequired),
            "got {err:?}",
        );
        assert_eq!(snapshot(&pinned.root), before, "and nothing was written");

        let unpinned = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        rebootstrap_generation(
            &unpinned.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            None,
        )
        .expect("the same call on a host that set no marker");
    }

    /// The no-pin refusal and the pin-mismatch refusal are different variants, so
    /// an operator can tell "this host requires a pin and you supplied none" from
    /// "the pin you supplied does not match". Matched on the value, never on a
    /// message.
    #[test]
    fn the_two_pin_refusals_are_distinct_variants() {
        let pair = keypair();
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        let required = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        set_pin_marker(&required.root, b"");
        let missing = rebootstrap_generation(
            &required.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            None,
        )
        .expect_err("no pin");

        let wrong = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let mismatch = rebootstrap_generation(
            &wrong.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            Some(STRANGER_COMMIT),
        )
        .expect_err("the wrong pin");

        assert_ne!(
            discriminant(&missing),
            discriminant(&mismatch),
            "{missing:?} and {mismatch:?} must not be the same refusal",
        );
    }

    /// The marker gate runs before the container is opened, so a host that demands
    /// a pin rejects an unpinned call without paying for a package verification.
    /// Bytes that are not a container at all are what makes that observable.
    #[test]
    fn the_pin_marker_gate_runs_before_the_container_is_opened() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        set_pin_marker(&t.root, b"");

        let err =
            rebootstrap_generation(&t.root, b"not a container", authorizing(SEED_EPOCH), None)
                .expect_err("refused");
        assert!(
            matches!(err, ReleaseTrustError::FingerprintPinRequired),
            "the container fault should never be reached, got {err:?}",
        );
    }

    /// The gate is additive: it relaxes nothing, so a pinned call whose epoch is
    /// not strictly greater is still refused by the floor.
    #[test]
    fn the_pin_marker_gate_relaxes_no_floor() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        set_pin_marker(&t.root, b"");
        let delivered = Generation::new(&pair, SEED_EPOCH - 1);

        let err = rebootstrap_generation(
            &t.root,
            &delivered.package,
            authorizing(SEED_EPOCH),
            Some(&member_digest(&delivered.member)),
        )
        .expect_err("the floor still refuses");
        assert!(
            matches!(err, ReleaseTrustError::StaleRebootstrap { .. }),
            "got {err:?}",
        );
    }

    /// The marker's presence is its entire state: there is no format, so no
    /// parser, and its contents are never read.
    #[test]
    fn the_pin_markers_contents_are_never_read() {
        let pair = keypair();
        let delivered = Generation::new(&pair, NEXT_EPOCH);

        for contents in [b"".as_slice(), b"anything at all\0\xff".as_slice()] {
            let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
            set_pin_marker(&t.root, contents);
            let err =
                rebootstrap_generation(&t.root, &delivered.package, authorizing(SEED_EPOCH), None)
                    .expect_err("an empty marker and a full one are the same state");
            assert!(
                matches!(err, ReleaseTrustError::FingerprintPinRequired),
                "got {err:?}",
            );
        }
    }

    /// Presence is tested without following symlinks, so a dangling symlink at the
    /// marker path reads as set. Otherwise deleting a symlink's target would
    /// silently clear the gate.
    #[test]
    fn a_dangling_symlink_at_the_marker_path_reads_as_set() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        std::os::unix::fs::symlink("nothing-is-here", require_pin_marker(&t.root))
            .expect("dangling marker");

        let err = rebootstrap_generation(
            &t.root,
            &Generation::new(&pair, NEXT_EPOCH).package,
            authorizing(SEED_EPOCH),
            None,
        )
        .expect_err("an entry of any kind is the marker");
        assert!(
            matches!(err, ReleaseTrustError::FingerprintPinRequired),
            "got {err:?}",
        );
    }

    /// The classification is unit-tested directly, because no filesystem
    /// arrangement can make the entry point's own stat of a direct child of the
    /// tree root fail with a non-`NotFound` error while leaving the earlier
    /// `read_active_epoch` intact. These run unprivileged everywhere and are
    /// deterministic.
    #[test]
    fn the_marker_classification_maps_each_stat_outcome() {
        let path = Path::new("/etc/clumit-security/release-trust").join(REQUIRE_TRUST_PIN_MARKER);
        let target = path.to_string_lossy().into_owned();

        assert!(
            classify_pin_marker(Ok(()), &path).expect("a stat that succeeded"),
            "an entry of any kind is the marker",
        );
        assert!(
            !classify_pin_marker(Err(std::io::ErrorKind::NotFound.into()), &path)
                .expect("the absent marker"),
            "`NotFound` is the only unset",
        );

        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::NotADirectory,
            std::io::ErrorKind::Other,
        ] {
            let err = classify_pin_marker(Err(kind.into()), &path)
                .expect_err("every other failure is fail-closed");
            match err {
                ReleaseTrustError::Io { path, source } => {
                    assert_eq!(path, target, "the refusal names the marker");
                    assert_eq!(source.kind(), kind, "and carries the fault verbatim");
                }
                other => panic!("{kind:?} should refuse through the i/o variant, got {other:?}"),
            }
        }
    }

    /// The join channel is the byte source, the seed's gate and sequence are the
    /// admission, and the operator's material is left where it was.
    #[test]
    fn the_bootstrap_admits_the_join_material_onto_an_empty_tree() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        set_join_material(&t.root, &generation.package);

        let admitted = bootstrap_from_join_material(&t.root, None).expect("the join channel");
        assert_eq!(
            admitted.activation,
            Activation {
                generation: 1,
                changed: true,
            },
        );
        assert_eq!(admitted.epoch, SEED_EPOCH);
        assert_active_is(&t.root, 1);
        assert_eq!(
            std::fs::read(active_link(&t.root).join(TRUST_SET_MEMBER)).expect("read"),
            generation.member,
        );
        assert_eq!(
            std::fs::read(join_generation_file(&t.root)).expect("read"),
            generation.package,
            "operator-delivered material is left in place",
        );
    }

    /// A supplied pin is enforced here too, and a mismatch leaves the tree as
    /// empty as it found it — no generation directory, no `active`, no record.
    #[test]
    fn a_bootstrap_pin_mismatch_leaves_the_tree_empty() {
        let t = tree();
        let pair = keypair();
        let generation = Generation::new(&pair, SEED_EPOCH);
        set_join_material(&t.root, &generation.package);

        let err = bootstrap_from_join_material(&t.root, Some(STRANGER_COMMIT))
            .expect_err("the pin is not this document's digest");
        assert!(
            matches!(err, ReleaseTrustError::FingerprintPinMismatch { .. }),
            "got {err:?}",
        );
        assert_eq!(
            entries(&t.root),
            vec![OsString::from(JOIN_GENERATION_FILE)],
            "nothing was installed",
        );
        assert_eq!(read_active_epoch(&t.root).expect("read"), None);

        let admitted =
            bootstrap_from_join_material(&t.root, Some(&member_digest(&generation.member)))
                .expect("the matching pin");
        assert_eq!(admitted.epoch, SEED_EPOCH);
    }

    /// The marker guards the path that supersedes an existing trust history, and
    /// this path has none to supersede.
    #[test]
    fn the_bootstrap_consults_no_pin_marker() {
        let t = tree();
        let pair = keypair();
        set_pin_marker(&t.root, b"");
        set_join_material(&t.root, &Generation::new(&pair, SEED_EPOCH).package);

        let admitted =
            bootstrap_from_join_material(&t.root, None).expect("the marker decides nothing here");
        assert_eq!(admitted.epoch, SEED_EPOCH);
        assert!(
            require_pin_marker(&t.root).is_file(),
            "and the bootstrap leaves it where it was",
        );
    }

    /// Nothing at the join-material location is an `Io` refusal naming that path —
    /// reachable only on a tree the gate already accepted.
    #[test]
    fn the_bootstrap_refuses_an_absent_join_material_by_name() {
        let t = tree();
        let err = bootstrap_from_join_material(&t.root, None)
            .expect_err("the operator delivered nothing");
        match err {
            ReleaseTrustError::Io { path, source } => {
                assert_eq!(path, join_generation_file(&t.root).to_string_lossy());
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected the i/o refusal naming the join material, got {other:?}"),
        }
        assert_eq!(entries(&t.root), Vec::<OsString>::new());
    }

    /// The gate runs before the read, so a provisioned host reports the condition
    /// that actually decided the call rather than a missing file. Paired with the
    /// test above, the two show which refusal each input gets.
    #[test]
    fn a_non_empty_tree_is_refused_before_the_join_material_is_read() {
        let pair = keypair();
        let t = seeded_tree(&Generation::new(&pair, SEED_EPOCH));
        let before = snapshot(&t.root);

        let err = bootstrap_from_join_material(&t.root, None)
            .expect_err("the tree already carries a generation");
        assert!(
            matches!(
                err,
                ReleaseTrustError::ActiveGenerationPresent {
                    generation: Some(1),
                },
            ),
            "got {err:?}",
        );
        assert_eq!(snapshot(&t.root), before, "and nothing was written");

        // And the same refusal with the join material present, so the two inputs
        // are not being told apart by what the location holds.
        set_join_material(&t.root, &Generation::new(&pair, NEXT_EPOCH).package);
        let err = bootstrap_from_join_material(&t.root, None).expect_err("still refused");
        assert!(
            matches!(err, ReleaseTrustError::ActiveGenerationPresent { .. }),
            "got {err:?}",
        );
    }

    /// The path is delegated rather than re-implemented: a package that does not
    /// self-admit is refused with the seed's own error, on the seed's own
    /// sequence.
    #[test]
    fn the_bootstrap_refuses_with_the_seeds_own_error() {
        let pair = keypair();
        let stranger = keypair();
        let package = generation_pkg(&stranger, &document_at(&pair, SEED_EPOCH), SEED_EPOCH);

        let bootstrapped = tree();
        set_join_material(&bootstrapped.root, &package);
        let by_bootstrap = bootstrap_from_join_material(&bootstrapped.root, None)
            .expect_err("the signer is not an anchor the document carries");

        let seeded = tree();
        let by_seed = admit_seed_generation(&seeded.root, &package)
            .expect_err("the same refusal, the same sequence");

        assert_eq!(
            discriminant(&by_bootstrap),
            discriminant(&by_seed),
            "{by_bootstrap:?} and {by_seed:?} are one sequence's refusal",
        );
        assert!(
            matches!(
                by_bootstrap,
                ReleaseTrustError::Verify(VerifyError::UnknownKeyId { .. })
            ),
            "got {by_bootstrap:?}",
        );
        assert_eq!(
            entries(&bootstrapped.root),
            vec![OsString::from(JOIN_GENERATION_FILE)]
        );
    }

    /// The floor is vacuous where no prior epoch exists, and none is synthesized:
    /// an arbitrarily low epoch bootstraps onto an empty tree.
    #[test]
    fn the_bootstrap_applies_no_floor() {
        let t = tree();
        let pair = keypair();
        set_join_material(&t.root, &Generation::new(&pair, 1).package);

        let admitted = bootstrap_from_join_material(&t.root, None).expect("the first generation");
        assert_eq!(admitted.epoch, 1);
        assert_eq!(read_active_epoch(&t.root).expect("read"), Some(1));
    }
}
