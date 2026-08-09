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
//! The runtime delivery channel — the one that *does* apply the epoch floor, the
//! chain rules and the `require-trust-pin` re-bootstrap gate — is neither of
//! these. It exports its own, separately named runtime entry point, and reaches
//! this tree through this same installer rather than around it.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::generation::{
    GenerationError, GenerationFile, GenerationTree, activate_generation, active_link,
    parse_generation,
};
use crate::payload;
use crate::roxyd_trust::Activation;
use crate::trust_set::{
    TRUST_SET_MEMBER, TrustSetDocument, TrustSetDocumentError, document_anchors, member_digest,
    read_trust_set_document, self_admission_candidate,
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
    Ok(TrustSet::new(
        anchors,
        withdrawn,
        document.min_manifest_format_version,
        epoch,
    )?)
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

/// The whole install-time admission sequence, shared verbatim by both doors.
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
/// # Errors
///
/// Returns whichever [`ReleaseTrustError`] the step that refused raises: the
/// container layer's through [`ReleaseTrustError::Verify`],
/// [`ReleaseTrustError::MissingTrustSetMember`],
/// [`ReleaseTrustError::ProvisionalDecode`] for every pre-verification decode
/// fault, [`ReleaseTrustError::Verify`] again for the verdict on the container,
/// [`ReleaseTrustError::Document`] for the refusing reader's own named refusal,
/// and the installer's on any I/O or validator fault.
fn admit(
    root: &Path,
    package: &[u8],
    scratch: Option<&Path>,
) -> Result<AdmittedGeneration, ReleaseTrustError> {
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

    // 5. The one funnel onto the tree, so the record is finalised by the same
    //    atomic swap that makes the generation active.
    let activation = install_generation(root, package, &member, document.epoch)?;
    Ok(AdmittedGeneration {
        activation,
        epoch: document.epoch,
        document,
    })
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

    admit(root, package, None)
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
/// - **No fingerprint pin, and no reading of
///   [`REQUIRE_TRUST_PIN_MARKER`](crate::layout::REQUIRE_TRUST_PIN_MARKER).**
///   That marker governs the *runtime* re-bootstrap, whose threat is a compromised
///   control plane pushing a forged higher-epoch generation to a host that has
///   fallen past the retention floor. An install-time replace is the operator
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
    admit(root, package, None)
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
        EPOCH_RECORD_FILE, GENERATION_PACKAGE_FILE, MATERIAL_SET_TARGET, ReleaseTrustError,
        active_trust_set, admit, admit_seed_generation, install_generation, material,
        read_active_epoch, replace_generation,
    };
    use crate::generation::{GenerationError, SYSTEMCTL_CALLS, active_link, generation_dir};
    use crate::layout::{ACTIVE_LINK, Layout, REQUIRE_TRUST_PIN_MARKER};
    use crate::manifest::MAX_MANIFEST_FORMAT_VERSION;
    use crate::trust_fixture::{
        Fields, anchor_json, anchor_of, array, default_document, generation_pkg,
        generation_pkg_member_named, hex_of, keypair, pkg_naming, public_key_of, withdrawn_json,
    };
    use crate::trust_set::{TRUST_SET_MEMBER, TrustSetDocumentError, member_digest};
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
}
