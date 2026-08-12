//! The tree-neutral trust-generation engine.
//!
//! A **trust tree** is a root-owned directory holding an `active` symlink and a
//! series of `gen-<n>/` generation directories. Installing new material into one is
//! always the same sequence: refuse a malformed material set, return an idempotent
//! no-op when the bytes already match `active`, otherwise stage a fresh root-only
//! `gen-<n>.tmp`, **validate the copy that was just written**, finalise it with a
//! `rename`, atomically repoint `active`, reload a unit if there is one, and prune
//! every superseded generation.
//!
//! [`activate_generation`] is that sequence, and it is the only copy of it in the
//! crate. What differs between trees is parameterized: the material set is a list of
//! named byte blobs the caller supplies, validation is a callback the caller
//! supplies, and the reload step is skipped entirely for a tree with nothing to
//! reload. What does **not** differ is deliberately not a parameter — the `0700`
//! directory and `0600` file modes, the validate-after-copy order, and the
//! keep-the-active-one pruning policy are the same discipline for every tree.
//!
//! # The bytes validated are the bytes installed
//!
//! The validator runs over the bytes **read back from `gen-<n>.tmp`**, never over the
//! caller's buffer. Material that passes a check and is then swapped before it is
//! copied is a TOCTOU the writer of the staging area wins; copying first and
//! validating the copy closes it (RFC 0003 §8.3).
//!
//! # The generation index is the tree's own
//!
//! `n` is a local directory index allocated from what is already on disk by
//! [`next_generation`], never derived from anything a caller delivers: the pruning
//! arithmetic depends on it only ever increasing by one from the tree's own state.
//!
//! # The tree root holds more than generations
//!
//! Four names at the tree root are the engine's own: `active`, the `active.tmp`
//! scratch link the swap goes through, `gen-<n>` and `gen-<n>.tmp`. Every other entry
//! is somebody else's, and the engine leaves it alone.
//!
//! Allocation and pruning both iterate the tree root and parse root-level entry
//! names, matching against the canonical spelling the engine writes rather than by
//! prefix, so a root entry that merely resembles a generation — `gen-retention.tmp`,
//! or the non-canonical `gen-01` and `gen-01.tmp` — survives a prune along with a
//! trust anchor snapshot or a marker file, and moves the next index not at all. That
//! is what makes the root a safe home for such a file.
//!
//! `active.tmp` is the one name that carries no such tolerance, and it is reserved
//! rather than merely parsed: [`swap_active_symlink`] clears what sits there before
//! every swap, because a leftover from an aborted swap would otherwise wedge the tree
//! for good. The clearing is a `remove_file`, so it covers what an aborted swap can
//! actually leave — a symlink, or a plain file — and only that. A *directory* at that
//! name is not removed and is not stepped around either: `remove_file` fails on it,
//! and the swap returns that error with `gen-<n>` already finalised and `active` still
//! on the previous generation, which is the finalised-but-not-live failure
//! [`activate_generation`] documents. Either way, root-owned state must not use that
//! name. It is the swap protocol's scratch entry, not part of any generation, and
//! nothing else at the root is treated this way.
//!
//! Material files, by contrast, live *inside* a generation directory, so a material
//! file named `active` or `gen-2` is inert: nothing at the root ever sees it.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::durability::sync_dir;
use crate::layout::{ACTIVE_LINK, GENERATION_PREFIX};
use crate::roxyd_trust::Activation;

/// The `systemctl` binary the reload step invokes.
const SYSTEMCTL: &str = "systemctl";

/// The extension a generation directory carries while it is being assembled, and
/// the `active` symlink carries while it is being swapped.
const TMP_EXTENSION: &str = "tmp";

/// A failure the generation engine itself produces: an I/O or reload fault, or a
/// material set refused before anything was staged.
///
/// Tree-neutral in both its name and its rendered messages, because the engine
/// drives more than one trust tree and a failure in one must not surface as text
/// naming another. A caller absorbs these into its own error type through `From`, so
/// no tree has to widen another tree's taxonomy; the type is crate-internal and
/// appears in no public signature.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GenerationError {
    /// A file could not be read or written, or a directory operation failed.
    #[error("trust generation i/o error at {path}: {source}")]
    Io {
        /// The path the operation targeted.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The material set holds no files, so the generation would carry nothing.
    #[error("the material set is empty")]
    EmptyMaterial,

    /// Two material files carry the same name, so one would land on the other.
    #[error("duplicate material file name `{}`", .0.to_string_lossy())]
    DuplicateName(OsString),

    /// A material file's name is not a single non-empty path component, so it could
    /// resolve outside the generation directory the engine intends to write it into.
    #[error("material file name `{}` is not a single path component", .0.to_string_lossy())]
    InvalidName(OsString),

    /// `systemctl reload` of the running unit failed after a swap.
    #[error("failed to reload {unit} after activation: {reason}")]
    Reload {
        /// The unit the reload targeted.
        unit: String,
        /// Why the reload failed.
        reason: String,
    },
}

impl GenerationError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        GenerationError::Io {
            path: path.to_string_lossy().into_owned(),
            source,
        }
    }
}

/// One named file of a generation's material set.
///
/// `name` is a bare file name rather than a path, and an [`OsString`] rather than a
/// `String`: a caller's staged basename need not be valid UTF-8, and the bytes of
/// the name it hands over are installed verbatim rather than converted.
pub(crate) struct GenerationFile {
    /// The file's name inside the generation directory.
    pub(crate) name: OsString,
    /// The file's contents.
    pub(crate) bytes: Vec<u8>,
}

impl GenerationFile {
    /// Builds one material file from its name and its contents.
    pub(crate) fn new(name: impl Into<OsString>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }
}

/// Renders the name and the length, never the contents: a material file's bytes are a
/// private key on the mTLS tree, and a derived `Debug` on this or on anything holding
/// it would put that key into whatever formatted it.
impl std::fmt::Debug for GenerationFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationFile")
            .field("name", &self.name)
            .field(
                "bytes",
                &format_args!("<redacted, {} bytes>", self.bytes.len()),
            )
            .finish()
    }
}

/// A trust tree: the directory holding `active` and `gen-<n>/`, plus the unit to
/// reload after a swap, if there is one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GenerationTree<'a> {
    /// The root-owned directory the engine owns, holding `active` and `gen-<n>/`.
    pub(crate) root: &'a Path,
    /// The unit to `systemctl reload` once `active` has been repointed. `None` skips
    /// the step entirely, for a tree whose readers need no notification.
    pub(crate) reload_unit: Option<&'a str>,
}

/// Installs `material` as the next generation of `tree`, validating the staged copy
/// through `validate` before anything live is repointed at it.
///
/// The sequence, which is the tree-neutral contract every caller gets:
///
/// 1. Refuse a malformed material set — empty, a duplicate name, or a name that is
///    not a single non-empty path component — before touching the filesystem.
/// 2. If `active` resolves and every named file byte-matches its counterpart under
///    it, return the current generation with `changed: false`, having written
///    nothing.
/// 3. Otherwise allocate the next index from the tree's own state, create a `0700`
///    `gen-<n>.tmp`, and write each file into it at `0600`.
/// 4. Read every file back from `gen-<n>.tmp` and hand that directory and those
///    bytes to `validate`. On a validator error, remove `gen-<n>.tmp` and return the
///    error with `active` untouched.
/// 5. Flush `gen-<n>.tmp`, `rename` it to `gen-<n>`, swap `active` onto it
///    atomically, reload `tree.reload_unit` when it is `Some` and the unit is
///    running, then prune every generation other than the one now active. Each of
///    the first three is flushed as it is taken, so what a reader resolves after a
///    crash is never an `active` naming material that did not land. The swap
///    is the point of no return: the two steps after it run with the new material
///    already live.
///
/// The files handed to `validate` carry the same names, in the same order, as
/// `material`.
///
/// # Errors
///
/// Returns the validator's error as-is, or the engine's own [`GenerationError`]
/// converted into `E`, on a refused material set or any I/O or reload failure.
///
/// Where in the sequence the failure falls decides what the tree looks like
/// afterwards, and the three cases are not the same contract:
///
/// - **Before `gen-<n>` is finalised** — a refused material set, any I/O fault from
///   step 2 through the flush that opens step 5, or a validator rejection.
///   Fail-closed and nothing published: `active` resolves to exactly what it
///   resolved to before the call, and no final `gen-<n>` exists that did not exist
///   before it. A half-staged copy may: the directory is created before the files
///   are written, so an I/O fault anywhere from step 3 up to and including that
///   flush leaves `gen-<n>.tmp` behind, which the next activation removes before it
///   reuses the name, and which any prune removes in any case. A copy the validator
///   rejected is removed on the way out.
/// - **Finalised but not yet live** — the `rename` of step 5 succeeded and either the
///   flush of the tree root after it or the `active` swap failed; a directory left at
///   the reserved `active.tmp` scratch name is one way to reach it, since clearing
///   that name is a `remove_file`. `active` still resolves to the previous
///   generation, so this too is fail-closed for every reader of the tree, but
///   `gen-<n>` is now on disk as a complete generation nothing points at. That
///   leftover is inert rather than live material: allocation only ever counts upward
///   from it, so the next activation stages `gen-<n+1>`, and the prune at the end of
///   that activation removes it. A caller must not read this `Err` as "no generation
///   directory was written" — only as "the previous material is still what readers
///   resolve".
/// - **After the swap** — a [`GenerationError::Reload`], or an I/O fault while
///   flushing the tree root after the swap or while pruning. `active` already points
///   at `gen-<n>` and the new material is live; what failed is making that swap
///   durable, notifying the tree's readers, or clearing the superseded generations,
///   not the installation. A caller must not read this `Err` as "the previous
///   material is still in place". Recovery is another activation: a call over the
///   same bytes is the step 2 no-op, which neither retries the reload nor prunes, so
///   the leftovers go when the next activation that changes something reaches step 5.
pub(crate) fn activate_generation<E>(
    tree: &GenerationTree<'_>,
    material: &[GenerationFile],
    validate: impl FnOnce(&Path, &[GenerationFile]) -> Result<(), E>,
) -> Result<Activation, E>
where
    E: From<GenerationError>,
{
    check_material(material)?;

    let root = tree.root;
    let active = active_link(root);
    if let Some(current) = current_generation(root)?
        && active_matches(&active, material)?
    {
        return Ok(Activation {
            generation: current,
            changed: false,
        });
    }

    let generation = next_generation(root)?;
    let final_dir = generation_dir(root, generation);
    let tmp_dir = tmp_generation_dir(root, generation);

    // Fresh, root-only staging copy. Remove any leftover from a prior aborted run.
    remove_dir_all_if_present(&tmp_dir)?;
    make_dir_0700(&tmp_dir)?;
    for file in material {
        write_file_0600(&tmp_dir.join(&file.name), &file.bytes)?;
    }

    // Validate the bytes now on disk in the root-owned copy — not the caller's
    // buffer — so what is validated is exactly what is installed.
    let mut copied = Vec::with_capacity(material.len());
    for file in material {
        let path = tmp_dir.join(&file.name);
        copied.push(GenerationFile::new(file.name.clone(), read_file(&path)?));
    }
    if let Err(err) = validate(&tmp_dir, &copied) {
        // Fail closed: discard the rejected copy, leave `active` as it was.
        let _ = remove_dir_all_if_present(&tmp_dir);
        return Err(err);
    }

    // Finalise the generation, then swap `active` onto it atomically. Each step
    // is flushed as it is taken, because what this sequence publishes is state
    // the tree's readers resolve at every start: an `active` that survives a
    // crash naming a generation whose files did not is the failure to prevent.
    //
    // The material files are already down, one at a time, but the entries
    // naming them inside `gen-<n>.tmp` are not until the directory itself is
    // flushed, and that has to happen before the rename that finalises it.
    sync_dir(&tmp_dir).map_err(|e| GenerationError::io(&tmp_dir, e))?;
    rename(&tmp_dir, &final_dir)?;
    // The generation's own entry lives in the tree root, and it has to be on
    // disk before anything at that root can name it. A single flush after the
    // swap instead of this one is not equivalent: it would let the filesystem
    // commit `active` ahead of the generation directory it points at.
    sync_dir(root).map_err(|e| GenerationError::io(root, e))?;
    swap_active_symlink(root, &active, generation)?;
    // The swap's durability is this flush and nothing else: a symlink cannot be
    // flushed itself — `File::open` follows it, and an `O_PATH`/`O_NOFOLLOW`
    // descriptor cannot be `fsync`ed — so the root's entry is all there is.
    sync_dir(root).map_err(|e| GenerationError::io(root, e))?;
    if let Some(unit) = tree.reload_unit {
        reload_if_active(unit)?;
    }
    prune_generations(root, generation)?;
    Ok(Activation {
        generation,
        changed: true,
    })
}

/// Refuses a material set the engine could not write exactly as intended: an empty
/// set, a duplicate name, or a name that is not a single non-empty path component.
///
/// A name that is a single component cannot traverse out of `gen-<n>.tmp/`, and
/// distinct names cannot collide with each other. There is deliberately **no**
/// reserved-name rule: `active` and `gen-<n>` are structural at the tree root only,
/// and a material file lands inside a generation directory, so such a name is inert.
fn check_material(material: &[GenerationFile]) -> Result<(), GenerationError> {
    if material.is_empty() {
        return Err(GenerationError::EmptyMaterial);
    }
    for (index, file) in material.iter().enumerate() {
        if !is_single_component(&file.name) {
            return Err(GenerationError::InvalidName(file.name.clone()));
        }
        if material
            .iter()
            .take(index)
            .any(|earlier| earlier.name == file.name)
        {
            return Err(GenerationError::DuplicateName(file.name.clone()));
        }
    }
    Ok(())
}

/// Returns whether `name` is exactly one normal path component.
///
/// The check runs over the name's `OsStr` bytes, never over a UTF-8 view of them, so
/// a name that is not valid UTF-8 is judged by the same rule as any other rather
/// than being refused or mangled. It rejects the empty name, `.`, `..`, `./x`,
/// anything carrying a separator, and a trailing separator that `components()` would
/// otherwise normalise away.
fn is_single_component(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    let first_is_the_whole_name =
        matches!(components.next(), Some(Component::Normal(c)) if c == name);
    first_is_the_whole_name && components.next().is_none()
}

/// Returns whether every file of `material` byte-matches its counterpart under
/// `active` — the idempotence check that makes a repeated activation cheap and keeps
/// generation numbers from churning.
fn active_matches(active: &Path, material: &[GenerationFile]) -> Result<bool, GenerationError> {
    for file in material {
        let path = active.join(&file.name);
        match std::fs::read(&path) {
            Ok(bytes) if bytes == file.bytes => {}
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(GenerationError::io(&path, e)),
        }
    }
    Ok(true)
}

/// The `active` symlink at the root of a trust tree, which readers resolve their
/// material through.
pub(crate) fn active_link(root: &Path) -> PathBuf {
    root.join(ACTIVE_LINK)
}

/// The generation directory `<root>/gen-<generation>/`.
pub(crate) fn generation_dir(root: &Path, generation: u64) -> PathBuf {
    root.join(format!("{GENERATION_PREFIX}{generation}"))
}

/// Returns the generation `active` currently points at, if any.
fn current_generation(root: &Path) -> Result<Option<u64>, GenerationError> {
    let active = active_link(root);
    match std::fs::read_link(&active) {
        Ok(target) => Ok(parse_generation(&target)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(GenerationError::io(&active, e)),
    }
}

/// Returns one greater than the highest existing generation number, or 1 when none
/// exist. Numbering only ever increases, so a just-superseded generation's directory
/// is never reused while it might still be resolved through an in-flight read.
fn next_generation(root: &Path) -> Result<u64, GenerationError> {
    let mut max = 0;
    for entry in read_dir(root)? {
        let entry = entry.map_err(|e| GenerationError::io(root, e))?;
        if let Some(n) = parse_generation(&PathBuf::from(entry.file_name())) {
            max = max.max(n);
        }
    }
    Ok(max + 1)
}

/// Removes every generation directory other than `keep`, plus any leftover
/// `gen-<n>.tmp`. Every other entry in the tree root is left alone.
fn prune_generations(root: &Path, keep: u64) -> Result<(), GenerationError> {
    for entry in read_dir(root)? {
        let entry = entry.map_err(|e| GenerationError::io(root, e))?;
        let name = PathBuf::from(entry.file_name());
        let is_stale_tmp = parse_tmp_generation(&name).is_some();
        let is_old_gen = parse_generation(&name).is_some_and(|n| n != keep);
        if is_stale_tmp || is_old_gen {
            remove_dir_all_if_present(&root.join(name))?;
        }
    }
    Ok(())
}

/// Parses a `gen-<n>` directory name into its generation number, ignoring `active`,
/// `gen-<n>.tmp`, and every other entry a tree root may hold.
///
/// The spelling must be the canonical one the engine writes. `u64::from_str` also
/// accepts a leading `+` and leading zeros, so `gen-01` and `gen-+1` would otherwise
/// parse as generation 1 — names the engine never creates, and therefore somebody
/// else's directories, which pruning would remove and allocation would count toward
/// the next index. Requiring the digits to round-trip through `to_string` keeps the
/// predicate to exactly the names the engine owns.
pub(crate) fn parse_generation(name: &Path) -> Option<u64> {
    let name = name.file_name()?.to_str()?;
    let digits = name.strip_prefix(GENERATION_PREFIX)?;
    let generation = digits.parse::<u64>().ok()?;
    (digits == generation.to_string()).then_some(generation)
}

/// Parses a `gen-<n>.tmp` staging directory's name into its generation number, and
/// nothing else.
///
/// Both halves are parsed — the extension must be exactly `tmp` and the stem exactly
/// the canonical `gen-<n>` [`parse_generation`] accepts — rather than the name being
/// prefix-matched, because pruning removes what this accepts. Only the engine creates
/// a staging directory, and only ever under this name, so anything else the tree root
/// holds is somebody else's file and survives: neither `gen-retention.tmp` nor
/// `gen-01.tmp` is a generation. Parsing also needs no lossy UTF-8 view of the name,
/// since a name that is not valid UTF-8 is by construction not this one.
fn parse_tmp_generation(name: &Path) -> Option<u64> {
    let name = Path::new(name.file_name()?);
    if name.extension()? != TMP_EXTENSION {
        return None;
    }
    parse_generation(Path::new(name.file_stem()?))
}

/// The temporary directory a generation is assembled and validated in before it is
/// finalised (`gen-<n>.tmp`).
fn tmp_generation_dir(root: &Path, generation: u64) -> PathBuf {
    root.join(format!("{GENERATION_PREFIX}{generation}.{TMP_EXTENSION}"))
}

/// Atomically repoints `active` at `gen-<generation>` by creating a temporary symlink
/// and renaming it over the existing one (rename replaces a symlink without following
/// it, so a reader never observes a missing or half-written `active`).
///
/// `<root>/active.tmp` is the scratch entry that protocol needs, and the name is
/// **reserved for it**: a removable entry there — a symlink or a plain file, which is
/// what an aborted swap can leave — is removed before the link is created, because
/// `symlink` refuses an existing path and such a leftover would otherwise fail every
/// later activation at the same step. So this is the one root entry the engine deletes
/// without parsing it — root-owned state kept beside a tree's generations may carry
/// any other name, but not this one. A *directory* there is not removed at all:
/// `remove_file` fails on it and the swap returns that error, with `gen-<n>` already
/// finalised and `active` still on the previous generation.
fn swap_active_symlink(root: &Path, active: &Path, generation: u64) -> Result<(), GenerationError> {
    let target = format!("{GENERATION_PREFIX}{generation}");
    let tmp_link = root.join(format!("{ACTIVE_LINK}.{TMP_EXTENSION}"));
    // Remove a leftover temp link from a prior aborted swap, then create ours.
    match std::fs::remove_file(&tmp_link) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(GenerationError::io(&tmp_link, e)),
    }
    std::os::unix::fs::symlink(&target, &tmp_link)
        .map_err(|e| GenerationError::io(&tmp_link, e))?;
    rename(&tmp_link, active)
}

// Every `systemctl` invocation `reload_if_active` makes in a test build, so a test
// can assert that a tree with no reload unit makes none. Thread-local, so tests
// running in parallel never observe each other's calls.
#[cfg(test)]
thread_local! {
    pub(crate) static SYSTEMCTL_CALLS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Reloads `unit` only when it is running, so a first-install seed (the unit not yet
/// started) and a test host (no such unit) skip cleanly, while a live rotation
/// reloads. A reload that is attempted and fails is a hard error.
fn reload_if_active(unit: &str) -> Result<(), GenerationError> {
    #[cfg(test)]
    SYSTEMCTL_CALLS.with_borrow_mut(|calls| calls.push(unit.to_string()));

    let active = Command::new(SYSTEMCTL)
        .args(["is-active", "--quiet", unit])
        .status();
    match active {
        Ok(status) if status.success() => {
            let reload = Command::new(SYSTEMCTL)
                .args(["reload", unit])
                .status()
                .map_err(|e| GenerationError::Reload {
                    unit: unit.to_string(),
                    reason: e.to_string(),
                })?;
            if !reload.success() {
                return Err(GenerationError::Reload {
                    unit: unit.to_string(),
                    reason: format!("`systemctl reload {unit}` exited with {reload}"),
                });
            }
            Ok(())
        }
        // Not active, or systemctl unavailable (seed time / test): nothing to reload.
        _ => Ok(()),
    }
}

// --- small filesystem helpers that annotate their path on error ---

fn read_file(path: &Path) -> Result<Vec<u8>, GenerationError> {
    std::fs::read(path).map_err(|e| GenerationError::io(path, e))
}

/// Writes `bytes` to a new file that is `0600` from the moment it exists.
///
/// The mode is asked for at creation rather than applied afterwards. Creating
/// first and tightening second leaves the contents readable by anyone on the
/// host for as long as the two calls take, and what goes through here is trust
/// material — a certificate, a CA bundle, a private key. `create_new` also makes a
/// pre-existing path an error rather than a silent overwrite, which is what staged
/// trust material wants.
///
/// The bytes are on disk when this returns, not merely written: what goes through
/// here is staged into a generation the tree reads back at every start, so it has to
/// survive a crash between the staging and the rename that publishes it.
pub(crate) fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), GenerationError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| GenerationError::io(path, e))?;
    file.write_all(bytes)
        .map_err(|e| GenerationError::io(path, e))?;
    // Protects the material itself: the generation directory holding this file is
    // renamed into place and pointed at by `active`, and a reader resolving that
    // link after a crash must not find an empty or truncated file behind it.
    file.sync_all().map_err(|e| GenerationError::io(path, e))
}

/// Creates `path` as a directory that is `0700` from the moment it exists.
///
/// Same reasoning as [`write_file_0600`]: a directory created with the umask's
/// mode and narrowed afterwards is traversable in between.
pub(crate) fn make_dir_0700(path: &Path) -> Result<(), GenerationError> {
    use std::os::unix::fs::DirBuilderExt as _;

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| GenerationError::io(path, e))
}

fn rename(from: &Path, to: &Path) -> Result<(), GenerationError> {
    std::fs::rename(from, to).map_err(|e| GenerationError::io(to, e))
}

fn read_dir(path: &Path) -> Result<std::fs::ReadDir, GenerationError> {
    std::fs::read_dir(path).map_err(|e| GenerationError::io(path, e))
}

fn remove_dir_all_if_present(path: &Path) -> Result<(), GenerationError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GenerationError::io(path, e)),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{
        GenerationError, GenerationFile, GenerationTree, SYSTEMCTL_CALLS, activate_generation,
        parse_generation, parse_tmp_generation, sync_dir,
    };
    use crate::layout::REQUIRE_TRUST_PIN_MARKER;

    /// A caller's error type: whatever its validator rejects material with, plus the
    /// engine's own faults absorbed through `From`. Nothing else is required of it,
    /// which is the point — a tree brings its own taxonomy.
    #[derive(Debug)]
    enum TestError {
        Engine(GenerationError),
        Rejected(String),
    }

    impl From<GenerationError> for TestError {
        fn from(err: GenerationError) -> Self {
            TestError::Engine(err)
        }
    }

    struct Tree {
        _tmp: TempDir,
        root: PathBuf,
    }

    fn tree() -> Tree {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path().join("release-trust");
        std::fs::create_dir_all(&root).expect("tree root");
        Tree { _tmp: tmp, root }
    }

    fn material(files: &[(&str, &[u8])]) -> Vec<GenerationFile> {
        files
            .iter()
            .map(|(name, bytes)| GenerationFile::new(*name, bytes.to_vec()))
            .collect()
    }

    /// A validator standing in for a real one: it accepts any non-empty file, which
    /// is enough for the tests whose subject is the sequence rather than the verdict.
    fn accept(_dir: &Path, copied: &[GenerationFile]) -> Result<(), TestError> {
        if let Some(empty) = copied.iter().find(|file| file.bytes.is_empty()) {
            return Err(TestError::Rejected(format!(
                "{} is empty",
                Path::new(&empty.name).display()
            )));
        }
        Ok(())
    }

    /// Activates over a tree with nothing to reload — the shape the second trust
    /// tree has, and the one that proves the engine needs no unit.
    fn activate(
        root: &Path,
        files: &[GenerationFile],
    ) -> Result<crate::roxyd_trust::Activation, TestError> {
        let tree = GenerationTree {
            root,
            reload_unit: None,
        };
        activate_generation(&tree, files, accept)
    }

    fn read_link_target(root: &Path) -> String {
        std::fs::read_link(root.join("active"))
            .expect("active symlink")
            .to_string_lossy()
            .into_owned()
    }

    fn entries(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<OsString> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn a_malformed_material_set_is_refused_before_anything_is_staged() {
        let t = tree();

        assert!(matches!(
            activate(&t.root, &[]),
            Err(TestError::Engine(GenerationError::EmptyMaterial))
        ));

        for name in ["", ".", "..", "a/b", "./x", "/abs", "sub/"] {
            let files = material(&[(name, b"x")]);
            assert!(
                matches!(
                    activate(&t.root, &files),
                    Err(TestError::Engine(GenerationError::InvalidName(bad))) if bad == name
                ),
                "`{name}` must be refused as a name that is not a single component",
            );
        }

        let duplicated = material(&[("same", b"one"), ("other", b"two"), ("same", b"three")]);
        assert!(matches!(
            activate(&t.root, &duplicated),
            Err(TestError::Engine(GenerationError::DuplicateName(name))) if name == "same"
        ));

        assert!(
            entries(&t.root).is_empty(),
            "a refusal creates no directory",
        );
    }

    #[test]
    fn structural_names_are_inert_inside_a_generation() {
        let t = tree();
        let first = material(&[
            ("active", b"a file, not a link"),
            ("gen-2", b"a file, not a dir"),
        ]);
        let seeded = activate(&t.root, &first).expect("seed");
        assert_eq!(seeded.generation, 1);
        assert!(seeded.changed);
        assert_eq!(read_link_target(&t.root), "gen-1");
        assert_eq!(
            std::fs::read(t.root.join("gen-1/active")).expect("read"),
            b"a file, not a link",
        );
        assert_eq!(
            std::fs::read(t.root.join("gen-1/gen-2")).expect("read"),
            b"a file, not a dir",
        );

        // The next index still comes from the root, and the prune still finds gen-1.
        let second = material(&[("active", b"new bytes"), ("gen-2", b"new bytes too")]);
        let rotated = activate(&t.root, &second).expect("rotate");
        assert_eq!(rotated.generation, 2);
        assert_eq!(read_link_target(&t.root), "gen-2");
        assert!(!t.root.join("gen-1").exists(), "gen-1 pruned");
        assert_eq!(
            std::fs::read(t.root.join("gen-2/gen-2")).expect("read"),
            b"new bytes too",
        );
    }

    #[test]
    fn the_validator_sees_the_staged_copy_and_a_failure_changes_nothing() {
        let t = tree();
        let seed = material(&[("one", b"first"), ("two", b"second")]);
        activate(&t.root, &seed).expect("seed");
        let live = std::fs::read(t.root.join("active/one")).expect("read");

        let rejected = material(&[("one", b"replacement"), ("two", b"other replacement")]);
        let tmp_dir = t.root.join("gen-2.tmp");
        let tree = GenerationTree {
            root: &t.root,
            reload_unit: None,
        };
        let err = activate_generation(&tree, &rejected, |dir, copied| {
            assert_eq!(dir, tmp_dir, "the validator is handed the staged copy");
            assert_eq!(copied.len(), rejected.len());
            for (file, want) in copied.iter().zip(&rejected) {
                assert_eq!(file.name, want.name, "same names, in the same order");
                // What arrived is what is on disk in `gen-<n>.tmp`, not a buffer
                // the caller still owns.
                assert_eq!(
                    file.bytes,
                    std::fs::read(dir.join(&file.name)).expect("read back"),
                );
            }
            Err::<(), TestError>(TestError::Rejected("no".to_string()))
        })
        .expect_err("the validator refused");

        assert!(matches!(err, TestError::Rejected(ref reason) if reason == "no"));
        assert!(!t.root.join("gen-2.tmp").exists(), "the tmp copy is gone");
        assert!(!t.root.join("gen-2").exists());
        assert_eq!(read_link_target(&t.root), "gen-1");
        assert_eq!(
            std::fs::read(t.root.join("active/one")).expect("read"),
            live,
            "the live material is byte-identical",
        );
    }

    #[test]
    fn a_tree_with_no_reload_unit_runs_no_systemctl() {
        let t = tree();
        SYSTEMCTL_CALLS.with_borrow_mut(Vec::clear);

        activate(&t.root, &material(&[("one", b"bytes")])).expect("seed");
        assert!(
            SYSTEMCTL_CALLS.with_borrow(Vec::is_empty),
            "`reload_unit: None` skips the reload step entirely",
        );

        // The probe does record a tree that has a unit, so the assertion above is
        // about the skipped step and not about a probe that never fires.
        let unit = "deploy-core-test-nonexistent.service";
        let tree = GenerationTree {
            root: &t.root,
            reload_unit: Some(unit),
        };
        activate_generation(&tree, &material(&[("one", b"new bytes")]), accept).expect("rotate");
        assert_eq!(SYSTEMCTL_CALLS.with_borrow(Vec::clone), vec![unit]);
        SYSTEMCTL_CALLS.with_borrow_mut(Vec::clear);
    }

    #[test]
    fn unchanged_material_is_an_idempotent_no_op() {
        let t = tree();
        let files = material(&[("one", b"first"), ("two", b"second")]);
        let seeded = activate(&t.root, &files).expect("seed");
        assert_eq!(seeded.generation, 1);

        let again = activate(&t.root, &files).expect("idempotent");
        assert_eq!(again.generation, 1);
        assert!(!again.changed);
        assert!(!t.root.join("gen-2").exists());
        assert!(!t.root.join("gen-2.tmp").exists());
        assert_eq!(entries(&t.root), vec!["active", "gen-1"]);
    }

    /// The no-op needs *every* named file to match. One file whose bytes changed, or
    /// one name the active generation does not hold at all, is a new generation —
    /// otherwise a partially rotated material set would silently keep serving the old
    /// bytes for the files that happened to match.
    #[test]
    fn one_changed_or_absent_file_defeats_the_idempotent_no_op() {
        let t = tree();
        activate(&t.root, &material(&[("one", b"first"), ("two", b"second")])).expect("seed");

        let partial = material(&[("one", b"first"), ("two", b"changed")]);
        let rotated = activate(&t.root, &partial).expect("rotate");
        assert_eq!(rotated.generation, 2);
        assert!(rotated.changed, "one changed file is not a no-op");

        // A name the active generation does not hold at all reads as a mismatch
        // rather than as an absent-file error.
        let widened = material(&[
            ("one", b"first"),
            ("two", b"changed"),
            ("three", b"a name active does not hold"),
        ]);
        let grown = activate(&t.root, &widened).expect("widen");
        assert_eq!(grown.generation, 3);
        assert!(grown.changed);
        assert_eq!(read_link_target(&t.root), "gen-3");
        assert_eq!(
            std::fs::read(t.root.join("gen-3/three")).expect("read"),
            b"a name active does not hold",
        );
    }

    /// Staging removes a leftover `gen-<n>.tmp` before creating its own. Without that
    /// step an aborted earlier run would wedge the tree at that index for good:
    /// `make_dir_0700` refuses an existing directory, so every later activation would
    /// fail on the same debris.
    #[test]
    fn a_leftover_staging_directory_from_an_aborted_run_is_replaced() {
        let t = tree();
        activate(&t.root, &material(&[("one", b"first")])).expect("seed");

        // Debris at exactly the index the next activation allocates, holding a file
        // whose name the new material also carries.
        let stale = t.root.join("gen-2.tmp");
        std::fs::create_dir(&stale).expect("stale tmp");
        std::fs::write(stale.join("one"), b"debris").expect("stale file");

        let rotated = activate(&t.root, &material(&[("one", b"second")])).expect("rotate");
        assert_eq!(
            rotated.generation, 2,
            "a `gen-<n>.tmp` is not itself a generation, so the index is unaffected",
        );
        assert_eq!(
            std::fs::read(t.root.join("gen-2/one")).expect("read"),
            b"second",
            "the debris was discarded rather than reused",
        );
        assert_eq!(entries(&t.root), vec!["active", "gen-2"]);
    }

    #[test]
    fn successive_generations_allocate_and_prune() {
        let t = tree();
        assert_eq!(
            activate(&t.root, &material(&[("one", b"first")]))
                .expect("seed")
                .generation,
            1,
        );
        assert_eq!(
            activate(&t.root, &material(&[("one", b"second")]))
                .expect("rotate")
                .generation,
            2,
        );
        assert_eq!(read_link_target(&t.root), "gen-2");
        assert_eq!(entries(&t.root), vec!["active", "gen-2"]);
    }

    /// The modes are the engine's, not a caller's: a tree that brings its own material
    /// set and its own validator still gets a `0700` generation directory holding
    /// `0600` files, because the policy is deliberately not a parameter.
    #[test]
    fn a_generation_is_root_only_whatever_the_tree() {
        use std::os::unix::fs::PermissionsExt as _;

        let t = tree();
        activate(&t.root, &material(&[("one", b"first"), ("two", b"second")])).expect("seed");

        let mode_of = |path: &Path| {
            std::fs::metadata(path)
                .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
                .permissions()
                .mode()
                & 0o777
        };
        let generation = t.root.join("gen-1");
        assert_eq!(mode_of(&generation), 0o700, "the generation directory");
        for name in ["one", "two"] {
            assert_eq!(mode_of(&generation.join(name)), 0o600, "{name}");
        }
    }

    #[test]
    fn the_pin_marker_survives_an_activation_and_a_prune() {
        let t = tree();
        let marker = t.root.join(REQUIRE_TRUST_PIN_MARKER);
        std::fs::write(&marker, b"pinned").expect("write marker");

        activate(&t.root, &material(&[("one", b"first")])).expect("seed");
        assert_eq!(std::fs::read(&marker).expect("read marker"), b"pinned");

        activate(&t.root, &material(&[("one", b"second")])).expect("rotate");
        assert!(!t.root.join("gen-1").exists(), "gen-1 pruned");
        assert_eq!(
            std::fs::read(&marker).expect("read marker"),
            b"pinned",
            "the engine never treats the marker as a generation",
        );
    }

    /// The tree root holds more than generations, and a name that merely resembles a
    /// staging directory is not one. Pruning parses both halves of `gen-<n>.tmp`, so it
    /// removes only what the engine itself could have left behind.
    #[test]
    fn a_root_entry_that_only_looks_like_a_staging_directory_survives_a_prune() {
        let t = tree();
        activate(&t.root, &material(&[("one", b"first")])).expect("seed");

        // Root-owned state whose name shares the generation prefix and the extension
        // without being a generation, beside real debris from an aborted run.
        let retention = t.root.join("gen-retention.tmp");
        std::fs::write(&retention, b"root-owned state").expect("write retention");
        // A non-canonical numeric spelling the engine never writes: `u64::from_str`
        // parses it, but `gen-01` and `gen-01.tmp` are somebody else's names.
        let padded_tmp = t.root.join("gen-01.tmp");
        std::fs::write(&padded_tmp, b"not staging").expect("write padded tmp");
        let padded_gen = t.root.join("gen-007");
        std::fs::create_dir(&padded_gen).expect("padded gen");
        let debris = t.root.join("gen-9.tmp");
        std::fs::create_dir(&debris).expect("stale tmp");

        let rotated = activate(&t.root, &material(&[("one", b"second")])).expect("rotate");
        assert_eq!(
            rotated.generation, 2,
            "no entry parses as a generation, so none moves the index",
        );
        assert_eq!(
            std::fs::read(&retention).expect("read retention"),
            b"root-owned state",
            "`gen-retention.tmp` is not a staging directory the engine ever created",
        );
        assert_eq!(
            std::fs::read(&padded_tmp).expect("read padded tmp"),
            b"not staging",
            "`gen-01.tmp` is not the canonical staging name the engine writes",
        );
        assert!(
            padded_gen.is_dir(),
            "`gen-007` is not the canonical generation name the engine writes",
        );
        assert!(!debris.exists(), "a real `gen-<n>.tmp` leftover is pruned");
        assert_eq!(
            entries(&t.root),
            vec![
                "active",
                "gen-007",
                "gen-01.tmp",
                "gen-2",
                "gen-retention.tmp",
            ],
        );
    }

    /// `active.tmp` is the swap protocol's scratch entry and the one root name the
    /// engine reserves: a file or symlink there is removed before the link is created,
    /// since `symlink` refuses an existing path and a leftover from an aborted swap
    /// would otherwise fail every later activation at that step. The boundary is
    /// exact — the reservation is the literal name, so a neighbour that merely starts
    /// with it survives like any other root-owned file.
    #[test]
    fn the_swap_scratch_name_is_reserved_and_its_neighbours_are_not() {
        let t = tree();
        activate(&t.root, &material(&[("one", b"first")])).expect("seed");

        let scratch = t.root.join("active.tmp");
        std::fs::write(&scratch, b"aborted swap debris").expect("write scratch");
        let neighbour = t.root.join("active.tmp.bak");
        std::fs::write(&neighbour, b"root-owned state").expect("write neighbour");

        let rotated = activate(&t.root, &material(&[("one", b"second")])).expect("rotate");
        assert_eq!(
            rotated.generation, 2,
            "debris at the scratch name does not wedge the swap",
        );
        assert_eq!(read_link_target(&t.root), "gen-2");
        assert!(
            !scratch.exists(),
            "the engine clears a file or symlink at `active.tmp` before every swap, \
             whatever put it there",
        );
        assert_eq!(
            std::fs::read(&neighbour).expect("read neighbour"),
            b"root-owned state",
            "only the exact name is reserved",
        );
        assert_eq!(entries(&t.root), vec!["active", "active.tmp.bak", "gen-2"]);
    }

    /// The clearing of the reserved scratch name is a `remove_file`, which covers what
    /// an aborted swap can leave — a symlink or a plain file — and fails on a
    /// directory. So a directory there is neither removed nor stepped around: the
    /// swap returns that error, and the tree lands in the documented
    /// finalised-but-not-live state, with `gen-<n>` complete on disk and `active`
    /// still on the previous generation. This is the boundary the module
    /// documentation qualifies; asserting it keeps the two from drifting.
    #[test]
    fn a_directory_at_the_swap_scratch_name_fails_the_swap_after_finalising() {
        let t = tree();
        activate(&t.root, &material(&[("one", b"first")])).expect("seed");

        let scratch = t.root.join("active.tmp");
        std::fs::create_dir(&scratch).expect("create scratch directory");
        std::fs::write(scratch.join("occupant"), b"not the engine's").expect("write occupant");

        let err = activate(&t.root, &material(&[("one", b"second")])).expect_err("swap fails");
        assert!(
            matches!(err, TestError::Engine(GenerationError::Io { ref path, .. })
                if Path::new(path) == scratch),
            "the swap reports the scratch name it could not clear, got {err:?}",
        );

        assert_eq!(
            read_link_target(&t.root),
            "gen-1",
            "`active` still resolves to the previous generation",
        );
        assert!(
            t.root.join("gen-2").is_dir(),
            "`gen-2` was finalised before the swap and stays on disk, unreferenced",
        );
        assert_eq!(
            std::fs::read(scratch.join("occupant")).expect("read occupant"),
            b"not the engine's",
            "a directory at the scratch name is left exactly as it was",
        );
        assert_eq!(
            entries(&t.root),
            vec!["active", "active.tmp", "gen-1", "gen-2"],
        );

        // The leftover is inert: once the obstruction is gone, the next activation
        // counts past it and prunes it.
        std::fs::remove_dir_all(&scratch).expect("remove scratch directory");
        let rotated = activate(&t.root, &material(&[("one", b"third")])).expect("rotate");
        assert_eq!(rotated.generation, 3);
        assert_eq!(entries(&t.root), vec!["active", "gen-3"]);
    }

    /// Both predicates decide a removal, so each accepts only the canonical spelling
    /// the engine writes — never every spelling `u64::from_str` happens to parse.
    #[test]
    fn the_generation_predicates_accept_only_canonical_names() {
        for (name, generation, staging) in [
            ("gen-1", Some(1), None),
            ("gen-12", Some(12), None),
            ("gen-1.tmp", None, Some(1)),
            ("gen-01", None, None),
            ("gen-01.tmp", None, None),
            ("gen-007", None, None),
            ("gen-+1", None, None),
            ("gen-+1.tmp", None, None),
            ("gen-", None, None),
            ("gen-retention.tmp", None, None),
            ("gen-1.tmp.tmp", None, None),
            ("active", None, None),
        ] {
            let path = Path::new(name);
            assert_eq!(parse_generation(path), generation, "{name}");
            assert_eq!(parse_tmp_generation(path), staging, "{name}");
        }
    }

    /// A material file's bytes are a private key on the mTLS tree, so formatting one
    /// must never render them — nor may a derived `Debug` on anything holding one.
    #[test]
    fn formatting_a_material_file_redacts_its_bytes() {
        let key = GenerationFile::new("roxyd-key.pem", b"-----BEGIN PRIVATE KEY-----".to_vec());
        let rendered = format!("{key:?}");
        assert!(rendered.contains("roxyd-key.pem"), "{rendered}");
        assert!(rendered.contains("<redacted, 27 bytes>"), "{rendered}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
    }

    #[test]
    fn engine_error_messages_name_no_tree() {
        let faults = [
            GenerationError::io(
                Path::new("/etc/release-trust/gen-1.tmp"),
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            ),
            GenerationError::EmptyMaterial,
            GenerationError::DuplicateName(OsString::from("dup")),
            GenerationError::InvalidName(OsString::from("..")),
            GenerationError::Reload {
                unit: "some.service".to_string(),
                reason: "exited with 1".to_string(),
            },
        ];
        for fault in faults {
            let rendered = fault.to_string();
            assert!(
                !rendered.contains("roxyd"),
                "the engine reports for every tree: {rendered}",
            );
        }
    }

    /// A directory flush that fails is an error the caller sees, carrying the path
    /// that was flushed — mapped exactly as the three `sync_dir` call sites in
    /// [`activate_generation`] map it, so what is checked here is the plumbing those
    /// sites use and not a spelling private to this test.
    #[test]
    fn a_failed_directory_flush_names_the_flushed_path() {
        let tree = tree();
        let missing = tree.root.join("gen-7.tmp");

        let err = sync_dir(&missing)
            .map_err(|e| GenerationError::io(&missing, e))
            .expect_err("flushing a directory that does not exist must not succeed");

        match err {
            GenerationError::Io { path, source } => {
                assert_eq!(path, missing.to_string_lossy());
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected a path-carrying i/o error, got: {other:?}"),
        }
    }
}
