use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::fault::{self, Corruption, Seam, Step};
use super::trusted_dir::{
    DirFacts, TrustedDirError, canonical_components, judge_ancestor, judge_selected,
    open_trusted_dir,
};
use super::*;
use crate::package::{
    CopyMismatchKind, DirectoryTrustReason, PublicationError, PublicationOperation, RetainedReader,
};

const EUID: u32 = 1000;
const FOREIGN: u32 = 2000;
const ROOT: u32 = 0;
const BIG: u64 = 1 << 30;

fn root() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(dir.path()).unwrap();
    (dir, path)
}

fn nz(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

fn scope(parent: &Path, budget: u64) -> RetentionScope {
    RetentionScope::new(parent, budget, nz(64)).unwrap()
}

fn snap(scope: &RetentionScope, bytes: &[u8]) -> RetainedBytes {
    scope.snapshot_from(&mut &bytes[..], u64::MAX).unwrap()
}

fn read_all(bytes: &RetainedBytes) -> Vec<u8> {
    let mut out = Vec::new();
    bytes.reader().read_to_end(&mut out).unwrap();
    out
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort_unstable();
    names
}

fn publish_siblings(dir: &Path) -> Vec<String> {
    names_in(dir)
        .into_iter()
        .filter(|n| n.starts_with(".deploy-core-publish-"))
        .collect()
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn retention_io(err: RetentionError) -> (RetentionOperation, Option<PathBuf>, io::ErrorKind) {
    match err {
        RetentionError::Io {
            operation,
            path,
            source,
        } => (operation, path, source.kind()),
        other => panic!("expected RetentionError::Io, got {other:?}"),
    }
}

fn publication_io(err: PublicationError) -> (PublicationOperation, Option<PathBuf>, io::ErrorKind) {
    match err {
        PublicationError::Io {
            operation,
            path,
            source,
        } => (operation, path, source.kind()),
        other => panic!("expected PublicationError::Io, got {other:?}"),
    }
}

fn unsafe_reason(err: TrustedDirError) -> (PathBuf, DirectoryTrustReason) {
    match err {
        TrustedDirError::Unsafe { path, reason } => (path, reason),
        TrustedDirError::Io { path, source } => {
            panic!(
                "expected a refusal, got i/o at {}: {source}",
                path.display()
            )
        }
    }
}

/// The steps in `record` that are one of `keep`, with consecutive repeats
/// collapsed.
fn sequence(record: &[Step], keep: &[Step]) -> Vec<Step> {
    let mut out: Vec<Step> = record
        .iter()
        .copied()
        .filter(|s| keep.contains(s))
        .collect();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Trusted directory policy, over synthetic facts

fn facts(uid: u32, mode: u32) -> DirFacts {
    DirFacts { uid, mode }
}

#[test]
fn selected_directory_policy() {
    use DirectoryTrustReason::{GroupOrOtherWritable, NotWritableByEffectiveUser, UntrustedOwner};
    assert_eq!(judge_selected(facts(EUID, 0o700), EUID), Ok(()));
    assert_eq!(judge_selected(facts(EUID, 0o755), EUID), Ok(()));
    assert_eq!(judge_selected(facts(ROOT, 0o755), ROOT), Ok(()));
    assert_eq!(
        judge_selected(facts(FOREIGN, 0o700), EUID),
        Err(UntrustedOwner)
    );
    for mode in [0o770, 0o707, 0o777, 0o1777] {
        assert_eq!(
            judge_selected(facts(EUID, mode), EUID),
            Err(GroupOrOtherWritable),
            "mode {mode:o}"
        );
    }
    assert_eq!(
        judge_selected(facts(EUID, 0o500), EUID),
        Err(NotWritableByEffectiveUser)
    );
    assert_eq!(
        judge_selected(facts(ROOT, 0o755), EUID),
        Err(NotWritableByEffectiveUser)
    );
}

#[test]
fn ancestor_policy() {
    use DirectoryTrustReason::UntrustedAncestor;
    let child = facts(EUID, 0o700);
    assert_eq!(judge_ancestor(facts(ROOT, 0o755), child, EUID), Ok(()));
    assert_eq!(judge_ancestor(facts(EUID, 0o755), child, EUID), Ok(()));
    assert_eq!(
        judge_ancestor(facts(FOREIGN, 0o755), child, EUID),
        Err(UntrustedAncestor)
    );
    assert_eq!(
        judge_ancestor(facts(ROOT, 0o777), child, EUID),
        Err(UntrustedAncestor)
    );
    // The allowed shape: a caller-owned private directory directly beneath
    // a root-owned sticky ancestor, as `/tmp/<private>`.
    assert_eq!(judge_ancestor(facts(ROOT, 0o1777), child, EUID), Ok(()));
    assert_eq!(
        judge_ancestor(facts(ROOT, 0o1777), facts(ROOT, 0o700), EUID),
        Ok(())
    );
    assert_eq!(
        judge_ancestor(facts(ROOT, 0o1777), facts(FOREIGN, 0o700), EUID),
        Err(UntrustedAncestor)
    );
    assert_eq!(
        judge_ancestor(facts(EUID, 0o1777), child, EUID),
        Err(UntrustedAncestor)
    );
}

#[test]
fn io_kind_maps_every_reason() {
    use DirectoryTrustReason::{
        GroupOrOtherWritable, NoFinalComponent, NotAbsolute, NotCanonical, NotDirectory,
        NotWritableByEffectiveUser, SymlinkComponent, UntrustedAncestor, UntrustedOwner,
    };
    for reason in [
        NotAbsolute,
        NotCanonical,
        NoFinalComponent,
        SymlinkComponent,
        NotDirectory,
    ] {
        assert_eq!(reason.io_kind(), io::ErrorKind::InvalidInput, "{reason:?}");
    }
    for reason in [
        UntrustedAncestor,
        UntrustedOwner,
        GroupOrOtherWritable,
        NotWritableByEffectiveUser,
    ] {
        assert_eq!(
            reason.io_kind(),
            io::ErrorKind::PermissionDenied,
            "{reason:?}"
        );
    }
}

#[test]
fn path_syntax() {
    assert_eq!(
        canonical_components(Path::new("relative/dir")),
        Err(DirectoryTrustReason::NotAbsolute)
    );
    assert_eq!(
        canonical_components(Path::new("")),
        Err(DirectoryTrustReason::NotAbsolute)
    );
    for path in ["/a//b", "/a/./b", "/a/../b", "/a/b/", "//", "/."] {
        assert_eq!(
            canonical_components(Path::new(path)),
            Err(DirectoryTrustReason::NotCanonical),
            "{path}"
        );
    }
    assert_eq!(canonical_components(Path::new("/")), Ok(Vec::new()));
    assert_eq!(
        canonical_components(Path::new("/a/b")).unwrap(),
        vec![std::ffi::OsStr::new("a"), std::ffi::OsStr::new("b")]
    );
}

#[test]
fn syntax_refusal_makes_no_system_call() {
    let guard = fault::install(Seam::new());
    let (path, reason) = unsafe_reason(open_trusted_dir(Path::new("/a/../b")).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::NotCanonical);
    assert_eq!(path, Path::new("/a/../b"));
    assert!(fault::record().is_empty());
    drop(guard);
}

// ---------------------------------------------------------------------------
// Trusted directory policy, on disk

#[test]
fn canonical_tempdir_root_is_accepted() {
    let (_dir, root) = root();
    let trusted = open_trusted_dir(&root).unwrap();
    assert_eq!(trusted.path(), root);
}

#[test]
fn symlink_components_are_refused() {
    let (_dir, root) = root();
    fs::create_dir(root.join("real")).unwrap();
    fs::create_dir(root.join("real/child")).unwrap();
    symlink(root.join("real"), root.join("link")).unwrap();

    let (path, reason) = unsafe_reason(open_trusted_dir(&root.join("link")).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::SymlinkComponent);
    assert_eq!(path, root.join("link"));

    let (path, reason) = unsafe_reason(open_trusted_dir(&root.join("link/child")).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::SymlinkComponent);
    assert_eq!(path, root.join("link"));
}

#[test]
fn non_directory_components_are_refused() {
    let (_dir, root) = root();
    fs::write(root.join("file"), b"x").unwrap();
    let (path, reason) = unsafe_reason(open_trusted_dir(&root.join("file")).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::NotDirectory);
    assert_eq!(path, root.join("file"));
    let (path, reason) = unsafe_reason(open_trusted_dir(&root.join("file/child")).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::NotDirectory);
    assert_eq!(path, root.join("file"));
}

#[test]
fn missing_component_is_io_not_found() {
    let (_dir, root) = root();
    match open_trusted_dir(&root.join("missing/child")).unwrap_err() {
        TrustedDirError::Io { path, source } => {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert_eq!(path, root.join("missing"));
        }
        TrustedDirError::Unsafe { reason, .. } => panic!("unexpected refusal {reason:?}"),
    }
}

#[test]
fn injected_component_open_failure_is_io() {
    let (_dir, root) = root();
    let _guard =
        fault::install(Seam::new().fail(Step::OpenComponent, io::ErrorKind::PermissionDenied));
    match open_trusted_dir(&root).unwrap_err() {
        TrustedDirError::Io { path, source } => {
            assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(path, Path::new("/"));
        }
        TrustedDirError::Unsafe { reason, .. } => panic!("unexpected refusal {reason:?}"),
    }
}

#[test]
fn writable_selected_directories_are_refused() {
    let (_dir, root) = root();
    for (name, mode) in [("sticky", 0o1777), ("group", 0o770)] {
        let dir = root.join(name);
        fs::create_dir(&dir).unwrap();
        chmod(&dir, mode);
        let (path, reason) = unsafe_reason(open_trusted_dir(&dir).unwrap_err());
        assert_eq!(reason, DirectoryTrustReason::GroupOrOtherWritable, "{name}");
        assert_eq!(path, dir);
    }
}

#[test]
fn unwritable_selected_directory_is_refused() {
    if euid() == ROOT {
        eprintln!("skipped: the effective user is root, which may write any directory");
        return;
    }
    let (_dir, root) = root();
    let dir = root.join("readonly");
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o500);
    let (_, reason) = unsafe_reason(open_trusted_dir(&dir).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::NotWritableByEffectiveUser);
    chmod(&dir, 0o700);
}

#[test]
fn writable_ancestors_are_refused() {
    let (_dir, root) = root();
    for (name, mode) in [("open", 0o777), ("sticky", 0o1777)] {
        let mid = root.join(name);
        fs::create_dir(&mid).unwrap();
        fs::create_dir(mid.join("child")).unwrap();
        chmod(&mid.join("child"), 0o700);
        chmod(&mid, mode);
        let (path, reason) = unsafe_reason(open_trusted_dir(&mid.join("child")).unwrap_err());
        assert_eq!(reason, DirectoryTrustReason::UntrustedAncestor, "{name}");
        assert_eq!(path, mid);
    }
}

#[test]
fn private_directory_under_root_owned_sticky_ancestor_is_accepted() {
    let (_dir, root) = root();
    let parent = root.parent().unwrap();
    let meta = fs::metadata(parent).unwrap();
    if meta.uid() != ROOT || meta.mode() & 0o1000 == 0 {
        eprintln!(
            "skipped: {} is not a root-owned sticky directory; the synthetic ancestor test covers the rule",
            parent.display()
        );
        return;
    }
    // The allowed private-directory-under-sticky-ancestor case.
    open_trusted_dir(&root).unwrap();
}

#[test]
fn foreign_owned_selected_directory_is_refused() {
    if euid() != ROOT {
        eprintln!("skipped: changing a directory's owner needs root");
        return;
    }
    let (_dir, root) = root();
    let dir = root.join("foreign");
    fs::create_dir(&dir).unwrap();
    std::os::unix::fs::chown(&dir, Some(65534), None).unwrap();
    let (_, reason) = unsafe_reason(open_trusted_dir(&dir).unwrap_err());
    assert_eq!(reason, DirectoryTrustReason::UntrustedOwner);
}

// ---------------------------------------------------------------------------
// Staging and snapshots

#[test]
fn scope_creates_private_directory_and_snapshot_modes() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let private = scope.private_path().to_owned();
    let name = private.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with(".deploy-core-retain-"), "{name}");
    assert_eq!(name.len(), ".deploy-core-retain-".len() + 32);
    assert_eq!(private.parent().unwrap(), root);
    assert_eq!(mode_of(&private), 0o700);

    let mut writer = scope.snapshot_writer().unwrap();
    assert_eq!(writer.mode_for_test(), 0o600);
    assert_eq!(names_in(&private), vec!["snap-0".to_owned()]);
    writer.write_all(b"hello").unwrap();
    let bytes = writer.finish().unwrap();
    assert!(names_in(&private).is_empty());
    assert_eq!(bytes.len(), 5);
    assert_eq!(bytes.sha256(), &sha(b"hello"));
    assert_eq!(read_all(&bytes), b"hello");

    scope.close().unwrap();
    assert!(!private.exists());
}

#[test]
fn unsafe_staging_parent_is_refused() {
    let (_dir, root) = root();
    chmod(&root, 0o1777);
    match RetentionScope::new(&root, BIG, nz(8)).unwrap_err() {
        RetentionError::UnsafeStagingParent { path, reason } => {
            assert_eq!(path, root);
            assert_eq!(reason, DirectoryTrustReason::GroupOrOtherWritable);
        }
        other => panic!("{other:?}"),
    }
    chmod(&root, 0o700);
    let (op, path, kind) =
        retention_io(RetentionScope::new(&root.join("absent"), BIG, nz(8)).unwrap_err());
    assert_eq!(op, RetentionOperation::OpenStagingParent);
    assert_eq!(path, Some(root.join("absent")));
    assert_eq!(kind, io::ErrorKind::NotFound);
}

#[test]
fn colliding_name_is_redrawn_and_existing_entry_untouched() {
    let (_dir, root) = root();
    let forced = [0xab; 16];
    let existing = root.join(format!(".deploy-core-retain-{}", to_hex(&forced)));
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("marker"), b"keep").unwrap();

    let guard = fault::install(Seam::new().force_name(forced));
    let scope = scope(&root, BIG);
    let record = fault::record();
    drop(guard);
    assert_ne!(scope.private_path(), existing);
    assert_eq!(
        sequence(&record, &[Step::DrawName, Step::MakeDirectory]),
        vec![
            Step::DrawName,
            Step::MakeDirectory,
            Step::DrawName,
            Step::MakeDirectory
        ]
    );
    assert_eq!(fs::read(existing.join("marker")).unwrap(), b"keep");
    scope.close().unwrap();
    assert!(existing.exists());
}

#[test]
fn eight_collisions_fail_with_already_exists() {
    let (_dir, root) = root();
    let forced = [0x11; 16];
    let existing = root.join(format!(".deploy-core-retain-{}", to_hex(&forced)));
    fs::create_dir(&existing).unwrap();
    let mut seam = Seam::new();
    for _ in 0..NAME_ATTEMPTS {
        seam = seam.force_name(forced);
    }
    let _guard = fault::install(seam);
    let (op, path, kind) = retention_io(RetentionScope::new(&root, BIG, nz(8)).unwrap_err());
    assert_eq!(op, RetentionOperation::CreateStagingDirectory);
    assert_eq!(path, Some(existing));
    assert_eq!(kind, io::ErrorKind::AlreadyExists);
}

#[test]
fn random_source_failure_is_not_retried() {
    let (_dir, root) = root();
    let _guard = fault::install(Seam::new().fail(Step::DrawName, io::ErrorKind::Other));
    let (op, path, kind) = retention_io(RetentionScope::new(&root, BIG, nz(8)).unwrap_err());
    assert_eq!(op, RetentionOperation::CreateStagingDirectory);
    assert_eq!(path, Some(root.clone()));
    assert_eq!(kind, io::ErrorKind::Other);
    let record = fault::record();
    assert_eq!(record.iter().filter(|s| **s == Step::DrawName).count(), 1);
    assert!(!record.contains(&Step::MakeDirectory));
    assert!(names_in(&root).is_empty());
}

#[test]
fn mkdir_failure_keeps_its_kind() {
    let (_dir, root) = root();
    let _guard = fault::install(Seam::new().fail(Step::MakeDirectory, io::ErrorKind::StorageFull));
    let (op, path, kind) = retention_io(RetentionScope::new(&root, BIG, nz(8)).unwrap_err());
    assert_eq!(op, RetentionOperation::CreateStagingDirectory);
    assert!(path.unwrap().starts_with(&root));
    assert_eq!(kind, io::ErrorKind::StorageFull);
}

#[test]
fn snapshot_creation_failure_names_the_file() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let _guard =
        fault::install(Seam::new().fail(Step::CreateSnapshot, io::ErrorKind::PermissionDenied));
    let (op, path, kind) = retention_io(scope.snapshot_writer().unwrap_err());
    assert_eq!(op, RetentionOperation::CreateSnapshot);
    assert_eq!(path, Some(scope.private_path().join("snap-0")));
    assert_eq!(kind, io::ErrorKind::PermissionDenied);
}

#[test]
fn finish_step_failures_release_everything() {
    for (step, operation) in [
        (Step::FlushSnapshot, RetentionOperation::WriteSnapshot),
        (Step::ReopenSnapshot, RetentionOperation::ReopenSnapshot),
        (Step::StatSnapshot, RetentionOperation::InspectSnapshot),
        (Step::UnlinkSnapshot, RetentionOperation::UnlinkSnapshot),
    ] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let mut writer = scope.snapshot_writer().unwrap();
        writer.write_all(b"payload").unwrap();
        assert_eq!(scope.budget_used(), 7);
        let guard = fault::install(Seam::new().fail(step, io::ErrorKind::Other));
        let (op, path, kind) = retention_io(writer.finish().unwrap_err());
        drop(guard);
        assert_eq!(op, operation, "{step:?}");
        assert_eq!(path, Some(scope.private_path().join("snap-0")), "{step:?}");
        assert_eq!(kind, io::ErrorKind::Other);
        assert_eq!(scope.budget_used(), 0, "{step:?}");
        if step == Step::UnlinkSnapshot {
            // Every unlink was refused, so the name is still there for
            // `close` to remove.
            assert_eq!(names_in(scope.private_path()), vec!["snap-0".to_owned()]);
        } else {
            assert!(names_in(scope.private_path()).is_empty(), "{step:?}");
        }
        let private = scope.private_path().to_owned();
        scope.close().unwrap();
        assert!(!private.exists());
    }
}

#[test]
fn snapshot_is_immune_to_source_changes() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let source = root.join("source.bin");
    let original = b"original bytes of the source".to_vec();
    fs::write(&source, &original).unwrap();
    let mut kept = OpenOptions::new().write(true).open(&source).unwrap();
    let bytes = scope
        .snapshot_from(&mut fs::File::open(&source).unwrap(), BIG)
        .unwrap();

    let check = |what: &str| {
        assert_eq!(read_all(&bytes), original, "{what}");
        assert_eq!(bytes.len(), original.len() as u64, "{what}");
        assert_eq!(bytes.sha256(), &sha(&original), "{what}");
    };
    check("snapshot");
    fs::write(&source, b"OVERWRITTEN bytes of the source").unwrap();
    check("overwrite");
    OpenOptions::new()
        .write(true)
        .open(&source)
        .unwrap()
        .set_len(3)
        .unwrap();
    check("truncate");
    OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(b"appended")
        .unwrap();
    check("append");
    kept.write_all(b"through the kept descriptor").unwrap();
    kept.sync_all().unwrap();
    check("kept descriptor");
    let replacement = root.join("replacement.bin");
    fs::write(&replacement, b"replacement").unwrap();
    fs::rename(&replacement, &source).unwrap();
    check("rename-replace");
    fs::remove_file(&source).unwrap();
    check("delete");
}

/// A source that mutates its backing file after delivering `after` bytes and
/// records every request and delivery.
struct MutatingSource {
    file: fs::File,
    path: PathBuf,
    after: usize,
    delivered: Vec<u8>,
    mutated: bool,
    largest_request: usize,
    reads: usize,
}

impl Read for MutatingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.largest_request = self.largest_request.max(buf.len());
        let read = self.file.read(buf)?;
        self.delivered.extend_from_slice(&buf[..read]);
        if !self.mutated && self.delivered.len() >= self.after {
            self.mutated = true;
            let mut f = OpenOptions::new().write(true).open(&self.path).unwrap();
            f.write_all(&[b'Z'; 64]).unwrap();
        }
        Ok(read)
    }
}

#[test]
fn snapshot_equals_exactly_the_bytes_read() {
    let (_dir, root) = root();
    let scope = RetentionScope::new(&root, BIG, nz(4)).unwrap();
    let path = root.join("racy.bin");
    fs::write(&path, b"abcdefghijklmnopqrstuvwxyz").unwrap();
    let mut source = MutatingSource {
        file: fs::File::open(&path).unwrap(),
        path: path.clone(),
        after: 8,
        delivered: Vec::new(),
        mutated: false,
        largest_request: 0,
        reads: 0,
    };
    let bytes = scope.snapshot_from(&mut source, BIG).unwrap();
    assert!(source.mutated);
    assert_eq!(read_all(&bytes), source.delivered);
    assert_eq!(&source.delivered[..8], b"abcdefgh");
    assert_eq!(bytes.sha256(), &sha(&source.delivered));
    // One pass: after the mutation the same descriptor carries on from byte
    // 8 into the rewritten, longer file, and the snapshot follows it.
    assert_eq!(source.delivered.len(), 64);
    assert!(source.delivered[8..].iter().all(|&b| b == b'Z'));
    assert!(source.largest_request <= 4);
    assert!(source.reads >= 64 / 4);
}

/// Counts what a source hands out.
struct CountingSource<'a> {
    data: &'a [u8],
    delivered: u64,
    largest_request: usize,
    interrupt_first: bool,
    fail_with: Option<io::ErrorKind>,
}

impl<'a> CountingSource<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            delivered: 0,
            largest_request: 0,
            interrupt_first: false,
            fail_with: None,
        }
    }
}

impl Read for CountingSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.interrupt_first {
            self.interrupt_first = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some(kind) = self.fail_with {
            return Err(kind.into());
        }
        self.largest_request = self.largest_request.max(buf.len());
        let read = self.data.read(buf)?;
        self.delivered += read as u64;
        Ok(read)
    }
}

#[test]
fn snapshot_from_enforces_max_len() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let data = [7u8; 30];

    let mut exact = CountingSource::new(&data[..10]);
    let bytes = scope.snapshot_from(&mut exact, 10).unwrap();
    assert_eq!(bytes.len(), 10);

    let mut long = CountingSource::new(&data);
    assert!(matches!(
        scope.snapshot_from(&mut long, 10).unwrap_err(),
        RetentionError::SourceTooLong { max_len: 10 }
    ));
    assert_eq!(long.delivered, 11);
    drop(bytes);
    assert_eq!(scope.budget_used(), 0);
}

#[test]
fn source_too_long_wins_over_budget_at_the_same_byte() {
    let (_dir, root) = root();
    let scope = scope(&root, 10);
    let data = [1u8; 20];
    let mut source = CountingSource::new(&data);
    assert!(matches!(
        scope.snapshot_from(&mut source, 10).unwrap_err(),
        RetentionError::SourceTooLong { max_len: 10 }
    ));
    assert_eq!(source.delivered, 11);
    assert_eq!(scope.budget_high_water(), 10);
    assert_eq!(scope.budget_used(), 0);
}

#[test]
fn source_errors() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let mut interrupted = CountingSource::new(b"abc");
    interrupted.interrupt_first = true;
    assert_eq!(
        read_all(&scope.snapshot_from(&mut interrupted, BIG).unwrap()),
        b"abc"
    );

    let mut failing = CountingSource::new(b"abc");
    failing.fail_with = Some(io::ErrorKind::ConnectionReset);
    let (op, path, kind) = retention_io(scope.snapshot_from(&mut failing, BIG).unwrap_err());
    assert_eq!(op, RetentionOperation::ReadSource);
    assert_eq!(path, None);
    assert_eq!(kind, io::ErrorKind::ConnectionReset);
    assert!(names_in(scope.private_path()).is_empty());
}

#[test]
fn copy_buffer_bounds_every_source_request() {
    let (_dir, root) = root();
    let scope = RetentionScope::new(&root, BIG, nz(7)).unwrap();
    let data: Vec<u8> = (0..100).collect();
    let mut source = CountingSource::new(&data);
    let bytes = scope.snapshot_from(&mut source, BIG).unwrap();
    assert!(source.largest_request <= 7, "{}", source.largest_request);
    assert_eq!(read_all(&bytes), data);
}

#[test]
fn retention_errors_round_trip_through_io() {
    let variants = || {
        vec![
            RetentionError::BudgetExceeded { limit: 5 },
            RetentionError::SourceTooLong { max_len: 9 },
            RetentionError::UnsafeStagingParent {
                path: PathBuf::from("/p"),
                reason: DirectoryTrustReason::UntrustedOwner,
            },
            RetentionError::SnapshotMismatch {
                kind: SnapshotMismatchKind::Identity,
            },
            RetentionError::SnapshotMismatch {
                kind: SnapshotMismatchKind::Length {
                    expected: 3,
                    actual: 4,
                },
            },
            RetentionError::Io {
                operation: RetentionOperation::UnlinkSnapshot,
                path: Some(PathBuf::from("/p/snap-1")),
                source: io::ErrorKind::StorageFull.into(),
            },
        ]
    };
    for (original, expected) in variants().into_iter().zip(variants()) {
        let recovered =
            RetentionError::from_io(original.into_io(), RetentionOperation::ReadSource, None);
        // `Debug` covers the variant and every field, the source's kind
        // included.
        assert!(
            !matches!(
                recovered,
                RetentionError::Io {
                    operation: RetentionOperation::ReadSource,
                    ..
                }
            ),
            "{recovered:?} was wrapped rather than recovered"
        );
        assert_eq!(format!("{recovered:?}"), format!("{expected:?}"));
    }
    // A plain error, whatever its kind, is wrapped under the given operation.
    let wrapped = RetentionError::from_io(
        io::Error::other("plain"),
        RetentionOperation::ReadSource,
        None,
    );
    assert_eq!(
        retention_io(wrapped),
        (RetentionOperation::ReadSource, None, io::ErrorKind::Other)
    );
}

// ---------------------------------------------------------------------------
// Readers

#[test]
fn readers_keep_independent_cursors() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let data: Vec<u8> = (0..=99).collect();
    let bytes = snap(&scope, &data);
    let mut a = bytes.reader();
    let mut b = bytes.reader();
    let mut c = bytes.reader();
    let mut buf = [0u8; 10];

    a.read_exact(&mut buf).unwrap();
    assert_eq!(buf, data[0..10]);
    assert_eq!(b.seek(SeekFrom::Start(50)).unwrap(), 50);
    b.read_exact(&mut buf).unwrap();
    assert_eq!(buf, data[50..60]);
    assert_eq!(c.seek(SeekFrom::End(-5)).unwrap(), 95);
    assert_eq!(c.read(&mut buf).unwrap(), 5);
    assert_eq!(buf[..5], data[95..]);
    a.read_exact(&mut buf).unwrap();
    assert_eq!(buf, data[10..20]);
    assert_eq!(b.seek(SeekFrom::Current(-20)).unwrap(), 40);
    b.read_exact(&mut buf).unwrap();
    assert_eq!(buf, data[40..50]);

    // At and past EOF.
    assert_eq!(c.seek(SeekFrom::End(0)).unwrap(), 100);
    assert_eq!(c.read(&mut buf).unwrap(), 0);
    assert_eq!(c.seek(SeekFrom::End(10)).unwrap(), 110);
    assert_eq!(c.read(&mut buf).unwrap(), 0);
    assert_eq!(c.seek(SeekFrom::Current(5)).unwrap(), 115);
    assert_eq!(c.read(&mut buf).unwrap(), 0);
    assert_eq!(c.seek(SeekFrom::Start(1000)).unwrap(), 1000);
    assert_eq!(c.read(&mut buf).unwrap(), 0);

    let full = |mut r: RetainedReader<'_>| {
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    };
    assert_eq!(full(a), data);
    assert_eq!(full(b), data);
    assert_eq!(full(c), data);
}

#[test]
fn invalid_seeks_leave_the_cursor() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"0123456789");
    let mut reader = bytes.reader();
    reader.seek(SeekFrom::Start(4)).unwrap();
    for target in [
        SeekFrom::Current(-5),
        SeekFrom::End(-11),
        SeekFrom::Current(i64::MAX),
    ] {
        if target == SeekFrom::Current(i64::MAX) {
            reader.seek(SeekFrom::Start(u64::MAX)).unwrap();
        }
        let before = reader.stream_position().unwrap();
        let err = reader.seek(target).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{target:?}");
        assert_eq!(reader.stream_position().unwrap(), before, "{target:?}");
    }
}

#[test]
fn empty_snapshot() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"");
    assert_eq!(bytes.len(), 0);
    assert!(bytes.is_empty());
    assert_eq!(bytes.sha256(), &sha(b""));
    assert_eq!(bytes.reader().read(&mut [0u8; 4]).unwrap(), 0);
}

#[test]
fn readers_work_across_threads() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let data: Vec<u8> = (0..200u8).collect();
    let bytes = snap(&scope, &data);
    let shared = bytes.share();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    bytes.reader().read_to_end(&mut out).unwrap();
                    out
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), data);
        }
    });
    assert_eq!(read_all(&shared), data);
}

#[test]
fn debug_shows_only_length_and_digest() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"secret-ish");
    let debug = format!("{bytes:?}");
    assert_eq!(
        debug,
        format!(
            "RetainedBytes {{ len: 10, sha256: \"{}\" }}",
            to_hex(&sha(b"secret-ish"))
        )
    );
}

// ---------------------------------------------------------------------------
// Close-on-exec

#[test]
fn child_process_cannot_read_a_retained_descriptor() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let marker = b"retained-marker-3f9a1c";
    let bytes = snap(&scope, marker);
    let output = std::process::Command::new("cat")
        .arg(format!("/dev/fd/{}", bytes.raw_fd_for_test()))
        .output()
        .unwrap();
    assert!(
        !output.status.success() || !output.stdout.windows(marker.len()).any(|w| w == marker),
        "a child read the retained bytes"
    );
    assert!(!output.stdout.windows(marker.len()).any(|w| w == marker));
}

// ---------------------------------------------------------------------------
// Cleanup and budget

#[test]
fn dropping_an_unfinished_writer_releases_everything() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let before = scope.budget_used();
    let mut writer = scope.snapshot_writer().unwrap();
    writer.write_all(b"partial").unwrap();
    assert_eq!(scope.budget_used(), before + 7);
    drop(writer);
    assert!(names_in(scope.private_path()).is_empty());
    assert_eq!(scope.budget_used(), before);
}

#[test]
fn live_snapshots_outlive_the_scope() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let budget = scope.budget().clone();
    let private = scope.private_path().to_owned();
    let bytes = snap(&scope, b"still here");
    scope.close().unwrap();
    assert!(!private.exists());
    assert_eq!(read_all(&bytes), b"still here");
    assert_eq!(budget.used(), 10);
    drop(bytes);
    assert_eq!(budget.used(), 0);

    // Drop removes it the same way.
    let scope = super::RetentionScope::new(&root, BIG, nz(8)).unwrap();
    let private = scope.private_path().to_owned();
    let bytes = snap(&scope, b"again");
    drop(scope);
    assert!(!private.exists());
    assert_eq!(read_all(&bytes), b"again");
}

#[test]
fn failed_listing_is_reported() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let private = scope.private_path().to_owned();
    let _guard =
        fault::install(Seam::new().fail(Step::ListStaging, io::ErrorKind::PermissionDenied));
    let (op, path, kind) = retention_io(scope.close().unwrap_err());
    assert_eq!(op, RetentionOperation::RemoveStagingEntry);
    assert_eq!(path, Some(private));
    assert_eq!(kind, io::ErrorKind::PermissionDenied);
}

#[test]
fn failed_entry_removal_is_reported() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let private = scope.private_path().to_owned();
    {
        let _guard = fault::install(Seam::new().fail(Step::UnlinkSnapshot, io::ErrorKind::Other));
        let mut writer = scope.snapshot_writer().unwrap();
        writer.write_all(b"left").unwrap();
    }
    assert_eq!(names_in(&private), vec!["snap-0".to_owned()]);
    let guard =
        fault::install(Seam::new().fail(Step::RemoveStagingEntry, io::ErrorKind::PermissionDenied));
    let (op, path, kind) = retention_io(scope.close().unwrap_err());
    drop(guard);
    assert_eq!(op, RetentionOperation::RemoveStagingEntry);
    assert_eq!(path, Some(private.join("snap-0")));
    assert_eq!(kind, io::ErrorKind::PermissionDenied);
    // The directory remains, as documented.
    assert!(private.join("snap-0").exists());
    fs::remove_dir_all(&private).unwrap();
}

#[test]
fn failed_directory_removal_is_reported() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let private = scope.private_path().to_owned();
    let guard =
        fault::install(Seam::new().fail(Step::RemoveStagingDirectory, io::ErrorKind::Other));
    let (op, path, kind) = retention_io(scope.close().unwrap_err());
    drop(guard);
    assert_eq!(op, RetentionOperation::RemoveStagingDirectory);
    assert_eq!(path, Some(private.clone()));
    assert_eq!(kind, io::ErrorKind::Other);
    assert!(private.exists());
}

#[test]
fn dropping_a_scope_under_failures_does_not_panic() {
    let (_dir, root) = root();
    for step in [
        Step::ListStaging,
        Step::RemoveStagingEntry,
        Step::RemoveStagingDirectory,
    ] {
        let scope = scope(&root, BIG);
        let _guard = fault::install(
            Seam::new()
                .fail(Step::UnlinkSnapshot, io::ErrorKind::Other)
                .fail(step, io::ErrorKind::Other),
        );
        let mut writer = scope.snapshot_writer().unwrap();
        writer.write_all(b"x").unwrap();
        drop(writer);
        drop(scope);
    }
}

#[test]
fn one_budget_covers_every_snapshot() {
    let (_dir, root) = root();
    let scope = scope(&root, 10);
    let a = snap(&scope, b"aaaa");
    let b = snap(&scope, b"bbbbbb");
    assert_eq!(scope.budget_used(), 10);
    assert!(matches!(
        scope.snapshot_from(&mut &b"c"[..], BIG).unwrap_err(),
        RetentionError::BudgetExceeded { limit: 10 }
    ));
    drop(b);
    assert_eq!(scope.budget_used(), 4);

    // Every byte within the budget is written; the failure lands on the
    // first byte beyond it.
    let mut writer = scope.snapshot_writer().unwrap();
    let err = writer.write_all(b"0123456789").unwrap_err();
    assert!(matches!(
        RetentionError::from_io(err, RetentionOperation::WriteSnapshot, None),
        RetentionError::BudgetExceeded { limit: 10 }
    ));
    assert_eq!(writer.len, 6);
    assert_eq!(scope.budget_used(), 10);
    assert_eq!(scope.budget_high_water(), 10);
    drop(writer);
    assert_eq!(scope.budget_used(), 4);
    drop(a);
    assert_eq!(scope.budget_used(), 0);
    assert_eq!(scope.budget_high_water(), 10);
}

#[test]
fn zero_budget_allows_only_empty_snapshots() {
    let (_dir, root) = root();
    let scope = scope(&root, 0);
    assert!(matches!(
        scope.snapshot_from(&mut &b"x"[..], BIG).unwrap_err(),
        RetentionError::BudgetExceeded { limit: 0 }
    ));
    let empty = snap(&scope, b"");
    assert!(empty.is_empty());
    assert!(names_in(scope.private_path()).is_empty());
}

#[test]
fn concurrent_writers_never_overshoot() {
    let (_dir, root) = root();
    let scope = scope(&root, 1000);
    let written: Vec<u64> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    let mut writer = scope.snapshot_writer().unwrap();
                    let mut written = 0u64;
                    while writer.write(&[1u8; 3]).map(|n| written += n as u64).is_ok() {}
                    let bytes = writer.finish().unwrap();
                    assert_eq!(bytes.len(), written);
                    (written, bytes)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(scope.budget_used(), 1000);
        results.into_iter().map(|(n, _)| n).collect()
    });
    assert_eq!(written.iter().sum::<u64>(), 1000);
    assert_eq!(scope.budget_high_water(), 1000);
    assert_eq!(scope.budget_used(), 0);
}

#[test]
fn storage_full_is_io_not_budget() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let _guard = fault::install(Seam::new().fail_write_at(5, io::ErrorKind::StorageFull));
    let (op, path, kind) = retention_io(scope.snapshot_from(&mut &[9u8; 20][..], BIG).unwrap_err());
    assert_eq!(op, RetentionOperation::WriteSnapshot);
    assert_eq!(path, Some(scope.private_path().join("snap-0")));
    assert_eq!(kind, io::ErrorKind::StorageFull);
    assert_eq!(scope.budget_used(), 0);
    assert!(names_in(scope.private_path()).is_empty());
}

#[test]
fn write_error_kinds_are_preserved() {
    for kind in [io::ErrorKind::Unsupported, io::ErrorKind::PermissionDenied] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let _guard = fault::install(Seam::new().fail(Step::WriteSnapshot, kind));
        let (op, _, got) = retention_io(scope.snapshot_from(&mut &b"abc"[..], BIG).unwrap_err());
        assert_eq!(op, RetentionOperation::WriteSnapshot);
        assert_eq!(got, kind);
        assert_eq!(scope.budget_used(), 0);
    }
}

// ---------------------------------------------------------------------------
// publish_file

const FILE_STEPS: &[Step] = &[
    Step::CreateTemporary,
    Step::WriteTemporary,
    Step::SyncFile,
    Step::VerifyRead,
    Step::Link,
    Step::Rename,
    Step::RemoveTemporary,
    Step::SyncParent,
];

#[test]
fn publish_file_success() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let data: Vec<u8> = (0..150u8).collect();
    let bytes = snap(&scope, &data);
    let destination = root.join("out.pkg");
    let guard = fault::install(Seam::new());
    let receipt = publish_file(&bytes, &destination, &scope).unwrap();
    let record = fault::record();
    drop(guard);
    assert_eq!(fs::read(&destination).unwrap(), data);
    assert_eq!(receipt.destination(), destination);
    assert_eq!(receipt.len(), 150);
    assert_eq!(receipt.sha256(), &sha(&data));
    assert_eq!(mode_of(&destination), 0o600);
    assert!(publish_siblings(&root).is_empty());
    assert_eq!(
        sequence(&record, FILE_STEPS),
        vec![
            Step::CreateTemporary,
            Step::WriteTemporary,
            Step::SyncFile,
            Step::VerifyRead,
            Step::Link,
            Step::RemoveTemporary,
            Step::SyncParent,
        ]
    );
    assert_eq!(scope.budget_used(), 150);
}

#[test]
fn publish_file_refuses_existing_destinations() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"new");
    fs::write(root.join("file"), b"old").unwrap();
    fs::create_dir(root.join("dir")).unwrap();
    symlink(root.join("nowhere"), root.join("dangling")).unwrap();
    for name in ["file", "dir", "dangling"] {
        let destination = root.join(name);
        match publish_file(&bytes, &destination, &scope).unwrap_err() {
            PublicationError::DestinationExists { destination: d } => assert_eq!(d, destination),
            other => panic!("{name}: {other:?}"),
        }
    }
    assert_eq!(fs::read(root.join("file")).unwrap(), b"old");
    assert!(root.join("dir").is_dir());
    assert_eq!(
        fs::read_link(root.join("dangling")).unwrap(),
        root.join("nowhere")
    );
    assert!(publish_siblings(&root).is_empty());
}

fn make_entry(kind: &str, path: &Path) {
    match kind {
        "file" => fs::write(path, b"theirs").unwrap(),
        "dir" => {
            fs::create_dir(path).unwrap();
            fs::write(path.join("inside"), b"theirs").unwrap();
        }
        "symlink" => symlink("/nonexistent-target", path).unwrap(),
        _ => unreachable!(),
    }
}

fn assert_entry(kind: &str, path: &Path) {
    match kind {
        "file" => assert_eq!(fs::read(path).unwrap(), b"theirs"),
        "dir" => assert_eq!(fs::read(path.join("inside")).unwrap(), b"theirs"),
        "symlink" => assert_eq!(
            fs::read_link(path).unwrap(),
            Path::new("/nonexistent-target")
        ),
        _ => unreachable!(),
    }
}

#[test]
fn publish_file_race_is_destination_exists() {
    for kind in ["file", "dir", "symlink"] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let bytes = snap(&scope, b"ours");
        let destination = root.join("out");
        let racer = destination.clone();
        let _guard = fault::install(Seam::new().before_publish(move || make_entry(kind, &racer)));
        assert!(
            matches!(
                publish_file(&bytes, &destination, &scope).unwrap_err(),
                PublicationError::DestinationExists { .. }
            ),
            "{kind}"
        );
        assert_entry(kind, &destination);
        assert!(publish_siblings(&root).is_empty(), "{kind}");
    }
}

#[test]
fn link_failure_is_classified_by_inspection() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"ours");
    let destination = root.join("out");

    let racer = destination.clone();
    let guard = fault::install(
        Seam::new()
            .fail(Step::Link, io::ErrorKind::PermissionDenied)
            .before_publish(move || make_entry("file", &racer)),
    );
    assert!(matches!(
        publish_file(&bytes, &destination, &scope).unwrap_err(),
        PublicationError::DestinationExists { .. }
    ));
    drop(guard);
    assert_entry("file", &destination);
    fs::remove_file(&destination).unwrap();

    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Unsupported] {
        let guard = fault::install(Seam::new().fail(Step::Link, kind));
        let (op, path, got) =
            publication_io(publish_file(&bytes, &destination, &scope).unwrap_err());
        let record = fault::record();
        drop(guard);
        assert_eq!(op, PublicationOperation::Link);
        assert_eq!(path, Some(destination.clone()));
        assert_eq!(got, kind);
        assert!(!destination.exists());
        assert!(!record.contains(&Step::Rename));
        assert!(publish_siblings(&root).is_empty());
    }
}

#[test]
fn publish_file_refuses_unsafe_destinations() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"x");
    fs::create_dir(root.join("real")).unwrap();
    symlink(root.join("real"), root.join("link")).unwrap();
    fs::create_dir(root.join("open")).unwrap();
    chmod(&root.join("open"), 0o1777);

    let guard = fault::install(Seam::new());
    let err = publish_file(&bytes, Path::new("/"), &scope).unwrap_err();
    assert!(fault::record().is_empty());
    drop(guard);
    match err {
        PublicationError::UnsafeDestinationParent { path, reason } => {
            assert_eq!(path, Path::new("/"));
            assert_eq!(reason, DirectoryTrustReason::NoFinalComponent);
        }
        other => panic!("{other:?}"),
    }

    let trailing = PathBuf::from(format!("{}/out/", root.display()));
    for (destination, expected) in [
        (
            PathBuf::from("relative/out"),
            DirectoryTrustReason::NotAbsolute,
        ),
        (
            root.join("link/out"),
            DirectoryTrustReason::SymlinkComponent,
        ),
        (
            root.join("open/out"),
            DirectoryTrustReason::GroupOrOtherWritable,
        ),
        (trailing, DirectoryTrustReason::NotCanonical),
    ] {
        match publish_file(&bytes, &destination, &scope).unwrap_err() {
            PublicationError::UnsafeDestinationParent { reason, .. } => {
                assert_eq!(reason, expected, "{}", destination.display());
            }
            other => panic!("{}: {other:?}", destination.display()),
        }
    }
    assert!(names_in(&root.join("real")).is_empty());
    assert!(names_in(&root.join("open")).is_empty());
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_file_random_source_failure() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"x");
    let _guard = fault::install(Seam::new().fail(Step::DrawName, io::ErrorKind::Other));
    let (op, path, kind) =
        publication_io(publish_file(&bytes, &root.join("out"), &scope).unwrap_err());
    assert_eq!(op, PublicationOperation::CreateTemporary);
    assert_eq!(path, Some(root.clone()));
    assert_eq!(kind, io::ErrorKind::Other);
    assert!(!fault::record().contains(&Step::CreateTemporary));
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_file_pre_publish_failures() {
    for (step, operation) in [
        (Step::CreateTemporary, PublicationOperation::CreateTemporary),
        (Step::WriteTemporary, PublicationOperation::WriteTemporary),
        (Step::SyncFile, PublicationOperation::SyncFile),
        (Step::VerifyRead, PublicationOperation::Verify),
    ] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let bytes = snap(&scope, b"payload");
        let destination = root.join("out");
        let guard = fault::install(Seam::new().fail(step, io::ErrorKind::StorageFull));
        let (op, path, kind) =
            publication_io(publish_file(&bytes, &destination, &scope).unwrap_err());
        drop(guard);
        assert_eq!(op, operation, "{step:?}");
        assert!(path.unwrap().starts_with(&root));
        assert_eq!(kind, io::ErrorKind::StorageFull);
        assert!(!destination.exists());
        assert!(publish_siblings(&root).is_empty(), "{step:?}");
        assert_eq!(scope.budget_used(), 7);
    }
}

#[test]
fn publish_file_verification_catches_corruption() {
    for (corruption, expected) in [
        (Corruption::FlipFirstByte, CopyMismatchKind::Digest),
        (
            Corruption::TruncateOne,
            CopyMismatchKind::Length {
                expected: 7,
                actual: 6,
            },
        ),
    ] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let bytes = snap(&scope, b"payload");
        let destination = root.join("out");
        let _guard = fault::install(Seam::new().corrupt(corruption));
        match publish_file(&bytes, &destination, &scope).unwrap_err() {
            PublicationError::CopyMismatch { path, kind } => {
                assert_eq!(kind, expected);
                assert_eq!(path.parent().unwrap(), root);
                assert!(
                    path.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with(".deploy-core-publish-")
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(!destination.exists());
        assert!(publish_siblings(&root).is_empty());
    }
}

#[test]
fn publish_file_failed_cleanup_leaves_named_temporary() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"payload");
    let destination = root.join("out");
    let _guard = fault::install(
        Seam::new()
            .fail(Step::WriteTemporary, io::ErrorKind::StorageFull)
            .fail(Step::RemoveTemporary, io::ErrorKind::PermissionDenied),
    );
    let (op, path, kind) = publication_io(publish_file(&bytes, &destination, &scope).unwrap_err());
    assert_eq!(op, PublicationOperation::WriteTemporary);
    assert_eq!(kind, io::ErrorKind::StorageFull);
    assert!(!destination.exists());
    let siblings = publish_siblings(&root);
    assert_eq!(siblings.len(), 1);
    assert_eq!(
        Path::new(&siblings[0]).extension(),
        Some(std::ffi::OsStr::new("tmp"))
    );
    assert_eq!(path, Some(root.join(&siblings[0])));
}

#[test]
fn publish_file_post_publish_failures() {
    for (step, kind, operation) in [
        (
            Step::RemoveTemporary,
            io::ErrorKind::PermissionDenied,
            PublicationOperation::RemoveTemporary,
        ),
        (
            Step::SyncParent,
            io::ErrorKind::Other,
            PublicationOperation::SyncDirectory,
        ),
        (
            Step::SyncParent,
            io::ErrorKind::Unsupported,
            PublicationOperation::SyncDirectory,
        ),
    ] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let bytes = snap(&scope, b"payload");
        let destination = root.join("out");
        let guard = fault::install(Seam::new().fail(step, kind));
        let err = publish_file(&bytes, &destination, &scope).unwrap_err();
        let record = fault::record();
        drop(guard);
        match err {
            PublicationError::PublishDurability {
                destination: d,
                operation: op,
                source,
            } => {
                assert_eq!(d, destination);
                assert_eq!(op, operation);
                assert_eq!(source.kind(), kind);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fs::read(&destination).unwrap(), b"payload");
        if step == Step::RemoveTemporary {
            // Later steps are not attempted.
            assert!(!record.contains(&Step::SyncParent));
        }
    }
}

#[test]
fn publish_file_retained_read_failure() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"payload");
    let _guard = fault::install(Seam::new().fail(Step::ReadRetained, io::ErrorKind::Other));
    let (op, path, _) =
        publication_io(publish_file(&bytes, &root.join("out"), &scope).unwrap_err());
    assert_eq!(op, PublicationOperation::ReadRetained);
    assert_eq!(path, None);
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_file_shares_the_budget() {
    let (_dir, root) = root();
    let scope = scope(&root, 10);
    let bytes = snap(&scope, b"sixsix");
    let destination = root.join("out");
    assert!(matches!(
        publish_file(&bytes, &destination, &scope).unwrap_err(),
        PublicationError::DiskBudgetExceeded { limit: 10 }
    ));
    assert_eq!(scope.budget_high_water(), 10);
    assert_eq!(scope.budget_used(), 6);
    assert!(!destination.exists());
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn mutating_a_published_file_leaves_the_retained_bytes() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let bytes = snap(&scope, b"payload");
    let destination = root.join("out");
    publish_file(&bytes, &destination, &scope).unwrap();
    fs::write(&destination, b"tampered with").unwrap();
    assert_eq!(read_all(&bytes), b"payload");
    assert_eq!(bytes.sha256(), &sha(b"payload"));
}

// ---------------------------------------------------------------------------
// publish_directory

fn three(scope: &RetentionScope) -> [RetainedBytes; 3] {
    [
        snap(scope, b"{\"manifest\":true}"),
        snap(scope, b"archive bytes"),
        snap(scope, b"{\"record\":1}"),
    ]
}

fn entries(files: &[RetainedBytes; 3]) -> Vec<(PublishedFileName, &RetainedBytes)> {
    vec![
        (PublishedFileName::PreparationManifest, &files[0]),
        (PublishedFileName::PreparationArchive, &files[1]),
        (PublishedFileName::PreparationRecord, &files[2]),
    ]
}

#[test]
fn publish_directory_success() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let files = three(&scope);
    let destination = root.join("prepared");
    let guard = fault::install(Seam::new());
    publish_directory(&entries(&files), &destination, &scope).unwrap();
    let record = fault::record();
    drop(guard);
    assert_eq!(
        names_in(&destination),
        vec!["archive.tar.zst", "manifest.json", "preparation.json"]
    );
    for (name, bytes) in entries(&files) {
        let path = destination.join(name.as_str());
        assert_eq!(fs::read(&path).unwrap(), read_all(bytes));
        assert_eq!(mode_of(&path), 0o600);
    }
    assert!(publish_siblings(&root).is_empty());
    assert_eq!(
        sequence(
            &record,
            &[Step::SyncStagingDirectory, Step::Rename, Step::SyncParent]
        ),
        vec![Step::SyncStagingDirectory, Step::Rename, Step::SyncParent]
    );
    assert_eq!(record.iter().filter(|s| **s == Step::SyncFile).count(), 3);
    let last_verify = record.iter().rposition(|s| *s == Step::VerifyRead).unwrap();
    let staging_sync = record
        .iter()
        .position(|s| *s == Step::SyncStagingDirectory)
        .unwrap();
    assert!(last_verify < staging_sync);
}

#[test]
fn publish_directory_refuses_existing_destinations() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let files = three(&scope);
    for kind in ["file", "dir"] {
        let destination = root.join(kind);
        make_entry(kind, &destination);
        assert!(matches!(
            publish_directory(&entries(&files), &destination, &scope).unwrap_err(),
            PublicationError::DestinationExists { .. }
        ));
        assert_entry(kind, &destination);
    }
    match publish_directory(&entries(&files), Path::new("/"), &scope).unwrap_err() {
        PublicationError::UnsafeDestinationParent { reason, .. } => {
            assert_eq!(reason, DirectoryTrustReason::NoFinalComponent);
        }
        other => panic!("{other:?}"),
    }
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_directory_rename_conflicts() {
    for kind in ["dir", "file", "symlink"] {
        let (_dir, root) = root();
        let scope = scope(&root, BIG);
        let files = three(&scope);
        let destination = root.join("prepared");
        let racer = destination.clone();
        let _guard = fault::install(Seam::new().before_publish(move || make_entry(kind, &racer)));
        assert!(
            matches!(
                publish_directory(&entries(&files), &destination, &scope).unwrap_err(),
                PublicationError::DestinationExists { .. }
            ),
            "{kind}"
        );
        assert_entry(kind, &destination);
        assert!(publish_siblings(&root).is_empty(), "{kind}");
    }
}

#[test]
fn publish_directory_other_rename_failure() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let files = three(&scope);
    let destination = root.join("prepared");
    let _guard = fault::install(Seam::new().fail(Step::Rename, io::ErrorKind::PermissionDenied));
    let (op, path, kind) =
        publication_io(publish_directory(&entries(&files), &destination, &scope).unwrap_err());
    assert_eq!(op, PublicationOperation::Rename);
    assert_eq!(path, Some(destination.clone()));
    assert_eq!(kind, io::ErrorKind::PermissionDenied);
    assert!(!destination.exists());
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_directory_random_source_failure() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let files = three(&scope);
    let _guard = fault::install(Seam::new().fail(Step::DrawName, io::ErrorKind::Other));
    let (op, path, kind) = publication_io(
        publish_directory(&entries(&files), &root.join("prepared"), &scope).unwrap_err(),
    );
    assert_eq!(op, PublicationOperation::CreateStagingDirectory);
    assert_eq!(path, Some(root.clone()));
    assert_eq!(kind, io::ErrorKind::Other);
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_directory_duplicate_name() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let files = three(&scope);
    let duplicated = vec![
        (PublishedFileName::PreparationManifest, &files[0]),
        (PublishedFileName::PreparationManifest, &files[1]),
    ];
    let destination = root.join("prepared");
    let (op, path, kind) =
        publication_io(publish_directory(&duplicated, &destination, &scope).unwrap_err());
    assert_eq!(op, PublicationOperation::CreateTemporary);
    assert!(path.unwrap().ends_with("manifest.json"));
    assert_eq!(kind, io::ErrorKind::AlreadyExists);
    assert!(!destination.exists());
    assert!(publish_siblings(&root).is_empty());
}

#[test]
fn publish_directory_pre_rename_failures() {
    for (step, operation) in [
        (Step::WriteTemporary, PublicationOperation::WriteTemporary),
        (Step::SyncFile, PublicationOperation::SyncFile),
        (Step::VerifyRead, PublicationOperation::Verify),
        (
            Step::SyncStagingDirectory,
            PublicationOperation::SyncDirectory,
        ),
    ] {
        for cleanup_fails in [false, true] {
            let (_dir, root) = root();
            let scope = scope(&root, BIG);
            let files = three(&scope);
            let destination = root.join("prepared");
            let mut seam = Seam::new().fail(step, io::ErrorKind::Unsupported);
            if cleanup_fails {
                seam = seam.fail(Step::RemoveTemporary, io::ErrorKind::PermissionDenied);
            }
            let guard = fault::install(seam);
            let (op, _, kind) = publication_io(
                publish_directory(&entries(&files), &destination, &scope).unwrap_err(),
            );
            drop(guard);
            assert_eq!(op, operation, "{step:?}");
            assert_eq!(kind, io::ErrorKind::Unsupported);
            assert!(!destination.exists());
            assert_eq!(
                publish_siblings(&root).len(),
                usize::from(cleanup_fails),
                "{step:?} cleanup_fails={cleanup_fails}"
            );
            assert_eq!(
                scope.budget_used(),
                files.iter().map(RetainedBytes::len).sum::<u64>()
            );
        }
    }
}

#[test]
fn publish_directory_post_rename_failure() {
    let (_dir, root) = root();
    let scope = scope(&root, BIG);
    let files = three(&scope);
    let destination = root.join("prepared");
    let _guard = fault::install(Seam::new().fail(Step::SyncParent, io::ErrorKind::Other));
    match publish_directory(&entries(&files), &destination, &scope).unwrap_err() {
        PublicationError::PublishDurability {
            destination: d,
            operation,
            ..
        } => {
            assert_eq!(d, destination);
            assert_eq!(operation, PublicationOperation::SyncDirectory);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(names_in(&destination).len(), 3);
    assert_eq!(
        fs::read(destination.join("archive.tar.zst")).unwrap(),
        b"archive bytes"
    );
}

#[test]
fn publish_directory_shares_the_budget() {
    let (_dir, root) = root();
    let scope = scope(&root, 20);
    let a = snap(&scope, b"0123456789");
    let destination = root.join("prepared");
    let files = [
        (PublishedFileName::PreparationArchive, &a),
        (PublishedFileName::PreparationRecord, &a),
    ];
    assert!(matches!(
        publish_directory(&files, &destination, &scope).unwrap_err(),
        PublicationError::DiskBudgetExceeded { limit: 20 }
    ));
    assert_eq!(scope.budget_high_water(), 20);
    assert_eq!(scope.budget_used(), 10);
    assert!(!destination.exists());
    assert!(publish_siblings(&root).is_empty());
}
