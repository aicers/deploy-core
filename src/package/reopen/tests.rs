use std::io::ErrorKind;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::super::contents::tests::fixture::{
    self as content_fixture, Art, COMMIT, COMPONENT, NAMESPACE, Signer, VERSION,
};
use super::super::prepare_fixture::{
    Dir, Ready, container, entries, limits, prepare, read_all, request, verify,
};
use super::super::source::seam::{self as source_seam, Op, Seam as SourceSeam};
use super::super::{PreparedPackage, RecordFault};
use super::*;
use crate::retain::fault::{self, Seam, Step};
use crate::verify::Statement;
use crate::verify::statement_order::recorded;

const MANIFEST: &str = "manifest.json";
const ARCHIVE: &str = "archive.tar.zst";
const RECORD: &str = "preparation.json";

const CHILD_DIR: &str = "DEPLOY_CORE_REOPEN_CHILD_DIR";
const CHILD_BINDING: &str = "DEPLOY_CORE_REOPEN_CHILD_BINDING";
const CHILD_STAGING: &str = "DEPLOY_CORE_REOPEN_CHILD_STAGING";
const CHILD_COPY: &str = "DEPLOY_CORE_REOPEN_CHILD_COPY";

/// A prepared package persisted into a fresh directory, and the binding the
/// caller saved for it.
struct Persisted {
    ready: Ready,
    out: Dir,
    dir: PathBuf,
    binding: PreparationBinding,
}

impl Persisted {
    fn new(arts: &[Art]) -> Persisted {
        let ready = prepare(arts, &ContentLimits::default()).ok();
        let out = Dir::new();
        let dir = out.path().join("prepared");
        ready.package.persist(&dir).expect("persisted");
        let binding =
            PreparationBinding::from_record_bytes(&ready.package.binding().to_record_bytes())
                .expect("the saved binding parses");
        Persisted {
            ready,
            out,
            dir,
            binding,
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn reopen(&self) -> Reopened {
        self.reopen_with(&self.binding, &request(), &ContentLimits::default())
    }

    fn reopen_with(
        &self,
        binding: &PreparationBinding,
        request: &VerifyRequest,
        limits: &ContentLimits,
    ) -> Reopened {
        reopen_at(&self.dir, binding, request, TargetArch::X86_64, limits)
    }
}

struct Reopened {
    result: Result<PreparedPackage, PackageWriteError>,
    staging: Dir,
}

/// A reopened package, with the staging parent its scope lives in.
struct Kept {
    package: PreparedPackage,
    _staging: Dir,
}

impl std::ops::Deref for Kept {
    type Target = PreparedPackage;

    fn deref(&self) -> &PreparedPackage {
        &self.package
    }
}

impl Reopened {
    #[track_caller]
    fn ok(self) -> Kept {
        Kept {
            package: self.result.expect("the preparation reopens"),
            _staging: self.staging,
        }
    }

    /// The refusal, after asserting nothing the call made remains.
    #[track_caller]
    fn err(self) -> PackageWriteError {
        let error = self.result.expect_err("the preparation is refused");
        assert!(
            self.staging.entries().is_empty(),
            "a refusal leaves nothing behind: {:?}",
            self.staging.entries()
        );
        error
    }
}

fn reopen_at(
    dir: &Path,
    binding: &PreparationBinding,
    request: &VerifyRequest,
    arch: TargetArch,
    limits: &ContentLimits,
) -> Reopened {
    let staging = Dir::new();
    let result = reopen_prepared(dir, binding, request, arch, limits, staging.path());
    Reopened { result, staging }
}

fn natives() -> Vec<Art> {
    vec![
        Art::native("bin/tool", b"\x7fELF tool"),
        Art::compose("compose.yaml", b"services: {}\n"),
    ]
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mkfifo(path: &Path) {
    let status = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo runs");
    assert!(status.success(), "mkfifo failed");
}

#[track_caller]
fn fault_of(error: &PackageWriteError) -> PreparationFault {
    match error {
        PackageWriteError::InvalidPreparation { reason } => *reason,
        other => panic!("expected an invalid preparation, got {other:?}"),
    }
}

#[track_caller]
fn directory_fault(error: &PackageWriteError) -> DirectoryFault {
    match fault_of(error) {
        PreparationFault::UnsafeDirectory { reason } => reason,
        other => panic!("expected an unsafe directory, got {other:?}"),
    }
}

#[track_caller]
fn mismatch(error: &PackageWriteError) -> BindingField {
    match error {
        PackageWriteError::BindingMismatch { field } => *field,
        other => panic!("expected a binding mismatch, got {other:?}"),
    }
}

#[track_caller]
fn limit_of(error: &PackageWriteError) -> (LimitResource, u64) {
    match error {
        PackageWriteError::Content(ContentError::LimitExceeded { resource, limit }) => {
            (*resource, *limit)
        }
        other => panic!("expected a limit, got {other:?}"),
    }
}

#[track_caller]
fn io_of(error: &PackageWriteError) -> (IoOperation, Option<PathBuf>, ErrorKind) {
    match error {
        PackageWriteError::Content(ContentError::Io {
            operation,
            path,
            source,
        }) => (*operation, path.clone(), source.kind()),
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).expect("metadata").len()
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[test]
fn a_persisted_preparation_reopens_byte_for_byte() {
    let persisted = Persisted::new(&content_fixture::mixed());
    let (reopened, order) = recorded(|| persisted.reopen().ok());
    assert_eq!(
        order,
        [
            Statement::Completeness,
            Statement::Identifiers,
            Statement::Target,
            Statement::Images
        ]
    );
    let original = &persisted.ready.package;
    assert_eq!(reopened.manifest_bytes(), original.manifest_bytes());
    assert_eq!(read_all(reopened.archive()), read_all(original.archive()));
    assert_eq!(reopened.binding(), original.binding());

    // Only A stays live, and it is all the budget holds.
    let scope = reopened.scope_for_test();
    assert_eq!(reopened.retained_disk_bytes(), reopened.archive().len());
    assert_eq!(scope.live_snapshots(), 1);
    assert_eq!(scope.budget_used(), reopened.archive().len());

    // Re-persisting gives the same three files.
    let again = persisted.out.path().join("again");
    reopened.persist(&again).expect("persisted again");
    for name in [MANIFEST, ARCHIVE, RECORD] {
        assert_eq!(
            std::fs::read(again.join(name)).expect("read"),
            std::fs::read(persisted.file(name)).expect("read"),
            "{name}"
        );
    }

    // And the reopened package still finalizes.
    let signer = Signer::new();
    let bytes = container(&signer, &reopened.package);
    verify(&bytes, &signer.trust(), &request(), TargetArch::X86_64)
        .expect("the reopened package verifies");
}

#[test]
fn a_child_process_reopens_and_persists_what_the_parent_saved() {
    let persisted = Persisted::new(&content_fixture::mixed());
    let saved = String::from_utf8(persisted.binding.to_record_bytes()).expect("ASCII");
    let staging = Dir::new();
    let copy = persisted.out.path().join("copy");
    let exe = std::env::current_exe().expect("the test binary");
    let output = Command::new(exe)
        .args([
            "--exact",
            "package::reopen::tests::child_reopens_a_persisted_preparation",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIR, &persisted.dir)
        .env(CHILD_BINDING, &saved)
        .env(CHILD_STAGING, staging.path())
        .env(CHILD_COPY, &copy)
        .output()
        .expect("the child runs");
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert!(stdout.contains("child reopened"), "{stdout}");

    let reopened = reopen_at(
        &copy,
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    assert_eq!(
        reopened.manifest_bytes(),
        persisted.ready.package.manifest_bytes()
    );
    for name in [MANIFEST, ARCHIVE, RECORD] {
        assert_eq!(
            std::fs::read(copy.join(name)).expect("read"),
            std::fs::read(persisted.file(name)).expect("read"),
            "{name}"
        );
    }
}

/// The child half of the cross-process round trip; returns at once unless
/// the parent passed its values.
#[test]
fn child_reopens_a_persisted_preparation() {
    let (Ok(dir), Ok(binding), Ok(staging), Ok(copy)) = (
        std::env::var(CHILD_DIR),
        std::env::var(CHILD_BINDING),
        std::env::var(CHILD_STAGING),
        std::env::var(CHILD_COPY),
    ) else {
        return;
    };
    let binding = PreparationBinding::from_record_bytes(binding.as_bytes()).expect("parses");
    let reopened = reopen_prepared(
        Path::new(&dir),
        &binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        Path::new(&staging),
    )
    .expect("the child reopens");
    let dir = Path::new(&dir);
    assert_eq!(
        reopened.manifest_bytes(),
        std::fs::read(dir.join(MANIFEST)).expect("read")
    );
    assert_eq!(
        read_all(reopened.archive()),
        std::fs::read(dir.join(ARCHIVE)).expect("read")
    );
    assert_eq!(reopened.binding(), &binding);
    reopened
        .persist(Path::new(&copy))
        .expect("the child persists");
    println!("child reopened");
}

#[test]
fn retained_disk_passes_at_the_reopen_high_water_mark() {
    let persisted = Persisted::new(&content_fixture::mixed());
    let reopened = persisted.reopen().ok();
    let high = reopened.scope_for_test().budget_high_water();
    let at = limits(LimitResource::RetainedDisk, high);
    persisted
        .reopen_with(&persisted.binding, &request(), &at)
        .ok();
    let below = limits(LimitResource::RetainedDisk, high - 1);
    let error = persisted
        .reopen_with(&persisted.binding, &request(), &below)
        .err();
    assert_eq!(limit_of(&error), (LimitResource::RetainedDisk, high - 1));
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[test]
fn each_file_passes_at_its_limit() {
    let persisted = Persisted::new(&natives());
    for (name, resource) in [
        (MANIFEST, LimitResource::RawManifest),
        (ARCHIVE, LimitResource::CompressedArchive),
        (RECORD, LimitResource::PreparationRecord),
    ] {
        let len = file_len(&persisted.file(name));
        persisted
            .reopen_with(&persisted.binding, &request(), &limits(resource, len))
            .ok();
        let error = persisted
            .reopen_with(&persisted.binding, &request(), &limits(resource, len - 1))
            .err();
        assert_eq!(limit_of(&error), (resource, len - 1), "{name}");
    }
}

#[test]
fn the_record_depth_limit_applies() {
    let persisted = Persisted::new(&natives());
    persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::JsonDepth, 1),
        )
        .ok();
    let record = std::fs::read_to_string(persisted.file(RECORD)).expect("read");
    std::fs::write(
        persisted.file(RECORD),
        record.replacen('{', "{\"deep\":[1],", 1),
    )
    .expect("written");
    let error = persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::JsonDepth, 1),
        )
        .err();
    assert_eq!(limit_of(&error), (LimitResource::JsonDepth, 1));
    let error = persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::JsonDepth, 2),
        )
        .err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::RecordInvalid(RecordFault::UnknownField)
    );
}

#[test]
fn a_file_growing_during_the_copy_is_held_to_its_limit() {
    let persisted = Persisted::new(&natives());
    let record = persisted.file(RECORD);
    let len = file_len(&record);
    let grow = record.clone();
    let _seam = fault::install(Seam::new().before(Step::ReadPreparationFile, 1, move || {
        let mut bytes = std::fs::read(&grow).expect("read");
        bytes.extend_from_slice(b" ");
        std::fs::write(&grow, bytes).expect("grown");
    }));
    let error = persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::PreparationRecord, len),
        )
        .err();
    assert_eq!(limit_of(&error), (LimitResource::PreparationRecord, len));
}

// ---------------------------------------------------------------------------
// Accepted transport
// ---------------------------------------------------------------------------

#[test]
fn readable_files_in_a_shared_but_sticky_parent_are_accepted() {
    let persisted = Persisted::new(&natives());
    for name in [MANIFEST, ARCHIVE, RECORD] {
        chmod(&persisted.file(name), 0o644);
    }
    chmod(&persisted.dir, 0o755);
    chmod(persisted.out.path(), 0o1777);
    let reopened = persisted.reopen().ok();
    assert_eq!(reopened.binding(), &persisted.binding);
    chmod(persisted.out.path(), 0o700);
}

#[test]
fn files_owned_by_another_user_are_accepted() {
    if rustix::process::geteuid().as_raw() != 0 {
        eprintln!("skipped: changing a file's owner needs root");
        return;
    }
    let persisted = Persisted::new(&natives());
    for name in [MANIFEST, ARCHIVE, RECORD] {
        let path = persisted.file(name);
        std::os::unix::fs::chown(&path, Some(65_534), Some(65_534)).expect("chown");
        chmod(&path, 0o644);
    }
    persisted.reopen().ok();
}

// ---------------------------------------------------------------------------
// Directory refusals
// ---------------------------------------------------------------------------

#[test]
fn directory_syntax_is_refused_before_any_system_call() {
    let persisted = Persisted::new(&natives());
    for (path, expected) in [
        ("relative/dir", DirectoryFault::NotAbsolute),
        ("/a/../b", DirectoryFault::NotCanonical),
        ("/a/b/", DirectoryFault::NotCanonical),
        ("/a//b", DirectoryFault::NotCanonical),
        ("/", DirectoryFault::NoParent),
    ] {
        let _seam = fault::install(Seam::new());
        let error = reopen_at(
            Path::new(path),
            &persisted.binding,
            &request(),
            TargetArch::X86_64,
            &ContentLimits::default(),
        )
        .err();
        assert_eq!(directory_fault(&error), expected, "{path}");
        assert!(fault::record().is_empty(), "{path}: {:?}", fault::record());
    }
}

#[test]
fn symlinked_and_non_directory_components_are_refused() {
    let persisted = Persisted::new(&natives());
    let root = persisted.out.path();

    let link = root.join("link");
    symlink(&persisted.dir, &link).expect("a symlink");
    let error = reopen_at(
        &link,
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(directory_fault(&error), DirectoryFault::SymlinkComponent);

    let ancestor = root.join("ancestor");
    symlink(root, &ancestor).expect("a symlink");
    let error = reopen_at(
        &ancestor.join("prepared"),
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(directory_fault(&error), DirectoryFault::SymlinkComponent);

    let error = reopen_at(
        &persisted.file(MANIFEST).join("x"),
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(directory_fault(&error), DirectoryFault::NotDirectory);
}

#[test]
fn writable_directories_are_refused() {
    let persisted = Persisted::new(&natives());
    for mode in [0o775, 0o757] {
        chmod(&persisted.dir, mode);
        let error = persisted.reopen().err();
        assert_eq!(
            directory_fault(&error),
            DirectoryFault::GroupOrOtherWritable,
            "{mode:o}"
        );
    }
    chmod(&persisted.dir, 0o700);
    chmod(persisted.out.path(), 0o777);
    let error = persisted.reopen().err();
    chmod(persisted.out.path(), 0o700);
    assert_eq!(
        directory_fault(&error),
        DirectoryFault::ParentGroupOrOtherWritable
    );
}

#[test]
fn a_missing_component_is_not_found_with_its_path() {
    let persisted = Persisted::new(&natives());
    let missing = persisted.out.path().join("missing");
    let error = reopen_at(
        &missing.join("prepared"),
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(
        io_of(&error),
        (
            IoOperation::OpenPreparation,
            Some(missing),
            ErrorKind::NotFound
        )
    );
}

// ---------------------------------------------------------------------------
// Member refusals
// ---------------------------------------------------------------------------

#[test]
fn an_extra_entry_is_refused() {
    let persisted = Persisted::new(&natives());
    std::fs::write(persisted.dir.join("manifest.json.sig"), b"sig").expect("written");
    let error = persisted.reopen().err();
    assert_eq!(fault_of(&error), PreparationFault::ExtraMember);
}

#[test]
fn a_missing_file_is_named_in_file_order() {
    let persisted = Persisted::new(&natives());
    std::fs::remove_file(persisted.file(RECORD)).expect("removed");
    std::fs::remove_file(persisted.file(ARCHIVE)).expect("removed");
    let error = persisted.reopen().err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::MissingMember {
            file: PreparationFile::Archive
        }
    );
}

#[test]
fn an_extra_entry_wins_over_a_missing_one() {
    let persisted = Persisted::new(&natives());
    std::fs::remove_file(persisted.file(ARCHIVE)).expect("removed");
    std::fs::write(persisted.dir.join("stray"), b"x").expect("written");
    let error = persisted.reopen().err();
    assert_eq!(fault_of(&error), PreparationFault::ExtraMember);
}

#[test]
fn a_symlinked_manifest_is_refused() {
    let persisted = Persisted::new(&natives());
    let elsewhere = persisted.out.path().join("elsewhere.json");
    std::fs::rename(persisted.file(MANIFEST), &elsewhere).expect("moved");
    symlink(&elsewhere, persisted.file(MANIFEST)).expect("a symlink");
    let error = persisted.reopen().err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::Symlink {
            file: PreparationFile::Manifest
        }
    );
}

#[test]
fn a_fifo_archive_is_not_a_regular_file() {
    let persisted = Persisted::new(&natives());
    std::fs::remove_file(persisted.file(ARCHIVE)).expect("removed");
    mkfifo(&persisted.file(ARCHIVE));
    let error = persisted.reopen().err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::NotRegularFile {
            file: PreparationFile::Archive
        }
    );
}

#[test]
fn writable_files_are_refused() {
    for (name, file) in [
        (MANIFEST, PreparationFile::Manifest),
        (ARCHIVE, PreparationFile::Archive),
        (RECORD, PreparationFile::Record),
    ] {
        for mode in [0o664, 0o646] {
            let persisted = Persisted::new(&natives());
            chmod(&persisted.file(name), mode);
            let error = persisted.reopen().err();
            assert_eq!(
                fault_of(&error),
                PreparationFault::GroupOrOtherWritable { file },
                "{name} {mode:o}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Races
// ---------------------------------------------------------------------------

/// Runs `swap` on the manifest just before it is opened, after `statat`,
/// and asserts no preparation file was read.
fn swap_before_open(persisted: &Persisted, swap: impl FnOnce(&Path) + 'static) -> Reopened {
    let manifest = persisted.file(MANIFEST);
    let _seam = fault::install(Seam::new().before(Step::OpenPreparationFile, 1, move || {
        swap(&manifest);
    }));
    let reopened = persisted.reopen();
    assert!(!fault::record().contains(&Step::ReadPreparationFile));
    reopened
}

#[test]
fn a_manifest_swapped_for_a_fifo_is_identity_changed_and_never_blocks() {
    let persisted = Persisted::new(&natives());
    let error = swap_before_open(&persisted, |manifest| {
        std::fs::remove_file(manifest).expect("removed");
        mkfifo(manifest);
    })
    .err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::IdentityChanged {
            file: PreparationFile::Manifest
        }
    );
}

#[test]
fn a_manifest_swapped_for_another_file_is_identity_changed() {
    let persisted = Persisted::new(&natives());
    let error = swap_before_open(&persisted, |manifest| {
        let other = manifest.with_file_name("other");
        std::fs::copy(manifest, &other).expect("copied");
        std::fs::rename(&other, manifest).expect("replaced");
    })
    .err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::IdentityChanged {
            file: PreparationFile::Manifest
        }
    );
}

#[test]
fn a_manifest_swapped_for_a_symlink_is_never_followed() {
    let persisted = Persisted::new(&natives());
    let target = persisted.out.path().join("target.json");
    std::fs::write(&target, persisted.ready.package.manifest_bytes()).expect("written");
    let link_target = target.clone();
    let error = swap_before_open(&persisted, move |manifest| {
        std::fs::remove_file(manifest).expect("removed");
        symlink(&link_target, manifest).expect("a symlink");
    })
    .err();
    let (operation, path, _) = io_of(&error);
    assert_eq!(operation, IoOperation::OpenPreparation);
    assert_eq!(path, Some(persisted.file(MANIFEST)));
}

#[test]
fn a_manifest_deleted_before_it_is_opened_is_named() {
    let persisted = Persisted::new(&natives());
    let error = swap_before_open(&persisted, |manifest| {
        std::fs::remove_file(manifest).expect("removed");
    })
    .err();
    assert_eq!(
        io_of(&error),
        (
            IoOperation::OpenPreparation,
            Some(persisted.file(MANIFEST)),
            ErrorKind::NotFound
        )
    );
}

#[test]
fn an_ancestor_swapped_for_a_symlink_mid_walk_does_not_redirect_it() {
    let persisted = Persisted::new(&natives());
    let root = persisted.out.path();
    let ancestor = root.join("ancestor");
    std::fs::create_dir(&ancestor).expect("created");
    let dir = ancestor.join("prepared");
    std::fs::rename(&persisted.dir, &dir).expect("moved");

    // A different, valid preparation the swap would redirect to.
    let decoy = Persisted::new(&content_fixture::mixed());
    let decoy_root = decoy.out.path().to_owned();

    // `/`, each component of `root`, then `ancestor`, then `prepared`.
    let components = root.components().count();
    let moved = root.join("moved");
    let (from, to) = (ancestor.clone(), moved.clone());
    let _seam = fault::install(Seam::new().before(
        Step::OpenPreparationComponent,
        components + 2,
        move || {
            std::fs::rename(&from, &to).expect("moved away");
            symlink(&decoy_root, &from).expect("swapped for a symlink");
        },
    ));
    let reopened = reopen_at(
        &dir,
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    assert_eq!(reopened.binding(), &persisted.binding);
    assert!(
        std::fs::symlink_metadata(&ancestor)
            .expect("the swap happened")
            .file_type()
            .is_symlink()
    );
    drop(decoy);
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

#[test]
fn failed_filesystem_steps_name_their_concrete_target() {
    let persisted = Persisted::new(&natives());
    let first_component = persisted
        .dir
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .nth(1)
        .expect("a first component")
        .to_owned();
    for (step, expected) in [
        (Step::OpenPreparationComponent, first_component),
        (Step::ListPreparation, persisted.dir.clone()),
        (Step::OpenPreparationFile, persisted.file(MANIFEST)),
        (Step::ReadPreparationFile, persisted.file(RECORD)),
    ] {
        let n = if step == Step::OpenPreparationComponent {
            2
        } else {
            1
        };
        let _seam = fault::install(Seam::new().fail_nth(step, n, ErrorKind::PermissionDenied));
        let error = persisted.reopen().err();
        assert_eq!(
            io_of(&error),
            (
                IoOperation::OpenPreparation,
                Some(expected),
                ErrorKind::PermissionDenied
            ),
            "{step:?}"
        );
    }
}

#[test]
fn a_failed_read_of_a_finished_snapshot_has_no_path() {
    let persisted = Persisted::new(&natives());
    let _seam = source_seam::install(SourceSeam::new().fail_nth(
        SourceRole::Reopened,
        Op::Read,
        1,
        ErrorKind::Other,
    ));
    let error = persisted.reopen().err();
    assert_eq!(
        io_of(&error),
        (IoOperation::ReadSnapshot, None, ErrorKind::Other)
    );
}

// ---------------------------------------------------------------------------
// Binding mismatches
// ---------------------------------------------------------------------------

#[test]
fn a_reformatted_manifest_is_a_digest_mismatch() {
    let persisted = Persisted::new(&natives());
    let manifest: serde_json::Value =
        serde_json::from_slice(persisted.ready.package.manifest_bytes()).expect("json");
    std::fs::write(
        persisted.file(MANIFEST),
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("written");
    let error = persisted.reopen().err();
    assert_eq!(mismatch(&error), BindingField::ManifestSha256);
}

#[test]
fn a_flipped_or_truncated_archive_is_a_digest_mismatch() {
    let persisted = Persisted::new(&natives());
    let archive = std::fs::read(persisted.file(ARCHIVE)).expect("read");
    let mut flipped = archive.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0xff;
    std::fs::write(persisted.file(ARCHIVE), &flipped).expect("written");
    assert_eq!(
        mismatch(&persisted.reopen().err()),
        BindingField::ArchiveSha256
    );
    std::fs::write(persisted.file(ARCHIVE), &archive[..last]).expect("written");
    assert_eq!(
        mismatch(&persisted.reopen().err()),
        BindingField::ArchiveSha256
    );
}

fn edit_record(persisted: &Persisted, from: &str, to: &str) {
    let record = std::fs::read_to_string(persisted.file(RECORD)).expect("read");
    assert!(record.contains(from));
    std::fs::write(persisted.file(RECORD), record.replacen(from, to, 1)).expect("written");
}

const OTHER_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";

#[test]
fn an_edited_record_is_a_mismatch_of_its_field() {
    let persisted = Persisted::new(&natives());
    edit_record(&persisted, COMMIT, OTHER_COMMIT);
    assert_eq!(mismatch(&persisted.reopen().err()), BindingField::Commit);
}

#[test]
fn a_self_consistent_substitute_is_a_manifest_mismatch() {
    let persisted = Persisted::new(&natives());
    let substitute = Persisted::new(&[Art::native("bin/tool", b"\x7fELF other tool")]);
    let error = reopen_at(
        &substitute.dir,
        &persisted.binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(mismatch(&error), BindingField::ManifestSha256);
}

#[test]
fn a_request_disagreeing_with_the_binding_is_refused_first() {
    let persisted = Persisted::new(&natives());
    let other_namespace =
        VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, "other-product")
            .expect("a request");
    let trust = VerifyRequest::for_trust(VERSION, COMMIT, 3).expect("a request");
    let plain = VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("a request");
    for (request, arch, field) in [
        (
            &other_namespace,
            TargetArch::X86_64,
            BindingField::Namespace,
        ),
        (&request(), TargetArch::Aarch64, BindingField::TargetArch),
        (&trust, TargetArch::X86_64, BindingField::Target),
        (&plain, TargetArch::X86_64, BindingField::Namespace),
    ] {
        let error = reopen_at(
            &persisted.dir,
            &persisted.binding,
            request,
            arch,
            &ContentLimits::default(),
        )
        .err();
        assert_eq!(mismatch(&error), field);
    }

    // An epoch is compared as recorded data: a trust binding under another
    // delivered epoch differs in `trust_epoch`.
    let trust_art = {
        let mut art = Art::native("trust-set.json", b"{}");
        art.kind = crate::manifest::ArtifactKind::StaticAssets;
        art.component = crate::verify::TRUST_TARGET.to_string();
        art.version = "8".to_string();
        art
    };
    let ready = super::super::prepare_fixture::prepare_with(
        &[trust_art],
        &VerifyRequest::for_trust("8", COMMIT, 3).expect("a request"),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    let later = VerifyRequest::for_trust("8", COMMIT, 4).expect("a request");
    let error = reopen_at(
        &persisted.dir,
        ready.package.binding(),
        &later,
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(mismatch(&error), BindingField::TrustEpoch);
}

// ---------------------------------------------------------------------------
// Paired faults
// ---------------------------------------------------------------------------

#[test]
fn a_request_mismatch_comes_before_any_filesystem_call() {
    let persisted = Persisted::new(&natives());
    let link = persisted.out.path().join("link");
    symlink(&persisted.dir, &link).expect("a symlink");
    let _seam = fault::install(Seam::new());
    let error = reopen_at(
        &link,
        &persisted.binding,
        &request(),
        TargetArch::Aarch64,
        &ContentLimits::default(),
    )
    .err();
    assert_eq!(mismatch(&error), BindingField::TargetArch);
    assert!(fault::record().is_empty(), "{:?}", fault::record());
}

#[test]
fn file_faults_follow_file_order_then_check_order() {
    // A symlinked manifest beside an oversize archive.
    let persisted = Persisted::new(&natives());
    let elsewhere = persisted.out.path().join("elsewhere.json");
    std::fs::rename(persisted.file(MANIFEST), &elsewhere).expect("moved");
    symlink(&elsewhere, persisted.file(MANIFEST)).expect("a symlink");
    let error = persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::CompressedArchive, 1),
        )
        .err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::Symlink {
            file: PreparationFile::Manifest
        }
    );

    // A writable archive beside an oversize record.
    let persisted = Persisted::new(&natives());
    chmod(&persisted.file(ARCHIVE), 0o664);
    let error = persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::PreparationRecord, 1),
        )
        .err();
    assert_eq!(
        fault_of(&error),
        PreparationFault::GroupOrOtherWritable {
            file: PreparationFile::Archive
        }
    );

    // An oversize manifest beside an invalid record.
    let persisted = Persisted::new(&natives());
    std::fs::write(persisted.file(RECORD), b"not json").expect("written");
    let len = file_len(&persisted.file(MANIFEST));
    let error = persisted
        .reopen_with(
            &persisted.binding,
            &request(),
            &limits(LimitResource::RawManifest, len - 1),
        )
        .err();
    assert_eq!(limit_of(&error), (LimitResource::RawManifest, len - 1));
}

#[test]
fn the_record_is_judged_before_the_manifest_and_the_manifest_before_the_archive() {
    // An invalid record beside a changed manifest.
    let persisted = Persisted::new(&natives());
    std::fs::write(persisted.file(RECORD), b"not json").expect("written");
    std::fs::write(persisted.file(MANIFEST), b"{}").expect("written");
    assert_eq!(
        fault_of(&persisted.reopen().err()),
        PreparationFault::RecordInvalid(RecordFault::Malformed)
    );

    // An edited record beside a changed manifest.
    let persisted = Persisted::new(&natives());
    edit_record(&persisted, COMMIT, OTHER_COMMIT);
    std::fs::write(persisted.file(MANIFEST), b"{}").expect("written");
    assert_eq!(mismatch(&persisted.reopen().err()), BindingField::Commit);

    // A changed manifest beside a changed archive: the archive is never read.
    let persisted = Persisted::new(&natives());
    std::fs::write(persisted.file(MANIFEST), b"{}").expect("written");
    std::fs::write(persisted.file(ARCHIVE), b"not an archive").expect("written");
    let _seam = fault::install(Seam::new());
    assert_eq!(
        mismatch(&persisted.reopen().err()),
        BindingField::ManifestSha256
    );
    let reads = fault::record()
        .iter()
        .filter(|step| **step == Step::ReadPreparationFile)
        .count();
    // The record and the manifest are each read to their end, and never the
    // archive: two reads apiece.
    assert_eq!(reads, 4, "{:?}", fault::record());
}

#[test]
fn content_matching_its_binding_is_still_revalidated() {
    let mut arts = content_fixture::mixed();
    arts[0].bytes = b"placeholder image bytes".to_vec();
    let manifest = content_fixture::manifest_bytes(&arts);
    let archive = content_fixture::archive(&arts);

    let out = Dir::new();
    let dir = out.path().join("prepared");
    std::fs::create_dir(&dir).expect("created");
    chmod(&dir, 0o700);
    let digest = |bytes: &[u8]| crate::payload::sha256_hex(bytes);
    let record = format!(
        concat!(
            "{{\"schema\":1,\"manifest_sha256\":\"sha256:{}\",\"manifest_length\":{},",
            "\"archive_sha256\":\"sha256:{}\",\"archive_length\":{},",
            "\"target\":\"{}\",\"version\":\"{}\",\"commit\":\"{}\",",
            "\"target_arch\":\"x86_64\",\"namespace\":\"{}\",\"trust_epoch\":null}}\n"
        ),
        digest(&manifest),
        manifest.len(),
        digest(&archive),
        archive.len(),
        COMPONENT,
        VERSION,
        COMMIT,
        NAMESPACE,
    );
    for (name, bytes) in [
        (MANIFEST, &manifest[..]),
        (ARCHIVE, &archive[..]),
        (RECORD, record.as_bytes()),
    ] {
        std::fs::write(dir.join(name), bytes).expect("written");
        chmod(&dir.join(name), 0o600);
    }
    let binding = PreparationBinding::from_record_bytes(record.as_bytes()).expect("parses");
    let error = reopen_at(
        &dir,
        &binding,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .err();
    assert!(
        matches!(
            error,
            PackageWriteError::Content(ContentError::Verify(crate::verify::VerifyError::Image(_)))
        ),
        "{error:?}"
    );
    assert_eq!(entries(&dir), [ARCHIVE, MANIFEST, RECORD]);
}
