use std::cell::{Cell, RefCell};
use std::io::{Cursor, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;

use ring::signature::Ed25519KeyPair;
use serde_json::{Value, json};

use super::super::contents::tests::fixture::{Art, COMMIT, COMPONENT, NAMESPACE, VERSION};
use super::super::prepare::new_scope;
use super::super::prepare_fixture::{
    Dir, Ready, entries, limits, prepare, prepare_with, read_all, request, six_images, verify,
};
use super::super::{PublicationOperation, VerifiedImages, reopen_prepared};
use super::*;
use crate::manifest::{ArtifactKind, PayloadManifest};
use crate::payload::{FOOTER_SIZE, FORMAT_VERSION, MAGIC, append_trailer_signed, counters};
use crate::retain::fault::{self, Seam, Step};
use crate::trust_fixture::{keypair, public_key_of};
use crate::verify::{TRUST_TARGET, TrustAnchor, VerifyError, key_id, verify_package};

const CHILD_DIR: &str = "DEPLOY_CORE_FINALIZE_CHILD_DIR";
const CHILD_BINDING: &str = "DEPLOY_CORE_FINALIZE_CHILD_BINDING";
const CHILD_STAGING: &str = "DEPLOY_CORE_FINALIZE_CHILD_STAGING";
const CHILD_SIGNATURE: &str = "DEPLOY_CORE_FINALIZE_CHILD_SIGNATURE";
const CHILD_KEY: &str = "DEPLOY_CORE_FINALIZE_CHILD_KEY";
const CHILD_OUTPUT: &str = "DEPLOY_CORE_FINALIZE_CHILD_OUTPUT";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A signing key minted for one test.
struct Key {
    pair: Ed25519KeyPair,
}

impl Key {
    fn new() -> Key {
        Key { pair: keypair() }
    }

    fn public(&self) -> [u8; 32] {
        public_key_of(&self.pair)
    }

    fn id(&self) -> String {
        key_id(&self.public())
    }

    fn anchor(&self, revoked: bool) -> TrustAnchor {
        TrustAnchor::new(self.public(), revoked)
    }

    /// Signs `message` and names this key.
    fn sign(&self, message: &[u8]) -> Signed {
        self.sign_as(message, &self.id())
    }

    /// Signs `message` and names `hint` as the key.
    fn sign_as(&self, message: &[u8], hint: &str) -> Signed {
        Signed {
            signature: self.pair.sign(message).as_ref().to_vec(),
            key_id: hint.to_string(),
        }
    }

    fn trust(&self) -> TrustSet {
        trust(vec![self.anchor(false)])
    }
}

fn trust(anchors: Vec<TrustAnchor>) -> TrustSet {
    TrustSet::new(anchors, Vec::new(), 0, 0).expect("a trust set")
}

fn copy(signed: &Signed) -> Signed {
    Signed {
        signature: signed.signature.clone(),
        key_id: signed.key_id.clone(),
    }
}

/// Finalizes `package` against its own binding for `x86_64` under the
/// fixture request.
fn finalize(
    package: &PreparedPackage,
    signed: &Signed,
    trust: &TrustSet,
    limits: &ContentLimits,
    staging: &Dir,
) -> Result<FinalizedPackage, PackageWriteError> {
    finalize_package(
        package,
        package.binding(),
        signed,
        trust,
        &request(),
        TargetArch::X86_64,
        limits,
        staging.path(),
    )
}

/// `M ‖ A ‖ signature ‖ key ID ‖ footer`, through the shared tail writer.
fn assemble_bytes(manifest: &[u8], archive: &[u8], signed: &Signed) -> Vec<u8> {
    let mut out = manifest.to_vec();
    out.extend_from_slice(archive);
    write_standalone_tail(
        &mut out,
        0,
        manifest.len() as u64,
        archive.len() as u64,
        Some(signed),
    )
    .expect("the tail is written");
    out
}

/// The footer's version and its eight fields.
fn footer_of(bytes: &[u8]) -> (u8, [u64; 8]) {
    let footer = &bytes[bytes.len() - FOOTER_SIZE..];
    assert_eq!(&footer[..MAGIC.len()], MAGIC);
    let version = footer[MAGIC.len()];
    let mut fields = [0u64; 8];
    for (at, field) in fields.iter_mut().enumerate() {
        let start = MAGIC.len() + 1 + at * 8;
        *field = u64::from_le_bytes(footer[start..start + 8].try_into().unwrap());
    }
    (version, fields)
}

/// What a prepared package holds, to show a call left it untouched.
struct Before {
    binding: PreparationBinding,
    manifest: Vec<u8>,
    archive: Vec<u8>,
    archive_sha256: [u8; 32],
    used: u64,
    live: u64,
    private: PathBuf,
}

fn capture(package: &PreparedPackage) -> Before {
    let scope = package.scope_for_test();
    Before {
        binding: package.binding().clone(),
        manifest: package.manifest_bytes().to_vec(),
        archive: read_all(package.archive()),
        archive_sha256: *package.archive().sha256(),
        used: scope.budget_used(),
        live: scope.live_snapshots(),
        private: scope.private_path().to_path_buf(),
    }
}

#[track_caller]
fn assert_unchanged(package: &PreparedPackage, before: &Before) {
    let scope = package.scope_for_test();
    assert_eq!(package.binding(), &before.binding);
    assert_eq!(package.manifest_bytes(), &before.manifest[..]);
    assert_eq!(read_all(package.archive()), before.archive);
    assert_eq!(package.archive().sha256(), &before.archive_sha256);
    assert_eq!(scope.budget_used(), before.used);
    assert_eq!(scope.live_snapshots(), before.live);
    assert!(before.private.is_dir(), "the prepared scope is still there");
}

/// The fixture every negative starts from: a prepared package of mixed
/// artifacts, the key that signs it, and a fresh staging parent.
struct Case {
    ready: Ready,
    key: Key,
    staging: Dir,
    before: Before,
}

impl Case {
    fn new() -> Case {
        Case::of(&super::super::contents::tests::fixture::mixed())
    }

    fn of(arts: &[Art]) -> Case {
        let ready = prepare(arts, &ContentLimits::default()).ok();
        let before = capture(&ready.package);
        Case {
            ready,
            key: Key::new(),
            staging: Dir::new(),
            before,
        }
    }

    fn package(&self) -> &PreparedPackage {
        &self.ready.package
    }

    fn signed(&self) -> Signed {
        self.key.sign(self.package().manifest_bytes())
    }

    fn finalize(&self) -> Result<FinalizedPackage, PackageWriteError> {
        finalize(
            self.package(),
            &self.signed(),
            &self.key.trust(),
            &ContentLimits::default(),
            &self.staging,
        )
    }

    /// Unwraps a refusal and checks what every refusal must leave behind:
    /// nothing of its own, an untouched prepared package that still
    /// finalizes.
    #[track_caller]
    fn refused(&self, result: Result<FinalizedPackage, PackageWriteError>) -> PackageWriteError {
        let error = result.expect_err("finalization is refused");
        assert!(
            self.staging.entries().is_empty(),
            "a refusal leaves nothing behind: {:?}",
            self.staging.entries()
        );
        assert_unchanged(self.package(), &self.before);
        let retried = self
            .finalize()
            .expect("the prepared package still finalizes");
        drop(retried);
        assert!(self.staging.entries().is_empty());
        assert_unchanged(self.package(), &self.before);
        error
    }

    fn bytes(&self, signed: &Signed) -> Vec<u8> {
        assemble_bytes(
            self.package().manifest_bytes(),
            &read_all(self.package().archive()),
            signed,
        )
    }
}

#[track_caller]
fn verdict_of(error: &PackageWriteError) -> &VerifyError {
    match error {
        PackageWriteError::Content(ContentError::Verify(verdict)) => verdict,
        other => panic!("expected a verification verdict, got {other:?}"),
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
fn mismatch_of(error: &PackageWriteError) -> BindingField {
    match error {
        PackageWriteError::BindingMismatch { field } => *field,
        other => panic!("expected a binding mismatch, got {other:?}"),
    }
}

fn scope_steps(record: &[Step]) -> Vec<Step> {
    record
        .iter()
        .copied()
        .filter(|step| {
            matches!(
                step,
                Step::OpenComponent
                    | Step::DrawName
                    | Step::MakeDirectory
                    | Step::CreateSnapshot
                    | Step::WriteSnapshot
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

#[test]
fn six_images_finalize_into_exactly_the_prepared_blocks() {
    for arch in [TargetArch::X86_64, TargetArch::Aarch64] {
        let arts = six_images(arch);
        let ready = prepare_with(&arts, &request(), arch, &ContentLimits::default()).ok();
        let package = &ready.package;
        let key = Key::new();
        let signed = key.sign(package.manifest_bytes());
        let staging = Dir::new();
        let finalized = finalize_package(
            package,
            package.binding(),
            &signed,
            &key.trust(),
            &request(),
            arch,
            &ContentLimits::default(),
            staging.path(),
        )
        .expect("the package finalizes");

        let bytes = read_all(finalized.bytes());
        let manifest = package.manifest_bytes();
        let archive = read_all(package.archive());
        let m = manifest.len();
        let a = archive.len();
        assert_eq!(&bytes[..m], manifest);
        assert_eq!(&bytes[m..m + a], &archive[..]);
        assert_eq!(&bytes[m + a..m + a + 64], &signed.signature[..]);
        assert_eq!(&bytes[m + a + 64..m + a + 128], signed.key_id.as_bytes());
        assert_eq!(bytes.len(), m + a + 128 + FOOTER_SIZE);
        let (version, fields) = footer_of(&bytes);
        assert_eq!(version, FORMAT_VERSION);
        let (m, a) = (m as u64, a as u64);
        assert_eq!(fields, [0, m, m, a, m + a, 64, m + a + 64, 64]);

        // The same object, not a copy.
        assert!(std::ptr::eq(
            finalized.bytes(),
            finalized.contents().package_bytes()
        ));
        assert_eq!(finalized.binding(), package.binding());

        // Byte-identical to the legacy writer's standalone output for the
        // same inputs and the same signature.
        let mut legacy = Vec::new();
        append_trailer_signed(
            std::io::empty(),
            &mut legacy,
            None,
            None,
            &ready.inputs,
            |message| {
                assert_eq!(message, manifest);
                Ok(copy(&signed))
            },
        )
        .expect("the legacy writer writes");
        assert_eq!(bytes, legacy);

        // The evidence is what a direct verification of the bytes gives.
        let direct = verify(&bytes, &key.trust(), &request(), arch).expect("the bytes verify");
        let contents = finalized.contents();
        assert_eq!(contents.manifest(), direct.manifest());
        assert_eq!(contents.artifacts().len(), direct.artifacts().len());
        for ((ours, theirs), art) in contents
            .artifacts()
            .iter()
            .zip(direct.artifacts())
            .zip(&arts)
        {
            assert_eq!(ours.artifact(), theirs.artifact());
            assert_eq!(read_all(ours.bytes()), read_all(theirs.bytes()));
            assert_eq!(read_all(ours.bytes()), art.bytes);
        }
        let (VerifiedImages::Present(ours), VerifiedImages::Present(theirs)) =
            (contents.images(), direct.images())
        else {
            panic!("both carry images");
        };
        assert_eq!(ours.len(), 6);
        for (ours, theirs) in ours.iter().zip(theirs.iter()) {
            assert_eq!(ours.declaration(), theirs.declaration());
            assert_eq!(read_all(ours.archive()), read_all(theirs.archive()));
        }
    }
}

#[test]
fn a_finalized_package_is_send_and_sync_and_debugs_no_content() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FinalizedPackage>();
    let case = Case::new();
    let finalized = case.finalize().expect("finalizes");
    let debug = format!("{finalized:?}");
    assert!(debug.starts_with("FinalizedPackage"), "{debug}");
    assert!(!debug.contains("services"), "{debug}");
}

#[test]
fn finalization_reads_no_source_and_neither_serializes_nor_compresses() {
    counters::reset();
    let case = Case::of(&six_images(TargetArch::X86_64));
    let (serialized, encoders) = counters::read();
    assert_eq!(
        (serialized, encoders),
        (1, 1),
        "preparation serializes M once and compresses A once"
    );
    for input in &case.ready.inputs {
        std::fs::remove_file(&input.source).expect("the source is deleted");
    }
    assert!(entries(case.ready.sources.path()).is_empty());

    counters::reset();
    let finalized = case.finalize().expect("finalizes without any source");
    assert_eq!(counters::read(), (0, 0));
    assert_eq!(
        read_all(finalized.bytes()),
        case.bytes(&case.signed()),
        "and still carries exactly M and A"
    );
}

#[test]
fn a_child_process_finalizes_what_the_parent_prepared() {
    let case = Case::new();
    let out = Dir::new();
    let dir = out.path().join("prepared");
    case.package().persist(&dir).expect("persisted");
    let saved = String::from_utf8(case.package().binding().to_record_bytes()).expect("ASCII");
    let signed = case.signed();
    let output = out.path().join("package.pkg");
    let staging = Dir::new();
    let exe = std::env::current_exe().expect("the test binary");
    let result = Command::new(exe)
        .args([
            "--exact",
            "package::finalize::tests::child_finalizes_a_reopened_preparation",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIR, &dir)
        .env(CHILD_BINDING, &saved)
        .env(CHILD_STAGING, staging.path())
        .env(CHILD_SIGNATURE, to_hex(&signed.signature))
        .env(CHILD_KEY, to_hex(&case.key.public()))
        .env(CHILD_OUTPUT, &output)
        .output()
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(result.status.success(), "child failed: {stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert!(stdout.contains("child finalized"), "{stdout}");

    let published = std::fs::read(&output).expect("the child published");
    assert_eq!(published, case.bytes(&signed));
    verify(
        &published,
        &case.key.trust(),
        &request(),
        TargetArch::X86_64,
    )
    .expect("the child's output verifies");
    assert!(staging.entries().is_empty(), "{:?}", staging.entries());
}

/// The child half of the cross-process round trip; returns at once unless
/// the parent passed its values.
#[test]
fn child_finalizes_a_reopened_preparation() {
    let (Ok(dir), Ok(binding), Ok(staging), Ok(signature), Ok(key), Ok(output)) = (
        std::env::var(CHILD_DIR),
        std::env::var(CHILD_BINDING),
        std::env::var(CHILD_STAGING),
        std::env::var(CHILD_SIGNATURE),
        std::env::var(CHILD_KEY),
        std::env::var(CHILD_OUTPUT),
    ) else {
        return;
    };
    let binding = PreparationBinding::from_record_bytes(binding.as_bytes()).expect("parses");
    let key: [u8; 32] = from_hex(&key).try_into().expect("a 32-byte key");
    let signed = Signed {
        signature: from_hex(&signature),
        key_id: key_id(&key),
    };
    let trust = trust(vec![TrustAnchor::new(key, false)]);
    let limits = ContentLimits::default();
    let reopened = reopen_prepared(
        Path::new(&dir),
        &binding,
        &request(),
        TargetArch::X86_64,
        &limits,
        Path::new(&staging),
    )
    .expect("the child reopens");
    let finalized = finalize_package(
        &reopened,
        &binding,
        &signed,
        &trust,
        &request(),
        TargetArch::X86_64,
        &limits,
        Path::new(&staging),
    )
    .expect("the child finalizes");
    finalized
        .publish(Path::new(&output))
        .expect("the child publishes");
    println!("child finalized");
}

fn to_hex(bytes: &[u8]) -> String {
    crate::payload::to_hex(bytes)
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// Budget accounting
// ---------------------------------------------------------------------------

/// The `RetainedDisk` a finalization of `case` needs: the prepared archive
/// plus the finalization scope's own high-water mark.
fn requirement(case: &Case) -> (u64, u64) {
    let finalized = case.finalize().expect("finalizes");
    let high = finalized.contents().scope_for_test().budget_high_water();
    (case.package().retained_disk_bytes(), high)
}

#[test]
fn retained_disk_counts_the_prepared_archive() {
    let case = Case::of(&six_images(TargetArch::X86_64));
    let (prepared, high) = requirement(&case);
    let need = prepared + high;
    let bytes = case.bytes(&case.signed()).len() as u64;
    assert!(high >= bytes, "the container alone is charged");

    let at = limits(LimitResource::RetainedDisk, need);
    let finalized = finalize(
        case.package(),
        &case.signed(),
        &case.key.trust(),
        &at,
        &case.staging,
    )
    .expect("the combined requirement fits");
    assert_eq!(
        finalized.contents().scope_for_test().budget().limit(),
        high,
        "the finalization scope gets what the prepared archive leaves"
    );
    drop(finalized);

    // One byte less refuses, although the finalization alone would fit.
    let below = limits(LimitResource::RetainedDisk, need - 1);
    assert!(high < need);
    let error = case.refused(finalize(
        case.package(),
        &case.signed(),
        &case.key.trust(),
        &below,
        &case.staging,
    ));
    assert_eq!(
        limit_of(&error),
        (LimitResource::RetainedDisk, need - 1),
        "the configured limit is reported"
    );
}

#[test]
fn a_limit_below_the_prepared_archive_is_refused_before_anything_is_created() {
    let case = Case::new();
    let prepared = case.package().retained_disk_bytes();
    let below = limits(LimitResource::RetainedDisk, prepared - 1);
    let _seam = fault::install(Seam::new());
    let result = finalize(
        case.package(),
        &case.signed(),
        &case.key.trust(),
        &below,
        &case.staging,
    );
    assert!(
        scope_steps(&fault::record()).is_empty(),
        "no scope, snapshot or write: {:?}",
        fault::record()
    );
    let error = case.refused(result);
    assert_eq!(
        limit_of(&error),
        (LimitResource::RetainedDisk, prepared - 1)
    );
}

#[test]
fn a_limit_with_no_room_for_the_publication_copy_fails_publish_on_the_budget() {
    let case = Case::new();
    let (prepared, high) = requirement(&case);
    let need = prepared + high;
    let finalized = finalize(
        case.package(),
        &case.signed(),
        &case.key.trust(),
        &limits(LimitResource::RetainedDisk, need),
        &case.staging,
    )
    .expect("finalizes at its requirement");
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    match finalized.publish(&destination) {
        Err(PublicationError::DiskBudgetExceeded { limit }) => assert_eq!(limit, need),
        other => panic!("expected the budget, got {other:?}"),
    }
    assert!(out.entries().is_empty(), "{:?}", out.entries());

    // With room, the same package publishes.
    let roomy = case.finalize().expect("finalizes");
    roomy.publish(&destination).expect("publishes");
}

// ---------------------------------------------------------------------------
// Binding and framing faults
// ---------------------------------------------------------------------------

/// `binding` with `key` set to `value` in its record.
fn edited(binding: &PreparationBinding, key: &str, value: Value) -> PreparationBinding {
    let mut record: Value = serde_json::from_slice(&binding.to_record_bytes()).expect("json");
    record[key] = value;
    let mut bytes = serde_json::to_vec(&record).expect("json");
    bytes.push(b'\n');
    PreparationBinding::from_record_bytes(&bytes).expect("an edited binding")
}

#[test]
fn a_wrong_expected_binding_names_its_first_differing_field() {
    let case = Case::new();
    let binding = case.package().binding();
    let other_digest = json!(format!("sha256:{}", "0".repeat(64)));
    let wrong = [
        (
            BindingField::Schema,
            binding.clone().with_schema_for_test(2),
        ),
        (
            BindingField::ManifestSha256,
            edited(binding, "manifest_sha256", other_digest.clone()),
        ),
        (
            BindingField::ManifestLength,
            edited(
                binding,
                "manifest_length",
                json!(binding.manifest_length() + 1),
            ),
        ),
        (
            BindingField::ArchiveSha256,
            edited(binding, "archive_sha256", other_digest),
        ),
        (
            BindingField::ArchiveLength,
            edited(
                binding,
                "archive_length",
                json!(binding.archive_length() + 1),
            ),
        ),
        (
            BindingField::Target,
            edited(binding, "target", json!("other-app")),
        ),
        (
            BindingField::Version,
            edited(binding, "version", json!("2.0.0")),
        ),
        (
            BindingField::Commit,
            edited(binding, "commit", json!("2".repeat(40))),
        ),
        (
            BindingField::TargetArch,
            edited(binding, "target_arch", json!("aarch64")),
        ),
        (
            BindingField::Namespace,
            edited(binding, "namespace", json!("other-product")),
        ),
        (
            BindingField::TrustEpoch,
            edited(binding, "trust_epoch", json!(7)),
        ),
    ];
    for (field, expected) in wrong {
        let error = case.refused(finalize_package(
            case.package(),
            &expected,
            &case.signed(),
            &case.key.trust(),
            &request(),
            TargetArch::X86_64,
            &ContentLimits::default(),
            case.staging.path(),
        ));
        assert_eq!(mismatch_of(&error), field);
    }

    // Two differences: the earlier field wins.
    let both = edited(
        &edited(binding, "commit", json!("2".repeat(40))),
        "archive_length",
        json!(binding.archive_length() + 1),
    );
    let error = case.refused(finalize_package(
        case.package(),
        &both,
        &case.signed(),
        &case.key.trust(),
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        case.staging.path(),
    ));
    assert_eq!(mismatch_of(&error), BindingField::ArchiveLength);
}

#[test]
fn a_request_or_architecture_other_than_the_binding_is_a_mismatch() {
    let case = Case::new();
    let other_commit =
        VerifyRequest::for_namespaced_package(COMPONENT, VERSION, &"2".repeat(40), NAMESPACE)
            .expect("a request");
    let other_namespace =
        VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, "other-product")
            .expect("a request");
    for (request, arch, field) in [
        (&other_commit, TargetArch::X86_64, BindingField::Commit),
        (
            &other_namespace,
            TargetArch::X86_64,
            BindingField::Namespace,
        ),
        (&request(), TargetArch::Aarch64, BindingField::TargetArch),
    ] {
        let error = case.refused(finalize_package(
            case.package(),
            case.package().binding(),
            &case.signed(),
            &case.key.trust(),
            request,
            arch,
            &ContentLimits::default(),
            case.staging.path(),
        ));
        assert_eq!(mismatch_of(&error), field);
    }
}

#[test]
fn a_preparation_of_other_inputs_does_not_match_the_original_binding() {
    let case = Case::new();
    let other = prepare(
        &[Art::native("bin/tool", b"\x7fELF other tool")],
        &ContentLimits::default(),
    )
    .ok();
    let signed = case.key.sign(other.package.manifest_bytes());
    let error = case.refused(finalize_package(
        &other.package,
        case.package().binding(),
        &signed,
        &case.key.trust(),
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        case.staging.path(),
    ));
    assert_eq!(mismatch_of(&error), BindingField::ManifestSha256);
}

/// A prepared package holding `manifest` and `archive` in place of what was
/// prepared, under the original binding: the constructor seam a changed M or
/// A needs, since retained bytes cannot be changed in place.
fn tampered(
    case: &Case,
    manifest: Vec<u8>,
    archive: Option<Vec<u8>>,
    staging: &Dir,
) -> PreparedPackage {
    let limits = ContentLimits::default();
    let scope = new_scope(&limits, staging.path()).expect("a scope");
    let archive = match archive {
        Some(bytes) => scope
            .snapshot_from(&mut bytes.as_slice(), u64::MAX)
            .expect("a snapshot"),
        None => case.package().archive().share(),
    };
    PreparedPackage::new(
        Arc::from(manifest),
        archive,
        case.package().binding().clone(),
        limits,
        scope,
    )
}

#[test]
fn a_changed_manifest_is_caught_by_the_rehash() {
    let case = Case::new();
    let manifest = case.package().manifest_bytes().to_vec();
    let mut whitespace = manifest.clone();
    whitespace.push(b'\n');
    let mut flipped = manifest.clone();
    let last = flipped.len() - 2;
    flipped[last] ^= 0x01;
    for changed in [whitespace, flipped] {
        let side = Dir::new();
        let package = tampered(&case, changed.clone(), None, &side);
        let error = case.refused(finalize_package(
            &package,
            case.package().binding(),
            &case.key.sign(&changed),
            &case.key.trust(),
            &request(),
            TargetArch::X86_64,
            &ContentLimits::default(),
            case.staging.path(),
        ));
        assert_eq!(mismatch_of(&error), BindingField::ManifestSha256);
    }
}

#[test]
fn a_same_length_archive_substitution_is_caught_by_the_rehash() {
    let case = Case::new();
    let mut archive = read_all(case.package().archive());
    let middle = archive.len() / 2;
    archive[middle] ^= 0x01;
    let side = Dir::new();
    let package = tampered(
        &case,
        case.package().manifest_bytes().to_vec(),
        Some(archive),
        &side,
    );
    assert_eq!(
        package.archive().len(),
        case.package().binding().archive_length()
    );
    let error = case.refused(finalize_package(
        &package,
        case.package().binding(),
        &case.signed(),
        &case.key.trust(),
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        case.staging.path(),
    ));
    assert_eq!(mismatch_of(&error), BindingField::ArchiveSha256);
}

#[test]
fn malformed_signature_framing_is_refused_before_any_scope_exists() {
    let case = Case::new();
    let manifest = case.package().manifest_bytes();
    let mut short = case.signed();
    short.signature.pop();
    let mut uppercase = case.signed();
    uppercase.key_id = uppercase.key_id.to_uppercase();
    for signed in [short, uppercase] {
        let expected = crate::payload::validate_signed(&signed).expect_err("malformed");
        let seam = fault::install(Seam::new());
        let result = finalize(
            case.package(),
            &signed,
            &case.key.trust(),
            &ContentLimits::default(),
            &case.staging,
        );
        assert!(
            scope_steps(&fault::record()).is_empty(),
            "no scope was created: {:?}",
            fault::record()
        );
        drop(seam);
        let error = case.refused(result);
        match &error {
            PackageWriteError::Payload(actual) => {
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
            }
            other => panic!("expected a framing refusal, got {other:?}"),
        }
    }
    assert_eq!(manifest, case.package().manifest_bytes());
}

// ---------------------------------------------------------------------------
// Assembly failures
// ---------------------------------------------------------------------------

#[test]
fn a_full_filesystem_while_assembling_leaves_nothing() {
    let case = Case::new();
    let seam = fault::install(Seam::new().fail_nth(Step::WriteSnapshot, 1, ErrorKind::StorageFull));
    let result = case.finalize();
    drop(seam);
    let error = case.refused(result);
    match &error {
        PackageWriteError::Content(ContentError::Io {
            operation: IoOperation::WriteSnapshot,
            source,
            ..
        }) => assert_eq!(source.kind(), ErrorKind::StorageFull),
        other => panic!("expected a snapshot write failure, got {other:?}"),
    }
}

#[test]
fn a_package_limit_the_tail_would_cross_is_refused() {
    let case = Case::new();
    let blocks =
        case.package().binding().manifest_length() + case.package().binding().archive_length();
    let container = blocks + 128 + FOOTER_SIZE as u64;
    // M and A fit, and the signature, key ID and footer cross.
    let tight = limits(LimitResource::Package, blocks + 100);
    let error = case.refused(finalize(
        case.package(),
        &case.signed(),
        &case.key.trust(),
        &tight,
        &case.staging,
    ));
    assert_eq!(limit_of(&error), (LimitResource::Package, blocks + 100));

    // Exactly the container's length fits.
    let exact = limits(LimitResource::Package, container);
    finalize(
        case.package(),
        &case.signed(),
        &case.key.trust(),
        &exact,
        &case.staging,
    )
    .expect("the container fits exactly");
}

// ---------------------------------------------------------------------------
// Verification verdicts
// ---------------------------------------------------------------------------

/// Finalizes with `signed` under `trust` and holds the verdict to what
/// `verify_package` decides for the same bytes.
fn same_verdict_as_verify_package(case: &Case, signed: &Signed, trust: &TrustSet) -> VerifyError {
    let error = case.refused(finalize(
        case.package(),
        signed,
        trust,
        &ContentLimits::default(),
        &case.staging,
    ));
    let verdict = verdict_of(&error);
    let legacy = verify_package(Cursor::new(case.bytes(signed)), trust, &request())
        .expect_err("verify_package refuses the same bytes");
    assert_eq!(format!("{verdict:?}"), format!("{legacy:?}"));
    legacy
}

#[test]
fn a_signature_over_anything_but_raw_m_is_a_bad_signature() {
    let case = Case::new();
    let manifest = case.package().manifest_bytes();
    let digest: [u8; 32] = Sha256::digest(manifest).into();
    let parsed = PayloadManifest::parse(manifest, FORMAT_VERSION).expect("M parses");
    let reserialized = serde_json::to_vec_pretty(&parsed).expect("serializes");
    assert_ne!(reserialized, manifest);
    for message in [&digest[..], &reserialized[..]] {
        let verdict =
            same_verdict_as_verify_package(&case, &case.key.sign(message), &case.key.trust());
        assert!(matches!(verdict, VerifyError::BadSignature), "{verdict:?}");
    }
}

#[test]
fn a_key_outside_the_trust_is_refused_as_verify_package_refuses_it() {
    let case = Case::new();
    let stranger = Key::new();
    let verdict = same_verdict_as_verify_package(&case, &case.signed(), &stranger.trust());
    assert!(
        matches!(verdict, VerifyError::UnknownKeyId { .. }),
        "{verdict:?}"
    );
}

#[test]
fn a_revoked_key_is_refused() {
    let case = Case::new();
    let verdict =
        same_verdict_as_verify_package(&case, &case.signed(), &trust(vec![case.key.anchor(true)]));
    assert!(
        matches!(verdict, VerifyError::RevokedKey { .. }),
        "{verdict:?}"
    );
}

#[test]
fn a_withdrawn_build_is_refused() {
    let case = Case::new();
    let trust = TrustSet::new(
        vec![case.key.anchor(false)],
        vec![(
            COMPONENT.to_string(),
            VERSION.to_string(),
            COMMIT.to_string(),
        )],
        0,
        0,
    )
    .expect("a trust set");
    let verdict = same_verdict_as_verify_package(&case, &case.signed(), &trust);
    assert!(
        matches!(verdict, VerifyError::WithdrawnBuild { .. }),
        "{verdict:?}"
    );
}

#[test]
fn a_trust_floor_above_the_format_is_refused() {
    let case = Case::new();
    let trust = TrustSet::new(vec![case.key.anchor(false)], Vec::new(), 7, 0).expect("trust");
    let verdict = same_verdict_as_verify_package(&case, &case.signed(), &trust);
    assert!(
        matches!(
            verdict,
            VerifyError::UnsupportedManifestFormat {
                found: 6,
                min: 7,
                ..
            }
        ),
        "{verdict:?}"
    );
}

fn trust_art() -> Art {
    let mut art = Art::native("trust-set.json", b"{}");
    art.kind = ArtifactKind::StaticAssets;
    art.component = TRUST_TARGET.to_string();
    art.version = "8".to_string();
    art
}

#[test]
fn a_trust_package_finalizes_only_past_the_active_epoch() {
    let trust_request = VerifyRequest::for_trust("8", COMMIT, 5).expect("a trust request");
    let ready = prepare_with(
        &[trust_art()],
        &trust_request,
        TargetArch::X86_64,
        &ContentLimits::default(),
    )
    .ok();
    let key = Key::new();
    let signed = key.sign(ready.package.manifest_bytes());
    let staging = Dir::new();
    let at = |epoch| {
        let trust = TrustSet::new(vec![key.anchor(false)], Vec::new(), 0, epoch).expect("trust");
        finalize_package(
            &ready.package,
            ready.package.binding(),
            &signed,
            &trust,
            &trust_request,
            TargetArch::X86_64,
            &ContentLimits::default(),
            staging.path(),
        )
    };
    let error = at(5).expect_err("a stale epoch is refused");
    assert!(
        matches!(
            verdict_of(&error),
            VerifyError::StaleTrustSet {
                delivered: 5,
                active: 5
            }
        ),
        "{error:?}"
    );
    assert!(staging.entries().is_empty());
    let finalized = at(4).expect("an advancing epoch finalizes");
    assert_eq!(finalized.binding().trust_epoch(), Some(5));
}

// ---------------------------------------------------------------------------
// Late failures
// ---------------------------------------------------------------------------

/// Finalizes with a corruption arranged after assembly and holds the verdict
/// to what `verify_contents` gives the same damaged bytes.
fn late(case: &Case, corrupt: impl FnOnce(&mut Vec<u8>) + 'static) -> PackageWriteError {
    let damaged = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&damaged);
    let guard = seam::corrupt(move |bytes| {
        corrupt(bytes);
        seen.borrow_mut().clone_from(bytes);
    });
    let result = case.finalize();
    drop(guard);
    let error = case.refused(result);
    let damaged = damaged.borrow().clone();
    assert!(!damaged.is_empty(), "the corruption ran");
    let direct = verify(&damaged, &case.key.trust(), &request(), TargetArch::X86_64)
        .expect_err("the damaged bytes are refused");
    match &error {
        PackageWriteError::Content(actual) => {
            assert_eq!(format!("{actual:?}"), format!("{direct:?}"));
        }
        other => panic!("expected a content error, got {other:?}"),
    }
    error
}

#[test]
fn framing_damaged_after_assembly_is_a_content_error() {
    let case = Case::new();
    let error = late(&case, |bytes| {
        // The footer's archive length, one too long.
        let at = bytes.len() - FOOTER_SIZE + MAGIC.len() + 1 + 3 * 8;
        let field = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) + 1;
        bytes[at..at + 8].copy_from_slice(&field.to_le_bytes());
    });
    assert!(
        matches!(
            error,
            PackageWriteError::Content(ContentError::Verify(VerifyError::Payload(_)))
        ),
        "{error:?}"
    );
}

#[test]
fn the_last_image_damaged_after_assembly_is_a_content_error() {
    let arts = six_images(TargetArch::X86_64);
    let last_image = arts
        .iter()
        .rev()
        .find(|art| art.kind == ArtifactKind::ContainerImage)
        .expect("an image")
        .path
        .clone();
    let case = Case::of(&arts);
    let manifest_len = usize::try_from(case.package().binding().manifest_length()).unwrap();
    let archive_len = usize::try_from(case.package().binding().archive_length()).unwrap();
    let signed = case.signed();
    let target = last_image.clone();
    let error = late(&case, move |bytes| {
        let manifest = bytes[..manifest_len].to_vec();
        let archive = &bytes[manifest_len..manifest_len + archive_len];
        let mut tar = zstd::decode_all(archive).expect("A decodes");
        let mut offset = None;
        let mut walker = tar::Archive::new(Cursor::new(tar.clone()));
        for entry in walker.entries().expect("entries") {
            let entry = entry.expect("an entry");
            if entry.path().expect("a path").to_str() == Some(target.as_str()) {
                offset = Some(entry.raw_file_position() + entry.size() / 2);
            }
        }
        let offset = usize::try_from(offset.expect("the last image")).unwrap();
        tar[offset] ^= 0xff;
        let archive = zstd::encode_all(&tar[..], 3).expect("A recompresses");
        *bytes = assemble_bytes(&manifest, &archive, &signed);
    });
    assert!(
        format!("{error:?}").contains(&last_image),
        "the last image is named: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Key-hint compatibility
// ---------------------------------------------------------------------------

#[test]
fn the_key_hint_selects_and_never_denies_exactly_as_verify_package() {
    let case = Case::new();
    let a = Key::new();
    let b = Key::new();
    let signed = b.sign_as(case.package().manifest_bytes(), &a.id());
    let bytes = case.bytes(&signed);

    for (anchors, accepted) in [
        (vec![a.anchor(false), b.anchor(false)], true),
        (vec![a.anchor(false)], false),
        (vec![b.anchor(false)], true),
    ] {
        let trust = trust(anchors);
        let legacy = verify_package(Cursor::new(&bytes), &trust, &request());
        let result = finalize(
            case.package(),
            &signed,
            &trust,
            &ContentLimits::default(),
            &case.staging,
        );
        assert_eq!(legacy.is_ok(), accepted);
        if accepted {
            let finalized = result.expect("finalizes as verify_package accepts");
            assert_eq!(read_all(finalized.bytes()), bytes);
        } else {
            let error = case.refused(result);
            let Err(legacy) = legacy else {
                panic!("verify_package refuses too");
            };
            assert_eq!(format!("{:?}", verdict_of(&error)), format!("{legacy:?}"));
        }
    }
}

// ---------------------------------------------------------------------------
// prepare_sign_finalize
// ---------------------------------------------------------------------------

#[test]
fn the_composition_is_byte_identical_to_its_three_steps() {
    let case = Case::of(&six_images(TargetArch::X86_64));
    let three = case.finalize().expect("finalizes");

    let seen = RefCell::new(Vec::new());
    let staging = Dir::new();
    let one = prepare_sign_finalize(
        &case.ready.inputs,
        None,
        None,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging.path(),
        &case.key.trust(),
        |manifest| {
            seen.borrow_mut().extend_from_slice(manifest);
            Ok(case.key.sign(manifest))
        },
    )
    .expect("the composition finalizes");
    assert_eq!(&seen.borrow()[..], case.package().manifest_bytes());
    assert_eq!(read_all(one.bytes()), read_all(three.bytes()));
    assert_eq!(one.binding(), three.binding());
    // Only the finalization's own scope is left; the preparation's is gone.
    assert_eq!(staging.entries().len(), 1, "{:?}", staging.entries());
    drop(one);
    assert!(staging.entries().is_empty());
}

#[test]
fn a_signer_error_is_reported_as_the_signer() {
    let case = Case::new();
    let staging = Dir::new();
    let error = prepare_sign_finalize(
        &case.ready.inputs,
        None,
        None,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging.path(),
        &case.key.trust(),
        |_| {
            Err(SignerError::new(std::io::Error::other(
                "the signer declined",
            )))
        },
    )
    .expect_err("the signer failed");
    match &error {
        PackageWriteError::Signer(inner) => {
            assert_eq!(inner.to_string(), "the signer declined");
        }
        other => panic!("expected the signer, got {other:?}"),
    }
    assert!(staging.entries().is_empty());
}

#[test]
fn a_preparation_refusal_surfaces_unchanged_and_never_signs() {
    let case = Case::new();
    let wrong = VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, "other-product")
        .expect("a request");
    let staging = Dir::new();
    let expected = prepare_package(
        &case.ready.inputs,
        None,
        None,
        &wrong,
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging.path(),
    )
    .expect_err("preparation refuses another namespace");
    let invoked = Cell::new(false);
    let error = prepare_sign_finalize(
        &case.ready.inputs,
        None,
        None,
        &wrong,
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging.path(),
        &case.key.trust(),
        |manifest| {
            invoked.set(true);
            Ok(case.key.sign(manifest))
        },
    )
    .expect_err("the composition refuses too");
    assert!(!invoked.get(), "the callback never ran");
    assert_eq!(format!("{error:?}"), format!("{expected:?}"));
    assert!(staging.entries().is_empty());
}

#[test]
fn a_finalization_refusal_surfaces_unchanged() {
    let case = Case::new();
    let staging = Dir::new();
    let stranger = Key::new();
    let error = prepare_sign_finalize(
        &case.ready.inputs,
        None,
        None,
        &request(),
        TargetArch::X86_64,
        &ContentLimits::default(),
        staging.path(),
        &stranger.trust(),
        |manifest| Ok(case.key.sign(manifest)),
    )
    .expect_err("an untrusted key is refused");
    assert!(
        matches!(verdict_of(&error), VerifyError::UnknownKeyId { .. }),
        "{error:?}"
    );
    assert!(staging.entries().is_empty());
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

#[test]
fn publish_writes_exactly_the_bytes_with_a_matching_receipt() {
    let case = Case::new();
    let finalized = case.finalize().expect("finalizes");
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    let receipt = finalized.publish(&destination).expect("publishes");
    let bytes = read_all(finalized.bytes());
    assert_eq!(std::fs::read(&destination).expect("read"), bytes);
    assert_eq!(receipt.destination(), destination);
    assert_eq!(receipt.len(), bytes.len() as u64);
    assert_eq!(receipt.sha256(), finalized.bytes().sha256());
    assert_eq!(out.entries(), ["package.pkg"]);

    // A later direct read sees the same bytes.
    assert_eq!(read_all(finalized.contents().package_bytes()), bytes);
}

#[test]
fn publish_never_clobbers_an_existing_destination() {
    let case = Case::new();
    let finalized = case.finalize().expect("finalizes");
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    std::fs::write(&destination, b"already here").expect("written");
    match finalized.publish(&destination) {
        Err(PublicationError::DestinationExists { destination: named }) => {
            assert_eq!(named, destination);
        }
        other => panic!("expected an existing destination, got {other:?}"),
    }
    assert_eq!(std::fs::read(&destination).expect("read"), b"already here");
}

#[test]
fn a_failure_before_the_link_leaves_neither_destination_nor_temporary() {
    let case = Case::new();
    let finalized = case.finalize().expect("finalizes");
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    let seam = fault::install(Seam::new().fail(Step::SyncFile, ErrorKind::Other));
    let result = finalized.publish(&destination);
    drop(seam);
    match result {
        Err(PublicationError::Io {
            operation: PublicationOperation::SyncFile,
            ..
        }) => {}
        other => panic!("expected the sync failure, got {other:?}"),
    }
    assert!(out.entries().is_empty(), "{:?}", out.entries());
}

#[test]
fn a_failure_after_the_link_is_publish_durability() {
    let case = Case::new();
    let finalized = case.finalize().expect("finalizes");
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    let seam = fault::install(Seam::new().fail(Step::SyncParent, ErrorKind::Other));
    let result = finalized.publish(&destination);
    drop(seam);
    match result {
        Err(PublicationError::PublishDurability {
            destination: named, ..
        }) => assert_eq!(named, destination),
        other => panic!("expected publish durability, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(&destination).expect("the output is present"),
        read_all(finalized.bytes())
    );
}

#[test]
fn changing_the_published_file_changes_nothing_retained() {
    let case = Case::new();
    let finalized = case.finalize().expect("finalizes");
    let original = read_all(finalized.bytes());
    let out = Dir::new();
    let destination = out.path().join("package.pkg");
    finalized.publish(&destination).expect("publishes");
    std::fs::write(&destination, b"replaced").expect("the published file is mutable");
    assert_eq!(read_all(finalized.bytes()), original);
    let mut fresh = Vec::new();
    finalized
        .contents()
        .package_bytes()
        .reader()
        .read_to_end(&mut fresh)
        .expect("reads");
    assert_eq!(fresh, original);
}
