//! Golden checks that the legacy writers keep their exact output.
//!
//! [`reference_append`] is a frozen copy of the writer as it stood before its
//! manifest derivation and archive layout were split into shared helpers.
//! `Cargo.lock` is not checked in, so a recorded digest of zstd output would
//! move with whichever zstd a build resolves; a frozen implementation built
//! against the same zstd records the pre-refactor bytes without that drift. Every combination of base, pinset, trust set and
//! signing is compared byte for byte, including sources whose length changes
//! between the hash pass and the archive pass.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use tar::{Builder, EntryType, Header};
use zstd::Encoder;

use super::{
    ArtifactInput, CountingWriter, ED25519_SIGNATURE_LEN, FOOTER_SIZE, FORMAT_VERSION, Footer,
    KEY_ID_HEX_LEN, MAGIC, PayloadError, Signed, SignerError, ZSTD_LEVEL, append_trailer,
    append_trailer_signed, hash_copy, rewrap_trailer, validate_signed,
};
use crate::image::{
    ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner, ImagePlatform, ImageProvenance,
    ProductBuildProvenance, ReferenceLifecycle,
};
use crate::manifest::PayloadManifest;
use crate::manifest::{ArchiveMember, ArtifactKind, Disposition, PayloadArtifact, TargetArch};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const BASE: &[u8] = b"#!/bin/false\na base executable\n";
const PINSET: &str =
    "bootler.pinset.v1:sha256:0000000000000000000000000000000000000000000000000000000000000000";
const GENERATION: &[u8] = b"an opaque signed generation container";
/// A fixed test seed, so a signed output is reproducible across runs.
const SEED: [u8; 32] = [7; 32];

type Hook = Box<dyn FnMut()>;

thread_local! {
    static BETWEEN_PASSES: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

/// Runs the hook a test arranged between the writer's hash pass and its
/// archive pass, once.
pub(super) fn between_passes() {
    let hook = BETWEEN_PASSES.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = hook {
        hook();
    }
}

fn arrange_between_passes(hook: impl FnMut() + 'static) {
    BETWEEN_PASSES.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// The writer exactly as it was before the shared helpers existed.
fn reference_append<B: Read, W: Write, F>(
    mut base: B,
    mut out: W,
    pinset: Option<&str>,
    trust_set: Option<&[u8]>,
    inputs: &[ArtifactInput],
    sign: F,
) -> Result<(), PayloadError>
where
    F: FnOnce(&[u8]) -> Result<Option<Signed>, SignerError>,
{
    let mut archive_members = Vec::with_capacity(inputs.len());
    let mut artifacts = Vec::with_capacity(inputs.len());
    for input in inputs {
        let source = std::fs::File::open(&input.source)?;
        let (sha256, length) = hash_copy(source, std::io::sink())?;
        archive_members.push(ArchiveMember {
            name: input.archive_path.clone(),
            length,
        });
        artifacts.push(PayloadArtifact {
            component: input.component.clone(),
            version: input.version.clone(),
            commit: Some(input.commit.clone()),
            target_arch: input.target_arch,
            kind: input.kind,
            dispositions: input.dispositions.clone(),
            archive_path: input.archive_path.clone(),
            sha256,
            spec: input.spec.clone(),
            image: input.image.clone(),
        });
    }
    between_passes();
    let member_lengths: Vec<u64> = archive_members.iter().map(|member| member.length).collect();
    let manifest = PayloadManifest::new(pinset.map(str::to_string), archive_members, artifacts)?;
    let manifest = match trust_set {
        Some(generation) => manifest.with_trust_set(generation)?,
        None => manifest,
    };
    let manifest_json = serde_json::to_vec(&manifest).map_err(PayloadError::ManifestSerialize)?;
    let signed = sign(&manifest_json).map_err(PayloadError::Signer)?;
    if let Some(signed) = signed.as_ref() {
        validate_signed(signed)?;
    }

    let manifest_offset = std::io::copy(&mut base, &mut out)?;
    out.write_all(&manifest_json)?;
    let manifest_len = manifest_json.len() as u64;
    let archive_offset = manifest_offset + manifest_len;

    let archive_len = {
        let mut counter = CountingWriter::new(&mut out);
        let encoder = Encoder::new(&mut counter, ZSTD_LEVEL)?;
        let mut builder = Builder::new(encoder);
        for (input, length) in inputs.iter().zip(member_lengths) {
            let source = std::fs::File::open(&input.source)?;
            let mut header = Header::new_gnu();
            header
                .set_path(&input.archive_path)
                .map_err(|_| PayloadError::ArchivePathTooLong {
                    path: input.archive_path.clone(),
                    len: input.archive_path.len(),
                })?;
            header.set_size(length);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder.append(&header, source)?;
        }
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        counter.count()
    };

    let (signature_offset, signature_len, key_id_offset, key_id_len) = match signed {
        Some(signed) => {
            let signature_len = ED25519_SIGNATURE_LEN as u64;
            let key_id_len = KEY_ID_HEX_LEN as u64;
            let signature_offset = archive_offset + archive_len;
            out.write_all(&signed.signature)?;
            let key_id_offset = signature_offset + signature_len;
            out.write_all(signed.key_id.as_bytes())?;
            (signature_offset, signature_len, key_id_offset, key_id_len)
        }
        None => (0, 0, 0, 0),
    };
    let footer = Footer {
        version: FORMAT_VERSION,
        manifest_offset,
        manifest_len,
        archive_offset,
        archive_len,
        signature_offset,
        signature_len,
        key_id_offset,
        key_id_len,
    };
    out.write_all(&footer.encode())?;
    Ok(())
}

fn declaration() -> ImageDeclaration {
    ImageDeclaration {
        schema: 1,
        owner: ImageOwner {
            namespace: "example-product".to_string(),
            component: "example".to_string(),
        },
        dependency: "web".to_string(),
        public_refs: vec!["ghcr.io/example/example:1.0.0".to_string()],
        platform: ImagePlatform {
            os: ImageOs::Linux,
            architecture: ImageArchitecture::Amd64,
            variant: None,
        },
        config_digest: format!("sha256:{}", "c".repeat(64)),
        reference_lifecycle: ReferenceLifecycle::SharedExternal,
        provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
            repository: "example".to_string(),
            commit: COMMIT.to_string(),
        }),
    }
}

fn input(dir: &Path, archive_path: &str, kind: ArtifactKind, bytes: &[u8]) -> ArtifactInput {
    let source = dir.join(archive_path.replace('/', "_"));
    std::fs::write(&source, bytes).expect("the source is written");
    ArtifactInput {
        component: "example".to_string(),
        version: "1.0.0".to_string(),
        commit: COMMIT.to_string(),
        target_arch: TargetArch::X86_64,
        kind,
        dispositions: BTreeSet::from([Disposition::Install]),
        archive_path: archive_path.to_string(),
        spec: None,
        image: (kind == ArtifactKind::ContainerImage).then(declaration),
        source,
    }
}

/// Several artifacts, a declared image among them.
fn inputs(dir: &Path) -> Vec<ArtifactInput> {
    let large: Vec<u8> = (0..200_000u32)
        .map(|n| u8::try_from(n % 251).expect("below 251"))
        .collect();
    vec![
        input(
            dir,
            "bin/agent",
            ArtifactKind::NativeBinary,
            b"\x7fELF agent",
        ),
        input(dir, "images/web.tar", ArtifactKind::ContainerImage, &large),
        input(
            dir,
            "compose.yaml",
            ArtifactKind::ComposeBundle,
            b"services: {}\n",
        ),
        input(dir, "empty.bin", ArtifactKind::StaticAssets, b""),
    ]
}

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&SEED).expect("a fixed test seed")
}

fn stamp(pair: &Ed25519KeyPair, manifest: &[u8]) -> Signed {
    Signed {
        signature: pair.sign(manifest).as_ref().to_vec(),
        key_id: crate::verify::key_id(
            pair.public_key()
                .as_ref()
                .try_into()
                .expect("a 32-byte public key"),
        ),
    }
}

struct Case {
    base: &'static [u8],
    pinset: Option<&'static str>,
    trust_set: Option<&'static [u8]>,
    signed: bool,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for base in [&b""[..], BASE] {
        for pinset in [None, Some(PINSET)] {
            for trust_set in [None, Some(GENERATION)] {
                for signed in [false, true] {
                    out.push(Case {
                        base,
                        pinset,
                        trust_set,
                        signed,
                    });
                }
            }
        }
    }
    out
}

fn live(case: &Case, inputs: &[ArtifactInput]) -> Result<Vec<u8>, PayloadError> {
    let mut out = Vec::new();
    live_into(case, inputs, &mut out)?;
    Ok(out)
}

fn live_into<W: Write>(case: &Case, inputs: &[ArtifactInput], out: W) -> Result<(), PayloadError> {
    if case.signed {
        let pair = key();
        append_trailer_signed(
            Cursor::new(case.base),
            out,
            case.pinset,
            case.trust_set,
            inputs,
            |manifest| Ok(stamp(&pair, manifest)),
        )
    } else {
        append_trailer(
            Cursor::new(case.base),
            out,
            case.pinset,
            case.trust_set,
            inputs,
        )
    }
}

fn reference(case: &Case, inputs: &[ArtifactInput]) -> Result<Vec<u8>, PayloadError> {
    let mut out = Vec::new();
    reference_into(case, inputs, &mut out)?;
    Ok(out)
}

fn reference_into<W: Write>(
    case: &Case,
    inputs: &[ArtifactInput],
    out: W,
) -> Result<(), PayloadError> {
    let pair = key();
    reference_append(
        Cursor::new(case.base),
        out,
        case.pinset,
        case.trust_set,
        inputs,
        |manifest| Ok(case.signed.then(|| stamp(&pair, manifest))),
    )
}

#[test]
fn every_writer_combination_matches_the_pre_refactor_bytes() {
    let dir = tempfile::tempdir().expect("a source directory");
    let inputs = inputs(dir.path());
    for case in cases() {
        let expected = reference(&case, &inputs).expect("the reference writes");
        let actual = live(&case, &inputs).expect("the writer writes");
        assert_eq!(
            actual,
            expected,
            "base {} pinset {} trust set {} signed {}",
            case.base.len(),
            case.pinset.is_some(),
            case.trust_set.is_some(),
            case.signed
        );
        let mut again = Vec::new();
        rewrap_trailer(Cursor::new(&actual), Cursor::new(BASE), &mut again)
            .expect("the output rewraps");
        let mut reference_again = Vec::new();
        rewrap_trailer(
            Cursor::new(&expected),
            Cursor::new(BASE),
            &mut reference_again,
        )
        .expect("the reference output rewraps");
        assert_eq!(again, reference_again);
    }
}

#[test]
fn identical_inputs_write_identical_bytes() {
    let dir = tempfile::tempdir().expect("a source directory");
    let inputs = inputs(dir.path());
    for case in cases() {
        assert_eq!(
            live(&case, &inputs).expect("the writer writes"),
            live(&case, &inputs).expect("the writer writes again")
        );
    }
}

#[test]
fn an_overlong_archive_path_is_still_refused() {
    let dir = tempfile::tempdir().expect("a source directory");
    let long = format!("dir/{}", "a".repeat(120));
    let inputs = vec![input(dir.path(), &long, ArtifactKind::NativeBinary, b"x")];
    for case in cases() {
        let live = live(&case, &inputs).expect_err("the writer refuses");
        let reference = reference(&case, &inputs).expect_err("the reference refuses");
        for error in [live, reference] {
            assert!(
                matches!(&error, PayloadError::ArchivePathTooLong { path, len }
                    if *path == long && *len == long.len()),
                "got {error:?}"
            );
        }
    }
}

/// Rewrites the source of `inputs[1]` to `bytes` between the two passes of
/// the next writer call on this thread.
fn change_between_passes(inputs: &[ArtifactInput], bytes: Vec<u8>) {
    let source = inputs[1].source.clone();
    arrange_between_passes(move || std::fs::write(&source, &bytes).expect("rewritten"));
}

#[test]
fn a_source_changing_length_between_passes_writes_what_it_always_did() {
    for delta in [1isize, -1, 4096, -4096] {
        for case in cases() {
            let dir = tempfile::tempdir().expect("a source directory");
            let inputs = inputs(dir.path());
            let original = std::fs::read(&inputs[1].source).expect("read");
            let changed = |len: usize| -> Vec<u8> {
                (0..len)
                    .map(|n| u8::try_from(n % 13).expect("below 13"))
                    .collect()
            };
            let len = original.len().checked_add_signed(delta).expect("a length");

            change_between_passes(&inputs, changed(len));
            let actual = live(&case, &inputs);
            std::fs::write(&inputs[1].source, &original).expect("restored");
            change_between_passes(&inputs, changed(len));
            let expected = reference(&case, &inputs);
            std::fs::write(&inputs[1].source, &original).expect("restored");

            let actual = actual.expect("the legacy writer does not refuse");
            let expected = expected.expect("nor did the pre-refactor one");
            assert_eq!(actual, expected, "delta {delta}");
        }
    }
}

/// The footer's eight fields.
fn footer_fields(bytes: &[u8]) -> [u64; 8] {
    let footer = &bytes[bytes.len() - FOOTER_SIZE..];
    assert_eq!(&footer[..MAGIC.len()], MAGIC);
    assert_eq!(footer[MAGIC.len()], FORMAT_VERSION);
    let mut fields = [0u64; 8];
    for (at, field) in fields.iter_mut().enumerate() {
        let start = MAGIC.len() + 1 + at * 8;
        *field = u64::from_le_bytes(footer[start..start + 8].try_into().expect("8 bytes"));
    }
    fields
}

#[test]
fn a_nonempty_base_puts_the_manifest_after_it() {
    let dir = tempfile::tempdir().expect("a source directory");
    let inputs = inputs(dir.path());
    for case in cases() {
        let output = live(&case, &inputs).expect("the writer writes");
        let [
            manifest_offset,
            manifest_len,
            archive_offset,
            archive_len,
            signature_offset,
            _,
            key_id_offset,
            _,
        ] = footer_fields(&output);
        assert_eq!(manifest_offset, case.base.len() as u64);
        assert_eq!(&output[..case.base.len()], case.base);
        assert_eq!(archive_offset, manifest_offset + manifest_len);
        if case.signed {
            assert_eq!(signature_offset, archive_offset + archive_len);
            assert_eq!(
                key_id_offset,
                signature_offset + ED25519_SIGNATURE_LEN as u64
            );
        } else {
            assert_eq!((signature_offset, key_id_offset), (0, 0));
        }
    }
}

/// A writer that accepts its first `limit` bytes and fails every write after
/// them.
struct FailAfter {
    accepted: Vec<u8>,
    limit: usize,
}

impl FailAfter {
    fn new(limit: u64) -> FailAfter {
        FailAfter {
            accepted: Vec::new(),
            limit: usize::try_from(limit).expect("a small limit"),
        }
    }
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let left = self.limit - self.accepted.len();
        if left == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected write failure",
            ));
        }
        let take = left.min(buf.len());
        self.accepted.extend_from_slice(&buf[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[track_caller]
fn io_kind(error: &PayloadError) -> std::io::ErrorKind {
    match error {
        PayloadError::Io(error) => error.kind(),
        other => panic!("expected an I/O failure, got {other:?}"),
    }
}

#[test]
fn a_writer_failing_partway_keeps_what_it_accepted_as_before() {
    let dir = tempfile::tempdir().expect("a source directory");
    let inputs = inputs(dir.path());
    for case in cases() {
        let full = live(&case, &inputs).expect("the writer writes");
        let [
            _,
            _,
            archive_offset,
            archive_len,
            signature_offset,
            _,
            key_id_offset,
            _,
        ] = footer_fields(&full);
        let footer_start = (full.len() - FOOTER_SIZE) as u64;
        let mut points = vec![archive_offset + archive_len / 2, footer_start + 5];
        if case.signed {
            points.extend([signature_offset + 10, key_id_offset + 10]);
        }
        for point in points {
            let mut live_out = FailAfter::new(point);
            let live_error =
                live_into(&case, &inputs, &mut live_out).expect_err("the writer fails");
            let mut reference_out = FailAfter::new(point);
            let reference_error = reference_into(&case, &inputs, &mut reference_out)
                .expect_err("the reference fails");
            assert_eq!(io_kind(&live_error), io_kind(&reference_error));
            assert_eq!(io_kind(&live_error), std::io::ErrorKind::BrokenPipe);
            let point = usize::try_from(point).expect("small");
            assert_eq!(live_out.accepted, &full[..point], "at {point}");
            assert_eq!(reference_out.accepted, live_out.accepted, "at {point}");
        }
    }
}
