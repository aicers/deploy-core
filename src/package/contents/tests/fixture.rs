//! Signed package fixtures for the full-content verification tests.
//!
//! Every package is signed by a key minted afresh for the test. Image members
//! come from the synthetic builder; the archive block is written here rather
//! than through the payload writer, so a test can break it in ways the writer
//! refuses to.

use std::collections::BTreeSet;
use std::io::Write as _;

use ring::signature::Ed25519KeyPair;
use serde_json::Value;
use tar::{EntryType, Header};

use crate::image::test_support::{LayerCompression, SyntheticImageArchiveBuilder, SyntheticLayer};
use crate::image::{
    IMAGE_DECLARATION_SCHEMA, ImageArchitecture, ImageDeclaration, ImageOs, ImageOwner,
    ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceLifecycle,
};
use crate::manifest::{
    ArchiveMember, ArtifactKind, Disposition, PayloadArtifact, PayloadManifest, TargetArch,
};
use crate::payload::{FORMAT_VERSION, MAGIC, sha256_hex};
use crate::trust_fixture::{keypair, public_key_of};
use crate::verify::{TrustAnchor, TrustSet, VerifyRequest, key_id};

pub(crate) const COMPONENT: &str = "example-app";
pub(crate) const VERSION: &str = "1.0.0";
pub(crate) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const NAMESPACE: &str = "example-product";

/// A key pair and the trust set anchoring it.
pub(crate) struct Signer {
    pair: Ed25519KeyPair,
}

impl Signer {
    pub(crate) fn new() -> Signer {
        Signer { pair: keypair() }
    }

    pub(crate) fn trust(&self) -> TrustSet {
        self.trust_with(Vec::new(), 0)
    }

    pub(crate) fn trust_with(
        &self,
        withdrawn: Vec<(String, String, String)>,
        epoch: u64,
    ) -> TrustSet {
        TrustSet::new(
            vec![TrustAnchor::new(public_key_of(&self.pair), false)],
            withdrawn,
            0,
            epoch,
        )
        .expect("a one-anchor trust set")
    }

    /// Assembles a signed `.pkg` from a raw manifest block and archive block.
    pub(crate) fn container(&self, manifest: &[u8], archive: &[u8]) -> Vec<u8> {
        let signature = self.pair.sign(manifest);
        container(manifest, archive, signature.as_ref(), &self.hint())
    }

    /// Assembles a `.pkg` whose signature verifies under no key.
    pub(crate) fn badly_signed(&self, manifest: &[u8], archive: &[u8]) -> Vec<u8> {
        let mut signature = self.pair.sign(manifest).as_ref().to_vec();
        if let Some(byte) = signature.first_mut() {
            *byte ^= 0xff;
        }
        container(manifest, archive, &signature, &self.hint())
    }

    fn hint(&self) -> String {
        key_id(&public_key_of(&self.pair))
    }
}

fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("a fixture fits in u64")
}

/// The footer of a current-version container.
pub(crate) fn footer(fields: [u64; 8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    for field in fields {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out
}

fn container(manifest: &[u8], archive: &[u8], signature: &[u8], hint: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(manifest);
    out.extend_from_slice(archive);
    let signature_offset = len_u64(manifest) + len_u64(archive);
    out.extend_from_slice(signature);
    let hint_offset = signature_offset + len_u64(signature);
    out.extend_from_slice(hint.as_bytes());
    out.extend_from_slice(&footer([
        0,
        len_u64(manifest),
        len_u64(manifest),
        len_u64(archive),
        signature_offset,
        len_u64(signature),
        hint_offset,
        len_u64(hint.as_bytes()),
    ]));
    out
}

/// One artifact of a fixture package.
#[derive(Clone, Debug)]
pub(crate) struct Art {
    pub(crate) path: String,
    pub(crate) kind: ArtifactKind,
    pub(crate) arch: TargetArch,
    pub(crate) bytes: Vec<u8>,
    pub(crate) image: Option<ImageDeclaration>,
    pub(crate) component: String,
    pub(crate) version: String,
    pub(crate) commit: String,
}

impl Art {
    fn new(path: &str, kind: ArtifactKind, bytes: Vec<u8>) -> Art {
        Art {
            path: path.to_string(),
            kind,
            arch: TargetArch::X86_64,
            bytes,
            image: None,
            component: COMPONENT.to_string(),
            version: VERSION.to_string(),
            commit: COMMIT.to_string(),
        }
    }

    pub(crate) fn native(path: &str, bytes: &[u8]) -> Art {
        Art::new(path, ArtifactKind::NativeBinary, bytes.to_vec())
    }

    pub(crate) fn compose(path: &str, bytes: &[u8]) -> Art {
        Art::new(path, ArtifactKind::ComposeBundle, bytes.to_vec())
    }

    /// A synthetic image of `arch` for `dependency`, tagged
    /// `registry.example/<dependency>:1.0`, with one layer holding `content`.
    pub(crate) fn image(path: &str, arch: TargetArch, dependency: &str, content: &[u8]) -> Art {
        let platform = ImagePlatform {
            os: ImageOs::Linux,
            architecture: ImageArchitecture::for_target(arch),
            variant: None,
        };
        let refs = vec![format!("registry.example/{dependency}:1.0")];
        let archive = SyntheticImageArchiveBuilder::new(platform.clone())
            .expect("a valid platform")
            .layer(
                SyntheticLayer::new().file("data.bin", content.to_vec()),
                LayerCompression::Gzip,
            )
            .expect("a valid layer")
            .finish(&refs)
            .expect("valid references");
        let declaration = ImageDeclaration {
            schema: IMAGE_DECLARATION_SCHEMA,
            owner: ImageOwner {
                namespace: NAMESPACE.to_string(),
                component: COMPONENT.to_string(),
            },
            dependency: dependency.to_string(),
            public_refs: refs,
            platform,
            config_digest: archive.config_digest().to_string(),
            reference_lifecycle: ReferenceLifecycle::SharedExternal,
            provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: "https://example.com/app.git".to_string(),
                commit: COMMIT.to_string(),
            }),
        };
        let mut art = Art::new(path, ArtifactKind::ContainerImage, archive.into_bytes());
        art.arch = arch;
        art.image = Some(declaration);
        art
    }

    pub(crate) fn on(mut self, arch: TargetArch) -> Art {
        self.arch = arch;
        self
    }

    pub(crate) fn artifact(&self) -> PayloadArtifact {
        PayloadArtifact {
            component: self.component.clone(),
            version: self.version.clone(),
            commit: Some(self.commit.clone()),
            target_arch: self.arch,
            kind: self.kind,
            dispositions: BTreeSet::from([Disposition::Install]),
            archive_path: self.path.clone(),
            sha256: sha256_hex(&self.bytes),
            spec: None,
            image: self.image.clone(),
        }
    }
}

/// The current-format manifest binding `arts`, in order.
pub(crate) fn manifest(arts: &[Art]) -> PayloadManifest {
    let members = arts
        .iter()
        .map(|art| ArchiveMember {
            name: art.path.clone(),
            length: len_u64(&art.bytes),
        })
        .collect();
    PayloadManifest::new(None, members, arts.iter().map(Art::artifact).collect())
        .expect("a valid manifest")
}

pub(crate) fn manifest_bytes(arts: &[Art]) -> Vec<u8> {
    serde_json::to_vec(&manifest(arts)).expect("a manifest serializes")
}

/// `arts`' manifest as JSON at `format_version` 5, with every `image` key
/// dropped: the shape an admitted legacy manifest carrying images has.
pub(crate) fn legacy_manifest_bytes(arts: &[Art]) -> Vec<u8> {
    let mut value: Value = serde_json::to_value(manifest(arts)).expect("a manifest serializes");
    value["format_version"] = Value::from(5);
    strip_images(&mut value);
    serde_json::to_vec(&value).expect("json serializes")
}

/// `arts`' manifest as JSON with every `image` key dropped, still at the
/// current format.
pub(crate) fn undeclared_manifest_bytes(arts: &[Art]) -> Vec<u8> {
    let mut value: Value = serde_json::to_value(manifest(arts)).expect("a manifest serializes");
    strip_images(&mut value);
    serde_json::to_vec(&value).expect("json serializes")
}

fn strip_images(value: &mut Value) {
    if let Some(artifacts) = value["artifacts"].as_array_mut() {
        for artifact in artifacts {
            if let Some(object) = artifact.as_object_mut() {
                object.remove("image");
            }
        }
    }
}

/// One entry of a hand-built outer tar.
pub(crate) enum Entry<'a> {
    /// A regular file named by its own header.
    File(&'a str, &'a [u8]),
    /// A regular file whose header name is `header` and whose name a PAX
    /// `path` record overrides with `path`.
    PaxPath {
        header: &'a str,
        path: &'a str,
        data: &'a [u8],
    },
    /// A regular file whose size a PAX `size` record overrides.
    PaxSize(&'a str, &'a [u8]),
    /// A regular file whose size a PAX `size` record overrides, that record
    /// followed in the same extension by a `comment` record of `comment`
    /// bytes.
    PaxSizeCommented {
        path: &'a str,
        data: &'a [u8],
        comment: usize,
    },
    /// A regular file preceded by a PAX extension holding nothing but a
    /// `comment` record of `comment` bytes, which overrides nothing.
    PaxCommented {
        path: &'a str,
        data: &'a [u8],
        comment: usize,
    },
    /// A regular file named by a GNU long-name entry.
    GnuLongName {
        header: &'a str,
        path: &'a str,
        data: &'a [u8],
    },
    /// A symbolic link at `header` whose target a GNU long-link entry names.
    GnuLongLink { header: &'a str, target: &'a str },
    /// A symbolic link.
    Symlink(&'a str),
    /// A regular file whose header name field holds `name` verbatim.
    RawName(&'a [u8], &'a [u8]),
}

fn header(name: &[u8], size: u64, kind: EntryType) -> Header {
    let mut header = Header::new_gnu();
    {
        let bytes = header.as_mut_bytes();
        bytes[..name.len()].copy_from_slice(name);
    }
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(kind);
    header.set_cksum();
    header
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut len = body.len();
    loop {
        let candidate = len.to_string().len() + body.len();
        if candidate == len {
            break;
        }
        len = candidate;
    }
    format!("{len}{body}").into_bytes()
}

fn padded(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// Appends a PAX extension holding `records`, then a regular file `name`
/// whose raw header states `size` and which carries `data`.
fn extended(out: &mut Vec<u8>, records: &[u8], name: &str, size: u64, data: &[u8]) {
    out.extend_from_slice(header(b"pax", len_u64(records), EntryType::XHeader).as_bytes());
    padded(out, records);
    out.extend_from_slice(header(name.as_bytes(), size, EntryType::Regular).as_bytes());
    padded(out, data);
}

/// An uncompressed tar of `entries` with its end-of-archive marker.
pub(crate) fn tar(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = tar_unfinished(entries);
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

/// An uncompressed tar of `entries` with no end-of-archive marker.
pub(crate) fn tar_unfinished(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            Entry::File(name, data) => {
                out.extend_from_slice(
                    header(name.as_bytes(), len_u64(data), EntryType::Regular).as_bytes(),
                );
                padded(&mut out, data);
            }
            Entry::RawName(name, data) => {
                out.extend_from_slice(header(name, len_u64(data), EntryType::Regular).as_bytes());
                padded(&mut out, data);
            }
            Entry::PaxPath {
                header: name,
                path,
                data,
            } => extended(
                &mut out,
                &pax_record("path", path),
                name,
                len_u64(data),
                data,
            ),
            Entry::PaxSize(name, data) => {
                let record = pax_record("size", &data.len().to_string());
                extended(&mut out, &record, name, len_u64(data) + 1, data);
            }
            Entry::PaxSizeCommented {
                path,
                data,
                comment,
            } => {
                let mut record = pax_record("size", &data.len().to_string());
                record.extend(pax_record("comment", &"c".repeat(*comment)));
                extended(&mut out, &record, path, len_u64(data) + 1, data);
            }
            Entry::PaxCommented {
                path,
                data,
                comment,
            } => {
                let record = pax_record("comment", &"c".repeat(*comment));
                extended(&mut out, &record, path, len_u64(data), data);
            }
            Entry::GnuLongLink {
                header: name,
                target,
            } => {
                let mut long = target.as_bytes().to_vec();
                long.push(0);
                out.extend_from_slice(
                    header(b"././@LongLink", len_u64(&long), EntryType::GNULongLink).as_bytes(),
                );
                padded(&mut out, &long);
                out.extend_from_slice(header(name.as_bytes(), 0, EntryType::Symlink).as_bytes());
            }
            Entry::GnuLongName {
                header: name,
                path,
                data,
            } => {
                let mut long = path.as_bytes().to_vec();
                long.push(0);
                out.extend_from_slice(
                    header(b"././@LongLink", len_u64(&long), EntryType::GNULongName).as_bytes(),
                );
                padded(&mut out, &long);
                out.extend_from_slice(
                    header(name.as_bytes(), len_u64(data), EntryType::Regular).as_bytes(),
                );
                padded(&mut out, data);
            }
            Entry::Symlink(name) => {
                out.extend_from_slice(header(name.as_bytes(), 0, EntryType::Symlink).as_bytes());
            }
        }
    }
    out
}

/// zstd-compresses `bytes` at `level`.
pub(crate) fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::encode_all(bytes, 3).expect("zstd compresses")
}

/// zstd-compresses `bytes` in a frame declaring a window of `2^log` bytes.
pub(crate) fn zstd_window(bytes: &[u8], log: u32) -> Vec<u8> {
    let mut encoder = zstd::Encoder::new(Vec::new(), 3).expect("an encoder");
    encoder.window_log(log).expect("a window log");
    encoder.write_all(bytes).expect("compresses");
    encoder.finish().expect("finishes")
}

/// The honest compressed archive of `arts`, in order.
pub(crate) fn archive(arts: &[Art]) -> Vec<u8> {
    let entries: Vec<Entry<'_>> = arts
        .iter()
        .map(|art| Entry::File(&art.path, &art.bytes))
        .collect();
    zstd(&tar(&entries))
}

/// A signed package of `arts`, honestly archived.
pub(crate) fn package(signer: &Signer, arts: &[Art]) -> Vec<u8> {
    signer.container(&manifest_bytes(arts), &archive(arts))
}

/// The namespaced request every fixture's build answers.
pub(crate) fn request() -> VerifyRequest {
    VerifyRequest::for_namespaced_package(COMPONENT, VERSION, COMMIT, NAMESPACE)
        .expect("a valid request")
}

/// An image-free fixture's plain request.
pub(crate) fn plain_request() -> VerifyRequest {
    VerifyRequest::for_package(COMPONENT, VERSION, COMMIT).expect("a valid request")
}

/// Two images and two ordinary artifacts, for `x86_64`.
pub(crate) fn mixed() -> Vec<Art> {
    vec![
        Art::image("images/db.tar", TargetArch::X86_64, "database", b"db layer"),
        Art::compose("compose.yaml", b"services: {}\n"),
        Art::image("images/web.tar", TargetArch::X86_64, "web", b"web layer"),
        Art::native("bin/tool", b"\x7fELF tool"),
    ]
}
