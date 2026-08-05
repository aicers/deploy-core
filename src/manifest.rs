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

/// The whole payload trailer manifest: the pin-set digest the payload was built
/// from, plus an ordered list of artifacts.
///
/// Constructed through [`PayloadManifest::new`], which enforces the manifest
/// invariants (non-empty dispositions, unique `archive_path`). Deserialization
/// runs the same validation, so a manifest read back from JSON is always valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawManifest")]
pub struct PayloadManifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pinset: Option<String>,
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
#[derive(Deserialize)]
struct RawManifest {
    #[serde(default)]
    pinset: Option<String>,
    artifacts: Vec<PayloadArtifact>,
}

impl TryFrom<RawManifest> for PayloadManifest {
    type Error = ManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, Self::Error> {
        Self::new(raw.pinset, raw.artifacts)
    }
}

impl PayloadManifest {
    /// Creates a manifest, rejecting an empty disposition set or a duplicate
    /// `archive_path`.
    ///
    /// `pinset` is the `bootler.pinset.v1` digest of the recipe the payload was
    /// assembled from; `None` records a payload built before the stamp existed.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when an artifact carries no dispositions, uses
    /// an unsafe `archive_path`, or shares an `archive_path` with another
    /// artifact.
    pub fn new(
        pinset: Option<String>,
        artifacts: Vec<PayloadArtifact>,
    ) -> Result<Self, ManifestError> {
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
        }
        Ok(Self { pinset, artifacts })
    }

    /// Returns the pin-set digest the payload was assembled from, or `None` for
    /// a payload that predates the stamp.
    #[must_use]
    pub fn pinset(&self) -> Option<&str> {
        self.pinset.as_deref()
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
        ArtifactKind, Disposition, ManifestError, PayloadArtifact, PayloadManifest, TargetArch,
    };

    fn artifact(
        archive_path: &str,
        kind: ArtifactKind,
        dispositions: &[Disposition],
    ) -> PayloadArtifact {
        PayloadArtifact {
            component: "example".to_string(),
            version: "1.2.3".to_string(),
            target_arch: TargetArch::X86_64,
            kind,
            dispositions: dispositions.iter().copied().collect(),
            archive_path: archive_path.to_string(),
            sha256: "00".repeat(32),
        }
    }

    /// A `bootler.pinset.v1` digest, in the 64-hex-character form the release
    /// tool stamps. This layer stores the stamp opaquely and deliberately does
    /// not validate its form — computing and checking it is `release-tool`'s job.
    const PINSET: &str = "656add7928cb1eee2d46a23546c477c9447ceb2afe78734239e21a785ddb9aec";

    #[test]
    fn round_trips_through_serde_covering_all_kinds_and_both_dispositions() {
        let manifest = PayloadManifest::new(
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
        let json = r#"{"artifacts":[{"component":"c","version":"1","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"bin/c","sha256":"00"}]}"#;
        let manifest: PayloadManifest =
            serde_json::from_str(json).expect("a pinset-less manifest must deserialize");
        assert_eq!(manifest.pinset(), None);
        assert_eq!(manifest.artifacts().len(), 1);
    }

    #[test]
    fn a_pinset_less_manifest_serializes_without_the_field() {
        // `RawManifest` carries no `deny_unknown_fields`, so a reader predating
        // the field ignores it; omitting it when absent additionally keeps such a
        // manifest's wire form byte-identical to the pre-stamp format.
        let manifest = PayloadManifest::new(
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
        let json = r#"{"pinset":"abc","surprise":true,"artifacts":[]}"#;
        let manifest: PayloadManifest =
            serde_json::from_str(json).expect("an unknown field must be ignored");
        assert_eq!(manifest.pinset(), Some("abc"));
    }

    #[test]
    fn kinds_and_dispositions_use_kebab_case_strings() {
        let manifest = PayloadManifest::new(
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
        let error =
            PayloadManifest::new(None, vec![bad]).expect_err("empty dispositions must be rejected");
        assert!(matches!(error, ManifestError::EmptyDispositions(_)));
    }

    #[test]
    fn deserialization_rejects_empty_disposition_set() {
        let json = r#"{"artifacts":[{"component":"c","version":"1","target_arch":"x86_64","kind":"native-binary","dispositions":[],"archive_path":"bin/c","sha256":"00"}]}"#;
        let result: Result<PayloadManifest, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "empty dispositions must fail to deserialize"
        );
    }

    #[test]
    fn new_rejects_duplicate_archive_path() {
        let error = PayloadManifest::new(
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
        let entry = r#"{"component":"c","version":"1","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"bin/dup","sha256":"00"}"#;
        let json = format!("{{\"artifacts\":[{entry},{entry}]}}");
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
            let error = PayloadManifest::new(
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
        let json = r#"{"artifacts":[{"component":"c","version":"1","target_arch":"x86_64","kind":"native-binary","dispositions":["install"],"archive_path":"../escape","sha256":"00"}]}"#;
        let result: Result<PayloadManifest, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unsafe archive_path must fail to deserialize"
        );
    }

    #[test]
    fn empty_manifest_is_valid() {
        let manifest = PayloadManifest::new(None, Vec::new()).expect("empty manifest is valid");
        assert!(manifest.artifacts().is_empty());
    }
}
