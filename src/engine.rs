//! Product-neutral install/update engine: the diff and classification layer.
//!
//! Given an installed baseline and a new release's [`PayloadManifest`], the
//! engine classifies what changed along the **artifact** axis (which packaged
//! artifacts were added, changed by SHA-256, or removed) and the **secret-key**
//! axis, and diffs a rendered config/unit file against its on-disk copy. It
//! speaks only component-id **strings** and package data — no product component
//! enum, placement, or renderer — so the same diff drives the installer's
//! config-less update and an on-host agent applying a module package.
//!
//! Apply (placing artifacts, restarting components) is the installer's
//! orchestration for now; this module owns the mechanical classification the
//! apply consumes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::exec::CoreError;
use crate::executor::{Executor, FileMeta, Identity};
use crate::manifest::{ArtifactKind, Disposition, PayloadArtifact, PayloadManifest, TargetArch};
use crate::payload::sha256_hex;

/// One recorded payload-artifact tuple — the artifact-axis baseline (§9/§11).
///
/// Records the `PayloadArtifact` fields update needs so multiple artifacts per
/// component and the dual-disposition Roxyd artifact stay unambiguous in the diff
/// map: the `(component, kind, dispositions, target_arch, archive_path)` tuple is
/// the identity, and `sha256` is the value the artifact axis compares. Within a
/// manifest `archive_path` is unique, so it is the natural per-artifact match key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Component the artifact belongs to (for example `roxyd`).
    pub component: String,
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// One or more dispositions (`install`, `stage`); drives per-disposition apply.
    pub dispositions: BTreeSet<Disposition>,
    /// Architecture the artifact is built for.
    pub target_arch: TargetArch,
    /// Path of this artifact's member inside the payload archive — unique within a
    /// manifest, so it is the per-artifact match key.
    pub archive_path: String,
    /// Lowercase hex SHA-256 over the artifact bytes — the artifact-axis value.
    pub sha256: String,
}

impl ArtifactRecord {
    /// Snapshots a payload artifact's diff-relevant tuple.
    #[must_use]
    pub fn from_artifact(artifact: &PayloadArtifact) -> Self {
        Self {
            component: artifact.component.clone(),
            kind: artifact.kind,
            dispositions: artifact.dispositions.clone(),
            target_arch: artifact.target_arch,
            archive_path: artifact.archive_path.clone(),
            sha256: artifact.sha256.clone(),
        }
    }
}

/// One changed artifact on the artifact axis — same `archive_path`, differing
/// bytes or tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedArtifact {
    /// Component the artifact belongs to.
    pub component: String,
    /// The archive path — the per-artifact match key, unique within a manifest.
    pub archive_path: String,
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// Dispositions carried by the new artifact; drives per-disposition apply.
    pub dispositions: BTreeSet<Disposition>,
    /// Architecture the artifact is built for.
    pub target_arch: TargetArch,
    /// The SHA-256 recorded in the installed baseline.
    pub installed_sha256: String,
    /// The SHA-256 of the new-release artifact.
    pub new_sha256: String,
}

impl ChangedArtifact {
    /// Reports whether this artifact carries the given disposition.
    #[must_use]
    pub fn has(&self, disposition: Disposition) -> bool {
        self.dispositions.contains(&disposition)
    }
}

/// The artifact-axis classification of a new release against installed state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactDiff {
    /// Artifacts present in the new release but not in the installed baseline.
    pub added: Vec<ArtifactRecord>,
    /// Artifacts whose bytes changed (same `archive_path`, different SHA-256).
    pub changed: Vec<ChangedArtifact>,
    /// Artifacts in the installed baseline no longer in the new release.
    pub removed: Vec<ArtifactRecord>,
}

impl ArtifactDiff {
    /// Reports whether the artifact axis found nothing to apply (no added, no
    /// changed; a removed artifact alone is informational and touches nothing).
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty()
    }

    /// Returns the set of component names touched on the artifact axis (added or
    /// changed), so the apply engine knows which components to act on.
    #[must_use]
    pub fn changed_components(&self) -> BTreeSet<String> {
        self.added
            .iter()
            .map(|artifact| artifact.component.clone())
            .chain(
                self.changed
                    .iter()
                    .map(|artifact| artifact.component.clone()),
            )
            .collect()
    }
}

/// Classifies the artifact axis: matches each new-release artifact against the
/// installed per-artifact tuple by `archive_path` and marks it changed when the
/// SHA-256 or any other tuple field differs.
///
/// `archive_path` is the match key (unique within a manifest), but the change
/// decision compares the **full recorded tuple** — `component`, `kind`,
/// `dispositions`, `target_arch`, and the SHA-256 — because a release can keep the
/// same path and bytes while re-dispositioning an artifact (for example adding
/// `stage` to an `install`-only artifact so it must now be written to the module
/// store). Keying on SHA-256 alone would silently drop that apply.
///
/// SHA-256 comparison is case-insensitive because different producers emit
/// different hex casing (the payload reader and `sha256sum` both do), so a mere
/// casing difference must never read as a changed artifact.
#[must_use]
pub fn diff_artifacts(installed: &[ArtifactRecord], new: &PayloadManifest) -> ArtifactDiff {
    let installed_by_path: BTreeMap<&str, &ArtifactRecord> = installed
        .iter()
        .map(|artifact| (artifact.archive_path.as_str(), artifact))
        .collect();
    let new_by_path: BTreeSet<&str> = new
        .artifacts()
        .iter()
        .map(|artifact| artifact.archive_path.as_str())
        .collect();

    let mut diff = ArtifactDiff::default();
    for artifact in new.artifacts() {
        match installed_by_path.get(artifact.archive_path.as_str()) {
            None => diff.added.push(ArtifactRecord::from_artifact(artifact)),
            Some(existing) => {
                let sha_differs = !existing.sha256.eq_ignore_ascii_case(&artifact.sha256);
                // A same-path artifact is also changed when any non-SHA tuple field
                // moved — re-disposition (install↔stage), a kind or arch change, or a
                // component rename — so the matching per-disposition apply still runs.
                let tuple_differs = existing.component != artifact.component
                    || existing.kind != artifact.kind
                    || existing.dispositions != artifact.dispositions
                    || existing.target_arch != artifact.target_arch;
                if sha_differs || tuple_differs {
                    diff.changed.push(ChangedArtifact {
                        component: artifact.component.clone(),
                        archive_path: artifact.archive_path.clone(),
                        kind: artifact.kind,
                        dispositions: artifact.dispositions.clone(),
                        target_arch: artifact.target_arch,
                        installed_sha256: existing.sha256.clone(),
                        new_sha256: artifact.sha256.clone(),
                    });
                }
            }
        }
    }
    for artifact in installed {
        if !new_by_path.contains(artifact.archive_path.as_str()) {
            diff.removed.push(artifact.clone());
        }
    }
    diff
}

/// The secret-schema-axis classification: which secret keys are newly required
/// (generate only these) and which are gone (informational; never delete a
/// secret from under a running product).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretSchemaDiff {
    /// Secret keys the new build requires that the installation lacks — the only
    /// secrets update generates (§7 generate-if-absent, never regenerate).
    pub newly_required: BTreeSet<String>,
    /// Keys the installation has that the new build no longer requires.
    pub removed: BTreeSet<String>,
}

impl SecretSchemaDiff {
    /// Reports whether the secret schema is unchanged.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.newly_required.is_empty() && self.removed.is_empty()
    }
}

/// Classifies the secret-schema axis: compares the new build's required secret
/// key set against the installed key set.
#[must_use]
pub fn diff_secret_schema(
    installed: &BTreeSet<String>,
    required_now: &BTreeSet<String>,
) -> SecretSchemaDiff {
    SecretSchemaDiff {
        newly_required: required_now.difference(installed).cloned().collect(),
        removed: installed.difference(required_now).cloned().collect(),
    }
}

/// The config-axis status of a single rendered file against its on-disk copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileStatus {
    /// The on-disk file is byte-identical to the freshly rendered output.
    Unchanged,
    /// The rendered output differs from the on-disk file — a config-only change.
    Changed,
    /// No file exists on disk yet, so the component must be (re-)rendered. Treated
    /// as changed by the apply engine.
    Missing,
}

impl ConfigFileStatus {
    /// Reports whether this status requires a re-render (changed or missing).
    #[must_use]
    pub fn needs_render(self) -> bool {
        matches!(self, ConfigFileStatus::Changed | ConfigFileStatus::Missing)
    }
}

/// Diffs a freshly rendered config/unit file against the root-owned copy on disk,
/// reading the on-disk bytes through the executor's root-identity read.
///
/// A missing on-disk file is [`ConfigFileStatus::Missing`] (re-render), not an
/// error — a config axis scoped to rendered text must treat an absent file as a
/// change rather than a hard failure. The comparison is byte-exact via SHA-256 so
/// it never buffers two large files for a full `==`; rendered config/unit text is
/// small, but the SHA path keeps the primitive uniform.
///
/// # Errors
///
/// Returns [`CoreError::Executor`] only on a hard transport failure; a non-zero
/// `cat` (missing/unreadable) maps to [`ConfigFileStatus::Missing`].
pub fn diff_rendered_file(
    executor: &dyn Executor,
    path: &Path,
    rendered: &[u8],
) -> Result<ConfigFileStatus, CoreError> {
    // Read the on-disk copy without treating "absent" as a transport error: a
    // root-identity `cat` that exits non-zero means the file is missing here.
    let output = executor.run(Identity::Root, "cat", &[&path.to_string_lossy()])?;
    if !output.success() {
        return Ok(ConfigFileStatus::Missing);
    }
    if sha256_hex(&output.stdout) == sha256_hex(rendered) {
        Ok(ConfigFileStatus::Unchanged)
    } else {
        Ok(ConfigFileStatus::Changed)
    }
}

/// What an update actually did to one subject (a component, artifact, or module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppliedAction {
    /// A changed `install`-disposition artifact was placed and its component
    /// restarted (stop → swap → start).
    ArtifactSwapped,
    /// A component's config re-rendered differently, so it was rewritten and the
    /// component reloaded/restarted.
    ConfigRerendered,
    /// A changed `stage`-disposition package was re-written to the module store
    /// and hash-verified.
    ModuleRestaged,
    /// A newly-required secret was generated (existing secrets never regenerated).
    SecretGenerated,
}

/// One recorded step an update applied, for the operator's structured report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedChange {
    /// The subject acted on (component name, artifact archive path, module, or
    /// secret key).
    pub subject: String,
    /// The host it was applied on.
    pub host: String,
    /// What was done.
    pub action: AppliedAction,
}

/// Every `install`-disposition artifact the new release changed or added, as
/// `(archive_path, component, kind)`.
#[must_use]
pub fn changed_install_artifacts(diff: &ArtifactDiff) -> Vec<(String, String, ArtifactKind)> {
    let changed = diff
        .changed
        .iter()
        .filter(|artifact| artifact.has(Disposition::Install))
        .map(|artifact| {
            (
                artifact.archive_path.clone(),
                artifact.component.clone(),
                artifact.kind,
            )
        });
    let added = diff
        .added
        .iter()
        .filter(|artifact| artifact.dispositions.contains(&Disposition::Install))
        .map(|artifact| {
            (
                artifact.archive_path.clone(),
                artifact.component.clone(),
                artifact.kind,
            )
        });
    changed.chain(added).collect()
}

/// Every `stage`-disposition artifact the new release changed or added.
#[must_use]
pub fn changed_stage_artifacts(diff: &ArtifactDiff) -> Vec<String> {
    let changed = diff
        .changed
        .iter()
        .filter(|artifact| artifact.has(Disposition::Stage))
        .map(|artifact| artifact.archive_path.clone());
    let added = diff
        .added
        .iter()
        .filter(|artifact| artifact.dispositions.contains(&Disposition::Stage))
        .map(|artifact| artifact.archive_path.clone());
    changed.chain(added).collect()
}

/// Returns the ownership and mode an artifact of `kind` is placed with, so an
/// updated binary lands executable for the same reason a freshly installed one
/// does rather than through a follow-up `chmod`.
#[must_use]
pub fn artifact_file_meta(kind: ArtifactKind) -> FileMeta {
    match kind {
        ArtifactKind::NativeBinary => FileMeta::ROOT_BINARY,
        _ => FileMeta::ROOT_CONFIG,
    }
}
