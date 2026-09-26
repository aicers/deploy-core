//! Container image declarations a manifest makes about its image artifacts.
//!
//! From manifest format version 6
//! ([`IMAGE_DECLARATION_FORMAT_VERSION`](crate::manifest::IMAGE_DECLARATION_FORMAT_VERSION))
//! every [`ArtifactKind::ContainerImage`](crate::manifest::ArtifactKind::ContainerImage)
//! artifact carries an [`ImageDeclaration`]: which namespace and component own
//! the image, which dependency of that component it is, the explicit
//! `name:tag` references it is restored under, the one Linux platform it is
//! built for, its config digest, whether its references are managed by the
//! runtime or shared with something else, and where it came from.
//!
//! This module states the wire shape and the **syntax** of every field. It
//! checks nothing about archive bytes: a declaration that parses and validates
//! here is an authenticated *statement* once its manifest's signature has been
//! verified, never evidence that the image the archive holds agrees with it.
//! The verifier's semantic checks — the declared architecture against the
//! artifact's, the reserved runtime alias binding, cross-artifact reference
//! conflicts and the caller's namespace — live in [`crate::verify`].
//!
//! Reference syntax follows [distribution/reference] v0.6.0, reimplemented
//! here rather than depended on: its grammar is a handful of character classes
//! and its normalization three rules, while no Rust crate in the dependency
//! tree states either. Nothing here contacts a registry, a Docker daemon or the
//! network.
//!
//! [distribution/reference]: https://github.com/distribution/reference/tree/v0.6.0

use serde::{Deserialize, Deserializer, Serialize};

use crate::manifest::{GIT_COMMIT_HEX_LEN, IMAGE_DIGEST_HEX_LEN, TargetArch};

// The byte-level image-archive validator. Crate-private: package verification
// is what calls it.
mod archive;

pub(crate) use archive::{ImageArchiveFault, ValidatedImageArchive, validate_image_archive};
// Synthetic image archives and an archive classifier, for this crate's tests
// and for dependents that enable `test-support` under `[dev-dependencies]`.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// The one declaration `schema` this build reads and writes.
pub const IMAGE_DECLARATION_SCHEMA: u32 = 1;

/// Registry hostname reserved for canonical runtime aliases.
///
/// `.invalid` is reserved by RFC 2606 and never resolves, so no registry can
/// ever serve a reference under it: an image named here can only have come out
/// of a package.
pub const RUNTIME_ALIAS_REGISTRY: &str = "runtime.invalid";

/// Prefix of a canonical runtime alias's tag, ahead of the config digest's hex.
pub const RUNTIME_ALIAS_TAG_PREFIX: &str = "cfg-";

/// Prefix of every digest a declaration carries.
const SHA256_DIGEST_PREFIX: &str = "sha256:";

/// Registry a familiar Docker name normalizes onto.
const DOCKER_DEFAULT_DOMAIN: &str = "docker.io";

/// Legacy Docker Hub domain, normalized onto [`DOCKER_DEFAULT_DOMAIN`].
const DOCKER_LEGACY_DEFAULT_DOMAIN: &str = "index.docker.io";

/// Path prefix a single-component Docker Hub name normalizes under.
const DOCKER_OFFICIAL_REPO_PREFIX: &str = "library/";

/// The first path element that is always read as a domain.
const DOCKER_LOCALHOST: &str = "localhost";

/// Longest normalized remote repository path, in bytes.
const MAX_REPOSITORY_PATH_BYTES: usize = 255;

/// Longest tag, in bytes: one leading character and up to 127 more.
const MAX_TAG_BYTES: usize = 128;

/// A container image declaration: the typed `image` object of a v6
/// `container-image` artifact.
///
/// Every field is required, nullable ones included, and unknown fields are
/// refused throughout, nested objects included. Decoding checks the shape
/// only; [`ImageDeclaration::validate`] checks the syntax, and every manifest
/// door runs both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageDeclaration {
    /// Declaration schema; exactly [`IMAGE_DECLARATION_SCHEMA`].
    pub schema: u32,
    /// Namespace and component that own the image.
    pub owner: ImageOwner,
    /// Which dependency of the owning component this image is.
    pub dependency: String,
    /// The explicit `name:tag` references the image is restored under, as the
    /// producer signed them: nonempty, and free of duplicates under Docker
    /// normalization.
    pub public_refs: Vec<String>,
    /// The one platform the image is built for.
    pub platform: ImagePlatform,
    /// `sha256:` digest of the image config, the image's identity.
    pub config_digest: String,
    /// Whether the references are managed by the runtime or shared.
    pub reference_lifecycle: ReferenceLifecycle,
    /// Where the image came from.
    pub provenance: ImageProvenance,
}

/// The namespace and component an image belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageOwner {
    /// Owning namespace, compared verbatim with the caller's.
    pub namespace: String,
    /// Owning component, compared verbatim with the requested target.
    pub component: String,
}

/// The one Linux platform an image artifact is built for.
///
/// Nothing is filled in from a host or daemon default: `variant` is required
/// on the wire even when it is `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePlatform {
    /// Operating system; Linux is the only one.
    pub os: ImageOs,
    /// CPU architecture.
    pub architecture: ImageArchitecture,
    /// Architecture variant, or `None` for none. A present variant is
    /// nonempty.
    #[serde(deserialize_with = "required_nullable")]
    pub variant: Option<String>,
}

/// Operating system of an image platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageOs {
    /// Linux.
    Linux,
}

/// CPU architecture of an image platform, spelled as OCI spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageArchitecture {
    /// 64-bit x86, the image counterpart of [`TargetArch::X86_64`].
    Amd64,
    /// 64-bit ARM, the image counterpart of [`TargetArch::Aarch64`].
    Arm64,
}

impl ImageArchitecture {
    /// Returns the image architecture an artifact built for `target_arch`
    /// declares.
    #[must_use]
    pub fn for_target(target_arch: TargetArch) -> Self {
        match target_arch {
            TargetArch::X86_64 => Self::Amd64,
            TargetArch::Aarch64 => Self::Arm64,
        }
    }
}

impl std::fmt::Display for ImageArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        })
    }
}

/// Who owns an image's references at runtime.
///
/// Both are required runtime references. Only a managed one confers future
/// teardown ownership on its component; nothing in this crate tears anything
/// down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceLifecycle {
    /// The runtime manages the references on the owning component's behalf.
    ManagedRuntime,
    /// The references are shared with something outside the component.
    SharedExternal,
}

/// Where an image came from: a closed union tagged by `kind`.
///
/// Neither arm changes the enclosing artifact's `component`, `version` or
/// `commit`, which name the requested component build the image ships in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageProvenance {
    /// A third-party image pulled from a registry.
    Registry(RegistryProvenance),
    /// An image built from product source.
    ProductBuild(ProductBuildProvenance),
}

/// The registry an image was pulled from, as release assembly approved it.
///
/// `pinned_digest` and `selected_manifest_digest` name different objects —
/// a pinned index can select a child manifest — and neither is the config
/// digest. Proving their relationship is release assembly's job; nothing
/// here requires them to be equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryProvenance {
    /// Fully qualified canonical repository, such as
    /// `docker.io/library/postgres`.
    pub repository: String,
    /// Upstream tag.
    pub tag: String,
    /// Canonical `SemVer` 2.0.0 comparison version, or `None` for an upstream
    /// scheme that does not compare that way. Required on the wire.
    #[serde(deserialize_with = "required_nullable")]
    pub version: Option<String>,
    /// Approved upstream index or manifest digest.
    pub pinned_digest: String,
    /// Digest of the platform manifest selected from it.
    pub selected_manifest_digest: String,
}

/// The source an image was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductBuildProvenance {
    /// Opaque source repository identifier, preserved literally.
    pub repository: String,
    /// Full 40-hex source commit.
    pub commit: String,
}

/// Decodes a field that is nullable but never optional: a missing key is an
/// error, `null` is `None`.
///
/// serde reads an absent `Option` field as `None` by default; routing the
/// field through a function of its own removes that default.
fn required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// Which identifier segment of a declaration a rule refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentField {
    /// `owner.namespace`.
    Namespace,
    /// `owner.component`.
    Component,
    /// `dependency`.
    Dependency,
}

impl std::fmt::Display for SegmentField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Namespace => "owner.namespace",
            Self::Component => "owner.component",
            Self::Dependency => "dependency",
        })
    }
}

/// Which digest of a declaration a rule refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestField {
    /// `config_digest`.
    Config,
    /// `provenance.pinned_digest`.
    Pinned,
    /// `provenance.selected_manifest_digest`.
    SelectedManifest,
}

impl std::fmt::Display for DigestField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Config => "config_digest",
            Self::Pinned => "provenance.pinned_digest",
            Self::SelectedManifest => "provenance.selected_manifest_digest",
        })
    }
}

/// Why a Docker reference or repository name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceError {
    /// The string is empty.
    #[error("the reference is empty")]
    Empty,
    /// The string carries an `@digest` part.
    #[error("a digest reference is not allowed")]
    DigestNotAllowed,
    /// A reference carries no explicit tag; no implicit `latest` is supplied.
    #[error("the reference carries no explicit tag")]
    MissingTag,
    /// A repository name carries a tag.
    #[error("a repository name carries a tag")]
    TagNotAllowed,
    /// The tag does not match `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
    #[error("invalid tag `{0}`")]
    InvalidTag(String),
    /// The name is a bare 64-hex identifier.
    #[error("a 64-hex identifier is not a repository name")]
    HexIdentifier,
    /// The repository path carries uppercase characters.
    #[error("repository path `{0}` must be lowercase")]
    Uppercase(String),
    /// The registry is not a valid domain or IPv6 address with an optional
    /// numeric port.
    #[error("invalid registry `{0}`")]
    InvalidDomain(String),
    /// The repository path is not `/`-separated Docker path components.
    #[error("invalid repository path `{0}`")]
    InvalidPath(String),
    /// The normalized repository path is longer than 255 bytes.
    #[error("normalized repository path is {0} bytes, more than 255")]
    PathTooLong(usize),
    /// A repository name is not written in its fully qualified canonical form.
    #[error("repository name is not canonical; it normalizes to `{normalized}`")]
    NotCanonical {
        /// The name the input normalizes to.
        normalized: String,
    },
}

/// A syntax rule an [`ImageDeclaration`] violates.
#[derive(Debug, thiserror::Error)]
pub enum ImageDeclarationError {
    /// `schema` is not [`IMAGE_DECLARATION_SCHEMA`].
    #[error(
        "unsupported image declaration schema {found} (this build reads {IMAGE_DECLARATION_SCHEMA})"
    )]
    UnsupportedSchema {
        /// Schema the declaration carried.
        found: u64,
    },
    /// An identifier segment is empty, or is not lowercase ASCII alphanumerics
    /// with `-` and `_` after an alphanumeric first character.
    #[error("invalid {field} `{value}`")]
    InvalidSegment {
        /// Which segment.
        field: SegmentField,
        /// The refused value.
        value: String,
    },
    /// `public_refs` is empty.
    #[error("`public_refs` is empty")]
    EmptyPublicRefs,
    /// A public reference is not an explicit Docker `name:tag`.
    #[error("invalid public reference `{reference}`")]
    InvalidReference {
        /// The refused reference.
        reference: String,
        /// Why.
        #[source]
        source: ReferenceError,
    },
    /// Two public references name the same normalized name and tag.
    #[error("public reference `{reference}` duplicates `{first}` after normalization")]
    DuplicateReference {
        /// The later reference.
        reference: String,
        /// The earlier one it duplicates.
        first: String,
    },
    /// `platform.variant` is an empty string.
    #[error("`platform.variant` is an empty string")]
    EmptyVariant,
    /// A digest is not `sha256:` and 64 lowercase hex characters.
    #[error("invalid {field} `{value}`")]
    InvalidDigest {
        /// Which digest.
        field: DigestField,
        /// The refused value.
        value: String,
    },
    /// `provenance.repository` of a registry image is not a fully qualified
    /// canonical repository name.
    #[error("invalid registry repository `{repository}`")]
    InvalidRegistryRepository {
        /// The refused repository.
        repository: String,
        /// Why.
        #[source]
        source: ReferenceError,
    },
    /// `provenance.tag` of a registry image is not a valid tag.
    #[error("invalid registry tag `{0}`")]
    InvalidRegistryTag(String),
    /// `provenance.version` of a registry image is not canonical `SemVer` 2.0.0.
    #[error("invalid registry version `{0}`")]
    InvalidRegistryVersion(String),
    /// `provenance.repository` of a product build is empty, carries a control
    /// character, or carries surrounding whitespace.
    #[error("invalid source repository `{0}`")]
    InvalidSourceRepository(String),
    /// `provenance.commit` of a product build is not 40 lowercase hex
    /// characters.
    #[error("invalid source commit `{0}`")]
    InvalidSourceCommit(String),
    /// The canonical runtime alias built from valid segments is still not a
    /// valid Docker reference.
    #[error("canonical runtime alias `{alias}` is not a valid reference")]
    InvalidRuntimeAlias {
        /// The alias as built.
        alias: String,
        /// Why.
        #[source]
        source: ReferenceError,
    },
}

impl ImageDeclaration {
    /// Checks every syntax rule of the declaration, in field order.
    ///
    /// This is the typed-parse check every manifest door runs. It does not
    /// compare the declaration with its artifact or with the caller's request,
    /// and it does not require a reference under [`RUNTIME_ALIAS_REGISTRY`]
    /// to be the canonical alias: those are the verifier's semantic checks.
    ///
    /// # Errors
    ///
    /// Returns the first [`ImageDeclarationError`] the declaration violates:
    /// an unsupported schema, an invalid owner or dependency segment, an empty
    /// or invalid or duplicated public reference, an empty variant, a
    /// malformed config digest, or a malformed provenance field.
    pub fn validate(&self) -> Result<(), ImageDeclarationError> {
        if self.schema != IMAGE_DECLARATION_SCHEMA {
            return Err(ImageDeclarationError::UnsupportedSchema {
                found: u64::from(self.schema),
            });
        }
        validate_segment(SegmentField::Namespace, &self.owner.namespace)?;
        validate_segment(SegmentField::Component, &self.owner.component)?;
        validate_segment(SegmentField::Dependency, &self.dependency)?;

        if self.public_refs.is_empty() {
            return Err(ImageDeclarationError::EmptyPublicRefs);
        }
        let mut seen: Vec<(NormalizedReference, &str)> = Vec::with_capacity(self.public_refs.len());
        for reference in &self.public_refs {
            let normalized = parse_tagged_reference(reference).map_err(|source| {
                ImageDeclarationError::InvalidReference {
                    reference: reference.clone(),
                    source,
                }
            })?;
            if let Some((_, first)) = seen.iter().find(|(key, _)| *key == normalized) {
                return Err(ImageDeclarationError::DuplicateReference {
                    reference: reference.clone(),
                    first: (*first).to_string(),
                });
            }
            seen.push((normalized, reference));
        }

        if self.platform.variant.as_deref() == Some("") {
            return Err(ImageDeclarationError::EmptyVariant);
        }
        validate_digest(DigestField::Config, &self.config_digest)?;

        match &self.provenance {
            ImageProvenance::Registry(registry) => registry.validate(),
            ImageProvenance::ProductBuild(build) => build.validate(),
        }
    }

    /// Returns the canonical runtime alias this declaration's owner,
    /// dependency and config digest determine.
    ///
    /// # Errors
    ///
    /// Returns what [`canonical_runtime_alias`] returns.
    pub fn canonical_runtime_alias(&self) -> Result<String, ImageDeclarationError> {
        canonical_runtime_alias(
            &self.owner.namespace,
            &self.owner.component,
            &self.dependency,
            &self.config_digest,
        )
    }

    /// Creates the declaration of a newly normalized third-party image: its
    /// only public reference is the canonical runtime alias, and its lifecycle
    /// is [`ReferenceLifecycle::ManagedRuntime`].
    ///
    /// This is for a producer normalizing a third-party image under a
    /// component. It is not how an existing product-built tag or a shared
    /// external reference is declared: those keep the references the producer
    /// chose.
    ///
    /// # Errors
    ///
    /// Returns what [`canonical_runtime_alias`] returns, and otherwise any
    /// rule [`ImageDeclaration::validate`] enforces.
    pub fn normalized_third_party(
        owner: ImageOwner,
        dependency: &str,
        platform: ImagePlatform,
        config_digest: &str,
        provenance: RegistryProvenance,
    ) -> Result<Self, ImageDeclarationError> {
        let alias = canonical_runtime_alias(
            &owner.namespace,
            &owner.component,
            dependency,
            config_digest,
        )?;
        let declaration = Self {
            schema: IMAGE_DECLARATION_SCHEMA,
            owner,
            dependency: dependency.to_string(),
            public_refs: vec![alias],
            platform,
            config_digest: config_digest.to_string(),
            reference_lifecycle: ReferenceLifecycle::ManagedRuntime,
            provenance: ImageProvenance::Registry(provenance),
        };
        declaration.validate()?;
        Ok(declaration)
    }
}

impl RegistryProvenance {
    fn validate(&self) -> Result<(), ImageDeclarationError> {
        validate_canonical_repository(&self.repository).map_err(|source| {
            ImageDeclarationError::InvalidRegistryRepository {
                repository: self.repository.clone(),
                source,
            }
        })?;
        if !is_valid_tag(&self.tag) {
            return Err(ImageDeclarationError::InvalidRegistryTag(self.tag.clone()));
        }
        if let Some(version) = &self.version
            && !is_canonical_semver(version)
        {
            return Err(ImageDeclarationError::InvalidRegistryVersion(
                version.clone(),
            ));
        }
        validate_digest(DigestField::Pinned, &self.pinned_digest)?;
        validate_digest(
            DigestField::SelectedManifest,
            &self.selected_manifest_digest,
        )?;
        Ok(())
    }
}

impl ProductBuildProvenance {
    fn validate(&self) -> Result<(), ImageDeclarationError> {
        let repository = self.repository.as_str();
        if repository.is_empty()
            || repository.trim() != repository
            || repository.chars().any(char::is_control)
        {
            return Err(ImageDeclarationError::InvalidSourceRepository(
                self.repository.clone(),
            ));
        }
        if self.commit.len() != GIT_COMMIT_HEX_LEN || !is_lower_hex(&self.commit) {
            return Err(ImageDeclarationError::InvalidSourceCommit(
                self.commit.clone(),
            ));
        }
        Ok(())
    }
}

/// Builds the canonical runtime alias
/// `runtime.invalid/<namespace>/<component>/<dependency>:cfg-<hex>` for a
/// newly normalized third-party image, where `<hex>` is the 64 lowercase hex
/// characters of `config_digest`.
///
/// The suffix comes from the config digest, never from an archive or registry
/// digest. Each segment must pass the generic segment rule, and the alias as a
/// whole must then be a valid Docker reference — so a segment such as `app-`,
/// whose trailing separator Docker's path grammar refuses, is refused here
/// rather than normalized into something else.
///
/// # Errors
///
/// Returns [`ImageDeclarationError::InvalidSegment`] for a segment failing
/// the generic rule, [`ImageDeclarationError::InvalidDigest`] for a malformed
/// `config_digest`, and [`ImageDeclarationError::InvalidRuntimeAlias`] when
/// the assembled alias is not a valid Docker reference.
pub fn canonical_runtime_alias(
    namespace: &str,
    component: &str,
    dependency: &str,
    config_digest: &str,
) -> Result<String, ImageDeclarationError> {
    validate_segment(SegmentField::Namespace, namespace)?;
    validate_segment(SegmentField::Component, component)?;
    validate_segment(SegmentField::Dependency, dependency)?;
    let hex = validate_digest(DigestField::Config, config_digest)?;
    let alias = format!(
        "{RUNTIME_ALIAS_REGISTRY}/{namespace}/{component}/{dependency}:{RUNTIME_ALIAS_TAG_PREFIX}{hex}"
    );
    match parse_tagged_reference(&alias) {
        // The domain contains a `.`, so normalization keeps it and prefixes
        // nothing: a valid alias is its own normalized form.
        Ok(_) => Ok(alias),
        Err(source) => Err(ImageDeclarationError::InvalidRuntimeAlias { alias, source }),
    }
}

/// Reports whether `value` is a valid identifier segment: nonempty lowercase
/// ASCII, an alphanumeric first character, then only alphanumerics, `-` and
/// `_`.
///
/// This is the rule for a declaration's `owner.namespace`, `owner.component`
/// and `dependency`, and for the namespace a caller supplies. It refuses a
/// slash, a placeholder, traversal and an empty segment by construction.
#[must_use]
pub fn is_valid_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn validate_segment(field: SegmentField, value: &str) -> Result<(), ImageDeclarationError> {
    if is_valid_segment(value) {
        Ok(())
    } else {
        Err(ImageDeclarationError::InvalidSegment {
            field,
            value: value.to_string(),
        })
    }
}

/// Checks `value` is `sha256:` and 64 lowercase hex characters, returning the
/// hex.
fn validate_digest(field: DigestField, value: &str) -> Result<&str, ImageDeclarationError> {
    value
        .strip_prefix(SHA256_DIGEST_PREFIX)
        .filter(|hex| hex.len() == IMAGE_DIGEST_HEX_LEN && is_lower_hex(hex))
        .ok_or_else(|| ImageDeclarationError::InvalidDigest {
            field,
            value: value.to_string(),
        })
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A reference reduced to what makes two references name the same thing:
/// the normalized registry and path, and the explicit tag, case-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NormalizedReference {
    domain: String,
    path: String,
    tag: String,
}

impl NormalizedReference {
    /// Returns the registry host with any port removed.
    pub(crate) fn host(&self) -> &str {
        if self.domain.starts_with('[') {
            // An IPv6 host is bracketed, and its colons are not a port.
            self.domain
                .find(']')
                .and_then(|end| self.domain.get(..=end))
                .unwrap_or(&self.domain)
        } else {
            self.domain
                .split_once(':')
                .map_or(self.domain.as_str(), |(host, _)| host)
        }
    }
}

/// Parses an explicit `name:tag` reference and returns its normalized form.
///
/// # Errors
///
/// Returns the [`ReferenceError`] naming the first rule `reference` breaks.
pub(crate) fn parse_tagged_reference(
    reference: &str,
) -> Result<NormalizedReference, ReferenceError> {
    if reference.is_empty() {
        return Err(ReferenceError::Empty);
    }
    if reference.contains('@') {
        return Err(ReferenceError::DigestNotAllowed);
    }
    let (name, tag) = split_tag(reference).ok_or(ReferenceError::MissingTag)?;
    if !is_valid_tag(tag) {
        return Err(ReferenceError::InvalidTag(tag.to_string()));
    }
    let (domain, path) = normalize_name(reference, name)?;
    Ok(NormalizedReference {
        domain,
        path,
        tag: tag.to_string(),
    })
}

/// Checks `repository` is a fully qualified canonical repository name: no
/// tag, no digest, and already exactly its own normalized form.
fn validate_canonical_repository(repository: &str) -> Result<(), ReferenceError> {
    if repository.is_empty() {
        return Err(ReferenceError::Empty);
    }
    if repository.contains('@') {
        return Err(ReferenceError::DigestNotAllowed);
    }
    if split_tag(repository).is_some() {
        return Err(ReferenceError::TagNotAllowed);
    }
    let (domain, path) = normalize_name(repository, repository)?;
    let normalized = format!("{domain}/{path}");
    if normalized == repository {
        Ok(())
    } else {
        Err(ReferenceError::NotCanonical { normalized })
    }
}

/// Splits `reference` at its tag separator: the last `:` after the last `/`.
///
/// A `:` before the first `/` belongs to a registry port and is never the tag
/// separator.
fn split_tag(reference: &str) -> Option<(&str, &str)> {
    let colon = reference.rfind(':')?;
    if reference.rfind('/').is_some_and(|slash| slash > colon) {
        return None;
    }
    Some((reference.get(..colon)?, reference.get(colon + 1..)?))
}

/// Normalizes and validates a repository `name`, the way distribution/reference
/// v0.6.0's `ParseNormalizedNamed` does, returning its registry and path.
///
/// `whole` is the full input, checked against the bare-identifier rule as
/// that function checks it.
fn normalize_name(whole: &str, name: &str) -> Result<(String, String), ReferenceError> {
    if whole.len() == IMAGE_DIGEST_HEX_LEN && is_lower_hex(whole) {
        return Err(ReferenceError::HexIdentifier);
    }
    let (domain, path) = split_docker_domain(name);
    if path.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ReferenceError::Uppercase(path));
    }
    if !is_valid_domain_and_port(&domain) {
        return Err(ReferenceError::InvalidDomain(domain));
    }
    if !path.split('/').all(is_valid_path_component) {
        return Err(ReferenceError::InvalidPath(path));
    }
    if path.len() > MAX_REPOSITORY_PATH_BYTES {
        return Err(ReferenceError::PathTooLong(path.len()));
    }
    Ok((domain, path))
}

/// distribution/reference v0.6.0's `splitDockerDomain`.
fn split_docker_domain(name: &str) -> (String, String) {
    let (domain, remote) = match name.split_once('/') {
        None => (DOCKER_DEFAULT_DOMAIN, name),
        Some((first, rest)) => {
            if first == DOCKER_LOCALHOST {
                (first, rest)
            } else if first == DOCKER_LEGACY_DEFAULT_DOMAIN {
                (DOCKER_DEFAULT_DOMAIN, rest)
            } else if first.contains(['.', ':']) || first.bytes().any(|b| b.is_ascii_uppercase()) {
                (first, rest)
            } else {
                (DOCKER_DEFAULT_DOMAIN, name)
            }
        }
    };
    let remote = if domain == DOCKER_DEFAULT_DOMAIN && !remote.contains('/') {
        format!("{DOCKER_OFFICIAL_REPO_PREFIX}{remote}")
    } else {
        remote.to_string()
    };
    (domain.to_string(), remote)
}

/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn is_valid_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    tag.len() <= MAX_TAG_BYTES
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// `[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*`: lowercase alphanumeric runs
/// joined by one `.`, one `_`, two `_`, or any number of `-`.
fn is_valid_path_component(component: &str) -> bool {
    let is_alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = component.as_bytes();
    let mut index = 0;
    loop {
        let run = bytes
            .get(index..)
            .unwrap_or_default()
            .iter()
            .take_while(|byte| is_alphanumeric(byte))
            .count();
        if run == 0 {
            return false;
        }
        index += run;
        let Some(rest) = bytes.get(index..).filter(|rest| !rest.is_empty()) else {
            return true;
        };
        let separator_len = rest
            .iter()
            .take_while(|byte| !is_alphanumeric(byte))
            .count();
        let separator = rest.get(..separator_len).unwrap_or_default();
        let valid = matches!(separator, b"." | b"_" | b"__")
            || (!separator.is_empty() && separator.iter().all(|byte| *byte == b'-'));
        if !valid {
            return false;
        }
        index += separator_len;
    }
}

/// `(?:domainName|ipv6address)(?::[0-9]+)?`.
fn is_valid_domain_and_port(domain: &str) -> bool {
    let (host_valid, port) = if let Some(bracketed) = domain.strip_prefix('[') {
        let Some((address, rest)) = bracketed.split_once(']') else {
            return false;
        };
        let address_valid = !address.is_empty()
            && address
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':');
        let port = if rest.is_empty() {
            None
        } else if let Some(port) = rest.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        };
        (address_valid, port)
    } else {
        let (host, port) = match domain.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (domain, None),
        };
        (host.split('.').all(is_valid_domain_component), port)
    };
    host_valid
        && port
            .is_none_or(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

/// `[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]`.
fn is_valid_domain_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(first), Some(last)) => {
            first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        }
        _ => false,
    }
}

/// Reports whether `version` is a canonical `SemVer` 2.0.0 version: explicit
/// major, minor and patch without leading zeros, an optional prerelease whose
/// numeric identifiers carry no leading zeros, and optional build metadata,
/// whose numeric identifiers may.
fn is_canonical_semver(version: &str) -> bool {
    let (rest, build) = match version.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (version, None),
    };
    let (core, prerelease) = match rest.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (rest, None),
    };
    let mut parts = core.split('.');
    let core_valid =
        (0..3).all(|_| parts.next().is_some_and(is_numeric_identifier)) && parts.next().is_none();
    core_valid
        && prerelease.is_none_or(|prerelease| {
            prerelease.split('.').all(|identifier| {
                is_alphanumeric_identifier(identifier)
                    && (!identifier.bytes().all(|byte| byte.is_ascii_digit())
                        || is_numeric_identifier(identifier))
            })
        })
        && build.is_none_or(|build| build.split('.').all(is_alphanumeric_identifier))
}

/// `0|[1-9][0-9]*`.
fn is_numeric_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.bytes().all(|byte| byte.is_ascii_digit())
        && (identifier == "0" || !identifier.starts_with('0'))
}

/// `[0-9A-Za-z-]+`.
fn is_alphanumeric_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DigestField, ImageArchitecture, ImageDeclaration, ImageDeclarationError, ImageOs,
        ImageOwner, ImagePlatform, ImageProvenance, ProductBuildProvenance, ReferenceError,
        ReferenceLifecycle, RegistryProvenance, SegmentField, canonical_runtime_alias,
        is_canonical_semver, is_valid_segment, parse_tagged_reference,
    };
    use crate::manifest::TargetArch;

    /// Names which reference rule a refusal must report.
    type ReferenceCheck = fn(&ReferenceError) -> bool;

    const CONFIG: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PINNED: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const SELECTED: &str =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const ALIAS: &str = "runtime.invalid/example-product/example-app/database:cfg-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// The issue's example wire shape, verbatim.
    fn example_wire() -> serde_json::Value {
        json!({
            "schema": 1,
            "owner": {"namespace": "example-product", "component": "example-app"},
            "dependency": "database",
            "public_refs": [ALIAS],
            "platform": {"os": "linux", "architecture": "amd64", "variant": null},
            "config_digest": CONFIG,
            "reference_lifecycle": "managed_runtime",
            "provenance": {
                "kind": "registry",
                "repository": "docker.io/library/postgres",
                "tag": "18.4",
                "version": "18.4.0",
                "pinned_digest": PINNED,
                "selected_manifest_digest": SELECTED
            }
        })
    }

    fn registry() -> RegistryProvenance {
        RegistryProvenance {
            repository: "docker.io/library/postgres".to_string(),
            tag: "18.4".to_string(),
            version: Some("18.4.0".to_string()),
            pinned_digest: PINNED.to_string(),
            selected_manifest_digest: SELECTED.to_string(),
        }
    }

    fn owner() -> ImageOwner {
        ImageOwner {
            namespace: "example-product".to_string(),
            component: "example-app".to_string(),
        }
    }

    fn platform(architecture: ImageArchitecture, variant: Option<&str>) -> ImagePlatform {
        ImagePlatform {
            os: ImageOs::Linux,
            architecture,
            variant: variant.map(str::to_string),
        }
    }

    /// A product-built image keeping the tag its producer chose.
    fn product_build() -> ImageDeclaration {
        ImageDeclaration {
            schema: 1,
            owner: owner(),
            dependency: "web".to_string(),
            public_refs: vec!["ghcr.io/example/example-app:1.2.3".to_string()],
            platform: platform(ImageArchitecture::Arm64, Some("v8")),
            config_digest: CONFIG.to_string(),
            reference_lifecycle: ReferenceLifecycle::SharedExternal,
            provenance: ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: "https://example.invalid/example-app.git".to_string(),
                commit: SOURCE_COMMIT.to_string(),
            }),
        }
    }

    fn decode(value: serde_json::Value) -> Result<ImageDeclaration, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn with_refs(refs: &[&str]) -> ImageDeclaration {
        let mut declaration = product_build();
        declaration.public_refs = refs.iter().map(|value| (*value).to_string()).collect();
        declaration
    }

    fn reference_error(reference: &str) -> ReferenceError {
        parse_tagged_reference(reference).expect_err(reference)
    }

    #[test]
    fn the_example_wire_shape_decodes_validates_and_round_trips_verbatim() {
        let declaration = decode(example_wire()).expect("the example decodes");
        declaration.validate().expect("the example is valid");
        assert_eq!(declaration.public_refs, vec![ALIAS.to_string()]);
        assert_eq!(declaration.platform.variant, None);
        assert_eq!(
            serde_json::to_value(&declaration).expect("serializes"),
            example_wire(),
            "the explicit null variant and every field are written back"
        );
    }

    #[test]
    fn both_provenance_arms_lifecycles_architectures_and_variants_round_trip() {
        let mut declarations = Vec::new();
        for architecture in [ImageArchitecture::Amd64, ImageArchitecture::Arm64] {
            for variant in [None, Some("v8")] {
                for lifecycle in [
                    ReferenceLifecycle::ManagedRuntime,
                    ReferenceLifecycle::SharedExternal,
                ] {
                    let mut built = product_build();
                    built.platform = platform(architecture, variant);
                    built.reference_lifecycle = lifecycle;
                    declarations.push(built.clone());
                    let mut pulled = built;
                    pulled.provenance = ImageProvenance::Registry(registry());
                    declarations.push(pulled.clone());
                    let mut unversioned = pulled;
                    unversioned.provenance = ImageProvenance::Registry(RegistryProvenance {
                        version: None,
                        ..registry()
                    });
                    declarations.push(unversioned);
                }
            }
        }
        for declaration in declarations {
            declaration.validate().expect("every combination is valid");
            let wire = serde_json::to_string(&declaration).expect("serializes");
            let restored: ImageDeclaration = serde_json::from_str(&wire).expect("decodes");
            assert_eq!(restored, declaration, "wire {wire}");
        }
    }

    #[test]
    fn the_architecture_mapping_follows_the_artifact_target() {
        assert_eq!(
            ImageArchitecture::for_target(TargetArch::X86_64),
            ImageArchitecture::Amd64
        );
        assert_eq!(
            ImageArchitecture::for_target(TargetArch::Aarch64),
            ImageArchitecture::Arm64
        );
    }

    #[test]
    fn missing_explicit_nullable_fields_do_not_decode() {
        let mut value = example_wire();
        value["platform"]
            .as_object_mut()
            .expect("an object")
            .remove("variant");
        assert!(decode(value).is_err(), "a missing variant must not decode");

        let mut value = example_wire();
        value["provenance"]
            .as_object_mut()
            .expect("an object")
            .remove("version");
        assert!(decode(value).is_err(), "a missing version must not decode");

        let mut value = example_wire();
        value["provenance"]["version"] = serde_json::Value::Null;
        let declaration = decode(value).expect("an explicit null version decodes");
        declaration.validate().expect("and is valid");
    }

    #[test]
    fn unknown_fields_are_refused_at_every_level_of_the_image_object() {
        let paths: [&[&str]; 5] = [&[], &["owner"], &["platform"], &["provenance"], &[]];
        let keys = [
            "surprise",
            "surprise",
            "surprise",
            "surprise",
            "source_policy",
        ];
        for (path, key) in paths.into_iter().zip(keys) {
            let mut value = example_wire();
            let mut target = &mut value;
            for step in path {
                target = &mut target[*step];
            }
            target
                .as_object_mut()
                .expect("an object")
                .insert(key.to_string(), json!("reuse"));
            let error = decode(value).expect_err("an unknown field must be refused");
            assert!(
                error.to_string().contains("unknown field"),
                "{path:?}/{key}: {error}"
            );
        }

        // The same for the product-build arm.
        let mut value = serde_json::to_value(product_build()).expect("serializes");
        value["provenance"]["surprise"] = json!(true);
        assert!(decode(value).is_err());
    }

    #[test]
    fn unknown_enum_values_and_mixed_provenance_arms_are_refused() {
        let cases: [(&[&str], serde_json::Value); 5] = [
            (&["platform", "os"], json!("windows")),
            (&["platform", "architecture"], json!("386")),
            (&["platform", "architecture"], json!("x86_64")),
            (&["reference_lifecycle"], json!("owned")),
            (&["provenance", "kind"], json!("local")),
        ];
        for (path, replacement) in cases {
            let mut value = example_wire();
            let mut target = &mut value;
            for step in path {
                target = &mut target[*step];
            }
            *target = replacement;
            assert!(decode(value).is_err(), "{path:?} must not decode");
        }

        // A product build carrying a registry-only field, and a registry
        // image carrying the product-build commit.
        let mut value = serde_json::to_value(product_build()).expect("serializes");
        value["provenance"]["pinned_digest"] = json!(PINNED);
        assert!(decode(value).is_err(), "a product build is not a registry");
        let mut value = example_wire();
        value["provenance"]["commit"] = json!(SOURCE_COMMIT);
        assert!(decode(value).is_err(), "a registry image carries no commit");

        // A provenance with no `kind` at all.
        let mut value = example_wire();
        value["provenance"]
            .as_object_mut()
            .expect("an object")
            .remove("kind");
        assert!(decode(value).is_err());
    }

    #[test]
    fn an_unsupported_schema_is_refused() {
        let mut declaration = product_build();
        declaration.schema = 2;
        assert!(matches!(
            declaration.validate(),
            Err(ImageDeclarationError::UnsupportedSchema { found: 2 })
        ));
    }

    #[test]
    fn segments_are_lowercase_identifiers_and_nothing_else() {
        for valid in [
            "a",
            "0",
            "example-product",
            "a_b-c",
            "app-",
            "a___b",
            "a--b",
        ] {
            assert!(is_valid_segment(valid), "{valid:?}");
        }
        for invalid in [
            "",
            "-a",
            "_a",
            "Example",
            "a/b",
            "..",
            ".",
            "a.b",
            "${NAMESPACE}",
            "<namespace>",
            "a b",
            "é",
        ] {
            assert!(!is_valid_segment(invalid), "{invalid:?}");
        }

        for (field, set) in [
            (
                SegmentField::Namespace,
                (|d: &mut ImageDeclaration, v: &str| d.owner.namespace = v.to_string())
                    as fn(&mut ImageDeclaration, &str),
            ),
            (SegmentField::Component, |d, v| {
                d.owner.component = v.to_string();
            }),
            (SegmentField::Dependency, |d, v| {
                d.dependency = v.to_string();
            }),
        ] {
            for invalid in ["", "a/b", "../x", "${X}"] {
                let mut declaration = product_build();
                set(&mut declaration, invalid);
                assert!(
                    matches!(
                        declaration.validate(),
                        Err(ImageDeclarationError::InvalidSegment { field: got, ref value })
                            if got == field && value == invalid
                    ),
                    "{field} {invalid:?}"
                );
            }
        }
    }

    #[test]
    fn public_refs_must_be_nonempty_explicit_tagged_references() {
        assert!(matches!(
            with_refs(&[]).validate(),
            Err(ImageDeclarationError::EmptyPublicRefs)
        ));

        let cases: [(&str, ReferenceCheck); 13] = [
            ("", |e| matches!(e, ReferenceError::Empty)),
            ("${IMAGE}:18.4", |e| {
                matches!(e, ReferenceError::Uppercase(_))
            }),
            ("postgres", |e| matches!(e, ReferenceError::MissingTag)),
            ("docker.io/library/postgres", |e| {
                matches!(e, ReferenceError::MissingTag)
            }),
            ("registry.example:5000/app", |e| {
                matches!(e, ReferenceError::MissingTag)
            }),
            (
                "postgres@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                |e| matches!(e, ReferenceError::DigestNotAllowed),
            ),
            (
                "postgres:18.4@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                |e| matches!(e, ReferenceError::DigestNotAllowed),
            ),
            ("postgres :18.4", |e| {
                matches!(e, ReferenceError::InvalidPath(_))
            }),
            ("postgres:18.4 ", |e| {
                matches!(e, ReferenceError::InvalidTag(_))
            }),
            ("${image}:18.4", |e| {
                matches!(e, ReferenceError::InvalidPath(_))
            }),
            ("app:${TAG}", |e| matches!(e, ReferenceError::InvalidTag(_))),
            ("Example/App:1", |e| {
                matches!(e, ReferenceError::Uppercase(_))
            }),
            ("bad_host.example/app:1", |e| {
                matches!(e, ReferenceError::InvalidDomain(_))
            }),
        ];
        for (reference, is_expected) in cases {
            let error = with_refs(&[reference])
                .validate()
                .expect_err("an invalid reference must be refused");
            let ImageDeclarationError::InvalidReference {
                reference: ref got,
                ref source,
            } = error
            else {
                panic!("{reference:?}: got {error:?}");
            };
            assert_eq!(got, reference);
            assert!(is_expected(source), "{reference:?}: got {source:?}");
        }
    }

    #[test]
    fn a_registry_port_colon_is_not_the_tag_separator() {
        with_refs(&[
            "localhost:5000/app:1.0",
            "registry.example:5000/team/app:v2",
            "[::1]:5000/app:1",
            "Registry.Example/app:1",
            "localhost:5000",
        ])
        .validate()
        .expect("ports, IPv6 hosts and uppercase registries are valid");
        assert!(matches!(
            reference_error("registry.example:/app:1"),
            ReferenceError::InvalidDomain(_)
        ));
        assert!(matches!(
            reference_error("registry.example:50a0/app:1"),
            ReferenceError::InvalidDomain(_)
        ));
    }

    #[test]
    fn path_component_separators_follow_the_docker_grammar() {
        for valid in ["a_b:1", "a__b:1", "a.b:1", "a-b:1", "a---b:1", "a/b.c/d:1"] {
            parse_tagged_reference(valid).expect(valid);
        }
        for invalid in [
            "a___b:1", "a..b:1", "a._b:1", "a-:1", "_a:1", "a/:1", "a//b:1",
        ] {
            assert!(
                matches!(reference_error(invalid), ReferenceError::InvalidPath(_)),
                "{invalid}"
            );
        }
    }

    #[test]
    fn tags_follow_the_docker_grammar_and_length_limit() {
        let longest = format!("_{}", "a".repeat(127));
        parse_tagged_reference(&format!("app:{longest}")).expect("128 bytes is the limit");
        for invalid in [
            format!("app:{longest}a"),
            "app:.1".to_string(),
            "app:-1".to_string(),
            "app:".to_string(),
            "app:a+b".to_string(),
        ] {
            assert!(
                matches!(reference_error(&invalid), ReferenceError::InvalidTag(_)),
                "{invalid}"
            );
        }
    }

    #[test]
    fn the_normalized_repository_path_is_limited_to_255_bytes() {
        // A registry name keeps its path as written.
        let at_limit = format!("registry.example/{}:1", "a".repeat(255));
        parse_tagged_reference(&at_limit).expect("255 bytes is the limit");
        let over = format!("registry.example/{}:1", "a".repeat(256));
        assert!(matches!(
            reference_error(&over),
            ReferenceError::PathTooLong(256)
        ));

        // A familiar name is measured after `library/` is prefixed.
        let familiar = format!("{}:1", "a".repeat(247));
        parse_tagged_reference(&familiar).expect("247 + 8 bytes is the limit");
        let familiar_over = format!("{}:1", "a".repeat(248));
        assert!(matches!(
            reference_error(&familiar_over),
            ReferenceError::PathTooLong(256)
        ));
    }

    #[test]
    fn duplicates_are_found_by_normalized_name_and_case_sensitive_tag() {
        let spellings = [
            "postgres:18.4",
            "docker.io/postgres:18.4",
            "index.docker.io/library/postgres:18.4",
            "docker.io/library/postgres:18.4",
        ];
        for first in spellings {
            for second in spellings {
                if first == second {
                    continue;
                }
                assert!(
                    matches!(
                        with_refs(&[first, second]).validate(),
                        Err(ImageDeclarationError::DuplicateReference { ref reference, first: ref earlier })
                            if reference == second && earlier == first
                    ),
                    "{first} / {second}"
                );
            }
        }
        // The literal is preserved as signed rather than rewritten.
        let declaration = with_refs(&["postgres:18.4", "postgres:18.4-alpine"]);
        declaration.validate().expect("two different tags");
        assert_eq!(declaration.public_refs[0], "postgres:18.4");

        // Tags compare case-sensitively; registries are not folded either.
        with_refs(&["app:v1", "app:V1"])
            .validate()
            .expect("tags are case-sensitive");
        with_refs(&["Registry.Example/app:1", "registry.example/app:1"])
            .validate()
            .expect("registry spellings are compared as written");
        // The same literal twice is a duplicate too.
        assert!(matches!(
            with_refs(&["app:1", "app:1"]).validate(),
            Err(ImageDeclarationError::DuplicateReference { .. })
        ));
    }

    #[test]
    fn an_empty_variant_is_refused_and_a_present_one_kept() {
        let mut declaration = product_build();
        declaration.platform.variant = Some(String::new());
        assert!(matches!(
            declaration.validate(),
            Err(ImageDeclarationError::EmptyVariant)
        ));
        declaration.platform.variant = Some("v7".to_string());
        declaration.validate().expect("a present variant is valid");
    }

    #[test]
    fn every_digest_is_full_lowercase_sha256() {
        let bad = [
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "sha256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "sha256:cccc",
            "sha512:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "sha256:gccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ];
        for value in bad {
            let mut declaration = product_build();
            declaration.config_digest = value.to_string();
            assert!(matches!(
                declaration.validate(),
                Err(ImageDeclarationError::InvalidDigest {
                    field: DigestField::Config,
                    ..
                })
            ));

            for field in [DigestField::Pinned, DigestField::SelectedManifest] {
                let mut provenance = registry();
                match field {
                    DigestField::Pinned => provenance.pinned_digest = value.to_string(),
                    _ => provenance.selected_manifest_digest = value.to_string(),
                }
                let mut declaration = product_build();
                declaration.provenance = ImageProvenance::Registry(provenance);
                assert!(
                    matches!(
                        declaration.validate(),
                        Err(ImageDeclarationError::InvalidDigest { field: got, .. }) if got == field
                    ),
                    "{field} {value}"
                );
            }
        }
    }

    #[test]
    fn the_three_digests_name_different_objects_and_need_not_agree() {
        // Config, pinned index and selected child manifest all differ, and the
        // declaration is valid: proving their relationship is release
        // assembly's job, not this schema's.
        let declaration = decode(example_wire()).expect("decodes");
        let ImageProvenance::Registry(registry) = &declaration.provenance else {
            panic!("the example is a registry image");
        };
        assert_ne!(declaration.config_digest, registry.pinned_digest);
        assert_ne!(registry.pinned_digest, registry.selected_manifest_digest);
        assert_ne!(declaration.config_digest, registry.selected_manifest_digest);
        declaration.validate().expect("valid");
    }

    #[test]
    fn a_registry_repository_is_fully_qualified_and_canonical() {
        for valid in [
            "docker.io/library/postgres",
            "ghcr.io/example/app",
            "localhost/app",
            "registry.example:5000/team/app",
        ] {
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::Registry(RegistryProvenance {
                repository: valid.to_string(),
                ..registry()
            });
            declaration.validate().expect(valid);
        }
        let cases: [(&str, ReferenceCheck); 8] = [
            ("postgres", |e| {
                matches!(e, ReferenceError::NotCanonical { .. })
            }),
            ("library/postgres", |e| {
                matches!(e, ReferenceError::NotCanonical { .. })
            }),
            (
                "docker.io/postgres",
                |e| matches!(e, ReferenceError::NotCanonical { normalized } if normalized == "docker.io/library/postgres"),
            ),
            ("index.docker.io/library/postgres", |e| {
                matches!(e, ReferenceError::NotCanonical { .. })
            }),
            ("docker.io/library/postgres:18.4", |e| {
                matches!(e, ReferenceError::TagNotAllowed)
            }),
            (
                "docker.io/library/postgres@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                |e| matches!(e, ReferenceError::DigestNotAllowed),
            ),
            (
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                |e| matches!(e, ReferenceError::HexIdentifier),
            ),
            ("", |e| matches!(e, ReferenceError::Empty)),
        ];
        for (repository, is_expected) in cases {
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::Registry(RegistryProvenance {
                repository: repository.to_string(),
                ..registry()
            });
            let error = declaration.validate().expect_err(repository);
            let ImageDeclarationError::InvalidRegistryRepository { ref source, .. } = error else {
                panic!("{repository}: got {error:?}");
            };
            assert!(is_expected(source), "{repository}: got {source:?}");
        }
    }

    #[test]
    fn a_registry_tag_follows_the_tag_grammar() {
        for invalid in ["", "-1", ".1", "18 4", &"a".repeat(129)] {
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::Registry(RegistryProvenance {
                tag: invalid.to_string(),
                ..registry()
            });
            assert!(matches!(
                declaration.validate(),
                Err(ImageDeclarationError::InvalidRegistryTag(_))
            ));
        }
    }

    #[test]
    fn a_registry_version_is_canonical_semver_or_null() {
        for valid in [
            "18.4.0",
            "0.0.0",
            "1.0.0-rc.1",
            "1.0.0-0",
            "1.0.0-alpha-1",
            "1.0.0-0a",
            "1.0.0+build.001",
            "1.0.0-rc.1+007",
            "10.20.30",
        ] {
            assert!(is_canonical_semver(valid), "{valid}");
        }
        for invalid in [
            "",
            "18.4",
            "18",
            "v18.4.0",
            "01.0.0",
            "1.02.0",
            "1.0.03",
            "1.0.0-01",
            "1.0.0-",
            "1.0.0+",
            "1.0.0-a..b",
            "1.0.0+a_b",
            "1.0.0.0",
            " 1.0.0",
            "1.0.0 ",
            "1.0.0-rc.1+",
        ] {
            assert!(!is_canonical_semver(invalid), "{invalid}");
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::Registry(RegistryProvenance {
                version: Some(invalid.to_string()),
                ..registry()
            });
            assert!(matches!(
                declaration.validate(),
                Err(ImageDeclarationError::InvalidRegistryVersion(_))
            ));
        }
    }

    #[test]
    fn a_product_build_source_is_opaque_and_its_commit_is_the_git_width() {
        // No per-field byte cap and no URL scheme: an identifier longer than
        // 256 bytes and one that is no URL at all are both preserved literally.
        for repository in [
            format!("https://example.invalid/{}", "r".repeat(300)),
            "git@example.invalid:team/app.git".to_string(),
            "an opaque source name".to_string(),
        ] {
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: repository.clone(),
                commit: SOURCE_COMMIT.to_string(),
            });
            declaration
                .validate()
                .expect("an opaque repository is valid");
            let restored: ImageDeclaration =
                serde_json::from_str(&serde_json::to_string(&declaration).expect("serializes"))
                    .expect("decodes");
            assert_eq!(restored, declaration);
        }
        for repository in ["", " app", "app ", "a\nb", "a\u{7}b"] {
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: repository.to_string(),
                commit: SOURCE_COMMIT.to_string(),
            });
            assert!(matches!(
                declaration.validate(),
                Err(ImageDeclarationError::InvalidSourceRepository(_))
            ));
        }
        for commit in [
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "0123456",
            "",
        ] {
            let mut declaration = product_build();
            declaration.provenance = ImageProvenance::ProductBuild(ProductBuildProvenance {
                repository: "app".to_string(),
                commit: commit.to_string(),
            });
            assert!(
                matches!(
                    declaration.validate(),
                    Err(ImageDeclarationError::InvalidSourceCommit(_))
                ),
                "{commit}"
            );
        }
    }

    #[test]
    fn the_canonical_alias_derives_from_the_config_digest() {
        let alias = canonical_runtime_alias("example-product", "example-app", "database", CONFIG)
            .expect("valid segments");
        assert_eq!(alias, ALIAS);

        let declaration = ImageDeclaration::normalized_third_party(
            owner(),
            "database",
            platform(ImageArchitecture::Amd64, None),
            CONFIG,
            registry(),
        )
        .expect("a newly normalized image");
        assert_eq!(declaration.public_refs, vec![ALIAS.to_string()]);
        assert_eq!(
            declaration.reference_lifecycle,
            ReferenceLifecycle::ManagedRuntime
        );
        assert_eq!(declaration.canonical_runtime_alias().expect("valid"), ALIAS);
        // The same wire object the example states, built rather than typed.
        assert_eq!(
            serde_json::to_value(&declaration).expect("serializes"),
            example_wire()
        );

        // Neither registry digest reaches the alias.
        let ImageProvenance::Registry(provenance) = &declaration.provenance else {
            panic!("a registry image");
        };
        let pinned_hex = provenance.pinned_digest.trim_start_matches("sha256:");
        assert!(!ALIAS.contains(pinned_hex));
    }

    #[test]
    fn a_product_tag_is_preserved_rather_than_rewritten() {
        let declaration = product_build();
        declaration.validate().expect("a product tag is valid");
        let restored: ImageDeclaration =
            serde_json::from_str(&serde_json::to_string(&declaration).expect("serializes"))
                .expect("decodes");
        assert_eq!(
            restored.public_refs,
            vec!["ghcr.io/example/example-app:1.2.3".to_string()]
        );
    }

    #[test]
    fn an_alias_the_docker_grammar_refuses_is_refused_rather_than_normalized() {
        // Each segment passes the generic rule, yet the alias built from it is
        // not a Docker reference: a trailing separator, or three underscores.
        for (namespace, component, dependency) in [
            ("app-", "example-app", "database"),
            ("example-product", "a___b", "database"),
            ("example-product", "example-app", "db_"),
        ] {
            let error = canonical_runtime_alias(namespace, component, dependency, CONFIG)
                .expect_err("an invalid alias must be refused");
            assert!(
                matches!(
                    error,
                    ImageDeclarationError::InvalidRuntimeAlias {
                        source: ReferenceError::InvalidPath(_),
                        ..
                    }
                ),
                "{namespace}/{component}/{dependency}: got {error:?}"
            );
        }
        // Invalid generic segments and digests are named as such.
        assert!(matches!(
            canonical_runtime_alias("Example", "app", "db", CONFIG),
            Err(ImageDeclarationError::InvalidSegment {
                field: SegmentField::Namespace,
                ..
            })
        ));
        assert!(matches!(
            canonical_runtime_alias("ns", "app", "db", PINNED.trim_start_matches("sha256:")),
            Err(ImageDeclarationError::InvalidDigest {
                field: DigestField::Config,
                ..
            })
        ));
        // A generic segment with a trailing separator stays valid where it
        // forms no alias.
        let mut declaration = product_build();
        declaration.dependency = "web-".to_string();
        declaration
            .validate()
            .expect("a generic segment is not held to the alias grammar");
    }

    #[test]
    fn the_host_of_a_reference_drops_its_port() {
        let host = |reference: &str| {
            parse_tagged_reference(reference)
                .expect(reference)
                .host()
                .to_string()
        };
        assert_eq!(host("runtime.invalid:5000/a/b/c:1"), "runtime.invalid");
        assert_eq!(host("RUNTIME.INVALID/a/b/c:1"), "RUNTIME.INVALID");
        assert_eq!(host("[::1]:5000/app:1"), "[::1]");
        assert_eq!(host("postgres:1"), "docker.io");
    }
}
