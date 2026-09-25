//! The closed shapes of an image archive's layout documents and descriptors:
//! `oci-layout`, `index.json`, the compatibility `manifest.json` and the OCI
//! image manifest.
//!
//! Each document arrives as a `serde_json::Value` the strict reader has
//! already bounded and scanned, and is classified here by hand, check by check
//! in the order the profile lists, so the first rule it breaks is the verdict.
//! Nothing relies on `deny_unknown_fields`, and nothing here reads a byte.

use serde_json::{Map, Value};

use super::{Checked, Verdict, invalid, is_digest, shape, unsupported};
use crate::package::{ContentLimits, LimitResource};
use crate::verify::{
    ExtensionField, ImageDocument, InvalidArchiveReason, PlatformLocation,
    UnsupportedArchiveFeature,
};

const OCI_LAYOUT_VERSION_KEY: &str = "imageLayoutVersion";
const OCI_LAYOUT_VERSION: &str = "1.0.0";

const SCHEMA_VERSION: &str = "schemaVersion";
const MEDIA_TYPE: &str = "mediaType";
const MANIFESTS: &str = "manifests";
const CONFIG: &str = "config";
const LAYERS: &str = "layers";
const ANNOTATIONS: &str = "annotations";
const DIGEST: &str = "digest";
const SIZE: &str = "size";
const PLATFORM: &str = "platform";
const OS: &str = "os";
const ARCHITECTURE: &str = "architecture";
const VARIANT: &str = "variant";

const SUBJECT: &str = "subject";
const ARTIFACT_TYPE: &str = "artifactType";
const URLS: &str = "urls";
const DATA: &str = "data";

const COMPAT_CONFIG: &str = "Config";
const COMPAT_REPO_TAGS: &str = "RepoTags";
const COMPAT_LAYERS: &str = "Layers";
const COMPAT_PARENT: &str = "Parent";
const COMPAT_LAYER_SOURCES: &str = "LayerSources";

/// The only `schemaVersion` either manifest format takes.
const SUPPORTED_SCHEMA_VERSION: u64 = 2;

pub(super) const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub(super) const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub(super) const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
pub(super) const OCI_GZIP_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The index descriptor annotation marking an attestation manifest.
const ATTESTATION_ANNOTATION: &str = "vnd.docker.reference.type";

/// Prefix of every standard OCI annotation the image manifest may carry.
const OCI_ANNOTATION_PREFIX: &str = "org.opencontainers.image.";
/// The standard OCI annotations the image manifest may carry, after
/// [`OCI_ANNOTATION_PREFIX`].
const OCI_MANIFEST_ANNOTATIONS: &[&str] = &[
    "created",
    "authors",
    "url",
    "documentation",
    "source",
    "version",
    "revision",
    "vendor",
    "licenses",
    "title",
    "description",
    "base.name",
    "base.digest",
];
/// The one non-OCI annotation the image manifest may carry.
const BASHBREW_ARCH_ANNOTATION: &str = "com.docker.official-images.bashbrew.arch";

/// The fields that refer outside the archive, in the order they are checked.
const DESCRIPTOR_EXTENSIONS: &[(&str, ExtensionField)] = &[
    (SUBJECT, ExtensionField::Subject),
    (ARTIFACT_TYPE, ExtensionField::ArtifactType),
    (URLS, ExtensionField::Urls),
    (DATA, ExtensionField::Data),
];
/// The fields a manifest or index document may not carry, in the order they
/// are checked.
const DOCUMENT_EXTENSIONS: &[(&str, ExtensionField)] = &[
    (SUBJECT, ExtensionField::Subject),
    (ARTIFACT_TYPE, ExtensionField::ArtifactType),
];

/// What a descriptor describes, which decides the keys and media types it
/// may carry and the limit its `size` is held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// An `index.json` descriptor, naming the image manifest.
    IndexManifest {
        /// Its index in `manifests`.
        index: usize,
    },
    /// The image manifest's config descriptor.
    Config,
    /// One of the image manifest's layer descriptors.
    Layer {
        /// Its position in `layers`.
        position: usize,
    },
}

impl Role {
    fn keys(self) -> &'static [&'static str] {
        match self {
            Role::IndexManifest { .. } => &[MEDIA_TYPE, DIGEST, SIZE, PLATFORM, ANNOTATIONS],
            Role::Config => &[MEDIA_TYPE, DIGEST, SIZE, PLATFORM],
            Role::Layer { .. } => &[MEDIA_TYPE, DIGEST, SIZE],
        }
    }

    fn size_limit(self) -> LimitResource {
        match self {
            Role::IndexManifest { .. } => LimitResource::ImageManifestJson,
            Role::Config => LimitResource::ConfigJson,
            Role::Layer { .. } => LimitResource::StoredLayerBlob,
        }
    }

    fn platform_location(self) -> Option<PlatformLocation> {
        match self {
            Role::IndexManifest { index } => Some(PlatformLocation::IndexDescriptor { index }),
            Role::Config => Some(PlatformLocation::ConfigDescriptor),
            Role::Layer { .. } => None,
        }
    }

    /// Checks `media_type` against the media types this role admits.
    fn check_media_type(self, media_type: &str) -> Checked<()> {
        let refusal = match self {
            Role::IndexManifest { .. } => match media_type {
                OCI_MANIFEST_MEDIA_TYPE => return Ok(()),
                OCI_INDEX_MEDIA_TYPE | DOCKER_MANIFEST_LIST_MEDIA_TYPE => {
                    UnsupportedArchiveFeature::NestedIndex
                }
                _ => UnsupportedArchiveFeature::ManifestMediaType,
            },
            Role::Config => match media_type {
                OCI_CONFIG_MEDIA_TYPE => return Ok(()),
                _ => UnsupportedArchiveFeature::ConfigMediaType,
            },
            Role::Layer { position } => match media_type {
                OCI_LAYER_MEDIA_TYPE | OCI_GZIP_LAYER_MEDIA_TYPE => return Ok(()),
                _ => UnsupportedArchiveFeature::LayerMediaType { position },
            },
        };
        Err(unsupported(refusal))
    }
}

/// A platform a descriptor states: strings compared byte for byte later, and
/// a variant that is `None` when absent or null.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DescriptorPlatform {
    pub(super) os: String,
    pub(super) architecture: String,
    pub(super) variant: Option<String>,
}

/// A descriptor that passed the rules of its role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Descriptor {
    pub(super) media_type: String,
    /// The full `sha256:<hex>` digest.
    pub(super) digest: String,
    pub(super) size: u64,
    pub(super) platform: Option<DescriptorPlatform>,
    /// The annotations of an index descriptor, all string-valued.
    pub(super) annotations: Option<Map<String, Value>>,
}

impl Descriptor {
    /// Returns the digest's 64 hex characters.
    pub(super) fn hex(&self) -> &str {
        self.digest
            .strip_prefix(super::SHA256_PREFIX)
            .unwrap_or_default()
    }

    /// Returns the path of the blob this descriptor names.
    pub(super) fn blob_path(&self) -> String {
        format!("{}{}", super::BLOB_PREFIX, self.hex())
    }
}

/// Refuses the first extension field of `fields` that `object` carries.
fn refuse_extensions(
    object: &Map<String, Value>,
    document: ImageDocument,
    fields: &[(&str, ExtensionField)],
) -> Checked<()> {
    match fields.iter().find(|(key, _)| object.contains_key(*key)) {
        Some((_, field)) => Err(unsupported(UnsupportedArchiveFeature::ExtensionField {
            document,
            field: *field,
        })),
        None => Ok(()),
    }
}

/// Whether every key of `object` is one of `allowed`.
fn only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

/// Whether `value` is the JSON integer 2.
fn is_schema_version(value: Option<&Value>) -> bool {
    value.and_then(Value::as_u64) == Some(SUPPORTED_SCHEMA_VERSION)
}

/// Returns `object` if every value it holds is a string.
fn string_map(value: &Value) -> Option<&Map<String, Value>> {
    value
        .as_object()
        .filter(|object| object.values().all(Value::is_string))
}

/// Checks a descriptor against the rules of `role`, in rule order.
pub(super) fn descriptor(
    value: &Value,
    role: Role,
    document: ImageDocument,
    limits: &ContentLimits,
) -> Checked<Descriptor> {
    let object = value.as_object().ok_or_else(|| shape(document))?;
    refuse_extensions(object, document, DESCRIPTOR_EXTENSIONS)?;
    if !matches!(role, Role::IndexManifest { .. }) && object.contains_key(ANNOTATIONS) {
        return Err(unsupported(UnsupportedArchiveFeature::DescriptorAnnotation));
    }
    if !only_keys(object, role.keys()) {
        return Err(shape(document));
    }
    let media_type = object
        .get(MEDIA_TYPE)
        .and_then(Value::as_str)
        .ok_or_else(|| shape(document))?;
    role.check_media_type(media_type)?;
    let digest = object
        .get(DIGEST)
        .and_then(Value::as_str)
        .filter(|digest| is_digest(digest))
        .ok_or_else(|| shape(document))?;
    let size = object
        .get(SIZE)
        .and_then(Value::as_u64)
        .ok_or_else(|| shape(document))?;
    let size_limit = limits.resource_limit(role.size_limit());
    if size > size_limit.max {
        return Err(Verdict::Limit {
            resource: size_limit.resource,
            limit: size_limit.max,
        });
    }
    let annotations = match (role, object.get(ANNOTATIONS)) {
        (Role::IndexManifest { .. }, Some(annotations)) => {
            let annotations = string_map(annotations).ok_or_else(|| shape(document))?;
            if annotations.contains_key(ATTESTATION_ANNOTATION) {
                return Err(unsupported(UnsupportedArchiveFeature::Attestation));
            }
            Some(annotations.clone())
        }
        _ => None,
    };
    let platform = match (role.platform_location(), object.get(PLATFORM)) {
        (Some(location), Some(platform)) => {
            Some(descriptor_platform(platform, location, document)?)
        }
        _ => None,
    };
    Ok(Descriptor {
        media_type: media_type.to_string(),
        digest: digest.to_string(),
        size,
        platform,
        annotations,
    })
}

/// Checks a descriptor's `platform` object.
fn descriptor_platform(
    value: &Value,
    location: PlatformLocation,
    document: ImageDocument,
) -> Checked<DescriptorPlatform> {
    let object = value
        .as_object()
        .filter(|object| only_keys(object, &[OS, ARCHITECTURE, VARIANT]))
        .ok_or_else(|| shape(document))?;
    let string = |key: &str| object.get(key).and_then(Value::as_str);
    let os = string(OS).ok_or_else(|| shape(document))?;
    let architecture = string(ARCHITECTURE).ok_or_else(|| shape(document))?;
    let variant = match object.get(VARIANT) {
        None | Some(Value::Null) => None,
        Some(Value::String(variant)) => Some(variant.as_str()),
        Some(_) => return Err(shape(document)),
    };
    if variant == Some("") {
        return Err(invalid(InvalidArchiveReason::EmptyPlatformVariant {
            location,
        }));
    }
    Ok(DescriptorPlatform {
        os: os.to_string(),
        architecture: architecture.to_string(),
        variant: variant.map(str::to_string),
    })
}

/// Checks `oci-layout`: exactly `{"imageLayoutVersion": "1.0.0"}`.
pub(super) fn oci_layout(value: &Value) -> Checked<()> {
    let valid = value.as_object().is_some_and(|object| {
        only_keys(object, &[OCI_LAYOUT_VERSION_KEY])
            && object.get(OCI_LAYOUT_VERSION_KEY).and_then(Value::as_str)
                == Some(OCI_LAYOUT_VERSION)
    });
    if valid {
        Ok(())
    } else {
        Err(shape(ImageDocument::OciLayout))
    }
}

/// Checks `index.json` and returns its descriptors, every one naming the same
/// image manifest as the first.
pub(super) fn index(value: &Value, limits: &ContentLimits) -> Checked<Vec<Descriptor>> {
    let document = ImageDocument::Index;
    let object = value.as_object().ok_or_else(|| shape(document))?;
    refuse_extensions(object, document, DOCUMENT_EXTENSIONS)?;
    if !only_keys(object, &[SCHEMA_VERSION, MEDIA_TYPE, MANIFESTS]) {
        return Err(shape(document));
    }
    if !is_schema_version(object.get(SCHEMA_VERSION)) {
        return Err(shape(document));
    }
    if let Some(media_type) = object.get(MEDIA_TYPE)
        && media_type.as_str() != Some(OCI_INDEX_MEDIA_TYPE)
    {
        return Err(shape(document));
    }
    let manifests = object
        .get(MANIFESTS)
        .and_then(Value::as_array)
        .filter(|manifests| !manifests.is_empty())
        .ok_or_else(|| shape(document))?;
    check_count(manifests.len(), limits, LimitResource::TagsPerImage)?;
    let descriptors = manifests
        .iter()
        .enumerate()
        .map(|(index, value)| descriptor(value, Role::IndexManifest { index }, document, limits))
        .collect::<Checked<Vec<_>>>()?;
    if let Some((first, rest)) = descriptors.split_first()
        && rest
            .iter()
            .any(|other| other.digest != first.digest || other.size != first.size)
    {
        return Err(unsupported(UnsupportedArchiveFeature::MultipleImages));
    }
    Ok(descriptors)
}

/// Refuses a count above `resource`'s limit.
pub(super) fn check_count(
    count: usize,
    limits: &ContentLimits,
    resource: LimitResource,
) -> Checked<()> {
    let limit = limits.get(resource);
    if u64::try_from(count).map_or(true, |count| count > limit) {
        Err(Verdict::Limit { resource, limit })
    } else {
        Ok(())
    }
}

/// The compatibility `manifest.json` record.
pub(super) struct Compatibility {
    /// `Config`: the config blob's path.
    pub(super) config: String,
    /// `RepoTags`, literally.
    pub(super) repo_tags: Vec<String>,
    /// `Layers`: each layer blob's path, in order.
    pub(super) layers: Vec<String>,
    /// `LayerSources`, when present and not null.
    pub(super) layer_sources: Option<Map<String, Value>>,
}

/// Returns `value` as an array of strings, or `None`.
fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect()
}

/// Checks the compatibility `manifest.json` and returns its one record.
pub(super) fn compatibility(value: &Value, limits: &ContentLimits) -> Checked<Compatibility> {
    let document = ImageDocument::CompatibilityManifest;
    let records = value
        .as_array()
        .filter(|records| !records.is_empty())
        .ok_or_else(|| shape(document))?;
    let [record] = records.as_slice() else {
        return Err(unsupported(UnsupportedArchiveFeature::MultipleImages));
    };
    let record = record
        .as_object()
        .filter(|record| {
            only_keys(
                record,
                &[
                    COMPAT_CONFIG,
                    COMPAT_REPO_TAGS,
                    COMPAT_LAYERS,
                    COMPAT_PARENT,
                    COMPAT_LAYER_SOURCES,
                ],
            )
        })
        .ok_or_else(|| shape(document))?;
    let config = record
        .get(COMPAT_CONFIG)
        .and_then(Value::as_str)
        .ok_or_else(|| shape(document))?;
    let repo_tags = strings(record.get(COMPAT_REPO_TAGS))
        .filter(|tags| !tags.is_empty())
        .ok_or_else(|| shape(document))?;
    check_count(repo_tags.len(), limits, LimitResource::TagsPerImage)?;
    let layers = strings(record.get(COMPAT_LAYERS)).ok_or_else(|| shape(document))?;
    check_count(layers.len(), limits, LimitResource::LayersPerImage)?;
    match record.get(COMPAT_PARENT) {
        None => {}
        Some(Value::String(parent)) if parent.is_empty() => {}
        Some(_) => return Err(shape(document)),
    }
    let layer_sources = match record.get(COMPAT_LAYER_SOURCES) {
        None | Some(Value::Null) => None,
        Some(Value::Object(sources)) => Some(sources.clone()),
        Some(_) => return Err(shape(document)),
    };
    Ok(Compatibility {
        config: config.to_string(),
        repo_tags,
        layers,
        layer_sources,
    })
}

/// The OCI image manifest's config and layer descriptors.
pub(super) struct ImageManifest {
    pub(super) config: Descriptor,
    pub(super) layers: Vec<Descriptor>,
}

/// Checks the OCI image manifest.
pub(super) fn image_manifest(value: &Value, limits: &ContentLimits) -> Checked<ImageManifest> {
    let document = ImageDocument::ImageManifest;
    let object = value.as_object().ok_or_else(|| shape(document))?;
    refuse_extensions(object, document, DOCUMENT_EXTENSIONS)?;
    if !only_keys(
        object,
        &[SCHEMA_VERSION, MEDIA_TYPE, CONFIG, LAYERS, ANNOTATIONS],
    ) {
        return Err(shape(document));
    }
    if !is_schema_version(object.get(SCHEMA_VERSION)) {
        return Err(shape(document));
    }
    let media_type = object
        .get(MEDIA_TYPE)
        .and_then(Value::as_str)
        .ok_or_else(|| shape(document))?;
    if media_type != OCI_MANIFEST_MEDIA_TYPE {
        return Err(unsupported(UnsupportedArchiveFeature::ManifestMediaType));
    }
    let config = descriptor(
        object.get(CONFIG).unwrap_or(&Value::Null),
        Role::Config,
        document,
        limits,
    )?;
    let layers = object
        .get(LAYERS)
        .and_then(Value::as_array)
        .ok_or_else(|| shape(document))?;
    check_count(layers.len(), limits, LimitResource::LayersPerImage)?;
    let layers = layers
        .iter()
        .enumerate()
        .map(|(position, value)| descriptor(value, Role::Layer { position }, document, limits))
        .collect::<Checked<Vec<_>>>()?;
    if let Some(annotations) = object.get(ANNOTATIONS) {
        let annotations = string_map(annotations).ok_or_else(|| shape(document))?;
        if !annotations.keys().all(|key| is_manifest_annotation(key)) {
            return Err(unsupported(UnsupportedArchiveFeature::ManifestAnnotation));
        }
    }
    Ok(ImageManifest { config, layers })
}

fn is_manifest_annotation(key: &str) -> bool {
    key == BASHBREW_ARCH_ANNOTATION
        || key
            .strip_prefix(OCI_ANNOTATION_PREFIX)
            .is_some_and(|name| OCI_MANIFEST_ANNOTATIONS.contains(&name))
}

/// The `LayerSources` keys a layer-source value must have exactly.
pub(super) const LAYER_SOURCE_KEYS: &[&str] = &[MEDIA_TYPE, DIGEST, SIZE];

/// Checks one `LayerSources` value against the layer descriptor at its
/// position.
pub(super) fn layer_source(value: &Value, layer: &Descriptor) -> Checked<()> {
    let inconsistent = || invalid(InvalidArchiveReason::InconsistentLayerSources);
    let object = value.as_object().ok_or_else(inconsistent)?;
    refuse_extensions(
        object,
        ImageDocument::CompatibilityManifest,
        DESCRIPTOR_EXTENSIONS,
    )?;
    if object.len() != LAYER_SOURCE_KEYS.len() || !only_keys(object, LAYER_SOURCE_KEYS) {
        return Err(inconsistent());
    }
    let matches = object.get(MEDIA_TYPE).and_then(Value::as_str) == Some(layer.media_type.as_str())
        && object.get(DIGEST).and_then(Value::as_str) == Some(layer.digest.as_str())
        && object.get(SIZE).and_then(Value::as_u64) == Some(layer.size);
    if matches { Ok(()) } else { Err(inconsistent()) }
}
