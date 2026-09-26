//! [`PreparationBinding`], the small record that correlates a prepared
//! package with the signing request made for it, and its canonical JSON form.

use std::fmt;
use std::io;

use serde_json::{Map, Value};

use super::prepare::{PackageWriteError, PreparationFault};
use super::{ContentError, ContentLimits, LimitResource};
use crate::content::{ContentFault, MalformedReason};
use crate::image::is_valid_segment;
use crate::manifest::{TargetArch, is_valid_commit};
use crate::verify::{VerifyRequest, is_safe_build_identifier};

#[cfg(test)]
mod tests;

/// The only record schema this build writes and reads.
const RECORD_SCHEMA: u32 = 1;
/// The prefix every digest in a record carries.
const DIGEST_PREFIX: &str = "sha256:";
const DIGEST_HEX_LEN: usize = 64;

/// The eleven fields of a record, as their JSON keys, in table order.
const FIELDS: [(BindingField, &str); 11] = [
    (BindingField::Schema, "schema"),
    (BindingField::ManifestSha256, "manifest_sha256"),
    (BindingField::ManifestLength, "manifest_length"),
    (BindingField::ArchiveSha256, "archive_sha256"),
    (BindingField::ArchiveLength, "archive_length"),
    (BindingField::Target, "target"),
    (BindingField::Version, "version"),
    (BindingField::Commit, "commit"),
    (BindingField::TargetArch, "target_arch"),
    (BindingField::Namespace, "namespace"),
    (BindingField::TrustEpoch, "trust_epoch"),
];

/// What binds a prepared package to the request it was prepared for: the
/// record schema, the raw manifest's and compressed archive block's digests
/// and lengths, the requested build, the target architecture, and the
/// namespace and trust-epoch context.
///
/// It is **data to match against, never a capability**. A copy says nothing
/// about who produced it and authorizes nothing: [`reopen_prepared`] takes the
/// caller's own saved binding as the expectation, and the record persisted
/// next to a preparation is only compared with it. Every value comes from the
/// manifest bytes, the archive bytes, the
/// [`VerifyRequest`] or the requested
/// architecture; nothing is inferred from a path or the host, and no path,
/// executable, signature, trust root or source name is held.
///
/// It is obtained only from [`PreparationBinding::from_record_bytes`] or from
/// a prepared or reopened package:
///
/// ```
/// use deploy_core::package::PreparationBinding;
///
/// let record = concat!(
///     r#"{"schema":1,"#,
///     r#""manifest_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
///     r#""manifest_length":4096,"#,
///     r#""archive_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
///     r#""archive_length":1048576,"#,
///     r#""target":"example-app","version":"1.0.0","#,
///     r#""commit":"1111111111111111111111111111111111111111","#,
///     r#""target_arch":"x86_64","namespace":"example-product","trust_epoch":null}"#,
///     "\n",
/// );
/// let binding = PreparationBinding::from_record_bytes(record.as_bytes())?;
/// assert_eq!(binding.target(), "example-app");
/// assert_eq!(binding.to_record_bytes(), record.as_bytes());
/// # Ok::<(), deploy_core::package::PackageWriteError>(())
/// ```
///
/// It cannot be built directly:
///
/// ```compile_fail
/// let binding = deploy_core::package::PreparationBinding {
///     schema: 1,
///     manifest_sha256: [0; 32],
///     manifest_length: 0,
///     archive_sha256: [0; 32],
///     archive_length: 0,
///     target: String::new(),
///     version: String::new(),
///     commit: String::new(),
///     target_arch: deploy_core::manifest::TargetArch::X86_64,
///     namespace: None,
///     trust_epoch: None,
/// };
/// ```
///
/// ```compile_fail
/// let binding = deploy_core::package::PreparationBinding::default();
/// ```
///
/// ```compile_fail
/// let binding: deploy_core::package::PreparationBinding = serde_json::from_str("{}").unwrap();
/// ```
///
/// [`reopen_prepared`]: super::reopen_prepared
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationBinding {
    schema: u32,
    manifest_sha256: [u8; 32],
    manifest_length: u64,
    archive_sha256: [u8; 32],
    archive_length: u64,
    target: String,
    version: String,
    commit: String,
    target_arch: TargetArch,
    namespace: Option<String>,
    trust_epoch: Option<u64>,
}

/// The parts of a binding a prepared package supplies.
pub(super) struct BindingParts<'a> {
    pub(super) manifest_sha256: [u8; 32],
    pub(super) manifest_length: u64,
    pub(super) archive_sha256: [u8; 32],
    pub(super) archive_length: u64,
    pub(super) request: &'a VerifyRequest,
    pub(super) target_arch: TargetArch,
}

impl PreparationBinding {
    /// Builds the binding of a prepared package, validating every field so
    /// none needs a JSON escape.
    ///
    /// Preparation has already held the request to the manifest, whose
    /// identifiers passed the same rules, so a refusal here is not expected;
    /// it is reported as the record fault it would be rather than trusted.
    pub(super) fn from_parts(parts: &BindingParts<'_>) -> Result<Self, RecordFault> {
        let binding = PreparationBinding {
            schema: RECORD_SCHEMA,
            manifest_sha256: parts.manifest_sha256,
            manifest_length: parts.manifest_length,
            archive_sha256: parts.archive_sha256,
            archive_length: parts.archive_length,
            target: parts.request.target().to_string(),
            version: parts.request.version().to_string(),
            commit: parts.request.commit().to_string(),
            target_arch: parts.target_arch,
            namespace: parts.request.namespace().map(str::to_string),
            trust_epoch: parts.request.epoch(),
        };
        binding.validate_identifiers()?;
        Ok(binding)
    }

    fn validate_identifiers(&self) -> Result<(), RecordFault> {
        let invalid = |field| Err(RecordFault::InvalidIdentifier { field });
        if !is_safe_build_identifier(&self.target) {
            return invalid(BindingField::Target);
        }
        if !is_safe_build_identifier(&self.version) {
            return invalid(BindingField::Version);
        }
        if !is_valid_commit(&self.commit) {
            return invalid(BindingField::Commit);
        }
        if self
            .namespace
            .as_deref()
            .is_some_and(|namespace| !is_valid_segment(namespace))
        {
            return invalid(BindingField::Namespace);
        }
        Ok(())
    }

    /// Returns the record schema, always `1`.
    #[must_use]
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// Returns the SHA-256 digest of the raw manifest bytes.
    #[must_use]
    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }

    /// Returns the length of the raw manifest bytes.
    #[must_use]
    pub fn manifest_length(&self) -> u64 {
        self.manifest_length
    }

    /// Returns the SHA-256 digest of the raw compressed archive block.
    #[must_use]
    pub fn archive_sha256(&self) -> &[u8; 32] {
        &self.archive_sha256
    }

    /// Returns the length of the raw compressed archive block.
    #[must_use]
    pub fn archive_length(&self) -> u64 {
        self.archive_length
    }

    /// Returns the requested package-id.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the requested version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the requested commit.
    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// Returns the requested target architecture.
    #[must_use]
    pub fn target_arch(&self) -> TargetArch {
        self.target_arch
    }

    /// Returns the namespace context the request was scoped to, if any.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Returns the trust epoch the request delivered, if any: `Some` only
    /// for a reserved trust package prepared under
    /// [`VerifyRequest::for_trust`].
    /// It is recorded, never compared against a trust set.
    #[must_use]
    pub fn trust_epoch(&self) -> Option<u64> {
        self.trust_epoch
    }

    /// Returns the canonical record: JSON with the keys in field order, no
    /// insignificant whitespace, and a trailing newline.
    ///
    /// It serializes only what the binding holds, and every field was
    /// validated, so none needs an escape. Its length is always exactly what
    /// the record-length check a limited caller runs first computes.
    #[must_use]
    pub fn to_record_bytes(&self) -> Vec<u8> {
        #[cfg(test)]
        seam::count_record_build();
        let mut out = String::with_capacity(usize::try_from(self.record_len()).unwrap_or(0));
        // Writing to a `String` cannot fail.
        let _ = self.emit(&mut out);
        out.into_bytes()
    }

    /// Parses a record under the default [`ContentLimits`]: at most 64 KiB and
    /// the default JSON nesting depth.
    ///
    /// This is the only way to obtain a binding without preparing or
    /// reopening a package, and the result is data to compare, nothing more.
    ///
    /// # Errors
    ///
    /// The first fault, in this order:
    ///
    /// - [`PackageWriteError::Content`] carrying
    ///   [`ContentError::LimitExceeded`] naming `PreparationRecord` when
    ///   `bytes` is longer than that limit, before anything is scanned.
    /// - [`PreparationFault::RecordInvalid`] with [`RecordFault::Malformed`]
    ///   for invalid JSON, invalid UTF-8, empty input or trailing data, and
    ///   [`RecordFault::DuplicateKey`] for a repeated key — or
    ///   [`ContentError::LimitExceeded`] naming `JsonDepth` for excess nesting
    ///   — whichever comes first in the bytes.
    /// - [`RecordFault::NotObject`] for a root that is not an object.
    /// - For `schema`, before any other key: [`RecordFault::MissingField`],
    ///   [`RecordFault::FieldType`] unless it is a non-negative integer, and
    ///   [`RecordFault::UnsupportedSchema`] unless it is `1`.
    /// - [`RecordFault::UnknownField`] for any key outside the eleven.
    /// - Then, field by field in record order, [`RecordFault::MissingField`]
    ///   for an absent key (`null` is required for an absent namespace or
    ///   epoch), [`RecordFault::FieldType`] for a wrong JSON type — a length
    ///   or epoch that is negative, fractional, in exponent form or beyond
    ///   `u64` included — and [`RecordFault::InvalidDigest`],
    ///   [`RecordFault::InvalidTargetArch`] or
    ///   [`RecordFault::InvalidIdentifier`] for a value breaking its rule.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<PreparationBinding, PackageWriteError> {
        parse_record(bytes, &ContentLimits::default())
    }

    /// Streams the canonical record into `out`, building no buffer of it.
    pub(super) fn write_record<W: io::Write>(&self, out: W) -> io::Result<()> {
        struct Adapter<W> {
            inner: W,
            error: Option<io::Error>,
        }
        impl<W: io::Write> fmt::Write for Adapter<W> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.inner.write_all(s.as_bytes()).map_err(|error| {
                    self.error = Some(error);
                    fmt::Error
                })
            }
        }
        let mut adapter = Adapter {
            inner: out,
            error: None,
        };
        match self.emit(&mut adapter) {
            Ok(()) => Ok(()),
            Err(fmt::Error) => Err(adapter
                .error
                .unwrap_or_else(|| io::Error::other("writing the record failed"))),
        }
    }

    /// Returns the canonical record's length in bytes, allocating nothing.
    /// An overflowing length is reported as `u64::MAX`, which no limit
    /// admits.
    pub(crate) fn record_len(&self) -> u64 {
        let mut count = Count(Some(0));
        let _ = self.emit(&mut count);
        count.0.unwrap_or(u64::MAX)
    }

    /// Writes the canonical record to `out`.
    fn emit<W: fmt::Write>(&self, out: &mut W) -> fmt::Result {
        write!(out, "{{\"schema\":{}", self.schema)?;
        out.write_str(",\"manifest_sha256\":")?;
        emit_digest(out, &self.manifest_sha256)?;
        write!(out, ",\"manifest_length\":{}", self.manifest_length)?;
        out.write_str(",\"archive_sha256\":")?;
        emit_digest(out, &self.archive_sha256)?;
        write!(out, ",\"archive_length\":{}", self.archive_length)?;
        write!(out, ",\"target\":\"{}\"", self.target)?;
        write!(out, ",\"version\":\"{}\"", self.version)?;
        write!(out, ",\"commit\":\"{}\"", self.commit)?;
        write!(out, ",\"target_arch\":\"{}\"", arch_name(self.target_arch))?;
        out.write_str(",\"namespace\":")?;
        match &self.namespace {
            Some(namespace) => write!(out, "\"{namespace}\"")?,
            None => out.write_str("null")?,
        }
        out.write_str(",\"trust_epoch\":")?;
        match self.trust_epoch {
            Some(epoch) => write!(out, "{epoch}")?,
            None => out.write_str("null")?,
        }
        out.write_str("}\n")
    }

    /// Returns the first field, in record order, in which `self` and `other`
    /// differ.
    pub(crate) fn first_difference(&self, other: &PreparationBinding) -> Option<BindingField> {
        let differs = [
            (BindingField::Schema, self.schema != other.schema),
            (
                BindingField::ManifestSha256,
                self.manifest_sha256 != other.manifest_sha256,
            ),
            (
                BindingField::ManifestLength,
                self.manifest_length != other.manifest_length,
            ),
            (
                BindingField::ArchiveSha256,
                self.archive_sha256 != other.archive_sha256,
            ),
            (
                BindingField::ArchiveLength,
                self.archive_length != other.archive_length,
            ),
            (BindingField::Target, self.target != other.target),
            (BindingField::Version, self.version != other.version),
            (BindingField::Commit, self.commit != other.commit),
            (
                BindingField::TargetArch,
                self.target_arch != other.target_arch,
            ),
            (BindingField::Namespace, self.namespace != other.namespace),
            (
                BindingField::TrustEpoch,
                self.trust_epoch != other.trust_epoch,
            ),
        ];
        differs
            .into_iter()
            .find_map(|(field, differs)| differs.then_some(field))
    }

    /// Returns the first field, in record order, in which this binding
    /// disagrees with `request` and `target_arch`.
    ///
    /// Recorded data is compared for equality; this decides nothing about an
    /// epoch.
    pub(crate) fn request_difference(
        &self,
        request: &VerifyRequest,
        target_arch: TargetArch,
    ) -> Option<BindingField> {
        let differs = [
            (BindingField::Target, self.target != request.target()),
            (BindingField::Version, self.version != request.version()),
            (BindingField::Commit, self.commit != request.commit()),
            (BindingField::TargetArch, self.target_arch != target_arch),
            (
                BindingField::Namespace,
                self.namespace.as_deref() != request.namespace(),
            ),
            (
                BindingField::TrustEpoch,
                self.trust_epoch != request.epoch(),
            ),
        ];
        differs
            .into_iter()
            .find_map(|(field, differs)| differs.then_some(field))
    }
}

/// A `fmt::Write` that only counts, with checked arithmetic.
struct Count(Option<u64>);

impl fmt::Write for Count {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 = self.0.and_then(|count| {
            u64::try_from(s.len())
                .ok()
                .and_then(|n| count.checked_add(n))
        });
        Ok(())
    }
}

fn emit_digest<W: fmt::Write>(out: &mut W, digest: &[u8; 32]) -> fmt::Result {
    out.write_str("\"sha256:")?;
    for byte in digest {
        write!(out, "{byte:02x}")?;
    }
    out.write_char('"')
}

fn arch_name(arch: TargetArch) -> &'static str {
    match arch {
        TargetArch::X86_64 => "x86_64",
        TargetArch::Aarch64 => "aarch64",
    }
}

fn record_invalid(fault: RecordFault) -> PackageWriteError {
    PackageWriteError::InvalidPreparation {
        reason: PreparationFault::RecordInvalid(fault),
    }
}

/// Parses a record under `limits`' `PreparationRecord` and `JsonDepth`, in
/// the order [`PreparationBinding::from_record_bytes`] documents.
pub(crate) fn parse_record(
    bytes: &[u8],
    limits: &ContentLimits,
) -> Result<PreparationBinding, PackageWriteError> {
    let document = limits.resource_limit(LimitResource::PreparationRecord);
    if u64::try_from(bytes.len()).map_or(true, |len| len > document.max) {
        return Err(PackageWriteError::Content(ContentError::LimitExceeded {
            resource: document.resource,
            limit: document.max,
        }));
    }
    let value: Value = crate::content::json::parse(
        bytes,
        document,
        limits.resource_limit(LimitResource::JsonDepth),
    )
    .map_err(|fault| match fault {
        ContentFault::LimitExceeded { resource, limit } => {
            PackageWriteError::Content(ContentError::LimitExceeded { resource, limit })
        }
        ContentFault::Malformed(MalformedReason::JsonDuplicateKey) => {
            record_invalid(RecordFault::DuplicateKey)
        }
        _ => record_invalid(RecordFault::Malformed),
    })?;
    let Value::Object(object) = value else {
        return Err(record_invalid(RecordFault::NotObject));
    };
    read_record(&object).map_err(record_invalid)
}

/// Steps 4 onwards of the record check, over a scanned object.
fn read_record(object: &Map<String, Value>) -> Result<PreparationBinding, RecordFault> {
    let schema = object.get("schema").ok_or(RecordFault::MissingField {
        field: BindingField::Schema,
    })?;
    let schema = schema.as_u64().ok_or(RecordFault::FieldType {
        field: BindingField::Schema,
    })?;
    if schema != u64::from(RECORD_SCHEMA) {
        return Err(RecordFault::UnsupportedSchema);
    }
    if object
        .keys()
        .any(|key| !FIELDS.iter().any(|(_, name)| name == key))
    {
        return Err(RecordFault::UnknownField);
    }

    let manifest_sha256 = digest(object, BindingField::ManifestSha256)?;
    let manifest_length = integer(object, BindingField::ManifestLength)?;
    let archive_sha256 = digest(object, BindingField::ArchiveSha256)?;
    let archive_length = integer(object, BindingField::ArchiveLength)?;
    let target = identifier(object, BindingField::Target, is_safe_build_identifier)?;
    let version = identifier(object, BindingField::Version, is_safe_build_identifier)?;
    let commit = identifier(object, BindingField::Commit, is_valid_commit)?;
    let target_arch = match string(object, BindingField::TargetArch)? {
        "x86_64" => TargetArch::X86_64,
        "aarch64" => TargetArch::Aarch64,
        _ => return Err(RecordFault::InvalidTargetArch),
    };
    let namespace = match present(object, BindingField::Namespace)? {
        Value::Null => None,
        Value::String(namespace) if is_valid_segment(namespace) => Some(namespace.clone()),
        Value::String(_) => {
            return Err(RecordFault::InvalidIdentifier {
                field: BindingField::Namespace,
            });
        }
        _ => {
            return Err(RecordFault::FieldType {
                field: BindingField::Namespace,
            });
        }
    };
    let trust_epoch = match present(object, BindingField::TrustEpoch)? {
        Value::Null => None,
        value => Some(value.as_u64().ok_or(RecordFault::FieldType {
            field: BindingField::TrustEpoch,
        })?),
    };

    Ok(PreparationBinding {
        schema: RECORD_SCHEMA,
        manifest_sha256,
        manifest_length,
        archive_sha256,
        archive_length,
        target,
        version,
        commit,
        target_arch,
        namespace,
        trust_epoch,
    })
}

fn key(field: BindingField) -> &'static str {
    FIELDS
        .iter()
        .find_map(|(candidate, name)| (*candidate == field).then_some(*name))
        .unwrap_or_default()
}

fn present(object: &Map<String, Value>, field: BindingField) -> Result<&Value, RecordFault> {
    object
        .get(key(field))
        .ok_or(RecordFault::MissingField { field })
}

fn string(object: &Map<String, Value>, field: BindingField) -> Result<&str, RecordFault> {
    present(object, field)?
        .as_str()
        .ok_or(RecordFault::FieldType { field })
}

fn integer(object: &Map<String, Value>, field: BindingField) -> Result<u64, RecordFault> {
    present(object, field)?
        .as_u64()
        .ok_or(RecordFault::FieldType { field })
}

fn identifier(
    object: &Map<String, Value>,
    field: BindingField,
    valid: fn(&str) -> bool,
) -> Result<String, RecordFault> {
    let value = string(object, field)?;
    if valid(value) {
        Ok(value.to_string())
    } else {
        Err(RecordFault::InvalidIdentifier { field })
    }
}

fn digest(object: &Map<String, Value>, field: BindingField) -> Result<[u8; 32], RecordFault> {
    let value = string(object, field)?;
    parse_digest(value).ok_or(RecordFault::InvalidDigest { field })
}

/// Parses `sha256:` followed by exactly 64 lowercase hex characters.
fn parse_digest(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix(DIGEST_PREFIX)?.as_bytes();
    if hex.len() != DIGEST_HEX_LEN {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    let (pairs, rest) = hex.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    for (slot, [high, low]) in out.iter_mut().zip(pairs) {
        *slot = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(out)
}

/// One field of a [`PreparationBinding`] and of its record, named after its
/// JSON key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingField {
    /// `schema`, the record schema.
    Schema,
    /// `manifest_sha256`, the raw manifest's digest.
    ManifestSha256,
    /// `manifest_length`, the raw manifest's length.
    ManifestLength,
    /// `archive_sha256`, the compressed archive block's digest.
    ArchiveSha256,
    /// `archive_length`, the compressed archive block's length.
    ArchiveLength,
    /// `target`, the requested package-id.
    Target,
    /// `version`, the requested version.
    Version,
    /// `commit`, the requested commit.
    Commit,
    /// `target_arch`, the requested architecture.
    TargetArch,
    /// `namespace`, the namespace context.
    Namespace,
    /// `trust_epoch`, the delivered trust epoch.
    TrustEpoch,
}

impl fmt::Display for BindingField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(key(*self))
    }
}

/// Why a preparation record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordFault {
    /// Invalid JSON, invalid UTF-8, empty input or trailing data.
    Malformed,
    /// An object repeats a key.
    DuplicateKey,
    /// The root is not an object.
    NotObject,
    /// A required key is absent; a namespace or epoch that is absent must be
    /// an explicit `null`.
    MissingField {
        /// The absent field.
        field: BindingField,
    },
    /// A field has the wrong JSON type, or is a number that is not a
    /// non-negative integer within `u64`.
    FieldType {
        /// The mistyped field.
        field: BindingField,
    },
    /// The `schema` is an integer other than `1`.
    UnsupportedSchema,
    /// A key is not one of the record's eleven.
    UnknownField,
    /// A digest is not `sha256:` followed by 64 lowercase hex characters.
    InvalidDigest {
        /// The digest field.
        field: BindingField,
    },
    /// `target_arch` is neither `x86_64` nor `aarch64`.
    InvalidTargetArch,
    /// `target` or `version` is not a safe build identifier, `commit` is not a
    /// valid commit, or a non-null `namespace` is not a valid segment.
    InvalidIdentifier {
        /// The identifier field.
        field: BindingField,
    },
}

impl fmt::Display for RecordFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("the record is not valid json"),
            Self::DuplicateKey => f.write_str("the record repeats a key"),
            Self::NotObject => f.write_str("the record is not a json object"),
            Self::MissingField { field } => write!(f, "the record has no `{field}`"),
            Self::FieldType { field } => write!(f, "the record's `{field}` has the wrong type"),
            Self::UnsupportedSchema => f.write_str("the record schema is not supported"),
            Self::UnknownField => f.write_str("the record has an unknown field"),
            Self::InvalidDigest { field } => {
                write!(f, "the record's `{field}` is not a sha-256 digest")
            }
            Self::InvalidTargetArch => {
                f.write_str("the record's `target_arch` is not a known architecture")
            }
            Self::InvalidIdentifier { field } => {
                write!(f, "the record's `{field}` is not a valid identifier")
            }
        }
    }
}

/// The test-only count of canonical records built.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::Cell;

    thread_local! {
        static BUILT: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count_record_build() {
        BUILT.with(|built| built.set(built.get() + 1));
    }

    /// Returns how many records this thread has built so far.
    pub(crate) fn records_built() -> usize {
        BUILT.with(Cell::get)
    }
}
