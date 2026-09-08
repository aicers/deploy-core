//! The frozen on-disk contract for roxyd self-update rollback supervision.
//!
//! Two repositories write the records this module names. roxyd writes the arm
//! and confirmation records and implements the decision subcommand; bootler
//! installs the units that invoke that subcommand and writes the
//! installed-contract marker. Holding the names, the path composition and the
//! JSON shapes here is what stops the two from independently shipping
//! incompatible views of the same files: the values are already on disk on every
//! host, so a changed one here is a silent behaviour change there.
//!
//! This module is a **sibling** of [`crate::roxyd_selfupdate`], not a part of
//! it, and neither depends on the other. They share a subject and nothing else.
//! The unit text is byte-identical data with one consumer and deliberately no
//! parameters; this is a versioned shape with two writers, whose whole point is
//! that both agree on it — which is why it carries [`FORMAT`] and the unit text
//! carries nothing of the kind. The enumeration of the decision-path units, and
//! the arming gate applied to a self-test record, are the one place the two
//! subjects meet, so they stay with the consumer that installs the units rather
//! than being pulled in here.
//!
//! # `format`
//!
//! Every record carries `format`, and the rule is contract-wide rather than
//! per-record: a consumer that does not accept a record's revision takes no
//! rollback action on it. It is stated once here so that no reader restates it
//! per type, and it applies before any other check a reader makes.
//!
//! # The self-test record is not the marker
//!
//! [`SelfTestRecord`] and [`SupervisorVersionMarker`] are **not**
//! interchangeable. The marker is a static install-time claim ("installed, at
//! this contract revision") and is what a consumer's capability tag is derived
//! from; the self-test record is a per-arm runtime proof and is never read as a
//! capability claim. Deriving the tag from the self-test, or gating an arm on
//! the marker, would make one of the two gates useless. The consumer that
//! installs the units ships that derivation rule, and no code here computes or
//! advertises a tag.
//!
//! Arming is gated on a **supervisor self-test**: the arming side starts
//! [`self_test_instance_unit_name`] with a fresh nonce, the helper behind that
//! unit writes [`SELF_TEST_FILE`], and the arming side holds what it finds to
//! the nonce it passed, to [`SELF_TEST_FRESHNESS_SECS`], and to the state of
//! every unit in [`SelfTestRecord::decision_path`]. The two halves that gate
//! needs are both in the one record — the nonce'd run is proof that supervisor
//! code ran on this host seconds ago, and the recorded decision path is a
//! read-only inspection of the units that would actually perform a rollback,
//! which the self-test's own unit deliberately is not.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// The root-owned directory containing self-update coordination records.
pub const DIRECTORY: &str = "/var/lib/roxyd/selfupdate";
/// The arm-record file name.
pub const ARM_FILE: &str = "arm.json";
/// The health-gate confirmation file name.
pub const CONFIRM_FILE: &str = "confirm.json";
/// The last terminal-decision status file name.
pub const STATUS_FILE: &str = "status.json";
/// The request for roxyd to publish a terminal status record.
pub const REPORT_REQUEST_FILE: &str = "report-request.json";
/// The installed unit/interface contract marker file name.
pub const SUPERVISOR_VERSION_FILE: &str = "supervisor.json";
/// The canonical roxyd binary path used by every supervisor activation.
pub const ROXYD_BINARY: &str = "/opt/roxyd/bin/roxyd";
/// The hidden roxyd subcommand invoked by the supervisor.
pub const DECISION_SUBCOMMAND: &str = "selfupdate-decide";
/// The `--reason` value for a boot activation.
pub const REASON_BOOT: &str = "boot";
/// The `--reason` value for a crash activation.
pub const REASON_CRASH: &str = "crash";
/// The `--reason` value for a deadline activation.
pub const REASON_DEADLINE: &str = "deadline";
/// The supervisor self-test record file name.
pub const SELF_TEST_FILE: &str = "selftest.json";
/// The window a self-test record satisfies the arming gate within, in seconds.
///
/// Compared as the **absolute** difference between the reading clock's now and
/// the record's `written_at`, so a file dated past the window into the future —
/// a backwards clock step on the host — fails the gate instead of satisfying it
/// indefinitely.
pub const SELF_TEST_FRESHNESS_SECS: u64 = 120;
/// The exact length of a self-test nonce.
pub const SELF_TEST_NONCE_LEN: usize = 32;
/// The only characters a self-test nonce may be built from.
///
/// Fixed at lowercase hexadecimal so systemd's instance-name escaping is a no-op
/// and `%i` is the nonce verbatim. Widening it would put an escaped instance name
/// in front of the helper and break the echo the gate compares.
pub const SELF_TEST_NONCE_ALPHABET: &str = "0123456789abcdef";
/// The hidden installer subcommand that runs the supervisor self-test.
pub const ROXYD_SUPERVISOR_SELFTEST_SUBCOMMAND: &str = "roxyd-supervisor-selftest";
/// The hidden installer subcommand that installs the supervisor on a host roxyd
/// onboarded through its join flow.
pub const ROXYD_SUPERVISOR_INSTALL_SUBCOMMAND: &str = "roxyd-supervisor-install";
/// The systemd drop-in file that carries the supervisor edges for a roxyd unit
/// owned by the join flow.
pub const ROXYD_SUPERVISOR_CRASH_ACTIVATION_DROP_IN_FILE: &str = "10-bootler-crash-activation.conf";
/// The self-test template unit's name, without the `<namespace>-` prefix and the
/// `@<nonce>` instance argument [`self_test_instance_unit_name`] adds.
const SELF_TEST_UNIT_STEM: &str = "roxyd-supervisor-selftest";

/// Returns the directory that holds every self-update contract record.
#[must_use]
pub fn directory() -> PathBuf {
    PathBuf::from(DIRECTORY)
}

/// Returns the canonical roxyd binary path.
#[must_use]
pub fn binary_path() -> PathBuf {
    PathBuf::from(ROXYD_BINARY)
}

/// Returns the directory containing the current and previous roxyd slots.
///
/// # Panics
///
/// Panics if [`ROXYD_BINARY`] has no parent directory, which cannot happen: it
/// is an absolute path with a file name, fixed in this module.
#[must_use]
pub fn binary_directory() -> PathBuf {
    binary_path()
        .parent()
        .map(Path::to_path_buf)
        .expect("the canonical roxyd binary path has a parent directory")
}

/// Returns the arm-record path.
#[must_use]
pub fn arm_path() -> PathBuf {
    directory().join(ARM_FILE)
}

/// Returns the health-gate confirmation path.
#[must_use]
pub fn confirm_path() -> PathBuf {
    directory().join(CONFIRM_FILE)
}

/// Returns the terminal-decision status path.
#[must_use]
pub fn status_path() -> PathBuf {
    directory().join(STATUS_FILE)
}

/// Returns the status-report request path.
///
/// This is the only resolver for the request read and written around report-only
/// activations, so every consumer follows a future directory relocation.
#[must_use]
pub fn report_request_path() -> PathBuf {
    directory().join(REPORT_REQUEST_FILE)
}

/// Returns the installed unit/interface contract marker path.
#[must_use]
pub fn supervisor_version_path() -> PathBuf {
    directory().join(SUPERVISOR_VERSION_FILE)
}

/// Returns the supervisor self-test record path.
#[must_use]
pub fn self_test_path() -> PathBuf {
    self_test_path_in(&directory())
}

/// Returns the supervisor self-test record path inside `directory`.
///
/// The single place the record's name is joined onto a directory, so the writer
/// and a test driving it against a temporary tree resolve the same name rather
/// than spelling it at a call site.
#[must_use]
pub fn self_test_path_in(directory: &Path) -> PathBuf {
    directory.join(SELF_TEST_FILE)
}

/// Returns the self-test template unit's name
/// (`<namespace>-roxyd-supervisor-selftest@.service`), the file the installer
/// places.
#[must_use]
pub fn self_test_template_unit_name(namespace: &str) -> String {
    format!("{namespace}-{SELF_TEST_UNIT_STEM}@.service")
}

/// Returns the self-test unit name for one nonce
/// (`<namespace>-roxyd-supervisor-selftest@<nonce>.service`), the unit the caller
/// starts per arm attempt.
///
/// `nonce` reaches the helper as `%i` verbatim, which holds only for a nonce
/// [`is_valid_self_test_nonce`] accepts.
#[must_use]
pub fn self_test_instance_unit_name(namespace: &str, nonce: &str) -> String {
    format!("{namespace}-{SELF_TEST_UNIT_STEM}@{nonce}.service")
}

/// Returns whether `nonce` is exactly [`SELF_TEST_NONCE_LEN`] characters drawn
/// from [`SELF_TEST_NONCE_ALPHABET`].
#[must_use]
pub fn is_valid_self_test_nonce(nonce: &str) -> bool {
    nonce.len() == SELF_TEST_NONCE_LEN
        && nonce.chars().all(|c| SELF_TEST_NONCE_ALPHABET.contains(c))
}

/// The self-update contract revision accepted by the supervisor.
///
/// It sits here rather than with the file-name constants above because it
/// versions the record types that follow, every one of which carries a `format`
/// field, and this is the one value a writer puts in one.
pub const FORMAT: u32 = 1;

/// The state one supervisor decision-path unit was observed in.
///
/// The self-test collapses systemd's raw property values into these variants
/// itself, so the side applying the arming gate never re-derives systemd
/// semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionUnitState {
    /// The unit meets everything the enumerated requirement asks of it.
    Ready,
    /// The unit is masked, so starting it is impossible.
    Masked,
    /// The unit is not installed on this host.
    NotFound,
    /// The unit is installed but not persistently enabled, so what would start
    /// it never will. A runtime-only enablement (`enabled-runtime`, backed by
    /// `/run`) is this state too: it is gone at the next boot, which is the one
    /// the activation has to survive.
    Disabled,
    /// The unit is enabled but not active, and its kind has to be active to fire.
    Inactive,
    /// The unit's last run left it in systemd's failed state.
    Failed,
    /// The edge that reaches the unit has dropped out of the unit that carries
    /// it — an `OnFailure=` activation, or the `Before=` ordering that puts the
    /// unit after the roxyd daemon it decides about.
    ChainMissing,
}

/// One decision-path unit as the self-test observed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPathEntry {
    /// The inspected unit's file name.
    pub unit: String,
    /// The state that inspection collapsed to.
    pub state: DecisionUnitState,
}

/// The proof one supervisor self-test run leaves behind.
///
/// It is written by the self-test helper, replacing any prior file, so only the
/// latest run is ever on disk. It is never a capability claim: see
/// [`SupervisorVersionMarker`], which is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTestRecord {
    /// The contract revision this record uses.
    pub format: u32,
    /// The instance argument the run was started with, echoed verbatim.
    pub nonce: String,
    /// The host-clock write time as whole seconds since the Unix epoch.
    pub written_at: u64,
    /// The self-test helper's own version string.
    pub supervisor_version: String,
    /// The read-only inspection of the decision path, one entry per unit, in the
    /// order the enumeration gives them.
    pub decision_path: Vec<DecisionPathEntry>,
}

/// A released roxyd build identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildIdentity {
    /// The released version string.
    pub version: String,
    /// The source commit string.
    pub commit: String,
}

/// A digest algorithm recorded with a binary digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
}

/// A binary digest with an explicit algorithm tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryDigest {
    /// The algorithm used to calculate `hex`.
    pub algorithm: DigestAlgorithm,
    /// The lowercase hexadecimal digest value.
    #[serde(
        deserialize_with = "deserialize_sha256_hex",
        serialize_with = "serialize_sha256_hex"
    )]
    pub hex: String,
}

/// The report-request-only view of a binary digest.
///
/// `BinaryDigest` is also embedded in arm and status records, where contract
/// readers permit extension fields. Report requests deliberately use this
/// stricter view so their status digest rejects unknown fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRequestDigest {
    algorithm: DigestAlgorithm,
    #[serde(deserialize_with = "deserialize_sha256_hex")]
    hex: String,
}

impl From<ReportRequestDigest> for BinaryDigest {
    fn from(digest: ReportRequestDigest) -> Self {
        Self {
            algorithm: digest.algorithm,
            hex: digest.hex,
        }
    }
}

/// Serializes a SHA-256 hex digest only in its accepted wire representation.
fn serialize_sha256_hex<S>(hex: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if is_lowercase_sha256_hex(hex) {
        serializer.serialize_str(hex)
    } else {
        Err(serde::ser::Error::custom(
            "SHA-256 digest must be exactly 64 lowercase hexadecimal characters",
        ))
    }
}

/// Deserializes a SHA-256 hex digest in its one accepted wire representation.
fn deserialize_sha256_hex<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let hex = String::deserialize(deserializer)?;
    if is_lowercase_sha256_hex(&hex) {
        Ok(hex)
    } else {
        Err(serde::de::Error::custom(
            "SHA-256 digest must be exactly 64 lowercase hexadecimal characters",
        ))
    }
}

/// Returns whether `hex` is exactly one lowercase hexadecimal SHA-256 digest.
fn is_lowercase_sha256_hex(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Calculates the SHA-256 digest of the exact durable status-record bytes.
///
/// Callers must pass the bytes read from `status.json`, without parsing and
/// reserializing them: the report request binds the publication to that exact
/// durable record.
#[must_use]
pub fn status_digest(status_bytes: &[u8]) -> BinaryDigest {
    let digest = Sha256::digest(status_bytes);
    BinaryDigest {
        algorithm: DigestAlgorithm::Sha256,
        hex: format!("{digest:x}"),
    }
}

/// A request for roxyd to publish the current terminal status record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRequest {
    /// The contract revision this request uses.
    ///
    /// Readers retain an unsupported value long enough to classify it as
    /// [`ReportRequestValidity::UnsupportedFormat`], but writers can serialize
    /// only the current revision.
    #[serde(serialize_with = "serialize_report_request_format")]
    pub format: u32,
    /// The SHA-256 digest of the exact bytes currently in `status.json`.
    #[serde(deserialize_with = "deserialize_report_request_digest")]
    pub status_digest: BinaryDigest,
}

/// Deserializes a report-request digest while rejecting unknown fields.
fn deserialize_report_request_digest<'de, D>(deserializer: D) -> Result<BinaryDigest, D::Error>
where
    D: Deserializer<'de>,
{
    ReportRequestDigest::deserialize(deserializer).map(Into::into)
}

/// Serializes only the report-request format this producer supports.
// `serialize_with` hands the field by reference whatever its size, so the
// reference here is serde's signature and not a choice this code can make.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_report_request_format<S>(format: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *format == FORMAT {
        serializer.serialize_u32(*format)
    } else {
        Err(serde::ser::Error::custom(format!(
            "report request format must equal {FORMAT}"
        )))
    }
}

/// The outcome of checking a report request against the current status bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportRequestValidity {
    /// The request names the present, parseable status record exactly.
    Valid,
    /// The request uses a contract revision this consumer does not accept.
    UnsupportedFormat,
    /// No current status record was available to bind the request to.
    MissingStatusRecord,
    /// The current status bytes cannot be parsed as a status record.
    InvalidStatusRecord,
    /// The request digest does not name the exact current status bytes.
    StatusDigestMismatch,
}

/// Validates a report request against the exact bytes currently in `status.json`.
///
/// `None` represents a missing or unreadable status record. A parseable record
/// and a matching digest are both required, so a request left behind for an
/// earlier status is stale rather than authority to publish a newer one.
#[must_use]
pub fn validate_report_request(
    request: &ReportRequest,
    status_bytes: Option<&[u8]>,
) -> ReportRequestValidity {
    if request.format != FORMAT {
        return ReportRequestValidity::UnsupportedFormat;
    }
    let Some(status_bytes) = status_bytes else {
        return ReportRequestValidity::MissingStatusRecord;
    };
    if serde_json::from_slice::<StatusRecord>(status_bytes).is_err() {
        return ReportRequestValidity::InvalidStatusRecord;
    }
    if request.status_digest != status_digest(status_bytes) {
        return ReportRequestValidity::StatusDigestMismatch;
    }
    ReportRequestValidity::Valid
}

/// The action permitted when an unconfirmed incoming build fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackPolicy {
    /// Restores the identity-asserted previous binary.
    Rollback,
    /// Records the outcome without restoring a binary.
    Hold,
}

/// A durable request to watch one self-update attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmRecord {
    /// The contract revision this record uses.
    pub format: u32,
    /// The binary being installed.
    pub incoming: BuildIdentity,
    /// The binary that was running before the update.
    pub outgoing: BuildIdentity,
    /// The incoming binary's digest.
    pub incoming_digest: BinaryDigest,
    /// The outgoing binary's digest.
    pub outgoing_digest: BinaryDigest,
    /// The action permitted if the health gate does not confirm.
    pub policy: RollbackPolicy,
    /// The host-clock deadline as whole seconds since the Unix epoch.
    pub deadline_epoch_seconds: u64,
}

/// A build-scoped health-gate confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmMarker {
    /// The contract revision this marker uses.
    pub format: u32,
    /// The build that passed the health gate.
    pub build: BuildIdentity,
}

/// The lifecycle outcome of a terminal supervisor decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// A matching health-gate marker committed the incoming binary.
    Committed,
    /// The update never swapped the outgoing binary.
    NoAction,
    /// The previous binary replaced the unconfirmed incoming binary.
    Reverted,
    /// The `Hold` policy declined a rollback.
    Declined,
    /// A safe decision could not be completed.
    Failed,
}

/// The terminal decision that consumed an arm record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// A matching health-gate marker committed the incoming binary.
    Confirmed,
    /// The outgoing binary was still installed, so the swap never occurred.
    OutgoingStillInstalled,
    /// The installed binary matched neither recorded digest.
    BinaryMatchesNeither,
    /// The supervisor restored the previous binary.
    Reverted,
    /// The `Hold` policy declined a rollback.
    HoldDeclined,
    /// The previous binary could not be asserted as the outgoing build.
    RevertRefused,
}

/// The condition that drove a terminal supervisor decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    /// The incoming build wrote a matching confirmation marker.
    MatchingConfirmMarker,
    /// The swap had not happened when the supervisor ran.
    OutgoingStillInstalled,
    /// The incoming build did not confirm before its deadline.
    MarkerDeadlineExpired,
    /// Systemd's durable crash threshold was reached.
    CrashThresholdReached,
    /// The installed binary matched neither recorded digest.
    BinaryMatchesNeither,
    /// The previous binary could not be asserted as the outgoing build.
    PreviousIdentityUnassertable,
    /// The outgoing build appears in the active trust generation's withdrawn list.
    PreviousBuildWithdrawn,
    /// The active release-trust generation could not be read or validated.
    TrustGenerationUnreadable,
}

/// The observed binary state captured in a terminal status record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedBinary {
    /// The digest calculated from the on-disk binary.
    pub digest: BinaryDigest,
    /// The build identity when it can be determined.
    pub build: Option<BuildIdentity>,
}

/// The durable result of the last terminal supervisor decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRecord {
    /// The contract revision this record uses.
    pub format: u32,
    /// The terminal lifecycle state.
    pub lifecycle: Lifecycle,
    /// The terminal decision that consumed the arm record.
    pub decision: Decision,
    /// The condition that drove the decision.
    pub reason: DecisionReason,
    /// The requested incoming build.
    pub incoming: BuildIdentity,
    /// The requested outgoing build.
    pub outgoing: BuildIdentity,
    /// The binary observed when making the decision.
    pub observed: ObservedBinary,
    /// The decision subcommand's own version string.
    pub supervisor_version: String,
    /// The host-clock recording time as whole seconds since the Unix epoch.
    pub recorded_at_epoch_seconds: u64,
}

/// The unit/interface revision the installer placed on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorVersionMarker {
    /// The installed contract revision.
    pub format: u32,
    /// The host-clock installation time as whole seconds since the Unix epoch.
    pub installed_at_epoch_seconds: u64,
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        ARM_FILE, ArmRecord, BinaryDigest, BuildIdentity, CONFIRM_FILE, ConfirmMarker,
        DECISION_SUBCOMMAND, DIRECTORY, Decision, DecisionPathEntry, DecisionReason,
        DecisionUnitState, DigestAlgorithm, FORMAT, Lifecycle, ObservedBinary, REASON_BOOT,
        REASON_CRASH, REASON_DEADLINE, REPORT_REQUEST_FILE, ROXYD_BINARY,
        ROXYD_SUPERVISOR_CRASH_ACTIVATION_DROP_IN_FILE, ROXYD_SUPERVISOR_INSTALL_SUBCOMMAND,
        ROXYD_SUPERVISOR_SELFTEST_SUBCOMMAND, ReportRequest, ReportRequestValidity, RollbackPolicy,
        SELF_TEST_FILE, SELF_TEST_FRESHNESS_SECS, SELF_TEST_NONCE_ALPHABET, SELF_TEST_NONCE_LEN,
        STATUS_FILE, SUPERVISOR_VERSION_FILE, SelfTestRecord, StatusRecord,
        SupervisorVersionMarker, arm_path, binary_directory, binary_path, confirm_path, directory,
        is_valid_self_test_nonce, report_request_path, self_test_instance_unit_name,
        self_test_path, self_test_path_in, self_test_template_unit_name, status_digest,
        status_path, supervisor_version_path, validate_report_request,
    };

    /// A nonce of the fixed length and charset, as a caller generates per arm.
    const NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    /// The namespace the fixture units are named under.
    const NAMESPACE: &str = "clumit-security";

    fn build() -> BuildIdentity {
        BuildIdentity {
            version: "1.2.3".to_string(),
            commit: "0123456789abcdef".to_string(),
        }
    }

    fn digest() -> BinaryDigest {
        BinaryDigest {
            algorithm: DigestAlgorithm::Sha256,
            hex: "ab".repeat(32),
        }
    }

    /// A status record fixture with intentional insignificant whitespace.
    ///
    /// The request digest binds to these exact bytes, rather than to the compact
    /// bytes serde would produce after parsing the record.
    fn status_fixture() -> Vec<u8> {
        format!(
            r#"{{
  "format": 1,
  "lifecycle": "failed",
  "decision": "revert_refused",
  "reason": "previous_build_withdrawn",
  "incoming": {{ "version": "2.0.0", "commit": "incoming" }},
  "outgoing": {{ "version": "1.0.0", "commit": "outgoing" }},
  "observed": {{
    "digest": {{ "algorithm": "sha256", "hex": "{}" }},
    "build": {{ "version": "2.0.0", "commit": "incoming" }}
  }},
  "supervisor_version": "2.0.0",
  "recorded_at_epoch_seconds": 1700000000
}}"#,
            "ab".repeat(32)
        )
        .into_bytes()
    }

    /// The values this module inherited, spelled out one by one.
    ///
    /// The contract is frozen and its records are already on disk under these
    /// names on every host, so a value is not something a later edit gets to
    /// choose. Naming each one here is what makes such an edit a failing test
    /// rather than a silent behaviour change on every host, and it is how this
    /// module's identity with the definition it was moved from is asserted
    /// rather than inspected.
    #[test]
    fn every_contract_value_is_the_one_this_module_inherited() {
        assert_eq!(FORMAT, 1);
        assert_eq!(DIRECTORY, "/var/lib/roxyd/selfupdate");
        assert_eq!(ARM_FILE, "arm.json");
        assert_eq!(CONFIRM_FILE, "confirm.json");
        assert_eq!(STATUS_FILE, "status.json");
        assert_eq!(REPORT_REQUEST_FILE, "report-request.json");
        assert_eq!(SUPERVISOR_VERSION_FILE, "supervisor.json");
        assert_eq!(SELF_TEST_FILE, "selftest.json");
        assert_eq!(ROXYD_BINARY, "/opt/roxyd/bin/roxyd");
        assert_eq!(DECISION_SUBCOMMAND, "selfupdate-decide");
        assert_eq!(REASON_BOOT, "boot");
        assert_eq!(REASON_CRASH, "crash");
        assert_eq!(REASON_DEADLINE, "deadline");
        assert_eq!(SELF_TEST_FRESHNESS_SECS, 120);
        assert_eq!(SELF_TEST_NONCE_LEN, 32);
        assert_eq!(SELF_TEST_NONCE_ALPHABET, "0123456789abcdef");
        assert_eq!(
            ROXYD_SUPERVISOR_SELFTEST_SUBCOMMAND,
            "roxyd-supervisor-selftest"
        );
        assert_eq!(
            ROXYD_SUPERVISOR_INSTALL_SUBCOMMAND,
            "roxyd-supervisor-install"
        );
        assert_eq!(
            ROXYD_SUPERVISOR_CRASH_ACTIVATION_DROP_IN_FILE,
            "10-bootler-crash-activation.conf"
        );
    }

    /// The composed paths, spelled as literals rather than rebuilt from the
    /// constants above.
    ///
    /// Composing them from the same constants the resolvers use would pass on a
    /// host where the directory had moved, which is the change this pins.
    #[test]
    fn every_resolver_composes_the_path_it_always_did() {
        assert_eq!(directory(), Path::new("/var/lib/roxyd/selfupdate"));
        assert_eq!(binary_path(), Path::new("/opt/roxyd/bin/roxyd"));
        assert_eq!(binary_directory(), Path::new("/opt/roxyd/bin"));
        assert_eq!(arm_path(), Path::new("/var/lib/roxyd/selfupdate/arm.json"));
        assert_eq!(
            confirm_path(),
            Path::new("/var/lib/roxyd/selfupdate/confirm.json")
        );
        assert_eq!(
            status_path(),
            Path::new("/var/lib/roxyd/selfupdate/status.json")
        );
        assert_eq!(
            report_request_path(),
            Path::new("/var/lib/roxyd/selfupdate/report-request.json"),
            "writers, readers and tests share the one resolver"
        );
        assert_eq!(
            supervisor_version_path(),
            Path::new("/var/lib/roxyd/selfupdate/supervisor.json")
        );
        assert_eq!(
            self_test_path(),
            Path::new("/var/lib/roxyd/selfupdate/selftest.json")
        );
        let elsewhere = PathBuf::from("/tmp/contract");
        assert_eq!(
            self_test_path_in(&elsewhere),
            elsewhere.join(SELF_TEST_FILE),
            "the resolver is the one place the record's name is joined on"
        );
    }

    #[test]
    fn the_arm_record_and_confirm_marker_round_trip_with_the_frozen_json_names() {
        let arm = ArmRecord {
            format: FORMAT,
            incoming: build(),
            outgoing: build(),
            incoming_digest: digest(),
            outgoing_digest: digest(),
            policy: RollbackPolicy::Rollback,
            deadline_epoch_seconds: 1_700_000_000,
        };
        let confirm = ConfirmMarker {
            format: FORMAT,
            build: build(),
        };

        let arm_json = serde_json::to_value(&arm).expect("arm serializes");
        assert_eq!(
            arm_json,
            serde_json::json!({
                "format": FORMAT,
                "incoming": { "version": "1.2.3", "commit": "0123456789abcdef" },
                "outgoing": { "version": "1.2.3", "commit": "0123456789abcdef" },
                "incoming_digest": { "algorithm": "sha256", "hex": "ab".repeat(32) },
                "outgoing_digest": { "algorithm": "sha256", "hex": "ab".repeat(32) },
                "policy": "rollback",
                "deadline_epoch_seconds": 1_700_000_000_u64,
            }),
            "the arm record's field names and enum encoding are part of the contract"
        );
        let confirm_json = serde_json::to_value(&confirm).expect("confirm serializes");
        assert_eq!(
            confirm_json,
            serde_json::json!({
                "format": FORMAT,
                "build": { "version": "1.2.3", "commit": "0123456789abcdef" },
            }),
            "the confirm marker's field names and build encoding are part of the contract"
        );
        assert_eq!(
            serde_json::from_value::<ArmRecord>(arm_json).expect("arm deserializes"),
            arm
        );
        assert_eq!(
            serde_json::from_value::<ConfirmMarker>(confirm_json).expect("confirm deserializes"),
            confirm
        );
    }

    #[test]
    fn the_status_record_and_version_marker_round_trip_with_the_frozen_json_names() {
        let status = StatusRecord {
            format: FORMAT,
            lifecycle: Lifecycle::Reverted,
            decision: Decision::Reverted,
            reason: DecisionReason::MarkerDeadlineExpired,
            incoming: build(),
            outgoing: build(),
            observed: ObservedBinary {
                digest: digest(),
                build: Some(build()),
            },
            supervisor_version: "1.2.3".to_string(),
            recorded_at_epoch_seconds: 1_700_000_001,
        };
        let marker = SupervisorVersionMarker {
            format: FORMAT,
            installed_at_epoch_seconds: 1_700_000_002,
        };

        let status_json = serde_json::to_value(&status).expect("status serializes");
        assert_eq!(
            status_json,
            serde_json::json!({
                "format": FORMAT,
                "lifecycle": "reverted",
                "decision": "reverted",
                "reason": "marker_deadline_expired",
                "incoming": { "version": "1.2.3", "commit": "0123456789abcdef" },
                "outgoing": { "version": "1.2.3", "commit": "0123456789abcdef" },
                "observed": {
                    "digest": { "algorithm": "sha256", "hex": "ab".repeat(32) },
                    "build": { "version": "1.2.3", "commit": "0123456789abcdef" },
                },
                "supervisor_version": "1.2.3",
                "recorded_at_epoch_seconds": 1_700_000_001_u64,
            }),
            "the status record's field names and enum encoding are part of the contract"
        );
        let marker_json = serde_json::to_value(marker).expect("marker serializes");
        assert_eq!(
            marker_json,
            serde_json::json!({
                "format": FORMAT,
                "installed_at_epoch_seconds": 1_700_000_002_u64,
            }),
            "the supervisor marker's field names are part of the contract"
        );
        assert_eq!(
            serde_json::from_value::<StatusRecord>(status_json).expect("status deserializes"),
            status
        );
        assert_eq!(
            serde_json::from_value::<SupervisorVersionMarker>(marker_json)
                .expect("marker deserializes"),
            marker
        );
    }

    #[test]
    fn report_request_round_trips_and_binds_to_exact_status_bytes() {
        let status = status_fixture();
        let request = ReportRequest {
            format: FORMAT,
            status_digest: status_digest(&status),
        };
        assert_eq!(
            serde_json::to_value(&request).expect("the report request serializes"),
            serde_json::json!({
                "format": FORMAT,
                "status_digest": { "algorithm": "sha256", "hex": status_digest(&status).hex },
            }),
            "the request has exactly its format and status digest"
        );
        assert_eq!(
            serde_json::from_value::<ReportRequest>(
                serde_json::to_value(&request).expect("the request serializes")
            )
            .expect("the request deserializes"),
            request
        );
        assert_eq!(
            validate_report_request(&request, Some(&status)),
            ReportRequestValidity::Valid
        );

        let compact = serde_json::to_vec(
            &serde_json::from_slice::<StatusRecord>(&status).expect("the fixture parses"),
        )
        .expect("the fixture record serializes");
        assert_ne!(
            status, compact,
            "the fixture deliberately is not compact JSON"
        );
        assert_eq!(
            validate_report_request(&request, Some(&compact)),
            ReportRequestValidity::StatusDigestMismatch,
            "the digest is calculated from durable bytes, never a reserialization"
        );
    }

    #[test]
    fn status_digest_uses_sha256() {
        assert_eq!(
            status_digest(b"abc").hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "the request digest is SHA-256, not another hash with the same wire tag"
        );
    }

    #[test]
    fn report_request_parsing_rejects_unknown_and_malformed_digests() {
        let valid = serde_json::json!({
            "format": FORMAT,
            "status_digest": { "algorithm": "sha256", "hex": "ab".repeat(32) },
        });
        for invalid in [
            serde_json::json!({
                "format": FORMAT,
                "status_digest": { "algorithm": "sha256", "hex": "ab".repeat(32) },
                "unexpected": true,
            }),
            serde_json::json!({
                "format": FORMAT,
                "status_digest": {
                    "algorithm": "sha256",
                    "hex": "ab".repeat(32),
                    "unexpected": true,
                },
            }),
            serde_json::json!({
                "format": FORMAT,
                "status_digest": { "algorithm": "sha512", "hex": "ab".repeat(32) },
            }),
            serde_json::json!({
                "format": FORMAT,
                "status_digest": { "algorithm": "sha256", "hex": "ab".repeat(31) },
            }),
            serde_json::json!({
                "format": FORMAT,
                "status_digest": { "algorithm": "sha256", "hex": "AB".repeat(32) },
            }),
        ] {
            assert!(
                serde_json::from_value::<ReportRequest>(invalid).is_err(),
                "only the exact report-request digest representation parses"
            );
        }
        assert!(
            serde_json::from_value::<ReportRequest>(valid).is_ok(),
            "the canonical digest representation parses"
        );
        let unsupported_format = ReportRequest {
            format: FORMAT + 1,
            status_digest: status_digest(b"status"),
        };
        assert!(
            serde_json::to_value(unsupported_format).is_err(),
            "a writer cannot serialize a report request with an unsupported format"
        );
        let invalid = ReportRequest {
            format: FORMAT,
            status_digest: BinaryDigest {
                algorithm: DigestAlgorithm::Sha256,
                hex: "ab".repeat(31),
            },
        };
        assert!(
            serde_json::to_value(invalid).is_err(),
            "a caller cannot serialize a malformed digest into a request"
        );
    }

    #[test]
    fn arm_and_status_parsing_allow_digest_extension_fields() {
        let arm = serde_json::json!({
            "format": FORMAT,
            "incoming": { "version": "2.0.0", "commit": "incoming" },
            "outgoing": { "version": "1.0.0", "commit": "outgoing" },
            "incoming_digest": {
                "algorithm": "sha256",
                "hex": "ab".repeat(32),
                "extension": true,
            },
            "outgoing_digest": { "algorithm": "sha256", "hex": "ab".repeat(32) },
            "policy": "rollback",
            "deadline_epoch_seconds": 1_700_000_000_u64,
        });
        let status = serde_json::json!({
            "format": FORMAT,
            "lifecycle": "failed",
            "decision": "revert_refused",
            "reason": "previous_build_withdrawn",
            "incoming": { "version": "2.0.0", "commit": "incoming" },
            "outgoing": { "version": "1.0.0", "commit": "outgoing" },
            "observed": {
                "digest": {
                    "algorithm": "sha256",
                    "hex": "ab".repeat(32),
                    "extension": true,
                },
                "build": { "version": "2.0.0", "commit": "incoming" },
            },
            "supervisor_version": "2.0.0",
            "recorded_at_epoch_seconds": 1_700_000_000_u64,
        });

        assert!(
            serde_json::from_value::<ArmRecord>(arm).is_ok(),
            "arm records permit unknown digest extension fields"
        );
        assert!(
            serde_json::from_value::<StatusRecord>(status).is_ok(),
            "status records permit unknown digest extension fields"
        );
    }

    #[test]
    fn report_request_validation_distinguishes_invalid_requests() {
        let status = status_fixture();
        let request = ReportRequest {
            format: FORMAT,
            status_digest: status_digest(&status),
        };
        assert_eq!(
            validate_report_request(
                &ReportRequest {
                    format: FORMAT + 1,
                    ..request.clone()
                },
                Some(&status)
            ),
            ReportRequestValidity::UnsupportedFormat
        );
        assert_eq!(
            validate_report_request(&request, None),
            ReportRequestValidity::MissingStatusRecord
        );
        assert_eq!(
            validate_report_request(&request, Some(br"{}")),
            ReportRequestValidity::InvalidStatusRecord
        );
        let stale = String::from_utf8(status_fixture())
            .expect("the fixture is UTF-8")
            .replacen("\"2.0.0\"", "\"3.0.0\"", 1)
            .into_bytes();
        assert_eq!(
            validate_report_request(&request, Some(&stale)),
            ReportRequestValidity::StatusDigestMismatch,
            "a request for an earlier record cannot authorize publishing a newer one"
        );
    }

    /// Every `lifecycle` spelling, not only the one the round trip names.
    ///
    /// The status record's round trip above fixes a single variant of each of
    /// its three enums, which leaves the rest free to be renamed without a
    /// failing test here. They are what one side writes into `status.json` and
    /// the other reads back out, so every spelling is contract.
    #[test]
    fn every_lifecycle_keeps_its_encoding() {
        for (lifecycle, encoding) in [
            (Lifecycle::Committed, "committed"),
            (Lifecycle::NoAction, "no_action"),
            (Lifecycle::Reverted, "reverted"),
            (Lifecycle::Declined, "declined"),
            (Lifecycle::Failed, "failed"),
        ] {
            assert_eq!(
                serde_json::to_value(lifecycle).expect("a lifecycle serializes"),
                serde_json::json!(encoding),
                "a `lifecycle` spelling is part of the contract"
            );
        }
    }

    #[test]
    fn every_decision_keeps_its_encoding() {
        for (decision, encoding) in [
            (Decision::Confirmed, "confirmed"),
            (Decision::OutgoingStillInstalled, "outgoing_still_installed"),
            (Decision::BinaryMatchesNeither, "binary_matches_neither"),
            (Decision::Reverted, "reverted"),
            (Decision::HoldDeclined, "hold_declined"),
            (Decision::RevertRefused, "revert_refused"),
        ] {
            assert_eq!(
                serde_json::to_value(decision).expect("a decision serializes"),
                serde_json::json!(encoding),
                "a `decision` spelling is part of the contract"
            );
        }
    }

    #[test]
    fn every_decision_reason_keeps_its_encoding() {
        for (reason, encoding) in [
            (
                DecisionReason::MatchingConfirmMarker,
                "matching_confirm_marker",
            ),
            (
                DecisionReason::OutgoingStillInstalled,
                "outgoing_still_installed",
            ),
            (
                DecisionReason::MarkerDeadlineExpired,
                "marker_deadline_expired",
            ),
            (
                DecisionReason::CrashThresholdReached,
                "crash_threshold_reached",
            ),
            (
                DecisionReason::BinaryMatchesNeither,
                "binary_matches_neither",
            ),
            (
                DecisionReason::PreviousIdentityUnassertable,
                "previous_identity_unassertable",
            ),
            (
                DecisionReason::PreviousBuildWithdrawn,
                "previous_build_withdrawn",
            ),
            (
                DecisionReason::TrustGenerationUnreadable,
                "trust_generation_unreadable",
            ),
        ] {
            assert_eq!(
                serde_json::to_value(reason).expect("a reason serializes"),
                serde_json::json!(encoding),
                "the refusal reason spelling is part of the shared contract"
            );
        }
    }

    #[test]
    fn the_self_test_record_round_trips_with_the_frozen_json_names() {
        let record = SelfTestRecord {
            format: FORMAT,
            nonce: NONCE.to_string(),
            written_at: 1_700_000_000,
            supervisor_version: "1.2.3".to_string(),
            decision_path: vec![DecisionPathEntry {
                unit: "roxyd-selfupdate-deadline.timer".to_string(),
                state: DecisionUnitState::Masked,
            }],
        };
        let json = serde_json::to_value(&record).expect("the self-test record serializes");
        assert_eq!(
            json,
            serde_json::json!({
                "format": FORMAT,
                "nonce": NONCE,
                "written_at": 1_700_000_000_u64,
                "supervisor_version": "1.2.3",
                "decision_path": [
                    { "unit": "roxyd-selfupdate-deadline.timer", "state": "masked" },
                ],
            }),
            "the self-test record's field names, entry shape and epoch-seconds \
             encoding are what the roxyd side parses"
        );
        assert_eq!(
            serde_json::from_value::<SelfTestRecord>(json).expect("the record deserializes"),
            record
        );
    }

    #[test]
    fn every_decision_unit_state_keeps_its_encoding() {
        for (state, encoding) in [
            (DecisionUnitState::Ready, "ready"),
            (DecisionUnitState::Masked, "masked"),
            (DecisionUnitState::NotFound, "not_found"),
            (DecisionUnitState::Disabled, "disabled"),
            (DecisionUnitState::Inactive, "inactive"),
            (DecisionUnitState::Failed, "failed"),
            (DecisionUnitState::ChainMissing, "chain_missing"),
        ] {
            assert_eq!(
                serde_json::to_value(state).expect("the state serializes"),
                serde_json::json!(encoding),
                "a `state` spelling is part of the contract"
            );
        }
    }

    #[test]
    fn every_rollback_policy_keeps_its_encoding() {
        for (policy, encoding) in [
            (RollbackPolicy::Rollback, "rollback"),
            (RollbackPolicy::Hold, "hold"),
        ] {
            assert_eq!(
                serde_json::to_value(policy).expect("the policy serializes"),
                serde_json::json!(encoding),
                "the policy spelling is what an operator's selection reaches the host as"
            );
        }
    }

    #[test]
    fn the_self_test_unit_names_are_a_template_and_its_instance() {
        assert_eq!(
            self_test_template_unit_name(NAMESPACE),
            "clumit-security-roxyd-supervisor-selftest@.service"
        );
        assert_eq!(
            self_test_instance_unit_name(NAMESPACE, NONCE),
            format!("clumit-security-roxyd-supervisor-selftest@{NONCE}.service")
        );
        for name in [
            self_test_template_unit_name(NAMESPACE),
            self_test_instance_unit_name(NAMESPACE, NONCE),
        ] {
            assert_ne!(name, format!("{NAMESPACE}-roxyd-activate.service"));
            assert_ne!(name, format!("{NAMESPACE}-roxyd-activate.path"));
        }
    }

    #[test]
    fn only_a_fixed_length_lowercase_hex_nonce_is_accepted() {
        assert!(is_valid_self_test_nonce(NONCE));
        assert!(
            !is_valid_self_test_nonce(&NONCE.to_uppercase()),
            "uppercase would be escaped differently by systemd"
        );
        assert!(!is_valid_self_test_nonce(&NONCE[1..]), "too short");
        assert!(!is_valid_self_test_nonce(&format!("{NONCE}0")), "too long");
        assert!(
            !is_valid_self_test_nonce(&format!("{}-", &NONCE[1..])),
            "a character outside the alphabet is refused, not escaped"
        );
    }
}
