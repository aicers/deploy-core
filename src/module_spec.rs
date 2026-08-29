//! The declarative per-module install spec a package carries in its manifest.
//!
//! A package **declares** how it is installed instead of an engine hardcoding
//! it per component: a [`ModuleSpec`] is the systemd unit template, the
//! host-agnostic bootroot registration template, and the placement rule for one
//! artifact. Because a root daemon executes what it reads here, the spec rides
//! inside the manifest block and is covered by the manifest's integrity checks;
//! nothing a consumer renders or executes rides outside it.
//!
//! Everything in the spec is a closed record or a closed enum. The unit
//! template is structured directives with typed argv elements rather than free
//! text with placeholders, so an unknown variable is *unrepresentable* — it
//! fails to deserialize rather than rendering an empty string or a literal
//! `{{config}}` into a root-executed `ExecStart=`. There is deliberately no
//! free-form directive field, no raw unit-text field, and no way for package
//! data to name a service account.
//!
//! [`validate`] enforces every rule in this module and is invoked from this
//! crate's manifest read path, so a consumer that never links an installer
//! still refuses a malformed spec before acting on it.

use serde::{Deserialize, Serialize};

use crate::manifest::ArtifactKind;
use crate::systemd::is_representable;

/// Maximum length of a DNS label, in octets.
const MAX_DNS_LABEL_LEN: usize = 63;

/// Maximum length of a Docker container name, in octets.
const MAX_CONTAINER_NAME_LEN: usize = 255;

/// How one artifact is installed: its unit, its registration, and where it
/// belongs.
///
/// The spec deliberately does **not** re-declare the artifact's
/// [`ArtifactKind`] — the kind is already on the enclosing artifact and a
/// second copy could disagree with it — and carries neither a service account
/// (a closed compile-time enum that can never come from package data) nor a
/// unit file name (derived host-side by the renderer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSpec {
    /// The systemd unit to render, when this artifact's kind has one.
    ///
    /// Required for [`ArtifactKind::NativeBinary`] and
    /// [`ArtifactKind::ComposeBundle`], and absent for
    /// [`ArtifactKind::StaticAssets`] and [`ArtifactKind::ContainerImage`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<UnitTemplate>,
    /// The host-agnostic half of this module's bootroot registration.
    pub registration: RegistrationTemplate,
    /// Which class of host the module is placed on.
    pub placement: PlacementClass,
}

/// A closed structured systemd unit: named directives with typed values, never
/// unit text.
///
/// # Canonical layout
///
/// The section layout and directive order are fixed here, because work in more
/// than one repository must produce identical bytes from one record. A unit
/// renders as `[Unit]`, a blank line, `[Service]`, a blank line, `[Install]`,
/// with a trailing newline, and within each section the directives are emitted
/// in exactly this order, each omitted when it has no value — which means
/// precisely an `Option` field that is `None`, an empty `Vec`, or a `bool` that
/// is `false`:
///
/// 1. `[Unit]` — `Description=`, then one `After=` line per [`Self::after`]
///    element in declared order, then one `Wants=` line per [`Self::wants`]
///    element in declared order.
/// 2. `[Service]` — `User=`, `ExecStart=`, `ExecReload=`, `WorkingDirectory=`,
///    one `Environment=` line per [`Self::environment`] entry in declared
///    order, `Restart=`, `RestartSec=`, `LimitNOFILE=`, then `ProtectHome=yes`,
///    `PrivateTmp=yes` and `NoNewPrivileges=yes`, each emitted only when its
///    flag is `true`.
/// 3. `[Install]` — one `WantedBy=` line per [`Self::wanted_by`] element in
///    declared order.
///
/// `User=` is deliberately **not** a field here — the account is a closed
/// compile-time enum that package data can never name — but its position
/// belongs to this layout, so it is fixed here rather than twice.
/// [`Self::description`], [`Self::exec_start`], [`Self::restart`] and
/// [`Self::restart_sec`] have no absent state, so their directives always
/// render; that is why an empty `description` is rejected rather than left to
/// each implementation to read as either a bare `Description=` or no line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitTemplate {
    /// `Description=` body. Free text, but never empty.
    pub description: String,
    /// One `After=` line per element, in declared order.
    pub after: Vec<SystemdTarget>,
    /// One `Wants=` line per element, in declared order.
    pub wants: Vec<SystemdTarget>,
    /// One `[Install]` `WantedBy=` line per element, in declared order.
    pub wanted_by: Vec<SystemdTarget>,
    /// `ExecStart=` argv. Non-empty, and its first element is
    /// `Arg::Var(RenderVar::ArtifactPath)`.
    pub exec_start: Vec<Arg>,
    /// `ExecReload=` argv. Non-empty when present, and the only place
    /// [`RenderVar::MainPid`] may appear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_reload: Option<Vec<Arg>>,
    /// `WorkingDirectory=` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<Arg>,
    /// One `Environment=` line per entry, in declared order. Keys match
    /// `[A-Za-z_][A-Za-z0-9_]*` in full.
    pub environment: Vec<(String, Arg)>,
    /// `Restart=` policy.
    pub restart: RestartPolicy,
    /// `RestartSec=`, in seconds.
    pub restart_sec: u32,
    /// `LimitNOFILE=`, in descriptors. Non-zero when present.
    ///
    /// Absent means the unit inherits the host's soft limit, which is what
    /// every unit rendered before this field existed does. There is no
    /// spelling for systemd's `infinity` on purpose: a package that wants no
    /// limit omits the field, leaving the unbounded case the host's decision
    /// rather than a package's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_nofile: Option<u64>,
    /// Emits `ProtectHome=yes` when set.
    pub protect_home: bool,
    /// Emits `PrivateTmp=yes` when set.
    pub private_tmp: bool,
    /// Emits `NoNewPrivileges=yes` when set.
    pub no_new_privileges: bool,
}

/// A systemd target a unit may order itself against.
///
/// Closed on purpose: a package declares an ordering relationship from a fixed
/// vocabulary rather than naming an arbitrary unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemdTarget {
    /// `network-online.target`.
    NetworkOnline,
    /// `multi-user.target`.
    MultiUser,
}

impl SystemdTarget {
    /// Returns the unit-file string this target renders as.
    ///
    /// This is the *unit-file* spelling and is deliberately distinct from the
    /// enum's *manifest* spelling: neither is derived from the other, and
    /// changing one does not change the other.
    #[must_use]
    pub fn as_unit_str(self) -> &'static str {
        match self {
            Self::NetworkOnline => "network-online.target",
            Self::MultiUser => "multi-user.target",
        }
    }
}

/// A systemd restart policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// `Restart=always`.
    Always,
}

impl RestartPolicy {
    /// Returns the unit-file string this policy renders as, which is separate
    /// from its manifest spelling exactly as [`SystemdTarget::as_unit_str`] is.
    #[must_use]
    pub fn as_unit_str(self) -> &'static str {
        match self {
            Self::Always => "always",
        }
    }
}

/// One element of a unit-file argument list.
///
/// Typed argv elements are what make an unknown variable unrepresentable: a
/// name outside [`RenderVar`] fails to deserialize on every read path rather
/// than reaching a rendered `ExecStart=`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arg {
    /// A fixed string the package declares.
    Literal(String),
    /// A value the renderer resolves host-side.
    Var(RenderVar),
}

/// A value a unit template refers to and the renderer resolves on the host.
///
/// Closed on purpose, and extended only by adding a variant here — never by a
/// free-form escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderVar {
    /// Installed path of the artifact itself.
    ArtifactPath,
    /// Path of the module's configuration file.
    ConfigPath,
    /// Path of the module's data directory.
    DataDir,
    /// The per-instance id.
    InstanceId,
    /// The host label the module is placed on.
    Hostname,
    /// The internal-mTLS domain.
    Domain,
    /// Path of the module's issued certificate.
    CertPath,
    /// Path of the module's issued private key.
    KeyPath,
    /// Path of the CA bundle the module trusts.
    CaBundlePath,
    /// The endpoint of the manager this module is pointed at, as **one** argv
    /// element in the form `<server_name>@<address>:<port>`.
    ///
    /// One variant rather than three because [`Arg`] carries one element per
    /// entry and concatenates nothing, so three would render three arguments
    /// where the consuming module's parser expects one.
    ///
    /// Its parts, which the caller composing the value owns:
    ///
    /// - `server_name` is the peer's internal-mTLS server name — a
    ///   **certificate identity**. The module verifies the peer's presented
    ///   leaf against it, so it is what distinguishes the intended peer from
    ///   any other holder of a certificate under the same CA. It is not
    ///   resolved, and it is not the module's own name.
    /// - `address` is a **numeric address, never a name**: consumers parse
    ///   this value into a name plus a numeric socket address, and a name in
    ///   that position does not parse.
    /// - `port` is the peer's RPC port.
    ///
    /// That contract is documentation, not a check. Nothing in this crate
    /// splits the value on `@`, validates the port, or rejects a name in the
    /// address position; the format belongs to the consuming module's own
    /// argument parser, and a second parser here would be a second definition
    /// of it, free to drift from the one that actually reads it. The renderer
    /// holds the resolved value to the same representability rule every other
    /// host-resolved value passes, and substitutes it.
    ManagerEndpoint,
    /// systemd's own `$MAINPID` expansion. Permitted **only** inside
    /// [`UnitTemplate::exec_reload`], because that is the one place a real unit
    /// needs it.
    MainPid,
}

/// The host-agnostic static half of a bootroot registration: the same bytes on
/// every host and every instance.
///
/// Nothing per-installation lives here — no delivery mode, `AppRole`,
/// hostname, domain, instance id, cert or key path, agent config or secret-id
/// path — and in particular no already-resolved flag list. A consumer derives
/// the reload flags from the closed [`ReloadSpec`]; letting a package declare
/// raw flag strings would put attacker-chosen arguments into a root-run
/// `bootroot service add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationTemplate {
    /// The module's package id, carried as a plain string so a consumer that
    /// links no installer can read the template standalone. Must equal the
    /// enclosing artifact's `component`.
    pub package_id: String,
    /// The component's fixed service keyword, validated only as a DNS label.
    pub service_name: String,
    /// How the module is told to reload after a certificate renewal.
    pub reload: ReloadSpec,
    /// A concrete cert-ownership gid, or `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_group_gid: Option<u32>,
}

/// How a module is signalled to reload renewed trust material.
///
/// Both payloads become semantic arguments to a root-run command, so each
/// carries a domain grammar (see [`validate`]) rather than only the
/// systemd-representability rule. The grammars structurally exclude a leading
/// `-` and any whitespace or separator, so neither string can present itself as
/// an option to the command that consumes it or split into further arguments.
/// That is the specific and only property claimed: what bounds these values is
/// that the consumer places each in a fixed argv position of a fixed command,
/// and that the closed enum bounds how many such strings a package contributes
/// at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReloadSpec {
    /// `SIGHUP` to a native process.
    Sighup {
        /// Absolute path of the process to signal.
        process_path: String,
    },
    /// `SIGHUP` to a process inside a Docker container.
    DockerSighup {
        /// Name of the container to signal.
        container: String,
    },
}

/// Which class of host a module is placed on.
///
/// Closed to two values on purpose: a package is the same bytes on every host,
/// so it cannot name one. Enforcing a class against a resolved placement is the
/// renderer's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlacementClass {
    /// Hosts carrying the core stack.
    CoreHosts,
    /// Hosts carrying distributed modules.
    ModuleHosts,
}

/// Errors raised while validating a [`ModuleSpec`]. Each variant names the rule
/// that was violated.
#[derive(Debug, thiserror::Error)]
pub enum ModuleSpecError {
    /// The artifact's kind requires a unit template and the spec carries none.
    #[error("a spec on a `{0:?}` artifact must carry a unit template")]
    MissingUnit(ArtifactKind),
    /// The artifact's kind has no unit and the spec declared one.
    #[error("a spec on a `{0:?}` artifact must not carry a unit template")]
    UnexpectedUnit(ArtifactKind),
    /// `description` was empty.
    #[error("unit template `description` is empty")]
    EmptyDescription,
    /// `description` carried a character no unit file can represent.
    #[error("unit template `description` is not representable in a unit file: {0:?}")]
    UnrepresentableDescription(String),
    /// A `Literal` was the empty string.
    #[error("unit template carries an empty `literal`")]
    EmptyLiteral,
    /// A `Literal` carried a character no unit file can represent.
    #[error("unit template `literal` is not representable in a unit file: {0:?}")]
    UnrepresentableLiteral(String),
    /// An `environment` key did not match `[A-Za-z_][A-Za-z0-9_]*` in full.
    #[error("unit template `environment` key {0:?} is not a valid variable name")]
    InvalidEnvironmentKey(String),
    /// `exec_start` was empty.
    #[error("unit template `exec_start` is empty")]
    EmptyExecStart,
    /// `exec_start` did not begin with `Arg::Var(RenderVar::ArtifactPath)`.
    #[error("unit template `exec_start` must begin with the `artifact-path` variable")]
    ExecStartNotArtifactPath,
    /// `exec_reload` was present and empty.
    #[error("unit template `exec_reload` is present and empty")]
    EmptyExecReload,
    /// `limit_nofile` was present and zero.
    #[error("unit template `limit_nofile` is present and zero")]
    ZeroLimitNofile,
    /// `main-pid` appeared outside `exec_reload`.
    #[error("the `main-pid` variable is permitted only inside `exec_reload`")]
    MainPidOutsideExecReload,
    /// The registration template's `package_id` was not the enclosing
    /// artifact's `component`.
    #[error(
        "registration `package_id` `{package_id}` is not the artifact's component `{component}`"
    )]
    PackageIdMismatch {
        /// The declared package id.
        package_id: String,
        /// The enclosing artifact's component.
        component: String,
    },
    /// `service_name` was not a DNS label.
    #[error("registration `service_name` {0:?} is not a DNS label")]
    InvalidServiceName(String),
    /// A `sighup` reload declared a `process_path` that is not an absolute,
    /// argument-shaped path.
    #[error("reload `process_path` {0:?} is not an absolute path")]
    InvalidProcessPath(String),
    /// A `docker-sighup` reload declared a container name outside the Docker
    /// container-name grammar.
    #[error("reload `container` {0:?} is not a Docker container name")]
    InvalidContainerName(String),
}

/// Validates `spec` against every rule this module states, given the enclosing
/// artifact's `component` and `kind`.
///
/// Both extra parameters are load-bearing: the `package_id` rule compares
/// against exactly the enclosing `component`, and the kind-conditional unit
/// rule cannot be decided without the enclosing kind. Both are plain fields of
/// the artifact being installed, not catalogue lookups.
///
/// The kind rule applies to declared specs only — an artifact that declares no
/// spec is untouched and stays valid for every kind. [`PlacementClass`] needs
/// no check here: it is closed, so a value outside the two variants never
/// deserializes.
///
/// # Errors
///
/// Returns the [`ModuleSpecError`] variant naming the first rule violated: the
/// kind-conditional unit rule, the unit-template shape rules, the
/// character-rejection rule of [`crate::systemd::is_representable`], or the
/// registration-template rules and their domain grammars.
pub fn validate(
    spec: &ModuleSpec,
    component: &str,
    kind: ArtifactKind,
) -> Result<(), ModuleSpecError> {
    match (kind, spec.unit.as_ref()) {
        (ArtifactKind::NativeBinary | ArtifactKind::ComposeBundle, None) => {
            return Err(ModuleSpecError::MissingUnit(kind));
        }
        (ArtifactKind::StaticAssets | ArtifactKind::ContainerImage, Some(_)) => {
            return Err(ModuleSpecError::UnexpectedUnit(kind));
        }
        _ => {}
    }

    if let Some(unit) = &spec.unit {
        validate_unit(unit)?;
    }
    validate_registration(&spec.registration, component)
}

/// Validates the unit-template shape rules and the strings that become
/// unit-file text.
fn validate_unit(unit: &UnitTemplate) -> Result<(), ModuleSpecError> {
    if unit.description.is_empty() {
        return Err(ModuleSpecError::EmptyDescription);
    }
    if !is_representable(&unit.description) {
        return Err(ModuleSpecError::UnrepresentableDescription(
            unit.description.clone(),
        ));
    }

    let first = unit
        .exec_start
        .first()
        .ok_or(ModuleSpecError::EmptyExecStart)?;
    if *first != Arg::Var(RenderVar::ArtifactPath) {
        return Err(ModuleSpecError::ExecStartNotArtifactPath);
    }
    for arg in &unit.exec_start {
        validate_arg(arg, false)?;
    }

    if let Some(exec_reload) = &unit.exec_reload {
        if exec_reload.is_empty() {
            return Err(ModuleSpecError::EmptyExecReload);
        }
        for arg in exec_reload {
            validate_arg(arg, true)?;
        }
    }

    if let Some(working_directory) = &unit.working_directory {
        validate_arg(working_directory, false)?;
    }

    for (key, value) in &unit.environment {
        if !is_environment_key(key) {
            return Err(ModuleSpecError::InvalidEnvironmentKey(key.clone()));
        }
        validate_arg(value, false)?;
    }

    // Zero is not a limit a package can mean: it would deny the service every
    // descriptor, including the ones systemd hands it before `ExecStart=` runs.
    // Absence is how a package declines to set one.
    if unit.limit_nofile == Some(0) {
        return Err(ModuleSpecError::ZeroLimitNofile);
    }

    Ok(())
}

/// Validates one argument element. `main_pid_allowed` is set only for an
/// element of `exec_reload`.
fn validate_arg(arg: &Arg, main_pid_allowed: bool) -> Result<(), ModuleSpecError> {
    match arg {
        Arg::Literal(text) => {
            if text.is_empty() {
                Err(ModuleSpecError::EmptyLiteral)
            } else if is_representable(text) {
                Ok(())
            } else {
                Err(ModuleSpecError::UnrepresentableLiteral(text.clone()))
            }
        }
        Arg::Var(RenderVar::MainPid) if !main_pid_allowed => {
            Err(ModuleSpecError::MainPidOutsideExecReload)
        }
        Arg::Var(_) => Ok(()),
    }
}

/// Validates the registration template against the enclosing `component`.
fn validate_registration(
    registration: &RegistrationTemplate,
    component: &str,
) -> Result<(), ModuleSpecError> {
    if registration.package_id != component {
        return Err(ModuleSpecError::PackageIdMismatch {
            package_id: registration.package_id.clone(),
            component: component.to_string(),
        });
    }
    if !is_dns_label(&registration.service_name) {
        return Err(ModuleSpecError::InvalidServiceName(
            registration.service_name.clone(),
        ));
    }
    match &registration.reload {
        ReloadSpec::Sighup { process_path } => {
            if !is_absolute_process_path(process_path) {
                return Err(ModuleSpecError::InvalidProcessPath(process_path.clone()));
            }
        }
        ReloadSpec::DockerSighup { container } => {
            if !is_container_name(container) {
                return Err(ModuleSpecError::InvalidContainerName(container.clone()));
            }
        }
    }
    Ok(())
}

/// Reports whether `key` matches `[A-Za-z_][A-Za-z0-9_]*` in full — that exact
/// rule, not an approximation of a POSIX-shaped name.
fn is_environment_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Reports whether `value` is a non-empty DNS label: at most
/// [`MAX_DNS_LABEL_LEN`] octets of lowercase alphanumerics and hyphens, with no
/// leading or trailing hyphen.
///
/// Visible to the crate because [`crate::render`] holds each component of a
/// unit file name to this same rule, and a second predicate would be free to
/// drift from this one.
pub(crate) fn is_dns_label(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_DNS_LABEL_LEN {
        return false;
    }
    if value.starts_with('-') || value.ends_with('-') {
        return false;
    }
    value
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Reports whether `value` is an absolute path made only of bytes in
/// `0x21..=0x7E`, so it carries no whitespace, no control character and no NUL.
fn is_absolute_process_path(value: &str) -> bool {
    value.starts_with('/') && value.bytes().all(|byte| matches!(byte, 0x21..=0x7E))
}

/// Reports whether `value` matches `[a-zA-Z0-9][a-zA-Z0-9_.-]*` in full and is
/// at most [`MAX_CONTAINER_NAME_LEN`] octets.
fn is_container_name(value: &str) -> bool {
    if value.len() > MAX_CONTAINER_NAME_LEN {
        return false;
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    matches!(first, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
        && bytes.all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-'),
        )
}

#[cfg(test)]
mod tests {
    use super::{
        Arg, ModuleSpec, ModuleSpecError, PlacementClass, RegistrationTemplate, ReloadSpec,
        RenderVar, RestartPolicy, SystemdTarget, UnitTemplate, validate,
    };
    use crate::manifest::ArtifactKind;

    /// `RestartSec=` value the shipped anchors carry.
    const RESTART_SEC: u32 = 5;

    fn review_unit() -> UnitTemplate {
        UnitTemplate {
            description: "Clumit Security review".to_string(),
            after: vec![SystemdTarget::NetworkOnline],
            wants: vec![SystemdTarget::NetworkOnline],
            wanted_by: vec![SystemdTarget::MultiUser],
            exec_start: vec![
                Arg::Var(RenderVar::ArtifactPath),
                Arg::Var(RenderVar::ConfigPath),
            ],
            exec_reload: None,
            working_directory: Some(Arg::Var(RenderVar::DataDir)),
            environment: Vec::new(),
            restart: RestartPolicy::Always,
            restart_sec: RESTART_SEC,
            limit_nofile: None,
            protect_home: false,
            private_tmp: false,
            no_new_privileges: false,
        }
    }

    fn registration(package_id: &str) -> RegistrationTemplate {
        RegistrationTemplate {
            package_id: package_id.to_string(),
            service_name: "review".to_string(),
            reload: ReloadSpec::Sighup {
                process_path: "/opt/clumit-security/bin/review".to_string(),
            },
            cert_group_gid: None,
        }
    }

    fn spec(unit: Option<UnitTemplate>) -> ModuleSpec {
        ModuleSpec {
            unit,
            registration: registration("example"),
            placement: PlacementClass::CoreHosts,
        }
    }

    #[test]
    fn the_closed_enums_render_their_fixed_unit_file_strings() {
        assert_eq!(
            SystemdTarget::NetworkOnline.as_unit_str(),
            "network-online.target"
        );
        assert_eq!(SystemdTarget::MultiUser.as_unit_str(), "multi-user.target");
        assert_eq!(RestartPolicy::Always.as_unit_str(), "always");
        // The unit-file spellings are deliberately not the manifest ones.
        let manifest_spelling =
            serde_json::to_string(&SystemdTarget::NetworkOnline).expect("serialization");
        assert_eq!(manifest_spelling, "\"network-online\"");
    }

    #[test]
    fn the_kind_conditional_unit_rule_holds_for_all_four_kinds() {
        for kind in [ArtifactKind::NativeBinary, ArtifactKind::ComposeBundle] {
            validate(&spec(Some(review_unit())), "example", kind)
                .expect("a unit is required for this kind");
            let error = validate(&spec(None), "example", kind)
                .expect_err("a missing unit must be rejected");
            assert!(
                matches!(error, ModuleSpecError::MissingUnit(got) if got == kind),
                "got: {error:?}"
            );
        }
        for kind in [ArtifactKind::StaticAssets, ArtifactKind::ContainerImage] {
            validate(&spec(None), "example", kind).expect("no unit is correct for this kind");
            let error = validate(&spec(Some(review_unit())), "example", kind)
                .expect_err("a declared unit must be rejected");
            assert!(
                matches!(error, ModuleSpecError::UnexpectedUnit(got) if got == kind),
                "got: {error:?}"
            );
        }
    }

    /// Validates `unit` under the one kind that requires one.
    fn validate_unit_template(unit: UnitTemplate) -> Result<(), ModuleSpecError> {
        validate(&spec(Some(unit)), "example", ArtifactKind::NativeBinary)
    }

    #[test]
    fn exec_start_must_be_non_empty_and_start_at_the_artifact_path() {
        let mut empty = review_unit();
        empty.exec_start = Vec::new();
        assert!(matches!(
            validate_unit_template(empty).expect_err("empty exec_start"),
            ModuleSpecError::EmptyExecStart
        ));

        let mut wrong_head = review_unit();
        wrong_head.exec_start = vec![
            Arg::Literal("/bin/sh".to_string()),
            Arg::Var(RenderVar::ArtifactPath),
        ];
        assert!(matches!(
            validate_unit_template(wrong_head).expect_err("wrong first element"),
            ModuleSpecError::ExecStartNotArtifactPath
        ));
    }

    #[test]
    fn a_present_exec_reload_must_be_non_empty() {
        let mut unit = review_unit();
        unit.exec_reload = Some(Vec::new());
        assert!(matches!(
            validate_unit_template(unit).expect_err("empty exec_reload"),
            ModuleSpecError::EmptyExecReload
        ));
    }

    #[test]
    fn a_present_limit_nofile_must_be_non_zero() {
        // Absence is how a package declines to set a limit, so `None` is not a
        // violation; `Some(0)` is, because it would deny the service every
        // descriptor rather than raising anything.
        for limit in [None, Some(1), Some(8000), Some(u64::MAX)] {
            let mut unit = review_unit();
            unit.limit_nofile = limit;
            validate_unit_template(unit).expect("a non-zero or absent limit is valid");
        }

        let mut unit = review_unit();
        unit.limit_nofile = Some(0);
        let error = validate_unit_template(unit).expect_err("a zero limit must be rejected");
        assert!(
            matches!(error, ModuleSpecError::ZeroLimitNofile),
            "got: {error:?}"
        );
    }

    #[test]
    fn main_pid_is_confined_to_exec_reload() {
        let mut in_exec_start = review_unit();
        in_exec_start.exec_start.push(Arg::Var(RenderVar::MainPid));
        assert!(matches!(
            validate_unit_template(in_exec_start).expect_err("main-pid in exec_start"),
            ModuleSpecError::MainPidOutsideExecReload
        ));

        let mut in_working_directory = review_unit();
        in_working_directory.working_directory = Some(Arg::Var(RenderVar::MainPid));
        assert!(matches!(
            validate_unit_template(in_working_directory)
                .expect_err("main-pid in working_directory"),
            ModuleSpecError::MainPidOutsideExecReload
        ));

        let mut in_environment = review_unit();
        in_environment.environment = vec![("PID".to_string(), Arg::Var(RenderVar::MainPid))];
        assert!(matches!(
            validate_unit_template(in_environment).expect_err("main-pid in environment"),
            ModuleSpecError::MainPidOutsideExecReload
        ));

        let mut in_exec_reload = review_unit();
        in_exec_reload.exec_reload = Some(vec![
            Arg::Literal("/bin/kill".to_string()),
            Arg::Var(RenderVar::MainPid),
        ]);
        validate_unit_template(in_exec_reload).expect("main-pid is allowed in exec_reload");
    }

    #[test]
    fn every_rejected_character_class_is_rejected_in_every_position() {
        for bad in ["\0", "a\0b", "a\nb", "a\rb", "a\x07b"] {
            let mut literal = review_unit();
            literal.exec_start.push(Arg::Literal(bad.to_string()));
            assert!(
                matches!(
                    validate_unit_template(literal).expect_err("literal"),
                    ModuleSpecError::UnrepresentableLiteral(_)
                ),
                "literal {bad:?}"
            );

            let mut key = review_unit();
            key.environment = vec![(format!("A{bad}"), Arg::Literal("v".to_string()))];
            assert!(
                matches!(
                    validate_unit_template(key).expect_err("environment key"),
                    ModuleSpecError::InvalidEnvironmentKey(_)
                ),
                "key {bad:?}"
            );

            let mut value = review_unit();
            value.environment = vec![("A".to_string(), Arg::Literal(bad.to_string()))];
            assert!(
                matches!(
                    validate_unit_template(value).expect_err("environment value"),
                    ModuleSpecError::UnrepresentableLiteral(_)
                ),
                "value {bad:?}"
            );

            let mut description = review_unit();
            description.description = format!("d{bad}");
            assert!(
                matches!(
                    validate_unit_template(description).expect_err("description"),
                    ModuleSpecError::UnrepresentableDescription(_)
                ),
                "description {bad:?}"
            );
        }
    }

    #[test]
    fn the_empty_string_is_rejected_in_each_position_by_its_own_rule() {
        let mut literal = review_unit();
        literal.exec_start.push(Arg::Literal(String::new()));
        assert!(matches!(
            validate_unit_template(literal).expect_err("empty literal"),
            ModuleSpecError::EmptyLiteral
        ));

        let mut value = review_unit();
        value.environment = vec![("A".to_string(), Arg::Literal(String::new()))];
        assert!(matches!(
            validate_unit_template(value).expect_err("empty environment value"),
            ModuleSpecError::EmptyLiteral
        ));

        let mut key = review_unit();
        key.environment = vec![(String::new(), Arg::Literal("v".to_string()))];
        assert!(matches!(
            validate_unit_template(key).expect_err("empty environment key"),
            ModuleSpecError::InvalidEnvironmentKey(_)
        ));

        let mut description = review_unit();
        description.description = String::new();
        assert!(matches!(
            validate_unit_template(description).expect_err("empty description"),
            ModuleSpecError::EmptyDescription
        ));
    }

    #[test]
    fn the_environment_key_grammar_is_the_stated_one() {
        for good in ["_A0", "PATH", "a", "_", "A_1_b"] {
            let mut unit = review_unit();
            unit.environment = vec![(good.to_string(), Arg::Literal("v".to_string()))];
            validate_unit_template(unit).unwrap_or_else(|error| {
                panic!("key {good:?} must be accepted, got {error:?}");
            });
        }
        for bad in ["1BAD", "A-B", "", "A B", "A.B", "Ä"] {
            let mut unit = review_unit();
            unit.environment = vec![(bad.to_string(), Arg::Literal("v".to_string()))];
            let error = validate_unit_template(unit).expect_err("bad key");
            assert!(
                matches!(error, ModuleSpecError::InvalidEnvironmentKey(_)),
                "key {bad:?} got: {error:?}"
            );
        }
    }

    /// Validates a registration carrying `reload` under a matching component.
    fn validate_reload(reload: ReloadSpec) -> Result<(), ModuleSpecError> {
        let mut declared = spec(Some(review_unit()));
        declared.registration.reload = reload;
        validate(&declared, "example", ArtifactKind::NativeBinary)
    }

    #[test]
    fn the_process_path_grammar_is_an_absolute_argument_shaped_path() {
        validate_reload(ReloadSpec::Sighup {
            process_path: "/opt/clumit-security/bin/roxyd".to_string(),
        })
        .expect("an absolute path is accepted");

        for bad in ["roxyd", "-c", "/opt/a b", "", "/opt/a\nb"] {
            let error = validate_reload(ReloadSpec::Sighup {
                process_path: bad.to_string(),
            })
            .expect_err("a non-path must be rejected");
            assert!(
                matches!(error, ModuleSpecError::InvalidProcessPath(_)),
                "path {bad:?} got: {error:?}"
            );
        }
    }

    #[test]
    fn the_container_name_grammar_is_the_docker_one() {
        for good in ["giganto", "review_1.0-a", "A0"] {
            validate_reload(ReloadSpec::DockerSighup {
                container: good.to_string(),
            })
            .unwrap_or_else(|error| panic!("container {good:?} must be accepted, got {error:?}"));
        }
        for bad in ["-net", "a/b", "", ".x", "a b"] {
            let error = validate_reload(ReloadSpec::DockerSighup {
                container: bad.to_string(),
            })
            .expect_err("a non-name must be rejected");
            assert!(
                matches!(error, ModuleSpecError::InvalidContainerName(_)),
                "container {bad:?} got: {error:?}"
            );
        }
    }

    #[test]
    fn the_package_id_must_equal_the_enclosing_component() {
        let declared = spec(Some(review_unit()));
        validate(&declared, "example", ArtifactKind::NativeBinary).expect("matching component");

        let error = validate(&declared, "other", ArtifactKind::NativeBinary)
            .expect_err("a mismatched package_id must be rejected");
        assert!(
            matches!(
                error,
                ModuleSpecError::PackageIdMismatch { ref package_id, ref component }
                    if package_id == "example" && component == "other"
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn the_service_name_is_validated_only_as_a_dns_label() {
        for good in ["review", "roxyd", "a", "a-b-1", &"a".repeat(63)] {
            let mut declared = spec(Some(review_unit()));
            declared.registration.service_name = good.to_string();
            validate(&declared, "example", ArtifactKind::NativeBinary)
                .unwrap_or_else(|error| panic!("label {good:?} must be accepted, got {error:?}"));
        }
        for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"a".repeat(64)] {
            let mut declared = spec(Some(review_unit()));
            declared.registration.service_name = bad.to_string();
            let error = validate(&declared, "example", ArtifactKind::NativeBinary)
                .expect_err("a non-label must be rejected");
            assert!(
                matches!(error, ModuleSpecError::InvalidServiceName(_)),
                "label {bad:?} got: {error:?}"
            );
        }
    }

    /// The wire form of a spec spelling every convention out: kebab-case enum
    /// variants, externally tagged `Arg` and `ReloadSpec`, `environment` as
    /// two-element arrays, and `snake_case` struct fields.
    const WIRE_SPEC: &str = r#"{"unit":{"description":"Clumit Security review","after":["network-online"],"wants":["network-online"],"wanted_by":["multi-user"],"exec_start":[{"var":"artifact-path"},{"literal":"-c"},{"var":"config-path"}],"exec_reload":[{"literal":"/bin/kill"},{"var":"main-pid"}],"working_directory":{"var":"data-dir"},"environment":[["RUST_LOG",{"literal":"info"}],["HOST",{"var":"hostname"}]],"restart":"always","restart_sec":5,"protect_home":true,"private_tmp":false,"no_new_privileges":true},"registration":{"package_id":"example","service_name":"review","reload":{"docker-sighup":{"container":"giganto"}},"cert_group_gid":1000},"placement":"module-hosts"}"#;

    #[test]
    fn the_wire_form_deserializes_into_the_expected_record_and_back_to_the_same_bytes() {
        let decoded: ModuleSpec = serde_json::from_str(WIRE_SPEC).expect("wire form must decode");

        let unit = decoded.unit.as_ref().expect("a unit is declared");
        assert_eq!(unit.description, "Clumit Security review");
        assert_eq!(unit.after, vec![SystemdTarget::NetworkOnline]);
        assert_eq!(unit.wants, vec![SystemdTarget::NetworkOnline]);
        assert_eq!(unit.wanted_by, vec![SystemdTarget::MultiUser]);
        assert_eq!(
            unit.exec_start,
            vec![
                Arg::Var(RenderVar::ArtifactPath),
                Arg::Literal("-c".to_string()),
                Arg::Var(RenderVar::ConfigPath),
            ]
        );
        assert_eq!(
            unit.exec_reload,
            Some(vec![
                Arg::Literal("/bin/kill".to_string()),
                Arg::Var(RenderVar::MainPid),
            ])
        );
        assert_eq!(unit.working_directory, Some(Arg::Var(RenderVar::DataDir)));
        assert_eq!(
            unit.environment,
            vec![
                ("RUST_LOG".to_string(), Arg::Literal("info".to_string())),
                ("HOST".to_string(), Arg::Var(RenderVar::Hostname)),
            ]
        );
        assert_eq!(unit.restart, RestartPolicy::Always);
        assert_eq!(unit.restart_sec, RESTART_SEC);
        // The anchor sets no limit, so this is also the assertion that an
        // unchanged package's bytes did not move when the field was added.
        assert_eq!(unit.limit_nofile, None);
        assert!(unit.protect_home);
        assert!(!unit.private_tmp);
        assert!(unit.no_new_privileges);
        assert_eq!(decoded.registration.package_id, "example");
        assert_eq!(decoded.registration.service_name, "review");
        assert_eq!(
            decoded.registration.reload,
            ReloadSpec::DockerSighup {
                container: "giganto".to_string(),
            }
        );
        assert_eq!(decoded.registration.cert_group_gid, Some(1000));
        assert_eq!(decoded.placement, PlacementClass::ModuleHosts);

        let re_encoded = serde_json::to_string(&decoded).expect("serialization must succeed");
        assert_eq!(re_encoded, WIRE_SPEC);
    }

    #[test]
    fn limit_nofile_round_trips_only_when_it_is_present() {
        // The absent case is asserted as whole bytes by the wire-form test
        // above; what this adds is the present one, on the same anchor, so the
        // two differ by exactly the key under test.
        const LIMIT: u64 = 8000;
        let with_limit = WIRE_SPEC.replace(
            r#""restart_sec":5,"#,
            &format!(r#""restart_sec":5,"limit_nofile":{LIMIT},"#),
        );
        let decoded: ModuleSpec =
            serde_json::from_str(&with_limit).expect("a declared limit must decode");
        let unit = decoded.unit.as_ref().expect("a unit is declared");
        assert_eq!(unit.limit_nofile, Some(LIMIT));
        let re_encoded = serde_json::to_string(&decoded).expect("serialization must succeed");
        assert_eq!(re_encoded, with_limit);

        // An explicit `null` is not a spelling of absence here: the field is
        // `Option`, so it decodes, and what it must not do is round-trip back
        // to a `null` key.
        let with_null = WIRE_SPEC.replace(
            r#""restart_sec":5,"#,
            r#""restart_sec":5,"limit_nofile":null,"#,
        );
        let decoded: ModuleSpec =
            serde_json::from_str(&with_null).expect("an explicit null must decode");
        assert_eq!(
            decoded
                .unit
                .as_ref()
                .expect("a unit is declared")
                .limit_nofile,
            None
        );
        let re_encoded = serde_json::to_string(&decoded).expect("serialization must succeed");
        assert_eq!(re_encoded, WIRE_SPEC);

        // The new field does not open the record: a sibling beside it is still
        // refused, and so is a value outside the field's own domain.
        assert!(
            serde_json::from_str::<ModuleSpec>(
                &with_limit.replace(r#""limit_nofile""#, r#""limit_nproc":64,"limit_nofile""#)
            )
            .is_err(),
            "a second `Limit*` key must not decode"
        );
        assert!(
            serde_json::from_str::<ModuleSpec>(&WIRE_SPEC.replace(
                r#""restart_sec":5,"#,
                r#""restart_sec":5,"limit_nofile":"infinity","#
            ))
            .is_err(),
            "`infinity` must not be expressible"
        );
        assert!(
            serde_json::from_str::<ModuleSpec>(&WIRE_SPEC.replace(
                r#""restart_sec":5,"#,
                r#""restart_sec":5,"limit_nofile":-1,"#
            ))
            .is_err(),
            "a negative sentinel must not be expressible"
        );
    }

    #[test]
    fn every_render_var_spells_its_kebab_case_name() {
        for (var, spelling) in [
            (RenderVar::ArtifactPath, "artifact-path"),
            (RenderVar::ConfigPath, "config-path"),
            (RenderVar::DataDir, "data-dir"),
            (RenderVar::InstanceId, "instance-id"),
            (RenderVar::Hostname, "hostname"),
            (RenderVar::Domain, "domain"),
            (RenderVar::CertPath, "cert-path"),
            (RenderVar::KeyPath, "key-path"),
            (RenderVar::CaBundlePath, "ca-bundle-path"),
            (RenderVar::ManagerEndpoint, "manager-endpoint"),
            (RenderVar::MainPid, "main-pid"),
        ] {
            let encoded = serde_json::to_string(&var).expect("serialization");
            assert_eq!(encoded, format!("\"{spelling}\""));
            let decoded: RenderVar =
                serde_json::from_str(&encoded).expect("deserialization must round-trip");
            assert_eq!(decoded, var);
        }
        assert_eq!(
            serde_json::to_string(&PlacementClass::CoreHosts).expect("serialization"),
            "\"core-hosts\""
        );
    }

    #[test]
    fn a_template_naming_the_manager_endpoint_decodes_as_one_argv_element() {
        let decoded: Vec<Arg> =
            serde_json::from_str(r#"[{"var":"manager-endpoint"}]"#).expect("the element decodes");
        assert_eq!(decoded, vec![Arg::Var(RenderVar::ManagerEndpoint)]);
    }

    #[test]
    fn an_unknown_render_var_name_fails_to_deserialize() {
        // A name no variant can be mistaken for: `RenderVar` is closed, so
        // what this pins is that a name outside it decodes nowhere.
        let error = serde_json::from_str::<Arg>(r#"{"var":"no-such-variable"}"#)
            .expect_err("an unknown variable must not decode");
        assert!(error.to_string().contains("no-such-variable"), "{error}");
        // The alternative this schema rejects — free text with a placeholder —
        // is not a decodable `Arg` either.
        assert!(serde_json::from_str::<Arg>(r#""{{config}}""#).is_err());
    }

    #[test]
    fn an_unknown_field_is_rejected_by_every_spec_struct() {
        assert!(
            serde_json::from_str::<ModuleSpec>(
                &WIRE_SPEC.replace(r#""placement""#, r#""surprise":1,"placement""#)
            )
            .is_err(),
            "ModuleSpec must deny unknown fields"
        );
        assert!(
            serde_json::from_str::<ModuleSpec>(
                &WIRE_SPEC.replace(r#""description""#, r#""raw_unit":"x","description""#)
            )
            .is_err(),
            "UnitTemplate must deny unknown fields"
        );
        // The specific field the closed registration record exists to exclude:
        // an already-resolved flag list a package must not be able to declare.
        assert!(
            serde_json::from_str::<ModuleSpec>(
                &WIRE_SPEC.replace(r#""package_id""#, r#""reload_args":["-x"],"package_id""#)
            )
            .is_err(),
            "RegistrationTemplate must deny `reload_args`"
        );
        assert!(
            serde_json::from_str::<ReloadSpec>(r#"{"sighup":{"process_path":"/a","extra":1}}"#)
                .is_err(),
            "ReloadSpec's struct variants must deny unknown fields"
        );
    }

    #[test]
    fn a_registration_template_omitting_reload_fails_to_deserialize() {
        // `reload` is required rather than optional, so a template that declares
        // none is refused by the decode instead of reaching a consumer that
        // would have to invent a reload for it.
        let without_reload =
            WIRE_SPEC.replace(r#""reload":{"docker-sighup":{"container":"giganto"}},"#, "");
        assert!(
            !without_reload.contains("docker-sighup"),
            "{without_reload}"
        );
        let error = serde_json::from_str::<ModuleSpec>(&without_reload)
            .expect_err("an omitted `reload` must not decode");
        assert!(error.to_string().contains("reload"), "{error}");
    }

    #[test]
    fn a_spec_with_no_unit_and_no_gid_omits_both_keys() {
        // Asserted as whole bytes rather than as two absent substrings, so this
        // pins the wire form a producer emits for a unitless spec — key order
        // included — and not merely that two names are missing from it.
        let json = serde_json::to_string(&spec(None)).expect("serialization");
        assert_eq!(
            json,
            r#"{"registration":{"package_id":"example","service_name":"review","reload":{"sighup":{"process_path":"/opt/clumit-security/bin/review"}}},"placement":"core-hosts"}"#
        );
    }
}
