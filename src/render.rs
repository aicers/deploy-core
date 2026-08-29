//! The generic renderer that turns a declared [`ModuleSpec`] into systemd unit
//! text, and the placement check that says whether the artifact belongs on this
//! host at all.
//!
//! Everything here is parameterized by spec data plus a [`RenderContext`], and
//! nothing in it names a product: there is no component catalogue, no product
//! manifest and no package-id registry in any signature, because a consumer
//! installs modules on hosts where no catalogue exists. Catalogue-dependent
//! checks — that a package id is registered, that a service keyword matches its
//! recipe — belong to release tooling on a machine that has the recipe, not to
//! the install path.
//!
//! The renderer **renders**; it does not decide when to render. Choosing
//! between a declared spec and a caller's own per-component renderer, resolving
//! each context value from an install's layout, writing the file and reloading
//! systemd are all caller concerns.
//!
//! Two properties are worth stating because they are deliberate rather than
//! incidental:
//!
//! - The whole [`ModuleSpec`] is re-checked by [`crate::module_spec::validate`]
//!   at its full arity on every call, because this is the last step before a
//!   root-executed unit reaches disk. The registration template is therefore
//!   *validated* here and *read* nowhere here: no field of it influences a
//!   rendered byte, the unit file name, or the placement decision.
//! - A spec that declares no unit is a valid input, not a refusal. The
//!   kind-conditional unit rule has exactly one owner — the validator — so a
//!   caller never has to inspect [`ArtifactKind`] before calling.

use crate::executor::ServiceAccount;
use crate::manifest::ArtifactKind;
use crate::module_spec::{
    Arg, ModuleSpec, ModuleSpecError, PlacementClass, RenderVar, UnitTemplate, is_dns_label,
    validate,
};
use crate::systemd::{self, UnitValue, is_representable};

/// Operator-facing reason a [`PlacementClass::CoreHosts`] artifact is refused.
const CORE_HOSTS_REASON: &str = "this host is not assigned the artifact's component";

/// Operator-facing reason a [`PlacementClass::ModuleHosts`] artifact is
/// refused.
const MODULE_HOSTS_REASON: &str = "this host carries no distributed modules";

/// Everything the renderer needs, resolved by the caller.
///
/// The context is **total**: there is one field per host-resolved
/// [`RenderVar`] variant, so resolving a variable is a field access that cannot
/// miss — no map lookup and no empty-string fallback.
/// [`RenderVar::MainPid`] is the one variant with no field, because it is
/// systemd's own expansion rather than a value anybody resolves.
///
/// One of those fields is an `Option`, because its value is genuinely absent
/// for some modules rather than empty: [`Self::manager_endpoint`], which a
/// caller with no such peer supplies as `None`. Absence is not a fallback — a
/// template naming that variable against a `None` field is
/// [`RenderError::UnresolvedVariable`], never a default, an empty string or a
/// placeholder.
#[derive(Debug, Clone, Copy)]
pub struct RenderContext<'a> {
    /// Installed path of the artifact itself ([`RenderVar::ArtifactPath`]).
    pub artifact_path: &'a str,
    /// Path of the module's configuration file ([`RenderVar::ConfigPath`]).
    pub config_path: &'a str,
    /// Path of the module's data directory ([`RenderVar::DataDir`]).
    pub data_dir: &'a str,
    /// The per-instance id ([`RenderVar::InstanceId`]).
    ///
    /// Always supplied, including for a singleton, because config paths and
    /// data directories are instance-scoped for every component. It is an
    /// opaque already-formatted string: the renderer never pads it, parses it,
    /// or derives it from [`Self::instance`].
    pub instance_id: &'a str,
    /// The host label the module is placed on ([`RenderVar::Hostname`]).
    pub hostname: &'a str,
    /// The internal-mTLS domain ([`RenderVar::Domain`]).
    pub domain: &'a str,
    /// Path of the module's issued certificate ([`RenderVar::CertPath`]).
    pub cert_path: &'a str,
    /// Path of the module's issued private key ([`RenderVar::KeyPath`]).
    pub key_path: &'a str,
    /// Path of the CA bundle the module trusts
    /// ([`RenderVar::CaBundlePath`]).
    pub ca_bundle_path: &'a str,
    /// The endpoint of the manager this module is pointed at
    /// ([`RenderVar::ManagerEndpoint`]), or `None` for a module with no such
    /// peer.
    ///
    /// An `Option` for the same reason [`Self::service_account`] is: the value
    /// is genuinely absent for a module that takes no manager argument, and a
    /// caller in that position says so rather than supplying a placeholder
    /// string that would render. A template that never names the variable
    /// needs no value.
    ///
    /// Composing the value — the peer's certificate identity, its numeric
    /// address and its port — is the caller's, whose contract
    /// [`RenderVar::ManagerEndpoint`] states. The renderer substitutes it and
    /// parses nothing.
    pub manager_endpoint: Option<&'a str>,
    /// The account the service runs as, or `None` for a root-run unit.
    ///
    /// `Some` emits `User=<account>`; `None` emits no `User=` line at all,
    /// which is how a root-run unit is expressed. This is a
    /// [`ServiceAccount`] rather than a string precisely so an account name
    /// read from operator input or off the host cannot become the identity a
    /// service runs as.
    pub service_account: Option<ServiceAccount>,
    /// Unit-file-name prefix. A DNS label.
    pub namespace: &'a str,
    /// Unit-file-name service keyword. A DNS label.
    ///
    /// Deliberately taken from the context and never from
    /// [`crate::module_spec::RegistrationTemplate::service_name`], even though
    /// the two normally agree: the duplication is what makes "the renderer
    /// does not reach into the registration template" a property rather than a
    /// convention.
    pub service_name: &'a str,
    /// The file-name discriminator only: `Some` for a many-per-host component
    /// and `None` for a singleton, which selects the un-suffixed unit name.
    ///
    /// This is **not** [`Self::instance_id`], which is always supplied and
    /// always resolves. Neither is derived from the other.
    pub instance: Option<&'a str>,
    /// The enclosing artifact's component, for
    /// [`crate::module_spec::validate`] only. Nothing is looked up with it and
    /// it reaches no rendered byte.
    pub component: &'a str,
    /// The enclosing artifact's kind, for [`crate::module_spec::validate`]
    /// only. Nothing is looked up with it and it reaches no rendered byte.
    pub kind: ArtifactKind,
}

/// A rendered systemd unit: its text and the file name it is written under.
///
/// This crate produces both and writes neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedUnit {
    /// The unit file's name, `<namespace>-<service_name>.service` or
    /// `<namespace>-<service_name>-<instance>.service`.
    pub file_name: String,
    /// The unit file's whole text, trailing newline included.
    pub text: String,
}

/// Which context field a rejected unit-file-name component came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameField {
    /// [`RenderContext::namespace`].
    Namespace,
    /// [`RenderContext::service_name`].
    ServiceName,
    /// [`RenderContext::instance`].
    Instance,
}

impl NameField {
    /// Returns the context field's name as it appears in an error message.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::ServiceName => "service_name",
            Self::Instance => "instance",
        }
    }
}

impl std::fmt::Display for NameField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The caller's resolved placement facts for the host being rendered for.
///
/// Two independent booleans rather than one host class, which is what makes
/// co-location structural: a single-host topology sets both, and each
/// [`PlacementClass`] reads its own fact and ignores the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementFacts {
    /// Whether the caller's placement assigns **this artifact's component** to
    /// this host.
    pub component_assigned: bool,
    /// Whether the caller's placement carries **distributed modules** on this
    /// host.
    pub carries_modules: bool,
}

/// Errors raised while rendering a unit or checking a placement class.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// The declared spec did not pass [`crate::module_spec::validate`]. It is
    /// re-checked here because this is the last step before a root-executed
    /// unit reaches disk.
    #[error("the declared module spec is invalid: {0}")]
    InvalidSpec(#[from] ModuleSpecError),
    /// A host-resolved variable value cannot appear in a unit file. Package
    /// literals were checked when the manifest was read; a hostname, a domain
    /// or a configured path is host input and reaches the same root-executed
    /// line.
    #[error("the resolved `{var:?}` value is not representable in a unit file: {value:?}")]
    UnrepresentableValue {
        /// The variable whose resolved value was rejected.
        var: RenderVar,
        /// The rejected value.
        value: String,
    },
    /// The template names a variable the context supplies no value for. Only
    /// an optional context field can reach this, and the refusal is the whole
    /// answer: the resolved value reaches a root-executed `ExecStart=` and
    /// decides which peer a module trusts, so there is no default, no empty
    /// string and no placeholder to fall back to.
    #[error("the template names `{var:?}`, for which this context supplies no value")]
    UnresolvedVariable {
        /// The variable the context left unresolved.
        var: RenderVar,
    },
    /// A component of the unit file name is not a DNS label. That name becomes
    /// the path of a root-executed unit file, so the shape is enforced before
    /// anything is produced.
    #[error("unit file name component `{field}` is not a DNS label: {value:?}")]
    InvalidNameComponent {
        /// Which context field carried the offending value.
        field: NameField,
        /// The rejected value.
        value: String,
    },
    /// The declared placement class does not hold on this host.
    #[error("a `{class:?}` artifact does not belong on this host: {reason}")]
    PlacementRefused {
        /// The class the package declared.
        class: PlacementClass,
        /// An operator-facing reason naming the fact that was clear.
        reason: &'static str,
    },
}

/// Renders the systemd unit `spec` declares, or reports that it declares none.
///
/// The whole `spec` goes through [`crate::module_spec::validate`] at its full
/// three-argument arity first, using [`RenderContext::component`] and
/// [`RenderContext::kind`] — the identical function the manifest read path
/// calls, never a narrower variant. Only then is anything rendered, so a
/// failing spec produces no partial output.
///
/// Returns `Ok(None)` when the validated spec carries no unit template, which
/// is the normal answer for an [`ArtifactKind::StaticAssets`] or
/// [`ArtifactKind::ContainerImage`] artifact rather than a failure. `None`
/// means "this valid spec asks for no unit", never "this spec was not
/// checked".
///
/// Rendering the same spec and context twice produces byte-identical output.
///
/// # Errors
///
/// Returns [`RenderError::InvalidSpec`] when the declared spec violates any
/// validator rule, [`RenderError::InvalidNameComponent`] when
/// [`RenderContext::namespace`], [`RenderContext::service_name`] or
/// [`RenderContext::instance`] is not a DNS label, and
/// [`RenderError::UnrepresentableValue`] when a resolved variable value cannot
/// appear in a unit file — which, by [`crate::systemd::is_representable`],
/// covers the empty string as well as every control character. A template
/// naming a variable whose optional context field is `None` returns
/// [`RenderError::UnresolvedVariable`] rather than rendering anything in its
/// place.
pub fn render_unit(
    spec: &ModuleSpec,
    context: &RenderContext<'_>,
) -> Result<Option<RenderedUnit>, RenderError> {
    validate(spec, context.component, context.kind)?;
    let Some(unit) = spec.unit.as_ref() else {
        return Ok(None);
    };

    let file_name = unit_file_name(context)?;
    let text = render_text(unit, context)?;
    Ok(Some(RenderedUnit { file_name, text }))
}

/// Reports whether an artifact declaring `class` may be installed on a host
/// whose resolved placement is `facts`.
///
/// Each class reads its own fact and ignores the other:
/// [`PlacementClass::CoreHosts`] is accepted only when
/// [`PlacementFacts::component_assigned`] is set, and
/// [`PlacementClass::ModuleHosts`] only when
/// [`PlacementFacts::carries_modules`] is. A co-located host sets both, so a
/// `module-hosts` artifact is accepted there because the module-host fact is
/// set — not because the core fact is; and a host carrying core components but
/// no distributed modules refuses a `module-hosts` artifact even though the
/// core fact is set.
///
/// The renderer never resolves placement itself: only the caller knows the
/// install's topology.
///
/// # Errors
///
/// Returns [`RenderError::PlacementRefused`], carrying an operator-facing
/// reason, when the class's own fact is clear. No combination of facts panics.
pub fn check_placement(class: PlacementClass, facts: PlacementFacts) -> Result<(), RenderError> {
    let (satisfied, reason) = match class {
        PlacementClass::CoreHosts => (facts.component_assigned, CORE_HOSTS_REASON),
        PlacementClass::ModuleHosts => (facts.carries_modules, MODULE_HOSTS_REASON),
    };
    if satisfied {
        Ok(())
    } else {
        Err(RenderError::PlacementRefused { class, reason })
    }
}

/// Builds the unit file name from the context alone, after holding each of its
/// three components to the crate's single DNS-label rule.
///
/// The shape structurally excludes a path separator, a `..` segment and any
/// whitespace from reaching the name of a root-executed unit file.
fn unit_file_name(context: &RenderContext<'_>) -> Result<String, RenderError> {
    check_label(NameField::Namespace, context.namespace)?;
    check_label(NameField::ServiceName, context.service_name)?;
    let Some(instance) = context.instance else {
        return Ok(format!(
            "{}-{}.service",
            context.namespace, context.service_name
        ));
    };
    check_label(NameField::Instance, instance)?;
    Ok(format!(
        "{}-{}-{}.service",
        context.namespace, context.service_name, instance
    ))
}

/// Holds one file-name component to [`is_dns_label`] — the crate's existing
/// predicate, never a second copy of the rule.
fn check_label(field: NameField, value: &str) -> Result<(), RenderError> {
    if is_dns_label(value) {
        Ok(())
    } else {
        Err(RenderError::InvalidNameComponent {
            field,
            value: value.to_string(),
        })
    }
}

/// Renders `unit` in the canonical layout fixed by [`UnitTemplate`]'s rustdoc.
///
/// The order is not chosen here: it is read off that record's documentation,
/// which is the single owner of the layout.
fn render_text(unit: &UnitTemplate, context: &RenderContext<'_>) -> Result<String, RenderError> {
    let mut lines = vec![
        "[Unit]".to_string(),
        format!(
            "Description={}",
            systemd::render(UnitValue::Description(&unit.description))
        ),
    ];
    for target in &unit.after {
        lines.push(format!("After={}", target.as_unit_str()));
    }
    for target in &unit.wants {
        lines.push(format!("Wants={}", target.as_unit_str()));
    }

    lines.push(String::new());
    lines.push("[Service]".to_string());
    // The account is a closed compile-time constant, exactly like a
    // `SystemdTarget`'s unit-file spelling, so it is emitted as it stands
    // rather than through the escaping rule that package-declared values need.
    if let Some(account) = context.service_account {
        lines.push(format!("User={}", account.as_str()));
    }
    lines.push(format!(
        "ExecStart={}",
        render_args(&unit.exec_start, context)?
    ));
    if let Some(exec_reload) = &unit.exec_reload {
        lines.push(format!("ExecReload={}", render_args(exec_reload, context)?));
    }
    if let Some(working_directory) = &unit.working_directory {
        lines.push(format!(
            "WorkingDirectory={}",
            render_arg(working_directory, context)?
        ));
    }
    for (key, value) in &unit.environment {
        // The escaping applies to the whole `KEY=VALUE` body, so the value is
        // resolved to raw text here rather than pre-rendered as an argument.
        let raw = resolve_raw(value, context)?;
        lines.push(format!(
            "Environment={}",
            systemd::render(UnitValue::Environment { key, value: &raw })
        ));
    }
    lines.push(format!("Restart={}", unit.restart.as_unit_str()));
    lines.push(format!("RestartSec={}", unit.restart_sec));
    if let Some(limit_nofile) = unit.limit_nofile {
        lines.push(format!("LimitNOFILE={limit_nofile}"));
    }
    if unit.protect_home {
        lines.push("ProtectHome=yes".to_string());
    }
    if unit.private_tmp {
        lines.push("PrivateTmp=yes".to_string());
    }
    if unit.no_new_privileges {
        lines.push("NoNewPrivileges=yes".to_string());
    }

    lines.push(String::new());
    lines.push("[Install]".to_string());
    for target in &unit.wanted_by {
        lines.push(format!("WantedBy={}", target.as_unit_str()));
    }

    let mut text = lines.join("\n");
    text.push('\n');
    Ok(text)
}

/// An argument element resolved to what it contributes: host or package text,
/// or systemd's own expansion.
enum Resolved<'a> {
    /// Raw text, already held to [`is_representable`] when it came from the
    /// context.
    Text(&'a str),
    /// [`RenderVar::MainPid`], which systemd expands itself.
    MainPid,
}

/// Renders one argument list, joined with a single space.
fn render_args(args: &[Arg], context: &RenderContext<'_>) -> Result<String, RenderError> {
    let mut rendered = Vec::with_capacity(args.len());
    for arg in args {
        rendered.push(render_arg(arg, context)?);
    }
    Ok(rendered.join(" "))
}

/// Renders one argument element through the shared serialization helper.
fn render_arg(arg: &Arg, context: &RenderContext<'_>) -> Result<String, RenderError> {
    Ok(match resolve(arg, context)? {
        Resolved::Text(text) => systemd::render(UnitValue::Argument(text)),
        Resolved::MainPid => systemd::render(UnitValue::MainPid),
    })
}

/// Resolves one argument element to raw text, for the one position — an
/// environment value — whose escaping happens on the whole `KEY=VALUE`.
fn resolve_raw(arg: &Arg, context: &RenderContext<'_>) -> Result<String, RenderError> {
    Ok(match resolve(arg, context)? {
        Resolved::Text(text) => text.to_string(),
        Resolved::MainPid => systemd::render(UnitValue::MainPid),
    })
}

/// Resolves one argument element against the context.
fn resolve<'a>(arg: &'a Arg, context: &RenderContext<'a>) -> Result<Resolved<'a>, RenderError> {
    match arg {
        Arg::Literal(text) => Ok(Resolved::Text(text)),
        Arg::Var(var) => resolve_var(*var, context),
    }
}

/// Resolves one variable against the context, holding what the host resolved
/// to the crate's single representability rule.
///
/// That one call is the whole check: it already refuses the empty string as
/// well as every control character, so nothing is layered on top of it — no
/// variable gets a second, shape-specific rule of its own.
///
/// A variable whose context field is optional is refused outright when the
/// caller supplied nothing, before that check has anything to run on.
fn resolve_var<'a>(
    var: RenderVar,
    context: &RenderContext<'a>,
) -> Result<Resolved<'a>, RenderError> {
    let value = match var {
        RenderVar::ArtifactPath => context.artifact_path,
        RenderVar::ConfigPath => context.config_path,
        RenderVar::DataDir => context.data_dir,
        RenderVar::InstanceId => context.instance_id,
        RenderVar::Hostname => context.hostname,
        RenderVar::Domain => context.domain,
        RenderVar::CertPath => context.cert_path,
        RenderVar::KeyPath => context.key_path,
        RenderVar::CaBundlePath => context.ca_bundle_path,
        RenderVar::ManagerEndpoint => context
            .manager_endpoint
            .ok_or(RenderError::UnresolvedVariable { var })?,
        RenderVar::MainPid => return Ok(Resolved::MainPid),
    };
    if is_representable(value) {
        Ok(Resolved::Text(value))
    } else {
        Err(RenderError::UnrepresentableValue {
            var,
            value: value.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NameField, PlacementFacts, RenderContext, RenderError, check_placement, render_unit,
    };
    use crate::executor::ServiceAccount;
    use crate::manifest::ArtifactKind;
    use crate::module_spec::{
        Arg, ModuleSpec, ModuleSpecError, PlacementClass, RegistrationTemplate, ReloadSpec,
        RenderVar, RestartPolicy, SystemdTarget, UnitTemplate,
    };

    /// `RestartSec=` value both shipped anchors carry.
    const RESTART_SEC: u32 = 5;

    /// Bound to every [`RenderVar`] an anchor does not use, so a test can
    /// assert the unused bindings reach no output byte.
    const UNUSED: &str = "UNUSED-BINDING";

    /// Every [`RenderVar`] the context resolves, which is the closed set minus
    /// [`RenderVar::MainPid`] — systemd's own expansion and the one variant
    /// with no context field.
    const HOST_RESOLVED_VARS: [RenderVar; 10] = [
        RenderVar::ArtifactPath,
        RenderVar::ConfigPath,
        RenderVar::DataDir,
        RenderVar::InstanceId,
        RenderVar::Hostname,
        RenderVar::Domain,
        RenderVar::CertPath,
        RenderVar::KeyPath,
        RenderVar::CaBundlePath,
        RenderVar::ManagerEndpoint,
    ];

    /// The endpoint the roxyd anchor is pointed at, in the form
    /// [`RenderVar::ManagerEndpoint`] documents: a certificate identity, a
    /// numeric address, and a port.
    const MANAGER_ENDPOINT: &str = "review@192.0.2.10:38390";

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

    fn roxyd_unit() -> UnitTemplate {
        UnitTemplate {
            description: "Roxyd host agent".to_string(),
            after: vec![SystemdTarget::NetworkOnline],
            wants: vec![SystemdTarget::NetworkOnline],
            wanted_by: vec![SystemdTarget::MultiUser],
            exec_start: vec![
                Arg::Var(RenderVar::ArtifactPath),
                Arg::Literal("-c".to_string()),
                Arg::Var(RenderVar::ConfigPath),
                Arg::Literal("--cert".to_string()),
                Arg::Var(RenderVar::CertPath),
                Arg::Literal("--key".to_string()),
                Arg::Var(RenderVar::KeyPath),
                Arg::Literal("--ca-certs".to_string()),
                Arg::Var(RenderVar::CaBundlePath),
                Arg::Literal("review.clumit.internal:38390".to_string()),
            ],
            exec_reload: Some(vec![
                Arg::Literal("/bin/kill".to_string()),
                Arg::Literal("-HUP".to_string()),
                Arg::Var(RenderVar::MainPid),
            ]),
            working_directory: None,
            environment: Vec::new(),
            restart: RestartPolicy::Always,
            restart_sec: RESTART_SEC,
            limit_nofile: None,
            protect_home: true,
            private_tmp: true,
            no_new_privileges: true,
        }
    }

    fn registration() -> RegistrationTemplate {
        RegistrationTemplate {
            package_id: "example".to_string(),
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
            registration: registration(),
            placement: PlacementClass::CoreHosts,
        }
    }

    /// A context binding every variable — the ones an anchor does not use to
    /// [`UNUSED`], so a test can prove a supplied-but-unreferenced binding
    /// reaches no output byte.
    fn review_context() -> RenderContext<'static> {
        RenderContext {
            artifact_path: "/opt/clumit-security/bin/review",
            config_path: "/etc/clumit-security/review.toml",
            data_dir: "/var/lib/clumit-security/review/data",
            instance_id: UNUSED,
            hostname: UNUSED,
            domain: UNUSED,
            cert_path: UNUSED,
            key_path: UNUSED,
            ca_bundle_path: UNUSED,
            manager_endpoint: Some(UNUSED),
            service_account: Some(ServiceAccount::Security),
            namespace: "clumit-security",
            service_name: "review",
            instance: None,
            component: "example",
            kind: ArtifactKind::NativeBinary,
        }
    }

    fn roxyd_context() -> RenderContext<'static> {
        RenderContext {
            artifact_path: "/opt/clumit-security/bin/roxyd",
            config_path: "/etc/clumit-security/roxyd.toml",
            data_dir: UNUSED,
            instance_id: UNUSED,
            hostname: UNUSED,
            domain: UNUSED,
            cert_path: "/var/lib/clumit-security/agent/roxyd/roxyd-cert.pem",
            key_path: "/var/lib/clumit-security/agent/roxyd/roxyd-key.pem",
            ca_bundle_path: "/var/lib/clumit-security/agent/roxyd/ca-bundle.pem",
            // Absent, so this anchor is also the case a `None` field has to
            // render: a template naming no manager endpoint is unaffected by
            // a caller having none to supply.
            manager_endpoint: None,
            service_account: None,
            namespace: "clumit-security",
            service_name: "roxyd",
            instance: None,
            component: "example",
            kind: ArtifactKind::NativeBinary,
        }
    }

    /// Renders a spec that must render, returning the unit it produced.
    fn rendered(spec: &ModuleSpec, context: &RenderContext<'_>) -> super::RenderedUnit {
        render_unit(spec, context)
            .expect("the fixture must render")
            .expect("the fixture declares a unit")
    }

    #[test]
    fn the_same_spec_and_context_render_byte_identically_twice() {
        let declared = spec(Some(roxyd_unit()));
        let context = roxyd_context();
        let first = rendered(&declared, &context);
        let second = rendered(&declared, &context);
        assert_eq!(first.text, second.text);
        assert_eq!(first.file_name, second.file_name);
    }

    #[test]
    fn the_production_renderer_reproduces_the_review_anchor_byte_for_byte() {
        let expected = "\
[Unit]
Description=Clumit Security review
After=network-online.target
Wants=network-online.target

[Service]
User=clumit-security
ExecStart=/opt/clumit-security/bin/review /etc/clumit-security/review.toml
WorkingDirectory=/var/lib/clumit-security/review/data
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
";
        let unit = rendered(&spec(Some(review_unit())), &review_context());
        assert_eq!(unit.text, expected);
        assert_eq!(unit.file_name, "clumit-security-review.service");
        // The unused bindings are supplied — the context binds every variable —
        // and reach no output byte.
        assert!(!unit.text.contains(UNUSED), "got: {}", unit.text);
    }

    #[test]
    fn the_production_renderer_reproduces_the_roxyd_anchor_byte_for_byte() {
        let expected = "\
[Unit]
Description=Roxyd host agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/clumit-security/bin/roxyd -c /etc/clumit-security/roxyd.toml --cert /var/lib/clumit-security/agent/roxyd/roxyd-cert.pem --key /var/lib/clumit-security/agent/roxyd/roxyd-key.pem --ca-certs /var/lib/clumit-security/agent/roxyd/ca-bundle.pem review.clumit.internal:38390
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
";
        let unit = rendered(&spec(Some(roxyd_unit())), &roxyd_context());
        // `service_account: None` emits no `User=` line at all, which is how
        // the shipped root-run unit is expressed.
        assert_eq!(unit.text, expected);
        assert!(!unit.text.contains("User="), "got: {}", unit.text);
        assert_eq!(unit.file_name, "clumit-security-roxyd.service");
        assert!(!unit.text.contains(UNUSED), "got: {}", unit.text);
    }

    /// The roxyd anchor with the one argument that varies per deployment named
    /// rather than baked in: the same unit, with its manager endpoint moved
    /// off the package and onto the host.
    fn roxyd_endpoint_unit() -> UnitTemplate {
        let mut unit = roxyd_unit();
        let endpoint = unit
            .exec_start
            .last_mut()
            .expect("the anchor declares arguments");
        *endpoint = Arg::Var(RenderVar::ManagerEndpoint);
        unit
    }

    #[test]
    fn the_manager_endpoint_renders_verbatim_as_the_one_final_argument() {
        let expected = "\
[Unit]
Description=Roxyd host agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/clumit-security/bin/roxyd -c /etc/clumit-security/roxyd.toml --cert /var/lib/clumit-security/agent/roxyd/roxyd-cert.pem --key /var/lib/clumit-security/agent/roxyd/roxyd-key.pem --ca-certs /var/lib/clumit-security/agent/roxyd/ca-bundle.pem review@192.0.2.10:38390
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
";
        let mut context = roxyd_context();
        context.manager_endpoint = Some(MANAGER_ENDPOINT);
        let unit = rendered(&spec(Some(roxyd_endpoint_unit())), &context);
        assert_eq!(unit.text, expected);
        assert_eq!(unit.file_name, "clumit-security-roxyd.service");
        // One argv element: the value the caller composed reaches the line as
        // it stands, neither split on `@` nor quoted nor otherwise reshaped.
        assert!(
            unit.text.contains(&format!(" {MANAGER_ENDPOINT}\n")),
            "got: {}",
            unit.text
        );
    }

    /// The variant in each position an [`Arg`] may occupy, so "permitted
    /// wherever an argument is" is exercised rather than asserted.
    fn units_naming_the_endpoint_in_every_position() -> [UnitTemplate; 4] {
        let mut in_exec_reload = roxyd_unit();
        in_exec_reload.exec_reload = Some(vec![
            Arg::Literal("/bin/reconnect".to_string()),
            Arg::Var(RenderVar::ManagerEndpoint),
        ]);

        let mut in_working_directory = roxyd_unit();
        in_working_directory.working_directory = Some(Arg::Var(RenderVar::ManagerEndpoint));

        let mut in_environment = roxyd_unit();
        in_environment.environment =
            vec![("MANAGER".to_string(), Arg::Var(RenderVar::ManagerEndpoint))];

        [
            roxyd_endpoint_unit(),
            in_exec_reload,
            in_working_directory,
            in_environment,
        ]
    }

    #[test]
    fn the_manager_endpoint_is_permitted_in_every_position_an_argument_may_appear() {
        // Nothing confines it to a field the way `main-pid` is confined to
        // `exec_reload`: there is no systemd rule to read one off.
        let mut context = roxyd_context();
        context.manager_endpoint = Some(MANAGER_ENDPOINT);
        for unit in units_naming_the_endpoint_in_every_position() {
            let text = rendered(&spec(Some(unit)), &context).text;
            assert!(text.contains(MANAGER_ENDPOINT), "got: {text}");
        }
    }

    #[test]
    fn a_template_naming_an_endpoint_the_context_does_not_supply_is_refused() {
        // `roxyd_context` supplies none. The refusal is the whole answer in
        // every position: no default, no empty string, no placeholder.
        for unit in units_naming_the_endpoint_in_every_position() {
            let error = render_unit(&spec(Some(unit)), &roxyd_context())
                .expect_err("an unresolved variable must be refused");
            assert!(
                matches!(
                    error,
                    RenderError::UnresolvedVariable {
                        var: RenderVar::ManagerEndpoint
                    }
                ),
                "got: {error:?}"
            );
            // And it names the variable it could not resolve.
            assert!(
                error.to_string().contains("ManagerEndpoint"),
                "got: {error}"
            );
        }
    }

    #[test]
    fn an_absent_endpoint_leaves_a_template_that_does_not_name_it_unchanged() {
        // The roxyd anchor renders byte-for-byte from a context supplying no
        // endpoint at all; here the same template renders identically whether
        // the caller supplies one or not, so the field reaches a byte only
        // when a template names the variable.
        let mut without = review_context();
        without.manager_endpoint = None;
        assert_eq!(
            rendered(&spec(Some(review_unit())), &without).text,
            rendered(&spec(Some(review_unit())), &review_context()).text
        );
    }

    #[test]
    fn the_production_renderer_reproduces_a_limit_setting_anchor_byte_for_byte() {
        // The same anchor as the review one, with the single field this record
        // gained set: the whole diff between the two expected strings is one
        // line, in one place.
        let mut unit = review_unit();
        unit.limit_nofile = Some(8000);
        let expected = "\
[Unit]
Description=Clumit Security review
After=network-online.target
Wants=network-online.target

[Service]
User=clumit-security
ExecStart=/opt/clumit-security/bin/review /etc/clumit-security/review.toml
WorkingDirectory=/var/lib/clumit-security/review/data
Restart=always
RestartSec=5
LimitNOFILE=8000

[Install]
WantedBy=multi-user.target
";
        let rendered = rendered(&spec(Some(unit)), &review_context());
        assert_eq!(rendered.text, expected);
        assert_eq!(rendered.file_name, "clumit-security-review.service");
    }

    #[test]
    fn the_limit_sits_between_restart_sec_and_the_first_sandbox_boolean() {
        // The neighbours are what fix the position, so they are asserted as
        // adjacent lines rather than as a substring that would still pass if
        // the directive drifted to the end of the section.
        let mut unit = review_unit();
        unit.limit_nofile = Some(8000);
        unit.protect_home = true;
        unit.private_tmp = true;
        unit.no_new_privileges = true;
        let text = rendered(&spec(Some(unit)), &review_context()).text;
        assert!(
            text.contains("RestartSec=5\nLimitNOFILE=8000\nProtectHome=yes\n"),
            "got: {text}"
        );
    }

    #[test]
    fn a_unit_setting_no_limit_renders_no_limit_directive_at_all() {
        // `Limit`, not `LimitNOFILE`: an absent field must not put *any*
        // resource directive into the unit.
        for unit in [review_unit(), roxyd_unit()] {
            assert_eq!(unit.limit_nofile, None);
        }
        let review = rendered(&spec(Some(review_unit())), &review_context()).text;
        assert!(!review.contains("Limit"), "got: {review}");
        let roxyd = rendered(&spec(Some(roxyd_unit())), &roxyd_context()).text;
        assert!(!roxyd.contains("Limit"), "got: {roxyd}");
    }

    #[test]
    fn the_canonical_directive_order_holds_for_a_record_using_every_optional_field() {
        let mut unit = review_unit();
        unit.exec_reload = Some(vec![
            Arg::Literal("/bin/kill".to_string()),
            Arg::Var(RenderVar::MainPid),
        ]);
        unit.environment = vec![
            ("RUST_LOG".to_string(), Arg::Literal("info".to_string())),
            ("HOST".to_string(), Arg::Var(RenderVar::Hostname)),
        ];
        unit.limit_nofile = Some(8000);
        unit.protect_home = true;
        unit.private_tmp = true;
        unit.no_new_privileges = true;

        let mut context = review_context();
        context.hostname = "host-a";
        let expected = "\
[Unit]
Description=Clumit Security review
After=network-online.target
Wants=network-online.target

[Service]
User=clumit-security
ExecStart=/opt/clumit-security/bin/review /etc/clumit-security/review.toml
ExecReload=/bin/kill $MAINPID
WorkingDirectory=/var/lib/clumit-security/review/data
Environment=\"RUST_LOG=info\"
Environment=\"HOST=host-a\"
Restart=always
RestartSec=5
LimitNOFILE=8000
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
";
        assert_eq!(rendered(&spec(Some(unit)), &context).text, expected);
    }

    #[test]
    fn main_pid_renders_bare_and_is_never_doubled() {
        let unit = rendered(&spec(Some(roxyd_unit())), &roxyd_context());
        assert!(unit.text.contains("ExecReload=/bin/kill -HUP $MAINPID"));
        assert!(!unit.text.contains("$$MAINPID"), "got: {}", unit.text);
    }

    #[test]
    fn a_spec_declaring_no_unit_is_a_valid_input_answered_with_none() {
        for kind in [ArtifactKind::StaticAssets, ArtifactKind::ContainerImage] {
            let mut context = review_context();
            context.kind = kind;
            // A static-asset or container-image module with a registration
            // template and a placement class legitimately runs no service.
            assert!(
                render_unit(&spec(None), &context)
                    .expect("a unit-less spec is not a failure")
                    .is_none(),
                "{kind:?}"
            );

            // `None` is the valid-but-unit-less answer, not a swallowed
            // failure: the same spec with a unit added is still refused by the
            // kind rule.
            let error = render_unit(&spec(Some(review_unit())), &context)
                .expect_err("a unit on a unit-less kind must be rejected");
            assert!(
                matches!(
                    error,
                    RenderError::InvalidSpec(ModuleSpecError::UnexpectedUnit(refused))
                        if refused == kind
                ),
                "{kind:?} got: {error:?}"
            );
        }
    }

    #[test]
    fn a_kind_that_requires_a_unit_still_refuses_a_spec_declaring_none() {
        // `Ok(None)` answers a kind whose unit is legitimately absent; it is
        // not a blanket escape from the kind rule. The two kinds that require
        // a unit refuse a spec carrying none, and render the one that carries
        // it — so the whole rule stays with its one owner, the validator.
        for kind in [ArtifactKind::NativeBinary, ArtifactKind::ComposeBundle] {
            let mut context = review_context();
            context.kind = kind;

            let error = render_unit(&spec(None), &context)
                .expect_err("a kind requiring a unit must reject a spec declaring none");
            assert!(
                matches!(
                    error,
                    RenderError::InvalidSpec(ModuleSpecError::MissingUnit(refused))
                        if refused == kind
                ),
                "{kind:?} got: {error:?}"
            );

            assert_eq!(
                rendered(&spec(Some(review_unit())), &context).file_name,
                "clumit-security-review.service",
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_instance_discriminator_alone_decides_the_file_name_suffix() {
        let declared = spec(Some(review_unit()));
        let singleton = review_context();
        let mut many = review_context();
        many.instance = Some("001");

        assert_eq!(
            rendered(&declared, &singleton).file_name,
            "clumit-security-review.service"
        );
        assert_eq!(
            rendered(&declared, &many).file_name,
            "clumit-security-review-001.service"
        );
        // Otherwise identical inputs: the discriminator reaches the name and
        // nothing else.
        assert_eq!(
            rendered(&declared, &singleton).text,
            rendered(&declared, &many).text
        );
    }

    #[test]
    fn an_instance_id_reaches_the_unit_verbatim_with_no_padding() {
        let mut unit = review_unit();
        unit.exec_start.push(Arg::Var(RenderVar::InstanceId));
        let mut context = review_context();
        context.instance_id = "7";
        context.instance = Some("007");

        let text = rendered(&spec(Some(unit)), &context).text;
        assert!(
            text.contains(
                "ExecStart=/opt/clumit-security/bin/review /etc/clumit-security/review.toml 7\n"
            ),
            "got: {text}"
        );
        // The file-name discriminator is a separate input and is not confused
        // with the instance id.
        assert!(!text.contains("007"), "got: {text}");
    }

    #[test]
    fn an_unrepresentable_resolved_value_is_refused_and_produces_nothing() {
        for bad in ["a\0b", "a\nb", "a\rb", "a\x07b", ""] {
            let mut context = review_context();
            context.config_path = bad;
            let error = render_unit(&spec(Some(review_unit())), &context)
                .expect_err("an unrepresentable resolved value must be rejected");
            assert!(
                matches!(
                    error,
                    RenderError::UnrepresentableValue {
                        var: RenderVar::ConfigPath,
                        ref value,
                    } if value == bad
                ),
                "value {bad:?} got: {error:?}"
            );
        }
    }

    /// A unit referring to every host-resolved [`RenderVar`], in the order the
    /// two tests below read them back.
    fn every_var_unit() -> UnitTemplate {
        let mut unit = review_unit();
        unit.exec_start = HOST_RESOLVED_VARS.iter().copied().map(Arg::Var).collect();
        unit
    }

    /// A context binding each host-resolved variable to its own field name, so
    /// a crossed wire in the resolver shows up as the wrong word.
    fn every_var_context() -> RenderContext<'static> {
        RenderContext {
            artifact_path: "artifact-path",
            config_path: "config-path",
            data_dir: "data-dir",
            instance_id: "instance-id",
            hostname: "hostname",
            domain: "domain",
            cert_path: "cert-path",
            key_path: "key-path",
            ca_bundle_path: "ca-bundle-path",
            manager_endpoint: Some("manager-endpoint"),
            ..review_context()
        }
    }

    /// Binds `var`'s context field to `value`.
    fn bind(context: &mut RenderContext<'static>, var: RenderVar, value: &'static str) {
        match var {
            RenderVar::ArtifactPath => context.artifact_path = value,
            RenderVar::ConfigPath => context.config_path = value,
            RenderVar::DataDir => context.data_dir = value,
            RenderVar::InstanceId => context.instance_id = value,
            RenderVar::Hostname => context.hostname = value,
            RenderVar::Domain => context.domain = value,
            RenderVar::CertPath => context.cert_path = value,
            RenderVar::KeyPath => context.key_path = value,
            RenderVar::CaBundlePath => context.ca_bundle_path = value,
            RenderVar::ManagerEndpoint => context.manager_endpoint = Some(value),
            RenderVar::MainPid => panic!("`main-pid` is not a context field"),
        }
    }

    #[test]
    fn every_host_resolved_variable_reads_its_own_context_field() {
        // Resolution is total — every variant has a field — and each variant
        // reads the field it names rather than a neighbour's.
        let text = rendered(&spec(Some(every_var_unit())), &every_var_context()).text;
        assert!(
            text.contains(
                "ExecStart=artifact-path config-path data-dir instance-id hostname domain \
                 cert-path key-path ca-bundle-path manager-endpoint\n"
            ),
            "got: {text}"
        );
        // `working_directory` resolves through the same field.
        assert!(text.contains("WorkingDirectory=data-dir\n"), "got: {text}");
    }

    #[test]
    fn every_host_resolved_value_goes_through_the_representability_rule() {
        // The check is applied to whatever the host resolved, not to one
        // favoured field: corrupting any of them refuses, naming that one.
        for var in HOST_RESOLVED_VARS {
            for bad in ["", "a\nb"] {
                let mut context = every_var_context();
                bind(&mut context, var, bad);
                let error = render_unit(&spec(Some(every_var_unit())), &context)
                    .expect_err("an unrepresentable resolved value must be rejected");
                assert!(
                    matches!(
                        error,
                        RenderError::UnrepresentableValue {
                            var: rejected,
                            ref value,
                        } if rejected == var && value == bad
                    ),
                    "{var:?} {bad:?} got: {error:?}"
                );
            }
        }
    }

    #[test]
    fn the_representability_rule_holds_in_every_position_a_variable_may_appear() {
        // `Environment=` resolves to raw text rather than a rendered argument,
        // and `WorkingDirectory=` renders a lone element rather than a list, so
        // each reaches the check by its own path. All three are pinned so a
        // later shortcut in one cannot drop it silently.
        let mut unit = review_unit();
        unit.exec_reload = Some(vec![
            Arg::Literal("/bin/kill".to_string()),
            Arg::Var(RenderVar::Hostname),
        ]);
        unit.environment = vec![("HOST".to_string(), Arg::Var(RenderVar::Domain))];

        for (var, bad) in [
            // `exec_start`, through the argument list.
            (RenderVar::ConfigPath, ""),
            // `exec_reload`, likewise.
            (RenderVar::Hostname, "a\nb"),
            // `working_directory`, a lone element.
            (RenderVar::DataDir, ""),
            // `environment`, resolved raw.
            (RenderVar::Domain, "a\nb"),
        ] {
            let mut context = review_context();
            bind(&mut context, var, bad);
            let error = render_unit(&spec(Some(unit.clone())), &context)
                .expect_err("an unrepresentable resolved value must be rejected");
            assert!(
                matches!(
                    error,
                    RenderError::UnrepresentableValue {
                        var: rejected,
                        ref value,
                    } if rejected == var && value == bad
                ),
                "{var:?} {bad:?} got: {error:?}"
            );
        }
    }

    #[test]
    fn a_file_name_component_outside_the_dns_label_rule_is_refused() {
        for bad in [
            "a/b",
            "..",
            "a b",
            "A",
            "a_b",
            "-a",
            "a-",
            "",
            &"a".repeat(64),
        ] {
            // All three components of the name are held to the same rule; the
            // context `service_name` included, which is the one a valid
            // registration template could otherwise be mistaken for covering.
            let mut namespace = review_context();
            namespace.namespace = bad;
            let mut service_name = review_context();
            service_name.service_name = bad;
            let mut instance = review_context();
            instance.instance = Some(bad);

            for (field, context) in [
                (NameField::Namespace, namespace),
                (NameField::ServiceName, service_name),
                (NameField::Instance, instance),
            ] {
                let error = render_unit(&spec(Some(review_unit())), &context)
                    .expect_err("a non-label file-name component must be rejected");
                assert!(
                    matches!(
                        error,
                        RenderError::InvalidNameComponent {
                            field: refused,
                            ref value,
                        } if refused == field && value == bad
                    ),
                    "{field} {bad:?} got: {error:?}"
                );
                // The refusal names which context field carried the value.
                assert!(error.to_string().contains(field.as_str()), "got: {error}");
            }
        }

        // The 63-octet counterpart of the rejected 64-octet one renders.
        let label = "a".repeat(63);
        let mut context = review_context();
        context.namespace = &label;
        assert_eq!(
            rendered(&spec(Some(review_unit())), &context).file_name,
            format!("{label}-review.service")
        );
    }

    #[test]
    fn a_spec_handed_in_directly_is_still_held_to_every_validator_rule() {
        // A registration-template rule, which needs the enclosing component.
        let mut mismatched = review_context();
        mismatched.component = "other";
        let error = render_unit(&spec(Some(review_unit())), &mismatched)
            .expect_err("a mismatched package_id must be rejected");
        assert!(
            matches!(
                error,
                RenderError::InvalidSpec(ModuleSpecError::PackageIdMismatch { .. })
            ),
            "got: {error:?}"
        );

        // A rule that needs the enclosing kind.
        let mut container = review_context();
        container.kind = ArtifactKind::ContainerImage;
        let error = render_unit(&spec(Some(review_unit())), &container)
            .expect_err("a unit on a container-image artifact must be rejected");
        assert!(
            matches!(
                error,
                RenderError::InvalidSpec(ModuleSpecError::UnexpectedUnit(
                    ArtifactKind::ContainerImage
                ))
            ),
            "got: {error:?}"
        );

        // A unit-template rule.
        let mut unit = review_unit();
        unit.description = String::new();
        let error = render_unit(&spec(Some(unit)), &review_context())
            .expect_err("an empty description must be rejected");
        assert!(
            matches!(
                error,
                RenderError::InvalidSpec(ModuleSpecError::EmptyDescription)
            ),
            "got: {error:?}"
        );
    }

    #[test]
    fn the_registration_template_is_validated_and_never_read() {
        let baseline = rendered(&spec(Some(review_unit())), &review_context());

        let mut varied = spec(Some(review_unit()));
        varied.registration.reload = ReloadSpec::DockerSighup {
            container: "giganto".to_string(),
        };
        varied.registration.cert_group_gid = Some(1000);
        let other = rendered(&varied, &review_context());
        assert_eq!(other.text, baseline.text);
        assert_eq!(other.file_name, baseline.file_name);

        // Where the two could disagree, the context wins.
        let mut disagreeing = spec(Some(review_unit()));
        disagreeing.registration.service_name = "not-review".to_string();
        let followed = rendered(&disagreeing, &review_context());
        assert_eq!(followed.file_name, "clumit-security-review.service");
        assert!(
            !followed.text.contains("not-review"),
            "got: {}",
            followed.text
        );
    }

    #[test]
    fn the_shared_escaping_rule_decides_quoting_and_doubling_in_each_position() {
        let mut unit = review_unit();
        unit.description = "50% done".to_string();
        unit.exec_start = vec![
            Arg::Var(RenderVar::ArtifactPath),
            Arg::Literal("--flag".to_string()),
            Arg::Literal("a b".to_string()),
            Arg::Literal("a$b".to_string()),
        ];
        unit.environment = vec![("Q".to_string(), Arg::Literal("a$b".to_string()))];

        let text = rendered(&spec(Some(unit)), &review_context()).text;
        assert!(
            text.contains("ExecStart=/opt/clumit-security/bin/review --flag \"a b\" a$$b\n"),
            "got: {text}"
        );
        // systemd expands nothing in `Environment=`, so the same value keeps
        // its single `$` there.
        assert!(text.contains("Environment=\"Q=a$b\"\n"), "got: {text}");
        // A `Description=` is a whole unquoted line and reaches the same
        // helper, so its `%` is doubled rather than emitted raw.
        assert!(text.contains("Description=50%% done\n"), "got: {text}");
    }

    #[test]
    fn each_placement_class_is_decided_by_its_own_fact_alone() {
        for component_assigned in [false, true] {
            for carries_modules in [false, true] {
                let facts = PlacementFacts {
                    component_assigned,
                    carries_modules,
                };

                let core = check_placement(PlacementClass::CoreHosts, facts);
                assert_eq!(
                    core.is_ok(),
                    component_assigned,
                    "core-hosts on {facts:?}: {core:?}"
                );

                // Including the co-located case, where both facts are set and
                // the module-host fact is still the one that decides.
                let module = check_placement(PlacementClass::ModuleHosts, facts);
                assert_eq!(
                    module.is_ok(),
                    carries_modules,
                    "module-hosts on {facts:?}: {module:?}"
                );

                for (class, outcome) in [
                    (PlacementClass::CoreHosts, core),
                    (PlacementClass::ModuleHosts, module),
                ] {
                    let Err(error) = outcome else {
                        continue;
                    };
                    assert!(
                        matches!(
                            error,
                            RenderError::PlacementRefused { class: refused, reason }
                                if refused == class && !reason.is_empty()
                        ),
                        "got: {error:?}"
                    );
                }
            }
        }

        // A host carrying core components but no distributed modules refuses a
        // module-hosts artifact, which an unconditional accept would not.
        assert!(
            check_placement(
                PlacementClass::ModuleHosts,
                PlacementFacts {
                    component_assigned: true,
                    carries_modules: false,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn every_refusal_carries_an_operator_facing_reason() {
        let refusal = check_placement(
            PlacementClass::ModuleHosts,
            PlacementFacts {
                component_assigned: true,
                carries_modules: false,
            },
        )
        .expect_err("the module-host fact is clear");
        let message = refusal.to_string();
        assert!(message.contains("ModuleHosts"), "got: {message}");
        assert!(message.contains("distributed modules"), "got: {message}");
    }
}
