//! Product-neutral service-registration primitives.
//!
//! Registering a certificate consumer with bootroot — `service info` to check a
//! registration by its registration id, `service add` to mint one — is generic:
//! it needs only the resolved registration facts (the registration id, the SAN's
//! service label, the delivery mode, the paths the agent reads, the `AppRole` to
//! authenticate with), not any product's `Component` catalog. This module holds
//! those primitives plus the small value types the phase reports through.
//!
//! The installer resolves a component's `ServiceRegistration`
//! and `ProductManifest` down to a
//! [`ServiceAddSpec`] of plain fields and calls [`service_add_args`]; the argv
//! builder itself carries no product concept. That resolve-then-call boundary is
//! what lets an external consumer (the on-host agent) drive the same registration
//! primitives without the installer's manifest machinery.

use std::path::PathBuf;
use std::time::Duration;

use crate::bootroot_cmd::{AppRole, BootrootRunner};
use crate::exec::CoreError;
use crate::executor::{ExecutorError, Identity};

/// Response-wrapping TTL passed to `service add --secret-id-wrap-ttl` for the
/// remote-bootstrap hand-off. Raised above bootroot's 30 min default to give the
/// SSH stage-and-bootstrap pipeline headroom before the single-use `wrap_token`
/// expires (RFC 0001 §6 Phase 3).
const REMOTE_WRAP_TTL: &str = "60m";

/// How a consumer's certificate is delivered, derived from placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// The consumer is co-located with bootroot: `--delivery-mode local-file` and
    /// the daemon-managed local agent.
    LocalFile,
    /// The consumer is off-host: `--delivery-mode remote-bootstrap` plus the SSH
    /// hand-off and `bootroot-remote bootstrap` on the target.
    RemoteBootstrap,
}

impl DeliveryMode {
    /// Returns the bootroot `--delivery-mode` flag value.
    #[must_use]
    pub fn flag(self) -> &'static str {
        match self {
            DeliveryMode::LocalFile => "local-file",
            DeliveryMode::RemoteBootstrap => "remote-bootstrap",
        }
    }

    /// Derives the delivery mode for a component placed on `host` relative to the
    /// bootroot host.
    #[must_use]
    pub fn for_host(host: &str, bootroot_host: &str) -> Self {
        if host == bootroot_host {
            DeliveryMode::LocalFile
        } else {
            DeliveryMode::RemoteBootstrap
        }
    }
}

/// A bounded poll for a consumer's first certificate issuance.
///
/// The wait must terminate: an agent that never self-authenticates would
/// otherwise hang the install. `attempts` polls of the declared cert path spaced
/// by `delay` cap the wait; on expiry the phase fails with
/// `InstallError::CertTimeout`.
/// Tests use a tiny `delay` so the loop does not actually sleep.
#[derive(Debug, Clone, Copy)]
pub struct CertWait {
    /// How many times the cert path is polled before giving up.
    pub attempts: u32,
    /// The delay between polls.
    pub delay: Duration,
}

impl CertWait {
    /// Creates a wait of `attempts` polls spaced by `delay`.
    #[must_use]
    pub fn new(attempts: u32, delay: Duration) -> Self {
        Self { attempts, delay }
    }
}

impl Default for CertWait {
    /// Returns the production wait: 60 polls two seconds apart (~2 minutes), long
    /// enough for a healthy fast-poll agent to mint its first leaf, bounded so a
    /// broken one fails rather than hangs.
    fn default() -> Self {
        Self::new(60, Duration::from_secs(2))
    }
}

/// The outcome of registering one cert consumer, surfaced for the operator report
/// and asserted by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceOutcome {
    /// The registered service name.
    pub service_name: String,
    /// The host the consumer (and its cert) live on.
    pub host: String,
    /// The delivery mode derived from placement.
    pub delivery: DeliveryMode,
    /// Whether this run ran `service add`. False when the service was already
    /// registered and needed no artifact refresh; true for a fresh registration,
    /// and also when an already-registered off-host service had its wrapped
    /// bootstrap artifact refreshed because its target cert was still absent.
    pub registered_now: bool,
    /// Whether this run ran the remote-bootstrap hand-off (false for local-file,
    /// or when the target was already bootstrapped).
    pub bootstrapped_now: bool,
    /// The `bootroot-agent` systemd unit installed and enabled on the consumer's
    /// host to issue and renew the cert. Its `enable --now` is idempotent, so it
    /// is (re-)asserted every run.
    pub agent_unit: String,
    /// The declared cert path the phase waited on.
    pub cert_path: PathBuf,
}

/// The resolved facts for one `bootroot service add`, with every product-specific
/// path/policy already computed by the caller.
///
/// The installer builds this from a component's registration and manifest (its
/// cert/key/agent-config paths, reload hook, agent owner, cert group); the argv
/// builder consumes only the plain fields, so it stays free of any
/// `Component` concept.
pub struct ServiceAddSpec<'a> {
    /// bootroot's namespace key for the registration (`--registration-id`): it
    /// names the `state.json` entry, the `AppRole` and policy, the
    /// `bootroot/services/<key>` KV subtree, the managed `agent.toml` block, and
    /// the fast-poll state file.
    ///
    /// deploy-core neither derives it from [`Self::service_name`] nor validates
    /// it: the caller chooses both, and bootroot validates them.
    pub registration_id: &'a str,
    /// The SAN's service label (`--service-name`) only; several registrations
    /// may share one.
    pub service_name: &'a str,
    /// The delivery mode derived from placement.
    pub delivery: DeliveryMode,
    /// The rotation `AppRole` the registration authenticates with.
    pub approle: &'a AppRole,
    /// The raw `[hosts]` label the component is placed on (the SAN host label,
    /// not the client-facing FQDN).
    pub hostname: &'a str,
    /// The internal-mTLS domain the leaf's SAN is composed under.
    pub domain: &'a str,
    /// The per-instance id forming the SAN's leading label.
    pub instance_id: &'a str,
    /// Where the issued cert lands on the consumer's host.
    pub cert_path: &'a str,
    /// Where the issued key lands on the consumer's host.
    pub key_path: &'a str,
    /// Where the agent config the daemon reads lands.
    pub agent_config: &'a str,
    /// The reload-hook flags (a `--reload-style` preset or bootroot's custom
    /// post-renew command), resolved from the registration.
    pub reload_args: Vec<String>,
    /// Where a relocated (non-root) agent keeps its rotatable `secret_id`
    /// (`--secret-id-path`), or `None` for bootroot's default. The flag is
    /// emitted exactly when this is `Some`; the caller decides when the
    /// relocation applies.
    pub secret_id_path: Option<&'a str>,
    /// A concrete cert-ownership gid to pass `--cert-group`, when the registration
    /// resolves one; `None` for a root consumer or a deferred gid.
    pub cert_group_gid: Option<u32>,
    /// The remote-reachable `--agent-server`/`--agent-responder-url` endpoints an
    /// off-host consumer bakes into its artifact; `None` for a co-located agent
    /// on bootroot's localhost defaults.
    pub endpoints: Option<(&'a str, &'a str)>,
}

/// Assembles the `bootroot service add` argument vector from a resolved
/// [`ServiceAddSpec`].
///
/// The vector opens with `service add --registration-id <registration_id>
/// --service-name <service_name>`: the registration id is bootroot's namespace
/// key, the service name only the SAN's service label, and each is passed as the
/// caller resolved it.
///
/// Common flags register the service under `--auth-mode approle` with the
/// rotation `AppRole`, the placement-derived delivery mode, the cert/key/
/// agent-config paths, and the reload-hook preset. `--cert-group` is emitted only
/// for a container consumer whose gid has resolved (a deferred gid emits nothing,
/// mirroring the deferred-port rule). The remote-bootstrap mode additionally
/// raises the response-wrapping TTL so the SSH hand-off fits inside it, and bakes
/// the remote-reachable `--agent-server`/`--agent-responder-url` supplied in
/// `endpoints` into the artifact — bootroot's own localhost defaults would strand
/// an off-host agent. A co-located (local-file) consumer passes `endpoints` as
/// `None`: its agent runs on the bootroot host, where the loopback defaults are
/// correct.
///
/// The rotation `AppRole` is passed with the direct `--approle-role-id`/
/// `--approle-secret-id` flags. On the single-tenant, root-controlled bootroot
/// host this is an accepted tradeoff for a small argv-exposure window; a
/// file-based (`--approle-*-file`) hand-off is the follow-up if that window ever
/// matters.
#[must_use]
pub fn service_add_args(spec: &ServiceAddSpec) -> Vec<String> {
    let mut args = vec![
        "service".to_string(),
        "add".to_string(),
        "--registration-id".to_string(),
        spec.registration_id.to_string(),
        "--service-name".to_string(),
        spec.service_name.to_string(),
        "--delivery-mode".to_string(),
        spec.delivery.flag().to_string(),
        "--auth-mode".to_string(),
        "approle".to_string(),
        "--approle-role-id".to_string(),
        spec.approle.role_id.clone(),
        "--approle-secret-id".to_string(),
        spec.approle.secret_id.clone(),
        "--hostname".to_string(),
        spec.hostname.to_string(),
        "--domain".to_string(),
        spec.domain.to_string(),
        "--instance-id".to_string(),
        spec.instance_id.to_string(),
        "--cert-path".to_string(),
        spec.cert_path.to_string(),
        "--key-path".to_string(),
        spec.key_path.to_string(),
        "--agent-config".to_string(),
        spec.agent_config.to_string(),
    ];
    // The reload hook: a `--reload-style` preset for a native-SIGHUP consumer, or
    // bootroot's low-level custom post-renew command (`docker kill --signal=HUP
    // <container>`) for a container-SIGHUP consumer (#125, #129).
    args.extend(spec.reload_args.iter().cloned());
    // A relocated (non-root) agent keeps its AppRole `secret_id` inside its own
    // `agent/<svc>/` directory, so the account can rewrite it on rotation without
    // reaching into the root-owned secrets tree (bootroot #722). A root
    // container-consumer agent needs no relocation and keeps bootroot's default.
    //
    // bootroot accepts the flag in either delivery mode, so it is emitted exactly
    // when the caller supplies `secret_id_path`; whether the relocation applies
    // is the caller's decision.
    if let Some(secret_id_path) = spec.secret_id_path {
        args.push("--secret-id-path".to_string());
        args.push(secret_id_path.to_string());
    }
    if let Some(gid) = spec.cert_group_gid {
        args.push("--cert-group".to_string());
        args.push(gid.to_string());
    }
    if spec.delivery == DeliveryMode::RemoteBootstrap {
        args.push("--secret-id-wrap-ttl".to_string());
        args.push(REMOTE_WRAP_TTL.to_string());
    }
    if let Some((server, responder)) = spec.endpoints {
        args.push("--agent-server".to_string());
        args.push(server.to_string());
        args.push("--agent-responder-url".to_string());
        args.push(responder.to_string());
    }
    args
}

/// Reports whether the registration keyed by `registration_id` — bootroot's
/// namespace key, not the SAN's service label — is already registered with
/// bootroot, via `service info --registration-id <registration_id>` run as
/// root.
///
/// The exit status is the whole answer: a zero exit means registered, and any
/// non-zero exit (unregistered, no `state.json`, or anything else bootroot
/// refuses) means not registered, so the caller runs `service add`.
///
/// # Errors
///
/// Returns [`ExecutorError`] when the `service info` invocation could not run.
pub fn service_registered(
    runner: &BootrootRunner,
    registration_id: &str,
) -> Result<bool, ExecutorError> {
    let output = runner.run(
        Identity::Root,
        &["service", "info", "--registration-id", registration_id],
    )?;
    Ok(output.success())
}

/// Runs `bootroot service add`, mapping a non-zero exit to
/// [`CoreError::ServiceRegistration`] — the installer folds it back into its own
/// `ServiceRegistration` error unchanged.
///
/// # Errors
///
/// Returns [`CoreError::Executor`] when the invocation could not run, or
/// [`CoreError::ServiceRegistration`] when `service add` exited non-zero.
pub fn run_service_add(
    runner: &BootrootRunner,
    service: &str,
    host: &str,
    args: &[String],
) -> Result<(), CoreError> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = runner.run(Identity::Root, &borrowed)?;
    if output.success() {
        Ok(())
    } else {
        Err(CoreError::ServiceRegistration {
            service: service.to_string(),
            host: host.to_string(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{DeliveryMode, ServiceAddSpec, service_add_args, service_registered};
    use crate::bootroot_cmd::{AppRole, BootrootRunner};
    use crate::executor::test_support::{RecordedCall, RecordingExecutor};
    use crate::executor::{CommandOutput, Identity};

    const COMMAND_PATH: &str = "/opt/bootroot/bin/bootroot";
    const STATE_DIR: &str = "/var/lib/clumit-test";

    fn approle() -> AppRole {
        AppRole {
            role_id: "role-1".to_string(),
            secret_id: "secret-1".to_string(),
        }
    }

    fn spec<'a>(
        approle: &'a AppRole,
        delivery: DeliveryMode,
        registration_id: &'a str,
        service_name: &'a str,
    ) -> ServiceAddSpec<'a> {
        ServiceAddSpec {
            registration_id,
            service_name,
            delivery,
            approle,
            hostname: "node1",
            domain: "mtls.internal",
            instance_id: "001",
            cert_path: "/etc/roxyd/cert.pem",
            key_path: "/etc/roxyd/key.pem",
            agent_config: "/etc/bootroot/agent.toml",
            reload_args: vec!["--reload-style".to_string(), "sighup".to_string()],
            secret_id_path: None,
            cert_group_gid: None,
            endpoints: None,
        }
    }

    fn expected(tail: &[&str]) -> Vec<String> {
        tail.iter().map(|arg| (*arg).to_string()).collect()
    }

    /// The flags every vector carries between the delivery mode and the
    /// optional ones, in order.
    const COMMON: [&str; 18] = [
        "--auth-mode",
        "approle",
        "--approle-role-id",
        "role-1",
        "--approle-secret-id",
        "secret-1",
        "--hostname",
        "node1",
        "--domain",
        "mtls.internal",
        "--instance-id",
        "001",
        "--cert-path",
        "/etc/roxyd/cert.pem",
        "--key-path",
        "/etc/roxyd/key.pem",
        "--agent-config",
        "/etc/bootroot/agent.toml",
    ];

    fn head(registration_id: &str, service_name: &str, delivery: &str) -> Vec<String> {
        let mut args = expected(&[
            "service",
            "add",
            "--registration-id",
            registration_id,
            "--service-name",
            service_name,
            "--delivery-mode",
            delivery,
        ]);
        args.extend(expected(&COMMON));
        args.extend(expected(&["--reload-style", "sighup"]));
        args
    }

    #[test]
    fn local_file_emits_the_registration_id_and_the_service_name() {
        let approle = approle();
        let mut spec = spec(&approle, DeliveryMode::LocalFile, "roxyd-mgmt", "roxyd");
        spec.secret_id_path = Some("/var/lib/bootroot/agent/roxyd-mgmt/secret_id");
        spec.cert_group_gid = Some(1234);
        spec.endpoints = Some(("https://ca:9000/acme", "http://ca:8080"));

        let mut want = head("roxyd-mgmt", "roxyd", "local-file");
        want.extend(expected(&[
            "--secret-id-path",
            "/var/lib/bootroot/agent/roxyd-mgmt/secret_id",
            "--cert-group",
            "1234",
            "--agent-server",
            "https://ca:9000/acme",
            "--agent-responder-url",
            "http://ca:8080",
        ]));
        assert_eq!(service_add_args(&spec), want);
    }

    #[test]
    fn remote_bootstrap_keeps_the_wrap_ttl_and_endpoints_after_the_new_pair() {
        let approle = approle();
        let mut spec = spec(
            &approle,
            DeliveryMode::RemoteBootstrap,
            "roxyd-mgmt",
            "roxyd",
        );
        spec.secret_id_path = Some("/var/lib/bootroot/agent/roxyd-mgmt/secret_id");
        spec.cert_group_gid = Some(1234);
        spec.endpoints = Some(("https://ca.example:9000/acme", "http://ca.example:8080"));

        let mut want = head("roxyd-mgmt", "roxyd", "remote-bootstrap");
        want.extend(expected(&[
            "--secret-id-path",
            "/var/lib/bootroot/agent/roxyd-mgmt/secret_id",
            "--cert-group",
            "1234",
            "--secret-id-wrap-ttl",
            "60m",
            "--agent-server",
            "https://ca.example:9000/acme",
            "--agent-responder-url",
            "http://ca.example:8080",
        ]));
        assert_eq!(service_add_args(&spec), want);
    }

    #[test]
    fn local_file_without_optional_fields_emits_none_of_their_flags() {
        let approle = approle();
        let spec = spec(&approle, DeliveryMode::LocalFile, "roxyd-mgmt", "roxyd");

        assert_eq!(
            service_add_args(&spec),
            head("roxyd-mgmt", "roxyd", "local-file")
        );
    }

    #[test]
    fn remote_bootstrap_with_only_endpoints_emits_no_secret_id_path_or_cert_group() {
        let approle = approle();
        let mut spec = spec(
            &approle,
            DeliveryMode::RemoteBootstrap,
            "roxyd-mgmt",
            "roxyd",
        );
        spec.endpoints = Some(("https://ca.example:9000/acme", "http://ca.example:8080"));

        let mut want = head("roxyd-mgmt", "roxyd", "remote-bootstrap");
        want.extend(expected(&[
            "--secret-id-wrap-ttl",
            "60m",
            "--agent-server",
            "https://ca.example:9000/acme",
            "--agent-responder-url",
            "http://ca.example:8080",
        ]));
        assert_eq!(service_add_args(&spec), want);
    }

    #[test]
    fn an_equal_registration_id_and_service_name_are_both_emitted() {
        let approle = approle();
        let spec = spec(&approle, DeliveryMode::LocalFile, "roxyd", "roxyd");

        let args = service_add_args(&spec);
        assert_eq!(args, head("roxyd", "roxyd", "local-file"));
        assert_eq!(
            args.iter()
                .filter(|arg| *arg == "--registration-id")
                .count(),
            1
        );
        assert_eq!(
            args.iter().filter(|arg| *arg == "--service-name").count(),
            1
        );
    }

    fn exit(code: i32) -> CommandOutput {
        CommandOutput {
            code: Some(code),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn service_registered_queries_by_registration_id_and_reads_the_exit_status() {
        let exec = RecordingExecutor::new();
        exec.script_run(Ok(exit(0)));
        exec.script_run(Ok(exit(1)));
        let runner = BootrootRunner::new(&exec, COMMAND_PATH.to_string(), PathBuf::from(STATE_DIR));

        assert!(service_registered(&runner, "roxyd-mgmt").expect("scripted run"));
        assert!(!service_registered(&runner, "roxyd-mgmt").expect("scripted run"));

        let calls = exec.calls();
        assert_eq!(calls.len(), 2);
        for call in calls {
            let RecordedCall::Run {
                identity,
                command,
                args,
            } = call
            else {
                panic!("expected a run, got {call:?}");
            };
            assert_eq!(identity, Identity::Root);
            assert_eq!(command, "sh");
            assert!(args.iter().any(|arg| arg == STATE_DIR), "{args:?}");
            assert!(
                args.ends_with(&expected(&[
                    COMMAND_PATH,
                    "service",
                    "info",
                    "--registration-id",
                    "roxyd-mgmt",
                ])),
                "{args:?}"
            );
            assert!(!args.iter().any(|arg| arg == "--service-name"), "{args:?}");
        }
    }
}
