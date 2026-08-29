# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `module_spec::UnitTemplate::limit_nofile`, an optional `LimitNOFILE=` a
  package declares against its own unit, so a service whose store outgrows the
  soft descriptor limit systemd hands a unit says so itself instead of leaving
  an operator to raise it on the host. The renderer emits the directive between
  `RestartSec=` and the sandbox booleans. Absence, which is what every unit
  rendered until now carries, inherits the host's soft limit; there is no
  spelling for systemd's `infinity`, so leaving a service unbounded stays the
  host's decision rather than a package's: a declared zero is refused as
  `module_spec::ModuleSpecError::ZeroLimitNofile`, and `u64::MAX` — the
  numeric value of Linux's `RLIM_INFINITY`, which systemd's own rlimit parser
  refuses — as `module_spec::ModuleSpecError::InfiniteLimitNofile`. A producer
  now stamps manifest format version 5 and this build still reads 3, so a
  payload already published stays readable, installable, and byte-identical in
  what it renders.
- `module_spec::RenderVar::ManagerEndpoint`, with which a unit template names
  the manager endpoint its module is pointed at, and the
  `render::RenderContext::manager_endpoint` field the renderer resolves it
  from. The value is one argv element, `<server_name>@<address>:<port>`, so a
  module that takes the endpoint as a mandatory positional argument no longer
  has to bake one deployment's manager into a package as a literal. This crate
  parses none of it: the format belongs to the consuming module's own argument
  parser. A caller with no such peer supplies `None`, and a template naming the
  variable against it is refused with `render::RenderError::UnresolvedVariable`
  rather than rendering a default, an empty string or a placeholder.
  `MANIFEST_FORMAT_VERSION` and `MAX_MANIFEST_FORMAT_VERSION` move with it; the
  accepted floor does not, so every manifest already published at it still
  decodes, validates and renders unchanged.
- `payload::widen_envelope_blocks`, a `test-support` fixture that builds a
  compact malformed-envelope case for a dependent crate to write sparsely when
  testing bounded package reads without duplicating deploy-core's private
  footer layout.
- `payload::UnparsedContainer::parse_unverified_manifest`, which lets a caller
  decode manifest metadata from `read_package_container` without reopening an
  untrusted package. The returned manifest is intentionally unauthenticated;
  callers with a `TrustSet` continue to use the verifying path.
- `payload::read_package_container`, which reports a package's signature and
  `key_id` metadata under the release format's fixed envelope bounds without
  allocating blocks advertised at another length.
- `payload::append_trailer_signed`, which gives a caller-supplied signer the
  exact manifest bytes the writer emits and stamps its detached Ed25519
  signature and `key_id` into either a `.pkg` package or an installer payload.
  The signing key and its custody remain entirely with the caller.
- The roxyd self-update rollback supervisor units, shipped as data under
  `roxyd_selfupdate`: the boot, crash and deadline activation services and the
  timer that drives the deadline one, each exported verbatim with no renderer
  and nothing for a consumer to substitute. Every activation execs the decision
  subcommand from the `.previous` sibling of the roxyd binary's canonical path
  and is gated on the arm record, so one text serves both the hosts an installer
  provisions and the hosts roxyd onboards itself. This crate owns the text: a
  consumer embeds these bytes rather than carrying a copy that would drift.
- The runtime release-trust accept path, which judges a delivered generation
  against the **active** generation's trust set and applies the `epoch` floor:
  `release_trust::accept_generation` for one delivered generation,
  `release_trust::accept_generation_chain` for the ordered replay that catches a
  lagging host up, and `release_trust::read_generation_state` for the question a
  caller asks before it pushes. A byte-identical redelivery of the active
  generation is an unchanged no-op rather than a refusal; anything else must be
  strictly newer than the active generation to activate.
- The two release-trust entry points for the hosts the accept path cannot serve,
  each admitting a generation under the anchors the delivered document itself
  carries: `release_trust::rebootstrap_generation` for a host offline past the
  control plane's retention window, and
  `release_trust::bootstrap_from_join_material` for a host with no prior
  generation. Both relax the signature-chain check and only that. The
  re-bootstrap demands a `release_trust::RebootstrapAuthorization` carrying the
  caller's assertion of the host's last-confirmed epoch, still applies the
  `epoch` floor against the verified epoch, and refuses an unpinned call on a
  host that carries the `require-trust-pin` marker; the bootstrap takes no
  caller-supplied bytes at all and reads its generation from
  `layout::JOIN_GENERATION_FILE` inside the release-trust tree, which
  `Layout::join_generation_path` resolves. Both take an optional out-of-band
  fingerprint pin, enforced whenever supplied.

[Unreleased]: https://github.com/aicers/deploy-core/commits/main
