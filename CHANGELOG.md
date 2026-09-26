# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Container image declarations and namespace-scoped package verification. A
  producer now stamps manifest format version 6, at which every
  `container-image` artifact carries a typed `image::ImageDeclaration` in
  `PayloadArtifact::image` (supplied through `payload::ArtifactInput::image`):
  its owning namespace and component, its dependency name, the explicit
  `name:tag` references it is restored under, its one Linux platform, its
  config digest, whether its references are `managed_runtime` or
  `shared_external`, and a `registry` or `product_build` provenance. Every
  manifest read door checks the declaration's shape and Docker reference
  syntax, and refuses an `image` key on any other artifact kind and on any
  format 3–5 or unversioned manifest, `null` included, so a legacy image is
  never read as declaring anything. `image::canonical_runtime_alias` and
  `ImageDeclaration::normalized_third_party` build the
  `runtime.invalid/<namespace>/<component>/<dependency>:cfg-<config hex>`
  alias a newly normalized third-party image is published under.
  `verify::VerifyRequest::for_namespaced_package` scopes a request to the
  caller's own namespace; a package declaring images verifies only under it,
  and a declaration that disagrees with its artifact's architecture, misuses
  the reserved alias registry, conflicts with another declaration's reference,
  or names another namespace or component is refused under the new
  `verify::VerifyError::Image` arm. `VerifiedPackage::image_references`
  reports whether a verified package carries no images, declared ones — with
  the union of their references — or legacy undeclared ones; it describes
  signed statements and checks no image bytes. Existing consumers migrate by
  adding `image: None` to `PayloadArtifact` and `ArtifactInput` literals for
  every non-image artifact, a declaration for every new image input, and an
  arm for `VerifyError::Image` and the new `ManifestError` variants to
  exhaustive matches. This build still reads formats 3–5, while a build
  predating it refuses a format-6 package for its version alone.
- Full-content package evidence and a detached-signing package writer.
  `package::verify_contents` turns a signed component package into immutable,
  fully checked evidence for one requested `TargetArch`: it copies the package
  once into private retained storage, authenticates that copy with exactly the
  verdicts `verify::verify_package` gives, refuses any artifact built for
  another architecture and any legacy undeclared image, extracts and hashes
  every outer member, and then holds each image archive to its signed
  declaration. One image form is accepted, the supported docker-save profile:
  an OCI-layout, single-image `docker save` tar with a Docker compatibility
  `manifest.json` and uncompressed or gzip layers, whose tags, config,
  platform and layers must all agree with the declaration. The returned
  `package::VerifiedContents` exposes the authenticated manifest, every
  artifact as a `package::VerifiedArtifact`, the images as
  `package::VerifiedImages`, and the exact package bytes, all as read-only
  `package::RetainedBytes` that later changes to the original cannot reach.
  Every step is bounded by `package::ContentLimits`, one ceiling per
  `package::LimitResource` — stored and decoded bytes, entries, path lengths,
  JSON sizes and nesting, disk and buffers — each starting at a generous
  default that a caller may lower with `with_limit` and never raise.
  `package::prepare_package` prepares an unsigned standalone package for a
  separate signing job: it copies each input once, builds exactly one raw
  manifest block and one compressed archive block from those copies, and runs
  the same content checks. The returned `package::PreparedPackage` is
  unsigned and untrusted for installation; its `package::PreparationBinding`
  records the blocks' digests and lengths and the requested build,
  architecture, namespace and trust epoch as data to correlate signing
  requests with, never a capability. `persist` writes it as a new three-file
  directory and `package::reopen_prepared` turns one back into a package only
  against a binding the caller saved itself. `package::finalize_package`
  takes a prepared package and a detached Ed25519 signature over its raw
  manifest block, holds both blocks to the saved binding again, assembles the
  signed container from exactly those bytes without holding a key, and runs
  the full `verify_contents` pipeline over it under the caller's trust; its
  disk budget is `RetainedDisk` less what the prepared package still holds.
  The resulting `package::FinalizedPackage` is what direct installation and
  store publication both consume, and `FinalizedPackage::publish`, like
  `VerifiedContents::publish_package`, writes a new file without ever
  replacing an existing entry and returns a `package::PublishedPackage`
  receipt that is not evidence. `package::prepare_sign_finalize` composes
  preparation, one signing callback and finalization, validating identically,
  and with the `test-support` feature's
  `image::test_support::SyntheticImageArchiveBuilder`, which writes
  deterministic image archives of the supported profile and exposes the config
  digest before any tag is chosen, it builds genuinely signed format-6
  fixtures for a consumer's tests; `image::test_support::check_image_archive`
  holds any archive to a declaration. `verify_package`, `extract_to` and the
  low-level `payload` writers are unchanged, and bytes those writers assemble
  are not a finalized package. Consumers migrate by adding arms for the new
  `verify::ImageVerifyError` variants — `LegacyImageEvidence`,
  `UnsupportedArchive`, `InvalidArchive`, `UndeclaredReference`,
  `MissingReference`, `ConfigDigestMismatch`, `ConfigPlatformMismatch` and
  `LayerMismatch` — to exhaustive matches. The new public error enums are
  `package::ContentError`, `package::ContentLimitsError`,
  `package::PublicationError`, `package::PackageWriteError`,
  `package::PreparationFault`, `package::RecordFault`,
  `image::test_support::SyntheticImageError` and
  `image::test_support::ArchiveCheckError`, with the detail enums they carry:
  `package::IoOperation`, `package::PublicationOperation`,
  `package::CopyMismatchKind`, `package::DirectoryTrustReason`,
  `package::DirectoryFault`, `package::PreparationFile`,
  `package::BindingField` and `package::LimitResource`, and in `verify` the
  image-archive fault types `UnsupportedArchiveFeature`, `TarFeature`,
  `ExtensionField`, `InvalidArchiveReason`, `TarFault`, `TarHeaderField`,
  `PaxKey`, `GzipFault`, `GzipHeaderFault`, `JsonFault`, `LayoutFile`,
  `ImageDocument`, `BlobRole`, `BlobMismatchKind`, `InvalidConfigReason`,
  `ConfigField`, `ReferenceSource`, `PlatformLocation`, `PlatformFacet` and
  `LayerMismatchKind`.
- `roxyd_selfupdate_contract`, the frozen on-disk contract the roxyd self-update
  rollback supervisor coordinates through: the record directory, the file names,
  the canonical roxyd binary path, the decision subcommand and its three
  activation reasons, the self-test freshness window and nonce rules, a resolver
  for every path composed from them, and the versioned JSON record types —
  `ArmRecord`, `ConfirmMarker`, `StatusRecord`, `SupervisorVersionMarker`,
  `ReportRequest` and `SelfTestRecord` — with the `FORMAT` revision each carries.
  It is the one definition both writers of these files can name: the shape is a
  versioned agreement between the installer and the on-host agent, and a second
  copy of it diverges after deployment with both repositories' tests green. It
  is a sibling of `roxyd_selfupdate` rather than part of it and neither module
  depends on the other — the unit text is byte-identical data with one consumer
  and deliberately no parameters, where this is a shape two writers have to
  agree on. Every value is the one already on disk on every host, held there by
  a test that names each rather than rebuilding it from the constant beside it.
- `executor::Executor::hard_link_over`, which preserves a root-owned regular
  file under another name by hard-linking it to a temporary sibling, renaming
  that over the destination, and flushing the directory the new entry appeared
  in. `apply::backup_previous_artifact` takes the `.previous` backup through it,
  so a backup is a second name for the artifact's own inode rather than a second
  copy of its bytes: an interrupted backup leaves no `.previous` at all, where an
  interrupted copy would leave a truncated one that a later revert succeeds onto,
  and the artifact's mode and timestamps are carried by the shared inode rather
  than preserved beside it. Replacing an existing backup leaves either the old
  file or the new one and never a partial or absent one, because the old entry is
  never unlinked and the rename is atomic. A temporary an interrupted attempt
  stranded beside the destination does not stand in a resumed apply's way
  either: the sequence steps onto a free temporary name rather than clearing the
  occupied one away or failing on it, so no host is left needing a leftover
  removed by hand before an apply can proceed. A symlink at the artifact is
  refused rather than followed — whether or not it resolves — and so is a
  directory or any other non-regular file.
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
