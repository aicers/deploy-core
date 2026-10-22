# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `module_spec::UnitTemplate::supplementary_groups` lets a package's unit
  declare supplementary groups from the closed `module_spec::SupplementaryGroup`
  (one variant, `Adm`, manifest spelling `"adm"`), rendered as
  `SupplementaryGroups=adm` right after `User=`. A duplicated group, groups
  together with `run_as`, groups in a manifest stamped below format version 8,
  and rendering groups with no service account are refused.
- A producer now stamps manifest format version 8, and this build reads 3
  through 8. A build that reads only up to 7 refuses a format-8 manifest.

### Changed

- `config_template::requires_template` no longer returns `true` for
  `reconverge`, so no component requires a configuration template.

### Removed

- The `reconverge` `default` configuration template is retired:
  `config_template::find("reconverge", "default")` returns `None`, the catalog
  is empty, and the id will not be reused.

## [0.2.1] - 2026-10-17

### Security

- Under `SudoAuth::Password`, `Executor::run`, `Executor::run_with_input` and
  `Executor::put_file` on `LocalExecutor` and `SshExecutor` no longer pass the
  password line on to the command when `sudo` does not read it (a `NOPASSWD`
  rule, or credentials `sudo` still has cached). Before, the command read the
  password as its first line of input, and `put_file` wrote it in plain text at
  the start of the file it landed, with that file's owner and mode.

## [0.2.0] - 2026-10-17

### Added

- `module_spec::UnitTemplate::run_as` lets a package declare that its service
  runs as root (`module_spec::RunAs::Root`, manifest spelling `"root"`); such a
  unit renders no `User=` line whatever account the caller supplies. A package
  still cannot name an account.
- A producer now stamps manifest format version 7, and this build reads 3
  through 7. A build that reads only up to 6 refuses a format-7 manifest.

## [0.1.1] - 2026-10-05

### Added

- A `default` configuration template for `reconverge`: one detector every 5 minutes
  on the Data Store's HTTP events with the HttpUriThreat label database, using
  the Central Manager model named `unsupervised-default`.
- A catalog of named configuration templates for components whose first-install
  configuration file comes from a template, with English and Korean names and
  descriptions, the set of components that require one, lookups by component and
  by template id, and a renderer that substitutes the host's values — the
  enrollment certificate, key and CA bundle paths and the manager's address and
  server name — into a template and returns the configuration file's TOML text.

### Changed

- An `AppRole`'s `Debug` output no longer shows its role id or secret id; both
  print as `<redacted>`.

## [0.1.0] - 2026-10-02

### Added

- Product-neutral deployment primitives shared by an installer and an on-host
  root agent: local and SSH execution, elevated command channels, bounded
  command input/output and deadlines, namespace-derived host paths, artifact
  and configuration diffs, durable staged writes, hard-link backups, and
  install/update apply operations.
- Declarative module install specifications and validation, generic systemd
  unit rendering, placement checks, manager endpoint substitution, file
  descriptor limits, and bootroot service registration commands.
- A shared container format for executable installer payloads and standalone
  `.pkg` packages, with bounded envelope reads, streaming raw blocks, manifest
  parsing, archive-member binding, and caller-owned detached Ed25519 signing.
- Namespace-scoped package signature verification using injected trust anchors
  and withdrawn-build records, with typed errors for callers to match.
- Manifest format 6 container image declarations describing ownership,
  references, Linux platform, config digest, lifecycle, and provenance, plus
  canonical runtime aliases. Legacy manifest formats 3–5 remain readable.
- Full-content package verification that retains immutable package and artifact
  bytes, checks supported docker-save image archives against their signed
  declarations, and reports canonical image manifest digests. Verification
  enforces resource ceilings that callers may lower, and refuses legacy images
  without declarations. Upload verification returns authenticated metadata
  under a staging budget callers can reserve in advance.
- Unsigned package preparation, persistence and reopening across signing jobs,
  detached finalization against a saved preparation binding, and combined
  preparation/signing/finalization. Finalized packages support durable
  publication without replacing existing files.
- Strict trust-set generation documents and on-host release-trust storage,
  including active and generation-scoped readers, install-time admission,
  ordered runtime generation replay with an epoch floor, re-bootstrap, and
  join-material bootstrap with optional out-of-band fingerprint pins.
- roxyd certificate/key validation and trust-material activation using AWS-LC,
  rollback supervisor systemd units, and the shared versioned on-disk
  self-update contract.
- The optional `test-support` feature for dependent crates' dev-dependencies:
  account and payload fixtures, a scriptable recording executor, synthetic
  image archive builders and validators, and signed package fixture support.

[Unreleased]: https://github.com/aicers/deploy-core/compare/0.2.1...main
[0.2.1]: https://github.com/aicers/deploy-core/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/aicers/deploy-core/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/aicers/deploy-core/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/aicers/deploy-core/releases/tag/0.1.0
