# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/aicers/deploy-core/compare/0.1.0...main
[0.1.0]: https://github.com/aicers/deploy-core/releases/tag/0.1.0
