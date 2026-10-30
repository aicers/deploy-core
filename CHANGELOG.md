# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `verify::SignatureAlgorithm`, `Ed25519` or `MlDsa87`, names a package
  signature algorithm, and `verify::ML_DSA_87_PUBLIC_KEY_LEN` is the 2,592 bytes
  of a raw ML-DSA-87 public key.

### Changed

- `Executor::run`, `Executor::run_with_input`, `Executor::open_channel` and
  everything built on them now refuse an invocation that goes through `sudo`
  when its command or any argument contains `__BOOTLER_SUDO_OK__`, before
  anything is spawned. This covers `Identity::Root` and `Identity::Service` on
  `LocalExecutor` and `SshExecutor`, and `Identity::Service` on
  `InDaemonExecutor`. The refusal is `ExecutorError::Spawn` with an
  `InvalidInput` source naming the word's position; `run_with_input` and
  `open_channel` wrap it in their `Executor` variant.
- The command line an elevated run hands `sudo` no longer contains
  `__BOOTLER_SUDO_OK__`: the scripts print it from two halves. A test double
  that recognises an elevated run by finding that word in its command line no
  longer finds it.
- `SshExecutor` passes
  `-o KexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512` to every `ssh`
  it runs, so a session either negotiates a hybrid post-quantum key exchange or
  fails; it never falls back to a classical one, and an `ssh_config` cannot
  loosen the list. It also passes `-o ControlPath=none`, so a session never runs
  over a connection-sharing master that an `ssh_config` names, whose key
  exchange another `ssh` negotiated, and never leaves one behind. A host whose
  `sshd` offers neither method now fails with the new
  `ExecutorError::KexRefusedByHost`, and a local `ssh` that does not know both
  names (OpenSSH before 9.9) with the new
  `ExecutorError::KexUnsupportedLocally`, each naming the host and the allowed
  methods; both were `ExecutorError::Connection` before. `ExecutorError` is not
  `#[non_exhaustive]`, so a `match` over it without a wildcard arm must handle
  the two new variants.
- The trust-set generation document is version 2. Every anchor carries an
  `algorithm`, `ed25519` or `ml-dsa-87`, and its `public_key` is that
  algorithm's raw public key in lowercase hex: 64 characters for Ed25519, 5,184
  for ML-DSA-87. A document must carry at least one non-revoked anchor of each
  algorithm and is refused with the new
  `TrustSetDocumentError::MissingLiveAnchor` otherwise. A version 1 document is
  refused and nothing converts it: every `release_trust` admission door refuses
  to admit one, and every function that reads an installed version 1 generation
  refuses it with `TrustSetDocumentError::UnsupportedVersion`.
  `trust_set::TrustSetAnchor` gains the `algorithm` field, and
  `TrustSetDocumentError::MalformedPublicKey` names the algorithm.
- `verify::TrustAnchor` carries its algorithm. `TrustAnchor::new` still builds
  an Ed25519 anchor, the new `TrustAnchor::new_ml_dsa_87` builds an ML-DSA-87
  one, `TrustAnchor::algorithm` says which, and `TrustAnchor::public_key`
  returns `&[u8]` instead of `&[u8; 32]`. `verify::key_id` takes any raw public
  key as `&[u8]`. A package's `key_id` hint, and every anchor tried for its
  Ed25519 signature, are taken only from the trust set's Ed25519 anchors, so a
  hint naming an ML-DSA-87 anchor is `VerifyError::UnknownKeyId`.

### Fixed

- A classic `sudo` that denies a command under sudoers and repeats the command
  line in its denial is now reported as `ExecutorError::SudoRefused` by
  `Executor::run`, `Executor::put_file` and the other elevated helpers, and by
  `Executor::run_with_input` and `Executor::open_channel` inside their
  `Executor` variant. Before, `run` returned the denial as the command's own
  output with exit code `1`, `put_file` reported it as
  `ExecutorError::Transfer`, `run_with_input` reported
  `RunWithInputError::TimedOut`, and `open_channel` returned a channel to a
  command that never started.

## [0.3.1] - 2026-10-29

### Fixed

- `executor::sudo_needs_password` now also recognises the wording of sudo-rs,
  the `sudo` of Ubuntu 26.04: `sudo: interactive authentication is required`
  and `sudo: A terminal is required to authenticate`. A
  `SudoAuth::NonInteractive` executor whose sudo-rs wants a password now fails
  with `ExecutorError::Elevation`, as it does with classic sudo, instead of
  `ExecutorError::SudoRefused`.
- The standard error that `Executor::run` returns for a command run through
  `sudo` now starts with the command's own first byte. What `sudo` or `ssh`
  wrote before the command started is dropped, as `Executor::run_with_input`
  and `Executor::open_channel` already did; that includes the empty line
  sudo-rs writes after it reads a password.

## [0.3.0] - 2026-10-22

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

[Unreleased]: https://github.com/aicers/deploy-core/compare/0.3.1...main
[0.3.1]: https://github.com/aicers/deploy-core/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/aicers/deploy-core/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/aicers/deploy-core/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/aicers/deploy-core/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/aicers/deploy-core/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/aicers/deploy-core/releases/tag/0.1.0
